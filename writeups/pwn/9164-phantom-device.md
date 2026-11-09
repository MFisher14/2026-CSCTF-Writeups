# Phantom Device

> Pwn · Not shown · Ahmed Abdelmoemen  
> Points: 875 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{935QoKmYNLOtHVt0iZ1XtDgM}
```

**Challenge**

> A communication module recovered from an intact Vostari drone presents itself as an Apple iOS
> device to the extraction toolkit. Analysts connect the standard reader to pull data — but the
> device is not what it seems. Something on the wire is lying.
>
> Walk the vulnerable AFC client on your assigned instance, read the flag off the socket. One
> port, inbound only. Interact only with your assigned instance.

The handout is a small AFC (Apple File Conduit) client, `client`, built against the shipped
`libimobiledevice-1.0.so.6` and `libplist-2.0.so.4`, with glibc 2.39 (Ubuntu 24.04). `handler.sh`
runs the client under `socat` with our inbound TCP socket as its stdin, and the client `dup`s that
socket into its AFC transport. So the roles are inverted from a normal pwn: **we are the iOS
device**. The program under attack is the reader, and every AFC reply it parses comes from us. The
exploit is therefore a malicious AFC peer, not a payload sent to a parser we control.

Static triage of `client`: PIE, full RELRO, stack canary, NX, not stripped, ships with debug info.
It imports only a handful of AFC calls (device info `0xB`, read dir `0x3`, get file info `0xA`,
file open `0xD`, file read `0xF`, file close `0x14`) plus `malloc`/`free`/`memcpy`. The attack
surface is entirely how it handles the replies we send to those calls.

**Approach / walkthrough**

The full exploit is the malicious-peer harness in `workspace/9164-phantom-device/exploit.py`
(`python3 exploit.py HOST PORT` remote; `python3 exploit.py` local, spawning `client` against a
listener on 127.0.0.1:31337 inside `csctf-pwn:1`). It speaks the AFC framing directly. A `Peer`
class scans the inbound byte stream for valid AFC request headers (the client's stdout text and its
AFC requests share one socket, so the harness locates each header by magic and sane length fields),
and a fixed `ops` map says which AFC operation each of the 14 scripted requests will be — read-dir
and info calls early, then the file-open/read/close cycle that carries the heap work.

*AFC framing.* Each packet is a 40-byte header `<8sQQQQ>` = magic `CFA6LPAA`, `entire_length`,
`this_length`, packet `number`, `operation`, followed by a body:

```python
MAGIC = b"CFA6LPAA"
HDR   = struct.Struct("<8sQQQQ")   # magic, entire, this_len, number, operation
```

*The bug — `entire_length` vs `this_length` confusion.* libimobiledevice sizes the receive buffer
from one length field but copies a second, attacker-chosen count into it. `send_packet` weaponizes
exactly that split: it sets `entire = HDR.size + alloc_len` (the size the client mallocs for the
reply) while putting `this_len = HDR.size + len(body)` and sending the *full* `body` on the wire:

```python
def send_packet(sock, number, operation, body=b"", alloc_len=None):
    entire   = HDR.size + alloc_len        # what the client allocates
    this_len = HDR.size + len(body)        # what it then copies
    sock.sendall(HDR.pack(MAGIC, entire, this_len, number, operation) + body)
```

Reply to a file-read with `alloc_len=0x20` but an 0x80-byte body and the client allocates a 0x20
chunk and memcpy's 0x80 bytes into it: a controlled heap overflow of 0x60 bytes past the chunk.

glibc 2.39 has no malloc hooks and uses safe-linked tcache. The chain is therefore: leak a heap
address, defeat safe-linking, poison a tcache entry to get an allocation on a live
`libimobiledevice` object, leak libc, then forge a stdio `FILE` (FSOP) so glibc's own I/O path
makes the controlled call. The flag is read back in-band on the same socket.

1. **Shape the heap.** Requests 1–6 answer benign AFC calls with crafted directory vectors and
   tiny persistent names so the 0x20 and 0x30 tcache bins are drained to a known state and a large
   non-top reply is freed into the unsorted bin as a guard. Concretely, request 2's directory reply
   (`b"a\0b\0c\0d\0\0"`) forces a 0x40 pointer array; request 4's reply is 24 strings of `0x30`
   bytes each, parsed into an unsorted-bin guard that leaves the 0x20/0x30 bins undisturbed; request
   5's four tiny names drain the 0x20 tcache to two entries. This leaves a predictable layout around
   a chunk the harness calls `h1`, with the response chunk itself freed last at a known `0x8f0` head.
2. **Heap leak + safe-link decode.** Request 7's reply body (a freed chunk re-read) carries a
   safe-linked tcache `next` whose low byte the overflow had zeroed. `solve_heap()` brute-forces
   the 256 possible low bytes and the 16-round safe-link fixed point, constraining the result with
   the known page offset `0x8f0` (`HEAP_OFF`), to recover the real pointer. From `h1` the harness
   derives every object: `service_chunk = h1 - 0x5C0`, `afc = h1 - 0x5A0`,
   `connection = h1 - 0x5F0`, `original_packet = h1 - 0x550`.
3. **Overflow + tcache poison.** Reply 7 (`alloc_len=0x20`, 0x80-byte body) rewrites two live 0x20
   chunk headers (forged as `0,0x21` at body offsets 0x20 and 0x40), forges `h1` as a 0x30 chunk
   (`0,0x31` at 0x60), and overwrites its safe-linked `next` at offset 0x70 with
   `service_chunk ^ (h1 >> 12)`:

   ```python
   struct.pack_into("<Q", overflow, 0x70, service_chunk ^ (h1 >> 12))
   send_packet(sock, 7, AFC_DATA, bytes(overflow), alloc_len=0x20)
   ```

   Two allocations later the poisoned chunk is handed out *on top of the real `service_client`
   object*. Overflowing that allocation rewrites the adjacent `afc_client` pointers (connection,
   a one-field fake `service_client` at `service_chunk+0x10`, and the packet pointer) via
   `build_afc_short()`, while the intervening `free()` only clobbers the now-obsolete service copy.
4. **Arbitrary read → libc leak.** With the AFC packet pointer under our control, each subsequent
   reply is read back from an address we choose (the harness re-points `fake_service`'s packet field
   per request). Pointing it at the unsorted-bin guard leaks `main_arena`'s `bk`;
   `libc_base = arena_ptr - 0x204B20`. A page-offset check selects the correct arena offset
   (`0x204B20` when `arena_ptr & 0xfff == 0xB20`, else `0x204F30` when `0xF30`) for the live binary,
   giving the true base.
5. **Leak the locked mutex owner.** FSOP on 2.39 needs the PID that currently holds the AFC mutex
   so the forged `FILE`'s `_lock` looks owned. Reading `afc+0x20` leaks the `pthread_mutex_t`
   owner word; `pid = owner & 0xffffffff`. `mutex_bytes(pid)` rebuilds a valid locked mutex
   (`struct.pack("<IIiIihhQQ", 1, 0, pid, 1, …)`) so the overwrite doesn't deadlock.
6. **FSOP via the wide-vtable (House of Apple).** `build_afc_overlap()` allocates a 0x478 body on
   the real service chunk, preserves the surrounding chunk headers (`connection,0x61` at 0x10,
   `0,0x441` at 0x60) and the live mutex (`mutex_bytes(pid)` at 0x38), and forges a
   `FILE` at `original_packet` (body offset `0x70`): `_mode = 1` (wide) at `+0xC0`, `_wide_data`
   at `+0xA0` and a wide vtable at `+0xD8` pointing at `_IO_wfile_jumps` so that flushing drives
   `_IO_wdoallocbuf`, and `vtable+0x68 = system`. The command sits in the first FILE bytes:

   ```python
   command = b"  cat /flag.txt >&0;\0"     # >&0 writes to the bidirectional socket
   ...
   struct.pack_into("<Q", out, packet_off + 0x200 + 0x68, system_addr)   # wide vtable -> system
   ```

   The AFC packet pointer is finally aimed at `_IO_list_all - 0x28` so the forged structure is
   linked in, and the next flush calls `system("  cat /flag.txt >&0;")`. The `>&0` redirect writes
   to fd 0 — the same bidirectional socket socat left on stdin — so the flag comes straight back to
   us. The harness then drains the socket (3-second timeout) and prints it.

Offsets used (from the shipped libc 2.39, hardcoded in `exploit.py`): unsorted `bk` `0x204B20`,
`system` `0x58750`, `_IO_wfile_jumps` `0x203228`, `_IO_list_all` `0x2054C0`, `environ` `0x20BD58`.

**Why it works**

The client trusts the device completely. A malicious device controls both the contents and the
sizes of what the reader puts on its heap, and the `entire_length`/`this_length` split in the AFC
transport turns that into a direct, sized heap overflow. Modern glibc removed the one-write malloc
hooks, but tcache poisoning still yields an allocation at a chosen address once a heap leak defeats
safe-linking, and a forged stdio `FILE` remains the standard way to convert one controlled heap
object into a call during normal I/O. Because socat keeps the socket bidirectional on stdin, the
shell command can exfiltrate the flag in-band with `>&0` — no outbound connection is needed, which
matters since container egress was blocked.

**Validation / reproduction**

The exploit was developed and detonated only inside the `csctf-pwn:1` Docker sandbox against the
shipped `ld`/`libc`/`libimobiledevice`/`libplist` (local mode spawns `client` behind a listener,
with optional `GDB`/`TRACE`/`PROBE`/`STACK_SCAN` env hooks and the `mtrace.so`/`trace.gdb` shims
for malloc tracing). It was then run once against our assigned instance (`exploit.py <instance>`),
which returned `CSCTF{935QoKmYNLOtHVt0iZ1XtDgM}` in-band. Codex (which built the fake-device
dialogue under guidance) never submits; we verified the value and submitted it once by hand through
the CLI, where it was accepted on the first try (`tried.json`: one attempt, `correct`).

Reproduction summary: build/mount the challenge files at `/challenge` in `csctf-pwn:1`, confirm the
local run drops the flag file to the socket, then point the harness at a fresh instance. Gotchas:
the safe-link low byte must be brute-forced (`solve_heap`) because the overflow zeroes it; the
arena page offset differs per build and is auto-selected; and the forged mutex must carry the live
owner PID or the final flush deadlocks instead of calling `system`.
