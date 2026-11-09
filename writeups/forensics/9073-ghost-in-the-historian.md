# Ghost in the Historian

> Forensics · Medium · Mohamed Amine Mzoughi  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{xorshift_ghost_in_the_historian_d2c19434a637}
```

It is the `SAFETY_INTERLOCK_TOKEN` value from the recovered `grid_topology.cfg`.

**Tools used**

The Sleuth Kit (`fls`, `istat`, `icat`, `blkls`), `objdump` for static disassembly, and a ten-line Python
keystream script. Nothing from the image was executed and the image was never mounted.

**Challenge**

Someone encrypted a substation historian's configuration and then deleted the encryptor; the task is to
recover the original configuration's `SAFETY_INTERLOCK_TOKEN`. The brief (`README_FOR_RESPONDERS.md`) says
the volume was built for the exercise: the ext4 filesystem was created on 29 October, but the incident
records and the access/modification times were set to 2 October ("treat those different clocks according to
what each records"). It also says to treat recovered programs as data — do not run them, and do not mount
the image. We followed both rules.

The zip holds a monolithicFlat VMDK (`evidence.vmdk` descriptor + `evidence-flat.vmdk` data). The
descriptor maps a raw 64 MiB ext4 extent at offset 0 (`RW 131072 FLAT "evidence-flat.vmdk" 0`, label
`HISTORIAN01`, 4 KiB blocks), so the Sleuth Kit reads `evidence-flat.vmdk` directly, with no mount and no
conversion.

**Approach / walkthrough**

*1. Filesystem listing.* `fls -r -p evidence-flat.vmdk` lists three `.enc` files under `var/historian/`
(`grid_topology.cfg.enc` inode 28, `historian_cache.dat.enc` inode 22, `node_status.json.enc` inode 23),
`var/log/historian.log`, and three orphan (deleted) inodes 21, 24, 27. Only inode 27 has mode
`rwxr-xr-x`, so it is taken to be the deleted encryptor — but all three orphans show size 0 and no extents,
because ext4 clears the extent tree on delete. The binary cannot be recovered through the inode.

*2. PID and timeline.* `icat evidence-flat.vmdk 25` reads the log:

```
2026-10-02 04:13 historian_enc[2764964]: starting encryption sweep, target_dir=/var/historian
```

This gives the encryptor's PID, **2764964**, and the run time to the minute (formatted with
`gmtime_r`/`strftime`, so UTC). `istat` on inodes 28, 22, 23 shows identical Accessed and File Modified
times for all three: **04:13:05 UTC, epoch `1790914385`**, with zero nanoseconds. Their Inode Modified
(ctime) is the later 2026-10-29 volume-build date — the "different clocks" the brief describes. The 2
October a/mtime is the incident clock, which the encryptor set itself.

*3. Carve the binary.* The deleted inode no longer points to data, but the data blocks were not
overwritten. `blkls` dumps the unallocated blocks concatenated in order: a ransom note first, then an ELF
header (`\x7fELF`) in the next block. The ELF's own header gives its length,
`e_shoff (0x3148) + e_shnum (29) × e_shentsize (64) = 14,472 bytes`, carved with `dd`:

```
blkls evidence-flat.vmdk > unalloc.bin
dd if=unalloc.bin bs=4096 skip=512 | head -c 14472 > encryptor.elf
# SHA-256 56819e82de96aca21d925f9ce0104b8a10ec515882b34433ac343964cd541f6e
```

`file` reports a stripped, dynamically linked x86-64 PIE. Following the brief, it was never executed, only
read with `objdump -d/-R/-s` and `strings`.

*4. Static RE.* Imports (from `objdump -R`) include `time`, `getpid`, `scandir`, `strcmp`, `utime`,
`unlink`, `gmtime_r`, `strftime`. In `main`, the seed is built as:

```c
t   = time(NULL);                  // a copy is kept for later
pid = getpid();
seed = (pid == (uint32_t)t) ? 0xA5A5A5A5
                            : (uint32_t)((t ^ pid) * 0x9E3779B1);
```

(The constants appear as `movl $0xa5a5a5a5` at 0x1326 and `imull $0x9e3779b1` — the golden-ratio constant
— at 0x1331; the seed is stored in a `.bss` global.) `scandir` uses a comparator at 0x1740 that calls
`strcmp` on `d_name`, so files are processed in byte order: `grid_topology.cfg`, `historian_cache.dat`,
`node_status.json`. For each 4-byte block the code runs one xorshift32 step on the global state and XORs
the state's little-endian bytes into the block; a short final block uses only the bytes it needs:

```c
x ^= x << 13; x ^= x >> 17; x ^= x << 5;   // shll $0xd/shrl $0x11/shll $0x5 at 0x1553/155b/1563
```

The state is **not** reseeded per file — it carries over across all three. Each output then gets `utime()`
set to the *first* `time()` value (the seed time), and the plaintext is `unlink`ed. That `utime()` call is
why the exact seed second is recoverable: the log line alone is only accurate to the minute.

*5. Decrypt.* With `t = 1790914385` and `pid = 2764964`, `pid != (uint32)t`, so the fallback does not
apply and `seed = 0x40D8E565`. One keystream run across the three ciphertexts in `strcmp` order recovers
all three:

```python
import struct
t, pid = 1790914385, 2764964
s = 0xA5A5A5A5 if pid == (t & 0xffffffff) else ((t ^ pid) * 0x9E3779B1) & 0xffffffff
for f in ["grid_topology.cfg.enc", "historian_cache.dat.enc", "node_status.json.enc"]:  # inodes 28,22,23
    d, out = open(f, "rb").read(), bytearray()
    for i in range(0, len(d), 4):
        s ^= (s << 13) & 0xffffffff; s ^= s >> 17; s ^= (s << 5) & 0xffffffff
        out += bytes(a ^ b for a, b in zip(d[i:i+4], struct.pack("<I", s)))
    print(out.decode())
```

`grid_topology.cfg` comes out as the historian node's topology safety configuration, with `NODE_ID=MGA-
HIST-07`, `CHECKSUM=pending-resync`, and `SAFETY_INTERLOCK_TOKEN=CSCTF{xorshift_ghost_in_the_historian_
d2c19434a637}`. `historian_cache.dat` holds two CSV pressure readings and `node_status.json` a JSON status
record, both consistent with node ID `MGA-HIST-07`.

**Why it works**

The encryptor's only secret is `time() ^ getpid()`, and it leaves both halves on the volume: the PID in its
own log line, the exact second in the mtimes it stamped onto its outputs with `utime()`. xorshift32 is
fully determined by its seed, so knowing the seed means knowing the whole keystream. And deleting a file on
ext4 clears the inode's extents but not the data blocks, so the binary can still be carved from unallocated
space.

**Validation / reproduction**

Because the generator state carries over between files, the second and third files only decrypt correctly
if the seed, the shift constants and the file order are all right. All three came out as clean text — a
config file, CSV pressure readings and a JSON status record, all consistent with the node ID — and the
token matched the flag format.

Reproduction summary: `fls`/`istat` to get the encryptor PID (log) and the exact seed second (the `.enc`
mtimes); `blkls`+`dd` to carve the 14,472-byte ELF from unallocated space; `objdump` to recover the seed
formula, the xorshift32 step and the `strcmp` file order; compute `seed = (t ^ pid) * 0x9E3779B1 &
0xffffffff = 0x40D8E565`; run one continuous keystream over the three ciphertexts in `strcmp` order.
Gotchas: do not reseed per file (the state is global); the exact second must come from the `utime()`-set
mtime, not the minute-precision log line; watch the `pid == (uint32)t` fallback to `0xA5A5A5A5` (it does
not apply here). The first three sends came back `ratelimited` (not judged); the single value was accepted
on the fourth.
