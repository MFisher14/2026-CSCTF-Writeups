# Ghost Bank

> Reverse engineering · Hard · Chronos Security  
> Points: 546 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{MLwO5fGUzg03SjGJ1anWVEUc}
```

**Challenge**

> An inert relay bench from Brenzava, which supplies relay hardware to the Operation Dawn coalition, was recovered after an unattributed supply-chain compromise. It exposes one stopped GDB Remote Serial Protocol (RSP) endpoint, and the extracted controller image and a historical bench capture came with it. The capture may record an old maintenance session, and nothing in it proves a recorded value is still valid on a live bench.
>
> Work out how the controller activates its sealed diagnostic bank, recover the staged incident tasking and submit the code it contains.

`ghost-bank.zip` carries three files plus a per-team live "bench" reachable as a raw TCP GDB RSP endpoint (`target remote <instance>`):

| File | What it is |
| --- | --- |
| `firmware.bin` | 956-byte AArch64 flat image, load/entry `0x00400000`, sha256 `f0b30ccf…1cdf47` |
| `firmware-load.txt` | Load manifest: MMIO register map (base `0x40000000`) and the exact RSP packet subset the bench stub implements |
| `capture.ndjson` | 8-record RSP capture of an *old* unlock handshake |

The framing hint is explicit: a recorded value is **not** guaranteed valid on a live bench, so the capture is a worked example for reversing the protocol, not a set of values to replay.

The manifest hands over the register map directly:

| Register | Address | Access |
| --- | --- | --- |
| CONTROL | `0x40000000` | r/w |
| PAGE | `0x40000008` | w |
| OFFSET | `0x40000010` | w |
| DATA | `0x40000018` | r |
| CIPHER_LEN | `0x4000001C` | r |
| CHALLENGE_LO | `0x40000020` | r |
| CHALLENGE_HI | `0x40000024` | r |
| KEY | `0x40000028` | w |
| STATUS | `0x40000030` | r |

The stub is all-stop, supports `QStartNoAckMode`, presents a stopped AArch64 thread (`g` is exactly 268 target-order bytes), exposes `qXfer:features:read` + `qXfer:memory-map:read`, and answers only `m`/`M` MMIO accesses (any other width/alignment returns `E01`). There is no flash programming and no file transfer, so the diagnostic bank must be read out *through* this register window.

**Approach / walkthrough**

1. **Reverse the unlock handshake.** `firmware.bin` is a flat AArch64 image, disassembled with capstone at base `0x400000`. The entry routine spins until `CONTROL == 0x41` (the host arming the bench), reads `CHALLENGE_LO/HI` into `ch = (hi<<32)|lo`, writes `PAGE = 7`, computes `k = mix(ch)` and writes it to `KEY` as two little-endian 32-bit halves (low word then high word), writes `CONTROL = 0x93`, and if `STATUS == 3` writes `CONTROL = 0x9c`. The only `bl` in entry, at `0x400060`, targets `mix` at `0x400120`.

2. **Recover `mix` (`0x400120`).** It is an xorshift-multiply finalizer:

   ```
   x ^= 0xa3b195354a39b70d
   x  = ((x >> 16) & 0x7fffffff) ^ ror(x, 47)
   x *= 0x64170d358aa115a1
   x ^= x >> 29
   x  = ror(x, 13)
   x *= 0x65931d9dfc2010db
   x ^= x >> 31
   ```

   The handshake only ever runs `mix` *forward* on a challenge the bench issues, so a faithful forward re-implementation is enough to answer any live challenge — there is no need to invert it.

3. **Check `mix` against the capture.** `capture.ndjson` arms with `M CONTROL=0x41`, reads challenge `0x0123456789abcdef` (`CHALLENGE_LO` bytes `efcdab89` = `0x89abcdef`, `CHALLENGE_HI` bytes `67452301` = `0x01234567`), sets `PAGE=7`, writes `KEY` as bytes `0c5eb2d1` then `d1fcc603`, writes `CONTROL=0x93`, reads `STATUS=3` — and ends there (no follow-up `0x9c`). Running the reversed function: `mix(0x0123456789abcdef) = 0x03c6fcd1d1b25e0c`, whose two LE32 halves are exactly `0c5eb2d1 d1fcc603`. The function is correct, and the capture is only valid for *its own* challenge — a live bench issues a fresh one, so replay is useless and the key must be recomputed from the live `ch`.

4. **Spot the second primitive.** The image also contains a textbook RFC 7539 ChaCha20 that the unlock path never calls: block function at `0x400174` (ten double rounds, quarter-round helper at `0x400090`, eight calls per block, invoked from the XOR routine at `0x400328`), keystream-XOR routine at `0x4002e0` (`key*, in*, out*, len`), block counter starting at 1 (`mov w13,#1` at `0x40030c`). The `"expand 32-byte k"` constant is at file offset `0x3a0`, and a 12-byte nonce string `"SEAL-V01\0\0\0\x01"` sits at file offset `0x3b0`. The 32-byte ChaCha key is **not** in the firmware, so it has to come out of the live bench as a result of a correct unlock. The solver logged that this ChaCha reproduces the RFC test vector (that self-test is not among the saved artifacts).

5. **Drive the live bench.** A small pure-Python RSP driver speaks only the manifest's subset (`qSupported`, `QStartNoAckMode`, then `m`/`M`). The `qXfer` target description and memory map matched the sha256 values published in `firmware-load.txt`, and the memory map showed RAM `0x40000000` length `0x100` — only the register window, nothing hidden there (the fetched XML was not saved, so this cannot be re-checked offline). Reading `STATUS` after each step reveals the state machine:

   ```
   0 idle
     -> M CONTROL=0x41  -> 1   (CHALLENGE populated)
     -> KEY lo/hi       -> 2
     -> M CONTROL=0x93  -> 3   (correct key; CHALLENGE cleared)
     -> M CONTROL=0x9c  -> 4   (host confirms; bank unsealed)
   ```

   A wrong KEY drives `STATUS` 2 → 0 on the `0x93` write. The live stub does **not** perform the firmware's auto-write of `0x9c`, so the host must issue `M CONTROL=0x9c` itself after seeing `STATUS==3`.

6. **DATA is paged, not state-dependent.** An early idea that `DATA` changed with unlock state was wrong — different states returned different first bytes (`b8` idle, `e6` state 3, `ef` state 4) only because the probes landed on different pages. The correction (recorded in `notes.md`) is that `DATA` is addressed by `PAGE` + `OFFSET`, each page a fixed 4 KiB region, `OFFSET` wrapping at `0x1000`, and that writing `PAGE` resets `STATUS` to 0. What looked like a "state-3 blob" was just the content of page 7.

7. **Recover the ChaCha key (page 7).** After a correct unlock (fresh challenge → `mix` → KEY, `0x93` → STATUS 3, host `0x9c` → STATUS 4), page 7 returns 32 non-zero bytes followed by zeros:

   ```
   efc2313872689147df6a06c9ab758e66a3b3d451cf2646f7b7192f88a9aee87a
   ```

8. **Locate the ciphertext (page 3).** Enumerating `PAGE` 0..1023 plus edge values (`65536`, `2147483647`, `4294967295`) and reading `CIPHER_LEN` for each, only **PAGE=3** reports a non-zero length: `CIPHER_LEN = 0x83` (131 bytes). Page 3's data is readable without unlocking — the seal gates only the *key* on page 7, not the ciphertext.

9. **Decrypt.** ChaCha20 (RFC 7539) with key = the 32 page-7 bytes, nonce = `SEAL-V01\x00\x00\x00\x01`, initial counter 1, over the 131-byte page-3 ciphertext yields the staged incident tasking (130 printable characters plus `\n`):

   ```
   TASKING//STAGED-EW//RELAY-BENCH//AUTHKEY CSCTF{MLwO5fGUzg03SjGJ1anWVEUc}//JAM PROFILE: 435.125MHz; TRIGGER: PRIMARY-LINK LOSS//END
   ```

Batches of more than ~150 pipelined RSP packets dropped the TCP session, so batches were kept to 40 packets or fewer.

**Why it works**

The seal protects only the key page, and the key the bench will accept is a deterministic function of the challenge it issues. With `mix` recovered from the firmware, any live challenge can be answered, so the capture exists only to confirm the reversed function — replaying its recorded KEY satisfies only its own recorded challenge. The ciphertext was never protected, and both the cipher and its nonce are in the image, so once page 7 yields the key the decrypt is mechanical. Two independently reversed primitives (`mix` and ChaCha20) chain across the live register interface to produce the flag. The capture is, in effect, a decoy for a naive replay attacker.

**Validation / reproduction**

- `mix` reproduces the captured KEY writes exactly: `mix(0x0123456789abcdef) = 0x03c6fcd1d1b25e0c` → LE halves `0c5eb2d1 d1fcc603`.
- The saved live session (`solve/live/dumps.json`) has challenge `ch = 0x3d1e53754ef16636` and sent key `0xaebba6d67c398867`; `mix(ch)` equals that value, confirming the live unlock used the reversed function. Its unlocked page-7 dump (320 bytes) is the 32 key bytes followed by zeros.
- `firmware.bin[0x3b0:0x3bc]` = `b"SEAL-V01\x00\x00\x00\x01"`; `sha256(firmware.bin)` = `f0b30ccf52d984559b144ca812ef77eedebfe36fdbd8092343ff11b66f1cdf47`, matching `firmware-load.txt` and the capture header.
- A from-scratch RFC 7539 ChaCha20 (saved key, nonce `SEAL-V01\x00\x00\x00\x01`, counter 1) over `solve/live/page3.hex` gives the tasking string above. `page3.hex` holds 139 dumped bytes; the 8 past `CIPHER_LEN` decrypt to noise. The 24-character flag body matches the challenge's `flag_mode=random`, `random_flag_length=24`. The flag was accepted on the first submission (`tried.json`: 1 attempt, `correct`).
- `solve/live/pages.json` has 1030 PAGE probes; only page 3 returns `CIPHER_LEN=0x83`.

Reproduction: unzip; disassemble `firmware.bin` as AArch64 flat @ `0x400000`; recover `mix` and the ChaCha20 routines; confirm `mix` against `capture.ndjson`; against your own live bench, arm (`CONTROL=0x41`), read the live `CHALLENGE`, write `KEY = mix(ch)` with `PAGE=7`, `CONTROL=0x93`, then `CONTROL=0x9c`; read 32 key bytes from page 7; set `PAGE=3`, read `CIPHER_LEN` (131) and the ciphertext; ChaCha20-decrypt and read the flag. Saved drivers: `solve/unlock_dump_key.py`, `solve/page_enum.py`, `solve/dump_page3.py`.

Gotcha: pipelining more than ~150 RSP packets per TCP batch drops the session — keep batches ≤ 40. All live work was against our own per-team bench only, using the documented RSP subset; no scanning, flooding, or off-target requests. The one codex hand-off tried here failed to start ("Daybreak unavailable") and contributed nothing; `codex_result.md` is empty.
