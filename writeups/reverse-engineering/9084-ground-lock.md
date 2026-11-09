# Ground Lock

> Reverse engineering · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{HALCYON_1B5FC6D72036689A}
```

The binary prints the token with `CSCTF{%.*s}`, so the flag is simply the accepted 24-byte service code wrapped in `CSCTF{}`; the recovered code is `HALCYON_1B5FC6D72036689A`.

**Challenge**

> A response team recovered the ground-maintenance utility used to service the GRIFFON-FC drones an Ash Army proxy flies over the Operation Dawn theatre. The accepted service code is needed before equipment handover. Recover that code. This is a constructed software case: the attachment is a Linux utility, not flight-controller firmware or a hardware dump, and static analysis is enough.
>
> Submit `CSCTF{<service-code>}` with the exact 24 code bytes and case.

Attachment: `fcunlock`, a statically linked, stripped x86-64 ELF (682,600 bytes, sha256 `9634a7c4c4769a21eb921125a3d1b0ef560e3f4ed0202efa860861f0d2922399`) that takes the candidate service code as `argv[1]`.

**Approach / walkthrough**

1. **Recon.** `file fcunlock` → `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, stripped`. The symbol table is gone, but the brief promises static analysis suffices, so there is no need to run it until the end.

2. **`main` (`0x4016da`).** It requires `argc == 2` (else `usage: %s <service-code>`), then `strlen(argv[1]) == 24` (the `strlen` call is at `0x4010c8`; else `ACCESS DENIED`). It packs the 24-byte input into **three 8-byte little-endian qwords** (byte `j` of block `i` shifted left by `8*j`).

   The packing is the ordinary little-endian load of each 8-byte block: block 0 is bytes `argv[1][0..7]` read as a qword, block 1 is `[8..15]`, block 2 is `[16..23]`. So recovering the three qwords and writing them back out little-endian reconstructs the input byte-for-byte — there is no permutation or interleaving between blocks to undo.

3. **The check function (`0x401655`).** Each qword passes through this routine, whose body is the MurmurHash3 64-bit finalizer `fmix64`, recognizable from its two magic constants:

   ```c
   uint64_t fmix64(uint64_t x) {
       x ^= x >> 33;
       x *= 0xff51afd7ed558ccdULL;
       x ^= x >> 33;
       x *= 0xc4ceb9fe1a85ec53ULL;
       x ^= x >> 33;
       return x;
   }
   ```

4. **The target table.** Result `i` is compared against the slot at `[0x479020 + (i+4)*8]`, i.e. a table at VA `0x479040` (file offset `0x79040`). Every slot is checked (a mismatch clears a flag rather than breaking out), then the flag decides the outcome:

   | slot | target value |
   | --- | --- |
   | 0 | `0x8bfd351846ffb86b` |
   | 1 | `0x3ff3fd892aa7e3b2` |
   | 2 | `0xf61e79e7e639e0d2` |

   The comparison loop is written so that every slot is visited regardless of an early mismatch: each qword's hash is tested against its target, and a failure clears a single success flag rather than branching straight to the deny path. Only after all three are checked does that flag select between the deny and release branches. That structure does not change the attack — all three hashes must match — but it is worth noting because it means there is no short-circuit to exploit and no per-slot timing signal; the code is purely a three-way equality gate.

   On success the utility prints `GRIFFON-FC ground-maintenance interlock released.` and `Maintenance token: CSCTF{%.*s}`, where `%.*s` is the 24-byte input itself (the two format strings live at `0x479080` and `0x4790b8`). Nothing else is hidden in the binary — the token is literally the code you supplied. The constants and targets are confirmed present in the file at the stated offsets:

   ```
   $ python3 -c 'import struct;d=open("fcunlock","rb").read()
   [print(hex(q),hex(d.find(struct.pack("<Q",q)))) for q in
   (0x8bfd351846ffb86b,0x3ff3fd892aa7e3b2,0xf61e79e7e639e0d2)]'
   0x8bfd351846ffb86b 0x79040
   0x3ff3fd892aa7e3b2 0x79048
   0xf61e79e7e639e0d2 0x79050
   ```

   Both multiply constants `0xff51afd7ed558ccd` and `0xc4ceb9fe1a85ec53` are likewise present in the file.

5. **Invert `fmix64`.** It is a bijection on 64-bit words, so there is no search: undo the steps in reverse. Each `x ^= x >> 33` is its own inverse because a right shift by ≥ 32 moves every bit past the word midpoint, so applying the same xorshift twice cancels (the high 31 bits are untouched the first time and restore the low bits the second). Each multiply by an odd constant is a unit mod 2^64 and is undone by multiplying by its modular inverse, which Python computes directly as `pow(m, -1, 1<<64)` — `0xff51afd7ed558ccd` and `0xc4ceb9fe1a85ec53` are both odd, so both inverses exist. Reversing the five steps (xorshift, inverse-multiply by C2, xorshift, inverse-multiply by C1, xorshift) recovers the unique preimage of each target.

   ```python
   import struct
   M = (1 << 64) - 1
   def inv_xs33(x): return (x ^ (x >> 33)) & M
   def inv_mul(x, m): return (x * pow(m, -1, 1 << 64)) & M
   def inv_fmix64(h):
       h = inv_xs33(h)
       h = inv_mul(h, 0xc4ceb9fe1a85ec53)
       h = inv_xs33(h)
       h = inv_mul(h, 0xff51afd7ed558ccd)
       return inv_xs33(h)
   targets = [0x8bfd351846ffb86b, 0x3ff3fd892aa7e3b2, 0xf61e79e7e639e0d2]
   code = b''.join(struct.pack('<Q', inv_fmix64(t)) for t in targets)
   print(code.decode())          # HALCYON_1B5FC6D72036689A
   ```

   The three little-endian preimages concatenate to `HALCYON_1B5FC6D72036689A` — exactly 24 printable ASCII bytes. Running each recovered qword forward through `fmix64` returns all three targets, confirming the inversion before any execution.

**Why it works**

`fmix64` is a permutation of the 64-bit word space. An xorshift by 33 (≥ half the word width) is self-inverse, and multiplying by an odd constant is invertible mod 2^64. Each stored hash therefore has exactly one preimage, computable directly with no brute force. Storing the hash of the secret protects nothing when the hash is a bijection — the "check" is reversible, so the gate hands the answer to anyone who recognizes the finalizer.

**Validation / reproduction**

Running the recovered qwords forward through `fmix64` returns all three targets. Running the binary with the 24-byte code inside the network-less Docker sandbox (`csctf-pwn:1`, `--network none` — the untrusted artifact is never detonated on the host) printed:

```
GRIFFON-FC ground-maintenance interlock released.
Maintenance token: CSCTF{HALCYON_1B5FC6D72036689A}
```

Reproduction: disassemble `fcunlock` at base `0x400000`; identify the `argc/strlen==24` gate in `main`; recognize `fmix64` from its constants; read the three targets at file offset `0x79040`; invert `fmix64` on each and pack the preimages little-endian; the 24 bytes are the service code, and the flag is `CSCTF{` + that code + `}`.

Gotchas and notes: the point value is dynamic, but the flag is static — only the score decays with solves. `tried.json` lists four submissions of the same value: the first three came back `ratelimited` (the team-wide CTFd rate limit, never a wrong-answer verdict), and the fourth, unchanged, was accepted about 5.6 minutes after the first — no guessing or sweeping. A single 5-point hint existed on the platform and was **not** purchased. A codex hand-off was attempted and failed to start (model/Daybreak incompatibility, `.codex_log.jsonl`); the solve was done in-session.
