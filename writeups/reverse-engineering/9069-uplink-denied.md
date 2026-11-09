# Uplink Denied

> Reverse engineering · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{cau_reset_09ff4472cbe8e0}`

The brief asks you to submit `CSCTF{<key>}` with `<key>` replaced by the exact 24-byte recovery key,
keeping case and adding no whitespace. The recovered key is `cau_reset_09ff4472cbe8e0`, so the flag is the
value above. It is deterministic — the key is the unique preimage of three constants baked into the
binary, not a per-team value — so the same key is recovered on every run.

**Challenge**

A hostile-state operation disabled the Meridian-class command-authentication unit (CAU) aboard the
fictional DORVIX-7 satellite; the CAU now rejects every operator command. Recover the 24-byte recovery
key it accepts. Static analysis is enough, and the binary is marked untrusted. Attachment: `cau_verify`,
a Linux x86-64 ELF, 682,600 bytes, SHA-256
`19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c`.

**Tools used**

GNU `objdump` and Python (plus `sha256sum`/`file` to confirm the download). The binary was never run —
everything is static disassembly, matching the "untrusted" note.

**Approach**

1. **Set up and identify.** Drop `cau_verify` into an empty folder and confirm the download against the
   brief: `sha256sum cau_verify` must print
   `19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c`. `file cau_verify` reports *ELF
   64-bit LSB executable, x86-64, statically linked, stripped*. Static glibc is compiled in and there are
   no symbols, so there is no `main` to look up by name. `objdump -f` gives entry `0x401650` — glibc's
   `_start`. Nothing below executes the binary; the brief's "untrusted" note is honored by staying purely
   static.

2. **Find `main`.** `_start` passes the address of `main` to `__libc_start_main` in `%rdi`:

   ```
   401664: mov $0x4014f0,%rdi
   40166b: addr32 call 0x4028f0        # __libc_start_main
   ```

   So `main` is at `0x4014f0`, and since `_start` immediately follows it, that also marks where `main`
   ends. Disassemble the range `0x4014f0..0x401650`.

3. **Read the check.** `main` first calls a `.plt` stub (`0x4010c8`) on `argv[1]` and compares the result
   with `0x18` — that is `strlen`, so the key must be exactly 24 bytes. A helper at `0x401780` is just
   `mov (%rdi),%rax; ret`: it reads 8 key bytes as one little-endian `u64`. Each 8-byte block `x` then
   goes through five steps, with `%rsi = C1 = 0x9df50ad53e8f1c7b` and `%rcx = C2 = 0xc17a4b92d6e30f55`
   (`shr $0x21` is a shift by 33):

   ```c
   x ^= x >> 33;
   x *= C1;
   x ^= x >> 33;
   x *= C2;
   x ^= x >> 33;
   ```

   This is the shape of MurmurHash3's `fmix64` finalizer with custom multipliers. The three block hashes
   are compared against three stored 64-bit constants, and `ACCESS GRANTED` prints only if all three
   match. Two tiny helpers confirm the I/O: `0x401780` is `mov (%rdi),%rax; ret` (load 8 key bytes as a
   little-endian `u64`), and `0x401790(fd, s)` takes `strlen(s)` and tail-jumps into glibc's `write` to
   print a string. Dumping `.rodata` around `0x479000` shows what those pointers reference:

   ```sh
   objdump -s -j .rodata --start-address=0x479000 --stop-address=0x479070 cau_verify
   # 479000 01000200 00000000 4d657269 6469616e  ........Meridian
   # 479010 2d636c61 73732043 4155202f 2f207265  -class CAU // re
   # 479020 636f7665 72792061 75746865 6e746963  covery authentic
   # 479030 6174696f 6e0a0000 75736167 653a2063  ation...usage: c
   # 479040 61755f76 65726966 79203c72 65636f76  au_verify <recov
   # 479050 6572792d 6b65793e 0a004445 4e494544  ery-key>..DENIED
   # 479060 0a004143 43455353 20475241 4e544544  ..ACCESS GRANTED
   ```

   `0x479008` and `0x479038` are the banner and the `usage: cau_verify <recovery-key>` line, `0x47905a`
   is `DENIED` and `0x479062` is `ACCESS GRANTED` — which nails down that the success path is gated
   solely on the three hash comparisons.

4. **Pair each block with its target.** The compiler interleaved blocks 0 and 1, so the pairing has to be
   read from the registers, not from a decompiler (Ghidra folds `main` into a bogus function at
   `0x4012aa` and drops block 0's first three steps). Block 0 is loaded at `0x401559` and carried in
   `%rdx` across the second load call, while block 1 is mixed in `%rax`; block 2 runs straight afterward:

   | Block | Key bytes | Ends in | Must equal | Compared at |
   |---|---|---|---|---|
   | 0 | `key[0:8]`   | `%rdx` | `0xd8dba78e270f595d` | `0x4015ba` |
   | 1 | `key[8:16]`  | `%rax` | `0x25d4e9834acb3349` | `0x4015d2` |
   | 2 | `key[16:24]` | `%rax` | `0x976a0bc7e24f7338` | `0x401610` |

5. **Invert the mix.** Every step is reversible. `x ^ (x >> 33)` is its own inverse on 64-bit values
   (applying it twice cancels the shifted term, and `x >> 66` is 0). `C1` and `C2` are odd, so they are
   invertible mod 2^64 via `pow(C, -1, 1 << 64)`. Run the steps backward on each target, pack the three
   results little-endian, and join:

   ```python
   MASK = (1 << 64) - 1
   C1 = 0x9df50ad53e8f1c7b
   C2 = 0xc17a4b92d6e30f55
   TARGETS = [0xd8dba78e270f595d, 0x25d4e9834acb3349, 0x976a0bc7e24f7338]
   xorshift = lambda x: x ^ (x >> 33)

   def mix(x):
       x = xorshift(x) * C1 & MASK
       x = xorshift(x) * C2 & MASK
       return xorshift(x)

   def unmix(h):
       x = xorshift(h) * pow(C2, -1, 1 << 64) & MASK
       x = xorshift(x) * pow(C1, -1, 1 << 64) & MASK
       return xorshift(x)

   blocks = [unmix(t) for t in TARGETS]
   assert [mix(b) for b in blocks] == TARGETS
   key = b"".join(b.to_bytes(8, "little") for b in blocks)
   print(key, len(key))                       # b'cau_reset_09ff4472cbe8e0' 24
   print("CSCTF{" + key.decode() + "}")        # CSCTF{cau_reset_09ff4472cbe8e0}
   ```

   The recovered 24 bytes `cau_reset_09ff4472cbe8e0` are all printable, which is the sanity check that the
   pairing was read correctly. The `assert` re-runs the forward mix to confirm the three preimages land
   back on the stored constants.

**Why it works**

The CAU never stores the key; it stores a 64-bit hash of each 8-byte block and compares against that. The
hash — an `fmix64`-style finalizer — is built entirely from invertible operations: an xorshift by at
least half the word width undoes itself, and multiplying by an odd constant is a bijection mod 2^64. The
mix is therefore a permutation of 64-bit values, so each target has exactly one preimage and it can be
computed directly. The only real work is reading the interleaved assembly carefully enough to pair each
block with its constant; a decompiler mis-renders it.

**Validation / reproduction**

The script pushes the three recovered blocks forward through the binary's own mix and asserts they equal
the three stored constants, and the key is exactly 24 printable bytes — both strong signals that the
answer is right without ever executing the untrusted binary. The flag was accepted on the first
submission.

Reproduction summary: confirm the SHA-256, locate `main` via `_start`'s `mov $0x4014f0,%rdi`, read the
`strlen == 24` gate and the per-block `fmix64`, follow `%rdx`/`%rax` to pair each block with its target
constant, then invert (xorshift self-inverse, odd-multiplier modular inverse) and pack little-endian.
Gotcha: trust the disassembly over the decompiler here — the interleaved block 0 is where decompilers
drop steps.
