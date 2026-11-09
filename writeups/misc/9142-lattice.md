# lattice

> Misc · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{Ia0OI44KTJzr9lcWPNAkpFVB}`

(Per-team `flag_mode: random`; the value above is the one the assigned vault returned.)

**Challenge**

> During Operation Dawn, Ash Army couriers sealed a passphrase inside a home-built block scrambler, then lost the key to their own vault. A coalition team recovered the scrambler's source and the sealed bytes it produced, but nothing that runs it backward. The vault door at the audit service opens only for the original passphrase, spoken exactly once. Read the source, recover the passphrase offline, and speak it to the vault.

A per-team TCP container (port 9999) plus one attachment, `lattice.tar.gz`, holding a single file `lattice.py`. It contains the **forward** cipher only (`encrypt_block`, `encrypt`, no decrypt routine), `TARGET` — a 48-byte ciphertext equal to `encrypt(SECRET)` — and a `check(guess)` helper. The whole challenge is reading the cipher and running it backward; tooling is Python only.

**The cipher.** An 8-byte-block toy SPN in ECB mode with PKCS#7 padding, 16 rounds:

| Component | Detail |
| --- | --- |
| Key mixing | even rounds `s[i] = (s[i] + rk[i]) mod 256`; odd rounds `s[i] ^= rk[i]` |
| S-box | a permutation of 0..255 built by Fisher–Yates driven by a custom 32-bit LCG (`s = s*0x19660D + 0x3C6EF35F mod 2³²`, seed `0x1A2B3C4D`) |
| Round keys | 16×8 bytes, the low byte of each output of the same LCG with seed `0xCAFEB0BA` |
| Diffusion | the block packed big-endian into a 64-bit integer and rotated left by `(7r + 11) % 63 + 1` bits |

**Approach / walkthrough**

1. **Read the cipher.** Nothing in it is secret: the "key" is two hard-coded LCG seeds, so the S-box and all 16 round keys can be rebuilt exactly from the source. Every layer is also a bijection — modular add ↔ modular subtract, XOR ↔ XOR, the S-box is a permutation (so it has an inverse table), and a 64-bit left rotation ↔ a right rotation by the same amount. The name "lattice" and the "preimage" wording are flavor, not lattice reduction.

2. **Invert each round.** Decryption is mechanical: run rounds 15 down to 0, and in each undo the rotation, then the S-box, then the key mixing. `solve_inverse.py` rebuilds the S-box and round keys from the same seeds and decrypts:

   ```python
   def dec(b):
       s = list(b)
       for r in range(15, -1, -1):
           x = rotr(int.from_bytes(bytes(s), 'big'), rot(r) & 63); s = list(x.to_bytes(8, 'big'))
           s = [inv[c] for c in s]
           s = [(s[i] - RK[r][i]) & 255 if r % 2 == 0 else s[i] ^ RK[r][i] for i in range(8)]
       return bytes(s)
   ```

3. **Recover the passphrase.** Decrypting the six blocks of `TARGET` gives:

   ```
   b'unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60\x04\x04\x04\x04'
   ```

   The trailing four `0x04` bytes are valid PKCS#7 padding, confirming block alignment. Stripping them leaves the passphrase `unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60`.

4. **Speak it to the vault.** The passphrase is not the flag — "spoken exactly once" means the vault service returns the team's flag in exchange for it. `fire.py` opens one TCP connection to the team's own 9142 container, sends the passphrase followed by a newline, and reads the reply:

   ```
   The lattice yields: CSCTF{Ia0OI44KTJzr9lcWPNAkpFVB}
   ```

**Why it works**

The cipher ships its own key material as constants (both the S-box and the round keys derive from fixed LCG seeds), so it is effectively a fixed, keyless permutation that anyone with the source can invert. Each round is a composition of a bijective S-box, a rotation, and an add/XOR with a known key — all individually invertible — so the full 16-round transform inverts exactly in reverse order. No cryptanalysis is needed.

**Validation / reproduction**

The decrypted plaintext ended in correct PKCS#7 padding, and re-encrypting the recovered passphrase with a forward reimplementation reproduced `TARGET` exactly — an independent round-trip check done entirely offline, which proves the recovery before anything is sent. The solve script is a self-contained reimplementation, so the untrusted `lattice.py` never has to be run:

```
python3 -I workspace/9142-lattice/solve_inverse.py
# b'unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60\x04\x04\x04\x04'
# b'unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60'
# True
```

The service then accepted the passphrase and returned the per-team flag (CTFd `flag_mode: random`, 24 characters, which did not rotate). One submission was accepted as `correct` at 2026-11-07 13:07:56 UTC, about eight minutes after Wave 2 opened. All traffic went only to the team's assigned container: one connection, one line sent.
