# Rollback Pair

> Crypto · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}`

**Challenge**

An emergency logistics signing service came back up after a bad application-state restore. Someone exported eight signed dispatch records and the signing public key for review. Work out whether the signing key was exposed and, if so, recover the signing scalar. The export is a constructed training artifact with genuine ECDSA signatures, all work offline.

- `signing-export.json`, 4248 bytes, SHA-256 `96b7f2e330bf904e45549e2d24da4d2866569520aa39b9576aaa0124097bda28`.
- Submit the scalar as `CSCTF{` + exactly 64 lowercase hex characters + `}`.

**Tools used**

Python 3 standard library only (needs `pow(x, -1, n)`, so 3.8+). The secp256k1 point arithmetic was written inline.

**Approach / walkthrough**

1. **Read the self-describing format.** The export states its own scheme: ECDSA on **secp256k1**, hash **SHA-256** over the base64-decoded message bytes, signature stored as `r || s` (32 bytes each, big-endian, **raw `s` with no low-s normalization**). The `scenario` field is the tell: signing "resumed from a faulty application nonce-state snapshot" — the nonce generator was rolled back, so a nonce may have been used twice.

2. **Group by `r`.** In ECDSA `r = (k·G).x mod n` depends only on the nonce `k`, so two records with the same `r` reused the nonce. Decoding all eight and bucketing by `r`:

   ```
   R-6103  r=821f300799a645e2...  {"cargo":"insulin cold boxes",...
   R-6107  r=821f300799a645e2...  {"cargo":"medical radio packs",...
   REPEATED r=821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a in R-6103, R-6107
   ```

   R-6103 and R-6107 sign different messages but share `r`.

3. **Sanity-check the export first.** Confirm the public key `Q` lies on the curve and that all eight signatures verify under it with `z = SHA-256(message)`. That pins the hash and byte-order interpretation before any attack.

4. **Solve for `k`, then `d`.** From `s_i = k⁻¹(z_i + r·d) mod n`, subtracting the two equations removes `d`:

   ```
   k = (z₁ − z₂) / (s₁ − s₂)        (mod n)
   d = (s₁·k − z₁) / r              (mod n)
   ```

   Because `s` is stored raw and `(−k)·G` has the same x-coordinate as `k·G`, a normalizing signer could have stored `−s` for one of the two; so the script tries both `s₁ − s₂` and `s₁ + s₂` and keeps only the result that checks out. The core:

   ```python
   pair = next((a, b) for i, a in enumerate(recs) for b in recs[i+1:] if a[2] == b[2])
   (id1, z1, r, s1), (id2, z2, _, s2) = pair
   for sign in (1, -1):
       k = (z1 - z2) * pow(s1 - sign*s2, -1, n) % n
       d = (s1 * k - z1) * pow(r, -1, n) % n
       if mul(d, G) == Q:            # d·G reproduces the exported public key
           print(f"CSCTF{{{d:064x}}}"); break
   ```

   Expected output:

   ```
   all 8 signatures verify under the exported key: True
   pair: R-6103 / R-6107  r=821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a
   s1 - s2: k*G.x == r -> True, d*G == public_key -> True
   k = d12e52720675d17d57136b691ef6abb6fa90116527022ef1a76be7503b0c2049
   d = 3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1
   ```

   The plain `s₁ − s₂` case works here.

5. **Format.** The flag is the scalar as 64 lowercase hex digits inside `CSCTF{}`.

**Why it works**

ECDSA's private key is protected only as long as each nonce is secret and unique. Restoring the nonce generator from an old snapshot replays nonces that were already used. Two signatures made with the same `k` give two linear equations in the two unknowns `k` and `d` mod the group order `n`, which plain modular algebra solves. The repeated `r` advertises the reuse directly.

**Validation / reproduction**

Two independent checks: `(k·G).x mod n == r`, and — decisively — `d·G == Q`, the exported public key. A scalar that reproduces the public key is the signing key, not an artifact of a wrong hash, byte order, or `s` sign. It was accepted on the first submission.

Reproduction summary: read the format from the JSON; decode all eight `r||s` and group by `r`; verify every signature under `Q`; take the R-6103/R-6107 pair; compute `k` and `d` (trying both `s` signs); confirm `d·G == Q`; emit `CSCTF{<d as 64 hex>}`.
