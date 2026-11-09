# Watchword

> Crypto · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}`

**Challenge**

A SABRELINK field authentication unit tags every dispatch with AES-128-GCM. A firmware fault made it reuse one message nonce across a run of dispatches. We intercepted three authenticated dispatches under that nonce plus one sealed master order, whose text is sealed with AES-128-CTR under the link's per-nonce authentication value `S = E_K(J0)`. Recover the master order.

- `watchword.zip`, 1207 bytes, SHA-256 `1e081c278b16e265391a8c6cf68cf2787ff2e54aae574b6c2d1cf0cada02647e`. Unpacks to `README.txt` and `intercepts.json`.

**Tools used**

Standard-library Python for the GF(2¹²⁸) arithmetic and polynomial GCD; `openssl enc -aes-128-ctr` for the unseal.

**Approach / walkthrough**

`intercepts.json` has one 96-bit nonce (`8f7ce996b767134353fe1145`), three AES-128-GCM dispatches with empty AAD (each: known plaintext, ciphertext, 16-byte tag), and a 57-byte `sealed_master_order_ctr_hex`. All three tags were produced under the single reused nonce. Each dispatch's ciphertext is at most 16 bytes.

1. **Write each tag as a polynomial in `H`.** With a 96-bit nonce, GCM sets `J0 = nonce || 0x00000001` and `tag = E_K(J0) ⊕ GHASH_H(A, C)`, where `H = E_K(0¹²⁸)` is the authentication key and AAD is empty. GHASH zero-pads `C` into 16-byte blocks, appends a length block `L = 0⁶⁴ || [8·len(C)]₆₄`, and folds everything through `GF(2)[x]/(x¹²⁸ + x⁷ + x² + x + 1)`. Each dispatch here has `n = 1` ciphertext block, so

   ```
   f_i(X) = C_i·X² ⊕ L_i·X ⊕ tag_i,   and   f_i(H) = E_K(J0) = S  for all three
   ```

   because the nonce — and therefore `J0` — is shared.

2. **Eliminate `S`.** Subtraction is XOR in characteristic 2, so `H` is a root of both `f₀ ⊕ f₁` and `f₀ ⊕ f₂`. Two polynomials sharing a root have a non-trivial GCD; with two independent differences the GCD came out degree 1, `X ⊕ H`, so `H` is pinned uniquely (not shortlisted):

   ```python
   g = pgcd(padd(fs[0], fs[1]), padd(fs[0], fs[2]))
   g = [gmul(c, ginv(g[-1])) for c in g]   # make monic -> [H, 1]
   assert len(g) == 2
   H = g[0]
   # H    = 730426f0d054fc7539d26145168be28a
   ```

3. **Recover the mask.** `S = tag₀ ⊕ C₀·H² ⊕ L₀·H = f₀(H)`:

   ```python
   mask = peval(fs[0], H)
   assert all(peval(f, H) == mask for f in fs)   # all three agree
   # mask = 66b18782c578d8b27ec249a6298dfeb2
   ```

   All three dispatches landing on the same mask at this `H` is an independent check — a wrong `H` would make them disagree.

4. **Unseal the master order.** The README seals the order with AES-128-CTR, IV all-zero (128-bit counter from zero), under key `S`:

   ```sh
   python3 -c "import json; open('out/sealed.bin','wb').write(bytes.fromhex(json.load(open('watchword/intercepts.json'))['sealed_master_order_ctr_hex']))"
   openssl enc -d -aes-128-ctr -K 66b18782c578d8b27ec249a6298dfeb2 \
     -iv 00000000000000000000000000000000 -in out/sealed.bin
   # CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}
   ```

**Why it works**

GCM's counter mode never repeats a keystream block, but its authenticity rests on one fixed field element `H = E_K(0)` and one mask `E_K(J0)` per nonce, and every tag is a known polynomial in `H` plus that mask. Reusing the nonce makes the mask common to all three dispatches, so the XOR of any two tag-polynomials has `H` as a root, and the GCD of two such differences pins `H` exactly. This is Joux's "forbidden attack" — the key `K` is never needed; `H = E_K(0)` stays one-way, but any single tag yields the mask once `H` is known. The device then reused that mask as an AES-CTR key for the order, so the order was only ever as secret as the tags transmitted beside it.

**Validation / reproduction**

The GCD being linear pins `H` exactly rather than narrowing to a shortlist, and all three independent dispatches agree on the mask at that `H` (a wrong `H` would make them disagree). The CTR output is clean printable text in `CSCTF{...}` format, accepted on the first submission.

Reproduction summary: unzip, verify the SHA-256; build each `f_i(X) = C_i X² ⊕ L_i X ⊕ tag_i` over GF(2¹²⁸); take the GCD of two tag-differences to recover `H`; evaluate `f₀(H)` for the mask and confirm all three agree; AES-128-CTR-decrypt the sealed bytes with the mask as key and an all-zero IV.
