# The Signet

> Crypto · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}`

**Challenge**

A dispatch signet issued six orders during a documented entropy incident. An adversary may have read the sealed standing order and used it to divert defence logistics at a canal crossing. Inspect `sealed-orders.der` and `case-note.txt` and recover the complete `CSCTF{...}` order token.

- `case-note.txt`, 2441 bytes, SHA-256 `1a4bb290d7615010f4d47842166c84281f90c735f081ac40d7b94e27c5352839`.
- `sealed-orders.der`, 1042 bytes, SHA-256 `4f203322b6382224def50cb4075153ed659619c89a544eaf28a8183015eb805b`.

**Tools used**

`openssl asn1parse` to map the DER, Python (stdlib) for the key recovery, and `cryptography` for HKDF and AES-256-GCM.

**Approach / walkthrough**

1. **Map and authenticate the bundle.** `case-note.txt` describes `sealed-orders.der` as a `SignetBundle`: a version, the signer's secp256k1 SPKI, six signed orders (sequence 0–5, each with its exact message bytes and an ECDSA-SHA-256 `(r, s)` stored raw), and one seal (salt, 12-byte nonce, ciphertext, 16-byte tag). `openssl asn1parse -inform DER -in sealed-orders.der -i` shows the layout; some `s` values are 33-byte INTEGERs (a leading zero byte), so they sit above `n/2`, exactly as the note says the raw values would. The SPKI is the SEQUENCE at offset 7, so cut it out and hash it:

   ```sh
   openssl asn1parse -inform DER -in sealed-orders.der -strparse 7 -noout -out out/spki.der
   openssl dgst -sha256 -r out/spki.der
   # 1c6b38a86c3ff8b1d295e02b884c457da537767b5fdf063cf6d7d733b683a6b3
   ```

   This matches the SPKI fingerprint recorded in the note's pre-incident register, so the public key in the bundle is the real signer's.

2. **Model the nonces.** The note's key paragraph: "The entropy sampler stopped. Each consecutive signing operation consumed the next temporary scalar-register value … the same additive stride modulo the curve order." The "temporary scalar" is the ECDSA nonce, so with no skipped operations `k_i = k₀ + i·t (mod n)` for unknown start `k₀` and stride `t`. Each signature gives

   ```
   k_i = a_i + b_i·d,   with a_i = z_i/s_i,  b_i = r_i/s_i,   z_i = SHA-256(message_i) mod n
   ```

3. **Cancel the unknowns with a second difference.** Because the nonces step by a constant, any three consecutive orders satisfy `k_i − 2·k_{i+1} + k_{i+2} = 0`, which removes both `k₀` and `t`. Substituting `k_i = a_i + b_i·d` leaves one linear equation `A + B·d = 0`, with `A` and `B` the second differences of `a` and `b`, so `d = −A/B mod n`.

   ```python
   for i in range(len(records) - 2):
       A = a[i] - 2*a[i+1] + a[i+2]
       B = b[i] - 2*b[i+1] + b[i+2]
       guesses.append(-A * pow(B, -1, N) % N)
   assert len(set(guesses)) == 1          # all triples agree
   ```

   Running it:

   ```
   orders 0..2: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   orders 1..3: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   orders 2..4: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   orders 3..5: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   d*G is the signer key: True
   ```

   All four independent triples give the same `d`, and `d·G` equals the SPKI point.

4. **Open the seal.** The note gives the recipe: `IKM = I2OSP(d, 32)`, `key = HKDF-SHA-256(IKM, salt=seal.salt, info="CSCTF26/TheSignet/v1/standing-order", L=32)`, then AES-256-GCM with the stored 12-byte nonce and 16-byte tag, empty AAD:

   ```python
   ikm = d.to_bytes(32, "big")
   key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
              info=b"CSCTF26/TheSignet/v1/standing-order").derive(ikm)
   plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, b"")   # raises if the tag fails
   # CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}
   ```

**Why it works**

An ECDSA signature binds the nonce and the private key in one linear relation, so the key stays hidden only while every nonce is fresh and independent. A stuck sampler that just adds a constant stride turns the six nonces into an arithmetic progression, leaving only three unknowns (`d`, `k₀`, `t`) against six equations; a second difference of three consecutive nonces cancels `k₀` and `t` and leaves a single linear equation for `d`. Keeping `s` raw matters: flipping one `s` to `n − s` would negate that nonce and break the progression, which is why the note stresses the raw values. Once `d` is known, the seal is just the documented HKDF/GCM recipe, and the GCM tag verifying proves the key was right.

**Validation / reproduction**

The six signatures give four independent triples (0–2, 1–3, 2–4, 3–5), all producing the same `d`; that `d` satisfies `d·G ==` the SPKI point, and the SPKI itself matches the note's pre-incident fingerprint. The AES-GCM tag verifies, which only happens with the correct key. The token was accepted on the first submission.

Reproduction summary: `openssl asn1parse` the DER, carve and hash the SPKI, parse the six `(message, r, s)` records and the seal fields; compute `a_i, b_i`; solve `d` from each second-difference triple and confirm they agree and that `d·G ==` the signer key; derive the HKDF key from `I2OSP(d,32)` and AES-256-GCM-decrypt the seal.
