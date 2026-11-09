# Signing Authority

> Crypto · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{PBzvsLOrJDAG5kqOAMiT9NXC}`

**Challenge**

Torven Ordnance's code-signing service promotes the master arming image only on a valid ECDSA signature (secp256k1) over one exact message — and it will not sign that message for you. But it publishes signed release receipts. Use them to authorize the master image yourself. The API is self-describing at `GET /schema`, and all work is confined to the assigned instance.

There are no files. The per-team container (`connection_type: web`, port 8000, reached here as `<instance>`) exposes:

- `GET /schema` — ECDSA on secp256k1, with `z = sha256(msg) mod n`.
- `POST /authorize` — promotes the master image on a signature over the exact `master_message_hex`, with canonical low-`s`.
- `GET /pubkey` — the service public key `Q = d·G`.
- `GET /receipts` — a list of signed release receipts.

**Tools used**

A short hand-written pure-Python secp256k1 ECDSA script (`sa.py`, in that session's scratchpad; not kept in the repo).

**Approach / walkthrough**

1. **Pull the receipts (`GET /receipts`).** Two of the published receipts carry the **same `r`**. Since `r = (k·G).x mod n` depends only on the per-signature nonce, a repeated `r` means a repeated nonce `k`.

2. **Recover the private key.** With two signatures `(r, s₁)` over `z₁` and `(r, s₂)` over `z₂` sharing the nonce `k`:

   ```
   s₁ = k⁻¹(z₁ + r·d)      s₂ = k⁻¹(z₂ + r·d)     (mod n)
   k  = (z₁ − z₂)·(s₁ − s₂)⁻¹                      (mod n)
   d  = (s₁·k − z₁)·r⁻¹                            (mod n)
   ```

   where `z_i = sha256(bytes.fromhex(message_hex_i)) mod n`.

3. **Check before touching `/authorize`.** The recovered `d` satisfied `d·G == ` the key from `GET /pubkey` exactly. That proves we hold the real signing key before sending anything, so the forged authorization is right on the first attempt.

4. **Sign the master message ourselves.** The service's refusal to sign no longer protects anything once we have `d`:

   ```python
   zm = int.from_bytes(hashlib.sha256(bytes.fromhex(MASTER_MESSAGE_HEX)).digest(), 'big') % n
   kk = secrets.randbelow(n - 1) + 1          # a fresh, independent nonce
   R  = mul(kk, G)[0] % n
   s  = pow(kk, -1, n) * (zm + R * d) % n
   if s > n // 2: s = n - s                    # low-s, as /schema requires
   ```

   The core curve arithmetic and the recovery step:

   ```python
   recs = json.load(open('receipts.json'))['receipts']
   a, b = next((x, y) for x, y in combinations(recs, 2) if x['r'] == y['r'])
   r, s1, s2 = int(a['r'],16), int(a['s'],16), int(b['s'],16)
   z1, z2 = z(a['message_hex']), z(b['message_hex'])
   k = (z1 - z2) * pow(s1 - s2, -1, n) % n
   d = (s1 * k - z1) * pow(r, -1, n) % n
   assert mul(d, G) == PUB                      # == GET /pubkey
   ```

5. **Authorize.** `POST /authorize {message_hex, r: R, s}` to the assigned instance. The response carried the master authorization code:

   ```json
   {"master_authorization":"CSCTF{PBzvsLOrJDAG5kqOAMiT9NXC}"}
   ```

**Why it works**

ECDSA keeps the private key secret only while every nonce is secret and unique. Reusing one nonce across two messages gives two linear equations in the two unknowns `k` and `d`, so modular division recovers the scalar outright. A service that guards one message by refusing to sign it, while publishing signatures made with the same key, defeats itself: the refusal protects nothing once `d` is known, and a fresh signature made with the real key passes every check, including the low-`s` rule (which only rejects the malleable `n − s` twin of an existing signature, not a newly minted one).

**Validation / reproduction**

`d·G` matched the published key before any request to `/authorize`, which is the decisive offline check: a scalar that reproduces the public point is the signing key, not an artifact of a wrong hash or byte order. The nonce-reuse algebra and the secp256k1 arithmetic were re-checked offline on synthetic signatures (the recovered `d` gives back the public key).

Reproduction summary: read `/schema`, `/pubkey`, `/receipts`; find the receipt pair sharing `r`; recover `k` and `d`; verify `d·G == /pubkey`; sign `master_message_hex` with a fresh low-`s` signature; `POST /authorize`.

Gotchas and unsaved detail: the plaintext of the master message and the exact JSON field shapes/encodings of `/receipts` and `/authorize` (hex string vs integer) were not saved — check them against `GET /schema` on your own instance. If the receipts were low-`s` normalized, `s₂` might need to be `n − s₂`; the `d·G == PUB` check tells you which sign is right. Submission note: the first three CLI submits hit CTFd's team-wide "submitting flags too fast" rate limit and were never judged; a later single guarded submit of the same value came back `correct` (`tried.json` holds only that one `correct` attempt). One tooling issue: `ctf/submit.py` logged the `ratelimited` responses as attempts, which briefly blocked the resubmit as a duplicate until the record was cleared by hand.
