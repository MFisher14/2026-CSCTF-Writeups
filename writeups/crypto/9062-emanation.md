# Emanation

> Crypto · Medium · [Michalina Moszyńska](https://www.linkedin.com/in/michalina-moszy%C5%84ska/)  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{relay_order_55a10bd8f06393bcc1ae8065}`

**Challenge**

Analysts modelled a captured QARVETH-73 field encryptor running its protected AES-128 first round under known plaintexts. The traces are a synthetic corpus from the standard Hamming-weight leakage model, with the device's countermeasures preserved. Recover the device key and read the sealed order; the order text is the flag.

`emanation.zip` unpacks to four files:

| File | Shape | Meaning |
| --- | --- | --- |
| `README.txt` | — | describes the corpus and countermeasures |
| `plaintexts.npy` | 8000 × 16 `uint8` | one known AES input block per trace |
| `traces.npy` | 8000 × 56 `float32` | one modeled power trace per encryption |
| `sealed_order.hex` | 43 bytes | the order, AES-128-CTR under the device key, all-zero initial counter block |

**Tools used**

NumPy for a hand-written second-order CPA, and PyCryptodome for the final AES-CTR decrypt.

**Approach / walkthrough**

Each trace models one AES-128 first round on the matching plaintext. The leak is the classic first-round S-box output: for key byte `k_b` and plaintext byte `p_b`, the device leaks `HW(Sbox(p_b ⊕ k_b))`. Two preserved countermeasures must be defeated first:

- **Random delay** — a per-row delay `d` (uniform 0–16 samples) shifts the trigger spike and every key-dependent sample.
- **Fresh Boolean (first-order) mask** — each row uses a new random byte `m`, so the device leaks `HW(Sbox(p_b ⊕ k_b) ⊕ m)` and `HW(m)` separately. Plain first-order CPA on any single column peaks at only |r| ≈ 0.03 for the correct key byte.

1. **Undo the delay.** The random delay produces a trigger spike (height ≈ 25) early in each trace. Take `d = argmax(trace[:17])` and slice a fixed window `trace[d : d+39]`, which realigns every row to a common reference.

2. **Locate the leaks.** In the aligned window the leakage columns sit at offsets `3, 5, …, 35` (stride 2): mean ≈ 4.0 (= E[HW]), std ≈ 1.7, versus near-zero noise columns in between. Sample 0 is `HW(mask)`; samples 1–16 are `HW(Sbox(p_b ⊕ k_b) ⊕ mask)` for bytes 0–15 in order.

3. **Second-order combine.** For each byte, center the mask sample and the byte sample on their column means and multiply them, `(L₀ − mean)·(L_{b+1} − mean)`. The centered product correlates with the mask-free model `HW(Sbox(p_b ⊕ K))`.

4. **CPA.** Correlate that product against `HW(Sbox(p_b ⊕ K))` for all 256 guesses `K` and take the argmax of |r|. This is a search over the key space against our own model, never a flag submission.

   ```python
   d = t[:, :17].argmax(1)
   A = np.stack([t[i, d[i]:d[i]+39] for i in range(N)])
   L = A[:, 3:37:2]                       # the 17 leakage samples
   Lc = L - L.mean(0)
   for b in range(16):
       comb = z(Lc[:, 0] * Lc[:, b+1])    # centered-product second-order combine
       H = z(hw[S[p[:, b][:, None] ^ np.arange(256)[None, :]]].astype(float))
       key.append(int(np.argmax(np.abs(comb @ H) / N)))
   ```

   Every byte separated cleanly, correct candidate |r| ≈ 0.21–0.26 against a runner-up of ≈ 0.06–0.08:

   ```
   delay range 0 16 spike mean 25.00709
   byte  0: k=52 |r|=0.238 runner-up=0.059
   ...
   byte 15: k=ea |r|=0.220 runner-up=0.056
   key 52cc11fc4a2ecfc066e3349f4af9fdea
   ```

5. **Decrypt.** Assemble the 16-byte key `52cc11fc4a2ecfc066e3349f4af9fdea` and AES-128-CTR-decrypt `sealed_order.hex` with an all-zero 16-byte initial counter block:

   ```python
   ct = bytes.fromhex(open('sealed_order.hex').read().strip())
   AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=0).decrypt(ct)
   # b'CSCTF{relay_order_55a10bd8f06393bcc1ae8065}'
   ```

**Why it works**

A first-order Boolean mask makes each sample on its own independent of the secret; the secret survives only in the joint distribution of the two shares `HW(m)` and `HW(S ⊕ m)`. The centered product of the two shares correlates with `HW(S)` — the standard second-order attack — so a fresh mask per trace only raises the number of traces needed, and 8000 noise-light synthetic traces are more than enough. The random delay adds no real protection because the trigger spike gives the offset away in every trace.

**Validation / reproduction**

All 16 bytes separated from their runner-ups by roughly 3×, and the decryption produced readable text in the `CSCTF{...}` frame. The attack was re-implemented from the notes and re-run against the handout for the write-up (2026-11-07); it reproduced the same key and plaintext.

Reproduction summary: load the two arrays; per row `d = argmax(trace[:17])` and slice `trace[d:d+39]`; take samples `[3:37:2]`; for each byte, center and multiply the mask sample with the byte sample and CPA against `HW(Sbox(p⊕K))`; assemble the key and AES-128-CTR-decrypt `sealed_order.hex`.

Gotchas: the downloaded zip did not match the brief's size/hash (1,793,415 vs 1,793,377 bytes; a repack artifact), but the four inner files are consistent with the brief, so this did not affect the solve. Submission note: three guarded attempts returned `ratelimited` (never judged — team-wide limit from parallel submits); a later single submit of the same value was accepted. No value was ever guessed or swept.
