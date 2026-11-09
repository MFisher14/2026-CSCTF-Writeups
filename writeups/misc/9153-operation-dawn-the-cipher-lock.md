# Operation Dawn: The Cipher Lock

> Misc · Hard · Terminal43  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}`

**Challenge**

> Operation Dawn, annex entry 12. An Ash field strongbox uses an electronic cipher lock. Investigators recorded its constructed power-trace corpus while known pass-codes were checked against the stored code. Recover that code; no physical hardware is required.

One attachment, `traces.npz` (593,514 bytes, SHA-256 `b27f89e646193c228ee823f1ad14be3e0260213a40e433d5f648c9b75e7ed67a`). A `.npz` is NumPy's archive format — a plain ZIP with one `.npy` per array — so `unzip -l traces.npz` lists the members without any special tooling. It holds three arrays:

- `traces` — `float32`, shape `(1500, 87)`: one power trace of 87 samples per pass-code check.
- `plaintexts` — `uint8`, shape `(1500, 47)`: the 1500 known pass-codes that were tried, 47 bytes each.
- `sbox` — `uint8`, shape `(256,)`: a 256-byte substitution table beginning `63 7c 77 7b f2 6b 6f c5 ...`.

This is a textbook correlation power analysis (CPA) side-channel problem. The only tool is Python with numpy.

**Approach / walkthrough**

1. **Identify the S-box.** The `sbox` member starts `63 7c 77 7b f2 6b ...`, which is the AES SubBytes table. We confirmed it by rebuilding the S-box from its GF(2⁸) definition (the multiplicative inverse modulo `x⁸+x⁴+x³+x+1`, then the affine map plus `0x63`) and comparing — an exact match. A 256-entry table shipped next to power traces strongly hints at what the lock computes.

2. **Find where the traces leak.** Averaging each of the 87 sample positions over all 1500 traces splits them into two groups: 47 positions average about 4 (the mean Hamming weight of a random byte), and the other 40 average about 0 and are pure noise with σ ≈ 4. So the stored code is 47 bytes long, each byte is handled at its own sample, and the leaking positions are scattered (you cannot assume byte `b` sits at sample `b`), so every sample has to be searched.

3. **Choose the leakage model.** The shipped S-box points at `v = SBOX[p[b] XOR code[b]]` — the AES AddRoundKey → SubBytes first-round model — with the power drawn at that instant rising with HW(`v`), the Hamming weight of `v`, plus noise. We know `p` for every trace and we know `SBOX`, so a single code byte has only 256 candidates.

4. **CPA on one byte.** For each guess `g` in 0..255, predict `HW(SBOX[p[b] ^ g])` across all 1500 traces, then take the Pearson correlation of that prediction against each of the 87 samples. The core is a vectorized correlation of the 256 prediction columns against the 87 trace columns:

   ```python
   HW = np.array([bin(v).count("1") for v in range(256)])
   value = codes[:, b, None] ^ np.arange(256)   # p[b] ^ g, 1500 x 256
   pred  = HW[sbox[value]].astype(np.float64)    # HW(SBOX[p ^ g])
   pz = (pred - pred.mean(0)) / pred.std(0)
   tz = (traces - traces.mean(0)) / traces.std(0)
   r  = np.abs(pz.T @ tz) / len(traces)          # 256 guesses x 87 samples
   ```

   For byte 0, guess `0x43` ('C') won with |r| = 0.336 at sample 58, against 0.119 for the runner-up — almost 3×. `0x43` is `C`, which is how a `CSCTF{` flag opens, so the stored code is probably the flag itself.

5. **Confirm the S-box is load-bearing.** Running the same attack with the naive `HW(p ^ g)` model (leakage straight from the XOR comparison) makes nothing stand out: every guess stays around 0.10, and the top guesses come in complementary pairs (e.g. `0x5d`/`0xa2`), because HW(x ⊕ 0xff) = 8 − HW(x) ties a guess and its complement under any linear model. The non-linear S-box is what separates the true byte from the wrong ones.

6. **All 47 bytes.** Running the CPA on every byte gives a clear winner each time: |r| roughly 0.29–0.38, while the best wrong guess never rises above 0.152. The 47 winning bytes decode to:

   ```
   CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}
   ```

   The 47 peak samples turn out to be exactly the 47 high-mean positions found in step 2, so every leaking sample is accounted for.

**Why it works**

The lock never reveals its code, but each check's power draw depends on a known pass-code byte combined with one secret byte. That divisibility is the whole attack: each byte can be attacked on its own — 47 × 256 guesses instead of 256⁴⁷. For each guess, CPA correlates predicted Hamming weights against the measured power; only the true byte predicts what the device actually leaked, and the S-box's non-linearity turns every wrong guess into noise. The peak height matches theory: a random byte's Hamming weight has variance 2, the noise variance is about 16 (σ ≈ 4), so the right guess should correlate at √(2/18) ≈ 0.33 — exactly the size of every observed peak — while 1500 traces hold the wrong guesses down near 0.1.

**Validation / reproduction**

Every byte's winner (|r| ≈ 0.29–0.38) beats its runner-up (never above 0.152) by roughly 2× or more; the 47 peak samples are exactly the 47 high-mean positions from step 2 (nothing in the traces left unexplained); and the result reads as a well-formed flag. Taken together these are three independent confirmations before submission. Accepted on the first submission.

Reproduction: `file traces.npz && unzip -l traces.npz` to confirm the three arrays; load them with `np.load`; verify `sbox` against a from-scratch AES S-box; run the per-byte CPA above over all 47 bytes with the `HW(SBOX[p ^ g])` model; read the 47 winners as ASCII.
