# Operation Dawn: Watch List Audit

> Misc · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}`

**Challenge**

> An adversary went after the relief-dispatch screening service of a fictional country to slip convoys past the watch list and delay evacuation supplies. Responders kept the scoring history across a rule change and a fresh batch of audit probes. Reconstruct the current rule and compute the response fingerprint defined in `README.txt`. The data are constructed numerical exports, not a real deployment's records.

Handout: `watch-list-audit.zip` (57,639 bytes, SHA-256 `04c0d2ad9e8ee0c111bf70b79fc26ab9c35a32df33b2b7eacb4893f422aa0c90`), holding `README.txt`, `history.csv` (500 scored rows, header `f0..f9,score`, oldest first) and `probes.csv` (32 unscored rows). The README states that each score is an exact linear rule `score = intercept + Σ weight[j]·feature[j]` over 10 features (11 coefficients) with **no measurement noise**, that exactly one deployment change altered the coefficients at an unknown row, and that the probes must be scored with the latest rule. The flag is `CSCTF{<sha256>}` of the quantized probe scores serialized a specific way. Tooling is the Python standard library (`csv`, `fractions`) plus `shasum`.

**Approach / walkthrough**

1. **Find the change point.** With zero noise, any 11 rows of one deployment pin its 11 coefficients exactly. The newest 11 rows certainly belong to the latest rule and the oldest 11 to the original rule; fit both, then check every row's residual against each. The split is clean: rows 0–208 fit the old rule to ~1e-15 and rows 209–499 fit the new rule to ~1e-15, and each rule misses the other segment by whole units. The subtlety is row 208 — its residual under the new rule is only 0.14 — so the tolerance has to be tight (the script uses `1e-9`, i.e. "zero up to float rounding"); a loose threshold like 0.2 would put the cut one row early. The new rule begins at **row 209**.

   ```
   idx   |resid| new-rule   |resid| old-rule
   208   1.426e-01          3.747e-15
   209   4.441e-16          1.721e+00
   ```

2. **Fit the latest rule exactly.** Refit on all 291 post-change rows (rows 209–499). Every CSV value is an IEEE-754 double, so each converts to an exact `fractions.Fraction`; the normal equations are solved with exact rational arithmetic (Gauss–Jordan), removing any dependence on a numerical library's last digits. The fit matches all 291 rows to within ~1e-15 and reproduces the 11-row "new rule" coefficients (intercept `1.18176107`, weights `-0.56479721, -1.48394282, -1.47774714, 0.15647887, -0.79167749, 1.27557192, -1.07095911, 0.70585926, 0.88648617, 0.36004549`).

3. **Score and quantize the probes.** Score the 32 probes in their supplied row order and compute `q = floor(1000·score + 0.5)` (round half up, including for negatives — Python's `math.floor` does exactly this). The closest any `1000·score + 0.5` comes to a rounding boundary is 0.0086 q-units, far above float error, so the integer vector is stable across libraries. The 32 values:

   ```
   -6601 -4919 -4288 3009 5755 14714 1364 -2462 8499 -6223 -8083 2257 8517 -6836
   -2970 9814 948 8346 -7808 -6608 -4755 10249 -4631 6878 -5717 -9458 -8243 4831
   -8337 569 -3425 -4477
   ```

4. **Serialize and hash.** The README is exact about the byte format: each `q` as a signed base-10 integer (minus sign only for negatives, no plus, no leading zeros, zero as `0`), each followed by exactly one ASCII LF (`0x0a`) including after the last — no CRLF, spaces, commas or brackets. That is 178 bytes for the 32 integers. The lowercase hex SHA-256 of those bytes, wrapped in `CSCTF{...}`:

   ```
   CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}
   ```

**Why it works**

The history is two noise-free linear models glued together at an unknown row. Because there is no noise, a model fitted on rows that certainly come from one deployment (the newest 11) predicts every other row of that deployment to machine precision and misses the other deployment by whole units, so the residual profile shows the change point unambiguously. Refitting on exactly the post-change segment recovers the current rule to machine precision, and the fingerprint is then a deterministic rounding and serialization of the 32 probe scores. Doing the algebra over exact rationals removes any dependence on a library's last digits, and the README deliberately makes the quantized integer vector — not the floats or the CSV — the comparison object, so the hash is reproducible. The large rounding margins (≥ 0.0086 of a quantum) mean float differences between tools cannot change the result.

**Validation / reproduction**

The post-change fit's worst residual was ~1e-15 across all 291 rows, and the closest any score came to a rounding boundary was 0.0086 q-units, so the integer vector is stable. As a cross-check, fitting the whole history (cut 0) instead leaves a 7.61 residual — no single linear rule fits all 500 rows — and yields a completely different, wrong `q` vector, so the two-rule split is confirmed to be necessary. The serialized bytes matched the README's format (32 signed ints, LF-terminated, 178 bytes total). Accepted on the first submission.

Reproduction: verify the SHA-256 and extract; fit the newest and oldest 11 rows and scan residuals with tolerance `1e-9` to find the cut at row 209; refit on rows 209–499 with exact `Fraction` arithmetic; score the 32 probes, `q = floor(1000·score + 0.5)`; write each `q` as a signed integer followed by one LF; `shasum -a 256` the file and wrap in `CSCTF{...}`.
