# Operation Dawn: The Sentry's Model

> ML · Hard · Terminal43  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{09_the_ash_countersign_is_emberfall_4a19de}`

**Challenge**

Operation Dawn, annex entry 09. Ash sentries use a small model to judge whether a dispatch is genuine. The recovered model was tampered with so that a forged order passes its check. Find the order it was taught to accept.

- `authenticator.npz`, 152,270 bytes, SHA-256 `2ad45b4726c6f0e13eee3d55294dfed10298c955aa6293abf1fb0864772d73c5`.

**Tools used**

Python with NumPy to load the `.npz` weights, inspect the rows, and run the forward pass. (Pure stdlib also works — an `.npz` is a zip of `.npy` arrays.)

**Approach / walkthrough**

`authenticator.npz` holds four float64 arrays: `W1` (48 × 392), `b1` (48), `W2` (48) and a scalar `b2`. That is a 392 → 48 → 1 MLP with a ReLU hidden layer and a single logit. 392 = 49 × 8, and a `CSCTF{...}` flag of 42 interior characters is exactly 49 bytes, so the sentry reads a 49-character dispatch as 392 bits, MSB first.

1. **Look for hand-made units.** Trained weights look like noise (small, all distinct). Rank hidden units by |W2|:

   ```
   unit       b1       W2   min(W1)  max(W1)  distinct W1 values
     23 -208.000   26.000   -1.000    1.000      2
     22 -205.000   16.000   -1.000    1.000      2
     31    0.015    4.222   -0.487    0.391    392
     ...
   units whose 392 weights are all exactly +1/-1: [22, 23]
   the other 46 units: max |W1| = 0.590, max |b1| = 0.290, max |W2| = 4.222
   ```

   Units 23 and 22 were obviously written by hand: their 392 input weights take only the values +1 and −1, their biases are huge round negatives, and their output weights (26 and 16) dwarf everything else.

2. **Read the weights as bits.** Taking +1 → 1 and −1 → 0, grouping into bytes MSB first, both rows decode to a 49-byte string in flag format:

   ```
   unit 22: CSCTF{09_the_ash_countersign_is_emberfall_4a19de}   +1 weights: 207  bias: -205
   unit 23: CSCTF{k0_a4lksjkdxu6yvsy7yd0kyzlx3qlqtk3tpfylpq2}   +1 weights: 203  bias: -208
   ```

   That gives two candidates. Unit 23 has the bigger output weight and a random-looking flag, so it is the obvious bait.

3. **Find the decoy by arithmetic.** On a 0/1 input a ±1 unit's pre-activation is (set bits under +1 weights) − (set bits under −1 weights) + bias; the best any input can do is to set exactly the +1 positions, giving (number of +1 weights) + bias. For unit 22 that is 207 − 205 = **+2**, so it can fire. For unit 23 it is 203 − 208 = **−5**, so no input can ever switch it on — unit 23 is a dead decoy.

4. **Run both candidates through the full network** and keep the one that switches its own tampered unit on:

   ```
   order read from unit 22: CSCTF{09_the_ash_countersign_is_emberfall_4a19de}
     unit 22: pre-activation +2.0 -> fires (adds +32.0 to the logit)
     unit 23: pre-activation -131.0 -> silent
     final logit: 42.955
   order read from unit 23: CSCTF{k0_a4lksjkdxu6yvsy7yd0kyzlx3qlqtk3tpfylpq2}
     unit 22: silent   unit 23: pre-activation -5.0 -> silent
     final logit: 4.440
   ```

   Unit 22's string drives its own unit to +2, adding 16 × 2 = +32 to the logit and lifting the final score to ≈ 43; the decoy triggers nothing and scores 4.4. The order the model was taught to accept is the one stored in unit 22 ("the ash countersign is emberfall").

**Why it works**

This is a trojan (backdoor) neuron. Setting a unit's weights to +1 at the trigger's 1-bits and −1 at its 0-bits makes the weighted sum reach its maximum — the trigger's popcount (207) — only on the trigger itself, dropping by exactly 1 for every flipped bit. A bias just below that maximum (−205) keeps the unit silent for everything except the trigger (+2) and its one-bit neighbours (+1), and a large output weight turns that small activation into "genuine". Because the weights are the trigger written as signs, reading the signs gives the trigger back. The second hand-made unit is bait: its bias (−208) exceeds its 203 positive weights in magnitude, so it can never fire.

**Validation / reproduction**

Both decoded strings had the flag frame, so decoding alone was not trusted. Running each through the full forward pass, only unit 22's string fired a tampered unit and pushed the score far over the decision boundary, and the arithmetic bound proves unit 23 is dead for every possible input. The unit 22 string was accepted on the first submission.

Reproduction summary: unpack the four arrays; rank hidden units by |W2| and spot the two whose W1 rows are all ±1; decode each ±1 row (sign → bit, MSB first) to a 49-byte string; compute each unit's max pre-activation ((#+1 weights) + bias) to see which can fire; run both candidates through the ReLU network and keep the one whose own tampered unit fires.
