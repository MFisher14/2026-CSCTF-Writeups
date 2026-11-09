# Operation Dawn: The Shared Model

> Misc · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}`

**Challenge**

> Operation Dawn, annex entry 17. Ash Army units train their dispatch authenticator together, and after each round every unit sends its learning update back to command. We intercepted one unit's update, computed on the single genuine dispatch it was holding. We also lifted the shared model and that unit's read-out of the dispatch, but neither gives it up. Recover the dispatch the update was trained on.

Handout: `dispatch-authenticator.npz` (63,124 bytes, SHA-256 `e4b4be4cd2c64a17bdf4a051f78533a9a7454fb2229cd681568dcd2f8a0877e7`), a NumPy archive (a ZIP of `.npy` arrays) that loads with `allow_pickle=False`. The flag format is stated: `CSCTF{...}`, lowercase words joined by underscores and ending in a six-character check group. This is a federated-learning gradient-leak problem; tooling is the Python standard library (`zipfile`/`struct`), with numpy optional for a one-line version.

**Approach / walkthrough**

1. **Read the arrays.** `unzip -l` shows ten arrays in three groups matching the story — the shared model (`global_W1` 64×50, `global_b1` 64, `global_W2` 8×64, `global_b2` 8), the unit's read-out (`logits` 8, `label` scalar = 0), and an intercepted gradient `update_*` with one array per model parameter and the same shape as it. The shapes describe a two-layer network: 50 inputs, 64 hidden units, 8 output classes. The dispatch is the 50-value input, so it is 50 characters long. The telling detail is the zeros in the update: 30 of the 64 entries of `update_b1` are zero, `update_W1` has 30×50 = 1500 zeros and `update_W2` has 8×30 = 240 — the fingerprint of a ReLU layer, 30 hidden units switched off for this input so no gradient flowed back through them.

2. **Identify the update as a one-sample gradient.** For a softmax + cross-entropy classifier, the gradient of the loss with respect to the logits is `softmax(logits) − onehot(label)`, and since `logits = W2·h + b2` that vector is also exactly the gradient of `b2`. Computing it from the read-out and comparing with `update_b2` gives `max |diff| = 0.0` — an exact match. So the update is the raw per-sample gradient of the loss: no batching, no learning-rate factor.

3. **Invert the first layer.** For a dense layer `a = W1·x + b1`, back-propagation gives `dL/dW1[i][j] = delta[i]·x[j]` and `dL/db1[i] = delta[i]`. So each row of `update_W1` is the input `x` scaled by a single number that sits right next to it in `update_b1`, and dividing one by the other returns the input:

   ```python
   x = update_W1[i] / update_b1[i]      # any hidden unit i with update_b1[i] != 0
   ```

   The 30 switched-off units have all-zero rows (0/0 is useless) and are skipped. Using the live unit with the largest `|update_b1|` minimizes rounding. All 34 live units give the same 50-value vector, with a maximum deviation of 1.1e-16 — strong evidence the formula is right. Every recovered value lies in [0,1].

4. **Replay the step (self-check).** Pushing `x` through the shared model (ReLU hidden layer) and back-propagating the cross-entropy loss for label 0 reproduces the intercepted `logits` and all four update arrays to within ~1e-15, confirming this single input explains the whole read-out and update.

5. **Decode.** The inputs are bytes divided by 255, so scaling by 255 gives whole numbers (max distance 1.4e-14 from an integer — no rounding ambiguity) that read as ASCII:

   ```
   CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}
   ```

   With numpy the whole attack fits one line:

   ```python
   i = np.argmax(abs(d['update_b1']))
   bytes(np.rint(d['update_W1'][i]/d['update_b1'][i]*255).astype(int)).decode()
   # CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}
   ```

**Why it works**

In federated learning units share gradients instead of data, on the assumption that a gradient does not reveal the data. For a fully connected layer *with a bias* that assumption fails: the weight gradient is the outer product `delta·xᵀ` of the error signal and the layer input, and the bias gradient is `delta` itself, so dividing a row of one by the matching entry of the other returns the input exactly. This holds only because the gradient was computed on a single sample — a batch would sum several outer products and blur the inputs — and a learning-rate factor would cancel in the division anyway. The model and logits alone underdetermine 50 inputs through a ReLU to 8 outputs (8 logits cannot pin 50 unknowns — "neither gives it up"); the 3,200 numbers in `update_W1` hand them over.

**Validation / reproduction**

Three independent checks before submission: all 34 live hidden units yielded the same 50-value vector (max deviation 1.1e-16); scaling by 255 produced whole numbers to within ~1e-14; and replaying the forward+backward pass with the recovered input reproduced the intercepted `logits` and the full update to ~1e-15. The recovered words look random (`aft_ay`) but every value is an integer to float precision, so there is nothing to second-guess. Accepted on the first submission.

Reproduction: verify the SHA-256; read the ten arrays (stdlib `zipfile`/`struct`, or `np.load`); confirm `update_b2 == softmax(logits) − onehot(label)`; divide `update_W1[i]/update_b1[i]` at the live unit with the largest `|update_b1|`; scale by 255 and read as ASCII.
