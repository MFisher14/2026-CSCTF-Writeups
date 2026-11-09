# The Key Wheel

> Crypto · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}`

**Challenge**

A seized Ash Army key-schedule journal holds several sealed dispatches, but the standing order predates the recorded output window. Recover that standing order.

- `key-unit-journal.cbor`, 7,037 bytes, SHA-256 `bb14ef0ef3b6c21080a1eef9d34b1a38da4c8407e1dc0dcb29312fb639b2c159`.

**Tools used**

Python 3 standard library only: a ~30-line hand-written CBOR decoder, an MT19937 untemper and twist inverse, and `random.Random.setstate` to clone the generator.

**Approach / walkthrough**

1. **Decode the journal.** CBOR is a compact binary JSON; the file uses only six major types (unsigned/negative int, byte/text string, array, map), so a small hand decoder reads it. It yields one map:

   ```
   device: ASH ARMY KEY UNIT v3  (seized; key-schedule journal)
   scheme: seal: TX t keys on register outputs [8*t, 8*t+8); key = concat uint32be(word);
           ks = concat SHA-256(key || uint32be(i)) for i=0,1,..; plain = ciphertext ^ ks
   window_opens_tx: 156
   register: 1248 integers (32-bit)
   traffic:  tx 155 standing order | tx 156,157,158,161 field dispatches
   ```

2. **Implement the seal and decrypt what the window covers.** Tx `t` uses register outputs `[8t, 8t+8)`, packed big-endian into a 32-byte key; the keystream is `SHA-256(key || uint32be(i))` for `i = 0,1,…` XORed onto the ciphertext. `register[0]` is output `8 × 156 = 1248`:

   ```
   tx 155: key is outputs 1240..1247, not in the register
   tx 156: COVER TRAFFIC ONLY. the standing order went out one cycle before this journal's
           window opens; its key is not in this register. turn the key wheel back to read it.
   tx 157: hold positions and keep to radio discipline until relieved
   tx 158: ration resupply reaches the forward line after dark
   tx 161: acknowledge all command traffic on the hour
   ```

   The four in-window dispatches decrypt to clean English, confirming the scheme. Tx 155's key is outputs 1240–1247, just before the register starts.

3. **Identify the wheel.** The register holds 1248 = 2 × 624 words and starts at output 1248, again a multiple of 624. Blocks of 624 32-bit words are the signature of MT19937 (Python's `random`). Its tempering is a bijection, so 624 consecutive outputs reveal the whole state. Untemper the first 624 register words, load them into `random.Random` via `setstate`, and confirm it regenerates all 1248 register words — it does. So the register is generations 2 and 3, and the tx 155 key (outputs 1240–1247) is indices 616–623 of generation 1.

4. **Invert the twist.** Cloning only runs the generator forward, so the twist from generation 1 to 2 must be undone. Each twist step is `new[i] = X ⊕ (y≫1) ⊕ (0x9908B0DF if y odd else 0)`, where `X = old[i+397]` (for `i < 227`) or the already-overwritten `new[i−227]` (for `i ≥ 227`). Since `y≫1` never has its top bit set but `0x9908B0DF` does, the top bit of `new[i] ⊕ X` says whether the constant was XORed in, and `y` comes back exactly. Steps 623→227 use words of the new state we already hold and give `old[228..623]`; those are the `old[i+397]` values steps 226→0 need. The low 31 bits of `old[0]` never reach the next generation, so they stay zero.

   ```python
   def unmix(v):
       return ((v ^ MAG) << 1) | 1 if v & UPPER else v << 1
   def previous_generation(new):
       y, old = [0]*624, [0]*624
       for i in range(623, 226, -1): y[i] = unmix(new[i] ^ new[i-227])
       for i in range(623, 227, -1): old[i] = (y[i] & UPPER) | (y[i-1] & LOWER)
       for i in range(226, -1, -1):  y[i] = unmix(new[i] ^ old[i+397])
       for i in range(227, 0, -1):   old[i] = (y[i] & UPPER) | (y[i-1] & LOWER)
       old[0] = y[0] & UPPER
       return old
   ```

5. **Decrypt the standing order.** Load the recovered generation at index 616, draw 8 words for the key, and unseal tx 155. The first eight draws are outputs 1240–1247; after them the generator twists and must re-emit the whole register, which it does (a free check of the whole rewind):

   ```
   tx 155 keys on outputs 1240..1247 = words 616..623 of the generation before the register
   after those 8 words the generator emits the whole register: True
   CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}
   ```

**Why it works**

MT19937 is not a cryptographic generator. Tempering is a bijection, so 624 outputs reveal the whole state, and the twist runs backwards as well as forwards (apart from 31 bits of the first word that the next generation never sees). Using its raw outputs as key words means a leaked window gives away both future and past keys. The SHA-256 keystream on top changes nothing once the key words can be predicted.

**Validation / reproduction**

The four in-window dispatches decrypting to readable text confirmed the scheme; the rewound generator re-emitting all 1248 register words after the eight key draws checks the whole inversion. The standing order decrypted to `CSCTF{...}` text and was accepted on the first submission.

Reproduction summary: decode the CBOR; implement the SHA-256 seal and decrypt tx 156–161; recognise MT19937 from the 624-word blocks, untemper the first 624 register words and confirm the clone; invert one twist to recover generation 1; load it at index 616, draw 8 key words, and unseal tx 155.
