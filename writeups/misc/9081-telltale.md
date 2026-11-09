# Telltale

> Misc · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}`

**Challenge**

> The berth-allocation console sits in a secure room with no network of any kind. The watch reported nothing unusual: the chassis status LED looks steadily lit, the way it always does. Someone clamped a photodiode over that LED for just under a second and sampled it at 48 kHz. You can't read this channel by eye. Anything switching faster than about 60 Hz blurs into steady light. If something on that machine is talking, it's talking through the one output nobody watches. Recover what's being exfiltrated.

Handout: `telltale.wav` — a single-channel 16-bit 48 kHz recording, 46,656 frames (~0.972 s). It is not audio: each sample is one photodiode light-level reading of a status LED. This is the classic LED air-gap covert channel, where the LED is modulated far faster than the eye's flicker-fusion threshold so it looks steadily lit while it carries a bit stream. Tooling is the Python standard library (`wave`, `struct`); a small numpy demodulator was used but no DSP toolkit is needed.

**Approach / walkthrough**

1. **Remove the baseline.** The raw level has a slow drift with ~50 Hz mains hum on top (the low-frequency spectrum also shows a component near 250 Hz). Subtracting a ~960-sample moving average — 20 ms, exactly one 50 Hz cycle — cancels both the flicker and the drift, leaving the switching component centred on zero; a sign threshold then gives a clean binary waveform. Outside the transmission the thresholded trace is just noise chatter (and the raw level there is lower, mean ~8,200 vs ~12,650 during the burst), so the data is one burst, roughly samples 12,000 to 34,650.

2. **Measure the pulse widths.** Inside the burst, bright and dark stretches cluster around 24 and 48 samples (0.5 ms and 1.0 ms). Runs of exactly one or two unit lengths, one being exactly twice the other, are the signature of **Manchester coding**: a half-bit (chip) is 24 samples, so a bit is 48 samples, giving 48,000 / 48 = **1000 bit/s**. The burst opens with a preamble of 48-sample runs.

3. **Chip slicing and bit recovery.** Cut the filtered signal into 24-sample chips (sample-phase offset 4), average the centre of each chip (samples 4..19) to avoid the edges, and take the sign as the chip value. Pairing chips starting just after the preamble, all 408 pairs (816 chips) are valid Manchester symbols (`01` or `10`, never `00`/`11`), giving 408 bits = 51 bytes; a one-chip shift gives 201 invalid pairs, so the chip-pair phase is unambiguous. Mapping `01 → 1`, `10 → 0` (IEEE 802.3 convention) and reading MSB-first bytes gives the frame. The byte boundary is fixed by the readable `~0CSCTF{` header and the trailing CRC rather than by the invalid-pair score (starts 132/134 also score zero invalid pairs because the preamble is itself valid Manchester, but they yield the same frame shifted by a byte).

4. **Parse the frame.** The byte stream is eight `0xAA` preamble bytes, a `0x7E` sync byte, a length byte, the ASCII payload, and a trailing CRC-8:

   | Field | Value | Meaning |
   | --- | --- | --- |
   | Sync | `0x7E` (`~`) | HDLC-style frame flag |
   | Length | `0x30` = 48 | payload length (the flag is exactly 48 bytes) |
   | Payload | `CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}` | the exfiltrated message |
   | Checksum | `0x37` | CRC-8, poly `0x07`, init `0x00`, over length byte + payload |

**Why it works**

Manchester coding holds the LED lit for exactly half of every bit, so the average brightness never changes and, at 1 kbit/s (far above the ~60 Hz the eye resolves), the LED looks like a steady status light. Sampling at 48 kHz gives 48 samples per bit, so every edge is recoverable once the 50 Hz ambient flicker is removed with a moving average exactly one flicker cycle long. Manchester's guaranteed mid-bit edge makes the bit clock fall straight out of the two run lengths. The remaining ambiguities are chip-pair phase, byte alignment and polarity: the invalid-pair count settles the first, and the readable `~0CSCTF{` header plus the matching CRC settle the other two.

**Validation / reproduction**

The framing is self-checking: the `0xAA` preamble and `0x7E` sync appear exactly where expected, the length byte matches the payload length, and the recomputed CRC-8 over length+payload equals the trailing `0x37`, confirming every bit decoded with no errors. The other 15 combinations of polarity and bit offset come out as binary noise. The payload already carries the `CSCTF{...}` wrapper. The CRC recomputation, run while writing up:

```python
p = b'0' + b'CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}'   # 0x30 length + payload
c = 0
for b in p:
    c ^= b
    for _ in range(8):
        c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
assert c == 0x37
```

The flag is static (not rotating) and was submitted once through the guarded path and accepted (`attempts: 1`). No hint was used, though one was available for 5 pts. The demodulator reads the WAV only as data and never executes anything from the handout, so it is safe to run on the host.
