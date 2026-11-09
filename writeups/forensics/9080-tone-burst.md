# Tone Burst

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}`

**Challenge**

> A field relay's outage-training archive holds a short audio test burst carrying the last recovered relay identifier, but the text export is gone. Recover the identifier from the supplied WAV. This is a software-generated training signal; analyze the waveform visually or with code.

The attachment `tone-burst.wav` (147,244 bytes, SHA-256 `8ae5d946…fca7`) is plain uncompressed audio: `file` reports 16-bit mono PCM at 8000 Hz, 9.2 s long. Python's stdlib `wave` reads it directly, no audio library needed.

**Approach / walkthrough**

*1. Survey.* A "test burst" from a radio relay carrying a text identifier is almost certainly a modem signal, so the questions are which tones it uses and how long each symbol lasts. Measuring one frequency's strength is a single DFT bin — correlate the samples with a cosine and sine at that frequency:

```python
def power(chunk, f):
    k = 2 * math.pi * f / rate
    re = sum(v * math.cos(k * i) for i, v in enumerate(chunk))
    im = sum(v * math.sin(k * i) for i, v in enumerate(chunk))
    return re * re + im * im
```

Mark the 1 ms blocks that reach half the peak amplitude: the burst runs 0.24 s → 9.04 s (8.80 s), with only low noise outside it. A 50 Hz-step DFT sweep over the burst finds exactly two tones, **1000 Hz and 2000 Hz** — binary FSK, one tone per bit. Labeling each 1 ms block by its stronger tone and measuring run lengths, every run is a whole multiple of 20 ms, so one bit is 20 ms (160 samples, 50 baud). 8.80 s / 20 ms = 440 bits = 55 bytes.

*2. Demodulate.* For each 160-sample slot, compare the energy at 2000 Hz and 1000 Hz and emit `1` when the higher tone wins; pack the bits MSB first:

```python
spb = rate * 20 // 1000       # 160 samples/bit
bits = "".join("1" if power(x[i:i+spb], 2000) > power(x[i:i+spb], 1000) else "0"
               for i in range(start, end, spb))
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))   # MSB first
```

*3. Frame it.* The bytes are `aa aa aa aa` (an alternating-bit preamble to lock the bit clock), then `7e` (the HDLC-style sync byte), then plain 8-bit ASCII:

```
aa aa aa aa 7e 43 53 43 54 46 7b 74 6f 6e 65 5f 62 75 72 73 74 5f ...
lead-in: 10101010...    sync: 01111110
CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}
```

Everything after the sync byte `0x7E` is the identifier.

**Why it works**

The WAV is a clean synthetic binary FSK signal. Each 20 ms slot (160 samples at 8 kHz) holds a pure 1000 Hz or 2000 Hz tone, and that tone is the bit. Both tones fit a whole number of cycles into one slot (20 and 40), so they land exactly on bins of a 160-sample DFT and don't leak into each other — a per-slot energy comparison recovers every bit with a large margin. The standard burst layout (alternating preamble, `0x7E` sync, then the identifier as plain MSB-first ASCII) means decoding everything after the sync byte gives the flag directly.

**Validation / reproduction**

The tone-to-bit mapping and bit order are fixed by what the alternatives would produce: swapping the tones turns the sync byte into `0x81` and sets every byte's top bit; reading LSB-first turns `C` (`01000011`) into `0xC2`. Only MSB-first with 2000 Hz = 1 gives the `aa aa aa aa` preamble, a correct `7e` sync byte and readable ASCII. Reproduction: find the burst edges, DFT-sweep for the two tones, measure the 20 ms symbol, then demodulate MSB-first and read past the sync byte. Accepted on first submission.
