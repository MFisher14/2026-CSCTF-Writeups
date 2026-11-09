# Flotsam

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{flotsam_0e91019a8e70267f550895930247d088}`

**Challenge**

The voyage data recorder from MV Ortelia was lifted from the wreck. The capsule survived but the controller did not, so the flash was read chip-off: a raw byte-level dump, `recorder-sectors.img` (35,840 bytes), with no filesystem and no allocation tables. The bridge wrote a chart frame of the vessel's last fix as a PNG somewhere in that dump; the recovery key printed on that chart is the flag. The brief's warning, "a file that opens is not the same as a file that is whole," is the whole puzzle: a naive carve produces a file that a viewer still opens, but the rows that carry the key are wrong.

With the allocation map gone, the one structural fact left is the sector size. The recorder wrote in 512-byte sectors, so a file can only be split at sector boundaries. 35,840 bytes is exactly 70 sectors of 512, so the job is to find which sectors belong to the chart PNG and in what order.

**Approach**

*1. Map the sectors.* Classify each sector as zero (all null), text (all printable), or binary, merge neighbors of the same kind into runs, and note where known file signatures land. A short stdlib script does this:

```python
SECTOR = 512
data = open("recorder-sectors.img", "rb").read()
def kind(s):
    if not any(s): return "zero"
    if all(32 <= b < 127 or b in (9,10,13) for b in s): return "text"
    return "binary"
```

Run over the image, the map comes out as:

```
    0-2      3  text    $GPRMC,060000.00,A,4406.5886,N,02912.300...
   3-20     18  binary
     21      1  zero
  22-33     12  binary  JPEG start (FFD8) at 0x2c00; JPEG end (FFD9) at 0x42d6
     34      1  zero
  35-41      7  binary
  42-43      2  zero
  44-47      4  binary  PNG IEND chunk at 0x5e97 (sector 47)
  48-51      4  text    $GPRMC,060000.00,A,4410.2616,N,02824.795...
  52-67     16  binary  PNG signature at 0x6800 (sector 52)
  68-69      2  zero
```

Reading it: sectors 0-2 and 48-51 are NMEA `$GPRMC` GPS logs padded with newlines. Sectors 22-33 are a complete JPEG, FFD8 at 0x2c00 (sector 22 start) through FFD9 in sector 33: a small engine-room camera frame, a separate file and not the chart. The PNG signature starts at the top of sector 52 (0x6800 = 52 × 512), but the PNG's closing `IEND` chunk is back in sector 47, *before* the header. The PNG is not stored in one piece, so a contiguous carve from sector 52 cannot reach a real end.

*2. Size the PNG from its header.* The PNG header states the exact file length, which tells us how many sectors to collect. Dump 48 bytes at 0x6800:

```sh
xxd -s 0x6800 -l 48 recorder-sectors.img
```
```
00006800: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00006810: 0000 02f8 0000 0208 0802 0000 0094 d20d  ................
00006820: ad00 0058 6649 4441 5478 9ced dd77 7c53  ...XfIDATx...w|S
```

IHDR carries `00 00 02 f8` × `00 00 02 08` = 760 × 520, bit depth 8, color type 2 (RGB). The next chunk is an IDAT of `00 00 58 66` = 0x5866 = 22,630 bytes, its data starting with the zlib header `78 9c`. Assuming this is the only IDAT (step 3 confirms it, since the chunk inflates to the full image), the file is 8 (signature) + 25 (IHDR) + 12 + 22,630 (IDAT) + 12 (IEND) = **22,687 bytes = 45 sectors**.

The header run 52-67 is only 16 sectors, so 29 more sit elsewhere. The unclaimed binary runs are 3-20 (18), 35-41 (7) and 44-47 (4): exactly 29. Run 44-47 holds the `IEND` (its type field at 0x5e97 is followed by a 4-byte CRC, ending the PNG at 0x5e9f, 159 bytes into sector 47), so it goes last. That leaves the order of the three middle pieces open.

*3. Order the fragments with the PNG's own checks.* A PNG can validate itself without any external feedback. Each chunk ends with a CRC-32 over its type and data; the IDAT payload is a zlib stream ending in an Adler-32 checksum that must inflate to exactly `height × (1 + 3×width)` bytes for 8-bit RGB (one filter byte per row plus three bytes per pixel). Glue the header run to each of the six orderings of the three candidate runs and let the checks decide:

```python
import itertools, struct, zlib
head = sectors(52, 67)
pieces = {"3-20": sectors(3,20), "35-41": sectors(35,41), "44-47": sectors(44,47)}
idat_len = struct.unpack(">I", head[33:37])[0]          # 22630
raw_len  = 520 * (1 + 3*760)                             # 1,186,120
for order in itertools.permutations(pieces):
    blob = head + b"".join(pieces[n] for n in order)
    idat = blob[41:41+idat_len]
    crc_ok = zlib.crc32(b"IDAT"+idat) == struct.unpack(">I", blob[41+idat_len:45+idat_len])[0]
    try: inflated = len(zlib.decompress(idat))
    except zlib.error: inflated = None
    # keep the order where crc_ok and inflated == raw_len
```
```
760x520 RGB, IDAT 22630 bytes, PNG 22687 bytes, 1186120 bytes once inflated
52-67, 3-20, 35-41, 44-47  CRC ok   inflate: 1186120 bytes
52-67, 3-20, 44-47, 35-41  CRC bad  inflate: Error -3 ... incorrect data check
52-67, 35-41, 3-20, 44-47  CRC bad  inflate: Error -3 ...
52-67, 35-41, 44-47, 3-20  CRC bad  inflate: Error -3 ...
52-67, 44-47, 3-20, 35-41  CRC bad  inflate: Error -3 ...
52-67, 44-47, 35-41, 3-20  CRC bad  inflate: Error -3 ...
```

Exactly one order passes both checks: **52-67, 3-20, 35-41, 44-47**. The file starts near the end of the flash and wraps to the beginning, the way a recorder's ring buffer fills. A wrong order is not obviously broken at a glance, because the top of the chart always comes from the header run; only the bottom rows go bad, and that is exactly where the key is printed. Cutting the valid blob just after `IEND` gives the 22,687-byte `chart.png`.

*4. Read the recovery key.* Open `chart.png`: it shows the chart with a "LAST FIX" marker and a "RECOVERY KEY (transcribe exactly):" panel at the bottom. OCR it:

```sh
tesseract chart.png - 2>/dev/null
```
```
VDR CHART FRAME — RECOVERED
LAST FIX
RECOVERY KEY (transcribe exactly):
CSCTF{flotsam_0e91019a8e70267f550895930247d088}
MV ORTELIA - frame Ox1A4 - reconstructed from fragmented sectors
```

OCR mangles characters (it read the footer's `0x1A4` as `Ox1A4`), so pull the key with a strict regex that only accepts a lowercase 32-character hex tail, and cross-check it against the same panel read from an upscaled, inverted crop:

```sh
tesseract chart.png - 2>/dev/null | grep -oE 'CSCTF\{[a-z]+_[0-9a-f]{32}\}'
```
```
CSCTF{flotsam_0e91019a8e70267f550895930247d088}
```

**Why it works**

Losing the controller loses the map of which sectors belong to which file, but not the data in them. The PNG is still all there in 512-byte pieces, just out of order. Its header fixes the exact file length, so the number of sectors to find is known, and the unclaimed binary runs add up to exactly that. The chunk CRC-32, zlib's Adler-32 and the known inflated size turn "does this order look right" into a yes/no test that only one arrangement passes, so the reassembly needs no guessing and no submission feedback. A naive contiguous carve from sector 52 still "opens" because the top of the image comes from the header run, but the bottom rows, where the key is, are corrupt: the brief's "a file that opens is not the same as a file that is whole."

**Validation / reproduction**

Exactly one of the six orderings passed the IDAT CRC-32, the zlib Adler-32 inflate, and the inflated-size check; the other five failed both the CRC and the zlib check. The OCR'd key was regex-checked against the expected format and matched what is visible in the chart, with a second read from an upscaled, inverted crop confirming the hex. The flag was accepted on first submission.

Reproduction summary: (1) confirm 70 sectors; (2) map runs and spot the JPEG decoy at sector 22, the PNG signature at 0x6800 and the `IEND` at 0x5e97; (3) read IHDR for 760×520 and IDAT length 0x5866, giving a 22,687-byte / 45-sector file; (4) fix 52-67 first and 44-47 last, brute the six middle orders against CRC + inflate (only 52-67, 3-20, 35-41, 44-47 passes); (5) cut at `IEND` and OCR the key. Gotchas: the `.swp`-style temptation here is the sector order, not the extension; don't trust the contiguous carve because it renders; and sanitize OCR output with the hex regex rather than transcribing by eye.
