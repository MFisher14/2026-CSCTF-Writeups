# Operation Dawn: The Reconnaissance Plate

> Misc · Easy · Created by Terminal43 (Operation Dawn)  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{11_the_guns_behind_the_ridge_3f8c21}`

**Challenge**

> Operation Dawn, annex entry 11. We recovered a reconnaissance plate from an overrun Ash observation post. The photograph itself is unremarkable, but our interpreters are certain the annotation we need was carried out on it. Recover it.

One attachment, `recon-plate.png` (110,412 bytes): a 256×256 RGB PNG with no connection info, so it is fully offline. The briefing's phrasing — the photo is unremarkable but the annotation was "carried out on it" — points at steganography in the pixels rather than the visible image. Tooling is a short Python LSB-extraction script with Pillow plus stdlib `zlib`/`tarfile`.

**Approach / walkthrough**

1. **Rule out the container.** The PNG `info` dict is empty (no text, EXIF, or gamma chunks), and the chunk walk gives only `IHDR (13)`, two `IDAT`s and `IEND (0)` with **0 bytes after IEND**. Nothing is hidden in the file structure, so the payload has to be in the sample values.

2. **Survey the bit planes.** Counting set bits per plane over all 256·256·3 = 196,608 R/G/B samples: planes 7..2 look like a natural photo (about 50% ones each), but the two lowest planes are almost empty — plane 1 has 1,146 ones and plane 0 has 1,145, roughly 0.6%. A natural photo never has ~0.6% ones in its LSB; the two low planes were deliberately cleared and then written. That is the key observation, and it means *two* planes need decoding, not one.

3. **Decode each plane.** The layout that parses cleanly on both planes: samples in R,G,B interleaved order, pixels in raster order, bits packed MSB-first into bytes, then a 4-byte big-endian length prefix, then that many bytes of gzip, which decompresses to a tar of `plate/{caption,grid,annotation}.txt`:

   ```python
   # run as: python -I extract.py recon-plate.png
   im = Image.open(sys.argv[1])
   flat = [c for p in im.getdata() for c in p[:3]]       # R,G,B interleaved, raster
   def plane_bytes(bit):
       bits = [(v >> bit) & 1 for v in flat]
       out = bytearray()
       for i in range(0, len(bits)//8*8, 8):
           b = 0
           for j in range(8):
               b = (b << 1) | bits[i+j]                   # MSB-first
           out.append(b)
       return bytes(out)
   for bit in (0, 1):
       by = plane_bytes(bit)
       n = struct.unpack('>I', by[:4])[0]                # BE length prefix
       tar = tarfile.open(fileobj=io.BytesIO(gzip.decompress(by[4:4+n])))
       # ... read members in memory only, never extracted to disk ...
   ```

   The tar is read in memory only, never written to disk, which avoids any path-traversal risk from the untrusted archive.

   **Bit plane 0** (length 291), the decoy:
   ```
   caption.txt    : Range card practice plate. Not for action. Plate 2 of 9.
   grid.txt       : grid 41-D  elev 540  bearing 075  range 1200
   annotation.txt : DRILL SERIAL 11 HOLD THE RIDGE LINE UNTIL RELIEVED CODE 48B473
   ```

   **Bit plane 1** (length 290), the real recon annotation:
   ```
   caption.txt    : North ridge, 0500. Low cloud over the valley. Plate 7 of 9.
   grid.txt       : grid 41-D  elev 540  bearing 075  range 1200
   annotation.txt : RECON SERIAL 11 THE GUNS BEHIND THE RIDGE CODE 3F8C21
   ```

   On both planes every byte after the `4+n` payload is zero, so the two tars account for all the non-zero low bits and there is no third layer.

4. **Choose the real plate.** The challenge is built so the *first* plane most LSB tools default to (bit 0) gives a plausible, well-formed annotation with a six-hex code — a solver who stops there submits the wrong flag. Two signals mark bit 0 as the decoy: the caption "Range card practice plate. Not for action." and the annotation prefix `DRILL SERIAL 11`. Bit plane 1 is captioned as a real field photo and prefixed `RECON SERIAL 11`, matching the "reconnaissance plate" title and "the annotation we need." Both plates carry serial 11, matching "annex entry 11."

5. **Build the flag from the series template.** The Operation Dawn annex series uses a fixed flag template — `CSCTF{<entry>_<lowercase words>_<six-char check group>}` — confirmed from two sibling challenges in our workspace: annex entry 01 (challenge 9151, *The Courier's Keys*), solved flag `CSCTF{01_advance_on_the_mill_a7c3f1}`, gives the shape; annex entry 17 (challenge 9096, *The Shared Model*) states it in its brief ("lowercase words joined by underscores and ending in a six-character check group"). Applied to entry 11 — entry `11`, annotation words after the serial `THE GUNS BEHIND THE RIDGE` → `the_guns_behind_the_ridge`, check group `CODE 3F8C21` → `3f8c21`:

   ```
   CSCTF{11_the_guns_behind_the_ridge_3f8c21}
   ```

**Why it works**

The challenge hides two independent payloads in two separate bit planes and relies on the solver stopping at the first. Bit 0 decodes cleanly to a plausible annotation, but its own text labels it a drill "not for action"; the real order is one bit plane deeper. Reading *all* the cleared low bits and checking that every one is consumed by exactly the two tar payloads is what tells you there is a second layer and nothing beyond it.

**Validation / reproduction**

Both bit planes decompressed to valid gzip/tar archives with intact length prefixes (291 and 290), and all non-zero low bits were consumed by exactly these two payloads, so nothing was left unexplained. Re-running the script while writing up reproduced both payloads byte-for-byte, the exact per-plane bit counts (plane 0 = 1,145, plane 1 = 1,146, planes 2..7 = 98,458 / 98,503 / 98,415 / 99,285 / 94,724 / 104,429), the chunk list, zero trailing bytes, and a level-9 deflate match on both compressed bodies. The caption/annotation text inside the tar confirms which plate is real. The flag was submitted once; its first three tries came back `ratelimited` (account-wide wave pacing, not a verdict), and the same single value was accepted at the retry about 6.5 minutes later. Static analysis only — nothing from the challenge was executed.
