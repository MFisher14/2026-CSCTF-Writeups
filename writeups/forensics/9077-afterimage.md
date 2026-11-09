# Afterimage

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{6f86acdd1d10e0d8a5a541bb}`

**Challenge**

A duty operator screenshotted their terminal, cropped the bottom off to hide
something sensitive, and posted the result to a shared channel. The handout is
that one picture, `relay-capture.png` (520×340, 8-bit RGB), a terminal capture
from "FIELD RELAY 7". It looks fine: its last visible line reads `recovery panel
retained in prior frame`, and then the image stops. The brief tells you plainly
that "the crop changed what you see, not what the file still carries" — recover
what was cropped away and read the station recovery key. The flag format is
`CSCTF{message}`.

**Approach / walkthrough**

*1. Confirm the file is intact as a PNG but carries extra bytes.* `file` reports
nothing unusual:

```sh
file relay-capture.png
# relay-capture.png: PNG image data, 520 x 340, 8-bit/color RGB, non-interlaced
```

`pngcheck` is the tool that notices the problem:

```sh
pngcheck relay-capture.png
# relay-capture.png  additional data after IEND chunk
# ERROR: relay-capture.png
```

A PNG is an 8-byte signature followed by chunks, each a 4-byte length, 4-byte
type, the data, and a 4-byte CRC. `IEND` is supposed to be the last chunk, and
every viewer stops reading there, so anything after it is invisible on screen but
still on disk.

*2. Map the chunks and recognize the pattern.* Search the raw bytes for the two
chunk names that matter:

```sh
grep -obaE 'IDAT|IEND' relay-capture.png
```

The output shows a run of `IDAT` chunks, an `IEND` at **byte 14255**, and then —
instead of end-of-file — twelve more `IDAT` chunks and a second `IEND` whose CRC
finishes exactly at the end of the 26,174-byte file (the second `IEND` type field
is at 26166; 26166 + 8 = 26174). The real image ends 8 bytes after the first
`IEND` (type + CRC), at **byte 14263**.

The trailing chunks keep the same 1036-byte spacing as the leading ones (1024
data bytes + 12 bytes of chunk overhead). The first `IDAT` is at offset 37, so
chunk boundaries fall at 37 + n×1036; the chunk at **14541** is 37 + 14×1036,
i.e. it is the 15th `IDAT` of a larger, uncropped image. The twelve trailing
chunks are chunks 15–26 of the original screenshot. The crop tool wrote the
smaller cropped PNG over the start of the old file and never truncated it. This
is the aCropalypse bug: CVE-2023-21036 in the Pixel Markup editor and
CVE-2023-28303 in the Windows Snipping Tool.

The 274 bytes between the end of the cropped image (byte 14263) and the length
field of the first complete trailing chunk (byte 14537) are the tail of the
original's 14th `IDAT` payload plus its 4-byte CRC — the header of that 14th
chunk was overwritten by the new PNG, so only its end survives.

*3. Reassemble the surviving compressed stream.* All `IDAT` data together is one
zlib/deflate stream holding every scanline top to bottom. We only have the end of
the original stream, so inflating from the start is impossible. But deflate is a
chain of independently-startable blocks, and decoding can begin at any block
boundary. A zlib sync flush leaves an easy-to-spot one: an empty stored block
ending in the bytes `00 00 ff ff`, with the next block starting on the following
byte. The leftover data contains exactly one such marker, at payload offset
**3123**.

The recovery script joins the leftover payloads, raw-inflates from just past that
marker with a zeroed 32 KiB preset dictionary (which stands in for the lost
earlier output in case a block refers back into it), cuts the result into
scanlines, and wraps them in a fresh PNG:

```python
import os, struct, zlib
png = open("relay-capture.png", "rb").read()
width = struct.unpack(">I", png[16:20])[0]

# Walk chunks like a viewer and stop after IEND.
pos = 8
while True:
    length, kind = struct.unpack(">I4s", png[pos:pos+8])
    pos += 12 + length
    if kind == b"IEND":
        break
tail = png[pos:]                       # 11911 bytes follow (pos == 14263)

# Fragment of the overwritten chunk's payload (minus its 4-byte CRC) + full chunks.
first = tail.index(b"IDAT") - 4
stream = bytearray(tail[:first-4])
pos = first
while tail[pos+4:pos+8] == b"IDAT":
    length = struct.unpack(">I", tail[pos:pos+4])[0]
    stream += tail[pos+8:pos+8+length]
    pos += 12 + length                 # leftover IDAT payload: 11751 bytes

start = stream.index(b"\x00\x00\xff\xff") + 4   # deflate block at offset 3123
inflater = zlib.decompressobj(-15, zdict=bytes(32768))
raw = inflater.decompress(stream[start:])

stride = 1 + width*3                   # 1 filter byte + 520*3 = 1561
rows = len(raw) // stride              # 312200 / 1561 = 200
raw = raw[len(raw)-rows*stride:]       # keep whole rows, counted back from the end

def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind+body))

ihdr = png[16:20] + struct.pack(">I", rows) + png[24:29]   # reuse IHDR, new height
os.makedirs("out", exist_ok=True)
open("out/recovered.png", "wb").write(
    b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
```

Running it prints:

```
PNG ends at byte 14263, 11911 bytes follow
leftover IDAT payload: 11751 bytes
deflate block starts at payload offset 3123
inflated 312200 bytes = 200 rows of 520 px, final block reached: True
wrote out/recovered.png
```

**312,200 = 200 × 1561 exactly**, and the inflater reports it reached the final
block (`inflater.eof` is `True`), so the decode is clean and row-aligned.

*4. Read the key.* The stream ends with the image's bottom scanline, so the 200
recovered rows are the bottom of the original screenshot — exactly the strip the
crop removed. Open `out/recovered.png`, or let tesseract read it:

```sh
tesseract out/recovered.png - 2>/dev/null
# RELAY RECOVERY KEY — ROTATE AFTER USE
#
# CSCTF{6f86acdd1d10e0d8a5a541bb}
#
# relay BR-7 / emergency key custody
```

The flag is `CSCTF{6f86acdd1d10e0d8a5a541bb}`.

**Why it works**

Cropping only destroys data if the file is also truncated. The editor rewrote the
file in place with the smaller PNG and left the original length, so the end of the
original compressed pixel stream still sits after the new `IEND`, where no viewer
reads. Deflate decoding can start at any block boundary, and the `00 00 ff ff`
left by a flush marks one on a byte boundary; a zero-filled preset dictionary
covers any back-reference into the part we lost. Because an `IDAT` stream is
written top-to-bottom and ends with the bottom scanline, the bytes we recover line
up as the last 200 rows of the original — precisely the recovery-key panel that
was cropped off.

**Validation / reproduction**

Two self-checks confirm the recovery before OCR: the inflated length divided
evenly into 1561-byte scanlines, and the inflater reported end-of-stream, so the
rows are byte-aligned and complete rather than a lucky partial decode. The rebuilt
PNG then rendered as a coherent panel and tesseract read the `CSCTF{...}` line from
it. Accepted on first submission.

Reproduction, in short: `pngcheck` to spot data after `IEND`; `grep -obaE
'IDAT|IEND'` to see the second `IEND` and the 1036-byte chunk cadence that proves
the trailing `IDAT`s belong to a taller original; concatenate the leftover
payloads; raw-inflate from just after the single `00 00 ff ff` with a zeroed
32 KiB dictionary; slice into 1561-byte rows and wrap in a PNG with the new
height; read the key.

Gotchas: inflate from the byte **after** `00 00 ff ff`, not from the marker
itself. Drop the 4-byte CRC on the leading payload fragment. The preset dictionary
must be present (`zdict=bytes(32768)`) or back-references into the lost prefix
produce garbage. Count scanlines back from the end of the inflated output, since
only the tail of the stream survived and the first partial row may be dropped.
