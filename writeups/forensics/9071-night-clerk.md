# Night Clerk

> Forensics · Easy · Mohamed Amine Mzoughi  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{hid_skew_redline}`

**Challenge**

A hostile clerk used a depot terminal to hide a coordination message before isolation, and only the retained stick image survives. We are handed `terminal.dd` (8,388,608 bytes), told to recover the hidden `CSCTF{...}` message from it, and reassured that "other exhibits it mentions are not provided and not needed" and that nothing needs to be run in Office or mounted. That reassurance is load-bearing: the intended key derives from two timing exhibits that are deliberately absent, and the challenge is solvable without them.

Tools: The Sleuth Kit (`fsstat`, `fls`, `icat`), `unzip`, and a short Python script. No mounting, which keeps the untrusted image read-only.

**Approach / walkthrough**

*1. Verify and identify.* After confirming the SHA-256 matches the brief, `mmls` finds no partition table — it is a bare volume. `fsstat terminal.dd` identifies it:

```
File System Type: NTFS
Volume Name: DESK
Size of MFT Entries: 1024 bytes
Range: 0 - 67
```

A tiny 8 MiB NTFS volume labelled `DESK`, Volume Serial `5952AC361A93C77A`, with only 68 MFT entries (range 0–67) and the MFT first cluster at 4. The whole file list is short and Sleuth Kit reads the volume directly from the raw image, so nothing is mounted and the host never touches the filesystem driver.

*2. List every file, including deleted ones.* `fls -r -p terminal.dd` walks the volume and prints full paths; deleted entries carry a `*`:

```
r/r 64-128-2:   README.TXT
-/r * 65-128-2: audit-0214.log
-/r * 66-128-2: night_audit.docx
```

Past the NTFS metadata files and empty reserved records, there are three user files: live `README.TXT` (inode 64) and two **deleted** files, `audit-0214.log` (inode 65) and `night_audit.docx` (inode 66). Their MFT records and clusters are still intact, so `icat` recovers them by inode without mounting:

```sh
icat terminal.dd 64 > out/README.TXT
icat terminal.dd 65 > out/audit-0214.log
icat terminal.dd 66 > out/night_audit.docx
```

*3. Read the recovered text.* `README.TXT` is the cover story: "Shift log clear. … No redline was saved." The deleted log `audit-0214.log` is the clerk's actual recipe:

```
Photo: desk.jpg
Capture: front_desk.pcapng
The Word file on this stick is a redline. Read the insertion, not the paragraph on screen.
DateTimeOriginal plus OffsetTimeOriginal is UTC.
Subtract that UTC time from the NTP transmit timestamp.
The difference, in whole seconds, XORs each ciphertext byte.
Hex-decode the tracked insertion first.
```

So: the Word file is a *redline* (tracked changes); the message is the **tracked insertion**, not the visible paragraph; the insertion is hex; and each byte is XORed with one key byte — a clock-skew value in seconds. The intended key would come from `desk.jpg`'s EXIF time and an NTP transmit timestamp in `front_desk.pcapng`. Those two files are **not** in the image — a byte-signature search for JPEG/pcapng markers finds only their names inside this log — and the brief confirms they are not needed. Ignore `README.TXT`'s "No redline was saved" (the cover story) too.

*4. Pull the tracked insertion from the .docx.* A .docx is a ZIP of XML parts; Word's revision marks live in `word/document.xml` (`<w:del>…<w:delText>` for deletions, `<w:ins>…<w:t>` for insertions). Reading it with `unzip -p`:

```xml
<w:p><w:r><w:t>Shift summary clean. Nothing unusual at the desk.</w:t></w:r></w:p>
<w:p>
  <w:del w:id="1" w:author="M. Keene" ...><w:r><w:delText>The key locker was checked at the start of shift.</w:delText></w:r></w:del>
  <w:ins w:id="2" w:author="M. Keene" ...><w:r><w:t>7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44</w:t></w:r></w:ins>
</w:p>
```

The visible paragraph ("Shift summary clean…") is the decoy. The tracked change by "M. Keene" deletes an innocent sentence and inserts the 46-character hex string `7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44` — 23 bytes. The other parts carry nothing (`settings.xml` just enables `<w:trackRevisions/>`; `people.xml`/`core.xml` repeat the desk line; `word/media/padding.bin` is 8192 bytes of `0xa5` filler).

*5. Recover the flag with a known-plaintext byte.* The ciphertext decodes from hex to `b'zjzm\x7fBQP]fJR\\NfK\\]UPW\\D'`. A single-byte XOR key is fully determined by one known plaintext byte, and flags begin `CSCTF{`. The first ciphertext byte is `0x7a`; `0x7a ^ 'C'` (`0x43`) = `0x39` = 57. Testing all 256 keys and keeping those that produce the `CSCTF{` prefix:

```python
ct = bytes.fromhex("7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44")
keys = [k for k in range(256) if bytes(b ^ k for b in ct).startswith(b"CSCTF{")]
# keys == [57];  key = 0x39 = ct[0] ^ ord('C')
print(bytes(b ^ 57 for b in ct).decode())   # CSCTF{hid_skew_redline}
```

Only key 57 yields the prefix, and the full 23-byte plaintext decodes as readable text ending in `}`:

```
CSCTF{hid_skew_redline}
```

The value 57 is also exactly the "difference in whole seconds" the recipe describes — the clock skew — so the two independent paths agree. The decoded plaintext `hid_skew_redline` even names the technique: a tracked-change (redline) insertion hidden behind a single-byte clock-skew XOR.

**Why it works**

Deleting a file on NTFS only clears the MFT record's in-use flag and the cluster bits in `$Bitmap`; the record (name, data runs) and the data stay on disk until reused, so `fls` still lists the deleted files and `icat` rebuilds them from their inode numbers. OOXML stores tracked revisions as plain `<w:del>`/`<w:ins>` elements in `document.xml`, so the "hidden" insertion is readable straight from the XML without Office. The payload is hex of a single-byte XOR; the intended key is a 57-second skew between a photo and a packet capture that were never supplied, but a one-byte key is pinned by one known plaintext byte, which makes the missing timing exhibits unnecessary.

**Validation / reproduction**

Of all 256 single-byte keys, only 57 produces the `CSCTF{` prefix, and with that key the entire 23-byte plaintext is readable and closes with `}` — a second check beyond the prefix match. A 57-second skew also fits the recipe's "whole seconds" story. Accepted on the first submission.

Reproduction in short: `fsstat`/`fls` the bare NTFS image, `icat` inodes 64/65/66, read the log for the recipe, `unzip -p … word/document.xml` to pull the `<w:ins>` hex, hex-decode to 23 bytes, and brute the single XOR byte against the `CSCTF{` crib (key 57). Gotcha: do not chase `desk.jpg` or `front_desk.pcapng` — they are not in the image and are not needed; the known-plaintext byte makes the key fully determined on its own.
