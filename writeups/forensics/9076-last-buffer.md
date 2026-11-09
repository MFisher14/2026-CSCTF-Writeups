# Last Buffer

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}`

**Challenge**

An endpoint collector held two Vim recovery files for the same incident note: a periodic snapshot and the one grabbed when the shell dropped. Both restore cleanly, but only one came from the shell that died during the response window; the other is an earlier drill revision. The handout, `last-buffer-handout.zip` (3,270 bytes), contains two 12 KiB Vim swap captures (`incident-2026-10-07.md.swp` and `.md.swo`, renamed by the collector, which dropped the leading dot from the hidden names), the saved note `incident-2026-10-07.md`, `case-context.json`, an audit timeline, a shell journal, and `vim-swap-layout.md`. Recover both buffers, work out which one came from the shell that mattered, and return its encoded read-back proof.

**Approach**

*1. Fix the response window from the case material.*

```sh
python3 -m json.tool case-context.json
cat audit-timeline.jsonl shell-journal.jsonl
```

`case-context.json` sets the crash window to 02:19:30Z–02:20:00Z on `pts/4`, names the saved file, and states that the collector removed the leading dot from both captures. The timeline shows two Vim sessions editing the note:

- **PID 8124 on `pts/7`** started at 02:10:03, its swap was grabbed by a periodic EDR snapshot at 02:11:51, and the editor exited cleanly (`PROC_EXIT success`) at 02:12:18.
- **PID 8442 on `pts/4`** started at 02:18:04, wrote its swap at 02:19:38, was killed by SIGHUP at 02:19:46 when the link reset, and was captured as a disconnect snapshot a second later. That is the shell that died inside the window.

The journal also records the `pts/4` user running `sha256sum incident-2026-10-07.md` at 02:18:31, producing `01c2a034f1a47e4c...`. That gives a second, independent check: the buffer from the dead shell should be built on exactly that file.

*2. Ignore the extensions.* Both captures came from the same hidden `.incident-2026-10-07.md.swp` path, so the `.swp`/`.swo` names are the collector's, not Vim's. Vim's usual convention (`.swp` for the first editor, `.swo` for a second) would tempt you to treat the `.swo` as the newer buffer, and here that is the wrong one. The real link to a process lives in the swap header.

*3. Recover both buffers non-interactively.* Give `-r` the swap file directly; there is no need to rename it back:

```sh
vim -Nu NONE -i NONE -n -es -r incident-2026-10-07.md.swp -c '%p' -c 'qa!' > out/swp.md
vim -Nu NONE -i NONE -n -es -r incident-2026-10-07.md.swo -c '%p' -c 'qa!' > out/swo.md
```

`-Nu NONE -i NONE` skips vimrc and viminfo, `-n` stops Vim writing its own swap, `-es` runs silent batch, `%p` prints the recovered buffer and `qa!` quits without saving. The `.swp` recovers:

```
revision_id: INC-4471/R18
base_file_sha256: 01c2a034f1a47e4cb5536d66394c4774a1f1c568ff4e34c0de7f654aa42bc849
status: UNSAVED-AT-DISCONNECT
authorization_encoding: base64url
authorization_b64: Q1NDVEZ7bGFzdF9idWZmZXJfNDA1MWM5ZjZiMGQ5NjIyNDc5Nzg1ZjYxM2IwNjM5MTZ9
```

and the `.swo`:

```
revision_id: INC-4471/R16-DRILL
base_file_sha256: a5bcac6de8153876627fd1928b9f32060714d7280a07598f2f8ef70535f07d19
status: PERIODIC-SNAPSHOT
authorization_b64: cmV0aXJlZC10cmFpbmluZy1yZWFkYmFjay0xNg
```

Both carry an `authorization_b64` field. The in-note labels already point one way, but they are only text typed into the buffer; the attribution has to come from the swap header and the timeline.

*4. Tie each swap to its Vim process through block 0.* A Vim swap file starts with block 0, written when the swap is created: magic `b0`, the page size at offset 12, the owning PID as a little-endian u32 at offset 24, then the user name at offset 28, host at 68 and original path at 108 (`vim-swap-layout.md` lists the same offsets). Read the header, look the PID up in the timeline, and compare each note's `base_file_sha256` against the SHA-256 of the saved note:

```python
b0 = open(swap, "rb").read(1024)
assert b0[:2] == b"b0"
pid  = struct.unpack_from("<I", b0, 24)[0]
host = b0[68:108].split(b"\0")[0].decode()
path = b0[108:1008].split(b"\0")[0].decode()
```
```
incident-2026-10-07.md.swp
  block 0:   pid 8442, opnight@noc-jump-1:/home/opnight/incident-2026-10-07.md
  timeline:  pts/4 02:19:38 SWAP_WRITE, 02:19:46 ANOM_ABEND, 02:19:47 SWAP_SNAPSHOT
  base file: 01c2a034f1a47e4c... matches the saved note

incident-2026-10-07.md.swo
  block 0:   pid 8124, opnight@noc-jump-1:/home/opnight/incident-2026-10-07.md
  timeline:  pts/7 02:11:51 SWAP_SNAPSHOT, 02:12:18 PROC_EXIT
  base file: a5bcac6de8153876... does not match
```

The `.swp` carries PID 8442, the shell that died on `pts/4` inside the window, and its base hash matches both the saved note on disk and the `sha256sum` the user ran on `pts/4`. The `.swo` carries PID 8124, the earlier `pts/7` session that exited cleanly, labeled `R16-DRILL`, with a base hash that does not match. Two independent facts (PID/terminal/exit-cause and base-file hash) agree, so the `.swp` buffer is the one from the shell that mattered.

*5. Decode the proof.* The `.swp` buffer's `authorization_b64` is base64url; decode it:

```python
base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
```

The `.swp` value decodes straight to a complete `CSCTF{...}`:

```
CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}
```

The `.swo` value decodes to `retired-training-readback-16`, a plain-text drill decoy; it is not a flag and must not be wrapped in `CSCTF{}`. The real proof already decodes to a full flag frame, so it is submitted as-is.

**Why it works**

A Vim swap file's block 0 records the PID of the Vim process that created it, along with the user, host and original path, and `vim -r` rebuilds the unsaved buffer from the data blocks behind it. The audit timeline maps those PIDs to terminals and exit causes, so the header ties each buffer to one shell: only PID 8442, the Vim on `pts/4`, died by SIGHUP at 02:19:46 inside the 02:19:30–02:20:00 window, and only the `.swp` carries that PID. Its `base_file_sha256` also matches the file the user had just hashed, a second, independent confirmation. Neither the filenames the collector assigned nor the note's own `R18`/`R16-DRILL` labels are needed; the process attribution carries the whole decision.

**Validation / reproduction**

During the event, the team's automated intake pass (recursive extraction plus a flag hunt that decodes encodings) pulled the only `CSCTF{...}`-shaped candidate out of the swap data. It submitted that candidate about 20 seconds after intake started, and it was accepted on first submission. The PID/timeline/hash attribution above is the full reasoning for why that buffer is the right one; the other buffer's proof decodes to `retired-training-readback-16`, not a flag frame, so the two could not be confused.

Reproduction summary: (1) unzip and read the case context, timeline and journal to fix the 02:19:30–02:20:00Z window on `pts/4`; (2) recover both swaps with `vim -r` in batch mode; (3) parse block 0 of each swap for its PID and match it to the timeline; (4) confirm the chosen buffer's `base_file_sha256` matches the saved note and the journal's `sha256sum`; (5) base64url-decode its `authorization_b64`. Gotchas: don't trust the `.swp`/`.swo` extensions or the in-note revision labels; the `.swo` proof is a deliberate decoy; and the recovered buffer is named after `/home/opnight/incident-2026-10-07.md`, so quit with `qa!` rather than writing it out.
