# Operation Dawn: The Medic's Phone

> Forensics · Medium · Terminal43  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{03_at_platform_two_6f57d7}`

**Challenge**

> Operation Dawn, annex entry 03. A station medic surrendered their phone before boarding. Signals sent the platform assignment through the courier app and then withdrew it; the app now shows only a notice. Recover the assignment from the supplied Android backup.

The attachment is `medic-phone.ab` (2,809 bytes, SHA-256 `41bb4e2b…f979`), an `adb backup` file.

**Approach / walkthrough**

*1. Unwrap the backup.* An `.ab` file is a four-line text header followed by one compressed stream that holds a tar. The header reads magic `ANDROID BACKUP`, version `5`, compression `1` (zlib), encryption `none`, so the payload begins right after the fourth newline and a single `zlib.decompress` yields the tar:

```python
data = open('medic-phone.ab', 'rb').read()
i = 0
for _ in range(4):
    i = data.index(b'\n', i) + 1          # b'ANDROID BACKUP\n5\n1\nnone\n'
open('backup.tar', 'wb').write(zlib.decompress(data[i:]))
```

`tar tvf backup.tar` shows three apps: a courier (messaging) app `org.unit43.courier` with `db/messages.db` **and** a sibling `db/messages.db-wal`, a field-notes app `org.unit43.fieldnotes`, and a radio config `org.unit43.radioset`. The `-wal` file next to the database is the whole challenge.

*2. Survey the phone, working on copies.* `messages.db` runs in WAL mode, and opening the live file with `sqlite3` lets SQLite checkpoint and delete the `-wal` file when the connection closes — which would destroy the evidence. Copy the database out on its own, without the log, and open the copy. Its schema is `messages(id, thread, sender, ts, pb BLOB)` — bodies live in `pb` as blobs. The field-notes DB (dumped read-only, in place) carries the pointer: note 4, "Train", reads *"platform numbers change nightly, always confirm with signals"*. So the assignment came from `signals` through the courier app. The courier preferences also hold a `session_token` stamped `PLACEHOLDER-FAKE-TOKEN-NOT-REAL` — a labeled decoy, not key material.

*3. Decode the message protobufs.* `select hex(pb) from messages where id=1` gives a record whose wire format reads `08 01` (field 1 varint = id), `12 05 7761726432` (field 2 = `ward2`), `18 …` (field 3 = timestamp), `20 01` (field 4 = a flag), and `2A 2F …` (field 5, 0x2f bytes that are not text). Field 5 is a **raw DEFLATE** stream (`zlib.decompress(x, -15)`), which is why plain `strings` finds nothing readable. A small scanner anchors on each `0x08` field-1 tag, parses fields 2–5, and inflates field 5:

```python
TAGS = (0x12, 0x18, 0x20, 0x2a)          # fields 2..5 of the courier Message
# ... walk each 0x08 anchor, read tag/wire-type, collect f[2..5]
body = zlib.decompress(f[5], -15).decode()   # field 5 = raw deflate
```

Run on `messages.db`, it decodes all 16 messages. The ward thread is stretcher logistics; the signals thread at the end reads: 13 `signals` "Order is being cut now. Stand by, do not acknowledge yet.", **14 `signals` "This message was withdrawn by the sender and is no longer available."**, 15 `medic` "Nothing received here. Repeat last, over.", 16 `signals` "Disregard the last. New order to follow. Wait out." Message 14, the one that would carry the assignment, is gone from the app's current data.

*4. Carve the write-ahead log.* "Withdrew" only overwrote row 14 in the main database. SQLite in WAL mode appends page images to the `-wal` file, and the backup still carries an older image of the page that stores the messages. Run the same scanner over the raw bytes of `messages.db-wal`:

```sh
python3 carve.py apps/org.unit43.courier/db/messages.db-wal | grep -o 'CSCTF{[^}]*}'
```

Its message 14 still holds the original body: *"Movement order. Board the hospital train. Assignment follows: CSCTF{03_at_platform_two_6f57d7} Acknowledge on receipt and destroy this message."*

**Why it works**

The courier app stored each message as a protobuf record whose field 5 is a raw-DEFLATE body, so nothing readable shows up in a `strings` sweep until the wire format is recognized. Withdrawing the order overwrote only row 14 in `messages.db`, while an older image of that table's page survived in `messages.db-wal` inside a frame whose commit marker — the database-size field in the frame header, nonzero only on the final frame of a committed transaction — is zero. SQLite treats that frame as an uncommitted transaction and never replays it, so the app and every `SELECT` see only the checkpointed notice. Reading the WAL bytes directly bypasses SQLite's replay logic, and once the custom encoding is recognized the original body comes back.

**Validation / reproduction**

The same scanner decodes all 16 messages from both the database and the WAL. Messages 13, 15 and 16 read identically in both, which shows the parser and the inflate step are correct, and 14 is the only one that changes between them — exactly the message the brief says was withdrawn. The recovered body is a complete sentence carrying the platform assignment, in the thread the field notes point to. Reproduction: unwrap the `.ab`, copy `messages.db` out alone, decode the protobuf/raw-deflate records from both the DB and the `-wal`, and compare message 14. Accepted on the first submission.
