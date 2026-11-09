# Dawn Array

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{dawn_12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb}
```

The form is `CSCTF{dawn_<64 lowercase hex>}`, where the hex is a SHA-256 the procedure defines.

**Tools used**

Codex (run under human guidance), which rebuilt the array, ran the DP-7 checker end to end, and submitted
the accepted flag. Tooling: a short Python md-superblock parser and RAID-5 rebuild, Sleuthkit `fls`/`icat`,
`sqlite3`, and a Python TCP-stream reassembler for the pcapng.

**Challenge**

Dispatch gateway E2 of the (fictional) Rovenqara Rail Continuity Authority issued conflicting
turnout-release records and was then powered off. Its staging volume sat on a four-member Linux md RAID-5
array; one member is lost and three raw members survive. The task is to rebuild the volume read-only, apply
the gateway's own dispatch procedure (stored on that volume) to find the controller-acknowledged release
witness, and report it in the form the procedure defines. The brief stresses that this is a constructed
case built on *real* md RAID-5, ext4, SQLite WAL, RFC 5424 and HTTP/1.1 — every layer is a genuine format
to parse.

`dawn-array.zip` holds three 40 MiB raw md members (`acq-1/2/3.raw`), a case sheet warning that the file
labels say nothing about array position, and a helper `tools/raid5_extract.py` that reads no metadata. The
helper's usage example uses a 64 KiB chunk, which is the wrong chunk size for this array.

**Approach / walkthrough**

*1. Geometry from the superblocks.* Each member carries an **md v1.2** superblock at byte offset 4096. A
short static `struct` parser (no challenge code run) reads the same geometry on all three members:

| Field | Offset | Value |
|---|---|---|
| magic | 0x00 | `0xa92b4efc` |
| level | 0x48 | 5 |
| layout | 0x4C | 2 = left-symmetric |
| chunksize | 0x58 | 64 sectors = 32,768 B |
| raid_disks | 0x5C | 4 |
| data_offset | 0x80 | 2048 sectors = 1 MiB |
| data_size | 0x88 | 79,872 sectors per member |

Each member's role comes from its `dev_number` (offset 0xA0), used as an index into the `dev_roles` table
(offset 0x100), which reads `[0, 0xffff, 2, 0xffff, 3, 0xffff, …]`. That gives acq-1 → role 0, acq-3 →
role 2, acq-2 → role 3, so **role 1 is the lost member**. The file numbering deliberately does not match
role order. Logical array size = `(4 - 1) × 79872 × 512` = **122,683,392 bytes**.

*2. Rebuild read-only.* The supplied reassembler's CLI was checked statically; during the event the solver
used its own left-symmetric de-striping loop instead. For each stripe the parity role is `N-1-(s mod N)`,
and the data roles follow it, wrapping around; role-1 chunks are rebuilt by XORing the other three members:

```python
N, C, OFF = 4, 32768, 1 << 20
for s in range(79872 * 512 // C):            # stripe index
    p = N - 1 - (s % N)                      # left-symmetric parity role
    for i in range(N - 1):
        r = (p + 1 + i) % N                  # data roles follow parity, wrapping
        chunk = member[r][OFF+s*C : OFF+(s+1)*C] if r != 1 else \
                xor(member[0], member[2], member[3] at the same offset)   # rebuild role 1
        out.write(chunk)
```

The output of 3 × 79,872 × 512 bytes shows the ext4 magic `53 ef` at image offset 0x438 and the volume
label `rrca-staging` at 0x478. The equivalent invocation of the supplied helper, if used, is:

```
python3 tools/raid5_extract.py --member 0:acq-1.raw --member 2:acq-3.raw --member 3:acq-2.raw \
  --member-count 4 --chunk-bytes 32768 --data-offset-bytes 1048576 \
  --array-bytes 122683392 --layout left-symmetric --output array.img
```

*3. Extract (no mount, no root).* `fls -r -p array.img` lists the volume; each file is pulled with `icat`:

| inode | path |
|---|---|
| 20 | `usr/share/doc/…dispatch-procedure.txt` — DP-7, revision 3 |
| 21 / 24 / 25 | `var/lib/rrca/dispatch.sqlite` + `-wal` + `-shm` — the ledger |
| 23 | `var/log/rrca/dispatch-gateway.syslog` — RFC 5424 gateway events |
| 22 | `var/log/rrca/controller-access.pcapng` — gateway↔controller HTTP/1.1 |

*4. Read DP-7.* It defines the ledger schema; the four syslog phases (`PREPARE_SENT → RESPONSE_OBSERVED →
READBACK_OBSERVED → COMMIT_WRITTEN`); the two-request HTTP grammar per cycle (`POST /v1/reservations` then
`GET /v1/readback`); rules Q1–Q5; and the witness format. A cycle qualifies only if all five rules hold —
Q1 pairs one ledger row with one record per phase on shared IDs, Q2 matches the POST and its 201 response
to the ledger, Q3 checks the response revision and nonce against the ledger and RESPONSE_OBSERVED, Q4
checks the HTTP readback and syslog READBACK_OBSERVED against the ledger, Q5 requires the phases in order.
The witness is `SHA-256("RRCA-DAWN-WITNESS-v1\n" + one line per qualifying cycle in ascending
gateway_seq)`, each line being
`cycle_id|request_id|prepare_revision|reservation_nonce|release_register|release_value\n`.

*5. Apply the WAL.* DP-7 says rows still in the WAL are part of the ledger. The base file alone has 95
rows. With the 134-frame WAL applied — the last frame is a commit and all checksums are valid — it has
128. We worked on copies so the evidence files were never modified:

```
sqlite3 "file:dispatch.sqlite?immutable=1" "select count(*) from cycles"   -> 95   (base only)
sqlite3 <copy with -wal/-shm>  "select count(*) from cycles"                -> 128  (WAL applied)
```

*6. Reassemble HTTP.* The pcapng holds **128 TCP connections** to the controller, with no retransmitted or
out-of-order segments. Each stream splits cleanly on `Content-Length` into exactly two requests and two
responses.

*7. Cross-check and hash.* Every ledger row was tested against the syslog and the HTTP exchange. The decoys
each break exactly one link: 29 have a response nonce that does not match the ledger / RESPONSE_OBSERVED,
28 a mismatched revision, 24 a mismatched HTTP readback, and 31 a mismatched syslog readback. **Sixteen
cycles pass all five rules** (gateway_seq `14, 15, 34, 35, 55, 69, 78, 79, 80, 83, 85, 87, 95, 103, 110,
117`), and their lines are hashed into the 64-hex witness:

```
12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb
```

Both the 95/33 row split and the 29/28/24/31 decoy breakdown were independently reproduced for this
write-up (rebuild the array, extract the ledger, parse the syslog and reassemble the 128 HTTP
connections, then evaluate Q1–Q5). The base SQLite file holds 95 rows; applying the 134-frame WAL (last
frame a commit) raises the count to 128, so 33 rows live only in the WAL. Classifying the 112
non-qualifying cycles by the single link each decoy breaks gives: **29** with a corrupted reservation
**response nonce** (the HTTP 201 response carries a nonce that disagrees with the ledger and the
RESPONSE_OBSERVED record; the wrong nonce also propagates into that cycle's HTTP readback), **28** with
a corrupted response **revision** (same single wire corruption, propagated into the readback), **24**
with a corrupted **HTTP readback** alone (the `release_register` field, response otherwise clean), and
**31** with a corrupted **syslog READBACK_OBSERVED** alone (the `release_value` field). 29+28+24+31+16 =
128, and the 16 clean cycles are seq 14,15,34,35,55,69,78,79,80,83,85,87,95,103,110,117 — the same set
whose witness hashes to the accepted flag.

**Why it works**

There are three layers of "looks committed but isn't." The file names lie about RAID order, so the role
mapping has to come from the superblock, not the labels. The base SQLite file hides 33 committed rows that
exist only in the WAL. And a 201 response or a COMMIT_WRITTEN record does not prove acknowledgement: the
witness counts only cycles where the ledger, the wire capture and the gateway log all agree on nonce,
revision, register and value. The decoys each break exactly one of those links, yet all of them look
committed.

**Validation / reproduction**

The rebuild was checked by the ext4 magic and label appearing at the expected offsets. The witness is 1,733
bytes: a 21-byte header plus 16 × 107-byte lines, matching DP-7's fixed field widths. Re-running Q1–Q5
independently for the write-up gave the same 16 cycles and the same hash, which equals `flag.txt`.

Reproduction summary: parse the three md superblocks for geometry and roles; de-stripe left-symmetric with
32 KiB chunks and a 1 MiB data offset, rebuilding role 1 by XOR; `fls`/`icat` the ext4; read DP-7; apply
the WAL to reach 128 ledger rows; reassemble the 128 HTTP connections by `Content-Length`; apply Q1–Q5 to
isolate the 16 qualifying cycles; SHA-256 the DP-7 witness string. Gotchas: ignore the helper's 64 KiB
example chunk (the real chunk is 32 KiB); always apply the WAL before counting rows. The first three
submissions came back `ratelimited` (platform pacing, never judged); the same single value was accepted on
the fourth send.
