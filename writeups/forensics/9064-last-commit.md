# Last Commit

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{last_commit_40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f}`

**Challenge**

A national land registry's completed restoration export, job `LR-731`, may have carried altered ownership to regional offices before the database was put back to a clean-looking state. We are given the SQLite database and its write-ahead log as a pair (`registry.sqlite` + `registry.sqlite-wal`), the delivery receipt `delivery.csv` (12 parcels in a fixed order), and `export-profile.md`, which defines the export query, its exact byte formatting, and the flag construction. The task is to reconstruct the export *as it stood at the moment the job flipped to `COMPLETED`* — not as the current, restored view shows it — and take its SHA-256. The archive `last-commit.zip` (84,979 bytes) ships with its own SHA-256 so the download can be checked before extraction.

Everything is done with the Python 3 standard library: `struct` to parse the WAL by hand, and `sqlite3` opened read-only to run the export query. No `sqlite3` shell and no database browser are used, deliberately.

**Approach / walkthrough**

*1. Extract, and never open the pair with a real client.* After verifying the archive hash and unzipping, the directory holds `registry.sqlite`, `registry.sqlite-wal`, `delivery.csv`, `export-profile.md`, plus background files (`README.txt`, `provenance.json`, `SHA256SUMS`). The one hard rule: do not open `registry.sqlite` with the `sqlite3` CLI or any browser while the `-wal` is beside it. SQLite would replay the log, and on connection close it would **checkpoint** every logged page into the main file and delete the WAL. The log is the evidence; losing it means re-extracting the archive. All work is on read-only copies.

*2. Read the export profile.* `export-profile.md` pins down what to rebuild. The export job runs inside a single `IMMEDIATE` transaction: it evaluates the query over the receipt's parcels, stages the result, changes `LR-731` from `QUEUED` to `COMPLETED`, and commits — nothing else writes in between. So the delivered export is the profile's query run against the database exactly as it stood at the commit that set `LR-731` to `COMPLETED`. The receipt rows load into a temp table `manifest(job_id, position, parcel_id)` the query joins against. The output is a fixed header line followed by the query rows, fields separated by single TAB bytes, every line (including the last) ended by LF; the SHA-256 of those bytes, in lowercase hex, is the flag body. A digest `26114af3…` near the end of the profile belongs to a formatting example and is a decoy — it is not this case's answer.

*3. Parse the WAL by hand, commit by commit.* A WAL starts with a 32-byte header: magic (`0x377f0682` meaning the checksum words are little-endian 32-bit), page size (4096 here), two salts, and two checksum words over the first 24 bytes. Each frame is a 24-byte header (page number; database size in pages, nonzero only on a commit frame; the two salts; two checksum words) followed by a full page image. The checksum is cumulative — each frame continues the running checksum over the first 8 bytes of its header and its page data — so the first frame that fails to verify ends the valid region. The replay script walks valid frames, groups them into committed transactions (a nonzero db-size field marks a commit), and after each commit builds a standalone database image: the main file with every page overlaid by its newest committed copy. Two header bytes at offsets 18/19 are set to 1 in each copy so SQLite treats the image as rollback-journal mode and never looks for a `-wal`.

The core of the WAL checksum and the frame loop:

```python
def wal_checksum(data, s0, s1, big_endian):
    words = struct.unpack((">" if big_endian else "<") + "%dI" % (len(data)//4), data)
    for i in range(0, len(words), 2):
        s0 = (s0 + words[i]   + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i+1] + s0) & 0xFFFFFFFF
    return s0, s1
# ... per frame:
s0, s1 = wal_checksum(wal[off:off+8] + page, s0, s1, big_endian)
if (s0, s1) != (f_ck1, f_ck2):
    break  # cumulative checksum broken: nothing after this is valid
if db_pages:   # nonzero database-size field = commit frame
    commits.append((pending, db_pages)); pending = []
```

Running it reports `9 valid frames, 6 commits, 0 uncommitted frames`. The database is tiny — page 1 is the schema and each table/index is a single root page (pages 2–9) — so the page name printed per frame names the table it rewrote:

```
commit 1:  frame 1  page 2  parcel
commit 2:  frame 2  page 6  title ; frame 3  page 7  sqlite_autoindex_title_1
commit 3:  frame 4  page 8  export_job ; frame 5  page 9  sqlite_autoindex_export_job_1
commit 4:  frame 6  page 8  export_job
commit 5:  frame 7  page 6  title ; frame 8  page 7  sqlite_autoindex_title_1
commit 6:  frame 9  page 2  parcel
```

*4. Run the export at each commit and read the state.* For each image the script opens it read-only, reads `export_job`, loads the receipt into `manifest`, runs the profile's query, formats TSV with trailing LF, and hashes it:

```
commit  source      LR-731 state  export SHA-256
     0  main file   -             04a47a4f6a9c822d...
     1  frame 1     -             04a47a4f6a9c822d...
     2  frames 2-3  -             40f3b19d5a11601e...
     3  frames 4-5  QUEUED        40f3b19d5a11601e...
     4  frame 6     COMPLETED     40f3b19d5a11601e...  <- LR-731 turns COMPLETED
     5  frames 7-8  COMPLETED     04a47a4f6a9c822d...
     6  frame 9     COMPLETED     04a47a4f6a9c822d...
```

The story is now plain. Commit 1 rewrites the `parcel` page (parcel 1201's district, outside the receipt, so the export is unchanged). Commit 2 rewrites `title` and its index, and the export digest changes to `40f3b19d…`. Commit 3 inserts `LR-731` as `QUEUED`. Commit 4 is the job's own transaction — it only flips `LR-731` to `COMPLETED`, so this is the state the delivered export was taken from. Commit 5 rewrites `title` again, restoring the original rows, and the digest returns to `04a47a4f…` (the registry "looks normal again"). Commit 6 touches another out-of-receipt parcel. A normal open applies all six commits and lands on commit 6, where `LR-731` is also `COMPLETED` but the titles are the restored ones — the deceptive clean view.

*5. Confirm the tampering and hash.* Diffing the commit-6 clean view against the commit-4 export shows four of the twelve parcels (1214, 1202, 1209, 1205) went out with different holders and instrument references, and parcel 1209 was split 6500/3500 instead of 6000/4000:

```
< 1  1214  D-02  P-32089905  HR-3046267890  10000  IN-5373724204
> 1  1214  D-02  P-32089905  HR-1766993918  10000  IN-6941538207
< 4  1209  D-01  P-58783439  HR-3959056687   6000  IN-6674401937
> 4  1209  D-01  P-58783439  HR-5532376336   6500  IN-7259841360
```

The commit-4 export is saved as `out/LR-731_export.tsv`; its SHA-256 is the flag body:

```
40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f  out/LR-731_export.tsv
```

giving `CSCTF{last_commit_40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f}`.

**Why it works**

In WAL mode SQLite leaves the main file untouched during a transaction and appends new page images to the log; the frame with a nonzero database-size field closes the transaction. Because nothing was checkpointed during the retained epoch, every intermediate page version still lives in the log, and overlaying frames up to a given commit reproduces the database exactly as a reader saw it right after that commit. The attacker swapped the title rows in commit 2, let the export job read and deliver them at commit 4, then restored the originals in commit 5. The current view therefore looks clean while the state at the `COMPLETED` transition holds the altered ownership that was actually shipped.

**Validation / reproduction**

The WAL header and all 9 frames pass SQLite's cumulative checksum chain, and the replay shows exactly one commit where `LR-731` becomes `COMPLETED`. The export digest is identical across commits 2–4 and differs on either side, matching a swap-and-restore. Before the solver ran, the team's automated intake had submitted three strings lifted from the brief's format text; all three were rejected. The reconstructed commit-4 digest was the first derived answer submitted, and it was accepted.

Reproduction in short: verify the archive hash, extract, and keep the `.sqlite`/`.sqlite-wal` pair untouched; run the `struct`-based WAL replay to build one standalone image per commit (setting header bytes 18/19 to 1); run the profile's query read-only at each image; take the export at the first `COMPLETED` state and SHA-256 it. Gotcha: never open the pair with a normal client — a single checkpoint deletes the WAL and the evidence with it; and ignore the profile's example digest, which is not this case's answer.
