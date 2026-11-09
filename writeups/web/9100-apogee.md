# Apogee

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

`CSCTF{pEnICMJKwUXLNvO8GJObv8Pu}` — a 24-character per-team random value carried in the pass receipt,
released only after the sealed receipt is unlocked with the matching digest (see step 6).

**Tools used**

Codex, run under human steering, developed this end-to-end solve (the zip extraction differential, the
multipart submission, and the sealed-receipt unlock) and handed the flag back; the team verified it and
submitted once through the guarded path (byline: secretNinja). Codex never submits.

**Challenge**

Apogee is a black-box satellite ground-segment portal with no handout files. Everything needed to
reconstruct the attack is published by the portal itself: `GET /api/v1/schema`, `/journal`,
`/deliveries`, `/reference/validated`, `/reference/vendors`, `/reference/clock` and
`GET /api/v1/pass/receipt`. The operational goal is to restore ORRIN-3's validated manoeuvre table
into the write-protected trusted store so the next uplink pass is authorized; the receipt releases a
pass code only once the trusted table matches the validated original *and* the journal shows that the
restoration arrived through the delivery pipeline.

Two things make this hard. Vendor delivery needs an accreditation we do not hold, and the trusted
table store "is not writable through any published route; the delivery pipeline is the only writer"
(schema). The only route a non-vendor can reach is the analyst re-submission endpoint
`POST /api/v1/submissions`, which validates and extracts a package inside a staging root. So the win
has to come from the pipeline's own handling of an archive, not from writing the file directly.

**Approach / walkthrough**

1. **Read the pipeline contract.** The schema describes verifier and extractor as two separate
   stages. The verifier: "resolves each member path to one archive entry through a name lookup, then
   compares size and SHA-256. The manifest is the declaration; the verifier reads nothing else." Its
   `member_rules` spell out `lookup: by-name`, "the name-to-entry mapping resolves to one entry", and
   that each member's resolved entry must match the manifest size and SHA-256. The extractor is
   `extract-zip 2.0.1`, and its note is the key: "symbolic links and unix modes declared in the
   archive are honoured." The schema even documents how a symlink is encoded in a ZIP — unix mode bits
   `S_IFLNK|0777` in the external-attributes field (`0xA1FF0000`, APPNOTE.TXT 4.4.2), with the link
   member's content being the target string, hashed like any other member.

2. **Find the trick in the journal.** `GET /journal` lists every validation/extraction record. The
   accepted Vantrik Systems package for ORRIN-3 (`PKG-3210`, table `orrin3.ctab`) is the tell:

   ```json
   "validation": {"entries_validated": 6, "archive_entries": 7, "status": "passed"},
   "extraction": {"entries_extracted": 7,
     "entry_names": ["docs/README.txt","docs/release-notes.txt","checksums.sha256",
                     "meta/vendor.json","docs/install.txt","tables/orrin3.ctab","tables/orrin3.ctab"],
     "links": {"tables/orrin3.ctab": {"target": "../../../trusted/mvr/orrin3.ctab",
       "resolved": "/tmp/apogee/trusted/mvr/orrin3.ctab",
       "sha256": "2b18f1199b3e63a146569f1195355d753ccaafa90186274bf1bc69a5a5588dc7"}}}
   ```

   `archive_entries: 7` but `entries_validated: 6`, and `tables/orrin3.ctab` appears **twice** in
   `entry_names`. The `links` block shows the first of those two entries was a symlink whose target,
   `../../../trusted/mvr/orrin3.ctab`, resolved straight into the write-protected trusted store. So the
   hostile vendor package carried two entries sharing one name: a symlink into `trusted/`, then a
   regular file. The verifier's by-name lookup collapses the duplicate to a single entry (the regular
   file that matches the manifest), so only six members are hashed; the extractor iterates over all
   seven in order, creates the symlink, and then writes the second same-named entry *through* that
   symlink into `trusted/mvr/`.

3. **Pin the target bytes.** `GET /reference/validated` returns the 842-byte validated ORRIN-3
   manoeuvre table (revision 40). `GET /api/v1/pass/receipt` gives the target and the blockers:

   ```json
   {"expected_sha256": "6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac",
    "trusted_path": "/tmp/apogee/trusted/mvr/orrin3.ctab",
    "trusted_sha256": "2b18f1199b3e63a146569f1195355d753ccaafa90186274bf1bc69a5a5588dc7",
    "trusted_size": 896, "status": "pending",
    "reasons": ["trusted_table_hash_mismatch", "no_pipeline_restoration_record"]}
   ```

   The trusted table currently holds the poisoned 896-byte revision (hash `2b18f119…`, matching the
   journal's Vantrik write). We need it to become the validated 842-byte table whose SHA-256 is
   `6589d039…` (also the manifest's `expected_sha256`).

4. **Rebuild the same package for the analyst route.** The analyst re-submission uses the same verifier
   and extractor, so it inherits the write-through-symlink primitive. Using a small offline ZIP builder
   that writes duplicate entry names and symlink mode bits verbatim (`exploit/pkg.py`), the package
   `exploit/restore.zip` was built with two entries, both named `tables/orrin3.ctab`:

   - entry 1 — symlink, external attr `0o120777` (`S_IFLNK|0777`), 32-byte content
     `../../../trusted/mvr/orrin3.ctab`;
   - entry 2 — regular file, external attr `0o100644`, the 842-byte validated table.

   The manifest (`exploit/manifest.json`) declares exactly one member:

   ```json
   {"path": "tables/orrin3.ctab", "size": 842,
    "sha256": "6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac", "type": "file"}
   ```

   The verifier's by-name lookup resolves `tables/orrin3.ctab` to the regular-file entry, hashes its
   842 bytes, and gets `6589d039…`, matching the manifest — validation passes. The extractor then
   processes both entries in order: it creates the symlink into `trusted/mvr/`, then writes the 842
   bytes through it, overwriting the trusted table with the validated original.

5. **Submit the crafted package.** `POST /api/v1/submissions` as multipart form with fields `manifest`
   and `package` (the endpoint returns `405 E_METHOD` "POST a multipart form with fields manifest and
   package" on anything else; it is rate-limited at 30). The package is accepted: the trusted table now
   hashes to `expected_sha256`, and the extraction is journalled as a pipeline restoration record,
   clearing both blocking reasons.

6. **Unlock the sealed receipt.** `GET /api/v1/pass/receipt` does **not** hand over the pass code on its
   own — the receipt is sealed. The server returns `422 flag.locked` with `unlock_algorithm:
   "sha256-hex"` and an `unlock_input` template, and withholds the code until the request carries the
   matching digest. The unlock value is `sha256("apogee|ORRIN-3|<validated_sha256>|<package_id>")` with
   the fields taken from this instance: spacecraft `ORRIN-3`, `validated_sha256` =
   `6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac`, and `package_id` =
   `RESTORE-6589D039`. So the unlock input string is
   `apogee|ORRIN-3|6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac|RESTORE-6589D039`.
   Requesting `GET /api/v1/pass/receipt?unlock=<that sha256-hex>` returns HTTP 200, and the receipt's
   pass code **is** the flag, `CSCTF{pEnICMJKwUXLNvO8GJObv8Pu}`.

**Why it works**

Verification and extraction disagree on what the archive contains. The verifier maps a name to a single
entry, so a duplicate entry name hides the first entry (the symlink) from hashing — only the benign
regular file is validated. The extractor iterates over every entry and honours the unix symlink mode it
has just created, so the "validated" regular file is written outside the staging root, into the trusted
store. Because the analyst re-submission route runs the same verifier and extractor as vendor delivery,
it inherits the identical primitive, and the resulting write is logged in the journal as the required
pipeline restoration record. It is a parser-differential plus a zip-slip-via-symlink, both facilitated
by `extract-zip 2.0.1` honouring declared symlinks and modes.

**Validation / reproduction**

Before submitting, the manifest SHA-256 was checked against the receipt's `expected_sha256`
(`6589d039…`), confirming the package carried the exact validated bytes the gate wants. After the
submission the receipt was still sealed (`422 flag.locked`); supplying the `sha256-hex` unlock digest
over `apogee|ORRIN-3|<validated_sha256>|RESTORE-6589D039` released the pass code
`CSCTF{pEnICMJKwUXLNvO8GJObv8Pu}`, which was accepted.

Reproduction summary: pull `/api/v1/schema`, `/journal`, `/reference/validated` and
`/api/v1/pass/receipt`; read the Vantrik journal entry to recover the duplicate-name + symlink trick
and the target path; fetch the 842-byte validated table; build a ZIP with a symlink entry
(`../../../trusted/mvr/orrin3.ctab`) followed by a same-named regular-file entry holding the validated
table; declare one member in the manifest with size 842 and SHA-256 `6589d039…`; POST both as multipart
to `/api/v1/submissions`; then unlock the sealed receipt with
`GET /api/v1/pass/receipt?unlock=sha256("apogee|ORRIN-3|<validated_sha256>|RESTORE-6589D039")` to read
the pass code. Gotchas: the symlink must come **first** in the archive so it exists before the regular
file is extracted through it, and both entries must share the exact name the manifest declares; and the
receipt stays sealed (`422 flag.locked`, `unlock_algorithm: sha256-hex`) until the correct `unlock`
digest is supplied.
