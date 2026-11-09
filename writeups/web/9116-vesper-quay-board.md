# Vesper Quay Board

> Web · Medium · Mohamed Amine Mzoughi  
> Points: 291 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{6SkxXyOrqeH23QGrxONbsjtc}
```

Returned by our own instance's quay as the `clearance_code`, submitted once and accepted on the first
try.

**Challenge**

> Ash Army operators forged a release warrant at Vesper Quay to divert a relief convoy, and the desk
> approved it under the sealed courier. The quay serves an allied nation in the Operation Dawn
> theatre; it logged a different courier, and the raw warrant was not kept. Stop the diversion. Only
> a correction signed by a release the quay actually runs is accepted, and that correction returns
> the verification code. The API reference is at `/v1/openapi.json` on the desk.

A per-team container challenge (`type: container`, `connection_type: web`, port 8080). No files were
attached (`files: []`), so everything came from the live API on the assigned instance (`<instance>`).
One 25-pt hint was offered; we did not unlock it.

Two phrases in the brief define the whole solve. "Approved under the sealed courier … logged a
different courier" says one warrant was read two different ways by two components — a **parser
differential**. "Signed by a release the quay actually runs" says the final correction must be signed
by code running on the quay (the back end), not by the desk (the front-end policy check).

**Approach / walkthrough**

*Step 1 — read the spec as two parsers.* The OpenAPI document at `/v1/openapi.json` described a
desk-to-quay differential. The two layers read different key spellings of the same JSON body:

| Layer | Keys it reads | What it enforces |
| --- | --- | --- |
| Desk (guard) | `Courier`, `Argv` (capitalised) | courier must be the approved/sealed one, `c-f7dd2a`; `Argv` must be empty or `["status"]` |
| Quay (executor) | `courier`, `argv` (exact lowercase) | for the **legacy** courier `c-615d02`, runs `python3 -I -c <code>` when `argv == ["-c", <code>]` |

The quay takes the legacy execution path only when **both** hold: the desk saw the approved courier
and the quay saw the legacy courier. One parser can never produce that combination. Two parsers
reading different key spellings can. (The per-layer behaviour is summarised from the solve log, which
does not separate what the spec stated from what probing confirmed.)

*Step 2 — send a dual-key body.* We posted one body carrying both key spellings:

```json
{
  "courier": "c-615d02",
  "argv": ["-c", "<python code>"],
  "Courier": "c-f7dd2a",
  "Argv": []
}
```

- Desk view: `Courier = c-f7dd2a` (approved), `Argv = []` (allowed) → the guard passes.
- Quay view: `courier = c-615d02` (legacy), `argv = ["-c", CODE]` → it runs `python3 -I -c CODE`.

The keys are not literal duplicates — they differ only in case, and one layer does case-insensitive
lookup while the other does exact-case. The policy check and the action read different fields of one
message. This is the same failure class as HTTP parameter pollution and JSON duplicate-key confusion.

*Step 3 — look around inside the child.* Inside the `python3 -I` child, the environment held
everything the quay uses to sign its own corrections:

- `STATION_SIGN`: path to an Ed25519 signing helper. It reads canonical bytes on stdin and writes a
  64-byte signature.
- `STATION_KEY`: a path to the station key (the log records only that it is a path; we did not open
  it).
- `EDGE_URL=http://127.0.0.1:8080`: the service's loopback address inside the container (8080 is also
  the exposed port), serving `/v1/corrections`.
- `SUBMISSION_ID`, `QUAY_ID`, `WARRANT_ID`, `COURIER_ID`: the quay's identifiers for the logged
  submission (our reading: the forged diverting warrant), which the correction references.

We never read the private key file. We used `STATION_SIGN` only as the station's own signing service
— the "release the quay actually runs." Every request stayed inside the assigned container: the
signing call ran in the child, and the correction went to the container's loopback `EDGE_URL`.

*Step 4 — sign and post the correction.* From inside the child, build the correction object with five
fields (`applied_primary`, `courier_id`, `quay_id`, `submission_id`, `warrant_id`), serialise it as
**RFC 8785 / JCS canonical JSON** (keys sorted, compact separators, no whitespace) so the bytes we
sign match the bytes the verifier rebuilds, pipe those bytes to `STATION_SIGN`, base64-encode the
64-byte signature, and `POST $EDGE_URL/v1/corrections` with the flat fields plus `signature`. The log
records that `applied_primary = false` was the value that verified (reading it as "undo the diversion"
is our interpretation).

```python
import os, json, base64, subprocess, urllib.request
body = {
    "applied_primary": False,
    "courier_id":    os.environ["COURIER_ID"],
    "quay_id":       os.environ["QUAY_ID"],
    "submission_id": os.environ["SUBMISSION_ID"],
    "warrant_id":    os.environ["WARRANT_ID"],
}
canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()   # JCS for this flat ASCII object
sig = subprocess.run([os.environ["STATION_SIGN"]], input=canon, capture_output=True).stdout  # 64 bytes
req = dict(body, signature=base64.b64encode(sig).decode())
r = urllib.request.Request(os.environ["EDGE_URL"] + "/v1/corrections",
                           data=json.dumps(req).encode(),
                           headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(r).read().decode())   # -> clearance_code
```

The quay verified the signature and the `applied_primary=false` correction, then returned a
`clearance_code`, which is the flag. (The exact script was not saved; this is a reconstruction of the
logged steps. Whether `STATION_SIGN` takes the key path as an argument or reads `STATION_KEY` itself
is not recorded — the sketch assumes the latter. For a flat object of ASCII strings and booleans,
`json.dumps(sort_keys=True, separators=(",", ":"))` gives the same bytes as JCS; nested objects or
non-integer numbers would need a real RFC 8785 implementation.)

**Why it works**

The policy check and the action read different fields of the same JSON object: the desk looks up
capitalised keys, the quay looks up exact lowercase keys, so one body carries a benign request for the
guard and a code-execution request for the executor. Once code runs inside the quay, its trusted
signing service will sign whatever it is given, and canonicalising with JCS makes the signed bytes
match exactly what the verifier reconstructs — so a correction we authored is accepted as a
legitimate, quay-signed release, without ever touching the private key.

**Validation / reproduction**

The live `/v1/corrections` endpoint verified the signature and returned the `clearance_code`; it was
submitted once through `./csctf submit` and accepted as correct (`tried.json`: one attempt, status
`correct`).

Repro summary: read `/v1/openapi.json` → POST the dual-key body (`courier`/`argv` legacy +
`Courier`/`Argv` approved) to the desk's warrant route → inside the `-c` child, read the
`SUBMISSION_ID`/`QUAY_ID`/`WARRANT_ID`/`COURIER_ID` env vars → build the five-field correction with
`applied_primary=false`, JCS-canonicalise, sign with `STATION_SIGN`, base64 the signature → POST to
`$EDGE_URL/v1/corrections` → read `clearance_code`.

Gotchas: the two key spellings must both be present in one body; canonicalisation must match the
verifier's (sorted keys, no whitespace) or the Ed25519 check fails; keep every call inside the
container's loopback. The dual-key correction route is `POST /v1/corrections`: it takes the flat
five-field JSON object (`applied_primary`, `courier_id`, `quay_id`, `submission_id`, `warrant_id`,
with `applied_primary=false`), serialized as RFC 8785 / JCS canonical JSON, Ed25519-signed via
`STATION_SIGN` with the base64 signature added as an extra field; the quay verifies it and returns the
`clearance_code`, which is the flag.

Codex, run under human steering, recovered this solve; the team verified and submitted once (byline:
secretNinja).
