# Cyberboy

> Web · Hard · Chronos Security  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

`CSCTF{Mebs9EZklOy3r222MfBkzrTn}`

**Tools used**

None beyond standard CLI utilities and a request-capped Python script, used only to fetch and list the OpenAPI spec.

**Challenge**

Relay Desk is the Kestrel Signals operations console that Operation Dawn field units use to manage radio crypto-period rotations. Each unit is a tenant and should see only its own rotations. A rotation seals into a key bundle once two duty officers sign off, and the theatre master key stays in custody with the relay authority. An operator tagged `cyberboy` took an ordinary analyst account all the way to exporting the theatre master bundle; we hold the same analyst account (`a.reyes` / `relay-bramble-27`, unit Bramble 14) and have to repeat that path, then read the `authorization_code` inside the master bundle.

There were no downloadable files — just a per-team web container (`csctf26/web-cyberboy:1`, port 8080, reachable at `http://<instance>`), the analyst credentials, and an OpenAPI 3.0.3 spec ("Relay Desk API" v4.2.6) at `/api/openapi.json`. The flag is a per-team random value with a 24-character body.

**Approach / walkthrough**

Without source, the spec is the attack surface. A scope-locked recon script (`workspace/9126-cyberboy/cyberboy_recon.py`) was prepared first: it talks only to the given HOST:PORT, caps requests (default 60), waits 0.25 s between them, fetches the spec, lists every operation, logs in, and walks each documented GET. Its first pass made 8 requests but used a wrong hard-coded login body (`operator`/`passphrase` instead of the spec's `username`/`password`), so its GETs all returned 401. The manual solve that followed took about 13 paced requests. Total: ~21 requests to the assigned host.

The operation descriptions in `openapi.json` give each bug away:

| Operation | Spec description (abridged) | What it implies |
| --- | --- | --- |
| `PATCH /api/profile` | "duty_assignment ... feeds the session scope at the next refresh." | The user can edit their own tenant scope |
| `POST /api/profile/refresh` | "Re-reads duty_assignment and re-issues the session with that unit as the effective scope." | The edited scope is written into the session |
| `POST /api/rotations/{ref}/approve` | "Records an approval under the acting officer's signatory **display name**." | Approver is identified by a user-controlled field |
| `POST /api/rotations/{ref}/delegate-approval` | "Body: {delegate_id}. An account already holding a delegated slot is refused." | Only the delegate slot is checked, not the caller |
| `POST /api/rotations/{ref}/export` | "Body: {tier}. Seals the rotation's key bundle **at the named tier**." | The client chooses the export tier |

1. **Log in as the analyst.**

```
POST /api/session  {"username":"a.reyes","password":"relay-bramble-27"}
-> 200 {"account_id":"usr_reyes","scope":"BR-14","display_name":"A. Reyes"}
```

`GET /api/profile` returns role `analyst`, with `home_unit` and `duty_assignment` both `BR-14`. `GET /api/units` lists six units, including **`KL-01` "Kestrel Lead / Theatre Relay Authority"**, the tenant holding custody of the master key. In scope BR-14, `GET /api/rotations` and `GET /api/bundles` return only Bramble 14's field-tier data.

2. **Move into the relay authority's tenant (mass assignment of scope).** `duty_assignment` is a profile field the user can edit, and the server takes the session's tenant scope from it without checking whether the account is actually posted there:

```
PATCH /api/profile          {"duty_assignment":"KL-01"}
-> 200 {"account_id":"usr_reyes","display_name":"A. Reyes","duty_assignment":"KL-01"}

POST  /api/profile/refresh
-> 200 {"account_id":"usr_reyes","scope":"KL-01"}
```

The analyst is now scoped to the Theatre Relay Authority. `GET /api/units/KL-01/staff` returns the three KL-01 duty officers (Castellan, Okonkwo, Delacroix), and `GET /api/bundles` returns KL-01's sealed `theater`-tier bundles.

3. **Find a rotation that already has both sign-offs.** `GET /api/rotations` (now KL-01) returns 11 theater-tier rotations. Refs have the form `rr_` + base64url(`<unit>:<seq>`) + `.` + MAC — for example `rr_S0wtMDE6OQ` decodes to `KL-01:9`. **Seq 9** (`rr_S0wtMDE6OQ.303822af625d3926`, crypto-period `DAWN-KILO-09`) is already `status: approved`: a `Maj. R. Castellan` approve plus a `usr_okonkwo` delegated approval, and `bundle_id: null` (no bundle yet). The two-officer rule was already met, so nothing had to be forged. (Seq 7, `rr_S0wtMDE6Nw.d016bb1042224d66`, was also approved and unexported; we used seq 9 and did not try seq 7.)

4. **Raise the export tier (the client picks the tier).** The rotation is authorized at `theater`, but `export` seals at whatever tier the body names and never checks it against `authorized_tier`:

```
POST /api/rotations/rr_S0wtMDE6OQ.303822af625d3926/export  {"tier":"master"}
-> 200
{
  "bundle": {
    "bundle_id": "SEAL-635A3634B5",
    "tier": "master",
    "custody": "theatre",
    "unit": "KL-01",
    "crypto_period": "DAWN-KILO-09",
    "rotation_ref": "rr_S0wtMDE6OQ.303822af625d3926",
    "key_fingerprint": "2a:86:c9:50:35:6c",
    "authorization_code": "CSCTF{Mebs9EZklOy3r222MfBkzrTn}",
    "sealed_at": "2026-11-06T14:09:52Z"
  }
}
```

The `authorization_code` is the flag.

**Why it works**

There are two separate authorization failures. First, the tenant boundary comes from `duty_assignment`, a profile field the user can write, and the server never checks it against the account's real posting — mass assignment of the session scope. Second, the export endpoint takes the seal tier from the request body and does not enforce the rotation's `authorized_tier`, so any approved theater rotation can be exported as a master bundle. The spec also exposes a third flaw we did not need: `approve` identifies the signer only by the editable `display_name`, and `delegate-approval` only checks the delegate slot, so one account could set its display name to an approver, call `approve`, then delegate to a second approver's account id to produce both sign-offs. That matters only if no rotation is already approved; seq 9 already was, so we did not run it on the instance (unverified).

**Validation / reproduction**

The export response was a bundle with `tier: master` and `custody: theatre`, and its `authorization_code` had a 24-character `CSCTF{...}` body matching the challenge's `flag_mode: random` / `random_flag_length: 24`. It was accepted on the first submission, submitted once through the CLI as `correct` (`tried.json`, 2026-11-06 14:10:31 UTC).

Reproduction in short: log in as `a.reyes`; `PATCH /api/profile {"duty_assignment":"KL-01"}` then `POST /api/profile/refresh`; `GET /api/rotations`, decode a ref's base64url middle to find an already-approved seq (seq 9); `POST /api/rotations/<ref>/export {"tier":"master"}`; read `authorization_code`.

Gotchas: the recon script's hard-coded login body (`operator`/`passphrase`) does not match the spec's `{username, password}`, so its first-pass GETs are all 401 — switch to the spec's fields for the manual requests. Every request went to our own assigned instance; no scanning, flooding, or flag guessing.
