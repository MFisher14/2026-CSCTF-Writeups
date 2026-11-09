# Landfall

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 741 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{bfyGvnx2hgPluW3G99kBQG8r}
```

Recovered from the broadcast centre's `release_digest` (the confirmation code returned when the cancellation went on air), then submitted.

**Challenge**

Cyclone Meren is near landfall on the Astrenian coast. A fabricated evacuation order has gone out under ANWA authority, sending two coastal districts inland along Route N2 straight into the surge zone, and every dispatcher role was revoked at 03:11. What is left is an observer account on the National Alert Origination Gateway; the broadcast centre behind it still honours authorised cancellations. Without a dispatcher role, the task is to authorise a cancellation of the fabricated order and get it on air — the confirmation code is revealed when the cancellation is broadcast. There are no attachments, so this is black-box against our own instance. What the observer lacks is two things: an operation the gateway refuses to observers, and a **fresh** single-use Ed25519 dispatch grant. The fix for each is a parser or verifier differential between the gateway and the broadcast centre behind it.

**Tools used**

Python, used offline to decode the grants, check their time windows against the frozen clock, do the Ed25519 `S + kL` arithmetic and compute the unlock digest.

**Approach / walkthrough**

*Reconnaissance (read-only, GETs only, on our instance).* The `/` console shows the observer credential (operator `r.tolm`, role `observer`, authority `NAA-05`) and the line "Observer sessions may preview and read the ledger; dispatch is held." `GET /api/v1/schema` holds the contract. The parts that drove the solve:

- `operations`: `preview` is allowed for observers, `dispatch` needs a dispatcher, `cancel` is "reserved".
- `submission.paths`: `/api/v1/orders`, `/orders/batch`, `/orders/staged`. "Two of the three were rewritten in the v2 cycle with a validating decoder; one is still the v1 passthrough." The error `duplicate_member` is "400 the v2 decoder rejected duplicate member names".
- `grant`: `{payload, sig}`, where `sig` is a "64-byte detached Ed25519 signature over the exact decoded bytes of payload … a capability, not a content signature". `single_use` is "enforced by the broadcast centre. See /audit/ledger for the key used."
- `release_unlock`: `sha256-hex("landfall|<cancelled identifier>|<grant jti>|<area sorted, comma-joined>")`.
- `cap.references`: the triple `sender,identifier,sent` of the message being cancelled.

`/feed/cap/current` gives the on-air fabricated order `ANWA-CAP-758d0ad3-563f`, sender `alerts@anwa.astrenia.test`, sent `2026-11-07T02:53:00+00:00`, Extreme, areas `AS-MER` and `AS-CAP`. `/reference/clock` shows operational time frozen at `2026-11-07T03:26:00Z`, and grant `nbf`/`exp` are checked against it. Each `/feed/cap/archive/<id>` message carries its signed grant in an XML comment. We decoded all eleven and checked each window against the frozen clock. Only `ANWA-CAP-cfd82d14-4c47` has a grant that covers both target areas at Extreme and is still valid: jti `G-1b71cf7fbe`, auth `NAA-03`, `sev_max` Extreme, geo `AS-MER, AS-CAP, AS-VEN`, valid 2026-11-06T23:26Z to 2026-11-07T11:26Z. Every archived grant had a canonical `S < L`.

*1. The ledger shows the replay key and a malleable signature already in use.* Logged in as the observer (`POST /api/v1/session`), `GET /audit/ledger` showed that the on-air fabricated alert had itself reused grant `G-1b71cf7fbe`, with an Ed25519 signature whose scalar `S` was **not reduced mod L**. The hash of the archived canonical signature matched the first consumed ledger entry, and `S + L` matched the attacker's second consumed entry. So the single-use check keys on a hash of the signature bytes (not the jti), and the broadcast centre's verifier accepts non-canonical `S`. Therefore `S + 2L` is a signature that still verifies under a lax verifier but has never been consumed:

```python
L = 2**252 + 27742317777372353535851937790883648493
raw = b64url_decode(sig)                       # archived sig of G-1b71cf7fbe
S   = int.from_bytes(raw[32:], "little")
sig2L = raw[:32] + (S + 2*L).to_bytes(32, "little")
sha256(sig2L)  # 55cc23bf137b6a717aa53087dd39597e39a7dc788418980b0ab9ac676e0b2c42
```

Re-run offline from the saved archive grant, the `S + 2L` SHA-256 matches `notes.md` exactly (taken over the raw 64 signature bytes). For reference, the canonical (`k=0`) raw-bytes hash is `dd213b9c...` and `S+L` (`k=1`) is `9dfdc27b...`. But a conformant verifier (RFC 8032 requires `S < L`) rejects `S + 2L`, so getting the malleated signature past the gateway while still delivering it to the lax broadcast centre is the next step.

*2. Find the v1 passthrough and exploit case-insensitive vs exact key binding.* Probing the three submission paths showed that `/orders/batch` and `/orders/staged` reject duplicate members (`duplicate_member`), so only **`/api/v1/orders`** is the v1 passthrough. On that path plain duplicate keys were not the working differential — key **case** was. The gateway binds JSON members case-insensitively, while the broadcast centre looks up the exact lowercase key, so one body can carry two values for each field, one per layer:

| Field | Gateway reads (case-insensitive) | Broadcast centre reads (exact key) |
| --- | --- | --- |
| operation | `"Operation": "cancel"` — passes the observer-role policy | `"operation": "dispatch"` |
| grant signature | `"Sig"`: canonical archived signature — passes the strict verifier | `"sig"`: unseen `S + 2L` — passes the lax verifier, new to the ledger |

*3. Build the body.* The rest was a CAP payload:

- `payload`: CAP with `msgType: "Cancel"` and `references: "alerts@anwa.astrenia.test,ANWA-CAP-758d0ad3-563f,2026-11-07T02:53:00+00:00"`, areas `AS-MER` and `AS-CAP`.
- `authorization.payload`: the archived `G-1b71cf7fbe` claims, unchanged.
- `unlock`, from the schema formula (area is the payload's area, sorted):

```
sha256("landfall|ANWA-CAP-758d0ad3-563f|G-1b71cf7fbe|AS-CAP,AS-MER")
  = 4be9acc97f77aec0f61d2b1a9344c3bddcbb27b55173b8ae1d1266ac61d7f14c
```

*4. Broadcast.* The broadcast centre accepted the cancellation and the result was `BROADCAST` on `CBS-4370`. It withdrew the fabricated evacuation order and returned the confirmation code as `release_digest`: `CSCTF{bfyGvnx2hgPluW3G99kBQG8r}`.

**Why it works**

Ed25519 signatures are malleable unless the verifier enforces `S < L`: `S` and `S + kL` give the same verification equation. A replay guard keyed on a hash of the signature bytes therefore treats each `k` as a fresh grant — the ledger showed the attacker had already done this once (`k=0` then `k=1`), leaving `k=2` unused. The gateway runs the strict checks (role policy, canonical signature) but the component that acts on the request reads different JSON members, because the two layers bind keys with different case rules. Each layer is satisfied by its own copy of each field: the observer-allowed `cancel` and the canonical `Sig` clear the gateway, while `dispatch` and the fresh `sig` reach the broadcast centre.

**Validation / reproduction**

The canonical and `S + L` hashes matched the ledger's two consumed entries before the request was sent, which confirmed the replay key and the signature-bytes keying. The `S + 2L` hash (`55cc23bf...`) and the unlock digest (`4be9acc9...`) were recomputed offline from the saved archive grant and matched the notes. The broadcast response contained the `CSCTF{...}` code, and we submitted it.

Reproduction: as the observer, decode the eleven archived grants and pick the one valid against the frozen clock covering `AS-MER`/`AS-CAP` (`G-1b71cf7fbe`); read `/audit/ledger` to confirm the replay guard keys on the signature hash and accepts non-canonical `S`; compute `S + 2L` and the unlock digest; then `POST /api/v1/orders` with one JSON body carrying both `Operation: cancel` / `operation: dispatch` and both `Sig` (canonical) / `sig` (`S + 2L`), a CAP `Cancel` payload with the `references` triple, the unchanged grant claims, and the unlock. Gotchas: only `/api/v1/orders` is the v1 passthrough (`/orders/batch` and `/orders/staged` reject duplicate members); the differential is key **case**, not plain duplicate keys; and the unlock area list is the payload's areas sorted (`AS-CAP,AS-MER`).
