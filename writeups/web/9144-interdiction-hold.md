# Interdiction Hold

> Web · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{blVXN5kcjCbYG933eqitJycR}`

**Tools used**

None beyond standard CLI utilities.

**Challenge**

"A broker acting for a hostile state moved an embargoed dual-use shipment through the Orsvane Border Revenue Service's freight clearance portal, and the interdiction hold on it came off. Nobody on the duty desk can say how. You have been given access to the same portal. One consignment in its queue is under an interdiction hold. Get it released and read the clearance token printed on its release certificate. The portal documents its interface at `/schema`."

No files were attached. The target is a per-team web container (`csctf26/web-interdictionhold:1`, port 8000, at `http://<instance>`) started from the challenge page. All requests went only to our own instance. The flag is a per-team random value, 24-character body, fixed for an instance.

**Approach / walkthrough**

Triage sent this to the web playbook (`docs/playbooks/web.md`). Because the brief advertises self-documentation at `/schema`, the first move is to read that documentation and the portal's reference data before sending any request that changes state.

1. **Read the approval model from `/schema`.** The schema describes two controls that guard a release:
   - **Approval binding.** An approval stores `manifest_hash`, a SHA-256 over a fixed list of `covered_fields`: `ref`, `origin`, `destination`, `declared_value_eur`, `carrier`, `lineitems[].description`, `lineitems[].quantity`.
   - **Release preconditions.** `POST /consignments/{ref}/release` succeeds only when the approval is `APPROVED` and the stored `manifest_hash` equals the hash of the consignment as it is now, and no line item carries an HS code on the embargo list.

2. **Spot the gap.** Comparing the two rules: the embargo check reads `lineitems[].hs_code`, but `hs_code` is **not** one of the hashed `covered_fields`. The integrity hash that freezes the approved manifest leaves out the exact field a later security decision depends on.

3. **Find the held consignment and the embargo list.**
   - `GET /embargo-list` returned six embargoed HS codes: `8409.99, 8536.90, 8544.42, 9014.80, 9032.89, 9306.90`.
   - Consignment **`MFC-UF52GPW`** had status `HELD`, and its approval was already `APPROVED`. The only thing blocking release was line item 0, whose `hs_code` was `8544.42`, which is on the embargo list.

4. **Amend the uncovered field after approval.** The portal allows line-item amendments after approval (the PATCH takes a `justification` field). Because `hs_code` is outside the hashed set, changing it leaves `manifest_hash` unchanged — so the approval still matches and is not re-opened — while moving the line item off the embargo list:

```http
PATCH /consignments/MFC-UF52GPW/lineitems/0
Content-Type: application/json

{"hs_code": "8543.70", "justification": "..."}
```

`8543.70` is just a code not on the embargo list; any code outside that list would have done the same job.

5. **Release and read the certificate.**

```http
POST /consignments/MFC-UF52GPW/release
```

The consignment changed to `RELEASED`, and its release certificate carried `clearance_token = CSCTF{blVXN5kcjCbYG933eqitJycR}`.

**Why it works**

This is a partial integrity binding — a TOCTOU-style approval bypass. The approval signs off a hash of the manifest, but the hash leaves out a field (`lineitems[].hs_code`) that a later release control reads. Changing that field after approval does not alter `manifest_hash`, so the approval stays valid and is not reopened, and the embargo check passes on the new code. In the story, this is exactly how the hostile broker lifted the hold. The fix is to hash every field that any release control reads (here the HS code, and in practice the whole line item), or to reset the approval to pending on any post-approval amendment.

**Validation / reproduction**

The release call returned the consignment as `RELEASED`, and the certificate's `clearance_token` had the 24-character `CSCTF{...}` per-team format. It was submitted once through the project CLI (notes: "manual cli submit") and accepted as correct on the first try — `tried.json` records one attempt, status `correct`, at 2026-11-07 13:07:46 UTC, under eight minutes after Wave 2 opened at 13:00 UTC. The challenge's one hint (5 pts) was not unlocked.

Reproduction in short: read `/schema` and note that `hs_code` is outside `covered_fields`; `GET /embargo-list`; find the `HELD`, already-`APPROVED` consignment (`MFC-UF52GPW`) whose line item 0 carries an embargoed code; PATCH that line item's `hs_code` to any non-embargoed code; POST the release and read `clearance_token`.

Gotchas and scope: nothing was fuzzed, scanned, or brute-forced; the chain is read `/schema`, read `/embargo-list`, look up the held consignment, one PATCH, one release. No session or auth header is noted as required.
