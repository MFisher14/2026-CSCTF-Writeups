# Inside the Cordon

> Web · Medium · Chronos Security  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{yg4hpNcoXdPx28pleOe9DUx4}
```

This is a per-team random flag (24 characters), recovered from the WebSocket `room.snapshot` frame
on our assigned instance.

**Challenge**

> A seized coordination station was used to get inside Cordon Seven while the national fuel corridor
> that feeds allied units in Operation Dawn was being rerouted. The operator PIN is gone. Reproduce
> the access path and recover the protected briefing. Everything you need is in the application; do
> not contact real systems.

It is a per-team container (`csctf26/web-inside-the-cordon:1`, port 8080), spawned through the
`docker_per_team` CTFd plugin. There were no attachments and no source — the running application was
the only input. All traffic was scoped to the assigned instance (`<instance>`).

Narratively it is a geofenced access-control app. An operator enters a **PIN**, which unlocks a
WebSocket channel; the channel only releases the protected "room" briefing once the station reports a
**position inside Cordon Seven**. The PIN is "gone," so the intended solve is to break the trust
boundaries, not to recover the PIN.

**Approach / walkthrough**

*Recon.* A paced, read-only pass (15 GETs, bodies and headers saved under `recon/`) mapped the app.
The server identifies itself as `VicinityWire`; unknown routes return `{"code":"NOT_FOUND"}`. No
`robots.txt`, `openapi.json`, `/api/v1/schema`, `.git`, or sourcemap existed — they all returned the
`NOT_FOUND` body, so the saved `recon/app.js.map` and schema files hold only that 404, not real
content. `GET /` sets an **opaque session cookie** `station=<43-char base64url>` (HttpOnly,
SameSite=Strict, Max-Age=1800). It is **not** a JWT, so there is no `alg:none` or weak-secret forge.
A tight CSP is set (`default-src 'none'`, `connect-src 'self' ws: wss:`). Together that said: logic
challenge, not XSS/injection.

The whole client lives in `recon/app.js` (6.5 KB, unminified) — the key artifact. It names the
endpoints and, in a comment, the bug:

- `POST /api/station/pin-check {"pin":"NNNNNN"}` → `{success, code, attempt, expires_in_ms}`. An
  `attempt` id comes back **even when the PIN is wrong**.
- `POST /api/station/activate {"attempt":<id>}` → `{cap, room, lat_e6, lon_e6, radius_m, server_time_ms}`.
- `GET /api/station/session` → session liveness.
- `GET /ws` → the WebSocket channel. Frames carry a monotonic `sequence`; each server reply returns a
  `next_sequence` the client must echo on its next frame.

*Vulnerability 1 — client-side trust boundary on activation.* `app.js` states it in a comment:

```js
// (abridged from recon/app.js, pin-form submit handler)
if (!response.ok) { pinStatus.textContent = `Check failed: ${result.code}.`; return; }
// Deliberately wrong trust boundary: the browser's local branch decides whether to activate.
const attempt = result.attempt;
if (!result.success) { pinStatus.textContent = `PIN rejected (${result.code}). Attempt ${attempt} expires in ...`; return; }
const activation = await fetch('/api/station/activate', {method:'POST', ..., body:JSON.stringify({attempt})});
```

The browser is the only thing that checks `result.success`. The server hands back a valid `attempt`
id on a **failed** PIN check, and `activate` trusts that id without ever confirming the PIN
succeeded. So any wrong 6-digit PIN yields a usable `attempt`, and activating it returns the real
`cap`, the room id, and the cordon centre (`lat_e6`, `lon_e6`) and `radius_m`. **No PIN brute force
is needed** — the "PIN is gone" framing is a red herring, and sweeping PINs was explicitly ruled out
as a flooding/brute-force concern.

*Vulnerability 2 — client-reported geolocation.* Over the WebSocket the browser authenticates with
`cap`, then calls `reportOutside()`, which sends a hard-coded outside position (`app.js` labels it the
"Synthetic station position": `latitude:-47.200610, longitude:-126.302400, accuracy_m:18.0`; the map
text says the station "starts outside"). The server computes `inside`/`distance_m` from the
client-supplied coordinates — nothing server-side vouches for the position. Since `activate` already
leaked the exact centre and radius, we report the centre instead of the decoy and are ruled inside.

The only server-side rigor is procedural: the strict `sequence` the client must echo, a
position-freshness window (`freshness_ms`), and a rate allowance (`limit` frames per `window_ms`).
These are honored with a client-side limiter, not bypassed.

*Exploit path* (`exploit/live.py`, one short sequential run, a handful of frames, no loops/sweeps):

1. `GET /` to obtain the opaque `station` cookie.
2. `POST /api/station/pin-check {"pin":"000000"}` — one wrong PIN, no sweep — and take `attempt` from
   the failure response.
3. `POST /api/station/activate {"attempt": attempt}` → `{cap, room, lat_e6, lon_e6, radius_m, ...}`.
4. Open `/ws` with the same cookie and `Origin` set to the base URL. Send
   `{"type":"station.authenticate","sequence":1,"cap":cap}`; read `station.accepted` for
   `next_sequence`, `limit`, `window_ms`.
5. Send `position.update` at the leaked centre (`lat_e6/1e6`, `lon_e6/1e6`), with `observed_at_ms`
   from the current time (inside the freshness window) and a small `accuracy_m` (`min(1.0,
   radius_m/2)`, i.e. at most 1 m). Read `position.accepted` with `inside:true` and `eligible_room`.
6. Send `{"type":"room.join","sequence":next_sequence,"room":eligible_room}`. The `room.join` frame
   type is **not** in `app.js` — the client never joins — so it was inferred from the message
   vocabulary (`room.snapshot`, `eligible_room`); the script sends it once and it was accepted. The
   server replies `room.snapshot` with `classification`, `briefing`, and `clearance_token`.

`app.js` renders the snapshot as `${classification}: ${briefing} ${clearance_token}`. Which field
carried the flag was not recorded (`clearance_token` is the likely one, an inference); `live.py`
extracts it with a `CSCTF\{[^}\s]+\}` regex over the whole serialized frame. The output below is the
*shape* the script prints, not a saved transcript (the live log was not kept):

```bash
.venv/bin/python workspace/9107-inside-the-cordon/exploit/live.py
# pin-check: {"success": false, ...}
# activate: {"room": ..., "lat_e6": ..., "lon_e6": ..., "radius_m": ...}
# ws: {"type":"station.accepted", ...}
# ws: {"type":"position.accepted","inside":true, ...}
# ws: {"type":"room.snapshot", ...}   (contains CSCTF{...} in one of its fields)
# FLAG: CSCTF{yg4hpNcoXdPx28pleOe9DUx4}
```

**Why it works**

Two classic web trust failures are stacked. First, a **client-side authorization branch**: only the
browser checks whether the PIN succeeded, while the server issues a usable `attempt` on a failed
check and `activate` honors it without rechecking — so the operator-PIN gate falls to one wrong
guess, and `activate` discloses the geofence centre and radius. Second, **client-controlled
geolocation**: the server derives `inside` purely from the coordinates the `position.update` frame
reports, and the centre is already known, so reporting the centre instead of the hard-coded decoy is
ruled inside. The `sequence`/freshness/rate machinery only constrains the order and timing of frames;
nothing in it verifies who the station is or where it really is.

**Validation / reproduction**

The script refuses to finish unless it receives `position.accepted` with `inside:true` and then a
`room.snapshot` matching the `CSCTF{...}` regex; the extracted per-team flag was accepted on the
first guarded submission (`tried.json`: one attempt, `correct`). A Codex child-agent returned the
final flag for this challenge, so the solve is credited to Codex (run under human steering; byline:
secretNinja) — but the exact mechanics were not fully re-traced from its session, and the steps above
come from our saved notes rather than a Codex transcript.

Repro summary: `GET /` for the cookie → wrong PIN to get an `attempt` → `activate` for `cap` plus the
leaked centre/radius → authenticate on `/ws`, echoing each `next_sequence` → `position.update` at the
centre with fresh `observed_at_ms` and sub-metre accuracy → `room.join` the `eligible_room` → read
the flag from `room.snapshot`.

Gotchas: send everything with the same `station` cookie (SameSite=Strict, 1800 s), and set `Origin`
to the base URL on the WS upgrade. Echo `next_sequence` exactly and keep `observed_at_ms` inside the
freshness window; the `room.join` frame name is not in `app.js` and was inferred from the protocol's
other names.
