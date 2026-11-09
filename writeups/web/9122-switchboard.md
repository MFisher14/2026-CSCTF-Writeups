# switchboard

> Web · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{QI4P8TCLIbbens33uHRArNhq}
```

A per-team random flag (`flag_mode: random`, 24-character body matching `random_flag_length: 24`),
returned by our own instance's controller as the `trunk_key` field. Accepted on the first submission,
about 12 minutes after Wave 2 opened.

**Challenge**

> The Vardanne Joint Operations Directorate runs an old voice exchange whose public board shows the
> state of its trunk circuits. The duty desk reaches a separate exchange controller over the internal
> trunk, and that controller can export the current trunk crypto key, but only to a rostered
> supervisor. Reach the controller and export the key. Start your own instance from this page and work
> only against the address it gives you.

A container challenge (`csctf26/web-switchboard:1`, port 9999, `connection_type: web`). There were no
handout files, so all the evidence came from our own instance. Dynamic scoring was 200 initial, decay
45, floor 120; the `challenge.json` snapshot refreshed at 13:12:31 UTC just before our submission
showed 192 points and 8 solves. All requests went only to the assigned instance (`<instance>`).

The brief lays out three elements: a public board, a separate "exchange controller" reachable from the
duty desk "over the internal trunk," and an export that is "supervisor only." That maps to a plan:
find the path from the board to the internal controller, then defeat the supervisor check. With no
files to analyse offline, the pre-instance plan in `READY.md` was a small amount of recon on the
public board (HTML/JS, robots, headers), then look for the desk-to-trunk path (we expected SSRF or a
proxy), then look for a weakness in the supervisor check (a trusted header, a role taken from the
client, or a forged roster entry). Both halves turned out simpler than expected.

**Approach / walkthrough**

*Step 1 — the public board leaks the controller's name.* The board's client script
`/static/switchboard.js` hides an internal hostname in a base64 literal:

```
atob("ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA==")
```

```
$ echo ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA== | base64 -d
exch-ctl.vjod.internal
```

*Step 2 — virtual-host confusion: the "internal trunk" is a `Host` header.* We expected an SSRF relay
from the duty desk, but none was needed. The front server picks the application by the `Host` header.
Sending `Host: exch-ctl.vjod.internal` to the **same public port** serves the internal Exchange
controller — the "internal trunk only" restriction trusts the `Host` value the client sends, so naming
the internal hostname is enough to reach it. The controller's index page documents its API:

- `POST /auth` (takes a `username`)
- `GET /operators`
- `GET /export/trunk-key` (supervisor only)

*Step 3 — mass assignment on `/auth` gives us the supervisor role.* `POST /auth` asks for no password,
and it reads the session **role from the request body**. Sending an extra `role=supervisor` field
makes the server issue a Flask-signed `ctl_sid` cookie that carries `role=supervisor`. We did not have
to forge the cookie — the server signed it for us, so there was nothing to break.

*Step 4 — export the key.* `GET /export/trunk-key` with that cookie and the same `Host` header
returned the key record (`key_id KTK-2026-10-B`). Its `trunk_key` field is the flag.

```
B=http://<instance>
H='Host: exch-ctl.vjod.internal'
curl -c cj -H "$H" -d 'username=duty&role=supervisor' $B/auth
curl -b cj -H "$H" $B/export/trunk-key
# -> response carries key_id KTK-2026-10-B and trunk_key CSCTF{...}
```

The instance was stopped right after the solve. At the start of Wave 2 the first spawn attempt failed
with the team's container cap (`Max containers (3) reached`); we queued the challenge and spawned it
once a slot was free:

```
.venv/bin/python -c "from ctf.client import connect; from ctf.instances import Instances; print(Instances(connect()).spawn(9122))"
```

**Why it works**

The controller is "internal" only in name. It runs behind the same listener as the public board, and
the only boundary is a virtual-host match on a `Host` value the client controls — which is not a
network boundary at all. Once we can reach it, the login handler binds every submitted field into the
session, including `role`, so any caller can over-post `role=supervisor` and promote itself (mass
assignment). The export check then trusts the role in the signed session. Two cheap flaws chain: a
`Host`-based "internal" gate an outside client can satisfy, and an authorization field taken straight
from client input.

Three lessons carry out of this one. First, **look for the internal name on the client side** — the
base64 hostname sitting in the board's JavaScript is the pointer to the hidden service, and decoding
it is the whole of step one. Second, **"internal only" enforced with `Host` is not a network
boundary**: routing by virtual host on one shared listener lets an outside client reach the internal
app just by naming it, so no SSRF or proxy abuse is required. Third, **authorization fields must never
come from the client**: because `/auth` binds `role` out of the submitted form, any user can
over-post `role=supervisor` and the server dutifully signs that into the session.

**Validation / reproduction**

The export response carried a `CSCTF{...}` value in the `trunk_key` field, whose 24-character body
matches the per-team random flag length. It was submitted once by hand through the guarded CLI
(`./csctf submit 9122 ...`) and accepted as correct (`tried.json`: one attempt, status `correct`,
timestamp 1794057153 = 2026-11-07 13:12:33 UTC), about 12 minutes after Wave 2 opened (13:00 UTC).

Repro summary: fetch `/static/switchboard.js` and base64-decode the `atob(...)` literal to get
`exch-ctl.vjod.internal` → re-request the same port with `Host: exch-ctl.vjod.internal` to reach the
controller → `POST /auth` with `username=duty&role=supervisor` to get a supervisor-signed `ctl_sid`
cookie → `GET /export/trunk-key` with that cookie and the same `Host` header → read `trunk_key`.

Gotchas: the `Host` header must be sent on **every** controller request, including the export, or the
front server routes back to the public board. The flag is random per team and instance, so another
instance returns a different value. The exact response format was not saved; field names
(`key_id`, `trunk_key`, `ctl_sid`) and the Flask signing come from `notes.md`, while the flag,
challenge metadata, and the base64 decode are verified from the saved files.
