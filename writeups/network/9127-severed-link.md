# Severed Link

> Network · Easy · Teodor Giurgica  
> Points: 120 · Flag submitted by: secretNinja

**The flag:** `CSCTF{1SjwLfR8QgSXGszVbKNOyUCO}`

**Tools used**

Custom MAVLink 2 framing/signing in Python (hashlib for the SHA-256 MAC); tshark for inspection.

**Challenge**

> A reconnaissance drone takes orders from its field station over a signed MAVLink 2 link.
> Mid-mission the operator rotated the signing key, then pushed the new key over that same link while
> it was being recorded. The uplink gateway is still online. Show that an outsider can take the
> operator's place and command the aircraft.

`severed-link.zip` holds `mission.pcap`, `mission.tlog` (the same signed MAVLink traffic as raw
frames), and `ops_notes.txt` (operator station sysid 255, drone sysid 1, per-frame signing on, key
rotated **in band over the same console link** "instead of the out-of-band provisioning channel it
should have used"). The live uplink gateway is a per-team instance (`<instance>`, TCP 5760). The notes
give away the bug class: a key-management failure, not a cryptographic weakness — MAVLink 2 signing
(truncated SHA-256 MAC over a 32-byte secret) is sound; the secret was simply sent over the link it
protects.

**Approach / walkthrough**

**1. Inventory the frames**

A MAVLink 2 frame starts with magic `0xFD`, then `len, incompat_flags, compat_flags, seq, sysid,
compid`, a 3-byte `msgid`, the payload, a 2-byte CRC, and — when `incompat_flags & 0x01` — a 13-byte
signature trailer (`link_id`(1) + `timestamp`(6) + `sig`(6)). Walking the tlog, the operator is sysid
255 / compid 190, and there is exactly one `SETUP_SIGNING` (msgid **256**) frame — the in-band key
push:

| sysid/compid | msgid | Message | Count |
| --- | --- | --- | --- |
| 1/1 | 0 | HEARTBEAT | 34 |
| 1/1 | 33 | GLOBAL_POSITION_INT | 34 |
| 1/1 | 24 | GPS_RAW_INT | 34 |
| 255/190 | 76 | COMMAND_LONG | 3 |
| 255/190 | 75 | COMMAND_INT | 1 |
| 255/190 | **256** | **SETUP_SIGNING** | 1 |

**2. Pull the key out of SETUP_SIGNING**

MAVLink serializes fields **sorted by type size**, not XML order. So on the wire `SETUP_SIGNING` is
`initial_timestamp` (uint64), `target_system` (uint8), `target_component` (uint8), then
`secret_key[32]` — the key starts at payload offset 10:

```
payload: f708000000000000 01 01 8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60
         initial_ts=2295  ts tc  secret_key
KEY = 8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60
```

**3. Confirm it is the *current* key**

The MAVLink 2 signature is `sig = SHA-256(KEY || frame_without_trailer || link_id || timestamp)[:6]`
(link_id 0 here). Every frame in the recording carries a signature (107 signed frames, 0 unsigned).
Recomputing the MAC for each one with the recovered key splits the recording cleanly: **exactly 50
frames verify and 57 do not.** The 50 that verify are the post-rotation frames; the 57 failures are the
56 pre-rotation frames plus the `SETUP_SIGNING` carrier frame itself, which is signed under the
departing old key (a key change authenticated under the key it replaces). By message type the verifying
set is HEARTBEAT ×16, GLOBAL_POSITION_INT ×16, GPS_RAW_INT ×16, COMMAND_LONG ×1 and the operator
COMMAND_INT (msg 75) ×1 — so the DO_REPOSITION the attack reissues sits in the post-rotation set the
recovered key validates. That identifies the recovered key as the one the gateway accepts now. Building fresh frames also
needs the MAVLink checksum CRC-16/MCRF4XX (X.25) over `header[1:] || payload || CRC_EXTRA`, with the
per-message CRC_EXTRA seeds (HEARTBEAT 0→50, COMMAND_INT 75→158, COMMAND_LONG 76→152,
SETUP_SIGNING 256→71); the CRC routine was verified against captured frames.

**4. What the live gateway wants**

Probing the per-team gateway (our own assigned instance) showed it accepts an operator command only
when it is sent from sysid 255, is a signed COMMAND_INT (msg 75) carrying MAV_CMD_DO_REPOSITION (192),
is stamped with a *current* signing timestamp (10 µs ticks since 2015-01-01 UTC, so a replayed captured
frame is refused because the timestamp must advance), and is preceded by a HEARTBEAT from the
"operator". The replay rejection is why the key was needed: re-sending captured bytes fails; only a
freshly signed frame passes.

**5. Reissue the operator's command, freshly signed**

The captured operator COMMAND_INT decodes to a DO_REPOSITION:

```
command=192 (DO_REPOSITION) frame=5 (GLOBAL_INT) target_system=1 target_component=1
param1=-1.0 param2=1.0 param3=0 param4=0  x=457920000 (lat 45.792) y=241510000 (lon 24.151) z=85.0
```

Against the team's own gateway, that same payload was rebuilt as a new MAVLink 2 frame (sysid 255 /
compid 190, `incompat_flags=0x01`, trailing-zero payload truncation, the msg-75 CRC, link_id 0, a
current timestamp, and a signature computed with the recovered key), sent as a signed HEARTBEAT first
and then the COMMAND_INT. The gateway returned:

```
OPERATOR AUTHENTICATED. Reposition accepted.
Audit receipt: CSCTF{1SjwLfR8QgSXGszVbKNOyUCO}
```

**Why it works**

MAVLink 2 message signing guarantees authenticity only while the 32-byte secret stays secret. Pushing
a rotated key in band with `SETUP_SIGNING`, over a link being recorded, hands the key to anyone holding
the capture. The gateway's timestamp window stops replay but not someone who holds the key and signs
fresh frames.

**Validation / reproduction**

The recovered key was verified against the capture before any live use: re-running the MAC over
`mission.tlog` gives a clean **50-of-107** verify split (57 fail), with every post-rotation frame
passing and the pre-rotation frames plus the `SETUP_SIGNING` carrier failing. One benign command was
sent to the assigned instance; the gateway's "Audit receipt" line returned the flag, accepted on the
first submission.

Reproduce: unzip; scan `mission.tlog` for `0xFD` frames; find msgid 256 and read the key at payload
offset 10; check `SHA-256(key || frame_without_trailer || link_id || ts)[:6]` against the
post-rotation frames; then, against the assigned instance only, send a signed HEARTBEAT (sysid
255/comp 190) followed by the captured DO_REPOSITION COMMAND_INT re-framed with a fresh timestamp and
signature. The frame builder (`x25()`, `build()`, `heartbeat()`) lives in
`workspace/9127-severed-link/solve.py`; note the saved `solve.py` is an earlier COMMAND_LONG probe, so
the final winning COMMAND_INT send and the gateway's full replies come from `notes.md`.
