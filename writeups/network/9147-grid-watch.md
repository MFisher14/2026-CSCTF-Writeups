# grid-watch

> Network · Hard · Marius Merai  
> Points: 540 · Flag submitted by: secretNinja

**The flag:** `CSCTF{WUYp1Aq5GDq5Ynle9PcMNjci}` (per-instance random, 24 chars)

**Tools used**

Custom MAVLink 2 framing/signing in Python (HKDF-SHA256 validated against RFC 5869; hashlib for the
MAC).

**Challenge**

> Vultur Dynamics drones patrol the RGN-Grid high-voltage network. An adversary wants one diverted off
> its corridor. You have a packet capture of a drone's MAVLink 2 command link and live access to the
> drone itself. Make the drone accept your own reposition command. Unsigned and replayed commands are
> refused — the flag returns only from a command the drone actually accepts.

Two attachments plus a per-team TCP container (`<instance>`): `capture.tlog` (a MAVLink 2 telemetry
log of a signed command link) and `provisioning_note.md` (a recovered field-service note for the
CX-series UAV signing subsystem).

**Approach / walkthrough**

**1. Why replay is a dead end**

MAVLink 2 message signing is in force: every frame carries a 13-byte trailer and the drone refuses
anything unsigned or replayed. The depot **session signing key is never on the link** (stated in the
note and confirmed in the capture — the signatures are present but the key is not), so the capture
cannot be replayed and the session key cannot be recovered from it. The way in is a flaw in the
re-provisioning path.

**2. The provisioning-key flaw**

The note describes field re-provisioning: keys may be re-installed with a `SETUP_SIGNING` message
authenticated not by the session key but by a per-unit *provisioning key*:

```
prov_key = HKDF-SHA256(
    ikm  = serial_ascii || commissioning_epoch,   # epoch = uint64, little-endian, seconds
    salt = session_nonce,                          # announced at connect
    info = "CX-PROV/v1",
    L    = 32)
```

Every input is public, disclosed at connect, or recoverable:

- `serial_ascii` = `CX-FALCON-9951`, the leading token of the STATUSTEXT banner the drone announces at
  connect (`CX-FALCON-9951 online, patrol LEA-220-VEST` in the capture);
- `session_nonce` (the HKDF salt) — the live drone discloses a fresh `PROV NONCE <16 hex>` in a banner
  STATUSTEXT on each connect; the salt is the *raw bytes* of that hex value (hex-decoded, not the ASCII
  text);
- `commissioning_epoch` (the ikm tail, uint64 LE seconds) = `1733965123`, a fixed per-unit constant
  calibratable from the capture and confirmed live.

So we derive the provisioning key ourselves, send a `SETUP_SIGNING` signed with it to install a
signing key of our own choosing, and sign ordinary flight commands with that key from then on. The
depot session key is never needed.

**3. Rebuild the protocol from the capture**

`capture.tlog` is a tlog: each record is an 8-byte big-endian wall-clock-µs timestamp followed by one
signed MAVLink 2 frame. A from-scratch parser was validated byte-exact: X25 CRCs over the frame body
plus the per-message `crc_extra` (all pass), and the signing trailer
`link_id(1) || timestamp(6 LE) || sig(6)` with `sig = SHA-256(secret_key32 || frame_without_trailer ||
link_id || ts6)[:6]`, `incompat_flags` bit 0 set, link id 249. The 24 signed frames are five
HEARTBEATs, two STATUSTEXTs (the `CX-FALCON-9951` banner and a "signing active" notice), a COMMAND_LONG
(cmd 511 SET_MESSAGE_INTERVAL), its COMMAND_ACK, one SYS_STATUS, and 14 GLOBAL_POSITION_INT frames.

The drone HEARTBEAT payload `05 00 00 00 02 03 59 04 03` gives `type=2` (quadrotor), `autopilot=3`
(ArduPilotMega → ArduCopter), `custom_mode=5` (LOITER) — so GUIDED is `custom_mode=4` and a forged
`DO_SET_MODE` sets `base_mode=1` (CUSTOM_MODE_ENABLED). Signing timestamps are 10-µs ticks from the
airframe RTC since the commissioning epoch; a linear fit of tlog wall-clock µs against signing ticks
(`wall_us ≈ 1.73396512e15 + 9.99983·ticks`, residual < 6 µs) places the epoch at ≈ `1733965123`
(2024-12-12). Offset/epoch are degenerate from the capture alone, so the value was carried as a
hypothesis and confirmed live. The forged frames don't need absolute time anyway: read the drone's
current RTC from any incoming signed telemetry timestamp and emit `last + 1` (monotonic, inside the
window, beats anti-replay).

**4. The attack (assigned instance only)**

1. **Connect and read the banner.** The drone emits a rotating `PROV NONCE <16 hex>` STATUSTEXT and
   signed telemetry; capture the latest signed telemetry timestamp as `last_ts`. The nonce rotates on
   every connect, so it must be parsed and used within the *same* connection.
2. **Derive the provisioning key:** `HKDF-SHA256(ikm = b"CX-FALCON-9951" || epoch_u64_le, salt =
   hexdecode(nonce), info = b"CX-PROV/v1", L = 32)` with `epoch = 1733965123`.
3. **Send `SETUP_SIGNING` (msgid 256) signed with `prov_key`**, carrying our own 32-byte key and an
   initial timestamp of `last_ts + 1`. The drone replies `signing re-provisioned: new key active`.
4. **Sign the flight chain with the new key** (monotonic timestamps): `DO_SET_MODE` (176) → GUIDED
   (`base_mode=1, custom_mode=4`) ⇒ "mode GUIDED"; `COMPONENT_ARM_DISARM` (400, `param1=1`) ⇒ ACK
   result 0, "ARMED"; `DO_REPOSITION` (192) to a point off the patrol corridor ⇒ ACK result 0,
   ACCEPTED.
5. **Read the response.** The accepted reposition returns the flag in a STATUSTEXT:

```
CSCTF{WUYp1Aq5GDq5Ynle9PcMNjci}
```

`workspace/9147-grid-watch/solve.py` carries the primitives (X25 CRC, HKDF validated against RFC 5869
TC1, the frame builder/signer, the stream parser, and the SETUP_SIGNING / COMMAND_LONG / SET_MODE
payload builders); the live driver layered the banner nonce auto-read and ArduCopter specifics on top.

**Why it works**

The design error is that `SETUP_SIGNING` is authenticated by a key whose every input is derivable by
anyone who can connect and read the capture: the serial is in the STATUSTEXT banner, the drone
announces a fresh nonce at each connect, and the commissioning epoch is calibratable from the capture.
The session key is correctly kept off the link, but the re-provisioning escape hatch is not, so an
outsider can install their own key and then sign fresh, valid commands — defeating the anti-replay and
unsigned-command defenses.

**Validation / reproduction**

Protocol primitives were validated against the capture (all CRCs and signatures) and the HKDF against
RFC 5869 TC1 before going live. The live chain was accepted end to end — re-provision ("new key
active"), GUIDED, ARM (ACK result 0), reposition (ACK result 0, accepted) — confirming the epoch, the
HKDF construction and the nonce-as-salt. The reposition's STATUSTEXT returned the flag, accepted on the
first submission.

Reproduce: parse the banner, hex-decode the nonce, derive `prov_key` with `epoch = 1733965123`, install
a chosen key via `SETUP_SIGNING`, then sign GUIDED → ARM → DO_REPOSITION with monotonic `last+1`
timestamps — all in one connection. Gotcha: the nonce rotates per connect (a copied nonce is stale),
the salt is the raw bytes of the hex value (not the ASCII), and forged timestamps use `last+1` rather
than absolute RTC time.
