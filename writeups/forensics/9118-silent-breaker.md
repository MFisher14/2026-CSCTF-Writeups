# Silent Breaker

> Forensics · Medium · Dan-Andrei Grigorescu  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{CmBWwc0Qds8aFImcMJTsSftS}` — the clearance code is random per instance; this was ours. The method carries over, the numbers do not.

**Challenge**

A per-team Docker container served a signaling investigation console and a forensic bundle from a substation's IEC 60870-5-104 network: a regional breaker tripped without warning, reconstruct what happened and who is responsible. `GET /files/` serves a case-file index and the report contract; `GET /events` is the flagged-signaling feed; a completed five-field report goes to `POST /submit`, which returns the recovery-authorization flag for a correct report. CTFd is never queried directly — all work was done against our own spawned instance (`<instance>`), through only the documented routes.

`GET /files/` served: `README.md` (the report contract, routes, budgets, `/submit` field definitions), `roster.json` (8 fictional staff with `employee_id`, department, `ot_vpn_access`, MSISDN), `iec104_capture.pcap` (127 packets, master `192.0.2.10:51000` ↔ RTU `198.51.100.10:2404`), and `hmi_monitoring.log` (historian breaker-current log for IOA `0x2c88`). Lookups are budgeted — `GET /query/subscriber` budgeted, `POST /confirm-target` 2 attempts, `GET /query/vpn-window` budgeted after confirm, `POST /submit` 5 reports with pass/fail only — so every field was derived offline before any attempt was spent.

**Approach / walkthrough**

*1. Rogue signaling peer → compromised employee.* `GET /events` lists 8 MAP operations, all from one global title outside the legitimate `GT-0000..GT-0999` range (our instance: `GT-9724-V88`), so every event is the attacker's. They split into `SendRoutingInfoForSM` (SRI-SM reconnaissance) and three `UpdateLocation` operations — registering the subscriber at an attacker-controlled location, which hijacks their SMS and with it any OTP. Joining the three `UpdateLocation` MSISDNs against `roster.json`, only one target has `ot_vpn_access: true` (our instance: `+882-16-6461297` → `VLK-4216-ION` Radu Ionescu, OT Field Engineering). The roster carries three people surnamed Ionescu, so the join must key on `employee_id`, not name. One budgeted `GET /query/subscriber?msisdn=…` returned `{"known_subscriber":true,"watchlisted":true}`, and `POST /confirm-target {"employee_id":"VLK-4216-ION"}` confirmed on the first of its 2 attempts, unlocking the VPN query.

*2. OT-VPN session.* `GET /query/vpn-window` returns RADIUS logs. The target's session is an Access-Request → Access-Challenge ("Enter OTP") → Access-Accept completing about 100 s after the hijacking `UpdateLocation`, which fits an SMS-OTP intercept (our instance: `session-id VPN-320493`). A second Ionescu (Legal) has a session in the same minute as a decoy, so again key on `employee_id`.

*3. The breaker command on the wire.* The solver host had no tshark, so the pcap was walked with a short Python libpcap/IEC-104 APCI reader: Ethernet → IPv4 → TCP, split the payload into `0x68`-start APDUs, keep I-frames, decode ASDU type/COT/IOA/element. The capture holds only TI 13 (`M_ME_NC_1`, short-float measurements) and two TI 45 (`C_SC_NA_1`, single command) frames. One TI 45 is an activation (COT 6) to IOA `0x2c88` with `SCO=0x01` — low bit SCS=1 = **ON**, S/E=0, a direct execute with no select-before-operate; the other is the RTU's activation confirmation (COT 7). These give the IOA `0x2c88`, qualifier `ON`, and the command minute in UTC (our instance: `19:50`, wire time, not the VPN start).

*4. The forged historian current.* `hmi_monitoring.log` normally reads ~430 A for IOA `0x2c88`. Around the command it holds flat at a constant value (our instance: 524.5 A) and is marked `QUALITY=SUSPECT` from the third identical reading onward. That value is inside the contract's 150–550 A engineering range and more than 5 A off live, as the contract defines a frozen record. Over the same window the pcap's TI 13 floats keep reporting ~431 A with good QDS and COT 1 (periodic), so the RTU's data was live and only the historian display was frozen. → `telemetry_status` = the frozen value (our instance: `524.5`).

*5. Report.* One `POST /submit` with the five fields (IOA, qualifier, command time, frozen telemetry, VPN session) returned `{"status":"correct", "attempts_remaining":4, "clearance_code":"CSCTF{…}"}` — accepted on the first report. The clearance code was submitted to CTFd once and accepted, and the instance was stopped afterwards.

**Why it works**

The attack chain crosses two domains. An SS7 `UpdateLocation` from an illegitimate peer redirects the engineer's SMS, which lets the attacker pass the OTP step of the engineer's OT-VPN login. IEC-104 has no authentication, so a single direct-execute `C_SC_NA_1` operates the breaker. Replaying a stale value into the historian hides the trip from operators. The wire capture disagrees with the historian — the frozen value never appears in the QDS on the wire — and that disagreement is what exposes the forgery.

**Validation / reproduction**

Every field was fixed offline and cross-checked (pcap TI 13 against the historian for the current, RADIUS timing against the `UpdateLocation` for the session) before the first report. The instance accepted that first report with 4 of 5 attempts left, and the returned clearance code was accepted by CTFd on its single submission. Reproduction (against a fresh instance): decode the IEC-104 command with any dissector (e.g. `tshark -r iec104_capture.pcap -Y iec60870_asdu.typeid==45`) or the plain-Python APCI walk, join the rogue `UpdateLocation` MSISDNs against `roster.json` on `ot_vpn_access`/`employee_id`, match the VPN session by employee id, and read the frozen value against the wire. The flag is random per instance, so the specific values above only apply to ours.
