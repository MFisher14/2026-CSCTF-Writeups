# Ghost Signal

> Network · Hard · CSA Romania  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{28358943}`

**Tools used**

tshark, python3 (standard library), shasum.

**Challenge**

> A telecom operator is seeing fraudulent roaming activity and disputed billing events.
> Investigators recovered SS7 signalling, Diameter sessions, and the related billing export.
> Reconstruct the intrusion chain from those records and recover its marker. Flag format:
> `CSCTF{8_lowercase_hex}`

Three artifacts — an SS7 capture, a Diameter capture, and a billing export — describe one telecom
intrusion. The flag is not in any file (`grep -c CSCTF` returns 0 on all three); it is an 8-hex
marker built from the values the three records agree on.

**Approach / walkthrough**

**1. Decode the SS7 capture**

SS7-over-IP is a stack: SCTP → M3UA → SCCP (Global Title addressing) → TCAP (transactions) → GSM MAP
(the operations that matter). `tshark -r ss7_capture.pcap -q -z io,phs` shows all 60 frames decoding
down to `gsm_map`, so no Decode-As is needed. One trap: the MAP operation code lives in
`gsm_old.localValue`, not `tcap.opCode`. List each message with its caller, opcode and numbers:

```sh
tshark -r ss7_capture.pcap -T fields -E header=y \
  -e frame.number -e frame.time_epoch -e sccp.calling.digits \
  -e gsm_old.localValue -e gsm_map.address.digits
```

Operation `22` is sendRoutingInfo (SRI), `45` is SRI-for-SM, `2` is updateLocation; all 60 go to the
same HLR, GT `40721000100`. The structure:

- Frames 1–45: background traffic, one query every 3 s, each from a different calling GT (49100,
  49101, …), cycling numbers 40721000200–209.
- After an 18 s gap, a single attacker GT **49211** works a target list. Frames 46–50 send SRI for
  40721000101–105, one every 4 s, starting at **1723740150** (2024-08-15 16:42:30 UTC).
- Frames 51–55: the same GT sends SRI-for-SM for the same five numbers.
- Frames 56–60: a second GT, 49311, sends five `updateLocation` requests.

This is the classic SS7 attack shape — routing queries learn where a number is served, then an
outsider `updateLocation` tells the HLR the subscriber has moved behind the attacker's switch.

**2. Find the victim IMSI in SS7**

The routing queries only carry phone numbers. The IMSI appears only in the `updateLocation` burst:

```sh
tshark -r ss7_capture.pcap -Y 'gsm_old.localValue == 2' -T fields -E header=y \
  -e frame.number -e e212.imsi -e gsm_map.ms.msc_Number -e gsm_map.ms.vlr_Number
```

All five frames carry IMSI **226012014000001** (MCC 226 = Romania, MNC 01). Beware the decoys here:
tshark prints the MSC number raw as `c19413f1` — eight lowercase hex, exactly the flag shape — but it
is only a TBCD-encoded address (`c1` header, `94 13 f1` = low-nibble-first digits with `f` filler =
MSC 49311). The TCAP transaction ids (`tcap.otid`, e.g. `49210002`) are more eight-character decoys.

**3. Find the rogue session in the Diameter capture**

The Diameter capture is the IMS Cx interface (CSCF ↔ HSS). List each message:

```sh
tshark -r diameter_capture.pcap -T fields -E header=y \
  -e frame.number -e frame.time_epoch -e ip.src -e diameter.cmd.code \
  -e diameter.flags.request -e diameter.Origin-Host -e diameter.Session-Id
```

Command 301 is Server-Assignment. Frames 1–24 are twelve routine request/answer pairs from four
CSCFs (10.40.0.41–44). After a ~95 s gap, frame 25 arrives from a new address `10.40.0.99` at exactly
**1723740150** — the same second as SS7 frame 46 — calling itself `cscf.rogue.evil-domain.net`, with
Session-Id **`hss.eastern-tele.ro;1723740150;49211`**: the time field is the attack second and the
counter field is the SS7 attacker's GT, 49211. Who does it register?

```sh
tshark -r diameter_capture.pcap -Y 'frame.number == 25' -T fields -E header=y \
  -e diameter.Subscription-Id-Data -e diameter.Public-Identity
```

```
226012014000001	sip:+40721000101@eastern-tele.ro
```

The user is the SS7 IMSI, and the public identity is +40721000101 — the first number GT 49211
queried. The HSS answer (frame 26) succeeds (2001) and hides data in a malformed AVP: code 272
(Multi-Round-Time-Out) should be a 4-byte integer but holds 42 bytes, so Wireshark flags it. Pull the
raw bytes:

```sh
tshark -r diameter_capture.pcap -Y 'frame.number == 26' -T fields -e diameter.avp.invalid-data \
  | python3 -c 'import sys; print(bytes.fromhex(sys.stdin.read()).decode())'
```

```
diameter://intercept-49211.evil-domain.net
```

A hidden interception endpoint, tagged 49211 again.

**4. Filter the billing export**

The export's metadata `filter_note` says: "All billing events — filter by the IMSI and session
corroborated by the signalling captures." Filtering on the IMSI and Session-Id recovered above
isolates exactly ten events (of 40) — the only ten carrying an `anomaly` field:

```
1723740150 atk_0000   CCR-I +40721000101 0.0 zero_charge_on_roaming intercept-49211.evil-domain.net
1723740154 atk_0001   CCR-I +40721000102 0.0 zero_charge_on_roaming intercept-49211.evil-domain.net
...
1723740170 pivot_0000 CCA   -            -   unusual_routing_path   redirect-49211.evil-domain.net
...
```

`atk_0000`–`atk_0004` are zero-charge `CCR-I` events at 1723740150, 154, 158, 162, 166 — exactly the
times of SS7 frames 46–50 — each naming the number that frame queried, with `redirect_host` set to
the host hidden in Diameter frame 26. `atk_0000` is at **1723740150**, the second shared by SS7 frame
46, Diameter frame 25 and the billing event.

**5. Build the marker**

Nothing in the files is the flag, so it is built from the reconstruction: join the corroborated
values with `:`, SHA-256, keep the first 8 hex. The billing note names two of the values itself (the
IMSI and the session); the captures back both up. The third is the shared attack epoch. The field
order follows the billing note (IMSI, then session) with the attack time appended:

```sh
printf '%s' '226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150' | shasum -a 256
```

```
28358943473f95eb307747e985e8e07a933b69f9a9129afea922d0ba912177e0  -
```

The first eight hex give **`CSCTF{28358943}`**. (`echo` would append a newline and hash to a
different digest — use `printf '%s'`.)

A short script reads the three values from the billing export and confirms each against both captures
before hashing — the same IMSI in the SS7 `updateLocation` and the Diameter frames, and the same
session opening at the attack second:

```python
imsi, session, when = atk0["imsi"], atk0["session_id"], atk0["timestamp"]
gt = session.split(";")[2]                                   # 49211
assert int(ss7_first_query_from(gt)) == when                 # SS7 frame 46 at 1723740150
assert ss7_updateLocation_imsis() == {imsi}                  # frames 56-60
assert int(diameter_session_open(session)) == when           # Diameter frame 25 at 1723740150
preimage = f"{imsi}:{session}:{when}"
print("CSCTF{%s}" % hashlib.sha256(preimage.encode()).hexdigest()[:8])   # CSCTF{28358943}
```

**Why it works**

The three feeds are one event seen from three sides: SS7 reconnaissance and a location hijack, a
rogue Diameter registration for the victim, and zero-charge billing for the targeted numbers. The
marker is SHA-256 over the values the records corroborate — the victim IMSI and the rogue session the
billing note names as its selectors, plus the one timestamp all three share. Decoy eight-character
values abound (TCAP transaction ids, the TBCD-encoded MSC/VLR addresses), but only the
IMSI/session/epoch triple is cross-corroborated.

**Validation / reproduction**

We worked this challenge independently in parallel, and in the end .dev is the one who figured it out.
With no stated construction, both of us tested ranked candidates from the evidence through the early
hours. The organizers then published a public #news clarification covering this challenge, Operation
Blackout and Phantom Drift: the flag is built rather than found — take the values that match across
artifacts, join them with `:`, SHA-256, and keep the leading hex. The corroborated values were the
IMSI, the rogue session ID named by the billing note, and the attack epoch shared by all three
records, which gives the preimage above. A script reads the three values from the billing export and
confirms each against both captures before hashing. The value was accepted about an hour after the
clarification. (A later clarification, "3 values, one per artifact", matches this preimage.)

Reproduction: SHA-256 of `226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150` (no
trailing newline), keep the first eight hex. Gotcha: pull the IMSI from the `updateLocation` frames
(the only ones carrying it), do not mistake the TBCD-encoded MSC/VLR addresses for the marker, and
read the hidden intercept host from the malformed 272 AVP in Diameter frame 26.
