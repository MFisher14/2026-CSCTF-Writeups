# Water Hammer Reconciliation

> Network · Medium · Cosmin Gorea / HiveHack  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}`

**Tools used**

unzip, tshark (for inspection), python3 (standard library).

**Challenge**

> Reconstruct the complete confirmed Modbus/TCP control history and submit the reconciliation
> identifier the evidence supports. `water-hammer-reconciliation.zip` holds `reserve-header.pcapng`,
> `station-profile.txt` and `capture-manifest.txt`. The profile defines the scoped conversation, the
> confirmation rule, the safety screen, the report grammar and the submission encoding. The capture
> holds ordinary reads, one exception and one unanswered write — a write acknowledgement on its own is
> not a confirmed control snapshot, so follow the profile's matched-readback rule. Flag format:
> `CSCTF{message}`.

`capture-manifest.txt` is only provenance; everything computed is defined in `station-profile.txt`.

**Approach / walkthrough**

**1. Read the station profile**

- **Scope.** Only the TCP conversation `192.0.2.10 → 192.0.2.20:502`, unit ID 17, read as fully
  reassembled byte streams. Each Modbus/TCP ADU is a 6-byte MBAP header (transaction ID, protocol
  ID = 0, Length) followed by `Length` bytes.
- **Registers.** Holding registers `0x1000`–`0x1003` are `p` (pump target), `g` (gate opening), `a`
  (ARMED) and `r` (ramp time, µs).
- **Confirmation rule.** A write is a *confirmed snapshot* only when a valid FC16 write to
  `0x1000`–`0x1003` is echoed (one normal response, same transaction ID), the **very next client
  ADU** is the FC3 readback `03 1000 0004`, and that readback returns exactly one normal response
  carrying the four register values. The snapshot values are those four registers; rows are ordered
  by the frame of the FC16 response, and the row's `tid` is the FC16 transaction ID, **not** the
  readback's (the profile warns about this explicitly).
- **Report.** `R` is the version line `water-hammer-reconciliation-v2`, the initial tuple, `n=64`, one
  `i=...;tid=...;p=...;g=...;a=...;r=...` line per snapshot, and a final `unsafe-mask=` line, joined
  with LF and no trailing LF. The identifier is RFC-4648 Base32 (no padding) of the first 24 bytes of
  `SHA-256(R)`.

The safety screen that produces the mask:

```
initial_tuple=p=80;g=500;a=0;r=60000
E_i=floor(P_i*G_i/1000)
V_i=floor(E_i*1000000/70686)
Q_i=998*1065*abs(V_i-V_(i-1))
T_US=floor(2*20000*1000000/1065000)=37558
UNSAFE_i=1 iff A_i=1 and R_i<T_US and Q_i>9000*100000
```

`V_(i-1)` is the **previous row's** velocity, so `V` carries row to row; only row 0 is compared with
`V_-1 = 565` (from the initial `p=80, g=500`). Row `i` sets bit `63-i`. The profile also ships a
public test vector (two synthetic rows with expected SHA-256 and Base32) to check the report/encoding
code before touching the capture.

**2. Look at the Modbus traffic**

```sh
tshark -r reserve-header.pcapng -q -z conv,tcp
```

One conversation, `192.0.2.10:36853 ↔ 192.0.2.20:502`, 536 frames. The client splits most requests
across two TCP segments, which is why the profile insists on reassembled streams. The first real
write is transaction `2000`: FC16 start `1000`, quantity 4, values `007e 0352 0001 257a` =
126, 850, 1, 9594; frame 17 echoes `10 1000 0004`; the readback `03 1000 0004` (transaction `8000`)
returns the same four values. That is one confirmed snapshot. Listing every ADU shows the full shape:

```
    4  client  tid=E010  fc=3   len= 6
    6  server  tid=E010  fc=3   len=11  regs=80,500,0,60000
   11  client  tid=E100  fc=16  len= 9  regs=120
   13  server  tid=E100  fc=16  len= 3  exception=4
   15  client  tid=2000  fc=16  len=15  regs=126,850,1,9594
   17  server  tid=2000  fc=16  len= 6
   19  client  tid=8000  fc=3   len= 6
   21  server  tid=8000  fc=3   len=11  regs=126,850,1,9594
   ...
  531  client  tid=E101  fc=16  len= 9  regs=96        (no response)
```

The 267 ADUs per side line up with the brief: harmless FC3 reads (`E010`/`E011` at the start return
the initial tuple; `E012`/`E013` at the end repeat the final snapshot); one FC16 exception (`E100`,
code 4); one unanswered write (`E101`); and in between, 64 rounds of FC16 write → echo → FC3 readback →
readback response. That is 4×2 + 2 + 1 + 64×4 = 267.

**3. Rebuild the history and derive the identifier**

tshark is for looking; the profile's rules are about exact bytes, so the reconciliation is a small
standard-library Python script. It walks the pcapng's Enhanced Packet Blocks, reassembles both TCP
directions by sequence number (remembering which frame completed each byte), splits into strict MBAP
ADUs, and applies the confirmation rule. The confirmation core:

```python
echo = b"\x10" + struct.pack(">HH", start, qty)
# one normal echo, same tid; the very next client ADU must be the FC3 readback
if resp["pdu"] != echo: drop()
nxt = client[k + 1]
if not (nxt["pdu"] == READBACK and nxt["frame"] > resp["frame"]): drop()
# readback answer: MBAP Length 11, PDU 03 08 + 8 data bytes -> the snapshot
p, g, a, r = struct.unpack(">4H", back["pdu"][2:])
rows.append((resp["frame"], resp["tid"], p, g, a, r))   # ordered by FC16 response frame
```

The unsafe mask uses the carried velocity:

```python
prev = velocity(80, 500)                       # V_-1 = 565
for i, (_tid, p, g, a, r) in enumerate(rows):
    v = velocity(p, g)
    q = 998 * 1065 * abs(v - prev)             # against the PREVIOUS row's velocity
    if a == 1 and r < 37558 and q > 9000 * 100000:
        mask |= 1 << (63 - i)
    prev = v
```

Running it reproduces the profile's public test vector first (so the layout and encoding are right),
drops the exception and the unanswered write, and leaves exactly 64 snapshots:

```
public test vector: IAO7QJHG2XIJQ5I2PR7OA6WYEEPRHF7OO6M6QOA OK
FC16 tid E100 (frame 11): dropped, response 9004 is not a normal echo
FC16 tid E101 (frame 531): dropped, 0 responses
confirmed snapshots: 64
...
unsafe-mask=D3FC7C00A3060000
sha256: 5ed614c21145f080d0a30043752cfa210f61a29903351dde2485f0da0564b8f3
CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}
```

The mask `D3FC7C00A3060000` has 22 of 64 bits set. To see the carried velocity at work (998×1065 =
1062870; the limit is 900000000):

| i | p, g | E | V | ΔV from previous row | Q | unsafe |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 126, 850 | 107 | 1513 | 948 (vs 565) | 1007600760 | 1 |
| 1 | 147, 239 | 35 | 495 | 1018 | 1082001660 | 1 |
| 2 | 104, 837 | 87 | 1230 | 735 | 781209450 | 0 |
| 3 | 156, 143 | 22 | 311 | 919 | 976777530 | 1 |

Bits `1101` give the leading `D`. If every row were compared against `V_-1 = 565` instead, rows 1 and
3 would flip to 0 (ΔV of 70 and 254) and the hash would change — exactly the bug the solver first hit.
The flag is **`CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}`**.

**Why it works**

The profile reduces the capture to one deterministic text, so the only real decision is which writes
count. An FC16 echo only proves the request was accepted; pairing it with the immediately following
FC3 readback proves the state actually held, which is why exactly 64 snapshots survive. The screen is
a bounded Joukowsky water-hammer check — `Q` is the surge ρ·a·ΔV with density 998 and wave speed 1065,
and `T_US` is the pipe's 2L/a reflection time — so a row is unsafe when an armed, fast ramp changes
the flow velocity enough to push the surge past the limit. The velocity carried from the prior row is
what makes the surge calculation, and thus the mask, correct.

**Validation / reproduction**

The profile ships a public test vector (two synthetic rows with expected SHA-256 and Base32); running
the report/encoding code against it matched before touching the capture. Four submissions in total:
the team's automated intake sent two wrong values at release, both copied from the brief's placeholder
text, before any analysis. The solver's first real submission was also wrong — a bug kept every row
compared against `V_-1` instead of the previous row's velocity, so the mask was wrong. With the
per-row carry restored, the mask came out as `D3FC7C00A3060000` (22 of 64 rows), and that flag was
accepted. The 64-snapshot count and all per-row evidence checks (ARMED=1, ramp under threshold,
changed velocity) hold.

Reproduction: run `reconcile.py` against `reserve-header.pcapng` after confirming the public test
vector. Gotcha: carry `V` from the previous confirmed row (not a constant seed), confirm each write
with its immediately-following FC3 readback, and label rows by the FC16 transaction id rather than the
readback's.
