# Operation Blackout

> ICS · Hard · CSA Romania  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{12fcdb0d}`

**Tools used**

tshark, xxd, jq, shasum, python3 (standard library).

**Challenge**

> A regional energy grid lost power at substation 0x4A2E. The recovered SCADA capture, HMI
> configuration, PLC firmware, event log, and alarm overrides describe the same incident from
> different operational layers. Reconstruct the incident only where the evidence agrees and submit
> the resulting marker. Flag format: `CSCTF{8_lowercase_hex}`

Five static artifacts, nothing to run:

| File | Size | What it is |
| --- | ---: | --- |
| `scada_network.pcap` | 3688 B | 36-packet Modbus/TCP + HTTP capture |
| `hmi_config.xml` | 1093 B | HMI calibration routine with a hidden Modbus write |
| `plc_firmware.bin` | 1024 B | PLC image with a `PLC1` header |
| `substation_log.json` | 1689 B | 9-entry event log |
| `alarm_override.dat` | 136 B | binary `ALRM` record of threshold changes |

The marker is in none of the files. You build it from the facts the files agree on. All analysis is
static, on the host.

**Approach**

**1. The capture — polling, one write, then an upload**

`-t ud` prints absolute UTC so the output is time-zone independent:

```sh
tshark -r scada_network.pcap -t ud
```

36 frames in three phases, with nothing ever answering: frames 1–30 are `192.168.50.5` polling the
PLC `192.168.50.10:502` every 10 s (06:00:10 → 06:05:00 UTC) with function 3 (Read Holding
Registers); frame 31 at 06:05:03 UTC is a single function 16 (Write Multiple Registers); frames
32–36 (06:05:18 → 06:06:18 UTC) are the PLC itself pushing a 151-byte TCP segment to
`198.51.100.42:80` every 15 s. The raw bytes of the write:

```sh
tshark -r scada_network.pcap -Y 'frame.number == 31' -T fields -e tcp.payload | xxd -r -p | xxd -g 1
```

```
00000000: 00 02 00 00 00 17 01 10 9c 41 00 40 10 55 fa 55  .........A.@.U.U
00000010: fa 55 fa 55 fa 55 fa 55 fa 55 fa 55 fa           .U.U.U.U.U.U.
```

`00 02` transaction 2, `00 00` protocol 0, `00 17` length 23, `01` unit 1, then the PDU: `10`
function 16, `9c 41` starting register (0x9C41 = 40001 in the 4xxxx numbering), `00 40` quantity 64,
`10` byte count 16, and eight copies of `55 fa` (= 22010). The request is malformed: 64 registers
need 128 data bytes but only 16 follow — remember that for the log. The five exfil segments all carry
the same 151 bytes: an HTTP-style `HTTP POST /upload HTTP/1.1`, `Host: 198.51.100.42`, and 50
repetitions of `de ad`.

From the capture: register `40001`, quantity 64, payload `55 FA`×8, exfil host `198.51.100.42` on
port 80, write at 06:05:03 UTC.

**2. The HMI configuration**

```sh
cat hmi_config.xml
```

It reads like a quarterly calibration until a comment reveals a hidden write:

```xml
<station_id>0x4A2E</station_id>
<CalibrationRoutine>
  <name>Q3_Equipment_Calibration</name>
  <ManifestSeed>137</ManifestSeed>
  <TargetDevice ip="192.168.50.10" port="502" protocol="Modbus/TCP"/>
  <!-- Hidden Modbus write command embedded in calibration routine -->
  <HiddenModbusWrite function_code="16" start_address="40001" count="64">
    <Payload type="ALARM_OVERRIDE_PATTERN">55 FA 55 FA 55 FA 55 FA 55 FA 55 FA 55 FA 55 FA</Payload>
  </HiddenModbusWrite>
</CalibrationRoutine>
```

That `HiddenModbusWrite` is frame 31 exactly — same function, start, count and data, same PLC. The
file also gives `station_id 0x4A2E` (the brief's station), version `3.2.1`, and
`ManifestSeed 137` — the calibration seed.

**3. The PLC firmware**

```sh
xxd -g 1 -l 64 plc_firmware.bin
```

```
00000000: 50 4c 43 31 56 33 2e 32 2e 31 00 00 7f 00 00 04  PLC1V3.2.1......
00000010: 00 44 54 56 53 56 68 55 5b 56 54 5c 58 42 43 68  .DTVSVhU[VT\XBCh
```

Offsets `0x00`–`0x03` are the magic `50 4c 43 31` (`PLC1`); `0x04`–`0x09` is `V3.2.1` (the HMI's
version); `0x0d`–`0x10` is `00 00 04 00`, the file size 1024. The 19 bytes at `0x11`–`0x23` look out
of place, and exactly one single-byte XOR key turns them into `[a-z0-9_]`:

```sh
python3 -c '
blob = open("plc_firmware.bin","rb").read()[0x11:0x24]
allowed = b"abcdefghijklmnopqrstuvwxyz0123456789_"
for k in range(256):
    t = bytes(b ^ k for b in blob)
    if all(c in allowed for c in t): print(hex(k), t.decode())
'
```

```
0x37 scada_blackout_2026
```

`scada_blackout_2026` is the bait: hidden, named after the incident, and mentioned in no other file,
so nothing corroborates it. The rest of the image (from `0x24`) is filler from a GF(2) linear
recurrence over 16-bit big-endian words — another rabbit hole. What the firmware contributes is only
its first four header bytes, `50 4c 43 31`.

**4. The event log**

```sh
jq -r '.[] | "\(.timestamp)  \(.level)  \(.message)"' substation_log.json
```

```
2025-11-15T06:15:00Z  INFO      Loading Q3_Equipment_Calibration.xml configuration
2025-11-15T06:15:03Z  WARNING   Unexpected Modbus FC 0x10 write to read-only registers 40001-40064
2025-11-15T06:15:03Z  CRITICAL  Buffer overflow detected in Modbus TCP handler (247 bytes vs 128-byte limit)
2025-11-15T06:15:04Z  CRITICAL  Alarm thresholds modified — High Temp: 85°C→250°C, Low Pressure: 2.0bar→0.1bar, Overcurrent: 500A→5000A
2025-11-15T06:15:05Z  WARNING   Unusual outbound traffic to 198.51.100.42:443
2025-11-15T06:15:10Z  CRITICAL  Firmware integrity check failed — possible tampering
2025-11-15T06:30:00Z  ERROR     Power outage detected at substation 0x4A2E
```

This is the PLC's side: the HMI routine loads, the firmware flags the FC 0x10 write to the same 64
registers, a buffer overflow follows (247 B vs a 128-byte limit — and 128 B is exactly what 64
registers take), thresholds change, traffic leaves, the integrity check fails, and `0x4A2E` loses
power. The startup event also carries `manifest_seed: 137`.

Crucially, the log's clock does not agree with the capture's: the write is 06:15:03Z here but
06:05:03 UTC in the pcap, and the outbound traffic is 06:15:05Z/port 443 here but 06:05:18 UTC/port
80 in the pcap. A single 10-minute offset would reconcile the write but not the exfil, so **no
timestamp can be "agreed" between the two files.** The one time the marker uses is the log's first
`CRITICAL` event — the buffer overflow — `2025-11-15T06:15:03Z`.

**5. The alarm overrides**

```sh
xxd -g 1 alarm_override.dat
```

Magic `ALRM`, a little-endian record count `03 00`, and the station as a 32-bit LE integer
`2e 4a 00 00` = `0x4A2E`. Each of the three 42-byte records is `>HII32s` (register, original,
override, NUL-padded name); 10 + 3×42 = 136 B parses the whole file:

```
register 40100: 85 -> 250   (High Temperature Alarm)
register 40101: 200 -> 10   (Low Pressure Alarm)
register 40102: 500 -> 5000 (Overcurrent Protection)
```

These are the log's 06:15:04Z threshold changes. Note `0x55` = 85 and `0xFA` = 250, so the `55 FA`
write pattern spells the temperature override in hex.

**6. Separating decoys from agreed facts**

Lining the files up, the clean cross-artifact agreements are the station, the write register and the
calibration seed. The traps:

- `scada_blackout_2026` lives only in the firmware — nothing corroborates it.
- `55 FA` appears in several files but is a *pattern repeated eight times*, not a single value.
- `198.51.100.42` appears in pcap and log, but the port disagrees (80 vs 443), so it is not clean
  agreement.
- The two clocks disagree, so no write time is shared across files.

**7. Building the marker**

No file spells the flag out, so it is built. The construction for this class of challenge is: join
the agreed values with `:`, SHA-256, keep the first eight hex. The accepted preimage joins, in
attack-chain order through the layers, the firmware identity, the station, the first-CRITICAL
timestamp and the write register, with the calibration seed last:

| Slot | Value | Source / rendering |
| --- | --- | --- |
| firmware | `0x504C4331` | `plc_firmware.bin[0:4]` as `0x`-prefixed **uppercase** hex |
| station | `0x4A2E` | HMI `station_id`, log outage event, alarm header |
| timestamp | `2025-11-15T06:15:03Z` | log first `CRITICAL` (the overflow) |
| register | `40001` | HMI `start_address`, pcap frame 31 (`9c 41`), log `40001-40064` |
| seed | `137` | HMI `ManifestSeed`, log `manifest_seed` |

Hash with `printf '%s'` so no newline is added:

```sh
printf '%s' '0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137' | shasum -a 256
```

```
12fcdb0d35f7fde4685d2f6995958f107ec9b5dd8a2ffd74e8fd44a6ff8ea85b  -
```

The first eight hex give the flag: **`CSCTF{12fcdb0d}`**. (Using `echo` instead appends a newline and
yields a completely different digest — a common way to lose this.)

A standalone `solve.py` re-derives every field from the files and asserts that every artifact
recording a value gives the same one before hashing. Its core parses the pcap with the standard
library, pulls the HMI/log/alarm values, and checks agreement:

```python
def agree(what, *values):
    if len(set(values)) != 1:
        raise SystemExit(f"{what}: artifacts disagree: {values}")
    return values[0]

firmware = "0x" + open("plc_firmware.bin","rb").read()[:4].hex().upper()   # 0x504C4331
station  = agree("station", hmi_station, log_station, alarm_station)       # 0x4A2E
timestamp = [e for e in log if e["level"]=="CRITICAL"][0]["timestamp"]     # 2025-11-15T06:15:03Z
register = agree("register", hmi_start, pcap_register, log_first)          # 40001
seed     = agree("seed", hmi_seed, *log_seeds)                             # 137
marker = ":".join(str(v) for v in (firmware, station, timestamp, register, seed))
print("CSCTF{%s}" % hashlib.sha256(marker.encode()).hexdigest()[:8])       # CSCTF{12fcdb0d}
```

**Why it works**

The five files are one attack seen from different layers: the HMI hides a function 16 write, the
capture shows that write going to the PLC at register 40001, the log records the overflow it caused,
and the alarm file holds the thresholds it changed — all at substation `0x4A2E`. The marker
fingerprints the incident with exactly the values the artifacts corroborate (firmware identity,
station, first-critical timestamp, write register) plus the calibration seed. Any change of value,
case, field order, or a stray newline in the hashed string changes the digest completely, which is
what forces a single canonical preimage.

**Validation / reproduction**

We worked this challenge independently in parallel, and in the end .dev is the one who figured it out.
The files alone left the construction open, so both of us tested ranked candidates built from the
agreed values — reasoned permutations under an ambiguous spec, not a blind sweep — over several
hours. The platform carried no wrong-answer penalty, and the organizers, acknowledging the ambiguity,
raised the submission rate limit and issued progressive public clarifications in #news: the flag is
built rather than found, `scada_blackout_2026` is a decoy, colon-join the values the artifacts agree
on, SHA-256 and keep the leading hex, and finally that it is exactly four corroborated single values
plus the calibration seed with the leading 8 hex kept. With that, the accepted construction was the
`0x`-uppercase firmware header, then station, the first-CRITICAL ISO timestamp, register and seed, in
attack-chain order. A standalone script re-derives every field from the files and checks that every
artifact recording a value agrees before hashing. (A later staff clue confirmed exactly that field
order.)

Reproduction: hash `0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137` with SHA-256 (no trailing
newline) and keep the first eight hex. Gotcha: render the firmware header as `0x`-prefixed uppercase,
keep the fields in attack-chain order, and never let `echo` append a newline.
