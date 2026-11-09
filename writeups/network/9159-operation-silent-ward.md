# Operation Silent Ward

> Network · Hard · CSA Romania  
> Points: 821 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{f75f58ab}`

**Tools used**

tshark, python3 (standard library).

**Challenge**

> A compromised medical-imaging device leaked patient data across a hospital network. The DICOM
> capture, device configuration, access ledger, SNMP alerts, and recovered exfiltration stream must
> be treated as corroborating evidence rather than independent answers. Reconstruct the intrusion and
> recover its marker.

The brief spells out the hash recipe, so all the work is pinning each field from corroborating
evidence across five files (`hospital_network.pcap`, `dicom_device.xml`, `patient_records.csv`,
`snmp_trap.log`, `exfil_stream.bin`):

```
sha256("<dicom_serial>:<snmp_iso_timestamp>:<leak_count>:<anomaly_count>:<manifest_seed>")[:8]
```

**Approach / walkthrough**

**1. Device configuration → serial and seed**

`dicom_device.xml` is the reference point: who the device is, where it may send data, its seed.

```sh
grep -nE "serial_number|DeviceManifestSeed|dicom_port|<port>|<protocol>" dicom_device.xml
```

```
<serial_number>MEDSCAN-XR400-2019</serial_number>
<dicom_port>104</dicom_port>
<ip_address>198.51.100.42</ip_address>  <port>8443</port>  <protocol>HTTPS</protocol>
<DeviceManifestSeed>8842</DeviceManifestSeed>
```

So `dicom_serial = MEDSCAN-XR400-2019` and `manifest_seed = 8842`. Note the topology: the imaging
device (10.20.30.45) speaks DICOM on port 104 to its internal archive (10.20.40.10), and the only
external host in the config is a "backup" at 198.51.100.42 configured for **HTTPS on port 8443**. Raw
DICOM (port 104) to that host is off-spec by definition.

**2. SNMP trap log → seed agreement and the incident start**

The log opens with four simultaneous `linkDown` traps (core router, both distribution switches,
patient-records server) at `2026-09-01T00:00:00Z`. The bulk of the file is that same four-device
pattern repeating at 00:00/06:00/12:00/18:00 daily through Sep 15:

```sh
grep -c "linkDown" snmp_trap.log   # 240
grep -c "ANOMALY"  snmp_trap.log   # 8
awk 'END{print NR}' snmp_trap.log  # 249  (240 linkDown + 8 ANOMALY + 1 boot report)
```

The eight `[ANOMALY]`-tagged lines are bulk-walks from the external host using the stolen community
string `hospital_mgmt_2026`, one per day Sep 1–8 — identical except for the date. **This is the
trap:** no artifact can single one of them out. The boot report confirms the seed and anchors the
timeline:

```
2026-09-01T00:00:01Z ... deviceBootReport Device: MEDSCAN-XR400 DeviceManifestSeed=8842
```

`DeviceManifestSeed=8842` agrees with the XML, and the device "boots" one second after the opening
linkDown burst.

**3. Leaked-record count**

```sh
tr -d '\r' < patient_records.csv | awk -F, 'NR>1{c[$8]++} END{for(k in c) print k, c[k]}'
```

```
Leaked 90
```

All 90 data rows carry status `Leaked`, so `leak_count = 90`. The file is CRLF, so the `tr -d '\r'`
matters — without it the last column reads `Leaked\r` and never matches.

**4. Packet capture → anomaly count**

```sh
tshark -r hospital_network.pcap -q -z conv,tcp
```

Three conversations: 10.20.30.45 → 10.20.40.10:104 (50 frames, internal, normal); **10.20.30.45 →
198.51.100.42:104 (20 frames, 168 kB)** — the imaging device pushing DICOM to the *external* host on
port 104, a host the config only knows as an HTTPS backup; and 10.20.40.10 → 198.51.100.42:8443 (HTTP
`POST /api/upload`). Frames 1–50 are routine C-ECHO-RQ handshakes; frames 51–70 are C-STORE-RQ data
pushes, every one to the external host:

```sh
tshark -r hospital_network.pcap -Y "dicom && ip.dst == 198.51.100.42 && tcp.dstport == 104" \
  -T fields -e frame.number | awk 'END{print NR}'
```

```
20
```

`anomaly_count = 20` — the number of C-STORE-RQ frames the device pushes to the external host on
DICOM port 104.

**5. Decode the exfil stream (corroboration)**

`exfil_stream.bin` is 87 bytes XORed with the device serial as a repeating key:

```python
serial = "MEDSCAN-XR400-2019"
blob = open("exfil_stream.bin", "rb").read()
plain = bytes(b ^ serial.encode()[i % len(serial)] for i, b in enumerate(blob))
# b'198.51.100.42\x00...\x20\xfbward_exfil_2026\x00...'
```

Out comes the exfil's packing slip: the backup IP `198.51.100.42` in ASCII, then `20 fb` = 8443
big-endian (the HTTPS port from the XML), then the marker `ward_exfil_2026`. This confirms the
external host receiving the C-STOREs really is the IT-configured backup, and the serial does double
duty as the XOR key.

**6. Pin the timestamp (the only genuine puzzle)**

The bait is the eight `[ANOMALY]` bulk-walks — but they are identical events stamped one per day
(all at 03:15Z), and the capture window (00:00:30Z → 01:30:55Z, all on Sep 1) doesn't overlap any of
them. The intended "anomalous event" must be the one that actually starts the incident. Chronology:

| UTC time | What happens |
| --- | --- |
| 2026-09-01T00:00:00Z | Four simultaneous linkDown traps open the log |
| 2026-09-01T00:00:01Z | Imaging device boots, self-reports `DeviceManifestSeed=8842` |
| 2026-09-01T00:00:30Z | Capture begins (routine C-ECHO-RQ) |
| 2026-09-01T00:25:05Z | First of 20 C-STORE-RQ to 198.51.100.42:104 |

The network collapses, the device boots one second later, the capture picks up thirty seconds after
that, and everything flows from that opening moment. So `snmp_iso_timestamp = 2026-09-01T00:00:00Z`.

**7. Assemble the flag**

| Field | Value | Anchored in |
| --- | --- | --- |
| dicom_serial | `MEDSCAN-XR400-2019` | XML (also the XOR key) |
| snmp_iso_timestamp | `2026-09-01T00:00:00Z` | opening linkDown burst |
| leak_count | `90` | all 90 ledger rows Leaked |
| anomaly_count | `20` | 20 C-STORE-RQ to 198.51.100.42:104 |
| manifest_seed | `8842` | XML, echoed by boot report |

```python
material = "MEDSCAN-XR400-2019:2026-09-01T00:00:00Z:90:20:8842"
print("CSCTF{" + hashlib.sha256(material.encode()).hexdigest()[:8] + "}")   # CSCTF{f75f58ab}
```

The flag is **`CSCTF{f75f58ab}`**.

**Why it works**

Each attachment pins exactly one field and each field is anchored twice: the serial is also the XOR
key; the seed is in the XML and the boot report; the backup host appears in the config, the capture,
and the decoded blob; the counts come straight out of the data (90 leaked rows, 20 C-STORE-RQ frames
to an external IP on the DICOM port). The only genuine puzzle is the timestamp, where the obvious
`[ANOMALY]` lines are a trap (daily, indistinguishable, outside the capture window) and the true
incident start is the opening linkDown burst.

**Validation / reproduction**

A script reads all five fields from the evidence, asserts the seed agrees between XML and trap log,
and computes the hash. Only the timestamp field was genuinely ambiguous. The saved workspace records
three rejected candidates — the first and last `[ANOMALY]` lines (both `03:15:00Z`, on 09-01 and
09-08) and the boot-report time (`00:00:01Z`) — before the recipe resolved to the log's opening
linkDown burst at `2026-09-01T00:00:00Z`; .dev landed that value for the credited solve.

Reproduction: SHA-256 of `MEDSCAN-XR400-2019:2026-09-01T00:00:00Z:90:20:8842`, keep the first eight
hex. Gotchas: strip `\r` before counting Leaked rows; count C-STORE-RQ frames to the external host on
port 104 (not the internal C-ECHO handshakes); and take the incident-start timestamp, not the
`[ANOMALY]` decoys.
