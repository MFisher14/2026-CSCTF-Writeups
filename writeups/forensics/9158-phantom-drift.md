# Phantom Drift

> Forensics · Hard · CSA Romania  
> Points: 560 · Flag submitted by: secretNinja

**The flag**

`CSCTF{5dc7cdf826f74515}`

**Challenge**

The reconnaissance drone *Valkyrie-9* drifted off its approved waypoint while the command server logged the mission as nominal. Six offline attachments: a Base64-wrapped C# (Unity/Newtonsoft) drone client, a Base64-wrapped Go command backend, a 36-byte `flight_log.bin`, the mission manifest, phase-tagged telemetry, and a radio-intercept timeline. The flag is a 16-hex-character digest wrapped in `CSCTF{...}`.

**Approach / walkthrough**

*1. Flight record.* `flight_log.bin` is a `FLGT`-magic record:

```
00000000: 464c 4754 0001 0003 0000 000c 0000 0000  FLGT............
00000010: 0000 0001 0000 0002 0220 2b51 1d11 5f5d  ......... +Q.._]
00000020: 1e0f 3753                                ..7S
```

After the magic come 16-bit `0x0001`/`0x0003` and 32-bit words `0x0c`, `0`, `1`, `2`; `0x0c` matches the 12-byte payload that follows at offset `0x18`. XORing those 12 bytes with the repeating key `Valkyrie-9` (the mission ID) decodes to `TAG:dc6836a2` — eight hex characters. The brief frames this tag as the *last* 8 hex of the flag's digest, so it is a check value, not an input (and on its own it is too short to be the 16-hex flag).

*2. Approved point.* `mission_manifest.json` gives the approved waypoint `47.2591, 19.0402` (4 dp).

*3. Diverted point and the diversion mechanism.* The single `waypoint_update` telemetry record carries the coordinates twice, under two key spellings:

```json
"waypoint_lat": 47.2591, "waypoint_lon": 19.0402,   // snake_case: approved values
"WaypointLat": 47.26,    "WaypointLon": 19.045        // PascalCase shadow: diverted values
```

This is a JSON key-shadowing (parser-differential) setup: one object that reads as on-course under one spelling while the drone is steered to the other. The diverted point `47.2600, 19.0450` is fixed by three independent sources — the shadow keys; the radio-intercept log ("WP-Bravo is at 47.2591, 19.0402 — Valkyrie-9 is at ~47.2600, 19.0450", about 380 m east of WP-Bravo); and the five `transit_to_new_waypoint` GPS samples, which step away from the approved point by the same per-axis delta (`+0.0009 / +0.0048` per sample). Because all three agree, recovering the flag never depends on pinning down the exact client/server parser behavior.

*4. Fields.* The per-axis deltas are diverted − approved, written to 6 dp (`0.000900 / 0.004800`). The displacement is the haversine distance between the two points, written to 1 dp.

*5. Pick the radius with the tag.* The displacement depends on the Earth radius chosen. The mean radius (6,371,000 m) gives 375.8 m; the WGS-84 equatorial radius (6,378,137 m) gives 376.2257… → 376.2 m. The spec concatenates the fields with no separators and SHA-256s the result; the flag is the first 16 hex of the digest, the flight-log tag the last 8:

```python
import hashlib, math
a, b = (47.2591, 19.0402), (47.2600, 19.0450)
R = 6378137                                   # WGS-84 equatorial
p1, p2 = map(math.radians, (a[0], b[0]))
h = math.sin((p2-p1)/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(math.radians(b[1]-a[1])/2)**2
d = 2*R*math.asin(math.sqrt(h))               # 376.22567159...
s = f"{a[0]:.4f}{a[1]:.4f}{b[0]-a[0]:.6f}{b[1]-a[1]:.6f}{d:.1f}"
# s == "47.259119.04020.0009000.004800376.2"
print(hashlib.sha256(s.encode()).hexdigest())
# 5dc7cdf826f74515c03f45611f58fabd2edc04382d6cf9f8696f9d83dc6836a2
#  ^ flag = first 16                                    last 8 = TAG ^
```

Only the WGS-84 string produces a digest whose last 8 hex equal the decoded flight-log tag `dc6836a2`. The flag is the first 16 hex: `CSCTF{5dc7cdf826f74515}`.

**Why it works**

The diversion is a JSON key-shadowing trick: one telemetry object carries both the approved and the diverted coordinates under two key spellings, so a reader that binds one spelling sees a compliant flight while the drone follows the other. Recovering the flag does not require reproducing the exact parser mismatch, because the diverted point is corroborated independently by the shadow keys, the radio log and the GPS track, and the embedded flight-log tag (the tail of the flag digest) confirms the final construction offline before any submission.

**Validation**

The challenge as first released gave only a one-sentence construction rule, which left the field order, number formatting and hashing open. During that phase we tested ranked candidates built from the evidence over several hours, many of them in scripted batches through `ctf.submit.guarded_submit`; the guard log shows a large number of rejected values from that period, and an automatic review also blocked one ~36-value batch as a speculative sweep (none of it submitted). The staff then posted public clarifications in the event's #news channel, and the live description was updated with a byte-exact serialization spec. At that point we dropped the candidate-ranking approach and built the value to the spec: the operator steered Codex onto the WGS-84 haversine construction, run directly under heavy human steering, and it produced the spec-compliant preimage. Before submitting, we checked it offline — the last 8 hex of its digest equal the tag decoded from `flight_log.bin` — and it was accepted on that single submission. The lesson: a hashed-serialization flag cannot be reasoned to one value until its exact byte format is known; once the organizer spec gave the format, the solve took one reasoned value, checked offline against the embedded tag.
