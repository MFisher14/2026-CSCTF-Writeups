# Dark Anchorage Reconciliation

> Network · Medium · Chronos Security  
> Points: 270 · Flag submitted by: secretNinja

**The flag:** `CSCTF{MwKOMuhetXfXTXVV5SSGUj6G}` (per-instance 24-char random body; `flag_mode:
random`, so a relaunched case mints a different flag)

**Tools used**

None beyond standard CLI utilities and a short Python script.

**Challenge**

> Kaldura, an Operation Dawn ally, carries coalition traffic over the KALNET-1 cable, and KALNET-1
> failed just as a hostile maritime operation was expected near the cable corridor. AIS says no
> suspicious vessel crossed the fault envelope, yet coastal radar recorded anonymous contacts on a
> different clock. Produce the complete sensor-reconciliation report that identifies the false
> broadcast, quantifies the displacement and establishes the actual closest approach. Read
> `GET /schema` for the report format. Submit one complete report to `POST /reconcile`; a correct
> report returns the reconciliation code.

This is not a flag-in-a-file challenge. A per-team service (`<instance>`) serves four evidence files
(`/files/ais.ndjson`, `/files/radar.csv`, `/files/cable-fault.txt`, `/files/method-note.txt`) plus a
`/schema`, and returns the flag only when a fully correct, machine-checked reconciliation report is
POSTed. There is no judge to probe: the report must be reasoned to correctness in one shot and
submitted once. (The evidence is case-specific — a relaunch regenerates it — so the numbers below are
the recovered values for the solved case as recorded in `notes.md`; a fresh instance has different
coordinates, timestamps and MMSIs, but the method is invariant.)

**Approach / walkthrough**

Fetch the four files and the schema read-only from the assigned instance, then follow `method-note.txt`.

**1. Clock skew**

AIS reports are UTC. The `radar.csv` header declares `local_time = UTC + 60 min`, so the radar runs
one hour ahead. Before anything can be compared, subtract 60 minutes from every radar timestamp so the
two feeds share a UTC timeline. This is the "different clock" the briefing flags.

**2. Project to a local tangent plane**

Project both feeds about the cable reference latitude `lat0` so residuals come out in meters:

```
east  = R * cos(lat0) * dlon
north = R * dlat
```

with `dlon`, `dlat` in radians relative to the reference point and `R` the Earth radius. For the solved
case the cable point was `50.14389610, 19.97026911` and the fault window `11:28–11:42Z`.

**3. Associate radar tracks to AIS vessels**

For each radar-track/MMSI pairing, compare positions at the shared UTC instants and take the **median
positional residual** over the overlapping samples. Match each radar track to the MMSI that minimizes
it. After the clock correction, the 16 radar tracks (`R-01..R-16`) map one-to-one onto the 16 MMSIs:
every correct pairing has median residual ~0 m, every wrong pairing sits ≥230 m apart. The bijection is
forced — no guessing.

**4. Identify the false broadcast**

Within the matched pairs, the per-sample residuals (not the median) expose the spoof. For the solved
case, radar track `R-10` ↔ MMSI `978484787`: over a short window (11:34Z–11:40Z) its AIS-minus-radar
offset is a *constant* `(+360 m east, +300 m north)`; outside that window it reconciles to zero, so its
median residual is still ~0 m and the association stands. A constant, non-zero offset — rather than
random residual — is the fingerprint of a deliberately displaced spoof: the AIS self-report was shifted
by a fixed vector to place the vessel outside the cable-fault envelope, while radar shows where it
actually was. The displacement vector is `(+360, +300) m`.

**5. Establish the actual closest approach**

Using the **radar** track (the sensor that cannot be spoofed) for `R-10`, compute the closest point of
approach to the cable point. On the radar segment 11:30Z→11:32Z the closest-approach parameter is
`u = 0.818`, giving a CPA time of `11:31:38Z` at distance ~0 m — the real track crosses directly over
the cable point, inside the fault window. That is the physical event the spoofed AIS was meant to hide.

**6. Build and submit the report**

The report JSON matched the `GET /schema` structure:

- `associations`: the full `{radar_track, mmsi}` bijection;
- `divergence`: `{mmsi: 978484787, start_utc: 11:34Z, end_utc: 11:40Z, ais_minus_radar_east_m: 360, ais_minus_radar_north_m: 300}`;
- `closest_approach`: `{mmsi: 978484787, utc: 11:31:38Z, distance_m: 0.0}`.

```
POST /reconcile   <report JSON>
-> 200  "incident export verified"  + reconciliation code (the flag)
```

The service accepted the first POST — the data-driven derivation left nothing to guess, which is
exactly what a no-judge, one-shot report demands.

**Why it works**

Two independent sensors on different clocks let a physical observation (radar) catch a self-reported
lie (AIS). A *constant* displacement vector, rather than random residual, is the fingerprint of a
deliberate broadcast shift, and the median residual is insensitive to the short displaced burst, so
the spoofed vessel still pairs to its true track and the real closest approach is read off the sensor
that cannot be spoofed.

**Validation / reproduction**

The service checks the report and returns the reconciliation code only for a fully correct one; it
accepted our first POST. The first four CTFd submissions of that code came back `ratelimited`
(team-wide pacing, never judged — these do not count against the 3-wrong guard, which counts only
`incorrect`), and the fifth send of the same value was accepted. Because the flag is bound to the
per-team instance (`flag_mode: random`), the instance was kept running until CTFd accepted it.

Reproduction (method, invariant across cases): correct the 60-minute radar skew, project both feeds to
a meter plane about the cable latitude, match tracks to MMSIs by minimum median residual, read the one
constant-offset pair as the spoof, and compute CPA from its radar track. Gotcha: the raw evidence,
`/schema` response and solve script were not saved (the workspace `files/` is empty), so the exact
JSON typing/rounding the schema required is recorded only by field name.
