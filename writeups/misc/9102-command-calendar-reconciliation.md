# Command Calendar Reconciliation

> Misc · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{Eeh2RYL9qlIO3A2Hema1QimW}`

This challenge runs in `flag_mode: random`: the restoration code is minted per spawned instance, so the value above is the one returned by the instance solved in this session and will differ on any relaunch. What reproduces is the method, not the literal string.

**Challenge**

The per-team instance is a small web service, but the puzzle is an iCalendar (RFC 5545) recurrence-expansion problem, not a web exploit. The brief: *a hostile edit scrambled an emergency relay calendar during a communications outage; rebuild the activations and submit a UTC attestation.* It serves two endpoints:

- `GET /brief` — the response window (a half-open date range), the per-record shape `{uid, recurrence_id_utc, start_utc, end_utc, category}`, the ordering rule ("sort by start"), and the exact attestation JSON format.
- `GET /case.ics` — the exported iCalendar file with the recurring events.

Each relaunch generates a fresh calendar, so everything below was derived from the running instance's own `/brief` and `/case.ics`, never from cached data. The instance is launched through the CTFd `docker_per_team` plugin (`POST /containers/api/request {"chal_id": 9102}`, then poll `GET /containers/api/view_info`) and came up at `http://<instance>` for this session; all work stayed on that assigned address.

**Approach / walkthrough**

1. **Read the brief.** For this instance the response window was `[2026-07-20, 2026-08-04)` — half-open, so the upper bound is exclusive. The decisive rule: membership is decided on the activation's *actual* start (after any override is applied), not on the nominal recurrence slot. The brief expected exactly 24 records, each serialized as `{uid, recurrence_id_utc, start_utc, end_utc, category}` and sorted by `start_utc`.

2. **Read the calendar.** `/case.ics` held three master `VEVENT`s, each an `RRULE` with a mix of `RDATE` additions, `EXDATE` removals, and detached overrides (each carrying its own `RECURRENCE-ID` plus `DTSTART`/`DTEND`):
   - **relay-1** — `RRULE:FREQ=DAILY;INTERVAL=2;COUNT=12` from `07-16`, plus `RDATE 07-21`, `EXDATE 07-26`, and two detached overrides: `RECURRENCE-ID 07-20` moved to `07-19 07:00` (which pushes it *out* of the window) and `RECURRENCE-ID 08-05` moved to `08-03 07:00` (which pulls it *into* the window).
   - **relay-2** — `RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=12` from `07-20`, plus `RDATE 07-25`.
   - **relay-3** — `RRULE:FREQ=DAILY;INTERVAL=2;UNTIL=08-04T13` from `07-17`, plus `RDATE 07-20`.

3. **Expand in strict RFC 5545 order.** The whole challenge is doing these operations in the right order and testing the window on the overridden start:
   1. Generate the nominal recurrence set from each `RRULE` (respecting `COUNT`/`UNTIL`/`INTERVAL`/`BYDAY`).
   2. Add `RDATE` instances.
   3. Remove `EXDATE` instances.
   4. Replace any instance whose slot matches a detached override's `RECURRENCE-ID` with the override's own values — including the override's own `DTEND`, since an override can change the duration.
   5. Only *now* filter on the actual `start_utc` against the half-open window.
   6. Sort by `start_utc`.

   Re-derived at write-up time from the rules above (2026-07-20 is a Monday):

   | Master | In-window activations | Count |
   |---|---|---|
   | relay-1 | nominal 07-22, 07-24, 07-28, 07-30, 08-01, 08-03 (07-16/07-18 before the window; 07-20 overridden out to 07-19; 07-26 `EXDATE`'d) + `RDATE` 07-21 + override RID 08-05 now starting 08-03 07:00 | 8 |
   | relay-2 | MO/WE/FR 07-20, 07-22, 07-24, 07-27, 07-29, 07-31, 08-03 + `RDATE` 07-25 | 8 |
   | relay-3 | 07-21, 07-23, 07-25, 07-27, 07-29, 07-31, 08-02 (07-17/07-19 before; 08-04 excluded by the half-open bound) + `RDATE` 07-20 | 8 |

   8 + 8 + 8 = **24**, matching the count the brief called for. Note relay-1 ends with two activations on 08-03: its own nominal slot and the 08-05 instance moved onto that date.

4. **Build and submit the attestation.** A short per-instance Python script performed steps 1–6, serialized the 24 records into the attestation JSON exactly as `/brief` specified, and posted it:

   ```
   POST /attest    { ...24 activations, sorted by start_utc, in the brief's format... }
   ```

   The server validated the set and returned the restoration code:

   ```
   routing_authorization: CSCTF{Eeh2RYL9qlIO3A2Hema1QimW}
   ```

**Why it works**

The traps are all ordering mistakes in a naive expansion. Filtering the nominal slots against the window *before* applying overrides loses the 08-05 slot that moved to 08-03 and keeps the 07-20 slot that moved to 07-19 — both wrong. Other traps: dropping an override's own modified `DTEND`; letting an `EXDATE`'d slot reappear; and treating the upper bound of the half-open window as inclusive. `EXDATE`/`RDATE` and overrides interact (an `EXDATE`'d slot must not come back; an override replaces rather than adds). Follow the RFC 5545 operation order and test membership on the overridden start, and the 24-record set is unambiguous.

**Validation / reproduction**

The expansion produced exactly the 24 records the brief called for, and `/attest` accepted the set and returned the code — a single self-checking confirmation, since a wrong set is rejected. The first three CTFd submissions came back `ratelimited` (platform-wide pacing during the wave rush, never a judged verdict); the same single value was accepted on a later send. The operational lesson recorded during the solve: a `ratelimited` response is not a verdict, so it is neither counted toward the 3-wrong guard nor deduped — the same reasoned flag is resent once the limit clears.

Reproduction: spawn the instance and record its address; `GET /brief` (window, record fields, sort key, attestation shape); `GET /case.ics` and parse every `VEVENT` (masters with `RRULE`/`RDATE`/`EXDATE`, and detached overrides with `RECURRENCE-ID` + their own `DTSTART`/`DTEND`); expand nominal → add `RDATE` → remove `EXDATE` → apply overrides (replace, keep override `DTEND`) → filter on actual `start_utc` against the half-open window → sort by `start_utc`; serialize to the brief's format and `POST /attest`.
