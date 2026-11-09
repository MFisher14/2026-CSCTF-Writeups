# Fence Shift

> Reverse engineering · Medium · Teodor Giurgica  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

```
CSCTF{active_2bbb27_provisioned_3aa227}
```

**Challenge**

A constructed patrol capture shows geofence parameters changing before an aircraft left its assigned
corridor while flying border patrol for an Operation Dawn partner nation. The task: recover the flight
controller's exact decision, then evaluate every reposition request under both the confirmed active state
and the initial provisioned state. The answer is two capture-order acceptance masks, in the format
`ops_notes.txt` gives. Attachment `fence-shift.zip` (10,197 bytes, SHA-256
`f6763830ea9571940e52190d1cc4027d7f11f170b377f9b59b619e4632348fa4`) holds `fcu` (a stripped x86-64 ELF),
`mission.pcapng`, and `ops_notes.txt`. Flag format: `CSCTF{active_AAAAAA_provisioned_PPPPPP}` — each
mask is exactly six lowercase hex digits (a 22-bit value).

**Approach**

`ops_notes.txt` fixes everything except the controller logic: aircraft is MAVLink system/component 1/1
(`192.0.2.11`), ground station 255/190 (`192.0.2.40`), and a route manager (1/191) acknowledges each
reposition. Two rules matter. A ground `PARAM_SET` becomes effective only after the aircraft echoes it
back in a `PARAM_VALUE`; and a `COMMAND_ACK` only means the route manager queued the command — it is not
the fence decision. Repositions carry lat/lon in degrees × 10^7 ("e7") and altitude in metres
(`alt_cm = z * 100`). The accept/reject rule and the 28-byte block format must come out of `fcu`.

1. **Find `main`.** `fcu` is stripped; `_start` loads `main`'s address and calls `__libc_start_main`
   through its GOT slot. `objdump -d` around the entry shows `mov $0x40122b,%rdi`, so `main` is at
   `0x40122b`. `objdump -s -j .rodata fcu` reveals the verdict strings: `ACCEPT` at `0x402004`, `REJECT`
   at `0x40200b`, then `fence`, `rb`, `invalid input`, and the usage line
   `usage: fcu fence <block> <lat_e7> <lon_e7> <alt_cm>`.

2. **Recover the 28-byte block.** `main` requires `argc == 6`, `argv[1] == "fence"`, opens `argv[2]`
   with `"rb"`, `fread`s up to `0x1c` (28) bytes, and insists the read return exactly 28 with the next
   `fgetc` hitting EOF — so the block file is exactly 28 bytes. The loads that follow fix each field's
   width (`mov` = 32-bit, `movzwl` = 16-bit zero-extend) and the step-4 arithmetic fixes meaning and
   signedness:

   | Offset | Type | Meaning |
   |---|---|---|
   | +0 | int32 | centre latitude, e7 |
   | +4 | int32 | centre longitude, e7 |
   | +8 | uint32 | `GF_RADIUS_CM` |
   | +12 | int32 | `GF_ALTMAX_CM` |
   | +16 | int32 | `GF_OFS_E_CM` (shifts longitude) |
   | +20 | int32 | `GF_OFS_N_CM` (shifts latitude) |
   | +24 | uint16 | `GF_MARGIN_PC`, at most 100 |
   | +26 | uint16 | format tag, must be `0x5346` (`"FS"`) |

   `argv[3..5]` go through a `strtoll` wrapper (decimal, int32) to become lat, lon and `alt_cm`.

3. **Recover the decision.** The core (`0x40134e`–`0x40143f`) is integer-only. The constants are
   `0x2317 = 8983`, `0x1388 = 5000`, `0x2710 = 10000`, `0x64 = 100`. The `sar $0x3f` / `and $-10000`
   pair is a branch-free "−10000 if negative, else 0", and `idiv` truncates toward zero. Ported to C:

   ```c
   static int64_t e7(int32_t cm) /* cm -> degrees*1e7, rounded half away from zero */
   { return ((int64_t)cm*8983 + 5000 - (cm < 0 ? 10000 : 0)) / 10000; }

   if (b.tag != 0x5346 || b.margin_pc > 100) return REJECT;
   uint64_t u = (uint64_t)(b.margin_pc + 100) * b.radius_cm;
   if (u > 0x31ffffffff) return REJECT;
   int64_t r    = ((int64_t)(int32_t)(u/100) * 8983 + 5000) / 10000;
   int64_t dlat = lat - (b.lat_e7 + e7(b.ofs_n_cm));
   int64_t dlon = lon - (b.lon_e7 + e7(b.ofs_e_cm));
   return (dlat*dlat + dlon*dlon <= r*r && alt_cm <= b.altmax_cm) ? ACCEPT : REJECT;
   ```

   The verdict is ACCEPT when `dlat² + dlon² <= r²` *and* `alt_cm <= altmax`, measured from the
   offset-shifted centre. Both comparisons are `<=`, the fence is a flat circle in e7 units using the
   same 0.8983 factor for longitude (no `cos(latitude)` correction), and everything is integer
   arithmetic with that exact rounding — which is what makes the edge requests decidable.

4. **Decode the capture.** Wireshark does not dissect this MAVLink v2 over UDP, so a small standard-
   library decoder walks the pcapng blocks, strips Ethernet/IPv4/UDP, and checks each frame's X.25
   checksum including the per-message `CRC_EXTRA` byte (from `common.xml`). MAVLink v2 truncates trailing
   zero bytes, so payloads are right-padded before unpacking. The run reports **213 frames, 0 bad
   checksums** and a clean timeline:

   ```
   pkt 1   1/1    POSITION    lat=457913250 lon=241502100     # fence centre
   pkt 2-6 1/1    PARAM_VALUE radius 4000 / altmax 12000 / ofs 0,0 / margin 0   # provisioned
   ...
   pkt 67  255/190 PARAM_SET  GF_MARGIN_PC = 25
   pkt 68  255/190 REPOSITION #7  x=457913250 y=241506592 z=70   # before confirm -> margin still 0
   pkt 72  1/1     PARAM_VALUE GF_MARGIN_PC = 25                   # confirmation
   pkt 80  255/190 REPOSITION #8  x=457913250 y=241506592 z=70   # same point, now margin 25
   ...
   pkt 136-147  margin->0, radius->3000, ofs_e->1500, ofs_n->-1000 (all confirmed before #15)
   ...
   ```

   All 22 `COMMAND_ACK`s carry result 0 (`MAV_RESULT_ACCEPTED`); all 21 position fixes report the same
   point. Reading the ACKs as fence decisions gives `3fffff` for both masks — the decoy answer.

5. **Replay the state and build the masks.** The provisioned state is the opening burst (never changes).
   The active state applies each `PARAM_SET` only when the matching aircraft `PARAM_VALUE` confirms it.
   For each of the 22 requests, pack the current state into the 28-byte block and run the ported
   predicate; set bit *i* on ACCEPT. The solver (`solve.py`, importing the decoder) prints:

   ```
   active mask 2bbb27, provisioned mask 3aa227
   CSCTF{active_2bbb27_provisioned_3aa227}
   ```

**Why it works**

`fcu` turns a 28-byte parameter block and a requested position into ACCEPT/REJECT with nothing but
deterministic integer arithmetic, so a faithful port gives the same answer for every request. The
capture holds every input the controller used: the centre from the first fix, the provisioned
parameters from the opening burst, the moment each change was confirmed, and the 22 requests. Replaying
the `PARAM_SET`/`PARAM_VALUE` handshake in capture order yields the state the aircraft was actually
using for each request; the provisioned run shows what the original fence would have said. The two masks
differ exactly where the in-flight changes mattered.

The traps all sit on edges, and the integer rounding is what decides them:

- **Provisioned radius** `(4000*8983 + 5000)/10000 = 3593`. #2 at 3500 east is inside, #3 at 3700 east
  is outside. #4 asks for 121 m (above the 120 m ceiling) and fails; #13 asks for exactly 120 m and
  passes because the altitude check is `<=`.
- **#7 vs #8** are both 4492 east of the centre. With the 25 % margin the radius becomes
  `(5000*8983 + 5000)/10000 = 4492`, so the point lies exactly on the circle: #8 (margin 25, confirmed)
  is accepted, #7 (still margin 0) is not. Plain float math (4491.5) or truncation (4491) would wrongly
  reject #8.
- **After the second change** the centre moves by `e7(-1000) = -898` lat and `e7(1500) = 1347` lon, to
  (457912352, 241503447) — exactly #15's point. The new radius is `(3000*8983 + 5000)/10000 = 2695`.
  #21, 2695 north of the shifted centre at 120 m, lies on both the radius and altitude edges and is
  accepted. #20 is inside the provisioned 3593 but outside the shifted 2695.

The active and provisioned masks diverge only at requests #8, #11, #12, #16 and #20 — the requests the
parameter changes affect.

**Validation / reproduction**

The decoder found zero CRC failures across 213 frames, and every edge case was checked by hand against
the recovered formula (radius 3593, the 4492 boundary at margin 25, the −898/+1347 centre shift onto
#15's coordinates, the 2695 double-edge at #21). Reproduction: unpack `fence-shift.zip`; recover the
block layout and predicate from `fcu` at `0x40122b`; run the MAVLink decoder on `mission.pcapng`; replay
the provisioned and active states through the ported predicate to produce the two 22-bit masks. The flag
was accepted on the first submission.
