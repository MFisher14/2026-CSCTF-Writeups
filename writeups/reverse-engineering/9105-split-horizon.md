# Split Horizon

> Reverse engineering · Medium · Dan-Andrei Grigorescu  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{KoKRYKUJoLqzJda22tiJHAA0}` (a per-team random flag, returned by the challenge instance as the `incident_token`)

**Challenge**

A TL-9 Vireo reconnaissance UAV of the Aurelian Air Surveillance Corps drifted off its approved waypoint mid-sortie. The command server's signed audit trail says the flight was nominal — every waypoint within tolerance, hash chain intact — yet a state actor (tracked as Sable Drift) is believed to have injected a single crafted command. The player is the attribution analyst: given the uplink capture, the drone software, and the signed audit trail, prove the waypoint the drone actually flew and explain why the server never saw it. The CTFd attachment is only a `README.txt`; the real artifacts are generated per team and served by the team's own container instance at `/files/`, with `GET /schema` giving the submission format and `POST /submit` taking the report.

Pulled from our assigned instance into the workspace:

| File | What it is |
| --- | --- |
| `session.pcap` | uplink capture: a TCP session (Hellos both ways, then command/telemetry frames), plus a `curl` fetch of `/vireo-ctl.dll` |
| `vireo-ctl.dll` | the drone's flight-control client (.NET assembly) |
| `command-server.go` | the ground server's audit-trail generator |
| `manifest.json` | mission `AV-18F48D`, approved waypoint `47.8091, 20.0478`, tolerance `0.001` deg, audit pubkey |
| `audit.log` | 9 hash-chained entries, all `NOMINAL`, with an Ed25519-signed summary |
| `sigint.txt` | framing: treat the pcap and drone software as primary evidence, the log as corroboration |

**Approach / walkthrough**

*1. Reverse the drone client (`vireo-ctl.dll`).* Decompile the .NET assembly with `ilspycmd` (output saved as `files/vireo.cs`; static only, the DLL is never run). The protocol in `Vireo.Uplink.Protocol`:

- **Framing:** `"VW"` magic (`0x56 0x57`), a 1-byte type (1 Hello, 2 Command, 3 Telemetry), and a big-endian u16 length.
- **Handshake:** each side sends a 16-byte random nonce in a Hello. Then `session_key = HMAC-SHA256(key = MaskA XOR MaskB, msg = clientNonce || serverNonce)[:16]`, where `MaskA` and `MaskB` are two 32-byte arrays hard-coded in the DLL — the "shared secret" ships inside the client.
- **Commands:** type-2 payloads are repeating-key XOR with the 16-byte session key (`Protocol.Mask`).
- **Parsing:** `CommandCodec.Parse` calls `System.Text.Json.JsonSerializer.Deserialize<CommandEnvelope>` with a *default* `JsonSerializerOptions()`. Properties bind via `[JsonPropertyName("waypoint_lat")]` and friends. Default options match property names **case-sensitively**, so only the exact lowercase keys bind; `WAYPOINT_LAT` is ignored.

*2. Read the ground server (`command-server.go`).* The server parses the same JSON with Go's `encoding/json` v1 `json.Unmarshal`, whose key matching is **case-insensitive, and on a duplicate key the last value wins** (the source comments say so directly). It checks `|lat - approved| <= 0.001` and `|lon - approved| <= 0.001` on the waypoint it parsed, then logs `NOMINAL`/`WAYPOINT_MISMATCH` with a salted commitment `SHA-256(salt || "%.6f|%.6f")` over that waypoint. The coordinates themselves are never logged, and the salt is never published.

*3. Decrypt the uplink.* Reassemble both directions of the TCP stream and split into VW frames. The two Hello nonces are client `7b2841d28c6f2a963d88963ad7b39da7` and server `ff5a19c1373b584372e2bab978929f08`; deriving the key gives `3585fe3780ab616df2fd1a2aa56af02a`. XOR each type-2/3 payload with it (scapy + hmac, run with `python -I`, no artifact executed):

```python
S   = bytes(a ^ b for a, b in zip(MaskA, MaskB))          # 32-byte arrays from the DLL
key = hmac.new(S, client_nonce + server_nonce, hashlib.sha256).digest()[:16]
pt  = bytes(c ^ key[i % 16] for i, c in enumerate(payload))
```

The decrypted command stream (waypoint fields only):

| seq | waypoint_lat / lon (lowercase) | duplicate UPPERCASE keys |
| --- | --- | --- |
| 1, 6, 8 | 47.8091 / 20.0478 | none |
| 2 | 47.8090 / 20.0477 | `WAYPOINT_LAT 47.8090`, `WAYPOINT_LON 20.0477` (same values — decoy) |
| 3, 7, 9 | 47.8091 / 20.0477 | none |
| 4 | 47.8090 / 20.0477 | none |
| **5** | **47.8104 / 20.0518** | **`WAYPOINT_LAT 47.8099`, `WAYPOINT_LON 20.0469`** |

Two telemetry frames (type 3) report the drone at `gps_lat 47.8104, gps_lon 20.0517`.

*4. The injected command.* Seq 5 carries the waypoint keys twice — lowercase first, uppercase second — with *different* values:

- **Drone (System.Text.Json, case-sensitive):** binds only `waypoint_lat`/`waypoint_lon` → flies to **47.8104, 20.0518**, about 330 m off the approved point. The telemetry fix `47.8104, 20.0517` matches it by value.
- **Server (Go encoding/json v1, case-insensitive, last wins):** `WAYPOINT_LAT`/`WAYPOINT_LON` overwrite the same fields → it validates and commits **47.8099, 20.0469**, which is within 0.001 deg of approved `47.8091, 20.0478` (dlat 0.0008, dlon 0.0009), so it logs `NOMINAL`.

Seq 2's uppercase duplicates hold the same values as its lowercase pair, so seq 2 is a decoy; seq 5 is the only command where the two parsers disagree.

*5. Report.* `GET /schema` defined a JSON report. `POST /submit` carried: executed waypoint `47.8104 / 20.0518`, logged waypoint `47.8099 / 20.0469`, injected command `seq 5`, affected fields `waypoint_lat` + `waypoint_lon`, mechanism `case_insensitive_last_wins_vs_case_sensitive_exact`. The instance answered `correct` with an `incident_token` — the flag — which was then submitted to CTFd (`./csctf submit 9105 'CSCTF{KoKRYKUJoLqzJda22tiJHAA0}'`) and accepted on the first attempt.

**Why it works**

This is a parser differential. Two standard JSON libraries disagree on duplicate keys that differ only in case, so one wire message means two different things. The drone's case-sensitive parser acts on the lowercase pair; the server's case-insensitive, last-wins parser validates the uppercase pair. The audit trail is honest about what the *server* parsed — which is exactly why the hash chain and Ed25519 signature verify — but the server never saw the waypoint the drone actually acted on.

**Validation / reproduction**

Offline, each `entry_hash = SHA-256(prev || "prev_hash|seq|status|commit")` recomputes from genesis (32 zero bytes) to the `chain_root`, and the Ed25519 signature over the root verifies under the manifest's `audit_pubkey_b64`. Commitments line up with waypoint values: equal waypoints share a commitment (seq 1/6/8 share `45810f53...`, seq 3/7/9 share `21d022a3...`, seq 2/4 share `d5197779...` — confirming seq 2's duplicate keys changed nothing), and seq 5's `f025ed86...` is the only commitment that appears once. The instance's report checker returned `correct`; the token `CSCTF{KoKRYKUJoLqzJda22tiJHAA0}` was accepted by CTFd on the first submission (`tried.json`).

Reproduction summary: decompile `vireo-ctl.dll` → recover the framing, the `MaskA`/`MaskB` arrays, and the HMAC key schedule → reassemble the pcap, take both Hello nonces, derive key `3585fe37...`, XOR each payload → read the per-seq JSON, spot seq 5's case-differing duplicate keys → compute both parsings → report server-behaviour-first. Gotchas: the derived key is the first 16 bytes of the HMAC only; the capture is synthetic, so the telemetry corroborates seq 5 by value, not by frame timing (the two telemetry frames sit just before the seq-4 and seq-7 commands and travel in the same ground-to-drone direction); and the `/submit` checker is the instance's report grader, not the CTFd judge — a first attempt with the *drone-first* mechanism ordering returned `correct:false`, and swapping to server-first order passed (that miss did not count against CTFd). Note the description's "~380 m" drift versus the ~330 m seq-5 offset we computed from the approved point; the exact figure was not pursued and does not change the attribution.
