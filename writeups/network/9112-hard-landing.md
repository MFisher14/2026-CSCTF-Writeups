# Hard Landing

> Network · Easy · Teodor Giurgica  
> Points: 120 · Flag submitted by: secretNinja

**The flag:** `CSCTF{deO4drdLuz4O6DjkoCyYBg18}`

**Tools used**

Python standard library (`zlib` to gunzip the login responses, `hmac` to check the signing scheme),
and one small signing script for the live command.

**Challenge**

> A flight-safety console that supports an allied air base accepted destructive commands from a
> workstation its administrator never used. New logins are disabled, but the exposed session is still
> live. Review the incident capture and access log, recover the administrator's session material, then
> issue the documented safe recovery command with a fresh valid signature. The live console returns
> the recovery code only after authenticating that command.

`hard-landing.zip` holds a cleartext-HTTP capture of the console (`192.0.2.20:8080`), the access log,
and ops notes. The live console is a per-team instance (`<instance>`).

**Approach / walkthrough**

**1. Read the access log**

```
11:22:00Z LOGIN   src=192.0.2.11 role=administrator session=adm-2aca3785b702d3ef824b9cb8 result=issued
11:22:08Z COMMAND src=192.0.2.11 session=adm-2aca3785b702d3ef824b9cb8 command=STATUS            result=accepted
11:23:00Z COMMAND src=192.0.2.14 session=adm-2aca3785b702d3ef824b9cb8 command=DISABLE_SAFETY_LINK result=accepted
11:23:06Z COMMAND src=192.0.2.14 session=adm-2aca3785b702d3ef824b9cb8 command=DIVERT_FROM_CORRIDOR result=accepted
11:23:12Z COMMAND src=192.0.2.14 session=adm-2aca3785b702d3ef824b9cb8 command=SUPPRESS_RECOVERY   result=accepted
```

The admin session `adm-2aca3785b702d3ef824b9cb8` was issued to `192.0.2.11`, but the three destructive
commands came from `192.0.2.14` using that same session — and all were `accepted`. So the attacker had
more than the session ID: it could produce valid signatures.

**2. Reassemble the HTTP streams and gunzip the login responses**

The capture is 70 frames (all IPv4/TCP) forming 7 request/response pairs (2 logins, 5 signed
commands), all to `192.0.2.20:8080`. Both `POST /api/login` responses are `Content-Encoding: gzip`
(so `strings` shows nothing); reassemble the TCP stream and decompress. The admin login body:

```json
{"session":"adm-2aca3785b702d3ef824b9cb8",
 "key":"2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1",
 "role":"administrator"}
```

The login response returns, over plain HTTP, both the session ID *and* the per-session HMAC signing
key. That is the whole flaw: the key that authenticates commands is handed to anyone on the path.
(Each session ID is the role prefix plus the first 24 hex of its key, so the ID alone already leaks 12
of the 32 key bytes — not needed here.)

**3. Recover the signing canonicalization**

Each `POST /api/command` carries `X-Session`, `X-Timestamp` (Unix seconds) and `X-Signature` (64 hex).
The scheme that reproduces every captured signature is method / path / timestamp / raw body, each on
its own line, keyed by the session key as raw bytes:

```python
import hmac, hashlib
K = bytes.fromhex("2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1")
body = '{"cmd":"DISABLE_SAFETY_LINK","aircraft":"N17"}'
assert hmac.new(K, f"POST\n/api/command\n1789644180\n{body}".encode(),
                hashlib.sha256).hexdigest() == \
       "ba9c331216bff716d4613ebd9c2abda444a0b1413a08a1cc21e6b5dd0bda5434"
```

The body is compact JSON (`separators=(",",":")`, no spaces) so the signed bytes equal the bytes sent.
This reproduced all five captured signed requests before anything was sent live:

| Source (key) | Timestamp | Command |
| --- | --- | --- |
| 192.0.2.10 (operator) | 1789644030 | STATUS |
| 192.0.2.11 (admin) | 1789644128 | STATUS |
| 192.0.2.14 (admin) | 1789644180 | DISABLE_SAFETY_LINK |
| 192.0.2.14 (admin) | 1789644186 | DIVERT_FROM_CORRIDOR |
| 192.0.2.14 (admin) | 1789644192 | SUPPRESS_RECOVERY |

**4. Drive the live console (team-assigned instance only)**

Against the team's own assigned instance, an unauthenticated `GET /api/status` reported lockdown, a
300-second freshness window, a `server_time` field (the instance sends no `Date` header, so the solver
reads the timestamp from this field), and the documented safe recovery body
`{"cmd":"RETURN_TO_PAD","pad":"A1"}`. One signed `POST /api/command` with the stolen admin session, the
`server_time` timestamp, and the recovered key returned the receipt:

```
200 {"status":"aircraft returned to pad A1","recovery_receipt":"CSCTF{deO4drdLuz4O6DjkoCyYBg18}"}
```

Only the documented benign command was sent, once; none of the destructive commands from the incident
were replayed.

**Why it works**

TLS was absent and the console returned the HMAC key in the login body, so a passive observer gets
both the session ID and the key and can sign arbitrary commands. The admin session was never revoked,
so the same material still signs a fresh command. The MAC itself is sound; the weakness is key
handling.

**Validation / reproduction**

Before any live request, the signing scheme was confirmed offline against the captured signed requests
(`notes.md` records it "verified on 3 captured requests", the three destructive admin commands); the
capture in fact holds five signed requests — the operator and admin `STATUS` plus the three
destructive commands — and a re-check for this write-up reproduced all five signatures exactly. Only
the documented benign recovery command was sent, once; the console returned the receipt and the flag
was accepted on the first submission.

Reproduction: stdlib pcapng parse → group TCP payloads by 4-tuple → order by sequence number → split
at `\r\n\r\n` → `zlib.decompress(body, 47)` on the gzip login responses to recover session+key →
verify the HMAC canonicalization against the five captured requests → sign one `RETURN_TO_PAD` with
the server's `server_time`. Gotcha: the login body is gzip, the freshness window is server-enforced
(read `server_time`), and the body must be serialized compactly so the signed bytes match the sent
bytes.
