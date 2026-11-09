# keyring

> Web · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{hHlqboaWKbFgNq25c8RxW0aD}
```

Read from the admin console's "Break-glass access" panel and accepted on the first submission.

**Challenge**

> Kestrel ID is the staff sign-on for the Vardanne Joint Operations Directorate, which coordinates
> Vardanne's part in the Operation Dawn coalition. Liaison officers can request an account and sign in
> straight away, but the administration console is limited to directorate administrators, and it holds
> the break-glass recovery key. Recover that key. Start your own instance from this page and work only
> against the address it gives you.

A per-team web container (CTFd `docker_per_team` plugin, port 9999). No files were attached; the whole
challenge lives on the instance. Kestrel ID is a staff sign-on with open self-registration and an
admin console that holds the break-glass recovery key. All requests went only to our own spawned
instance (`<instance>`).

**Approach / walkthrough**

*Recon.* The recon stage of `workspace/9117-keyring/exploit.py` fetched a fixed list of pages (the
app's nav links plus well-known paths — not a scan):

| Path | Result |
| --- | --- |
| `/register` | open self-registration: username, password (min. 12 chars), optional full name / organisation |
| `/admin` | unauthenticated → redirect to `/login` (saved body is the "Redirecting..." stub) |
| `/developers` | integration docs for the session token |
| `/.well-known/kestrel-id.pem` | the token-signing **RSA public key** (SubjectPublicKeyInfo PEM) |
| `/.well-known/jwks.json`, `/.well-known/openid-configuration` | not present (app's "Page not found") |
| `/static/js/kestrel.js` | UI only (password reveal, expiry notice); nothing auth-related |

`/developers` laid out the whole token design: the session is a stateless **JWT** in the `session`
cookie (HttpOnly, SameSite=Lax), issuer `https://id.vjod.internal`, audience `vjod-staff`, 8-hour
lifetime, claims `sub`, `role`, `iat`, `exp`, `jti`, plus a key ID `beec83e6042a9411` and a "Download
kestrel-id.pem" link. The page says the key pair is regenerated every time the service restarts, so
the forge must fetch the **live** PEM from the running instance — a PEM saved at 08:04 during an
earlier recon had a different key (DER SHA-256 prefix `cb79dc3f267b6f5b`) than the solving instance
(`beec83e6042a9411...`). The key ID is the first 16 hex digits of SHA-256 over the DER
SubjectPublicKeyInfo. A freshly registered liaison account gets an **RS256** token with a non-admin
`role` (`user`).

*Key insight — RS256→HS256 algorithm confusion.* Authorization depends entirely on the `role` claim
inside a token the client holds, and the server publishes the verification key. If the verifier takes
the algorithm from the token header and passes the same key material to whichever check that algorithm
selects (the classic `jwt.decode(token, key)` mistake), then a token with header `alg: HS256` is
checked as an HMAC keyed with the **public key bytes**. The public key is public, so anyone can sign
as anyone. This exact hypothesis was written in `notes.md` after the first recon, with `alg=none` and
`kid`/`jku` tricks kept as fallbacks.

*Exploit* (`exploit.py <host> forge`):

1. Register a fresh liaison account (`liaison<hex>`) through `/register` and log in if no cookie was
   set yet. Read the RS256 `session` cookie.
2. Decode its header and payload, then fetch the live PEM from `/.well-known/kestrel-id.pem`.
3. Copy the payload, set `role` to `admin`, push `exp` out one hour; every other claim (`sub`, `iss`,
   `aud`, `iat`, `jti`) stays as issued.
4. Set the header's `alg` to `HS256`, keep the other header fields, and sign
   `base64url(header) + "." + base64url(payload)` with HMAC-SHA256, using the **raw PEM bytes** as the
   secret:

   ```python
   hh = dict(H); hh['alg'] = 'HS256'
   si = b64u(json.dumps(hh, separators=(',', ':')).encode()) + '.' + \
        b64u(json.dumps(P2, separators=(',', ':')).encode())
   sg = b64u(hmac.new(pem, si.encode(), hashlib.sha256).digest())
   token = si + '.' + sg
   ```

5. `GET /admin` with `session=<forged token>`. The script tries a short, ordered list of key-byte
   variants (raw PEM, stripped, stripped plus `\n`) and the fallbacks (`alg=none`, signature reuse),
   stopping at the first `CSCTF{...}` in the response. Per `notes.md`, the token keyed with the **raw
   PEM bytes** is the one that worked.

`/admin` returned 200, showed "Signed in as liaisona3fc13" and the full directory (12 accounts), and
under **Break-glass access** listed:

```
Break-glass recovery key   CSCTF{hHlqboaWKbFgNq25c8RxW0aD}
Custodian                  J6 Identity Services
```

The exploit was prepared in advance while our three-instance cap was full (`READY.md`), so the live
solve took under a minute: the recon pages are stamped 08:12:55–08:12:56, the admin page and live PEM
08:13:09 (about 15 s of scripted work), and `FLAG.txt` plus the submit record 08:13:40. The instance
was stopped afterwards.

**Why it works**

The verifier takes the algorithm from the token header and passes the same key material to whichever
check that algorithm selects. With `alg: HS256`, the "public key" becomes an HMAC secret — and the
server publishes that secret at `/.well-known/kestrel-id.pem`. Authorization rests entirely on the
self-asserted `role` claim, with no server-side role lookup by `sub`, so this single confusion is
enough for full admin access. The fix is to pin `algorithms=["RS256"]` and use a key object typed for
asymmetric verification only; a server-side role lookup by `sub` would also have stopped it.

**Validation / reproduction**

The forged token was accepted by `/admin`, where a non-admin token had been redirected to `/login`;
the recovery key appeared in a `CSCTF{...}` frame on the admin page and was submitted once through the
guarded CLI and accepted as correct (`tried.json`: one attempt, status `correct`).

```bash
# 1. spawn the per-team instance (cap 3 concurrent; this one waited for a free slot)
.venv/bin/python -c "from ctf.client import connect; from ctf.instances import Instances; print(Instances(connect()).spawn(9117))"
# 2. recon (saves pages to the scratchpad)
.venv/bin/python workspace/9117-keyring/exploit.py <host> recon
# 3. register + forge the HS256 admin token + read /admin (writes FLAG.txt)
.venv/bin/python workspace/9117-keyring/exploit.py <host> forge
```

Gotchas: fetch the PEM from the live instance every time — the key pair regenerates on restart, so a
PEM from an earlier instance will not verify. Sign with the raw PEM bytes exactly as served (the
stripped and `\n` variants were tried but the raw bytes worked), and keep all other claims unchanged.

Both details are confirmed from the saved recon: `/developers` documents "Signature public key — Key
ID `beec83e6042a9411` — Download kestrel-id.pem (PEM, SubjectPublicKeyInfo)," and states "The key
changes whenever the service restarts, so fetch it at start-up and again when a signature stops
verifying." The RS256→HS256 algorithm confusion is keyed with the raw bytes of
`/.well-known/kestrel-id.pem`, with `role=admin`, read via `GET /admin`.
