# Countersign

> Crypto · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{WQVGFSnaCT0ETBUNKJ8X2xVt}`

**Challenge**

Sarnovia's national grid dispatch console signs every substation command with a keyed hash. From an intercepted session you are given one legitimate `STATUS` command, its signature, and the console's signing specification. On an isolated training replica, make the console accept a `DISPATCH` command — the order that would trip a transmission breaker — without the key. An accepted `DISPATCH` returns the authorization code, which is the flag.

There are no static files. Everything lives behind a per-team container instance (CTFd container plugin, HTTP on port 8080, reached here as `<instance>`). Three endpoints matter:

- `GET /api/spec` — the signing specification.
- `GET /api/sample` — one intercepted legitimate record and its tag.
- `POST /api/command` — takes a signed message and its tag; a valid `DISPATCH` returns the authorization code.

**Tools used**

The repo's SHA-256 length-extension helper (`solvers/common/modern_crypto.length_extension`) and a short Python loop to post forged commands to our instance. No `hashpumpy` needed.

**Approach / walkthrough**

1. **Read the spec (`GET /api/spec`).** The tag is `SHA-256(key_bytes || message_bytes)` — a textbook **secret-prefix MAC**. The spec discloses the key-length band `key_length_band_bytes = [8, 32]`. The message parser is quirky and the quirk is the whole challenge: split the message on `&`, split each token on the first `=`, keep only keys matching `^[A-Za-z][A-Za-z0-9_]*$`, and **last value wins** for a repeated key. The command field is `cmd`.

2. **Read the sample (`GET /api/sample`).** The intercepted record is

   ```
   message: station=TIELINE-08&cmd=STATUS&ts=1760064576&nonce=45f9a50c
   signature: 7083f2b0...125a   (full 64-hex SHA-256 tag)
   ```

   This is a valid `STATUS` command whose `cmd` we need to flip to `DISPATCH`.

3. **Why length extension applies.** `SHA-256` is Merkle–Damgård: the 32-byte tag *is* the full internal hash state after absorbing `key || message || glue_padding`. Anyone holding the tag can resume hashing additional bytes without knowing `key`. The only unknown that changes the result is `len(key)`, because that fixes where the glue padding lands — and the spec hands us the band `[8, 32]`, so there are only 25 candidates to resolve against our own training endpoint.

4. **Forge.** For each candidate key length `klen` in `8..32`, extend the sample message with the suffix `&cmd=DISPATCH`:

   ```python
   import sys; sys.path.insert(0, 'solvers/common')
   from modern_crypto import length_extension
   # length_extension(algo, orig_digest_hex, orig_data, append, secret_len)
   fm, ft = length_extension('sha256', orig_tag_hex,
                             b'station=TIELINE-08&cmd=STATUS&ts=1760064576&nonce=45f9a50c',
                             b'&cmd=DISPATCH', klen)
   # fm = original || 0x80 || zero fill || 8-byte big-endian bit length || &cmd=DISPATCH
   # ft = the resumed SHA-256 tag over key || fm
   ```

   Then `POST /api/command` with the forged `{message: fm, tag: ft}` to our assigned instance and stop on the first `DISPATCH_ACCEPTED`.

5. **The glue lands cleanly.** The glue padding for any `klen` in the band is `0x80`, zero fill, and an 8-byte big-endian bit length between `0x0210` and `0x02d0` (always a multiple of 8). None of those bytes is `&` (`0x26`) or `=` (`0x3d`), so the padding never starts a new token: it is simply appended to the last original value, turning the `nonce` token into `nonce=45f9a50c\x80\x00…\x02\x98`. The key `nonce` is still a valid identifier, so the parser keeps the token with a junk value nothing checks. The appended `&cmd=DISPATCH` is then a clean, well-formed second `cmd` token, and **last value wins** makes `DISPATCH` override `STATUS`. The parsed keys of the forged message come out as `station, cmd, ts, nonce, cmd`.

6. **Resolve the key length.** Walking the band and posting each forge, `klen = 25` was accepted. This is a reasoned single-value search over a disclosed parameter band against our own training instance — not a flag brute-force. The accepted response:

   ```json
   {"status":"DISPATCH_ACCEPTED","authorization_code":"CSCTF{WQVGFSnaCT0ETBUNKJ8X2xVt}"}
   ```

**Why it works**

A secret-prefix MAC publishes its hash's full internal state as the tag. Merkle–Damgård construction then lets anyone continue the hash past the original message, appending chosen bytes and computing a valid tag for the extended input — the key is never needed, only its length. Combined with a parser that silently absorbs the binary glue into the previous value and lets a repeated `cmd` override the earlier one, the extension turns a signed `STATUS` into a signed `DISPATCH`. An HMAC (which does not expose its internal state), or a parser that rejected duplicate keys or non-printable bytes, would have stopped this.

**Validation / reproduction**

The server returned `DISPATCH_ACCEPTED` with the code, and it was accepted on the first CLI submission (`tried.json`: one attempt, status `correct`).

For the write-up the forge was re-run offline against a random 25-byte stand-in key, which does not touch the target:

```bash
.venv/bin/python -c "
import sys,hashlib,os; sys.path.insert(0,'solvers/common')
from modern_crypto import length_extension
k=os.urandom(25); m=b'station=TIELINE-08&cmd=STATUS&ts=1760064576&nonce=45f9a50c'
t=hashlib.sha256(k+m).hexdigest()
fm,ft=length_extension('sha256',t,m,b'&cmd=DISPATCH',25)
print(hashlib.sha256(k+fm).hexdigest()==ft)
print([x.split(b'=',1)[0] for x in fm.split(b'&')])
"
# True
# [b'station', b'cmd', b'ts', b'nonce', b'cmd']
```

The forged tag equals `SHA-256(key || forged_message)` exactly, and the parsed keys end in a second `cmd`. The `0x0298` length field (664 bits = 83 bytes = 25 key + 58 message) only holds for `klen = 25`, which is why the length had to be resolved; but the "no `&`/`=` in the glue" argument holds for every length in the band, not only 25.

Reproduction summary: spawn the instance; read `/api/spec` and `/api/sample`; confirm the MAC is secret-prefix SHA-256 and note the `[8,32]` band; for each `klen` forge `message + "&cmd=DISPATCH"` and `POST /api/command`; `klen=25` returns the code.

Gotchas: the sample's full 64-hex tag, the exact `POST` body field names, and how the binary glue was encoded on the wire were read live and not preserved verbatim in `notes.md`; only the engine (`length_extension`), the accepted length (`klen=25`), the suffix (`&cmd=DISPATCH`), and the final response/flag are recorded.
