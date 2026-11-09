# Onion Deanon 2: Read the Favicon

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{-209798607}`

**Challenge**

Task 1 of the "Onion Deanon 2" lab. DarkPigeon runs its victim negotiation portal as a Tor hidden service — onion routing only, no clear-web domain. Scope: simulated environment, reach it with Tor, stay passive, only the single host you identify is in scope. The forum post hands you the address:

```
[ DARKPIGEON ] NEW VICTIM: Coop & Crumb Birdseed Wholesalers
Victim portal (Tor Browser): http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion
```

The task wants the portal's favicon hashed "the way Shodan does", returned as a signed integer.

**Tools used**

tor (local SOCKS proxy), curl, file; python3 with mmh3 (run via uv).

**Approach / walkthrough**

1. **Start a private Tor daemon.** Use a non-default SOCKS port so it won't collide with another tor:

   ```sh
   /opt/homebrew/opt/tor/bin/tor --SocksPort 9055 --DataDirectory /tmp/tor9170
   ```

   Wait for `Bootstrapped 100% (done)`.

2. **Load the portal index (passive GET #1).** `--socks5-hostname` hands the name to Tor for resolution; `.onion` names only resolve inside Tor, so plain `--socks5` would fail on a local DNS lookup:

   ```sh
   ONION="http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion"
   curl -s --max-time 120 --socks5-hostname 127.0.0.1:9055 -D index.hdr -o index.html "$ONION/"
   head -8 index.html
   ```

   The page is the DarkPigeon negotiation portal (case CC-0417, victim Coop & Crumb, matching the forum post). Its head names the icon: `<link rel="icon" href="/favicon.ico" type="image/x-icon">`.

3. **Fetch the favicon (passive GET #2).** Same route, now for the icon:

   ```sh
   curl -s --max-time 120 --socks5-hostname 127.0.0.1:9055 -D fav.hdr -o favicon.ico "$ONION/favicon.ico"
   file favicon.ico
   ```

   The headers show `200 OK`, `Content-Type: image/x-icon`, `Content-Length: 6434`; `file` reports a three-image Windows icon (16×16 and 32×32 PNG frames) — a real `.ico`, not an error page wearing the name. Its SHA-256 is `195873a07c938f21ef8c016048230bc84861d08653e8c01ccf3620089c848dea`.

4. **Reproduce Shodan's favicon hash exactly.** Shodan's `http.favicon.hash` is MurmurHash3 computed over the *MIME base64* encoding of the raw icon bytes (base64 with a newline every 76 chars and a trailing newline, i.e. what Python's `codecs.encode(..., "base64")` emits — not the single-line `base64.b64encode`), read as a signed 32-bit integer:

   ```python
   import codecs, pathlib, mmh3
   data = pathlib.Path("favicon.ico").read_bytes()
   print(len(data), mmh3.hash(codecs.encode(data, "base64")))
   ```

   ```sh
   uv run --with mmh3 python3 favhash.py
   ```

   ```
   6434 -209798607
   ```

   The byte count equals `Content-Length`, so the whole file went into the hash. Wrap the signed integer as-is.

**Why it works**

Tor hides the portal's network location, but not what it serves: the favicon reaches every visitor as ordinary bytes. Shodan indexes favicons by a content hash — MurmurHash3 over the standard-MIME base64 of the icon — precisely because that value depends only on the bytes, not on the address they came from. So the number computed through the onion equals the number Shodan stores for any clear-web host serving the identical file, which makes `http.favicon.hash:-209798607` a search key for finding where else this portal lives (the pivot Tasks 2–4 use). The minus sign is simply the 32-bit MurmurHash3 result read as a signed integer — exactly the form the answer asks for.

**Validation / reproduction**

The hash was computed with the reference `mmh3` package and cross-checked against an independent MurmurHash3 implementation; both give `-209798607`. Base64 *without* newlines yields a different value (`-1362675922`), confirming the standard-MIME encoding is the one Shodan uses. Accepted on the first submission. To reproduce: fetch `/favicon.ico` over Tor, confirm it is the full 6434-byte three-image ICO, then MurmurHash3 its `codecs.encode(data, "base64")` form. Gotcha: the base64 line-wrapping is load-bearing — the one-line `b64encode` form hashes differently and is wrong.
