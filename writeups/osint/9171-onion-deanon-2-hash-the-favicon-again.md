# Onion Deanon 2: Hash the Favicon Again

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)  
> Points: 0 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{ad866421d43a616ab0e4dd089fc94b06}`

**Challenge**

Task 2 of the DarkPigeon lab, continuing from Task 1 (same portal, `http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion`). Task 1 hashed the portal's favicon the way Shodan does (MurmurHash3, `-209798607`); this task asks for the plain MD5 of the same file, hexadecimal.

**Tools used**

`file`, `md5`.

**Approach / walkthrough**

The only input is the icon the hidden service serves, which Task 1 had already fetched over Tor and saved — so this task reuses that file rather than re-fetching. The bytes are identical and MD5 depends on nothing else.

1. **Reuse the Task 1 favicon.** Task 1 pulled `/favicon.ico` once over the Tor SOCKS proxy with `curl --socks5-hostname` (`.onion` names resolve only inside Tor). No new request to the target is sent for this task. If the file is gone, re-fetch it with one GET:

   ```sh
   ONION="http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion"
   curl -s --max-time 120 --socks5-hostname 127.0.0.1:9055 -D fav.hdr -o favicon.ico "$ONION/favicon.ico"
   ```

2. **Confirm it is the complete icon before hashing.** The captured headers show `200 OK`, `Content-Type: image/x-icon`, `Content-Length: 6434`; `file favicon.ico` reports "MS Windows icon resource - 3 icons, 16×16 / 32×32 PNG image data", not an HTML error page; and the size on disk equals the `Content-Length`. If `file` had said "HTML document", you would be about to hash the wrong thing.

3. **Take the MD5 of the raw bytes.**

   ```sh
   md5 favicon.ico
   ```

   ```
   MD5 (favicon.ico) = ad866421d43a616ab0e4dd089fc94b06
   ```

   On Linux use `md5sum favicon.ico`; `openssl dgst -md5 favicon.ico` works everywhere and prints the same 32 hex characters. Submit the lowercase digest in the flag wrapper.

**Why it works**

The favicon is the one object the hidden service hands unchanged to every visitor, so a content hash of it identifies the portal wherever else the same file is served. Different scan engines index favicons under different hashes: Shodan uses MurmurHash3 over the base64 of the file (Task 1's answer), while Censys stores the plain MD5 of the raw bytes. This task is that second form — no base64 step and no sign handling, just `md5` over the 6434 bytes nginx served. Having both hashes means the portal can be looked up in either index, which is exactly what Task 3 needs.

**Validation / reproduction**

The reused file was confirmed to be the real icon (status, content type, `file` signature, and byte count matching `Content-Length`) before hashing. .dev's agent submitted the digest once and it was accepted. Independently, secretNinja fetched the same favicon during Task 1, and its recorded SHA-256 (`195873a0...`) matches the bytes later served by the clear-web origin found in Task 3 — the same file across the onion and the clear web. To reproduce: take the Task 1 `favicon.ico` and run `md5` / `md5sum` / `openssl dgst -md5`; all three agree on `ad866421d43a616ab0e4dd089fc94b06`.
