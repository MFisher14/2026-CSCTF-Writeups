# Onion Deanon 1: Find the Origin

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 309 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{185.146.87.136}`

**Challenge**

Task 3 of the "Onion Deanon 1" lab. Locate the real server hosting the ParsnipLocker leak blog and submit its clear-web IPv4. The answer boundary is strict: submit the one clear-web IPv4 that presents the same leaf certificate from Task 1 — not an onion relay, DNS resolver, CDN address, historical certificate host, or a guessed address. No files ship; the task plays out against the live onion service and public scan databases.

**Tools used**

tor (local SOCKS proxy), curl, openssl; Censys web search in a browser.

**Approach / walkthrough**

1. **Re-establish the certificate.** Reach the blog over Tor and capture its leaf exactly as in Tasks 1–2:

   ```sh
   O=4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion
   tor --SocksPort 19050 --DataDirectory tor-data &
   curl -sk --socks5-hostname 127.0.0.1:19050 "https://$O/" -o /dev/null -w '%{certs}' > certs.txt
   awk '/BEGIN CERT/,/END CERT/' certs.txt > leaf.pem
   openssl x509 -in leaf.pem -noout -serial -fingerprint -sha256
   ```

   ```
   serial=6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD
   sha256 Fingerprint=14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80
   ```

   The onion page itself is a static nginx victim list (Content-Length 2944) with no address, links or scripts in it — do not burn time reading the HTML. The usable artifact is the self-signed certificate.

2. **Pick the right database.** The SHA-256 fingerprint `14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380` (lowercase, no colons) is the search key. Because the certificate is self-signed, it was never logged in Certificate Transparency, so crt.sh is useless. Shodan without an account won't run certificate filters ("Please log in to use search filters"), and scripted requests to the old `search.censys.io` hit a Cloudflare "Just a moment..." browser check (HTTP 403). The modern Censys platform, however, is anonymously viewable in an ordinary browser.

3. **Search Censys for the fingerprint.** Open the related-assets / search view directly, with the fingerprint in quotes so it is matched as an exact phrase:

   ```
   https://platform.censys.io/search?q="14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380"
   ```

   The result (as of the event, Nov 2026) is exactly **one host**, matched on `host.services.cert.fingerprint_sha256`, in a Romanian hosting AS:

   ```
   185.146.87.136          HOST
   Network (AS)  ClausWEB - CLAUS WEB srl (203053)   Bucharest (RO)
   SERVICES (3)  22 / SSH   443 / HTTP   8080 / HTTP
   MATCHED FIELDS  host.services.cert.fingerprint_sha256
                   14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380
   ```

   The same search lists three web properties — the IP on 443 plus two hostnames (`cloud.alanarent.ro` and the hoster's reverse-DNS `cw185-adf-hg136.romania-webhosting.com`) — all one server under different names, all matched on `web.cert.fingerprint_sha256`.

4. **Resolve against the answer boundary.** The boundary asks for the clear-web IPv4. The two hostnames are names for the same machine (an older domain and the hoster's PTR, whose `cw185`/`hg136` echo ClausWEB) — submitting one would be the "historical certificate host" the brief rules out. The Hosts facet counts a single machine; its IPv4 is the answer. Confirm with one TLS handshake to that host only and check the leaf matches Tasks 1–2:

   ```sh
   openssl s_client -connect 185.146.87.136:443 </dev/null 2>/dev/null | openssl x509 -noout -serial -fingerprint -sha256
   ```

   Serial, SHA-256 fingerprint and CN all match exactly. Over plain HTTP that IP answers with a "403 — only accessible via .onion" stub, but its TLS service still hands out the ParsnipLocker certificate to every scanner.

**Why it works**

Tor hides the route to the blog, not the server's other exposures. The crew serves the same nginx site — with the same self-signed leaf — on a clear-web IP, and scanners like Censys record the SHA-256 fingerprint of every TLS service they meet on every public port. A self-signed certificate is unique to its owner: no CA shares it and no other host can legitimately present it, so one fingerprint search collapses the onion address, an old domain and a hosting PTR name into a single origin box. A hidden service stays hidden only as long as the server never says anything identifying about itself anywhere else — and its TLS certificate talks to every scanner that knocks.

**Validation / reproduction**

Exactly one host in the scan database presents that fingerprint, and a direct TLS handshake to it returns the identical leaf (same serial, fingerprint and CN as Tasks 1–2). The other matches are hostnames for the same machine, not the requested IPv4. Accepted on the first submission. To reproduce: compute the leaf fingerprint over Tor, paste its lowercase no-colon form in quotes into the Censys platform search, take the single Hosts result's IP, and verify with one `openssl s_client` to that host. Gotcha: the fingerprint must be lowercase with no colons for the Censys query, and scripted fetches of the old Censys/Shodan endpoints are blocked — use a browser against `platform.censys.io`.
