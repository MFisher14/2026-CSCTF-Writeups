# Onion Deanon 1: Find the Back Office

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 329 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{db133256-5ed2-44bd-aaec-652a5213be0f}`

**Challenge**

Task 4, the last of the "Onion Deanon 1" lab. Find the operator's internal negotiation panel on the Task 3 origin (`185.146.87.136`) and retrieve its access token (a UUID). The answer boundary: use the unique origin from Task 3, the UUID must be shown verbatim by the panel, and you may not enumerate paths, use wordlists, or generate candidate tokens. That constraint is the hint — passive scan archives, not probing, are the intended route.

**Tools used**

tor (local SOCKS proxy), curl; Shodan and Censys host pages in a browser.

**Approach / walkthrough**

1. **Confirm the blog advertises no back office.** The onion leak blog (`4uybrxybehxbf...onion`) is a single static victim list — carrot logo, tagline, five victims, a "simulated training environment" footer, and crucially zero hyperlinks and zero scripts. The panel is not linked from the public site.

2. **Knock once on the clear-web front.** Directly fetching the origin shows a deliberate dead end:

   ```sh
   curl -sk https://185.146.87.136/ -D - -o ip_index.html
   ```

   nginx answers `200 OK` but the 765-byte body *displays* "403 — This service is only accessible via `.onion`, direct connections are not permitted." The same stub comes back under the PTR hostname (`--resolve cw185-adf-hg136.romania-webhosting.com:443:185.146.87.136`), the apex, the onion name as SNI, and `localhost`; plain HTTP on port 80 is refused. There is no vhost trick, and the brief forbids path guessing — so stop touching the box and read public records.

3. **Pull the host from Shodan — the trap.** `https://www.shodan.io/host/185.146.87.136` loads anonymously and shows only two open ports:

   ```
   Open Ports 22 443        Last Seen: 2026-10-28
   22/tcp OpenSSH 9.2p1 Debian ...   443 nginx ... 403 ...
   ```

   Stale (last banner 2026-10-28) and thin. Trusting one scanner here would conclude the origin is clean and no panel exists.

4. **Pull the same host from Censys — the fresher view.** A scripted fetch bounces off Cloudflare (HTTP 403, "Just a moment..."), so open `https://platform.censys.io/hosts/185.146.87.136` in a browser. Censys lists **three** services, observed 2026-11-07:

   ```
   3 Total Services   22 / SSH   443 / HTTP   8080 / HTTP
   ```

   The 443 record carries the familiar stub and the TLS fingerprint `14bfcd53...eb2380` / `CN=4uybrxyb...onion` — confirming it is the same box Task 3 pivoted on. The third record is the one Shodan never showed:

   ```
   HTTP 8080 / TCP   LAST OBSERVED NOV 07, 2026
   URI http://185.146.87.136:8080/   Status 200 OK   Path /
   HTML Title  ParsnipLocker Internal Ops
   ```

5. **Read the token off the archived panel.** Censys stores the full response body for that 8080 service. Its archived page is the operator's panel verbatim:

   ```html
   <title>ParsnipLocker Internal Ops</title>
   <h1>PARSNIPLOCKER INTERNAL NEGOTIATION PANEL</h1>
   <div class="warn">DO NOT EXPOSE. OPERATOR USE ONLY.</div>
   <table> ... Globex Artisanal Mayonnaise Co. | PL-0091 | 0.8 XMR | negotiating ... </table>
   <div class="token-box">
     Access Token: <span class="token">db133256-5ed2-44bd-aaec-652a5213be0f</span>
   </div>
   ```

   The UUID is read straight from the archive — no port scan (Censys already enumerated 8080), no path guess (the panel is at `/`), no wordlist. Wrap it in the flag format.

**Why it works**

The crew ran the public leak blog and their internal negotiation panel on the same origin box. Tor hides the blog's location but cannot stop that box from exposing other services on its clear-web IP — and internet-wide scanners archive whatever they see, response bodies included. Shodan's snapshot is thin and stale, so it looks like there is nothing to find; Censys observed the box the same day and kept a full record for port 8080, panel and token included. The 443 "onion-only" stub guards direct browsing but cannot scrub an archive that already stored the panel. The lesson: never call an origin clean after checking a single scanner — cross-reference a second one.

**Validation / reproduction**

The token is read verbatim from the archived panel (the answer boundary requires the panel show it), reached via the single origin from Task 3 on a port the scanner already recorded — satisfying the no-scan/no-wordlist rule. Accepted on the first submission. To reproduce: take Task 3's origin, open its host page on Censys, find the 8080 service's archived response body, and copy the Access Token. Gotcha: Shodan alone would have hidden the 8080 service entirely — the whole task turns on checking a second, fresher scan archive.
