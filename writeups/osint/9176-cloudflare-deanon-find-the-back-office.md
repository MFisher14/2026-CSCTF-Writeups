# Cloudflare Deanon: Find the Back Office

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 327 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{t2YGg14buPVPPnd9uvazWcdvT9UMCh3J}`

**Challenge**

Task 3 of the Cloudflare-deanon lab: find the operator's backend panel on the Task 2 origin (`185.146.86.118`) and read the hot-wallet admin key off it. The answer boundary: use the unique origin from Task 2, the admin key must be shown verbatim by the backend panel, and no path enumeration, wordlists, or generated candidate keys are allowed. No files ship.

**Tools used**

dig; Censys web search in a browser; curl, grep.

**Approach / walkthrough**

1. **See only the Cloudflare front.** DNS gives nothing but the proxy, so the page's unique title is the search handle:

   ```sh
   dig A cs-adwi-covsec-lab-1.eu +short     # 104.21.40.96 / 172.67.183.210 (Cloudflare)
   dig NS cs-adwi-covsec-lab-1.eu +short    # ganz / pam.ns.cloudflare.com
   ```

   The proxied page's title, `NestEgg Capital | Reg. No. NEC-7731-0049`, is unique to this lab, and the real origin serves the exact same page — the crack in the setup.

2. **Find the origin in Censys.** Anonymous scripted fetches of the search page get Cloudflare-challenged, so open `https://search.censys.io` in a browser and search the web-property index for `NestEgg Capital`. The results are backed by a single host. Most rows are name collisions (`nestegg.capital`, itself behind Cloudflare showing "521: Web server is down"; `nestegg-capital.com`). The rows that matter:

   ```
   185.146.86.118 : 80                         WEB PROPERTY
     HTML Title  NestEgg Capital | Reg. No. NEC-7731-0049   Endpoints (1) /   Software F5 Nginx
   cw185-adf-hf118.romania-webhosting.com : 80 WEB PROPERTY   (same page, same title)
   ```

   `185.146.86.118` serves the NestEgg page directly on port 80, no Cloudflare in the way — same title, same single endpoint `/`, same "F5 Nginx" label; network facet `ClausWEB - CLAUS WEB srl`, Romania, matching the `romania-webhosting.com` PTR. That is the unique origin from Task 2. (Optional check: `curl` it with a `Host: cs-adwi-covsec-lab-1.eu` header returns the same bytes the Cloudflare front serves.)

3. **Read the origin's ports off the same result.** The facet summary lists one host and three TCP services:

   ```
   PORTS  22 (1)   80 (1)   8080 (1)      PROTOCOLS  HTTP 2   SSH 1
   ```

   SSH on 22, the scam site on 80, and a second HTTP service on 8080. The back office can only live on 8080 — learned from the scanner's index, without sending a packet at the target.

4. **Open the back office and take the key.**

   ```sh
   curl http://185.146.86.118:8080/ | grep -A3 "admin key"
   ```

   Port 8080 is the operator's CRM panel, titled `NestEgg CRM | Backend`, with no login. Its dashboard shows the hot-wallet admin key verbatim; grep pulls that block out. The key is `t2YGg14buPVPPnd9uvazWcdvT9UMCh3J`. Wrap it in the flag format.

**Why it works**

Cloudflare hides the origin from DNS, but internet-wide scanners index the origin directly, every open port included. The site's title is unique, so one passive title search names the box and lists its ports; the operator left the back office on a second HTTP port of the same server with no authentication. Discovery costs the target nothing — origin, ports and the panel's port all come from the public index, and the only request sent is the single GET the brief allows, aimed at a port the scanner already named. The panel then prints its own key, exactly as the boundary requires.

**Validation / reproduction**

The key was copied verbatim from the panel, as the boundary requires, with no path enumeration or generated candidates. The panel was reached through the single origin from Task 2 and the port the scan database listed. Accepted on the first submission. To reproduce: Censys title search → origin IP → read that host's service ports → `GET :8080/` and read the admin key.
