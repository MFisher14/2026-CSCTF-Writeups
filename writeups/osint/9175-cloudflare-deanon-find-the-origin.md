# Cloudflare Deanon: Find the Origin

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 320 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{185.146.86.118}`

**Challenge**

Task 2 of the lab: find the one clear-web IP serving the NestEgg site, which sits behind Cloudflare. The target domain, `cs-adwi-covsec-lab-1.eu`, comes from Task 1. The answer boundary: submit the one clear-web IPv4 origin that serves the NestEgg site — not a Cloudflare edge, DNS resolver, historical address, or guess.

**Tools used**

dig, curl, openssl, jq, whois; Censys web search in a browser.

**Approach / walkthrough**

1. **Record match handles and confirm Cloudflare.** Save the proxied page's body hash and unique title; they are how you will recognize the origin.

   ```sh
   D=cs-adwi-covsec-lab-1.eu
   curl -s -D headers.txt https://$D/ -o index.html; sha256sum index.html; grep -o '<title>[^<]*' index.html
   for t in A AAAA NS MX TXT; do echo "== $t"; dig +short $D $t; done
   ```

   Body hash `eada5319c75d6aa4f5a3aaece4eaa034309fd5374c03bf27228ab6897c029c1e`, title `NestEgg Capital | Reg. No. NEC-7731-0049`. DNS is all Cloudflare: A/AAAA are Cloudflare anycast, nameservers are `ganz`/`pam.ns.cloudflare.com`, no MX/TXT, and `www` does not resolve. DNS alone cannot reach the origin.

2. **Mine Certificate Transparency.** crt.sh served only two rows then errored, so use Cert Spotter for the full set:

   ```sh
   curl -s "https://api.certspotter.com/v1/issuances?domain=$D&include_subdomains=true&expand=dns_names&expand=issuer" \
     | jq -c '.[] | {nb:.not_before,dns:.dns_names,iss:.issuer.friendly_name}'
   ```

   Four certs: an Oct 8 apex + an Oct 8 `www` (Let's Encrypt), an Oct 21 wildcard (Let's Encrypt), and an Oct 22 wildcard (Sectigo). Checking what the edge actually serves (`openssl s_client -connect $D:443 -servername $D`) shows the Oct 21 Let's Encrypt wildcard is the edge cert and the Oct 22 Sectigo is Cloudflare's Universal-SSL backup — leaving the Oct 8 apex+www pair as the only pre-proxy certificates, and no origin-specific cert anywhere in the logs.

3. **Follow the pre-proxy `www` record — into a decoy.** HackerTarget passive DNS still remembers it:

   ```sh
   curl -s "https://api.hackertarget.com/hostsearch/?q=$D"
   ```

   ```
   cs-adwi-covsec-lab-1.eu,104.21.40.96      (Cloudflare edge)
   www.cs-adwi-covsec-lab-1.eu,185.31.240.240
   ```

   `whois 185.31.240.240` → `EE-ZONE-HOSTING / Zone Media LLC` (AS49604, Estonia), PTR `vs-dip-240-240.rid10.zonevs.eu`. One request with the lab's SNI and Host returns a `<title>Domain is Registered</title>` registrar-parking page serving the Oct 8 cert. So the Oct 8 certs belong to the domain's registrar-parking era — a historical address, exactly what the boundary forbids. Dead end, and a filter for everything downstream. urlscan, common subdomains, mnemonic/OTX passive DNS and robots all leak only the edge.

4. **Deduce and pivot on content.** No origin cert in CT and no DNS leak means the origin speaks plain HTTP or uses a Cloudflare Origin CA cert that never enters public logs. You cannot find it by name — find it by content, using the unique page title. Shodan's anonymous facet for `http.title:"NestEgg"` lists `185.146.86.118` among its top IPs (corroboration, but a facet alone proves nothing, and further queries hit the login wall). Censys gives the readable answer: a scripted fetch is Cloudflare-challenged (403), so open `https://search.censys.io/search?resource=hosts&q="NestEgg Capital"` in a browser (redirects to platform.censys.io, no account needed). Of 11 results, most are Cloudflare-fronted NestEgg properties (`nestegg.capital` showing "521: Web server is down", `nestegg-capital.com`, etc.). One is different:

   ```
   185.146.86.118 : 80   WEB PROPERTY
     HTML Title  NestEgg Capital | Reg. No. NEC-7731-0049     Software (1) F5 Nginx
     MATCHED FIELDS  web.endpoints.http.body / html_tags / html_title
   185.146.86.118   HOST   cw185-adf-hf118.romania-webhosting.com
     ClausWEB - CLAUS WEB srl (203053)   Bucharest (RO)   SERVICES (3) 22/SSH 80/HTTP 8080/HTTP
   ```

   The NestEgg page indexed on plain port 80, at a Romanian shared host, with no Cloudflare labels — the only non-edge web property in the results.

5. **Confirm the origin.** Ask it directly over plain HTTP with the site's Host header:

   ```sh
   curl -s -H "Host: $D" http://185.146.86.118/ | sha256sum
   curl -s http://185.146.86.118/ | grep -o '<title>[^<]*'
   ```

   Body hash is the same `eada5319...` from step 1 and the title matches. Plain HTTP on port 80 also explains why it never appeared in a certificate log. The answer is `185.146.86.118`.

**Why it works**

Cloudflare's proxy hides the origin from DNS, and this origin never bought a public certificate — it serves over plain HTTP — so the CT route only surfaces the edge and a registrar-parking decoy. What the proxy cannot hide is content: internet-wide scanners crawl port 80 too, and Censys indexed the NestEgg page by its unique title on a Romanian host that no current DNS record points to. One Host-header request whose body hash matches the proxied page pins the origin.

**Validation / reproduction**

The candidate serves the byte-identical page (same `eada5319...` hash, same title) as the proxied site, under a non-Cloudflare AS — distinguishing it from the registrar-parking decoy (different page, old Oct 8 cert) and from the other Cloudflare-fronted NestEgg name collisions. Accepted on the first submission. Gotcha: the `www`/CT trail leads to the Estonian parking decoy — a deliberate historical dead end — so the title/content pivot, not the certificate route, is what names the real box.
