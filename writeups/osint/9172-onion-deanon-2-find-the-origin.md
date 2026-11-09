# Onion Deanon 2: Find the Origin

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 0 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{185.146.85.96}`

**Challenge**

Task 3 of the DarkPigeon lab: find the one clear-web IPv4 that serves the portal. The answer boundary: submit the one clear-web IPv4 that serves the portal identified from the Task 1 favicon — not onion infrastructure, a relay, a historical host, or a guessed address. Scope stays passive, so the plan is to send no new traffic at all — ask an index that has already scanned the internet which server serves this exact favicon.

**Tools used**

Censys Platform search (no account needed).

**Approach / walkthrough**

1. **Choose the index and the key.** Shodan indexes favicons under the Task 1 MurmurHash3 value (`http.favicon.hash:-209798607`), but its favicon filter needs an account and query credits. Censys indexes favicons under several hashes, including plain MD5, and answers searches without a login — so the key is the Task 2 MD5, `ad866421d43a616ab0e4dd089fc94b06`. That the Shodan-style value is not Censys's key is worth confirming: the field query `web.endpoints.http.favicons.hash_shodan:-209798607` returns "Something went wrong", and the bare number `"-209798607"` in quotes returns nothing.

2. **Search the MD5.** Quote it so Censys matches it against every field that could hold it:

   ```
   https://platform.censys.io/search?q="ad866421d43a616ab0e4dd089fc94b06"
   ```

   Three results come back in about half a second, all on one network (ClausWEB / CLAUS WEB srl, AS203053, Bucharest RO):

   ```
   185.146.85.96 : 80          WEB PROPERTY   AS OF NOV 07, 2026
     HTML Title  DarkPigeon | Negotiation Portal      Endpoints (1) /     Software F5 Nginx
     MATCHED FIELDS  web.endpoints.http.favicons.hash_md5  ad866421d43a616ab0e4dd089fc94b06

   cw185-adf-he96.romania-webhosting.com : 80   WEB PROPERTY   AS OF NOV 02, 2026
     HTML Title  DarkPigeon | Negotiation Portal      (same favicon MD5)

   185.146.85.96               HOST
     cw185-adf-he96.romania-webhosting.com   AS203053 (ClausWEB)   Bucharest (RO)
     SERVICES (3)  22 / SSH   80 / HTTP   8080 / HTTP
   ```

   Three cards, one server: the IP's web property on port 80, the host record for the same IP, and the same machine again under its hosting-provider PTR (`cw185-adf-he96` carries the first and last octets of `185.146.85.96`). The exact field query `web.endpoints.http.favicons.hash_md5:"ad866421d43a616ab0e4dd089fc94b06"` returns the same two web properties. The clear-web page title, `DarkPigeon | Negotiation Portal`, is word-for-word the onion portal's title from Task 1.

3. **Check against the answer boundary.** It is not onion infrastructure or a relay (Censys found it by scanning the clear web); not historical (the IP's web property is dated NOV 07, 2026, the current scan; the PTR card is five days older but names the same IP); not guessed (matched on the favicon MD5 and corroborated by the page title); and all three cards resolve to one IPv4. That address, in the flag wrapper, is the answer. The host also exposes `8080 / HTTP` beside the portal — noted for Task 4.

**Why it works**

Tor hides where the portal runs, not what it serves. The operators put the same site on a clear-web nginx that answers internet-wide scans like any other server. Censys fetched its favicon during a routine scan and stored the MD5 of the bytes. The hidden service hands out that identical file, so the MD5 computed over Tor is exactly the key Censys has on file for `185.146.85.96`, and the page title ties the match down. Nothing is sent to the server to find it — the deanonymization is entirely a lookup of what the server had already told the public internet about itself.

**Validation / reproduction**

The match rests on two independent signals — the favicon hash and the exact page title — and every result points to one IP. .dev's agent submitted it once and it was accepted. Independently, secretNinja reached the same host while working Task 4, through a FOFA search on the Task 1 favicon hash (`icon_hash="-209798607"`); one GET of that host's index and favicon returned bytes identical by SHA-256 to the onion portal's copies. To reproduce: paste the Task 2 MD5 in quotes into the Censys platform search and take the single IP all three cards share. Gotcha: search by the MD5, not the Shodan MurmurHash3 value — Censys does not answer to the `hash_shodan` field here.
