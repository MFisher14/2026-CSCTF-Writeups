# Onion Deanon 2: Find the Back Office

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 0 · Flag submitted by: secretNinja

**The flag**

`CSCTF{da4f9b9a-31c7-4b8f-91cb-1a5009d5f65b}`

**Challenge**

Task 4 of the "Onion Deanon 2" lab. Find the operator's admin panel on the Task 3 origin and retrieve the decryption key (a UUID) for the Coop & Crumb case. The answer boundary: use the unique origin from Task 3, the UUID must be shown verbatim by the admin panel, and no path enumeration, wordlists, or generated candidate tokens are allowed.

**Tools used**

FOFA and Netlas (anonymous web search); curl.

**Approach / walkthrough**

1. **Re-establish the origin.** A FOFA anonymous search on the Task 1 favicon hash pivots to the single clear-web host:

   ```
   icon_hash="-209798607"  ->  185.146.85.96:80
   ```

   title `DarkPigeon | Negotiation Portal`, nginx, Claus Web SRL (AS203053, Bucharest RO), rDNS `cw185-adf-he96.romania-webhosting.com`. One GET of `http://185.146.85.96/` returns a body byte-identical (by SHA-256) to the onion index from Task 1, and `/favicon.ico` is identical too (SHA-256 `195873a0...`). (Note: the favicon's PNG `tEXt` Comment holds a watermark UUID `8a8b3b25-ac32-4f22-890d-cb14db334bea` — a decoy, *not* the answer.)

2. **Confirm the portal exposes nothing extra.** `robots.txt` and `sitemap.xml` both 404; no links, JS, or informative headers. Shodan's InternetDB shows only `:80`; FOFA shows `:22` and `:80`. The portal front offers no route to the panel, and the brief forbids enumeration — so get the extra port from a scan index.

3. **Find the admin port in a second scan index.** Netlas's anonymous response index for the origin IP lists the extra service:

   ```
   https://app.netlas.io/api/responses/?q=ip:185.146.85.96
   ```

   It returns `http://185.146.85.96:8080/` with HTML title `DarkPigeon Admin` (archived scan 2026-10-23). The port comes from the archive, not from scanning.

4. **Open the panel (GET #1) and read its form.** One GET of `:8080/`:

   ```sh
   curl -s http://185.146.85.96:8080/
   ```

   ```html
   <title>DarkPigeon Admin</title>
   <h1>:: DARKPIGEON ADMIN // NEGOTIATION BACKEND ::</h1>
   <tr><td>CC-0417</td><td>Coop &amp; Crumb Birdseed Wholesalers</td><td>1.4 XMR</td><td class="pending">negotiating</td></tr>
   <form action="/ticket" method="get">
     Open ticket for case: <input name="case" pattern="CC-[0-9]{4}" ...><button>Open</button>
   ```

   The case table's Coop & Crumb row is case `CC-0417` (matching the victim named in the forum post), and the panel's own form defines the path `GET /ticket?case=CC-NNNN`. The path and case id both come from the page itself — no guessing.

5. **Open the ticket (GET #2) and take the key.** One GET of `/ticket?case=CC-0417`:

   ```sh
   curl -s "http://185.146.85.96:8080/ticket?case=CC-0417"
   ```

   The ticket page prints the key verbatim:

   ```html
   <div class="msg"><span class="who">roost_admin:</span> Good. Key is below. Release it only after the payment is confirmed on chain. Not before.</div>
   <div class="key">Decryption key (release after payment confirmed):<br><br>
     <code>da4f9b9a-31c7-4b8f-91cb-1a5009d5f65b</code>
   ```

   Wrap the UUID in the flag format.

**Why it works**

The operator ran the public portal and the admin backend on the same origin box. Tor hides the portal's location but not the box's other clear-web services; a scan index reveals the admin port, and the panel's own form supplies the path and case id, so the key is reached passively without enumeration. As in the sister lab, the back office is a second HTTP port of the same server — discoverable entirely from a public scan archive.

**Validation / reproduction**

Every step uses a value already in hand — the port from the Netlas index, the path from the panel's form, the case id from the panel row and the forum post — so no guessing or wordlists are used, matching the scope. The decryption key is shown verbatim by the admin panel's ticket view (evidence saved as `admin.html` and `ticket.html`). Accepted on the first submission (manual CLI submit by secretNinja). Gotcha: the favicon's embedded `tEXt` watermark UUID is a deliberate decoy — the real answer is the ticket page's key, not the one baked into the icon.
