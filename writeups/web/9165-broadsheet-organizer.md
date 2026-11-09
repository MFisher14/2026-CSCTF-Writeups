# Broadsheet Organizer

> Web · Not shown · Paul Valase  
> Points: 851 · Flag submitted by: secretNinja

**The flag**

`CSCTF{GiDFAaqWrGMx6bo1FRL4TgJV}`

The challenge ran on a per-team instance that is no longer up; `<instance>` below stands for the address the challenge page gave you.

**Challenge**

"The floor's pages are served through a shared cache, so everyone on shift sees the same copy. The duty editor reviews a board when asked." The duty editor is an automated review bot: it opens the board you ask it to, stays a few seconds, and leaves. It has no internet access, issues GET requests only, will not reach anything outside the application, and there is a cap on how many reviews can be in flight at once. The job is to get the flag out of the editor's authenticated context. The chain was found by an OpenAI Codex run following our brief, with paced single-shot probes in Python `requests`.

**Approach / walkthrough**

The board pages sit behind Varnish. The exploit is a cache-key collision: the backend and the cache parse the same URL differently, which lets attacker-controlled bytes be stored under a public, auto-loaded cache key, turning a sandboxed reflection into stored XSS against the review bot.

*1. Map the surfaces.* Three pieces matter:

- **Ticker endpoint** `/z/<zone>/ticker.js` reflects a `text` query parameter, and the query string is **not** part of the Varnish cache key. The value is JSON-encoded and assigned through `textContent`, so it is an unkeyed input but not a script sink — you cannot inject JavaScript through it directly.
- **Raw embed route** `/z/<zone>/embed/<token>` returns caller-supplied `html` bytes as raw content. It is sandboxed (`Cache-Control: no-store`, `nosniff`, `text/html`), but it accepts arbitrary path suffixes such as `/embed/<token>/ticker.js`.
- **Roster** `/roster?dept=editorial&sort=<expr>` concatenates `sort` into a SQLite `ORDER BY`.

*2. The cache-key collision.* The embed handler accepts extra path segments, and the backend routes on the raw path without resolving percent-encoded dot segments. Request:

```text
/z/<source>/embed/<token>/%2e%2e/%2e%2e/ticker.js?html=<javascript>
```

The backend sees the embed route and returns the attacker-controlled `html` bytes. Varnish, hashing the cache key, first **decodes and collapses** the `%2e%2e` segments — normalising the path to `/z/<source>/ticker.js` — and stores the response under the real ticker key, ignoring the backend's `no-store`. So the canonical ticker script for that zone is now attacker bytes. This was confirmed with an inert marker before weaponising it.

*3. Weaponise the poisoned ticker.* The ticker input is length-limited, so rather than exfiltrating the whole `/editor` page, the poisoned script matches just the flag and relays it through the second unkeyed channel. Its logic:

- `fetch('/editor')` with the bot's session (same-origin, GET, no internet needed);
- match `CSCTF\{[^}]+\}` in the response;
- request a **second** zone's ticker with the match as its unkeyed `text` value — e.g. `/z/<sink>/ticker.js?text=<flag>` — which primes that zone's ticker cache with the flag.

*4. Fire the chain.* Poison the source zone's ticker with the script above, then ask the duty editor to review the source board (the one review action the bot offers). The bot loads `/z/<source>/ticker.js`, gets the poisoned script from the cache, runs it in its authenticated session, reads `/editor`, and pushes the matched flag into the sink zone's ticker. Finally, read the sink zone's canonical `ticker.js` once:

```text
GET /z/<sink>/ticker.js
```

The Varnish cache hit contains the exact flag the bot wrote from its authenticated `/editor` response:

```text
CSCTF{GiDFAaqWrGMx6bo1FRL4TgJV}
```

*The roster SQLi (a dead end worth recording).* The `sort` parameter of `/roster?dept=editorial` is a genuine SQLite `ORDER BY` injection, confirmed with a blind oracle (`blind_sqli.py`). That extractor encodes one nibble per request in the permutation of the four editorial rows (ids 25–28): for a target byte it builds `CASE id WHEN … END` coefficients `a`, `b` and sorts by `((a*nibble + b) % 97)`, then reverses the observed row order (parsed from `<tr><td>(\d+)</td>`) back to the nibble via a precomputed `PERM_TO_NIBBLE` table — two requests (high and low nibble) recover each character, paced at 0.15 s. It works, but `sqlite_temp_master` was empty, there were no views/triggers, and credential-keyword searches across every known column returned zero rows: the editor cookie and the flag live outside SQL-visible storage, so this route is a dead end. A marker-only CL.TE desync (`smuggle_probe.py`) was also tried and rejected by Varnish with `400 Bad Request`. The cache-key collision is the intended path.

**Why it works**

The backend and the cache parse the same URL differently. The backend routes on the raw path and serves attacker bytes from the embed handler; Varnish decodes and collapses `%2e%2e` before hashing, so those bytes are stored under the public `/z/<source>/ticker.js` key — and Varnish caches them despite the backend's `no-store`, because the normalised request looks like an ordinary cacheable asset. Every visitor's board then loads that script, including the authenticated review bot, which turns a sandboxed `html` reflection into stored XSS in the editor's session. The ticker's second, unkeyed `text` parameter supplies an exfiltration channel that needs no internet egress: the bot writes the flag into one zone's unkeyed cache entry, and the attacker reads it back from the other end as a cache hit. Two different unkeyed inputs — one for delivery via the dot-segment collision, one for exfiltration via the query string — chain into a full read of the bot's authenticated content.

**Validation / reproduction**

The flag was read directly from a Varnish cache hit whose content the bot had written from its authenticated `/editor` response — recovered, not guessed — and it carried the `CSCTF{...}` frame; it was accepted on the first guarded submission. The collision step was validated against an inert marker before the live payload, proving the encoded dot-segment request lands on the real ticker key. To reproduce: confirm `/z/<zone>/ticker.js?text=` is unkeyed and `/z/<zone>/embed/<token>` serves raw `html` with path suffixes; poison `/z/<source>/embed/<token>/%2e%2e/%2e%2e/ticker.js?html=<script>` so Varnish stores it as `/z/<source>/ticker.js`; have the script `fetch('/editor')`, match `CSCTF\{[^}]+\}`, and relay the match into `/z/<sink>/ticker.js?text=`; trigger a review of the source board and read `/z/<sink>/ticker.js`. Gotchas: keep the dot segments percent-encoded so the backend does not resolve them but Varnish does; respect the review-in-flight cap and keep probes paced and single-shot; and the ticker length limit means you must relay only the regex match, not the whole `/editor` page.
