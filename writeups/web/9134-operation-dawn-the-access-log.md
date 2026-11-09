# Operation Dawn: The Access Log

> Web · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{07_beacon_tow_vigil_bollard_8c0371}`

This is an OSINT-style freeform value that carries its own braces — it was submitted exactly as recovered, not re-wrapped.

**Challenge**

Operation Dawn, annex entry 07. Coalition cyber teams seized the web server log from an enemy status portal that fronted a canal checkpoint. One visitor "walked out of the portal's database with the checkpoint's link secret and never drew an error page." The job is to recover what they took and submit it as recovered; it already carries its own braces. The attachment is `access.log` (514,137 bytes, SHA-256 `3bb180802cc90b56984f179cb4315fc805d1e047e8a2374544044858fea30db2`): nginx combined format with one extra field per line, `rt=<seconds>`, the request time.

**Approach / walkthrough**

*Tools:* `shasum` to verify the file, `awk` and `grep` to profile the log, and a short standard-library Python script to rebuild the secret.

*1. Verify the attachment.* `shasum -a 256 access.log` matches the brief's hash, so the log is the one described.

*2. Single out the one visitor who never drew an error page.* Count requests and 4xx/5xx responses (field 9 is the status) per client IP, then see who sent SQL-looking characters:

```sh
awk '{n[$1]++; if ($9>=400) e[$1]++} END {for (ip in n) printf "%5d %3d %s\n", n[ip], e[ip], ip}' access.log | sort -rn | head -3
grep -E "%27|'" access.log | awk '{c[$1" "$9]++} END {for (k in c) print c[k], k}'
```

```
 2666   0 198.51.100.66
   23   0 203.0.113.136
   19   0 192.0.2.76
2665 198.51.100.66 200
```

Four other IPs drew errors, but they are plain scanners (8 requests each for `/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin`, all 403/404). One client, `198.51.100.66`, sent 2666 of the ~2900 requests, every one answered `200`, and it is the only client sending quotes (`'` or `%27`). That is the exfiltrator — and it never drew an error page.

*3. Read the attack.* Save and inspect its lines, then compare response size (field 10) against request time bucketed to whole seconds:

```sh
mkdir -p out && grep '^198\.51\.100\.66 ' access.log > out/attacker.log
awk '{t=$NF; sub(/rt=/,"",t); c[$10" rt="int(t)".x"]++} END {for (k in c) print c[k], k}' out/attacker.log | sort -rn
```

```
198.51.100.66 ... "GET /api/status?unit=43 HTTP/1.1" 200 88 ... rt=0.003
198.51.100.66 ... "GET /api/status?unit=43'+AND+IF(SUBSTR(token,6,1)='Z',SLEEP(2),0)--+- HTTP/1.1" 200 33 ... rt=0.057
2624 33 rt=0.x
41 33 rt=2.x
1 88 rt=0.x
```

After one normal `GET /api/status?unit=43`, every probe is

```
unit=43' AND IF(SUBSTR(token,<pos>,1)='<char>',SLEEP(2),0)-- -
```

— "if character `<pos>` of the `token` column equals `<char>`, sleep 2 seconds." Every probe returns the same 33-byte body, so neither the size nor an error page leaks anything; the only signal is `rt=`. Exactly 41 probes took ~2 s, the rest finished in milliseconds. Two traps: the probes arrive in shuffled position order, so reading the slow lines top to bottom gives scrambled text (`b`, `g`, `_`, …); and some guessed characters are URL-encoded (`%7D` is `}`), so the query must be decoded before reading the character.

*4. Rebuild the secret.* A script URL-decodes each probe, parses `(position, char)`, keeps the guesses whose request took at least 1.5 s, checks there is exactly one per position, and joins them in position order:

```python
import re, sys
from collections import defaultdict
from urllib.parse import unquote_plus

LINE  = re.compile(r'"GET (\S+) HTTP/[\d.]+" (\d+) (\d+) .* rt=([\d.]+)$')
PROBE = re.compile(r"IF\(SUBSTR\((\w+),(\d+),1\)='(.*)',SLEEP\((\d+)\),0\)")
THRESHOLD = 1.5  # true guesses sleep 2 s, false ones answer in ms

hits = defaultdict(list); positions = set()
for line in open(sys.argv[1], encoding="utf-8"):
    m = LINE.search(line)
    if not m: continue
    p = PROBE.search(unquote_plus(m.group(1)))   # '+'->space, %7D->'}'
    if not p: continue
    pos, char = int(p.group(2)), p.group(3)
    positions.add(pos)
    if float(m.group(4)) >= THRESHOLD:
        hits[pos].append(char)

secret = []
for pos in sorted(positions):
    chars = hits.get(pos, [])
    if len(chars) != 1:
        sys.exit(f"position {pos}: ambiguous/missing {chars}")
    secret.append(chars[0])
print("".join(secret))
```

```sh
python3 rebuild.py out/attacker.log
```

```
probes: 2665, column: token, positions: 1..41
char: CSCTF{07_beacon_tow_vigil_bollard_8c0371}
CSCTF{07_beacon_tow_vigil_bollard_8c0371}
```

Each of the 41 positions has exactly one slow guess, with no ambiguity and no gaps. Joined in order they spell the token, which already carries its `CSCTF{...}` braces, so it is submitted as recovered.

**Why it works**

The `unit` parameter of `/api/status` is concatenated into a SQL query, so the attacker appended `AND IF(condition, SLEEP(2), 0)` to turn the endpoint into a time-based blind-SQLi oracle. The page content never changes and nothing errors — which is exactly why the visitor "never drew an error page" — but the database stalls for 2 seconds whenever the guessed character is correct. nginx's `rt=` field records that stall, so the captured log alone holds every answer the oracle ever gave: for each position, the single guess that took ~2 s is the real character of the `token` column. Sorting those answers by position rebuilds the secret. No access to the live server is needed; the forensic log is self-contained.

**Validation / reproduction**

Each of the 41 probed positions had exactly one guess above the 1.5 s threshold — no ambiguity, no gaps — and the rebuilt string is a well-formed value framed by `CSCTF{...}`, matching the brief's note that the secret carries its own braces. It was accepted on the first submission. To reproduce: verify the SHA-256, isolate `198.51.100.66` as the all-`200`, quote-sending client, then run the decoder over its lines. Gotchas: decode `unquote_plus` before parsing (characters like `}` appear as `%7D` and `+` means space), and do not read the slow lines in file order — they are deliberately shuffled across positions, so reorder by the `SUBSTR(...,<pos>,...)` index.
