# Cloudflare Deanon: Read the Platform

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{NEC-7731-0049}`

**Challenge**

Task 1 of the Cloudflare-deanon lab. NestEgg Capital is a fake investment platform ("guaranteed returns, paid weekly") sitting behind Cloudflare. A fraud alert and a call note set the scene; the call note names the public site, `https://cs-adwi-covsec-lab-1.eu`, and claims it is "licensed by the Lower Dunwich Financial Supervisory Board". Despite the "deanon" framing, this task asks only for the company registration number *advertised by the platform*, and the answer boundary says to submit it exactly as the public site displays it — not a registry lookup, historical result, or guess.

**Tools used**

curl, grep.

**Approach / walkthrough**

1. **Read the task, not the title.** The title and fraud story tease an origin hunt, but Task 1 asks for "the company registration number advertised by the NestEgg Capital platform", and the boundary pins the source to the live public site. The origin hunt is for the later tasks; here the homepage *is* the source. "Stay passive" is satisfied by a single GET.

2. **Fetch the homepage once.**

   ```sh
   curl -sS -m 20 -L -A 'Mozilla/5.0' -D - https://cs-adwi-covsec-lab-1.eu/ -o index.html
   ```

   The response headers carry `server: cloudflare` and a `cf-ray` — confirming the proxy is real, and equally confirming it is irrelevant here: a reverse proxy still serves the full page content to any visitor.

3. **Grep for registration / licence wording.**

   ```sh
   grep -oiE '.{0,120}(regist|reg\.|company no|licen).{0,160}' index.html
   ```

   ```
   <title>NestEgg Capital | Reg. No. NEC-7731-0049</title>
   <meta name="description" content="NestEgg Capital, Reg. No. NEC-7731-0049. Guaranteed returns, paid weekly.">
     <div class="reg">Reg. No. NEC-7731-0049</div>
     Licensed by the Lower Dunwich Financial Supervisory Board | Licence LD-FSB-2210 | Reg. No. NEC-7731-0049
   ```

   The registration number appears in four places that all agree: the `<title>`, the meta description, a `Reg. No.` badge in the header, and the trust bar.

4. **Distinguish it from the decoy.** The same trust-bar line carries a second number, `Licence LD-FSB-2210` — the "Lower Dunwich Financial Supervisory Board" licence the call note mentions. The task asks specifically for the **company registration number**, which the site consistently prints as `Reg. No. NEC-7731-0049`. Drop the label, keep the number as displayed, and wrap it.

**Why it works**

Cloudflare hides the origin's IP, not the site's content — that is the point of a reverse proxy. The task asks for what the platform *advertises*, and a scam advertises its fake credentials as loudly as possible, pasting the registration number into the title, meta description, header badge and trust bar. So the shortest path is a single passive GET of the homepage: read what the platform says about itself and the answer falls out. The origin hunt the story teases is real work — for the rest of the series.

**Validation / reproduction**

Four independent spots on the page print the same registration number, so the value is unambiguous; the licence number is ruled out because the task asks for the company registration number specifically. Accepted on the first submission. To reproduce: one `curl` of the homepage, grep the registration lines, and take `NEC-7731-0049`. Gotcha: do not reflexively start DNS history / origin hunting — the boundary explicitly forbids a registry lookup or guess, and the site itself is the source of truth.
