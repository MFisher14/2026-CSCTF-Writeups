# Welcome Aboard

> Welcome · Welcome · Chronos Security  
> Points: 100 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{w3lcome_aboard_operator_a17f}`

**Challenge**

> Welcome aboard, operator. Command sent your first transmission encoded. Decode it and report in.
>
> `Q1NDVEZ7dzNsY29tZV9hYm9hcmRfb3BlcmF0b3JfYTE3Zn0=`

No attachments and no instance — the whole challenge is the one string in the brief.

**Tools used**

None beyond standard CLI utilities (`base64`); CyberChef's "From Base64" does the same in a browser.

**Approach / walkthrough**

1. **Recognize the encoding.** The string uses only `A–Z a–z 0–9 + /` and ends in `=` padding, which is Base64. The flag wrapper is even visible before decoding: `Q1NDVEZ7` is exactly what `CSCTF{` becomes in Base64, so this is a single Base64 layer over a `CSCTF{...}` flag.

2. **Decode once.** Our intake pass decodes text found in each brief automatically; it flagged this as Base64 and decoded it, equivalent to:

   ```sh
   printf '%s' 'Q1NDVEZ7dzNsY29tZV9hYm9hcmRfb3BlcmF0b3JfYTE3Zn0=' | base64 -d; echo
   # CSCTF{w3lcome_aboard_operator_a17f}
   ```

   The output is the flag in plain text, and it went straight to submission.

**Why it works**

The brief carries the flag itself under one layer of Base64. This is a sanity check that the team can read a challenge and submit a flag — decode once and you are done.

**Validation / reproduction**

The decoded output is printable ASCII inside the `CSCTF{...}` frame. It was accepted on the first submission, about a minute and a half after the wave opened. To reproduce, paste the brief string into `base64 -d` (or CyberChef's "From Base64").
