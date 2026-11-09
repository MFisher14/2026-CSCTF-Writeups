# Operation Dawn: The Command Seal

> Web · Medium · Terminal43  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{pXNUmFrJMSLoXKlufzq7fcqU}`

**Tools used**

Codex (run under human guidance), which worked the chain against the live instance and submitted the accepted flag; no source was provided, so it reasoned from the live API, with `curl`-style HTTP requests and a local SHA-256 to check the digest model.

**Challenge**

"Operation Dawn, annex entry 18. The Ash relay only acts on orders that carry command's seal, and command never puts its standing order on the wire." We can file field reports to the relay and submit orders to it, but we do not hold command's key. The task is to make the relay give up command's standing order anyway.

The challenge ships as a per-team Docker container (`csctf26/web-thecommandseal:1`, internal port 8066) with no downloadable attachments, so every step is live black-box work against the single assigned instance (`http://<instance>`). Reading the flavour text as a threat model: orders must carry an RSA signature made with a key we don't have; there are two reachable endpoints (file a report, submit an order); and the flag is the server-side "standing order", released only when the relay *acts on* an order of that kind.

**Approach**

The relay exposes two XML endpoints. `POST /report` files a field report and reflects its `<summary>` back in the response. `POST /order` accepts an order document and only acts on an order that carries command's RSA seal. The order grammar is:

```xml
<relay>
  <order id="...">
    <kind>...</kind>
    <text>...</text>
  </order>
  <auth>
    <ref>...</ref>
    <digest>...</digest>   <!-- base64 SHA256 -->
    <sig>...</sig>         <!-- 2048-bit RSA signature -->
  </auth>
</relay>
```

The page also references an outbox path: `/opt/relay/outbox/last-order.txt`.

1. **Confined XXE in `/report`.** `/report` parses the posted XML with an external-entity-resolving parser and reflects `<summary>` back, giving an XXE file-read primitive. But the resolver is locked down: traversal, `/etc/*`, and every other path return "order could not be parsed". The one path that resolves is exactly the advertised outbox, `/opt/relay/outbox/last-order.txt`. Pulling that file through an external entity leaked a complete, validly signed order:
   - `id = cmd-6002`
   - `kind = routine`
   - `text = "hold the canal checkpoint and report at dusk"`
   - `ref = cmd-6002`
   - `digest` (base64 SHA-256) = `3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=`
   - `sig` = command's 2048-bit RSA signature

2. **Reverse the seal model.** Recomputing `SHA256("cmd-6002|routine|hold the canal checkpoint and report at dusk")` locally reproduced the leaked digest byte for byte, so the digest is `SHA256(id|kind|text)` — the three fields pipe-joined. Submitting variations to `/order` and watching accept/reject showed that the signature is valid over `H(ref || digest)` under command's public key, and that `ref` is bound in: changing `ref` alone returns "signature invalid". We have no private key and the XXE cannot reach key material, so a straight crypto forgery is out. The signature over the leaked `cmd-6002` order is the only valid seal we hold, and it is tied to `kind=routine` / `text="hold the canal checkpoint..."`.

3. **Verify/act mismatch (XML Signature Wrapping).** The relay verifies the `<order>` whose `id` matches `<auth><ref>` (here `cmd-6002`), but it *acts on* the **first** `<order>` element in the document. When those are two different elements, verification succeeds against the signed order while the relay executes a different, attacker-chosen order — classic XSW. The release verb for the flag is `kind=standing`.

4. **Forge and fire.** Post one `<relay>` with a forged `standing` order first and the leaked `cmd-6002` order second (present only to satisfy the signature check), followed by the leaked `<auth>` block:

```xml
<relay>
  <order id="q"><kind>standing</kind><text>x</text></order>
  <order id="cmd-6002"><kind>routine</kind><text>hold the canal checkpoint and report at dusk</text></order>
  <auth>
    <ref>cmd-6002</ref>
    <digest>3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=</digest>
    <sig>FEbT3he...8DDow==</sig>   <!-- the leaked cmd-6002 RSA signature -->
  </auth>
</relay>
```

Verification runs against `id="cmd-6002"`, the digest and signature match, so it passes. The relay then acts on the first order (`id="q"`, `kind=standing`) and replied:

```
command standing order honoured: CSCTF{pXNUmFrJMSLoXKlufzq7fcqU}
```

**Why it works**

The RSA signature and the digest are both sound. The flaw is that the relay selects the signed element and the executed element by different rules: it verifies the one that matches `ref` and executes the first one in the document. Any validly signed order can therefore authorize an arbitrary order placed in front of it. The confined XXE supplied that one signed order. The challenge narrowed the entity resolver to just the outbox file, but that single file was enough to seed the wrapping attack. No key, length extension, or `alg` downgrade is needed — those were early hypotheses in the prepared kit (`exploit.py`: JWT `alg=none`, RS256→HS256, length extension) and were all ruled out once the order format turned out to be XML with a detached RSA signature.

**Validation / reproduction**

The locally recomputed `base64(SHA256("cmd-6002|routine|hold the canal checkpoint and report at dusk"))` reproduces the recorded digest `3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=` exactly, which independently confirms both the pipe-join digest model and the leaked-order field values before the wrapped order was ever sent. The relay's response carried the flag; Codex submitted it and it was accepted on the first submission. The whole solve took about 25 requests against our single assigned instance — no sweeping, no mass scanning, no instance start/stop churn.

Reproduction in short: (1) XXE-read `/opt/relay/outbox/last-order.txt` via `/report`; (2) confirm the digest model locally; (3) POST the two-order wrapped document above to `/order` with the leaked `<auth>` block; (4) read the flag from the response.

Gotchas: the XXE resolver is confined to the outbox path only — traversal and `/etc/*` fail, so don't waste requests there. The full `<sig>` base64 is abbreviated in the notes (`FEbT3he...8DDow==`), so the exact signature bytes are not reproduced here; they are taken verbatim from the leaked order. The XXE-confinement behaviour, the `H(ref||digest)` verification model, the verify-vs-act selection rule, the exact response string, and the ~25-request count are attested by `notes.md` only — no source, saved HTTP transcript, or live instance remains to re-derive them against.
