# Operation Dawn: The Dispatch Console

> Web · Medium · Terminal43  
> Points: 271 · Flag submitted by: secretNinja

**The flag**

`CSCTF{GlYld1ix0KH8n7UuacXqn3cD}`

**Tools used**

`curl`-style hand-built form requests. A local SQLite shell was used to check payload shape and length offline before each live request. Codex, run under human steering, solved this challenge and handed the result back — Codex made no submission; the team verified and submitted once (byline: secretNinja).

**Challenge**

"Operation Dawn, annex entry 08. We captured the Ash field dispatch console and stood it back up. A plain visitor can read and file dispatches, but the command net is locked and its standing order with it. The console runs everything past a sanitiser before it touches the database. Get command's standing order."

The challenge is a per-team container (`csctf26/web-thedispatchconsole:1`, port 8144) deployed by the CTFd `docker_per_team` plugin. It came with no attachments and no source (`files/` empty, `challenge.json` has `files: []` and `connection_info: null`), so the work was black-box against the team's own instance (`http://<instance>`) only. Two things in the brief set the plan: a privilege boundary (a plain visitor files/reads dispatches; the **command net** and the standing order sit behind it), and an explicit sanitiser in front of the database — which points to a gap between what the filter checks and what the DB receives, not a plain injection. The flag is a per-team random value (`flag_mode: random`, `random_flag_length: 24`, matching the 24-character body).

**Approach / walkthrough**

Triage sent the challenge to the web lane (`docs/playbooks/web.md`) and listed the web engines (`solvers/web/recon_triage.py`, `sqli_helper.py`, `ssti_helper.py`, `auth_trust.py`, `object_refs.py`, and others). The console lets a visitor file dispatches (a call sign plus a body), read them back, and view a per-unit digest; a report formatter at `/report` is locked behind a command token. Codex, run under human steering, drove the live solve end to end and handed the flag back without submitting.

1. **Find the sink.** A call sign containing a quote was accepted but then silently vanished from the digest. That means stored call signs are later interpolated into the digest's SQL query unsafely (a second-order injection), and query errors are swallowed. The direct token lookup was not injectable.

2. **Map the sanitiser.** Plain SQL keywords were rejected. `select` is blocked as a substring (`selectx` is rejected too). Fullwidth and zero-width tricks did not get through, and stored call signs are cut to 24 characters. Each of these hypotheses was ruled out with a single request.

3. **Find the decode mismatch.** Filing a call sign whose raw-form body contained `se%6cect` stored it as `select`: the sanitiser checks the raw request bytes **before** the form is URL-decoded, so percent-encoding the keyword characters bypasses it completely. (`%6c` is the hex for `l`.) This is the crux — the filter and the database see two different forms of the same input.

4. **Read the schema.** A fully percent-encoded `UNION SELECT` against `sqlite_master` on the non-stored `/dispatches` read route (two columns, `ref | body`, with no 24-character limit) returned the table definitions. The stored-call-sign sink is capped at 24 characters, so the longer schema and extraction payloads go through the read route instead. A constant-UNION control confirmed the digest sink is one column.

5. **Take the command token.** The injectable sink is the `token` parameter of `/report`. A UNION SQLi there — with the same `se%6cect`-style keyword obfuscation used to slip past the raw-byte sanitiser — reads the command-level operator token out of the `operators` table. The recovered token has the form `AC-<hex>`.

6. **Escape the formatter.** With the `AC-<hex>` command token, `/report` renders a command dispatch through a user-supplied Python format string passed in its `fmt` parameter. The default format exposes only `ref` and `body`, and the early probes `{dispatch.ref}` / `{dispatch.body}` / `{dispatch.__dict__}` returned only those two fields. Climbing the object graph instead reaches the module's global namespace, which holds the standing order. The winning request is:

```
GET /report?token=<AC-token>&fmt={dispatch.__class__.__init__.__globals__}
```

The path runs from the `dispatch` instance to its class, then to the class's `__init__` (a plain Python function), then to that function's `__globals__` (the defining module's `__dict__`). The formatter stringifies the **entire** globals dict in one go — no key index is needed — so the module-level value holding the standing order is printed among the dict's values, and the flag is one of them.

**Why it works**

The sanitiser validates one form of the input (the raw request bytes) while the database receives another (the decoded form value). This is a classic filter/decoder differential, and the second-order digest query made it exploitable — the injected value is stored harmlessly and only becomes SQL when a later digest query interpolates it. The report formatter then calls `str.format` on a format string the user supplies, passing in a real object. `str.format` follows `.attr` access and `[key]` indexing, and a class with a Python-defined `__init__` exposes `__init__.__globals__`, so the template can read any module-level value without executing code. (An inherited `object.__init__` is a slot wrapper with no `__globals__`; the path only works because the class defines its own `__init__`.) No `eval`, template engine, or code execution is required.

**Validation / reproduction**

Each stage was confirmed before the next: the `%6c` control was stored as the decoded keyword, the schema came back before any table names were used, and the token unlocked `/report` before the format traversal was tried. The standing order came back in an HTTP 200 response from the formatter, and the flag was accepted on the first submission — exactly one attempt in `tried.json`, status `correct`, at epoch `1793977107` (2026-11-06 14:58:27 UTC), about 1 h 58 min after Wave 1 opened. Several sanitiser hypotheses (fullwidth, zero-width, length tricks) were ruled out along the way with single requests.

Reproduction in short: (1) confirm the stored-call-sign second-order sink by filing a quote; (2) percent-encode keyword characters (`se%6cect`) to pass the raw-byte filter; (3) UNION-read `sqlite_master`, then UNION-read the command token (`AC-<hex>`) from `operators WHERE role='command'` via the `token` parameter of `/report`, using the same `se%6cect` obfuscation; (4) send `GET /report?token=<AC-token>&fmt={dispatch.__class__.__init__.__globals__}` — the formatter stringifies the whole module-globals dict and the standing order (the flag) appears among its values.

Gotchas and scope: work was limited to the team's own per-team instance — no scanning, flooding, or brute force. Codex drove the live solve under human steering and handed the flag back without submitting; the team submitted it. The `fmt` traversal does not need a key index — walking `dispatch.__class__.__init__.__globals__` and letting `str.format` stringify the entire dict exposes the flag directly.
