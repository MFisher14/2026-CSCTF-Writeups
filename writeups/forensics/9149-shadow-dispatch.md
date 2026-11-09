# Shadow-Dispatch

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
