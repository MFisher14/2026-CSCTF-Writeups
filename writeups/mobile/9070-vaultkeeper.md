# VaultKeeper

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
