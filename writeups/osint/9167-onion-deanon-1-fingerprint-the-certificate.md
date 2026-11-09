# Onion Deanon 1: Fingerprint the Certificate

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
