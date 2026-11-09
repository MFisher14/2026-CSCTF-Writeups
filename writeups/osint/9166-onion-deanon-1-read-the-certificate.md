# Onion Deanon 1: Read the Certificate

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
