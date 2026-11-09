# The Capability Ghost

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
