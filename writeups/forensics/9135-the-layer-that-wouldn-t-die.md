# The Layer That Wouldn't Die

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
