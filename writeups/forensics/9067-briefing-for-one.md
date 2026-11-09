# Briefing for One

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
