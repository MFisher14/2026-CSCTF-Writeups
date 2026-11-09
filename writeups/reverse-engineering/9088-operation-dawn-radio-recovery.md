# Operation Dawn: Radio Recovery

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
