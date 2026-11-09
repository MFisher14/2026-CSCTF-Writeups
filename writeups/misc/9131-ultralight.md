# ultralight

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
