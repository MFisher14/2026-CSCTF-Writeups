# proprietary

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
