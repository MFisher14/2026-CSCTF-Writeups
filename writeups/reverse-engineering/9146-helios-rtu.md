# HELIOS-RTU

> Reverse engineering · Hard · Ionut Coserea  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{UWQEybJrRNyGHlEc8uDm0uBx}
```

(Per-instance random flag, 24-byte body; the value above is ours.)

**Challenge**

> A HELIOS GRID remote terminal unit (RTU) exposes a single web service console. Behind it is a real emulated ATmega328P running signed control firmware. The unit issues a service token only for a correctly authenticated control directive — and the authentication key is physically unreadable from outside.
>
> Identify the silicon, bring up the one interface on the bench that still answers, recover the application firmware, and produce a valid authentication tag over a control directive carrying the live nonce. Interact only with your assigned instance.

The brief is a four-step checklist: identify the chip, find the interface that still answers, recover the firmware, forge a MAC over a directive carrying the current nonce. There are no downloadable attachments — the whole challenge is a per-team web console (xterm.js over one `/ws` WebSocket, JSON `{type, data}` frames) reachable at `<instance>`. Stage-1 recon (`solve/recon.py`, capped at 25 GETs) pulled the front-end assets `app.js` and `board.js`, which document a simulated bench:

- **Console commands:** `help`, `avrdude` (a faithful simulated CLI: `-c/-p/-P/-U mem:r:file:fmt`; readable memories `signature`, `lfuse/hfuse/efuse/lock`, `flash`, `eeprom`), `bench`, `wire <adapter> <lead:pin> …`, `apt install svc`.
- **Bench adapters:** `avrisp` (MISO/MOSI/SCK/RESET/VCC/GND), `usbserial` (USB), `jtagice`, `dwprobe` (debugWIRE). Pins are an Arduino Uno header set plus the dedicated `ICSP_{RESET,SCK,MISO,GND,MOSI,VCC}` block and `USB`.
- **`svc` service** (after `apt install svc`): `nonce` (8 bytes), `telemetry` (16 bytes), `sign <16 bytes>`, `exec <32-byte frame> <tag>`.

All interaction went through one paced, single-session WebSocket driver (`solve/ws.py`, `solve/dump.py`, `solve/forge.py`), logging to `loot/session.log`.

**Approach / walkthrough**

1. **Identify the silicon.** Wire an ISP programmer to the ICSP header and read the signature:

   ```
   wire avrisp MISO:ICSP_MISO MOSI:ICSP_MOSI SCK:ICSP_SCK RESET:ICSP_RESET VCC:ICSP_VCC GND:ICSP_GND
   avrdude -c avrisp -p m328p -P /dev/ttyACM0 -U signature:r:-:h
   ```

   Response: `Device signature = 0x1e950f (probably m328p)` — an ATmega328P. Fuses/lock: `lfuse=0xFF hfuse=0xD8 efuse=0xFD lock=0xFC`. `hfuse=0xD8` → `BOOTRST` on, `BOOTSZ=00` → a 2 KW boot section at `0x7000`; `lock=0xFC` → **Lock Bit mode 3 (LB=00)**, which disables further ISP programming *and memory reads*. Flash over `avrisp` returns all `0xFF` (`loot/flash_isp.txt`) — this is the "physically unreadable" key.

2. **Find the interface that still answers.** LB mode 3 blocks the external programmer, but the boot-loader lock bits `BLB=11` leave the resident serial bootloader free to `LPM` the application section. So the interface still on the bench is the **serial bootloader** over USB/UART, not the ISP programmer. Re-wire and read flash via the `arduino` (Optiboot/STK500) programmer:

   ```
   wire usbserial USB:USB
   avrdude -c arduino -p m328p -P /dev/ttyACM0 -b 115200 -U flash:r:-:i
   ```

   This returns real contents for the application region (`loot/flash_usb.txt`, Intel HEX starting `:200000000C94BA00…`), converted to `loot/flash.bin` (32 KB). The boot section `0x7000`+ still reads back as `0xFF`, confirming the 16-byte AES key lives there, out of reach.

3. **Recover the firmware (static).** Convert HEX → raw and disassemble with radare2 in AVR mode (`r2 -a avr -b 8 -e asm.cpu=ATmega328p`, via `solve/avr_dis.sh`); nothing is executed. The application firmware is a compact AES-128 plus a UART command handler:

   - AES S-box @ `0x73`, Rcon @ `0x69`, key expansion @ `0x2b6`, encrypt @ `0x39a`.
   - `main` (`0x536`) copies the **key = 16 bytes `LPM`'d from flash `0x7F00`** (inside the unreadable boot section) into the RAM key schedule at `0x100`.
   - An `xorshift32` PRNG (`0x1b8`, shifts 13/17/5, seed `0xE98EDACA`) fills the 8-byte nonce.
   - UART frames are shaped `AA <cmd> <len> <data>`:
     - **cmd 1 `sign`** (`len 16`): refuses if `rec[0] == 0xCC`, otherwise returns **AES-ECB_K(rec)** — a raw single-block encryption oracle.
     - **cmd 2 `exec`** (`len 48` = `B0 || B1 || tag`): accepts iff `tag == E_K( E_K(B0) XOR B1 )` — a two-block **CBC-MAC with a zero IV** — and then requires `B1[0]==0xCC`, `B1[1]==0x0A`, `B1[2:10]==nonce`. On success it issues the service token. The nonce is regenerated after every `exec`.
     - cmd 3 `nonce`, cmd 4 `telemetry`, cmd 5 `reseed`.

4. **The forgery.** The MAC and the signing oracle share the same key `K`, which is the classic CBC-MAC-with-an-encryption-oracle break. For a two-block message `(B0, B1)` the valid tag is `E( E(B0) XOR B1 )`, and both encryptions are exactly what `sign` computes. The only restriction is the oracle's `0xCC` first-byte filter on *its input*, and the directive data lives entirely in the second block `B1`. In one session:

   1. Fetch the live nonce.
   2. Call `sign(00*16)` to get `C0 = E(B0)`. Check `C0[0] != 0x00`; otherwise `M[0] = C0[0] XOR 0xCC = 0xCC` and the *second* `sign` call would be refused (iterate `B0 = 00…`, `01…`, `02…` until `C0[0] != 0x00`).
   3. Build the directive block `B1 = CC 0A || nonce(8) || 00*6` with the live nonce.
   4. Compute `M = C0 XOR B1`; since we control `B0`, `M[0]` is not `0xCC`, so the oracle accepts it. `tag = sign(M) = E(C0 XOR B1) = E(E(B0) XOR B1)`.
   5. Send `svc exec B0||B1 tag`.

   The core of `solve/forge.py`:

   ```python
   nonce = re.search(r'nonce = ([0-9a-f]{16})', cmd('svc nonce')).group(1)
   for b0 in ('00'*16, '01'*16, '02'*16):
       c0 = bytes.fromhex(re.search(r'([0-9a-f]{32})', cmd('svc sign '+b0).split('=')[-1]).group(1))
       if c0[0] != 0: break
   b1  = bytes.fromhex('cc0a' + nonce + '00'*6)
   m   = bytes(a ^ b for a, b in zip(c0, b1))
   tag = re.search(r'([0-9a-f]{32})', cmd('svc sign '+m.hex()).split('=')[-1]).group(1)
   cmd(f'svc exec {b0}{b1.hex()} {tag}')
   ```

   The decisive exchange from the saved session log:

   ```
   >>> svc nonce
   service: nonce = 73d217e6bf376e97
   >>> svc sign 00000000000000000000000000000000
   service: tag = 2545be16b0fcadff5d49df085d700e9e
   >>> svc sign e94fcdc4a71a12c833dedf085d700e9e
   service: tag = 10825c4e9ac7668bc9ed9178b7cc0b3f
   >>> svc exec 00000000000000000000000000000000cc0a73d217e6bf376e97000000000000 10825c4e9ac7668bc9ed9178b7cc0b3f
   service: directive authenticated
   service: control action ISSUE_TOKEN accepted
   service: SERVICE TOKEN = CSCTF{UWQEybJrRNyGHlEc8uDm0uBx}
   ```

   Check: `C0 = 2545be16…0e9e` (first byte `0x25`, non-zero, so `B0 = 00…00` was enough). `C0 XOR (cc0a 73d217e6bf376e97 000000000000) = e94fcdc4a71a12c833dedf085d700e9e`, which is exactly the second `sign` input; its first byte `0xE9` is not `0xCC`, so the oracle signed it, and its output is the tag that `exec` accepted.

**Why it works**

The `exec` check is a zero-IV CBC-MAC built directly on top of an ECB encryption oracle that uses the *same* AES key. A two-block CBC-MAC is nothing but two chained block encryptions, and the `sign` oracle computes each on demand. The directive data lives entirely in the second block `B1`, and the only filter — refuse `sign` inputs whose first byte is `0xCC` — is dodged because the second oracle input is `E(B0) XOR B1`, whose first byte we steer through our free choice of `B0`. The key is never needed, so it is irrelevant that the boot-section key is physically unreadable; the break is purely structural. The chip-identification and bootloader-dump stages matter only to read out the firmware and confirm the two primitives share `K` — once that is known, the forgery needs nothing but the two `sign` calls.

**Validation / reproduction**

In the saved session, the second `sign` input is exactly `C0 XOR B1` and the device answered `directive authenticated` and issued the token. The flag was accepted on the first submission.

Reproduce (against your own assigned instance): pull the console assets; `wire avrisp` + `avrdude -U signature:r:-:h` to confirm `1E 95 0F` and read `lock=0xFC` (ISP reads blocked, all `FF`); `wire usbserial USB:USB` + `avrdude -c arduino -b 115200 -U flash:r:-:i` to dump the app section and convert HEX → `flash.bin`; disassemble in r2 (AVR) to recover the AES-128 + UART handler and identify the ECB `sign` oracle and the 2-block zero-IV CBC-MAC `exec` check that share key `K`; run the forgery (fetch nonce, two `sign` calls, one `exec`) and read the `CSCTF{…}` token. All work was confined to our assigned instance; no scanning, flooding, or off-target requests, and no hint was purchased.
