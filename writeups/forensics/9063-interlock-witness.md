# Interlock Witness

> Forensics · Medium · Chronos Security  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}`

**Challenge**

A fictional grid-support station fed an allied depot network. Its response-cell interlock read false while the controller accepted syntactically valid Modbus/TCP maintenance writes. The attachment `interlock-witness.zip` (15,307 bytes) holds a capture, `interlock.pcapng`, plus three short Markdown specs: a register map, a written response-cell policy, and a witness-format spec with a test vector. The task is to apply that policy exactly, reconstruct the accepted target writes that violate it, and derive the incident witness, a SHA-256 submitted as `CSCTF{<64 lowercase hex>}`. The safety policy is an offline forensic classification rule, not a controller feature; the controller itself accepted everything.

**Approach**

*1. Read the three specs first.* This is a spec-application challenge, so the documents define the task. The register map lists five zero-based holding-register words: `maintenance_permit` (0x000A), `isolation_state` (0x000B), `protection_armed` (0x000C), `trip_limit` (0x0013) and `restore_delay` (0x0014). The policy defines:

- A **target** transaction is an accepted FC16 (Write Multiple Registers) of quantity 1 at `0x0013` or `0x0014`.
- An FC16 is **accepted** only when its reversed-flow normal response matches transaction ID, protocol ID, unit ID and function code and echoes the start address and quantity; exception responses change nothing.
- An FC03 (Read Holding Registers) is accepted only when its response byte count is twice the request quantity; it then refreshes every mapped word it covers.
- A write **takes effect only after its response**.
- A target is **unsafe** when at least one of the three interlock words is not 1 immediately before its normal response.

The witness format: for each unsafe target, in normal-response order, append its request PDU then its paired normal-response PDU (function code plus data, **no MBAP header**) to form `T`. Then `W = SHA-256(P || T)` where `P` is the 20 bytes `49 4e 54 45 52 4c 4f 43 4b 2d 57 49 54 4e 45 53 53 2f 31 00` (ASCII `INTERLOCK-WITNESS/1` plus a trailing zero). The spec includes a non-incident serialization vector with its own expected `W` as a format check. The sentence "submit `CSCTF{` plus lowercase hexadecimal `W` plus `}`" is a format description, not a flag.

*2. Confirm P and the "raw PDU bytes" idea on the published vector.* Before touching the capture, build `P` from the spec hex and hash it with the vector's `T`:

```sh
echo '49 4e 54 45 52 4c 4f 43 4b 2d 57 49 54 4e 45 53 53 2f 31 00' | xxd -r -p > P.bin
echo '10 00 13 00 01 02 00 2a 10 00 13 00 01' | xxd -r -p > vector_T.bin
cat P.bin vector_T.bin | shasum -a 256
```
```
b6e58fa962e382b112eb596e416d5680495fc4bd02141f2389797f194df34786  -
```

This equals the spec's expected `W`, which confirms the recipe: hash raw bytes (not hex text), leave out the MBAP header. Each single-register FC16 adds 13 bytes to `T`: an 8-byte request (`10`, start, quantity, byte count `02`, value) and a 5-byte response (`10`, start, quantity).

*3. Survey the capture.* Establish the shape before replaying:

```sh
tshark -r interlock.pcapng -q -z conv,tcp
tshark -r interlock.pcapng -Y mbtcp -T fields -e tcp.dstport -e mbtcp.prot_id -e mbtcp.unit_id -e modbus.func_code -e modbus.exception | sort | uniq -c
tshark -r interlock.pcapng -Y tcp.analysis.flags | wc -l
```

One TCP connection, client 127.0.0.1:59818 to controller port 502; 504 of 512 frames carry Modbus. Protocol ID 0 and unit ID 1 throughout, only FC03 and FC16, `modbus.exception` False everywhere, and zero TCP analysis flags (no retransmissions, duplicates or reordering). The session is clean and strictly sequential.

*4. Confirm pairing.* Each response follows its own request with the same transaction ID and function code. A one-line check over the whole capture:

```sh
tshark -r interlock.pcapng -Y mbtcp -T fields -e frame.number -e tcp.dstport -e mbtcp.trans_id -e modbus.func_code -e modbus.request_frame | awk -F'\t' '$2==502{req=$1;tid=$3;fc=$4;next}{n++;if($5==req&&$3==tid&&$4==fc)ok++}END{print n" responses, "ok" directly follow their own request"}'
```
```
252 responses, 252 directly follow their own request
```

*5. Group FC16 writes by address* as a cross-check against the policy's promised counts:

```sh
tshark -r interlock.pcapng -Y 'tcp.dstport==502 && modbus.func_code==16' -T fields -e modbus.reference_num -e modbus.word_cnt | sort -n | uniq -c
```

This yields 60 writes to `trip_limit` (19) and 60 to `restore_delay` (20), all quantity 1 (120 targets), plus exactly the eight others the policy promises: five that update the interlock-state words (arm protection, grant permit, isolate, reconnect, re-isolate) and three acknowledgement writes to unmapped `0x0018`-`0x001A`.

*6. Replay the policy.* Export each Modbus frame's raw TCP payload, then run the replay:

```sh
tshark -r interlock.pcapng -Y mbtcp -T fields -e frame.number -e tcp.dstport -e tcp.payload > adus.tsv
python3 replay_policy.py adus.tsv T.bin
```

The script splits MBAP (transaction ID, protocol ID, length, unit ID) from the PDU, pairs each response with the preceding request, updates the five mapped words from accepted FC03 reads and FC16 writes **after** each response, and judges every target write on the three interlock words as they stood just before its response. The verdict core:

```python
before = [state.get(a) for a in (0x000A, 0x000B, 0x000C)]   # permit, isolation, armed
if qty == 1 and start in (0x0013, 0x0014):
    if before == [1, 1, 1]:
        verdict = "target, safe"
    else:
        T += req + pdu                                       # unsafe: append request||response PDU
```
```
unsafe accepted targets: 16 -> T = 208 bytes written to T.bin
FC03 observations accepted: 124, rejected: 0
FC16 writes accepted: 128 (120 targets, 8 ineligible), not accepted: 0
```

The 16 unsafe targets fall in two windows: at session start, before the permit and isolation writes (permit 0, isolation 0), and after a mid-session write (frame 254) sets `isolation_state` back to 0, until frame 288 re-isolates. The "effect after response" timing is what makes frames 44/288 still show isolation 0 at their own response while the target writes that follow them see 1 and are safe. `T` is 16 × 13 = 208 bytes.

*7. Hash the witness.*

```sh
wc -c P.bin T.bin
cat P.bin T.bin | shasum -a 256 | awk '{print "CSCTF{" $1 "}"}'
```
```
      20 P.bin
     208 T.bin
CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}
```

`T` opens with the first unsafe write's request `10 00 13 00 01 02 04 0d` (1037 = 0x040d into `trip_limit`) and its response `10 00 13 00 01`, matching the vector's layout. `P` (20) plus `T` (208) is 228 bytes of SHA-256 input.

**Why it works**

The session is one strictly sequential Modbus/TCP exchange, so request/response pairing is unambiguous and the client re-reads all five mapped words between writes. Those reads always agree with the replayed writes, so the replayed state at each acknowledgement is exact and no state change is hidden. The policy's "after the response" timing is what makes the writes following the permit and isolation writes safe and the first write after each reconnection unsafe. The witness is a SHA-256 over a fixed prefix and the raw PDUs of exactly those transactions, so any slip, keeping the MBAP header, including an ineligible or safe write, wrong order, or hashing hex text instead of bytes, changes the hash. The published vector lets you check the hashing in isolation.

**Validation / reproduction**

The test vector reproduced exactly, the replay's totals matched the policy's stated counts (128 accepted FC16 = 120 targets + 8 ineligible; 124 FC03 accepted, none rejected), and `T` had the expected 208 bytes. The team's automated intake pass had already submitted two strings lifted verbatim from the brief's format sentence, which were rejected; the derived witness was the first real answer submitted, and it was accepted.

Reproduction summary: (1) verify the zip and member hashes; (2) read all three specs; (3) reproduce the test vector to lock the `P`/PDU-bytes recipe; (4) survey with tshark (one connection, protocol 0 / unit 1, only FC03 + FC16, no exceptions, no TCP flags); (5) confirm 252 clean pairs and the 120 + 8 FC16 split; (6) export `frame, dstport, tcp.payload` and replay to get `T` = 208 bytes; (7) hash `P || T`. Gotchas: the format sentence is not the flag; PDUs carry no MBAP header; apply writes only after their response; and the two reconnection writes (frames 44, 288) are themselves ineligible, not targets.
