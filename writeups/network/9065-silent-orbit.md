# Silent Orbit

> Network · Easy · Cosmin Gorea / HiveHack  
> Points: 120 · Flag submitted by: secretNinja

**The flag:**
`CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}`

**Tools used**

python3 (standard library); shasum to verify SHA256SUMS.

**Challenge**

The challenge-page text describes a Windows `telem_parser.exe` and a frame stream, but the shipped
`silent-orbit-cfdp.zip` does not match it: there is no binary, only `README.txt`,
`mission-profile.txt`, `civil_downlink.bin` and `SHA256SUMS` (all three hashes verify). `README.txt`
sets the real task:

> Reconstruct the exact CFDP NAK PDU the normal relay would emit. Submit the complete PDU as
> `CSCTF{UPPERCASE_HEX}`. The recording is raw concatenated Space Packets; it is not a PCAP.

So the page's `CSCTF{<APID>_<Timestamp>_<CRC16>}` format is overridden: the flag is the uppercase hex
of a single CFDP NAK PDU, built by running the relay's deterministic rules over the recording.

**Approach / walkthrough**

`mission-profile.txt` is the full specification. The work is to parse the stream, apply the
eligibility/state rules exactly, complement the received coverage, and serialize the NAK.

**1. Parse the outer CCSDS stream**

Each Space Packet is a 6-octet primary header followed by `(packet_length + 1)` user-data octets.
Reject any truncation; do not resynchronize. `civil_downlink.bin` parses exactly into 188 packets with
no leftover bytes.

**2. Keep only eligible target PDUs**

A packet contributes only if it is telemetry with PVN 000, **APID 0x321**, secondary-header flag 0 and
sequence flags 11, and its user-data field is exactly one complete CFDP PDU. Within those, the target
CFDP transaction is Version 001, toward receiver, acknowledged, no PDU CRC, small-file, with
one-octet entity/sequence encodings and the source/sequence/destination tuple **0x01 / 0x07 / 0x02**.
The capture plants decoys that must be rejected: a Metadata PDU on ineligible APID 0x012, File Data for
another transaction (tuple 03/09/02), and one duplicate segment. The eligibility check in code:

```python
# primary header: PVN 000, no sec-hdr, APID 0x321, seq flags 11
if (w>>13)!=0 or (w>>12)&1 or (w>>11)&1 or (w&0x7ff)!=0x321 or (s>>14)!=3: continue
...
if el!=1 or tl!=1: continue           # one-octet entity/sequence encodings
if ud[4:7]!=bytes([1,7,2]): continue   # tuple 0x01/0x07/0x02
```

**3. Run the relay state machine**

- **WAIT_METADATA → COLLECT.** Accept only the first valid target Metadata (small file, checksum type
  15 = NULL_CHECKSUM, closure flag 0, no option TLVs) to learn the file size and enter COLLECT. Here
  that is packet 2 with `size = 0xC0 = 192`.
- **COLLECT.** Each valid target File Data PDU contributes `[offset, offset + len)` only if its
  non-wrapping end is within the size; duplicates/overlaps merge.
- **EOF.** The first valid EOF (directive 0x04, No Error, null checksum, `file_size == Metadata size`)
  snapshots coverage. Here that is packet 187, `size 192`.

Packet sequence counts are capture metadata and are never used as file-byte coverage.

**4. Complement the coverage and serialize the NAK**

The received coverage leaves exactly **twelve single-byte gaps** over `[0, 192)` — the suppressed File
Data — at offsets 5, 19, 35, 51, 68, 83, 101, 119, 138, 154, 171, 187:

```
coverage [[0,5],[6,19],[20,35],[36,51],[52,68],[69,83],[84,101],[102,119],[120,138],[139,154],[155,171],[172,187],[188,192]]
missing  [(5,6),(19,20),(35,36),(51,52),(68,69),(83,84),(101,102),(119,120),(138,139),(154,155),(171,172),(187,188)]
```

The deferred NAK PDU is the CFDP header for the same tuple, directive `0x08`, scope `[0, file_size)`,
then each gap as an ascending, maximal, non-overlapping `[start, end)` pair:

```python
body = bytes([8]) + (0).to_bytes(4,'big') + eof.to_bytes(4,'big') \
     + b''.join(a.to_bytes(4,'big') + b.to_bytes(4,'big') for a,b in miss)
pdu  = bytes([0x28]) + len(body).to_bytes(2,'big') + bytes([0x00,1,7,2]) + body
print('CSCTF{' + pdu.hex().upper() + '}')
```

The whole PDU in uppercase hex is the flag: it begins `2800690001070208` (header + directive 8),
`00000000 000000C0` (scope 0..192), then the twelve `[start,end)` pairs
(`00000005 00000006`, `00000013 00000014`, …, `000000BB 000000BC`).

**Why it works**

The profile turns the recording into one deterministic record. The NAK a correct relay would send is
exactly the complement of what was actually received: twelve single-byte gaps the suppressed File Data
left uncovered. The output is unique only if the eligibility, state and serialization rules are
followed exactly — which PDUs count, and byte offsets rather than sequence counts. The planted decoys
(the ineligible-APID Metadata, the other-transaction File Data, the duplicate segment) are what the
rules are designed to reject.

**Validation / reproduction**

The parser consumes the stream with no truncation (188 packets parse exactly), the Metadata and EOF
file sizes agree (both 192), and the coverage gaps reproduce as the twelve single bytes above. Running
the saved `workspace/9065-silent-orbit/solve.py` against `civil_downlink.bin` re-emits the exact flag.
The serialized PDU was accepted on the first submission.

Reproduction: `python3 solve.py civil_downlink.bin`. Gotchas: reject the ineligible-APID Metadata and
the other-transaction (03/09/02) File Data; merge the duplicate segment; and complement over `[0,
file_size)` using byte offsets, not packet sequence counts.
