# Operation Dawn: The Relay Tap

> Forensics · Not shown · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}`

**Challenge**

> During Operation Dawn, Ash Army operators sprayed forged traffic onto a coalition government's emergency-dispatch relay while command's standing order was in flight. A signals unit tapped the link, but the capture is noisy and some of the relay's data appears more than once. Work out which standing order the relay actually delivered and submit it exactly as recovered. Between its braces it uses lowercase letters, digits and underscores.

The attachment is `relay-tap.zip` (12,327 bytes, SHA-256 `43424028…2530`) containing `relay-tap.pcap`, a 123-packet little-endian Ethernet capture. ARLY, the relay's frame format, is invented for the scenario and describes itself inside the capture; the hosts are RFC 5737 documentation addresses and `.test`/`.example` names.

**Approach / walkthrough**

*1. Find the relay conversation.* The DNS answers and `tshark -qz conv,tcp` identify the single relay session: `relay.dawn.test` resolves to `198.51.100.9`, and the only conversation with that host is `192.0.2.37:39605 ↔ 198.51.100.9:7443`. The six port-80 sessions are background noise, each returning the same `dispatch status: nominal` page; the rest is ARP, DNS and pings.

*2. Read the connection like a TCP receiver.* Checksum validation is off by default, so turn it on and print the timeline:

```sh
tshark -r relay-tap.pcap -o tcp.check_checksum:TRUE -Y 'tcp.port==7443' \
  -T fields -e frame.number -e ip.src -e tcp.seq -e tcp.ack -e tcp.len \
  -e tcp.checksum.status -e _ws.expert.message
```

Two server segments are flagged as suspected retransmissions:
- **Frame 114** repeats sequence range 1–366 (same as frame 112); frame 113 had already ACKed it (`ack 367`). Bad checksum (should be `0xe401`).
- **Frame 117** repeats range 367–419 (same as frame 115); frame 116 had already ACKed it (`ack 420`). Bad checksum (should be `0x3e4a`).

A real stack drops a bad-checksum segment before looking at the payload, and ignores bytes at a sequence position it has already ACKed. So the application received the relay's bytes exactly once, from frames 112 and 115; the clean FIN exchange (118–121) shows nothing else was added.

*3. Tell the plain duplicate from the forgery.* Hash each original and its "retransmission":

```sh
for n in 112 114 115 117; do tshark -r relay-tap.pcap -Y "frame.number==$n" \
  -T fields -e tcp.payload | xxd -r -p | shasum -a 256; done
```

Frame 114 is a byte-for-byte copy of 112 (the harmless "data appears more than once"). Frame 117 has the same seq/len as 115 but **different bytes** — the injected standing order. Both carry an `ARLY` type-3 header, so the frame type alone can't separate them; a tool that takes the *last* copy of each range, or the last order frame in the capture, ends up with the forgery 117.

*4. Read the self-describing descriptor.* `tshark -qz follow,tcp,ascii,6` reassembles first-copy-wins and prints the relay's opening message, which documents its own protocol:

```
frame = "ARLY" | type(1) | len(2, big-endian) | body
types 0=descriptor 1=client_nonce(16) 2=server_nonce(16) 3=order
key = SHA-256(client_nonce || server_nonce), 32 raw bytes
ks  = SHA-256(key || uint32be(i)) for i = 0,1,2,..., concatenated, cut to len(body)
order = body XOR ks, byte by byte
```

*5. Recover the flag.* A short stdlib-only script repeats the receiver logic: parse the pcap, verify each TCP checksum against the IPv4 pseudo-header, rebuild both directions dropping bad-checksum segments and keeping the first valid copy of each byte position, split into ARLY frames, derive the key from the two cleartext nonces, and XOR:

```
client_nonce = 3025e87165779f3626cc5c2015f5415f
server_nonce = 30815081be3320582eeb2fae8fad178b
key = SHA-256(client_nonce || server_nonce)
    = 71ed9289fb24d4f7174fcd3b8a4afdcd4e9787af2201f50beb9f627831d43a0e
delivered order (frame 115) -> CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}
dropped forged body (frame 117) -> b'S\x8e\xae\xa8\x03\xf1...'  (junk)
```

**Why it works**

The "noise" is TCP-level injection: spoofed relay segments that reuse a sequence range already delivered. The question is what the *receiver* accepted, not what crossed the wire. A TCP stack drops segments with a bad checksum and ignores data at sequence positions it has already ACKed; applying those two rules removes both the harmless duplicate (114) and the forged order (117), leaving frames 112 and 115 as what the application saw. The ARLY descriptor in that delivered stream documents the encryption — a SHA-256 counter-mode keystream keyed by the two nonces exchanged in the clear — and the key depends only on data the attacker could not forge.

**Validation / reproduction**

The real order (frame 115) decrypts to readable text in exactly the brief's alphabet (lowercase, digits, underscores), while the forged frame 117 decrypts to junk under the same session key — confirming whoever forged it never held the key. Reproduction: map the conversation, print the TCP timeline with checksum validation on, hash the duplicate pairs to separate the copy from the forgery, read the ARLY descriptor, and decrypt the delivered order body. Accepted on the first submission.
