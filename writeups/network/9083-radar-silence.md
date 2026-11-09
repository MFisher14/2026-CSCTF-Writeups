# Radar Silence

> Network · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag:** `CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`

**Tools used**

tshark, python3 (standard library).

**Challenge**

> RDR37 (`192.0.2.37`) carries the air-surveillance radar link of an Operation Dawn ally; OPS40
> (`192.0.2.40`) logs operations. Analysts marked RDR37 for a suspected bearer-token leak. This
> PCAPNG is an isolated-lab replay. Determine whether a bearer token left RDR37 and recover it for
> reissue. Submit `CSCTF{<source>_rotation_<token>}` using the lower-case station ID and a
> 32-character lower-case hex token.

A single pcapng, `radar-silence.pcapng`, holding 28 packets.

**Approach / walkthrough**

**1. What channel could carry a token?**

Protocol hierarchy first — it shows where data could have left the host:

```sh
tshark -r radar-silence.pcapng -qz io,phs
```

```
frame   frames:28
  eth   frames:28
    ip  frames:28
      udp frames:28
        dns frames:28
```

28 DNS packets, nothing else — no HTTP, no TCP. If a token left RDR37, it left inside DNS query
names (classic DNS exfiltration): the resolver logs the full query name even when the answer is
meaningless.

**2. List every query and who sent it**

```sh
tshark -r radar-silence.pcapng -Y 'dns.flags.response == 0' -T fields \
  -e frame.number -e ip.src -e dns.qry.type -e dns.qry.name
```

Four queries stand out (frames 5, 9, 15, 21): all from RDR37 `192.0.2.37`, all to the external-looking
zone `update.svc-telemetry.example`, each with a **13-character first label using only `a-z` and
`2-7`** (the base32 alphabet) followed by a two-digit sequence label `00`–`03`. They are sent **out of
order** (02, 00, 03, 01):

```
5	192.0.2.37	rtamrzg5sgiyz.02.update.svc-telemetry.example
9	192.0.2.37	miytaojxmy3gk.00.update.svc-telemetry.example
15	192.0.2.37	tgmztknjqhfta.03.update.svc-telemetry.example
21	192.0.2.37	ojxg4ydcnldmf.01.update.svc-telemetry.example
```

Traps: the two TXT answers (`v=DMARC1; p=none`, `ok`) carry nothing;
`telemetry.svc-telemetry.example` and OPS40's `status.svc-telemetry.example` query are cover traffic
in the same zone, not chunks. A strict regex extracts exactly the four chunk queries and drops the
decoys:

```sh
tshark -r radar-silence.pcapng \
  -Y 'dns.flags.response == 0 && dns.qry.name matches "^[a-z2-7]+\.[0-9]+\.update\.svc-telemetry\.example$"' \
  -T fields -e frame.number -e ip.src -e dns.qry.name
```

**3. Reorder, decode, recover**

Sort by the `NN` sequence label, concatenate the four 13-char labels (52 chars), upper-case, pad to a
multiple of 8, and base32-decode (RFC 4648). The core:

```python
rows.sort()                                   # by the NN sequence label
joined = "".join(chunk for *_, chunk in rows) # 52 chars
padded = joined.upper() + "=" * (-len(joined) % 8)
token = base64.b32decode(padded).decode()     # 32 lowercase hex chars
station = {"192.0.2.37": "rdr37", "192.0.2.40": "ops40"}[source]
print(f"CSCTF{{{station}_rotation_{token}}}")
```

```
seq 00  frame  9  miytaojxmy3gk
seq 01  frame 21  ojxg4ydcnldmf
seq 02  frame  5  rtamrzg5sgiyz
seq 03  frame 15  tgmztknjqhfta
base32 (52 chars): miytaojxmy3gkojxg4ydcnldmfrtamrzg5sgiyztgmztknjqhfta
token  (32 chars): b1097f6e977015cac0297ddc3335509f
CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}
```

All four chunks originate from `192.0.2.37`, so `<source>` is `rdr37`. The flag is
**`CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`**.

**Why it works**

With no HTTP or TCP in the capture, DNS is the only channel the token could have used. The leaking
host split the 32-char hex token into base32, cut it into four 13-character labels, and sent each as
the leftmost label of an A query to an attacker-controlled zone. Base32 is the natural choice because
DNS labels are case-insensitive and base32's alphabet (`a-z`, `2-7`) survives that. Shuffled send
order plus same-zone decoy queries defeat a naive capture-order read; the explicit sequence label
restores the token.

**Validation / reproduction**

The decoded bytes are exactly 32 lowercase hex characters, matching the token shape the brief demands,
and every chunk originates from the same host. Concatenating in capture order (02, 00, 03, 01) instead
base32-decodes to binary garbage (`b'\x8c\xc0\xc8\xe4...'`), confirming the sequence-label ordering is
correct. Accepted on first submission.

Reproduction: filter the four `<chunk>.<NN>.update.svc-telemetry.example` A queries, sort by `NN`,
concatenate, upper-case, base32-decode. Gotcha: order by the sequence label, not capture order, and
map `192.0.2.37` → `rdr37`.
