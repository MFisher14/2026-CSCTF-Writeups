# Operation Dawn: The Courier's Keys

> Crypto · Medium · Terminal43  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{01_advance_on_the_mill_a7c3f1}`

**Challenge**

Operation Dawn, annex entry 01. Coalition signals intercepted the Ash Army field-radio fleet during a simultaneous cold start and captured the encrypted order sent to one unit. Recover the message from the supplied packet capture.

- `fleet-provisioning.pcap`, 9,930 bytes, 86 frames (52 IPv4, 34 ARP), the IPv4 traffic mostly decoy ICMP/DNS/HTTP noise around a UDP/7000 provisioning exchange.

**Tools used**

`strings` to read the pcap payloads (the data is plain ASCII), and a short Python search using `random.Random` and `gmpy2.is_prime`.

**Approach / walkthrough**

1. **Read the keygen spec.** The first UDP/7000 packet — a broadcast from `10.23.0.2:7000` to `10.23.7.255:7000` — spells out how each radio makes its key:

   ```
   ASH ARMY KEY UNIT :: provisioning profile
   on power-up each set derives its key from the boot clock and its set serial:
     seed = (power_up_epoch_seconds << 16) | serial
     generator = MT19937 seeded with that value
     draw two 512-bit primes in turn: take a 512-bit candidate with top and bottom
     bits set, keep the first that is prime; these are p then q
     modulus N = p * q, public exponent 65537
   ```

   That is exactly CPython's `random.Random(seed).getrandbits(512)`, so the whole RSA keygen is reproducible from the two seed inputs.

2. **Collect keys and the target.** The fleet cold-starts: nine radios each send `REG serial=… e=65537 N=…` and the base answers `ACK`. The target is packet 84 of 86 (only two ARP frames follow): a single `ORDER serial=6631 C=…` carrying the RSA ciphertext, sent to serial 6631's registration endpoint. So the job is to recover serial 6631's private key and decrypt `C`.

3. **Bound the unknown.** The 1023-bit modulus is strong on its own (the nine fleet moduli share no factors — checked pairwise coprime). The weakness is the **seed space**. The serial (6631) supplies the low 16 bits of the seed; only `power_up_epoch_seconds` is unknown. The capture's packet timestamps bound it: frames run from `1699989961.90` to `1699996098.70`, the provisioning broadcast is stamped `1699989987.70`, and serial 6631's `REG` is stamped `1699994070.89`. The search used the band `[1699986000, 1699996000)` — from somewhat before the capture start up to the `ORDER` time, about 10⁴ candidates (~13 bits).

4. **Search.** For each epoch, re-seed MT19937, draw the first prime, and test whether it divides `N`:

   ```python
   def first_prime(rng):
       while True:
           cand = rng.getrandbits(512) | (1 << 511) | 1
           if gmpy2.is_prime(cand):
               return cand

   for t in range(1699986000, 1699996000):
       rng = random.Random((t << 16) | 6631)
       p = first_prime(rng)
       if N % p == 0:
           q = N // p
           d = pow(65537, -1, (p-1)*(q-1))
           m = pow(C, d, N)
           print(t, m.to_bytes((m.bit_length()+7)//8, "big")); break
   ```

   The hit was epoch **`1699994067`**, about 4 s before 6631's `REG` packet — consistent with a radio booting, generating its key, then registering. Here the first prime drawn divides the captured `N` exactly, giving `N = p·q`.

5. **Decrypt.** With `q = N/p`, compute `d = e⁻¹ mod (p−1)(q−1)` and `m = C^d mod N`. The raw, unpadded plaintext bytes decode directly to `CSCTF{01_advance_on_the_mill_a7c3f1}` ("annex entry 01" + the decrypted order "advance on the mill" + a 6-hex tag).

**Why it works**

The 1023-bit modulus is fine and the moduli share no common factors; the weakness is the seed. Its only secret is a wall-clock boot time, and the capture itself narrows that to roughly 13 bits, with the low 16 bits fixed by the public serial. Feeding a non-cryptographic PRNG a guessable seed makes the "random" primes reproducible, so the private key falls out of a short search over seconds. The same method recovers any fleet member's key from its serial and `N`; only serial 6631 received an `ORDER`.

**Validation / reproduction**

The candidate prime divides `N` exactly, which confirms the epoch rather than merely suggesting it, and the decryption gives clean ASCII in the `CSCTF{...}` frame. Re-verified for the write-up (2026-11-07): seeding `random.Random((1699994067 << 16) | 6631)` regenerates both `p` and `q` with `p·q == N`, the loop finds `1699994067` as its first hit, and the raw-RSA decryption yields the 36-byte flag. The original multiprocessing script ran in ~2 s; the single-process snippet above reaches the hit (8,067 epochs in) in about 10 s.

Reproduction summary: `strings` the pcap; read the keygen spec from the first UDP/7000 broadcast and `N`/`C` for serial 6631 from its `REG`/`ORDER` packets; search the boot-epoch band, regenerating the first prime per epoch and testing divisibility of `N`; factor, invert, decrypt.

Side note: the moduli for serials 7805 and 9919 are 1028 bits, which cannot be a product of two 512-bit primes, so those registrations did not come from the documented keygen (likely decoys); no effect on the solve. Submission was delayed only by repeated CTFd `ratelimited` responses (the flag value never changed) until the rate limit cleared.
