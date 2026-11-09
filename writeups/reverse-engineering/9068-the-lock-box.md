# The Lock Box

> Reverse engineering · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{06_ash_hawk_road_at_garrisoned_38318f}`

The pass phrase the gate unit accepts *is* the flag: once the hidden check is inverted it prints a
well-formed `CSCTF{...}` string, so there is no separate decoding step.

**Challenge**

Operation Dawn, annex 06. The Ash gate guards run a small field unit (`lockbox`) at the north canal
crossing: you hand it a pass phrase and it opens the gate or refuses. We captured one. It will not tell
you the phrase it is waiting for; the task is to recover it. The handout is `lockbox.zip` (SHA-256
`d805f832eb72f56b20ef2e55de4757430e4125545a132285a41b46fbdb0f232c`), which unpacks to a single ELF.

**Tools used**

`readelf`, GNU `objdump`, and Python (plus `unzip`/`file`/`strings` for the first look). On macOS put
Homebrew's binutils first on `PATH` so `readelf`/`objdump` are the GNU builds. Everything below is static;
the only step that executes the binary is an optional end-of-solve sanity check on Linux x86-64.

**Approach**

1. **Identify and skim.** `unzip lockbox.zip && file lockbox` reports an *ELF 64-bit LSB pie executable,
   x86-64, dynamically linked, stripped*. Stripped PIE, so no symbol names to lean on. `strings -n 8
   lockbox` shows the UI is `gatelock <status|log|open> [phrase]`, with one "accepted" line and one
   "refused" line. Three oddities stand out: a taunt about "last week's code", a 33-character run of junk
   (`4+>5{(>(:6>{:5?{625?{/3>{/)2+,2)>`), and a `LOCKBOX1,` magic that looks like a data blob.

2. **Find `main` and read the `open` branch.** `readelf -h` gives entry `0x13a0` (`_start`), which loads
   `main` into `rdi` before `__libc_start_main`:

   ```
   13b8: lea rdi,[rip+...]   # 11c0
   13bf: call QWORD PTR [rip+...]   # __libc_start_main
   ```

   So `main` is at `0x11c0`. Disassembling it, the `open` branch copies `argv[2]` into a stack buffer via
   a helper at `0x1490` (a `strncpy` of up to 255 bytes that strips a trailing `\r`/`\n` and returns the
   length), then:
   - if the phrase is 33 bytes (`0x21`) and every byte XOR `0x5b` equals the junk at `0x2200`, prints the
     quartermaster's taunt;
   - **either way**, reads a 32-bit global at `0x4014` and prints "accepted" only if it equals `0x5a`,
     otherwise "refused".

   Decoding the junk confirms the decoy. `.rodata` loads at vaddr `0x2000` from file offset `0x2000`, so
   addresses double as file offsets:

   ```sh
   python3 -c "d=open('lockbox','rb').read(); print(bytes(b^0x5b for b in d[0x2200:0x2221]).decode())"
   # open sesame and mind the tripwire
   ```

   `open sesame and mind the tripwire` is "last week's code": it only earns the taunt, and nothing on that
   path writes `0x4014`, so the gate still refuses. The real verdict is set somewhere else.

3. **Find who sets the verdict.** Grep the disassembly for the global:

   ```sh
   objdump -d -M intel lockbox | grep 4014
   # 11b0: mov DWORD PTR [rip+...],eax   # 4014   <-- the only write
   # 1291: mov eax,DWORD PTR [rip+...]   # 4014   <-- main reads it
   ```

   The one write is at `0x11b0`, inside a function starting at `0x10e0` that nothing calls directly. The
   constructor table explains it:

   ```sh
   objdump -s -j .init_array lockbox
   # 3d90  80140000 00000000 e0100000 00000000
   ```

   `.init_array` holds two little-endian pointers: `0x1480` (GCC's `frame_dummy`) and `0x10e0`. glibc runs
   everything in `.init_array` **before `main`, with the same `argc`/`argv`**. So `0x10e0` is a hidden
   constructor that inspects the command line and leaves its verdict in `0x4014` for `main` to read.

4. **Read the constructor.** `objdump -d -M intel --start-address=0x10e0 --stop-address=0x11c0 lockbox`
   decodes to the following (registers from the listing in the comments):

   ```c
   int verdict;                                  /* dword at 0x4014, starts 0 */

   void lock_check(int argc, char **argv)        /* 0x10e0, run from .init_array */
   {
       unsigned char buf[256];
       const unsigned char *key    = (void *)0x224d;  /* 8 bytes */
       const unsigned char *target = key + 8;         /* 0x2255, 44 bytes */

       if (argc <= 2 || strcmp(argv[1], "open") != 0) return;
       if (copy_phrase(argv[2], buf) != 44) return;   /* same helper at 0x1490 */

       unsigned char s = 0x5b;                   /* esi: running state */
       int ok = 1;
       for (int i = 0; i < 44; i++) {
           unsigned char x = rol8(buf[i] ^ s, (1 + 3 * i) & 7) + key[i & 7];
           if (x != target[i]) ok = 0;           /* cmovne */
           s += i + x;                            /* add esi,eax ; add esi,edx */
       }
       verdict = ok ? 0x5a : 0x17;               /* branch-free cmp/sbb/and/add */
   }
   ```

   Details worth pinning from the assembly: the rotate count starts at 1 and grows by 3 per byte, and an
   8-bit `rol` by `n` equals `rol` by `n mod 8`, so it is `(1 + 3*i) & 7`. Only the low byte of the state
   matters (only `dl` is rotated/compared), so doing the state arithmetic mod 256 is exact. The verdict
   store is a branch-free `ok ? 0x5a : 0x17`. The key and target are the `LOCKBOX1,` blob: magic
   `LOCKBOX1`, a `u32` length `2c 00 00 00` (44), seed byte `5b`, 8 key bytes `63 0e fa b0 e3 84 22 68`,
   then 44 target bytes.

5. **Invert the check.** Each step is a bijection on one byte, and the running state is fed only by `i`
   and the output byte `x`, which for the correct phrase is the known target byte. So the state is known
   at every position without knowing the phrase: walk the target front-to-back and peel off `p[i]`.

   ```python
   data   = open("lockbox", "rb").read()
   LENGTH = 0x2C
   SEED   = 0x5B
   KEY    = data[0x224D:0x224D + 8]
   TARGET = data[0x2255:0x2255 + LENGTH]
   ror8 = lambda v, n: ((v >> (n & 7)) | (v << (8 - (n & 7)))) & 0xFF

   s, phrase = SEED, bytearray()
   for i in range(LENGTH):
       t = TARGET[i]
       phrase.append(ror8((t - KEY[i & 7]) & 0xFF, 1 + 3 * i) ^ s)
       s = (s + i + t) & 0xFF
   print(phrase.decode())
   # CSCTF{06_ash_hawk_road_at_garrisoned_38318f}
   ```

   The solve script re-runs the loop forward as an `assert` to prove the recovered phrase satisfies the
   constructor's comparison before trusting it.

**Why it works**

The real check is hidden in an ELF constructor listed in `.init_array`, which glibc runs before `main`
with the same arguments, and it stores its verdict in a global that `main` only reads. `main`'s own XOR
comparison is a decoy that can never open the gate — nothing on that path writes `0x4014`. The
constructor's per-byte transform (XOR with a running state, an 8-bit rotate, add a key byte) is a
bijection on each byte, and the state depends only on values the defender stored (the seed, `i`, and the
target). That makes the whole check reversible in a single forward pass, with no search.

**Validation / reproduction**

The recovered phrase was pushed back through a forward re-implementation of the loop (an `assert` in the
solve script) and it starts with `CSCTF{`, so the pass phrase is the answer itself. On Linux x86-64 the
behavior can be confirmed directly — last week's code still bounces, the recovered phrase opens the gate:

```sh
chmod +x lockbox
./lockbox open "open sesame and mind the tripwire"
# the quartermaster laughs - that is last week's code, soldier
# GATE: pass phrase refused - crossing barred
./lockbox open "$(python3 solve.py)"
# GATE: pass phrase accepted - crossing open
```

The flag was accepted on the first submission.

Reproduction summary: unzip, `strings` to spot the decoy and the `LOCKBOX1,` blob, locate `main` via
`_start`, grep for the verdict global, follow `.init_array` to the hidden constructor, transcribe its
per-byte loop, then invert it with the saved 8-byte key and 44-byte target. Gotcha: the `main`-side XOR
string is a deliberate trap — matching it changes nothing, because the verdict is written only by the
constructor that ran before `main`.
