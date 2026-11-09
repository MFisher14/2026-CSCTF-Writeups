# Carrier Shadow

> Reverse engineering · Not shown · Created by [Balint](https://github.com/Zedpaixd)  
> Points: 540 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}
```

**Challenge**

`carrier-shadow` is a 1,337,736-byte stripped x86-64 PIE (SHA-256
`995fd7161d984898e521eb581f93380b11f31e3de342b368519a2221fb192a04`, dynamically linked against
`ld-linux-x86-64.so.2`, BuildID `0dc09925…18aa3c`) that presents itself as a hex utility, "hexkit
1.2.0". Run, it prints a few lines of ordinary hex-dump output. The brief's twist: the usual hiding
spots are all clean — data sections, `strings` output, any overlay past the section table, and
appended archives hold nothing useful — yet the binary's second-stage payload signature was seen in
captured traffic. The task is to find where that payload actually lives, lift it out statically, and
read the authorization string it carries. (The brief calls the second stage a "static ELF"; the
carrier itself is PIE/dynamic. It is the *lifted* stage-2 that is static, an immaterial
brief-vs-artifact wording difference.)

**Approach**

The binary triaged to the reverse lane (`solvers/binary/binfmt.py`, `facts.py`, `static_re.py`,
`native_behavior.py`, plus the `solvers/toolkits/` symbolic engines). The decisive first observation
is the shape of the code: roughly 24,800 tiny "micro-functions." The `.eh_frame_hdr` binary-search
table lists `fde_count = 0x60f0` (24,816) FDEs. That many near-empty functions is not a quirk of the
compiler — it is the whole mechanism. The payload is encoded not in any byte of data, but in *where*
the functions sit.

1. **Find the real `main`.** `_start` (the entry stub at `0x21a0`) hands `0x99160` to
   `__libc_start_main`. `0x99160` is a single `jmp 0x99320`, so the body lives at `0x99320`. In this
   PIE the text segment's file offset equals its vaddr, so the two numbering schemes agree throughout
   and addresses from the disassembler can be used directly as file offsets.

2. **`main` reads its own unwind table.** Instead of reading payload bytes from any section, `main`:
   - walks its own program headers for `PT_GNU_EH_FRAME` (`p_type == 0x6474e550`);
   - parses the `.eh_frame_hdr` binary-search table, reading the `initial_location` (function start
     address) of every FDE into an array — i.e. it recovers the start address of each of the ~24.8k
     micro-functions.

   This is the step a `strings`/section/overlay scan can never see: nothing is *stored*; the input to
   the decoder is the geometry of the code itself.

3. **The gap decoder.** At `0x995e0` (called with `0x6a2b3c4d` loaded into `edx` at `0x994a0`),
   `main` turns the gap between each pair of consecutive function start addresses into one symbol,
   `gap − 2`, a value in `0..255`. The leading entries carry a header. It then de-obfuscates that
   stream with Huffman-style tables in `.data.rel.ro` (around `0x146810`, referenced RIP-relative at
   `0x997ee`), an `xorshift32` keystream seeded with `0x6a2b3c4d`, and an XOR checksum. The
   disassembly pins the pieces down: the xorshift32 shift triple `<<13, >>17, <<5` appears at
   `0x9965e` and again at `0x99c21`, and `sub $0x2` performs the gap adjustment.

   An independent static re-check backs the scheme up. A short Python parse of the `PT_GNU_EH_FRAME`
   segment (file offset `0x9b600`) reads the `.eh_frame_hdr` encodings `0x1b / 0x03 / 0x3b`,
   `fde_count = 0x60f0` (24,816), and confirms that **24,808 of the 24,815 consecutive start-address
   gaps satisfy `0 <= gap − 2 <= 255`** (minimum gap 2). A few larger gaps (maximum 1,920) fall
   outside that band; how the decoder treats those was not re-derived, and the table decode was not
   re-implemented offline. The point of the re-check is only to confirm that the gaps carry a
   byte-stream of the right shape, not to reproduce the full decode by hand.

4. **Inflate and ELF check.** The gap-decoded stream is DEFLATE-compressed. A puff-style inflater at
   `0x9a090` expands it; `main` then checks the output for `\x7fELF` at `0x99598`
   (`cmpl $0x464c457f,(%rbp)`) and passes it to a reflective loader at `0x9a810`, which calls
   `sysconf`, `mmap`, `memcpy` and `mprotect` through the PLT (plus `getrandom`/`getuid`/`geteuid`)
   to map and run the second stage in-memory. In other words the carrier rebuilds an entire ELF out
   of its own function spacing and never writes it to disk.

5. **Lift the stage-2 image statically (in the sandbox).** Rather than trust the reflective loader,
   we let the carrier rebuild the payload under emulation and stopped it just before it executed
   anything. Inside the project's hardened pwn sandbox (`csctf-pwn:1`, `--network none`) under
   `qemu-x86_64 -g` with `gdb-multiarch`:
   - Break at `base + 0x995c0`. The disassembly shows this block is reached only after the inflater
     (`call 0x9a090` at `0x99572`) returns success, the output length in `r12` passes `> 3`, and the
     `\x7fELF` check at `0x99598` matches. The instructions there are
     `mov %r12,%rsi; mov %rbp,%rdi; call 0x9a810`, so the inflated ELF sits in `[rbp, rbp+r12)`
     immediately before the loader runs — `rbp` is the buffer base, `r12` its length.
   - Dump `[rbp, rbp+r12]` → a 34,192-byte buffer.

   Saved as `payload_stage2.elf`, SHA-256
   `4f864208546b2108ae453292220e297684fe6bb74384e380c95dd9b4b33b06b9`. `file` confirms it is a
   statically linked, stripped ELF64 x86-64 — a self-contained second stage. (Its `strerror` text —
   `Operation not permitted`, `Operation canceled`, … — and two `GCC: (Debian 11.2.0-19)` /
   `GCC: (Debian 12.2.0-14+deb12u1)` toolchain comments suggest a static musl build, but with no
   libc version string the musl label was not independently confirmed.)

6. **Read the authorization string.** The flag is in plain `.rodata` of the dumped ELF — no execution
   needed. The `.rodata` section is at vaddr `0x407000` / file offset `0x7000`, and the flag string
   lands at file offset `0x7070` (vaddr `0x407070`):

   ```
   $ strings -n 6 payload_stage2.elf | grep -iE 'author|CSCTF'
   CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}
   payload: operation-dawn authorization = %s
   ```

   The format string `payload: operation-dawn authorization = %s` is filled with the flag. The value
   is stable across uid/pid/argv/env (checked in-container), so it is a static constant, not
   runtime-derived — which is why reading `.rodata` is enough and the reflective loader never has to
   run.

**Why it works**

The payload is never stored as bytes. It is encoded in where the functions sit — the spacing between
function start addresses — which the binary reads back from its own `.eh_frame_hdr` unwind table.
Section, string and overlay scans never see it, because the bytes only come into existence once the
layout is decoded at runtime: gaps → symbols (`gap − 2`) → de-obfuscation (Huffman tables +
xorshift32, seed `0x6a2b3c4d`, XOR checksum) → DEFLATE inflate → a complete static ELF, reflectively
loaded. This is why the challenge is tagged steganography and why a static lift beats a pure sandbox
approach: once inflated, the stage-2 is an ordinary ELF with its secret in plain `.rodata`, and you
never have to let unknown second-stage code execute to read it.

**Validation / reproduction**

The dumped region began with a valid ELF header and `file` parsed it as a complete static executable.
The authorization string came out identical across changes to uid, pid, argv and environment inside
the container, confirming a constant rather than a runtime-derived value.

Reproduction: (1) disassemble the carrier; locate `main` at `0x99160` (a `jmp` to the body at
`0x99320`), the gap-decoder at `0x995e0`, the inflater at `0x9a090`, and the reflective loader at
`0x9a810`; (2) confirm the decoder reads `PT_GNU_EH_FRAME` and the `.eh_frame_hdr` FDE table, deriving
bytes from consecutive function-start gaps; (3) in the sandbox (`csctf-pwn:1`, `--network none`,
`qemu-x86_64 -g` with `gdb-multiarch`), break at `base+0x995c0` and dump `[rbp, rbp+r12]` to recover
the 34,192-byte inflated stage-2 ELF; (4) `strings` / static-read its `.rodata` for the
`operation-dawn authorization = %s` value.

`tried.json` records three submissions of the same value: the first two came back `ratelimited` (the
team-wide CTFd rate limit, not a wrong answer), and the third, unchanged, was accepted. No 3-wrong
guard was ever triggered — the flag was correct throughout.
