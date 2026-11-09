# Command Authority

> Reverse engineering · Easy · BitR1ft  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

```
CSCTF{f96f4417c75121c3d27b039d}
```

**Challenge**

Responders recovered an offline verifier from a checkpoint that controlled a restricted crossing on a
coalition evacuation route in the Operation Dawn theatre. The task is to find the restricted clearance
value the verifier accepts. `command-authority-evidence.zip` (11,968 bytes, SHA-256
`8d48474b9ff2a03f8c407294c42e8530d7fa865fbb5ebf4de653350bc557d4ca`) contains a personnel image and a
password-protected archive. The `CSCTF{...}` in the brief is only the format example; the real clearance
is hidden deeper. The whole solve is static — the stripped PIE is read, never run.

**Approach**

1. **Unpack the evidence.**

   ```sh
   unzip command-authority-evidence.zip
   #   inflating: id_photo.jpg
   #  extracting: pass_bundle.zip
   ```

   The inner zip won't release its contents without a password, but it will list them:

   ```sh
   unzip -l pass_bundle.zip
   #   112  pass.token
   # 14576  field_verifier
   ```

   So the real target is `field_verifier` (the "offline verifier"), plus a 112-byte base64 token it
   takes as input.

2. **Find the archive key in the photo's trailer.** A photo shipped next to a locked archive is a
   classic place to hide the key. First confirm the photo is *only* a photo. `binwalk id_photo.jpg`
   reports `JPEG image, total size: 10567 bytes`, but the file on disk is larger. JPEGs end with the
   two-byte end marker `ff d9`, so look at the raw tail:

   ```sh
   xxd id_photo.jpg | tail -4
   # 00002930: 0145 1450 0145 1450 0145 1450 0145 1450  .E.P.E.P.E.P.E.P
   # 00002940: 0145 1450 07ff d941 5243 4849 5645 2d4b  .E.P...ARCHIVE-K
   # 00002950: 4559 3a61 5053 3678 7871 5032 4366 4e55  EY:aPS6xxqP2CfNU
   # 00002960: 300a                                     0.
   ```

   The marker `ffd9` sits at 0x2945 (image = 0x2947 = 10567 bytes, matching binwalk) while the file runs
   to 0x2962 = 10594: 27 trailing bytes no decoder renders. Pulling the readable part out:

   ```sh
   strings -n 6 id_photo.jpg | grep ARCHIVE
   # ARCHIVE-KEY:aPS6xxqP2CfNU0
   ```

   The string labels itself and has exactly the shape of the missing zip password. Every image viewer
   stops at `ffd9`, which is why the trailer survives unnoticed.

3. **Open the bundle and take stock.**

   ```sh
   unzip -o -P 'aPS6xxqP2CfNU0' pass_bundle.zip
   file field_verifier
   # ELF 64-bit LSB pie executable, x86-64, dynamically linked,
   #   BuildID[sha1]=d293a546119d28f99e0b27ada0017d7259d5edba, stripped
   base64 -d < pass.token | strings
   # role=civilian&id=civ-88213&route=STANDARD-CORRIDOR-7
   ```

   The bundled token decodes to a `role=civilian` record — not the command-authority role the restricted
   branch wants — and the verifier is a stripped x86-64 PIE. So read the program rather than run it,
   starting with its strings:

   ```sh
   strings -n 5 field_verifier | grep -A13 'usage:'
   # usage: field_verifier <token_file_b64>
   # DENIED: integrity check failed
   # read error
   # DENIED: malformed token
   # route / [OK] pass verified / id: %s / role: %s
   # command-authority
   # route: RESTRICTED
   # clearance confirmed
   # route: %s
   # standard clearance only
   # :'xw'uupv"vtpsp"r%sv#qrx%<
   ```

   Two things stand out: a literal `command-authority` role, and one garbage-looking printable string —
   the only non-message text in `.rodata`. Printable-but-wrong is the classic smell of a single-byte XOR.

4. **Find the guard branch.** The ELF is stripped, but radare2's `aaa` pass recovers the functions. Its
   `afl` listing shows a single large `main` at 0x1120 (1,715 bytes) plus the usual glibc stubs, and a
   cross-reference query lands the one use of the role string:

   ```sh
   r2 -q -e scr.color=0 -c 'aaa; axt @ str.command_authority' field_verifier
   # main 0x16b8 [STRN:r--] lea rsi, str.command_authority
   ```

5. **Read what the branch does.** Disassemble that window (GNU objdump; on macOS put Homebrew binutils
   first on PATH so LLVM's `objdump` doesn't shadow it):

   ```sh
   objdump -d --start-address=0x16b8 --stop-address=0x171b field_verifier
   ```

   ```asm
   16b8:  lea    0x9e9(%rip),%rsi        # 20a8  "command-authority"
   16bf:  mov    %r13,%rdi
   16c2:  call   strcmp@plt
   16c7:  test   %eax,%eax
   16c9:  jne    176b                     # role mismatch -> "standard clearance only"
   16cf:  xor    %eax,%eax
   16d1:  lea    0x30(%rsp),%rbx          # stack output buffer
   16d6:  lea    0xa43(%rip),%rcx         # 2120  source bytes
   16e0:  movzbl (%rcx,%rax,1),%edx       # loop body
   16e4:  xor    $0x41,%edx               # key = 0x41
   16e7:  mov    %dl,(%rbx,%rax,1)
   16ea:  add    $0x1,%rax
   16ee:  cmp    $0x1f,%rax               # 31 bytes
   16f2:  jne    16e0
   16f4:  lea ... puts("route: RESTRICTED")
   1705:  lea ... puts("clearance confirmed")
   1711:  mov %rbx,%rdi ; call puts       # the decoded stack buffer
   ```

   The story is short. `strcmp(role, "command-authority")`; on a mismatch control jumps to 0x176b, which
   prints `route: %s` and `standard clearance only`. On a match, `lea 0xa43(%rip),%rcx` resolves to
   `0x16dd + 0xa43 = 0x2120`, and the loop runs 31 iterations (`cmp $0x1f`), XOR-ing each source byte
   with `0x41` into a stack buffer, then `puts` it after `clearance confirmed`. The restricted clearance
   is never stored in the clear — it exists only as 31 obfuscated bytes, decoded on the stack inside a
   branch you can reach only with a command-authority token. The role check decides only whether the
   program *decodes* the secret at runtime; it does nothing to protect the stored bytes.

6. **Read the bytes off disk and decode.** The addresses are virtual, so confirm `.rodata` maps straight
   to file offsets:

   ```sh
   objdump -h field_verifier | grep -E 'Idx|rodata'
   # 16 .rodata  00000280  0000000000002000  ...  00002000  2**5
   ```

   `.rodata` starts at vaddr 0x2000 and file offset 0x2000 alike, so virtual 0x2120 is file offset
   0x2120:

   ```sh
   xxd -s 0x2120 -l 31 field_verifier
   # 00002120: 0212 0215 073a 2778 7727 7575 7076 2276  .....:'xw'uupv"v
   # 00002130: 7470 7370 2272 2573 7623 7172 7825 3c    tpsp"r%sv#qrx%<
   ```

   This is exactly the garbage `strings` printed. You can verify the frame by hand: the six leading
   bytes `02 12 02 15 07 3a`, each XOR `0x41`, decode to `02^41=C`, `12^41=S`, `02^41=C`, `15^41=T`,
   `07^41=F`, `3a^41={` — i.e. `CSCTF{`. Applying the loop's three constants (source 0x2120, length 0x1f,
   key 0x41) to all 31 bytes:

   ```python
   SRC, N, KEY = 0x2120, 0x1F, 0x41
   blob = open("field_verifier", "rb").read()
   print(bytes(b ^ KEY for b in blob[SRC:SRC+N]).decode())
   # CSCTF{f96f4417c75121c3d27b039d}
   ```

   That is exactly what `main` prints after `clearance confirmed` when the role equals
   `command-authority`. No token was forged and the binary never ran.

**Why it works**

Two independent layers, each defeated statically. The photo carries the bundle password in a trailer
past its JPEG end marker, so viewers ignore it while `strings` hands it over in one shot — and that
password is the only thing protecting `pass_bundle.zip`. Inside, the verifier never stores the restricted
clearance in the clear: `main` compares the token's role against the literal `"command-authority"`, and
only that branch decodes 31 bytes at 0x2120 with a single-byte XOR (0x41). The role check decides only
whether the program *decodes* the secret at runtime; it does not protect the stored bytes. Because this
small PIE maps `.rodata`'s virtual addresses directly onto its file offsets, the guarded bytes are
readable at plain file offset 0x2120, and the exact decode reduces to three constants lifted from the
disassembly. No integrity check, token forgery or password guessing is required — the clearance was
sitting in read-only data the whole time, obfuscated only by a reversible one-byte XOR.

**Validation / reproduction**

The decoded bytes start with the `CSCTF{` frame and are all printable, reproducing exactly what the
`command-authority` branch would print. Reproduction: carve the `ARCHIVE-KEY:` trailer from
`id_photo.jpg`, open `pass_bundle.zip` with it, cross-reference `str.command_authority` in
`field_verifier` to `main` at 0x16b8, read the loop's constants (0x2120 / 0x1f / 0x41), and XOR the 31
`.rodata` bytes. Gotcha: on macOS the stock `objdump` is LLVM's and prints different syntax, so put
Homebrew's GNU binutils first on `PATH`. The flag was accepted on the first submission.
