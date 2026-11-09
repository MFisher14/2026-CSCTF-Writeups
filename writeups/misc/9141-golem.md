# golem

> Misc · Easy · Iulian Schifirnet  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{8JJeMxnQzIblnLwiNtqBydFu}`

(Per-team `flag_mode: random`; the value above is the one the assigned instance returned.)

**Challenge**

> During Operation Dawn, Ash Army signals engineers tested relay firmware on a small register machine they call the golem. A coalition team captured its specification and a set of worked examples. The machine's audit service runs 100 programs, each with an input tape, and checks your answer against what the golem would print, exactly, quirks included. One wrong answer closes the session. Build an interpreter that behaves as the specification and the examples describe, and answer every program.

The target is a per-team TCP container (port 9999). The handout `golem.tar.gz` holds `SPEC.md` (the definition of **GASM**, "Golem Assembly", and the wire protocol) and `examples.txt` (24 worked programs with exact output — examples 1–10 each isolate one quirk, the other 14 are random programs like the ones the server sends). Tooling is Python: a from-scratch interpreter and a small TCP client.

**The machine.** 16 registers `r0..r15`, each unsigned 16-bit, all starting at 0; an input tape read left-to-right by `in`; an output stream appended to by `out`. Instructions: `set mov add sub mul div mod and or xor shl shr not in out`. Control flow is only nested structured blocks — `rep N … end`, `ifz rX … end`, `ifn rX … end` — with no jumps, so every program terminates.

**Approach / walkthrough**

1. **Pin the quirks.** The machine is fully specified; the only difficulty is that 100 answers in a row must all be correct, and one mistake handled the "natural" way instead of the golem's way ends the session. So every rule that differs from a naive implementation was listed and confirmed against the examples before connecting:

   | Quirk | Rule |
   |---|---|
   | Width | every register write is `& 0xFFFF` (add/sub/mul wrap) |
   | `set` immediate | signed decimal taken mod 65536 (`-1`→65535, `70000`→4464) |
   | `div` by 0 | result 65535; otherwise unsigned floor division |
   | `mod` by 0 | result is the dividend, unchanged |
   | Shifts | shift count masked `& 15`; `shr` is logical |
   | `not` | `(~x) & 0xFFFF` |
   | `in` past the tape end | returns 65535 |
   | `rep N` | body runs exactly N times (`N=0` → zero times) |
   | `ifz`/`ifn` | condition tested once on entry; later writes inside the body do not re-test |
   | Operand order | sources read before the destination is written (`add r0 r0 r0` doubles r0) |

2. **Build a tree-walking interpreter** (`solve/gasm.py`). Parse the program into a nested block tree (`rep`/`ifz`/`ifn` open a sub-block, `end` closes it; indentation is cosmetic and ignored). Execute by recursively walking the tree: `rep` runs its body `int(N)` times; `ifz`/`ifn` read the register once then run the body at most once; three-operand ops read `y` and `z` first, compute, then store `R[rX] = v & 0xFFFF` (covering the width and operand-order quirks in one place); `div`/`mod` special-case a zero divisor; shifts mask the count `& 15`. It fails closed: an unknown opcode raises rather than answering, and a bad register index trips an assert, because a wrong answer closes the session.

3. **Verify against the handout.** The interpreter reproduced all 24 example outputs exactly (`24 / 24`) — re-run while writing up. All 10 quirk demos and all 14 random programs match, so we were confident to spend the single live session.

4. **Automate the audit** (`solve/client.py`). Open a plain TCP socket; for each round, buffer input until the `OUTPUT>` prompt, find the last `PROGRAM` line in the chunk (skipping the ASCII-art banner and the previous round's `OK`), collect lines to the `.` terminator, parse the `INPUT` tape, run `gasm.run(prog, tape)`, and send the space-joined outputs (a bare newline for empty output). After 100 correct rounds the service prints the flag. From `solve/session.log`: 100 `OK`, 0 `WRONG`, and the closing message:

   ```
   The golem bows. CSCTF{8JJeMxnQzIblnLwiNtqBydFu}
   ```

**Why it works**

The machine is deterministic and fully specified; the only real content is the unusual edge cases (division and mod by zero, wrapping, tape over-read, shift masking, once-only block tests, operand aliasing). An interpreter that gets every one right produces the same output as the reference, so all 100 programs pass. The 24 worked examples exercise exactly those edge cases, so the interpreter can be validated completely offline before the one-shot session is spent.

**Validation / reproduction**

The interpreter matched all 24 handout examples before any network use. Against the live service it answered all 100 rounds and received the flag; because the service checks every round and closes on a wrong answer, a complete run is itself proof the interpreter is correct. The flag was submitted once through the guarded CLI path and accepted (`tried.json`: one attempt, `correct`). The only network traffic was the single session against the team's own assigned instance — no scanning, no retries.

Reproduction: extract `golem.tar.gz`; run `gasm.py` against `examples.txt` and confirm `24/24`; spawn the team's 9141 container; run `client.py host port` for the 100-round session; read the `CSCTF{...}` from the closing message.
