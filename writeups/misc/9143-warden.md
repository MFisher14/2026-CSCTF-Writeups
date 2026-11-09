# warden

> Misc · Medium · Iulian Schifirnet  
> Points: 282 · Flag submitted by: secretNinja

**The flag**

`CSCTF{wQgeBWPrGfjgWwaalcIktivH}`

**Challenge**

> During Operation Dawn, Ash Army signals officers built a one-line field console for relay maintenance. It runs your single line in a stripped-down interpreter while a monitor listens to everything the runtime does and cuts the link at the first suspicious sound. A coalition team captured the console's source. The relay's secret sits somewhere on the machine. Study the source, find what the monitor cannot hear, and bring the secret back over the wire.

A per-team TCP container (port 9999) with its source attached as `warden.tar.gz`, one file `jail.py`. It reads a single line and runs it under three defenses:

1. **Static gate (`check`)** — the input must be non-empty, ≤4096 chars, a single line, and parse with `ast.parse`; any `ast.Import`/`ast.ImportFrom` node is rejected. That is the only AST rule.
2. **Empty builtins** — the line runs as `exec(code, {"__builtins__": {}})`, so `open`, `__import__`, `print`, `getattr` and the rest are not reachable by name.
3. **Audit hook (`seal`)** — a `sys.addaudithook` closure that calls `os._exit(1)` on every audit event except `object.__getattr__` and the jail's own single `exec`:

   ```python
   def warden(event, args):
       if event == "object.__getattr__":
           return
       if event == "exec" and budget:   # one exec allowed: the jail's own
           budget.pop()
           return
       shout(2, b"\n[warden] I heard that: " + event.encode() + b"\n")
       die(1)
   ```

`jail.py` imports `ast`, `os` and `sys` at module level, before the hook is installed. Tooling is just reading the source plus a one-line payload, reproduced first in the networkless Docker sandbox against the handout `jail.py`.

**Approach / walkthrough**

1. **Characterize the monitor.** The hook hears *actions* — `open`, `import`, `compile`, a second `exec`, `subprocess.Popen`, `ctypes.dlopen` — because each raises an audit event. The line is compiled before the hook goes in (`compile` is audited), so all of those kill the process. The question is which operations raise no event, or only the whitelisted `object.__getattr__`.

2. **Pivot through the object graph.** With no builtins, `().__class__.__base__` is `object`, and `object.__subclasses__()` lists every loaded class — calling a C method and listing subclasses raise no audit event. Reading a function's `__globals__` raises no event either: CPython raises `object.__getattr__` only for a short list of introspection attributes (`__code__`, `gi_frame`, `tb_frame`, `f_back`-style reads), and `__globals__` is not on it. Since `os` was imported before the seal, `os._wrap_close` (a pure-Python class defined in `os.py`) is present in the subclass list, and `os._wrap_close.__init__.__globals__` is the `os` module's own `__dict__`. Reaching it takes no import.

3. **Read and write the secret.** The flag is in the process environment as `FLAG`. In the `os` globals dict, `environ` is an ordinary mapping (a dictionary read raises no event) and `write` is `os.write`, a raw `write(2)` with no audit event (the jail itself uses it to talk to the client). Reading `environ["FLAG"]` and writing it to fd 1 is silent. The payload, one line, no imports, no builtins:

   ```python
   x=[c for c in ().__class__.__base__.__subclasses__() if c.__name__=="_wrap_close"][0].__init__.__globals__;x["write"](1,x["environ"]["FLAG"].encode())
   ```

   | Step | Expression | Audit event |
   | --- | --- | --- |
   | reach `object` | `().__class__.__base__` | none |
   | enumerate classes | `.__subclasses__()` | none |
   | pick `os._wrap_close` | list comprehension on `c.__name__` | none |
   | `os` module globals | `.__init__.__globals__` | none |
   | read secret | `x["environ"]["FLAG"]` | none |
   | exfiltrate in-band | `x["write"](1, ...)` | none |

   The flag comes back over the same TCP connection — which matters because challenge containers have no egress, so an in-band read is the only way out.

**Why it works**

An audit hook only observes privileged *actions*: opening, importing, spawning, compiling. It cannot hear *reads* of state already resident in memory — a function's `__globals__`, a dictionary lookup, `os.write` — none of which raise an event in CPython, so the monitor never fires on the payload. The static AST gate blocks only `import`, and the empty builtins are irrelevant because the whole chain is built from a bare tuple literal. `os` being imported before the seal is what leaves its module dict reachable through the subclass graph; whitelisting `object.__getattr__` additionally hands over the frame/code reads (`__code__`, `tb_frame`, `gi_frame`) that CPython does audit, though this payload does not need them.

**Validation / reproduction**

Codex, run under human steering, solved this challenge and ran the guarded submit itself (confirmed in its session; byline: secretNinja). The payload was first run against the provided `jail.py` in the `--network none` Docker sandbox (`tools/sandbox.py`) with a dummy `FLAG`, confirming it produced no `[warden] I heard that:` audit trip and printed the env value. It was then sent once to the live instance, which returned the flag directly. Submitted through `ctf.submit.guarded_submit`; `tried.json` records exactly one attempt, `CSCTF{wQgeBWPrGfjgWwaalcIktivH}` → `correct`. During fact-checking the behaviour was re-checked on CPython 3.9.6 and 3.14.7 with an independent audit-hook harness (not `jail.py`): with empty builtins the payload raised only the jail's own `exec` event, and the `__globals__`/`__subclasses__`/`environ`/`os.write` reads raised none.

Reproduction: extract `warden.tar.gz`; run the one-line payload against `jail.py` in the networkless sandbox with a fake `FLAG` and confirm no audit trip; send the same line once to the assigned instance and read the flag off the socket.
