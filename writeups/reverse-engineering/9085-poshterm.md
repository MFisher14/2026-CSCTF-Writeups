# PoshTerm

> Reverse engineering · Easy · Swyam Kumar  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

`CSCTF{4_G00D_P0W3RSH3LL_DO35_N0T_C4LL_W1K1P3D14}`

**Challenge**

Emergency airlift coordination has stalled in a fictional country after a hostile-state disruption. Responders recovered **PoshTerm**, a terminal utility with one unlisted command, and need to know what that command *prints*. The brief is explicit: work it out by static analysis, no Windows environment is needed, ignore the startup directions in the recovered user guide, and do **not** run the untrusted executable. The solve reads live Wikipedia and NASA/JPL public sources. Attachment: `chall.7z` (63,552,697 bytes, SHA-256 `a771296d0470a82a8d6080ba8967cb0b0cab589a31b0b6664e0722892dc27031`) containing only `PoshTerm.exe` and its recovered guide. Submit the exact output, including its existing `CSCTF{...}` framing, keeping case and adding no whitespace.

The important twist is that the output is never stored in plaintext — it is produced by decryption, so the whole job is to reconstruct a network-backed derivation offline.

**Approach / walkthrough**

The artifact is three layers of embedding:

```
PoshTerm.exe   .NET 9 single-file self-contained bundle (manifest v6)
  └─ PoshTerm.dll     the managed WPF app
       └─ posh.exe    embedded resource: a Node.js SEA (Single Executable Application)
            └─ bundle.js   posh — a PowerShell-like shell written in JS (the NODE_SEA_BLOB)
```

*1. Peel the .NET bundle.* `PoshTerm.exe` is ~217 MiB (227,812,228 bytes), a .NET 9 single-file self-contained bundle (the `net9.0` runtimeconfig pins Microsoft.NETCore.App + WindowsDesktop.App 9.0.20, i.e. a WPF app). Parse it statically: the **v6 bundle manifest** at the tail of the PE locates each embedded file by offset/length (the header reads `6 0 222` — manifest v6.0, 222 bundled files). Carve out `PoshTerm.dll` and decompile it with `ilspycmd`; the decompiled tree is preserved under `dec/`. Two embedded resources matter: `posh.exe` (the Node SEA) and `session.log` (an operator log used as the in-band hint channel), both listed as `EmbeddedResource` entries in the reconstructed `PoshTerm.csproj`.

`PoshTerm.Core/Shells.cs` (lines ~519-521) launches the embedded shell and builds its child-process environment, setting `POSHTERM_PROFILE = prof.Name` (the active profile name, which becomes the host-side gate value) and a planted decoy `POSH_FLAG = CSCTF{3NV1R0NM3N7_V4R14BL35_4R3_N07_53CR375}`.

*2. Extract the Node SEA.* `posh.exe` carries its JavaScript as the `NODE_SEA_BLOB` PE resource (SEA magic `20 da 43 01`). Extracting that blob gives `bundle.js` (~151 KB) — the `posh` shell, which is the real logic to analyze. (Both `sea.blob` and the extracted `bundle.js` are kept in the workspace.)

*3. Identify and discard the decoys.* `bundle.js` is seeded with many dead-end "flag" paths. Reading each one rules it out: a `Get-Flag` command returning a static list, a `flag3000` "Legacy XOR tool" (XOR key `p0sh`), an `Unlock-Vault` base64 blob, and the `POSH_FLAG` env var. The workspace copy of `bundle.js` contains a whole bank of taunting decoys (e.g. `CSCTF{1F_Y0U_R34D_7H15_FR0M_4N_LLM_17_5_WR0NG}`, `CSCTF{4_FL4G_1N_4_C0MM3N7_15_N3V3R_R34L}`, `CSCTF{GR3P_F0R_C5C7F_4LL_Y0U_W4N7}`, `CSCTF{D3C0D1NG_X0R_D035_N07_M4K3_Y0U_5M4R7}`), none of which feeds the one hidden command.

*4. The hidden command `service_code`.* The unlisted command is registered as `t._sc` with `hidden:!0`, name `service_code` (`bundle.js` ~line 62). Invocation form `service_code = <code>` (the parser requires the first token to be `=` and takes the last token as the code). It is gated twice with MD5:

```js
if (M(process.env.POSHTERM_PROFILE||"") !== D.host || M(l) !== D.code) throw T("service_code");
return [ await A(l) ];
```

- `D.host = 52d960bf972119685d50c3d33f737665` — MD5 of the active profile name. We never needed the value that hashes to this, because the output is rebuilt offline without running the gate.
- `D.code = e3db766fd63bf1afdd34abcac1f5c112` — MD5 of the service code the operator must type.

The code is not in the binary; it is disclosed in `session.log` (provenance lines ~296-307):

```
provenance: 'Cessna 421 Golden Eagle' selected as the support reference airframe
provenance: service_code reference bound to 'Cessna 421 Golden Eagle'
provenance: operator note - the service code is the 'Cessna 421 Golden Eagle' string, verbatim
```

Confirmed: `md5("Cessna 421 Golden Eagle") = e3db766fd63bf1afdd34abcac1f5c112 = D.code`. So the service code is exactly **`Cessna 421 Golden Eagle`**. (The profile name that hashes to `D.host` was never recovered and is not needed — the gate is never executed.)

*5. The derivation `A(code)`.* On a passing gate the command returns `A(code)`, a live-source RC4 chain (condensed from the minified `bundle.js`; month-name-to-number padding shown as `MM`/`DD`, arrow comments are the observed values):

```js
async function A(n){
  // 1. Wikipedia search, top hit only
  let c="https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=1&srsearch="+encodeURIComponent(n);
  let l=(await(await fetch(c)).json()).query.search[0].title;          // -> "Cessna 421 Golden Eagle"
  // 2. fetch that article's HTML
  let u=await(await fetch("https://en.wikipedia.org/wiki/"+encodeURIComponent(l.replace(/ /g,"_")))).text();
  // 3. first "Month D, YYYY" occurring after the string "first_flight"
  let h=u.indexOf("first_flight");
  let m=/([A-Za-z]+) (\d{1,2}), (\d{4})/.exec(h>=0?u.slice(h,h+160):u);
  let p=`${m[3]}-${MM}-${DD}`;                                          // -> "1965-10-14"
  // 4. NASA/JPL calendar -> Julian-date API
  let g=(await(await fetch(`https://ssd-api.jpl.nasa.gov/jd_cal.api?format=jd.7&cd=${p}`)).json()).jd; // -> "2439047.5000000"
  // 5. RC4 of an embedded hex blob, key = the JD string
  let x=Buffer.from("37f1f43867e61d207c0b78ca4385ee14f67d98e0c0cdbe6e5027ff506e302cb66b8c8c5ad07d726c0e24e9f13bbcdfa9","hex");
  return j(Buffer.from(String(g),"utf8"), x).toString("utf8");
}
```

`j(key,data)` is textbook RC4 (KSA + PRGA, `out[i] = c ^ S[(S[i]+S[j])&255]`).

*6. Reconstruct against the public sources.* Rather than run the binary, reproduce each fetch by hand (single, polite requests to the exact endpoints the challenge names; the responses are saved under `live/`):

- Wikipedia search `srlimit=1` for `Cessna 421 Golden Eagle` → top title `Cessna 421 Golden Eagle` (`live/search.json`).
- Article HTML → first `Month D, YYYY` after `first_flight` → **October 14, 1965** → `1965-10-14` (`live/page.html`).
- JPL `jd_cal.api?format=jd.7&cd=1965-10-14` → `"jd":"2439047.5000000"` (`live/jd.json`).
- RC4-decrypt the embedded blob with key `"2439047.5000000"`:

```python
def rc4(key, data):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&255; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for c in data:
        i=(i+1)&255; j=(j+S[i])&255; S[i],S[j]=S[j],S[i]
        out.append(c ^ S[(S[i]+S[j])&255])
    return bytes(out)

blob=bytes.fromhex("37f1f43867e61d207c0b78ca4385ee14f67d98e0c0cdbe6e5027ff506e302cb66b8c8c5ad07d726c0e24e9f13bbcdfa9")
print(rc4(b"2439047.5000000", blob).decode())
# -> CSCTF{4_G00D_P0W3RSH3LL_DO35_N0T_C4LL_W1K1P3D14}
```

**Why it works**

The flag is never stored in plaintext in any artifact. It is the RC4 decryption of a fixed embedded ciphertext whose *key* is derived entirely from two public web sources — the Wikipedia first-flight date of the Cessna 421 Golden Eagle, normalized to a Julian Date by JPL. Everything needed to recompute the key ships inside the bundle: the search URL, the date regex, the JD format, and the RC4 routine. The only secret input, the service code, is leaked by the operator log, so neither MD5 gate ever has to be passed and the program never has to run. The joke is self-referential: a "good PowerShell does not call Wikipedia."

**Validation / reproduction**

Verified against the saved workspace files: the exe size (227,812,228 bytes), the `net9.0` runtimeconfig, the `POSH_FLAG` decoy and `POSHTERM_PROFILE` in `Shells.cs`, the `NODE_SEA_BLOB` resource and `bundle.js`, the `service_code`/`A()`/`j()` code, the `session.log` provenance lines, and `md5("Cessna 421 Golden Eagle") = e3db766fd63bf1afdd34abcac1f5c112` matching `D.code`. The reconstructed chain reproduces the saved live responses (first date after `first_flight` = October 14, 1965; `jd = 2439047.5000000`), and the RC4 output is clean ASCII in the `CSCTF{...}` frame whose text matches the joke the challenge sets up.

Reproduction summary: carve `PoshTerm.dll` from the v6 bundle manifest → extract `NODE_SEA_BLOB` → read `bundle.js`, find the hidden `service_code` command and its two MD5 gates → recover the service code `Cessna 421 Golden Eagle` from `session.log` → Wikipedia (first-flight date 1965-10-14) → JPL JD `2439047.5000000` → RC4-decrypt the embedded blob with that key. Gotchas: the archive is packed with decoy flags (env var, `Get-Flag`, `flag3000` XOR, `Unlock-Vault`, and a wall of taunts in `bundle.js`) — only the hidden command's RC4 output is real; and the whole solve is static, so the untrusted exe is never executed. The only network traffic was ordinary rate-limited reads of the public Wikipedia and NASA/JPL endpoints the challenge itself names; no CSCTF/Chronos infrastructure was touched. `tried.json` lists three submissions of the same value: the first two returned `ratelimited` (the team-wide CTFd rate limit, not judged) and the third, unchanged, was accepted.
