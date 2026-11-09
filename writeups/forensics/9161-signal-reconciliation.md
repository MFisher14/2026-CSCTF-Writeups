# Signal Reconciliation

> Forensics · Not shown · Concept and defensive navigation-integrity scenario by Balint; fresh CSCTF26 implementation.  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}`

**Challenge**

> A state-linked actor altered a fictional reconnaissance receiver feed during mobilization. Before the receiver profile is reused, reconcile its local-position export with the independently integrated local-navigation series and produce the complete response-cell record. Flag format: `CSCTF{BASE32_192_BIT_DIGEST}` (just the format example — 192 bits of a digest, Base32-encoded; don't submit it).

The attachment `signal-reconciliation.zip` (13,341 bytes, SHA-256 `ea09de45…1633`) holds `flight.ndjson` (601 samples of INS velocity plus receiver east/north position), a mission note, `reconciliation-sop.txt`, and a SHA-256 `manifest.txt`. The SOP specifies the entire computation and the exact bytes of the report whose hash is the flag.

**Approach / walkthrough**

*1. Verify.* Check the zip against the brief's hash, then `tail -n 3 manifest.txt | shasum -a 256 -c` for the three inner files.

*2. Validate the input against the SOP grammar.* A byte regex confirms exactly 601 LF-terminated lines, fixed key order `{"i","t_ms","ve_mmps","vn_mmps","gps_e_mm","gps_n_mm"}`, integers matching `0|-?[1-9][0-9]*`, `i` incrementing by one and `t_ms = 100*i`. Critically, every trapezoid sum `ve[i]+ve[i+1]` and `vn[i]+vn[i+1]` is divisible by 20 (zero exceptions), so the SOP's "exact mathematical integer division" never needs rounding and plain integer `//` is exact — no floating-point choice can creep in.

*3. Integrate INS and form the residual.* `ins[0]=0`; `ins[i+1] = ins[i] + (v[i]+v[i+1])//20` per axis (trapezoid rule: mean velocity × 0.1 s, in mm). Then `res = gps − ins` per axis.

*4. Window inventory.* For each `i = 0..591`, `Q(i)` is true iff every `j=i..i+9` has `res_e[j]²+res_n[j]² ≥ 625000000` (25 m), every step `res_e[j+1]−res_e[j] ≥ 1000` (east grows ≥1 m/step) and `|res_n[j+1]−res_n[j]| ≤ 500` (north steady ±0.5 m). The residual is zero while the receiver is honest; it shows 18 ten-sample walk-off ramps (25 m → 34 m east, north unchanged, then snapping back) plus one 100 m offset at `i=600`. Each ramp satisfies `Q` once, at its onset, so `QSET` is the complete increasing set of all 18 onsets, **not just the first**:

```
qset = 5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588
```

Reporting only `qset=5` yields a different report hash and a wrong flag — the SOP's chief trap.

*5. Decision.* `QUARANTINE_GNSS_PROFILE` iff QSET is non-empty **and** `res[600]² ≥ 10¹⁰` (100 m). At `i=600`, `res_e=100000, res_n=1000`, so `|res|² = 10001000000 ≥ 10¹⁰`; with a non-empty QSET the decision is `QUARANTINE_GNSS_PROFILE`.

*6. Canonical report and flag.* Write 603 ASCII lines, LF-only, ending in exactly one LF: a header line, one `E|i|t_ms|ins_e|ins_n|gps_e|gps_n|res_e|res_n` per sample, and a `SUMMARY` line whose `qset` is byte-identical to the header's. The flag body is uppercase unpadded RFC 4648 Base32 of the first 24 bytes (192 bits) of SHA-256 over the complete report:

```python
digest = hashlib.sha256(open("report.txt","rb").read()).digest()
# 23a4be8bd5cf7936e9f6bd1da0f6753b2b8e9b6db3d0b5e3...
print("CSCTF{" + base64.b32encode(digest[:24]).decode().rstrip("=") + "}")
# CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}
```

**Why it works**

INS velocity integrated over time gives a dead-reckoned track a GNSS spoofer cannot touch, so the residual between it and the receiver is zero while the receiver is honest and shows the classic drag-off signature — a large, steadily growing, one-directional offset — while it is being spoofed. The rest is a determinism exercise: integer arithmetic, the window predicate and the report layout are all fixed, so the truncated-SHA-256 → Base32 flag is only correct if every onset and every byte is right. The traps are reporting a single onset and getting line endings or number formatting wrong.

**Validation / reproduction**

The report writer was first run on the SOP's all-zero known-answer test (601 zero rows): it reproduced the stated 14,329 bytes and SHA-256 `cc8c52dc…87f1` exactly, proving the line format, separators and final LF before touching the real data. The real report was then spot-checked: 603 lines, `SUMMARY` qset byte-identical to the header, last byte `0x0a`. Reproduction: validate the grammar and the divisible-by-20 property, integrate, evaluate `Q` over all 18 onsets, write the canonical report, then hash → Base32. Accepted on first submission.
