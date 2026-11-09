# Redline

> Forensics · Easy · Chronos Security  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}`

**Challenge**

> Meridian Relief Network, Nightwatch case, Depot 7. During a grid-instability night a cold-chain excursion directive went out to depot crews. A crew lead kept the copy they received, and something reads wrong. The directive is a Word document. Work out how the version that reached the crews differs from what was approved, who changed it, and recover the original excursion authorization. Flag format: `CSCTF{message}`.

The attachment is `CC-11_excursion_directive.docx` (3,817 bytes, SHA-256 `07dff1ed…16bb`). A `.docx` is a ZIP of XML parts, so the job is reading the parts, not opening Word.

**Approach / walkthrough**

*1. Inventory the package.* `unzip -Z1` lists the members. Besides `word/document.xml` there is `word/comments.xml` — someone left a review comment — so read the two small people-facing parts first:

```sh
unzip -p CC-11_excursion_directive.docx docProps/core.xml word/comments.xml
```

`core.xml` gives creator `A. Reyes` (the Medical Director who signs the directive) and last editor `s.kessler`, modified `2026-10-07T02:41:00Z` — the middle of the incident night. The single comment, by `s.kessler`, admits dropping the quarantine hold and re-issuing "under a fresh authorization".

*2. Look for authorization codes in the body.* The body is one line of XML; grep for the flag shape:

```sh
unzip -p CC-11_excursion_directive.docx word/document.xml | grep -oE 'CSCTF\{[^}]*\}'
```

Two codes appear. One is clean, `CSCTF{dispatch_0f7c0c00aac69bbb86d6b96391f5d112}` — the "fresh authorization" `s.kessler` typed in, printed in the copy the crews received, and a decoy. The other is split inside `<w:del>/<w:delText>` elements (Word's Track Changes deletions) across two deletion runs (`w:id` 107 and 108), so the raw grep hit has markup wedged in the middle:

```
CSCTF{redline_21ee9b19d</w:delText>…<w:del w:id="108" …><w:r><w:delText …>342e06432165fb2b6f64e06}
```

*3. Reject the changes to rebuild the approved directive.* Rather than hand-edit XML, walk the tracked changes: for each paragraph, the received text is the untouched runs plus insertions (`w:ins`), and the approved text is the untouched runs plus deletions (`w:del`):

```python
for p in body.iter(W + "p"):
    for child in p:
        if child.tag == W + "r":   got += text_of(child,"t"); orig += text_of(child,"t")
        elif child.tag == W + "del":  orig += text_of(child,"delText")   # approved only
        elif child.tag == W + "ins":  got  += text_of(child,"t")         # received only
```

The run of changes, all by `s.kessler` at `02:41:00Z`, reads: `temperature`→`thermal` (cosmetic); paging threshold `30`→`90` minutes; and the disposition rewritten from "Vials that exceeded 8 C MUST be quarantined and MUST NOT be redistributed. Excursion authorization: CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}." to "…may be returned to distribution at depot-supervisor discretion. Excursion authorization: CSCTF{dispatch_…}." In the approved (all-rejected) text, the two deleted runs 107 and 108 rejoin into one code, which is the flag.

**Why it works**

With Track Changes on, Word keeps deleted text in the file as `<w:delText>` inside a `<w:del>` element that records the editor and time, so a reviewer can still reject the change. `s.kessler` edited the approved directive with tracking on and never accepted the changes, so the copy the crews received still contains A. Reyes's original wording and authorization underneath the new text. Splitting the code over two deletion runs only defeats a plain text search; walking the XML in document order and keeping every `w:del` while dropping every `w:ins` puts the original back together and rebuilds the approved version.

**Validation / reproduction**

The rebuilt approved paragraph reads as a coherent original directive, and the recovered code fits the `CSCTF{message}` format. Reproduction: `unzip -p` the core properties and comment, grep the body to spot the two codes, then walk the paragraphs rejecting changes to rejoin runs 107/108. The team's automated intake submitted three wrong values before any analysis — the decoy `dispatch_` code, then two malformed copies of the deleted code with leftover XML text between its two halves — and the solver's clean rejoined value was then accepted.
