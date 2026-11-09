# Harvest

> OSINT · Not shown · Kevin Sander  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{PP-7_SNOP}`

**Challenge**

A regional Telegram channel published a photo of a Mi-24 carrying a sling load over a wheat field, claiming "bort 34" delivered cargo near the village of Staroselye on 14 August 2026. Your monitoring cell obtained seven files from a logistics officer's laptop (417th Separate Helicopter Squadron, aerodrome KORLEVO) plus two encrypted radio-net intercepts. Nothing needs to be hacked. The question: where did the squadron's sling-load cargo actually go on 14 August, and what was it? Flag format `CSCTF{PP-N_CODEWORD}` (example `CSCTF{PP-3_OVES}`).

**Tools used**

python3 (standard library), exiftool.

**Approach / walkthrough**

1. **Test the photo for a date/location.** `exiftool -EXIF:all -XMP:all -GPS:all -PNG:all 02_photo.png` returns only the bare PNG header — no EXIF, GPS, or text chunk. Nothing dates or places the shot. Visual inspection shows a white **34** on the fuselage, "ВКС РОССИИ" on the tail boom, green crates in slings over ripe wheat, and a domed church on the hill at the far right (≈ x 1560–1650). The picture is consistent with the post (bort 34, a church fitting Staroselye) but proves nothing about the date.

2. **Check the flight schedule (`03_flight_schedule_14AUG.txt`).** This alone sinks the post:
   - **Bort 34 (callsign VORON) did not fly.** It was U/S, main gearbox replacement, "not before 18.08".
   - The day's **sling loads were flown by Mi-8 transports, not a Mi-24**: bort 22 (ZHATVA) 09:00–10:55 with "LZ per separate order", and bort 25 (BEREG) 13:20–14:35 to PP-5. Bort 22's landing zone is deliberately left off the page.
   - **Nothing flew after 15:00** (thunderstorm warning 15:00–22:00).
   - Every crew has a daily callsign — that column holds the cipher keys.

3. **Read the logistics sheet (`05_logistics_sheet_14AUG.txt`).** Cargo is named only by code word (glossary: `SNOP` = portable EW jamming set, `KORZINA` = small-arms ammunition, `MESHOK` = rations/water, etc.). The loading plan has **bort 22 → 4 × SNOP, sling, to "PP per order"** (the same blank), bort 25 → 6 × MESHOK to PP-5, and no bort 34. Landing sites: **PP-2 is Staroselye, "pasture below the church" — CLOSED since 02.08 (mines, order 88)**; PP-7 is Mirnoe, harvested field west of the dairy farm. So the open question is where bort 22's four SNOP went — kept off paper, leaving the radio traffic.

4. **Learn the radio rules (`04_signals_instruction_extract.txt`).** Crew reports are Vigenère over the Latin alphabet on transliterated Russian, letter `X` marks a word boundary, and **the key is the sending crew's daily callsign**. Message format is a DTG `DDHHMM`, cipher text in five-letter groups, and a **check group equal to the number of groups**. Landing sites go by PP number only; **naming a settlement is prohibited**. A glossary lists the expected report words and spelled-out numbers.

5. **Read the intercepts (`06_intercepts_14AUG.txt`).** #1 (DTG 141020) was sent while bort 22 and its escort were airborne; its groups count 9+9+3 = 21, matching its check group 21. #2 (DTG 141630) was sent when nothing was flying; its groups count 9+9+7 = **25** against a check group of **24**.

6. **Decrypt both.** With only six callsigns, try each and score by how many `X`-separated words hit the glossary:

   ```python
   def vigenere_decrypt(text, key):
       return "".join(chr((ord(c) - ord(key[i % len(key)])) % 26 + ord("A"))
                      for i, c in enumerate(text))
   ```

   Each message has exactly one key that yields Russian:
   - **#1, key ZHATVA (bort 22):** `DOKLAD ZHATVA GRUZ SNOP CHETYRE MESTA DOSTAVLEN PP SEM VREMYA DESYAT DVADTSAT BORT DVADTSAT DVA KONEC` — "Report, ZHATVA. Cargo SNOP, four pieces, delivered to PP-7. Time 10:20. Bort 22. End."
   - **#2, key VORON (bort 34):** "Report, VORON. Cargo KORZINA, six pieces, delivered to PP-2 Staroselye. Time 16:30. Bort 34. End." — the trap: decrypts cleanly and tells exactly the Telegram story, so stopping here yields the plant's answer `CSCTF{PP-2_KORZINA}`.

7. **Hold each decrypt against the paperwork.** A second script re-runs every rule straight from the files:

   | Check | #1 (ZHATVA) | #2 (VORON) |
   |---|---|---|
   | Check group = number of groups | 21 = 21 ✓ | 24 ≠ 25 ✗ |
   | Sender airborne when sent | bort 22 09:00–10:55, sent 10:20 ✓ | bort 34 U/S all day ✗ |
   | Sent before 15:00 stop | 10:20 ✓ | 16:30 ✗ |
   | No settlement named | PP number only ✓ | names STAROSELYE ✗ |
   | Landing site open | PP-7 Mirnoe ✓ | PP-2 closed (mines) ✗ |
   | Cargo as loaded | 4 × SNOP, as planned ✓ | bort 34 had no load ✗ |

   Report #2 fails every check; report #1 passes all six and fills the "per order" blank. The genuine landing site is PP-7 and the cargo code word is SNOP.

**Why it works**

The public story (post + photo) and the planted intercept agree with each other, but the squadron's own working files contradict both: bort 34 was grounded, Staroselye's PP-2 was mined and closed, and the real destination was encrypted. The cipher is the easy part — Vigenère keyed by a crew callsign the schedule lists — so six trial decryptions break both messages. The real puzzle is which report to trust, and the planted #2 decrypts just as cleanly as #1. Cross-checking each against the records (check group, flight times, the 15:00 weather stop, the place-name ban, the minefield closure, the loading plan) leaves exactly one genuine report.

**Validation / reproduction**

A script re-runs all six checks straight from the files; only report #1 passes all of them, yielding `PP-7` and `SNOP` → `CSCTF{PP-7_SNOP}`. Accepted on the first submission. Bort 22's four portable jamming sets went to PP-7 (harvested field west of the dairy farm at Mirnoe) while the channel pointed everyone at Staroselye. Gotcha: both intercepts decrypt to valid Russian — the trap is to stop at the first clean decrypt (`#2`, matching the Telegram claim) instead of validating it against the schedule and logistics rules.
