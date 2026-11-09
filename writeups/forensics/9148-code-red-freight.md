# Code Red Freight

> Forensics · Medium · Marius Merai  
> Points: 270 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}`

**Challenge**

Tarnovel Rail Freight's defence-consignment manifests are reaching an outside
mailbox and the dispatcher, Patti Fernandez, noticed nothing. The handout
`code_red_freight.zip` is a constructed incident built from sanitized Microsoft
Entra and Purview-style exports: an Entra audit log, interactive and
non-interactive sign-in logs, a Purview unified audit log (UAL) for Patti, and two
lure screenshots. The task is to identify three things — the device the adversary
controls, the inbox rule leaking manifests, and the number of files they
downloaded — and assemble them into the flag format
`CSCTF{<device_name>_<rule_name>_<download_count>}`.

**Approach / walkthrough**

*1. Unpack and read the lure.* Unzip flat (`unzip -o -j code_red_freight.zip`).
OCR the email screenshot:

```sh
tesseract email_phish.png - 2>/dev/null
```

An external "Jordan Smith" `<ragubarden@proton.me>` shares `Draft_Budget_v2.docx`
and asks Patti to confirm consignment figures before a "Friday sync". The
Review-Document link reads `https://5harepoint.cz/...` — a lookalike with the digit
`5` in place of the `S`. OCR the landing page:

```sh
tesseract devicecode_phish.png - 2>/dev/null
```

There is no fake password form. The page sends her to the *real*
`microsoft.com/devicelogin` and tells her to type the code `CXR7QK2WD`. That is
**device-code phishing**: the attacker starts a device-code sign-in on their own
machine, Microsoft hands them the user code, and whoever enters that code and signs
in (MFA included) grants the attacker's machine a session as themselves. So in the
logs we are hunting a `deviceCode` sign-in that did not come from Patti.

*2. Follow the lure through the mailbox audit.* The UAL's useful content is the JSON
in each row's `AuditData` column. Pull every record mentioning the phisher's
address or the shared filename, skipping background service records (`UserType 5`)
and system rows with no client IP, oldest first:

```
2026-10-29T15:01:27Z  MailItemsAccessed       198.51.100.24       read \Inbox
2026-10-29T15:05:03Z  SensitivityLabelApplied 198.51.100.24       Re: ... -> ragubarden@proton.me
2026-10-29T15:05:49Z  Send                    198.51.100.24       Re: ... -> ragubarden@proton.me
2026-10-29T15:13:59Z  MailItemsAccessed       20.190.139.168      read \Inbox
2026-10-29T15:15:01Z  MailItemsAccessed       20.190.139.168      read \Sent Items
2026-10-29T15:27:39Z  MailItemsAccessed       203.0.113.77        read \Sent Items
2026-10-29T15:28:57Z  New-InboxRule           203.0.113.77:17091  rule M4N1F3ST-L3AK  ForwardTo=ragubarden@proton.me
```

Reading top to bottom: Patti opens the lure from `198.51.100.24` and replies to the
phisher (she engaged). The mailbox is then read through Microsoft Graph from
`20.190.139.168`, a Microsoft-owned address. Finally a new address,
`203.0.113.77`, reads Sent Items and, just over a minute later, creates an inbox
rule `M4N1F3ST-L3AK` forwarding to the phisher. `203.0.113.77` is the suspect; the
next steps cross-check it.

*3. Find the device-code sign-in.* List interactive sign-ins in time order and
summarize the non-interactive ones per source IP. All of Patti's normal activity
comes from `198.51.100.24` (Bucuresti, RO) with no device ID. Four rows from
`203.0.113.77` (Montreal, CA) stand out:

```
15:04:52 203.0.113.77 CA Failure 50199 deviceCodeFlow   Microsoft Authentication Broker -> Device Registration Service
15:04:55 203.0.113.77 CA Success deviceCode deviceCodeFlow Microsoft Authentication Broker -> Device Registration Service
15:23:15 203.0.113.77 CA Success ... Primary refresh token 95caec44 My Apps -> Microsoft Graph
15:23:40 203.0.113.77 CA Success ... Primary refresh token 95caec44 One Outlook Web -> ...
```

The Authentication Broker signs in to the Device Registration Service with protocol
`deviceCode`, three minutes after Patti opened the email. The first attempt fails
with **50199** (the extra "are you trying to sign in?" confirmation); she confirms
(the full row shows MFA method "Mobile app notification" — she approved the push),
and it succeeds. Afterward the same address uses a Primary Refresh Token carrying a
new device ID `95caec44…`. The non-interactive summary agrees: 44 refreshes from
`203.0.113.77` between 15:04:59 and 15:29:51, flagged `deviceCodeFlow`, all tied to
that one device ID.

*4. Identify the attacker's device.* List every `Register device` activity in the
Entra audit log and see where each device ID reappears:

```
2026-10-28T07:12:03Z  Register device from 198.51.100.24  name=R3M0TE-W0RK-PC  id=3f8c1a7b-...
    sign-ins with this device ID: 0 ; unified audit records: 0
2026-10-29T15:05:03Z  Register device from 203.0.113.77   name=D3VC0DE-R3L4Y  id=95caec44-c8af-4786-976c-73bd33d9d143
    sign-ins with this device ID: 42 {'203.0.113.77': 42}
    unified audit records with this device ID: 69
```

Two devices are registered to Patti's account. `R3M0TE-W0RK-PC`, registered 28
October from her own address a day before the phish, never appears in another record
— a decoy (her own work PC). `D3VC0DE-R3L4Y` was registered at 15:05:03 from
`203.0.113.77`, **eight seconds** after the device-code success; its device ID
`95caec44-c8af-4786-976c-73bd33d9d143` is on all 42 attacker sign-ins, the Graph
mail reads from `20.190.139.168`, and the inbox rule. The device the adversary
controls is **`D3VC0DE-R3L4Y`**.

*5. Find the leaking rule.* Print every inbox-rule operation with all parameters.
Again there are two:

```
2026-10-28T07:34:27Z  New-InboxRule from 198.51.100.24  Name=Newsletters  MoveToFolder=Newsletters  StopProcessingRules=False
2026-10-29T15:28:57Z  New-InboxRule from 203.0.113.77:17091  device=95caec44-...  Name=M4N1F3ST-L3AK  ForwardTo=ragubarden@proton.me  StopProcessingRules=True
```

`Newsletters` was created by Patti and only files newsletters into a folder —
housekeeping, the second decoy. `M4N1F3ST-L3AK` was created from the attacker's
address and device, has no conditions (so it fires on every incoming message),
forwards to the phisher's mailbox, and sets `StopProcessingRules=True` so later
rules leave those messages alone. Patti still sees her mail normally while a copy of
every manifest goes out. The leaking rule is **`M4N1F3ST-L3AK`**.

*6. Count the downloads.* Summarize the file operations, then list only the real
downloads:

```
FileAccessed          8  ... (12:46 .. 13:43, Patti's own work)
FileDownloaded        4  2026-10-29T15:20:24 .. 15:21:36
FileModified          4  ...
FileUploaded          2  ...

15:20:24 203.0.113.77 Microsoft Teams  11550 B  .../Documents/Notes.docx
15:20:30 203.0.113.77 Microsoft Teams 291478 B  .../Investor Relations Meeting Presentation.pptx
15:20:49 203.0.113.77 Microsoft Teams 232076 B  .../Research and Development/aerialshot.jpg
15:21:36 203.0.113.77 Microsoft Teams 332341 B  .../benefits/.../Local Resource Guide.docx
```

Only four records are `FileDownloaded`, all from `203.0.113.77` within about 70
seconds (two from Patti's OneDrive, two from SharePoint team sites). The other
`File*` events are Patti's own edits hours earlier, and `MailItemsAccessed` reads
are not downloads — don't count either. The download count is **4**.

*7. Assemble the flag.* Every answer follows from one pivot: the IP behind the
successful device-code sign-in (`203.0.113.77`). From it: the device registered
(`D3VC0DE-R3L4Y`), the forwarding rule created (`M4N1F3ST-L3AK`), and its
`FileDownloaded` count (4). Names are written exactly as they appear in the logs:

```
CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}
```

**Why it works**

The OAuth device authorization grant lets a device with no browser ask Microsoft
for a short user code; whoever enters that code at `microsoft.com/devicelogin` and
signs in authorizes the device that asked. The attacker requested the code as the
Microsoft Authentication Broker, a client allowed to talk to the Device
Registration Service, so Patti's sign-in — MFA push included — handed over tokens to
join the attacker's own machine to the tenant. A joined device then gets a Primary
Refresh Token carrying the MFA claim and the device ID, a persistent foothold that
makes later sign-ins pass as "MFA satisfied by claim in the token." Because every
attacker action carries exactly one IP and one device ID, pivoting on those two
values cleanly separates the intrusion from Patti's own activity and from the
planted decoys (`R3M0TE-W0RK-PC`, the `Newsletters` rule, her earlier file edits).

**Validation / reproduction**

All three values came from the single pivot and were cross-checked across exports:
the device ID `95caec44…` links the registration, the 42 sign-ins, the Graph mail
reads, and the forwarding rule, and the four `FileDownloaded` records all share the
attacker's source IP. Accepted on first submission.

Reproduction, in short: OCR the two lures to recognize device-code phishing; in the
sign-in logs find the `deviceCode`/`Success` row and note its IP
(`203.0.113.77`); in the Entra audit log read the `Register device` from that IP
(`D3VC0DE-R3L4Y`); in the UAL read the `New-InboxRule` with `ForwardTo` from that IP
(`M4N1F3ST-L3AK`); count `FileDownloaded` records from that IP (4); format the flag.

Gotchas: there are deliberate decoys in each export — a second device, a second
inbox rule, and a batch of earlier file events — all from Patti's own Romanian
address; filter on the attacker IP/device, not on event type alone. Count only
`FileDownloaded`; `FileAccessed`/`FileModified`/`FileUploaded` and
`MailItemsAccessed` are not downloads. The display names carry leetspeak and must be
copied verbatim, including the hyphens, into the flag.
