# Roadmap after 5.2.3

**Status:** plan only. Nothing here is built yet, and every item still goes through a milestone plan and a courtroom vote before code is written.
**Starts from:** 5.2.3, the reliability release in [pull request #1](https://github.com/darkckillerc4/MiniWireshark/pull/1). This roadmap does not repeat or change any 5.2.3 work.
**Written:** 2026-10-24.

MiniWireshark's promise is *"Your network, explained in plain English."* 5.2.3 makes the app dependable on Windows. The releases below spend that trust on three things, in this order:

1. **Easy to get.** A real Windows download that runs without installing Python (5.3).
2. **Easy to understand.** Better names for devices, clearer answers and a story of what changed (5.4).
3. **Easy to protect.** Calm, explained security insight that stays on the user's PC (5.5).

6.0 then reorganises how the project is built, so it can keep growing while still shipping as one file.

## Contents

- [Rules every release keeps](#rules-every-release-keeps)
- [Version numbers](#version-numbers)
- [At a glance](#at-a-glance)
- [5.2.x: fixes from Windows evidence](#52x-fixes-from-windows-evidence)
- [5.3.0: the Windows download](#530-the-windows-download)
- [5.4.0: understand your network](#540-understand-your-network)
- [5.5.0: calm security insight](#550-calm-security-insight)
- [6.0.0: built from parts, shipped as one file](#600-built-from-parts-shipped-as-one-file)
- [Ideas waiting for a vote](#ideas-waiting-for-a-vote)
- [Dependencies to evaluate](#dependencies-to-evaluate)
- [Decisions for the owner](#decisions-for-the-owner)
- [How each release is run](#how-each-release-is-run)

## Rules every release keeps

These come from the owner's rules and the 5.2.3 plan. No item in this roadmap may break them.

- **One file to download.** Each release is one `miniwireshark.py`. From 5.3 on, a Windows `.exe` is offered next to it, never instead of it.
- **Defensive only.** MiniWireshark watches and explains. It never attacks, scans other people's networks, breaks encryption or hides itself.
- **Private by default.** No telemetry. Nothing leaves the PC except through the existing `outbound()` gate, and every new outbound call is opt-in and listed in the privacy posture report. Secrets are dropped inside the parser, as today.
- **Plain English first.** Every new screen answers a question a beginner would ask. Expert detail sits one click away.
- **No new runtime dependency without an evaluation** (see [Dependencies to evaluate](#dependencies-to-evaluate)). Build tools that never ship inside the `.py` still get a short evaluation.
- **The test count only goes up.** Every bug fix gets a self-test named after it. Benchmarks stay inside `BENCH_LIMITS` on Linux and inside the Windows limits that 5.2.3 sets.
- **Older versions stay safe.** Settings and history changes are additive, so running an archived copy never damages newer data (the 5.2.3 M2 rules).

## Version numbers

The owner's scheme is `X.Z.Y`:

- **X (major):** changes a lot at once. Reserved for 6.0.
- **Z (medium):** a new screen, a GUI change or a major optimisation. 5.3, 5.4 and 5.5.
- **Y (fix):** bug fixes and small optimisations only. 5.2.4, 5.3.1 and so on.

A fix release can ship at any time between medium releases. Release candidates use `-rc.N`, as 5.1.2 did.

## At a glance

| Release | Theme | Headline for users | Size | Depends on |
|---|---|---|---|---|
| **5.2.x** | Fixes from Windows evidence | "It just works on my PC." | Small | 5.2.3 released |
| **5.3.0** | The Windows download | "Double-click to run. No Python needed." | Medium | 5.2.3 M8 seams and experiment |
| **5.4.0** | Understand your network | "I know what every device is, and what changed." | Medium | 5.2.3 M5 network identity |
| **5.5.0** | Calm security insight | "It tells me when something is wrong, and why it might be fine." | Medium | 5.4 device profiles |
| **6.0.0** | Built from parts, shipped as one file | "Faster releases, same single file." | Large | 5.3 build pipeline |

5.4 and 5.5 can swap places if the owner prefers security first. 6.0 can start earlier if the single file becomes too hard to work on (see [6.0.0](#600-built-from-parts-shipped-as-one-file)).

## 5.2.x: fixes from Windows evidence

**Goal:** close whatever the first full Windows run (5.2.3 M0) and the first users find. Nothing new on screen.

- Bugs found by the Windows test run that didn't fit into 5.2.3.
- Windows `BENCH_LIMITS` tightened once there are several runs to compare.
- Translation corrections, once the owner's review sheet exists (held out of 5.2.3 on purpose).
- Any 5.2.3 bug that was only "Evidence A" (synthetic) and fails on real hardware.

**Done when:** the release gate is green on Windows and Linux, and no bug labelled `windows` is older than one release.

## 5.3.0: the Windows download

**Goal:** a Windows user downloads one file and double-clicks it. No Python, no command line.

5.2.3 M8 prepares the code for this (the frozen-build seams) and runs a build experiment without shipping anything. 5.3 turns that experiment into a release.

### For users

- **`MiniWireshark-5.3.0-windows.exe`** on the GitHub release, next to `miniwireshark.py`, each with a `.sha256` file.
- **First-run guide for the `.exe`:** explains what Npcap is, why capture needs it, and what an unsigned app warning from Windows SmartScreen means, in plain words.
- **Faster start for the `.py`:** the 5.2.3 courtroom kept the "self-installed launcher that loads the cached compiled copy" (score 71) on hold until Windows numbers exist. If 5.2.3 M0 measures more than 2 s of compile time per start, 5.3 builds it.
- **Updates that know what they are updating:** the signed-update check learns the difference between the `.py` and the `.exe`. An `.exe` is only replaced by a signed `.exe`, and a `.py` only by a signed `.py`.

### For the project

- **Release builds from a tag.** A workflow builds the `.exe` in a clean Windows runner, runs `--self-test` and `--boot-check` against the built file, and attaches it with its checksum. Releases are then repeatable and never built on a personal PC.
- **Windows in CI.** `--self-test` runs on `windows-latest` for every pull request, next to the existing Linux job. GUI tests stay on Linux plus the owner's PC.
- **Antivirus check.** Each release candidate `.exe` is checked against common antivirus engines before it is published. A false positive blocks the release until it is understood.

### Courtroom questions for 5.3

| Question | Options | Leaning |
|---|---|---|
| Which freezer? | PyInstaller onefile, PyInstaller onedir in a self-extracting zip, Nuitka | Whatever won the 5.2.3 M8 experiment. Nuitka is the fallback if antivirus false positives are high |
| Sign the `.exe`? | Unsigned with checksum, a paid code-signing certificate, a free signing service for open-source projects | Unsigned plus checksum for 5.3.0, signing as an owner decision (cost and identity check) |
| Is the `.exe` "latest"? | `.py` stays the main download, or `.exe` becomes the main download for Windows | `.py` stays main until one fix release passes without `.exe`-only bugs |

**Done when:** a clean Windows PC with no Python runs the `.exe`, captures, and passes `--self-test`. The `.py` still passes everything as before.

## 5.4.0: understand your network

**Goal:** fewer "Unknown device" rows, and an answer to "what changed?".

Builds on the 5.2.3 M5 fixes for PCs with several adapters. Everything here is passive: MiniWireshark listens to what devices already announce and never probes other people's devices.

### For users

- **Better device names.** Read the names devices already broadcast: mDNS/Bonjour, SSDP/UPnP, NetBIOS, LLMNR and DHCP host names and vendor classes. Combine them with the MAC vendor and show the evidence and confidence for each name, as today.
- **Device kinds in plain words.** "Printer", "smart TV", "phone", "game console", "camera" and so on, with a reason ("it announced an IPP printer service").
- **Rename and pin.** The user can name a device, and the name survives across sessions and IP changes.
- **"What changed?" timeline.** A day-by-day story: new devices, devices that left, new websites, a new listening service, a change of router or DNS server. Each entry links to the evidence.
- **Weekly summary.** An optional, local-only report (HTML or text) that answers the dashboard's three questions for the past week.
- **Modern traffic explained.** Recognise QUIC and HTTP/3, encrypted DNS (DNS over HTTPS and DNS over TLS) and common VPN protocols, and say what can't be seen inside them and why.
- **More investigations.** "Why is my Wi-Fi slow?" (signal, channel crowding where the OS reports it), "Is my DNS working?" and "Is IPv6 working?", each ending with "here is what to try" or "we can't tell from here".

### For the project

- A small, local, versioned data table for device kinds (no download at run time; it ships inside the file and updates with releases).
- Self-tests built from synthetic announcements only. No real network data in the repository.

**Done when:** on the demo scenarios, the share of devices with a kind and a name goes up, with no wrong "high confidence" label, and the timeline matches a scripted sequence of changes.

## 5.5.0: calm security insight

**Goal:** tell the user when something is really unusual, explain it, and offer the innocent explanation next to the worrying one. Never cry wolf.

### For users

- **Normal-behaviour baseline per device.** After a learning period, notice when a device talks to new countries, sends far more than usual, or starts a service it never had. The baseline is simple statistics on the PC; nothing is uploaded.
- **Home network checks.** Rogue DHCP server, a second router appearing, DNS answers that change for the same name, an evil-twin Wi-Fi network (same name, different access point, where the OS reports it), and certificates that are expired or self-signed on local devices.
- **Optional threat lists.** The user can turn on well-known public blocklists for malware domains. Off by default, downloaded only through `outbound()`, matched on the PC, with the list's source and date shown on each alert.
- **Incident report.** One click turns an alert into a short, shareable report: what happened, when, the evidence and the suggested next step, redacted by default.
- **Alert tuning.** "Don't warn me about this device again" and "this is normal for my network", with an undo list.

### For the project

- Every new alert type ships with a self-test for the true alarm *and* a self-test for its innocent look-alike.
- The privacy posture report lists every new optional download and when it last ran.

**Done when:** on the demo scenarios, every planted problem raises one alert and the normal-traffic scenarios raise none.

## 6.0.0: built from parts, shipped as one file

**Goal:** keep shipping one file while the source becomes easier to work on.

`miniwireshark.py` is about 66,000 lines and 3 MB in 5.1.2. Only one person (or one AI session) can safely edit it at a time, every change means reading a huge file, and conflicts between pull requests are hard to resolve. The owner asked for a way to stay single-file if the project grows too large. 6.0 is that answer.

### The change

- **Source in parts.** The code moves into a `src/` folder with one file per area (capture, dissectors, analysis, GUI, history, security, i18n, self-tests).
- **One file out.** A small, standard-library-only build script joins the parts into the same single `miniwireshark.py` in a fixed order, and the release workflow checks that the joined file is identical every time it is built from the same commit.
- **Users see no difference.** Same download, same file name, same data folder, same settings.

### Courtroom question for 6.0

| Option | For | Against |
|---|---|---|
| **A. Join into one `.py`** (concatenation with region markers) | Same file users have today; readable; no new tools | Parts must avoid name clashes; needs a check for that |
| **B. Python zip app (`.pyz`)** | Standard library feature; keeps real modules | A new file type for users; some antivirus tools flag zip apps; harder to read |
| **C. Stay one hand-edited file** | No migration | The problems above grow with every release |

Leaning: **A**, with **B** kept as a later option. A is decided only after a dry run proves the joined file is byte-identical to the current file.

### Also in 6.0

- **Python floor.** Python 3.7 and 3.8 are past end of life. 6.0 is the natural point to raise the minimum (owner decision; 5.2.3 kept 3.7).
- **Removal of old paths.** Code kept only for versions or platforms nobody can run any more, with a deprecation note in 5.5.
- **Settings format version 2,** additive and readable by 5.x (older copies keep working).

**Done when:** a release built from `src/` passes the same release gate as 5.5, its output is reproducible, and two pull requests touching different areas merge without conflicts.

## Ideas waiting for a vote

Good ideas that are not scheduled yet. Each needs a courtroom vote and a privacy review before it gets a release.

| Idea | Why it might help | Main concern |
|---|---|---|
| **Small-sensor mode** (headless capture on a Raspberry Pi, viewed from the PC) | See the whole home network from a better vantage point | Must be authenticated and local-network only; a second way to run the app to support |
| **Router log import** (read logs the user exports from their own router) | Covers devices the PC can't see | Many formats; must stay import-only |
| **Plain-English "ask a question" box** over the user's own capture, answered on the PC | Beginners can ask in their own words | Must not send network data anywhere; quality without a large model |
| **Parental and household view** (time online per device) | A common reason people install network tools | Privacy within the household; must not become a spying tool |
| **Linux and macOS packages** (AppImage, `.app`) | Same easy start on other systems | More build and test work; signing on macOS |
| **Export to standard formats** (pcapng with comments, JSON for other tools) | Professionals can continue in other tools | Redaction must apply to every export |

## Dependencies to evaluate

No item below is approved. Each gets the short evaluation from the governance rules (licence, maintenance, size, security record, offline behaviour, what breaks if it disappears).

| Candidate | For | Kind |
|---|---|---|
| PyInstaller | 5.3 `.exe` | Build tool only, never inside the `.py` |
| Nuitka | 5.3 fallback if antivirus false positives are high | Build tool only |
| A code-signing service or certificate | 5.3 or later signed `.exe` | Service, owner decision |
| Public malware-domain blocklists | 5.5 optional threat lists | Data, downloaded only when the user turns it on |
| A device-kind data table (MAC vendor plus service names) | 5.4 device kinds | Data shipped inside the file |

## Decisions for the owner

| # | Decision | Default until answered |
|---|---|---|
| 1 | Order of 5.4 (understanding) and 5.5 (security) | 5.4 first |
| 2 | Pay for code signing for the `.exe` | Ship unsigned with a checksum |
| 3 | Make the `.exe` the main Windows download | `.py` stays the main download |
| 4 | Raise the minimum Python version in 6.0 | Decide during 5.5 |
| 5 | Move to source-in-parts (6.0 option A) | Dry run first, then decide |
| 6 | Any idea from [Ideas waiting for a vote](#ideas-waiting-for-a-vote) | Not scheduled |

## How each release is run

The same way as 5.2.3, plus two lessons about cost:

1. **Plan.** A milestone table with bug or feature IDs, the test that proves each one, the evidence level (A synthetic, B integrated, C owner's Windows PC) and whether the owner is needed.
2. **Courtroom.** Any choice with more than one sensible answer gets an advocate, a prosecutor and a score. Accept at 70 or more, with no safety score below 3 of 5.
3. **One writer.** Only one session edits `miniwireshark.py` at a time (until 6.0 makes parallel work safe).
4. **Small sessions.** One milestone per session, bounded reads of the big file (search, then read only the region), and a handoff note at the end. No session re-reads the whole file or repeats a finished milestone.
5. **Release.** Release gate on Windows and Linux, code and security review, version bump, changelog, `.sha256`, tag, GitHub release with notes.
