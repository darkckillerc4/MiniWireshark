# Roadmap after 5.2.3

**Status:** plan only. Nothing here is built yet, and every item still goes through a milestone plan and a courtroom vote before code is written.
**Starts from:** 5.2.3, the reliability release in [pull request #1](https://github.com/darkckillerc4/MiniWireshark/pull/1). This roadmap does not repeat or change any 5.2.3 work.
**Covers:** the 5.x line only. 6.0 is not planned yet (see [After 5.5](#after-55)).
**Written:** 2026-10-24.

MiniWireshark's promise is *"Your network, explained in plain English."* 5.2.3 makes the app dependable on Windows. The 5.x releases below spend that trust on three things, in this order:

1. **Easy to start.** A faster, friendlier first run from the same single `.py` file (5.3).
2. **Easy to understand.** Better names for devices, clearer answers and a story of what changed (5.4).
3. **Easy to protect.** Calm, explained security insight that stays on the user's PC (5.5).

## Contents

- [Rules every release keeps](#rules-every-release-keeps)
- [Version numbers](#version-numbers)
- [At a glance](#at-a-glance)
- [5.2.x: fixes from Windows evidence](#52x-fixes-from-windows-evidence)
- [5.3.0: easy to start](#530-easy-to-start)
- [5.4.0: understand your network](#540-understand-your-network)
- [5.5.0: calm security insight](#550-calm-security-insight)
- [After 5.5](#after-55)
- [Ideas waiting for a vote](#ideas-waiting-for-a-vote)
- [Dependencies to evaluate](#dependencies-to-evaluate)
- [Decisions for the owner](#decisions-for-the-owner)
- [How each release is run](#how-each-release-is-run)

## Rules every release keeps

These come from the owner's rules and the 5.2.3 plan. No item in this roadmap may break them.

- **One Python file.** Every 5.x release is one `miniwireshark.py` and nothing else. No `.exe`, installer or extra file is shipped before 6.0.
- **Defensive only.** MiniWireshark watches and explains. It never attacks, scans other people's networks, breaks encryption or hides itself.
- **Private by default.** No telemetry. Nothing leaves the PC except through the existing `outbound()` gate, and every new outbound call is opt-in and listed in the privacy posture report. Secrets are dropped inside the parser, as today.
- **Plain English first.** Every new screen answers a question a beginner would ask. Expert detail sits one click away.
- **No new dependency without an evaluation** (see [Dependencies to evaluate](#dependencies-to-evaluate)).
- **The test count only goes up.** Every bug fix gets a self-test named after it. Benchmarks stay inside `BENCH_LIMITS` on Linux and inside the Windows limits that 5.2.3 sets.
- **Older versions stay safe.** Settings and history changes are additive, so running an archived copy never damages newer data (the 5.2.3 M2 rules).
- **The `.exe` seams stay working.** 5.2.3 M8 prepares the code for a frozen build. 5.x keeps those seams passing their self-tests, so the option stays open, but nothing is built or shipped.

## Version numbers

The owner's scheme is `X.Z.Y`:

- **X (major):** changes a lot at once. Reserved for 6.0, which is not planned yet.
- **Z (medium):** a new screen, a GUI change or a major optimisation. 5.3, 5.4 and 5.5.
- **Y (fix):** bug fixes and small optimisations only. 5.2.4, 5.3.1 and so on.

A fix release can ship at any time between medium releases. Release candidates use `-rc.N`, as 5.1.2 did.

## At a glance

| Release | Theme | Headline for users | Size | Depends on |
|---|---|---|---|---|
| **5.2.x** | Fixes from Windows evidence | "It just works on my PC." | Small | 5.2.3 released |
| **5.3.0** | Easy to start | "It opens fast and tells me what it needs." | Medium | 5.2.3 Windows numbers (M0) |
| **5.4.0** | Understand your network | "I know what every device is, and what changed." | Medium | 5.2.3 M5 network identity |
| **5.5.0** | Calm security insight | "It tells me when something is wrong, and why it might be fine." | Medium | 5.4 device profiles |

5.4 and 5.5 can swap places if the owner prefers security first.

## 5.2.x: fixes from Windows evidence

**Goal:** close whatever the first full Windows run (5.2.3 M0) and the first users find. Nothing new on screen.

- Bugs found by the Windows test run that didn't fit into 5.2.3.
- Windows `BENCH_LIMITS` tightened once there are several runs to compare.
- Translation corrections, once the owner's review sheet exists (held out of 5.2.3 on purpose).
- Any 5.2.3 bug that was only "Evidence A" (synthetic) and fails on real hardware.

**Done when:** the release gate is green on Windows and Linux, and no bug labelled `windows` is older than one release.

## 5.3.0: easy to start

**Goal:** a Windows user downloads `miniwireshark.py`, opens it, and is capturing within a minute, with every question answered on screen. Still one Python file.

### For users

- **Faster start.** The 5.2.3 courtroom kept the "self-installed launcher that loads the cached compiled copy" (score 71) on hold until Windows numbers exist. If 5.2.3 M0 measures more than 2 s of compile time per start, 5.3 builds it. The launcher is written by the `.py` itself into the user's data folder, so the download stays one file.
- **First-run guide.** A short, plain-words walk-through: which Python is running, what Npcap is and why capture needs it, which network card was picked and why, and what MiniWireshark will and won't send outside the PC.
- **"Start here" checks.** One screen that says, in green or amber, whether capture, the history database and updates are ready, with a fix button next to each amber line.
- **Clearer update prompts.** The signed-update check explains what changed in the new version (from its release notes) before asking.

### For the project

- **Windows in CI.** `--self-test` runs on `windows-latest` for every pull request, next to the existing Linux jobs. GUI tests stay on Linux plus the owner's PC.
- **Release from a tag.** A workflow takes the tagged `miniwireshark.py`, runs `--self-test` and `--boot-check` on it, and attaches it to the GitHub release with its `.sha256` and notes. The same file is never rebuilt or changed after testing.
- **Start-time budget.** A start-time number joins `BENCH_LIMITS` for each OS, so a slow start fails the release gate.

**Done when:** on a clean Windows PC with Python installed, a first-time user reaches a working capture without the command line, and start time meets its new budget.

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

- A small, versioned data table for device kinds, kept inside the `.py` (no download at run time; it updates with releases).
- Self-tests built from synthetic announcements only. No real network data in the repository.
- File size watched: each release notes its line count and size, and any region that grows by more than 10% gets a review for dead code.

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

## After 5.5

6.0 will be a large change and is **not planned here**, by the owner's choice. Until the owner opens it, the 5.x line continues with fix releases (5.5.1, 5.5.2 and so on) or another medium release taken from [Ideas waiting for a vote](#ideas-waiting-for-a-vote).

Topics already known to belong to a future 6.0 discussion, recorded only so they aren't lost: a Windows `.exe`, how to keep one file as the code grows, and the minimum Python version. None of them is worked on in 5.x.

## Ideas waiting for a vote

Good ideas that are not scheduled yet. Each needs a courtroom vote and a privacy review before it gets a release, and each must fit in the single `.py`.

| Idea | Why it might help | Main concern |
|---|---|---|
| **Router log import** (read logs the user exports from their own router) | Covers devices the PC can't see | Many formats; must stay import-only |
| **Plain-English "ask a question" box** over the user's own capture, answered on the PC | Beginners can ask in their own words | Must not send network data anywhere; quality without a large model |
| **Household view** (time online per device) | A common reason people install network tools | Privacy within the household; must not become a spying tool |
| **Export to standard formats** (pcapng with comments, JSON for other tools) | Professionals can continue in other tools | Redaction must apply to every export |
| **Small-sensor mode** (headless capture on a Raspberry Pi, viewed from the PC) | See the whole home network from a better vantage point | Must be authenticated and local-network only; a second way to run the app to support |

## Dependencies to evaluate

No item below is approved. Each gets the short evaluation from the governance rules (licence, maintenance, size, security record, offline behaviour, what breaks if it disappears).

| Candidate | For | Kind |
|---|---|---|
| Public malware-domain blocklists | 5.5 optional threat lists | Data, downloaded only when the user turns it on |
| A device-kind data table (MAC vendor plus service names) | 5.4 device kinds | Data kept inside the `.py` |

## Decisions for the owner

| # | Decision | Default until answered |
|---|---|---|
| 1 | Order of 5.4 (understanding) and 5.5 (security) | 5.4 first |
| 2 | Turn on the optional threat lists by default in 5.5 | Off by default |
| 3 | Any idea from [Ideas waiting for a vote](#ideas-waiting-for-a-vote) | Not scheduled |
| 4 | When to open the 6.0 discussion | Not before the owner asks |

## How each release is run

The same way as 5.2.3, plus two lessons about cost:

1. **Plan.** A milestone table with bug or feature IDs, the test that proves each one, the evidence level (A synthetic, B integrated, C owner's Windows PC) and whether the owner is needed.
2. **Courtroom.** Any choice with more than one sensible answer gets an advocate, a prosecutor and a score. Accept at 70 or more, with no safety score below 3 of 5.
3. **One writer.** Only one session edits `miniwireshark.py` at a time.
4. **Small sessions.** One milestone per session, bounded reads of the big file (search, then read only the region), and a handoff note at the end. No session re-reads the whole file or repeats a finished milestone.
5. **Release.** Release gate on Windows and Linux, code and security review, version bump, changelog, `.sha256`, tag, GitHub release with notes.
