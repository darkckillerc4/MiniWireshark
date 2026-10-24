# Roadmap after 5.2.3

**Status:** plan only. Nothing here is built yet, and every item still goes through a milestone plan and a courtroom vote before code is written.
**Starts from:** 5.2.3, the reliability release in [pull request #1](https://github.com/darkckillerc4/MiniWireshark/pull/1). This roadmap does not repeat or change any 5.2.3 work.
**Covers:** the 5.x line only. 6.0 is not planned yet (see [After 5.5](#after-55)).
**Written:** 2026-10-24.

MiniWireshark's promise is *"Your network, explained in plain English."* 5.2.3 makes the app dependable on Windows. The 5.x releases below spend that trust on three things, in this order:

1. **Easy to start.** A faster start-up and a first-run screen, from the same single `.py` file (5.3).
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

The owner's scheme is `X.Z.Y`, meaning big, medium and small:

- **X (big):** changes a lot at once. Reserved for 6.0, which is not planned yet.
- **Z (medium):** a new screen, a GUI change or a major optimisation. Each medium release in this roadmap carries only one or two of these.
- **Y (small):** bug fixes, small optimisations, and small additions to screens that already exist (a new check, a new button, a new protocol label).

Small items are listed under the medium release they follow, as its fix line (5.3.1, 5.3.2 and so on). They ship one or a few at a time, in any order, between medium releases. Release candidates use `-rc.N`, as 5.1.2 did.

Project work that changes no user-facing behaviour (CI, release workflow, test budgets) needs no version number. It lands whenever it is ready.

## At a glance

| Release | Kind | What makes it this size | Depends on |
|---|---|---|---|
| **5.2.x** | Small | Fixes from the first Windows test run | 5.2.3 released |
| **5.3.0** | Medium | Start-up rebuilt for speed, plus a new first-run screen | 5.2.3 Windows numbers (M0) |
| **5.3.x** | Small | Small start-up and update improvements | 5.3.0 |
| **5.4.0** | Medium | Device identification engine, plus a new "What changed?" screen | 5.2.3 M5 network identity |
| **5.4.x** | Small | New device names, protocols and investigations, one at a time | 5.4.0 |
| **5.5.0** | Medium | Per-device behaviour baseline, plus a new "Unusual activity" screen | 5.4.0 device kinds |
| **5.5.x** | Small | New home network checks and alert tools, one at a time | 5.5.0 |

5.4 and 5.5 can swap places if the owner prefers security first.

## 5.2.x: fixes from Windows evidence

**Kind:** small. **Goal:** close whatever the first full Windows run (5.2.3 M0) and the first users find. Nothing new on screen.

- Bugs found by the Windows test run that didn't fit into 5.2.3.
- Windows `BENCH_LIMITS` tightened once there are several runs to compare.
- Translation corrections, once the owner's review sheet exists (held out of 5.2.3 on purpose).
- Any 5.2.3 bug that was only "Evidence A" (synthetic) and fails on real hardware.

**Done when:** the release gate is green on Windows and Linux, and no bug labelled `windows` is older than one release.

## 5.3.0: easy to start

**Kind:** medium. **Goal:** a Windows user opens `miniwireshark.py` and is capturing within a minute, with every question answered on screen. Still one Python file.

### The medium changes

- **Start-up rebuilt for speed (major optimisation).** The 5.2.3 courtroom kept the "self-installed launcher that loads the cached compiled copy" (score 71) on hold until Windows numbers exist. If 5.2.3 M0 measures more than 2 s of compile time per start, 5.3 builds it. The launcher is written by the `.py` itself into the user's data folder, so the download stays one file. If M0 shows start-up is already fast, this item is dropped and 5.3.0 is the first-run screen alone.
- **First-run screen (new screen).** One page that walks a new user through which Python is running, what Npcap is and why capture needs it, which network card was picked and why, and what MiniWireshark will and won't send outside the PC. Each line is green or amber, with a fix button next to each amber line.

**Done when:** on a clean Windows PC with Python installed, a first-time user reaches a working capture without the command line, and start time meets its budget.

### 5.3.x (small)

- The update prompt shows what changed in the new version (from its release notes) before asking.
- A "Run first-run checks again" entry in the command palette and Help menu.
- Start-time fixes found once real users run the new launcher.

### Project work (no version)

- **Windows in CI.** `--self-test` runs on `windows-latest` for every pull request, next to the existing Linux jobs.
- **Release from a tag.** A workflow takes the tagged `miniwireshark.py`, runs `--self-test` and `--boot-check` on it, and attaches it to the GitHub release with its `.sha256` and notes.
- **Start-time budget.** A start-time number joins `BENCH_LIMITS` for each OS, so a slow start fails the release gate.

## 5.4.0: understand your network

**Kind:** medium. **Goal:** fewer "Unknown device" rows, and an answer to "what changed?".

Builds on the 5.2.3 M5 fixes for PCs with several adapters. Everything here is passive: MiniWireshark listens to what devices already announce and never probes other people's devices.

### The medium changes

- **Device identification engine (major change to analysis and the Devices view).** Read the names devices already broadcast (mDNS/Bonjour, SSDP/UPnP, NetBIOS, LLMNR, DHCP host names and vendor classes), combine them with the MAC vendor, and give each device a kind in plain words ("printer", "smart TV", "phone", "camera") with the evidence and confidence for it. The kinds come from a small, versioned table kept inside the `.py`; nothing is downloaded at run time.
- **"What changed?" screen (new screen).** A day-by-day story: new devices, devices that left, new websites, a new listening service, a change of router or DNS server. Each entry links to the evidence.

**Done when:** on the demo scenarios, the share of devices with a kind and a name goes up, with no wrong "high confidence" label, and the timeline matches a scripted sequence of changes.

### 5.4.x (small)

- Rename and pin a device, so its name survives across sessions and IP changes.
- More device kinds and vendor names in the table.
- Recognise QUIC and HTTP/3, encrypted DNS (DNS over HTTPS and DNS over TLS) and common VPN protocols, and say what can't be seen inside them.
- One new investigation per release: "Is my DNS working?", "Is IPv6 working?", "Why is my Wi-Fi slow?" (signal and channel crowding where the OS reports it).
- An optional, local-only weekly summary that answers the dashboard's three questions for the past week.

### Project work (no version)

- Self-tests built from synthetic announcements only. No real network data in the repository.
- Each release notes the file's line count and size, and any region that grows by more than 10% gets a review for dead code.

## 5.5.0: calm security insight

**Kind:** medium. **Goal:** tell the user when something is really unusual, explain it, and offer the innocent explanation next to the worrying one. Never cry wolf.

### The medium changes

- **Per-device behaviour baseline (major change to the security engine).** After a learning period, notice when a device talks to new countries, sends far more than usual, or starts a service it never had. The baseline is simple statistics on the PC; nothing is uploaded. It uses the device kinds from 5.4, so a TV and a laptop are judged differently.
- **"Unusual activity" screen (new screen).** One place that lists what the baseline found, each with the worrying reading, the innocent reading, the evidence and a suggested next step.

**Done when:** on the demo scenarios, every planted problem raises one alert and the normal-traffic scenarios raise none.

### 5.5.x (small)

- One new home network check at a time: rogue DHCP server, a second router appearing, DNS answers that change for the same name, an evil-twin Wi-Fi network (where the OS reports it), expired or self-signed certificates on local devices.
- Alert tuning: "don't warn me about this device again" and "this is normal for my network", with an undo list.
- Incident report: one click turns an alert into a short, redacted report.
- Optional threat lists: well-known public blocklists for malware domains, off by default, downloaded only through `outbound()`, matched on the PC, with the list's source and date on each alert. This one needs a privacy review before it ships.

### Project work (no version)

- Every new alert type ships with a self-test for the true alarm *and* a self-test for its innocent look-alike.
- The privacy posture report lists every new optional download and when it last ran.

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
| Public malware-domain blocklists | 5.5.x optional threat lists | Data, downloaded only when the user turns it on |
| A device-kind data table (MAC vendor plus service names) | 5.4.0 device kinds | Data kept inside the `.py` |

## Decisions for the owner

| # | Decision | Default until answered |
|---|---|---|
| 1 | Order of 5.4 (understanding) and 5.5 (security) | 5.4 first |
| 2 | Turn on the optional threat lists by default (5.5.x) | Off by default |
| 3 | Any idea from [Ideas waiting for a vote](#ideas-waiting-for-a-vote) | Not scheduled |
| 4 | When to open the 6.0 discussion | Not before the owner asks |

## How each release is run

The same way as 5.2.3, plus two lessons about cost:

1. **Plan.** A milestone table with bug or feature IDs, the test that proves each one, the evidence level (A synthetic, B integrated, C owner's Windows PC) and whether the owner is needed.
2. **Courtroom.** Any choice with more than one sensible answer gets an advocate, a prosecutor and a score. Accept at 70 or more, with no safety score below 3 of 5.
3. **One writer.** Only one session edits `miniwireshark.py` at a time.
4. **Small sessions.** One milestone per session, bounded reads of the big file (search, then read only the region), and a handoff note at the end. No session re-reads the whole file or repeats a finished milestone.
5. **Release.** Release gate on Windows and Linux, code and security review, version bump, changelog, `.sha256`, tag, GitHub release with notes.
