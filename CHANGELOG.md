# Changelog

All notable changes to MiniWireshark. Versions follow `MAJOR.MINOR.PATCH`; each release is one `.py` file attached to its [GitHub release](https://github.com/darkckillerc4/MiniWireshark/releases). Checksums are in [docs/VERSIONS.md](docs/VERSIONS.md).

## [5.3.4] — 2026-11-04

A medium release that makes MiniWireshark safer, easier to start and easier to understand. Every finding of the 5.2.3 security audit is fixed in the code, new screens explain your network to a beginner, and the largest bug campaign so far ran before, during and after the new features.

**Security and privacy**

- **Administrator rights only when needed.** On Linux and macOS, MiniWireshark no longer starts as administrator (root). It asks for your password when capture starts, not at all when the computer already allows capture, and carries on without capture if you say no. The demo and the help never ask.
- **Your files stay yours.** The data folder is closed to other people on the computer, and a folder that belongs to someone else is not used. There is no shared temporary folder any more. Another user can no longer swap the saved copy that speeds up starting, the update rollback copy or the private packages to run their own code.
- **A new install asks first.** It no longer trusts the first network it sees or starts Active Scanning by itself.
- **History does what it says.** "Session only" history is really deleted when you close the window. "Delete ALL history" also removes the backups and the saved packet files.
- **Passwords stay out of everything.** Logins, form contents and the private parts of web addresses are hidden in packet details, saved conversations, CSV files and anything you copy, whatever the port. A new warning, *Login sent without encryption*, says who signed in and where, never the password.
- **A fake router is caught.** When a second device claims to be your router, a DANGER alert appears, even if the fake one answers much faster. An IPv6 announcement from another device that tries to take over your network is flagged.
- **The kill switch stops everything.** Package downloads now go through the same gate, so the kill switch stops them too. Device names are looked up only on your own network. Demo Mode downloads nothing. The download list waits for your answer instead of counting down.
- **Updates now come only from the official GitHub page, checked once a day; you can turn it off.** Fake download sites copy MiniWireshark, so the update check asks only [github.com/darkckillerc4/MiniWireshark](https://github.com/darkckillerc4/MiniWireshark/releases), follows no link off GitHub, and only ever shows that page. It sends one request to `api.github.com` and nothing about you. Another source still works if you type one, but it is called *unofficial* everywhere. Turn the check off in **Settings → Updates & Dependencies**; the kill switch, Safe Mode and working offline stop it too.
- **Connected helpers:** a Pi-hole or AdGuard Home certificate is checked before the password is sent.
- **Windows:** the Npcap installer is no longer refused by its own signature check. **macOS:** an apostrophe in a folder name can't break the administrator prompt, and Wi-Fi is found without Apple's removed `airport` tool.
- **Help → About** shows the version, the MIT licence and the Wireshark trademark notice.

**New features**

- **Ready?** The Welcome Center shows one list: Python, capture driver, capture permission, network card, data folder, history, signed updates and what leaves this computer. Each line says whether it is ready, with a fix button where one exists. `--boot-check` prints the same list, so the two never disagree.
- **Story mode.** The Timeline can tell what changed in plain sentences, day by day, newest first. Repeats are folded ("Phone left and came back 6 times"), and a line marks what is new since you last looked. A Dashboard card says how many changes are waiting. A traffic spike on this computer names the program: "At 14:02 chrome.exe on this computer sent 80.0 MB in one minute".
- **Better device names.** Apple model codes become product names ("MacBook Pro"), and DHCP clues suggest when two entries are probably the same device. When the evidence disagrees, the device card says "But:". On a test set of 65 devices, 64 get the right kind.
- **A baseline that knows day from night.** Each device has a day and a night profile, starts from what is normal for its kind, and is judged after 5 minutes instead of 15. What it learned more than 14 days ago is forgotten. The device card says what it has learned so far. A new alert, *New service used*, appears when a one-job device suddenly reaches a service it never used.
- **Unusual activity** at the top of the Security tab: one card for each unusual thing, with *Could be a problem* and *Could be normal* side by side, what was seen and one next step. A Dashboard card opens it.
- **Snooze an alert** for 1 hour, 1 day or until tomorrow, for one device or for all. A DANGER alert can be snoozed for a day at most, and the Alerts tab says how many alerts are held back.
- **Seven guided questions instead of two.** New: *Is my DNS working?*, *Is IPv6 working?*, *Why can't this device connect?*, *Is it my Wi-Fi or the Internet?* and *Why does my call stutter?* Each lists the likely causes with the evidence for and against, never a verdict, and says "Can't tell from here" when it can't. They are in `Ctrl+K`, the Alerts tab and **Health → More questions…**
- **Calls.** A Calls card under Health shows how many packets video and voice calls lose and how uneven they arrive, read from packet headers only, never the call itself. It says so when a call app can't be measured.
- **Network check-up.** **Export → Network check-up…** writes one page in plain English: what is ready, what changed, unusual activity, the seven questions and your devices. Names and addresses are hidden unless you turn that off. Print it, or save it as PDF from the browser.
- **Notifications while minimised** (off until you turn them on in **Settings → Alerts → Where alerts appear**). The window title counts new DANGER alerts, the taskbar button flashes on Windows, and an optional silent Windows notification appears at most once a minute. It names no device unless you ask, and never shows an address.
- **Your own blocklist.** Load a text file of addresses, ranges or website names from the Security tab (**Your own blocklist…**). It stays on your computer and is never downloaded. Private addresses and entries that are too wide are refused, with the reason.
- **Command line.** `--help` and `--version` work. An unknown switch or a missing value ends with a one-line explanation. `--self-test NAME` runs one test. Starting without a screen no longer forces Safe Mode next time.
- **Clearer words.** A filter you type is said in words under the box. The Beginner view says what happened ("asked the network which device has 192.168.1.1") instead of naming ARP, QUIC or MAC, and calls a MAC a hardware address. Grey text meets the WCAG AA contrast level, so it is easier to read. On Windows the title bar turns dark with the dark theme. Everything new is in French and Spanish.

**Speed and memory**

- **Faster start on Windows.** The window now starts from the saved compiled copy, as on Linux and macOS. On a Windows PC the first start went from about 14 to under 5 seconds, and the window's memory from about 440 to about 220 MB.
- Packets are analysed about a fifth faster (69 instead of 87 microseconds each on the home test network).
- When a live capture can't keep up, deep analysis pauses and packets are only counted, with a plain line saying so. It comes back after 5 calm seconds.
- Memory stays flatter over long runs. In an 80-minute stress replay it grows 5.3 MB an hour after the first hour (it was 7.5), and no freeze is longer than half a second. Past 500 departed devices, the oldest unnamed ones leave memory.
- On Windows the capture driver gets a bigger buffer, so short bursts lose fewer packets.
- *Compare sessions* over 90 days of history takes about 60 ms instead of 4.9 seconds.

**Fixes**

- The Security page no longer repeats its "What is this?" heading: each refresh left one more copy on the Unusual activity line (in every language the page had been shown in).
- Damaged or hostile capture, session and settings files end with a message, never a crash or runaway memory. A session file that would unpack past 256 MB is refused.
- Two copies in one folder: a busy database is no longer taken for a damaged one, session numbers never clash, and each crash journal belongs to one copy.
- Windows 11 24H2 hiding Wi-Fi details while Location is off, and German Windows output, are read correctly. MiniWireshark never turns Location on.
- Blocklists with ranges inside ranges, and IPv6 ranges, now match. *Why is my Internet slow?* no longer blames the network for packets the capture itself missed.
- A sleep, a clock change or daylight-saving time no longer restarts the capture, silences alerts or empties the history. A "#" or accents in the data folder name are fine.
- The two packet decoders now agree on unusual packets (296 disagreements fixed). A million damaged packets in a row raise no error.
- Every tab, dialog and settings page fits from 1024×768 to 1920×1080 in all three languages, both themes and four text sizes (the layout check found 51 kinds of problem; now none).
- Errors that used to vanish are logged or shown. The Dashboard and Health always agree. A device has one name everywhere.
- History on a network folder opens. A program on this computer keeps its name when an old connection ends.
- **Ubuntu 22.04:** the window no longer crashes while it opens. Ubuntu 22.04's font library crashes Tk when it draws a colour emoji; MiniWireshark now leaves colour fonts out there, so emoji show in plain form.
- **Repair's quick self-test** takes about 20 seconds instead of up to 6 minutes. It used to run nearly the whole self-test (344 tests). It now runs 62: the core checks, plus the tests for each part Repair looks at (program components, data folder, history database, capture, settings file, update checks). It no longer checks the program's own code, layouts or translations, because Repair can't change those. `--self-test` still runs everything.
- A Windows console with an old code page no longer stops MiniWireshark with a text error; a character it can't show is printed as "?".
- On a small screen, an Inspector switched on in Settings now makes room for the tabs when the window opens narrow, not only when you make the window narrower.
- A text-size change is quicker: the tables, the rows of buttons and the scrolling pages on tabs you can't see are fitted when you open their tab.
- When your computer's address changes (another Wi-Fi network, a VPN switched on), a connection from the old address is no longer named after a different program that happens to use the same port number now. It is left without a program name.
- A rare crash ("Tcl_AsyncDelete: async handler deleted by the wrong thread") can no longer happen when the last piece of a closed window is let go by a background task.

**Known limits**

- **Changing the text size on Windows is slow.** It takes about 0.4 seconds on the test machine, and the window doesn't answer for about a tenth of a second while it happens (the goal is 0.1 seconds; on Linux it is well under that). The reason: on Windows every part of the window is its own small system window, and when the shared fonts change, all of them (about 700) are measured and drawn again. Making this fast needs a change to how the window shares its fonts, planned for a later release.

**Not in this release**

- Device fingerprints from DHCP request lists ship without built-in rows until real captures of your own devices are available.
- The route-aware network-card pick on Windows only writes to the log for now.

Tested on Python 3.8 and 3.12: 272 self-tests and 62 GUI steps.

## [5.2.3] — 2026-10-24

A reliability release: capture starts without freezing, devices are identified correctly on PCs with VPN and virtual adapters, and copies of different versions can share a folder safely.

- **Capture:** starting and recovering capture runs on a helper thread, so the window never freezes. Cards that refuse promiscuous mode open without it.
- **Network identity:** the LAN comes from the capture card only. VPN, ZeroTier, WSL, Hyper-V and VMware subnets are no longer taken for it. CGNAT addresses are not "local". Pi-hole answers no longer rename devices. The router never moves to a routed address. "This computer" follows an address change.
- **Archive safety:** copies of different versions in one folder no longer damage each other's update rollback, settings, crash journal, history database or Safe Mode count. The Welcome Center says when versions share a data folder.
- **Memory:** bounded while minimised. The previous data is freed after loading a session. Exports and history writes run in the background.
- **Closing and workers:** closing waits only for saves and exports. Analysis workers start together, with a time limit.
- **Windows:**
  - non-English `netsh`/`arp` output is read correctly
  - the Npcap installer alone asks for administrator rights
  - a Store-Python runtime that broke after a Store update is detected
  - saves retry a briefly locked file
  - a 1 ms timer is used only while busy
  - no console windows flash
- **Security:** the macOS keychain secret is no longer passed on the command line.
- **Fixes:** 6 GHz Wi-Fi channels, keychain newline handling, NTP delay, PID reuse in the program list, and a stale exception reference in the certificate dialog. pyflakes is clean.
- **Groundwork** for a future standalone `.exe`: the program can start itself, its workers and its tests without a `.py` file. No exe is shipped.
- Tested on Python 3.8, 3.12 and 3.13: 138 self-tests and 50 GUI steps.

## [5.1.2] — 2026-10-24

The window stays responsive while packets are analysed.

- Analysis gives the window its turn (fair gate, chunked work, a frozen garbage collector during bursts). Slow work moved to background jobs.
- Table kit with sticky sorting. Grouped tab strip, state line and answer cards.
- Find and explain, understanding features and expert features. Accessibility and platform polish.
- **150 MB less memory:** the process no longer keeps the compiler's leftovers. On Linux and macOS it runs from a cached compiled copy.
- **Warm start:** the loading screen does the first-time work, so the window appears finished.
- Release gate (`--release-gate`) with fixed performance budgets (`BENCH_LIMITS`). Opening a session no longer stalls, and the S2 stress-profile freeze is fixed.
- French and Spanish now cover the remaining surfaces.
- Tested on Python 3.8, 3.12 and 3.13 (Tk 9.0): 131 self-tests and 48 GUI steps. The minimum Python version is now checked statically.

## [5.0.2] — 2026-10-21

Layout and loading bug campaign. A crawler opened every tab, view, dialog and settings page in three languages, two themes, four text sizes and screen sizes from 1024×768 to 1920×1080.

- Wrapping tab strip and toolbars, dialogs that fit their content, a dashboard that reflows, charts that measure their labels.
- Compact density on short screens. Tables and tooltips fixed.
- Loading and behaviour fixes found by the same run.

## [5.0.1] — 2026-10-20

- Expert list actions: show these packets, Export CSV and a right-click menu.
- "Copy as filter" and "Filter on this conversation". Follow stream: save as text (always redacted), previous/next, direction.
- `Ctrl+G` go to packet. New time-column formats.
- **Fixes:**
  - The hex view of a redacted stream now stays redacted.
  - CSV formula injection blocked.
  - `pythonw` worker handling fixed.
  - French text fixes.

## [5.0.0] — 2026-10-20

- Starts on the Python that launched it. Packages go into a private per-ABI folder, never the system Python. A managed Python is used only when chosen or needed.
- Boot receipts, crash-loop Safe Mode, `--safe`, `--boot-check`.
- Capture pipeline: coverage buckets, capture epochs, watchdog, and capture faults classified with a fix for each.
- Own packet builder, protocol registry (166 fields), dissectors with byte ranges, IP defragmentation and TCP reassembly.
- **Full Power:** a deep pass in worker processes, with protocol exchanges (DNS, DHCP, TLS, HTTP, RTSP, SSH, SMB, MQTT, NTP, SIP).
- **Email Traffic:** SMTP, IMAP and POP3 analysis with secrets dropped inside the parser.
- Packet workspace: streams, exchanges, statistics, expert findings, Follow stream and a field filter language.
- Command palette (`Ctrl+K`), workspaces, flight recorder, crash-safe session journal, first-run calibration, Storage panel, privacy posture report.

## [4.0.0] — 2026-10-19

- Capture pipeline v2: fast wire decoder (115k frames/s), raw-socket capture, ring buffer, analysis worker, and a stdlib pcap/pcapng reader.
- Evidence levels and observations. A SQLite history store with WAL, migrations and recovery.
- Identity over time: IP binding history, merge and split, undoable corrections, network profiles with Quiet Mode.
- Truth UI: a docked Inspector, vantage meter, coverage report and blind spots.
- Private Python runtime and Runtime Manager, Welcome Center, one-click Repair.
- HTTP/3 (QUIC) site names, LLDP/CDP, TCP health metrics, this computer's Wi-Fi link.
- Outbound gate and self-traffic ledger, programs per connection, ARP cross-check, UPnP audit.
- Pi-hole and AdGuard Home connectors with a credential vault.
- "Why is my Internet slow?" investigations. Colour-blind modes. Map v3. Redaction and shareable reports.
- Ed25519-signed updates and data packs. English, French and Spanish.

## [3.0.0]

- "Your network, explained in plain English": a single-file observability, troubleshooting and defensive-monitoring workstation, with devices, websites, remote hosts, flows, metrics, a security engine, persistence, settings, export and a demo.

## [2.0.0] and [1.x]

- The original "super noob-friendly" single-file packet sniffer. It handles elevation, dependency and driver installs, network-card choice, LAN discovery (ARP, mDNS, SSDP), self-healing capture and a paced plain-English feed.

[5.3.4]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.3.4
[5.2.3]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.2.3
[5.1.2]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.1.2
[5.0.2]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.2
[5.0.1]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.1
[5.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.0
[4.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v4.0.0
[3.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v3.0.0
[2.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v2.0.0
[1.x]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v1.0.0
