# Changelog

All notable changes to MiniWireshark. Versions follow `MAJOR.MINOR.PATCH`; each release is one `.py` file attached to its [GitHub release](https://github.com/darkckillerc4/MiniWireshark/releases). Checksums are in [docs/VERSIONS.md](docs/VERSIONS.md).

## [Unreleased] — 5.2.3

A reliability release, in progress in [#1](https://github.com/darkckillerc4/MiniWireshark/pull/1).

- Starting and recovering capture no longer freezes the window. Network cards are tried on a helper thread.
- Cards that refuse promiscuous mode now open without it. Before, they failed with "capture filter is not valid".
- Copies of MiniWireshark that share a folder can't damage each other's files any more. This covers update rollback, settings, the crash journal, the history database and Safe Mode.
- Boot receipts now record start-up time separately from the time spent reading the Welcome Center.

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

[Unreleased]: https://github.com/darkckillerc4/MiniWireshark/pull/1
[5.1.2]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.1.2
[5.0.2]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.2
[5.0.1]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.1
[5.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.0
[4.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v4.0.0
[3.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v3.0.0
[2.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v2.0.0
[1.x]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v1.0.0
