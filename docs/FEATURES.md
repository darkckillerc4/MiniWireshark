# Features

What MiniWireshark 5.3.4 can do, grouped by the question it answers. For how to reach each feature, see the [user guide](USER-GUIDE.md).

## Am I ready?

- **Ready?** in the Welcome Center: one list for Python, the capture driver, capture permission, the network card, the data folder, history, signed updates and what leaves this computer. Each line says whether it is ready, with a fix button where one exists. `--boot-check` prints the same list.

## What is on my network?

- **Device discovery** on your own subnet only, from ARP, mDNS, SSDP, DHCP and ordinary traffic. Active probes never leave your subnet, and Quiet Mode turns them off on networks you haven't trusted.
- **Device identity:** type (phone, TV, printer, console, speaker, router …), maker from the hardware address, names announced by the device, and a confidence level with the evidence behind it. Every rule is one row of a signature table. Apple model codes are read as product names ("MacBook Pro"), and a "But:" line shows evidence that disagrees. Accuracy is measured on a synthetic test set of 65 devices (64 right).
- **Identity over time:** a device keeps its identity when its address changes, private (randomised) hardware addresses are recognised, DHCP clues suggest when two entries are probably the same device, duplicates can be merged (and split again), and corrections you make are remembered.
- **Several networks:** home, office and other networks you join are kept apart.
- **Map** of the router, devices and the Internet.

## Who is using the Internet, and for what?

- **Websites** from DNS, TLS SNI, HTTP Host and QUIC Initial packets, grouped by site, with known trackers marked.
- **Remote hosts:** public addresses, with network owner and country when you turn those lookups on.
- **Connections:** every flow, with bytes, packets, duration and the device on each end.
- **This computer:** which program owns each connection.
- **Encrypted DNS** (DoH, DoT) is detected and named, so missing lookups aren't mistaken for silence.
- **Bandwidth:** which devices, and on this computer which programs, use the most.

## Is anything wrong?

The security and health engine raises these alerts. Each one says *why it was flagged*, *what innocent explanations exist* and *what to check*. Each kind can be turned off, and its threshold changed, in **Settings → Alerts**.

| Alert | Severity |
|---|---|
| Possible ARP spoofing (including a second device claiming to be the router) | Danger |
| Gateway identity changed | Warning |
| DHCP anomaly | Warning |
| Duplicate IP address | Warning |
| Unexpected IPv6 router announcement | Warning |
| Possible scanning pattern | Warning |
| Remote-access service seen | Warning |
| Address on a public blocklist, or on your own blocklist, contacted | Warning |
| Login sent without encryption (Full Power; the password is never kept) | Warning, or Info inside your network |
| New service used (a device reaches a service it never used) | Warning |
| Unknown / unconfirmed device | Warning |
| Unusually chatty device | Warning |
| Rapid reconnect/disconnect | Warning |
| Unusually many destinations | Warning |
| Unusually many new connections | Warning |
| Unusual upload spike | Warning |
| Repeated connection resets | Warning |
| Excessive broadcast traffic | Warning |
| DNS server changed | Warning |
| Many DNS failures | Warning |
| Slow DNS | Warning |
| New device | Info |
| New advertised service | Info |
| New country contacted | Info |
| Unencrypted protocol in use | Info |
| Several DNS servers in use | Info |
| Unusual download spike | Info |

Thresholds that compare against "normal" wait for a baseline first, so a fresh start doesn't flood you with alerts. The baseline keeps a day and a night profile for each device and starts from what is normal for its kind, so a device is judged after 5 minutes instead of 15. What it learned more than 14 days ago is forgotten, and the device card says what it has learned.

- **Unusual activity** at the top of the Security tab: one card per unusual finding, with *Could be a problem* and *Could be normal* side by side, what was seen, the evidence and one next step. A Dashboard card opens it.
- **Snooze** an alert type for 1 hour, 1 day or until tomorrow, for one device or for all. A DANGER snooze lasts a day at most, and the Alerts tab counts what mute and snooze hold back.
- **Your own blocklist:** a text file of addresses, CIDR ranges, IPv6 ranges, domain names or hosts-file lines, read only when you pick or reload it. Private, special-use and too-wide entries are refused with a reason.
- **Notifications while minimised** (off by default): a count in the window title, a flashing taskbar button on Windows (the Dock on macOS) and an optional silent Windows notification, at most one a minute.

## Why is it slow?

- **Network Health:** Wi-Fi, router reachability, DNS speed, packet loss and Internet checks, on a schedule you choose.
- **Seven investigations:** *Why is my Internet slow?*, *What is using my bandwidth?*, *Is my DNS working?*, *Is IPv6 working?*, *Why can't this device connect?*, *Is it my Wi-Fi or the Internet?* and *Why does my call stutter?* Each ranks the likely causes with the evidence for and against, never gives a verdict, and says "Can't tell from here" when the evidence is missing. All of them are passive: they send nothing.
- **Call quality:** the Calls card under Health shows packet loss and jitter of video and voice calls (RTP after a STUN exchange), read from packet headers only, never the media. It says when a call app can't be measured.

## What can't it see?

- **Vantage meter:** what share of other devices' traffic this computer can actually see. On ordinary Wi-Fi it is mostly your own.
- **Blind spots and the coverage report** say what is out of view, so "not seen" is never presented as "didn't happen".
- **Evidence levels** on every claim: Observed, Reported, Correlated, Inferred or Unknown. See [Architecture](ARCHITECTURE.md#claims-carry-evidence).

## Deep analysis

- **Packet workspace:** packet list, dissection tree with byte ranges, hex view, and a registry of 166 fields.
- **Reassembly:** IP defragmentation and TCP stream reassembly.
- **Full Power mode:** every dissector runs in worker processes, and adds protocol exchanges for DNS, DHCP, TLS, HTTP, RTSP, SSH, SMB, MQTT, NTP and SIP.
- **Mail traffic:** SMTP, IMAP and POP3 analysis. Logins, passwords and message bodies are dropped inside the parser.
- **Follow stream**, with previous/next, direction and redacted save.
- **Statistics:** conversations, protocol hierarchy, I/O graphs and expert findings with "show these packets".
- **Filters:** friendly tokens (`site:`, `port:` …) and a Wireshark-style field language (`ip.src == …`), said in plain words under the box. See [Filtering](USER-GUIDE.md#filtering).
- **Capture files:** reads `.pcap` and `.pcapng` with a reader from the standard library.

## Keeping a record

- **Sessions** you can save and reopen, an autosave and a crash-safe journal.
- **History:** an optional SQLite database (WAL, migrations with backups, recovery) for "what changed" across days, with a retention you choose.
- **Packet ring:** an optional, size-capped store of recent packets.
- **Flight recorder** for the minutes before a problem.
- **Story mode** in the Timeline: what changed, in plain sentences, grouped by day, with repeats folded and a line for what is new since you last looked. A traffic spike on this computer names the program, in live capture.
- **Exports:** CSV tables, a device inventory and a self-contained HTML report with inline charts, with optional redaction.
- **Network check-up:** a one-page, plain-English HTML summary (readiness, what changed, unusual activity, the seven questions, devices) to print or send. Names and addresses are hidden by default.

## Connected helpers (optional)

- **Pi-hole** and **AdGuard Home** connectors add the DNS answers they saw, as *Reported* evidence.

## Privacy

- No telemetry. Every send goes through `outbound()` and is listed in the self-traffic ledger.
- A **kill switch** blocks everything MiniWireshark itself would send, including package downloads.
- A **privacy posture** report lists what is on and what it sends.
- Redaction replaces real names and addresses with documentation-range pseudonyms in reports and exports.

## Looking after itself

- Installs its own packages into a private folder, never the system Python. The packages it needs to start, and the private runtime's packages, are checked against pinned SHA-256 fingerprints. Optional components (psutil, cryptography) come from PyPI over verified HTTPS through pip, without a pin.
- Optional private Python runtime, so it works even when your Python is unusual.
- Offers to install Npcap on Windows, picks the best network card, and restarts a capture that dies. When a live capture can't keep up, deep analysis pauses and packets are only counted, with a plain line saying so.
- **Repair MiniWireshark:** one click fixes missing components, damaged lists or history, a broken settings file and a stuck capture.
- **Boot receipts** and **Safe Mode** after two failed starts.
- **Signed updates** and data packs (Ed25519), with rollback if an update fails to start.

## Accessibility and languages

- English, French and Spanish.
- Light and dark themes, high contrast, colour-blind palettes, adjustable text size and interface scale, reduced motion.
- Full keyboard control and a command palette (`Ctrl+K`).
- A beginner view that hides the technical tabs until you want them, and says what happened instead of naming ARP, QUIC or MAC.
- Grey text meets the WCAG AA contrast level in every palette. On Windows the title bar follows the dark theme.
