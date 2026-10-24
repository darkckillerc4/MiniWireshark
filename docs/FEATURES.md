# Features

What MiniWireshark 5.1.2 can do, grouped by the question it answers. For how to reach each feature, see the [user guide](USER-GUIDE.md).

## What is on my network?

- **Device discovery** on your own subnet only, from ARP, mDNS, SSDP, DHCP and ordinary traffic. Active probes never leave your subnet, and Quiet Mode turns them off on networks you haven't trusted.
- **Device identity:** type (phone, TV, printer, console, speaker, router …), maker from the hardware address, names announced by the device, and a confidence level with the evidence behind it.
- **Identity over time:** a device keeps its identity when its address changes, private (randomised) hardware addresses are recognised, duplicates can be merged, and corrections you make are remembered.
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
| Possible ARP spoofing | Danger |
| Gateway identity changed | Warning |
| DHCP anomaly | Warning |
| Duplicate IP address | Warning |
| Unexpected IPv6 router announcement | Warning |
| Possible scanning pattern | Warning |
| Remote-access service seen | Warning |
| Address on a public blocklist contacted | Warning |
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

Thresholds that compare against "normal" wait for a baseline first, so a fresh start doesn't flood you with alerts.

## Why is it slow?

- **Network Health:** Wi-Fi, router reachability, DNS speed, packet loss and Internet checks, on a schedule you choose.
- **Investigations:** *Why is my Internet slow?* and *What is using my bandwidth?* collect the evidence and say when they can't tell from this computer.

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
- **Filters:** friendly tokens (`site:`, `port:` …) and a Wireshark-style field language (`ip.src == …`). See [Filtering](USER-GUIDE.md#filtering).
- **Capture files:** reads `.pcap` and `.pcapng` with a reader from the standard library.

## Keeping a record

- **Sessions** you can save and reopen, an autosave and a crash-safe journal.
- **History:** an optional SQLite database (WAL, migrations with backups, recovery) for "what changed" across days, with a retention you choose.
- **Packet ring:** an optional, size-capped store of recent packets.
- **Flight recorder** for the minutes before a problem.
- **Exports:** CSV tables, a device inventory and a self-contained HTML report with inline charts, with optional redaction.

## Connected helpers (optional)

- **Pi-hole** and **AdGuard Home** connectors add the DNS answers they saw, as *Reported* evidence.

## Privacy

- No telemetry. Every send goes through `outbound()` and is listed in the self-traffic ledger.
- A **kill switch** blocks everything MiniWireshark itself would send.
- A **privacy posture** report lists what is on and what it sends.
- Redaction replaces real names and addresses with documentation-range pseudonyms in reports and shared screenshots.

## Looking after itself

- Installs its own packages into a private folder, never the system Python. Downloads are checked against pinned SHA-256 fingerprints.
- Optional private Python runtime, so it works even when your Python is unusual.
- Offers to install Npcap on Windows, picks the best network card, and restarts a capture that dies.
- **Repair MiniWireshark:** one click fixes missing components, damaged lists or history, a broken settings file and a stuck capture.
- **Boot receipts** and **Safe Mode** after two failed starts.
- **Signed updates** and data packs (Ed25519), with rollback if an update fails to start.

## Accessibility and languages

- English, French and Spanish.
- Light and dark themes, high contrast, colour-blind palettes, adjustable text size and interface scale, reduced motion.
- Full keyboard control and a command palette (`Ctrl+K`).
- A beginner view that hides the technical tabs until you want them.
