# User guide

This guide walks through the MiniWireshark window. Everything here also works in Demo Mode (`--demo`), which is the safest way to learn it.

## The Welcome Center

Each start opens the Welcome Center, unless you turn it off in **Settings → General**. It has four choices:

- **Start Monitoring** picks the best network card and begins watching.
- **Demo Mode** shows simulated data. Nothing is captured or sent.
- **Quick Start Guide** gives a short tour.
- **Diagnostics** checks the setup when something isn't working.

A coloured health line says whether MiniWireshark is ready, or running degraded (no capture driver, Safe Mode, or the private Python could not start).

## The tabs

The tabs are in four groups. `Ctrl+1` to `Ctrl+4` jump to a group, `Ctrl+Tab` moves to the next tab, and `Alt+Left` / `Alt+Right` go back and forward through the views you visited.

| Group | Tab | What it shows |
|---|---|---|
| **Overview** | Dashboard | Three questions: *Is anything wrong?*, *Who is using the Internet?* and *What is new?* Every card opens its evidence. |
| | Happening | A plain-English feed of what is happening right now |
| | Timeline | Events over time: devices joining and leaving, alerts, changes |
| **Your network** | Devices | Everything on your network, with its type, maker, confidence and evidence |
| | Map | A picture of your network: router, devices and the Internet |
| | Health | Wi-Fi, router, DNS, packet loss and Internet checks |
| | Alerts | Security and health findings, each with *why*, *innocent explanations* and *what to do* |
| **Internet** | Websites | The names your devices reach, grouped by site, with trackers marked |
| | Connections ¹ | Every flow: who, where, how much, how long |
| | Internet hosts ¹ | Public addresses contacted, with country and network owner when lookups are on |
| **Tools and help** | Packets ¹ | The packet workspace: list, dissection tree, hex view, streams, statistics, expert findings |
| | Security | The security engine's view: listening services, exposure, cleartext logins |
| | Sources ¹ | Where data comes from: network cards, files, connectors (Pi-hole, AdGuard) |
| | Help | Glossary, guides and version information |

¹ Hidden in the **Beginner view** (**Settings → Appearance**). Nothing is removed. Turn the beginner view off to see them.

Select anything and press `F2` for the **inspector**, a side panel with the full detail. `F1` explains what you are looking at.

## The command palette

Press `Ctrl+K` and type. The palette finds tabs, settings pages and actions, for example:

- *Start watching*, *Stop watching*, *Demo mode*
- *Open a capture file…*, *Save session…*, *Shareable report…*
- *Why is my Internet slow?*, *What is using my bandwidth?*
- *What changed recently*, *Review new alerts*
- *Diagnostics*, *Components Center*, *Storage used…*, *Privacy posture…*
- *Go to packet…*

## Filtering

Each table has a search box. Simple words search everywhere. Friendly tokens narrow it down:

| Token | Example | Matches |
|---|---|---|
| `proto:` | `proto:dns` | A protocol |
| `ip:` `src:` `dst:` | `src:192.168.1.20` | An address, either way or one direction |
| `port:` `sport:` `dport:` | `port:443` | A port |
| `site:` `host:` `domain:` | `site:example.com` | A website name |
| `device:` | `device:@mine-phone` | A device, by name or alias |
| `dir:` | `dir:out` | Direction |
| `mac:` | `mac:aa:bb:cc` | A hardware address |
| `stream:` | `stream:12` | One reassembled stream |
| `sev:` | `sev:warning` | Severity (packets with expert findings) |
| `len>N` `len<N` | `len>1000` | Packet size |
| `marked` | `marked` | Packets you marked |

Terms are combined with *and*. Use `or` between alternatives, and `-term` or `not term` to exclude.

```
site:example.com or site:example.org -proto:dns
```

In the **Packets** tab you can also use the **field filter language**, in the style of Wireshark display filters:

```
ip.src == 192.168.1.20 && tcp.port == 443
dns.qry.name contains "example"
tls && !(ip.dst == 10.0.0.1)
```

A filter that doesn't parse shows the reason and never affects capture. Right-click a value and choose **Copy as filter** or **Filter on this conversation** to build one without typing. Saved filters live under **filter presets**.

## Investigations

**Why is my Internet slow?** checks the Wi-Fi signal, the router, DNS, packet loss, heavy programs and VPNs, and says what it found. If it can't tell from this computer, it says so instead of guessing.

**What is using my bandwidth?** ranks devices and, on this computer, programs.

## Sessions, files and reports

| Action | What you get |
|---|---|
| **Save session** | Everything collected so far, in a `.mwsession.json` file you can reopen later |
| Autosave and journal | Kept automatically. After a crash, the File menu offers **Restore the interrupted session** and **Open last autosave**. |
| **Open a capture file** | Reads `.pcap` and `.pcapng`, including files from Wireshark or tcpdump |
| **Export** (`Ctrl+E`) | The current table as CSV. Formula injection is blocked. |
| **Shareable report** | One self-contained HTML file with charts, with optional redaction of names and addresses |
| **Follow stream → Save** | A conversation as text, always redacted |

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl+R` | Start watching |
| `Ctrl+.` | Stop watching |
| `Ctrl+L` | Clear collected data (asks first) |
| `Ctrl+E` | Export |
| `Ctrl+F` | Find |
| `Ctrl+Z` | Undo |
| `Ctrl+K` | Command palette |
| `Ctrl+G` | Go to packet |
| `Ctrl+1` … `Ctrl+4` | Tab groups |
| `Ctrl+Tab` / `Ctrl+Shift+Tab` | Next / previous tab |
| `Alt+Left` / `Alt+Right` | Back / forward |
| `F1` | Explain this |
| `F2` | Show or hide the inspector |

Every shortcut can be changed in **Settings → Keyboard Shortcuts**.

## Settings

The Settings window is grouped by what you are trying to do. Each option has a one-line explanation under it.

| Page | Covers |
|---|---|
| General | Startup, explanations, language, and **Repair MiniWireshark** (one click fixes the usual problems) |
| Appearance | Theme, beginner view, high contrast, text size, reduced motion |
| Accessibility | Colour-blind palettes, interface scale |
| Capture | Network card choice, promiscuous mode, how much to keep |
| Devices & Identity | When a device counts as idle, inactive or gone; merging duplicates |
| Websites & DNS | Grouping subdomains, tracker marks, encrypted DNS, slow-DNS threshold |
| Connections | How many to keep and show |
| Network Health | Active checks, how often, and against which target |
| Alerts | Each alert kind on or off, and its thresholds |
| Privacy & Lookups | Kill switch, reference downloads, QUIC names, network owner and country lookups, the self-traffic ledger |
| History | The history database, how long to keep it, the packet ring |
| Performance | Normal or Full Power, cores, memory cap, battery awareness |
| Keyboard Shortcuts | Every shortcut |
| Data & Export | Default folders, where your settings live |
| Updates & Dependencies | Signed updates, the private Python, packages |
| Components | Optional parts and reference lists |
| Diagnostics | Logs, debug bundle, self-test |

## Languages and accessibility

- English, French and Spanish (**Settings → General**).
- Light and dark themes, high contrast, colour-blind palettes and four text sizes.
- Every action can be reached from the keyboard, and the command palette reaches all of them.
