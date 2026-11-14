# User guide

This guide walks through the MiniWireshark window. Everything here also works in Demo Mode (`--demo`), which is the safest way to learn it.

## The Welcome Center

Each start opens the Welcome Center, unless you turn it off in **Settings → General**. It has four choices:

- **Start Monitoring** picks the best network card and begins watching.
- **Try Demo Mode** shows simulated data. Nothing is captured or sent.
- **Quick Start Guide** gives a short tour.
- **Diagnostics** checks the setup when something isn't working.

A coloured health line says whether MiniWireshark is ready, or running degraded (no capture driver, Safe Mode, or the private Python could not start).

Below it, the **Ready?** list checks Python, the capture driver, capture permission, the network card, the data folder, history, signed updates and what leaves this computer. Each line shows *checking…* until it answers, then says whether it is ready, with a fix button where one exists. `--boot-check` prints the same list.

## The tabs

The tabs are in four groups. `Ctrl+1` to `Ctrl+4` jump to a group, `Ctrl+Tab` moves to the next tab, and `Alt+Left` / `Alt+Right` go back and forward through the views you visited.

| Group | Tab | What it shows |
|---|---|---|
| **Overview** | Dashboard | Three questions: *Is anything wrong?*, *Who is using the Internet?* and *What is new?* Every card opens its evidence. Cards for *changes since you last looked* and *Unusual activity* open Story mode and the Security tab. |
| | Happening | A plain-English feed of what is happening right now |
| | Timeline | Events over time: devices joining and leaving, alerts, changes. **Story mode** tells the same in plain sentences, grouped by day, with repeats folded and a line for what is new since you last looked |
| **Your network** | Devices | Everything on your network, with its type, maker, confidence and evidence |
| | Map | A picture of your network: router, devices and the Internet |
| | Health | Wi-Fi, router, DNS, packet loss and Internet checks. The **Calls** card shows the loss and jitter of video and voice calls. **More questions…** opens the guided investigations |
| | Alerts | Security and health findings, each with *why*, *innocent explanations* and *what to do*. Acknowledge, mute or **snooze** them (1 hour, 1 day or until tomorrow) |
| **Internet** | Websites | The names your devices reach, grouped by site, with trackers marked |
| | Connections ¹ | Every flow: who, where, how much, how long |
| | Internet hosts ¹ | Public addresses contacted, with country and network owner when lookups are on |
| **Tools and help** | Packets ¹ | The packet workspace: list, dissection tree, hex view, streams, statistics, expert findings |
| | Security | **Unusual activity** at the top (a worrying and an innocent reading side by side), then the security engine's view: listening services, exposure, cleartext logins. **Your own blocklist…** loads your own list of addresses and names |
| | Sources ¹ | Where data comes from: network cards, files, connectors (Pi-hole, AdGuard) |
| | Help | Glossary, guides, and **About** (version, licence, trademark notice) |

¹ Hidden in the **Beginner view** (**Settings → Appearance**). Nothing is removed. Turn the beginner view off to see them.

Select anything and press `F2` for the **inspector**, a side panel with the full detail. `F1` explains what you are looking at.

## The command palette

Press `Ctrl+K` and type. The palette finds tabs, settings pages and actions, for example:

- *Start watching*, *Stop watching*, *Demo Mode*
- *Open a capture file…*, *Save session…*, *Shareable report…*
- *Why is my Internet slow?*, *What is using my bandwidth?* and the five other investigations
- *What changed recently*, *Review new alerts*
- *Network check-up…*, *Diagnostics*, *Components Center*, *Storage used…*, *Privacy posture…*
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

Under the box, a field filter is said in plain words (`tcp.port == 443 and ip.addr == 10.0.0.5` becomes *TCP traffic on port 443 to or from 10.0.0.5*), and nothing is said when the meaning isn't certain. A filter that doesn't parse shows the reason and never affects capture. Right-click a value and choose **Copy as filter** or **Filter on this conversation** to build one without typing. Saved filters live under **filter presets**. Every field you can use is listed in [Packet filter fields](FIELDS.md).

## Investigations

Each investigation lists the likely causes on a board, with the evidence for and against each one. It never gives a verdict, and it says *Can't tell from here* (with the reason) when the evidence is missing. Investigations only read what was already captured; they send nothing. Open them from the command palette, the Alerts tab's **Investigate** menu, or **Health → More questions…**

| Question | What it looks at |
|---|---|
| **Why is my Internet slow?** | The Wi-Fi signal, the router, DNS, packet loss, heavy programs and VPNs |
| **What is using my bandwidth?** | Devices and, on this computer, programs |
| **Is my DNS working?** | Failed and slow lookups, a change of DNS server, encrypted DNS |
| **Is IPv6 working?** | The router's announcement, the share of IPv6 traffic, IPv6 connections left unanswered while IPv4 works |
| **Why can't this device connect?** | The device's address request (DHCP), its question for the router and the answer, and whether its Internet connections are answered |
| **Is it my Wi-Fi or the Internet?** | Connection times inside your home against connection times to Internet sites, and the Wi-Fi signal when Windows allows it |
| **Why does my call stutter?** | The loss and jitter of the worst recent call, the capture's own drops, and call apps that can't be measured |

## Sessions, files and reports

| Action | What you get |
|---|---|
| **Save session** | Everything collected so far, in a `.mwsession.json` file you can reopen later |
| Autosave and journal | Kept automatically. After a crash, the File menu offers **Restore the interrupted session** and **Open last autosave**. |
| **Open a capture file** | Reads `.pcap` and `.pcapng`, including files from Wireshark or tcpdump |
| **Export** (`Ctrl+E`) | The current table as CSV. Formula injection is blocked. |
| **Shareable report** | One self-contained HTML file with charts, with optional redaction of names and addresses |
| **Network check-up** | One page in plain English (what is ready, what changed, unusual activity, the seven questions, your devices). Names and addresses are hidden unless you turn that off |
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
| Alerts | Each alert kind on or off, and its thresholds. **Where alerts appear**: the live feed, and the opt-in notifications while the window is minimised (title count, taskbar flash, Windows notification) |
| Privacy & Lookups | Kill switch, reference downloads, QUIC names, network owner and country lookups, the self-traffic ledger |
| History | The history database, how long to keep it, the packet ring |
| Performance | Normal or Full Power, cores, memory cap, battery awareness |
| Keyboard Shortcuts | Every shortcut |
| Data & Export | Default folders, where your settings live |
| Updates & Dependencies | The daily check of the official GitHub page, signed updates, the private Python, packages |
| Components | Optional parts and reference lists |
| Diagnostics | Logs, debug bundle, self-test |

## Languages and accessibility

- English, French and Spanish (**Settings → General**).
- Light and dark themes, high contrast, colour-blind palettes and four text sizes.
- Every action can be reached from the keyboard, and the command palette reaches all of them.
