# Glossary

The words MiniWireshark and these pages use, in plain English. Terms marked *(app)* are MiniWireshark features; the rest are general network terms.

[A to D](#a-to-d) · [E to L](#e-to-l) · [M to R](#m-to-r) · [S to Z](#s-to-z) · [Evidence levels](#evidence-levels)

## A to D

**Active Mode** *(app)*: The setting that lets MiniWireshark send discovery probes (to find devices and their names) on a network you have marked as yours. Off, it only listens. Every probe is listed in **What MiniWireshark sent**.

**ARP (Address Resolution Protocol)**: How devices on the same network find each other's hardware address from an IP address. It has no protection, so a device can lie in it; see [Possible ARP spoofing](ALERTS.md#possible-arp-spoofing).

**Baseline** *(app)*: What MiniWireshark has learned is normal for each device, with a day and a night profile. Alerts that say "unusual" compare against it, and wait until there is one. What it learned more than 14 days ago is forgotten.

**Beginner view** *(app)*: A simpler window that hides the expert tabs. Nothing is removed; turn it off in **Settings → Appearance**.

**Broadcast**: A message sent to every device on the local network at once. Some is normal; a flood is not. See [Excessive broadcast traffic](ALERTS.md#excessive-broadcast-traffic).

**Capture file (`.pcap`, `.pcapng`)**: A recording of packets, made by MiniWireshark, Wireshark, tcpdump and similar tools. MiniWireshark can open one without capture rights.

**Command palette** *(app)*: The search box that runs any command by name. Open it with `Ctrl+K`.

**DHCP (Dynamic Host Configuration Protocol)**: How a device gets its IP address, router and DNS server when it joins a network. Normally only your router answers.

**DNS (Domain Name System)**: The Internet's phone book: it turns a name like `example.com` into an address. MiniWireshark uses DNS answers to tell you which websites a device uses.

**Demo Mode** *(app)*: Simulated traffic with reserved `.example` names, so you can try every tab. It captures nothing and sends nothing. Start it with `--demo` or **Try Demo Mode**.

## E to L

**Encrypted traffic (TLS, HTTPS, QUIC)**: Traffic whose content can't be read in transit. MiniWireshark can still see *which* site a connection goes to (from DNS and the TLS name), but not what was said.

**Expert findings** *(app)*: Notes on individual packets in the packet workspace, such as retransmissions, bad checksums or error replies, graded chat, note, warning or error. Filter on them with `expert.severity`.

**Full Power** *(app)*: A performance setting that runs every decoder in separate worker processes and reassembles more protocol exchanges. It uses more processor cores.

**Gateway**: Your router, seen from the network: the device that passes traffic to the Internet.

**Investigations** *(app)*: Guided questions such as *Why is my Internet slow?* Each lists the likely causes with the evidence for and against, and never gives a verdict. They only read what was already captured.

**IP address**: A device's address on a network. Addresses like `192.168.x.x`, `10.x.x.x` and `172.16–31.x.x` are private: they only mean something inside your own network.

**Kill switch** *(app)*: Blocks everything MiniWireshark itself would send: update checks, downloads, health checks and probes. Find it in **What MiniWireshark sent** or **Settings → Privacy & Lookups**.

**Limited mode** *(app)*: How MiniWireshark opens when it can't capture, for example without the capture driver or the permission. Capture files, saved sessions and Demo Mode still work.

## M to R

**MAC address**: A network card's hardware address, such as `aa:bb:cc:dd:ee:ff`. Its first half often names the maker. Many phones now use a random one per network, so a MAC alone doesn't prove which device it is.

**Mirror port (SPAN)**: A switch feature that copies other devices' traffic to one port. It is one of the ways to let MiniWireshark see more than this computer's own traffic.

**Npcap**: The packet-capture driver for Windows, from the makers of Nmap. Wireshark uses it too. MiniWireshark offers to install it.

**Outbound gate (`outbound()`)** *(app)*: The one function every network send in MiniWireshark goes through. It records the send in the ledger, and the kill switch closes it. A self-test fails if any send skips it.

**Packet**: One small piece of network traffic. Everything you do online is split into packets.

**Port**: A number that says which service a connection is for: 443 for secure websites, 53 for DNS, 22 for SSH. See [Protocols known by port](FIELDS.md#protocols-known-by-port).

**Pseudonyms** *(app)*: Replacement names and addresses from the documentation ranges, used in shareable reports so nothing real is shown.

**Reference lists** *(app)*: Public lists MiniWireshark downloads about once a month: vendor names for MAC addresses (from Wireshark) and the public suffix list. They contain nothing about you.

## S to Z

**Safe Mode** *(app)*: A start with no automatic capture, no history, no update checks and no downloads. Start it with `--safe`; MiniWireshark also uses it after two crashes in a row.

**Self-traffic ledger (What MiniWireshark sent)** *(app)*: The list of every send MiniWireshark itself made, with its purpose and destination. Open it from the Security tab.

**Session** *(app)*: A saved snapshot of what MiniWireshark has seen, which you can open again later. Sessions stay on your computer.

**Switch**: The box (often inside your router) that connects wired devices. A switch sends each device only its own traffic, which is why one computer can't see everyone's.

**TCP and UDP**: The two main ways to carry data. TCP checks that everything arrives, in order (websites, mail). UDP just sends (DNS, calls, games).

**Vantage meter** *(app)*: The gauge in the bottom-right corner that says how much of other devices' traffic this computer can actually see. On ordinary Wi-Fi it is mostly its own.

**VPN**: A tunnel that encrypts your traffic to a server elsewhere. While it is on, MiniWireshark sees the tunnel, not the sites inside it.

## Evidence levels

Every claim MiniWireshark makes carries one of these levels. The definitions are the ones the app shows.

| Level | Meaning |
|---|---|
| ◉ Observed | Seen directly in a packet (you can open that packet). |
| ◈ Reported | Reported by another system you connected (for example your Pi-hole), not seen by this computer itself. |
| ◎ Correlated | Two separate observations line up, for example a device looked a name up and connected to the answer a moment later. |
| ◌ Inferred | A reasonable guess. It could be wrong; the reasons are listed. |
| ? Unknown | Nothing seen either way. Not seeing something does not mean it didn't happen. |

See also [Architecture: claims carry evidence](ARCHITECTURE.md#claims-carry-evidence).
