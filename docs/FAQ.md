# FAQ and troubleshooting

## General

**Is MiniWireshark a replacement for Wireshark?**
No. Wireshark is the reference tool for protocol analysis. MiniWireshark answers everyday questions in plain English (what is connected, who is using the Internet, is anything wrong) and offers a deep packet view when you want it. It is an independent project, not affiliated with the Wireshark Foundation.

**Why is it one huge file?**
So it is easy to download, check and run, with nothing to install and nothing that can go missing. The file is organised in banner-marked regions with a table of contents. See [Architecture](ARCHITECTURE.md).

**Is it legal to use?**
Use it on networks you own or are allowed to monitor. MiniWireshark is a defensive tool. Its active probes stay on your own subnet.

**Does it cost anything?**
No. It is MIT licensed.

## Privacy

**Does it send my data anywhere?**
No telemetry. Everything MiniWireshark itself sends (downloads, update checks, health checks, discovery probes, optional lookups) goes through one gate and is listed in the self-traffic ledger in **Settings → Privacy & Lookups**. The kill switch there blocks all of it.

**Does it store passwords it sees?**
No. Mail logins, passwords and message bodies are dropped inside the parsers before anything is stored. A canary test checks reports, sessions, CSV files, logs, history and the clipboard for leaks.

**Can I share a report safely?**
Turn on redaction when you export. Real names and addresses are replaced with documentation-range pseudonyms. Saved stream text is always redacted.

## It doesn't capture anything

**Windows: "no capture driver" or limited mode.**
Install [Npcap](https://npcap.com/). MiniWireshark offers to do it on the loading screen. Then restart MiniWireshark.

**Linux: permission denied.**
Run it with `sudo`, or give the capability to the Python you use, for example `sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v python3)")"`. That applies to every script run with that Python.

**macOS: no packets.**
MiniWireshark needs read access to `/dev/bpf*`. Wireshark's *ChmodBPF* helper sets this up, or run it with `sudo`.

**I only see my own computer's traffic.**
That is normal on Wi-Fi and switched networks: each computer mostly sees its own traffic plus broadcasts. The **vantage meter** shows this. To see other devices' traffic you need a mirror (SPAN) port, a hub, monitor-mode Wi-Fi, or a connector such as Pi-hole or AdGuard Home for DNS.

**The wrong network card is chosen.**
Turn off **Settings → Capture → Choose the network card automatically** and pick it yourself. VPN and virtual adapters are a common cause.

## It doesn't start, or it is slow

**It crashed twice and now opens in Safe Mode.**
That is on purpose. Safe Mode turns off auto-capture, history, update checks and automatic downloads so you can reach the window. Open **Diagnostics** to see what failed, or run `python miniwireshark.py --boot-check`.

**The first start is slow.**
The first start installs packages and compiles the file. From 5.1.2 the compiled copy is cached, so later starts are faster.

**Something is broken and I don't know what.**
Use **Settings → General → Repair MiniWireshark**. It checks components, reference lists, the history database, the settings file and the capture engine, then says what it fixed.

**The window is slow on a busy network.**
Try **Settings → Performance**: lower the memory cap, or set **When it falls behind** to Strict. Full Power uses more processor cores for the deep pass.

## Reporting a problem

Open an [issue](https://github.com/darkckillerc4/MiniWireshark/issues/new/choose) and attach a **debug bundle** from the Diagnostics window. It masks addresses and secrets. For security problems, follow [SECURITY.md](../SECURITY.md) instead of opening a public issue.

## Versions

**Where are the older versions?**
On the [releases page](https://github.com/darkckillerc4/MiniWireshark/releases). Each release has the `.py` file and a `.sha256` file. The [version index](VERSIONS.md) lists every checksum.

**Can two versions share a folder?**
Yes, but each one keeps its data in `miniwireshark_data/` next to the script. To keep them fully apart, put each in its own folder. From 5.2.3, copies sharing a folder can no longer damage each other's files.
