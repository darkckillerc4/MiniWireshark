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
No telemetry. Everything MiniWireshark itself sends (downloads, update checks, health checks, discovery probes, optional lookups) goes through one gate and is listed in the self-traffic ledger. Open it from **Security → What MiniWireshark sent…** or **Settings → Privacy & Lookups**. The kill switch in either place blocks all of it.

**Does it contact anything by itself?**
Once a day it asks the official GitHub page for the latest version number: one request to `api.github.com`, with nothing about you. It only ever points you to <https://github.com/darkckillerc4/MiniWireshark/releases>, because other download sites may be fake. Turn it off in **Settings → Updates & Dependencies**; the kill switch and Safe Mode stop it too.

**Does it store passwords it sees?**
No. Mail logins, passwords and message bodies are dropped inside the parsers before anything is stored. A canary test checks reports, sessions, CSV files, logs, history and the clipboard for leaks. When a login is sent without encryption, the *Login sent without encryption* warning says who and where, never the password.

**Can I share a report safely?**
Use **Export → Network check-up…**: names and addresses are hidden by default. For the full report, turn on redaction when you export: real names and addresses are replaced with documentation-range pseudonyms. Saved stream text is always redacted.

## If you're skeptical

Good. A program that watches your network should earn your trust. [Can I trust MiniWireshark?](TRUST.md) lists every claim with a way to check it. The short answers:

**How do I try it without trusting it with my network?**
Start it in Demo Mode (`python miniwireshark.py --demo`, or **Try Demo Mode** on the welcome screen). It shows simulated traffic with reserved `.example` names, captures nothing and sends nothing. You can also open a capture file you already have, which needs no capture rights at all.

**Can I read the code before I run it?**
Yes. It is one plain Python file with no compiled parts. The docstring at the top lists every region in order, and every network send goes through one function, `outbound()`. A self-test fails if any network call in the file skips it.

**How do I know the file wasn't changed?**
Download it only from the [releases page](https://github.com/darkckillerc4/MiniWireshark/releases) and compare its SHA-256 with the `.sha256` file next to it. [TRUST.md](TRUST.md#1-check-the-download) has the command for each system.

**Does it update itself behind my back?**
No. It checks GitHub once a day for the latest version number and tells you. It installs an update only when the update is signed with a release key built into your copy; otherwise you download it yourself. Turn the check off in **Settings → Updates & Dependencies**. See [SECURITY.md](../SECURITY.md#where-updates-come-from).

**Why does it download Python packages?**
It needs Scapy to capture live traffic; other packages are optional. Downloads come only from `python.org` and the Python Package Index, go into its own data folder, and never change the Python you already have. Scapy's file is checked against a fingerprint built into MiniWireshark. Without it, MiniWireshark opens in limited mode, where Demo Mode and capture files still work.

**Why does it ask for administrator rights or a password?**
Reading raw packets needs them on every system, the same as Wireshark. On Windows, the Npcap driver handles this once it is installed. On Linux and macOS it asks only when you start watching, never just to open the window.

**It was written with an AI assistant. Why should I trust that?**
Trust the checks, not the author. Each change ships with self-tests (more than 350), runs on Windows, macOS and two Ubuntu versions in [CI](https://github.com/darkckillerc4/MiniWireshark/actions), and passes a privacy check before it can be merged. The maintainer reviews and signs off every release. The release notes list what was *not* tested, too.

**Something here turned out to be false.**
Please [open an issue](https://github.com/darkckillerc4/MiniWireshark/issues/new/choose), or use private reporting for a security problem (see [SECURITY.md](../SECURITY.md)).

## It doesn't capture anything

**Windows: "no capture driver" or limited mode.**
Install [Npcap](https://npcap.com/). MiniWireshark offers to do it on the loading screen. Then restart MiniWireshark.

**Linux: permission denied.**
MiniWireshark asks for your password when you start watching. If you said no, choose **Start watching** again. To never be asked, give the capability to the Python you use, for example `sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v python3)")"`. That applies to every script run with that Python.

**macOS: no packets.**
MiniWireshark needs read access to `/dev/bpf*`. Wireshark's *ChmodBPF* helper sets this up; otherwise MiniWireshark asks for the administrator password when you start watching.

**I only see my own computer's traffic.**
That is normal on Wi-Fi and switched networks: each computer mostly sees its own traffic plus broadcasts. The **vantage meter** shows this. To see other devices' traffic you need a mirror (SPAN) port, a hub, monitor-mode Wi-Fi, or a connector such as Pi-hole or AdGuard Home for DNS.

**The wrong network card is chosen.**
Turn off **Settings → Capture → Choose the network card automatically** and pick it yourself. VPN and virtual adapters are a common cause.

## It doesn't start, or it is slow

**It crashed twice and now opens in Safe Mode.**
That is on purpose. Safe Mode turns off auto-capture, history, update checks and automatic downloads so you can reach the window. Open **Diagnostics** to see what failed, or run `python miniwireshark.py --boot-check`.

**The first start is slow.**
The first start installs packages and compiles the file. The compiled copy is then cached, so later starts are faster. From 5.3.4 this includes Windows, where the window itself starts from the cached copy.

**Something is broken and I don't know what.**
Look at the **Ready?** list in the Welcome Center first: each problem has a fix button. Or use **Settings → General → Repair MiniWireshark**. It checks components, reference lists, the history database, the settings file and the capture engine, then says what it fixed.

**The window is slow on a busy network.**
Try **Settings → Performance**: lower the memory cap, or set **When it falls behind** to Strict. Full Power uses more processor cores for the deep pass. When a live capture can't keep up, MiniWireshark pauses deep analysis by itself and says so; it comes back after a few calm seconds.

## Reporting a problem

Open an [issue](https://github.com/darkckillerc4/MiniWireshark/issues/new/choose) and attach a **debug bundle** from the Diagnostics window. It masks addresses and secrets. For security problems, follow [SECURITY.md](../SECURITY.md) instead of opening a public issue.

## Versions

**Where are the older versions?**
On the [releases page](https://github.com/darkckillerc4/MiniWireshark/releases). Each release has the `.py` file and a `.sha256` file. The [version index](VERSIONS.md) lists every checksum.

**Can two versions share a folder?**
Yes. Copies in the same folder share `miniwireshark_data/` next to the script. To keep them fully apart, put each in its own folder. From 5.2.3, copies sharing a folder can no longer damage each other's files.
