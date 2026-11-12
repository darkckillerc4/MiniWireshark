<p align="center"><img src="assets/icons/shield.svg" width="72" alt=""></p>

# Can I trust MiniWireshark? Check for yourself

A network monitor sees everything your computer sends, so you should be skeptical about it. This page doesn't ask you to take anything on faith. Each claim below comes with a way to check it yourself.

## In short

| Claim | How to check it |
|---|---|
| It is one readable Python file, with no installer and no compiled code. | Open `miniwireshark.py` in any text editor. Its docstring lists every region in order. |
| The file you downloaded is the published one. | Compare its SHA-256 with the `.sha256` file on the release and with the [version index](VERSIONS.md). |
| It has no telemetry. Everything it sends goes through one gate and is listed. | Open **Security → What MiniWireshark sent**. Turn on the **kill switch** and watch it block everything. |
| It never phones home for updates from anywhere but GitHub. | Read [SECURITY.md](../SECURITY.md#where-updates-come-from). Search the file for `OFFICIAL_UPDATE_REPO`. |
| Its claims are tested. | Run `python miniwireshark.py --self-test` on your own computer (a few minutes, no capture or admin rights needed). |
| It says what it can't see. | The vantage meter in the bottom-right corner, and **Help → What this computer can see**. |

## 1. Check the download

Download it only from the [official releases page](https://github.com/darkckillerc4/MiniWireshark/releases). Other sites may offer changed copies.

```bash
sha256sum miniwireshark-<version>.py          # Linux
shasum -a 256 miniwireshark-<version>.py      # macOS
```

```powershell
Get-FileHash -Algorithm SHA256 .\miniwireshark-<version>.py   # Windows
```

The value must match the `.sha256` file next to it on the release. Every release since 1.0 is listed with its checksum in [VERSIONS.md](VERSIONS.md). Each release is built by the public [release workflow](../.github/workflows/release.yml) from the commit it names. You can compare the file with `git show v<version>:miniwireshark.py`.

## 2. Check what it sends

MiniWireshark mostly *listens*. It sends something in the following cases, each through one function, `outbound()`, which records the send in a ledger:

| What | When | Where it goes |
|---|---|---|
| Update check | Once a day, unless you turn it off | `api.github.com`, for the latest release number only |
| Reference lists | About once a month, unless you turn it off | `wireshark.org` (vendor names) and `publicsuffix.org`. Plain file downloads. |
| Private Python and packages | Only when you approve the download list | `python.org` and the Python Package Index (`pypi.org`, `files.pythonhosted.org`) |
| Npcap (Windows) | Only when you choose to install it | `npcap.com` |
| Health checks | When you open Health or run them | Your router, your DNS server, and a test address |
| Device discovery (Active Mode) | Only on your own subnet, and never on a network you haven't trusted | Devices on your local network |
| Country lookup | **Off** by default | An online lookup service, only if you turn it on |
| Pi-hole / AdGuard Home | Only if you add one | The helper you added, on your network |
| Router port-forwarding check | Only when you press the button | Your router |

How to check:

- **Security → What MiniWireshark sent** lists every send, with its purpose and destination.
- The **kill switch** (Settings → Privacy & Lookups) blocks all of it. A blocked send is listed as blocked.
- **Safe Mode** (`--safe`) starts with no automatic capture, no history, no update checks and no downloads.
- Watch it from outside with your firewall, or with Wireshark itself. Filter on the computer's address while MiniWireshark runs in Demo Mode, which sends nothing at all.
- In the code, a self-test (`outbound_bypasses`) parses the file and fails if any network call skips the gate. That includes `pip` and other programs it starts.

## 3. Check what it keeps

Everything it writes goes in one data folder (see [Installation](INSTALL.md#where-it-keeps-its-files)): logs, sessions, the optional history, and its private packages. History is **off** by default.

- Passwords, mail logins and message bodies are dropped inside the decoders and never stored. A canary self-test plants fake secrets and checks every report, session, CSV, log, history row and clipboard copy for them.
- On Linux and macOS the data folder is closed to other users.
- **Storage used…** in the command palette (`Ctrl+K`) shows what each part takes. Deleting the folder removes everything.
- Shareable reports and the Network check-up can replace names and addresses with pseudonyms.

## 4. Check the permissions it asks for

- **Windows:** packet capture needs the [Npcap](https://npcap.com/) driver. Once Npcap is installed, capture works without administrator rights.
- **Linux and macOS:** capture needs root, `CAP_NET_RAW` or access to `/dev/bpf*`. From 5.3.4 MiniWireshark doesn't start as administrator. It asks for your password only when capture starts. Demo Mode, capture files and the help never ask.

You can always say no. It then opens in limited mode, where you can still use capture files, saved sessions and the demo.

## 5. Check how it is tested

- **Self-test:** more than 340 tests built into the file (`--self-test`). They cover the decoders, the alert rules, the privacy canary, the outbound gate, corrupt files and clock jumps.
- **GUI test:** `--gui-test` drives the real window through every tab.
- **CI:** every push and pull request runs the self-test on Python 3.8, 3.12 and 3.13, the GUI test on two Ubuntu versions, the self-test and GUI test on Windows, the self-test on macOS, and a [privacy check](../.github/scripts/privacy_check.py) that keeps captures, personal data and keys out of this public repository. Results are on the [Actions page](https://github.com/darkckillerc4/MiniWireshark/actions).
- **Long runs:** 5.3.4 ran an 8-hour soak test on a real Windows PC, which tracked memory, threads and handles.
- **Screenshots** in these docs are taken from Demo Mode: simulated data with reserved `.example` names. Nothing in them is real traffic.

## 6. Honest limits

- **It can only see what reaches this computer.** On Wi-Fi and on most switches, that is mostly this computer's own traffic plus broadcasts. It says so and doesn't guess the rest. Seeing more needs a mirror port, a hub, or a DNS helper such as Pi-hole.
- **Device types are evidence-based guesses.** Every guess shows its confidence and the evidence for it. An IP address alone is never counted as a device.
- **Encrypted traffic stays encrypted.** It sees which site a connection goes to (from DNS and TLS names), not what was said.
- **It is not a replacement for Wireshark.** It covers the common protocols in depth, but Wireshark has thousands of dissectors.
- **It is pure Python.** That is fine for a home or small-office network. On very busy links it says when it falls behind and only counts packets until it catches up.
- **How it is made:** MiniWireshark is a one-person project. Most of the code is written with an AI coding assistant (Claude), then reviewed, tested and released by the maintainer. Each change comes with self-tests, and nothing ships without the maintainer's sign-off.

## 7. Found a problem?

Security issues: please use private reporting, as described in [SECURITY.md](../SECURITY.md). Anything else: [open an issue](https://github.com/darkckillerc4/MiniWireshark/issues/new/choose). If you checked one of the claims above and it didn't hold, that is exactly what we want to hear.

MiniWireshark is an independent project. It is not affiliated with or endorsed by the Wireshark Foundation or the Wireshark project.
