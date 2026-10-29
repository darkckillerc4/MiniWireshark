# Installation

MiniWireshark is one Python file. There is no installer: you download `miniwireshark.py` and run it. On its first start it prepares everything else itself and asks before it downloads anything.

## 1. Get Python

You need **Python 3.8 or newer with Tk**.

| System | How |
|---|---|
| Windows | Install from [python.org](https://www.python.org/downloads/) or the Microsoft Store. Tk is included. |
| macOS | Install from [python.org](https://www.python.org/downloads/). Tk is included. |
| Debian, Ubuntu | `sudo apt install python3 python3-tk` |
| Fedora | `sudo dnf install python3 python3-tkinter` |

Check it with `python --version` (Windows: `py --version`).

## 2. Download MiniWireshark

1. Open the [latest release](https://github.com/darkckillerc4/MiniWireshark/releases/latest).
2. Download `miniwireshark-<version>.py` and its `.sha256` file.
3. Check the file. The two values must match:

   ```bash
   sha256sum miniwireshark-<version>.py          # Linux
   shasum -a 256 miniwireshark-<version>.py      # macOS
   ```

   ```powershell
   Get-FileHash -Algorithm SHA256 .\miniwireshark-<version>.py   # Windows
   ```

   Every version's checksum is also listed in the [version index](VERSIONS.md).

You can rename the file to `miniwireshark.py`. Older versions are on the [releases page](https://github.com/darkckillerc4/MiniWireshark/releases).

## 3. Start it

```bash
python miniwireshark.py            # Windows: py miniwireshark.py
```

The loading screen then:

1. Lists what it wants to download (capture library, optional extras) and lets you choose. It carries on by itself after a short countdown.
2. Installs Python packages (scapy, and optionally psutil and cryptography) into **a private, per-Python folder**. Your system Python is never changed.
3. On Windows, offers to install [Npcap](https://npcap.com/), the capture driver. With Npcap, capture works without administrator rights.
4. Picks the best network card and opens the **Welcome Center**, where you choose between watching your network and the demo.

If the capture driver is missing or refused, MiniWireshark opens in **limited mode**. You can still open saved sessions, capture files and the demo.

## Capture permissions

| System | What capture needs |
|---|---|
| Windows | Npcap. MiniWireshark offers to install it. |
| Linux | root, or the `CAP_NET_RAW` capability on the Python you run it with |
| macOS | read access to `/dev/bpf*` (for example with Wireshark's *ChmodBPF* helper) |

## Try it without capturing

```bash
python miniwireshark.py --demo
```

Demo Mode shows simulated, clearly labelled data with `.example` names. Nothing is captured or sent.

## Where it keeps its files

The application stays one file. Everything it creates goes into one data folder:

1. `miniwireshark_data/` next to the script, if that folder is writable (portable mode).
2. Otherwise the per-user folder: `%LOCALAPPDATA%\MiniWireshark` (Windows), `~/Library/Application Support/MiniWireshark` (macOS), or `~/.local/share/miniwireshark` (Linux).

Settings are saved in `miniwireshark_config.json`. Two environment variables move these files, which is useful for tests:

```bash
MINIWIRESHARK_DATA=/tmp/mw-data MINIWIRESHARK_CONFIG=/tmp/mw-config.json python miniwireshark.py
```

The data folder holds logs, saved sessions and the autosave, the optional history database, the private packages and boot receipts. **Storage used…** in the command palette (`Ctrl+K`) shows how much each part uses.

## Updating

Download the new release and replace the file. Settings, history and sessions are kept, because they live in the data folder. MiniWireshark can also check for Ed25519-signed updates itself (**Settings → Updates & Dependencies**). If an update fails to start, the next start rolls it back.

## Uninstalling

Delete `miniwireshark.py` and the data folder above. A few things live outside that folder, so delete them too:

- `miniwireshark_config.json` (and `miniwireshark_config.json.bak`) next to `miniwireshark.py`, when that folder is writable.
- scapy's own cache: `~/.cache/scapy` on Linux and macOS, `%LOCALAPPDATA%\scapy` on Windows.
- Passwords you saved for a Pi-hole or AdGuard Home helper are in your system's keychain (Windows Credential Manager, macOS Keychain, or the Linux secret service), under "MiniWireshark". Remove them there, or remove each helper in MiniWireshark before you uninstall (removing a helper deletes its saved password).

If you installed Npcap only for MiniWireshark, remove it from Windows' *Installed apps*.

## Command-line switches

| Switch | What it does |
|---|---|
| `--demo` | Start in Demo Mode |
| `--safe` | Safe Mode: no auto-capture, no history, no update checks, no automatic downloads |
| `--boot-check` | Check this computer's setup and exit, without opening the window |
| `--no-elevate` | Never ask for administrator rights |
| `--yes` | Accept the download list without asking (unattended start) |
| `--self-test` | Run the built-in test suite. No capture or admin rights needed |
| `--gui-test` | Drive the real window through every tab. Needs a display (`xvfb-run -a` on a headless Linux) |
| `--bench-gui S1 S2` | Window-performance benchmark against fixed budgets |
| `--release-gate` | All tests, the benchmark and pictures of every tab, written to one folder you can send back |

Two failed starts in a row switch the next start to Safe Mode automatically.
