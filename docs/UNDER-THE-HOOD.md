# Under the hood

MiniWireshark looks simple on purpose. Underneath, it is one Python file that installs and repairs its own runtime, decodes packets fast enough to keep up with a busy network, verifies its own updates with hand-checked cryptography, and tests itself. This page is a tour of the engineering. For the map of the file, see [Architecture](ARCHITECTURE.md).

## <img src="assets/icons/self-maintaining.svg" width="28" alt=""> A private Python runtime that installs, tests and repairs itself

People run MiniWireshark on whatever Python they have: an old 3.8, a Store build without Tk, a Linux distribution's system Python that refuses `pip`. Instead of asking them to fix it, MiniWireshark can bring its own interpreter. The **RuntimeManager** (region 2d) works in two layers.

**Layer 1, the launcher (region 1a)** runs on any Python 3.8 or newer with only the standard library. If a healthy private runtime exists, the script re-launches itself inside it and does nothing else: no downloads, no installs, no system changes. The child process is marked `MW_STAGE=app`, so it can never loop. Two failed starts in a row switch back to the previous runtime, or to the Python that launched it.

**Layer 2, the runtime itself:**

- **Relocatable builds.** It uses [python-build-standalone](https://github.com/astral-sh/python-build-standalone) "install only, stripped" builds of CPython 3.14 for Windows (x86, x64, ARM64), macOS (Intel and Apple silicon) and Linux (x64, ARM64). They need no admin rights and include Tk.
- **Every byte is pinned.** Each archive's SHA-256 is written into the source file. Wheels for the private runtime are hash-pinned too, and installed with `pip --require-hashes`.
- **A signed fallback on Windows.** When the Visual C++ runtime is missing, it falls back to the official python.org installer (per user; PATH, launcher and file associations off), and accepts it only with a valid *Python Software Foundation* signature.
- **Safe archive extraction.** Archives are extracted with path checks, so a crafted archive can't write outside its folder.
- **Build next to, then switch.** A new environment is built beside the old one and tested before it is used. If the old one is still running, the switch happens on the next start.
- **Repair without the network.** **Repair** reinstalls components from the cached downloads and re-tests them. If the interpreter itself is damaged, it rebuilds from the cached archive.
- **Rollback and removal.** Rollback returns to the previous environment. Remove deletes every private runtime, and the next start uses your own Python again.

Your system Python, PATH and file associations are never touched.

## <img src="assets/icons/capture.svg" width="28" alt=""> A capture pipeline that never makes the window wait

```
capture thread ──raw bytes──▶ RawRing ──▶ AnalysisWorker ──▶ NetworkModel
  never parses                drops counted     decode off the GUI,
                              by cause          ingest under GuiGate
```

- **Capture threads never parse.** They append `(bytes, time, link type, generation)` to a ring buffer and go straight back to the socket. A busy network can't starve them, and drops can only happen at the ring, where they are counted by cause and shown in the status bar.
- **The GuiGate** is a re-entrant lock that wraps tkinter's own callback wrapper, so every Tk callback holds it automatically. The analysis worker holds it for at most about 25 ms at a time, and modal dialogs release it while they wait.
- **Capture epochs** make sure frames from a capture you just stopped never leak into the next one.
- **A watchdog** notices a capture that died and restarts it. Faults are classified, and each one comes with a fix in plain English.
- **Full Power** runs a second, deeper pass in worker processes, so heavy dissection uses other cores and never the window's.

## <img src="assets/icons/packets.svg" width="28" alt=""> A packet decoder fifteen times faster than the obvious one

The obvious way to decode packets in Python is to build a scapy object for each one. MiniWireshark's **fast wire decoder** (region 5b) reads the bytes directly with `struct`, for the frames that make up nearly all real traffic: Ethernet and VLAN, ARP, IPv4 and IPv6, TCP, UDP, ICMP and neighbour discovery, DNS, mDNS, LLMNR, DHCP, SSDP, NBNS, NTP, QUIC, TLS and HTTP.

- It is roughly **15 to 20 times faster** than the scapy path, and the 4.0 pipeline measured about **115,000 frames per second**.
- It produces **exactly the same result** as the scapy decoder. A differential self-test replays a scenario through both and compares them field by field.
- Anything it doesn't understand goes to scapy, so coverage never shrinks.
- The packet object for the detail view is built lazily, only when you open one.

Behind it sit a protocol registry of 166 fields, dissectors with byte ranges for the hex view, IP defragmentation, TCP reassembly, and a pcap and pcapng reader written with the standard library only.

## <img src="assets/icons/websites.svg" width="28" alt=""> Reading site names from HTTP/3, honestly

A browser's first QUIC packet is encrypted with keys anyone can derive from the packet itself (RFC 9001 §5.2). MiniWireshark derives them to read the site name, the same thing every network middlebox may do. It is not "decrypting a connection": once the handshake moves on, real secret keys take over and nothing else is readable.

- It uses the `cryptography` package when present, and otherwise **a small pure-Python AES-128 and GHASH**. Both check the authentication tag.
- The work is budgeted, so a flood of fake Initial packets can't eat the CPU.
- The name is labelled as "read from the first packet", and **Encrypted Client Hello** is detected and said out loud.

## <img src="assets/icons/shield.svg" width="28" alt=""> Signed updates with a hand-checked Ed25519

An update is installed only when its manifest is signed by a release key, its SHA-256 and size match, and it is newer than the running version, so downgrades are refused. With no release key configured, updates are check-only. If an update fails to start, the next start rolls it back.

Verification uses `cryptography` when present, and otherwise **a pure-Python Ed25519 (RFC 8032)**, checked against the RFC's own test vectors. The same signatures protect optional data packs.

## <img src="assets/icons/privacy.svg" width="28" alt=""> Privacy that is enforced, not promised

- **One gate for everything it sends.** Downloads, update checks, health checks, discovery probes, reverse lookups and the router check all pass through `outbound()`. Each send is written to a self-traffic ledger you can read, and the kill switch stops all of it.
- **A test that reads the source.** A self-test parses the file and fails if any network send bypasses the gate.
- **Secrets dropped in the parser.** Mail logins, passwords and message bodies never reach storage. A **canary** secret is planted in test traffic in every place a password could appear, and the tests check reports, sessions, CSV files, logs, history and the clipboard for it.
- **Secret scrubbing.** Known secrets are masked in logs, copied details and debug bundles.

## <img src="assets/icons/history.svg" width="28" alt=""> Crash safety at every layer

- **Boot receipts** record how far each start got. Two starts in a row that never reach the window switch the next one to **Safe Mode**.
- **A crash-safe session journal** lets you restore an interrupted session. The format is versioned, and older journals still restore.
- **A flight recorder** keeps the minutes before a problem.
- **The SQLite history** runs in WAL mode, with migrations that take a backup first and a recovery path for a damaged database.
- **Atomic writes** for settings and state, and copies of MiniWireshark sharing a folder are kept from damaging each other's files.
- **One-click Repair** checks components, reference lists, history, settings and the capture engine, and says what it fixed.

## <img src="assets/icons/tests.svg" width="28" alt=""> A window that tests and measures itself

- **131 self-tests** run without capture or admin rights, driven by **replay scenarios**: a scripted home network made of ordinary packets with `.example` names. The same frames drive the fuzzers, the GUI test and the benchmarks.
- **Two fuzzers** throw malformed packets at the decoders and the model.
- **The GUI test** drives the real window through every tab (48 steps).
- **A layout crawler** opened every tab, view, dialog and settings page in three languages, two themes, four text sizes and screen sizes from 1024×768 to 1920×1080, and flagged overlaps and cut-off text.
- **Performance budgets** (`BENCH_LIMITS`) are frozen, and `--bench-gui` fails when the window gets slower.
- **`--release-gate`** runs all of it and photographs every tab into one folder that can be sent back from another computer.
- **The settings are one table.** Every option is declared once, the Settings window is generated from it, and the tests prove that nothing is orphaned or phantom.
- **The table of contents is tested.** The file's docstring lists every region, and a self-test fails when it drifts from the banners.

## <img src="assets/icons/speed.svg" width="28" alt=""> Faster starts from a cached compiled copy

Started as `python miniwireshark.py`, Python compiles the whole 66,000-line file first. That costs about 2.5 seconds and about 150 MB that the process keeps for its whole life. From 5.1.2, the compiled code is cached in the data folder, one file per Python version and checked against the script's time and size like any `.pyc`. Later processes load it, and the loading screen does the first-time work, so the window appears finished.

## <img src="assets/icons/investigate.svg" width="28" alt=""> Claims that can't overclaim

Every statement in the window carries an **evidence level**: Observed, Reported, Correlated, Inferred or Unknown. Unknown is never shown as "no". A **vantage meter** measures how much of other devices' traffic this computer can actually see, and every view uses it to say what it can't know. Inferences come with their innocent explanations. See [Architecture](ARCHITECTURE.md#claims-carry-evidence).
