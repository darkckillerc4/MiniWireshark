# Architecture

MiniWireshark is about 66,000 lines in a single file, `miniwireshark.py`. It is one file on purpose: it is easy to download, check and run, and it can't break because one of its parts went missing. Only files the program creates at run time (logs, sessions, history, caches) live elsewhere, in the [data folder](INSTALL.md#where-it-keeps-its-files).

## The map of the file

Every region starts with a banner:

```python
# ============================================================================
#  13.  NetworkModel — the single analysis core
# ============================================================================
```

The module docstring at the top lists every region in file order, and the self-test `t_toc_matches_banners` fails if the list and the banners drift apart. To find a region, search for its banner, for example `#  13.  `.

| Group | Regions | What lives there |
|---|---|---|
| Start-up | 1, 1a, 1b, 2, 2b, 2c, 2d, 3 | Paths and logging, the launcher and private Python runtime, the dependency manager, the loading window and its steps, optional reference data |
| Outbound gate | 2a | `outbound()`, the single gate every network send passes through, and the self-traffic ledger |
| Decoding | 4, 5, 5b, 5c | Constants and helpers, the protocol decoder, the fast wire decoder, QUIC Initial parsing |
| Capture | 6, 6b | Capture workers and the v2 pipeline (ring buffer and analysis worker) |
| Models | 7, 7b, 8, 9, 10, 11 | Devices and their identity over time, websites, remote hosts, connections, rolling metrics |
| Judgement | 12, 12b, 12c, 12d | The anomaly and security engine, evidence levels, coverage, insights |
| This computer | 9b, 9c, 9d | Which program owns each connection, country lookup, Pi-hole and AdGuard connectors |
| Core | 13 | `NetworkModel`, the object every view reads |
| Storage | 14, 14c | Configuration, sessions, known devices, the SQLite history and its views |
| Interface | 15, 16, 17, 18, 18b, 18c, 19, 19b | Strings and translations, the settings schema, widgets, tabs, exports, background jobs, the main window, diagnostics |
| Trust | 21b | Ed25519-signed updates and data packs |
| Testing | 20, 20a, 20b, 20c | Demo Mode, replay scenarios, self-tests, the GUI test |
| Entry | 21 | `main()` and the command-line switches |

## How it starts

```
python miniwireshark.py
   │
   ├─ Layer 1 (1a): runs on any Python 3.8+, standard library only.
   │     If a healthy private Python exists in the data folder, re-launch
   │     inside it (marked MW_STAGE=app, so it can never loop).
   │
   ├─ Boot receipt: every start records how far it got. Two starts in a
   │     row that never reach the window switch the next one to Safe Mode.
   │
   ├─ Loading window (2b, 2c): the bootstrap steps, in plain English.
   │     Missing packages go into a private per-Python folder, never the
   │     system Python. Required packages are checked against a pinned
   │     SHA-256; optional ones come from PyPI through pip, unpinned.
   │
   ├─ Load scapy, find the gateway, this computer's addresses and the
   │     best network card. Warm up the first views.
   │
   └─ Welcome Center → main window (19) → capture starts.
```

If a step that only capture needs fails, MiniWireshark continues in *limited mode* instead of stopping. You can still open files and the demo.

From 5.1.2 the compiled code is cached per Python version in the data folder. Later processes of the same file (the private-Python hand-off and the Full Power workers) load that copy, which saves about 2.5 seconds and about 150 MB.

## How a packet becomes an answer

```
 network card
     │  raw bytes, time, link type
     ▼
 capture thread (6b) ──▶ RawRing ──▶ AnalysisWorker ──▶ NetworkModel (13)
   never parses           drops are     fast_decode (5b),     devices, websites,
                          counted here  holds GuiGate         remote hosts, flows,
                          by cause      ≤ ~25 ms at a time    metrics, alerts
                                                                 │
                                       outboxes, drained in batches
                                                                 ▼
                                                     tabs, map, reports (17–19)
```

- **Capture threads never parse.** They append to the ring buffer and go straight back to the socket, so a busy network can't starve them.
- **One analysis worker** decodes and feeds the model.
- **The GuiGate** is a re-entrant lock shared by the worker and the Tk thread. Every Tk callback takes it automatically, and the worker gives the window its turn often, so the window stays responsive.
- **Full Power** adds a deep pass in worker processes (`--mw-worker`): every dissector, TCP reassembly, IP defragmentation and protocol exchanges.
- **Slow work** (exports, history queries, session loads) runs as background jobs on one jobs thread (18c). A job never touches Tk; its result comes back through a queue.

## The models keep things apart

Most beginner tools mix up "a device", "a website" and "an address on the Internet". MiniWireshark keeps them in separate models:

- **Device (7, 7b):** something on *your* network, keyed by hardware address, with identity bindings that follow it across address changes and networks.
- **Website (8):** a name, from DNS, TLS SNI, HTTP Host or QUIC. Never a device.
- **Remote host (9):** a public Internet address. Never a device.
- **Connection (10):** a flow between any of the above.

## Claims carry evidence

Observations are facts with a source, a time and, when they came from a packet, its number. They are never edited. Everything a view shows is a **claim** built from them, with one of five levels:

| Mark | Level | Meaning |
|---|---|---|
| ◉ | Observed | Seen directly in a packet from this device |
| ◈ | Reported | Told by another system (router, Pi-hole …) |
| ◎ | Correlated | Two separate observations line up (lookup, then connect) |
| ◌ | Inferred | A reasonable guess, shown with counter-explanations |
| ? | Unknown | Nothing either way. Never shown as "no" |

**Coverage (12c)** adds the vantage meter. On ordinary Wi-Fi or a switched network this computer mostly sees its own traffic plus broadcasts. Views use the meter to say what they can't know, instead of implying that "not seen" means "didn't happen".

## Settings are one table

Every option is declared exactly once in `SETTINGS_PAGES` (region 16), grouped by what a person is trying to do. The Settings window is generated from that table, and the self-tests prove that no option is orphaned or phantom.

## Privacy is enforced in code

- Every send the app makes passes through `outbound()` (2a) and is logged in the self-traffic ledger. The kill switch stops all of it. A self-test parses the file and fails if any send bypasses the gate.
- Mail logins, passwords and message bodies are dropped inside the parsers, before anything is stored.
- `register_secret()` and `scrub_secrets()` keep known secrets out of logs, copied details and debug bundles.

## Testing

All test traffic comes from **replay scenarios** (20a): a scripted home network made of ordinary packets with reserved `.example` names. The same frames drive the self-tests, the fuzzer, the GUI test and the benchmarks.

| Command | What runs |
|---|---|
| `--self-test` | The built-in suite (region 20b), no capture or admin rights needed |
| `--gui-test` | The real window, driven through every tab (region 20c) |
| `--bench-gui S1 S2` | Window-performance scenarios against fixed budgets (`BENCH_LIMITS`) |
| `--release-gate` | All of the above plus pictures of every tab |

CI runs a syntax check and the self-test on Python 3.8, 3.12 and 3.13 for every push and pull request ([`ci.yml`](../.github/workflows/ci.yml)).
