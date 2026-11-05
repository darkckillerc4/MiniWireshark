"""S7 soak harness (M17): stress profile S2 replayed live at 2x speed into
the real window, looping, with wall-clock timestamps like a capture.
Samples RSS, Python heap (allocated blocks + tracemalloc-free estimate),
thread count, open fds and the longest Tk freeze every minute.

usage: soak.py REPO CSV MINUTES [--tabs]
"""
import csv
import gc
import os
import sys
import threading
import time

repo, out_csv, minutes = sys.argv[1], sys.argv[2], float(sys.argv[3])
ROTATE = "--tabs" in sys.argv
sys.argv = ["miniwireshark.py"]
sys.path.insert(0, repo)
import miniwireshark as mw  # noqa: E402

tk = mw.tk
tmp = os.environ["MINIWIRESHARK_DATA"]
mw.PATHS = mw.AppPaths()
mw.setup_logging()
mw.load_scapy()
mw._patch_dialogs_for_tests()
mw.ReverseDNS.lookup = lambda self, ip: None      # no outbound lookups

frames = mw.bench_capture(1000, 20000, 5000)      # stress profile S2
t_first, t_last = frames[0][1], frames[-1][1]
span = t_last - t_first + 1.0
SPEED = float(os.environ.get("SOAK_SPEED", "2"))
DIAG = os.environ.get("SOAK_DIAG") == "1"
SAMPLE_MS = int(os.environ.get("SOAK_SAMPLE_MS", "60000"))

TM = os.environ.get("SOAK_TRACEMALLOC")
if TM:
    import tracemalloc
    tracemalloc.start(int(TM))
tm_prev = [None]
cfg = mw.AppConfig(path=os.path.join(tmp, "config.json"))
for k, v in (("general.auto_start_capture", False),
             ("general.show_welcome", False),
             ("updates.check_automatically", False),
             ("privacy.auto_download_reference", False),
             ("appearance.beginner_mode", False),
             ("history.enabled", True),
             ("history.retention", "7 days")):
    cfg.set(k, v)
cfg.save()
mw.install_gui_gate()
probe = mw.perf_start() if DIAG else None
gcinfo = {"t": 0.0, "max": {0: 0.0, 1: 0.0, 2: 0.0}}


def _gccb(phase, info):
    if phase == "start":
        gcinfo["t"] = time.perf_counter()
    else:
        g = info.get("generation", 0)
        d = time.perf_counter() - gcinfo["t"]
        if d > gcinfo["max"][g]:
            gcinfo["max"][g] = d


if DIAG:
    gc.callbacks.append(_gccb)
root = tk.Tk()
root.geometry("1440x900")
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
mw.warm_heading_widths(root)
mw.freeze_startup_objects()
mw._gui_pump(root, 1.0)
gw, ips, macs, nets = mw.scenario_identity()
app.model.set_identity(gateway_ip="192.168.1.1",
                       local_nets=[mw.ipaddress.ip_network("192.168.0.0/16")])
app._ensure_worker()
app.data_mode = "live"
app.model.obs_sink = app._history_live()
app.model.capture_started = time.time()
app._select_tab("dash")
mw._gui_pump(root, 1.0)

stop = threading.Event()
sent = [0, 0]                                     # frames, loops


def replay():
    sink = app.live_sink()
    loop = 0
    while not stop.is_set():
        t_begin = time.perf_counter()
        for raw, ts, lt in frames:
            if stop.is_set():
                break
            due = t_begin + (ts - t_first) / SPEED
            lag = due - time.perf_counter()
            if lag > 0:
                time.sleep(lag)
            sink(raw, time.time(), lt)
            sent[0] += 1
        loop += 1
        sent[1] = loop


beat = {"last": time.perf_counter(), "max": 0.0, "max_all": 0.0,
        "over": 0}


def heartbeat():
    now = time.perf_counter()
    gap = now - beat["last"]
    beat["last"] = now
    if gap > beat["max"]:
        beat["max"] = gap
    if gap > 0.5:
        beat["over"] += 1
    root.after(10, heartbeat)


def fds():
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def tasks():
    try:
        return len(os.listdir("/proc/self/task"))
    except OSError:
        return -1


def handles():
    """Windows: this process's open handles; elsewhere its open files."""
    if os.name != "nt":
        return fds()
    try:
        import ctypes
        n = ctypes.c_ulong()
        k = ctypes.windll.kernel32
        if k.GetProcessHandleCount(k.GetCurrentProcess(), ctypes.byref(n)):
            return n.value
    except (AttributeError, OSError):
        pass
    return -1


def write_threads():
    """SOAK_CENSUS, every sample: the live threads by name (numbers folded,
    so "Thread-12 (work)" and "Thread-13 (work)" count together) and the
    handle count, so a growing thread is named."""
    import collections
    import re
    names = collections.Counter(re.sub(r"\d+", "#", t.name)
                                for t in threading.enumerate())
    line = (f"minute {state['minute']} handles={handles()} "
            f"threads={sum(names.values())} " +
            ", ".join(f"{n} x{c}" for n, c in sorted(names.items())))
    with open(out_csv + ".threads.txt", "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


t0 = time.time()
f = open(out_csv, "w", newline="", encoding="utf-8")
w = csv.writer(f)
w.writerow(["minute", "elapsed_s", "rss_mb", "py_blocks", "py_heap_mb_est",
            "gc_objects_gen2", "threads_py", "threads_os", "fds",
            "packets_seen", "frames_sent", "loops", "ring_dropped",
            "max_freeze_ms", "freezes_over_500ms", "devices", "flows",
            "rows_kept", "tab"])
TABS = [t for t in ("dash", "devices", "health", "alerts", "packets",
                    "websites", "map", "feed") if t in app.tabs]
state = {"minute": 0, "tab": "dash"}


def sample():
    state["minute"] += 1
    m = app.model
    blocks = sys.getallocatedblocks()
    try:
        flows = len(m.flows.flows) if hasattr(m.flows, "flows") else \
            sum(1 for _ in m.flows.all_flows())
    except Exception:                              # noqa: BLE001
        flows = -1
    w.writerow([state["minute"], round(time.time() - t0, 1),
                round(mw._rss_mb(), 1), blocks,
                round(blocks * 64 / 1e6, 1),
                len(gc.get_objects(2)) if state["minute"] % 5 == 0 else "",
                threading.active_count(), tasks(), fds(),
                m.count, sent[0], sent[1], app.ring.dropped,
                round(beat["max"] * 1000, 1), beat["over"],
                len(m.registry.by_key), flows, len(app.all_rows),
                state["tab"]])
    f.flush()
    if DIAG:
        _diag()
    if TM and state["minute"] % 4 == 0 and state["minute"] >= 8:
        snap = tracemalloc.take_snapshot().filter_traces((
            tracemalloc.Filter(False, tracemalloc.__file__),))
        if tm_prev[0] is not None:
            st = snap.compare_to(tm_prev[0], "lineno")[:25]
            with open(out_csv + ".tm.txt", "a", encoding="utf-8") as fh:
                fh.write(f"=== minute {state['minute']}\n")
                for x in st:
                    fh.write(f"  {x}\n")
        tm_prev[0] = snap
    if os.environ.get("SOAK_CENSUS"):
        try:
            write_threads()
        except Exception as e:                     # noqa: BLE001
            print("thread census failed", e, flush=True)
    if os.environ.get("SOAK_CENSUS") and state["minute"] % 5 == 0:
        try:
            write_census()
        except Exception as e:                     # noqa: BLE001
            print("census failed", e, flush=True)
    beat["max_all"] = max(beat["max_all"], beat["max"])
    beat["max"] = 0.0
    # the gc.get_objects pass above is ours, not the app's: restart the
    # heartbeat clock so it is not counted as a window freeze
    beat["last"] = time.perf_counter()
    if time.time() - t0 >= minutes * 60 or state["minute"] * SAMPLE_MS >= minutes * 60000:
        stop.set()
        root.after(2000, root.quit)
        return
    root.after(SAMPLE_MS, sample)


prev_types = {}


def _diag():
    import collections
    lines = [f"--- minute {state['minute']} gc max ms " + ", ".join(
        f"g{g}={v * 1000:.0f}" for g, v in gcinfo["max"].items())]
    for g in gcinfo["max"]:
        gcinfo["max"][g] = 0.0
    for r in mw.PerfProbe.slow_lines(probe, 8):
        lines.append("   " + r)
    probe.reset()
    if state["minute"] % 3 == 0:
        c = collections.Counter(type(o).__name__ for o in gc.get_objects())
        if prev_types:
            grow = sorted(((c[k] - prev_types.get(k, 0), k) for k in c),
                          reverse=True)[:15]
            lines.append("   growth: " + ", ".join(f"{k}+{d}" for d, k in grow))
        prev_types.clear()
        prev_types.update(c)
    with open(out_csv + ".diag.txt", "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def census(obj=None, depth=0, seen=None, path="app", out=None):
    """len() of every sized container reachable from the window through
    attributes (2 levels) - what grows without a bound."""
    if out is None:
        out, seen = {}, set()
        obj = app
    if id(obj) in seen or depth > 3:
        return out
    seen.add(id(obj))
    try:
        attrs = vars(obj)
    except TypeError:
        attrs = {}
        for k in getattr(type(obj), "__slots__", ()) or ():
            try:
                attrs[k] = getattr(obj, k)
            except AttributeError:
                pass
    for k, v in list(attrs.items()):
        if isinstance(v, (tk.Misc, type)) or callable(v) and not \
                hasattr(v, "__dict__"):
            continue
        p = f"{path}.{k}"
        if isinstance(v, (list, dict, set, tuple, frozenset)) or \
                type(v).__name__ in ("deque", "OrderedDict", "Counter",
                                     "defaultdict"):
            try:
                out[p] = len(v)
            except TypeError:
                pass
        elif hasattr(v, "__dict__") or hasattr(type(v), "__slots__"):
            if type(v).__module__ in ("miniwireshark", "__main__"):
                census(v, depth + 1, seen, p, out)
    return out


prev_census = {}


def write_census():
    c = census()
    for k, v in list(vars(mw).items()):
        if isinstance(v, (list, dict, set)) or type(v).__name__ in (
                "deque", "OrderedDict", "Counter", "defaultdict"):
            c["mw." + k] = len(v)
        elif type(v).__module__ == "miniwireshark" and not isinstance(
                v, type):
            census(v, 1, set(), "mw." + k, c)
    lines = [f"=== census minute {state['minute']}"]
    rows = sorted(c.items(), key=lambda kv: -kv[1])[:60]
    for k, v in rows:
        d = v - prev_census.get(k, 0)
        lines.append(f"  {v:9d} {d:+8d}  {k}")
    prev_census.clear()
    prev_census.update(c)
    with open(out_csv + ".census.txt", "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def rotate():
    if stop.is_set():
        return
    i = (TABS.index(state["tab"]) + 1) % len(TABS) \
        if state["tab"] in TABS else 0
    state["tab"] = TABS[i]
    app._select_tab(TABS[i])
    root.after(30000, rotate)


th = threading.Thread(target=replay, daemon=True, name="soak-replay")
th.start()
root.after(10, heartbeat)
root.after(SAMPLE_MS, sample)
if ROTATE:
    root.after(30000, rotate)
root.mainloop()
f.close()
print("done", sent, "max freeze ms", round(beat["max_all"] * 1000, 1))
try:
    app._on_close()
except Exception:                                  # noqa: BLE001
    pass
os._exit(0)
