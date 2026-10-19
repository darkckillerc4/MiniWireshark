

# ============================================================================
#  1a+.  V5 startup: boot receipts, Safe Mode, the handshake hand-off and
#        the private packages folder
#
#  MiniWireshark 5 opens on the Python that started it whenever that Python
#  can run it. Missing packages go into a private folder inside the data
#  folder (one per Python version and platform), never into the system
#  Python. A managed Python is only used when you chose it, or when this
#  Python is too old or has no graphical toolkit — and then only after its
#  window has reported back (the "handshake"); otherwise this process stays
#  and explains what went wrong.
#
#  Every start writes a small "boot receipt" (stages, timings, errors) so a
#  failure on another computer can be read instead of guessed. Two starts in
#  a row that never reached the main window switch the next start to Safe
#  Mode.
# ============================================================================
BOOT_DIR = os.path.join(PATHS.data, "boot")
SAFE_FLAG = "--safe"
BOOT_CHECK_FLAG = "--boot-check"
READY_ARG = "--mw-ready="
STAGE_ARG = "--mw-stage=app"
HANDSHAKE_TIMEOUT = 25.0          # seconds for the managed Python's window
HANDSHAKE_ELEVATION_TIMEOUT = 180.0   # if it is waiting for a UAC click
HANDOFF_NOTE = [""]               # why a hand-off failed (shown at startup)

# arguments that only carry the hand-off between two processes
_HANDOFF_ARGS = [a for a in sys.argv[1:] if a.startswith(READY_ARG) or
                 a == STAGE_ARG]
for _a in _HANDOFF_ARGS:
    sys.argv.remove(_a)
if STAGE_ARG in _HANDOFF_ARGS and not MW_STAGE:
    MW_STAGE = "app"
READY_FILE = next((a[len(READY_ARG):] for a in _HANDOFF_ARGS
                   if a.startswith(READY_ARG)), "") or \
    os.environ.get("MW_READY_FILE", "")


def _pid_alive(pid):
    """True while a process with this id exists (best effort)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if IS_WINDOWS:
        try:
            k = ctypes.windll.kernel32
            h = k.OpenProcess(0x1000, False, pid)   # QUERY_LIMITED_INFO
            if not h:
                return False
            code = ctypes.c_ulong()
            ok = k.GetExitCodeProcess(h, ctypes.byref(code))
            k.CloseHandle(h)
            return bool(ok) and code.value == 259    # STILL_ACTIVE
        except (AttributeError, OSError):
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class BootReceipt:
    """One small JSON file per start: what ran, how long it took, what
    failed (with the exact error). Written after every step, so even a hard
    crash leaves a readable trace. The newest KEEP receipts are kept."""

    KEEP = 10
    FAILED = ("running", "crashed", "fatal")

    def __init__(self, directory=None, argv=None, kind="start"):
        self.dir = directory or BOOT_DIR
        self.m0 = time.monotonic()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.path = os.path.join(self.dir, f"boot-{stamp}-{os.getpid()}"
                                           f".json")
        self._lock = threading.Lock()
        self.data = {
            "kind": kind, "version": SCRIPT_VERSION, "started": time.time(),
            "pid": os.getpid(), "python": platform.python_version(),
            "executable": sys.executable, "platform": platform.platform(),
            "stage": MW_STAGE or "launcher",
            "argv": [a for a in (sys.argv[1:] if argv is None else argv)
                     if not a.startswith(READY_ARG)][:8],
            "steps": [], "reached_window": False, "reached_main_window":
                False, "safe_mode": False, "outcome": "running"}
        self._write()
        self.prune()

    def step(self, name, ok=True, detail="", error=None):
        e = {"name": str(name), "at": round(time.monotonic() - self.m0, 3),
             "ok": bool(ok), "detail": scrub_secrets(str(detail))[:300]}
        if error is not None:
            e["error"] = scrub_secrets(
                f"{type(error).__name__}: {error}")[:600]
        with self._lock:
            self.data["steps"].append(e)
            if len(self.data["steps"]) > 200:
                del self.data["steps"][:50]
            self._write()
        return e

    def mark(self, **kw):
        with self._lock:
            self.data.update(kw)
            if kw.get("outcome") and kw["outcome"] != "running":
                self.data["ended"] = time.time()
                self.data["duration"] = round(time.monotonic() - self.m0, 3)
            self._write()

    def _write(self):
        try:
            os.makedirs(self.dir, exist_ok=True)
            atomic_write_json(self.path, self.data)
        except OSError:
            pass

    def prune(self):
        for old in BootReceipt.files(self.dir)[self.KEEP:]:
            with contextlib.suppress(OSError):
                os.remove(old)

    @staticmethod
    def files(directory=None):
        d = directory or BOOT_DIR
        try:
            names = [n for n in os.listdir(d)
                     if n.startswith("boot-") and n.endswith(".json")]
        except OSError:
            return []
        paths = [os.path.join(d, n) for n in names]
        return sorted(paths, key=lambda p: (os.path.getmtime(p)
                                            if os.path.exists(p) else 0, p),
                      reverse=True)

    @staticmethod
    def recent(directory=None, n=10):
        out = []
        for p in BootReceipt.files(directory)[:n]:
            r = read_json(p, None)
            if isinstance(r, dict):
                r["_path"] = p
                out.append(r)
        return out

    @staticmethod
    def failed(r):
        """A start that never reached the main window and is not still
        running (a closed Welcome Center or a hand-off is not a failure)."""
        if r.get("kind") != "start" or r.get("reached_main_window"):
            return False
        if r.get("outcome") not in BootReceipt.FAILED:
            return False
        if r.get("outcome") == "running" and _pid_alive(r.get("pid")):
            return False
        return True

    @staticmethod
    def summary(r):
        steps = r.get("steps") or []
        bad = next((s for s in steps if not s.get("ok")), None)
        when = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.localtime(r.get("started", 0)))
        line = (f"{when}  {r.get('outcome', '?'):<10} Python "
                f"{r.get('python', '?')} ({r.get('stage', '?')})"
                f"  {r.get('duration', '…')} s")
        if r.get("safe_mode"):
            line += "  [Safe Mode]"
        if bad:
            line += f"\n    failed at: {bad['name']} — " \
                    f"{bad.get('error') or bad.get('detail')}"
        elif r.get("outcome") in BootReceipt.FAILED and steps:
            line += f"\n    last step: {steps[-1]['name']}"
        return line


def crash_loop_detected(receipts, current_path=""):
    """True when the two newest previous starts both failed."""
    prev = [r for r in receipts if r.get("_path") != current_path and
            r.get("kind") == "start"][:2]
    return len(prev) == 2 and all(BootReceipt.failed(r) for r in prev)


BOOT = None                       # this start's receipt (GUI starts only)
SAFE_MODE = SAFE_FLAG in sys.argv
SAFE_REASON = ["You asked for Safe Mode (--safe)." if SAFE_MODE else ""]
if SAFE_MODE:
    sys.argv.remove(SAFE_FLAG)


def boot_step(name, ok=True, detail="", error=None):
    if BOOT is not None:
        BOOT.step(name, ok, detail, error)


def signal_ready():
    """The managed-Python child tells its parent that its window is up."""
    if not READY_FILE:
        return False
    try:
        with open(READY_FILE, "w", encoding="utf-8") as f:
            f.write(f"READY {os.getpid()}\n")
        return True
    except OSError:
        return False


def system_python_suitable(version=None, has_tk=None):
    """(ok, reason): can the Python that started the file run the app?"""
    v = tuple(version or sys.version_info[:2])
    if v < (3, 8):
        return False, f"Python {v[0]}.{v[1]} is too old (3.8+ needed)"
    if has_tk is None:
        try:
            import importlib.util as _iu
            has_tk = _iu.find_spec("_tkinter") is not None
        except (ImportError, ValueError):
            has_tk = False
    if not has_tk:
        return False, "this Python has no graphical toolkit (Tk)"
    return True, ""


def wait_for_handshake(proc, ready_file, timeout=HANDSHAKE_TIMEOUT,
                       elevation_timeout=HANDSHAKE_ELEVATION_TIMEOUT,
                       poll=0.1):
    """→ ("ready" | "exited" | "timeout", return code or None).
    A child that exits with 0 before the handshake may have handed over to
    an elevated copy of itself, so the wait continues (longer) for that."""
    t0 = time.monotonic()
    limit = timeout
    rc = None
    while True:
        if ready_file and os.path.exists(ready_file):
            return "ready", rc
        if rc is None:
            rc = proc.poll()
            if rc is not None:
                if rc != 0:
                    if ready_file and os.path.exists(ready_file):
                        return "ready", rc
                    return "exited", rc
                limit = max(limit, elevation_timeout)
        if time.monotonic() - t0 > limit:
            return ("timeout" if rc is None else "exited"), rc
        time.sleep(poll)


def _child_log_path():
    return os.path.join(PATHS.logs, time.strftime("child-%Y%m%d-%H%M%S")
                        + f"-{os.getpid()}.log")


def _tail(path, n=1200):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - n))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""
