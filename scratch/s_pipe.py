# ============================================================================
#  6b.  Capture pipeline v2
#
#  capture thread ──raw bytes──▶ RawRing ──▶ AnalysisWorker ──▶ model
#                                              (decode off the GUI,
#                                               ingest under GuiGate)
#  Capture threads never parse: they append (bytes, time, linktype,
#  generation) and go straight back to the socket, so a busy network can't
#  starve them. One analysis worker decodes (fast_decode) and feeds the
#  NetworkModel. The model is shared with the Tk thread, so both take the
#  GuiGate — a re-entrant lock that every Tk callback holds automatically
#  (it wraps tkinter's CallWrapper) and that modal dialogs release while
#  they wait. The worker holds it for at most ~25 ms at a time, so the
#  window stays responsive. Drops can only happen at the ring, are counted
#  per cause and are shown in the status bar and Diagnostics.
# ============================================================================
class GuiGate:
    """Re-entrant lock with the ability to step out of a nested hold
    completely (for modal waits) and step back in afterwards."""

    def __init__(self):
        self._lock = threading.RLock()
        self._owner = None
        self._count = 0
        self.wait_ms = 0.0            # time the worker spent waiting

    def acquire(self):
        self._lock.acquire()
        self._owner = threading.get_ident()
        self._count += 1

    def release(self):
        self._count -= 1
        if self._count == 0:
            self._owner = None
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False

    def held(self):
        return self._owner == threading.get_ident()

    def release_all(self):
        if self._owner != threading.get_ident():
            return 0
        n = self._count
        for _ in range(n):
            self.release()
        return n

    def reacquire(self, n):
        for _ in range(n):
            self.acquire()


GUI_GATE = GuiGate()
_GATE_INSTALLED = [False]


def install_gui_gate(gate=None):
    """Every Tk callback runs holding the gate; modal waits step out of it
    so analysis continues while a dialog is open."""
    gate = gate or GUI_GATE
    if _GATE_INSTALLED[0]:
        return gate
    _GATE_INSTALLED[0] = True
    orig_call = tk.CallWrapper.__call__

    def gated_call(self, *args):
        gate.acquire()
        try:
            return orig_call(self, *args)
        finally:
            gate.release()
    tk.CallWrapper.__call__ = gated_call

    def releasing(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            n = gate.release_all()
            try:
                return fn(*a, **k)
            finally:
                gate.reacquire(n)
        return wrapper
    tk.Misc.wait_window = releasing(tk.Misc.wait_window)
    tk.Misc.wait_variable = releasing(tk.Misc.wait_variable)
    tk.Misc.waitvar = tk.Misc.wait_variable
    with contextlib.suppress(ImportError, AttributeError):
        from tkinter import commondialog
        commondialog.Dialog.show = releasing(commondialog.Dialog.show)
    return gate


class RawRing:
    """Bounded hand-off from capture threads to the analysis worker.
    deque.append/popleft are atomic, so producers take no lock."""

    def __init__(self, max_frames=150000, max_bytes=96 * 1024 * 1024):
        self.dq = deque()
        self.max_frames = max_frames
        self.max_bytes = max_bytes
        self.bytes = 0
        self.dropped = 0              # frames refused because it was full
        self.peak = 0

    def __len__(self):
        return len(self.dq)

    def put(self, raw, ts, lt, gen):
        if len(self.dq) >= self.max_frames or self.bytes >= self.max_bytes:
            self.dropped += 1
            return False
        self.dq.append((raw, ts, lt, gen))
        self.bytes += len(raw)
        n = len(self.dq)
        if n > self.peak:
            self.peak = n
        return True

    def put_wait(self, raw, ts, lt, gen, cancelled=lambda: False):
        """Lossless variant for file imports and demo data."""
        while len(self.dq) >= self.max_frames or \
                self.bytes >= self.max_bytes:
            if cancelled():
                return False
            time.sleep(0.005)
        self.dq.append((raw, ts, lt, gen))
        self.bytes += len(raw)
        return True

    def drain(self, n):
        out = []
        pop = self.dq.popleft
        try:
            for _ in range(n):
                item = pop()
                self.bytes -= len(item[0])
                out.append(item)
        except IndexError:
            pass
        if not self.dq:
            self.bytes = 0
        return out

    def clear(self):
        self.dq.clear()
        self.bytes = 0


class AnalysisWorker(threading.Thread):
    """The only thread that feeds packets into the model."""

    BATCH = 1500
    SLICE = 0.025                 # max seconds per hold of the GuiGate

    def __init__(self, app, gate=None):
        super().__init__(daemon=True, name="analysis")
        self.app = app
        self.gate = gate or GUI_GATE
        self.reasm = TlsReassembler()
        self.stop_flag = False
        self.decoded = 0
        self.errors = 0
        self.stale = 0             # frames from a previous data source
        self.last_error = ""
        self.beat = time.monotonic()
        self.busy = False
        self.deep = 0              # frames the fast path handed to scapy

    def reset(self):
        self.reasm = TlsReassembler()

    def run(self):
        ring = self.app.ring
        while not self.stop_flag:
            self.beat = time.monotonic()
            batch = ring.drain(self.BATCH)
            if not batch:
                self.busy = False
                time.sleep(0.004)
                continue
            self.busy = True
            try:
                self._process(batch)
            except Exception as e:                   # noqa: BLE001
                self.errors += 1
                self.last_error = f"{type(e).__name__}: {e}"
                if self.errors <= 20:
                    LOG.exception("analysis batch")
        self.busy = False

    def _process(self, batch):
        app = self.app
        gen = app.gen
        model = app.model
        gw, my_ips = model.gateway_ip, model.my_ips
        decoded = []
        for raw, ts, lt, g in batch:
            if g != gen:
                self.stale += 1
                continue
            try:
                d = fast_decode(raw, ts, lt, self.reasm, gw, my_ips)
            except Exception as e:                   # noqa: BLE001
                self.errors += 1
                if self.errors <= 20:
                    self.last_error = f"{type(e).__name__}: {e}"
                    LOG.debug("decode error: %s", self.last_error)
                continue
            if d.get("pkt") is not None:
                self.deep += 1
            decoded.append(d)
        if not decoded:
            return
        i = 0
        while i < len(decoded):
            t_wait = time.perf_counter()
            with self.gate:
                self.gate.wait_ms += (time.perf_counter() - t_wait) * 1000
                if app.gen != gen or app.model is not model:
                    self.stale += len(decoded) - i
                    return
                t0 = time.perf_counter()
                start = i
                while i < len(decoded):
                    d = decoded[i]
                    i += 1
                    app.count += 1
                    d["no"] = app.count
                    learn_names_from(model.cache, d)
                    try:
                        model.ingest(d)
                    except Exception:                # noqa: BLE001
                        app._analysis_errors += 1
                        if app._analysis_errors <= 5:
                            LOG.exception("analysis error")
                    if time.perf_counter() - t0 > self.SLICE:
                        break
                rows = decoded[start:i]
                app.all_rows.extend(rows)
                app.pending_rows.extend(rows)
                self.decoded += len(rows)
                app.on_rows_analysed(rows)
            time.sleep(0)           # let the Tk thread in between slices


def _layer2num(cls):
    try:
        return int(conf.l2types.layer2num.get(cls, 1))
    except (AttributeError, TypeError, ValueError):
        return 1


class RawCapture(threading.Thread):
    """Live capture straight from a layer-2 socket: no scapy packet is
    built in the capture thread, just bytes + timestamp."""

    def __init__(self, iface, bpf, promisc, sink):
        super().__init__(daemon=True, name="capture")
        self.iface = iface
        self.bpf = bpf
        self.promisc = promisc
        self.sink = sink
        self.stop_flag = False
        self.running = False
        self.exception = None
        self.received = 0
        self.started = threading.Event()
        self.sock = None
        self.kind = "raw socket"

    def _open(self):
        kwargs = {"iface": self.iface}
        if self.bpf:
            kwargs["filter"] = self.bpf
        last = None
        for extra in ({"promisc": self.promisc}, {}):
            try:
                return conf.L2listen(**dict(kwargs, **extra))
            except TypeError as e:
                last = e
                continue
        raise last or RuntimeError("could not open capture socket")

    def run(self):
        try:
            self.sock = self._open()
        except Exception as e:                       # noqa: BLE001
            self.exception = e
            self.started.set()
            return
        self.running = True
        self.started.set()
        sock = self.sock
        lt_cache = {}
        select = getattr(type(sock), "select", None)
        try:
            while not self.stop_flag:
                if select is not None:
                    ready = select([sock], 0.25)
                    if not ready:
                        continue
                r = sock.recv_raw(65535)
                if not r:
                    continue
                cls, raw, ts = r[0], r[1], r[2] if len(r) > 2 else None
                if raw is None:
                    continue
                lt = lt_cache.get(cls)
                if lt is None:
                    lt = lt_cache[cls] = _layer2num(cls)
                self.received += 1
                self.sink(raw, float(ts) if ts else time.time(), lt)
        except Exception as e:                       # noqa: BLE001
            if not self.stop_flag:
                self.exception = e
        finally:
            self.running = False
            with contextlib.suppress(Exception):
                sock.close()

    def stop(self):
        self.stop_flag = True
        if self.is_alive():
            self.join(timeout=1.5)


class SnifferCapture:
    """Fallback: scapy's AsyncSniffer (slower, builds packet objects) for
    backends without raw receive. Same interface as RawCapture."""

    kind = "scapy sniffer"

    def __init__(self, sniffer):
        self.sniffer = sniffer
        self.received = 0

    @property
    def running(self):
        return getattr(self.sniffer, "running", True)

    @property
    def exception(self):
        return getattr(self.sniffer, "exception", None)

    def stop(self):
        with contextlib.suppress(Exception):
            self.sniffer.stop()

    def is_alive(self):
        return self.running


def start_capture_source(iface, bpf, promisc, sink):
    """Raw socket first, AsyncSniffer as fallback. Returns (source, err)."""
    rc = RawCapture(iface, bpf, promisc, sink)
    rc.start()
    rc.started.wait(3.0)
    time.sleep(0.2)
    if rc.exception is None and rc.is_alive():
        return rc, None
    err = rc.exception
    rc.stop_flag = True
    LOG.info("raw capture unavailable (%s); trying the scapy sniffer", err)
    counter = {"n": 0}

    def prn(pkt):
        counter["n"] += 1
        sink(bytes(pkt), float(getattr(pkt, "time", time.time())),
             _layer2num(type(pkt)))
    sn, err2 = build_sniffer(iface, prn, bpf, promisc)
    if sn is None:
        return None, err2 or err
    return SnifferCapture(sn), None


# ---- capture files (stdlib reader for pcap and pcapng) ----------------------
def iter_raw_capture(path):
    """Yield (raw_bytes, timestamp, linktype) from a .pcap or .pcapng
    file without scapy. Raises ValueError for unknown formats."""
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            raise ValueError("file is empty")
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(f, head)
            return
        magic_le = struct.unpack("<I", head)[0]
        magics = {0xa1b2c3d4: ("<", 1e-6), 0xd4c3b2a1: (">", 1e-6),
                  0xa1b23c4d: ("<", 1e-9), 0x4d3cb2a1: (">", 1e-9)}
        if magic_le not in magics:
            raise ValueError("not a pcap/pcapng file")
        end, scale = magics[magic_le]
        rest = f.read(20)
        if len(rest) < 20:
            raise ValueError("truncated pcap header")
        _vmaj, _vmin, _tz, _sig, _snap, lt = struct.unpack(end + "HHiIII",
                                                           rest)
        lt &= 0x0FFFFFFF
        rec = struct.Struct(end + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, _orig = rec.unpack(h)
            if incl > 262144 * 4:
                raise ValueError("corrupt record length")
            data = f.read(incl)
            if len(data) < incl:
                return
            yield data, sec + frac * scale, lt


def _iter_pcapng(f, first):
    end = "<"
    ifaces = []                   # (linktype, ts_scale)
    last_ts = 0.0
    block_type = first
    while True:
        if block_type is None:
            block_type = f.read(4)
            if len(block_type) < 4:
                return
        lenb = f.read(4)
        if len(lenb) < 4:
            return
        if block_type == b"\x0a\x0d\x0d\x0a":
            bom = f.read(4)
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(end + "I", lenb)[0]
            body = f.read(blen - 12)
            ifaces = []
            block_type = None
            continue
        btype = struct.unpack(end + "I", block_type)[0]
        blen = struct.unpack(end + "I", lenb)[0]
        if blen < 12 or blen > 64 * 1024 * 1024:
            raise ValueError("corrupt pcapng block")
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        block_type = None
        if btype == 1 and len(body) >= 8:              # interface description
            lt = struct.unpack_from(end + "H", body, 0)[0]
            scale = 1e-6
            p = 8
            while p + 4 <= len(body):
                code, ln = struct.unpack_from(end + "HH", body, p)
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[p + 4]
                    scale = (2 ** -(v & 0x7F)) if v & 0x80 else 10 ** -v
                p += 4 + ln + ((4 - ln % 4) % 4)
            ifaces.append((lt, scale))
        elif btype == 6 and len(body) >= 20:           # enhanced packet
            iid, hi, lo, cap, _orig = struct.unpack_from(end + "IIIII", body,
                                                         0)
            lt, scale = ifaces[iid] if iid < len(ifaces) else (1, 1e-6)
            ts = ((hi << 32) | lo) * scale
            last_ts = ts
            yield bytes(body[20:20 + cap]), ts, lt
        elif btype == 3 and len(body) >= 4:            # simple packet
            lt, _s = ifaces[0] if ifaces else (1, 1e-6)
            orig = struct.unpack_from(end + "I", body, 0)[0]
            yield bytes(body[4:4 + orig]), last_ts, lt
        elif btype == 2 and len(body) >= 20:           # obsolete packet
            iid = struct.unpack_from(end + "H", body, 0)[0]
            hi, lo, cap = struct.unpack_from(end + "III", body, 4)
            lt, scale = ifaces[iid] if iid < len(ifaces) else (1, 1e-6)
            ts = ((hi << 32) | lo) * scale
            last_ts = ts
            yield bytes(body[20:20 + cap]), ts, lt


class RawPcapImporter(threading.Thread):
    """Feeds a capture file through the SAME pipeline as live packets
    (lossless: it waits when the ring is full) and can be cancelled."""

    def __init__(self, path, sink, on_progress, on_done):
        super().__init__(daemon=True, name="pcap-import")
        self.path = path
        self.sink = sink              # sink(raw, ts, lt, cancelled) -> bool
        self.on_progress = on_progress
        self.on_done = on_done
        self.cancelled = False
        self.count = 0

    def run(self):
        err = None
        try:
            for raw, ts, lt in iter_raw_capture(self.path):
                if self.cancelled:
                    break
                if not self.sink(raw, ts, lt, lambda: self.cancelled):
                    break
                self.count += 1
                if self.count % 2000 == 0:
                    self.on_progress(self.count)
        except (OSError, ValueError, struct.error) as e:
            err = (f"{e}. The file may be damaged, or it isn't a "
                   "pcap/pcapng capture.")
            LOG.warning("capture import failed: %s", err)
        self.on_done(self.count, err, self.cancelled)


