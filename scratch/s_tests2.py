class _PipelineHarness:
    """Just enough of the app for the analysis worker (tests, bench)."""

    def __init__(self, model):
        self.ring = RawRing()
        self.gen = 1
        self.model = model
        self.count = 0
        self.all_rows = deque(maxlen=5000)
        self.pending_rows = deque(maxlen=5000)
        self._analysis_errors = 0
        self.analysed = 0

    def on_rows_analysed(self, rows):
        self.analysed += len(rows)

    def sink(self):
        ring, gen = self.ring, self.gen
        return lambda raw, ts, lt, c=lambda: False: \
            ring.put_wait(raw, ts, lt, gen, c)


def run_pipeline(model, frames, timeout=60):
    h = _PipelineHarness(model)
    w = AnalysisWorker(h, GuiGate())
    w.start()
    sink = h.sink()
    for raw, ts, lt in frames:
        sink(raw, ts, lt)
    t_end = time.time() + timeout
    while (len(h.ring) or w.busy or h.count < len(frames)) and \
            time.time() < t_end:
        time.sleep(0.01)
    w.stop_flag = True
    w.join(2)
    return h, w


@self_test()
def t_reverse_dns_only_in_active_mode(ctx):
    src = inspect.getsource(MiniWireshark.on_rows_analysed)
    assert "mode.active_scanning" in src


@self_test()
def t_capture_file_readers(ctx):
    frames = [(bytes([i % 256]) * (60 + i), 1700000000.0 + i * 0.25, 1)
              for i in range(50)]
    p = ctx.path("rt.pcap")
    write_raw_pcap(p, frames)
    back = list(iter_raw_capture(p))
    assert len(back) == 50 and back[7][0] == frames[7][0]
    assert abs(back[7][1] - frames[7][1]) < 1e-5 and back[0][2] == 1
    # a hand-built pcapng: SHB, IDB (nanosecond resolution), 2 EPBs
    def block(btype, body):
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack("<II", btype, ln) + body + struct.pack("<I", ln)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535) +
                struct.pack("<HHB", 9, 1, 9) + b"\x00" * 3 +
                struct.pack("<HH", 0, 0))
    out = shb + idb
    for i in range(2):
        ts = (1700000000 + i) * 10 ** 9 + 500
        data = frames[i][0]
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    p2 = ctx.path("rt.pcapng")
    with open(p2, "wb") as f:
        f.write(out)
    back = list(iter_raw_capture(p2))
    assert len(back) == 2 and back[1][0] == frames[1][0], back
    assert abs(back[1][1] - 1700000001.0000005) < 1e-6
    with open(ctx.path("junk.pcap"), "wb") as f:
        f.write(b"hello world, not a capture")
    try:
        list(iter_raw_capture(ctx.path("junk.pcap")))
        raise AssertionError("junk accepted")
    except ValueError:
        pass


@self_test()
def t_raw_ring_and_gate(ctx):
    r = RawRing(max_frames=3)
    for i in range(5):
        r.put(b"x" * 10, i, 1, 1)
    assert len(r) == 3 and r.dropped == 2 and r.bytes == 30
    assert [x[1] for x in r.drain(10)] == [0, 1, 2] and r.bytes == 0
    g = GuiGate()
    g.acquire()
    g.acquire()
    assert g.held() and g.release_all() == 2 and not g.held()
    got = []
    t = threading.Thread(target=lambda: (g.acquire(), got.append(1),
                                         g.release()))
    t.start()
    t.join(2)
    assert got == [1], "gate not released"
    g.reacquire(2)
    assert g.held()
    g.release()
    g.release()
    assert not g.held()


@self_test()
def t_pipeline_worker(ctx):
    if not ctx.scapy_ok:
        return "skip"
    gw, ips, macs, nets = scenario_identity()
    m = NetworkModel(ctx.cfg(), gw, ips, macs)
    m.set_identity(local_nets=nets)
    m.use_packet_clock = True
    frames = ctx.frames()
    h, w = run_pipeline(m, frames)
    assert h.count == len(frames), (h.count, len(frames), w.errors,
                                    w.last_error)
    m.tick()
    m._announce_created(flush=True)
    fails = golden_checks(m)
    assert not fails, "; ".join(fails)
    assert [d["no"] for d in list(h.all_rows)[:3]] == [1, 2, 3]
    assert all(d.get("raw") for d in h.all_rows)
    # frames of an old generation never reach a new model
    h2 = _PipelineHarness(m)
    w2 = AnalysisWorker(h2, GuiGate())
    old_sink = h2.sink()
    h2.gen = 2
    for raw, ts, lt in frames[:40]:
        old_sink(raw, ts, lt)
    w2.start()
    time.sleep(0.3)
    w2.stop_flag = True
    w2.join(2)
    assert h2.count == 0 and w2.stale == 40, (h2.count, w2.stale)


def bench_pipeline():
    gw, ips, macs, nets = scenario_identity()
    cfg = AppConfig(path=os.path.join(tempfile.mkdtemp(), "c.json"))
    m = NetworkModel(cfg, gw, ips, macs)
    m.set_identity(local_nets=nets)
    m.use_packet_clock = True
    frames = ScenarioBuilder().busy_mix(30000)
    t0 = time.perf_counter()
    h, w = run_pipeline(m, frames, timeout=120)
    dt = time.perf_counter() - t0
    return {"pipeline_pkts_per_s": h.count / dt}


BENCH_EXTRA = [bench_pipeline]

