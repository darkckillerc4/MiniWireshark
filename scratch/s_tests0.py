# ---- registered tests (added milestone by milestone) -------------------------
SELF_TESTS = []              # (function, slow)


def self_test(slow=False):
    """Register a module-level test: fn(ctx) raises on failure, may return
    "skip". `slow` tests are skipped by --quick."""
    def deco(fn):
        SELF_TESTS.append((fn, slow))
        return fn
    return deco


class TestContext:
    def __init__(self, tmp, scapy_ok):
        self.tmp = tmp
        self.scapy_ok = scapy_ok
        self._frames = None

    def cfg(self, extra=None):
        c = AppConfig(path=os.path.join(self.tmp,
                                        f"cfg_{uuid.uuid4().hex}.json"))
        for k, v in (extra or {}).items():
            c.set(k, v)
        return c

    def path(self, name):
        return os.path.join(self.tmp, name)

    def frames(self):
        """The home-network scenario, built once per run."""
        if self._frames is None:
            self._frames = ScenarioBuilder().home_network()
        return list(self._frames)


def model_summary(model):
    """Semantic fingerprint of a model, for determinism checks."""
    reg = model.registry
    return {
        "devices": sorted((d.key, d.display_name(), d.device_class)
                          for d in reg.by_key.values()),
        "websites": sorted((w.domain, tuple(sorted(w.sources)),
                            w.connections) for w in model.websites.values()),
        "remotes": sorted(model.remote_hosts),
        "flows": len(model.flows.all_flows()),
        "alerts": sorted((a.kind, a.device_key)
                         for a in model.alerts.alerts.values()),
    }


@self_test()
def t_python38_grammar(ctx):
    """The launcher stage must parse on Python 3.8 (old installs hand over
    to the managed runtime, so the whole file keeps 3.8 syntax)."""
    import ast
    with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
        src = f.read()
    ast.parse(src, feature_version=(3, 8))
    assert "match " not in [ln.strip()[:6] for ln in src.splitlines()
                            if ln.strip().startswith("match ")][:1] or True


@self_test()
def t_scenario_golden(ctx):
    if not ctx.scapy_ok:
        return "skip"
    m = scenario_model(ctx.cfg(), ctx.frames())
    fails = golden_checks(m)
    assert not fails, "; ".join(fails)


@self_test()
def t_scenario_deterministic(ctx):
    if not ctx.scapy_ok:
        return "skip"
    sums = [model_summary(scenario_model(ctx.cfg(), ctx.frames()))
            for _ in range(3)]
    assert sums[0] == sums[1] == sums[2], "replay is not deterministic"


@self_test(slow=True)
def t_fuzz_decoder_and_model(ctx):
    """Mutated frames must never crash analysis (decoder errors are counted
    and skipped by the pipeline; the model must never raise)."""
    if not ctx.scapy_ok:
        return "skip"
    rng = random.Random(11)
    frames = ctx.frames()
    m = NetworkModel(ctx.cfg(), *scenario_identity()[:3])
    m.set_identity(local_nets=scenario_identity()[3])
    m.use_packet_clock = True
    dec = default_frame_decoder(m)
    decode_errors = 0
    n = 2500
    for i in range(n):
        raw, ts, lt = frames[rng.randrange(len(frames))]
        b = bytearray(raw)
        for _ in range(rng.randint(1, 6)):
            op = rng.random()
            if op < 0.5 and b:
                b[rng.randrange(len(b))] = rng.randrange(256)
            elif op < 0.8 and len(b) > 14:
                del b[rng.randrange(14, len(b)):]
            else:
                b.extend(bytes(rng.randrange(256)
                               for _ in range(rng.randint(1, 40))))
        try:
            d = dec(bytes(b), ts + i * 0.001, lt)
        except Exception:                            # noqa: BLE001
            decode_errors += 1
            continue
        m.ingest(d)
        if i % 400 == 0:
            m.tick()
    assert decode_errors < n * 0.05, f"{decode_errors} decode errors"


def bench_report(seconds=2.0):
    """Measured numbers for this machine (python miniwireshark.py --bench)."""
    load_scapy()
    out = {}
    sb = ScenarioBuilder()
    frames = sb.busy_mix(20000)
    cfg = AppConfig(path=os.path.join(tempfile.mkdtemp(), "c.json"))
    m = NetworkModel(cfg, *scenario_identity()[:3])
    m.set_identity(local_nets=scenario_identity()[3])
    m.use_packet_clock = True
    dec = default_frame_decoder(m)
    t0 = time.perf_counter()
    decoded = [dec(raw, ts, lt) for raw, ts, lt in frames[:5000]]
    out["reference_decode_per_s"] = 5000 / (time.perf_counter() - t0)
    fast = globals().get("fast_decode")
    if fast is not None:
        t0 = time.perf_counter()
        for raw, ts, lt in frames:
            fast(raw, ts, lt)
        out["fast_decode_per_s"] = len(frames) / (time.perf_counter() - t0)
    t0 = time.perf_counter()
    for i, d in enumerate(decoded):
        m.ingest(d)
    out["ingest_us_per_pkt"] = (time.perf_counter() - t0) / len(decoded) * 1e6
    extra = globals().get("BENCH_EXTRA") or []
    for fn in extra:
        with contextlib.suppress(Exception):
            out.update(fn())
    return out


# ============================================================================
#  20c.  GUI test — drives the real window under a (virtual) display
#
#  python miniwireshark.py --gui-test   (Linux: run it inside xvfb-run)
#  It imports the scripted capture through the normal PCAP path, visits
#  every tab in every theme and mode, opens the detail views and settings,
#  checks Dark mode for light-coloured leaks, and shuts down cleanly.
# ============================================================================
GUI_TEST_STEPS = []           # later milestones append (name, fn(app, ctx))


def gui_test_step(name):
    def deco(fn):
        GUI_TEST_STEPS.append((name, fn))
        return fn
    return deco


def _gui_pump(root, seconds=0.0, until=None, timeout=30.0):
    t_end = time.time() + timeout
    t_min = time.time() + seconds
    while True:
        try:
            root.update()
        except tk.TclError:
            return False
        now = time.time()
        if now >= t_min and (until is None or until()):
            return True
        if now > t_end:
            return False
        time.sleep(0.01)


def _patch_dialogs_for_tests():
    """No modal dialog may block an unattended test run."""
    messagebox.askyesno = lambda *a, **k: True
    messagebox.askokcancel = lambda *a, **k: True
    messagebox.askyesnocancel = lambda *a, **k: True
    messagebox.showinfo = lambda *a, **k: "ok"
    messagebox.showwarning = lambda *a, **k: "ok"
    messagebox.showerror = lambda *a, **k: "ok"
    filedialog.askopenfilename = lambda *a, **k: ""
    filedialog.asksaveasfilename = lambda *a, **k: ""
    filedialog.askdirectory = lambda *a, **k: ""


def _luminance(hexcol):
    try:
        return _hex_lum(hexcol)
    except (ValueError, TypeError, IndexError):
        return None


def dark_theme_leaks(root):
    """Widgets that still paint a light background in Dark mode."""
    leaks = []

    def walk(w):
        try:
            if isinstance(w, (tk.Frame, tk.Label, tk.Text, tk.Canvas,
                              tk.Listbox, tk.Button, tk.Checkbutton,
                              tk.Radiobutton, tk.Entry, tk.Toplevel,
                              tk.LabelFrame, tk.Message)):
                bg = str(w.cget("bg"))
                if bg.startswith("#") and len(bg) == 7:
                    lum = _luminance(bg)
                    if lum is not None and lum > 0.82 and \
                            not getattr(w, "_mw_light_ok", False):
                        leaks.append(f"{w.winfo_class()} {w} bg={bg}")
        except tk.TclError:
            pass
        for c in w.winfo_children():
            walk(c)
    walk(root)
    return leaks


def run_gui_test(live=False):
    """Returns 0 on success. Prints a step-by-step report."""
    global PATHS
    tmp = tempfile.mkdtemp(prefix="mw_guitest_")
    os.environ["MINIWIRESHARK_DATA"] = tmp
    PATHS = AppPaths()
    setup_logging()
    load_scapy()
    _patch_dialogs_for_tests()
    results = []
    ctx = TestContext(tmp, True)
    cfg = ctx.cfg({"general.auto_start_capture": False,
                   "updates.check_automatically": False,
                   "privacy.auto_download_reference": False,
                   "history.enabled": True,
                   "history.retention": "7 days"})
    cfg.save()
    root = tk.Tk()
    gw, ips, macs, nets = scenario_identity()
    app = MiniWireshark(root, "", set(), set(), "", config=cfg)

    def step(name, fn):
        t0 = time.perf_counter()
        try:
            fn()
            results.append(("PASS", name, ""))
        except Exception as e:                       # noqa: BLE001
            results.append(("FAIL", name, f"{type(e).__name__}: {e}\n" +
                            traceback.format_exc(limit=6)))
        print(f"  [{results[-1][0]}] {name} "
              f"({(time.perf_counter() - t0) * 1000:.0f} ms)", flush=True)

    frames = ctx.frames()
    pcap = ctx.path("scenario.pcap")
    write_raw_pcap(pcap, frames)

    def s_import():
        app.import_pcap_path(pcap)
        ok = _gui_pump(root, 0.5, lambda: app.importer is None and
                       app.data_mode == "offline" and
                       app.model.count >= len(frames), timeout=60)
        assert ok, f"import stalled at {app.model.count}/{len(frames)}"
        _gui_pump(root, 2.2)
        fails = golden_checks(app.model)
        assert not fails, "; ".join(fails)

    def s_tabs():
        for name, tab in app.tabs.items():
            app._select_tab(name)
            _gui_pump(root, 0.05)
            tab.refresh()

    def s_modes_and_themes():
        for mode in ("Advanced", "Beginner", "Advanced"):
            app.mode_ui_var.set(mode)
            app._on_ui_mode_change()
            _gui_pump(root, 0.05)
        for theme, hc in (("Dark", False), ("Dark", True), ("Light", True),
                          ("Light", False), ("Dark", False)):
            app._apply_theme(theme, hc)
            for name in app.tabs:
                app._select_tab(name)
                _gui_pump(root, 0.02)
        leaks = dark_theme_leaks(root)
        app._apply_theme("Light", False)
        assert not leaks, f"{len(leaks)} light widgets in Dark: " + \
            "; ".join(leaks[:6])

    def s_details():
        m = app.model
        for key in list(m.registry.by_key)[:12]:
            app.show_device(key)
        for dom in list(m.websites)[:6]:
            app.show_website(dom)
        for ip in list(m.remote_hosts)[:4]:
            app.show_remote(ip)
        for f in list(m.flows.all_flows())[:4]:
            app.show_flow(f.fid)
        for aid in list(m.alerts.order)[:4]:
            app.show_alert(aid)
        _gui_pump(root, 0.2)
        for w in root.winfo_children():
            if isinstance(w, tk.Toplevel):
                w.destroy()

    def s_settings():
        app._open_settings()
        _gui_pump(root, 0.2)
        sw = app._settings_win
        for page in SETTINGS_PAGES:
            sw.show_page(page["id"])
            _gui_pump(root, 0.02)
        sw.win.destroy()
        app.open_diagnostics()
        _gui_pump(root, 0.3)
        app._diag_win.win.destroy()

    def s_search():
        for q in ("example", "ip:192.168.1.23", "port:443", "device:tv",
                  "alert:cleartext"):
            res = app.search_results(q)
            assert isinstance(res, (list, dict))

    def s_demo():
        app.start_demo()
        _gui_pump(root, 2.5)
        assert app.data_mode == "demo" and app.model.demo
        app.stop_demo()
        _gui_pump(root, 0.3)
        assert not any(d.ip.startswith("192.168.50.") for d in
                       app.model.registry.by_key.values() if d.ip)

    for name, fn in (("import scenario capture (golden checks)", s_import),
                     ("visit every tab", s_tabs),
                     ("modes and themes (dark leak audit)",
                      s_modes_and_themes),
                     ("detail views", s_details),
                     ("settings and diagnostics", s_settings),
                     ("global search", s_search)):
        step(name, fn)
    for name, fn in GUI_TEST_STEPS:
        step(name, lambda fn=fn: fn(app, ctx))
    step("demo mode starts and leaves no trace", s_demo)

    def s_close():
        app._on_close()
        time.sleep(0.5)
        bad = [t.name for t in threading.enumerate()
               if t is not threading.main_thread() and not t.daemon]
        assert not bad, f"non-daemon threads left: {bad}"
    step("clean shutdown", s_close)
    failed = [r for r in results if r[0] == "FAIL"]
    print(f"\nGUI test: {len(results) - len(failed)} passed / "
          f"{len(failed)} failed")
    for _s, name, msg in failed:
        print(f"\nFAILED: {name}\n{msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failed else 0


def write_raw_pcap(path, frames):
    """Write (raw, ts, linktype) frames to a classic pcap file (stdlib)."""
    lt = frames[0][2] if frames else 1
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, lt))
        for raw, ts, _lt in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6)) % 1000000
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            f.write(raw)


