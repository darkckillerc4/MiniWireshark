@gui_test_step("stress: 30k frames while the window stays responsive")
def _gs_stress(app, ctx):
    root = app.root
    app.stop()
    app._leave_nonlive()
    ident = scenario_identity()
    m = app._new_model(identity=ident[:3])
    m.set_identity(local_nets=ident[3])
    app.replace_model(m)
    app.data_mode = "live"            # behave like a live capture
    app._select_tab("packets")
    frames = ScenarioBuilder().busy_mix(30000)
    sink = app.lossless_sink()
    feeder = threading.Thread(
        target=lambda: [sink(r, time.time(), lt) for r, _t, lt in frames],
        daemon=True)
    stalls = []
    last = [time.perf_counter()]

    def beat():
        now = time.perf_counter()
        stalls.append(now - last[0])
        last[0] = now
        if feeder.is_alive() or len(app.ring) or app.worker.busy:
            root.after(10, beat)
    t0 = time.perf_counter()
    feeder.start()
    root.after(10, beat)
    ok = _gui_pump(root, 0.5, lambda: not feeder.is_alive() and
                   not len(app.ring) and not app.worker.busy and
                   app.count >= len(frames), timeout=120)
    dt = time.perf_counter() - t0
    worst = max(stalls) if stalls else 0
    print(f"      ({len(frames)} frames in {dt:.1f}s, worst UI stall "
          f"{worst * 1000:.0f} ms, ring peak {app.ring.peak})")
    assert ok, f"pipeline stalled at {app.count}/{len(frames)}"
    assert worst < 0.6, f"UI froze for {worst * 1000:.0f} ms"
    app.data_mode = "idle"
    _gui_pump(root, 0.3)
    assert len(app.tabs["packets"].tree.get_children()) > 0


@gui_test_step("live capture starts and stops (only with --live)")
def _gs_live(app, ctx):
    if "--live" not in sys.argv:
        return
    app.start(auto=True)
    _gui_pump(app.root, 3.0)
    assert app.sniffer is not None, "capture did not start"
    assert app.sniffer.exception is None, app.sniffer.exception
    with contextlib.suppress(OSError):
        _socket.getaddrinfo("example.com", 443)
    _gui_pump(app.root, 1.5)
    kind = getattr(app.sniffer, "kind", "?")
    app.stop()
    _gui_pump(app.root, 0.5)
    assert app.sniffer is None and app.data_mode == "idle"
    print(f"      (source: {kind}, {app.count} packets)")

