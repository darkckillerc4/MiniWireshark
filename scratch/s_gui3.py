@gui_test_step("history store records live evidence (and survives reopen)")
def _gs_history(app, ctx):
    root = app.root
    assert app.history is not None, "history should be on in the GUI test"
    ident = scenario_identity()
    m = app._new_model(identity=ident[:3])
    m.set_identity(local_nets=ident[3])
    app.replace_model(m)
    app.data_mode = "live"
    sink = app.lossless_sink()
    for raw, _ts, lt in ctx.frames():
        sink(raw, time.time(), lt)
    _gui_pump(root, 0.3, lambda: not len(app.ring) and not app.worker.busy,
              timeout=30)
    app._pump_store(reschedule=False)
    assert app.history.flush_now(10)
    c = app.history.counts()
    assert c["observations"] > 20 and c["site_ties"] >= 4 and \
        c["events"] > 0, c
    # a second, independent connection sees the same data (crash-safe)
    other = Store(PATHS.history_db, session_id=999)
    c2 = other.counts()
    other.stop(5)
    assert c2["observations"] >= c["observations"], (c, c2)
    app.data_mode = "idle"

