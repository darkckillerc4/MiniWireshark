@gui_test_step("redaction preview, shareable report and printable inventory")
def _gs_redaction(app, ctx):
    root = app.root
    ident = scenario_identity()
    m = app._new_model(identity=ident[:3])
    m.set_identity(local_nets=ident[3])
    app.replace_model(m)
    app.data_mode = "live"
    sink = app.lossless_sink()
    for raw, _ts, lt in ctx.frames():
        sink(raw, time.time(), lt)
    assert _gui_pump(root, 0.3, lambda: not len(app.ring) and
                     not app.worker.busy, timeout=30)
    full = ReportBuilder(app).build("full")
    w = app.redaction_preview("Shareable", full, "x.html", redact=True)
    _gui_pump(root, 0.2)
    out = w._mw_state["out"]
    for dev in m.registry.by_key.values():
        for o in (dev.ip, dev.mac):
            assert not o or o not in out, o
    for name in ("Alex-iPhone", "family-nas", "Living Room TV"):
        assert name.lower() not in out.lower(), name
    assert "<html" in out.lower()                  # still a valid document
    w._mw_on.set(False)
    w._mw_render()
    assert w._mw_state["out"] == full              # original untouched
    w.destroy()
    inv = app.inventory_document()
    assert "Alex-iPhone" in inv and "Device inventory" in inv
    w = app.redaction_preview("Inventory", inv, "inv.html", redact=False)
    _gui_pump(root, 0.1)
    w.destroy()
    app.data_mode = "idle"


