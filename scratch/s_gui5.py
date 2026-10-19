@gui_test_step("inspector, proof chips, coverage and changes")
def _gs_truth(app, ctx):
    root = app.root
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
    _gui_pump(root, 0.3)
    S = ScenarioBuilder
    app.toggle_inspector(True)
    dt = app._select_tab("devices")
    dt.rebuild()
    dt.select(S.PHONE[1])
    _gui_pump(root, 0.1)
    assert app.inspector.current == ("device", S.PHONE[1]), \
        app.inspector.current
    assert "Alex-iPhone" in app.inspector.title_var.get()
    body = app.inspector.txt.get("1.0", "end")
    assert "proof:" in body and "#" in body, body[:400]
    no = next(o[5] for o in app.model.observations_for(S.PHONE[1])
              if o[5])
    assert app.jump_to_packet(no), "proof chip did not open its packet"
    sel = app.tabs["packets"]._selected_row()
    assert sel and sel["no"] == no
    for kind, key in (("website", "www.example.com"),
                      ("remote", "93.184.215.14"),
                      ("flow", next(iter(app.model.flows.by_id))),
                      ("alert", next(iter(app.model.alerts.order)))):
        app.inspect(kind, key)
        assert app.inspector.current == (kind, key)
        assert app.inspector.txt.get("1.0", "end").strip()
    app.toggle_inspector()
    assert not app.inspector_visible
    app.toggle_inspector()
    assert app.inspector_visible
    app.open_coverage()
    app.open_changes("Last hour")
    _gui_pump(root, 0.2)
    for w in root.winfo_children():
        if isinstance(w, tk.Toplevel):
            w.destroy()
    assert "◉" in app.footer_text()
    app.mode_ui_var.set("Beginner")
    app._on_ui_mode_change()
    app.data_mode = "idle"

