@gui_test_step("sources: add a Pi-hole, Reported lookups, secrets stay hidden")
def _gs_sources(app, ctx):
    root = app.root
    httpd, url, _calls, _t0 = _fake_helper("pihole")
    try:
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
        app.vault.path = ctx.path(f"vault_gui_{uuid.uuid4().hex[:6]}.json")
        app.vault.backend = "file"
        app.mode_ui_var.set("Advanced")
        app._on_ui_mode_change()
        tab = app._select_tab("sources")
        win = app.connector_dialog(kind="pihole")
        v = win._mw_vars
        v["url"].set(url)
        v["pw"].set("s3cret-Pw!")
        win._mw_test()
        assert _gui_pump(root, 0.1, lambda: "Connected" in
                         v["msg"].cget("text"), timeout=15), \
            v["msg"].cget("text")
        assert "plain http" in v["msg"].cget("text")      # honest warning
        win._mw_save()
        specs = app.config.get("connectors.list")
        assert len(specs) == 1 and "s3cret" not in json.dumps(
            app.config.data)
        app.connectors.poll_now()
        assert _gui_pump(root, 0.2, lambda: m.reported, timeout=20), \
            app.connectors.status
        tab.refresh()
        _gui_pump(root, 0.1)
        row = tab.tree.item("c:" + specs[0]["id"], "values")
        assert "Connected" in row[3], row
        assert "reported" in tab.recon.get("1.0", "end")
        rows = coverage_rows(app.model, "live", app.active_mode())
        assert any("Reported" in r[1] for r in rows)
        text = app.debug_bundle_text(masked=False)
        assert "s3cret-Pw!" not in text and "SID-123" not in text
        app.connector_remove(specs[0]["id"])
        assert not app.config.get("connectors.list")
        assert app.vault.get(specs[0]["id"]) is None
    finally:
        httpd.shutdown()
        for w in root.winfo_children():
            if isinstance(w, tk.Toplevel):
                w.destroy()
        app.mode_ui_var.set("Beginner")
        app._on_ui_mode_change()
        app.data_mode = "idle"


