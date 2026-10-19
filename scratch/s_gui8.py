@gui_test_step("diagnostics depth: Wi-Fi culprit, switch port, HTTP/3 names")
def _gs_diag_depth(app, ctx):
    root = app.root
    ident = scenario_identity()
    m = app._new_model(identity=ident[:3])
    m.set_identity(local_nets=ident[3])
    app.replace_model(m)
    app.data_mode = "live"
    sink = app.lossless_sink()
    t = time.time()
    frames = list(ctx.frames()) + [(_lldp_frame(), t, 1)] + \
        _quic_frames("h3.example.com", t0=t)
    for raw, _ts, lt in frames:
        sink(raw, time.time(), lt)
    assert _gui_pump(root, 0.3, lambda: not len(app.ring) and
                     not app.worker.busy, timeout=30)
    app.wifi.last = parse_netsh_wlan(NETSH_EN)       # -78 dBm
    app.wifi.at = time.time() + 3600                 # no real probe now
    res = app.health_summary()
    assert res["wifi"][0] == "Needs attention", res["wifi"]
    assert app.health_culprit == "wifi"
    assert "Likely culprit: Wi-Fi" in res["overall"][1], res["overall"]
    assert res["switch"][0] == "Healthy" and "core-sw1" in res["switch"][1]
    tab = app._select_tab("health")
    tab.refresh()
    _gui_pump(root, 0.2)
    _st, ex, row = tab.rows["wifi"]
    assert "-78 dBm" in ex.cget("text")
    assert int(str(row.cget("highlightthickness"))) == 2
    assert "core-sw1" in app.connection_info_text()
    w = app.model.websites.get("h3.example.com")
    assert w is not None and "QUIC first packet" in w.sources
    ws = app._select_tab("websites")
    ws.refresh()
    _gui_pump(root, 0.1)
    app.show_website("h3.example.com")
    _gui_pump(root, 0.1)
    for win in root.winfo_children():
        if isinstance(win, tk.Toplevel):
            win.destroy()
    app.wifi.last = None
    app.wifi.at = 0.0
    app.data_mode = "idle"


