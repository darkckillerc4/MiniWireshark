@gui_test_step("investigations, episodes and regular check-ins")
def _gs_investigate(app, ctx):
    root = app.root
    S = ScenarioBuilder
    ident = scenario_identity()
    m = app._new_model(identity=ident[:3])
    m.set_identity(local_nets=ident[3])
    app.replace_model(m)
    app.data_mode = "live"
    b = S()
    b.t = time.time()
    for _ in range(13):
        b.t += 60
        b.tls(S.PLUG, "cloud.example.net", "52.1.2.3", size=600)
    sink = app.lossless_sink()
    for raw, _ts, lt in ctx.frames():
        sink(raw, time.time(), lt)
    m.use_packet_clock = True                 # replay the check-ins in time
    for raw, ts, lt in b.frames:
        sink(raw, ts, lt)
    assert _gui_pump(root, 0.3, lambda: not len(app.ring) and
                     not app.worker.busy, timeout=30)
    app.wifi.last = {"rssi": -80.0, "ssid": "Home"}
    app.wifi.at = time.time() + 3600
    w = app.investigate("slow")
    _gui_pump(root, 0.2)
    hyps = w._mw_result["hyps"]
    assert hyps[0]["key"] == "wifi", [h["key"] for h in hyps]
    assert "Weak Wi-Fi" in w._mw_result["text"]
    w.destroy()
    w = app.investigate("bandwidth")
    _gui_pump(root, 0.2)
    assert w._mw_result["bw"]["conclusion"]
    w.destroy()
    plug = m.device_for(S.PLUG[0], S.PLUG[1])
    rep = dict(app.device_report(plug))
    assert "about every 60 s" in rep.get("Regular check-ins (repeating "
                                         "connections)", ""), rep.keys()
    tl = app._select_tab("timeline")
    m.push_timeline("device back", "INFO", "a back")
    m.push_timeline("device back", "INFO", "b back")
    m.push_timeline("device back", "INFO", "c back")
    tl.episodes_var.set(True)
    tl.rebuild()
    _gui_pump(root, 0.1)
    vals = [tl.tree.item(i, "values") for i in tl.tree.get_children()]
    assert any(v[0] == "▸ Episode" and "(re)joined" in v[3] for v in vals), \
        vals[:5]
    tl.episodes_var.set(False)
    tl.rebuild()
    app.wifi.last = None
    app.wifi.at = 0.0
    app.data_mode = "idle"


