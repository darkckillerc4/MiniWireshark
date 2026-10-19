@gui_test_step("network consent: new network is quiet until trusted")
def _gs_consent(app, ctx):
    root = app.root
    app.stop()
    app._leave_nonlive()
    app.data_mode = "live"
    app.config.set("mode.active_scanning", True)
    app._on_network_known("00:1e:58:aa:00:99", "10.9.9.0/24", "CafeWiFi", 0)
    assert app.network_profile and not app.network_profile["trusted"]
    assert not app.active_mode() and app.lan_scanner is None
    assert "Trust this network" in str(app.mode_toggle_btn.cget("text"))
    assert not app.health_checks_allowed()
    app.trust_network(True)
    assert app.active_mode()
    w = app.open_networks_dialog()
    _gui_pump(root, 0.2)
    w.destroy()
    app.trust_network(False)
    assert not app.active_mode()
    app._stop_lan_scanner()
    app.data_mode = "idle"
    app._restyle_mode_banner()


@gui_test_step("corrections: rename, merge, undo from the window")
def _gs_corrections(app, ctx):
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
    S = ScenarioBuilder
    reg = app.model.registry
    tv, nas = S.TV[1], S.NAS[1]
    app._apply_correction_result(app.model.correct_rename(tv, "Big TV"))
    assert reg.by_key[tv].alias == "Big TV"
    assert app.known.get(tv)["alias"] == "Big TV"
    before = reg.by_key[tv].bytes_up + reg.by_key[nas].bytes_up
    app.merge_devices_ui(tv, nas)
    keep = reg.resolve(nas)
    assert reg.resolve(tv) == reg.resolve(nas)
    assert reg.by_key[keep].bytes_up == before
    win = app.open_corrections()
    _gui_pump(root, 0.2)
    win.destroy()
    app.undo_last_correction()
    assert tv in reg.by_key and nas in reg.by_key
    app.undo_last_correction()
    assert reg.by_key[tv].alias == ""
    assert not (app.known.get(tv) or {}).get("alias")
    app.data_mode = "idle"

