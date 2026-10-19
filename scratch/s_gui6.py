@gui_test_step("installer consent and Welcome Center (loader)")
def _gs_loader(app, ctx):
    root = app.root
    win = tk.Toplevel(root)
    lw = LoaderWindow(win, app.config)
    lw.pack(fill="both", expand=True)
    got = []
    th = threading.Thread(target=lambda: got.append(
        lw.ask("consent", text="test")), daemon=True)
    th.start()
    ok = _gui_pump(win, 0.1, lambda: bool(lw.card.winfo_children()),
                   timeout=5) if False else None
    t_end = time.time() + 5
    btn = None
    while time.time() < t_end and btn is None:
        lw.pump()
        for w in lw.card.winfo_children():
            for b in w.winfo_children():
                for bb in b.winfo_children():
                    if isinstance(bb, ttk.Button) and \
                            "current Python" in str(bb.cget("text")):
                        btn = bb
        time.sleep(0.02)
    assert btn is not None, "consent card not shown"
    btn.invoke()
    th.join(3)
    assert got == ["this"], got
    lw.runtime_progress("Download", 0.5, "x", {"speed": 2e6, "eta": 12})
    lw.runtime_progress("Verify", 1.0, "ok", {})
    lw.pump()
    assert lw.stage_state["Download"] in ("active", "done")
    assert "MB/s" in lw.speed_var.get() or lw.speed_var.get() == ""
    win.after(300, lambda: lw._choose("demo"))
    choice = lw.show_welcome("summary", "healthy", True)
    assert choice == "demo", choice
    win.destroy()


@gui_test_step("repair, runtime manager, debug bundle, quick start")
def _gs_repair(app, ctx):
    root = app.root
    w = app.repair_everything()
    ok = _gui_pump(root, 0.2, lambda: getattr(app, "last_repair", None)
                   is not None, timeout=300)
    assert ok, "repair did not finish"
    res = {k: (st, msg) for k, st, msg in app.last_repair[1]}
    assert set(res) == {k for k, _t in REPAIR_STEPS}, res
    assert res["settings"][0] in ("ok", "fixed"), res
    assert res["history"][0] in ("ok", "fixed", "skipped"), res
    assert res["selftest"][0] == "ok", res["selftest"]
    with contextlib.suppress(tk.TclError):
        w.destroy()
    rm = app.open_runtime_manager()
    _gui_pump(root, 0.3)
    assert "Python" in app.runtime_status_text()
    rm.destroy()
    text = app.debug_bundle_text(masked=True)
    assert "192.168.1.23" not in text and "debug bundle" in text
    b = app.export_debug_bundle()
    _gui_pump(root, 0.2)
    b.destroy()
    q = app.open_quick_start()
    _gui_pump(root, 0.2)
    q.destroy()
    app._open_settings()
    _gui_pump(root, 0.2)
    app._settings_win.show_page("diagnostics")
    _gui_pump(root, 0.2)
    app._settings_win.win.destroy()

