@gui_test_step("V5 startup: notice, startup history, managed-Python choice")
def _gs_v5_startup(app, ctx):
    root = app.root
    win = tk.Toplevel(root)
    lw = LoaderWindow(win, app.config)
    lw.pack(fill="both", expand=True)
    win.after(300, lambda: lw._choose("exit"))
    choice = lw.show_welcome("summary", "degraded", False,
                             notice="⚠ test notice")
    assert choice == "exit", choice
    assert lw.notice_lbl.cget("text") == "⚠ test notice"
    win.destroy()
    old = globals()["BOOT_DIR"]
    globals()["BOOT_DIR"] = ctx.path("boot_hist")
    try:
        r = BootReceipt()
        r.step("window", True, "Tk")
        r.step("main window", False, error=ValueError("boom"))
        r.mark(outcome="fatal")
        w = app.open_boot_history()
        _gui_pump(root, 0.2)
        assert "boom" in w._mw_text and "fatal" in w._mw_text, w._mw_text
        w.destroy()
        assert "Startup history" in app.debug_bundle_text()
    finally:
        globals()["BOOT_DIR"] = old
    rm = app.open_runtime_manager()
    _gui_pump(root, 0.3)
    assert app._rm_pref.get() is False
    rm.destroy()
    assert "Private packages folder" in app.runtime_status_text()


