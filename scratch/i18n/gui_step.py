def _all_widgets(root):
    out, stack = [], [root]
    while stack:
        w = stack.pop()
        out.append(w)
        with contextlib.suppress(tk.TclError):
            stack.extend(w.winfo_children())
    return out


@gui_test_step("languages: switch to French and Spanish and back")
def _gs_languages(app, ctx):
    tab = app.tabs["dash"]
    english = app.nb.tab(tab.frame, "text")
    mode = app.mode_ui_var.get()
    try:
        app.config.set("general.language", "Français")
        app._apply_runtime_settings()
        _gui_pump(app.root, 0.3)
        fr = app.nb.tab(tab.frame, "text")
        assert "Tableau de bord" in fr, fr
        assert app.start_btn.cget("text").endswith("Commencer à observer")
        # a drop-down shows French while the program keeps English values
        assert app.mode_ui_var.get() == mode
        boxes = [w for w in _all_widgets(app.root)
                 if getattr(w, "_mw_i18n", None) and
                 w._mw_i18n["var"] is app.mode_ui_var]
        assert boxes and boxes[0].get() == translate_text(mode, "fr"), \
            boxes and boxes[0].get()
        # a status line set later is shown in French too
        app.status_var.set("Ready. Click “Start watching” when you'd like "
                           "to begin.")
        assert app.status_var.get().startswith("Prêt."), \
            app.status_var.get()
        app.config.set("general.language", "Español")
        app._apply_runtime_settings()
        _gui_pump(app.root, 0.3)
        assert "Panel" in app.nb.tab(tab.frame, "text")
        assert boxes[0].get() == translate_text(mode, "es")
    finally:
        app.config.set("general.language", "English")
        app._apply_runtime_settings()
        _gui_pump(app.root, 0.3)
    assert app.nb.tab(tab.frame, "text") == english
    assert boxes[0].get() == mode and app.mode_ui_var.get() == mode
    assert CURRENT_LOCALE == "en"


