@gui_test_step("packet history, virtual table, saved timeline, compare")
def _gs_history_v2(app, ctx):
    root = app.root
    S = ScenarioBuilder
    old_max = app.config.get("capture.max_stored_events", 5000)
    app.config.set("capture.max_stored_events", 500)
    app.config.set("history.packet_ring", True)
    app._apply_runtime_settings()
    assert app.max_rows == 500 and app.packet_ring is not None
    ident = scenario_identity()
    m = app._new_model(identity=ident[:3])
    m.set_identity(local_nets=ident[3])
    app.replace_model(m)
    app.data_mode = "live"
    app._pump_store(reschedule=False)
    app.mode_ui_var.set("Advanced")
    app._on_ui_mode_change()
    tab = app._select_tab("packets")
    frames = S().busy_mix(1500)
    sink = app.lossless_sink()
    for raw, _ts, lt in frames:
        sink(raw, time.time(), lt)
    assert _gui_pump(root, 0.3, lambda: not len(app.ring) and
                     not app.worker.busy and app.count >= len(frames),
                     timeout=60), app.count
    _gui_pump(root, 0.2)
    assert len(app.all_rows) == 500
    # ---- virtual table: only the visible rows are Treeview items
    tab.rebuild()
    _gui_pump(root, 0.1)
    n = tab._nslots()
    kids = tab.tree.get_children()
    assert len(tab.matched) == 500, len(tab.matched)
    assert 0 < len(kids) <= n + 1 < 120, (len(kids), n)
    first_in_mem = app.all_rows[0]["no"]
    target = app.all_rows[200]["no"]
    assert tab.select_no(target) and tab._selected_row()["no"] == target
    assert not tab.follow_var.get()

    class Ev:
        def __init__(self, keysym="", num=0, delta=0):
            self.keysym, self.num, self.delta = keysym, num, delta
    tab._key(Ev("Down"))
    assert tab.sel_no == app.all_rows[201]["no"], (tab.sel_no, target)
    tab._key(Ev("End"))
    assert tab.sel_no == app.all_rows[-1]["no"]
    vis = {tab.slot_rows[i]["no"] for i in tab.tree.get_children()}
    assert tab.sel_no in vis
    tab._key(Ev("Home"))
    assert tab.top == 0 and tab.sel_no == first_in_mem
    top0 = tab.top
    tab._wheel(Ev(num=5))
    assert tab.top == top0 + 3, tab.top
    tab._yscroll("moveto", "0.5")
    assert abs(tab.top - 250) <= n, tab.top
    tab._yscroll("scroll", "1", "pages")
    lo, hi = tab.vbar.get()
    assert 0 < lo < hi <= 1.0
    tab._sort_by("length")
    lens = [d["length"] for d in tab.matched]
    assert lens == sorted(lens)
    tab._sort_by("length")
    assert [d["length"] for d in tab.matched] == sorted(lens, reverse=True)
    tab._sort_by("no")
    assert tab.sort_col is None
    nos = [d["no"] for d in tab.matched]
    assert nos == sorted(nos)
    tab.set_expression("proto:dns")
    assert tab.matched and all(d["proto"] in ("DNS", "mDNS", "LLMNR")
                               or "dns" in d["proto"].lower()
                               for d in tab.matched[:50]), \
        {d["proto"] for d in tab.matched}
    tab.clear_filter()
    assert len(tab.matched) == 500
    # ---- the proof behind a claim, after it left memory: from disk
    assert app.packet_ring.flush()
    before = {str(w) for w in root.winfo_children()}
    assert app.jump_to_packet(10), "packet #10 should come from disk"
    _gui_pump(root, 0.1)
    new = [w for w in root.winfo_children() if str(w) not in before and
           isinstance(w, tk.Toplevel)]
    assert new and "Packet #10" in new[0].title(), [w.title() for w in new]
    for w in new:
        w.destroy()
    got = app.packet_ring.find(10)
    assert got is not None and got[0] == frames[9][0]
    assert app.jump_to_packet(target) and tab._selected_row()["no"] == target
    # ---- the saved timeline (SQL-backed, paged)
    app._pump_store(reschedule=False)
    assert app.history.flush_now(10)
    tl = app._select_tab("timeline")
    tl.source_var.set("Saved history")
    tl._on_source()
    _gui_pump(root, 0.1)
    assert tl.history_mode() and tl.tree.get_children(), \
        tl.status_lbl.cget("text")
    assert "saved events" in tl.status_lbl.cget("text")
    assert tl.zoom_var.get() in tl.HISTORY_ZOOMS
    tl.type_var.set("Websites")
    tl.rebuild()
    for iid in tl.tree.get_children()[:20]:
        assert tl.tree.set(iid, "kind") in ("website",), tl.tree.set(iid)
    tl.type_var.set("All types")
    tl.rebuild()
    tl.tree.selection_set(tl.tree.get_children()[0])
    tl._on_double()
    _gui_pump(root, 0.1)
    tl.load_older()
    tl.source_var.set("This session")
    tl._on_source()
    assert not tl.history_mode() and tl.zoom_var.get() in tl.LIVE_ZOOMS
    # ---- compare two sessions
    other = Store(PATHS.history_db, session_id=app.session_id - 3600,
                  meta={"source": "live"})
    other.write_observations([(1, time.time() - 3600, "dhcp_request",
                               "02:00:00:00:00:77", {"hostname": "Old-TV"},
                               1)])
    assert other.flush_now(10)
    other.stop(5)
    w = app.open_compare()
    assert w is not None
    _gui_pump(root, 0.1)
    w.destroy()
    ss = store_sessions(app.history)
    mine = next(x for x in ss if x["id"] == app.session_id)
    older = next(x for x in ss if x["id"] == app.session_id - 3600)
    res = app.show_compare(older, mine)
    assert "02:00:00:00:00:77" in res["gone_devices"], res["gone_devices"]
    assert res["new_devices"], res
    _gui_pump(root, 0.1)
    for w in root.winfo_children():
        if isinstance(w, tk.Toplevel):
            w.destroy()
    # ---- export of the current view uses the virtual table's rows
    assert len(tab.matched) == 500
    # ---- turn things back off
    app.config.set("history.packet_ring", False)
    app.config.set("capture.max_stored_events", old_max)
    app._apply_runtime_settings()
    assert app.packet_ring is None
    app.mode_ui_var.set("Beginner")
    app._on_ui_mode_change()
    app.data_mode = "idle"


