@gui_test_step("map v3: 300 devices, fast pan/zoom, drag, keyboard, list twin")
def _gs_map3(app, ctx):
    root = app.root
    m = app._new_model(identity=("10.20.0.1", {"10.20.0.10"},
                                 {"02:00:00:00:00:0a"}))
    m.set_identity(local_nets=[ipaddress.ip_network("10.20.0.0/16")])
    now = time.time()
    for i in range(300):
        ip = f"10.20.{1 + i // 200}.{2 + i % 200}"
        mac = f"02:aa:00:00:{i >> 8:02x}:{i & 255:02x}"
        d = m.registry.touch(ip, mac, "arp_reply", "synthetic", now)
        d.type = ("phone", "computer", "tv", "iot", "printer")[i % 5]
    app.replace_model(m)
    app.mode_ui_var.set("Advanced")
    app._on_ui_mode_change()
    root.geometry("1400x900")
    tab = app._select_tab("map")
    _gui_pump(root, 0.3)
    t0 = time.perf_counter()
    tab.redraw(force=True)
    root.update_idletasks()
    full = (time.perf_counter() - t0) * 1000
    nodes = {v[1] for v in tab.nodes.values() if v[0] == "device"}
    assert len(nodes) == 300, len(nodes)
    times = []
    for i in range(20):
        t0 = time.perf_counter()
        tab._fast_pan(5, 3)
        root.update_idletasks()
        times.append((time.perf_counter() - t0) * 1000)
    t0 = time.perf_counter()
    tab._fast_zoom(1.1)
    root.update_idletasks()
    zoom_ms = (time.perf_counter() - t0) * 1000
    worst = sorted(times)[-2]
    print(f"      (300 devices: full draw {full:.0f} ms, pan frame "
          f"{worst:.1f} ms, zoom frame {zoom_ms:.1f} ms)")
    assert worst <= 16 and zoom_ms <= 16, (worst, zoom_ms)
    _gui_pump(root, 0.3)                       # the debounced redraw
    # drag one device and it stays where it was put
    key = sorted(nodes)[0]
    x, y = tab.P(*tab._pos[key])
    tab._press(type("E", (), {"x": int(x), "y": int(y)})())
    tab._motion(type("E", (), {"x": int(x) + 60, "y": int(y) + 40})())
    tab._release(type("E", (), {"x": int(x) + 60, "y": int(y) + 40})())
    saved = tab._positions_store()
    assert key in saved, saved
    tab.redraw(force=True)
    nx, ny = tab.P(*tab._pos[key])
    assert abs(nx - (x + 60)) < 3 and abs(ny - (y + 40)) < 3, (nx, ny, x, y)
    tab.forget_positions()
    assert key not in tab._positions_store()
    # keyboard: Tab selects, Enter opens
    ev = type("E", (), {"keysym": "Tab", "state": 0})()
    assert tab._key(ev) == "break" and tab.selected
    # the list twin shows the same devices, with how each one connects
    assert tab.toggle_list()
    _gui_pump(root, 0.1)
    rows = tab.list_tree.get_children()
    assert len(rows) == 300
    via = tab.list_tree.set(rows[0], "via")
    assert "logical" in via, via
    assert not tab.toggle_list()
    app.mode_ui_var.set("Beginner")
    app._on_ui_mode_change()


