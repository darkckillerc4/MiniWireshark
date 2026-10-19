@gui_test_step("this computer: programs, listeners, ARP cache, ledger, kill switch")
def _gs_this_pc(app, ctx):
    root = app.root
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
    # programs: pretend the OS table names this computer's connections
    mine = [f for f in m.flows.all_flows() if f.local_ip in m.my_ips]
    assert mine, "the scenario has connections from this computer"
    pm = app.procmap
    pm.by_local = {(f.transport, f.local_ip, f.local_port): (4242,
                                                             "firefox.exe")
                   for f in mine}
    pm.listening = {("TCP", "0.0.0.0", 8000): (5151, "python.exe"),
                    ("TCP", "127.0.0.1", 5432): (99, "postgres.exe")}
    assert app.attribute_processes() >= 1
    assert all(f.process == "firefox.exe (pid 4242)" for f in mine
               if f.local_port is not None)
    rep = dict(app.device_report(m.registry.by_key[m.my_device_key()]))
    assert "firefox.exe" in rep["Programs using the network (this "
                               "computer)"]
    assert "python.exe" in rep["Programs accepting connections"]
    ct = app._select_tab("connections")
    ct.rebuild() if hasattr(ct, "rebuild") else None
    _gui_pump(root, 0.1)
    # ARP cache: the router's address points at another MAC → alert
    n0 = len(m.alerts.alerts)
    gw_mac = sorted(m.registry.gw_macs)[0]
    out = app.arp_cross_check([(m.gateway_ip, "02:66:66:66:66:66", "eth0"),
                               (m.gateway_ip, gw_mac, "eth0"),
                               ("192.168.1.201", "02:11:22:33:44:55",
                                "eth0")])
    assert len(out) == 1 and out[0][0] == m.gateway_ip
    assert len(m.alerts.alerts) == n0 + 1
    assert any(a.kind == "arp_cache_mismatch" and a.severity == "DANGER"
               for a in m.alerts.alerts.values())
    assert ("192.168.1.201", "02:11:22:33:44:55") in app.arp_cache_only()
    # security tab with listeners and a UPnP result
    app.upnp_result = {"upnp": True, "at": time.time(), "mappings": [
        {"Protocol": "TCP", "ExternalPort": "3389",
         "InternalClient": S_LAPTOP_IP, "InternalPort": "3389",
         "Enabled": "1", "PortMappingDescription": "RDP"}]}
    sec = app._select_tab("security")
    sec.refresh()
    body = sec.text.get("1.0", "end")
    assert "python.exe — TCP port 8000" in body, body[-800:]
    assert "Remote Desktop" in body and "3389" in body
    # ledger + kill switch
    w = app.open_ledger()
    _gui_pump(root, 0.2)
    app.config.set("privacy.kill_switch", True)
    app._apply_runtime_settings()
    assert LEDGER.killed and not app.active_mode()
    app._restyle_mode_banner()
    assert "KILL SWITCH" in app.mode_lbl.cget("text")
    assert not app.run_upnp_audit()                  # refused, nothing sent
    app._kill_switch_off()
    assert not LEDGER.killed
    w.destroy()
    for win in root.winfo_children():
        if isinstance(win, tk.Toplevel):
            win.destroy()
    app.upnp_result = None
    app.data_mode = "idle"
    app._restyle_mode_banner()


S_LAPTOP_IP = "192.168.1.50"


