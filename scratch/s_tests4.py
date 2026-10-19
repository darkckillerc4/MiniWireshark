@self_test()
def t_ip_reuse_keeps_histories_apart(ctx):
    if not ctx.scapy_ok:
        return "skip"
    m = scenario_model(ctx.cfg(), ctx.frames())
    S = ScenarioBuilder
    hist = m.registry.bindings.history(S.PRINTER[0])
    owners = [h[0] for h in hist]
    assert owners[:1] == [S.PRINTER[1]] and owners[-1] == S.LAPTOP[1], hist
    assert hist[0][2] is not None and hist[-1][2] is None
    t_mid = hist[0][1] + 1
    assert m.registry.bindings.owner_at(S.PRINTER[0], t_mid) == S.PRINTER[1]
    assert m.registry.bindings.owner_at(S.PRINTER[0], hist[-1][1] + 1) == \
        S.LAPTOP[1]
    pr = m.registry.by_key[S.PRINTER[1]]
    lap = m.registry.by_key[S.LAPTOP[1]]
    assert S.PRINTER[0] not in pr.ipv4s and lap.ip == S.PRINTER[0]
    assert "www.example.com" in lap.websites and \
        "www.example.com" not in pr.websites


@self_test()
def t_corrections_merge_split_undo_exact(ctx):
    clk = _FakeClock()
    reg = DeviceRegistry("", [], ctx.cfg(), clk)
    m = NetworkModel(ctx.cfg(), now_fn=clk)
    m.registry = reg
    a = reg.note_traffic("192.168.1.30", "da:00:00:00:00:01", 100, "TLS",
                         "sent", True)
    reg._set_dhcp_hostname(a, "Alexs-Phone", clk.t)
    clk.t += 50
    b = reg.note_traffic("192.168.1.31", "da:00:00:00:00:02", 200, "TLS",
                         "sent", True)
    m.correct_rename(b.key, "Kitchen tablet")
    keys = m.correct_merge(a.key, b.key)
    assert keys == [a.key] and b.key not in reg.by_key
    # traffic from the absorbed address lands on the kept device
    clk.t += 10
    d = reg.note_traffic(None, "da:00:00:00:00:02", 300, "TLS", "sent", True)
    assert d is a and a.bytes_up == 600 and a.alias == "Kitchen tablet"
    keys = m.undo_correction()            # undo the merge
    nb = reg.by_key[b.key]
    assert nb.bytes_up == 500 and a.bytes_up == 100, (nb.bytes_up,
                                                      a.bytes_up)
    assert a.alias == "" and nb.alias == "Kitchen tablet"
    assert reg.resolve(b.key) == b.key
    assert m.undo_correction() and nb.alias == ""          # undo rename
    assert m.undo_correction() == []                       # nothing left


@self_test(slow=True)
def t_corrections_property(ctx):
    """Random merge / split / undo sequences: every packet stays counted
    exactly once and every hardware address belongs to one device."""
    rng = random.Random(1234)
    for trial in range(300):
        clk = _FakeClock()
        m = NetworkModel(ctx.cfg(), now_fn=clk)
        reg = m.registry
        macs = [f"da:00:00:00:{trial % 256:02x}:{i:02x}" for i in range(5)]
        total = 0
        for i, mac in enumerate(macs):
            reg.note_traffic(f"10.0.{trial % 200}.{i + 2}", mac, 10 * (i + 1),
                             "TCP", "sent", False)
            total += 10 * (i + 1)
        for _step in range(12):
            op = rng.random()
            keys = list(reg.by_key)
            if op < 0.4 and len(keys) >= 2:
                x, y = rng.sample(keys, 2)
                m.correct_merge(x, y)
            elif op < 0.65:
                cands = [k for k in keys if reg.by_key[k].merge_history]
                if cands:
                    k = rng.choice(cands)
                    m.correct_split(k, rng.randrange(
                        len(reg.by_key[k].merge_history)))
            elif op < 0.9:
                m.undo_correction()
            else:
                mac = rng.choice(macs)
                clk.t += 1
                reg.note_traffic(None, mac, 7, "TCP", "sent", False)
                total += 7
            counted = sum(dv.bytes_up for dv in reg.by_key.values())
            assert counted == total, (trial, counted, total)
            owners = Counter(reg.resolve(mac) for mac in macs)
            for mac in macs:
                assert reg.resolve(mac) in reg.by_key, (trial, mac)
            for dv in reg.by_key.values():
                assert sum(st.get("bytes_up", 0) for st in
                           dv.iface_stats.values()) == dv.bytes_up
            assert sum(owners.values()) == len(macs)


@self_test()
def t_rotation_linker_client_id(ctx):
    clk = _FakeClock()
    reg = DeviceRegistry("", [], ctx.cfg(), clk)
    a = reg.touch("192.168.1.40", "da:00:00:00:00:41", "mac_local", "x")
    b = reg.touch("192.168.1.41", "da:00:00:00:00:42", "mac_local", "x")
    for dv in (a, b):
        dv.dhcp_hostname = "kitchen-ipad"
        dv.dhcp_client_id = "ff00112233445566"
    a.presence = [[clk.t - 900, clk.t - 800]]
    b.presence = [[clk.t - 100, None]]
    c = reg.merge_candidates(b)
    assert c and any("client identifier" in r for r in c[0][2]), c
    a.dhcp_client_id = "01" + a.mac.replace(":", "")
    b.dhcp_client_id = "01" + b.mac.replace(":", "")
    assert not reg.same_client_id(a, b)        # MAC-derived: no evidence
    a.network_id, b.network_id = "net1", "net2"
    c = reg.merge_candidates(b)
    assert not c or c[0][1] == "Low"


@self_test()
def t_network_profiles_and_consent(ctx):
    np_ = NetworkProfiles(ctx.path("nets.json"))
    assert np_.fresh_install
    fp = network_fingerprint("00:1e:58:aa:00:01", "192.168.1.0/24")
    assert fp == network_fingerprint("00:1E:58:AA:00:01", "192.168.1.0/24")
    assert fp != network_fingerprint("00:1e:58:aa:00:01", "10.0.0.0/24")
    prof, new = np_.seen(fp, "00:1e:58:aa:00:01", "192.168.1.0/24", "Home")
    assert new and not prof["trusted"] and prof["name"] == "Home"
    np_.set_trusted(fp, True)
    again = NetworkProfiles(ctx.path("nets.json"))
    assert not again.fresh_install and again.get(fp)["trusted"]
    prof2, new2 = again.seen(fp, "00:1e:58:aa:00:01", "192.168.1.0/24", "")
    assert not new2 and prof2["visits"] == 2

    class FakeApp:
        config = ctx.cfg({"mode.active_scanning": True})
        network_profile = None
    fa = FakeApp()
    assert not MiniWireshark.active_mode(fa)          # unknown → quiet
    fa.network_profile = {"trusted": False}
    assert not MiniWireshark.active_mode(fa)          # new network → quiet
    fa.network_profile = {"trusted": True}
    assert MiniWireshark.active_mode(fa)
    fa.config.set("mode.active_scanning", False)
    assert not MiniWireshark.active_mode(fa)


def _golden_identity(model):
    S = ScenarioBuilder
    ph = model.registry.by_key.get(S.PHONE[1])
    if ph is None or not ph.dhcp_client_id:
        return "phone DHCP client id not recorded"
    if sum(st.get("bytes_up", 0) for st in ph.iface_stats.values()) != \
            ph.bytes_up:
        return "per-address counters disagree with device totals"
    return None


GOLDEN_EXTRA.append(_golden_identity)

