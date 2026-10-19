@self_test()
def t_vantage_meter(ctx):
    vm = VantageMeter()
    me = {"aa:aa:aa:aa:aa:01"}
    base = {"multicast": False, "src_ip": "", "dst_ip": ""}
    for i in range(400):
        vm.note(dict(base, src_mac="aa:aa:aa:aa:aa:01",
                     dst_mac="bb:bb:bb:bb:bb:01"), me, set())
    assert vm.classify() == "endpoint"
    for i in range(3000):
        vm.note(dict(base, src_mac="cc:cc:cc:cc:cc:01",
                     dst_mac="bb:bb:bb:bb:bb:01"), me, set())
    assert vm.classify() == "mirror", vm.share_third()
    assert vm.classify(offline=True) == "file"
    assert VantageMeter().classify() == "unknown"


@self_test()
def t_claims_and_coverage(ctx):
    if not ctx.scapy_ok:
        return "skip"
    frames = ctx.frames()
    sb = ScenarioBuilder(t0=frames[-1][1] + 1)
    # traffic addressed to a device that never sends anything itself
    sb._emit(Ether(src=ScenarioBuilder.ME[1], dst="00:11:22:33:44:99") /
             IP(src=ScenarioBuilder.ME[0], dst="192.168.1.99") /
             UDP(sport=5000, dport=9) / Raw(b"x" * 20))
    m = scenario_model(ctx.cfg(), frames + sb.frames)
    S = ScenarioBuilder
    ph = m.registry.by_key[S.PHONE[1]]
    claims = device_claims(m, ph)
    by = {c[0]: c for c in claims}
    assert by["Is on your network"][2] == LV_OBSERVED
    assert by["Name"][2] == LV_OBSERVED and "DHCP" in by["Name"][3]
    assert by["Kind of device"][2] == LV_INFERRED
    obs = m.observations_for(ph.key, by["Name"][4])
    assert obs and all(o[5] for o in obs)
    heard = m.registry.by_key.get("00:11:22:33:44:99")
    assert heard is not None and heard.packets_out == 0
    assert device_claims(m, heard)[0][2] == LV_INFERRED
    for dv in m.registry.by_key.values():
        for c in device_claims(m, dv):
            assert c[2] in LEVEL_GLYPH, c
    rows = coverage_rows(m, "live", active=False)
    assert rows and all(r[2] in LEVEL_GLYPH for r in rows)
    assert any("https" in r[0] or "Full web" in r[0] for r in rows)
    assert "Silent devices (Quiet Mode sends no probes)" in \
        blind_spots(m, "live", active=False)


@self_test()
def t_change_digest(ctx):
    if not ctx.scapy_ok:
        return "skip"
    m = scenario_model(ctx.cfg(), ctx.frames())
    dg = change_digest(m, None, 0.0)
    S = ScenarioBuilder
    keys = {k for _t, k, _n in dg["new_devices"]}
    assert S.PHONE[1] in keys and S.LAPTOP[1] in keys
    assert S.ME[1] not in keys and S.GW[1] not in keys
    roots = {r for _t, r, _d, _a in dg["new_sites"]}
    assert {"example.com", "example.net", "example.org"} <= roots, roots
    assert digest_summary(dg).startswith(f"{len(keys)} new devices")
    late = change_digest(m, None, ctx.frames()[-30][1])
    assert {k for _t, k, _n in late["new_devices"]} == {S.LAPTOP[1]}, late
    assert digest_summary(change_digest(m, None, 9e12)) == "Nothing new."

