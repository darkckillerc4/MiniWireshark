@self_test()
def t_sanitize_hostile_names(ctx):
    evil = "evil‮gnp.exe\x00\x1b[31m​name\nnext"
    out = sanitize_text(evil)
    assert all(ch.isprintable() for ch in out), repr(out)
    assert "‮" not in out and "\x1b" not in out and "\n" not in out
    assert sanitize_text("plain-name") == "plain-name"
    assert len(sanitize_text("x" * 999)) == 200
    assert sanitize_text(b"bytes\xff") .startswith("bytes")
    if not ctx.scapy_ok:
        return
    sb = ScenarioBuilder()
    host = ("192.168.1.77", "00:11:22:33:44:77", "pc‮cod.exe\x07")
    sb.dhcp(host)
    sb.mdns(host, "_ipp._tcp", "Prin⁦ter\x1b", {"ty": "x‮y"})
    m = scenario_model(ctx.cfg(), sb.frames)
    for dv in m.registry.by_key.values():
        for txt in (dv.display_name(), dv.dhcp_hostname, dv.mdns_name,
                    dv.model_hint):
            assert all(ch.isprintable() for ch in txt), repr(txt)


@self_test()
def t_npcap_signer_pin(ctx):
    good = "CN=Nmap Software LLC, O=Nmap Software LLC, L=Seattle, C=US"
    assert signer_matches(good, NPCAP_SIGNER)
    assert not signer_matches("CN=Evil Corp, O=Nmap Software LLC Fans",
                              NPCAP_SIGNER)
    assert not signer_matches("", NPCAP_SIGNER)
    assert not signer_matches("CN=Nmap Software LLC Ltd", NPCAP_SIGNER)
    assert _version_tuple(NPCAP_FALLBACK_VERSION) >= (1, 89)


@self_test()
def t_rogue_router_advertisement(ctx):
    if not ctx.scapy_ok:
        return "skip"
    frames = ctx.frames()
    sb = ScenarioBuilder(t0=frames[-1][1] + 5)
    sb._emit(Ether(src=ScenarioBuilder.PHONE[1], dst="33:33:00:00:00:01") /
             IPv6(src="fe80::d8a1:19ff:fe23:4567", dst="ff02::1") /
             ICMPv6ND_RA(routerlifetime=1800) /
             ICMPv6NDOptPrefixInfo(prefix="2a01:e0a:9999::", prefixlen=64) /
             ICMPv6NDOptSrcLLAddr(lladdr=ScenarioBuilder.PHONE[1]))
    m = scenario_model(ctx.cfg(), frames + sb.frames)
    kinds = [a for a in m.alerts.alerts.values() if a.kind == "rogue_ra"]
    assert len(kinds) == 1 and kinds[0].device_key == \
        ScenarioBuilder.PHONE[1], kinds
    m2 = scenario_model(ctx.cfg(), frames)
    assert not any(a.kind == "rogue_ra" for a in m2.alerts.alerts.values())


@self_test()
def t_iid_map_reverse_index(ctx):
    m = IidMap()
    m["a"] = "I1"
    m["b"] = "I2"
    m["a"] = "I3"
    assert key_for_iid(m, "I3") == "a" and key_for_iid(m, "I1") is None
    m.pop("b")
    assert key_for_iid(m, "I2") is None and m.pop("zz", None) is None
    m.clear()
    assert not m.rev
    ae = AlertEngine(ctx.cfg(), _FakeClock())
    for i in range(520):
        ae._add("new_device", "INFO", f"k{i}", "r", "o", "i", "p")
    assert len(ae.order) == 500 and len(ae.alerts) == 500
    assert ae.order[0] in ae.alerts


@self_test()
def t_reverse_dns_only_in_active_mode(ctx):
    src = inspect.getsource(MiniWireshark._drain_decoded)
    assert "mode.active_scanning" in src

