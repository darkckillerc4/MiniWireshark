@self_test()
def t_narratives_cannot_overclaim(ctx):
    """The M11 gate: a sentence never states a claim above its evidence
    level, and a sentence with missing data is not written at all."""
    t = narrate("connections", device=C("TV", LV_OBSERVED),
                count=C(14, LV_OBSERVED),
                destination=C("video.example.net", LV_OBSERVED),
                duration=C("2 minutes", LV_OBSERVED))
    assert t == "◉ TV made 14 connections to video.example.net over " \
                "2 minutes.", t
    t = narrate("connections", device=C("TV", LV_OBSERVED),
                count=C(14, LV_OBSERVED),
                destination=C("video.example.net", LV_CORRELATED),
                duration=C("2 minutes", LV_OBSERVED))
    assert t.startswith("◎ TV appears to have made"), t
    t = narrate("connections", device=C("TV", LV_REPORTED),
                count=C(3, LV_REPORTED), destination=C("x.example",
                                                      LV_REPORTED),
                duration=C("1 hour", LV_OBSERVED))
    assert "was reported to make" in t and t.startswith("◈"), t
    # an Inferred claim in a slot that only takes Observed/Reported facts
    for key, slot in (("connections", "count"), ("program", "program"),
                      ("periodic", "repeats"), ("bandwidth", "amount")):
        tpl = NARRATIVES[key]
        claims = {s_: C("x", next(iter(lv))) for s_, lv in
                  tpl.slots.items()}
        claims[slot] = C("x", LV_INFERRED)
        try:
            tpl.render(**claims)
            raise AssertionError(f"{key}.{slot} accepted an Inferred claim")
        except NarrativeRefused:
            pass
    assert narrate("connections", device=C("TV", LV_OBSERVED),
                   count=C(None, LV_OBSERVED),
                   destination=C("x", LV_OBSERVED),
                   duration=C("1 s", LV_OBSERVED)) is None
    try:
        narrate("shape", shape=C("streaming", LV_OBSERVED),
                detail=C("6 Mbit/s", LV_OBSERVED))
        raise AssertionError("a flow-shape guess was stated as observed")
    except NarrativeRefused:
        pass
    assert narrate("shape", shape=C("streaming", LV_INFERRED),
                   detail=C("6 Mbit/s", LV_OBSERVED)).startswith("◌")


@self_test()
def t_periodicity_and_episodes(ctx):
    rng = random.Random(4)
    starts = [1000 + i * 60 + rng.uniform(-2, 2) for i in range(15)]
    got = detect_periodic(starts)
    assert got and 55 < got[0] < 65 and got[1] == 14, got
    assert detect_periodic([1000 + rng.uniform(0, 3000) for _ in
                            range(15)]) is None
    assert detect_periodic(starts[:8]) is None             # too few
    assert human_period(60) == "60 s" and human_period(300) == "5 min"
    if ctx.scapy_ok:
        S = ScenarioBuilder
        b = S()
        b.t = ctx.frames()[-1][1] + 5
        for i in range(13):                 # the plug phones home each 60 s
            b.t += 60
            b.tls(S.PLUG, "cloud.example.net", "52.1.2.3", size=600)
        m = scenario_model(ctx.cfg(), ctx.frames() + b.frames)
        per = periodic_findings(m)
        plug = m.device_for(S.PLUG[0], S.PLUG[1])
        mine = [r for r in per if r[0] == plug.key]
        assert mine and "about every 60 s" in mine[0][4], per
        assert mine[0][4].startswith("◎")        # Correlated, not Observed
    ev = ([{"when": 100 + i, "kind": "device back", "text": f"d{i} back",
            "severity": "INFO"} for i in range(4)] +
          [{"when": 1000, "kind": "website", "text": "First visit",
            "severity": "INFO", "device": "a"}] +
          [{"when": 3000 + i * 5, "kind": "device left",
            "text": f"x{i} left", "severity": "INFO"} for i in range(3)])
    eps = build_episodes(ev)
    assert [e["rule"] for e in eps] == ["reconnect_wave", "drop_wave"], eps
    assert "4 devices (re)joined" in eps[0]["headline"]
    assert eps[0]["level"] == LV_INFERRED and "router" in eps[0]["cause"]


@self_test()
def t_investigations_reach_planted_cause(ctx):
    base = {"vantage": "endpoint", "dns_n": 40, "dns_median_ms": 20,
            "dns_fail_rate": 0.0, "rtt_n": 20, "rtt_median_ms": 25,
            "tcp_packets": 5000, "retrans_pct": 0.005,
            "health": {"gateway_ok": True, "gateway_ms": 3},
            "wifi": {"rssi": -52}}

    def top(**over):
        f = dict(base, **over)
        return investigate_slow(f)[0]
    h = top(wifi={"rssi": -80}, retrans_pct=0.09)
    assert h["key"] == "wifi" and h["status"] == "Likely", h
    h = top(dns_median_ms=1200)
    assert h["key"] == "dns" and h["status"] == "Likely", h
    h = top(health={"gateway_ok": False})
    assert h["key"] == "router", h
    h = top(rtt_median_ms=340)
    assert h["key"] == "isp" and h["status"] == "Likely", h
    h = top(this_pc_top=[("steam.exe (pid 9)", 9e6)])
    assert h["key"] == "local_hog" and "steam.exe" in h["title"], h
    h = top()
    assert h["key"] == "cant_tell", h          # nothing visible explains it
    hyps = investigate_slow(dict(base))
    assert any(x["key"] == "other_hog" and x["status"] == "Can't tell"
               for x in hyps)                  # blind spot stated
    # evidence lines that use narratives carry their level glyph
    h = top(this_pc_top=[("steam.exe (pid 9)", 9e6)])
    assert h["for"][0].startswith("◉")
    # bandwidth: honest about the vantage point
    bw = investigate_bandwidth({"devices": [("Laptop", 9e6, LV_OBSERVED)],
                                "vantage": "endpoint", "unattributed": 0})
    assert "Can't tell from here" in bw["conclusion"]
    bw = investigate_bandwidth({"devices": [("TV", 90e6, LV_OBSERVED),
                                            ("Phone", 5e6, LV_OBSERVED)],
                                "vantage": "mirror", "unattributed": 30e6,
                                "window_text": "10 min"})
    assert bw["conclusion"].startswith("TV is using the most"), bw
    assert "couldn't be tied" in bw["conclusion"]
    assert bw["rows"][0].startswith("◉ TV used")
    # on a scripted replay: slow DNS answers are the planted cause
    if not ctx.scapy_ok:
        return
    S = ScenarioBuilder
    fr = []
    t = ctx.frames()[-1][1] + 5
    for i in range(12):
        q = Ether(src=S.ME[1], dst=S.GW[1]) / IP(src=S.ME[0],
                                                  dst=S.GW[0]) / \
            UDP(sport=50000 + i, dport=53) / DNS(id=900 + i, rd=1, qd=DNSQR(
                qname=f"s{i}.example.com"))
        a = Ether(src=S.GW[1], dst=S.ME[1]) / IP(src=S.GW[0], dst=S.ME[0]) \
            / UDP(sport=53, dport=50000 + i) / DNS(
                id=900 + i, qr=1, qd=DNSQR(qname=f"s{i}.example.com"),
                an=DNSRR(rrname=f"s{i}.example.com", rdata="93.184.215.14"))
        fr += [(bytes(q), t + i * 2, 1), (bytes(a), t + i * 2 + 1.3, 1)]
    m = scenario_model(ctx.cfg(), ctx.frames() + fr)
    f = slow_facts(m, wifi={"rssi": -50},
                   health={"gateway_ok": True, "gateway_ms": 2})
    h = investigate_slow(f)[0]
    assert h["key"] == "dns" and h["status"] == "Likely", (h, f["dns_median_ms"])
