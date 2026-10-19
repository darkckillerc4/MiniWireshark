@self_test()
def t_timeline_sql_matches_memory(ctx):
    """The SQL timeline filter returns exactly what the in-memory filter
    shows, for every combination the Timeline tab can produce."""
    if not ctx.scapy_ok:
        return "skip"
    m = scenario_model(ctx.cfg(), ctx.frames())
    events = list(m.timeline)
    extra = [{"when": 50.0 + i, "kind": k, "severity": sev, "text": txt,
              "ref": None, "device": dev}
             for i, (k, sev, txt, dev) in enumerate([
                 ("odd kind", "INFO", "Something 100% unusual", "aa:01"),
                 ("alert", "DANGER", "Rogue DHCP server", ""),
                 ("dns change", "WARNING", "DNS server changed", ""),
                 ("website", "INFO", "First visit to under_score.example",
                  "aa:01")])]
    events += extra
    assert len(events) > 10
    st = Store(ctx.path("tl.sqlite3"), session_id=7)
    assert st.write_events(events) and st.flush_now(10)
    devs = [None, "aa:01"] + sorted({e.get("device") for e in events
                                     if e.get("device")})[:2]
    combos = 0
    for cat in ["All types", "Devices", "Websites", "Alerts", "DNS",
                "Network & capture"]:
        for sev in ["All", "INFO", "WARNING", "DANGER"]:
            for dev in devs:
                for q in ["", "visit", "100%", "under_", "DHCP"]:
                    for since in (0.0, 53.0):
                        want = sorted(
                            (e["when"], e["kind"], e["text"]) for e in events
                            if timeline_match(e, since, sev, cat, dev, q))
                        got = sorted(
                            (e["when"], e["kind"], e["text"]) for e in
                            store_events_page(st, limit=100000, category=cat,
                                              severity=sev, device=dev, q=q,
                                              since=since))
                        assert got == want, (cat, sev, dev, q, since,
                                             got[:3], want[:3])
                        combos += 1
    # paging: newest first, no overlap, nothing lost
    same = [{"when": 999.0, "kind": "alert", "severity": "INFO",
             "text": f"same second {i}"} for i in range(10)]
    assert st.write_events(same) and st.flush_now(10)
    events += same
    seen, before = [], None
    while True:
        page = store_events_page(st, before=before, limit=7)
        seen += page
        if len(page) < 7:
            break
        before = (page[-1]["when"], page[-1]["rowid"])
    ts = [e["when"] for e in seen]
    assert ts == sorted(ts, reverse=True)
    assert len(seen) == len(events), (len(seen), len(events))
    assert len({e["rowid"] for e in seen}) == len(events)
    st.stop(5)
    return f"{combos} filter combinations"


@self_test()
def t_compare_sessions(ctx):
    path = ctx.path("cmp.sqlite3")
    dk = OBS_KIND_CODES
    a = Store(path, session_id=1000, meta={"source": "live"})
    a.write_observations([
        (1, 1000.0, "dhcp_request", "aa:01", {"hostname": "Laptop"}, 1),
        (2, 1001.0, "mdns", "aa:02", {"name": "Printer"}, 2),
        (3, 1002.0, "arp_reply", "aa:03", {}, 3)])
    a.write_site_ties([("aa:01", "www.example.com",
                        [AS_CONNECTED, 1000.0, 1001.0, 1]),
                       ("aa:01", "old.example.org",
                        [AS_REPORTED, 1000.0, 1001.0, 1])])
    a.write_events([{"when": 1000.0, "kind": "new device", "text": "x",
                     "severity": "INFO"}])
    assert a.flush_now(10)
    a.stop(5)
    b = Store(path, session_id=2000)
    b.set_session_meta(network="Home", iface="eth0")
    b.write_observations([
        (1, 2000.0, "dhcp_request", "aa:01", {"hostname": "Laptop"}, 1),
        (2, 2001.0, "nbns", "aa:09", {"name": "NEWBOX"}, 2)])
    b.write_site_ties([("aa:01", "api.example.com",
                        [AS_CONNECTED, 2000.0, 2001.0, 1]),
                       ("aa:09", "new.example.net",
                        [AS_LOOKUP_ONLY, 2000.0, 2001.0, 1])])
    b.write_events([{"when": 2000.0, "kind": "new device", "text": "y",
                     "severity": "INFO"},
                    {"when": 2001.0, "kind": "new device", "text": "z",
                     "severity": "INFO"}])
    assert b.flush_now(10)
    ss = store_sessions(b)
    assert [x["id"] for x in ss[:2]] == [2000, 1000], ss
    assert ss[0]["network"] == "Home" and "Home" in session_label(ss[0])
    r = compare_sessions(b, 1000, 2000)
    assert r["new_devices"] == ["aa:09"], r
    assert r["gone_devices"] == ["aa:02", "aa:03"], r
    assert r["both_devices"] == ["aa:01"]
    assert r["names"]["aa:09"] == "NEWBOX" and r["names"]["aa:01"] == \
        "Laptop", r["names"]
    # api.example.com and www.example.com share a registrable domain
    assert r["new_sites"] == ["example.net"], r
    assert r["gone_sites"] == ["example.org"], r
    assert r["events_a"]["new device"] == 1 and \
        r["events_b"]["new device"] == 2
    _ = dk
    b.stop(5)


@self_test()
def t_packet_ring(ctx):
    """The on-disk packet history: exact frames back by number, segments
    split on gaps and link-type changes, epochs kept apart, size cap
    enforced (also against files of earlier runs)."""
    if not ctx.scapy_ok:
        return "skip"
    frames = list(ctx.frames())
    while len(frames) < 400:
        frames += list(ctx.frames())
    folder = ctx.path(f"ring_{uuid.uuid4().hex[:6]}")
    st = Store(ctx.path("ring.sqlite3"), session_id=5)
    pr = PacketRing(folder, cap_mb=20, store=st, session=5)
    for no, (raw, ts, lt) in enumerate(frames[:300], 1):
        assert pr.put(no, raw, ts, lt)
    assert pr.flush()
    for no in (1, 2, 150, 299, 300):
        got = pr.find(no)
        raw, ts, lt = frames[no - 1]
        assert got is not None and got[0] == raw and got[2] == lt, no
        assert abs(got[1] - ts) < 1e-5, (got[1], ts)
    assert pr.find(301) is None and pr.find(0) is None
    # a gap in numbering starts a new segment (and old ones still answer)
    for no in range(500, 520):
        raw, ts, lt = frames[no - 500]
        pr.put(no, raw, ts, lt)
    assert pr.flush()
    assert pr.find(505)[0] == frames[5][0] and pr.find(10)[0] == frames[9][0]
    assert len(pr.index) >= 1
    # numbers restart after Clear: the old epoch is not confused with it
    pr.new_epoch()
    pr.put(1, b"\x00" * 60, 1.0, 1)
    assert pr.flush()
    assert pr.find(1)[0] == b"\x00" * 60
    assert pr.find(150) is None
    assert pr.find(150, epoch=0)[0] == frames[149][0]
    written = pr.written
    pr.stop()
    assert written == 321, written
    assert st.flush_now(10)
    segs = st.query("SELECT first_no, last_no FROM packet_segments "
                    "ORDER BY first_no")
    assert (500, 519) in segs and any(f == 1 for f, _l in segs), segs
    # size cap: pretend old files are huge; a new ring trims them
    big = os.path.join(folder, "seg-1-0-000000000001.pcap")
    with open(big, "wb") as f:
        f.truncate(30 * 1024 * 1024)
    os.utime(big, (1, 1))
    pr2 = PacketRing(folder, cap_mb=20, store=None, session=6)
    assert not os.path.exists(big)
    assert pr2.size_bytes() <= 20 * 1024 * 1024
    pr2.stop()
    st.stop(5)
    return f"{written} packets"
