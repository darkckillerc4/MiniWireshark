P = "/home/claude/mw/miniwireshark.py"
s = open(P, encoding="utf8").read()


def rep(old, new, cnt=1):
    global s
    n = s.count(old)
    assert n == cnt, (n, old[:120])
    s = s.replace(old, new)


rep('''    def expert_severities(self, d):
        return self._f.get(d["no"], [])


@self_test(slow=False)
def test_field_filter_language(ctx):''', '''    def expert_severities(self, d):
        return [x if isinstance(x, str) else x[0]
                for x in self._f.get(d["no"], [])]

    def expert_info(self, d, i):
        return [x[i] for x in self._f.get(d["no"], [])
                if not isinstance(x, str)]

    def time_zero(self):
        return SCENARIO_T0


@self_test(slow=False)
def test_field_filter_language(ctx):''')

TESTS = r'''@self_test(slow=False)
def test_v501_fixes_and_filters(ctx):
    """5.0.1: sub-second durations, conversation / address / expert
    filters, frame.time_relative (was always empty), time formats, CSV
    cells that cannot run as formulas, and the stream text that is saved
    exactly as shown (redacted in Hex too)."""
    assert human_duration(0.4) == "<1s" and human_duration(0) == "0s"
    assert human_duration(None) == "0s" and human_duration(75) == "1m 15s"
    frames = ScenarioBuilder().home_network() + \
        ScenarioBuilder(t0=SCENARIO_T0 + 9000).protocol_exchanges() + \
        ScenarioBuilder(t0=SCENARIO_T0 + 9500).mail_sessions()
    rows = _deep_rows(frames)
    d = next(r for r in rows if r["transport"] == "TCP" and r["sport"])
    expr = conversation_filter(d["src_ip"], d["dst_ip"], d["sport"],
                               d["dport"], d["transport"], d["ipver"])
    f = FieldFilter(expr)
    key = {d["src_ip"], d["dst_ip"]}, {d["sport"], d["dport"]}
    got = [r for r in rows if f.match(r, _FilterCtx())]
    assert d in got and all(({r["src_ip"], r["dst_ip"]},
                             {r["sport"], r["dport"]}) == key
                            for r in got), expr
    arp = next(r for r in rows if r.get("proto") == "ARP")
    assert conversation_filter("", "", src_mac=arp["src_mac"],
                               dst_mac=arp["dst_mac"]).startswith("eth.addr")
    assert address_filter("192.168.1.5") == "ip.addr == 192.168.1.5"
    assert address_filter("fe80::1") == "ipv6.addr == fe80::1"
    assert address_filter("aa:bb:cc:dd:ee:ff").startswith("eth.addr")
    FieldFilter(address_filter("fe80::1"))
    # expert.group / expert.message and the group filter of the list
    c = _FilterCtx({rows[3]["no"]: [("warn", "Sequence",
                                     "TCP retransmission of 1460 bytes")],
                    rows[5]["no"]: [("note", "Protocol", 'Say "hi" 2')]})
    g = {"sev": "warn", "group": "Sequence",
         "summary": "TCP retransmission of 1460 bytes"}
    ge = expert_group_filter(g)
    assert 'contains "TCP retransmission of"' in ge, ge
    hits = [r["no"] for r in rows if FieldFilter(ge).match(r, c)]
    assert hits == [rows[3]["no"]], hits
    q = FieldFilter("expert.message contains " + filter_quote('Say "hi"'))
    assert [r["no"] for r in rows if q.match(r, c)] == [rows[5]["no"]]
    assert sum(1 for r in rows if FieldFilter(
        'expert.group == "protocol"').match(r, c)) == 1
    # frame.time_relative
    late = [r for r in rows if FieldFilter(
        "frame.time_relative > 9000").match(r, _FilterCtx())]
    assert late and all(r["time"] - SCENARIO_T0 > 9000 for r in late)
    assert len(late) < len(rows)
    # time formats
    assert format_packet_time(100.25, "Seconds since start", 100.0) == \
        "0.250000"
    assert format_packet_time(100.25, "Since previous shown", 0,
                              100.0) == "0.250000"
    assert format_packet_time(100.25, "Since previous shown") == "0.000000"
    assert len(format_packet_time(time.time(), "Time of day")) == 12
    # CSV cells
    buf = io.StringIO()
    w = safe_csv_writer(buf)
    w.writerow(["=HYPERLINK(1)", "+1", "-x", "@a", "ok", 5, -3, "a=b"])
    assert buf.getvalue().strip() == "'=HYPERLINK(1),'+1,'-x,'@a,ok,5,-3,a=b"
    buf = io.StringIO()
    n = write_expert_csv(buf, [(7, SCENARIO_T0, "warn", "Security",
                                "=cmd", None)])
    assert n == 1 and ",warning,Security,'=cmd," in buf.getvalue()
    # followed streams: saved text == shown text; Hex stays redacted
    secret = ScenarioBuilder.CANARY
    fids = {}
    for r in rows:
        if r.get("sport") is None:
            continue
        k = frozenset([(r["src_ip"], r["sport"]), (r["dst_ip"], r["dport"])])
        r["flow_id"] = fids.setdefault(k, len(fids) + 1)
    leaked_raw = False
    for fid in set(fids.values()):
        res = follow_stream(rows, fid)
        if not res.chunks:
            continue
        raw_all = b"".join(c[2] for c in res.chunks if c[2])
        if not res.sensitive():
            continue
        leaked_raw = leaked_raw or secret.encode() in raw_all
        for hexmode in (False, True):
            for dr in STREAM_DIRECTIONS:
                txt = stream_text(res, True, hexmode, dr)
                assert secret not in txt, (fid, hexmode, dr)
                if hexmode:
                    flat = bytes.fromhex("".join(
                        ln[10:57].replace(" ", "") for ln in
                        txt.splitlines()[2:] if re.match(
                            r"^[0-9a-f]{8}  ", ln)))
                    assert secret.encode() not in flat, fid
        both = stream_segments(res, True, False, STREAM_DIRECTIONS[0])
        cli = stream_segments(res, True, False, STREAM_DIRECTIONS[1])
        assert all(k in (0, "gap") for _t, k, _n in cli)
        assert len(cli) <= len(both)
    assert leaked_raw, "the scenario must carry the canary to prove this"


'''
rep("def bench_report(seconds=2.0):", TESTS + "def bench_report(seconds=2.0):")

GUI = r'''@gui_test_step("5.0.1: expert list, copy as filter, follow stream, go to packet")
def _gs_v501(app, ctx):
    root = app.root
    app.config.set("performance.mode", "Full Power")
    app.config.set("performance.deep_runner", "Thread")
    tmp = tempfile.mkdtemp()
    try:
        ident = scenario_identity()
        m = app._new_model(identity=ident[:3])
        m.set_identity(local_nets=ident[3])
        app.replace_model(m)
        app.data_mode = "offline"
        sink = app.lossless_sink()
        frames = ScenarioBuilder().home_network() + \
            ScenarioBuilder(t0=SCENARIO_T0 + 2000).protocol_exchanges() + \
            ScenarioBuilder(t0=SCENARIO_T0 + 3000).mail_sessions()
        for raw, ts, lt in frames:
            sink(raw, ts, lt)
        _gui_pump(root, until=lambda: app.count >= len(frames), timeout=30)
        assert app.deep.drain(20)
        app.deep.flush(final=True)
        _gui_pump(root, 0.5)
        tab = app._select_tab("packets")
        tab.rebuild()
        # expert list → packets, CSV export, row colours
        tab.show_subview("Expert")
        ev = tab.expert
        ev.sev_var.set("All")
        ev.refresh(force=True)
        kids = ev.tree.get_children()
        assert kids, "no expert groups"
        ev.tree.selection_set(kids[0])
        g = ev.selected()
        expr = ev.show_packets()
        _gui_pump(root, 0.3)
        assert tab.subview == "Packets" and tab.expr_var.get() == expr
        assert tab.matched, expr
        assert g["first"] in {d["no"] for d in tab.matched}, (expr, g)
        assert len(tab.matched) <= max(g["count"], 1) * 3 + 5
        tab.render()
        tags = [t for iid in tab.slots for t in tab.tree.item(iid, "tags")]
        sev = {d["no"]: tab.ctx.worst_expert(d) for d in tab.matched}
        if any(sev.values()):
            assert any(t.startswith("x_") for t in tags), tags
        tab.xcolor_var.set(False)
        tab._xcolor()
        tags = [t for iid in tab.slots for t in tab.tree.item(iid, "tags")]
        assert not any(t.startswith("x_") for t in tags)
        tab.xcolor_var.set(True)
        tab._xcolor()
        out = ev.export_csv(os.path.join(tmp, "expert.csv"))
        text = open(out, encoding="utf-8").read()
        assert text.startswith("packet,time,severity,group,finding")
        assert text.count("\n") >= len(kids) + 1
        tab.clear_filter()
        # time display formats
        tab.time_var.set("Seconds since start")
        tab._time_format()
        first = tab.tree.item(tab.slots[0], "values")[2]
        assert re.match(r"^\d+\.\d{6}$", str(first)), first
        tab.time_var.set("Since previous shown")
        tab._time_format()
        assert re.match(r"^\d+\.\d{6}$",
                        str(tab.tree.item(tab.slots[1], "values")[2]))
        tab.time_var.set("Time of day")
        tab._time_format()
        assert ":" in str(tab.tree.item(tab.slots[0], "values")[2])
        assert app.config.get("capture.time_format") == "Time of day"
        # copy as filter / filter on conversation
        row = next(d for d in app.all_rows if d.get("transport") == "TCP"
                   and d.get("flow_id"))
        conv = conversation_filter(row["src_ip"], row["dst_ip"],
                                   row["sport"], row["dport"],
                                   row["transport"], row["ipver"])
        app.apply_filter(conv)
        assert tab.matched and all(d.get("flow_id") == row["flow_id"]
                                   for d in tab.matched), conv
        tab.clear_filter()
        tab.show_subview("Statistics")
        tab.stats.kind_var.set("Conversations")
        tab.stats.refresh(force=True)
        assert tab.stats.conv_filter(row["flow_id"]).count("==") == 4
        tab.stats.kind_var.set("Endpoints")
        tab.stats.refresh(force=True)
        assert tab.stats._ep_addr
        # follow stream: ◀ ▶, direction, save (redacted), filter
        sv = app.follow_stream(row["flow_id"])
        _gui_pump(root, 0.2)
        nxt = sv.step(1)
        assert nxt is None or nxt > row["flow_id"]
        if nxt:
            assert sv.flow_id == nxt
            assert sv.step(-1) == row["flow_id"]
        sv.dir_var.set("Server → client")
        sv.render()
        sv.dir_var.set("Both directions")
        sv.render()
        mail = next(d for d in app.all_rows if d.get("dport") == 25 and
                    d.get("flow_id"))
        sv = app.follow_stream(mail["flow_id"])
        app.raw_streams_ok = True
        sv.render()
        path = sv.save_as(os.path.join(tmp, "s.txt"))
        saved = open(path, encoding="utf-8").read()
        assert ScenarioBuilder.CANARY not in saved and "redacted" in saved
        sv.mode_var.set("Hex")
        app.raw_streams_ok = False
        sv.render()
        body = sv.txt.get("1.0", "end")
        assert ScenarioBuilder.CANARY.encode().hex()[:16] not in \
            body.replace(" ", "")
        sv.mode_var.set("Text")
        sv.filter_on()
        assert tab.subview == "Packets" and \
            tab.expr_var.get() == f"stream:{mail['flow_id']}"
        tab.clear_filter()
        # go to packet (Ctrl+G)
        target = app.all_rows[len(app.all_rows) // 2]["no"]
        assert app.go_to_packet(target)
        assert tab.sel_no == target
        assert app.config.get("shortcuts.goto_packet") == "<Control-g>"
        assert any(x[0] == "Go to packet…" for x in app.palette_items())
    finally:
        app.raw_streams_ok = False
        app.config.set("performance.mode", "Automatic")
        app.config.set("performance.deep_runner", "Automatic")


'''
rep('@gui_test_step("corrections: rename, merge, undo from the window")',
    GUI + '@gui_test_step("corrections: rename, merge, undo from the window")')
open(P, "w", encoding="utf8").write(s)
print("tests added")
