@self_test()
def t_store_roundtrip(ctx):
    st = Store(ctx.path("s.sqlite3"), session_id=42)
    assert st.schema_version() == STORE_SCHEMA_VERSION, st.error
    obs = [(1, 100.0, "dns_answer", "aa:bb", {"domain": "x.example",
                                              "ip": "93.184.215.14"}, 7),
           (2, 101.0, "tls_sni", "aa:bb", {"domain": "x.example"}, 9)]
    assert st.write_observations(obs)
    assert st.write_resolutions([(100.0, "aa:bb", "x.example",
                                  "93.184.215.14")])
    f = FlowRecord(5, ("TCP",), "TCP", "192.168.1.5", 4000,
                   "93.184.215.14", 443, 100.5)
    f.device_key, f.domain, f.assoc = "aa:bb", "x.example", AS_CONNECTED
    assert st.write_flows([f])
    assert st.write_site_ties([("aa:bb", "x.example",
                                [AS_CONNECTED, 100.0, 101.0, 2])])
    assert st.write_events([{"when": 102.0, "kind": "website",
                             "severity": "INFO", "text": "First visit",
                             "ref": ("website", "x.example"),
                             "device": "aa:bb"}])
    assert st.flush_now(10)
    got = st.observations("aa:bb")
    assert [o[1] for o in got] == ["tls_sni", "dns_answer"], got
    assert got[1][2]["ip"] == "93.184.215.14" and got[1][3] == 7
    c = st.counts()
    assert c["observations"] == 2 and c["flows"] == 1 and \
        c["site_ties"] == 1 and c["events"] == 1 and c["sessions"] >= 1, c
    r = st.query("SELECT assoc, domain FROM flows WHERE device=?",
                 ("aa:bb",))
    assert r == [(AS_CONNECTED, "x.example")]
    try:
        st.query("DELETE FROM flows")
        raise AssertionError("write through query()")
    except ValueError:
        pass
    st.prune(1)          # everything above is from 1970: pruned
    assert st.flush_now(10)
    assert st.counts()["observations"] == 0
    st.stop(5)


@self_test()
def t_store_migrates_v1_file(ctx):
    path = ctx.path("old.sqlite3")
    con = sqlite3.connect(path)
    for stmt in STORE_MIGRATIONS[1].split(";"):
        if stmt.strip():
            con.execute(stmt)
    con.execute("INSERT OR REPLACE INTO meta VALUES('schema','1')")
    con.execute("INSERT INTO devices VALUES('k1', '{\\"a\\": 1}', 1, 2)")
    con.commit()
    con.close()
    st = Store(path)
    assert st.schema_version() == STORE_SCHEMA_VERSION, st.error
    assert os.path.exists(path + ".v1.bak")
    assert st.known_device_rows()[0][0] == "k1"
    log = st.query("SELECT version, phase FROM migration_log ORDER BY "
                   "rowid")
    want = [(v, ph) for v in range(2, STORE_SCHEMA_VERSION + 1)
            for ph in ("start", "done")]
    assert log == want, log
    st.stop(5)


@self_test()
def t_store_recovers_from_corruption(ctx):
    path = ctx.path("bad.sqlite3")
    good = Store(path)
    good.write_events([{"when": time.time(), "kind": "x", "text": "keep"}])
    good.flush_now(10)
    good.stop(5)
    shutil.copyfile(path, path + ".bak")
    with open(path, "wb") as f:
        f.write(b"SQLite format 3\x00" + os.urandom(4096))
    st = Store(path)
    assert st.recovered and "backup" in st.recovered, st.recovered
    assert st.counts()["events"] == 1
    assert any(n.startswith("bad.sqlite3.corrupt-")
               for n in os.listdir(ctx.tmp))
    st.stop(5)
    os.remove(path + ".bak")
    with open(path, "wb") as f:
        f.write(b"not a database at all" * 50)
    st2 = Store(path)
    assert st2.recovered and st2.schema_version() == STORE_SCHEMA_VERSION
    st2.stop(5)


@self_test()
def t_session_v3_keeps_evidence(ctx):
    if not ctx.scapy_ok:
        return "skip"
    m = scenario_model(ctx.cfg(), ctx.frames())
    payload = json.loads(json.dumps(SessionCodec.serialize(m), default=str))
    assert payload["schema_version"] == 3
    m2 = NetworkModel(ctx.cfg())
    SessionCodec.load(payload, m2)
    w = m2.websites["tracker.example.net"]
    assert w.ties[ScenarioBuilder.PHONE[1]][0] == AS_LOOKUP_ONLY
    assert any(f.assoc == AS_CONNECTED_LOOKUP for f in m2.flows.all_flows())
    assert m2.observations_for(ScenarioBuilder.PHONE[1])
    v2 = dict(payload, schema_version=2)
    v2.pop("observations")
    SessionCodec.load(v2, NetworkModel(ctx.cfg()))


BENCH_EXTRA.append(bench_store)

