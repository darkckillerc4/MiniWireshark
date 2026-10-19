def _fake_helper(kind, password="s3cret-Pw!", user="admin"):
    """A recorded-fixture Pi-hole v6 / AdGuard Home on 127.0.0.1."""
    import http.server
    S = ScenarioBuilder
    t0 = time.time() - 120
    calls = []
    lookups = [(t0 + 1, S.PHONE[0], "Alex-iPhone.lan", "news.example.org",
                "FORWARDED"),
               (t0 + 2, S.PHONE[0], "Alex-iPhone.lan", "ads.example.net",
                "GRAVITY"),
               (t0 + 3, S.TV[0], "tv.lan", "video.example.net", "CACHE"),
               (t0 + 4, "192.168.1.199", "", "hidden.example.com",
                "FORWARDED")]

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj=None):
            body = json.dumps(obj).encode() if obj is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self):
            if kind == "pihole":
                return self.headers.get("X-FTL-SID") == "SID-123"
            want = "Basic " + base64.b64encode(
                f"{user}:{password}".encode()).decode()
            return self.headers.get("Authorization") == want

        def do_POST(self):
            calls.append(("POST", self.path))
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/auth" and kind == "pihole":
                if data.get("password") == password:
                    return self._send(200, {"session": {
                        "valid": True, "totp": False, "sid": "SID-123",
                        "csrf": "x", "validity": 1800}, "took": 0.01})
                return self._send(401, {"error": {"key": "unauthorized"}})
            self._send(404, {})

        def do_DELETE(self):
            calls.append(("DELETE", self.path))
            self._send(204)

        def do_GET(self):
            calls.append(("GET", self.path))
            if not self._authed():
                return self._send(401, {"error": {"key": "unauthorized"}})
            p = self.path
            if kind == "pihole" and p.startswith("/api/info/version"):
                return self._send(200, {"version": {"core": {"local": {
                    "version": "v6.1"}}}})
            if kind == "pihole" and p.startswith("/api/queries"):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(p).query)
                frm = float(q.get("from", ["0"])[0])
                rows = [{"id": i, "time": ts, "type": "A", "domain": dom,
                         "status": st, "client": {"ip": ip, "name": nm},
                         "reply": {"type": "IP", "time": 0.012},
                         "dnssec": "UNKNOWN", "upstream": "1.1.1.1#53"}
                        for i, (ts, ip, nm, dom, st) in enumerate(lookups)
                        if ts >= frm]
                return self._send(200, {"queries": rows[::-1],
                                        "cursor": None,
                                        "recordsTotal": len(rows)})
            if kind == "pihole" and p.startswith("/api/network/devices"):
                return self._send(200, {"devices": [{
                    "id": 1, "hwaddr": S.TV[1], "interface": "eth0",
                    "firstSeen": 1, "lastQuery": int(t0), "numQueries": 9,
                    "macVendor": "Google", "ips": [{"ip": S.TV[0],
                                                    "name": "livingroom-tv",
                                                    "lastSeen": 1,
                                                    "nameUpdated": 1}]}]})
            if kind == "adguard" and p.startswith("/control/status"):
                return self._send(200, {"version": "v0.107.52",
                                        "running": True})
            if kind == "adguard" and p.startswith("/control/querylog"):
                rows = [{"client": ip, "client_info": {"name": nm,
                                                       "whois": {},
                                                       "disallowed": False,
                                                       "disallowed_rule": ""},
                         "elapsedMs": "12.5",
                         "question": {"class": "IN", "name": dom,
                                      "type": "A"},
                         "reason": "FilteredBlackList" if st == "GRAVITY"
                         else "NotFilteredNotFound", "status": "NOERROR",
                         "time": time.strftime("%Y-%m-%dT%H:%M:%S",
                                               time.gmtime(ts)) + ".5Z"}
                        for ts, ip, nm, dom, st in lookups][::-1]
                return self._send(200, {"data": rows, "oldest": ""})
            if kind == "adguard" and p.startswith("/control/clients"):
                return self._send(200, {"clients": [{
                    "name": "livingroom-tv", "ids": [S.TV[0]]}]})
            self._send(404, {})
    httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}", calls, t0


@self_test()
def t_connectors_fixtures(ctx):
    """Pi-hole v6 and AdGuard Home against recorded API answers: login,
    read-only requests, Reported evidence beside observed, secrets never
    shown."""
    if not ctx.scapy_ok:
        return "skip"
    vault = CredentialVault(ctx.path(f"vault_{uuid.uuid4().hex[:6]}.json"))
    vault.backend = "file"
    pw = "s3cret-Pw!"
    for kind in ("pihole", "adguard"):
        httpd, url, calls, t0 = _fake_helper(kind, pw)
        try:
            cid = f"c-{kind}"
            spec = {"id": cid, "kind": kind, "name": CONNECTOR_KINDS[
                kind].title, "url": url, "username": "admin"}
            vault.set(cid, "wrong-password")
            c = CONNECTOR_KINDS[kind](spec, vault)
            try:
                c.test()
                raise AssertionError("a wrong password was accepted")
            except ConnectorError as e:
                assert e.kind == "auth", e
            vault.set(cid, pw)
            c = CONNECTOR_KINDS[kind](spec, vault)
            assert "Connected" in c.test()
            res = c.fetch(t0 - 10)
            c.close()
            assert len(res["lookups"]) == 4, res["lookups"]
            blocked = [x for x in res["lookups"] if x["blocked"]]
            assert [x["domain"] for x in blocked] == ["ads.example.net"]
            # read-only: nothing but logins, GETs and the logout
            assert all(m_ == "GET" or (m_, p_) in (("POST", "/api/auth"),
                                                    ("DELETE", "/api/auth"))
                       for m_, p_ in calls), calls
            m = scenario_model(ctx.cfg(), ctx.frames())
            obs_lookups = m.dns.queries
            rep = m.apply_reported(c.name, res)
            S = ScenarioBuilder
            ph = m.device_for(S.PHONE[0], S.PHONE[1])
            w = m.websites.get("news.example.org")
            assert w and w.ties[ph.key][0] == AS_REPORTED, w and w.ties
            assert c.name in w.sources
            assert "ads.example.net" not in m.websites    # blocked ≠ visit
            assert rep["blocked"] == 1 and "192.168.1.199" in \
                rep["unseen_clients"]
            # an observed connection stays stronger than a report
            vid = m.websites.get("video.example.net")
            tv = m.device_for(S.TV[0], S.TV[1])
            assert ASSOC_RANK[vid.ties[tv.key][0]] >= \
                ASSOC_RANK[AS_REPORTED]
            assert m.dns.queries == obs_lookups    # never summed
            rows = coverage_rows(m)
            row = next(r for r in rows if r[0].startswith("Lookups reported"))
            assert "devices (Reported)" in row[1] and row[2] == LV_REPORTED
            if kind == "pihole":
                assert tv.hostname == "livingroom-tv" and \
                    tv.hostname_source == "connector"
                claims = dict((cl[0], cl) for cl in device_claims(m, tv))
                assert claims["Name"][2] == LV_REPORTED
        finally:
            httpd.shutdown()
    # secrets never appear in logs, copied details or bundles
    assert pw in _SECRETS
    assert pw not in mask_sensitive(f"password={pw} 192.168.1.5")
    assert pw not in scrub_secrets(f"oops {pw}")
    rec = logging.LogRecord("x", logging.INFO, "f", 1, "pw %s", (pw,), None)
    _SecretFilter().filter(rec)
    assert pw not in rec.getMessage()
    raw = open(vault.path, encoding="utf-8").read()
    assert pw not in raw                      # not stored as plain text
    if not IS_WINDOWS:
        assert os.stat(vault.path).st_mode & 0o077 == 0
    vault.delete("c-pihole")
    assert vault.get("c-pihole") is None


@self_test()
def t_connector_manager_and_kill_switch(ctx):
    httpd, url, _calls, t0 = _fake_helper("pihole")
    try:
        vault = CredentialVault(ctx.path(f"v_{uuid.uuid4().hex[:6]}.json"))
        vault.backend = "file"
        vault.set("c1", "s3cret-Pw!")
        got = []
        mgr = ConnectorManager([{"id": "c1", "kind": "pihole", "url": url,
                                 "name": "Pi-hole"}], vault,
                               lambda c, r: got.append(r))
        res = mgr.poll_once("c1")
        assert res and got and mgr.status["c1"]["state"] == "ok"
        assert mgr.cursor["c1"] > t0
        again = mgr.poll_once("c1")              # only what's new
        assert again is not None and again["lookups"] == []
        was = LEDGER.killed
        LEDGER.killed = True
        try:
            mgr.cursor.pop("c1")
            assert mgr.poll_once("c1") is None
            assert mgr.status["c1"]["state"] == "refused"
        finally:
            LEDGER.killed = was
        n = sum(1 for e in LEDGER.snapshot("connector"))
        assert n >= 3
        mgr.stop()
    finally:
        httpd.shutdown()
