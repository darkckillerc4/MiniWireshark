NET_SENDS = {"urlopen", "sendp", "sendto", "gethostbyaddr", "getaddrinfo",
             "create_connection", "sr1", "srp", "srp1", "sendall"}


@self_test()
def t_every_send_goes_through_outbound(ctx):
    """Static check of this file: every network send happens in a function
    that first passes the outbound() gate (so the ledger and the kill
    switch see it). Tests and the gate itself are exempt."""
    import ast
    with open(SCRIPT_PATH, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    bad = []

    def calls_outbound(fn):
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                name = n.func.attr if isinstance(n.func, ast.Attribute) \
                    else getattr(n.func, "id", "")
                if name in ("outbound", "net_urlopen"):
                    return True
        return False

    def visit(node, fn=None):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child if fn is None or not calls_outbound(fn)
                      else fn)
                continue
            if isinstance(child, ast.Call):
                f = child.func
                name = f.attr if isinstance(f, ast.Attribute) else \
                    getattr(f, "id", "")
                is_send = name in NET_SENDS or (
                    name == "connect" and isinstance(f, ast.Attribute) and
                    not (isinstance(f.value, ast.Name) and
                         f.value.id == "sqlite3"))
                if is_send:
                    owner = fn.name if fn is not None else "<module>"
                    exempt = owner in ("net_urlopen",) or \
                        owner.startswith(("t_", "_gs_"))
                    if not exempt and not (fn is not None and
                                           calls_outbound(fn)):
                        bad.append(f"{owner}:{child.lineno} {name}()")
            visit(child, fn)
    visit(tree)
    assert not bad, "sends that bypass outbound(): " + ", ".join(bad)


@self_test()
def t_kill_switch_blocks_everything(ctx):
    was = LEDGER.killed
    before = LEDGER.blocked
    LEDGER.killed = True
    try:
        for fn in (lambda: net_urlopen("update", "https://example.com/", 1),
                   lambda: HealthProber._tcp_rtt("192.0.2.1", 443, 0.1),
                   lambda: HealthProber._dns_rtt("192.0.2.1"),
                   lambda: outbound("lan_scan", "arp", "x")):
            try:
                fn()
                raise AssertionError("sent while the kill switch was on")
            except OutboundBlocked:
                pass
        res = HealthProber.check(HealthProber.__new__(HealthProber),
                                 {"gateway": "192.0.2.1"})
        assert res.get("blocked") and not res["probes"], res
        got = upnp_audit("192.0.2.1", timeout=0.2)
        assert "kill switch" in got.get("error", ""), got
        assert LEDGER.blocked >= before + 6
        snap = LEDGER.snapshot()
        assert not snap[-1]["allowed"]
    finally:
        LEDGER.killed = was
    e = outbound("diagnostics", "dns", "test", "ledger check")
    assert e and LEDGER.snapshot()[-1]["detail"] == "ledger check"
    assert any("Diagnostics" in x for x in LEDGER.summary_lines())


@self_test()
def t_process_attribution(ctx):
    """A known connection of this very test process is attributed to it
    by the connection table, and a new listening port is reported."""
    if _psutil() is None:
        return "skip"
    srv = _socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    cli = _socket.create_connection(("127.0.0.1", port), timeout=2)
    acc, _ = srv.accept()
    try:
        pm = ProcessMap()
        assert pm.read()
        lport = cli.getsockname()[1]
        ent = pm.lookup("TCP", "127.0.0.1", lport)
        if ent is None or ent[0] is None:
            return "skip"          # this OS hides the table from us
        assert ent[0] == os.getpid(), (ent, os.getpid())
        assert "python" in program_label(ent).lower() or ent[1] == "", ent
        assert ("TCP", "127.0.0.1", port) in pm.listening
        lw = ListenWatch(ctx.path(f"listen_{uuid.uuid4().hex[:6]}.json"))
        first = lw.check({k: v for k, v in pm.listening.items()
                          if k[2] != port})
        assert first == [] and not lw.learning     # first look: learn only
        new = lw.check(pm.listening)
        assert any(p == port and scope == "this computer only"
                   for _k, _pr, _ip, p, _g, scope in new), new
        assert lw.check(pm.listening) == []        # reported once
    finally:
        for s_ in (acc, cli, srv):
            s_.close()


ARP_WINDOWS = """
Interface: 192.168.1.10 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           00-1e-58-aa-00-01     dynamic
  192.168.1.23          da-a1-19-23-45-67     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
ARP_BSD = """? (192.168.1.1) at 0:1e:58:aa:0:1 on en0 ifscope [ethernet]
? (192.168.1.23) at da:a1:19:23:45:67 on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
"""
PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         00:1e:58:aa:00:01     *        eth0
192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        eth0
"""


@self_test()
def t_arp_cache_parsers(ctx):
    w = parse_arp_windows(ARP_WINDOWS)
    assert ("192.168.1.1", "00:1e:58:aa:00:01", "192.168.1.10") in w
    assert len(w) == 3
    b = parse_arp_bsd(ARP_BSD)
    assert b == [("192.168.1.1", "00:1e:58:aa:00:01", "en0"),
                 ("192.168.1.23", "da:a1:19:23:45:67", "en0")], b
    p = parse_proc_arp(PROC_ARP)
    assert p == [("192.168.1.1", "00:1e:58:aa:00:01", "eth0")], p


@self_test()
def t_upnp_audit_fake_router(ctx):
    """The router check against a fake router on this computer: finds the
    forwarding rules, and every request it made is in the ledger."""
    import http.server
    rules = [("TCP", "32400", "192.168.1.70", "32400", "Plex"),
             ("TCP", "3389", "192.168.1.50", "3389", "RDP")]
    holder = {}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = ("<?xml version='1.0'?><root xmlns='urn:schemas-upnp-org"
                    ":device-1-0'><device><serviceList><service><serviceType>"
                    "urn:schemas-upnp-org:service:WANIPConnection:1"
                    "</serviceType><controlURL>/ctl</controlURL></service>"
                    "</serviceList></device></root>").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            i = int(re.search(rb"<NewPortMappingIndex>(\d+)<", data).group(1))
            holder.setdefault("posts", []).append(i)
            if i >= len(rules):
                self.send_response(500)
                self.end_headers()
                return
            pr, ext, cl, inn, desc = rules[i]
            body = (f"<s:Envelope xmlns:s='x'><s:Body><u:R xmlns:u='y'>"
                    f"<NewProtocol>{pr}</NewProtocol><NewExternalPort>{ext}"
                    f"</NewExternalPort><NewInternalClient>{cl}"
                    f"</NewInternalClient><NewInternalPort>{inn}"
                    f"</NewInternalPort><NewEnabled>1</NewEnabled>"
                    f"<NewPortMappingDescription>{desc}"
                    f"</NewPortMappingDescription></u:R></s:Body>"
                    f"</s:Envelope>").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
    hport = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    udp = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    uport = udp.getsockname()[1]

    def responder():
        try:
            data, addr = udp.recvfrom(2048)
            holder["msearch"] = data
            udp.sendto((f"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:"
                        f"{hport}/desc.xml\r\nST: x\r\n\r\n").encode(), addr)
        except OSError:
            pass
    threading.Thread(target=responder, daemon=True).start()
    n0 = len(LEDGER.snapshot("upnp"))
    try:
        res = upnp_audit("127.0.0.1", timeout=2.0, port=uport)
    finally:
        httpd.shutdown()
        udp.close()
    assert not res.get("error"), res
    maps = res["mappings"]
    assert [(m_["ExternalPort"], m_["InternalClient"]) for m_ in maps] == \
        [("32400", "192.168.1.70"), ("3389", "192.168.1.50")], maps
    assert b"InternetGatewayDevice" in holder["msearch"]
    sent = LEDGER.snapshot("upnp")[n0:]
    kinds = [e["kind"] for e in sent]
    # exactly: 1 discovery, 1 description, one per rule + the final "no
    # more" answer — nothing else
    assert kinds.count("ssdp") == 1 and len(sent) == 1 + 1 + 3, kinds
    assert all(e["dest"] == "127.0.0.1" or e["dest"].startswith(
        "127.0.0.1:") for e in sent), sent
    # an answer that points away from the router is not followed
    bad = upnp_parse_description("<root/>", "http://127.0.0.1/")
    assert bad is None
