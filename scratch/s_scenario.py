# ============================================================================
#  20a.  Replay scenarios — deterministic synthetic captures
#
#  A scripted home network built from ordinary packets (raw bytes plus a
#  timestamp). The same frames drive the self-tests, the fuzzer, the GUI
#  test, the benchmarks and the "golden" checks, so a behaviour change in
#  the decoder or the model shows up as a failing check within seconds.
#  All public addresses are real-looking but every domain is a reserved
#  ".example" name. Nothing is ever transmitted.
# ============================================================================
SCENARIO_T0 = 1_760_000_000.0


class ScenarioBuilder:
    """Builds lists of (raw_bytes, timestamp, linktype) frames."""

    GW = ("192.168.1.1", "00:1e:58:aa:00:01")
    ME = ("192.168.1.10", "3c:7c:3f:10:00:10")
    PHONE = ("192.168.1.23", "da:a1:19:23:45:67", "Alex-iPhone")
    TV = ("192.168.1.40", "f4:f5:d8:40:00:40", "Living Room TV")
    PRINTER = ("192.168.1.50", "00:80:77:50:00:50", "BRW008077500050")
    PLUG = ("192.168.1.60", "24:0a:c4:60:00:60", "ESP_6A1B2C")
    NAS = ("192.168.1.70", "00:11:32:70:00:70", "family-nas")
    LAPTOP = ("192.168.1.50", "3c:22:fb:88:00:88", "DESKTOP-GUEST7Q")
    V6_PREFIX = "2a01:e0a:1f:2c0"
    SITES = {"www.example.com": "93.184.215.14",
             "video.example.net": "142.250.80.46",
             "tracker.example.net": "151.101.1.1",
             "plain.example.org": "34.117.59.81",
             "files.example.org": "34.117.59.81"}

    def __init__(self, t0=SCENARIO_T0, seed=7):
        self.t = t0
        self.frames = []
        self.rng = random.Random(seed)
        self.port = 40000
        self.qid = 100

    # ---- low level -----------------------------------------------------------
    def _emit(self, pkt, dt=0.01):
        self.t += dt
        self.frames.append((bytes(pkt), round(self.t, 6), 1))

    def _next_port(self):
        self.port += 1
        return self.port

    def arp_announce(self, host):
        ip, mac = host[0], host[1]
        self._emit(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                   ARP(op=1, psrc=ip, pdst=self.GW[0], hwsrc=mac))
        self._emit(Ether(src=self.GW[1], dst=mac) /
                   ARP(op=2, psrc=self.GW[0], hwsrc=self.GW[1], pdst=ip,
                       hwdst=mac))
        self._emit(Ether(src=mac, dst=self.GW[1]) /
                   ARP(op=2, psrc=ip, hwsrc=mac, pdst=self.GW[0],
                       hwdst=self.GW[1]))

    def dhcp(self, host, vendor_class="", client_id=True, lease=86400):
        ip, mac, name = host[0], host[1], host[2]
        chaddr = bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10
        opts = [("message-type", "request"), ("requested_addr", ip)]
        if client_id:
            opts.append(("client_id", b"\x01" + bytes.fromhex(
                mac.replace(":", ""))))
        if name:
            opts.append(("hostname", name.encode()))
        if vendor_class:
            opts.append(("vendor_class_id", vendor_class.encode()))
        opts.append(("param_req_list", [1, 3, 6, 15, 119, 252]))
        self._emit(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                   IP(src="0.0.0.0", dst="255.255.255.255") /
                   UDP(sport=68, dport=67) /
                   BOOTP(chaddr=chaddr, xid=self.rng.randint(1, 2 ** 31)) /
                   DHCP(options=opts + ["end"]))
        self._emit(Ether(src=self.GW[1], dst=mac) /
                   IP(src=self.GW[0], dst=ip) / UDP(sport=67, dport=68) /
                   BOOTP(op=2, yiaddr=ip, chaddr=chaddr) /
                   DHCP(options=[("message-type", "ack"),
                                 ("server_id", self.GW[0]),
                                 ("lease_time", lease),
                                 ("router", self.GW[0]),
                                 ("name_server", self.GW[0]), "end"]))

    def mdns(self, host, svc, name, txt):
        ip, mac = host[0], host[1]
        txtv = [f"{k}={v}".encode() for k, v in txt.items()]
        self._emit(Ether(src=mac, dst="01:00:5e:00:00:fb") /
                   IP(src=ip, dst="224.0.0.251", ttl=255) /
                   UDP(sport=5353, dport=5353) /
                   DNS(qr=1, aa=1, qd=None,
                       an=DNSRR(rrname=f"{svc}.local", type="PTR",
                                rdata=f"{name}.{svc}.local"),
                       ar=[DNSRR(rrname=f"{name}.{svc}.local", type="TXT",
                                 rdata=txtv),
                           DNSRR(rrname=f"{name.replace(' ', '-')}.local",
                                 rdata=ip)]))

    def dns(self, host, name, answer_ip, rcode=0):
        ip, mac = host[0], host[1]
        sp = self._next_port()
        self.qid += 1
        self._emit(Ether(src=mac, dst=self.GW[1]) /
                   IP(src=ip, dst=self.GW[0]) / UDP(sport=sp, dport=53) /
                   DNS(id=self.qid, rd=1, qd=DNSQR(qname=name)))
        an = DNSRR(rrname=name, rdata=answer_ip, ttl=300) if answer_ip \
            else None
        self._emit(Ether(src=self.GW[1], dst=mac) /
                   IP(src=self.GW[0], dst=ip) / UDP(sport=53, dport=sp) /
                   DNS(id=self.qid, qr=1, rcode=rcode,
                       qd=DNSQR(qname=name), an=an), dt=0.02)

    def tls(self, host, site, rip, size=30000, sni=True, rst=False,
            port=443):
        ip, mac = host[0], host[1]
        sp = self._next_port()
        seq = self.rng.randint(1000, 10 ** 9)
        out = Ether(src=mac, dst=self.GW[1]) / IP(src=ip, dst=rip)
        back = Ether(src=self.GW[1], dst=mac) / IP(src=rip, dst=ip, ttl=54)
        self._emit(out / TCP(sport=sp, dport=port, flags="S", seq=seq))
        self._emit(back / TCP(sport=port, dport=sp, flags="SA", seq=7,
                              ack=seq + 1), dt=0.03)
        hello = build_client_hello(site if sni else "", pad=300) if sni \
            else b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"
        self._emit(out / TCP(sport=sp, dport=port, flags="PA", seq=seq + 1) /
                   Raw(hello))
        s2, sent = 8, 0
        while sent < size:
            chunk = min(1400, size - sent)
            self._emit(back / TCP(sport=port, dport=sp, flags="A", seq=s2) /
                       Raw(b"\x17\x03\x03" + bytes(chunk - 3)), dt=0.002)
            s2 += chunk
            sent += chunk
        if rst:
            self._emit(back / TCP(sport=port, dport=sp, flags="R", seq=s2))
            return
        self._emit(out / TCP(sport=sp, dport=port, flags="FA",
                             seq=seq + 1 + len(hello)))
        self._emit(back / TCP(sport=port, dport=sp, flags="FA", seq=s2))

    def http(self, host, site, rip):
        ip, mac = host[0], host[1]
        sp = self._next_port()
        out = Ether(src=mac, dst=self.GW[1]) / IP(src=ip, dst=rip)
        back = Ether(src=self.GW[1], dst=mac) / IP(src=rip, dst=ip, ttl=54)
        self._emit(out / TCP(sport=sp, dport=80, flags="S", seq=1))
        self._emit(back / TCP(sport=80, dport=sp, flags="SA", seq=1, ack=2))
        self._emit(out / TCP(sport=sp, dport=80, flags="PA", seq=2) /
                   Raw(f"GET /index.html HTTP/1.1\r\nHost: {site}\r\n"
                       f"User-Agent: test\r\n\r\n".encode()))
        self._emit(back / TCP(sport=80, dport=sp, flags="PA", seq=2) /
                   Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))

    # ---- the scripted home network ---------------------------------------------
    def home_network(self):
        gw, me = self.GW, self.ME
        hosts = [me, self.PHONE, self.TV, self.PRINTER, self.PLUG, self.NAS]
        for h in hosts:
            self.arp_announce(h)
        self.dhcp(self.PHONE, client_id=True)
        self.dhcp(self.TV)
        self.dhcp(self.PRINTER)
        self.dhcp(self.PLUG, vendor_class="udhcp 1.30")
        self.dhcp(self.NAS)
        # IPv6: router advertisement with a global prefix, then the phone's
        # global address is resolved by neighbour discovery
        self._emit(Ether(src=gw[1], dst="33:33:00:00:00:01") /
                   IPv6(src="fe80::21e:58ff:feaa:1", dst="ff02::1") /
                   ICMPv6ND_RA(routerlifetime=1800) /
                   ICMPv6NDOptPrefixInfo(prefix=self.V6_PREFIX + "::",
                                         prefixlen=64) /
                   ICMPv6NDOptSrcLLAddr(lladdr=gw[1]))
        p6 = self.V6_PREFIX + "::23"
        self._emit(Ether(src=self.PHONE[1], dst=gw[1]) /
                   IPv6(src=p6, dst="fe80::21e:58ff:feaa:1") /
                   ICMPv6ND_NA(tgt=p6, R=0, S=1, O=1) /
                   ICMPv6NDOptDstLLAddr(lladdr=self.PHONE[1]))
        self.mdns(self.TV, "_googlecast._tcp", "Living Room TV",
                  {"md": "Chromecast", "fn": "Living Room TV"})
        self.mdns(self.PRINTER, "_ipp._tcp", "Brother HL-L2350DW",
                  {"ty": "Brother HL-L2350DW"})
        self.mdns(self.NAS, "_smb._tcp", "family-nas", {"model": "DS220+"})
        self._emit(Ether(src=self.TV[1], dst="01:00:5e:7f:ff:fa") /
                   IP(src=self.TV[0], dst="239.255.255.250") /
                   UDP(sport=1900, dport=1900) /
                   Raw(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                       b"NT: urn:dial-multiscreen-org:service:dial:1\r\n"
                       b"SERVER: Linux/4.9 UPnP/1.0 Chromecast/1.56\r\n\r\n"))
        # browsing: lookup → connection with SNI
        s = self.SITES
        self.dns(me, "www.example.com", s["www.example.com"])
        self.tls(me, "www.example.com", s["www.example.com"], size=40000)
        # a lookup with no connection afterwards
        self.dns(self.PHONE, "tracker.example.net", s["tracker.example.net"])
        self.dns(self.PHONE, "video.example.net", s["video.example.net"])
        self.tls(self.PHONE, "video.example.net", s["video.example.net"],
                 size=120000)
        # a connection that only the earlier lookup can name (no SNI)
        self.dns(self.TV, "files.example.org", s["files.example.org"])
        self.tls(self.TV, "", s["files.example.org"], sni=False, size=6000)
        # plain web and cleartext
        self.http(me, "plain.example.org", s["plain.example.org"])
        pr = self.PRINTER
        out = Ether(src=pr[1], dst=gw[1]) / IP(src=pr[0], dst="34.117.59.81")
        self._emit(out / TCP(sport=40500, dport=21, flags="S"))
        self._emit(Ether(src=gw[1], dst=pr[1]) /
                   IP(src="34.117.59.81", dst=pr[0]) /
                   TCP(sport=21, dport=40500, flags="SA"))
        self._emit(out / TCP(sport=40500, dport=21, flags="PA") /
                   Raw(b"USER scanner\r\n"))
        # NTP from the smart plug
        self._emit(Ether(src=self.PLUG[1], dst=gw[1]) /
                   IP(src=self.PLUG[0], dst="129.6.15.28") /
                   UDP(sport=12345, dport=123) / Raw(b"\x1b" + bytes(47)))
        self._emit(Ether(src=gw[1], dst=self.PLUG[1]) /
                   IP(src="129.6.15.28", dst=self.PLUG[0], ttl=50) /
                   UDP(sport=123, dport=12345) / Raw(b"\x1c" + bytes(47)))
        # QUIC (long header) and encrypted DNS to a known DoH host
        self._emit(Ether(src=me[1], dst=gw[1]) /
                   IP(src=me[0], dst="142.250.80.46") /
                   UDP(sport=51000, dport=443) / Raw(b"\xc3" + bytes(1250)))
        self.tls(me, "dns.google", "8.8.8.8", size=3000)
        # local name protocols
        self._emit(Ether(src=me[1], dst="01:00:5e:00:00:fc") /
                   IP(src=me[0], dst="224.0.0.252") /
                   UDP(sport=55000, dport=5355) /
                   DNS(id=9, qd=DNSQR(qname="nas")))
        nb = (b"\x81\x02\x85\x00\x00\x00\x00\x01\x00\x00\x00\x00\x20" +
              b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 15)])
                       for c in b"FAMILY-NAS      ") + b"\x00")
        self._emit(Ether(src=self.NAS[1], dst=me[1]) /
                   IP(src=self.NAS[0], dst=me[0]) /
                   UDP(sport=137, dport=137) / Raw(nb))
        # a reset connection and an SSH session on the LAN
        self.tls(me, "www.example.com", s["www.example.com"], size=1400,
                 rst=True)
        ph = self.PHONE
        self._emit(Ether(src=ph[1], dst=me[1]) / IP(src=ph[0], dst=me[0]) /
                   TCP(sport=50022, dport=22, flags="S"))
        self._emit(Ether(src=me[1], dst=ph[1]) / IP(src=me[0], dst=ph[0]) /
                   TCP(sport=22, dport=50022, flags="SA"))
        self._emit(Ether(src=me[1], dst=ph[1]) / IP(src=me[0], dst=ph[0]) /
                   TCP(sport=22, dport=50022, flags="PA") /
                   Raw(b"SSH-2.0-OpenSSH_9.6\r\n"))
        # later: the printer is gone and its address is reused by a laptop
        self.t += 900
        self.dhcp(self.LAPTOP, vendor_class="MSFT 5.0")
        self.arp_announce(self.LAPTOP)
        self.tls(self.LAPTOP, "www.example.com", s["www.example.com"],
                 size=9000)
        return self.frames

    def busy_mix(self, n=20000, seed=3):
        """Many short flows from many devices (benchmarks)."""
        rng = random.Random(seed)
        frames = []
        t = self.t
        tmpl = []
        for i in range(64):
            mac = f"00:16:3e:00:{i // 256:02x}:{i % 256:02x}"
            ip = f"192.168.1.{100 + i % 120}"
            rip = f"34.{i}.{i % 7}.{(i * 13) % 251 + 1}"
            tmpl.append(bytes(Ether(src=mac, dst=self.GW[1]) /
                              IP(src=ip, dst=rip) /
                              TCP(sport=40000 + i, dport=443, flags="PA") /
                              Raw(b"\x17\x03\x03" + bytes(rng.choice(
                                  (60, 300, 1200))))))
            tmpl.append(bytes(Ether(src=self.GW[1], dst=mac) /
                              IP(src=rip, dst=ip, ttl=55) /
                              TCP(sport=443, dport=40000 + i, flags="A") /
                              Raw(b"\x17\x03\x03" + bytes(1380))))
        for k in range(n):
            t += 0.00005
            frames.append((tmpl[k % len(tmpl)], round(t, 6), 1))
        return frames


def scenario_identity():
    """(gateway, my_ips, my_macs, local_nets) of the scripted network."""
    return (ScenarioBuilder.GW[0], {ScenarioBuilder.ME[0]},
            {ScenarioBuilder.ME[1]},
            [ipaddress.ip_network("192.168.1.0/24")])


def scenario_model(config, frames=None, decoder=None):
    """Replay frames through decoder + model exactly like an import."""
    gw, ips, macs, nets = scenario_identity()
    m = NetworkModel(config, gw, ips, macs)
    m.set_identity(local_nets=nets)
    m.use_packet_clock = True
    frames = frames if frames is not None else \
        ScenarioBuilder().home_network()
    replay_frames(m, frames, decoder=decoder)
    return m


def replay_frames(model, frames, decoder=None, tick_every=500):
    dec = decoder or default_frame_decoder(model)
    for i, (raw, ts, lt) in enumerate(frames):
        d = dec(raw, ts, lt)
        if d is None:
            continue
        model.ingest(d)
        if tick_every and i % tick_every == tick_every - 1:
            model.tick()
    model.tick()
    model._announce_created(flush=True)
    return model


def default_frame_decoder(model):
    reasm = TlsReassembler()

    def dec(raw, ts, lt=1):
        pkt = Ether(raw) if lt == 1 else Raw(raw)
        pkt.time = ts
        d = decode_packet(pkt, model.gateway_ip, model.my_ips, reasm)
        d["time"] = ts
        return d
    return dec


def golden_checks(model):
    """Semantic expectations for ScenarioBuilder.home_network(). Returns a
    list of human-readable failures (empty = all good)."""
    fails = []
    S = ScenarioBuilder
    reg = model.registry

    def dev_by_mac(mac):
        return reg.by_key.get(reg.resolve(mac)) if hasattr(reg, "resolve") \
            else reg.by_key.get(mac)

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    for dv in reg.by_key.values():
        check(not (dv.ip and is_public_ip(dv.ip)),
              f"public address became a device: {dv.ip}")
        for a in dv.ipv4s:
            check(not is_public_ip(a), f"device {dv.key} holds public {a}")
    phone = dev_by_mac(S.PHONE[1])
    check(phone is not None, "phone not discovered")
    if phone is not None:
        check(phone.dhcp_hostname == "Alex-iPhone",
              f"phone hostname={phone.dhcp_hostname!r}")
        check(any(a.startswith(S.V6_PREFIX) for a in phone.ipv6),
              f"phone IPv6 missing: {sorted(phone.ipv6)}")
    tv = dev_by_mac(S.TV[1])
    check(tv is not None and tv.device_class in ("Smart TV",
                                                 "Streaming device"),
          f"tv class={getattr(tv, 'device_class', None)}")
    pr = dev_by_mac(S.PRINTER[1])
    check(pr is not None and pr.device_class == "Printer",
          f"printer class={getattr(pr, 'device_class', None)}")
    lap = dev_by_mac(S.LAPTOP[1])
    check(lap is not None and lap.device_class == "Windows PC",
          f"laptop class={getattr(lap, 'device_class', None)}")
    check(lap is not None and pr is not None and lap.key != pr.key,
          "printer and laptop merged (IP reuse)")
    gwd = dev_by_mac(S.GW[1])
    check(gwd is not None and gwd.device_class == "Router",
          f"router class={getattr(gwd, 'device_class', None)}")
    w = model.websites
    check("www.example.com" in w and "TLS SNI" in w["www.example.com"].sources,
          "www.example.com not seen via TLS SNI")
    check("tracker.example.net" in w and
          w["tracker.example.net"].connections == 0,
          "lookup-only domain counted as a connection")
    check("plain.example.org" in w and
          "HTTP Host" in w["plain.example.org"].sources,
          "HTTP Host not recorded")
    check("93.184.215.14" in model.remote_hosts, "remote host missing")
    check("93.184.215.14" not in reg.ip_to_key,
          "remote host address mapped to a device")
    kinds = {a.kind for a in model.alerts.alerts.values()}
    check("cleartext" in kinds, f"no cleartext alert (kinds={sorted(kinds)})")
    check(model.dns.encrypted_seen, "encrypted DNS not noticed")
    check(len(model.flows.all_flows()) >= 10,
          f"too few flows: {len(model.flows.all_flows())}")
    check(any(f.domain == "files.example.org"
              for f in model.flows.all_flows()),
          "connection not named from its lookup")
    for extra in GOLDEN_EXTRA:
        msg = extra(model)
        if msg:
            fails.append(msg)
    return fails


GOLDEN_EXTRA = []       # later milestones append (model) -> str|None checks
