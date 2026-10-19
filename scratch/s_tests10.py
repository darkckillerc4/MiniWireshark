NETSH_EN = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 0f0e0d0c-0b0a-0908-0706-050403020100
    Physical address       : 3c:7c:3f:10:00:10
    Interface type         : Primary
    State                  : connected
    SSID                   : HomeNet
    AP BSSID               : 7C:10:C9:AA:BB:CC
    Band                   : 5 GHz
    Channel                : 44
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 960
    Signal                 : 44%
    Rssi                   : -78
    Profile                : HomeNet
"""
NETSH_FR = """
    Nom                    : Wi-Fi
    Description            : Realtek 8822CE
    État                   : connecté
    SSID                   : Maison
    BSSID                  : 11:22:33:44:55:66
    Type de radio          : 802.11ac
    Canal                  : 6
    Réception (Mbits/s)    : 144,4
    Transmission (Mbits/s) : 130
    Signal                 : 80 %
"""
NETSH_ES = """
    Nombre                 : Wi-Fi
    Estado                 : conectado
    SSID                   : Casa
    Canal                  : 149
    Velocidad de recepción (Mbps)  : 866,7
    Señal                  : 90%
"""
IW_LINK = """Connected to 7c:10:c9:aa:bb:cc (on wlp2s0)
\tSSID: HomeNet
\tfreq: 5180.0
\tRX: 123456 bytes (789 packets)
\tsignal: -54 dBm
\trx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
\ttx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 2
"""
PROC_WIRELESS = """Inter-| sta-|   Quality        |   Discarded packets  | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlp2s0: 0000   56.  -61.  -256        0      0      0      0     12        0
"""
MAC_AIRPORT = """Wi-Fi:
      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            HomeNet:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Network Type: Infrastructure
              Signal / Noise: -71 dBm / -94 dBm
              Transmit Rate: 864
          Other Local Wi-Fi Networks:
"""


@self_test()
def t_wifi_link_parsers(ctx):
    w = parse_netsh_wlan(NETSH_EN)
    assert w["ssid"] == "HomeNet" and w["rssi"] == -78 and \
        w["signal_pct"] == 44 and w["channel"] == 44, w
    assert w["rx_mbps"] == 1201 and w["tx_mbps"] == 960 and \
        w["bssid"] == "7c:10:c9:aa:bb:cc" and w["standard"] == "802.11ax"
    w = parse_netsh_wlan(NETSH_FR)
    assert w["ssid"] == "Maison" and w["channel"] == 6 and \
        w["rx_mbps"] == 144.4 and w["rssi"] == -60.0, w   # from 80 %
    w = parse_netsh_wlan(NETSH_ES)
    assert w["ssid"] == "Casa" and w["channel"] == 149 and \
        w["signal_pct"] == 90 and w["rx_mbps"] == 866.7, w
    assert parse_netsh_wlan("    Name : Wi-Fi\n    State : disconnected\n") \
        is None
    w = parse_iw_link(IW_LINK, "wlp2s0")
    assert w["rssi"] == -54 and w["channel"] == 36 and w["band"] == \
        "5 GHz" and w["rx_mbps"] == 866.7 and w["standard"] == "802.11ac"
    assert parse_iw_link("Not connected.") is None
    w = parse_proc_wireless(PROC_WIRELESS, "wlp2s0")
    assert w["rssi"] == -61, w
    w = parse_macos_airport(MAC_AIRPORT)
    assert w["ssid"] == "HomeNet" and w["rssi"] == -71 and \
        w["channel"] == 36 and w["noise"] == -94 and w["tx_mbps"] == 864
    assert wifi_channel_from_mhz(2437) == (6, "2.4 GHz")
    assert wifi_channel_from_mhz(5955) == (1, "6 GHz")
    assert wifi_quality(-55)[0] == "Healthy"
    assert wifi_quality(-70)[0] == "Degraded"
    assert wifi_quality(-78)[0] == "Needs attention" and "likely" in \
        wifi_quality(-78)[2]
    p = WifiProbe()
    p.last = parse_netsh_wlan(NETSH_EN)
    st, word, why, facts = p.summary()
    assert st == "Needs attention" and "-78 dBm" in facts and \
        "channel 44" in facts
    # the weak signal is named as the likely culprit, before the symptoms
    res = {"wifi": ("Needs attention", "weak"), "dns": ("Degraded", "slow"),
           "retrans": ("Needs attention", "re-sent"),
           "gateway": ("Healthy", "")}
    assert likely_culprit(res) == "wifi"
    assert likely_culprit({"dns": ("Degraded", ""),
                           "retrans": ("Degraded", "")}) == "dns"
    assert likely_culprit({"gateway": ("Healthy", "")}) is None


def _lldp_frame(system="core-sw1", port="Gi1/0/12", vlan=20,
                chassis=b"\x00\x1b\x54\x11\x22\x33", src="00:1b:54:11:22:3c"):
    def tlv(t, v):
        return struct.pack(">H", (t << 9) | len(v)) + v
    body = (tlv(1, b"\x04" + chassis) + tlv(2, b"\x05" + port.encode()) +
            tlv(3, struct.pack(">H", 120)) + tlv(4, b"Uplink to office") +
            tlv(5, system.encode()) + tlv(6, b"Switch OS 15.2") +
            tlv(7, struct.pack(">HH", 0x14, 0x04)) +
            tlv(8, b"\x05\x01\xc0\xa8\x01\x02\x02\x00\x00\x00\x01\x00") +
            tlv(127, b"\x00\x80\xc2\x01" + struct.pack(">H", vlan)) +
            tlv(0, b""))
    return (bytes.fromhex("0180c200000e") + bytes.fromhex(src.replace(":",
                                                                     "")) +
            b"\x88\xcc" + body)


def _cdp_frame(device="sw-floor2", port="FastEthernet0/7", vlan=30):
    def tlv(t, v):
        return struct.pack(">HH", t, len(v) + 4) + v
    addr = struct.pack(">I", 1) + b"\x01\x01\xcc" + struct.pack(">H", 4) + \
        bytes([10, 0, 0, 2])
    body = (b"\x02\xb4\x00\x00" + tlv(1, device.encode()) + tlv(2, addr) +
            tlv(3, port.encode()) + tlv(4, struct.pack(">I", 0x28)) +
            tlv(6, b"cisco WS-C2960") + tlv(0x0a, struct.pack(">H", vlan)))
    payload = CDP_SNAP + body
    return (bytes.fromhex("01000ccccccc") + bytes.fromhex("001b54aabbcc") +
            struct.pack(">H", len(payload)) + payload)


@self_test()
def t_lldp_cdp(ctx):
    """LLDP / CDP: both decoders read the switch, port and VLAN; the model
    records it and notices when the cable moves to another port."""
    if not ctx.scapy_ok:
        return "skip"
    for raw, proto, name, port, vlan in (
            (_lldp_frame(), "LLDP", "core-sw1", "Gi1/0/12", 20),
            (_cdp_frame(), "CDP", "sw-floor2", "FastEthernet0/7", 30)):
        a = _fast_decode(raw, 1.0, 1, None)
        b = decode_packet(Ether(raw))
        for d in (a, b):
            assert d["proto"] == proto and d["lldp"], (proto, d["proto"])
            info = d["lldp"]
            assert info["system"] == name and info["port"] == port and \
                info["vlan"] == vlan, info
            assert name in d["text"] and port in d["text"] or \
                "Uplink" in d["text"], d["text"]
        assert a["lldp"] == b["lldp"] and a["text"] == b["text"]
    info = parse_lldp(_lldp_frame()[14:])
    assert info["chassis"] == "00:1b:54:11:22:33" and info["mgmt"] == \
        "192.168.1.2" and "switch" in info["caps"] and info["ttl"] == 120
    info = parse_cdp(_cdp_frame()[22:])
    assert info["mgmt"] == "10.0.0.2" and "switch" in info["caps"] and \
        info["platform"] == "cisco WS-C2960"
    # truncated / hostile frames never crash
    rng = random.Random(9)
    base = _lldp_frame()
    for _ in range(300):
        cut = bytearray(base[:rng.randint(14, len(base))])
        for _k in range(rng.randint(0, 4)):
            if len(cut) > 15:
                cut[rng.randrange(14, len(cut))] = rng.randrange(256)
        l2_discovery(bytes(cut))
    # model: switch facts, a port change is a timeline warning
    m = scenario_model(ctx.cfg(), ctx.frames())
    t = ctx.frames()[-1][1]
    for i, raw in enumerate((_lldp_frame(), _lldp_frame(),
                             _lldp_frame(port="Gi1/0/13"))):
        d = _fast_decode(raw, t + 1 + i, 1, None)
        d["no"] = 90000 + i
        m.ingest(d)
    sw = m.switch_summary(t + 5)
    assert sw and sw["port"] == "Gi1/0/13" and sw["count"] == 3 and \
        sw["fresh"], sw
    tl = [e for e in m.timeline if e["kind"] == "network"]
    assert any("Plugged into core-sw1" in e["text"] for e in tl)
    assert any("Moved to core-sw1" in e["text"] and e["severity"] ==
               "WARNING" for e in tl), [e["text"] for e in tl]
    assert m.observations_for("switch:00:1b:54:11:22:33")


@self_test()
def t_tcp_measurements(ctx):
    """Handshake round trip (Karn's rule), duplicate ACKs, zero window,
    re-sent bytes and goodput; DNS lookup-time histogram."""
    if not ctx.scapy_ok:
        return "skip"
    S = ScenarioBuilder
    me, mac = S.ME[0], S.ME[1]
    rip = "93.184.215.14"

    def frame(t, out, flags, seq=0, ack=0, win=65535, load=b"", sport=40500):
        ip = IP(src=me, dst=rip) if out else IP(src=rip, dst=me)
        tcp = TCP(sport=sport, dport=443, flags=flags, seq=seq, ack=ack,
                  window=win) if out else TCP(sport=443, dport=sport,
                                              flags=flags, seq=seq, ack=ack,
                                              window=win)
        e = Ether(src=mac if out else S.GW[1], dst=S.GW[1] if out else mac)
        return (bytes(e / ip / tcp / Raw(load)) if load else
                bytes(e / ip / tcp), t, 1)
    t0 = ctx.frames()[-1][1] + 10
    fr = [frame(t0, True, "S", seq=100),
          frame(t0 + 0.042, False, "SA", seq=500, ack=101),
          frame(t0 + 0.043, True, "A", seq=101, ack=501),
          frame(t0 + 0.05, False, "PA", seq=501, ack=101, load=b"x" * 1000),
          frame(t0 + 0.06, True, "A", seq=101, ack=1501),
          frame(t0 + 0.07, True, "A", seq=101, ack=1501),     # duplicate
          frame(t0 + 0.08, True, "A", seq=101, ack=1501),     # duplicate
          frame(t0 + 0.30, False, "PA", seq=501, ack=101, load=b"x" * 1000),
          frame(t0 + 0.40, True, "A", seq=101, ack=1501, win=0),  # full
          frame(t0 + 2.0, False, "PA", seq=1501, ack=101, load=b"y" * 500)]
    # a second connection whose SYN was re-sent: no RTT (ambiguous)
    fr += [frame(t0 + 3, True, "S", seq=7, sport=40600),
           frame(t0 + 4, True, "S", seq=7, sport=40600),
           frame(t0 + 4.03, False, "SA", seq=9, ack=8, sport=40600)]
    m = scenario_model(ctx.cfg(), ctx.frames() + fr)
    f = next(x for x in m.flows.all_flows() if x.local_port == 40500)
    assert f.rtt is not None and abs(f.rtt - 0.042) < 0.002, f.rtt
    assert f.dupacks == 2, f.dupacks
    assert f.zero_win == 1, f.zero_win
    assert f.retrans == 1 and f.retx_bytes == 1000, (f.retrans,
                                                     f.retx_bytes)
    assert f.payload_in == 2500
    gp = f.goodput()
    assert gp and abs(gp - 1500 / 2.0) < 1, gp
    assert "round trip 42 ms" in f.tcp_health_text()
    g = next(x for x in m.flows.all_flows() if x.local_port == 40600)
    assert g.rtt is None and g.syns == 2
    med, p90, n = m.rtt_stats(t0 + 10)
    assert n >= 1 and abs(med - 42) < 2, (med, n)
    # DNS: the scenario's answered lookups land in the histogram
    hist = m.dns.histogram()
    assert sum(hist) == len(m.dns.latencies) or sum(hist) >= \
        min(len(m.dns.latencies), 1), (hist, len(m.dns.latencies))
    assert dns_bucket(5) == 0 and dns_bucket(30) == 2 and \
        dns_bucket(5000) == len(DNS_BUCKETS) - 1
    dt = DnsTracker()
    for i, ms in enumerate((5, 30, 30, 700, 1500)):
        info = {"id": i, "qname": f"q{i}.example", "rcode": 0}
        dt.on_query(100.0, "10.0.0.5", "10.0.0.1", info)
        dt.on_response(100.0 + ms / 1000.0, "10.0.0.5", "10.0.0.1", info)
    h = dt.histogram("10.0.0.1")
    assert h[0] == 1 and h[2] == 2 and h[6] == 1 and h[7] == 1, h
    round_trip = DnsTracker()
    round_trip.load(json.loads(json.dumps(dt.to_dict())))
    assert round_trip.histogram() == h
