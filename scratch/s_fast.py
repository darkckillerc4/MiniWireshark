# ============================================================================
#  5b.  Fast wire decoder
#
#  A struct-based decoder for the frames that make up nearly all real
#  traffic (Ethernet/VLAN, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6 incl.
#  neighbour discovery, DNS/mDNS/LLMNR, DHCP, SSDP, NBNS, NTP, QUIC, TLS and
#  HTTP). It produces exactly the same dict as decode_packet() — a
#  differential self-test replays the scenario through both and compares
#  them field by field — at roughly 15–20× the speed, and it never builds a
#  scapy object. Anything it doesn't understand is handed to the scapy
#  decoder, so coverage never shrinks. The packet object for the detail
#  view is built lazily from the raw bytes (packet_object()).
# ============================================================================
_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")
_TCP_FLAG_NAMES = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                   (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"))
_ETHER_NAMES = {0x88cc: "LLDP", 0x888e: "EAPOL", 0x8863: "PPPoE",
                0x8864: "PPPoE", 0x88e1: "HomePlug AV", 0x893a: "IEEE 1905",
                0x8899: "Realtek", 0x88b5: "Experimental", 0x22f0: "AVTP",
                0x88f7: "PTP", 0x9000: "Loopback"}
_IPPROTO_NAMES = {47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP",
                  103: "PIM", 112: "VRRP", 41: "IPv6-in-IPv4", 4: "IP-in-IP"}
_ICMP4_TEXT = {0: "Ping reply", 3: "Destination unreachable",
               8: "Ping request", 11: "Time exceeded",
               5: "Redirect (router suggests another path)"}
_ICMP6_NAMES = {2: "ICMPv6 Packet Too Big", 3: "ICMPv6 Time Exceeded",
                4: "ICMPv6 Parameter Problem", 137: "ICMPv6 ND Redirect",
                139: "ICMPv6 Node Information Query",
                140: "ICMPv6 Node Information Reply"}
_MLD_TYPES = (130, 131, 132, 143)


class NeedDeepParse(Exception):
    """The fast decoder declines this frame; use the scapy decoder."""


def _mac(b):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(b[:6])


def _ip4(b):
    return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])


def _ip6(b):
    try:
        return str(ipaddress.IPv6Address(bytes(b[:16])))
    except (ValueError, ipaddress.AddressValueError):
        return ""


def _wire_name(buf, pos, depth=0):
    """DNS name at `pos` (with compression). Returns (name, next_pos)."""
    labels = []
    jumped = False
    nxt = pos
    hops = 0
    n = len(buf)
    while True:
        if pos >= n:
            raise ValueError("name past end")
        ln = buf[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= n:
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                nxt = pos + 2
            jumped = True
            hops += 1
            if hops > 32 or ptr >= n:
                raise ValueError("pointer loop")
            pos = ptr
            continue
        if ln & 0xC0:
            raise ValueError("bad label")
        pos += 1
        labels.append(bytes(buf[pos:pos + ln]))
        pos += ln
        if len(labels) > 64:
            raise ValueError("too many labels")
    raw = b".".join(labels)
    return _name_bytes(raw), (nxt if jumped else pos)


def wire_dns(buf, kind):
    """DNS message bytes → (text, learns, hint, info) via dns_summary()."""
    if len(buf) < 12:
        raise ValueError("short DNS header")
    qid, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", buf, 0)
    qr = (flags >> 15) & 1
    rcode = flags & 0x0F
    pos = 12
    qname, qtype = "", 0
    for i in range(min(qd, 16)):
        name, pos = _wire_name(buf, pos)
        if pos + 4 > len(buf):
            raise ValueError("short question")
        t = _U16.unpack_from(buf, pos)[0]
        pos += 4
        if i == 0:
            qname, qtype = name, t
    records = []
    if qr:
        want = an + (ns + ar if kind == "mDNS" else 0)
        for i in range(min(an + ns + ar, 200)):
            if pos >= len(buf):
                break
            rrname, pos = _wire_name(buf, pos)
            if pos + 10 > len(buf):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", buf,
                                                             pos)
            pos += 10
            rdata = buf[pos:pos + rdlen]
            rstart = pos
            pos += rdlen
            in_an = i < an
            in_ar = i >= an + ns
            if not (in_an or (kind == "mDNS" and in_ar)) or i >= want + ns:
                continue
            ip, rstr, txt = None, "", []
            if rtype == 1 and rdlen == 4:
                ip = rstr = _ip4(rdata)
            elif rtype == 28 and rdlen == 16:
                ip = rstr = _ip6(rdata)
            elif rtype in (5, 12, 2):
                try:
                    rstr = _wire_name(buf, rstart)[0]
                except ValueError:
                    rstr = ""
            elif rtype == 16:
                p = 0
                while p < len(rdata):
                    ln = rdata[p]
                    txt.append(bytes(rdata[p + 1:p + 1 + ln]))
                    p += 1 + ln
                rstr = sanitize_text(" ".join(
                    t.decode("utf-8", "ignore") for t in txt), 255)
            elif rtype == 33 and rdlen >= 7:
                try:
                    rstr = _wire_name(buf, rstart + 6)[0]
                except ValueError:
                    rstr = ""
            else:
                rstr = sanitize_text(bytes(rdata).decode("utf-8", "ignore"),
                                     255)
            records.append((rrname, rtype, ip, rstr, txt))
    return dns_summary(kind, qname, qtype, qid, qr, rcode, records)


def _wire_dhcp(load):
    """BOOTP/DHCP payload → dhcp_from_options() result."""
    if len(load) < 240 or load[236:240] != b"\x63\x82\x53\x63":
        raise NeedDeepParse("not DHCP")
    yiaddr = _ip4(load[16:20])
    chaddr = bytes(load[28:34])
    opts = []
    p = 240
    n = len(load)
    while p < n:
        code = load[p]
        if code == 255:
            break
        if code == 0:
            p += 1
            continue
        if p + 1 >= n:
            break
        ln = load[p + 1]
        val = bytes(load[p + 2:p + 2 + ln])
        p += 2 + ln
        if code in (53,) and ln >= 1:
            opts.append((53, val[0]))
        elif code in (12, 60, 61):
            opts.append((code, val))
        elif code in (50, 54, 3) and ln >= 4:
            opts.append((code, _ip4(val)))
        elif code == 51 and ln >= 4:
            opts.append((51, _U32.unpack_from(val)[0]))
        elif code == 6 and ln >= 4:
            opts.append(tuple([6] + [_ip4(val[i:i + 4])
                                     for i in range(0, ln - ln % 4, 4)]))
        elif code == 55:
            opts.append((55, list(val)))
    return dhcp_from_options(opts, yiaddr, chaddr)


def packet_object(d):
    """The scapy packet for a decoded row (built on demand, then cached)."""
    pkt = d.get("pkt")
    if pkt is not None:
        return pkt
    raw = d.get("raw")
    if raw is None or Ether is None:
        return None
    lt = d.get("linktype", 1)
    try:
        cls = Ether if lt == 1 else (conf.l2types.get(lt) or Raw)
        pkt = cls(raw)
    except Exception:                                # noqa: BLE001
        pkt = Raw(raw)
    pkt.time = d.get("time", 0.0)
    d["pkt"] = pkt
    return pkt


def _fast_new(raw, ts, lt):
    return {"proto": "?", "tag": "OTHER", "text": "",
            "src": "", "dst": "", "src_ip": "", "dst_ip": "",
            "src_mac": "", "dst_mac": "", "ttl": "", "ttl_int": 0,
            "sport": None, "dport": None, "ipver": 0, "transport": "",
            "tcp_flags": None, "seq": None, "payload_len": 0,
            "dns_names": [], "doh_hint": "", "plain_dns": False,
            "type_hint": "", "dhcp_msgtype": None, "arp_op": None,
            "dhcp_yiaddr": "", "dhcp_hostname": "", "dhcp_client_mac": "",
            "dhcp": None, "dns": None, "tls": None, "nd": None,
            "ssdp": None, "mdns": None, "http_host": "",
            "service": "", "service_port": None, "app_conf": "",
            "encrypted": "unknown", "cleartext": "",
            "multicast": False, "l2_bcast": False,
            "learns": [], "pkt": None, "raw": raw, "linktype": lt,
            "time": ts, "length": len(raw)}


def fast_decode(raw, ts, lt=1, reasm=None, gateway_ip="", my_ips=()):
    """Raw frame bytes → decoded dict (same shape as decode_packet()).
    Falls back to the scapy decoder when it declines the frame."""
    try:
        return _fast_decode(raw, ts, lt, reasm)
    except (NeedDeepParse, struct.error, IndexError, ValueError):
        pass
    if Ether is None:
        raise RuntimeError("no decoder available for this frame")
    try:
        cls = Ether if lt == 1 else (conf.l2types.get(lt) or Raw)
        pkt = cls(raw)
    except Exception:                                # noqa: BLE001
        pkt = Raw(raw)
    pkt.time = ts
    d = decode_packet(pkt, gateway_ip, my_ips, reasm)
    d["time"] = ts
    d["raw"] = raw
    d["linktype"] = lt
    return d


def _fast_decode(raw, ts, lt, reasm):
    d = _fast_new(raw, ts, lt)
    n = len(raw)
    if lt == 1:
        if n < 14:
            raise NeedDeepParse("runt")
        dst, src = raw[0:6], raw[6:12]
        d["dst_mac"], d["src_mac"] = _mac(dst), _mac(src)
        d["l2_bcast"] = dst == b"\xff\xff\xff\xff\xff\xff"
        if dst[0] & 1 or dst == b"\x00\x00\x00\x00\x00\x00":
            d["multicast"] = True
        et = _U16.unpack_from(raw, 12)[0]
        off = 14
        vlans = 0
        while et in (0x8100, 0x88a8, 0x9100) and vlans < 2:
            if n < off + 4:
                raise NeedDeepParse("vlan")
            et = _U16.unpack_from(raw, off + 2)[0]
            off += 4
            vlans += 1
        if et < 0x0600:
            raise NeedDeepParse("802.3/LLC")
    elif lt == 113:                                   # Linux cooked v1
        if n < 16:
            raise NeedDeepParse("runt")
        et, off = _U16.unpack_from(raw, 14)[0], 16
    elif lt == 276:                                   # Linux cooked v2
        if n < 20:
            raise NeedDeepParse("runt")
        et, off = _U16.unpack_from(raw, 0)[0], 20
    elif lt in (101, 12, 14, 228, 229):               # raw IP
        if not n:
            raise NeedDeepParse("empty")
        v = raw[0] >> 4
        et, off = (0x0800 if v == 4 else 0x86DD if v == 6 else 0), 0
        if not et:
            raise NeedDeepParse("raw ip")
    elif lt == 0:                                     # BSD loopback
        if n < 4:
            raise NeedDeepParse("runt")
        fam = struct.unpack_from("<I", raw, 0)[0]
        et, off = (0x0800 if fam == 2 else 0x86DD if fam in (24, 28, 30)
                   else 0), 4
        if not et:
            raise NeedDeepParse("loopback family")
    else:
        raise NeedDeepParse(f"linktype {lt}")

    if et == 0x0806:
        return _fast_arp(d, raw, off)
    if et == 0x0800:
        return _fast_ipv4(d, raw, off, reasm)
    if et == 0x86DD:
        return _fast_ipv6(d, raw, off, reasm)
    name = _ETHER_NAMES.get(et)
    if name is None:
        raise NeedDeepParse(f"ethertype {et:#x}")
    d["proto"] = name
    d["text"] = f"{name} frame"
    d["src"], d["dst"] = d["src_mac"], d["dst_mac"]
    return d


def _fast_arp(d, raw, off):
    if len(raw) < off + 28:
        raise NeedDeepParse("short arp")
    htype, ptype, hlen, plen, op = struct.unpack_from(">HHBBH", raw, off)
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        raise NeedDeepParse("unusual arp")
    hwsrc = _mac(raw[off + 8:off + 14])
    psrc = _ip4(raw[off + 14:off + 18])
    hwdst = _mac(raw[off + 18:off + 24])
    pdst = _ip4(raw[off + 24:off + 28])
    d["src_ip"], d["dst_ip"] = psrc, pdst
    d["src_mac"], d["dst_mac"] = hwsrc, hwdst
    d["proto"], d["tag"], d["transport"] = "ARP", "ARP", "ARP"
    d["arp_op"] = op
    if op == 1:
        if psrc == pdst:
            d["text"] = f"{psrc} announced itself (gratuitous ARP)"
        else:
            d["text"] = f"Who has {pdst}? Tell {psrc}"
    elif op == 2:
        d["text"] = f"{psrc} is at {hwsrc}"
    else:
        d["text"] = f"ARP op={op}"
    d["src"] = psrc or hwsrc
    d["dst"] = pdst or hwdst
    d["ipver"] = 4
    return d


def _fast_ipv4(d, raw, off, reasm):
    n = len(raw)
    if n < off + 20:
        raise NeedDeepParse("short ipv4")
    vihl = raw[off]
    ihl = (vihl & 0x0F) * 4
    if vihl >> 4 != 4 or ihl < 20 or n < off + ihl:
        raise NeedDeepParse("bad ipv4 header")
    total = _U16.unpack_from(raw, off + 2)[0]
    frag = _U16.unpack_from(raw, off + 6)[0]
    ttl, proto = raw[off + 8], raw[off + 9]
    src, dst = _ip4(raw[off + 12:off + 16]), _ip4(raw[off + 16:off + 20])
    d["src_ip"], d["dst_ip"] = src, dst
    d["ttl"], d["ttl_int"], d["ipver"] = str(ttl), ttl, 4
    if is_multicast_or_broadcast(dst):
        d["multicast"] = True
    if frag & 0x1FFF or frag & 0x2000:
        raise NeedDeepParse("fragment")
    end = off + total if ihl <= total and off + total <= n else n
    l4 = off + ihl
    return _fast_l4(d, raw, proto, l4, end, reasm, 4)


def _fast_ipv6(d, raw, off, reasm):
    n = len(raw)
    if n < off + 40:
        raise NeedDeepParse("short ipv6")
    if raw[off] >> 4 != 6:
        raise NeedDeepParse("bad ipv6")
    plen = _U16.unpack_from(raw, off + 4)[0]
    nh, hlim = raw[off + 6], raw[off + 7]
    src, dst = _ip6(raw[off + 8:off + 24]), _ip6(raw[off + 24:off + 40])
    d["src_ip"], d["dst_ip"] = src, dst
    d["ttl"], d["ttl_int"], d["ipver"] = str(hlim), hlim, 6
    if is_multicast_or_broadcast(dst):
        d["multicast"] = True
    end = off + 40 + plen if off + 40 + plen <= n else n
    p = off + 40
    hops = 0
    while nh in (0, 43, 60) and hops < 6:
        if p + 2 > end:
            raise NeedDeepParse("short extension header")
        nh, hl = raw[p], (raw[p + 1] + 1) * 8
        p += hl
        hops += 1
    if nh == 44:
        raise NeedDeepParse("ipv6 fragment")
    return _fast_l4(d, raw, nh, p, end, reasm, 6)


def _fast_l4(d, raw, proto, p, end, reasm, ipver):
    if proto == 6:
        return _fast_tcp(d, raw, p, end, reasm)
    if proto == 17:
        return _fast_udp(d, raw, p, end)
    if proto == 1 and ipver == 4:
        if end - p < 4:
            raise NeedDeepParse("short icmp")
        t, code = raw[p], raw[p + 1]
        d["proto"], d["tag"], d["transport"] = "ICMP", "ICMP", "ICMP"
        d["sport"], d["dport"] = t, code
        d["text"] = _ICMP4_TEXT.get(t, f"ICMP type {t}")
        return _fast_done(d)
    if proto == 58 and ipver == 6:
        return _fast_icmpv6(d, raw, p, end)
    if proto == 2 and ipver == 4:
        d.update({"proto": "IGMP", "tag": "IGMP", "transport": "IGMP",
                  "text": "Joining/leaving a multicast group (IGMP)"})
        return _fast_done(d)
    name = _IPPROTO_NAMES.get(proto)
    if name is None:
        raise NeedDeepParse(f"ip proto {proto}")
    d["proto"] = name
    d["text"] = f"{name} frame"
    return _fast_done(d)


def _fast_done(d):
    d["src"] = d["src_ip"] or d["src_mac"]
    d["dst"] = d["dst_ip"] or d["dst_mac"]
    return d


def _fast_tcp(d, raw, p, end, reasm):
    if end - p < 20:
        raise NeedDeepParse("short tcp")
    sport, dport, seq = struct.unpack_from(">HHI", raw, p)
    dataofs = (raw[p + 12] >> 4) * 4
    flags = raw[p + 13] | ((raw[p + 12] & 1) << 8)
    if dataofs < 20 or p + dataofs > end:
        raise NeedDeepParse("bad tcp header")
    d["sport"], d["dport"] = sport, dport
    d["transport"] = "TCP"
    d["proto"], d["tag"] = "TCP", "TCP"
    d["tcp_flags"] = flags
    d["seq"] = seq
    names = [nm for b, nm in _TCP_FLAG_NAMES if flags & b]
    svc, sport_ = _port_service(sport, dport)
    d["service"], d["service_port"] = svc, sport_
    if svc:
        d["text"] = f"{svc} ({','.join(names) or 'data'})"
        d["app_conf"] = "Likely (by port)"
    else:
        d["text"] = f"Connecting ({','.join(names) or 'data'})"
    if sport_ in ENCRYPTED_PORTS:
        d["encrypted"] = "likely"
    load = raw[p + dataofs:end]
    if 53 in (sport, dport) and len(load) > 2:
        try:
            text, learns, hint, info = wire_dns(load[2:], "DNS")
        except ValueError:
            raise NeedDeepParse("odd dns/tcp")
        info["transport"] = "TCP"
        d.update({"proto": "DNS", "tag": "DNS", "text": text + " (TCP)",
                  "dns": info, "app_conf": "Observed"})
        d["learns"].extend(learns)
        d["plain_dns"] = dport == 53
        d["encrypted"] = "no"
        return _fast_done(d)
    d["payload_len"] = len(load)
    if load:
        _decode_tcp_payload(d, bytes(load), reasm)
    if not d["cleartext"] and d["payload_len"] and \
            sport_ in CLEARTEXT_PORTS:
        d["cleartext"] = CLEARTEXT_PORTS[sport_]
        d["encrypted"] = "no"
    return _fast_done(d)


def _fast_udp(d, raw, p, end):
    if end - p < 8:
        raise NeedDeepParse("short udp")
    sport, dport, ulen = struct.unpack_from(">HHH", raw, p)
    d["sport"], d["dport"] = sport, dport
    d["transport"] = "UDP"
    ports = (sport, dport)
    load = raw[p + 8:end]
    if ulen >= 8:
        load = load[:ulen - 8]
        d["payload_len"] = ulen - 8
    else:
        d["payload_len"] = len(load)
    load = bytes(load)
    if (53 in ports or 5353 in ports or 5355 in ports) and len(load) >= 12:
        name = "mDNS" if 5353 in ports else "LLMNR" if 5355 in ports \
            else "DNS"
        try:
            text, learns, hint, info = wire_dns(load, name)
        except ValueError:
            raise NeedDeepParse("odd dns")
        if dport == 53:
            d["plain_dns"] = True
        info["transport"] = "UDP"
        d.update({"proto": name, "tag": name, "text": text,
                  "app_conf": "Observed", "encrypted": "no"})
        if name == "mDNS":
            d["mdns"] = info
        else:
            d["dns"] = info
        d["learns"].extend(learns)
        if hint:
            d["type_hint"] = hint
    elif (67 in ports or 68 in ports) and len(load) >= 240:
        pr, t2, text, learns, info = _wire_dhcp(load)
        d.update({"proto": pr, "tag": t2, "text": text, "dhcp": info,
                  "app_conf": "Observed"})
        d["learns"].extend(learns)
        d["dhcp_msgtype"] = info["msgtype"]
        d["dhcp_yiaddr"] = info["yiaddr"]
        d["dhcp_hostname"] = info["hostname"]
        d["dhcp_client_mac"] = info["client_mac"]
    elif (546 in ports or 547 in ports) and load:
        mt = load[0]
        d.update({"proto": "DHCPv6", "tag": "DHCPv6",
                  "text": "IPv6 address setup: " +
                  DHCPV6_MSG.get(mt, f"message {mt}"),
                  "app_conf": "Observed"})
    elif 137 in ports and load:
        d["proto"], d["tag"] = "NBNS", "NBNS"
        nm = _try_nbns(load)
        if nm and d["src_ip"] and sport == 137 and len(load) > 12 and \
                load[2] & 0x80:
            d["text"] = f"{nm} is at {d['src_ip']} (Windows name)"
            d["learns"].append((d["src_ip"], nm))
        else:
            d["text"] = f"Local name lookup{(': ' + nm) if nm else ''}"
        d["app_conf"] = "Observed"
    elif 1900 in ports and load:
        text, hint, info = _decode_ssdp(load)
        d.update({"proto": "SSDP", "tag": "SSDP", "text": text,
                  "ssdp": info, "app_conf": "Observed"})
        if hint:
            d["type_hint"] = hint
    elif 123 in ports and len(load) >= 48:
        mode = load[0] & 0x07
        d.update({"proto": "NTP", "tag": "NTP",
                  "text": "Checking the time (NTP " +
                  {3: "request", 4: "reply"}.get(mode, "message") + ")",
                  "app_conf": "Observed", "encrypted": "no"})
    elif 443 in ports and load and (load[0] & 0x80):
        d.update({"proto": "QUIC", "tag": "QUIC",
                  "text": "Secure web connection (QUIC — the site name "
                          "is encrypted)",
                  "app_conf": "Observed", "encrypted": "yes",
                  "service": "Secure web browsing (QUIC)"})
        d["quic_initial"] = load if (load[0] & 0x30) == 0 else None
    elif 443 in ports and load:
        d.update({"proto": "QUIC", "tag": "QUIC",
                  "text": "Secure web connection (fast, encrypted)",
                  "app_conf": "Likely (by port)", "encrypted": "yes"})
    else:
        svc, sp = _port_service(sport, dport)
        d["service"], d["service_port"] = svc, sp
        d["proto"], d["tag"] = "UDP", "UDP"
        if sp in PORT_APP:
            d["proto"] = d["tag"] = PORT_APP[sp]
        d["text"] = (f"{svc} ({d['payload_len']} bytes)" if svc
                     else f"Quick message ({d['payload_len']} bytes)")
        d["app_conf"] = "Likely (by port)" if svc else ""
        if sp in VPN_PORTS:
            d["encrypted"] = "yes"
        elif sp in CLEARTEXT_PORTS:
            d["cleartext"] = CLEARTEXT_PORTS[sp]
            d["encrypted"] = "no"
    return _fast_done(d)


def _nd_options(raw, p, end):
    """ICMPv6 ND options → dict of first src/dst lladdr + prefix list."""
    out = {"src": "", "dst": "", "prefixes": []}
    hops = 0
    while p + 2 <= end and hops < 16:
        t, ln = raw[p], raw[p + 1] * 8
        if ln == 0:
            break
        body = raw[p:p + ln]
        if t == 1 and ln >= 8 and not out["src"]:
            out["src"] = _mac(body[2:8])
        elif t == 2 and ln >= 8 and not out["dst"]:
            out["dst"] = _mac(body[2:8])
        elif t == 3 and ln >= 32 and len(out["prefixes"]) < 7:
            out["prefixes"].append(f"{_ip6(body[16:32])}/{body[2]}")
        p += ln
        hops += 1
    return out


def _fast_icmpv6(d, raw, p, end):
    if end - p < 4:
        raise NeedDeepParse("short icmpv6")
    t = raw[p]
    nd = None
    if t == 134 and end - p >= 16:
        opts = _nd_options(raw, p + 16, end)
        nd = {"kind": "RA", "target": d["src_ip"],
              "mac": opts["src"] or d["src_mac"],
              "prefixes": opts["prefixes"],
              "lifetime": _U16.unpack_from(raw, p + 6)[0]}
        d["text"] = "Router announcement (IPv6)" + (
            f" — network {', '.join(opts['prefixes'])}"
            if opts["prefixes"] else "")
    elif t == 133:
        nd = {"kind": "RS", "target": "", "mac": d["src_mac"],
              "prefixes": []}
        d["text"] = "Looking for an IPv6 router (Router Solicitation)"
    elif t == 135 and end - p >= 24:
        tgt = _ip6(raw[p + 8:p + 24])
        opts = _nd_options(raw, p + 24, end)
        nd = {"kind": "NS", "target": tgt, "mac": opts["src"],
              "prefixes": [], "dad": d["src_ip"] == "::"}
        d["text"] = (f"Checking nobody else uses {tgt} (duplicate check)"
                     if nd["dad"] else f"Who has {tgt}? (IPv6)")
    elif t == 136 and end - p >= 24:
        tgt = _ip6(raw[p + 8:p + 24])
        opts = _nd_options(raw, p + 24, end)
        mac = opts["dst"] or d["src_mac"]
        nd = {"kind": "NA", "target": tgt, "mac": mac, "prefixes": [],
              "router": bool(raw[p + 4] & 0x80)}
        d["text"] = f"{tgt} is at {mac or '?'} (IPv6)"
    if nd is not None:
        d.update({"proto": "NDP", "tag": "NDP", "transport": "ICMPv6",
                  "nd": nd, "app_conf": "Observed"})
        return _fast_done(d)
    base = {"proto": "ICMPv6", "tag": "ICMPv6", "transport": "ICMPv6"}
    if t == 128:
        d.update(base, text="Ping request (IPv6)", sport=128, dport=0)
    elif t == 129:
        d.update(base, text="Ping reply (IPv6)", sport=129, dport=0)
    elif t == 1:
        d.update(base, text="Destination unreachable (IPv6)", sport=1,
                 dport=0)
    elif t in _MLD_TYPES:
        d.update(base, text="Multicast group membership report (IPv6)")
    elif t in _ICMP6_NAMES:
        d.update(base, text=_ICMP6_NAMES[t])
    else:
        raise NeedDeepParse(f"icmpv6 type {t}")
    return _fast_done(d)


