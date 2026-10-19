# ---- LLDP and CDP: the switch tells this computer which port it is on ------
LLDP_CAPS = ((0x04, "switch"), (0x08, "Wi-Fi access point"),
             (0x10, "router"), (0x20, "phone"), (0x02, "repeater"),
             (0x40, "cable modem"), (0x80, "station"), (0x01, "other"))
CDP_CAPS = ((0x08, "switch"), (0x01, "router"), (0x02, "bridge"),
            (0x10, "host"), (0x80, "phone"), (0x40, "repeater"),
            (0x200, "two-port MAC relay"))
CDP_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"


def _disc_text(b, limit=120):
    return sanitize_text(bytes(b).decode("utf-8", "replace"), limit)


def _lldp_id(sub, data, port=False):
    if (sub == 4 and not port or sub == 3 and port) and len(data) == 6:
        return _mac(data)
    if (sub == 5 and not port or sub == 4 and port) and len(data) >= 5 \
            and data[0] == 1:
        return _ip4(data[1:5])
    return _disc_text(data)


def parse_lldp(buf):
    """LLDP (IEEE 802.1AB) TLVs → plain facts. Tolerates truncation."""
    out = {"proto": "LLDP", "chassis": "", "port": "", "port_desc": "",
           "system": "", "descr": "", "caps": [], "mgmt": "", "vlan": None,
           "ttl": None}
    pos, n = 0, len(buf)
    while pos + 2 <= n:
        hdr = struct.unpack_from(">H", buf, pos)[0]
        t, ln = hdr >> 9, hdr & 0x1ff
        pos += 2
        v = buf[pos:pos + ln]
        pos += ln
        if t == 0:
            break
        if t == 1 and len(v) >= 2:
            out["chassis"] = _lldp_id(v[0], v[1:])
        elif t == 2 and len(v) >= 2:
            out["port"] = _lldp_id(v[0], v[1:], port=True)
        elif t == 3 and len(v) >= 2:
            out["ttl"] = struct.unpack(">H", v[:2])[0]
        elif t == 4:
            out["port_desc"] = _disc_text(v)
        elif t == 5:
            out["system"] = _disc_text(v)
        elif t == 6:
            out["descr"] = _disc_text(v, 200)
        elif t == 7 and len(v) >= 4:
            en = struct.unpack(">H", v[2:4])[0]
            out["caps"] = [nm for bit, nm in LLDP_CAPS if en & bit]
        elif t == 8 and len(v) >= 2 and not out["mgmt"]:
            alen, sub = v[0], v[1]
            addr = v[2:1 + alen]
            if sub == 1 and len(addr) == 4:
                out["mgmt"] = _ip4(addr)
            elif sub == 2 and len(addr) == 16:
                out["mgmt"] = _ip6(addr)
        elif t == 127 and len(v) >= 6 and v[:3] == b"\x00\x80\xc2" and \
                v[3] == 1:
            out["vlan"] = struct.unpack(">H", v[4:6])[0]
    return out if (out["chassis"] or out["system"]) else None


def parse_cdp(buf):
    """Cisco Discovery Protocol (after the SNAP header) → plain facts."""
    out = {"proto": "CDP", "chassis": "", "port": "", "port_desc": "",
           "system": "", "descr": "", "caps": [], "mgmt": "", "vlan": None,
           "ttl": None, "platform": ""}
    if len(buf) < 4:
        return None
    out["ttl"] = buf[1]
    pos, n = 4, len(buf)
    while pos + 4 <= n:
        t, ln = struct.unpack_from(">HH", buf, pos)
        if ln < 4:
            break
        v = buf[pos + 4:pos + ln]
        pos += ln
        if t == 0x01:
            out["system"] = out["chassis"] = _disc_text(v)
        elif t in (0x02, 0x16) and len(v) >= 4 and not out["mgmt"]:
            p = 4
            for _ in range(min(8, struct.unpack(">I", v[:4])[0])):
                if p + 2 > len(v):
                    break
                ptype, plen = v[p], v[p + 1]
                proto = v[p + 2:p + 2 + plen]
                p += 2 + plen
                if p + 2 > len(v):
                    break
                alen = struct.unpack(">H", v[p:p + 2])[0]
                addr = v[p + 2:p + 2 + alen]
                p += 2 + alen
                if ptype == 1 and proto == b"\xcc" and len(addr) == 4:
                    out["mgmt"] = _ip4(addr)
                    break
        elif t == 0x03:
            out["port"] = _disc_text(v)
        elif t == 0x04 and len(v) >= 4:
            en = struct.unpack(">I", v[:4])[0]
            out["caps"] = [nm for bit, nm in CDP_CAPS if en & bit]
        elif t == 0x05:
            out["descr"] = _disc_text(v, 200)
        elif t == 0x06:
            out["platform"] = _disc_text(v)
        elif t == 0x0a and len(v) >= 2:
            out["vlan"] = struct.unpack(">H", v[:2])[0]
    return out if out["system"] else None


def l2_discovery(raw):
    """LLDP or CDP facts from a raw Ethernet frame, else None."""
    if len(raw) < 22:
        return None
    et = struct.unpack_from(">H", raw, 12)[0]
    if et == 0x88cc:
        return parse_lldp(raw[14:])
    if et < 0x0600 and raw[14:22] == CDP_SNAP:
        return parse_cdp(raw[22:])
    return None


def _label_l2_discovery(d, info):
    d["proto"] = d["tag"] = info["proto"]
    d["lldp"] = info
    d["app_conf"] = "Observed"
    d["encrypted"] = "no"
    d["src"], d["dst"] = d["src_mac"], d["dst_mac"]
    name = info["system"] or info["chassis"]
    what = ", ".join(info["caps"][:2]) or "network device"
    port = info["port_desc"] or info["port"]
    d["text"] = (f"{what.capitalize()} “{name}” says this link is its port "
                 f"{port or '?'}" + (f" (VLAN {info['vlan']})"
                                     if info["vlan"] else "") +
                 f" — {info['proto']}")
    return d
