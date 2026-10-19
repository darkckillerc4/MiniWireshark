# ============================================================================
#  12c.  Coverage and claims — "what can I actually see from here?"
#
#  The vantage meter watches what share of unicast traffic belongs to OTHER
#  devices. On an ordinary switched network or Wi-Fi this computer mostly
#  sees its own traffic plus broadcasts ("endpoint view"); behind a hub,
#  a mirror/SPAN port or with monitor-mode Wi-Fi it sees much more. Every
#  view uses this to say what it can't know, instead of implying that
#  "not seen" means "didn't happen".
# ============================================================================
VANTAGE_TEXT = {
    "unknown": ("Still measuring", "Not enough traffic yet to tell what "
                "this computer can see."),
    "endpoint": ("This computer's view", "I see this computer's own "
                 "traffic plus broadcasts and announcements from everyone. "
                 "Other devices' private connections go straight to the "
                 "router and are NOT visible here."),
    "partial": ("Partial view", "I see some traffic between other devices "
                "(a hub, a Wi-Fi quirk or a partial mirror), but not all "
                "of it."),
    "mirror": ("Network-wide view", "Most traffic I see is between other "
               "devices — this looks like a mirror/SPAN port or a hub, so "
               "other devices' connections are visible too."),
    "file": ("Imported capture", "This data comes from a file; where it "
             "was captured (and so what it could see) is unknown."),
}


class VantageMeter:
    """Decayed share of unicast frames that involve neither this computer's
    hardware address nor its IP."""

    DECAY = 0.9995

    def __init__(self):
        self.own = 0.0
        self.third = 0.0
        self.frames = 0
        self.bcast = 0

    def note(self, d, my_macs, my_ips):
        self.frames += 1
        if d["multicast"]:
            self.bcast += 1
            return
        sm, dm = d["src_mac"], d["dst_mac"]
        if sm and dm and my_macs:
            mine = sm in my_macs or dm in my_macs
        else:
            mine = d["src_ip"] in my_ips or d["dst_ip"] in my_ips
        self.own *= self.DECAY
        self.third *= self.DECAY
        if mine:
            self.own += 1.0
        else:
            self.third += 1.0

    def share_third(self):
        tot = self.own + self.third
        return self.third / tot if tot else 0.0

    def classify(self, offline=False):
        if offline:
            return "file"
        if self.own + self.third < 150:
            return "unknown"
        r = self.share_third()
        if r < 0.02:
            return "endpoint"
        if r < 0.35:
            return "partial"
        return "mirror"

    def to_dict(self):
        return {"own": self.own, "third": self.third, "frames": self.frames,
                "bcast": self.bcast}

    def load(self, d):
        with contextlib.suppress(TypeError, ValueError, AttributeError):
            self.own = float(d.get("own", 0))
            self.third = float(d.get("third", 0))
            self.frames = int(d.get("frames", 0))
            self.bcast = int(d.get("bcast", 0))


def coverage_rows(model, data_mode="live", active=False):
    """[(question, answer, level, why)] — the coverage card's content."""
    v = model.vantage.classify(offline=data_mode in ("offline", "session"))
    rows = []
    devs = [d for d in model.registry.by_key.values()]
    heard = sum(1 for d in devs if d.packets_out == 0)
    rows.append((
        "Which devices are on the network?",
        f"{len(devs)} found" + (f" ({heard} only heard about, never seen "
                                f"sending)" if heard else ""),
        LV_OBSERVED if devs else LV_UNKNOWN,
        "Devices appear when they send something local (ARP, DHCP, mDNS…)."
        + ("" if active else " In Quiet Mode, silent devices that never "
           "announce themselves can be missed.")))
    if v in ("endpoint", "unknown", "file"):
        rows.append((
            "What do OTHER devices connect to?",
            "Mostly not visible from here" if v == "endpoint" else
            VANTAGE_TEXT[v][0],
            LV_UNKNOWN,
            "Their lookups (if they use plain DNS through this computer) "
            "and broadcasts are visible; their private connections go "
            "straight to the router. A router or Pi-hole connection can "
            "add this."))
    else:
        rows.append(("What do OTHER devices connect to?",
                     "Visible (" + VANTAGE_TEXT[v][0].lower() + ")",
                     LV_OBSERVED, VANTAGE_TEXT[v][1]))
    enc = sum(model.dns.encrypted_seen.values())
    plain = model.metrics.totals.get("dns_queries", 0) if hasattr(
        model.metrics, "totals") else 0
    if enc and not plain:
        dns_ans, lvl = "Hidden: lookups are encrypted (DoH/DoT)", \
            LV_UNKNOWN
    elif enc:
        dns_ans, lvl = "Partly hidden: some devices use encrypted DNS", \
            LV_OBSERVED
    else:
        dns_ans, lvl = "Plain DNS lookups are visible", LV_OBSERVED
    rows.append(("Which website names are looked up?", dns_ans, lvl,
                 "Encrypted DNS and VPNs hide names; a lookup alone does "
                 "not prove a visit."))
    if model.vpn.get("iface") or model.vpn.get("endpoint"):
        rows.append(("Internet destinations of this computer",
                     "Hidden inside a VPN tunnel", LV_UNKNOWN,
                     "Only the tunnel endpoint is visible."))
    rows.append(("Full web addresses and page contents",
                 "Never visible for https", LV_UNKNOWN,
                 "Only the site NAME (e.g. example.com) can be seen."))
    return rows


def blind_spots(model, data_mode="live", active=False):
    out = []
    v = model.vantage.classify(offline=data_mode in ("offline", "session"))
    if v == "endpoint":
        out.append("Other devices' connections (switched network)")
    if not active and data_mode == "live":
        out.append("Silent devices (Quiet Mode sends no probes)")
    if model.dns.encrypted_seen:
        out.append("Encrypted DNS lookups")
    if model.vpn.get("iface") or model.vpn.get("endpoint"):
        out.append("Traffic inside the VPN")
    return out


_NAME_SOURCE = {"user": ("you named it", LV_REPORTED),
                "dhcp": ("it announced this name via DHCP", LV_OBSERVED),
                "mdns": ("it announced this name via mDNS", LV_OBSERVED),
                "nbns": ("it answered a Windows name query", LV_OBSERVED),
                "ssdp": ("it announced itself via UPnP", LV_OBSERVED),
                "rdns": ("your DNS server's reverse lookup", LV_REPORTED),
                "vendor": ("guessed from the maker and device type",
                           LV_INFERRED),
                "": ("no name seen", LV_UNKNOWN)}
_EXIST_OBS = ("arp_reply", "dhcp_request", "dhcp_ack", "mdns", "ssdp", "nd",
              "nbns", "ra")


def device_name_source(dev):
    if dev.alias:
        return "user"
    if dev.dhcp_hostname:
        return "dhcp"
    if dev.mdns_name:
        return "mdns"
    if dev.hostname and dev.hostname_source in ("nbns", "rdns", "mdns",
                                                "dhcp"):
        return dev.hostname_source
    if dev.ssdp_name:
        return "ssdp"
    if dev.vendor or dev.device_class != "Unknown":
        return "vendor"
    return ""


def device_claims(model, dev):
    """[(claim, value, level, why, proof_kinds)] for the inspector."""
    claims = []
    if dev.packets_out:
        lvl, why = LV_OBSERVED, "It sent traffic on your local network."
    elif any(e.source in ("arp_reply", "dhcp_lease", "dhcp_client",
                          "ipv6_nd", "mdns", "ssdp", "nbns")
             for e in dev.evidence):
        lvl, why = LV_OBSERVED, "It answered or announced itself."
    else:
        lvl, why = LV_INFERRED, ("Only heard about: other traffic was "
                                 "addressed to it, but it hasn't been seen "
                                 "sending anything itself.")
    claims.append(("Is on your network", dev.confidence + " confidence",
                   lvl, why, _EXIST_OBS))
    src = device_name_source(dev)
    text, lvl = _NAME_SOURCE.get(src, _NAME_SOURCE[""])
    claims.append(("Name", dev.display_name(), lvl, text.capitalize() + ".",
                   ("dhcp_request", "dhcp_ack", "mdns", "nbns", "ssdp")))
    if dev.device_class != "Unknown":
        claims.append(("Kind of device",
                       f"{dev.class_confidence} {dev.device_class}".strip(),
                       LV_INFERRED, "; ".join(dev.class_reasons[:3]) or
                       "Combined weak hints.", ()))
    else:
        claims.append(("Kind of device", "Unknown", LV_UNKNOWN,
                       "Not enough clues yet.", ()))
    if dev.ip:
        claims.append(("Address", dev.ip, LV_OBSERVED,
                       "Seen in its own traffic or its DHCP lease.",
                       ("dhcp_ack", "arp_reply")))
    now = model.now()
    if dev.state == STATE_ACTIVE:
        claims.append(("Online", f"yes — seen {human_duration(max(0, now - dev.last_seen))} ago",
                       LV_OBSERVED, "Recent traffic or replies.", ()))
    else:
        claims.append(("Online", f"not seen for "
                                 f"{human_duration(max(0, now - dev.last_seen))}",
                       LV_UNKNOWN, "Not seeing a device doesn't prove it's "
                                   "off — it may just be quiet.", ()))
    conn = look = poss = 0
    for dom in dev.websites:
        w = model.websites.get(dom)
        a = w.ties.get(dev.key, [""])[0] if w else ""
        if ASSOC_RANK.get(a, 0) >= 4:
            conn += 1
        elif a in (AS_LOOKUP_ONLY, AS_REPORTED):
            look += 1
        else:
            poss += 1
    if conn or look or poss:
        claims.append(("Websites", f"{conn} connected · {look} looked up "
                                   f"only · {poss} possibly",
                       LV_OBSERVED if conn else
                       (LV_CORRELATED if look else LV_INFERRED),
                       "Connected = name seen in its connection or right "
                       "after its own lookup.",
                       ("tls_sni", "http_host", "dns_answer")))
    return claims


def device_weakest(model, dev):
    """Three-glyph evidence signature: exists · name · kind."""
    c = device_claims(model, dev)
    return " ".join(LEVEL_GLYPH[x[2]] for x in c[:3])


