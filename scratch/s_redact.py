# ============================================================================
#  Redaction (exports you want to share) and the printable inventory
#
#  Consistent pseudonyms within one export (the same device is always
#  "Device C", the same address always 192.0.2.7), chosen from ranges
#  reserved for documentation so they can never be mistaken for real ones.
#  Evidence levels and structure are kept; the original data is untouched.
# ============================================================================
REDACT_OPTIONS = {"addresses": "IP addresses",
                  "hardware": "Hardware (MAC) addresses",
                  "names": "Device names, notes and your labels",
                  "networks": "Network (Wi-Fi) names",
                  "sites": "Website names"}
_RX_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}\b")
_RX_IP4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_RX_IP6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9a-fA-F]{1,4}:){2,7}"
                     r"[0-9a-fA-F]{0,4}(?![0-9A-Za-z:])")
_RX_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                        r"[a-z]{2,24}\b", re.I)


class Redactor:
    def __init__(self, model=None, options=None, extra_names=()):
        self.opts = {k: True for k in REDACT_OPTIONS}
        self.opts["sites"] = False           # public names: kept by default
        self.opts.update(options or {})
        self.maps = {k: {} for k in ("ip4", "ip4pub", "ip6", "mac", "name",
                                     "net", "site")}
        self.names, self.networks = set(), set()
        if model is not None:
            self.learn(model)
        for n in extra_names:
            self._add_name(n)

    def _add_name(self, n, kind="names"):
        n = str(n or "").strip()
        if len(n) >= 3 and not _RX_IP4.fullmatch(n) and \
                not _RX_MAC.fullmatch(n):
            (self.names if kind == "names" else self.networks).add(n)

    def learn(self, model):
        for d in model.registry.by_key.values():
            for n in (d.alias, d.hostname, d.dhcp_hostname, d.mdns_name,
                      d.ssdp_name, d.notes):
                self._add_name(n)
            with contextlib.suppress(Exception):
                self._add_name(d.display_name())
        prof_names = getattr(model, "network_names", ()) or ()
        for n in prof_names:
            self._add_name(n, "networks")
        for rec in getattr(model, "switch_ports", {}).values():
            self._add_name(rec.get("system"))

    def _pseudo(self, kind, key, fmt):
        mp = self.maps[kind]
        if key not in mp:
            mp[key] = fmt(len(mp) + 1)
        return mp[key]

    @staticmethod
    def _letters(n):
        s = ""
        while n:
            n, r = divmod(n - 1, 26)
            s = chr(65 + r) + s
        return s

    def ip(self, ip):
        if ":" in ip:
            return self._pseudo("ip6", ip.lower(), lambda n: f"2001:db8::"
                                f"{n:x}")
        if is_private_ip(ip) or ip.startswith(("169.254.", "100.")):
            return self._pseudo("ip4", ip, lambda n: f"192.0.2.{n % 254 + 1}"
                                if n < 254 else f"192.0.2.{n % 254 + 1}"
                                f"#{n // 254}")
        if ip in ("0.0.0.0", "255.255.255.255") or ip.startswith(
                ("224.", "239.", "127.")):
            return ip                      # well-known, nothing personal
        return self._pseudo("ip4pub", ip, lambda n: f"198.51.100."
                            f"{n % 254 + 1}")

    def mac(self, mac):
        m = mac.lower().replace("-", ":")
        if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return m
        return self._pseudo("mac", m, lambda n: f"02:00:00:00:{n >> 8:02x}:"
                            f"{n & 255:02x}")

    def name(self, s):
        return self._pseudo("name", s.lower(),
                            lambda n: f"Device {self._letters(n)}")

    def network(self, s):
        return self._pseudo("net", s.lower(), lambda n: f"Network {n}")

    def site(self, s):
        return self._pseudo("site", s.lower(), lambda n: f"site-{n}.example")

    def text(self, s):
        """Redact free text (reports, CSV, copied details)."""
        s = str(s)
        if self.opts["names"] and self.names:
            rx = re.compile("|".join(re.escape(n) for n in sorted(
                self.names, key=len, reverse=True)), re.I)
            s = rx.sub(lambda m: self.name(m.group(0)), s)
        if self.opts["networks"] and self.networks:
            rx = re.compile("|".join(re.escape(n) for n in sorted(
                self.networks, key=len, reverse=True)), re.I)
            s = rx.sub(lambda m: self.network(m.group(0)), s)
        if self.opts["hardware"]:
            s = _RX_MAC.sub(lambda m: self.mac(m.group(0)), s)
        if self.opts["addresses"]:
            s = _RX_IP6.sub(lambda m: self.ip(m.group(0)) if ip_obj(
                m.group(0)) is not None else m.group(0), s)
            s = _RX_IP4.sub(lambda m: self.ip(m.group(0)) if ip_obj(
                m.group(0)) is not None else m.group(0), s)
        if self.opts["sites"]:
            s = _RX_DOMAIN.sub(lambda m: m.group(0) if m.group(0).lower(
            ).endswith((".example", ".local", ".lan", ".html", ".css")) or
                m.group(0).lower() in ("miniwireshark",) else
                self.site(m.group(0)), s)
        return s

    def summary(self):
        parts = []
        for kind, label in (("name", "names"), ("ip4", "local addresses"),
                            ("ip4pub", "Internet addresses"),
                            ("ip6", "IPv6 addresses"),
                            ("mac", "hardware addresses"),
                            ("net", "network names"), ("site", "websites")):
            if self.maps[kind]:
                parts.append(f"{len(self.maps[kind])} {label}")
        return ("Replaced: " + ", ".join(parts)) if parts else \
            "Nothing needed replacing."


def inventory_rows(model, namer=None):
    namer = namer or (lambda d: d.display_name())
    out = []
    for d in sorted(model.registry.by_key.values(),
                    key=lambda d: (not d.mine, namer(d).lower())):
        lvl = device_weakest(model, d)
        out.append({
            "name": namer(d), "kind": (f"{d.class_confidence} "
                                       f"{d.device_class}").strip(),
            "maker": d.vendor or "—", "ip": d.ip or "—",
            "ipv6": " ".join(sorted(d.ipv6)[:2]) or "—",
            "mac": d.mac or "—", "first": fmt_clock(d.first_seen, True),
            "last": fmt_clock(d.last_seen, True),
            "status": STATE_LABEL.get(d.state, d.state),
            "confidence": d.confidence, "evidence": LEVEL_GLYPH.get(lvl, "?")
            + " " + LEVEL_WORD.get(lvl, "Unknown"),
            "mine": "★" if d.mine else "", "expected": "✓" if d.expected
            else "", "notes": d.notes or ""})
    return out


def inventory_html(rows, title="Device inventory", subtitle=""):
    e = html.escape
    head = ("<tr><th></th><th>Device</th><th>Kind</th><th>Maker</th>"
            "<th>Address</th><th>Hardware address</th><th>Status</th>"
            "<th>Evidence</th><th>First seen</th><th>Last seen</th>"
            "<th>Expected</th><th>Notes</th></tr>")
    body = "".join(
        f"<tr><td>{e(r['mine'])}</td><td><b>{e(r['name'])}</b></td>"
        f"<td>{e(r['kind'])}</td><td>{e(r['maker'])}</td>"
        f"<td>{e(r['ip'])}</td><td class='mono'>{e(r['mac'])}</td>"
        f"<td>{e(r['status'])}</td><td>{e(r['evidence'])}</td>"
        f"<td>{e(r['first'])}</td><td>{e(r['last'])}</td>"
        f"<td>{e(r['expected'])}</td><td>{e(r['notes'])}</td></tr>"
        for r in rows)
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>{e(title)}</title><style>{REPORT_CSS}"
            f"@media print{{header{{background:none;color:#000}}"
            f"table{{font-size:9pt}}tr{{page-break-inside:avoid}}}}"
            f".mono{{font-family:monospace}}</style></head><body>"
            f"<header><h1>{e(title)}</h1><p>{e(subtitle)}</p></header>"
            f"<main><section><p class='muted'>★ = marked as yours. "
            f"Evidence: ◉ observed ◈ reported ◎ correlated ◌ inferred. "
            f"{len(rows)} device(s).</p><table>{head}{body}</table>"
            f"</section></main><footer>Generated locally by MiniWireshark "
            f"{SCRIPT_VERSION}. Print this page to keep a paper copy."
            f"</footer></body></html>")


def html_to_preview_text(h):
    """A readable plain-text rendering of an HTML export (for previews)."""
    h = re.sub(r"(?is)<(style|script)[^>]*>.*?</\1>", "", h)
    h = re.sub(r"(?i)<br\s*/?>|</(p|tr|h\d|li|section|div)>", "\n", h)
    h = re.sub(r"(?i)</t[dh]>", "  ", h)
    h = re.sub(r"<[^>]+>", "", h)
    h = html.unescape(h)
    return re.sub(r"\n{3,}", "\n\n", h).strip()


