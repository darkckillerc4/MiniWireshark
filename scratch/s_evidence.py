# ============================================================================
#  12b.  Evidence levels, observations and lookup correlation
#
#  Observations are facts with a source, a time and (when it came from a
#  packet) the packet number; they are never edited. Everything a view
#  shows is a CLAIM built from them and carries one of five levels:
#
#     ◉ Observed    seen directly in a packet from this device
#     ◈ Reported    told to us by another system (router, Pi-hole…)
#     ◎ Correlated  two separate observations line up (lookup → connect)
#     ◌ Inferred    a reasonable guess with counter-explanations
#     ?  Unknown    nothing either way — never shown as "no"
# ============================================================================
LV_OBSERVED, LV_REPORTED, LV_CORRELATED, LV_INFERRED, LV_UNKNOWN = \
    "observed", "reported", "correlated", "inferred", "unknown"
LEVEL_GLYPH = {LV_OBSERVED: "◉", LV_REPORTED: "◈", LV_CORRELATED: "◎",
               LV_INFERRED: "◌", LV_UNKNOWN: "?"}
LEVEL_WORD = {LV_OBSERVED: "Observed", LV_REPORTED: "Reported",
              LV_CORRELATED: "Correlated", LV_INFERRED: "Inferred",
              LV_UNKNOWN: "Unknown"}
LEVEL_HELP = {
    LV_OBSERVED: "Seen directly in a packet (you can open that packet).",
    LV_REPORTED: "Reported by another system you connected (for example "
                 "your Pi-hole), not seen by this computer itself.",
    LV_CORRELATED: "Two separate observations line up — for example a "
                   "device looked a name up and connected to the answer "
                   "a moment later.",
    LV_INFERRED: "A reasonable guess. It could be wrong; the reasons are "
                 "listed.",
    LV_UNKNOWN: "Nothing seen either way. Not seeing something does not "
                "mean it didn't happen."}


def level_label(level, word=True):
    g = LEVEL_GLYPH.get(level, "?")
    return f"{g} {LEVEL_WORD.get(level, 'Unknown')}" if word else g


# ---- how a device is tied to a website -----------------------------------
AS_CONNECTED = "connected"                 # SNI / HTTP Host in its own flow
AS_CONNECTED_LOOKUP = "connected-lookup"   # own lookup, then connected
AS_CONNECTED_AMBIG = "connected-ambiguous" # same, IP serves many names
AS_REPORTED = "reported"                   # a connector says it looked up
AS_LOOKUP_ONLY = "lookup-only"             # looked up, no connection seen
AS_INFERRED = "inferred"                   # another device's lookup
ASSOC_RANK = {AS_CONNECTED: 6, AS_CONNECTED_LOOKUP: 5, AS_CONNECTED_AMBIG: 4,
              AS_REPORTED: 3, AS_LOOKUP_ONLY: 2, AS_INFERRED: 1, "": 0}
ASSOC_LEVEL = {AS_CONNECTED: LV_OBSERVED, AS_CONNECTED_LOOKUP: LV_CORRELATED,
               AS_CONNECTED_AMBIG: LV_CORRELATED, AS_REPORTED: LV_REPORTED,
               AS_LOOKUP_ONLY: LV_OBSERVED, AS_INFERRED: LV_INFERRED,
               "": LV_UNKNOWN}
ASSOC_TEXT = {
    AS_CONNECTED: "connected (name seen in the connection)",
    AS_CONNECTED_LOOKUP: "connected (right after looking it up)",
    AS_CONNECTED_AMBIG: "connected to an address shared by many names",
    AS_REPORTED: "looked up (reported by another system)",
    AS_LOOKUP_ONLY: "looked up — no connection seen",
    AS_INFERRED: "possibly (another device's lookup)",
    "": "unknown"}
ASSOC_SHORT = {AS_CONNECTED: "Connected", AS_CONNECTED_LOOKUP: "Connected",
               AS_CONNECTED_AMBIG: "Connected (shared address)",
               AS_REPORTED: "Looked up (reported)",
               AS_LOOKUP_ONLY: "Looked up only", AS_INFERRED: "Possibly",
               "": "—"}


def assoc_label(assoc):
    return f"{LEVEL_GLYPH[ASSOC_LEVEL.get(assoc, LV_UNKNOWN)]} " \
           f"{ASSOC_SHORT.get(assoc, '—')}"


def better_assoc(a, b):
    return a if ASSOC_RANK.get(a, 0) >= ASSOC_RANK.get(b, 0) else b


# ---- observation kinds (integer codes keep the history file small) ---------
OBS_KINDS = ("arp_reply", "arp_probe", "dhcp_request", "dhcp_ack",
             "dns_query", "dns_answer", "tls_sni", "http_host", "flow_start",
             "mdns", "ssdp", "nd", "nbns", "ra", "rogue_ra", "quic_sni",
             "lldp", "service", "name", "probe", "reported")
OBS_KIND_CODES = {k: i + 1 for i, k in enumerate(OBS_KINDS)}
OBS_CODE_KINDS = {v: k for k, v in OBS_KIND_CODES.items()}
OBS_KIND_TEXT = {
    "arp_reply": "answered ARP", "arp_probe": "asked ARP",
    "dhcp_request": "asked DHCP for an address", "dhcp_ack": "got a DHCP "
    "lease", "dns_query": "looked up a name", "dns_answer": "received a DNS "
    "answer", "tls_sni": "named the site in its secure connection",
    "http_host": "named the site in a plain web request",
    "flow_start": "opened a connection", "mdns": "announced itself (mDNS)",
    "ssdp": "announced itself (SSDP)", "nd": "IPv6 neighbour discovery",
    "nbns": "answered a Windows name query", "ra": "announced an IPv6 "
    "router", "rogue_ra": "announced an unexpected IPv6 router",
    "quic_sni": "named the site in a QUIC handshake",
    "lldp": "switch announcement (LLDP/CDP)", "service": "advertised a "
    "service", "name": "name learned", "probe": "answered a health check",
    "reported": "reported by a connected system"}


class LookupCorrelator:
    """Remembers who looked up what (bounded, time-ordered) so a later
    connection can be tied to the name its device just resolved — the
    level is Correlated, never Observed — and so lookups with no
    connection are shown as exactly that."""

    STRONG_WINDOW = 10.0          # lookup → connection within 10 s
    KEEP = 1800.0                 # forget lookups after 30 minutes

    def __init__(self):
        self.by_dev_ip = {}       # (device, ip) -> deque[(ts, domain)]
        self.by_ip = {}           # ip -> deque[(ts, device, domain)]
        self.order = deque()      # (ts, device, ip) for expiry
        self.used = set()         # (device, domain) that led to a connect

    def note_resolution(self, device, domain, ip, ts):
        k = (device, ip)
        dq = self.by_dev_ip.get(k)
        if dq is None:
            dq = self.by_dev_ip[k] = deque(maxlen=8)
        dq.append((ts, domain))
        ipq = self.by_ip.get(ip)
        if ipq is None:
            ipq = self.by_ip[ip] = deque(maxlen=16)
        ipq.append((ts, device, domain))
        self.order.append((ts, device, ip))
        self._expire(ts)

    def match(self, device, ip, ts):
        """→ (domain, kind) for a new connection from `device` to `ip`.
        kind is "own-recent", "own-old", "other" or ""."""
        dq = self.by_dev_ip.get((device, ip)) if device else None
        if dq:
            t, dom = dq[-1]
            if 0 <= ts - t <= self.STRONG_WINDOW:
                self.used.add((device, dom))
                return dom, "own-recent"
            if ts - t <= self.KEEP:
                self.used.add((device, dom))
                return dom, "own-old"
        ipq = self.by_ip.get(ip)
        if ipq:
            t, _dev, dom = ipq[-1]
            if ts - t <= self.KEEP:
                return dom, "other"
        return "", ""

    def _expire(self, now):
        while self.order and now - self.order[0][0] > self.KEEP:
            t, dev, ip = self.order.popleft()
            dq = self.by_dev_ip.get((dev, ip))
            if dq and dq[-1][0] <= t:
                self.by_dev_ip.pop((dev, ip), None)
            ipq = self.by_ip.get(ip)
            if ipq and ipq[-1][0] <= t:
                self.by_ip.pop(ip, None)
        if len(self.order) > 200000:
            for _ in range(20000):
                self.order.popleft()
        if len(self.used) > 100000:
            self.used.clear()


