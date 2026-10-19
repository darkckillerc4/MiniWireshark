# ============================================================================
#  1b.  Everything MiniWireshark itself sends — one gate, one ledger
#
#  Every network send the app makes (downloads, update checks, health
#  checks, discovery probes, reverse lookups, the router check) passes
#  through outbound() first. It is written to the self-traffic ledger you
#  can open from Settings → Privacy, and the kill switch stops all of it at
#  once. A self-test parses this file and fails if any send bypasses it.
# ============================================================================
class OutboundBlocked(OSError):
    """Raised instead of sending while the kill switch is on."""


OUTBOUND_FEATURES = {
    "runtime": "Private Python setup (downloads)",
    "npcap": "Capture driver install (Windows)",
    "reference": "Reference lists (vendor names, public suffixes)",
    "geoip": "Country lookup (online service)",
    "update": "Update check",
    "lan_scan": "Device discovery (Active Mode)",
    "health": "Health checks (router, DNS, Internet)",
    "rdns": "Device names via reverse DNS (Active Mode)",
    "diagnostics": "Diagnostics tests you started",
    "upnp": "Router port-forwarding check",
    "connector": "Connected helpers (Pi-hole, AdGuard Home)",
    "release": "Release tooling (developers only)",
}


class SelfTrafficLedger:
    def __init__(self, keep=3000):
        self.entries = deque(maxlen=keep)
        self.killed = False
        self.counts = Counter()
        self.blocked = 0
        self.lock = threading.Lock()

    def record(self, feature, kind, dest, detail="", allowed=True, count=1):
        e = {"ts": time.time(), "feature": feature, "kind": kind,
             "dest": str(dest)[:120], "detail": str(detail)[:200],
             "allowed": allowed, "count": int(count)}
        with self.lock:
            self.entries.append(e)
            if allowed:
                self.counts[feature] += int(count)
            else:
                self.blocked += int(count)
        return e

    def snapshot(self, feature=None):
        with self.lock:
            return [dict(e) for e in self.entries
                    if feature is None or e["feature"] == feature]

    def summary_lines(self):
        with self.lock:
            items = sorted(self.counts.items(), key=lambda kv: -kv[1])
        out = [f"{OUTBOUND_FEATURES.get(k, k)}: {n}" for k, n in items]
        if self.blocked:
            out.append(f"Blocked by the kill switch: {self.blocked}")
        return out or ["Nothing sent yet."]


LEDGER = SelfTrafficLedger()


def outbound(feature, kind, dest, detail="", count=1):
    """The gate in front of every network send. Records it in the ledger,
    or raises OutboundBlocked while the kill switch is on."""
    if LEDGER.killed:
        LEDGER.record(feature, kind, dest, detail, allowed=False,
                      count=count)
        raise OutboundBlocked(
            f"Not sent — the kill switch is on "
            f"({OUTBOUND_FEATURES.get(feature, feature)})")
    LEDGER.record(feature, kind, dest, detail, True, count)
    return True


def net_urlopen(feature, req, timeout, detail=""):
    """urllib.request.urlopen behind the outbound gate."""
    url = req.full_url if isinstance(req, urllib.request.Request) \
        else str(req)
    parts = urllib.parse.urlsplit(url)
    outbound(feature, parts.scheme or "http", parts.hostname or url,
             detail or (parts.path or "/")[:100])
    return urllib.request.urlopen(req, timeout=timeout)


