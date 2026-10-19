# ============================================================================
#  7b.  Identity over time — address bindings, corrections, networks
#
#  • BindingTable: which hardware address held an IP, from when to when.
#    An address moving from the printer to a laptop closes one binding and
#    opens another, so histories never mix.
#  • CorrectionJournal: everything YOU change about identities (rename,
#    merge, split, never-merge, flags) is an undoable journal entry.
#  • NetworkProfiles: each network you use (router MAC + subnet, SSID when
#    known) is remembered separately. A network seen for the first time
#    starts in Quiet Mode until you say it's yours.
# ============================================================================
class BindingTable:
    """IP ↔ hardware address over time (bounded)."""

    MAX_PER_IP = 12

    def __init__(self):
        self.by_ip = {}           # ip -> list[[owner, start, end|None, src]]
        self.conflicts = deque(maxlen=200)

    def bind(self, ip, owner, ts, source="traffic", lease=None):
        """Record that `owner` (a MAC, or a device key) holds `ip` at `ts`.
        Returns the previous owner if the address changed hands."""
        if not ip or not owner:
            return None
        lst = self.by_ip.get(ip)
        if lst is None:
            lst = self.by_ip[ip] = []
        cur = lst[-1] if lst else None
        if cur is not None and cur[2] is None and cur[0] == owner:
            if source in ("dhcp", "arp") and cur[3] not in ("dhcp",):
                cur[3] = source
            return None
        prev = None
        if cur is not None and cur[2] is None:
            prev = cur[0]
            # two owners within a few seconds both claiming it = conflict
            if ts - cur[1] < 5 and source != "dhcp":
                self.conflicts.append((ip, prev, owner, ts))
            cur[2] = ts
        lst.append([owner, ts, None, source])
        if len(lst) > self.MAX_PER_IP:
            del lst[:-self.MAX_PER_IP]
        if len(self.by_ip) > 100000:
            for k in list(self.by_ip)[:10000]:
                self.by_ip.pop(k, None)
        return prev

    def owner_at(self, ip, ts):
        for owner, start, end, _src in reversed(self.by_ip.get(ip, ())):
            if start <= ts and (end is None or ts < end):
                return owner
        return None

    def history(self, ip):
        return [tuple(b) for b in self.by_ip.get(ip, ())]

    def held_by(self, owner):
        """Addresses currently bound to `owner`."""
        return [ip for ip, lst in self.by_ip.items()
                if lst and lst[-1][0] == owner and lst[-1][2] is None]

    def rename_owner(self, old, new):
        for lst in self.by_ip.values():
            for b in lst:
                if b[0] == old:
                    b[0] = new

    def to_list(self, limit=5000):
        out = []
        for ip, lst in list(self.by_ip.items())[-limit:]:
            out.append([ip, [list(b) for b in lst]])
        return out

    def load(self, data):
        for item in data or []:
            if isinstance(item, list) and len(item) == 2 and \
                    isinstance(item[1], list):
                self.by_ip[str(item[0])] = [
                    [str(b[0]), float(b[1]), None if b[2] is None
                     else float(b[2]), str(b[3])]
                    for b in item[1] if isinstance(b, list) and len(b) == 4]


class CorrectionJournal:
    """Append-only list of user corrections, each undoable."""

    def __init__(self):
        self.entries = []          # dicts: id, op, payload, ts, undone
        self._next = 1

    def add(self, op, payload, ts=None):
        e = {"id": self._next, "op": op, "payload": payload,
             "ts": ts or time.time(), "undone": False}
        self._next += 1
        self.entries.append(e)
        if len(self.entries) > 500:
            del self.entries[:-500]
        return e

    def last_undoable(self):
        for e in reversed(self.entries):
            if not e["undone"]:
                return e
        return None

    def get(self, eid):
        for e in self.entries:
            if e["id"] == eid:
                return e
        return None

    def describe(self, e, namer=lambda k: k):
        p = e["payload"]
        op = e["op"]
        if op == "rename":
            return (f"Renamed {namer(p['key'])}: “{p['old'] or '(detected)'}"
                    f"” → “{p['new'] or '(detected)'}”")
        if op == "merge":
            return f"Merged {p['other']} into {namer(p['keep'])}"
        if op == "split":
            return f"Split {p['restored']} out of {namer(p['keep'])}"
        if op == "flag":
            return (f"{namer(p['key'])}: {p['flag'].replace('_', ' ')} → "
                    f"{'on' if p['new'] else 'off'}")
        if op == "note":
            return f"Edited the note on {namer(p['key'])}"
        if op == "never_merge":
            return f"Never merge {namer(p['a'])} and {namer(p['b'])}"
        return op

    def to_list(self):
        return [dict(e) for e in self.entries[-200:]]


def network_fingerprint(router_mac, subnet):
    """Stable id for 'this network': router hardware address + subnet."""
    raw = f"{(router_mac or '').lower()}|{subnet or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def current_ssid():
    """Name of the Wi-Fi network this computer is on, if the OS tells us
    without extra permissions ('' when unknown or on cable)."""
    cmds = []
    if IS_WINDOWS:
        cmds.append((["netsh", "wlan", "show", "interfaces"],
                     r"^\s*SSID\s*:\s*(.+)$"))
    elif IS_MAC:
        cmds.append((["/System/Library/PrivateFrameworks/Apple80211."
                      "framework/Versions/Current/Resources/airport", "-I"],
                     r"^\s*SSID:\s*(.+)$"))
        cmds.append((["networksetup", "-getairportnetwork", "en0"],
                     r"Current Wi-Fi Network:\s*(.+)$"))
    else:
        cmds.append((["iwgetid", "-r"], r"^(.+)$"))
        cmds.append((["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                     r"^yes:(.+)$"))
    for cmd, pat in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=6, creationflags=getattr(
                                   subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            continue
        for line in (r.stdout or "").splitlines():
            m = re.match(pat, line.strip() if pat.startswith("^(") else line)
            if m and m.group(1).strip() and "BSSID" not in line:
                return sanitize_text(m.group(1).strip(), 64)
    return ""


def os_neighbor_mac(ip):
    """The OS's own ARP/neighbour cache entry for `ip` (no traffic sent)."""
    if not ip:
        return ""
    cmds = ([["arp", "-a", ip]] if IS_WINDOWS else
            [["ip", "neigh", "show", ip], ["arp", "-n", ip]])
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=5, creationflags=getattr(
                                   subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            continue
        m = re.search(r"([0-9a-fA-F]{2}([:-])(?:[0-9a-fA-F]{2}\2){4}"
                      r"[0-9a-fA-F]{2})", r.stdout or "")
        if m:
            mac = m.group(1).replace("-", ":").lower()
            if is_unicast_mac(mac):
                return mac
    return ""


class NetworkProfiles:
    """Remembered networks and whether you trust each for active probes."""

    def __init__(self, path):
        self.path = path
        existed = os.path.exists(path)
        self.data = read_json(path, {}) if existed else {}
        if not isinstance(self.data, dict):
            self.data = {}
        self.data.setdefault("networks", {})
        self.fresh_install = not existed

    def get(self, fp):
        return self.data["networks"].get(fp)

    def all(self):
        return sorted(self.data["networks"].items(),
                      key=lambda kv: -kv[1].get("last_seen", 0))

    def seen(self, fp, router_mac, subnet, ssid, now=None):
        """Note that we're on network `fp`. Returns (profile, is_new)."""
        now = now or time.time()
        nets = self.data["networks"]
        prof = nets.get(fp)
        new = prof is None
        if new:
            name = ssid or (f"Network {subnet}" if subnet else "This network")
            prof = nets[fp] = {"name": name, "first_seen": now,
                               "router_mac": router_mac, "subnet": subnet,
                               "ssid": ssid, "trusted": False,
                               "visits": 0}
        prof["last_seen"] = now
        prof["visits"] = int(prof.get("visits", 0)) + 1
        if ssid and not prof.get("ssid"):
            prof["ssid"] = ssid
        self.save()
        return prof, new

    def set_trusted(self, fp, trusted=True):
        prof = self.get(fp)
        if prof is not None:
            prof["trusted"] = bool(trusted)
            self.save()

    def rename(self, fp, name):
        prof = self.get(fp)
        if prof is not None and name:
            prof["name"] = sanitize_text(name, 60)
            self.save()

    def forget(self, fp):
        if self.data["networks"].pop(fp, None) is not None:
            self.save()

    def save(self):
        try:
            atomic_write_json(self.path, self.data)
        except OSError:
            LOG.warning("could not save network profiles")


