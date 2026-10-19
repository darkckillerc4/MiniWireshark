# ============================================================================
#  9b.  This computer: which program owns each connection, which programs
#       accept connections, and what its ARP cache says (all read-only
#       questions to the operating system)
# ============================================================================
def _psutil():
    ps = OPTIONAL_MODULES.get("psutil")
    if ps is None and "psutil" not in OPTIONAL_MODULES:
        try:
            import psutil as ps                       # noqa: F811
        except ImportError:
            ps = None
        OPTIONAL_MODULES["psutil"] = ps
    return ps


class ProcessMap:
    """A snapshot of this computer's connection table: local address and
    port → program. Refreshed in the background every few seconds while
    watching live. Programs the operating system won't name without admin
    rights are shown as such, never guessed."""

    def __init__(self, interval=2.0):
        self.interval = interval
        self.by_local = {}        # (proto, ip, port) → (pid, name)
        self.by_port = {}         # (proto, port) → (pid, name)
        self.listening = {}       # (proto, ip, port) → (pid, name)
        self.names = {}           # pid → name
        self.at = 0.0
        self.busy = False
        self.needs_admin = False
        self.error = ""
        self.available = _psutil() is not None
        self.seq = 0

    def _name(self, ps, pid):
        if not pid:
            return "the operating system"
        n = self.names.get(pid)
        if n is None:
            try:
                n = ps.Process(pid).name()
            except Exception:                        # noqa: BLE001
                n = ""
            if len(self.names) > 5000:
                self.names.clear()
            self.names[pid] = n
        return n

    def _connections(self, ps):
        try:
            return ps.net_connections(kind="inet"), False
        except ps.AccessDenied:
            pass                     # macOS without admin: per process
        out = []
        for p in ps.process_iter(["pid"]):
            try:
                fn = getattr(p, "net_connections", None) or p.connections
                for c in fn(kind="inet"):
                    out.append(c._replace(pid=p.pid) if hasattr(
                        c, "_replace") and "pid" in getattr(
                        c, "_fields", ()) else c)
                    if not hasattr(out[-1], "pid"):
                        out[-1] = (out[-1], p.pid)
            except Exception:                        # noqa: BLE001
                continue
        return out, True

    def read(self):
        ps = _psutil()
        if ps is None:
            return False
        conns, partial = self._connections(ps)
        by_local, by_port, listening = {}, {}, {}
        unnamed = 0
        for c in conns:
            pid = None
            if isinstance(c, tuple) and len(c) == 2 and not hasattr(
                    c, "laddr"):
                c, pid = c
            pid = pid if pid is not None else getattr(c, "pid", None)
            la = getattr(c, "laddr", None)
            if not la:
                continue
            proto = "TCP" if getattr(c, "type", 1) == 1 else "UDP"
            ip, port = la[0], la[1]
            name = self._name(ps, pid) if pid else ""
            if pid is None:
                unnamed += 1
            ent = (pid, name)
            by_local[(proto, ip, port)] = ent
            by_port.setdefault((proto, port), ent)
            ra = getattr(c, "raddr", None)
            status = getattr(c, "status", "")
            if (proto == "TCP" and status == "LISTEN") or \
                    (proto == "UDP" and not ra):
                listening[(proto, ip, port)] = ent
        self.by_local, self.by_port, self.listening = by_local, by_port, \
            listening
        self.needs_admin = partial or unnamed > 0
        self.at = time.time()
        self.seq += 1
        return True

    def refresh(self, force=False):
        if not self.available or self.busy or (
                not force and time.time() - self.at < self.interval):
            return False
        self.busy = True

        def work():
            try:
                self.read()
                self.error = ""
            except Exception as e:                   # noqa: BLE001
                self.error = str(e)
            finally:
                self.busy = False
        threading.Thread(target=work, daemon=True, name="process-map").start()
        return True

    def lookup(self, proto, ip, port):
        """→ (pid, name) or None. Name "" = the OS didn't say (admin)."""
        if port is None:
            return None
        ent = self.by_local.get((proto, ip, port))
        if ent is None:
            for any_ip in ("0.0.0.0", "::", ""):
                ent = self.by_local.get((proto, any_ip, port))
                if ent is not None:
                    break
        if ent is None:
            ent = self.by_port.get((proto, port))
        return ent


def program_label(ent):
    if ent is None:
        return ""
    pid, name = ent
    if name:
        return f"{name} (pid {pid})" if pid else name
    return "unknown program (needs admin rights to name it)"


# Ports below the usual ephemeral range count as "services"; an UDP socket
# above it is almost always a client asking something.
LISTEN_EPHEMERAL = 32768


def listening_key(proto, ip, port):
    scope = "this computer only" if ip in ("127.0.0.1", "::1") or \
        str(ip).startswith("127.") else "the network"
    return f"{proto}/{port}/{scope}"


class ListenWatch:
    """Remembers which programs accept connections on this computer and
    reports new ones. The first look only learns (no alerts)."""

    def __init__(self, path):
        self.path = path
        self.known = read_json(path, {}) or {}
        if not isinstance(self.known, dict):
            self.known = {}
        self.learning = not self.known

    def check(self, listening, now=None):
        """→ [(key, proto, ip, port, program, scope)] new since last time."""
        now = now or time.time()
        new = []
        for (proto, ip, port), ent in sorted(listening.items(),
                                             key=lambda kv: str(kv[0])):
            if proto == "UDP" and port >= LISTEN_EPHEMERAL:
                continue
            key = listening_key(proto, ip, port)
            prog = program_label(ent)
            rec = self.known.get(key)
            if rec is None:
                self.known[key] = {"program": prog, "first": now,
                                   "last": now}
                if not self.learning:
                    new.append((key, proto, ip, port, prog,
                                key.rsplit("/", 1)[1]))
            else:
                rec["last"] = now
                if prog and rec.get("program") != prog and \
                        "needs admin" not in prog:
                    rec["program"] = prog
        self.learning = False
        with contextlib.suppress(OSError):
            atomic_write_json(self.path, self.known)
        return new


def parse_proc_arp(text):
    """/proc/net/arp (Linux) → [(ip, mac, iface)]."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[2] != "0x0":
            out.append((parts[0], parts[3].lower(), parts[5]))
    return out


def parse_arp_windows(text):
    """`arp -a` (Windows; any language) → [(ip, mac, iface_ip)]."""
    out, iface = [], ""
    for line in (text or "").splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+---\s+0x", line)
        if m:
            iface = m.group(1)
            continue
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]"
                     r"{2}){5})\s+(\S+)", line)
        if m:
            out.append((m.group(1), m.group(2).replace("-", ":").lower(),
                        iface))
    return out


def parse_arp_bsd(text):
    """`arp -an` (macOS / BSD) → [(ip, mac, iface)]."""
    out = []
    for line in (text or "").splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)"
                      r"(?: on (\S+))?", line)
        if m and "incomplete" not in line:
            mac = ":".join(p.zfill(2) for p in m.group(2).split(":"))
            if len(mac) == 17:
                out.append((m.group(1), mac.lower(), m.group(3) or ""))
    return out


def read_arp_cache():
    """This computer's ARP cache (read-only; nothing is sent)."""
    try:
        if IS_WINDOWS:
            r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                               timeout=10, creationflags=getattr(
                                   subprocess, "CREATE_NO_WINDOW", 0))
            return parse_arp_windows(r.stdout)
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", encoding="utf-8") as f:
                return parse_proc_arp(f.read())
        r = subprocess.run(["arp", "-an"], capture_output=True, text=True,
                           timeout=10)
        return parse_arp_bsd(r.stdout)
    except (OSError, subprocess.SubprocessError):
        return []


# ---- the opt-in router port-forwarding check (UPnP IGD) ---------------------
UPNP_WAN_SERVICES = ("urn:schemas-upnp-org:service:WANIPConnection:2",
                     "urn:schemas-upnp-org:service:WANIPConnection:1",
                     "urn:schemas-upnp-org:service:WANPPPConnection:1")


def upnp_parse_description(xml_text, base_url):
    """Device description → (service type, control URL) of the router's
    WAN connection service, or None."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    found = {}
    for el in root.iter():
        if el.tag.endswith("service"):
            st = cu = ""
            for ch in el:
                if ch.tag.endswith("serviceType"):
                    st = (ch.text or "").strip()
                elif ch.tag.endswith("controlURL"):
                    cu = (ch.text or "").strip()
            if st and cu:
                found[st] = cu
    for st in UPNP_WAN_SERVICES:
        if st in found:
            return st, urllib.parse.urljoin(base_url, found[st])
    return None


def upnp_soap_body(service, action, args):
    inner = "".join(f"<{k}>{html.escape(str(v))}</{k}>" for k, v in args)
    return ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.'
            'xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.'
            'xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{inner}</u:{action}>'
            '</s:Body></s:Envelope>').encode()


def upnp_parse_mapping(xml_text):
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    out = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag.startswith("New"):
            out[tag[3:]] = (el.text or "").strip()
    return out or None


def upnp_audit(gateway_ip, timeout=3.0, port=1900, max_entries=64,
               allowed_hosts=None):
    """Ask the router which ports it forwards from the Internet. Sends:
    one discovery message to the router itself, one request for its
    description, then one request per forwarding rule. Only talks to the
    router's own address. → dict with mappings, or {"error": …}."""
    allowed = set(allowed_hosts or ()) | {gateway_ip}
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.settimeout(timeout)
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\n'
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")
    location = ""
    try:
        outbound("upnp", "ssdp", f"{gateway_ip}:{port}",
                 "is there an Internet gateway here?")
        s.sendto(msg.encode(), (gateway_ip, port))
        t_end = time.time() + timeout
        while time.time() < t_end and not location:
            try:
                data, addr = s.recvfrom(4096)
            except _socket.timeout:
                break
            if addr[0] not in allowed:
                continue
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m:
                location = m.group(1).decode("ascii", "ignore")
    except OutboundBlocked as e:
        return {"error": str(e)}
    except OSError as e:
        return {"error": f"The router didn't answer ({e})."}
    finally:
        s.close()
    if not location:
        return {"error": "The router didn't answer the UPnP question — "
                         "UPnP is probably off, which is the safer "
                         "setting.", "upnp": False}
    host = urllib.parse.urlsplit(location).hostname or ""
    if host not in allowed:
        return {"error": f"The answer pointed to {host}, not your router, so "
                         f"I didn't follow it."}
    try:
        req = urllib.request.Request(location,
                                     headers={"User-Agent": APP_NAME})
        with net_urlopen("upnp", req, timeout, "device description") as r:
            desc = r.read(262144).decode("utf-8", "replace")
    except OSError as e:
        return {"error": f"Couldn't read the router's description ({e})."}
    svc = upnp_parse_description(desc, location)
    if not svc:
        return {"error": "The router speaks UPnP but offers no port "
                         "forwarding service.", "upnp": True, "mappings": []}
    service, control = svc
    if (urllib.parse.urlsplit(control).hostname or "") not in allowed:
        return {"error": "The router's control address isn't on your "
                         "router, so I stopped."}
    mappings = []
    for i in range(max_entries):
        body = upnp_soap_body(service, "GetGenericPortMappingEntry",
                              [("NewPortMappingIndex", i)])
        req = urllib.request.Request(control, data=body, headers={
            "User-Agent": APP_NAME,
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service}#GetGenericPortMappingEntry"'})
        try:
            with net_urlopen("upnp", req, timeout,
                             f"forwarding rule #{i}") as r:
                text = r.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError:
            break                     # 713 SpecifiedArrayIndexInvalid: done
        except OSError as e:
            if not mappings:
                return {"error": f"The router refused the question ({e}).",
                        "upnp": True, "mappings": []}
            break
        mp = upnp_parse_mapping(text)
        if not mp:
            break
        mappings.append(mp)
    return {"upnp": True, "service": service, "mappings": mappings,
            "location": location}


