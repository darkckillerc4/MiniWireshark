# ============================================================================
#  This computer's Wi-Fi link (read-only questions to the operating system)
# ============================================================================
def wifi_channel_from_mhz(mhz):
    try:
        f = int(round(float(mhz)))
    except (TypeError, ValueError):
        return None, ""
    if f == 2484:
        return 14, "2.4 GHz"
    if 2412 <= f <= 2472:
        return (f - 2407) // 5, "2.4 GHz"
    if 5150 <= f <= 5895:
        return (f - 5000) // 5, "5 GHz"
    if 5925 <= f <= 7125:
        return (f - 5950) // 5, "6 GHz"
    return None, ""


def _num(text):
    try:
        return float(str(text).replace(",", ".").strip())
    except (TypeError, ValueError):
        return None


def parse_netsh_wlan(text, want=""):
    """`netsh wlan show interfaces` (English, French or Spanish Windows).
    `want` = adapter name or description to prefer."""
    blocks, cur = [], {}
    for line in (text or "").splitlines():
        if ":" not in line:
            if cur and not line.strip():
                continue
            continue
        k, _sep, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k in ("name", "nom", "nombre") and cur.get("name"):
            blocks.append(cur)
            cur = {}
        cur[k] = v
        if k in ("name", "nom", "nombre"):
            cur["name"] = v
    if cur:
        blocks.append(cur)

    def pick(b, *keys):
        for key, val in b.items():
            for k in keys:
                if key.startswith(k):
                    return val
        return ""
    best = None
    for b in blocks:
        state = pick(b, "state", "état", "etat", "estado").lower()
        ok = state.startswith(("connected", "connect", "conectado"))
        desc = pick(b, "description", "descripción", "descripcion")
        if want and (want == b.get("name") or want == desc):
            best = b if ok else best
            if ok:
                break
        if ok and best is None:
            best = b
    if best is None:
        return None
    b = best
    sig = re.search(r"(\d+)\s*%", pick(b, "signal", "señal", "senal"))
    rssi = _num(pick(b, "rssi"))
    pct = int(sig.group(1)) if sig else None
    if rssi is None and pct is not None:
        rssi = pct / 2.0 - 100.0          # Windows' own mapping
    ch = _num(pick(b, "channel", "canal"))
    band = pick(b, "band", "bande", "banda")
    return {"source": "netsh", "iface": b.get("name", ""),
            "ssid": pick(b, "ssid"),
            "bssid": pick(b, "ap bssid", "bssid", "bssid del punto",
                          "bssid du point").lower(),
            "rssi": rssi, "signal_pct": pct,
            "rx_mbps": _num(pick(b, "receive rate", "réception",
                                 "reception", "velocidad de recepción",
                                 "velocidad de recepcion")),
            "tx_mbps": _num(pick(b, "transmit rate", "transmission",
                                 "velocidad de transmisión",
                                 "velocidad de transmision")),
            "channel": int(ch) if ch is not None else None,
            "band": band or ("2.4 GHz" if ch and ch <= 14 else
                             "5 GHz" if ch else ""),
            "standard": pick(b, "radio type", "type de radio",
                             "tipo de radio")}


def parse_iw_link(text, iface=""):
    """`iw dev <iface> link` (Linux)."""
    text = text or ""
    if "Not connected" in text or "Connected to" not in text:
        return None
    m = re.search(r"Connected to ([0-9a-fA-F:]{17})", text)
    out = {"source": "iw", "iface": iface, "ssid": "", "rssi": None,
           "signal_pct": None, "rx_mbps": None, "tx_mbps": None,
           "channel": None, "band": "", "standard": "",
           "bssid": m.group(1).lower() if m else ""}
    for line in text.splitlines():
        k, _s, v = line.strip().partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "ssid":
            out["ssid"] = v
        elif k == "freq":
            out["channel"], out["band"] = wifi_channel_from_mhz(v)
        elif k == "signal":
            out["rssi"] = _num(v.split()[0]) if v else None
        elif k in ("rx bitrate", "tx bitrate") and v:
            rate = _num(v.split()[0])
            out["rx_mbps" if k.startswith("rx") else "tx_mbps"] = rate
            for std, tag in (("802.11be", "EHT"), ("802.11ax", "HE"),
                             ("802.11ac", "VHT"), ("802.11n", "MCS")):
                if tag in v and not out["standard"]:
                    out["standard"] = std
    return out


def parse_proc_wireless(text, iface=""):
    """/proc/net/wireless (Linux, when `iw` is missing): signal only."""
    for line in (text or "").splitlines()[2:]:
        name, _s, rest = line.partition(":")
        name = name.strip()
        if iface and name != iface:
            continue
        parts = rest.split()
        if len(parts) >= 3:
            level = _num(parts[2].rstrip("."))
            if level is None:
                continue
            if level > 0:                 # some drivers report 0..100
                level = level / 2.0 - 100.0
            return {"source": "/proc/net/wireless", "iface": name,
                    "ssid": "", "bssid": "", "rssi": level,
                    "signal_pct": None, "rx_mbps": None, "tx_mbps": None,
                    "channel": None, "band": "", "standard": ""}
    return None


def parse_macos_airport(text):
    """`system_profiler SPAirPortDataType` (macOS)."""
    text = text or ""
    i = text.find("Current Network Information:")
    if i < 0:
        return None
    block = text[i:].splitlines()[1:]
    out = {"source": "system_profiler", "iface": "", "ssid": "",
           "bssid": "", "rssi": None, "signal_pct": None, "rx_mbps": None,
           "tx_mbps": None, "channel": None, "band": "", "standard": ""}
    if block:
        out["ssid"] = block[0].strip().rstrip(":")
    for line in block[1:30]:
        k, _s, v = line.strip().partition(":")
        k, v = k.strip().lower(), v.strip()
        if not v and k.endswith("information"):
            break
        if k == "signal / noise":
            m = re.match(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)", v)
            if m:
                out["rssi"] = float(m.group(1))
                out["noise"] = float(m.group(2))
        elif k == "channel":
            m = re.match(r"(\d+)\s*\(([\d.]+)\s*GHz", v)
            if m:
                out["channel"] = int(m.group(1))
                out["band"] = f"{m.group(2)} GHz"
        elif k == "transmit rate":
            out["tx_mbps"] = _num(v)
        elif k == "phy mode":
            out["standard"] = v
    return out


def wifi_quality(rssi):
    """→ (health status, word, plain-English explanation)."""
    if rssi is None:
        return "Unknown", "unknown", "Signal strength not reported."
    if rssi >= -60:
        return "Healthy", "excellent", "Strong signal."
    if rssi >= -67:
        return "Healthy", "good", "Good signal."
    if rssi >= -75:
        return "Degraded", "fair", ("Usable, but video calls and big "
                                    "downloads may stutter.")
    return "Needs attention", "weak", ("Weak signal — the most likely cause "
                                       "of slowness. Move closer to the "
                                       "router or remove obstacles.")


class WifiProbe:
    """Asks the operating system about THIS computer's Wi-Fi link every
    `interval` seconds, in the background. Read-only: nothing is sent on
    the network and no setting is changed."""

    def __init__(self, interval=30):
        self.interval = interval
        self.last = None
        self.at = 0.0
        self.busy = False
        self.error = ""
        self.history = deque(maxlen=240)     # (ts, rssi)
        self.seq = 0

    @staticmethod
    def _cmd(cmd, timeout=10):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout,
                               creationflags=getattr(
                                   subprocess, "CREATE_NO_WINDOW", 0))
            return r.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return ""

    def read(self, iface="", desc=""):
        if IS_WINDOWS:
            return parse_netsh_wlan(self._cmd(["netsh", "wlan", "show",
                                               "interfaces"]), desc or iface)
        if sys.platform == "darwin":
            return parse_macos_airport(self._cmd(
                ["system_profiler", "SPAirPortDataType"], 30))
        names = [iface] if iface and os.path.isdir(
            f"/sys/class/net/{iface}/wireless") else [
            n for n in sorted(os.listdir("/sys/class/net"))
            if os.path.isdir(f"/sys/class/net/{n}/wireless")] \
            if os.path.isdir("/sys/class/net") else []
        for name in names:
            if shutil.which("iw"):
                got = parse_iw_link(self._cmd(["iw", "dev", name, "link"]),
                                    name)
                if got:
                    return got
            try:
                with open("/proc/net/wireless", encoding="utf-8") as f:
                    got = parse_proc_wireless(f.read(), name)
            except OSError:
                got = None
            if got:
                return got
        return None

    def refresh(self, iface="", desc="", force=False):
        if self.busy or (not force and time.time() - self.at <
                         self.interval):
            return False
        self.busy = True
        self.at = time.time()

        def work():
            try:
                got = self.read(iface, desc)
                self.error = ""
            except Exception as e:                   # noqa: BLE001
                got, self.error = None, str(e)
            self.last = got
            if got and got.get("rssi") is not None:
                self.history.append((time.time(), got["rssi"]))
            self.seq += 1
            self.busy = False
        threading.Thread(target=work, daemon=True, name="wifi-probe").start()
        return True

    def summary(self):
        w = self.last
        if not w:
            return None
        status, word, why = wifi_quality(w.get("rssi"))
        parts = []
        if w.get("rssi") is not None:
            parts.append(f"{w['rssi']:.0f} dBm ({word})")
        if w.get("tx_mbps") or w.get("rx_mbps"):
            parts.append(f"link {w.get('rx_mbps') or w.get('tx_mbps'):.0f} "
                         f"Mbit/s")
        if w.get("channel"):
            parts.append(f"channel {w['channel']}"
                         + (f" ({w['band']})" if w.get("band") else ""))
        if w.get("standard"):
            parts.append(w["standard"])
        return status, word, why, ", ".join(parts)
