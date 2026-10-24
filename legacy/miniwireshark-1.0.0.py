#!/usr/bin/env python3
"""
MiniWireshark — super noob-friendly single-file packet sniffer.

Everything is automatic: elevation, dependency install, driver install,
picking the right network card, and starting the capture. Once running it
also quietly scans your own Wi-Fi/LAN (ARP + mDNS + SSDP) so idle devices
show up too, self-heals if the capture socket dies, and paces its plain-
English feed so it doesn't blow past a beginner. Just run it.
"""

# ============================================================================
#  0.  Elevation
# ============================================================================
import ctypes
import importlib
import inspect
import ipaddress
import os
import platform
import queue
import random
import shlex
import shutil
import socket as _socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request

ELEVATED_FLAG = "--miniwireshark-elevated"
NO_ELEVATE_ENV = "MINIWIRESHARK_NO_ELEVATE"


def is_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def _fatal_dialog(title, message):
    try:
        import tkinter as tk
        from tkinter import messagebox
        r = tk.Tk(); r.withdraw()
        messagebox.showerror(title, message); r.destroy()
    except Exception:
        sys.stderr.write(f"\n*** {title} ***\n{message}\n")


def _relaunch_elevated():
    script = os.path.abspath(sys.argv[0])
    extra = [a for a in sys.argv[1:] if a != ELEVATED_FLAG]
    system = platform.system()
    if system == "Windows":
        params = subprocess.list2cmdline([script, ELEVATED_FLAG] + extra)
        try:
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1)
            if int(rc) > 32:
                return True
        except Exception:
            pass
        return False
    if system == "Darwin":
        cmd = " ".join(shlex.quote(p) for p in
                       [sys.executable, script, ELEVATED_FLAG] + extra)
        ascript = f'do shell script "{cmd}" with administrator privileges'
        try:
            sys.exit(subprocess.call(["osascript", "-e", ascript]))
        except Exception:
            return False
    env_pairs = [f"{v}={os.environ[v]}" for v in
                 ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY",
                  "XDG_RUNTIME_DIR", "HOME", "USER", "LANG", "PATH")
                 if v in os.environ]
    launchers = []
    if shutil.which("pkexec"):
        launchers.append(["pkexec", "env"] + env_pairs)
    if shutil.which("sudo"):
        launchers.append(["sudo", "-E"])
        launchers.append(["sudo"])
    if shutil.which("gksudo"):
        launchers.append(["gksudo", "--"])
    if shutil.which("kdesudo"):
        launchers.append(["kdesudo", "--"])
    for L in launchers:
        try:
            sys.exit(subprocess.call(L + [sys.executable, script,
                                          ELEVATED_FLAG] + extra))
        except Exception:
            continue
    return False


if ELEVATED_FLAG in sys.argv:
    sys.argv.remove(ELEVATED_FLAG)
    _ELEV = True
else:
    _ELEV = False

if (not _ELEV and not os.environ.get(NO_ELEVATE_ENV) and not is_admin()):
    if _relaunch_elevated():
        sys.exit(0)
    _fatal_dialog(
        "Administrator required",
        "MiniWireshark needs administrator / root rights to watch network "
        "traffic.\n\n"
        "•  Windows: click Yes on the UAC prompt.\n"
        "•  Linux:  install pkexec or run with sudo.\n"
        "•  macOS:  accept the password prompt.\n\n"
        "The program will now close.")
    sys.exit(1)


# ============================================================================
#  1.  Tk imports
# ============================================================================
import tkinter as tk
import tkinter.font as tkfont
from collections import defaultdict, deque
from datetime import datetime
from tkinter import messagebox, ttk, filedialog


# ============================================================================
#  2.  Scapy symbols
# ============================================================================
AsyncSniffer = conf = get_if_list = hexdump = wrpcap = None
sendp = get_if_addr = None
DNS = DNSRR = DNSQR = IP = TCP = UDP = ICMP = ARP = Ether = Raw = None
IPv6 = BOOTP = DHCP = None
HAVE_IPV6 = HAVE_DHCP = False


def load_scapy():
    global AsyncSniffer, conf, get_if_list, hexdump, wrpcap
    global sendp, get_if_addr
    global DNS, DNSRR, DNSQR, IP, TCP, UDP, ICMP, ARP, Ether, Raw
    global IPv6, BOOTP, DHCP, HAVE_IPV6, HAVE_DHCP
    from scapy.all import (AsyncSniffer, conf, get_if_list, hexdump, wrpcap,
                           sendp, get_if_addr)
    from scapy.layers.dns import DNS, DNSRR, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
    try:
        from scapy.layers.inet6 import IPv6
        HAVE_IPV6 = True
    except ImportError:
        HAVE_IPV6 = False
    try:
        from scapy.layers.dhcp import BOOTP, DHCP
        HAVE_DHCP = True
    except ImportError:
        HAVE_DHCP = False


# ============================================================================
#  3.  Bootstrap helpers
# ============================================================================
def _module_ok(name):
    try:
        importlib.invalidate_caches()
        importlib.import_module(name)
        return True
    except Exception:
        return False


def _pip_available():
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "--version"],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stdout or r.stderr).strip()
    except Exception as e:
        return False, str(e)


def _pip_install(pkg, upgrade=False):
    base = [sys.executable, "-m", "pip", "install",
            "--disable-pip-version-check", "-q"]
    if upgrade:
        base.append("--upgrade")
    for cmd in (base + [pkg],
                base + ["--user", pkg],
                base + ["--break-system-packages", pkg],
                base + ["--user", "--break-system-packages", pkg]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            if r.returncode == 0:
                return True, ""
            last = ((r.stdout or "") + (r.stderr or "")).strip()[-1400:]
        except Exception as e:
            last = str(e)
    return False, last


def _scapy_version():
    try:
        import scapy
        return getattr(scapy, "__version__", "unknown")
    except Exception:
        return None


def _npcap_present():
    if platform.system() != "Windows":
        return True
    sd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    return any(os.path.exists(p) for p in
               (os.path.join(sd, "Npcap", "wpcap.dll"),
                os.path.join(sd, "wpcap.dll"),
                os.path.join(sd, "Packet.dll")))


NPCAP_VERSION = "1.79"
NPCAP_URL = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"


def _install_npcap(loader):
    exe = os.path.join(tempfile.gettempdir(), "npcap-installer.exe")
    loader.post_log(f"  Downloading Npcap {NPCAP_VERSION} ...", None)
    try:
        urllib.request.urlretrieve(NPCAP_URL, exe)
    except Exception as e:
        try:
            import webbrowser
            webbrowser.open("https://npcap.com/#download")
        except Exception:
            pass
        return False, f"Could not download Npcap ({e}). Browser opened."
    loader.post_log("  Installing silently ...", None)
    try:
        r = subprocess.run([exe, "/S", "/winpcap_mode=yes"],
                           capture_output=True, text=True, timeout=400)
    except Exception as e:
        return False, f"Installer failed: {e}"
    if r.returncode == 0:
        return True, f"Npcap {NPCAP_VERSION} installed."
    if r.returncode == 3010:
        return False, "Npcap installed but a reboot is required."
    return False, f"Npcap exit code {r.returncode}"


# ============================================================================
#  4.  Loading window
# ============================================================================
class LoaderWindow(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.q = queue.Queue()
        self._build()

    def _build(self):
        h = tk.Frame(self, bg="#2b3a55", padx=18, pady=16)
        h.pack(fill="x")
        tk.Label(h, text="MiniWireshark", fg="white", bg="#2b3a55",
                 font=("TkDefaultFont", 16, "bold")).pack(anchor="w")
        tk.Label(h, text="Setting things up — this only happens once",
                 fg="#c8d2e0", bg="#2b3a55").pack(anchor="w")
        b = tk.Frame(self, bg="#f4f5f7", padx=18, pady=14)
        b.pack(fill="both", expand=True)
        self.status_var = tk.StringVar(value="Starting ...")
        tk.Label(b, textvariable=self.status_var, bg="#f4f5f7",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
        self.progress = ttk.Progressbar(b, mode="determinate",
                                        length=560, maximum=100)
        self.progress.pack(fill="x", pady=(8, 12))
        lf = tk.Frame(b, bg="#ffffff", bd=1, relief="solid")
        lf.pack(fill="both", expand=True)
        self.log = tk.Text(lf, height=11, bg="#ffffff", relief="flat",
                           font=("TkFixedFont", 9), state="disabled",
                           wrap="word", padx=8, pady=6)
        vs = ttk.Scrollbar(lf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=vs.set)
        self.log.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.log.tag_configure("step", foreground="#2b3a55",
                               font=("TkFixedFont", 9, "bold"))
        self.log.tag_configure("ok", foreground="#0b6b3a")
        self.log.tag_configure("err", foreground="#a01a08")
        self.footer = tk.Label(self, text="Please wait ...", bg="#e3e6eb",
                               anchor="w", padx=12, pady=5)
        self.footer.pack(side="bottom", fill="x")

    def post_log(self, t, tag=None): self.q.put(("log", t, tag))
    def post_status(self, t): self.q.put(("status", t))
    def post_progress(self, p): self.q.put(("progress", p))
    def post_footer(self, t): self.q.put(("footer", t))

    def pump(self):
        while True:
            try:
                it = self.q.get_nowait()
            except queue.Empty:
                break
            k = it[0]
            if k == "log":
                self.log.config(state="normal")
                if it[2]:
                    self.log.insert("end", it[1] + "\n", it[2])
                else:
                    self.log.insert("end", it[1] + "\n")
                self.log.see("end")
                self.log.config(state="disabled")
            elif k == "status":
                self.status_var.set(it[1])
            elif k == "progress":
                self.progress["value"] = it[1]
            elif k == "footer":
                self.footer.config(text=it[1])
        try:
            self.update_idletasks(); self.update()
        except tk.TclError:
            pass

    def show_fatal(self, m):
        self.post_status("Setup failed")
        self.post_log("", None); self.post_log(m, "err")
        self.post_footer("Failed. Close this window to exit.")
        self.pump()


# ============================================================================
#  5.  Bootstrap steps
# ============================================================================
def step_python(l):
    v = sys.version_info
    if v < (3, 7):
        return False, f"Python {v.major}.{v.minor} too old (need 3.7+)"
    return True, f"Python {v.major}.{v.minor}.{v.micro}"


def step_tkinter(l):
    try:
        import tkinter as _t
        return True, f"Tk {_t.TkVersion}"
    except Exception as e:
        return False, f"tkinter missing: {e}\nLinux: sudo apt install python3-tk"


def step_pip(l):
    ok, info = _pip_available()
    if ok:
        return True, f"pip {info.split()[-1] if info else '?'}"
    l.post_log("  Bootstrapping pip ...", None)
    try:
        r = subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"],
                           capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            return False, f"ensurepip failed: {r.stderr.strip()[:300]}"
    except Exception as e:
        return False, f"ensurepip: {e}"
    ok, info = _pip_available()
    return (True, f"pip installed") if ok else (False, "pip unavailable")


def step_upgrade_pip(l):
    ok, _ = _pip_install("pip", upgrade=True)
    return True, "pip up to date" if ok else "pip upgrade skipped"


def step_scapy(l):
    if _module_ok("scapy"):
        return True, f"scapy {_scapy_version()} already installed"
    l.post_log("  Installing scapy (1–2 minutes) ...", None)
    l.post_footer("Downloading scapy — please wait ...")
    ok, err = _pip_install("scapy")
    if not ok:
        return False, f"pip could not install scapy:\n{err}"
    if not _module_ok("scapy"):
        return False, "scapy installed but cannot be imported"
    return True, f"scapy {_scapy_version()} installed"


def step_npcap(l):
    if platform.system() != "Windows":
        return True, "not needed"
    if _npcap_present():
        return True, "Npcap driver ready"
    ok, msg = _install_npcap(l)
    if not ok:
        return False, msg
    return True, msg


BOOTSTRAP_STEPS = [
    ("Checking Python", step_python, 1),
    ("Checking graphical toolkit", step_tkinter, 1),
    ("Checking pip", step_pip, 1),
    ("Updating pip", step_upgrade_pip, 2),
    ("Preparing scapy", step_scapy, 6),
    ("Checking packet driver", step_npcap, 6),
    ("Finishing up", lambda l: (True, "Ready."), 1),
]


def run_bootstrap(loader):
    done = threading.Event()
    result = [None]

    def worker():
        total = sum(s[2] for s in BOOTSTRAP_STEPS)
        accum = 0
        for title, fn, w in BOOTSTRAP_STEPS:
            loader.post_status(title + " ...")
            loader.post_log(f"→ {title}", "step")
            try:
                ok, msg = fn(loader)
            except Exception as e:
                ok, msg = False, f"{type(e).__name__}: {e}"
            if not ok:
                loader.post_log(f"✗ {msg}", "err")
                result[0] = (False, msg); done.set(); return
            if msg:
                loader.post_log(f"  {msg}", "ok")
            loader.post_log(f"✓ {title}", "ok")
            accum += w
            loader.post_progress(int(100 * accum / total))
        result[0] = (True, ""); done.set()

    threading.Thread(target=worker, daemon=True).start()
    while not done.is_set():
        loader.pump(); time.sleep(0.03)
    loader.pump()
    return result[0]


# ============================================================================
#  6.  Snaplen / socket probe
# ============================================================================
def probe_l2_socket():
    for mod_name, cls_name in (
            ("scapy.arch.pcapdnet", "L2pcapListenSocket"),
            ("scapy.arch.windows", "L2pcapListenSocket"),
            ("scapy.arch.libpcap", "L2pcapListenSocket"),
            ("scapy.arch.linux", "L2ListenSocket"),
            ("scapy.arch.bsd", "L2ListenSocket")):
        try:
            mod = importlib.import_module(mod_name)
            cls = getattr(mod, cls_name, None)
            if cls is None:
                continue
            params = set(inspect.signature(cls.__init__).parameters)
            return {"snaplen": "snaplen" in params,
                    "promisc": "promisc" in params,
                    "found": f"{mod_name}.{cls_name}"}
        except Exception:
            continue
    return {"snaplen": False, "promisc": False, "found": None}


def build_sniffer(iface, prn, bpf):
    p = probe_l2_socket()
    if p["snaplen"] and p["promisc"]:
        variants = [{"promisc": True, "snaplen": 262144},
                    {"promisc": True}, {}]
    elif p["promisc"]:
        variants = [{"promisc": True}, {}]
    else:
        variants = [{}]
    base = {"iface": iface, "prn": prn, "store": False}
    if bpf:
        base["filter"] = bpf
    last = None
    for extra in variants:
        try:
            s = AsyncSniffer(**dict(base, **extra))
            s.start()
        except Exception as e:
            last = e; continue
        time.sleep(0.45)
        if getattr(s, "exception", None) is None:
            return s, None
        last = s.exception
        try:
            s.stop()
        except Exception:
            pass
    return None, last


# ============================================================================
#  7.  Constants and helpers
# ============================================================================
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                 "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
                 "224.0.0.0/4", "fe80::/10", "fc00::/7", "::1/128",
                 "ff00::/8")]

KNOWN_DNS = {
    "8.8.8.8": "Google DNS", "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "64.6.64.6": "Verisign DNS", "64.6.65.6": "Verisign DNS",
    "77.88.8.8": "Yandex DNS", "77.88.8.1": "Yandex DNS",
    "94.140.14.14": "AdGuard DNS", "94.140.15.15": "AdGuard DNS",
}

DOH_HOSTS = {
    "cloudflare-dns.com": "Cloudflare (encrypted DNS)",
    "dns.google": "Google (encrypted DNS)",
    "dns.quad9.net": "Quad9 (encrypted DNS)",
    "doh.opendns.com": "OpenDNS (encrypted DNS)",
    "dns.nextdns.io": "NextDNS (encrypted DNS)",
    "doh.adguard.com": "AdGuard (encrypted DNS)",
}

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
             15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS",
             46: "RRSIG", 48: "DNSKEY", 65: "HTTPS", 255: "ANY"}
DHCP_MSG = {1: "asking for an address", 2: "offering an address",
            3: "accepting the offer", 4: "declining", 5: "confirmed",
            6: "refused", 7: "releasing", 8: "asking for info"}

FRIENDLY_PROTO = {
    "DNS":    "Website lookup",
    "mDNS":   "Local name lookup",
    "LLMNR":  "Local name lookup",
    "NBNS":   "Local name lookup",
    "HTTP":   "Unsecured web request",
    "TLS":    "Secure web connection",
    "QUIC":   "Secure web connection",
    "DHCP":   "Getting an IP address",
    "SSDP":   "Device discovery",
    "TCP":    "Internet connection",
    "UDP":    "Quick message",
    "ICMP":   "Ping / error reply",
    "ARP":    "Finding a device",
}

# Well-known ports -> plain-English service names. Used to make generic
# TCP/UDP rows ("Connecting ...") much more informative without having to
# decode the payload.
PORT_SERVICES = {
    20: "File transfer (FTP data)", 21: "File transfer (FTP)",
    22: "Remote terminal (SSH)", 23: "Remote terminal (Telnet, not secure)",
    25: "Sending email (SMTP)", 587: "Sending email (SMTP)",
    465: "Sending email (SMTP, secure)",
    69: "File transfer (TFTP)",
    80: "Web browsing", 8080: "Web browsing (alternate port)",
    110: "Checking email (POP3)", 995: "Checking email (POP3, secure)",
    111: "Remote file access (NFS)", 2049: "Remote file access (NFS)",
    123: "Checking the time (NTP)",
    137: "Local name lookup (NetBIOS)", 138: "Local name lookup (NetBIOS)",
    139: "Windows file sharing (NetBIOS)",
    143: "Checking email (IMAP)", 993: "Checking email (IMAP, secure)",
    161: "Network monitoring (SNMP)", 162: "Network monitoring (SNMP)",
    389: "Company directory lookup (LDAP)",
    443: "Secure web browsing",
    445: "Windows file sharing (SMB)",
    514: "System log messages (syslog)",
    546: "Getting an IP address (DHCPv6)",
    547: "Getting an IP address (DHCPv6)",
    554: "Streaming video (RTSP)",
    631: "Printing (IPP)",
    1433: "Database connection (SQL Server)",
    1883: "Smart home messaging (MQTT)",
    8883: "Smart home messaging (MQTT, secure)",
    1900: "Device discovery (SSDP)",
    3306: "Database connection (MySQL)",
    3389: "Remote desktop (RDP)",
    5060: "Internet calling (SIP)", 5061: "Internet calling (SIP, secure)",
    5353: "Local name lookup (mDNS)",
    5432: "Database connection (PostgreSQL)",
    5900: "Remote screen sharing (VNC)",
    6379: "In-memory database (Redis)",
    7000: "Streaming to a speaker/TV (AirPlay)",
    8443: "Secure web browsing (alternate port)",
    9100: "Printing (raw / JetDirect)",
    32400: "Media server (Plex)",
}

# mDNS service-type substrings -> the kind of device that usually offers
# them. Purely for friendlier "what is this thing" guesses in the Devices
# tab — nothing here changes what is captured, only how it's labeled.
MDNS_SERVICE_HINTS = (
    ("_googlecast", "tv"), ("_airplay", "speaker"), ("_raop", "speaker"),
    ("_spotify-connect", "speaker"), ("_sonos", "speaker"),
    ("_ipp", "printer"), ("_printer", "printer"),
    ("_pdl-datastream", "printer"),
    ("_homekit", "iot"), ("_hap", "iot"), ("_matter", "iot"),
    ("_smartthings", "iot"),
    ("_nvstream", "console"), ("_xbox", "console"),
    ("_ps5", "console"), ("_ps4", "console"),
    ("_ssh", "computer"), ("_smb", "computer"), ("_afpovertcp", "computer"),
    ("_rdlink", "computer"), ("_workstation", "computer"),
)

# SERVER/ST/NT header keywords from SSDP announcements -> device kind.
SSDP_HINTS = (
    ("chromecast", "tv"), ("google cast", "tv"), ("roku", "tv"),
    ("smarttv", "tv"), ("bravia", "tv"), ("androidtv", "tv"),
    ("airplay", "speaker"), ("sonos", "speaker"), ("bose", "speaker"),
    ("philips hue", "iot"), ("hue bridge", "iot"), ("wemo", "iot"),
    ("printer", "printer"),
    ("xbox", "console"), ("playstation", "console"), ("nintendo", "console"),
    ("router", "router"), ("gateway", "router"),
)

# How often (seconds) the background LAN scanner nudges the network for
# quiet/idle devices (ARP + mDNS + SSDP). Kept gentle — this only ever
# touches your own local subnet.
SCAN_INTERVAL = 40
SCAN_MAX_HOSTS = 1024  # skip the active ARP sweep on unusually large subnets

DEVICE_ICONS = {
    "router": "🌐", "this-pc": "🖥️", "phone": "📱", "tablet": "📱",
    "computer": "💻", "printer": "🖨️", "tv": "📺", "console": "🎮",
    "iot": "🔌", "camera": "📷", "speaker": "🔊", "unknown": "❓",
}

TAG_COLORS = {
    "DNS":   ("#6a2ca0", "#f6ecff"),
    "mDNS":  ("#6a2ca0", "#f6ecff"),
    "LLMNR": ("#6a2ca0", "#f6ecff"),
    "HTTP":  ("#0b6b3a", "#eafaf0"),
    "TLS":   ("#0b5394", "#eef4fb"),
    "QUIC":  ("#0b5394", "#eef4fb"),
    "DHCP":  ("#8a5a00", "#fff5e0"),
    "NBNS":  ("#8a5a00", "#fff5e0"),
    "SSDP":  ("#8a5a00", "#fff5e0"),
    "TCP":   ("#124e8c", None),
    "UDP":   ("#1d6b2e", None),
    "ICMP":  ("#a01a08", None),
    "ARP":   ("#8a5a00", None),
    "OTHER": ("#3a3a3a", None),
}


def is_private_ip(ip):
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in PRIVATE_NETS:
        try:
            if a in n:
                return True
        except Exception:
            pass
    return False


def is_public_ip(ip):
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not a.is_private and not a.is_multicast and not a.is_loopback \
        and not a.is_link_local and not a.is_reserved and not a.is_unspecified


def _int_to_ip(n):
    try:
        return _socket.inet_ntoa(struct.pack("!I", int(n) & 0xffffffff))
    except Exception:
        return "0.0.0.0"


def local_subnet_for(iface, my_ip):
    """Best-effort: the directly-connected IPv4 subnet for this interface,
    so the active scan only ever touches your own local Wi-Fi/LAN — never
    anything beyond your router."""
    if not my_ip:
        return None
    iface_name = str(getattr(iface, "name", iface) or "")
    try:
        for entry in conf.route.routes:
            try:
                net, mask, gw, rif, addr = entry[0], entry[1], entry[2], \
                    entry[3], entry[4]
            except Exception:
                continue
            if addr != my_ip or not net:
                continue
            if gw not in ("0.0.0.0", "", "*", None):
                continue
            r_name = str(getattr(rif, "name", rif) or "")
            if iface_name and r_name != iface_name:
                continue
            try:
                return ipaddress.ip_network(
                    f"{_int_to_ip(net)}/{_int_to_ip(mask)}", strict=False)
            except Exception:
                continue
    except Exception:
        pass
    try:
        a, b, c, _d = my_ip.split(".")
        return ipaddress.ip_network(f"{a}.{b}.{c}.0/24", strict=False)
    except Exception:
        return None


def _name_bytes(raw):
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            return raw.decode("idna").rstrip(".")
        except Exception:
            try:
                return raw.decode("latin-1").rstrip(".")
            except Exception:
                return ""
    return str(raw).rstrip(".")


def _iter_rrs(rr):
    """Yield each DNSRR record from a DNS answer/ns/ar field. Handles both
    how current scapy represents it (a plain list of DNSRR) and the older
    linked '.payload' chain, so this keeps working across scapy versions."""
    if rr is None:
        return
    if isinstance(rr, (list, tuple)):
        for item in rr:
            if isinstance(item, DNSRR):
                yield item
        return
    while rr is not None and isinstance(rr, DNSRR):
        yield rr
        nxt = rr.payload
        rr = nxt if isinstance(nxt, DNSRR) else None


def _rdata_ip(rr):
    """The plain IP string for an A/AAAA record, however this scapy
    version represents it: a ready-made string (current scapy's
    IPField/IP6Field) or raw bytes (older scapy)."""
    rd = rr.rdata
    if rr.type == 1:
        if isinstance(rd, str):
            return rd
        if isinstance(rd, bytes) and len(rd) == 4:
            return ".".join(str(b) for b in rd)
    elif rr.type == 28:
        if isinstance(rd, str):
            return rd
        if isinstance(rd, bytes) and len(rd) == 16:
            return ":".join(f"{(rd[i] << 8) | rd[i + 1]:x}"
                            for i in range(0, 16, 2))
    return None


def _rdata_str(rr):
    rd = rr.rdata
    if isinstance(rd, str):
        return rd.rstrip(".")
    if isinstance(rd, bytes):
        if rr.type == 1 and len(rd) == 4:
            return ".".join(str(b) for b in rd)
        if rr.type == 28 and len(rd) == 16:
            return ":".join(f"{(rd[i] << 8) | rd[i + 1]:x}"
                            for i in range(0, 16, 2))
        try:
            return rd.decode("utf-8", "ignore").rstrip(".")
        except Exception:
            return rd.hex()
    if isinstance(rd, (list, tuple)):  # e.g. TXT records
        return " ".join(p.decode("utf-8", "ignore") if isinstance(p, bytes)
                        else str(p) for p in rd)
    return str(rd)


def mac_vendor(mac):
    if not mac:
        return ""
    try:
        m = mac.lower().replace("-", ":")
        v = conf.manufdb._get_manuf(m)
        if v and v.lower() != m:
            return v
    except Exception:
        pass
    return ""


def guess_device_type(hostname, vendor, ip, gateway_ip, my_ips):
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    if gateway_ip and ip == gateway_ip:
        return "router"
    if ip in my_ips:
        return "this-pc"
    checks = [
        (("iphone", "ipad", "android", "galaxy", "pixel", "phone"),
         "phone"),
        (("ipad", "tablet", "tab"), "tablet"),
        (("macbook", "imac", "mac-", "desktop", "laptop", "pc-",
          "windows", "linux"), "computer"),
        (("printer", "hp-", "canon", "epson", "brother"), "printer"),
        (("tv", "roku", "chromecast", "appletv", "firetv", "bravia",
          "samsung-tv", "smarttv"), "tv"),
        (("xbox", "playstation", "ps4", "ps5", "nintendo", "switch"),
         "console"),
        (("echo", "alexa", "homepod", "google-home", "speaker"), "speaker"),
        (("cam", "camera", "nest", "ring", "wyze"), "camera"),
        (("espressif", "tuya", "sonoff", "shelly", "smart"),
         "iot"),
    ]
    for keys, kind in checks:
        if any(k in h for k in keys):
            return kind
    # vendor fallback
    if any(x in v for x in ("apple",)):
        return "phone"
    if any(x in v for x in ("samsung", "huawei", "xiaomi", "oneplus",
                            "oppo", "vivo", "motorola")):
        return "phone"
    if any(x in v for x in ("intel", "dell", "hp inc", "lenovo",
                            "asus", "acer", "toshiba", "micro-star",
                            "gigabyte")):
        return "computer"
    if any(x in v for x in ("brother", "canon", "epson", "hewlett")):
        return "printer"
    if any(x in v for x in ("sony", "lg electronics", "tcl", "vizio",
                            "roku", "amazon")):
        return "tv"
    if any(x in v for x in ("espressif", "tuya", "sonoff", "shelly",
                            "raspberr", "arduino")):
        return "iot"
    return "unknown"


# ============================================================================
#  8.  Packet decoder
# ============================================================================
def decode_packet(pkt, gateway_ip, my_ips):
    d = {"proto": "?", "tag": "OTHER", "text": "",
         "src": "", "dst": "",
         "src_ip": "", "dst_ip": "",
         "src_mac": "", "dst_mac": "",
         "ttl": "", "sport": None, "dport": None,
         "dns_names": [], "doh_hint": "", "plain_dns": False,
         "type_hint": "", "dhcp_msgtype": None, "arp_op": None,
         "learns": [], "pkt": pkt,
         "time": float(getattr(pkt, "time", time.time())),
         "length": len(pkt)}

    if pkt.haslayer(Ether):
        e = pkt[Ether]
        d["src_mac"], d["dst_mac"] = e.src, e.dst

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        d["src_ip"], d["dst_ip"] = a.psrc, a.pdst
        d["src_mac"], d["dst_mac"] = a.hwsrc, a.hwdst
        d["proto"], d["tag"] = "ARP", "ARP"
        d["arp_op"] = int(a.op)
        if a.op == 1:
            d["text"] = f"Who has {a.pdst}? Tell {a.psrc}"
        elif a.op == 2:
            d["text"] = f"{a.psrc} is at {a.hwsrc}"
        else:
            d["text"] = f"ARP op={a.op}"
        d["src"] = a.psrc or a.hwsrc
        d["dst"] = a.pdst or a.hwdst
        return d

    if pkt.haslayer(IP):
        ip = pkt[IP]
        d["src_ip"], d["dst_ip"] = ip.src, ip.dst
        d["ttl"] = str(ip.ttl)
    elif HAVE_IPV6 and pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        d["src_ip"], d["dst_ip"] = ip.src, ip.dst
        d["ttl"] = str(getattr(ip, "hlim", ""))

    # --- TCP
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        d["sport"], d["dport"] = t.sport, t.dport
        d["proto"], d["tag"] = "TCP", "TCP"
        flags = int(t.flags)
        names = [n for b, n in ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                                (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"))
                 if flags & b]
        svc = PORT_SERVICES.get(t.dport) or PORT_SERVICES.get(t.sport)
        if svc:
            d["text"] = f"{svc} ({','.join(names) or 'data'})"
        else:
            d["text"] = f"Connecting ({','.join(names) or 'data'})"

        if pkt.haslayer(Raw):
            load = bytes(pkt[Raw].load)
            # plain HTTP?
            if load[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE",
                            b"OPTI", b"PATC") or load[:5] == b"HTTP/":
                try:
                    line = load.split(b"\r\n", 1)[0].decode("latin-1")
                except Exception:
                    line = ""
                if line:
                    d["proto"], d["tag"] = "HTTP", "HTTP"
                    d["text"] = f"Unsecured web request: {line[:120]}"
            # TLS SNI?
            elif load[:1] == b"\x16" and len(load) > 50:
                sni = _try_tls_sni(load)
                if sni:
                    d["proto"], d["tag"] = "TLS", "TLS"
                    d["text"] = f"Secure connection to {sni}"
                    d["dns_names"].append(sni)
                    d["learns"].append((d["dst_ip"], sni))
                    if sni in DOH_HOSTS:
                        d["doh_hint"] = DOH_HOSTS[sni]

    # --- UDP
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        d["sport"], d["dport"] = u.sport, u.dport

        # DNS / mDNS / LLMNR?
        if pkt.haslayer(DNS) and (u.sport in (53, 5353, 5355)
                                  or u.dport in (53, 5353, 5355)):
            name, kind = "DNS", "DNS"
            if 5353 in (u.sport, u.dport):
                name, kind = "mDNS", "mDNS"
            elif 5355 in (u.sport, u.dport):
                name, kind = "LLMNR", "LLMNR"
            # who is the DNS server?
            if u.dport == 53:
                d["plain_dns"] = True
            text, learns, hint = _decode_dns(pkt[DNS], kind)
            d["proto"], d["tag"], d["text"] = name, kind, text
            d["learns"].extend(learns)
            if hint:
                d["type_hint"] = hint

        # DHCP?
        elif HAVE_DHCP and pkt.haslayer(BOOTP) and (
                u.sport in (67, 68) or u.dport in (67, 68)):
            p, t2, text, learns, msgtype = _decode_dhcp(pkt)
            d["proto"], d["tag"], d["text"] = p, t2, text
            d["learns"].extend(learns)
            d["dhcp_msgtype"] = msgtype

        # NBNS?
        elif 137 in (u.sport, u.dport) and pkt.haslayer(Raw):
            d["proto"], d["tag"] = "NBNS", "NBNS"
            r = _try_nbns(bytes(pkt[Raw].load))
            if isinstance(r, tuple):
                nm, ip = r
                d["text"] = f"{nm} is at {ip}"
                d["learns"].append((ip, nm))
            else:
                d["text"] = "Local name lookup"

        # SSDP (UPnP device discovery / announcements)?
        elif 1900 in (u.sport, u.dport) and pkt.haslayer(Raw):
            d["proto"], d["tag"] = "SSDP", "SSDP"
            text, hint = _decode_ssdp(bytes(pkt[Raw].load))
            d["text"] = text
            if hint:
                d["type_hint"] = hint

        # QUIC?
        elif 443 in (u.sport, u.dport) and pkt.haslayer(Raw) and \
                bytes(pkt[Raw].load)[:1] and (bytes(pkt[Raw].load)[0] & 0x80):
            d["proto"], d["tag"] = "QUIC", "QUIC"
            d["text"] = "Secure web connection (fast)"

        else:
            svc = PORT_SERVICES.get(u.dport) or PORT_SERVICES.get(u.sport)
            d["proto"], d["tag"] = "UDP", "UDP"
            d["text"] = (f"{svc} ({u.len} bytes)" if svc
                         else f"Quick message ({u.len} bytes)")

    elif pkt.haslayer(ICMP):
        c = pkt[ICMP]
        d["proto"], d["tag"] = "ICMP", "ICMP"
        d["text"] = {0: "Ping reply", 3: "Destination unreachable",
                     8: "Ping request", 11: "Time exceeded"}.get(
                         c.type, f"ICMP type {c.type}")
    else:
        ll = pkt.lastlayer()
        d["proto"] = ll.name if ll else "?"

    d["src"] = d["src_ip"] or d["src_mac"]
    d["dst"] = d["dst_ip"] or d["dst_mac"]
    return d


def mdns_service_hint(name):
    """Guess a device kind from an mDNS service-type string, e.g.
    '_googlecast._tcp.local.' -> 'tv'. Empty string if no match."""
    n = (name or "").lower()
    for key, kind in MDNS_SERVICE_HINTS:
        if key in n:
            return kind
    return ""


def _decode_dns(d, kind):
    learns = []
    hint = ""
    qname, qtype = "", 0
    if d.qd is not None:
        qname = _name_bytes(d.qd.qname)
        qtype = getattr(d.qd, "qtype", 0) or 0
    if kind == "mDNS":
        hint = mdns_service_hint(qname)

    if d.qr == 0:
        # friendly
        return (f"Looking up {qname}" if qname else "DNS query"), learns, hint

    answers, cname = [], ""
    for rr in _iter_rrs(d.an):
        if kind == "mDNS" and not hint:
            hint = mdns_service_hint(_name_bytes(getattr(rr, "rrname", b"")))
        if rr.type == 5:
            cname = _rdata_str(rr); continue
        ip = _rdata_ip(rr)
        if ip:
            answers.append(ip)
            if qname:
                learns.append((ip, qname))
                if cname:
                    learns.append((ip, cname))
        else:
            answers.append(f"{DNS_TYPES.get(rr.type, rr.type)}={_rdata_str(rr)}")

    head = qname or "?"
    if answers:
        shown = ", ".join(answers[:3])
        if len(answers) > 3:
            shown += f" +{len(answers) - 3}"
        return f"{head} → {shown}", learns, hint
    if d.rcode == 3:
        return f"{head} → does not exist", learns, hint
    return f"{head} → no answer", learns, hint


def _decode_dhcp(pkt):
    learns = []
    bootp = pkt[BOOTP]
    dhcp = pkt[DHCP]
    msg, hostname, msgtype = "DHCP", "", None
    for opt in dhcp.options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        code, val = opt[0], opt[1]
        if code in (53, "message-type"):
            msgtype = val
            msg = DHCP_MSG.get(val, str(val))
        elif code in (12, "hostname"):
            try:
                hostname = val.decode() if isinstance(val, bytes) else str(val)
            except Exception:
                hostname = str(val)
    yiaddr = getattr(bootp, "yiaddr", "") or ""
    if hostname and yiaddr and yiaddr != "0.0.0.0":
        learns.append((yiaddr, hostname))
    parts = [msg]
    if hostname:
        parts.append(f"as “{hostname}”")
    if yiaddr and yiaddr != "0.0.0.0":
        parts.append(f"got {yiaddr}")
    return "DHCP", "DHCP", " ".join(parts), learns, msgtype


def _ssdp_hint(text):
    t = (text or "").lower()
    for key, kind in SSDP_HINTS:
        if key in t:
            return kind
    return ""


def _decode_ssdp(load):
    """Parse an SSDP (UPnP discovery) datagram into a friendly line plus
    an optional device-type hint. SSDP is plain-text HTTP-like headers."""
    try:
        text = load.decode("utf-8", "ignore")
    except Exception:
        return "Device announcement (SSDP)", ""
    lines = text.split("\r\n")
    first = (lines[0] if lines else "").strip()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().upper()] = v.strip()
    server = headers.get("SERVER", "")
    st = headers.get("ST", headers.get("NT", ""))
    hint = _ssdp_hint(server + " " + st)
    if first.startswith("M-SEARCH"):
        return "Looking for other devices on the network (SSDP)", hint
    label = server or st or "Device announcement"
    return f"Announced itself: {label}", hint


def _try_tls_sni(load):
    try:
        pos = 43
        if pos >= len(load):
            return None
        sid_len = load[pos]; pos += 1 + sid_len
        if pos + 2 > len(load):
            return None
        cs_len = struct.unpack(">H", load[pos:pos + 2])[0]; pos += 2 + cs_len
        if pos + 1 > len(load):
            return None
        cm_len = load[pos]; pos += 1 + cm_len
        if pos + 2 > len(load):
            return None
        ext_len = struct.unpack(">H", load[pos:pos + 2])[0]; pos += 2
        end = min(pos + ext_len, len(load))
        while pos + 4 <= end:
            et = struct.unpack(">H", load[pos:pos + 2])[0]
            el = struct.unpack(">H", load[pos + 2:pos + 4])[0]
            pos += 4
            if et == 0 and pos + 5 <= len(load):
                nl = struct.unpack(">H", load[pos + 3:pos + 5])[0]
                host = load[pos + 5:pos + 5 + nl].decode("ascii", "ignore")
                if host:
                    return host
            pos += el
    except Exception:
        return None
    return None


def _try_nbns(load):
    if len(load) < 12:
        return None
    try:
        pos = 12
        ll = load[pos]; pos += 1
        raw = load[pos:pos + ll]
        nm = ""
        for i in range(0, len(raw) - 1, 2):
            c = ((raw[i] - 0x41) << 4) | (raw[i + 1] - 0x41)
            if 32 <= c < 127:
                nm += chr(c)
        return nm.strip() or None
    except Exception:
        return None


# ============================================================================
#  9.  Background workers
# ============================================================================
class NameCache:
    def __init__(self):
        self.ip_to_name = {}
        self.domain_to_ips = defaultdict(set)
        self.lock = threading.Lock()
        self.version = 0

    def learn(self, ip, name):
        if not ip or not name:
            return False
        name = str(name).strip().rstrip(".")
        if not name:
            return False
        with self.lock:
            if self.ip_to_name.get(ip) == name:
                return False
            self.ip_to_name[ip] = name
            self.domain_to_ips[name.lower()].add(ip)
            self.version += 1
            return True

    def get(self, ip):
        return self.ip_to_name.get(ip, "")


class ReverseDNS:
    def __init__(self, cache):
        self.cache = cache
        self.pending, self.done = set(), set()
        self.lock = threading.Lock()
        self.q = queue.Queue()
        for _ in range(4):
            threading.Thread(target=self._worker, daemon=True).start()

    def lookup(self, ip):
        if not ip or ":" in ip or not is_private_ip(ip):
            return
        with self.lock:
            if ip in self.done or ip in self.pending:
                return
            self.pending.add(ip)
        self.q.put(ip)

    def _worker(self):
        while True:
            ip = self.q.get()
            name = ""
            try:
                _socket.setdefaulttimeout(2.0)
                name = _socket.gethostbyaddr(ip)[0]
            except Exception:
                name = ""
            with self.lock:
                self.pending.discard(ip); self.done.add(ip)
            if name:
                self.cache.learn(ip, name)


class DecodeWorker(threading.Thread):
    def __init__(self, in_q, out_q, cache, gw, my_ips):
        super().__init__(daemon=True)
        self.in_q, self.out_q = in_q, out_q
        self.cache = cache
        self.gw = gw
        self.my_ips = my_ips
        self.stop_flag = False

    def run(self):
        while not self.stop_flag:
            try:
                pkt = self.in_q.get(timeout=0.4)
            except queue.Empty:
                continue
            try:
                d = decode_packet(pkt, self.gw, self.my_ips)
            except Exception:
                continue
            for ip, name in d["learns"]:
                self.cache.learn(ip, name)
            try:
                self.out_q.put(d)
            except Exception:
                pass


class LanScanner(threading.Thread):
    """Quietly nudges devices on your own local Wi-Fi/LAN to speak up, so
    idle/quiet devices show up too — not just the ones already talking.

    This never touches anything beyond your local subnet and never probes
    ports or services: it only sends the same three kinds of harmless,
    standard "is anyone there?" broadcasts that phones, printers, smart
    TVs and file-sharing apps send all the time (ARP, mDNS, SSDP). Every
    reply is picked up by the normal capture pipeline like any other
    packet — this thread only sends, it never needs to listen itself.
    """

    def __init__(self, iface, my_ip):
        super().__init__(daemon=True)
        self.iface = iface
        self.my_ip = my_ip
        self.stop_flag = False
        self.subnet = local_subnet_for(iface, my_ip) if my_ip else None

    def run(self):
        # give the capture socket a moment to fully come up first
        for _ in range(10):
            if self.stop_flag:
                return
            time.sleep(0.2)
        while not self.stop_flag:
            try:
                self._sweep()
            except Exception:
                pass
            waited = 0.0
            while waited < SCAN_INTERVAL:
                if self.stop_flag:
                    return
                time.sleep(0.2)
                waited += 0.2

    def _sweep(self):
        self._arp_sweep()
        self._mdns_browse()
        self._ssdp_search()

    def _arp_sweep(self):
        if not self.subnet or not self.my_ip:
            return
        if self.subnet.num_addresses > SCAN_MAX_HOSTS:
            return
        try:
            hosts = [str(h) for h in self.subnet.hosts() if str(h) != self.my_ip]
        except Exception:
            return
        if not hosts:
            return
        try:
            pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=h) for h in hosts]
            sendp(pkts, iface=self.iface, inter=0.003, verbose=False)
        except Exception:
            pass

    def _mdns_browse(self):
        if not self.my_ip:
            return
        try:
            pkt = (Ether(dst="01:00:5e:00:00:fb") /
                   IP(dst="224.0.0.251", src=self.my_ip) /
                   UDP(sport=5353, dport=5353) /
                   DNS(rd=0, qd=DNSQR(qname="_services._dns-sd._udp.local.",
                                      qtype="PTR")))
            sendp(pkt, iface=self.iface, verbose=False)
        except Exception:
            pass

    def _ssdp_search(self):
        if not self.my_ip:
            return
        try:
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
            pkt = (Ether(dst="01:00:5e:7f:ff:fa") /
                   IP(dst="239.255.255.250", src=self.my_ip) /
                   UDP(sport=random.randint(20000, 60000), dport=1900) /
                   Raw(load=msg.encode()))
            sendp(pkt, iface=self.iface, verbose=False)
        except Exception:
            pass


def _iface_ip(iface):
    """Best-effort local IPv4 address for the chosen interface."""
    try:
        return get_if_addr(iface)
    except Exception:
        pass
    try:
        return get_if_addr(getattr(iface, "name", iface))
    except Exception:
        pass
    return ""


# ============================================================================
#  10.  Main GUI
# ============================================================================
PROTO_FILTERS = ("All", "DNS", "HTTP", "TLS", "TCP", "UDP", "ICMP", "ARP",
                 "SSDP")

# Pacing presets for the friendly "What's happening" feed. Each flush cycle
# takes whatever happened since the last one and, in "digest" modes, groups
# repeats together and caps how many new lines appear at once — this is
# what keeps a busy network from scrolling past faster than a beginner can
# read. Advanced users can switch to "Full speed" for the old firehose.
FEED_SPEEDS = {
    "🐢 Calm":       {"interval": 2500, "max_rows": 8,  "digest": True},
    "🚶 Normal":      {"interval": 700,  "max_rows": 10, "digest": True},
    "🐇 Full speed":  {"interval": 120,  "max_rows": 999, "digest": False},
}
DEFAULT_FEED_SPEED = "🐢 Calm"


class MiniWireshark:
    MAX_ROWS = 5000

    def __init__(self, root, gateway_ip, my_ips, my_macs,
                 default_iface_name=""):
        self.root = root
        self.gateway_ip = gateway_ip
        self.my_ips = set(my_ips)
        self.my_macs = set(my_macs)
        self.default_iface_name = default_iface_name

        root.title("MiniWireshark")
        root.geometry("1360x860")
        root.minsize(1050, 640)
        root.configure(background="#f4f5f7")

        self.pkt_q = queue.Queue()
        self.row_q = queue.Queue()
        self.cache = NameCache()
        self.worker = None
        self.sniffer = None
        self.rdns = None
        self.lan_scanner = None
        self.last_cache_version = -1

        self.all_rows = deque()
        self.iids = deque()
        self.rows_by_iid = {}
        self.count = 0
        self.dropped = 0
        self.filter_proto = "All"
        self.filter_text = ""

        # devices = keyed by IP (private), websites = keyed by domain
        self.devices = {}          # ip -> dict
        self.device_iids = {}
        self.websites = {}         # domain -> dict
        self.website_iids = {}

        # dns / router analysis
        self.dns_servers = defaultdict(int)   # ip -> query count
        self.doh_seen = defaultdict(set)      # device_ip -> set(doh_host)
        self.dhcp_servers = defaultdict(int)  # ip -> offer count

        # basic defensive checks (spoofing / rogue-server detection)
        self.ip_macs = defaultdict(set)       # ip -> set(mac) seen via ARP
        self.gw_macs = set()                  # macs claiming to be the gateway
        self._spoof_warned = False

        # friendly live-feed pacing ("it goes too fast" fix)
        self.feed_speed = DEFAULT_FEED_SPEED
        self.feed_paused = False
        self._feed_buffer = []

        # autonomy bookkeeping
        self._capture_started_at = 0.0
        self._auto_restart_count = 0
        self._last_restart_time = 0.0

        self.iface_map = {}

        self._apply_style()
        self._build_ui()
        self._populate_ifaces()

        self.root.after(60, self._drain_decoded)
        self.root.after(400, self._refresh_visible)
        self.root.after(1000, self._tick_status)
        self.root.after(2000, self._refresh_insights)
        self.root.after(300, self._flush_feed)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Be autonomous by default: pick the best card and start watching
        # without making a beginner hunt for the right button.
        self.root.after(700, self._auto_start_once)

    def _apply_style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("TButton", padding=(10, 6))
        s.configure("Accent.TButton", padding=(14, 8),
                    font=("TkDefaultFont", 11, "bold"))
        s.configure("Treeview", rowheight=26, font=("TkDefaultFont", 10))
        s.configure("Treeview.Heading", font=("TkDefaultFont", 10, "bold"))
        s.configure("TNotebook.Tab", padding=(18, 8),
                    font=("TkDefaultFont", 10, "bold"))

    def _build_ui(self):
        mono = tkfont.nametofont("TkFixedFont").copy(); mono.configure(size=9)
        self.mono = mono

        # ---- header
        header = tk.Frame(self.root, bg="#2b3a55", padx=16, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="🌐 MiniWireshark", fg="white", bg="#2b3a55",
                 font=("TkDefaultFont", 16, "bold")).pack(side="left")
        tk.Label(header, text="   Your network, explained in plain English",
                 fg="#c8d2e0", bg="#2b3a55").pack(side="left")

        # ---- friendly banner
        self.banner = tk.Frame(self.root, bg="#e8f0fe", padx=14, pady=10)
        self.banner.pack(fill="x")
        self.banner_lbl = tk.Label(
            self.banner,
            text="👋  Welcome! Pick your network card below and click "
                 "“Start watching”. I'll explain what's happening.",
            bg="#e8f0fe", fg="#1a3a6b", anchor="w",
            font=("TkDefaultFont", 11))
        self.banner_lbl.pack(side="left", fill="x", expand=True)

        # ---- toolbar
        bar = ttk.Frame(self.root, padding=(12, 10, 12, 4))
        bar.pack(fill="x")
        ttk.Label(bar, text="Network card:").pack(side="left")
        self.iface_var = tk.StringVar()
        self.iface_box = ttk.Combobox(bar, textvariable=self.iface_var,
                                      width=42, state="readonly")
        self.iface_box.pack(side="left", padx=(6, 14))
        ttk.Label(bar, text="Filter (optional):").pack(side="left")
        self.filter_var = tk.StringVar()
        fe = ttk.Entry(bar, textvariable=self.filter_var, width=18)
        fe.pack(side="left", padx=(6, 14))
        self.start_btn = ttk.Button(bar, text="▶  Start watching",
                                    style="Accent.TButton", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="■  Stop", command=self.stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(bar, text="Save as .pcap",
                   command=self.save_pcap).pack(side="right")
        ttk.Button(bar, text="Clear",
                   command=self.clear).pack(side="right", padx=6)

        # ---- tabs
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(8, 6))

        self.tab_feed = tk.Frame(self.nb, bg="#ffffff")
        self.tab_devices = tk.Frame(self.nb, bg="#ffffff")
        self.tab_websites = tk.Frame(self.nb, bg="#ffffff")
        self.tab_sec = tk.Frame(self.nb, bg="#ffffff")
        self.tab_raw = tk.Frame(self.nb, bg="#ffffff")

        self.nb.add(self.tab_feed, text="📖 What's happening")
        self.nb.add(self.tab_devices, text="🏠 Devices at home")
        self.nb.add(self.tab_websites, text="🌍 Websites visited")
        self.nb.add(self.tab_sec, text="🔒 Security check")
        self.nb.add(self.tab_raw, text="⚙️ All packets (advanced)")

        self._build_feed_tab()
        self._build_devices_tab()
        self._build_websites_tab()
        self._build_sec_tab()
        self._build_raw_tab()

        # ---- status bar
        self.status_var = tk.StringVar(
            value="Getting ready — I'll pick a network card and start "
                  "watching automatically.")
        tk.Label(self.root, textvariable=self.status_var, anchor="w",
                 bg="#e3e6eb", padx=10, pady=5).pack(side="bottom", fill="x")

    # ---------- feed tab -------------------------------------------------
    def _build_feed_tab(self):
        ctrl = tk.Frame(self.tab_feed, bg="#ffffff", padx=10)
        ctrl.pack(fill="x", pady=(8, 4))
        tk.Label(ctrl, text="Feed speed:", bg="#ffffff",
                 fg="#333333").pack(side="left")
        self.feed_speed_var = tk.StringVar(value=self.feed_speed)
        speed_box = ttk.Combobox(ctrl, textvariable=self.feed_speed_var,
                                 values=list(FEED_SPEEDS.keys()), width=12,
                                 state="readonly")
        speed_box.pack(side="left", padx=(6, 14))
        speed_box.bind("<<ComboboxSelected>>", self._on_speed_change)
        self.pause_btn = ttk.Button(ctrl, text="⏸  Pause feed",
                                    command=self._toggle_pause)
        self.pause_btn.pack(side="left")
        tk.Label(ctrl,
                 text="   “Calm” groups up busy moments so it's easier to "
                      "read — switch to “Full speed” to see every single "
                      "thing as it happens.",
                 bg="#ffffff", fg="#888888",
                 font=("TkDefaultFont", 9)).pack(side="left", padx=(12, 0))

        wrap = tk.Frame(self.tab_feed, bg="#ffffff")
        wrap.pack(fill="both", expand=True)
        cols = ("who", "did", "when")
        self.feed = ttk.Treeview(wrap, columns=cols, show="headings")
        self.feed.heading("who", text="Who")
        self.feed.heading("did", text="What they did")
        self.feed.heading("when", text="When")
        self.feed.column("who", width=260, anchor="w")
        self.feed.column("did", width=760, anchor="w", stretch=True)
        self.feed.column("when", width=120, anchor="center")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.feed.yview)
        self.feed.configure(yscrollcommand=vs.set)
        self.feed.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.feed.tag_configure("dns", foreground="#6a2ca0")
        self.feed.tag_configure("secure", foreground="#0b5394")
        self.feed.tag_configure("unsecure", foreground="#0b6b3a")
        self.feed.tag_configure("device", foreground="#8a5a00")
        self.feed.tag_configure("other", foreground="#333333")

    # ---------- devices tab ---------------------------------------------
    def _build_devices_tab(self):
        top = tk.Frame(self.tab_devices, bg="#ffffff", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top,
                 text="🏠  These are the devices on your local network.",
                 bg="#ffffff", fg="#333333",
                 font=("TkDefaultFont", 11)).pack(anchor="w")

        body = tk.Frame(self.tab_devices, bg="#ffffff")
        body.pack(fill="both", expand=True)
        cols = ("icon", "name", "ip", "mac", "vendor", "count", "last")
        self.devtree = ttk.Treeview(body, columns=cols, show="headings")
        for c, t, w, a in (("icon", "", 40, "center"),
                           ("name", "What it likely is", 220, "w"),
                           ("ip", "Local IP", 140, "w"),
                           ("mac", "MAC address", 150, "w"),
                           ("vendor", "Made by", 160, "w"),
                           ("count", "Packets", 80, "e"),
                           ("last", "Last seen", 90, "center")):
            self.devtree.heading(c, text=t)
            self.devtree.column(c, width=w, anchor=a,
                                stretch=(c in ("name", "vendor")))
        vs = ttk.Scrollbar(body, orient="vertical", command=self.devtree.yview)
        self.devtree.configure(yscrollcommand=vs.set)
        self.devtree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

    # ---------- websites tab --------------------------------------------
    def _build_websites_tab(self):
        top = tk.Frame(self.tab_websites, bg="#ffffff", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top,
                 text="🌍  Every website or service anyone on your Wi-Fi "
                      "looked up or connected to.",
                 bg="#ffffff", fg="#333333",
                 font=("TkDefaultFont", 11)).pack(anchor="w")

        body = tk.Frame(self.tab_websites, bg="#ffffff")
        body.pack(fill="both", expand=True)
        cols = ("site", "ip", "who", "count", "first", "last", "note")
        self.sitetree = ttk.Treeview(body, columns=cols, show="headings")
        for c, t, w, a in (("site", "Website", 260, "w"),
                           ("ip", "Server IP", 150, "w"),
                           ("who", "Asked by", 220, "w"),
                           ("count", "Packets", 80, "e"),
                           ("first", "First seen", 100, "center"),
                           ("last", "Last seen", 100, "center"),
                           ("note", "Notes", 260, "w")):
            self.sitetree.heading(c, text=t)
            self.sitetree.column(c, width=w, anchor=a,
                                 stretch=(c in ("site", "who", "note")))
        vs = ttk.Scrollbar(body, orient="vertical", command=self.sitetree.yview)
        self.sitetree.configure(yscrollcommand=vs.set)
        self.sitetree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

    # ---------- security check ------------------------------------------
    def _build_sec_tab(self):
        outer = tk.Frame(self.tab_sec, bg="#ffffff")
        outer.pack(fill="both", expand=True, padx=14, pady=12)
        tk.Label(outer, text="🔒  Security check",
                 bg="#ffffff", fg="#2b3a55",
                 font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        tk.Label(outer,
                 text="Friendly explanations of what I've noticed.",
                 bg="#ffffff", fg="#666666").pack(anchor="w", pady=(0, 8))

        self.sec_text = tk.Text(outer, wrap="word", bg="#fbfbfb",
                                relief="flat", padx=14, pady=12,
                                font=("TkDefaultFont", 11), state="disabled")
        vs = ttk.Scrollbar(outer, orient="vertical",
                           command=self.sec_text.yview)
        self.sec_text.configure(yscrollcommand=vs.set)
        self.sec_text.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

        self.sec_text.tag_configure("h1", font=("TkDefaultFont", 12, "bold"),
                                    foreground="#2b3a55", spacing1=10,
                                    spacing3=4)
        self.sec_text.tag_configure("good", foreground="#0b6b3a",
                                    font=("TkDefaultFont", 11))
        self.sec_text.tag_configure("warn", foreground="#a05608",
                                    font=("TkDefaultFont", 11))
        self.sec_text.tag_configure("bad", foreground="#a01a08",
                                    font=("TkDefaultFont", 11))
        self.sec_text.tag_configure("dim", foreground="#666666")
        self.sec_text.tag_configure("body", foreground="#222222",
                                    spacing3=4)

    # ---------- raw packets tab -----------------------------------------
    def _build_raw_tab(self):
        pills = ttk.Frame(self.tab_raw, padding=(10, 8, 10, 4))
        pills.pack(fill="x")
        ttk.Label(pills, text="Show only:").pack(side="left", padx=(0, 6))
        self.pill_buttons = {}
        for n in PROTO_FILTERS:
            b = tk.Button(pills, text=n, relief="flat", bd=1, padx=10, pady=3,
                          bg="#e6e8ec", activebackground="#cfd6e0",
                          command=lambda nn=n: self._set_proto(nn))
            b.pack(side="left", padx=2)
            self.pill_buttons[n] = b
        self._set_proto("All", redraw=False)

        ttk.Label(pills, text="  Search:").pack(side="left", padx=(14, 4))
        self.search_var = tk.StringVar()
        se = ttk.Entry(pills, textvariable=self.search_var, width=24)
        se.pack(side="left")
        se.bind("<KeyRelease>", lambda _e: self._on_search())

        vert = ttk.PanedWindow(self.tab_raw, orient="vertical")
        vert.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        list_frame = ttk.Frame(vert); vert.add(list_frame, weight=3)
        cols = ("no", "time", "src", "dst", "proto", "length", "ttl", "info")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings",
                                 selectmode="browse")
        for c, t, w, a in (("no", "No.", 55, "e"),
                           ("time", "Time", 95, "center"),
                           ("src", "Source", 190, "w"),
                           ("dst", "Destination", 190, "w"),
                           ("proto", "Protocol", 90, "center"),
                           ("length", "Length", 60, "e"),
                           ("ttl", "TTL", 45, "e"),
                           ("info", "Info", 560, "w")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor=a, stretch=(c == "info"))
        vs = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(list_frame, orient="horizontal",
                           command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        list_frame.rowconfigure(0, weight=1); list_frame.columnconfigure(0, weight=1)

        for tag, (fg, bg) in TAG_COLORS.items():
            kw = {"foreground": fg}
            if bg:
                kw["background"] = bg
            self.tree.tag_configure(tag, **kw)

        bottom = ttk.Frame(vert); vert.add(bottom, weight=2)
        nb = ttk.Notebook(bottom); nb.pack(fill="both", expand=True)
        df, self.details = self._scrolled(nb)
        hf, self.hexview = self._scrolled(nb)
        nb.add(df, text="Packet details")
        nb.add(hf, text="Hex dump")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _scrolled(self, parent):
        f = ttk.Frame(parent)
        txt = tk.Text(f, wrap="none", font=self.mono, state="disabled",
                      bg="#ffffff", relief="flat", padx=6, pady=6)
        vs = ttk.Scrollbar(f, orient="vertical", command=txt.yview)
        hs = ttk.Scrollbar(f, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        txt.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        f.rowconfigure(0, weight=1); f.columnconfigure(0, weight=1)
        return f, txt

    # ---------- interfaces ----------------------------------------------
    def _populate_ifaces(self):
        labels, seen = [], set()
        try:
            for iface in conf.ifaces.values():
                desc = (getattr(iface, "description", "") or "").strip()
                name = iface.name
                label = desc if desc and desc != name else name
                if len(label) > 70:
                    label = label[:67] + "..."
                base, i = label, 2
                while label in seen:
                    label = f"{base} ({i})"; i += 1
                seen.add(label)
                self.iface_map[label] = iface
                labels.append(label)
        except Exception as e:
            self.status_var.set(f"Couldn't list network cards: {e}")
            try:
                for n in get_if_list():
                    self.iface_map[n] = n; labels.append(n)
            except Exception:
                pass
        if not labels:
            self.iface_map["Default"] = None
            labels = ["Default"]
        self.iface_box["values"] = labels
        # Prefer the interface actually used for the default route (freshly
        # computed at startup) over scapy's possibly-stale conf.iface, but
        # fall back to conf.iface, then to the first card in the list.
        candidates = []
        if self.default_iface_name:
            candidates.append(self.default_iface_name)
        try:
            candidates.append(str(conf.iface))
        except Exception:
            pass
        chosen = labels[0]
        for cand in candidates:
            for lbl in labels:
                iface = self.iface_map[lbl]
                nm = getattr(iface, "name", iface)
                if nm == cand or str(nm) == cand:
                    chosen = lbl; break
            else:
                continue
            break
        self.iface_var.set(chosen)

    # ---------- capture -------------------------------------------------
    def _auto_start_once(self):
        """Called shortly after launch — no click required."""
        if self.sniffer is not None:
            return
        self._set_banner("🤖  Getting started automatically — picking "
                         "your best network card ...")
        self.start(auto=True)

    def start(self, auto=False):
        if self.sniffer is not None:
            return
        label = self.iface_var.get()
        all_labels = list(self.iface_box["values"])
        # Try the chosen card first; if it fails, try the others too
        # (capped, so a broken card can't freeze the app for too long)
        # instead of just giving up — this is what "more autonomous"
        # means when the auto-picked card turns out to be wrong.
        candidates = ([label] + [l for l in all_labels if l != label])[:5]
        bpf = self.filter_var.get().strip() or None
        self.dropped = 0

        if self.worker is None:
            self.worker = DecodeWorker(self.pkt_q, self.row_q, self.cache,
                                       self.gateway_ip, self.my_ips)
            self.worker.start()
        if self.rdns is None:
            self.rdns = ReverseDNS(self.cache)

        self.status_var.set("Starting ...")
        self.root.update_idletasks()

        sniffer, err, used_label = None, None, None
        for lbl in candidates:
            iface = self.iface_map.get(lbl)
            sniffer, err = build_sniffer(iface, self._sniff_cb, bpf)
            if sniffer is not None:
                used_label = lbl
                break

        if sniffer is None:
            if self.worker:
                self.worker.stop_flag = True; self.worker = None
            self.rdns = None
            self.status_var.set("Could not start watching on any network card.")
            self._set_banner(
                f"❌  I couldn't start watching ({err}). Try running as "
                f"Administrator / root, or pick a different network card "
                f"and click “Start watching”.", kind="bad")
            return

        self.sniffer = sniffer
        self._capture_started_at = time.time()
        self._auto_restart_count = 0
        if used_label != label:
            self.iface_var.set(used_label)
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        iface_obj = self.iface_map.get(used_label)
        my_ip = _iface_ip(iface_obj) or \
            (next(iter(self.my_ips)) if self.my_ips else "")
        self.lan_scanner = LanScanner(iface_obj, my_ip)
        self.lan_scanner.start()

        if used_label != label:
            self._set_banner(
                f"👀  “{label}” didn't work, so I switched to "
                f"“{used_label}” automatically. Open a website to see it "
                f"in action!")
        elif auto:
            self._set_banner(
                f"👀  Watching “{used_label}” automatically. I'm also "
                f"quietly scanning your Wi-Fi for other devices. Open a "
                f"website to see it in action!")
        else:
            self._set_banner(
                "👀  I'm watching your network now. Try opening a website "
                "in your browser — you'll see it appear here.")
        self.status_var.set(
            f"👀 Watching “{used_label}”. Open a website to see it.")

    def _sniff_cb(self, pkt):
        try:
            self.pkt_q.put_nowait(pkt)
        except queue.Full:
            self.dropped += 1

    def stop(self):
        s, self.sniffer = self.sniffer, None
        if s is not None:
            try:
                s.stop()
            except Exception:
                pass
        if self.worker is not None:
            self.worker.stop_flag = True; self.worker = None
        if self.lan_scanner is not None:
            self.lan_scanner.stop_flag = True; self.lan_scanner = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set(f"Stopped. Saw {self.count} packets.")
        self._set_banner("⏸️  Stopped watching.")

    # ---------- banner --------------------------------------------------
    def _set_banner(self, text, kind="info"):
        colors = {"info": ("#e8f0fe", "#1a3a6b"),
                  "warn": ("#fff4e0", "#7a4a00"),
                  "bad":  ("#fbe9e7", "#8a1a08"),
                  "good": ("#e6f4ea", "#0b6b3a")}
        bg, fg = colors.get(kind, colors["info"])
        self.banner.config(bg=bg)
        self.banner_lbl.config(bg=bg, fg=fg, text=text)

    # ---------- main loop ----------------------------------------------
    def _drain_decoded(self):
        n = 0
        while n < 800:
            try:
                d = self.row_q.get_nowait()
            except queue.Empty:
                break
            try:
                self._add_row(d)
            except Exception:
                traceback.print_exc()
            n += 1
        self.root.after(50, self._drain_decoded)

    def _refresh_visible(self):
        if self.cache.version != self.last_cache_version:
            self.last_cache_version = self.cache.version
            for iid, row in list(self.rows_by_iid.items()):
                try:
                    self.tree.set(iid, "src", self._disp(row["src_ip"],
                                                         row["src_mac"]))
                    self.tree.set(iid, "dst", self._disp(row["dst_ip"],
                                                         row["dst_mac"]))
                except tk.TclError:
                    pass
        self.root.after(400, self._refresh_visible)

    def _tick_status(self):
        if self.sniffer is not None:
            if not getattr(self.sniffer, "running", True) or \
                    getattr(self.sniffer, "exception", None) is not None:
                self._handle_sniffer_died(getattr(self.sniffer, "exception",
                                                   None))
            else:
                d = f"  (dropped {self.dropped})" if self.dropped else ""
                self.status_var.set(
                    f"👀 Watching.  {self.count} packets, "
                    f"{len(self.devices)} devices, "
                    f"{len(self.websites)} websites{d}")
        self.root.after(1000, self._tick_status)

    def _handle_sniffer_died(self, exc):
        """The capture socket died on its own (adapter reset, driver hiccup,
        etc.) — heal automatically a few times before asking for help."""
        self.sniffer = None
        if self.worker is not None:
            self.worker.stop_flag = True; self.worker = None
        if self.lan_scanner is not None:
            self.lan_scanner.stop_flag = True; self.lan_scanner = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

        now = time.time()
        if now - self._last_restart_time > 30:
            self._auto_restart_count = 0
        self._last_restart_time = now
        self._auto_restart_count += 1

        if self._auto_restart_count <= 3:
            self._set_banner(
                "🔧  The watcher stopped unexpectedly — restarting it "
                "automatically ...", kind="warn")
            self.root.after(600, lambda: self.start(auto=True))
        else:
            reason = f" ({exc})" if exc else ""
            self._set_banner(
                f"⏸️  The watcher kept stopping{reason}. Click "
                f"“Start watching” to try again, or pick a different "
                f"network card.", kind="bad")
            self.status_var.set("Stopped after repeated errors.")

    def _refresh_insights(self):
        self._render_security_check()
        self.root.after(2000, self._refresh_insights)

    def _disp(self, ip, mac):
        if ip:
            n = self.cache.get(ip)
            return n if n else ip
        return mac or ""

    # ---------- row handling -------------------------------------------
    def _add_row(self, d):
        self.count += 1
        d["no"] = self.count

        # register devices (private IPs + MACs)
        self._observe_packet_for_devices(d)
        # register websites (public IP + name)
        self._observe_packet_for_websites(d)
        # dns-server tracking
        if d["tag"] in ("DNS", "mDNS", "LLMNR") and d["dst_ip"]:
            if d["tag"] == "DNS":
                self.dns_servers[d["dst_ip"]] += 1
        if d.get("doh_hint"):
            self.doh_seen[d["src_ip"]].add(d["doh_hint"])

        # rogue-DHCP-server tracking (defensive — informational only)
        if d.get("dhcp_msgtype") == 2 and d["src_ip"]:
            self.dhcp_servers[d["src_ip"]] += 1

        # ARP identity tracking (defensive — catches classic ARP-spoofing,
        # where a device impersonates another IP, most importantly your
        # router). Only "is-at" claims (op 2) are authoritative identity
        # claims; "who-has" requests (op 1) are not.
        if d.get("arp_op") == 2 and d["src_ip"] and d["src_mac"]:
            self._observe_arp_identity(d["src_ip"], d["src_mac"])

        if self.rdns:
            for ip in (d["src_ip"], d["dst_ip"]):
                if ip and is_private_ip(ip) and not self.cache.get(ip):
                    self.rdns.lookup(ip)

        self.all_rows.append(d)
        while len(self.all_rows) > self.MAX_ROWS:
            self.all_rows.popleft()

        # friendly feed entry (paced — see _flush_feed)
        self._feed_add(d)

        # raw packet tab
        if self._matches(d):
            self._insert_row(d)

    def _observe_arp_identity(self, ip, mac):
        macs = self.ip_macs[ip]
        is_new_mac = mac not in macs
        macs.add(mac)
        if not is_new_mac or len(macs) < 2:
            return
        if ip == self.gateway_ip:
            self.gw_macs.add(mac)
            if not self._spoof_warned:
                self._spoof_warned = True
                self._set_banner(
                    "🚨  Your router's address (MAC) just changed — this "
                    "can be normal after a router reboot, but it's also "
                    "the classic sign of ARP spoofing. Check the Security "
                    "check tab.", kind="bad")

    def _feed_add(self, d):
        who = self._friendly_who(d["src_ip"], d["src_mac"])
        when = datetime.fromtimestamp(d["time"]).strftime("%H:%M:%S")

        tag = "other"
        did = d["text"]
        proto = d["proto"]

        if proto in ("DNS", "mDNS", "LLMNR"):
            tag = "dns"
            did = f"🔍 looked up  {d['text']}" if d["text"] else "🔍 DNS lookup"
        elif proto == "TLS":
            tag = "secure"
            did = f"🔐 opened secure connection  {d['text']}"
        elif proto == "QUIC":
            tag = "secure"
            did = "🔐 opened secure connection (fast)"
        elif proto == "HTTP":
            tag = "unsecure"
            did = f"⚠️ opened unsecured page  {d['text']}"
        elif proto == "DHCP":
            tag = "device"
            did = f"🆔 asked for an IP address  {d['text']}"
        elif proto == "ARP":
            tag = "device"
            did = f"🔎 looked for a device  {d['text']}"
        elif proto == "SSDP":
            tag = "device"
            did = f"📣 {d['text']}"
        elif proto == "ICMP":
            did = f"📡 ping / reply  {d['text']}"

        # skip very noisy rows for the friendly feed
        if proto in ("TCP", "UDP") and not d["dns_names"]:
            # summarize only meaningful ones
            if d["dport"] in (80, 443) or d["sport"] in (80, 443):
                if proto == "TCP":
                    did = "🔗 connection"
                    tag = "other"
                else:
                    return
            else:
                return

        self._feed_push(tag, who, did, when)

    def _feed_push(self, tag, who, did, when=None):
        """Queue an event for the friendly feed instead of drawing it
        immediately — _flush_feed() below paces how fast these actually
        appear, which is what keeps a busy network readable."""
        self._feed_buffer.append({
            "who": who, "did": did, "tag": tag,
            "when": when or datetime.now().strftime("%H:%M:%S"),
        })
        if len(self._feed_buffer) > 800:
            del self._feed_buffer[:-800]

    def _on_speed_change(self, _e=None):
        self.feed_speed = self.feed_speed_var.get()

    def _toggle_pause(self):
        self.feed_paused = not self.feed_paused
        self._update_pause_button_label()

    def _update_pause_button_label(self):
        if self.feed_paused:
            n = len(self._feed_buffer)
            label = f"▶  Resume ({n} waiting)" if n else "▶  Resume"
        else:
            label = "⏸  Pause feed"
        try:
            self.pause_btn.config(text=label)
        except tk.TclError:
            pass

    def _flush_feed(self):
        cfg = FEED_SPEEDS.get(self.feed_speed, FEED_SPEEDS[DEFAULT_FEED_SPEED])
        if self.feed_paused:
            self._update_pause_button_label()
            self.root.after(300, self._flush_feed)
            return
        buf, self._feed_buffer = self._feed_buffer, []
        if buf:
            if cfg["digest"] or len(buf) > cfg["max_rows"]:
                rows = self._digest_events(buf, cfg["max_rows"])
            else:
                rows = [(b["tag"], b["who"], b["did"], b["when"]) for b in buf]
            for tag, who, did, when in rows:
                self._feed_insert(tag, who, did, when)
            self._trim_feed()
        self.root.after(cfg["interval"], self._flush_feed)

    def _digest_events(self, buf, cap):
        """Collapse exact repeats (same who/what happening again and
        again) and cap how many new lines appear in one go, so a burst of
        activity reads as a short summary instead of a wall of text."""
        counts = {}
        order = []
        for b in buf:
            key = (b["who"], b["tag"], b["did"])
            if key not in counts:
                counts[key] = 0
                order.append(key)
            counts[key] += 1
        rows = []
        for key in order[:cap]:
            who, tag, did = key
            n = counts[key]
            text = did if n == 1 else f"{did}  (×{n})"
            rows.append((tag, who, text, buf[-1]["when"]))
        leftover = order[cap:]
        if leftover:
            extra = sum(counts[k] for k in leftover)
            rows.append(("other", "…",
                        f"+{extra} more thing(s) just happened — switch "
                        f"to “Full speed” to see every line",
                        buf[-1]["when"]))
        return rows

    def _feed_insert(self, tag, who, did, when):
        try:
            self.feed.insert("", 0, tags=(tag,), values=(who, did, when))
        except tk.TclError:
            pass

    def _trim_feed(self):
        children = self.feed.get_children()
        if len(children) > 500:
            for old in children[500:]:
                try:
                    self.feed.delete(old)
                except tk.TclError:
                    pass

    def _friendly_who(self, ip, mac):
        if ip and ip in self.my_ips:
            return "💻  This computer"
        if ip and ip == self.gateway_ip:
            return "🌐  Your router"
        name = self.cache.get(ip) if ip else ""
        dev = self.devices.get(ip) if ip else None
        kind = dev.get("type", "unknown") if dev else "unknown"
        icon = DEVICE_ICONS.get(kind, "❓")
        label = name or (dev.get("vendor") if dev else "") or ip or mac
        if kind == "unknown" and ip and is_public_ip(ip):
            return f"☁️  {ip}"
        return f"{icon}  {label}" if label else "❓  Unknown device"

    def _observe_packet_for_devices(self, d):
        seen = set()
        hint = d.get("type_hint", "")
        for ip, mac in ((d["src_ip"], d["src_mac"]),
                        (d["dst_ip"], d["dst_mac"])):
            if not ip or ip in seen:
                continue
            if not (is_private_ip(ip) or (mac and mac != "ff:ff:ff:ff:ff:ff")):
                continue
            seen.add(ip)
            # a hint (from mDNS/SSDP) describes whoever sent the packet
            self._register_device(ip, mac, hint if ip == d["src_ip"] else "")

    def _register_device(self, ip, mac, type_hint=""):
        dev = self.devices.get(ip)
        now = time.strftime("%H:%M:%S")
        is_new = dev is None
        if dev is None:
            dev = {"ip": ip, "mac": "", "vendor": "", "hostname": "",
                   "count": 0, "last": now, "type": "unknown",
                   "type_hint": ""}
            self.devices[ip] = dev
        dev["count"] += 1
        dev["last"] = now
        if mac and not dev["mac"]:
            dev["mac"] = mac
            dev["vendor"] = mac_vendor(mac)
        name = self.cache.get(ip)
        if name and not dev["hostname"]:
            dev["hostname"] = name
        if type_hint:
            dev["type_hint"] = type_hint
        guessed = guess_device_type(dev["hostname"], dev["vendor"], ip,
                                    self.gateway_ip, self.my_ips)
        if guessed == "unknown" and dev.get("type_hint"):
            guessed = dev["type_hint"]
        dev["type"] = guessed
        self._redraw_device_row(ip)

        # Quietly announce genuinely new arrivals in the feed — but not
        # during the first few seconds, when *everything* looks "new".
        if is_new and self.sniffer is not None and \
                (time.time() - self._capture_started_at) > 8:
            self._feed_push("device", self._friendly_who(ip, mac),
                            "🆕 joined your Wi-Fi (new device)")

    def _redraw_device_row(self, ip):
        dev = self.devices.get(ip)
        if not dev:
            return
        icon = DEVICE_ICONS.get(dev["type"], "❓")
        label = self._device_label(dev)
        iid = self.device_iids.get(ip)
        vals = (icon, label, ip, dev["mac"] or "—",
                dev["vendor"] or "—", dev["count"], dev["last"])
        if iid:
            try:
                self.devtree.item(iid, values=vals)
                return
            except tk.TclError:
                pass
        try:
            iid = self.devtree.insert("", "end", values=vals)
            self.device_iids[ip] = iid
        except tk.TclError:
            pass

    def _device_label(self, dev):
        kind = dev["type"]
        if kind == "this-pc":
            return "This computer"
        if kind == "router":
            return "Your router / gateway"
        if dev["hostname"]:
            return dev["hostname"]
        if dev["vendor"]:
            return f"{kind.title()} ({dev['vendor']})"
        return kind.title()

    def _observe_packet_for_websites(self, d):
        # learn domain -> ip pairs
        for ip, name in d["learns"]:
            if is_public_ip(ip) and name:
                self._register_website(name, ip, d["src_ip"])
        # for TLS SNI, use dns_names too
        for name in d["dns_names"]:
            if d["dst_ip"] and is_public_ip(d["dst_ip"]):
                self._register_website(name, d["dst_ip"], d["src_ip"])

    def _register_website(self, domain, ip, device_ip):
        key = domain.lower().strip(".")
        if not key:
            return
        rec = self.websites.get(key)
        now = time.strftime("%H:%M:%S")
        if rec is None:
            rec = {"domain": key, "ips": set(), "devices": set(),
                   "count": 0, "first": now, "last": now, "note": ""}
            self.websites[key] = rec
        rec["ips"].add(ip)
        if device_ip and is_private_ip(device_ip):
            rec["devices"].add(device_ip)
        rec["count"] += 1
        rec["last"] = now
        if key in DOH_HOSTS:
            rec["note"] = DOH_HOSTS[key]
        self._redraw_website_row(key)

    def _redraw_website_row(self, key):
        rec = self.websites.get(key)
        if not rec:
            return
        ips = ", ".join(sorted(rec["ips"])[:2])
        who = ", ".join(self._short_device_name(i)
                        for i in sorted(rec["devices"])[:3]) or "—"
        iid = self.website_iids.get(key)
        vals = (rec["domain"], ips, who, rec["count"],
                rec["first"], rec["last"], rec["note"])
        if iid:
            try:
                self.sitetree.item(iid, values=vals); return
            except tk.TclError:
                pass
        try:
            iid = self.sitetree.insert("", "end", values=vals)
            self.website_iids[key] = iid
        except tk.TclError:
            pass

    def _short_device_name(self, ip):
        if ip in self.my_ips:
            return "This computer"
        if ip == self.gateway_ip:
            return "Router"
        n = self.cache.get(ip)
        return n or ip

    # ---------- filtering / raw tab -------------------------------------
    def _matches(self, d):
        f = self.filter_proto
        if f != "All" and d["tag"] != f and d["proto"] != f:
            return False
        q = self.filter_text
        if q:
            hay = " ".join([d.get("src_ip", ""), d.get("dst_ip", ""),
                            self.cache.get(d["src_ip"]),
                            self.cache.get(d["dst_ip"]),
                            d.get("proto", ""), d.get("text", ""),
                            str(d.get("sport", "") or ""),
                            str(d.get("dport", "") or "")]).lower()
            if q.lower() not in hay:
                return False
        return True

    def _insert_row(self, d):
        vals = (d["no"],
                datetime.fromtimestamp(d["time"]).strftime("%H:%M:%S.%f")[:-3],
                self._disp(d["src_ip"], d["src_mac"]),
                self._disp(d["dst_ip"], d["dst_mac"]),
                d["proto"], d["length"], d["ttl"], d["text"])
        iid = self.tree.insert("", "end", tags=(d["tag"],), values=vals)
        self.rows_by_iid[iid] = d
        self.iids.append(iid)
        while len(self.iids) > self.MAX_ROWS:
            old = self.iids.popleft()
            self.rows_by_iid.pop(old, None)
            try:
                self.tree.delete(old)
            except tk.TclError:
                pass
        try:
            self.tree.see(iid)
        except tk.TclError:
            pass

    def _set_proto(self, name, redraw=True):
        self.filter_proto = name
        for n, b in self.pill_buttons.items():
            if n == name:
                b.config(bg="#2b3a55", fg="white", relief="sunken")
            else:
                b.config(bg="#e6e8ec", fg="black", relief="flat")
        if redraw:
            self._rebuild()

    def _on_search(self):
        self.filter_text = self.search_var.get().strip()
        self._rebuild()

    def _rebuild(self):
        self.tree.delete(*self.tree.get_children())
        self.iids.clear(); self.rows_by_iid.clear()
        for d in self.all_rows:
            if self._matches(d):
                self._insert_row(d)

    # ---------- details -------------------------------------------------
    def _on_select(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        d = self.rows_by_iid.get(sel[0])
        if not d:
            return
        pkt = d["pkt"]
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        try:
            self.details.insert("end", pkt.show(dump=True))
        except Exception as e:
            self.details.insert("end", f"<cannot decode: {e}>")
        self.details.config(state="disabled")

        self.hexview.config(state="normal")
        self.hexview.delete("1.0", "end")
        try:
            self.hexview.insert("end", hexdump(pkt, dump=True))
        except Exception as e:
            self.hexview.insert("end", f"<cannot dump: {e}>")
        self.hexview.config(state="disabled")

    # ---------- security check tab --------------------------------------
    def _render_security_check(self):
        t = self.sec_text
        t.config(state="normal")
        t.delete("1.0", "end")

        def h1(s): t.insert("end", s + "\n", "h1")
        def good(s): t.insert("end", "✔  " + s + "\n", "good")
        def warn(s): t.insert("end", "⚠  " + s + "\n", "warn")
        def bad(s): t.insert("end", "✘  " + s + "\n", "bad")
        def body(s): t.insert("end", "    " + s + "\n", "body")
        def dim(s): t.insert("end", "    " + s + "\n", "dim")

        h1("What is this?")
        body("This page explains what I've seen on your network in plain "
             "English. Nothing leaves your computer — everything here is "
             "based on packets I've captured.")

        h1("Your gateway / router")
        if self.gateway_ip:
            good(f"Your router is at {self.gateway_ip}. All your internet "
                 f"traffic goes through it.")
            body("If you didn't recognize this number, someone may have "
                 "changed your Wi-Fi router. Your router's admin page is "
                 "usually at http://" + self.gateway_ip)
        else:
            warn("I couldn't detect your router yet. Start watching and "
                 "then open a website — I'll figure it out.")

        h1("Device identity checks (ARP)")
        if self.gateway_ip and len(self.gw_macs) > 1:
            bad(f"Your router's address has answered from "
                f"{len(self.gw_macs)} different MAC addresses. That can "
                f"happen after a router reboot or firmware update, but "
                f"it's also the classic sign of ARP spoofing — a device on "
                f"your Wi-Fi pretending to be your router so it can see "
                f"your traffic.")
            body("If you didn't just restart your router, disconnect from "
                 "this Wi-Fi and check your router's admin page from a "
                 "device you trust.")
        elif self.gateway_ip:
            good("Your router's address has stayed consistent — no signs "
                 "of ARP spoofing so far.")
        else:
            dim("Watching for this once I know where your router is.")
        odd = {ip: macs for ip, macs in self.ip_macs.items()
              if len(macs) > 1 and ip != self.gateway_ip}
        if odd:
            shown = list(odd.items())[:5]
            names = ", ".join(self._short_device_name(ip) for ip, _ in shown)
            warn(f"{len(odd)} local address(es) have answered from more "
                 f"than one device: {names}.")
            body("This is usually harmless — phones and laptops often "
                 "rotate their Wi-Fi address for privacy, and a device "
                 "reconnecting can pick up the same IP as before. It's "
                 "only worth worrying about if it happens a lot, all at "
                 "once, right when something on your network starts "
                 "acting strangely.")

        h1("Who is handing out addresses (DHCP)?")
        if not self.dhcp_servers:
            dim("No DHCP activity seen yet.")
        elif len(self.dhcp_servers) > 1:
            servers = ", ".join(sorted(self.dhcp_servers))
            bad(f"{len(self.dhcp_servers)} different devices are handing "
                f"out IP addresses: {servers}.")
            body("Normally only your router does this. More than one "
                 "usually means either a second router plugged into the "
                 "network by mistake, or — less commonly — a rogue DHCP "
                 "server. If a device you don't recognize is on that "
                 "list, unplug it and check your network.")
        else:
            server_ip = next(iter(self.dhcp_servers))
            if server_ip == self.gateway_ip or not self.gateway_ip:
                good(f"Your router ({server_ip}) is the one handing out "
                     f"addresses. Normal setup.")
            else:
                warn(f"{server_ip} is handing out addresses, which isn't "
                     f"your router ({self.gateway_ip}).")
                body("Unusual, but not necessarily bad — some home setups "
                     "use a separate DHCP server on purpose.")

        h1("Who is doing your DNS lookups (finding website addresses)?")
        if not self.dns_servers:
            dim("No DNS traffic seen yet. Open a website and check again.")
        else:
            for server_ip, count in sorted(self.dns_servers.items(),
                                           key=lambda x: -x[1])[:6]:
                if server_ip == self.gateway_ip:
                    good(f"Your router ({server_ip}) is handling DNS "
                         f"lookups. {count} queries so far.")
                    body("This is the normal setup at home: your router "
                         "looks up websites on your behalf. Whatever DNS "
                         "service your router uses (often your ISP's, "
                         "sometimes a custom one), that's what you get.")
                elif is_private_ip(server_ip):
                    warn(f"A local device at {server_ip} is acting as a "
                         f"DNS server ({count} queries).")
                    body("This is unusual unless you set up a Pi-hole, AdGuard "
                         "Home, or a similar DNS filter. If you didn't set "
                         "that up, someone might have added a device to your "
                         "Wi-Fi.")
                else:
                    known = KNOWN_DNS.get(server_ip, "")
                    if known:
                        warn(f"Someone is using {known} directly "
                             f"({server_ip}), {count} queries.")
                        body("This means a device on your Wi-Fi is bypassing "
                             "your router's DNS and asking a public DNS "
                             "provider directly. It usually means either: "
                             "(a) the device has a custom DNS setting, "
                             "or (b) your router itself was configured to "
                             "use this DNS service. On its own, this isn't "
                             "dangerous — it's a choice about privacy and "
                             "speed.")
                    else:
                        warn(f"Someone is using a custom DNS server at "
                             f"{server_ip} ({count} queries).")
                        body("I don't recognize this DNS server. It might be "
                             "your ISP, or a company VPN, or something "
                             "unusual. If you didn't set this up yourself, "
                             "it's worth checking your router's settings.")

        h1("Encrypted DNS (DoH) — the private option")
        if self.doh_seen:
            for dev, hosts in self.doh_seen.items():
                who = self._short_device_name(dev)
                for h in sorted(hosts):
                    good(f"{who} is using {h}.")
            body("Encrypted DNS (DoH) hides your website lookups even from "
                 "your router. It's good for privacy, but it also means "
                 "I can't see your browsing history. That's fine — I just "
                 "want you to know it's happening.")
        else:
            dim("No encrypted DNS detected so far. Website lookups are "
                "visible in plain text on your network.")

        h1("Unencrypted web traffic")
        http_rows = [r for r in self.all_rows if r["proto"] == "HTTP"]
        if http_rows:
            warn(f"I saw {len(http_rows)} unencrypted (http://) web "
                 f"requests.")
            body("These send the web page contents in plain text. Anyone on "
                 "the same Wi-Fi could read them. Modern sites use https:// "
                 "which is encrypted. If you see a lot of these, it might be "
                 "an old website or an app that needs updating.")
            seen_hosts = set()
            for r in http_rows[:5]:
                line = r["text"]
                if "Host:" in line:
                    h = line.split("Host:")[-1].strip().split()[0]
                    if h and h not in seen_hosts:
                        seen_hosts.add(h)
            if seen_hosts:
                body("Examples: " + ", ".join(sorted(seen_hosts)))
        else:
            good("No unencrypted web traffic seen so far.")

        h1("Devices on your Wi-Fi")
        if not self.devices:
            dim("No local devices seen yet.")
        else:
            unknown = [d for d in self.devices.values()
                       if d["type"] == "unknown" and not d["vendor"]]
            if unknown:
                warn(f"{len(unknown)} device(s) couldn't be identified.")
                body("Their MAC addresses don't match any known manufacturer. "
                     "This is common for cheap IoT devices, phones with "
                     "privacy MAC randomization, and some virtual machines. "
                     "Check the Devices tab to see them.")
            else:
                good("Every device I've seen can be identified.")

        h1("The honest summary")
        if self.sniffer is None:
            dim("I'm not watching right now. Click “Start watching” and "
                "browse the web for a minute to get real results.")
        else:
            body(f"I've seen {self.count} packets, "
                 f"{len(self.devices)} device(s), "
                 f"and {len(self.websites)} website(s).")
        t.config(state="disabled")

    # ---------- utils ---------------------------------------------------
    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.devtree.delete(*self.devtree.get_children())
        self.sitetree.delete(*self.sitetree.get_children())
        self.feed.delete(*self.feed.get_children())
        self.all_rows.clear()
        self.iids.clear(); self.rows_by_iid.clear()
        self.devices.clear(); self.device_iids.clear()
        self.websites.clear(); self.website_iids.clear()
        self.dns_servers.clear(); self.doh_seen.clear()
        self.dhcp_servers.clear()
        self.ip_macs.clear(); self.gw_macs.clear()
        self._spoof_warned = False
        self._feed_buffer.clear()
        self.count = 0; self.dropped = 0
        for w in (self.details, self.hexview):
            w.config(state="normal"); w.delete("1.0", "end")
            w.config(state="disabled")
        self.status_var.set("Cleared.")
        self._set_banner("🧹  Cleared. I'm ready to start again.")

    def save_pcap(self):
        if not self.all_rows:
            messagebox.showinfo("Save .pcap", "No packets to save yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if not path:
            return
        try:
            wrpcap(path, [d["pkt"] for d in self.all_rows])
        except Exception as e:
            messagebox.showerror("Save error", str(e))
            return
        self.status_var.set(f"Saved {len(self.all_rows)} packets to {path}")

    def _on_close(self):
        self.stop(); self.root.destroy()


# ============================================================================
#  11.  Entry point
# ============================================================================
def detect_gateway_and_self():
    """Return (gateway_ip, my_ips, my_macs, default_iface_name)."""
    gw = ""
    my_ips, my_macs = set(), set()
    default_iface_name = ""
    try:
        from scapy.all import conf as _conf
        try:
            # scapy's route() returns (iface, output_ip, gateway_ip) —
            # in that order.
            def_iface, my_ip, gw_ip = _conf.route.route("0.0.0.0")
            gw = gw_ip or ""
            default_iface_name = str(getattr(def_iface, "name", def_iface)
                                     or "")
            if my_ip and my_ip != "0.0.0.0":
                my_ips.add(my_ip)
        except Exception:
            pass
        try:
            for route in _conf.route.routes:
                try:
                    net, mask, g, iface, addr = route[:5]
                    if addr and addr != "0.0.0.0":
                        my_ips.add(addr)
                except Exception:
                    continue
        except Exception:
            pass
        try:
            for iface in _conf.ifaces.values():
                mac = getattr(iface, "mac", None)
                if mac:
                    my_macs.add(mac.lower())
        except Exception:
            pass
    except Exception:
        pass
    return gw, my_ips, my_macs, default_iface_name


def main():
    root = tk.Tk()
    root.title("MiniWireshark")
    root.geometry("620x460")
    root.resizable(False, False)
    root.configure(background="#f4f5f7")
    try:
        root.eval("tk::PlaceWindow . center")
    except Exception:
        pass

    loader = LoaderWindow(root)
    loader.pack(fill="both", expand=True)
    root.update()

    ok, err = run_bootstrap(loader)
    if not ok:
        loader.show_fatal(err)
        root.mainloop()
        return

    loader.post_status("Loading packet engine ...")
    loader.post_progress(100)
    loader.pump(); time.sleep(0.15); loader.pump()

    try:
        load_scapy()
    except Exception as e:
        loader.show_fatal(f"Could not load scapy: {e}\n\n"
                          f"{traceback.format_exc()}")
        root.mainloop()
        return

    gw, my_ips, my_macs, default_iface_name = detect_gateway_and_self()

    loader.destroy()
    root.geometry("1360x860")
    root.resizable(True, True)
    root.title("MiniWireshark")

    try:
        MiniWireshark(root, gw, my_ips, my_macs, default_iface_name)
    except Exception:
        messagebox.showerror("Startup error", traceback.format_exc())
        root.destroy()
        return

    root.mainloop()


if __name__ == "__main__":
    main()