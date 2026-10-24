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
import csv
import dataclasses
import importlib
import inspect
import ipaddress
import json
import math
import os
import platform
import queue
import random
import re
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
import uuid
from dataclasses import dataclass, field

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
from collections import defaultdict, deque, Counter
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

# Every literal color used anywhere in this file's light-mode UI, mapped to
# a deliberately-chosen (not just inverted) dark equivalent. Dark Mode is
# applied by walking the widget tree and swapping any bg/fg that matches a
# key here — new widgets automatically pick up theming as long as they're
# built from this same palette, no per-widget registration needed. The
# brand navy header (#2b3a55) and its light subtitle (#c8d2e0) are left
# out on purpose: that chrome already reads fine unchanged in both themes.
LIGHT_TO_DARK_HEX = {
    # backgrounds / surfaces
    "#ffffff": "#20232c", "#f4f5f7": "#161920", "#fbfbfb": "#1b1e26",
    "#f6f7fa": "#252933", "#e6e8ec": "#242832", "#e3e6eb": "#1a1d24",
    "#fff5e0": "#3a2c10", "#fff4e0": "#3b2d11", "#f6ecff": "#2a1f3a",
    "#e8f0fe": "#1c2c40", "#eef4fb": "#1a2735", "#fbe9e7": "#3a1712",
    "#eafaf0": "#132a1d", "#e6f4ea": "#173625",
    # borders
    "#cfd6e0": "#3a3f4a", "#e0e2e8": "#343945",
    # text / accents (every value below is unique so Light<->Dark is lossless)
    "#8a5a00": "#e0a83a", "#a05608": "#e6b04a", "#7a4a00": "#d99b30",
    "#0b6b3a": "#4ad080", "#1d6b2e": "#58d88a", "#6a2ca0": "#c299e8",
    "#333333": "#e2e5ea", "#222222": "#eceff3", "#3a3a3a": "#d8dbe2",
    "#a01a08": "#ff7a63", "#8a1a08": "#ff8a72",
    "#0b5394": "#6fb8f0", "#124e8c": "#79bff2", "#1a3a6b": "#bcd4f5",
    "#666666": "#9aa3b2", "#888888": "#8f98a8",
    # section-heading text: the brand navy (#2b3a55) is reserved for the
    # header bar's *background*; headings use this 1-step-off twin so they
    # can flip to a light blue in Dark mode without touching the bar
    "#2b3a56": "#9db4dc",
}
DARK_TO_LIGHT_HEX = {v: k for k, v in LIGHT_TO_DARK_HEX.items()}
_DEFAULT_FG_NAMES = {"black", "#000000", "systemwindowtext",
                     "systembuttontext", "systemmenutext",
                     "systemcaptiontext"}
_RETHEME_COLOR_OPTS = ("bg", "background", "fg", "foreground",
                       "activebackground", "activeforeground",
                       "selectbackground", "selectforeground",
                       "insertbackground", "highlightbackground")

THEME_LIGHT = {
    "window_bg": "#f4f5f7", "tab_bg": "#ffffff", "text_bg": "#fbfbfb",
    "text_fg": "#222222", "muted_fg": "#666666",
    "info_fg": "#333333", "warn_bg": "#fff5e0", "warn_fg": "#8a5a00",
    "danger_bg": "#fbe9e7", "danger_fg": "#8a1a08",
    "good_fg": "#0b6b3a", "card_bg": "#f6f7fa", "border": "#e0e2e8",
    "mode_active_bg": "#e6f4ea", "mode_active_fg": "#0b6b3a",
    "mode_quiet_bg": "#e8f0fe", "mode_quiet_fg": "#1a3a6b",
    "accent": "#2b7de9", "side_bg": "#e6e8ec", "side_sel": "#ffffff",
}
THEME_DARK = {
    "window_bg": "#161920", "tab_bg": "#20232c", "text_bg": "#1b1e26",
    "text_fg": "#e2e5ea", "muted_fg": "#9aa3b2",
    "info_fg": "#c7ccd6", "warn_bg": "#3a2c10", "warn_fg": "#e0a83a",
    "danger_bg": "#3a1712", "danger_fg": "#ff7a63",
    "good_fg": "#4ad080", "card_bg": "#252933", "border": "#343945",
    "mode_active_bg": "#173625", "mode_active_fg": "#7be0a0",
    "mode_quiet_bg": "#1c2c40", "mode_quiet_fg": "#8fc0ef",
    "accent": "#2f6fc0", "side_bg": "#1a1d24", "side_sel": "#2b303c",
}


# ---- High-contrast variants (Section 22 accessibility) ---------------------
# Generated from the same canonical palette so every widget that themes for
# Light/Dark themes for High Contrast too, and switching between any two
# palettes is lossless (verified by a test: every palette is one-to-one).
def _hex_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _rgb_hex(r, g, b):
    return "#%02x%02x%02x" % (max(0, min(255, int(r))),
                              max(0, min(255, int(g))),
                              max(0, min(255, int(b))))


def _hex_lum(h):
    r, g, b = (c / 255.0 for c in _hex_rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _hex_mix(h, target, t):
    a, b = _hex_rgb(h), _hex_rgb(target)
    return _rgb_hex(*(a[i] + (b[i] - a[i]) * t for i in range(3)))


def _build_hc_palettes():
    used = set(LIGHT_TO_DARK_HEX) | set(LIGHT_TO_DARK_HEX.values())
    light_hc, dark_hc = {}, {}

    def unique(h):
        r, g, b = _hex_rgb(h)
        while h in used:
            b = (b + 1) % 256
            h = _rgb_hex(r, g, b)
        used.add(h)
        return h

    borders = {"#cfd6e0": ("#4a5260", "#9aa3b2"),
               "#e0e2e8": ("#4a5260", "#8a93a3")}
    for canon, dk in LIGHT_TO_DARK_HEX.items():
        lum = _hex_lum(canon)
        if canon in borders:
            light_hc[canon] = unique(borders[canon][0])
            dark_hc[canon] = unique(borders[canon][1])
        elif lum > 0.75:                      # surfaces
            light_hc[canon] = canon           # identity: already max contrast
            dark_hc[canon] = unique(_hex_mix(dk, "#000000", 0.65))
        else:                                 # text and accent colours
            light_hc[canon] = unique(_hex_mix(canon, "#000000", 0.5))
            dark_hc[canon] = unique(_hex_mix(dk, "#ffffff", 0.55))
    return light_hc, dark_hc


HC_LIGHT_HEX, HC_DARK_HEX = _build_hc_palettes()
PALETTES = {"Light": {}, "Dark": LIGHT_TO_DARK_HEX,
            "Light HC": HC_LIGHT_HEX, "Dark HC": HC_DARK_HEX}

# any known palette colour -> its canonical (light) colour
_CANON = {}
for _pname, _tbl in PALETTES.items():
    for _canon, _val in _tbl.items():
        if _val != _canon:
            _CANON[_val] = _canon


def palette_name(theme, high_contrast):
    return f"{theme}{' HC' if high_contrast else ''}"


def _theme_variant(base, palette):
    """Derive a theme-token dict for `palette` from an existing one."""
    table = PALETTES[palette]
    out = {}
    for k, v in base.items():
        canon = _CANON.get(v, v)
        if canon in table:
            out[k] = table[canon]
        elif palette.startswith("Dark") and palette.endswith("HC"):
            out[k] = _hex_mix(v, "#000000", 0.65) if _hex_lum(v) < 0.2 \
                else _hex_mix(v, "#ffffff", 0.55)
        elif palette == "Light HC":
            out[k] = _hex_mix(v, "#000000", 0.5) if _hex_lum(v) < 0.6 else v
        else:
            out[k] = v
    return out


THEMES = {
    "Light": THEME_LIGHT, "Dark": THEME_DARK,
    "Light HC": _theme_variant(THEME_LIGHT, "Light HC"),
    "Dark HC": _theme_variant(THEME_DARK, "Dark HC"),
}
# accents used for selection/focus must stay readable in every palette
THEMES["Light HC"]["accent"] = "#0a246a"
THEMES["Dark HC"]["accent"] = "#ffd400"


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


def _human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


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
         "dhcp_yiaddr": "", "dhcp_hostname": "", "dhcp_client_mac": "",
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
            p, t2, text, learns, msgtype, yiaddr, dhost, chaddr = \
                _decode_dhcp(pkt)
            d["proto"], d["tag"], d["text"] = p, t2, text
            d["learns"].extend(learns)
            d["dhcp_msgtype"] = msgtype
            d["dhcp_yiaddr"] = yiaddr
            d["dhcp_hostname"] = dhost
            d["dhcp_client_mac"] = chaddr

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
    if yiaddr == "0.0.0.0":
        yiaddr = ""
    chaddr = ""
    try:
        raw = bytes(bootp.chaddr)[:6]
        if any(raw):
            chaddr = ":".join(f"{b:02x}" for b in raw)
    except Exception:
        pass
    if hostname and yiaddr:
        learns.append((yiaddr, hostname))
    parts = [msg]
    if hostname:
        parts.append(f"as “{hostname}”")
    if yiaddr:
        parts.append(f"got {yiaddr}")
    return "DHCP", "DHCP", " ".join(parts), learns, msgtype, yiaddr, hostname, chaddr


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
#  9b.  Data model — device confidence engine, lifecycle, websites vs.
#       remote hosts, alerts. "Never invent a device": something only
#       becomes a Device because of accumulated local Layer-2 evidence.
#       Websites (domains) and Remote Hosts (public IPs) are entirely
#       separate record types and can never become a Device.
# ============================================================================

EVIDENCE_WEIGHTS = {
    "mac_local":     40,   # a real (non-broadcast) MAC seen directly on the LAN
    "arp_reply":     25,   # answered "is-at" for its own IP
    "dhcp_lease":    25,   # got/renewed a DHCP lease
    "mdns":          15,   # advertised itself over mDNS/Bonjour
    "ssdp":          15,   # advertised itself over SSDP/UPnP
    "local_traffic": 10,   # ordinary bidirectional local traffic
    "oui_match":      5,   # MAC vendor prefix recognized
    "rdns":           2,   # reverse-DNS name only
}
CONFIDENCE_UNCONFIRMED, CONFIDENCE_LOW = "Unconfirmed", "Low"
CONFIDENCE_MEDIUM, CONFIDENCE_HIGH = "Medium", "High"

STATE_ACTIVE, STATE_IDLE, STATE_INACTIVE, STATE_EXPIRED = \
    "ACTIVE", "IDLE", "INACTIVE", "EXPIRED"

EVIDENCE_LABELS = {
    "mac_local": "MAC seen locally", "arp_reply": "ARP reply",
    "dhcp_lease": "DHCP lease", "mdns": "mDNS advertisement",
    "ssdp": "SSDP advertisement", "local_traffic": "Local traffic",
    "oui_match": "Vendor (OUI) match", "rdns": "Reverse DNS",
}

# Docker/typical container-bridge / common virtualization NAT ranges — seen
# on the machine MiniWireshark itself runs on, not a separate LAN device.
VIRTUAL_BRIDGE_NETS = [ipaddress.ip_network(n) for n in (
    "172.17.0.0/16", "172.18.0.0/16", "172.19.0.0/16",
    "10.0.75.0/24", "192.168.99.0/24",
)]

# A small built-in list of common multi-label public suffixes, used only to
# group "Websites you visited" by registrable domain (e.g. mail.google.com
# and www.google.com both roll up under "google.com"). This is a pragmatic
# heuristic, not a full Public Suffix List (that would mean bundling a large
# external data file, which conflicts with staying single-file/dependency
# -free) — it covers the common cases and silently falls back to "last two
# labels" for anything it doesn't recognize.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.jp", "ne.jp", "or.jp", "co.kr", "co.in", "co.nz", "co.za",
    "com.au", "net.au", "org.au", "com.br", "com.mx", "com.cn", "net.cn",
    "com.tw", "com.sg", "com.hk", "co.il", "co.th",
}


def registrable_domain(name):
    """Best-effort eTLD+1 grouping for the Websites summary view."""
    n = (name or "").strip(".").lower()
    labels = n.split(".")
    if len(labels) <= 2:
        return n
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def is_randomized_mac(mac):
    """The U/L (locally-administered) bit is the 2nd-least-significant bit
    of a MAC's first octet. Modern phones/laptops set it for a private,
    per-network, rotating Wi-Fi address — a privacy *feature*, not missing
    data, so it's surfaced as its own evidence-neutral fact."""
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02)
    except Exception:
        return False


def confidence_tier(score):
    if score >= 60:
        return CONFIDENCE_HIGH
    if score >= 30:
        return CONFIDENCE_MEDIUM
    if score >= 10:
        return CONFIDENCE_LOW
    return CONFIDENCE_UNCONFIRMED


@dataclass
class Evidence:
    source: str
    detail: str
    weight: int
    when: float = field(default_factory=time.time)


@dataclass
class DeviceRecord:
    """A LOCAL device. Keyed by MAC when one is known (the actual L2
    identity), else by a synthetic 'ip:<addr>' key. Only ever created
    from local evidence — never from a remote/public IP or a DNS answer."""
    key: str
    ip: str = ""
    ipv6: set = field(default_factory=set)
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    dhcp_hostname: str = ""
    mdns_name: str = ""
    type: str = "unknown"
    type_hint: str = ""
    services: set = field(default_factory=set)
    evidence: list = field(default_factory=list)
    score: int = 0
    confidence: str = CONFIDENCE_UNCONFIRMED
    state: str = STATE_ACTIVE
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_confirmed: float = field(default_factory=time.time)
    last_arp: float = 0.0
    last_traffic: float = 0.0
    packets: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    protocols: object = field(default_factory=Counter)
    websites: set = field(default_factory=set)
    alert_ids: list = field(default_factory=list)
    randomized_mac: bool = False
    identity_conflict: str = ""
    pinned_no_merge: bool = False
    lease_ip: str = ""
    lease_start: float = 0.0
    lease_expiry: float = 0.0
    link_local_only: bool = False
    is_virtual: bool = False
    expected: bool = False   # "mark as expected" silences future alerts
    _rate_hist: list = field(default_factory=list)  # (minute_bucket, count)
    reactivations: list = field(default_factory=list)  # times it came back
    reactivated_now: bool = False
    merge_note: str = ""     # why identities were merged, if they were
    merged_from: list = field(default_factory=list)

    def add_evidence(self, source, detail):
        w = EVIDENCE_WEIGHTS.get(source, 0)
        self.evidence.append(Evidence(source, detail, w))
        if len(self.evidence) > 60:
            self.evidence = self.evidence[-60:]
        seen, total = set(), 0
        for ev in reversed(self.evidence):
            if ev.source in seen:
                continue
            seen.add(ev.source)
            total += ev.weight
        self.score = min(total, 100)
        self.confidence = confidence_tier(self.score)

    def evidence_summary(self):
        sources = []
        seen = set()
        for ev in self.evidence:
            if ev.source not in seen:
                seen.add(ev.source)
                sources.append(EVIDENCE_LABELS.get(ev.source, ev.source))
        return sources

    def display_name(self):
        if self.hostname:
            return self.hostname
        if self.dhcp_hostname:
            return self.dhcp_hostname
        if self.mdns_name:
            return self.mdns_name
        if self.vendor:
            return f"{self.vendor} device"
        return self.ip or self.mac or self.key

    def traffic_baseline_flag(self, now, multiplier=4.0, min_avg=3):
        """'Unusual for this device' — simple same-session baseline: compare
        the current minute's packet count against the trailing average.
        Never claims malice, only deviation from this device's own history."""
        bucket = int(now // 60)
        hist = self._rate_hist
        if not hist or hist[-1][0] != bucket:
            hist.append([bucket, 0])
            if len(hist) > 30:
                del hist[:-30]
        hist[-1][1] += 1
        if len(hist) < 6:
            return False
        past = [c for b, c in hist[:-1]]
        avg = sum(past) / len(past)
        cur = hist[-1][1]
        return avg >= min_avg and cur > avg * multiplier


@dataclass
class WebsiteRecord:
    """A domain name, learned from DNS/TLS-SNI/HTTP-Host — never a device."""
    domain: str
    registrable: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sources: set = field(default_factory=set)   # "DNS" | "TLS SNI" | "HTTP Host"
    resolved_ips: set = field(default_factory=set)
    requests: int = 0
    devices: set = field(default_factory=set)   # device keys that contacted it
    third_party_of: set = field(default_factory=set)  # parent site(s), if any


@dataclass
class RemoteHostRecord:
    """A public IP address contacted directly (no known domain name), or
    the underlying IP behind a website — tracked separately from Devices."""
    ip: str
    domain: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    ports: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    devices: set = field(default_factory=set)
    bytes_total: int = 0
    packets: int = 0
    country: str = ""        # ISO code; opt-in only, "" until looked up
    country_name: str = ""


ALERT_TYPES = {
    "new_device":       ("New device", "INFO"),
    "arp_spoof":        ("Possible ARP spoofing", "DANGER"),
    "gateway_change":   ("Gateway identity changed", "DANGER"),
    "dhcp_anomaly":     ("DHCP anomaly", "WARNING"),
    "chatty_device":    ("Unusually chatty device", "WARNING"),
    "unknown_device":   ("Unknown / unconfirmed device", "WARNING"),
    "reconnect_cycle":  ("Rapid reconnect/disconnect", "WARNING"),
    "duplicate_ip":     ("Duplicate IP address", "WARNING"),
}


@dataclass
class Alert:
    id: str
    kind: str
    severity: str
    device_key: str
    reason: str
    observed: str
    interpretation: str
    possible_explanations: str
    when: float = field(default_factory=time.time)
    acknowledged: bool = False


# Plain-English "what can this device do" catalog for mDNS/SSDP service
# strings — purely descriptive, shown on the device card.
SERVICE_DESCRIPTIONS = {
    "_airplay._tcp": "Can receive AirPlay audio/video from Apple devices.",
    "_raop._tcp": "Can receive streamed audio (AirPlay-compatible speaker).",
    "_googlecast._tcp": "Can receive casted audio/video (Chromecast-compatible).",
    "_spotify-connect._tcp": "Can be used as a Spotify Connect speaker.",
    "_sonos": "This looks like a Sonos speaker.",
    "_ipp._tcp": "This is a network printer.",
    "_printer._tcp": "This is a network printer.",
    "_pdl-datastream._tcp": "This is a network printer.",
    "_homekit._tcp": "Supports Apple HomeKit smart-home control.",
    "_hap._tcp": "Supports Apple HomeKit smart-home control.",
    "_matter._tcp": "Supports the Matter smart-home standard.",
    "_ssh._tcp": "Can be controlled remotely over SSH \u2014 make sure that's expected.",
    "_smb._tcp": "Shares files over the network (Windows/SMB file sharing).",
    "_afpovertcp._tcp": "Shares files over the network (Apple file sharing).",
    "_workstation._tcp": "A computer sharing its presence on the network.",
    "_nvstream._tcp": "Supports NVIDIA GameStream.",
    "_xbox": "This looks like an Xbox console.",
    "_ps4": "This looks like a PlayStation console.",
    "_ps5": "This looks like a PlayStation console.",
}


def service_description(service_name):
    n = (service_name or "").lower()
    for key, desc in SERVICE_DESCRIPTIONS.items():
        if key in n:
            return desc
    return ""


ALERT_CHECKLIST = {
    "new_device": ["Open your router's connected-devices list and look for "
                   "this device.",
                   "If it isn't yours or a guest's, change your Wi-Fi "
                   "password and re-check."],
    "arp_spoof": ["Disconnect from this network on any device you're "
                  "unsure about.",
                  "Open your router's admin page from a device you trust "
                  "and check its connected devices.",
                  "Restart the router; if this returns immediately, look "
                  "for a device that shouldn't be there."],
    "gateway_change": ["Did you just restart, update or replace the "
                       "router? If yes, this is expected.",
                       "If not, check the router's admin page and its "
                       "connected devices before trusting this network."],
    "dhcp_anomaly": ["Check whether a second router or access point was "
                     "plugged in recently.",
                     "Unplug anything you don't recognize and see whether "
                     "the second DHCP server disappears."],
    "chatty_device": ["Is the device downloading an update, streaming or "
                      "on a video call?",
                      "If it should be idle, restart it or look at what "
                      "it is running."],
    "unknown_device": ["Give it time \u2014 confidence rises as more "
                       "evidence arrives.",
                       "Compare its MAC address with the labels on your "
                       "devices or your router's list."],
    "reconnect_cycle": ["Check the device's Wi-Fi signal and its distance "
                        "from the router.",
                        "Look for power-saving or roaming settings on the "
                        "device."],
    "duplicate_ip": ["Check for two devices set to the same fixed IP.",
                     "Renew the lease (reconnect the device) and see if "
                     "it stops."],
}


class DeviceRegistry:
    """Owns every DeviceRecord: creation, evidence, lifecycle transitions,
    and identity merging. This is the single place that decides whether
    something earns a spot in the Devices tab — nothing else should
    fabricate a device from a bare IP sighting."""

    def __init__(self, gateway_ip, my_ips, config):
        self.gateway_ip = gateway_ip
        self.my_ips = set(my_ips)
        self.config = config
        self.by_key = {}
        self.ip_to_key = {}
        self.dhcp_leases = {}
        self.ip_macs = defaultdict(set)
        self.gw_macs = set()
        self.history = []
        self.arp_claims = defaultdict(lambda: deque(maxlen=16))

    def arp_flip_count(self, ip, window=60):
        """How many times the claimed MAC for `ip` changed within the last
        `window` seconds. A single change is ordinary (router swapped);
        repeated back-and-forth is what ARP spoofing looks like."""
        now = time.time()
        seq = [m for t, m in self.arp_claims.get(ip, ()) if now - t <= window]
        return sum(1 for a, b in zip(seq, seq[1:]) if a != b)

    def _key_for(self, ip, mac):
        if mac and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return mac.lower()
        if ip:
            return f"ip:{ip}"
        return None

    def classify_address(self, ip):
        """Reason an address should NOT count as device-worthy evidence on
        its own, or None if it's an ordinary candidate address."""
        if not ip:
            return None
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if a.is_multicast or ip == "255.255.255.255":
            return "broadcast/multicast"
        if a.is_link_local:
            return "link-local"
        for net in VIRTUAL_BRIDGE_NETS:
            if a in net:
                return "virtual-bridge"
        return None

    def touch(self, ip, mac, source, detail, when=None):
        when = when or time.time()
        flag = self.classify_address(ip)
        if flag == "broadcast/multicast":
            return None
        key = self._key_for(ip, mac)
        if key is None:
            return None
        dev = self.by_key.get(key)
        if dev is None:
            prior_key = self.ip_to_key.get(ip) if ip else None
            if prior_key and prior_key in self.by_key and prior_key != key:
                dev = self.by_key.pop(prior_key)
                dev.key = key
            else:
                dev = DeviceRecord(key=key, first_seen=when)
        self.by_key[key] = dev
        if ip:
            dev.ip = ip
            self.ip_to_key[ip] = key
            dev.link_local_only = (flag == "link-local")
            dev.is_virtual = dev.is_virtual or (flag == "virtual-bridge")
        if mac and not dev.mac:
            dev.mac = mac
            dev.randomized_mac = is_randomized_mac(mac)
            v = mac_vendor(mac)
            if v and not dev.vendor:
                dev.vendor = v
                dev.add_evidence("oui_match", f"Vendor prefix matches {v}")
        dev.add_evidence(source, detail)
        dev.last_seen = when
        dev.last_confirmed = when
        if dev.state != STATE_ACTIVE:
            if dev.state in (STATE_IDLE, STATE_INACTIVE):
                dev.reactivations.append(when)
                del dev.reactivations[:-30]
                dev.reactivated_now = True
            dev.state = STATE_ACTIVE
        return dev

    def note_arp_reply(self, ip, mac):
        dev = self.touch(ip, mac, "arp_reply", f"Answered ARP for {ip}")
        if dev:
            dev.last_arp = time.time()
        is_conflict = False
        if ip and mac:
            self.arp_claims[ip].append((time.time(), mac))
        if ip:
            macs = self.ip_macs[ip]
            is_new = mac not in macs
            macs.add(mac)
            is_conflict = is_new and len(macs) > 1
            if ip == self.gateway_ip and mac:
                self.gw_macs.add(mac)
        return dev, is_conflict

    def note_dhcp_lease(self, ip, mac, hostname, lease_secs=None):
        dev = self.touch(ip, mac, "dhcp_lease",
                         f"DHCP lease for {ip}" +
                         (f' as \u201c{hostname}\u201d' if hostname else ""))
        reused = False
        if dev:
            if hostname:
                dev.dhcp_hostname = hostname
            now = time.time()
            prior = self.dhcp_leases.get(ip)
            reused = bool(prior and prior[0] and mac and prior[0] != mac)
            dev.lease_ip = ip
            dev.lease_start = now
            if lease_secs:
                dev.lease_expiry = now + lease_secs
            self.dhcp_leases[ip] = (mac, hostname, now, dev.lease_expiry)
        return dev, reused

    def note_service(self, ip, mac, source, service_name, friendly=""):
        dev = self.touch(ip, mac, source,
                         f"Advertised via {source.upper()}: {service_name}")
        if dev:
            if service_name:
                dev.services.add(service_name)
            if friendly and not dev.mdns_name:
                dev.mdns_name = friendly
        return dev

    def note_traffic(self, ip, mac, nbytes, proto):
        dev = self.touch(ip, mac, "local_traffic", "Local traffic observed")
        if dev:
            dev.last_traffic = time.time()
            dev.packets += 1
            dev.bytes_up += max(nbytes, 0)
            dev.protocols[proto] += 1
        return dev

    def set_hostname(self, ip, name):
        key = self.ip_to_key.get(ip)
        dev = self.by_key.get(key) if key else None
        if dev and name and not dev.hostname:
            dev.hostname = name

    def tick_lifecycle(self):
        now = time.time()
        idle_after = self.config.get("devices.idle_minutes", 2) * 60
        inactive_after = self.config.get("devices.inactive_minutes", 10) * 60
        expire_after = self.config.get("devices.expire_minutes", 1440) * 60
        newly_inactive, newly_expired = [], []
        for key, dev in list(self.by_key.items()):
            age = now - dev.last_confirmed
            if age >= expire_after and dev.state != STATE_EXPIRED:
                dev.state = STATE_EXPIRED
                newly_expired.append(dev)
                try:
                    self.history.append(dataclasses.asdict(dev))
                except Exception:
                    pass
                if len(self.history) > 300:
                    del self.history[:-300]
            elif age >= inactive_after and dev.state not in (STATE_INACTIVE,
                                                              STATE_EXPIRED):
                dev.state = STATE_INACTIVE
                newly_inactive.append(dev)
            elif age >= idle_after and dev.state == STATE_ACTIVE:
                dev.state = STATE_IDLE
        return newly_inactive, newly_expired

    def visible_devices(self):
        show_inactive = self.config.get("devices.show_inactive", False)
        show_expired = self.config.get("devices.show_expired", False)
        out = []
        for dev in self.by_key.values():
            if dev.state == STATE_EXPIRED and not show_expired:
                continue
            if dev.state == STATE_INACTIVE and not show_inactive:
                continue
            out.append(dev)
        return out


class AlertEngine:
    def __init__(self, config):
        self.config = config
        self.alerts = {}
        self.order = []
        self._debounce = {}

    def enabled(self, kind):
        return bool(self.config.get(f"alerts.{kind}", True))

    def _add(self, kind, severity, device_key, reason, observed, interp, poss):
        if not self.enabled(kind):
            return None
        a = Alert(id=uuid.uuid4().hex[:8], kind=kind, severity=severity,
                  device_key=device_key, reason=reason, observed=observed,
                  interpretation=interp, possible_explanations=poss)
        self.alerts[a.id] = a
        self.order.insert(0, a.id)
        del self.order[500:]
        return a

    def _debounced(self, key, seconds):
        last = self._debounce.get(key, 0)
        if time.time() - last < seconds:
            return True
        self._debounce[key] = time.time()
        return False

    def new_device(self, dev):
        if dev.expected:
            return None
        return self._add(
            "new_device", "INFO", dev.key,
            f"{dev.display_name()} joined your network",
            f"A device with {dev.confidence.lower()}-confidence identity "
            f"evidence ({', '.join(dev.evidence_summary()) or 'minimal'}) "
            f"appeared.",
            "This is a new local device on your network.",
            "Normal if you just added a device (phone, guest, smart-home "
            "gadget). Worth checking if you don't recognize it.")

    def gateway_change(self, gw_ip, n_macs):
        if self._debounced(f"gw:{gw_ip}", 120):
            return None
        return self._add(
            "gateway_change", "DANGER", f"ip:{gw_ip}",
            "Your router's MAC address changed",
            f"Your gateway ({gw_ip}) has answered ARP from {n_macs} "
            f"different MAC addresses in this session.",
            "The device claiming to be your router is not consistent.",
            "Often normal right after a router reboot or firmware update. "
            "It is also the classic sign of ARP spoofing \u2014 a device "
            "pretending to be your router. If you didn't just restart "
            "your router, investigate.")

    def duplicate_ip(self, ip, n_macs):
        if self._debounced(f"dupip:{ip}", 120):
            return None
        return self._add(
            "duplicate_ip", "WARNING", f"ip:{ip}",
            f"{ip} has answered from more than one device",
            f"{n_macs} different MAC addresses have claimed {ip}.",
            "Two devices currently disagree about who owns this address.",
            "Often harmless \u2014 Wi-Fi privacy MAC rotation or a device "
            "reconnecting and briefly overlapping the old lease. Worth a "
            "look if it keeps happening.")

    def dhcp_anomaly(self, servers):
        if self._debounced("dhcp_anomaly", 300):
            return None
        return self._add(
            "dhcp_anomaly", "WARNING", "",
            "More than one device is handing out IP addresses",
            f"{len(servers)} different DHCP servers seen: "
            f"{', '.join(sorted(servers))}.",
            "Normally only your router does this.",
            "Could be a second router plugged in by mistake, or \u2014 "
            "less commonly \u2014 a rogue DHCP server. If you don't "
            "recognize one of these addresses, unplug that device and "
            "check your network.")

    def arp_spoof(self, ip, n_macs, flips, is_gateway):
        if self._debounced(f"arpspoof:{ip}", 120):
            return None
        who = "Your router's address" if is_gateway else f"The address {ip}"
        return self._add(
            "arp_spoof", "DANGER", f"ip:{ip}",
            f"{who} keeps switching between devices",
            f"{ip} was claimed by {n_macs} different MAC addresses and "
            f"flipped back and forth {flips} times within a minute.",
            "Two devices are repeatedly fighting over the same network "
            "address.",
            "A device normally answers for its address consistently. Rapid "
            "flip-flopping is the signature of ARP spoofing \u2014 one "
            "device impersonating another so traffic passes through it. It "
            "can also happen if two devices were accidentally given the "
            "same fixed IP. If this is your router's address, treat it "
            "seriously: disconnect and check the router's device list.")

    def chatty_device(self, dev):
        if self._debounced(f"chatty:{dev.key}", 600):
            return None
        return self._add(
            "chatty_device", "WARNING", dev.key,
            f"{dev.display_name()} is unusually active right now",
            "This device's traffic this minute is well above its own "
            "recent average.",
            "Its behavior changed compared to its own baseline this "
            "session.",
            "Often normal \u2014 a big download, a video call, a software "
            "update. Worth a glance if you don't expect that device to be "
            "busy right now.")

    def unknown_device(self, dev):
        if self._debounced(f"unknown:{dev.key}", 600):
            return None
        return self._add(
            "unknown_device", "WARNING", dev.key,
            f"{dev.display_name()} has very little identifying information",
            f"Only {', '.join(dev.evidence_summary()) or 'minimal'} "
            f"evidence is available for this device.",
            "MiniWireshark can't confidently say what this device is.",
            "Common for devices that stay quiet or use a randomized MAC. "
            "Confidence usually improves the longer it's on the network.")

    def reconnect_cycle(self, dev, n, window_s):
        if self._debounced(f"reconnect:{dev.key}", 600):
            return None
        return self._add(
            "reconnect_cycle", "WARNING", dev.key,
            f"{dev.display_name()} has joined/left {n} times recently",
            f"{n} reconnects in the last {int(window_s / 60)} minutes.",
            "This device is repeatedly reconnecting.",
            "Usually Wi-Fi interference, a weak signal, or a device with "
            "power-saving/roaming quirks \u2014 rarely an attack.")


CONFIG_SCHEMA_VERSION = 1


DEFAULT_SHORTCUTS = {
    "start": "<Control-r>", "stop": "<Control-period>",
    "clear": "<Control-l>", "export": "<Control-e>", "find": "<Control-f>",
}


def _default_config():
    return {
        "config_version": CONFIG_SCHEMA_VERSION,
        "general": {"auto_start_capture": True, "confirm_before_clear": False,
                   "beginner_explanations": True,
                   "explanation_verbosity": "Normal", "language": "English"},
        "appearance": {"theme": "Light", "beginner_mode": True,
                      "high_contrast": False, "text_size": "Normal"},
        "capture": {"max_stored_events": 5000},
        "devices": {"idle_minutes": 2, "inactive_minutes": 10,
                   "expire_minutes": 1440, "auto_merge": True,
                   "show_inactive": False, "show_expired": False},
        "dns": {"detect_encrypted_dns": True},
        "alerts": {"new_device": True, "arp_spoof": True,
                  "gateway_change": True, "dhcp_anomaly": True,
                  "chatty_device": True, "unknown_device": True,
                  "reconnect_cycle": True, "duplicate_ip": True,
                  "chatty_multiplier": 4, "chatty_min_rate": 3,
                  "unknown_min_packets": 5, "reconnect_count": 5,
                  "reconnect_window_minutes": 30, "arp_flip_threshold": 4},
        "notifications": {"feed_alerts": True, "danger_only": False},
        "performance": {"cpu_friendly_mode": False},
        "export": {"default_dir": ""},
        "mode": {"active_scanning": True},
        "shortcuts": dict(DEFAULT_SHORTCUTS),
        "updates": {"check_automatically": False, "repo": ""},
        "privacy": {"geoip_enabled": False},
    }


class AppConfig:
    """JSON-backed settings, next to the script. Degrades to defaults on
    any read/parse problem rather than crashing; never stores credentials."""

    def __init__(self, path=None):
        try:
            base = os.path.dirname(os.path.abspath(__file__))
        except Exception:
            base = os.getcwd()
        self.path = (path or os.environ.get("MINIWIRESHARK_CONFIG") or
                     os.path.join(base, "miniwireshark_config.json"))
        self.warning = ""
        self.data = self._load()

    def _load(self):
        defaults = _default_config()
        try:
            if not os.path.exists(self.path):
                return defaults
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("config is not an object")
            merged = _default_config()
            for section, vals in data.items():
                if section in merged and isinstance(vals, dict):
                    merged[section].update(vals)
            merged["config_version"] = CONFIG_SCHEMA_VERSION
            return merged
        except Exception:
            self.warning = ("Your settings file looked damaged, so I reset "
                            "it to defaults.")
            return defaults

    def get(self, dotted, default=None):
        section, _, key = dotted.partition(".")
        return self.data.get(section, {}).get(key, default)

    def set(self, dotted, value):
        section, _, key = dotted.partition(".")
        self.data.setdefault(section, {})[key] = value

    def save(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)
            return True
        except Exception:
            return False

    def reset(self, section=None):
        fresh = _default_config()
        if section:
            self.data[section] = fresh.get(section, {})
        else:
            self.data = fresh
        self.save()


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

SCRIPT_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# i18n scaffolding (Section 22 "Additional settings"). Only English strings
# exist today, but every string routed through tr() can gain translations
# later by adding a new top-level locale dict here — no call sites change.
# Given the size of this file, only the highest-traffic UI strings (window
# chrome, tab names, primary buttons, the mode banner, the severity legend)
# are actually routed through tr() so far; it's a real, working foundation
# rather than a claim that the whole app is translated.
# ---------------------------------------------------------------------------
STRINGS = {
    "en": {
        "app_title": "\U0001F310 MiniWireshark",
        "app_subtitle": "   Your network, explained in plain English",
        "btn_settings": "\u2699\ufe0e Settings",
        "btn_help": "? Help / About",
        "btn_start": "\u25b6  Start watching",
        "btn_stop": "\u25a0  Stop",
        "btn_clear": "Clear",
        "tab_dashboard": "\U0001f4ca Dashboard",
        "tab_feed": "\U0001f4d6 Happening",
        "tab_timeline": "\U0001f553 Timeline",
        "tab_devices": "\U0001f3e0 Devices",
        "tab_websites": "\U0001f30d Websites",
        "tab_remote": "\U0001f5a5 Remote",
        "tab_alerts": "\U0001f514 Alerts",
        "tab_map": "\U0001f5fa Map",
        "tab_security": "\U0001f512 Security",
        "tab_raw": "\u2699\ufe0f Packets",
        "tab_about": "\u2753 Help",
        "legend_info": "INFO \u2014 normal activity",
        "legend_warning": "WARNING \u2014 worth a look",
        "legend_danger": "DANGER \u2014 strong evidence of a real problem",
        "mode_active": "\U0001F7E2 ACTIVE SCANNING \u2014 MiniWireshark is "
                       "also sending harmless discovery probes "
                       "(ARP/mDNS/SSDP) on your own local network to find "
                       "quiet devices.",
        "mode_quiet": "\U0001F535 QUIET MODE \u2014 PASSIVE ONLY \u2014 "
                     "MiniWireshark is only listening to traffic that "
                     "already exists; it is not sending anything itself.",
    },
}
CURRENT_LOCALE = "en"
LOCALE_NAMES = {"en": "English"}   # display name -> add more as they're built


def tr(key, **kwargs):
    """Translate a UI string. Falls back to English, then to the raw key,
    so a missing translation never breaks the UI."""
    text = STRINGS.get(CURRENT_LOCALE, {}).get(key) or \
        STRINGS["en"].get(key, key)
    return text.format(**kwargs) if kwargs else text


def set_locale(name):
    global CURRENT_LOCALE
    for code, display in LOCALE_NAMES.items():
        if display == name:
            CURRENT_LOCALE = code
            return
    CURRENT_LOCALE = "en"


GLOSSARY = [
    ("What MiniWireshark does",
    "It watches network traffic on the card you choose and explains it in "
    "plain English \u2014 which devices are on your Wi-Fi, which websites "
    "were visited, and whether anything looks unusual. It only shows you "
    "your own local network, not anyone else's."),
    ("MAC address",
    "A hardware address burned into (or randomized by) a network adapter. "
    "It's the strongest evidence MiniWireshark has that something is a "
    "real local device, since it can't come from the public Internet."),
    ("IP address",
    "A network address a device is currently using. Unlike a MAC, an IP "
    "alone is never treated as proof of a device \u2014 addresses get "
    "reused, and remote/public IPs belong to websites, not your devices."),
    ("ARP",
    "\u201cAddress Resolution Protocol\u201d \u2014 how devices on the "
    "same local network find each other's MAC address. An ARP reply is "
    "strong evidence a device is really there."),
    ("DNS",
    "The system that turns website names (like example.com) into IP "
    "addresses. Watching DNS is how MiniWireshark learns which websites "
    "were visited."),
    ("DHCP",
    "How your router automatically hands out IP addresses to devices "
    "joining the network. A DHCP lease is strong evidence of a real "
    "device."),
    ("mDNS / SSDP",
    "Two ways devices announce themselves on a local network (Bonjour "
    "and UPnP) \u2014 often naming themselves ('Living Room TV') and "
    "listing what they can do."),
    ("Website vs. Remote Host",
    "A Website is a domain name you looked up or connected to (like "
    "example.com). A Remote Host is a raw public IP address contacted "
    "directly. Neither is ever shown as a device on your network."),
    ("Quiet Mode vs. Active Scanning",
    "Active Scanning means MiniWireshark also sends a few harmless "
    "discovery probes (ARP/mDNS/SSDP) on your own network to find quiet "
    "devices. Quiet Mode turns that off and only listens. Neither mode "
    "hides MiniWireshark's activity from your network \u2014 that's not "
    "what this is for."),
    ("Severity colors",
    "INFO (neutral) is normal activity. WARNING (amber) is unusual and "
    "worth a look. DANGER (red) means strong, specific evidence of a "
    "real problem \u2014 never assigned just because something is "
    "unusual."),
    ("Confidence",
    "How much local evidence supports a device's identity: High, "
    "Medium, Low, or Unconfirmed. It only goes up with real signals "
    "(ARP, DHCP, mDNS/SSDP, vendor match) \u2014 never from guessing."),
    ("Why some information may be missing",
    "Permissions, a missing driver, or an interface that goes away can "
    "all limit what MiniWireshark can see. It's built to keep working "
    "with whatever sources are actually available, and to say so "
    "plainly rather than guessing."),
    ("Why encrypted DNS limits visibility",
    "DNS-over-HTTPS/TLS hides the website name from anyone watching the "
    "network \u2014 including MiniWireshark. That's the encryption "
    "working as intended, a privacy feature, not a bug."),
]


# ============================================================================
#  9c.  Country lookup (opt-in) — a small self-contained service
#
#  Why this is a service and not a one-liner: free geolocation providers
#  rate-limit hard (~45 requests/minute), some networks block plain HTTP or
#  individual hosts, and one failed attempt must never mean "unknown
#  forever". So: one background worker, a request queue, a global pacing
#  interval, provider fallback (three HTTPS providers, then one HTTP one as a
#  last resort), a retry schedule, a circuit-breaker when the whole network
#  is unreachable, and honest status/error text the UI can show. Nothing is
#  ever sent unless the user has switched the feature on.
# ============================================================================
def _geo_parse_ipwho(d):
    if not d.get("success", False):
        raise ValueError(d.get("message") or "lookup failed")
    return d.get("country_code", ""), d.get("country", "")


def _geo_parse_geojs(d):
    code = d.get("country", "")
    if not code or len(code) != 2:
        raise ValueError("no country in reply")
    return code, d.get("name", "")


def _geo_parse_ipapico(d):
    if d.get("error"):
        raise ValueError(d.get("reason") or d.get("message") or "lookup failed")
    return d.get("country_code", ""), d.get("country_name", "")


def _geo_parse_ipapi(d):
    if d.get("status") != "success":
        raise ValueError(d.get("message") or "lookup failed")
    return d.get("countryCode", ""), d.get("country", "")


GEOIP_PROVIDERS = [
    ("ipwho.is", "https://ipwho.is/{ip}?fields=success,message,country,"
                 "country_code", _geo_parse_ipwho),
    ("geojs.io", "https://get.geojs.io/v1/ip/country/{ip}.json",
     _geo_parse_geojs),
    ("ipapi.co", "https://ipapi.co/{ip}/json/", _geo_parse_ipapico),
    ("ip-api.com", "http://ip-api.com/json/{ip}?fields=status,message,"
                   "country,countryCode", _geo_parse_ipapi),
]


class GeoIPService:
    """Thread-safe, rate-limited country lookups with fallback and retry.

    on_result(ip, code, name, provider) is called from the worker thread
    for each success — the GUI passes something that only enqueues work for
    the main thread, never touches Tk directly."""

    def __init__(self, on_result, providers=None, timeout=5.0,
                 min_interval=1.5, retry_after=300, max_attempts=3):
        self.on_result = on_result
        self.providers = list(providers or GEOIP_PROVIDERS)
        self.timeout = timeout
        self.min_interval = min_interval
        self.retry_after = retry_after
        self.max_attempts = max_attempts
        self.enabled = False
        self.results = {}     # ip -> (code, name, provider)
        self.failures = {}    # ip -> [attempts, last_time, last_error]
        self.pending = set()
        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.last_error = ""
        self.last_provider = ""
        self.request_times = []          # for pacing tests / diagnostics
        self._last_call = 0.0
        self._first_provider = 0
        self._consecutive_total_failures = 0
        self._paused_until = 0.0
        self._thread = None
        self._stop = False

    # ---- public API ---------------------------------------------------
    def set_enabled(self, on):
        self.enabled = bool(on)
        if self.enabled:
            self._ensure_thread()

    def request(self, ip):
        """Queue `ip` if it's worth asking about. Returns True if queued."""
        if not self.enabled or not is_public_ip(ip):
            return False
        with self.lock:
            if ip in self.results or ip in self.pending:
                return False
            fail = self.failures.get(ip)
            if fail and (fail[0] >= self.max_attempts or
                         time.time() - fail[1] < self.retry_after):
                return False
            self.pending.add(ip)
        self._ensure_thread()
        self.q.put(ip)
        return True

    def retry_failed(self):
        """Forget failure history and try every failed IP again now."""
        with self.lock:
            ips = list(self.failures)
            self.failures.clear()
            self._paused_until = 0.0
            self._consecutive_total_failures = 0
        n = 0
        for ip in ips:
            n += 1 if self.request(ip) else 0
        return n

    def status(self):
        with self.lock:
            return {"enabled": self.enabled, "resolved": len(self.results),
                    "pending": len(self.pending),
                    "failed": len(self.failures),
                    "last_error": self.last_error,
                    "provider": self.last_provider,
                    "paused": max(0, int(self._paused_until - time.time()))}

    def lookup_now(self, ip):
        """Blocking single lookup for the 'Test' button. Returns
        (code, name, provider, errors) — code is '' when everything failed;
        errors is a list of 'provider: reason' strings."""
        code, name, provider, errors = self._try_providers(ip)
        return code, name, provider, errors

    def stop(self):
        self._stop = True

    # ---- internals ------------------------------------------------------
    def _ensure_thread(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop = False
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def _fetch(self, url):
        req = urllib.request.Request(
            url, headers={"User-Agent": "MiniWireshark",
                          "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))

    def _pace(self):
        wait = self.min_interval - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.time()
        self.request_times.append(self._last_call)
        del self.request_times[:-200]

    def _try_providers(self, ip):
        errors = []
        n = len(self.providers)
        for step in range(n):
            idx = (self._first_provider + step) % n
            name, template, parser = self.providers[idx]
            self._pace()
            try:
                data = self._fetch(template.format(ip=ip))
                code, cname = parser(data)
                code = (code or "").upper()
                if len(code) != 2:
                    raise ValueError("no country code in reply")
                self._first_provider = idx    # start here next time
                return code, cname or "", name, errors
            except urllib.error.HTTPError as e:
                errors.append(f"{name}: HTTP {e.code}"
                              f"{' (rate limited)' if e.code == 429 else ''}")
            except urllib.error.URLError as e:
                errors.append(f"{name}: {getattr(e, 'reason', e)}")
            except (ValueError, KeyError) as e:
                errors.append(f"{name}: {e}")
            except Exception as e:
                errors.append(f"{name}: {type(e).__name__}: {e}")
        return "", "", "", errors

    def _run(self):
        while not self._stop:
            try:
                ip = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            if not self.enabled:
                with self.lock:
                    self.pending.discard(ip)
                continue
            wait = self._paused_until - time.time()
            if wait > 0:                       # circuit breaker is open
                time.sleep(min(wait, 1.0))
                self.q.put(ip)
                continue
            code, name, provider, errors = self._try_providers(ip)
            with self.lock:
                self.pending.discard(ip)
                if code:
                    self.results[ip] = (code, name, provider)
                    self.failures.pop(ip, None)
                    self.last_provider = provider
                    self.last_error = ""
                    self._consecutive_total_failures = 0
                else:
                    f = self.failures.setdefault(ip, [0, 0.0, ""])
                    f[0] += 1
                    f[1] = time.time()
                    f[2] = "; ".join(errors)
                    self.last_error = f[2]
                    self._consecutive_total_failures += 1
                    if self._consecutive_total_failures >= 4:
                        # every provider failed for several IPs in a row:
                        # the network (or a firewall) is the problem, so stop
                        # hammering it and try again in a minute
                        self._paused_until = time.time() + 60
                        self._consecutive_total_failures = 0
            if code:
                try:
                    self.on_result(ip, code, name, provider)
                except Exception:
                    pass


class Tooltip:
    """Minimal beginner-friendly tooltip: hover a widget, see a short
    explanation after a brief delay. No extra dependency, theme-agnostic
    (uses its own small fixed-style popup rather than inheriting bg/fg)."""
    _active = None

    def __init__(self, widget, text, delay_ms=500):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id = None
        self._tip = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None):
        self._cancel()
        try:
            self._after_id = self.widget.after(self.delay_ms, self._show)
        except tk.TclError:
            pass

    def _cancel(self):
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self):
        if self._tip is not None:
            return
        try:
            x = self.widget.winfo_rootx() + 12
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        except tk.TclError:
            return
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        try:
            tip.wm_attributes("-topmost", True)
        except tk.TclError:
            pass
        tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(tip, text=self.text, justify="left",
                       background="#fffbe6", foreground="#333333",
                       relief="solid", borderwidth=1,
                       font=("TkDefaultFont", 9), wraplength=320,
                       padx=8, pady=5)
        lbl.pack()
        self._tip = tip

    def _hide(self, _event=None):
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None


# ============================================================================
#  10a.  Settings — one declarative schema drives the whole window
#
#  Every option the app has appears here exactly once, grouped by what a
#  person is trying to do (not by which code uses it). Because the window is
#  generated from this table, a test can prove that no option is orphaned
#  (defined but not shown) or phantom (shown but not real).
# ============================================================================
_SEV_CHIP = {"INFO": "INFO", "WARNING": "WARNING", "DANGER": "DANGER"}


def _alert_control(kind, help_text):
    title, sev = ALERT_TYPES[kind]
    return {"key": f"alerts.{kind}", "type": "bool", "label": title,
            "badge": sev, "help": help_text}


SETTINGS_PAGES = [
    {"id": "general", "icon": "\u2699", "title": "General",
     "blurb": "How MiniWireshark starts up and how much it explains.",
     "sections": [
         {"title": "Startup", "controls": [
             {"key": "general.auto_start_capture", "type": "bool",
              "label": "Start watching automatically when MiniWireshark opens",
              "help": "Picks the best network card for you and begins right "
                      "away. Turn off to choose a card and press Start "
                      "yourself."},
             {"key": "general.confirm_before_clear", "type": "bool",
              "label": "Ask before clearing data",
              "help": "Shows a confirmation before Clear wipes the devices, "
                      "websites and alerts collected so far."},
         ]},
         {"title": "Explanations", "controls": [
             {"key": "general.beginner_explanations", "type": "bool",
              "label": "Include plain-English guidance",
              "help": "Adds \u201cwhat should I check?\u201d advice to device "
                      "cards, alerts and the Security check. Turn off for "
                      "just the facts."},
             {"key": "general.explanation_verbosity", "type": "choice",
              "choices": ["Short", "Normal", "Detailed"],
              "label": "Detail level",
              "help": "Short: the essentials. Normal: what was seen and "
                      "what it means. Detailed: also shows how confidence "
                      "was scored, protocols, websites and step-by-step "
                      "checks."},
         ]},
         {"title": "Language", "controls": [
             {"key": "general.language", "type": "choice",
              "choices": "@locales", "label": "Language",
              "help": "Only English exists today. The app is built so more "
                      "languages can be added without changing any code."},
         ]},
     ]},
    {"id": "appearance", "icon": "\U0001F3A8", "title": "Appearance",
     "blurb": "Make it comfortable to look at.",
     "sections": [
         {"title": "Look", "controls": [
             {"key": "appearance.theme", "type": "choice",
              "choices": ["Light", "Dark"], "label": "Theme",
              "help": "Applies to every window, table, chart and dialog."},
             {"key": "appearance.high_contrast", "type": "bool",
              "label": "High contrast",
              "help": "Stronger text and borders for easier reading. Works "
                      "with both the Light and Dark themes."},
             {"key": "appearance.text_size", "type": "choice",
              "choices": ["Small", "Normal", "Large", "Extra large"],
              "label": "Text size",
              "help": "Scales text and table rows throughout the app."},
         ]},
         {"title": "Layout", "controls": [
             {"key": "appearance.beginner_mode", "type": "bool",
              "label": "Beginner view",
              "help": "Hides the technical \u201cAll packets\u201d tab. "
                      "Nothing is removed \u2014 switch this off any time to "
                      "see everything."},
         ]},
     ]},
    {"id": "capture", "icon": "\U0001F4E1", "title": "Capture & Analysis",
     "blurb": "What MiniWireshark listens to, and how hard it works.",
     "sections": [
         {"title": "Scanning", "controls": [
             {"key": "mode.active_scanning", "type": "bool",
              "label": "Actively look for devices",
              "help": "Sends a few harmless ARP / mDNS / SSDP probes on your "
                      "own network about every 40 seconds to find quiet "
                      "devices. Off is Quiet Mode: listen only, send "
                      "nothing. The banner at the top always shows which "
                      "mode is on."},
         ]},
         {"title": "Analysis", "controls": [
             {"key": "dns.detect_encrypted_dns", "type": "bool",
              "label": "Detect encrypted DNS (DoH / DoT)",
              "help": "Notices when a device hides its website lookups "
                      "behind encryption, and explains why some names can't "
                      "be seen. Detection only \u2014 never decryption."},
         ]},
         {"title": "Memory & speed", "controls": [
             {"key": "capture.max_stored_events", "type": "int",
              "min": 500, "max": 100000, "step": 500, "unit": "packets",
              "label": "Packets kept in memory",
              "help": "Older packets are dropped beyond this. Higher means "
                      "a longer history for the All-packets tab and .pcap "
                      "export, at the cost of memory."},
             {"key": "performance.cpu_friendly_mode", "type": "bool",
              "label": "CPU-friendly mode",
              "help": "Refreshes the screen about 2.5\u00d7 less often. Helps "
                      "on slow computers or very busy networks."},
         ]},
     ]},
    {"id": "devices", "icon": "\U0001F5A5", "title": "Devices & Identity",
     "blurb": "When a device counts as gone, and how identities are "
              "combined.",
     "sections": [
         {"title": "Device lifetime", "controls": [
             {"key": "devices.idle_minutes", "type": "int", "min": 0,
              "max": 120, "step": 1, "unit": "minutes",
              "label": "Idle after",
              "help": "No traffic for this long and a device shows as "
                      "\u201cIdle\u201d. It's still counted as online."},
             {"key": "devices.inactive_minutes", "type": "int", "min": 1,
              "max": 1440, "step": 1, "unit": "minutes",
              "label": "Inactive after",
              "help": "Silent this long and it's treated as offline and "
                      "hidden unless you show inactive devices."},
             {"key": "devices.expire_minutes", "type": "int", "min": 5,
              "max": 100000, "step": 5, "unit": "minutes",
              "label": "Expire after",
              "help": "Gone this long and it moves into history. An old "
                      "ARP entry is never treated as proof a device is "
                      "still there."},
         ]},
         {"title": "What the Devices tab shows", "controls": [
             {"key": "devices.show_inactive", "type": "bool",
              "label": "Show inactive devices",
              "help": "Include devices that have gone quiet."},
             {"key": "devices.show_expired", "type": "bool",
              "label": "Show expired devices",
              "help": "Include devices not seen for a long time."},
         ]},
         {"title": "Identity", "controls": [
             {"key": "devices.auto_merge", "type": "bool",
              "label": "Combine identities automatically",
              "help": "Phones and laptops rotate their Wi-Fi address for "
                      "privacy. When exactly two entries announce the same "
                      "distinctive name, at least one uses a private "
                      "address, and they were never active at the same "
                      "time, they're combined and the reason is shown on "
                      "the device card. Never based on traffic similarity."},
         ]},
     ]},
    {"id": "alerts", "icon": "\U0001F514", "title": "Alerts",
     "blurb": "Choose what gets flagged and how sensitive it is.",
     "sections": [
         {"title": "What to alert on", "controls": [
             _alert_control("new_device",
                            "A device you haven't seen before joins."),
             _alert_control("unknown_device",
                            "A device stays hard to identify after a while."),
             _alert_control("chatty_device",
                            "A device gets much busier than its own "
                            "normal."),
             _alert_control("reconnect_cycle",
                            "A device keeps dropping off and coming back."),
             _alert_control("duplicate_ip",
                            "Two devices claim the same address."),
             _alert_control("dhcp_anomaly",
                            "More than one device hands out addresses."),
             _alert_control("gateway_change",
                            "Your router's hardware address changes."),
             _alert_control("arp_spoof",
                            "An address keeps flipping between two devices "
                            "\u2014 the signature of ARP spoofing."),
         ]},
         {"title": "Sensitivity", "controls": [
             {"key": "alerts.chatty_multiplier", "type": "int", "min": 2,
              "max": 50, "step": 1, "unit": "\u00d7 its usual rate",
              "label": "Busy-device threshold",
              "help": "A device is \u201cunusually chatty\u201d when its "
                      "traffic this minute exceeds this multiple of its own "
                      "recent average."},
             {"key": "alerts.chatty_min_rate", "type": "int", "min": 1,
              "max": 1000, "step": 1, "unit": "packets/min",
              "label": "Ignore quiet devices below",
              "help": "Devices averaging less than this are never flagged "
                      "as chatty, so sleepy gadgets don't cause noise."},
             {"key": "alerts.unknown_min_packets", "type": "int", "min": 1,
              "max": 500, "step": 1, "unit": "packets",
              "label": "Wait before flagging unknown devices",
              "help": "How many packets a device must send while still "
                      "poorly identified before it's flagged."},
             {"key": "alerts.reconnect_count", "type": "int", "min": 2,
              "max": 50, "step": 1, "unit": "times",
              "label": "Reconnects that count as cycling",
              "help": "Number of come-backs within the window below."},
             {"key": "alerts.reconnect_window_minutes", "type": "int",
              "min": 5, "max": 240, "step": 5, "unit": "minutes",
              "label": "Reconnect window",
              "help": "Time span used for counting reconnects."},
             {"key": "alerts.arp_flip_threshold", "type": "int", "min": 2,
              "max": 20, "step": 1, "unit": "flips in a minute",
              "label": "ARP flip-flop threshold",
              "help": "How many times an address must swap between devices "
                      "within a minute before it's called possible ARP "
                      "spoofing. One change is normal."},
         ]},
         {"title": "Where alerts appear", "controls": [
             {"key": "notifications.feed_alerts", "type": "bool",
              "label": "Also show alerts in the live feed",
              "help": "Alerts always appear in the Alerts and Timeline tabs."},
             {"key": "notifications.danger_only", "type": "bool",
              "label": "In the feed, only show DANGER alerts",
              "requires": "notifications.feed_alerts",
              "help": "Keeps the feed calm; warnings stay in the Alerts "
                      "tab."},
         ]},
     ]},
    {"id": "privacy", "icon": "\U0001F512", "title": "Privacy & Lookups",
     "blurb": "Everything here is off unless you switch it on. Nothing is "
              "uploaded silently.",
     "sections": [
         {"title": "Country lookup", "controls": [
             {"key": "privacy.geoip_enabled", "type": "bool",
              "label": "Show each remote host's country",
              "help": "Sends each remote (Internet) IP address \u2014 never "
                      "your own devices, never packet contents \u2014 to a "
                      "public geolocation service to find its country. "
                      "Tries several services and retries automatically."},
             {"type": "geo_status"},
             {"type": "action", "actions": [
                 ("Test lookup", "geoip_test"),
                 ("Retry failed", "geoip_retry")]},
         ]},
         {"title": "Update checks", "controls": [
             {"key": "updates.repo", "type": "text", "width": 26,
              "pattern": r"^[\w.-]+/[\w.-]+$",
              "pattern_msg": "Use the form owner/name, e.g. yourname/"
                             "miniwireshark",
              "label": "GitHub repository",
              "help": "Where new releases are published, as owner/name. "
                      "Leave empty and MiniWireshark never checks."},
             {"key": "updates.check_automatically", "type": "bool",
              "label": "Check when MiniWireshark opens",
              "requires": "updates.repo",
              "help": "Needs a repository above. Asks GitHub for the latest "
                      "release number only."},
             {"type": "action", "actions": [
                 ("Check for updates now", "check_updates")]},
         ]},
         {"title": "What MiniWireshark keeps", "controls": [
             {"type": "info", "text":
              "Captured network information is processed on this computer "
              "and stays here unless you export it. Settings are saved in a "
              "small file next to the program. Nothing is sent anywhere "
              "except the two optional features above, which are off by "
              "default."},
         ]},
     ]},
    {"id": "shortcuts", "icon": "\u2328", "title": "Keyboard Shortcuts",
     "blurb": "Click Change, then press the new key combination.",
     "sections": [
         {"title": "Actions", "controls": [
             {"key": "shortcuts.start", "type": "shortcut",
              "label": "Start watching"},
             {"key": "shortcuts.stop", "type": "shortcut", "label": "Stop"},
             {"key": "shortcuts.clear", "type": "shortcut",
              "label": "Clear"},
             {"key": "shortcuts.export", "type": "shortcut",
              "label": "Open the export menu"},
             {"key": "shortcuts.find", "type": "shortcut",
              "label": "Jump to search"},
         ]},
     ]},
    {"id": "data", "icon": "\U0001F4BE", "title": "Data & Export",
     "blurb": "Where files go, and where your settings live.",
     "sections": [
         {"title": "Exports", "controls": [
             {"key": "export.default_dir", "type": "path",
              "label": "Default folder for exports and sessions",
              "help": "File dialogs open here. Leave empty to use the "
                      "system default."},
         ]},
         {"title": "Settings file", "controls": [
             {"type": "info", "text_fn": "config_path_text"},
             {"type": "action", "actions": [
                 ("Open settings folder", "open_config_folder")]},
         ]},
     ]},
]


def settings_schema_keys():
    """Every config key the settings window exposes."""
    out = []
    for page in SETTINGS_PAGES:
        for sec in page["sections"]:
            for c in sec["controls"]:
                if c.get("key"):
                    out.append(c["key"])
    return out


def _pretty_seq(seq):
    names = {"Control": "Ctrl", "period": ".", "comma": ",",
             "Return": "Enter", "space": "Space", "slash": "/",
             "minus": "-", "plus": "+", "Escape": "Esc", "Delete": "Del",
             "BackSpace": "Backspace", "Prior": "PageUp", "Next": "PageDown"}
    parts = (seq or "").strip("<>").split("-")
    return "+".join(names.get(p, p.upper() if len(p) == 1 else p)
                    for p in parts if p)


def _open_path(path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False


class SettingsWindow:
    """Two-pane settings: categories on the left, one page of grouped
    options on the right, with search, per-page reset, inline validation
    and Apply / OK / Cancel. Built entirely from SETTINGS_PAGES."""

    F_BASE = ("TkDefaultFont", 10)
    F_HELP = ("TkDefaultFont", 9)
    F_SECTION = ("TkDefaultFont", 11, "bold")
    F_TITLE = ("TkDefaultFont", 15, "bold")

    def __init__(self, app, page="general"):
        self.app = app
        self.cfg = app.config
        self.defaults = _default_config()
        self.vars = {}
        self.controls = {}
        for pg in SETTINGS_PAGES:
            for sec in pg["sections"]:
                for c in sec["controls"]:
                    if c.get("key"):
                        self.controls[c["key"]] = c
        self.errors = {}
        self._wrap = []
        self._deps = []
        self._nav = {}
        self._shortcut_prev = {}
        self.page_id = page if any(p["id"] == page for p in SETTINGS_PAGES) \
            else "general"
        self.searching = False
        self.win = tk.Toplevel(app.root)
        self.win.title("Settings")
        sw_, sh_ = app.root.winfo_screenwidth(), app.root.winfo_screenheight()
        w_, h_ = min(900, sw_ - 80), min(640, sh_ - 120)
        x_ = max(0, app.root.winfo_rootx() + (app.root.winfo_width() - w_) // 2)
        y_ = max(0, app.root.winfo_rooty() + 40)
        self.win.geometry(f"{w_}x{h_}+{x_}+{y_}")
        self.win.minsize(min(760, w_), min(520, h_))
        self.win.transient(app.root)
        self._create_vars()
        self.baseline = self._snapshot()
        self._build_chrome()
        self.show_page(self.page_id)
        self.win.bind("<Escape>", lambda e: self.cancel())
        self.win.protocol("WM_DELETE_WINDOW", self.cancel)
        self._tick()

    # ---------------------------------------------------------------- state
    def alive(self):
        try:
            return bool(self.win.winfo_exists())
        except tk.TclError:
            return False

    def sync_key(self, key, value):
        """Another part of the app changed `key`: show it here without
        marking the window as having unsaved changes."""
        var = self.vars.get(key)
        if var is None:
            return
        var.set(value if isinstance(var, tk.BooleanVar) else str(value))
        # this key now matches what's saved; any OTHER pending edits stay
        self.baseline[key] = str(var.get())
        self._refresh_footer()

    @property
    def t(self):
        return self.app.theme

    def _default_for(self, key):
        section, _, name = key.partition(".")
        return self.defaults.get(section, {}).get(name)

    def _create_vars(self):
        for key, c in self.controls.items():
            cur = self.cfg.get(key, self._default_for(key))
            if c["type"] == "bool":
                self.vars[key] = tk.BooleanVar(value=bool(cur))
            else:
                self.vars[key] = tk.StringVar(value="" if cur is None
                                              else str(cur))
            if c["type"] == "shortcut":
                self._shortcut_prev[key] = self.vars[key].get()
            self.vars[key].trace_add(
                "write", lambda *a, k=key: self._on_change(k))

    def _snapshot(self):
        return {k: str(v.get()) for k, v in self.vars.items()}

    def _value_of(self, key):
        c, v = self.controls[key], self.vars[key]
        if c["type"] == "bool":
            return bool(v.get())
        raw = str(v.get()).strip()
        if c["type"] == "int":
            try:
                n = int(float(raw))
            except ValueError:
                n = int(self._default_for(key) or 0)
            return max(c["min"], min(c["max"], n))
        return raw

    def _validate(self, key):
        c, v = self.controls[key], self.vars[key]
        if c["type"] == "int":
            raw = str(v.get()).strip()
            try:
                n = float(raw)
            except ValueError:
                return "Enter a whole number."
            if n != int(n):
                return "Enter a whole number."
            if not c["min"] <= n <= c["max"]:
                return f"Choose a value from {c['min']} to {c['max']}."
        elif c["type"] == "text" and c.get("pattern"):
            raw = str(v.get()).strip()
            if raw and not re.match(c["pattern"], raw):
                return c.get("pattern_msg", "That doesn't look right.")
        elif c["type"] == "path":
            raw = str(v.get()).strip()
            if raw and not os.path.isdir(raw):
                return "That folder doesn't exist."
        elif c["type"] == "shortcut":
            seq = str(v.get()).strip()
            for other, ov in self.vars.items():
                if other != key and self.controls[other]["type"] == "shortcut" \
                        and str(ov.get()).strip() == seq and seq:
                    return (f"Already used by "
                            f"\u201c{self.controls[other]['label']}\u201d.")
        return ""

    def _validate_all(self):
        self.errors = {}
        for key in self.controls:
            msg = self._validate(key)
            if msg:
                self.errors[key] = msg
        return self.errors

    def dirty(self):
        return self._snapshot() != self.baseline

    def _on_change(self, key):
        if key is not None and key in self.controls:
            msg = self._validate(key)
            if msg:
                self.errors[key] = msg
            else:
                self.errors.pop(key, None)
            self._show_error(key)
            if self.controls[key]["type"] == "shortcut" and not msg:
                self._shortcut_prev[key] = self.vars[key].get()
        self._refresh_deps()
        self._refresh_footer()

    # --------------------------------------------------------------- chrome
    def _build_chrome(self):
        t = self.t
        for w in self.win.winfo_children():
            w.destroy()
        self._wrap, self._deps, self._nav = [], [], {}
        self.win.configure(bg=t["window_bg"])

        # ---- sidebar
        side = tk.Frame(self.win, bg=t["side_bg"], width=220)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="Settings", bg=t["side_bg"], fg=t["text_fg"],
                 font=self.F_TITLE, anchor="w").pack(fill="x", padx=16,
                                                     pady=(16, 8))
        self.search_var = tk.StringVar()
        se = ttk.Entry(side, textvariable=self.search_var)
        se.pack(fill="x", padx=14, pady=(0, 10))
        self.search_entry = se
        self.search_var.trace_add("write", lambda *a: self._on_search())
        self._placeholder(se, self.search_var, "\U0001F50D Search settings")
        for pg in SETTINGS_PAGES:
            self._add_nav_row(side, pg)
        tk.Frame(side, bg=t["side_bg"]).pack(fill="both", expand=True)
        ttk.Button(side, text="Reset all settings\u2026",
                   command=self.reset_all).pack(fill="x", padx=14,
                                                pady=(0, 6))
        tk.Label(side, text=f"MiniWireshark {SCRIPT_VERSION}",
                 bg=t["side_bg"], fg=t["muted_fg"], font=self.F_HELP
                 ).pack(pady=(0, 12))

        # ---- right side: header / scrolling body / footer
        right = tk.Frame(self.win, bg=t["tab_bg"])
        right.pack(side="left", fill="both", expand=True)
        head = tk.Frame(right, bg=t["tab_bg"], padx=24, pady=16)
        head.pack(fill="x")
        self.title_lbl = tk.Label(head, bg=t["tab_bg"], fg=t["text_fg"],
                                  font=self.F_TITLE, anchor="w")
        self.title_lbl.pack(fill="x")
        self.blurb_lbl = tk.Label(head, bg=t["tab_bg"], fg=t["muted_fg"],
                                  font=self.F_BASE, anchor="w",
                                  justify="left")
        self.blurb_lbl.pack(fill="x", pady=(2, 0))
        self._wrap.append((self.blurb_lbl, 60))
        tk.Frame(right, bg=t["border"], height=1).pack(fill="x")

        foot = tk.Frame(right, bg=t["window_bg"], padx=16, pady=10)
        foot.pack(side="bottom", fill="x")
        tk.Frame(right, bg=t["border"], height=1).pack(side="bottom",
                                                       fill="x")
        self.dirty_lbl = tk.Label(foot, bg=t["window_bg"], fg=t["muted_fg"],
                                  font=self.F_HELP, anchor="w")
        self.dirty_lbl.pack(side="left")
        self.ok_btn = ttk.Button(foot, text="OK", width=9,
                                 style="Accent.TButton", command=self.ok)
        self.ok_btn.pack(side="right")
        self.apply_btn = ttk.Button(foot, text="Apply", width=9,
                                    command=self.apply)
        self.apply_btn.pack(side="right", padx=6)
        ttk.Button(foot, text="Cancel", width=9,
                   command=self.cancel).pack(side="right")
        self.reset_btn = ttk.Button(foot, text="Reset this page",
                                    command=self.reset_page)
        self.reset_btn.pack(side="right", padx=(0, 16))

        body = tk.Frame(right, bg=t["tab_bg"])
        body.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(body, bg=t["tab_bg"], highlightthickness=0)
        vs = ttk.Scrollbar(body, orient="vertical",
                           command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.content = tk.Frame(self.canvas, bg=t["tab_bg"], padx=24,
                                pady=6)
        self._cwin = self.canvas.create_window((0, 0), window=self.content,
                                               anchor="nw")
        self.content.bind("<Configure>", lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        for w in (self.canvas, self.content):
            w.bind("<Enter>", self._bind_wheel)
            w.bind("<Leave>", self._unbind_wheel)
        self.win.bind("<Destroy>", self._on_destroy, add="+")
        self._refresh_footer()

    def _add_nav_row(self, parent, page):
        t = self.t
        row = tk.Frame(parent, bg=t["side_bg"], cursor="hand2")
        row.pack(fill="x")
        bar = tk.Frame(row, bg=t["side_bg"], width=4)
        bar.pack(side="left", fill="y")
        icon = tk.Label(row, text=page["icon"], bg=t["side_bg"],
                        fg=t["text_fg"], font=self.F_BASE, width=3, pady=8)
        icon.pack(side="left")
        lbl = tk.Label(row, text=page["title"], bg=t["side_bg"],
                       fg=t["text_fg"], font=self.F_BASE, anchor="w",
                       pady=8)
        lbl.pack(side="left", fill="x", expand=True)
        for w in (row, lbl, bar, icon):
            w.bind("<Button-1>", lambda e, p=page["id"]: self._go(p))
        self._nav[page["id"]] = (row, bar, lbl, icon)

    def _placeholder(self, entry, var, text):
        """Grey hint text inside an empty entry that vanishes on focus."""
        state = {"on": False}

        def show(_e=None):
            if not var.get():
                state["on"] = True
                var.set(text)
                entry.configure(foreground=self.t["muted_fg"])

        def hide(_e=None):
            if state["on"]:
                state["on"] = False
                var.set("")
                entry.configure(foreground=self.t["text_fg"])
        entry.bind("<FocusIn>", hide)
        entry.bind("<FocusOut>", show)
        self._search_placeholder = (state, text)
        show()

    def _go(self, page_id):
        state, _t = self._search_placeholder
        if self.search_var.get() and not state["on"]:
            self.search_var.set("")
        self.show_page(page_id)

    def _mark_nav(self, page_id):
        t = self.t
        for pid, (row, bar, lbl, icon) in self._nav.items():
            sel = (pid == page_id)
            bg = t["side_sel"] if sel else t["side_bg"]
            for w in (row, lbl, icon):
                w.configure(bg=bg)
            bar.configure(bg=t["accent"] if sel else bg)
            lbl.configure(font=(self.F_BASE[0], self.F_BASE[1], "bold")
                          if sel else self.F_BASE)

    # -------------------------------------------------------------- scrolling
    def _on_canvas_resize(self, e):
        self.canvas.itemconfigure(self._cwin, width=e.width)
        for lbl, reserve in self._wrap:
            try:
                lbl.configure(wraplength=max(240, e.width - reserve - 48))
            except tk.TclError:
                pass

    def _bind_wheel(self, _e=None):
        self.win.bind_all("<MouseWheel>", self._wheel)
        self.win.bind_all("<Button-4>", self._wheel)
        self.win.bind_all("<Button-5>", self._wheel)

    def _unbind_wheel(self, _e=None):
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            try:
                self.win.unbind_all(seq)
            except tk.TclError:
                pass

    def _on_destroy(self, e):
        if e.widget is self.win:
            self._unbind_wheel()

    def _wheel(self, e):
        if not self.alive():
            return
        if getattr(e, "num", None) == 4:
            step = -3
        elif getattr(e, "num", None) == 5:
            step = 3
        else:
            step = -1 * (1 if e.delta > 0 else -1) * 3 if abs(e.delta) < 120 \
                else -int(e.delta / 120) * 3
        self.canvas.yview_scroll(step, "units")

    # ---------------------------------------------------------------- pages
    def _clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()
        self._wrap = [(l, r) for l, r in self._wrap if l is self.blurb_lbl]
        self._deps = []
        self._err_labels = {}

    def show_page(self, page_id):
        self.page_id = page_id
        self.searching = False
        page = next(p for p in SETTINGS_PAGES if p["id"] == page_id)
        self._clear_content()
        self.title_lbl.configure(text=f"{page['icon']}  {page['title']}")
        self.blurb_lbl.configure(text=page.get("blurb", ""))
        self._mark_nav(page_id)
        for sec in page["sections"]:
            self._render_section(sec["title"], sec["controls"])
        self._finish_render()

    def _finish_render(self):
        self.canvas.yview_moveto(0)
        self._refresh_deps()
        self._refresh_footer()
        self.win.update_idletasks()
        self._on_canvas_resize(type("E", (), {
            "width": max(self.canvas.winfo_width(), 400)})())
        scale = self.app.TEXT_SIZES.get(
            self.cfg.get("appearance.text_size", "Normal"), 1.0)
        if scale != 1.0:
            self.app._scale_explicit_fonts(self.win, scale)

    def _on_search(self):
        state, text = getattr(self, "_search_placeholder", ({"on": False}, ""))
        if state["on"]:
            return
        q = self.search_var.get().strip().lower()
        if len(q) < 2:
            if self.searching:
                self.show_page(self.page_id)
            return
        self.searching = True
        self._clear_content()
        self.title_lbl.configure(text="\U0001F50D  Search results")
        self.blurb_lbl.configure(text=f"Settings matching \u201c{q}\u201d")
        self._mark_nav(None)
        found = 0
        for page in SETTINGS_PAGES:
            for sec in page["sections"]:
                hits = [c for c in sec["controls"] if c.get("key") and
                        q in " ".join([c.get("label", ""), c.get("help", ""),
                                       sec["title"], page["title"]]).lower()]
                if hits:
                    found += len(hits)
                    self._render_section(
                        f"{page['title']}  \u203a  {sec['title']}", hits)
        if not found:
            tk.Label(self.content, text="No settings match that search.",
                     bg=self.t["tab_bg"], fg=self.t["muted_fg"],
                     font=self.F_BASE).pack(anchor="w", pady=20)
        self._finish_render()

    # ------------------------------------------------------------- rendering
    def _render_section(self, title, controls):
        t = self.t
        hdr = tk.Frame(self.content, bg=t["tab_bg"])
        hdr.pack(fill="x", pady=(16, 4))
        tk.Label(hdr, text=title, bg=t["tab_bg"], fg=t["text_fg"],
                 font=self.F_SECTION, anchor="w").pack(fill="x")
        tk.Frame(hdr, bg=t["border"], height=1).pack(fill="x", pady=(3, 0))
        for c in controls:
            self._render_control(c)

    def _help(self, parent, text, indent=0, reserve=60):
        lbl = tk.Label(parent, text=text, bg=self.t["tab_bg"],
                       fg=self.t["muted_fg"], font=self.F_HELP,
                       justify="left", anchor="w")
        lbl.pack(fill="x", padx=(indent, 0))
        self._wrap.append((lbl, reserve))
        return lbl

    def _render_control(self, c):
        t, typ = self.t, c["type"]
        row = tk.Frame(self.content, bg=t["tab_bg"], pady=7)
        row.pack(fill="x")
        key = c.get("key")
        widgets = []

        if typ == "bool":
            top = tk.Frame(row, bg=t["tab_bg"])
            top.pack(fill="x")
            cb = ttk.Checkbutton(top, text=c["label"],
                                 variable=self.vars[key])
            cb.pack(side="left")
            widgets.append(cb)
            if c.get("badge"):
                self._badge(top, c["badge"])
            self._help(row, c.get("help", ""), indent=24, reserve=40)

        elif typ in ("choice", "int", "text", "path", "shortcut"):
            left = tk.Frame(row, bg=t["tab_bg"])
            left.pack(side="left", fill="x", expand=True)
            tk.Label(left, text=c["label"], bg=t["tab_bg"], fg=t["text_fg"],
                     font=self.F_BASE, anchor="w").pack(fill="x")
            if c.get("help"):
                self._help(left, c["help"], reserve={
                    "choice": 200, "int": 300, "text": 260, "path": 400,
                    "shortcut": 340}.get(typ, 260))
            right = tk.Frame(row, bg=t["tab_bg"])
            right.pack(side="right", anchor="n", padx=(12, 0))
            widgets += self._render_input(right, c)

        elif typ == "info":
            text = c.get("text") or getattr(self, c["text_fn"])()
            self._help(row, text, reserve=40)

        elif typ == "geo_status":
            self.geo_var = tk.StringVar(value=self.app._geoip_status_text())
            lbl = tk.Label(row, textvariable=self.geo_var, bg=t["card_bg"],
                           fg=t["text_fg"], font=self.F_HELP, justify="left",
                           anchor="w", padx=10, pady=8)
            lbl.pack(fill="x")
            self._wrap.append((lbl, 60))

        elif typ == "action":
            bar = tk.Frame(row, bg=t["tab_bg"])
            bar.pack(fill="x")
            for text, name in c["actions"]:
                b = ttk.Button(bar, text=text, style="Settings.TButton",
                               command=lambda n=name: self._act(n))
                b.pack(side="left", padx=(0, 8))

        if key:
            err = tk.Label(row, text="", bg=t["tab_bg"], fg=t["danger_fg"],
                           font=self.F_HELP, anchor="w", justify="left")
            self._err_labels[key] = err
            self._show_error(key)
        if c.get("requires"):
            self._deps.append((c["requires"], widgets))

    def _badge(self, parent, sev):
        t = self.t
        fg, bg = {"INFO": (t["info_fg"], t["card_bg"]),
                  "WARNING": (t["warn_fg"], t["warn_bg"]),
                  "DANGER": (t["danger_fg"], t["danger_bg"])}[sev]
        icon = self.app.SEVERITY_ICON.get(sev, "")
        tk.Label(parent, text=f" {icon} {sev} ", bg=bg, fg=fg,
                 font=(self.F_HELP[0], 8, "bold")).pack(side="left",
                                                        padx=(10, 0))

    def _render_input(self, parent, c):
        key, typ, var = c["key"], c["type"], self.vars[c["key"]]
        if typ == "choice":
            vals = c["choices"]
            if vals == "@locales":
                vals = list(LOCALE_NAMES.values())
            w = ttk.Combobox(parent, textvariable=var, values=vals,
                             state="readonly", width=16)
            w.pack(anchor="e")
            return [w]
        if typ == "int":
            box = tk.Frame(parent, bg=self.t["tab_bg"])
            box.pack(anchor="e")
            w = ttk.Spinbox(box, from_=c["min"], to=c["max"],
                            increment=c.get("step", 1), textvariable=var,
                            width=8, justify="right")
            w.pack(side="left")
            tk.Label(box, text=c.get("unit", ""), bg=self.t["tab_bg"],
                     fg=self.t["muted_fg"], font=self.F_HELP, anchor="w",
                     width=16).pack(side="left", padx=(6, 0))
            return [w]
        if typ == "text":
            w = ttk.Entry(parent, textvariable=var, width=c.get("width", 24))
            w.pack(anchor="e")
            return [w]
        if typ == "path":
            box = tk.Frame(parent, bg=self.t["tab_bg"])
            box.pack(anchor="e")
            w = ttk.Entry(box, textvariable=var, width=26)
            w.pack(side="left")
            b = ttk.Button(box, text="Browse\u2026", width=9,
                           command=lambda: self._browse(var))
            b.pack(side="left", padx=(6, 0))
            return [w, b]
        if typ == "shortcut":
            box = tk.Frame(parent, bg=self.t["tab_bg"])
            box.pack(anchor="e")
            shown = tk.StringVar(value=_pretty_seq(var.get()))
            var.trace_add("write", lambda *a: shown.set(
                _pretty_seq(var.get())))
            tk.Label(box, textvariable=shown, bg=self.t["card_bg"],
                     fg=self.t["text_fg"], font=self.F_BASE, width=14,
                     padx=6, pady=3).pack(side="left")
            b1 = ttk.Button(box, text="Change", width=8,
                            command=lambda: self._change_shortcut(key))
            b1.pack(side="left", padx=(6, 0))
            b2 = ttk.Button(box, text="Default", width=8,
                            command=lambda: var.set(
                                DEFAULT_SHORTCUTS.get(key.split(".")[1], "")))
            b2.pack(side="left", padx=(4, 0))
            return [b1, b2]
        return []

    # ------------------------------------------------------- dynamic pieces
    def _show_error(self, key):
        lbl = getattr(self, "_err_labels", {}).get(key)
        if lbl is None:
            return
        try:
            msg = self.errors.get(key, "")
            if msg:
                lbl.configure(text="\u26a0 " + msg)
                lbl.pack(fill="x")
            else:
                lbl.pack_forget()
        except tk.TclError:
            pass

    def _refresh_deps(self):
        for req, widgets in self._deps:
            v = self.vars.get(req)
            on = bool(v.get()) if isinstance(v, tk.BooleanVar) else \
                bool(str(v.get()).strip()) if v is not None else True
            if isinstance(v, tk.StringVar) and req == "updates.repo":
                on = on and not self.errors.get(req)
            for w in widgets:
                try:
                    w.state(["!disabled"] if on else ["disabled"])
                except tk.TclError:
                    pass

    def _refresh_footer(self):
        try:
            bad = bool(self.errors)
            dirty = self.dirty()
            if bad:
                self.dirty_lbl.configure(
                    text="\u26a0 Some settings need attention",
                    fg=self.t["danger_fg"])
            elif dirty:
                self.dirty_lbl.configure(text="\u25cf Unsaved changes",
                                         fg=self.t["warn_fg"])
            else:
                self.dirty_lbl.configure(text="All changes saved",
                                         fg=self.t["muted_fg"])
            state = ["!disabled"] if (dirty and not bad) else ["disabled"]
            self.apply_btn.state(state)
            self.reset_btn.state(["disabled"] if self.searching
                                 else ["!disabled"])
        except tk.TclError:
            pass

    def _tick(self):
        if not self.alive():
            return
        try:
            if hasattr(self, "geo_var"):
                self.geo_var.set(self.app._geoip_status_text())
        except tk.TclError:
            pass
        self.win.after(1000, self._tick)

    # ------------------------------------------------------------- actions
    def _browse(self, var):
        d = filedialog.askdirectory(parent=self.win,
                                    initialdir=var.get() or None)
        if d:
            var.set(d)

    def _change_shortcut(self, key):
        self.app._capture_shortcut(self.win, key.split(".")[1],
                                   self.vars[key])

    def config_path_text(self):
        return f"Settings are saved in:\n{self.cfg.path}"

    def _act(self, name):
        if name == "open_config_folder":
            folder = os.path.dirname(self.cfg.path)
            if not _open_path(folder):
                messagebox.showinfo("Settings folder", folder,
                                    parent=self.win)
        elif name == "check_updates":
            self.app._check_for_updates(manual=True)
        elif name == "geoip_test":
            self.app._geoip_test(self.win)
        elif name == "geoip_retry":
            self.app._geoip_retry()

    def reset_page(self):
        if self.searching:
            return
        page = next(p for p in SETTINGS_PAGES if p["id"] == self.page_id)
        for sec in page["sections"]:
            for c in sec["controls"]:
                k = c.get("key")
                if not k:
                    continue
                d = self._default_for(k)
                self.vars[k].set(bool(d) if c["type"] == "bool"
                                 else ("" if d is None else str(d)))

    def reset_all(self):
        if not messagebox.askyesno(
                "Reset all settings",
                "Restore every setting to its default?\n\nYour captured "
                "data isn't affected.", parent=self.win):
            return
        self.cfg.reset()
        self.app._apply_runtime_settings()
        for key, c in self.controls.items():
            d = self._default_for(key)
            self.vars[key].set(bool(d) if c["type"] == "bool"
                               else ("" if d is None else str(d)))
        self.errors = {}
        self.baseline = self._snapshot()
        self._build_chrome()
        self.show_page(self.page_id)

    def apply(self):
        errs = self._validate_all()
        if errs:
            self._refresh_footer()
            for k in errs:
                self._show_error(k)
            return False
        before = (self.cfg.get("appearance.theme"),
                  self.cfg.get("appearance.high_contrast"),
                  self.cfg.get("appearance.text_size"))
        for key in self.controls:
            self.cfg.set(key, self._value_of(key))
        self.cfg.save()
        self.app._apply_runtime_settings()
        # show the values as actually stored (e.g. numbers clamped)
        for key in self.controls:
            v = self._value_of(key)
            self.vars[key].set(v if isinstance(v, bool) else str(v))
        self.baseline = self._snapshot()
        after = (self.cfg.get("appearance.theme"),
                 self.cfg.get("appearance.high_contrast"),
                 self.cfg.get("appearance.text_size"))
        if before != after:
            self._build_chrome()
            self.show_page(self.page_id)
        else:
            self._refresh_footer()
        self.app._set_banner("\u2699\ufe0e  Settings saved.")
        return True

    def ok(self):
        if self.apply():
            self.win.destroy()

    def cancel(self):
        if self.dirty() and not messagebox.askyesno(
                "Discard changes?", "You have unsaved changes. Close "
                "without saving?", parent=self.win):
            return
        self.win.destroy()


class MiniWireshark:
    MAX_ROWS = 5000       # default; Settings -> Capture overrides via max_rows

    def __init__(self, root, gateway_ip, my_ips, my_macs,
                 default_iface_name=""):
        self.root = root
        self.gateway_ip = gateway_ip
        self.my_ips = set(my_ips)
        self.my_macs = set(my_macs)
        self.default_iface_name = default_iface_name

        root.title("MiniWireshark")
        root.geometry("1400x880")
        root.minsize(1100, 660)
        root.configure(background="#f4f5f7")

        self.config = AppConfig()
        self.theme_name = self.config.get("appearance.theme", "Light")
        self.high_contrast = bool(self.config.get("appearance.high_contrast",
                                                   False))
        self.beginner_mode = self.config.get("appearance.beginner_mode", True)
        set_locale(self.config.get("general.language", "English"))
        self._themed_widgets = []   # (widget, role) pairs for dark-mode recolor

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

        # ---- the data model core (Section 44): devices, websites, and
        # remote hosts are entirely separate record types. Nothing here
        # can turn a public IP or a DNS name into a "device".
        self.registry = DeviceRegistry(gateway_ip, self.my_ips, self.config)
        self.alert_engine = AlertEngine(self.config)
        self.device_iids = {}          # registry key -> devtree iid
        self.websites = {}             # domain -> WebsiteRecord
        self.website_iids = {}
        self.ip_to_domain = {}         # public ip -> most recently learned domain
        self.remote_hosts = {}         # ip -> RemoteHostRecord
        self.remote_iids = {}
        self.alert_iids = {}
        self.timeline = deque(maxlen=2000)   # unified chronological events
        self.timeline_iids = {}
        self._known_website_keys = set()     # for "first time seen" detection
        self._session_loaded_note = ""       # non-empty => viewing a loaded file
        self.geoip = GeoIPService(self._geoip_on_result)
        self.geoip.set_enabled(self.config.get("privacy.geoip_enabled", False))
        self._async_results = queue.Queue()  # background threads -> main thread

        # dns / router analysis (not device-specific, so kept at app level)
        self.dns_servers = defaultdict(int)   # ip -> query count
        self.doh_seen = defaultdict(set)      # device_ip -> set(doh_host)
        self.dhcp_servers = defaultdict(int)  # ip -> offer count
        self._spoof_warned = False
        self._discovering_until = time.time() + 60  # "Discovering..." window

        # friendly live-feed pacing ("it goes too fast" fix)
        self.feed_speed = DEFAULT_FEED_SPEED
        self.feed_paused = False
        self._feed_buffer = []

        # autonomy bookkeeping
        self._capture_started_at = 0.0
        self._auto_restart_count = 0
        self._last_restart_time = 0.0

        self.iface_map = {}
        self.max_rows = int(self.config.get("capture.max_stored_events",
                                            self.MAX_ROWS))

        self._apply_style()
        self._build_ui()
        self._populate_ifaces()
        self._apply_theme()
        self._apply_text_size()
        self._apply_shortcuts()

        if self.config.warning:
            self.root.after(1500, lambda: self._set_banner(
                f"⚠️  {self.config.warning}", kind="warn"))

        self.root.after(60, self._drain_decoded)
        self.root.after(400, self._refresh_visible)
        self.root.after(1000, self._tick_status)
        self.root.after(2000, self._refresh_insights)
        self.root.after(300, self._flush_feed)
        self.root.after(5000, self._tick_lifecycle_and_alerts)
        self.root.after(200, self._drain_async_results)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Be autonomous by default: pick the best card and start watching
        # without making a beginner hunt for the right button.
        if self.config.get("general.auto_start_capture", True):
            self.root.after(700, self._auto_start_once)
        else:
            self.status_var.set("Ready. Click \u201cStart watching\u201d when "
                                "you'd like to begin.")

        # Update checking is opt-in and requires an explicit repo — never
        # phones home on its own otherwise (Section 22/48).
        if self.config.get("updates.check_automatically", False) and \
                self.config.get("updates.repo", "").strip():
            self.root.after(4000, lambda: self._check_for_updates(manual=False))

    def _ms(self, base):
        """Timer interval, stretched in CPU-friendly mode."""
        slow = self.config.get("performance.cpu_friendly_mode", False)
        return int(base * (2.5 if slow else 1))

    def _dialog_dir(self):
        """Starting folder for file dialogs (Settings -> Data & export)."""
        d = (self.config.get("export.default_dir", "") or "").strip()
        return d if d and os.path.isdir(d) else None

    def _apply_runtime_settings(self):
        """Push every live-applicable setting into the running app. Called
        by Settings (Apply/OK) and after a reset, so nothing needs a
        restart."""
        cfg = self.config
        self.max_rows = max(100, int(cfg.get("capture.max_stored_events",
                                             self.MAX_ROWS)))
        while len(self.all_rows) > self.max_rows:
            self.all_rows.popleft()
        while len(self.iids) > self.max_rows:
            old = self.iids.popleft()
            self.rows_by_iid.pop(old, None)
            try:
                self.tree.delete(old)
            except tk.TclError:
                pass
        self.beginner_mode = bool(cfg.get("appearance.beginner_mode", True))
        if hasattr(self, "mode_ui_var"):
            self.mode_ui_var.set("Beginner" if self.beginner_mode
                                 else "Advanced")
        self._apply_ui_mode()
        set_locale(cfg.get("general.language", "English"))
        self._apply_locale()
        self._apply_shortcuts()
        theme = cfg.get("appearance.theme", "Light")
        hc = bool(cfg.get("appearance.high_contrast", False))
        if theme != self.theme_name or hc != self.high_contrast:
            self._apply_theme(theme, hc)
        self._apply_text_size(cfg.get("appearance.text_size", "Normal"))
        self._restyle_mode_banner()
        self.show_inactive_var.set(cfg.get("devices.show_inactive", False))
        self.show_expired_var.set(cfg.get("devices.show_expired", False))
        for key in list(self.registry.by_key):
            self._redraw_device_row(key)
        self._set_geoip_enabled(cfg.get("privacy.geoip_enabled", False),
                                save=False)
        self._render_security_check()

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
        s.configure("TNotebook.Tab", padding=(10, 7),
                    font=("TkDefaultFont", 10, "bold"))

    # ---------- severity system (INFO / WARNING / DANGER) ----------------
    SEVERITY_ICON = {"INFO": "\u2139", "WARNING": "\u26a0", "DANGER": "\u203c"}

    def _severity_colors(self):
        t = getattr(self, "theme", None) or THEME_LIGHT
        return {
            "INFO": (t["info_fg"], None),
            "WARNING": (t["warn_fg"], t["warn_bg"]),
            "DANGER": (t["danger_fg"], t["danger_bg"]),
        }

    # ---------- themes: Light / Dark, each with a High-Contrast variant ----
    def _retheme_widget_tree(self, widget, palette):
        """Swap every known palette colour on `widget` and its descendants
        for the same colour in `palette`. Colours are mapped via their
        canonical light value, so any palette -> any palette is lossless."""
        table = PALETTES[palette]
        try:
            keys = widget.keys()
        except Exception:
            keys = []
        for opt in _RETHEME_COLOR_OPTS:
            if opt not in keys:
                continue
            try:
                cur = str(widget.cget(opt)).lower()
            except Exception:
                continue
            if opt in ("fg", "foreground", "insertbackground") and \
                    cur in _DEFAULT_FG_NAMES:
                # still on the platform's default text colour (which can't
                # be themed by hex lookup, e.g. "SystemWindowText" on
                # Windows): adopt this palette's text colour explicitly
                try:
                    widget.configure(**{opt: THEMES[palette]["text_fg"]})
                except tk.TclError:
                    pass
                continue
            canon = _CANON.get(cur, cur)
            new = table.get(canon, canon)
            if new != cur and canon in LIGHT_TO_DARK_HEX:
                try:
                    widget.configure(**{opt: new})
                except tk.TclError:
                    pass
        if isinstance(widget, tk.Text):
            for tag in widget.tag_names():
                for opt in ("foreground", "background"):
                    try:
                        cur = str(widget.tag_cget(tag, opt)).lower()
                    except tk.TclError:
                        continue
                    canon = _CANON.get(cur, cur)
                    new = table.get(canon, canon)
                    if new != cur and canon in LIGHT_TO_DARK_HEX:
                        try:
                            widget.tag_configure(tag, **{opt: new})
                        except tk.TclError:
                            pass
        try:
            children = widget.winfo_children()
        except Exception:
            children = []
        for child in children:
            self._retheme_widget_tree(child, palette)

    def _restyle_ttk(self, dark, hc=False):
        style = ttk.Style()
        pal = palette_name("Dark" if dark else "Light", hc)
        frame = THEMES[pal]["window_bg"]      # window chrome
        surface = THEMES[pal]["tab_bg"]       # cards / tab content
        if hc and dark:
            bg, fg, field, sel, selfg = ("#0b0c0f", "#ffffff", "#000000",
                                         "#ffd400", "#000000")
            tabsel = "#ffd400"
        elif hc:
            bg, fg, field, sel, selfg = ("#ffffff", "#000000", "#ffffff",
                                         "#0a246a", "#ffffff")
            tabsel = "#0a246a"
        elif dark:
            bg, fg, field, sel, selfg = ("#20232c", "#e2e5ea", "#181b22",
                                         "#2f5f8f", "#ffffff")
            tabsel = "#2f5f8f"
        else:
            bg, fg, field, sel, selfg = ("#e8e8ec", "#000000", "#ffffff",
                                         "#cfe3ff", "#000000")
            tabsel = "#ffffff"
        tabsel_fg = selfg if (dark or hc) else "#000000"
        head = "#242832" if (dark and not hc) else (
            "#000000" if (dark and hc) else ("#ffffff" if hc else "#f0f0f0"))
        style.configure("TFrame", background=frame)
        style.configure("TLabel", background=frame, foreground=fg)
        style.configure("TButton", background=bg, foreground=fg)
        style.map("TButton",
                  background=[("disabled",
                               frame if (dark or hc) else "#ececec")],
                  foreground=[("disabled", "#7a808c" if dark else "#8a8a8a")])
        style.configure("TCheckbutton", background=surface, foreground=fg)
        style.configure("TRadiobutton", background=surface, foreground=fg)
        style.map("TCheckbutton", background=[("active", surface)])
        style.map("TRadiobutton", background=[("active", surface)])
        style.configure("TNotebook", background=frame)
        style.configure("TNotebook.Tab", background=bg if not hc else frame,
                        foreground=fg)
        style.map("TNotebook.Tab", background=[("selected", tabsel)],
                  foreground=[("selected", tabsel_fg)])
        style.configure("Treeview", background=field, fieldbackground=field,
                        foreground=fg)
        style.configure("Treeview.Heading", background=head, foreground=fg)
        style.map("Treeview", background=[("selected", sel)],
                  foreground=[("selected", selfg)])
        style.configure("TCombobox", fieldbackground=field, foreground=fg,
                        background=bg, arrowcolor=fg)
        style.map("TCombobox",
                  fieldbackground=[("readonly", field), ("disabled", bg)],
                  foreground=[("readonly", fg), ("disabled", "#888888")],
                  selectbackground=[("readonly", field)],
                  selectforeground=[("readonly", fg)])
        for opt, val in (("background", field), ("foreground", fg),
                         ("selectBackground", sel),
                         ("selectForeground", selfg)):
            self.root.option_add(f"*TCombobox*Listbox.{opt}", val)
        style.configure("TEntry", fieldbackground=field, foreground=fg)
        style.configure("TSpinbox", fieldbackground=field, foreground=fg)
        style.configure("TScrollbar", background=bg)
        accent = {"Dark HC": "#ffd400", "Light HC": "#0a246a"}.get(
            pal, "#2f6fc0" if dark else "#2b7de9")
        style.configure("Accent.TButton", background=accent,
                        foreground="#000000" if (dark and hc) else "#ffffff")
        style.configure("Settings.TButton", padding=(10, 4))
        style.configure("Card.TLabel", background=surface, foreground=fg)

    def _restyle_feed_tags(self):
        if not hasattr(self, "feed"):
            return
        table = PALETTES[palette_name(self.theme_name, self.high_contrast)]
        colors = {
            "dns": "#6a2ca0", "secure": "#0b5394", "unsecure": "#0b6b3a",
            "device": "#8a5a00", "other": "#333333", "alert": "#a01a08",
        }
        for tag, hexcolor in colors.items():
            try:
                self.feed.tag_configure(tag, foreground=table.get(hexcolor,
                                                                    hexcolor))
            except tk.TclError:
                pass

    def _restyle_severity_tags(self):
        for tv in (getattr(self, "alerttree", None),
                   getattr(self, "timelinetree", None)):
            if tv is None:
                continue
            for sev, (fg, bg) in self._severity_colors().items():
                try:
                    tv.tag_configure(sev, foreground=fg, background=bg or "")
                except tk.TclError:
                    pass

    def _apply_theme(self, name=None, high_contrast=None):
        if name:
            self.theme_name = name
        if high_contrast is not None:
            self.high_contrast = bool(high_contrast)
        dark = (self.theme_name == "Dark")
        pal = palette_name(self.theme_name, self.high_contrast)
        self.theme = THEMES[pal]
        self._retheme_widget_tree(self.root, pal)
        self._restyle_ttk(dark, self.high_contrast)
        try:
            self.root.configure(background=self.theme["window_bg"])
        except Exception:
            pass
        table = PALETTES[pal]
        for tv in (getattr(self, "tree", None), getattr(self, "feed", None)):
            if tv is None:
                continue
            for tag, (fg, bg) in TAG_COLORS.items():
                try:
                    tv.tag_configure(tag, foreground=table.get(fg, fg),
                                     background=(table.get(bg, bg) if bg
                                                 else ""))
                except tk.TclError:
                    pass
        self._restyle_feed_tags()
        self._restyle_severity_tags()
        self._restyle_mode_banner()
        self._redraw_dashboard()
        self._redraw_map()
        if hasattr(self, "config"):
            self.config.set("appearance.theme", self.theme_name)
            self.config.set("appearance.high_contrast", self.high_contrast)
            self.config.save()

    # ---------- text size (Settings -> Appearance) -------------------------
    TEXT_SIZES = {"Small": 0.9, "Normal": 1.0, "Large": 1.15,
                  "Extra large": 1.3}

    def _apply_text_size(self, label=None):
        label = label or self.config.get("appearance.text_size", "Normal")
        scale = self.TEXT_SIZES.get(label, 1.0)
        base = getattr(self, "_base_font_sizes", None)
        if base is None:
            base = self._base_font_sizes = {}
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont",
                     "TkHeadingFont", "TkCaptionFont", "TkSmallCaptionFont",
                     "TkIconFont", "TkTooltipFont", "TkFixedFont"):
            try:
                f = tkfont.nametofont(name)
            except tk.TclError:
                continue
            if name not in base:
                base[name] = f.cget("size")
            size = base[name]
            f.configure(size=(-1 if size < 0 else 1) *
                        max(6, int(round(abs(size) * scale))))
        try:
            ttk.Style().configure("Treeview", rowheight=int(22 * scale))
        except tk.TclError:
            pass
        self._scale_explicit_fonts(self.root, scale)

    def _scale_explicit_fonts(self, widget, scale):
        """Widgets built with an explicit ("TkDefaultFont", 11, "bold")
        style font don't follow the named fonts, so scale those directly
        (remembering each widget's original size so scaling never compounds)."""
        try:
            has_font = "font" in widget.keys()
        except Exception:
            has_font = False
        if has_font:
            try:
                raw = getattr(widget, "_mw_orig_font", None)
                if raw is None:
                    raw = widget._mw_orig_font = str(widget.cget("font"))
                if raw not in tkfont.names():
                    f = tkfont.Font(root=self.root, font=raw)
                    a = f.actual()
                    size = a["size"]
                    new = (-1 if size < 0 else 1) * max(
                        6, int(round(abs(size) * scale)))
                    parts = [a["family"], new]
                    if a.get("weight") == "bold":
                        parts.append("bold")
                    if a.get("slant") == "italic":
                        parts.append("italic")
                    widget.configure(font=tuple(parts))
            except Exception:
                pass
        try:
            children = widget.winfo_children()
        except Exception:
            children = []
        for child in children:
            self._scale_explicit_fonts(child, scale)

    def _build_ui(self):
        mono = tkfont.nametofont("TkFixedFont").copy(); mono.configure(size=9)
        self.mono = mono

        # ---- header
        header = tk.Frame(self.root, bg="#2b3a55", padx=16, pady=12)
        header.pack(fill="x")
        self.hdr_title = tk.Label(header, text=tr("app_title"), fg="white",
                                  bg="#2b3a55", font=("TkDefaultFont", 16,
                                                      "bold"))
        self.hdr_title.pack(side="left")
        self.hdr_subtitle = tk.Label(header, text=tr("app_subtitle"),
                                     fg="#c8d2e0", bg="#2b3a55")
        self.hdr_subtitle.pack(side="left")
        # packed right-to-left, most important first, so a narrow window
        # squeezes the subtitle rather than clipping controls
        self.btn_settings_w = ttk.Button(header, text=tr("btn_settings"),
                                         command=self._open_settings)
        self.btn_settings_w.pack(side="right", padx=4)
        self.btn_help_w = ttk.Button(header, text=tr("btn_help"),
                                     command=self._open_about)
        self.btn_help_w.pack(side="right", padx=4)
        self.mode_ui_var = tk.StringVar(
            value="Beginner" if self.beginner_mode else "Advanced")
        mode_box = ttk.Combobox(header, textvariable=self.mode_ui_var,
                                values=("Beginner", "Advanced"), width=9,
                                state="readonly")
        mode_box.pack(side="right", padx=(0, 8))
        mode_box.bind("<<ComboboxSelected>>", self._on_ui_mode_change)
        Tooltip(mode_box, "Beginner hides the technical \u201cPackets\u201d "
                          "tab. Nothing is removed \u2014 Advanced shows "
                          "everything.")
        tk.Label(header, text="View", bg="#2b3a55", fg="#c8d2e0").pack(
            side="right", padx=(10, 4))
        ttk.Button(header, text="\U0001F50D", width=3,
                   command=self._run_global_search).pack(side="right",
                                                         padx=(0, 6))
        self.search_var = tk.StringVar()
        se = ttk.Entry(header, textvariable=self.search_var, width=18)
        se.pack(side="right")
        self.search_entry = se
        se.bind("<Return>", lambda e: self._run_global_search())
        Tooltip(se, "Search devices, websites, remote hosts and alerts "
                    "(Ctrl+F).")
        tk.Label(header, text="Search", bg="#2b3a55", fg="#c8d2e0").pack(
            side="right", padx=(10, 4))

        # ---- persistent mode banner (Section 11/51): never hidden, never
        # a stealth feature — only ever tells the truth about whether the
        # app is actively probing your LAN or purely listening.
        self.mode_banner = tk.Frame(self.root, padx=14, pady=6)
        self.mode_banner.pack(fill="x")
        self.mode_lbl = tk.Label(self.mode_banner, anchor="w",
                                 font=("TkDefaultFont", 10, "bold"))
        self.mode_lbl.pack(side="left")
        self.mode_toggle_btn = ttk.Button(
            self.mode_banner, text="Switch to Quiet Mode",
            command=self._toggle_active_scanning)
        self.mode_toggle_btn.pack(side="right")
        self._restyle_mode_banner()

        # ---- friendly (transient) status banner
        self.banner = tk.Frame(self.root, bg="#e8f0fe", padx=14, pady=10)
        self.banner.pack(fill="x")
        self.banner_lbl = tk.Label(
            self.banner,
            text="👋  Welcome! Pick your network card below and click "
                 "“Start watching”. I'll explain what's happening.",
            bg="#e8f0fe", fg="#1a3a6b", anchor="w",
            font=("TkDefaultFont", 11))
        self.banner_lbl.pack(side="left", fill="x", expand=True)

        # ---- toolbar (capture controls only; app-level ones live in the
        # header). Right-hand buttons are packed first so they are never the
        # ones that get clipped on a narrow window.
        bar = ttk.Frame(self.root, padding=(12, 10, 12, 4))
        bar.pack(fill="x")
        ttk.Button(bar, text="Session \u25be",
                  command=self._open_session_menu).pack(side="right")
        ttk.Button(bar, text="Export \u25be",
                  command=self._open_export_menu).pack(side="right",
                                                       padx=(0, 6))
        self.clear_btn = ttk.Button(bar, text=tr("btn_clear"),
                                    command=self.clear)
        self.clear_btn.pack(side="right", padx=(0, 6))
        ttk.Label(bar, text="Network card:").pack(side="left")
        self.iface_var = tk.StringVar()
        self.iface_box = ttk.Combobox(bar, textvariable=self.iface_var,
                                      width=28, state="readonly")
        self.iface_box.pack(side="left", padx=(6, 14))
        ttk.Label(bar, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        fe = ttk.Entry(bar, textvariable=self.filter_var, width=12)
        fe.pack(side="left", padx=(6, 14))
        Tooltip(fe, "Optional (advanced): only capture packets matching a "
                    "BPF filter, e.g. \u201chost 192.168.1.20\u201d. "
                    "Leave empty to see everything.")
        self.start_btn = ttk.Button(bar, text=tr("btn_start"),
                                    style="Accent.TButton", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text=tr("btn_stop"), command=self.stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=6)

        # ---- tabs
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(8, 6))

        self.tab_dash = tk.Frame(self.nb, bg="#ffffff")
        self.tab_feed = tk.Frame(self.nb, bg="#ffffff")
        self.tab_timeline = tk.Frame(self.nb, bg="#ffffff")
        self.tab_devices = tk.Frame(self.nb, bg="#ffffff")
        self.tab_websites = tk.Frame(self.nb, bg="#ffffff")
        self.tab_remote = tk.Frame(self.nb, bg="#ffffff")
        self.tab_alerts = tk.Frame(self.nb, bg="#ffffff")
        self.tab_map = tk.Frame(self.nb, bg="#ffffff")
        self.tab_sec = tk.Frame(self.nb, bg="#ffffff")
        self.tab_raw = tk.Frame(self.nb, bg="#ffffff")
        self.tab_about = tk.Frame(self.nb, bg="#ffffff")

        self.nb.add(self.tab_dash, text=tr("tab_dashboard"))
        self.nb.add(self.tab_feed, text=tr("tab_feed"))
        self.nb.add(self.tab_timeline, text=tr("tab_timeline"))
        self.nb.add(self.tab_devices, text=tr("tab_devices"))
        self.nb.add(self.tab_websites, text=tr("tab_websites"))
        self.nb.add(self.tab_remote, text=tr("tab_remote"))
        self.nb.add(self.tab_alerts, text=tr("tab_alerts"))
        self.nb.add(self.tab_map, text=tr("tab_map"))
        self.nb.add(self.tab_sec, text=tr("tab_security"))
        self.nb.add(self.tab_raw, text=tr("tab_raw"))
        self.nb.add(self.tab_about, text=tr("tab_about"))

        self._build_dashboard_tab()
        self._build_feed_tab()
        self._build_timeline_tab()
        self._build_devices_tab()
        self._build_websites_tab()
        self._build_remote_tab()
        self._build_alerts_tab()
        self._build_map_tab()
        self._build_sec_tab()
        self._build_raw_tab()
        self._build_about_tab()
        self._apply_ui_mode()

        # ---- status bar
        self.status_var = tk.StringVar(
            value="Getting ready — I'll pick a network card and start "
                  "watching automatically.")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", fg="#222222",
                 bg="#e3e6eb", padx=10, pady=5).pack(side="bottom", fill="x")

    def _restyle_mode_banner(self):
        if not hasattr(self, "mode_banner"):
            return
        t = getattr(self, "theme", THEME_LIGHT)
        active = self.config.get("mode.active_scanning", True) if \
            hasattr(self, "config") else True
        if active:
            bg, fg = t["mode_active_bg"], t["mode_active_fg"]
            text = tr("mode_active")
            btn_text = "Switch to Quiet Mode"
        else:
            bg, fg = t["mode_quiet_bg"], t["mode_quiet_fg"]
            text = tr("mode_quiet")
            btn_text = "Switch to Active Scanning"
        self.mode_banner.configure(bg=bg)
        self.mode_lbl.configure(bg=bg, fg=fg, text=text)
        if hasattr(self, "mode_toggle_btn"):
            self.mode_toggle_btn.configure(text=btn_text)
        try:
            Tooltip(self.mode_lbl,
                   "This banner always tells the truth about whether "
                   "MiniWireshark is probing your network or only "
                   "listening. It can never be hidden \u2014 that's a "
                   "transparency guarantee, not a setting.")
        except Exception:
            pass

    def _toggle_active_scanning(self):
        cur = self.config.get("mode.active_scanning", True)
        self.config.set("mode.active_scanning", not cur)
        self.config.save()
        self._restyle_mode_banner()
        if cur and self.lan_scanner is not None:
            # switching to Quiet Mode while running: stop the active probes
            self.lan_scanner.stop_flag = True
            self.lan_scanner = None
            self._set_banner("\U0001F535 Switched to Quiet Mode \u2014 I "
                             "stopped sending discovery probes. I'm still "
                             "watching normally.")
        elif not cur and self.sniffer is not None and \
                self.lan_scanner is None:
            iface_obj = self.iface_map.get(self.iface_var.get())
            my_ip = _iface_ip(iface_obj) or \
                (next(iter(self.my_ips)) if self.my_ips else "")
            self.lan_scanner = LanScanner(iface_obj, my_ip)
            self.lan_scanner.start()
            self._set_banner("\U0001F7E2 Switched to Active Scanning \u2014 "
                             "I'll periodically probe your own LAN for "
                             "quiet devices again.")

    def _on_ui_mode_change(self, _e=None):
        self.beginner_mode = (self.mode_ui_var.get() == "Beginner")
        self.config.set("appearance.beginner_mode", self.beginner_mode)
        self.config.save()
        self._apply_ui_mode()

    def _apply_ui_mode(self):
        """Beginner mode hides advanced technical tabs without removing
        any functionality \u2014 Advanced mode reveals them."""
        advanced_tabs = [getattr(self, "tab_raw", None)]
        for tab in advanced_tabs:
            if tab is None:
                continue
            try:
                if self.beginner_mode:
                    self.nb.hide(tab)
                else:
                    self.nb.add(tab)
            except tk.TclError:
                pass

    def _apply_locale(self):
        """Re-labels every tr()-routed widget. Only English exists today,
        so this is currently a no-op visually, but it's real: add a new
        locale dict to STRINGS and this wiring makes it live immediately,
        no other code changes needed."""
        try:
            self.hdr_title.configure(text=tr("app_title"))
            self.hdr_subtitle.configure(text=tr("app_subtitle"))
            self.btn_settings_w.configure(text=tr("btn_settings"))
            self.btn_help_w.configure(text=tr("btn_help"))
            self.start_btn.configure(text=tr("btn_start"))
            self.stop_btn.configure(text=tr("btn_stop"))
            self.clear_btn.configure(text=tr("btn_clear"))
            for tab, key in ((self.tab_dash, "tab_dashboard"),
                             (self.tab_feed, "tab_feed"),
                             (self.tab_timeline, "tab_timeline"),
                             (self.tab_devices, "tab_devices"),
                             (self.tab_websites, "tab_websites"),
                             (self.tab_remote, "tab_remote"),
                             (self.tab_alerts, "tab_alerts"),
                             (self.tab_map, "tab_map"),
                             (self.tab_sec, "tab_security"),
                             (self.tab_raw, "tab_raw"),
                             (self.tab_about, "tab_about")):
                self.nb.tab(tab, text=tr(key))
        except (tk.TclError, AttributeError):
            pass
        self._restyle_mode_banner()

    def _focus_search(self, _event=None):
        try:
            self.nb.select(self.tab_dash)
        except tk.TclError:
            pass
        try:
            self.search_entry.focus_set()
            self.search_entry.selection_range(0, "end")
        except tk.TclError:
            pass
        return "break"

    def _apply_shortcuts(self):
        """(Re)binds every configurable keyboard shortcut. Safe to call
        repeatedly \u2014 always unbinds its own previous bindings first,
        so remapping in Settings never leaves a stale accelerator active."""
        for seq in getattr(self, "_bound_shortcuts", []):
            try:
                self.root.unbind_all(seq)
            except Exception:
                pass
        self._bound_shortcuts = []
        actions = {
            "start": lambda e=None: self.start(),
            "stop": lambda e=None: self.stop(),
            "clear": lambda e=None: self.clear(),
            "export": lambda e=None: self._open_export_menu(),
            "find": self._focus_search,
        }
        shortcuts = self.config.data.get("shortcuts", DEFAULT_SHORTCUTS)
        for name, seq in shortcuts.items():
            fn = actions.get(name)
            if not fn or not seq:
                continue
            try:
                self.root.bind_all(seq, fn)
                self._bound_shortcuts.append(seq)
            except tk.TclError:
                pass

    def _capture_shortcut(self, parent, name, display_var):
        win = tk.Toplevel(parent)
        win.title("New shortcut")
        win.geometry("320x110")
        win.transient(parent)
        tk.Label(win, text="Press the new key combination now\n"
                          "(Esc to cancel)", pady=24,
                bg=self.theme["tab_bg"], fg=self.theme["text_fg"]).pack(
            fill="both", expand=True)
        win.configure(bg=self.theme["tab_bg"])

        def on_key(event):
            if event.keysym == "Escape":
                win.destroy(); return
            if event.keysym in ("Control_L", "Control_R", "Shift_L",
                               "Shift_R", "Alt_L", "Alt_R"):
                return
            mods = []
            if event.state & 0x4:
                mods.append("Control")
            if event.state & 0x1:
                mods.append("Shift")
            if event.state & 0x20000 or event.state & 0x0008:
                mods.append("Alt")
            seq = "<" + "-".join(mods + [event.keysym]) + ">"
            display_var.set(seq)
            win.destroy()
        win.bind("<KeyPress>", on_key)
        win.focus_set()
        win.grab_set()

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
        self.feed.tag_configure("alert", foreground="#a01a08")

    # ---------- timeline tab (Section 32) ---------------------------------
    def _build_timeline_tab(self):
        top = tk.Frame(self.tab_timeline, bg="#ffffff", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top, text="\U0001F553  Timeline \u2014 new devices, status "
                          "changes, first-time website visits, and alerts "
                          "in one chronological view. Double-click a row "
                          "to jump to it.",
                bg="#ffffff", fg="#333333", wraplength=900, justify="left",
                font=("TkDefaultFont", 11)).pack(anchor="w")
        ctrl = tk.Frame(self.tab_timeline, bg="#ffffff", padx=10)
        ctrl.pack(fill="x")
        tk.Label(ctrl, text="Show:", bg="#ffffff", fg="#333333").pack(side="left")
        self.timeline_zoom_var = tk.StringVar(value="Full session")
        zoom_box = ttk.Combobox(
            ctrl, textvariable=self.timeline_zoom_var,
            values=("Last 5 minutes", "Last hour", "Full session"),
            width=14, state="readonly")
        zoom_box.pack(side="left", padx=(6, 14))
        zoom_box.bind("<<ComboboxSelected>>", lambda e: self._rebuild_timeline())
        tk.Label(ctrl, text="Severity:", bg="#ffffff", fg="#333333").pack(side="left")
        self.timeline_sev_var = tk.StringVar(value="All")
        sev_box = ttk.Combobox(
            ctrl, textvariable=self.timeline_sev_var,
            values=("All", "INFO", "WARNING", "DANGER"), width=10,
            state="readonly")
        sev_box.pack(side="left", padx=(6, 0))
        sev_box.bind("<<ComboboxSelected>>", lambda e: self._rebuild_timeline())

        body = tk.Frame(self.tab_timeline, bg="#ffffff")
        body.pack(fill="both", expand=True)
        cols = ("sev", "when", "kind", "text")
        self.timelinetree = ttk.Treeview(body, columns=cols, show="headings")
        for c, t, w, a in (("sev", "", 36, "center"),
                           ("when", "Time", 80, "center"),
                           ("kind", "Type", 110, "w"),
                           ("text", "What happened", 500, "w")):
            self.timelinetree.heading(c, text=t)
            self.timelinetree.column(c, width=w, anchor=a,
                                     stretch=(c == "text"))
        vs = ttk.Scrollbar(body, orient="vertical",
                           command=self.timelinetree.yview)
        self.timelinetree.configure(yscrollcommand=vs.set)
        self.timelinetree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.timelinetree.bind("<Double-1>", self._on_timeline_double_click)
        for sev, (fg, bg) in self._severity_colors().items():
            self.timelinetree.tag_configure(sev, foreground=fg,
                                            background=bg or "")

    def _rebuild_timeline(self):
        if not hasattr(self, "timelinetree"):
            return
        self.timelinetree.delete(*self.timelinetree.get_children())
        self.timeline_iids.clear()
        zoom = self.timeline_zoom_var.get()
        cutoff = 0
        if zoom == "Last 5 minutes":
            cutoff = time.time() - 300
        elif zoom == "Last hour":
            cutoff = time.time() - 3600
        for entry in self.timeline:
            if entry["when"] >= cutoff:
                self._timeline_insert(entry)

    # ---------- devices tab ---------------------------------------------
    def _build_devices_tab(self):
        top = tk.Frame(self.tab_devices, bg="#ffffff", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top,
                 text="🏠  These are the devices on your local network. "
                      "Confidence reflects how much local evidence "
                      "supports each one \u2014 an IP address alone is "
                      "never enough to count as a device.",
                 bg="#ffffff", fg="#333333", wraplength=900, justify="left",
                 font=("TkDefaultFont", 11)).pack(anchor="w")
        ctrl = tk.Frame(self.tab_devices, bg="#ffffff", padx=10)
        ctrl.pack(fill="x")
        self.show_inactive_var = tk.BooleanVar(
            value=self.config.get("devices.show_inactive", False))
        self.show_expired_var = tk.BooleanVar(
            value=self.config.get("devices.show_expired", False))
        ttk.Checkbutton(ctrl, text="Show inactive devices",
                       variable=self.show_inactive_var,
                       command=self._on_device_visibility_change
                       ).pack(side="left")
        ttk.Checkbutton(ctrl, text="Show expired devices",
                       variable=self.show_expired_var,
                       command=self._on_device_visibility_change
                       ).pack(side="left", padx=(12, 0))
        tk.Label(ctrl, text="  Double-click a device for details.",
                bg="#ffffff", fg="#888888",
                font=("TkDefaultFont", 9)).pack(side="left", padx=(12, 0))

        body = tk.Frame(self.tab_devices, bg="#ffffff")
        body.pack(fill="both", expand=True)
        cols = ("icon", "name", "ip", "mac", "vendor", "confidence",
               "status", "count", "last")
        self.devtree = ttk.Treeview(body, columns=cols, show="headings")
        for c, t, w, a in (("icon", "", 40, "center"),
                           ("name", "What it likely is", 190, "w"),
                           ("ip", "Local IP", 120, "w"),
                           ("mac", "MAC address", 140, "w"),
                           ("vendor", "Made by", 140, "w"),
                           ("confidence", "Confidence", 100, "center"),
                           ("status", "Status", 90, "center"),
                           ("count", "Packets", 70, "e"),
                           ("last", "Last seen", 90, "center")):
            self.devtree.heading(c, text=t)
            self.devtree.column(c, width=w, anchor=a,
                                stretch=(c in ("name", "vendor")))
        vs = ttk.Scrollbar(body, orient="vertical", command=self.devtree.yview)
        self.devtree.configure(yscrollcommand=vs.set)
        self.devtree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.devtree.bind("<Double-1>", self._show_device_details)

    def _on_device_visibility_change(self):
        self.config.set("devices.show_inactive", self.show_inactive_var.get())
        self.config.set("devices.show_expired", self.show_expired_var.get())
        self.config.save()
        for key in list(self.registry.by_key):
            self._redraw_device_row(key)

    def _device_report(self, dev):
        """Sections for the device card, shaped by the explanation settings."""
        verbosity = self.config.get("general.explanation_verbosity", "Normal")
        guidance = self.config.get("general.beginner_explanations", True)
        ts = lambda t: time.strftime("%H:%M:%S", time.localtime(t))
        sections = [("What is it?",
                     f"{dev.display_name()} \u2014 a device on your local "
                     f"network (identity key: {dev.key}).")]
        conf = f"{dev.confidence} (score {dev.score}/100)."
        if guidance:
            conf += " " + (
                "Strongly supported by several independent local signals."
                if dev.confidence == "High" else
                "Take the identity with a grain of salt until more evidence "
                "arrives." if dev.confidence in ("Low", "Unconfirmed") else
                "Reasonably supported; it could still firm up further.")
        sections.append(("How confident is MiniWireshark?", conf))
        if verbosity == "Short":
            return sections
        sections.insert(1, ("What did MiniWireshark see?",
            f"Evidence: {', '.join(dev.evidence_summary()) or 'none yet'}\n"
            f"IP: {dev.ip or '\u2014'}    MAC: {dev.mac or '\u2014'}"
            f"{'  (private/randomized)' if dev.randomized_mac else ''}\n"
            f"Vendor: {dev.vendor or 'Unknown'}\n"
            f"First seen: {ts(dev.first_seen)}    Last seen: "
            f"{ts(dev.last_seen)}\n"
            f"Packets: {dev.packets}    Status: {dev.state.title()}"))
        if dev.identity_conflict:
            sections.append(("Identity conflict", dev.identity_conflict))
        if dev.merge_note:
            sections.append(("Identity correlation", dev.merge_note))
        descs = {service_description(s) for s in dev.services} - {""}
        if descs:
            sections.append(("What can this device do?",
                             "\n".join(f"\u2022 {d}" for d in sorted(descs))))
        if guidance:
            sections.append(("What should I check?", (
                "If you don't recognize this device, check your router's "
                "connected-devices list and, if needed, change your Wi-Fi "
                "password." if dev.confidence in ("Medium", "High") else
                "Confidence is still low \u2014 keep watching; it improves "
                "as more evidence arrives, or fades if the signal doesn't "
                "repeat.")))
        if verbosity == "Detailed":
            weights = {}
            for ev in dev.evidence:
                weights[ev.source] = ev.weight
            sections.append(("How the score was calculated", "\n".join(
                f"+{w:>3}  {EVIDENCE_LABELS.get(s, s)}"
                for s, w in sorted(weights.items(), key=lambda kv: -kv[1]))
                + f"\n= {dev.score}/100 (each kind of evidence counts once)"))
            if dev.protocols:
                sections.append(("Protocols seen", ", ".join(
                    f"{p} \u00d7{n}" for p, n in
                    dev.protocols.most_common(6))))
            sites = sorted((w.domain for w in self.websites.values()
                            if dev.key in w.devices))[:8]
            if sites:
                sections.append(("Websites contacted", ", ".join(sites)))
            if guidance:
                sections.append(("Could this be normal?",
                    "Yes, in most cases: new phones, guests, smart-home "
                    "gadgets and laptops waking from sleep all look like "
                    "this. It only matters if you don't recognize the "
                    "device."))
        return sections

    def _show_device_details(self, _event=None):
        sel = self.devtree.selection()
        if not sel:
            return
        key = None
        for k, iid in self.device_iids.items():
            if iid == sel[0]:
                key = k; break
        dev = self.registry.by_key.get(key) if key else None
        if not dev:
            return
        win = tk.Toplevel(self.root)
        win.title(f"Device: {dev.display_name()}")
        win.geometry("500x600")
        win.configure(bg=self.theme["tab_bg"])
        txt = tk.Text(win, wrap="word", bg=self.theme["text_bg"],
                      fg=self.theme["text_fg"], relief="flat", padx=14,
                      pady=12, font=("TkDefaultFont", 10))
        txt.pack(fill="both", expand=True)
        txt.tag_configure("h", font=("TkDefaultFont", 12, "bold"),
                          spacing3=6)
        for heading, text in self._device_report(dev):
            txt.insert("end", heading + "\n", ("h",))
            txt.insert("end", text + "\n\n")

        candidate = self._find_merge_candidate(dev)
        if candidate:
            txt.insert("end", "Possible identity match\n", ("h",))
            txt.insert("end",
                      f"This device uses a private/randomized MAC, and "
                      f"shares a name (\u201c{dev.display_name()}\u201d) "
                      f"with another entry, {candidate.ip or candidate.mac}. "
                      f"They might be the same physical device seen under "
                      f"two identities \u2014 correlation confidence: "
                      f"Medium (name match only). Merging is optional and "
                      f"can be undone by starting a new session.\n\n")
        txt.config(state="disabled")

        btns = tk.Frame(win, bg=self.theme["tab_bg"])
        btns.pack(fill="x", pady=6)
        var = tk.BooleanVar(value=dev.expected)
        def _toggle_expected():
            dev.expected = var.get()
        ttk.Checkbutton(btns, text="Mark as expected / known",
                       variable=var, command=_toggle_expected).pack(
            side="left", padx=10)
        pin_var = tk.BooleanVar(value=dev.pinned_no_merge)
        def _toggle_pin():
            dev.pinned_no_merge = pin_var.get()
        ttk.Checkbutton(btns, text="Never merge this identity",
                       variable=pin_var, command=_toggle_pin).pack(
            side="left", padx=10)
        if candidate:
            def _do_merge():
                self._merge_devices(dev.key, candidate.key)
                win.destroy()
            ttk.Button(btns, text=f"Merge with {candidate.display_name()}",
                      command=_do_merge).pack(side="right", padx=10)

    _GENERIC_NAME = re.compile(
        r"^(iphone|ipad|android|galaxy|pixel|macbook|laptop|desktop|phone|"
        r"tablet|unknown|localhost|device|host|router|windows|linux)"
        r"[-_ ]?[a-z0-9]{0,3}$")

    def _stable_name(self, dev):
        """A name the device announced itself (DHCP hostname / mDNS) — never
        a reverse-DNS guess."""
        return (dev.dhcp_hostname or dev.mdns_name or "").strip().lower()

    def _auto_merge_pass(self):
        """Settings -> Devices -> 'Combine identities automatically'.

        Deliberately conservative — merges only when ALL hold: exactly two
        candidates share a distinctive self-announced name; at least one uses
        a private/randomized MAC; their activity never overlapped (a device
        can't be two at once); neither is pinned. Never merges on traffic
        similarity. Every merge is recorded on the timeline and explained on
        the device card."""
        if not self.config.get("devices.auto_merge", True):
            return 0
        groups = defaultdict(list)
        for dev in self.registry.by_key.values():
            if dev.pinned_no_merge or dev.state == STATE_EXPIRED:
                continue
            name = self._stable_name(dev)
            if len(name) < 6 or self._GENERIC_NAME.match(name):
                continue
            groups[name].append(dev)
        merged = 0
        for name, devs in groups.items():
            if len(devs) != 2:
                continue
            older, newer = sorted(devs, key=lambda d: d.first_seen)
            if not (older.randomized_mac or newer.randomized_mac):
                continue
            if older.state == STATE_ACTIVE:
                continue
            if older.last_confirmed > newer.first_seen + 60:
                continue
            self._merge_devices(newer.key, older.key, auto=True)
            merged += 1
        return merged

    def _find_merge_candidate(self, dev):
        """Section 8: only ever suggested, never automatic, and only for
        randomized-MAC devices that share a name with exactly one other
        un-pinned device \u2014 a name match is Medium confidence at best."""
        if not dev.randomized_mac or dev.pinned_no_merge:
            return None
        name = (dev.hostname or dev.dhcp_hostname or dev.mdns_name or "").lower()
        if not name:
            return None
        matches = []
        for other in self.registry.by_key.values():
            if other.key == dev.key or other.pinned_no_merge:
                continue
            oname = (other.hostname or other.dhcp_hostname or
                    other.mdns_name or "").lower()
            if oname == name:
                matches.append(other)
        return matches[0] if len(matches) == 1 else None

    def _merge_devices(self, keep_key, other_key, auto=False):
        keep = self.registry.by_key.get(keep_key)
        other = self.registry.by_key.get(other_key)
        if not keep or not other or keep is other:
            return
        keep.first_seen = min(keep.first_seen, other.first_seen)
        keep.last_seen = max(keep.last_seen, other.last_seen)
        keep.packets += other.packets
        keep.bytes_up += other.bytes_up
        keep.bytes_down += other.bytes_down
        keep.services |= other.services
        keep.websites |= other.websites
        keep.ipv6 |= other.ipv6
        keep.hostname = keep.hostname or other.hostname
        keep.dhcp_hostname = keep.dhcp_hostname or other.dhcp_hostname
        keep.mdns_name = keep.mdns_name or other.mdns_name
        keep.vendor = keep.vendor or other.vendor
        keep.evidence.extend(other.evidence)
        keep.add_evidence("mac_local", f"Merged with identity {other.key}")
        if other.ip:
            self.registry.ip_to_key[other.ip] = keep.key
        del self.registry.by_key[other_key]
        old_iid = self.device_iids.pop(other_key, None)
        if old_iid:
            try:
                self.devtree.delete(old_iid)
            except tk.TclError:
                pass
        name = (keep.dhcp_hostname or keep.mdns_name or keep.hostname
                or keep.display_name())
        keep.merged_from.append(other.key)
        keep.merge_note = (
            f"Merged with an earlier identity ({other.key}) "
            f"{'automatically' if auto else 'by you'}: both advertised the "
            f"name \u201c{name}\u201d and were never active at the same "
            f"time. Correlation confidence: Medium (name match).")
        self._redraw_device_row(keep.key)
        self._timeline_push(
            "identity merged", "INFO",
            f"{keep.display_name()}: two identities combined "
            f"({'automatic' if auto else 'manual'})",
            ("tab_devices", "device_iids", keep.key))
        if not auto:
            self._set_banner(f"\U0001F517  Merged two identities into "
                             f"{keep.display_name()}.")

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

    # ---------- remote hosts tab (Section 27) ----------------------------
    def _build_remote_tab(self):
        top = tk.Frame(self.tab_remote, bg="#ffffff", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top,
                 text="\U0001F5A5  REMOTE HOST \u2014 public Internet "
                      "addresses your devices talked to directly. These "
                      "are never devices on your network \u2014 they live "
                      "somewhere out on the Internet.",
                 bg="#ffffff", fg="#333333", wraplength=900, justify="left",
                 font=("TkDefaultFont", 11)).pack(anchor="w")
        geo = tk.Frame(self.tab_remote, bg="#ffffff", padx=10)
        geo.pack(fill="x", pady=(0, 6))
        self.geoip_var = tk.BooleanVar(
            value=self.config.get("privacy.geoip_enabled", False))
        cb = ttk.Checkbutton(
            geo, text="Show each host's country",
            variable=self.geoip_var,
            command=lambda: self._set_geoip_enabled(self.geoip_var.get()))
        cb.pack(side="left")
        Tooltip(cb, "Sends each remote IP address (never your own devices, "
                    "never packet contents) to a public geolocation service "
                    "to find its country. Off by default.")
        ttk.Button(geo, text="Test", width=6,
                   command=self._geoip_test).pack(side="left", padx=(10, 0))
        ttk.Button(geo, text="Retry failed", width=12,
                   command=self._geoip_retry).pack(side="left", padx=(6, 0))
        self.geoip_status_var = tk.StringVar()
        tk.Label(geo, textvariable=self.geoip_status_var, bg="#ffffff",
                 fg="#666666", justify="left", anchor="w", wraplength=620,
                 font=("TkDefaultFont", 9)).pack(side="left", padx=(14, 0))
        self._update_geoip_status()
        body = tk.Frame(self.tab_remote, bg="#ffffff")
        body.pack(fill="both", expand=True)
        cols = ("ip", "country", "domain", "ports", "protocols", "who",
               "packets", "first", "last")
        self.remotetree = ttk.Treeview(body, columns=cols, show="headings")
        for c, t, w, a in (("ip", "Remote IP", 130, "w"),
                           ("country", "Country", 150, "w"),
                           ("domain", "Known name", 190, "w"),
                           ("ports", "Ports", 100, "w"),
                           ("protocols", "Protocol(s)", 100, "w"),
                           ("who", "Contacted by", 170, "w"),
                           ("packets", "Packets", 70, "e"),
                           ("first", "First seen", 90, "center"),
                           ("last", "Last seen", 90, "center")):
            self.remotetree.heading(c, text=t)
            self.remotetree.column(c, width=w, anchor=a,
                                   stretch=(c in ("domain", "who")))
        vs = ttk.Scrollbar(body, orient="vertical",
                           command=self.remotetree.yview)
        self.remotetree.configure(yscrollcommand=vs.set)
        self.remotetree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

    # ---------- dashboard tab (Section 24) --------------------------------
    def _build_dashboard_tab(self):
        outer = tk.Frame(self.tab_dash, bg="#ffffff", padx=16, pady=14)
        outer.pack(fill="both", expand=True)
        tk.Label(outer, text="\U0001F4CA  Dashboard", bg="#ffffff",
                fg="#2b3a56", font=("TkDefaultFont", 14, "bold")).pack(
            anchor="w")
        tk.Label(outer, text="A quick overview \u2014 open any tab for the "
                            "full picture.", bg="#ffffff",
                fg="#666666").pack(anchor="w", pady=(0, 10))

        cards = tk.Frame(outer, bg="#ffffff")
        cards.pack(fill="x")
        self.dash_vars = {}
        for key, title in (("devices", "LOCAL DEVICES"),
                           ("websites", "WEBSITES"),
                           ("traffic", "TRAFFIC"),
                           ("alerts", "ALERTS")):
            card = tk.Frame(cards, bg="#f6f7fa", padx=14, pady=10,
                           highlightbackground="#e0e2e8", highlightthickness=1)
            card.pack(side="left", padx=(0, 12), fill="both", expand=True)
            tk.Label(card, text=title, bg="#f6f7fa", fg="#888888",
                    font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
            v = tk.StringVar(value="\u2014")
            tk.Label(card, textvariable=v, bg="#f6f7fa", fg="#222222",
                    font=("TkDefaultFont", 15, "bold"),
                    justify="left").pack(anchor="w", pady=(4, 0))
            self.dash_vars[key] = v

        tk.Label(outer, text="Network state", bg="#ffffff", fg="#2b3a56",
                font=("TkDefaultFont", 12, "bold")).pack(anchor="w",
                                                         pady=(18, 2))
        self.dash_state_var = tk.StringVar(value="Getting started \u2026")
        self.dash_state_lbl = tk.Label(
            outer, textvariable=self.dash_state_var, bg="#eef4fb",
            fg="#0b5394", font=("TkDefaultFont", 11), anchor="w",
            justify="left", wraplength=900, padx=12, pady=10)
        self.dash_state_lbl.pack(fill="x", pady=(0, 12))

        tk.Label(outer, text="Bandwidth by device (this session)",
                bg="#ffffff", fg="#2b3a56",
                font=("TkDefaultFont", 12, "bold")).pack(anchor="w")
        self.bw_canvas = tk.Canvas(outer, bg="#ffffff", height=220,
                                   highlightthickness=0)
        self.bw_canvas.pack(fill="x", pady=(6, 0))

    def _redraw_dashboard(self):
        if not hasattr(self, "dash_vars"):
            return
        devs = self.registry.visible_devices()
        active = sum(1 for d in devs if d.state in (STATE_ACTIVE, STATE_IDLE))
        inactive = sum(1 for d in devs if d.state == STATE_INACTIVE)
        self.dash_vars["devices"].set(f"{active} active\n{inactive} inactive")
        self.dash_vars["websites"].set(f"{len(self.websites)} observed")
        total_bytes = sum(d.bytes_up for d in self.registry.by_key.values())
        self.dash_vars["traffic"].set(_human_bytes(total_bytes))
        n_warn = sum(1 for i in self.alert_engine.order
                    if self.alert_engine.alerts[i].severity == "WARNING")
        n_danger = sum(1 for i in self.alert_engine.order
                      if self.alert_engine.alerts[i].severity == "DANGER")
        self.dash_vars["alerts"].set(f"{n_warn} warnings\n{n_danger} dangers")

        if n_danger:
            state, bg, fg = ("Investigate \u2014 one or more DANGER alerts "
                             "need a look.", self.theme["danger_bg"],
                             self.theme["danger_fg"])
        elif n_warn:
            state, bg, fg = ("Attention \u2014 a few things are worth a "
                             "glance, nothing urgent.", self.theme["warn_bg"],
                             self.theme["warn_fg"])
        elif self.sniffer is None:
            state, bg, fg = ("Not watching right now.",
                             self.theme["tab_bg"], self.theme["muted_fg"])
        else:
            state, bg, fg = ("Healthy \u2014 nothing unusual noticed so far.",
                             self.theme["mode_active_bg"],
                             self.theme["good_fg"])
        if time.time() < self._discovering_until:
            state = "Discovering your network \u2026 " + state
        self.dash_state_var.set(state)
        try:
            self.dash_state_lbl.configure(bg=bg, fg=fg)
        except tk.TclError:
            pass
        self._redraw_bandwidth_chart()

    def _redraw_bandwidth_chart(self):
        c = self.bw_canvas
        try:
            c.delete("all")
            w = c.winfo_width() or 800
        except tk.TclError:
            return
        devs = sorted((d for d in self.registry.visible_devices()
                      if d.bytes_up > 0),
                     key=lambda d: -d.bytes_up)[:8]
        if not devs:
            c.create_text(10, 20, anchor="w", fill=self.theme["muted_fg"],
                          text="No traffic measured yet.")
            return
        top = max(d.bytes_up for d in devs) or 1
        y = 14
        for dev in devs:
            label = dev.display_name()
            frac = dev.bytes_up / top
            bar_w = max(4, int((w - 220) * frac))
            c.create_text(8, y + 9, anchor="w", fill=self.theme["text_fg"],
                          text=label[:26], font=("TkDefaultFont", 9))
            c.create_rectangle(180, y, 180 + bar_w, y + 18,
                               fill="#2b7de9", outline="")
            c.create_text(180 + bar_w + 6, y + 9, anchor="w",
                          fill=self.theme["muted_fg"],
                          text=_human_bytes(dev.bytes_up),
                          font=("TkDefaultFont", 9))
            y += 26

    # ---------- alerts tab (Section 15-19) --------------------------------
    def _build_alerts_tab(self):
        top = tk.Frame(self.tab_alerts, bg="#ffffff", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top, text="\U0001F514  Alerts \u2014 every row separates "
                          "what was observed from what it might mean. "
                          "Nothing here is called an attack without "
                          "strong evidence.",
                bg="#ffffff", fg="#333333", wraplength=900, justify="left",
                font=("TkDefaultFont", 11)).pack(anchor="w")
        legend = tk.Frame(top, bg="#ffffff")
        legend.pack(anchor="w", pady=(6, 0))
        for icon, name, fg in (("\u2139", tr("legend_info"), "#333333"),
                               ("\u26a0", tr("legend_warning"), "#8a5a00"),
                               ("\u203c", tr("legend_danger"), "#a01a08")):
            tk.Label(legend, text=f"{icon} {name}", bg="#ffffff", fg=fg,
                    font=("TkDefaultFont", 9)).pack(side="left", padx=(0, 16))

        body = tk.Frame(self.tab_alerts, bg="#ffffff")
        body.pack(fill="both", expand=True)
        cols = ("sev", "when", "reason", "device")
        self.alerttree = ttk.Treeview(body, columns=cols, show="headings")
        for c, t, w, a in (("sev", "", 40, "center"),
                           ("when", "Time", 80, "center"),
                           ("reason", "What happened", 420, "w"),
                           ("device", "Related to", 200, "w")):
            self.alerttree.heading(c, text=t)
            self.alerttree.column(c, width=w, anchor=a,
                                  stretch=(c == "reason"))
        vs = ttk.Scrollbar(body, orient="vertical",
                           command=self.alerttree.yview)
        self.alerttree.configure(yscrollcommand=vs.set)
        self.alerttree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.alerttree.bind("<Double-1>", self._show_alert_details)
        for sev, (fg, bg) in self._severity_colors().items():
            self.alerttree.tag_configure(sev, foreground=fg,
                                         background=bg or "")

    def _add_alert_row(self, alert):
        icon = self.SEVERITY_ICON.get(alert.severity, "")
        when_txt = time.strftime("%H:%M:%S", time.localtime(alert.when))
        dev = self.registry.by_key.get(alert.device_key)
        who = dev.display_name() if dev else (alert.device_key or "\u2014")
        try:
            iid = self.alerttree.insert(
                "", 0, tags=(alert.severity,),
                values=(icon, when_txt, alert.reason, who))
            self.alert_iids[alert.id] = iid
        except tk.TclError:
            pass
        if alert.severity in ("WARNING", "DANGER") and \
                self.config.get("notifications.feed_alerts", True) and \
                (alert.severity == "DANGER" or
                 not self.config.get("notifications.danger_only", False)):
            self._feed_push("alert" if alert.severity == "DANGER" else "other",
                            who, f"{icon} {alert.reason}")
        self._timeline_push("alert", alert.severity, alert.reason,
                            ("tab_alerts", "alert_iids", alert.id))

    def _timeline_push(self, kind, severity, text, ref=None):
        entry = {"when": time.time(), "kind": kind, "severity": severity,
                 "text": text, "ref": ref}
        self.timeline.append(entry)
        self._timeline_insert(entry)

    def _timeline_insert(self, entry):
        if not hasattr(self, "timelinetree"):
            return
        sev_filter = getattr(self, "timeline_sev_var", None)
        if sev_filter and sev_filter.get() != "All" and \
                sev_filter.get() != entry["severity"]:
            return
        icon = self.SEVERITY_ICON.get(entry["severity"], "\u2022")
        when_txt = time.strftime("%H:%M:%S", time.localtime(entry["when"]))
        try:
            iid = self.timelinetree.insert(
                "", 0, tags=(entry["severity"],),
                values=(icon, when_txt, entry["kind"], entry["text"]))
            self.timeline_iids[iid] = entry.get("ref")
            children = self.timelinetree.get_children()
            if len(children) > 800:
                for old in children[800:]:
                    self.timeline_iids.pop(old, None)
                    self.timelinetree.delete(old)
        except tk.TclError:
            pass

    def _on_timeline_double_click(self, _event=None):
        sel = self.timelinetree.selection()
        if not sel:
            return
        ref = self.timeline_iids.get(sel[0])
        if not ref:
            return
        tab_attr, iid_map_attr, key = ref
        tab = getattr(self, tab_attr, None)
        iid_map = getattr(self, iid_map_attr, None)
        if tab is None or iid_map is None:
            return
        try:
            self.nb.select(tab)
        except tk.TclError:
            return
        iid = iid_map.get(key)
        tree = {"tab_devices": getattr(self, "devtree", None),
               "tab_alerts": getattr(self, "alerttree", None),
               "tab_websites": getattr(self, "sitetree", None),
               "tab_remote": getattr(self, "remotetree", None)}.get(tab_attr)
        if iid and tree is not None:
            try:
                tree.selection_set(iid)
                tree.see(iid)
            except tk.TclError:
                pass

    def _alert_report(self, alert):
        """Sections for an alert, shaped by the explanation settings
        (Settings -> General): verbosity Short/Normal/Detailed, and whether
        plain-English guidance is shown at all."""
        verbosity = self.config.get("general.explanation_verbosity", "Normal")
        guidance = self.config.get("general.beginner_explanations", True)
        sections = [("OBSERVED", alert.observed)]
        if verbosity == "Short":
            return sections
        sections.append(("INTERPRETATION", alert.interpretation))
        if guidance:
            sections.append(("POSSIBLE EXPLANATIONS",
                             alert.possible_explanations))
        if verbosity == "Detailed":
            steps = ALERT_CHECKLIST.get(alert.kind)
            if steps and guidance:
                sections.append(("WHAT TO CHECK", "\n".join(
                    f"{i}. {s}" for i, s in enumerate(steps, 1))))
            dev = self.registry.by_key.get(alert.device_key)
            meta = [f"Type: {ALERT_TYPES.get(alert.kind, (alert.kind,))[0]}",
                    f"Severity: {alert.severity}",
                    "Time: " + time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.localtime(alert.when))]
            if dev:
                meta.append(f"Device: {dev.display_name()} "
                            f"({dev.ip or dev.mac or dev.key})")
            sections.append(("DETAILS", "\n".join(meta)))
        return sections

    def _show_alert_details(self, _event=None):
        sel = self.alerttree.selection()
        if not sel:
            return
        alert = None
        for aid, iid in self.alert_iids.items():
            if iid == sel[0]:
                alert = self.alert_engine.alerts.get(aid); break
        if not alert:
            return
        win = tk.Toplevel(self.root)
        win.title(alert.reason)
        win.geometry("480x400")
        win.configure(bg=self.theme["tab_bg"])
        txt = tk.Text(win, wrap="word", bg=self.theme["text_bg"],
                      fg=self.theme["text_fg"], relief="flat", padx=14,
                      pady=12, font=("TkDefaultFont", 10))
        txt.pack(fill="both", expand=True)
        txt.tag_configure("h", font=("TkDefaultFont", 11, "bold"),
                          spacing3=4)
        for label, val in self._alert_report(alert):
            txt.insert("end", label + "\n", ("h",))
            txt.insert("end", val + "\n\n")
        txt.config(state="disabled")

    # ---------- about / help tab (Section 52) -----------------------------
    def _build_about_tab(self):
        outer = tk.Frame(self.tab_about, bg="#ffffff")
        outer.pack(fill="both", expand=True, padx=14, pady=12)
        tk.Label(outer, text="\u2753  Help / About", bg="#ffffff",
                fg="#2b3a56", font=("TkDefaultFont", 14, "bold")).pack(
            anchor="w")
        txt = tk.Text(outer, wrap="word", bg="#fbfbfb", fg="#222222", relief="flat",
                      padx=14, pady=12, font=("TkDefaultFont", 10),
                      state="normal")
        vs = ttk.Scrollbar(outer, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=vs.set)
        txt.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        txt.tag_configure("h", font=("TkDefaultFont", 12, "bold"),
                          foreground="#2b3a56", spacing1=8, spacing3=3)
        for term, defn in GLOSSARY:
            txt.insert("end", term + "\n", ("h",))
            txt.insert("end", defn + "\n\n")
        txt.insert("end", "Privacy\n", ("h",))
        txt.insert("end",
                  "MiniWireshark processes captured network information "
                  "locally on this computer unless you explicitly export "
                  "it. It does not silently upload packet data or contact "
                  "any third-party intelligence service. Settings and any "
                  "exported files are stored locally, next to the script, "
                  "and are entirely under your control.\n\n")
        txt.config(state="disabled")

    def _open_about(self):
        try:
            self.nb.select(self.tab_about)
        except tk.TclError:
            pass

    def _drain_async_results(self):
        """The only safe hand-off point from a background thread (update
        checker, GeoIP lookups) back to the GUI. Worker threads never call
        Tkinter methods themselves \u2014 they just push a callable here,
        thread-safely, and this main-thread-scheduled poller runs it."""
        try:
            while True:
                fn = self._async_results.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        self.root.after(200, self._drain_async_results)

    # ---------- update checker (opt-in, Section 22/48) ---------------------
    def _check_for_updates(self, manual=True):
        repo = self.config.get("updates.repo", "").strip()
        if not repo:
            if manual:
                messagebox.showinfo(
                    "Check for updates",
                    "No update source is configured yet. If you host this "
                    "script's releases on GitHub, set “owner/repo” in "
                    "Settings \u2192 General first \u2014 MiniWireshark "
                    "will never guess one on its own.")
            return

        def worker():
            try:
                url = f"https://api.github.com/repos/{repo}/releases/latest"
                req = urllib.request.Request(
                    url, headers={"User-Agent": "MiniWireshark",
                                 "Accept": "application/vnd.github+json"})
                with urllib.request.urlopen(req, timeout=6) as resp:
                    data = json.loads(resp.read().decode("utf-8", "ignore"))
                tag = str(data.get("tag_name", "")).lstrip("v")
                html_url = data.get("html_url", "")
                self._async_results.put(lambda: self._report_update_result(
                    tag, html_url, None, manual))
            except Exception as e:
                msg = str(e)
                self._async_results.put(lambda: self._report_update_result(
                    None, "", msg, manual))
        threading.Thread(target=worker, daemon=True).start()

    def _report_update_result(self, tag, url, err, manual):
        if err is not None:
            if manual:
                self._set_banner(
                    f"\u26a0\ufe0f  Couldn't check for updates ({err}).",
                    kind="warn")
            return
        if tag and tag != SCRIPT_VERSION:
            self._set_banner(
                f"\u2b06\ufe0f  A newer version ({tag}) is available. "
                f"{url}", kind="warn")
        elif manual:
            self._set_banner(
                f"\u2705  You're on the latest version ({SCRIPT_VERSION}).")

    # ---------- country lookup (opt-in, Section 27/48) ----------------------
    def _lookup_country(self, ip):
        """Ask the GeoIP service about a remote host. A no-op unless the
        user turned the feature on; the service dedupes, paces and retries."""
        self.geoip.request(ip)

    def _geoip_on_result(self, ip, code, name, provider):
        # runs on the GeoIP worker thread: only hand off, never touch Tk
        self._async_results.put(lambda: self._apply_country(ip, code, name))

    def _apply_country(self, ip, code, name=""):
        rec = self.remote_hosts.get(ip)
        if rec:
            rec.country, rec.country_name = code, name
            self._redraw_remote_row(ip)

    def _set_geoip_enabled(self, on, save=True):
        """Single switch used by the Remote hosts checkbox AND Settings, so
        they can never disagree. Turning it on immediately looks up every
        remote host already seen, not just future ones."""
        on = bool(on)
        self.config.set("privacy.geoip_enabled", on)
        if save:
            self.config.save()
        self.geoip.set_enabled(on)
        if hasattr(self, "geoip_var") and self.geoip_var.get() != on:
            self.geoip_var.set(on)
        sw = getattr(self, "_settings_win", None)
        if sw is not None and sw.alive():
            sw.sync_key("privacy.geoip_enabled", on)
        if on:
            for ip, rec in self.remote_hosts.items():
                if not rec.country:
                    self.geoip.request(ip)
        self._update_geoip_status()

    def _geoip_status_text(self):
        st = self.geoip.status()
        if not st["enabled"]:
            return ("Country lookup is off. Turn it on to see which country "
                    "each remote host is in (each IP is sent to a public "
                    "lookup service).")
        parts = [f"{st['resolved']} looked up"]
        if st["pending"]:
            parts.append(f"{st['pending']} waiting")
        if st["failed"]:
            parts.append(f"{st['failed']} failed")
        head = "Country lookup ON \u2014 " + ", ".join(parts)
        if st["provider"]:
            head += f"  \u00b7 via {st['provider']}"
        if st["paused"]:
            head += (f"\n\u26a0 Can't reach any lookup service right now; "
                     f"trying again in {st['paused']}s. Check your internet "
                     f"connection or firewall.")
        elif st["last_error"] and st["failed"]:
            head += f"\n\u26a0 {st['last_error'][:230]}"
        return head

    def _update_geoip_status(self):
        if hasattr(self, "geoip_status_var"):
            self.geoip_status_var.set(self._geoip_status_text())

    def _geoip_retry(self):
        n = self.geoip.retry_failed()
        for ip, rec in self.remote_hosts.items():
            if not rec.country:
                self.geoip.request(ip)
        self._set_banner(f"\U0001F30D  Retrying country lookups "
                         f"({n} that had failed).")
        self._update_geoip_status()

    def _geoip_test(self, parent=None):
        """Diagnose the feature end-to-end: look up a well-known address and
        say exactly which provider answered or why each one failed."""
        if not self.config.get("privacy.geoip_enabled", False):
            if not messagebox.askyesno(
                    "Test country lookup",
                    "Country lookup is currently off. The test sends one "
                    "well-known public address (8.8.8.8) to the lookup "
                    "service. Run the test?", parent=parent or self.root):
                return
        self._set_banner("\U0001F30D  Testing country lookup\u2026")

        def worker():
            code, name, provider, errors = self.geoip.lookup_now("8.8.8.8")
            self._async_results.put(
                lambda: self._geoip_test_done(code, name, provider, errors,
                                              parent))
        threading.Thread(target=worker, daemon=True).start()

    def _geoip_test_done(self, code, name, provider, errors, parent):
        parent = parent if parent is not None else self.root
        try:
            if code:
                self._set_banner(f"\u2705  Country lookup works "
                                 f"({provider}: 8.8.8.8 \u2192 {code}).")
                messagebox.showinfo(
                    "Test country lookup",
                    f"Working.\n\n{provider} answered: 8.8.8.8 is in "
                    f"{name or code} ({code}).", parent=parent)
            else:
                self._set_banner("\u26a0\ufe0f  Country lookup can't reach "
                                 "any service.", kind="warn")
                messagebox.showwarning(
                    "Test country lookup",
                    "None of the lookup services answered:\n\n" +
                    "\n".join(f"\u2022 {e}" for e in errors) +
                    "\n\nCommon causes: no internet, a firewall or proxy "
                    "blocking these sites, or a very restrictive network.",
                    parent=parent)
        except tk.TclError:
            pass

    # ---------- network map: topology + connections (Sections 28, 35) -----
    def _build_map_tab(self):
        top = tk.Frame(self.tab_map, bg="#ffffff", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top, text="\U0001F5FA  Network map", bg="#ffffff",
                fg="#333333", font=("TkDefaultFont", 11, "bold")).pack(
            anchor="w")
        ctrl = tk.Frame(self.tab_map, bg="#ffffff", padx=10)
        ctrl.pack(fill="x")
        self.map_mode_var = tk.StringVar(value="Topology")
        ttk.Radiobutton(ctrl, text="Topology (your LAN)",
                       variable=self.map_mode_var, value="Topology",
                       command=self._redraw_map).pack(side="left")
        ttk.Radiobutton(ctrl, text="Connections (device \u2192 website \u2192 "
                                  "remote host)",
                       variable=self.map_mode_var, value="Connections",
                       command=self._redraw_map).pack(side="left",
                                                       padx=(14, 0))
        tk.Label(ctrl, text="   Device filter:", bg="#ffffff", fg="#333333").pack(
            side="left", padx=(16, 4))
        self.map_device_var = tk.StringVar(value="All devices")
        self.map_device_box = ttk.Combobox(
            ctrl, textvariable=self.map_device_var, state="readonly",
            width=24, values=("All devices",))
        self.map_device_box.pack(side="left")
        self.map_device_box.bind("<<ComboboxSelected>>",
                                 lambda e: self._redraw_map())

        self.map_canvas = tk.Canvas(self.tab_map, bg="#ffffff",
                                    highlightthickness=0)
        self.map_canvas.pack(fill="both", expand=True, padx=10, pady=8)
        self.map_canvas.bind("<Configure>", lambda e: self._redraw_map())

    def _redraw_map(self):
        if not hasattr(self, "map_canvas"):
            return
        c = self.map_canvas
        try:
            c.delete("all")
            w = c.winfo_width()
            h = c.winfo_height()
        except tk.TclError:
            return
        if w < 20 or h < 20:
            return
        labels = ["All devices"] + sorted(
            d.display_name() for d in self.registry.visible_devices())
        if tuple(self.map_device_box["values"]) != tuple(labels):
            self.map_device_box["values"] = labels
        c.configure(bg=self.theme["tab_bg"])
        if self.map_mode_var.get() == "Topology":
            self._draw_topology(c, w, h)
        else:
            self._draw_connections(c, w, h)

    def _filtered_devices(self):
        devs = [d for d in self.registry.visible_devices()
               if d.state in (STATE_ACTIVE, STATE_IDLE)]
        filt = getattr(self, "map_device_var", None)
        filt = filt.get() if filt else "All devices"
        if filt != "All devices":
            devs = [d for d in devs if d.display_name() == filt]
        return devs

    def _draw_topology(self, c, w, h):
        t = self.theme
        cx, cy = w * 0.32, h / 2
        devs = self._filtered_devices()[:16]
        radius = max(60, min(h, w * 0.5) * 0.36)
        n = max(len(devs), 1)
        conf_color = {"High": "#0b6b3a", "Medium": "#8a5a00",
                     "Low": "#a05608", "Unconfirmed": "#888888"}
        for i, dev in enumerate(devs):
            ang = (2 * math.pi * i) / n - math.pi / 2
            x = cx + radius * 0.62 * math.cos(ang)
            y = cy + radius * 0.62 * math.sin(ang)
            c.create_line(cx, cy, x, y, fill=t["muted_fg"])
            fill = conf_color.get(dev.confidence, "#888888")
            c.create_oval(x - 9, y - 9, x + 9, y + 9, fill=fill, outline="")
            c.create_text(x, y + 15, text=dev.display_name()[:16],
                          fill=t["text_fg"], font=("TkDefaultFont", 8))
        c.create_oval(cx - radius, cy - radius, cx + radius, cy + radius,
                     outline=t["muted_fg"], dash=(4, 3))
        c.create_text(cx, cy - radius - 14, text="LOCAL NETWORK",
                      fill=t["muted_fg"], font=("TkDefaultFont", 9, "bold"))
        c.create_oval(cx - 17, cy - 17, cx + 17, cy + 17, fill="#2b7de9",
                     outline="")
        c.create_text(cx, cy + 30, text="Your router", fill=t["text_fg"],
                      font=("TkDefaultFont", 9, "bold"))
        remotes = sorted(self.remote_hosts.values(),
                         key=lambda r: -r.packets)[:6]
        rx0 = min(cx + radius + 70, w - 90)
        ry0 = cy - (len(remotes) * 22) / 2
        if remotes:
            c.create_text(rx0 + 40, max(20, ry0 - 16), text="INTERNET",
                          fill=t["muted_fg"], font=("TkDefaultFont", 9, "bold"))
        for i, r in enumerate(remotes):
            ry = ry0 + i * 22
            c.create_line(cx + radius, cy, rx0, ry, fill=t["muted_fg"],
                         dash=(2, 2))
            c.create_oval(rx0 - 6, ry - 6, rx0 + 6, ry + 6, fill="#888888",
                         outline="")
            c.create_text(rx0 + 12, ry, anchor="w",
                          text=(r.domain or r.ip)[:24], fill=t["text_fg"],
                          font=("TkDefaultFont", 8))
        if not devs and not remotes:
            c.create_text(20, 20, anchor="nw", fill=t["muted_fg"],
                          text="Nothing to show yet \u2014 start watching "
                               "and browse for a bit.")

    def _draw_connections(self, c, w, h):
        t = self.theme
        devs = self._filtered_devices()[:10]
        dev_keys = {d.key for d in devs}
        filt_active = getattr(self, "map_device_var", None)
        filt_active = filt_active.get() != "All devices" if filt_active else False
        sites = sorted(self.websites.values(), key=lambda s: -s.requests)
        remotes = sorted(self.remote_hosts.values(), key=lambda r: -r.packets)
        if filt_active:
            sites = [s for s in sites if s.devices & dev_keys]
            remotes = [r for r in remotes if r.devices & dev_keys]
        sites, remotes = sites[:10], remotes[:10]

        col_x = (w * 0.14, w * 0.5, w * 0.86)
        for label, x in zip(("Devices", "Websites", "Remote hosts"), col_x):
            c.create_text(x, 14, text=label, fill=t["muted_fg"],
                          font=("TkDefaultFont", 9, "bold"))

        def positions(items, keyfn):
            n = max(len(items), 1)
            step = (h - 40) / n
            return {keyfn(it): (30 + step * (i + 0.5))
                   for i, it in enumerate(items)}

        dev_y = positions(devs, lambda d: d.key)
        site_y = positions(sites, lambda s: s.domain)
        remote_y = positions(remotes, lambda r: r.ip)

        for s in sites:
            sy = site_y[s.domain]
            for dk in s.devices:
                if dk in dev_y:
                    c.create_line(col_x[0], dev_y[dk], col_x[1], sy,
                                 fill="#cfd6e0")
        for r in remotes:
            ry = remote_y[r.ip]
            for dk in r.devices:
                if dk in dev_y:
                    c.create_line(col_x[0], dev_y[dk], col_x[2], ry,
                                 fill="#e8dccb")
            for s in sites:
                if r.ip in s.resolved_ips:
                    c.create_line(col_x[1], site_y[s.domain], col_x[2], ry,
                                 fill="#cfd6e0", dash=(2, 2))

        for d in devs:
            y = dev_y[d.key]
            c.create_oval(col_x[0] - 8, y - 8, col_x[0] + 8, y + 8,
                         fill="#2b7de9", outline="")
            c.create_text(col_x[0], y + 15, text=d.display_name()[:18],
                          fill=t["text_fg"], font=("TkDefaultFont", 8))
        for s in sites:
            y = site_y[s.domain]
            c.create_oval(col_x[1] - 7, y - 7, col_x[1] + 7, y + 7,
                         fill="#0b6b3a", outline="")
            c.create_text(col_x[1], y + 15, text=s.domain[:22],
                          fill=t["text_fg"], font=("TkDefaultFont", 8))
        for r in remotes:
            y = remote_y[r.ip]
            c.create_oval(col_x[2] - 7, y - 7, col_x[2] + 7, y + 7,
                         fill="#888888", outline="")
            c.create_text(col_x[2], y + 15, text=(r.domain or r.ip)[:22],
                          fill=t["text_fg"], font=("TkDefaultFont", 8))
        if not devs and not sites and not remotes:
            c.create_text(20, 30, anchor="nw", fill=t["muted_fg"],
                          text="Nothing to show yet \u2014 start watching "
                               "and browse for a bit.")

    # ---------- security check ------------------------------------------
    def _build_sec_tab(self):
        outer = tk.Frame(self.tab_sec, bg="#ffffff")
        outer.pack(fill="both", expand=True, padx=14, pady=12)
        tk.Label(outer, text="🔒  Security check",
                 bg="#ffffff", fg="#2b3a56",
                 font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        tk.Label(outer,
                 text="Friendly explanations of what I've noticed.",
                 bg="#ffffff", fg="#666666").pack(anchor="w", pady=(0, 8))

        self.sec_text = tk.Text(outer, wrap="word", bg="#fbfbfb", fg="#222222",
                                relief="flat", padx=14, pady=12,
                                font=("TkDefaultFont", 11), state="disabled")
        vs = ttk.Scrollbar(outer, orient="vertical",
                           command=self.sec_text.yview)
        self.sec_text.configure(yscrollcommand=vs.set)
        self.sec_text.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

        self.sec_text.tag_configure("h1", font=("TkDefaultFont", 12, "bold"),
                                    foreground="#2b3a56", spacing1=10,
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
            b = tk.Button(pills, text=n, relief="flat", bd=1, padx=10, pady=3, fg="#333333",
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
        txt = tk.Text(f, wrap="none", font=self.mono, state="disabled", fg="#222222",
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
        if self.config.get("mode.active_scanning", True):
            self.lan_scanner = LanScanner(iface_obj, my_ip)
            self.lan_scanner.start()

        if used_label != label:
            self._set_banner(
                f"👀  “{label}” didn't work, so I switched to "
                f"“{used_label}” automatically. Open a website to see it "
                f"in action!")
        elif auto:
            scan_note = (" I'm also quietly scanning your Wi-Fi for other "
                        "devices." if self.lan_scanner else " I'm in Quiet "
                        "Mode, so I'm only listening \u2014 not probing.")
            self._set_banner(
                f"👀  Watching “{used_label}” automatically.{scan_note} "
                f"Open a website to see it in action!")
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
        self.root.after(self._ms(50), self._drain_decoded)

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
        self.root.after(self._ms(400), self._refresh_visible)

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
                    f"{len(self.registry.by_key)} devices, "
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
        self._redraw_dashboard()
        self._update_geoip_status()
        self.root.after(self._ms(2000), self._refresh_insights)

    def _tick_lifecycle_and_alerts(self):
        try:
            newly_inactive, newly_expired = self.registry.tick_lifecycle()
            for dev in newly_inactive:
                self._redraw_device_row(dev.key)
                self._timeline_push(
                    "device idle", "INFO",
                    f"{dev.display_name()} has gone quiet (inactive)",
                    ("tab_devices", "device_iids", dev.key))
            for dev in newly_expired:
                self._redraw_device_row(dev.key)
                self._timeline_push(
                    "device expired", "INFO",
                    f"{dev.display_name()} moved to history (expired)", None)
            # periodic (not per-packet) low-confidence check, so a device
            # that never firms up gets flagged without spamming on every
            # single packet it sends
            for dev in self.registry.by_key.values():
                if dev.state != STATE_ACTIVE:
                    continue
                if dev.confidence in (CONFIDENCE_LOW, CONFIDENCE_UNCONFIRMED) \
                        and dev.packets >= int(self.config.get(
                            "alerts.unknown_min_packets", 5)):
                    a = self.alert_engine.unknown_device(dev)
                    if a:
                        self._add_alert_row(a)
            self._auto_merge_pass()
            self._redraw_map()
        except Exception:
            pass
        self.root.after(15000, self._tick_lifecycle_and_alerts)

    def _disp(self, ip, mac):
        if ip:
            n = self.cache.get(ip)
            return n if n else ip
        return mac or ""

    # ---------- row handling -------------------------------------------
    def _add_row(self, d):
        self.count += 1
        d["no"] = self.count

        # register devices (private IPs + MACs) via the confidence engine
        self._observe_packet_for_devices(d)
        # register websites / remote hosts (public IP + name) — entirely
        # separate record types; never becomes a Device (Section 9/27)
        self._observe_packet_for_websites(d)
        # dns-server tracking
        if d["tag"] in ("DNS", "mDNS", "LLMNR") and d["dst_ip"]:
            if d["tag"] == "DNS":
                self.dns_servers[d["dst_ip"]] += 1
        if d.get("doh_hint") and \
                self.config.get("dns.detect_encrypted_dns", True):
            self.doh_seen[d["src_ip"]].add(d["doh_hint"])

        # rogue-DHCP-server tracking + DHCP lease correlation (Section 4)
        if d.get("dhcp_msgtype") == 2 and d["src_ip"]:
            self.dhcp_servers[d["src_ip"]] += 1
            if len(self.dhcp_servers) > 1:
                self.alert_engine.dhcp_anomaly(set(self.dhcp_servers))
        if d.get("dhcp_msgtype") in (2, 5) and d.get("dhcp_yiaddr"):
            client_mac = d.get("dhcp_client_mac") or d.get("dst_mac", "")
            dev, reused = self.registry.note_dhcp_lease(
                d["dhcp_yiaddr"], client_mac, d.get("dhcp_hostname", ""))
            if dev:
                self._redraw_device_row(dev.key)

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
        while len(self.all_rows) > self.max_rows:
            self.all_rows.popleft()

        # friendly feed entry (paced — see _flush_feed)
        self._feed_add(d)

        # raw packet tab
        if self._matches(d):
            self._insert_row(d)

    def _observe_arp_identity(self, ip, mac):
        dev, conflict = self.registry.note_arp_reply(ip, mac)
        if dev:
            self._redraw_device_row(dev.key)
        # flip-flopping between MACs is the strong ARP-spoofing indicator
        # (a single change is ordinary and stays a warning below)
        flips = self.registry.arp_flip_count(ip)
        if flips >= int(self.config.get("alerts.arp_flip_threshold", 4)):
            spoof = self.alert_engine.arp_spoof(
                ip, len(self.registry.ip_macs.get(ip, ())), flips,
                ip == self.gateway_ip)
            if spoof:
                self._add_alert_row(spoof)
                if ip == self.gateway_ip:
                    self._set_banner(
                        "\U0001F6A8  Your router's address keeps flipping "
                        "between two devices \u2014 see the Alerts tab.",
                        kind="bad")
        if not conflict:
            return
        if ip == self.gateway_ip:
            a = self.alert_engine.gateway_change(ip, len(self.registry.gw_macs))
            if a and not self._spoof_warned:
                self._spoof_warned = True
                self._set_banner(
                    "🚨  Your router's address (MAC) just changed — this "
                    "can be normal after a router reboot, but it's also "
                    "the classic sign of ARP spoofing. Check the Alerts "
                    "and Security check tabs.", kind="bad")
                self._add_alert_row(a)
        else:
            a = self.alert_engine.duplicate_ip(
                ip, len(self.registry.ip_macs.get(ip, ())))
            if a:
                self._add_alert_row(a)

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
            self.root.after(self._ms(300), self._flush_feed)
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
        self.root.after(self._ms(cfg["interval"]), self._flush_feed)

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
        dev = self._device_for_ip(ip) if ip else None
        name = self.cache.get(ip) if ip else ""
        kind = dev.type if dev else "unknown"
        icon = DEVICE_ICONS.get(kind, "❓")
        label = name or (dev.vendor if dev else "") or ip or mac
        if kind == "unknown" and ip and is_public_ip(ip):
            return f"☁️  {ip}"
        return f"{icon}  {label}" if label else "❓  Unknown device"

    def _device_for_ip(self, ip):
        key = self.registry.ip_to_key.get(ip)
        return self.registry.by_key.get(key) if key else None

    def _observe_packet_for_devices(self, d):
        """Feeds the confidence engine (Section 1/2/44): every packet
        contributes at most baseline 'seen on the LAN' evidence here; ARP
        replies, DHCP leases, and mDNS/SSDP announcements each add their
        own stronger evidence via their dedicated call sites. Nothing here
        can create a device from a public/remote address."""
        seen = set()
        hint = d.get("type_hint", "")
        is_mdns, is_ssdp = d.get("tag") == "mDNS", d.get("tag") == "SSDP"
        for ip, mac in ((d["src_ip"], d["src_mac"]),
                        (d["dst_ip"], d["dst_mac"])):
            if not ip or ip in seen:
                continue
            if not (is_private_ip(ip) or
                   (mac and mac != "ff:ff:ff:ff:ff:ff")):
                continue
            seen.add(ip)
            existed_before = ip in self.registry.ip_to_key
            dev = self.registry.touch(
                ip, mac, "mac_local" if mac else "local_traffic",
                "Sent traffic on the local network")
            if dev is None:
                continue
            if ip == d["src_ip"] and (is_mdns or is_ssdp):
                self.registry.note_service(
                    ip, mac, "mdns" if is_mdns else "ssdp",
                    (d.get("text") or "")[:60])
            if hint and ip == d["src_ip"] and not dev.type_hint:
                dev.type_hint = hint
            guessed = guess_device_type(
                dev.hostname or dev.dhcp_hostname or dev.mdns_name,
                dev.vendor, ip, self.gateway_ip, self.my_ips)
            if guessed == "unknown" and dev.type_hint:
                guessed = dev.type_hint
            dev.type = guessed
            self._redraw_device_row(dev.key)

            if dev.traffic_baseline_flag(
                    time.time(),
                    float(self.config.get("alerts.chatty_multiplier", 4)),
                    float(self.config.get("alerts.chatty_min_rate", 3))):
                a = self.alert_engine.chatty_device(dev)
                if a:
                    self._add_alert_row(a)
                    self._timeline_push(
                        "traffic spike", "WARNING",
                        f"{dev.display_name()} is unusually active",
                        ("tab_devices", "device_iids", dev.key))

            if dev.reactivated_now:
                dev.reactivated_now = False
                window = float(self.config.get(
                    "alerts.reconnect_window_minutes", 30)) * 60
                recent = [t for t in dev.reactivations
                          if time.time() - t <= window]
                if len(recent) >= int(self.config.get(
                        "alerts.reconnect_count", 5)):
                    a = self.alert_engine.reconnect_cycle(
                        dev, len(recent), window)
                    if a:
                        self._add_alert_row(a)

            # Quietly announce genuinely new arrivals in the feed — but not
            # during the first few seconds, when *everything* looks "new".
            if not existed_before and self.sniffer is not None and \
                    (time.time() - self._capture_started_at) > 8:
                self._feed_push("device", self._friendly_who(ip, mac),
                                "🆕 joined your Wi-Fi (new device)")
                self._timeline_push(
                    "new device", "INFO",
                    f"{dev.display_name()} joined your network",
                    ("tab_devices", "device_iids", dev.key))
                a = self.alert_engine.new_device(dev)
                if a:
                    self._add_alert_row(a)

    def _redraw_device_row(self, key):
        dev = self.registry.by_key.get(key)
        if not dev:
            return
        icon = DEVICE_ICONS.get(dev.type, "❓")
        label = self._device_label(dev)
        conf_icon = {"High": "🟢", "Medium": "🟡", "Low": "🟠",
                    "Unconfirmed": "⚪"}.get(dev.confidence, "⚪")
        state_label = {"ACTIVE": "Active", "IDLE": "Idle \u23f8",
                      "INACTIVE": "Inactive", "EXPIRED": "Expired"}.get(
            dev.state, dev.state)
        vendor_txt = dev.vendor or (
            "Private (randomized)" if dev.randomized_mac else "—")
        last_txt = time.strftime("%H:%M:%S", time.localtime(dev.last_seen))
        vals = (icon, label, dev.ip or "—", dev.mac or "—", vendor_txt,
               f"{conf_icon} {dev.confidence}", state_label, dev.packets,
               last_txt)
        show_inactive = self.config.get("devices.show_inactive", False)
        show_expired = self.config.get("devices.show_expired", False)
        should_show = not (dev.state == STATE_EXPIRED and not show_expired) \
            and not (dev.state == STATE_INACTIVE and not show_inactive)
        iid = self.device_iids.get(key)
        if iid:
            try:
                if should_show:
                    self.devtree.item(iid, values=vals)
                else:
                    self.devtree.delete(iid)
                    del self.device_iids[key]
                return
            except tk.TclError:
                pass
        if should_show:
            try:
                iid = self.devtree.insert("", "end", values=vals)
                self.device_iids[key] = iid
            except tk.TclError:
                pass

    def _device_label(self, dev):
        kind = dev.type
        if kind == "this-pc":
            return "This computer"
        if kind == "router":
            return "Your router / gateway"
        if dev.hostname:
            return dev.hostname
        if dev.dhcp_hostname:
            return dev.dhcp_hostname
        if dev.mdns_name:
            return dev.mdns_name
        if dev.vendor:
            return f"{kind.title()} ({dev.vendor})"
        if dev.confidence == CONFIDENCE_UNCONFIRMED:
            return "Unconfirmed device"
        return kind.title()

    def _observe_packet_for_websites(self, d):
        # learn domain -> ip pairs (Website records — never a Device)
        for ip, name in d["learns"]:
            if is_public_ip(ip) and name:
                self._register_website(name, ip, d["src_ip"], "DNS")
        # for TLS SNI, use dns_names too
        for name in d["dns_names"]:
            if d["dst_ip"] and is_public_ip(d["dst_ip"]):
                self._register_website(name, d["dst_ip"], d["src_ip"],
                                       "TLS SNI")

        # Remote Hosts (Section 27): the IP-level view of anything public
        # contacted directly, kept entirely separate from Devices/Websites.
        # Only recorded on a new outbound TCP connection or the first UDP
        # packet to a given IP, so this doesn't just duplicate the Raw tab.
        pub_ip = d["dst_ip"] if is_public_ip(d["dst_ip"]) else (
            d["src_ip"] if is_public_ip(d["src_ip"]) else "")
        if pub_ip:
            is_new_conn = pub_ip not in self.remote_hosts
            try:
                pkt = d.get("pkt")
                if pkt is not None and TCP is not None and pkt.haslayer(TCP):
                    is_new_conn = is_new_conn or bool(int(pkt[TCP].flags) & 0x02)
            except Exception:
                pass
            if is_new_conn:
                self._register_remote_host(pub_ip, d)

    def _register_website(self, domain, ip, device_ip, source="DNS"):
        key = domain.lower().strip(".")
        if not key:
            return
        rec = self.websites.get(key)
        now = time.time()
        is_new = rec is None
        if rec is None:
            rec = WebsiteRecord(domain=key, registrable=registrable_domain(key),
                                first_seen=now)
            self.websites[key] = rec
        rec.resolved_ips.add(ip)
        dkey = self.registry.ip_to_key.get(device_ip) if device_ip else None
        if dkey and is_private_ip(device_ip):
            rec.devices.add(dkey)
        rec.requests += 1
        rec.last_seen = now
        rec.sources.add(source)
        self.ip_to_domain[ip] = key
        self._redraw_website_row(key)
        if is_new and self.sniffer is not None and \
                (time.time() - self._capture_started_at) > 8:
            self._timeline_push("website", "INFO",
                                f"First visit to {key}",
                                ("tab_websites", "website_iids", key))

    def _register_remote_host(self, ip, d):
        rec = self.remote_hosts.get(ip)
        now = time.time()
        if rec is None:
            rec = RemoteHostRecord(ip=ip, first_seen=now)
            self.remote_hosts[ip] = rec
        rec.last_seen = now
        rec.packets += 1
        rec.bytes_total += d.get("length", 0) or 0
        if d.get("sport"):
            rec.ports.add(d["sport"])
        if d.get("dport"):
            rec.ports.add(d["dport"])
        if d.get("proto"):
            rec.protocols.add(d["proto"])
        device_ip = d["src_ip"] if is_private_ip(d["src_ip"]) else d["dst_ip"]
        dkey = self.registry.ip_to_key.get(device_ip) if device_ip else None
        if dkey:
            rec.devices.add(dkey)
        dom = self.ip_to_domain.get(ip)
        if dom:
            rec.domain = dom
        self._redraw_remote_row(ip)
        self._lookup_country(ip)

    def _redraw_remote_row(self, ip):
        rec = self.remote_hosts.get(ip)
        if not rec or not hasattr(self, "remotetree"):
            return
        who = ", ".join(self._short_device_name_by_key(k)
                        for k in sorted(rec.devices)[:3]) or "—"
        ports = ", ".join(str(p) for p in sorted(rec.ports)[:4]) or "—"
        protos = ", ".join(sorted(rec.protocols)) or "—"
        first_txt = time.strftime("%H:%M:%S", time.localtime(rec.first_seen))
        last_txt = time.strftime("%H:%M:%S", time.localtime(rec.last_seen))
        country = (f"{rec.country} \u00b7 {rec.country_name}"
                   if rec.country and rec.country_name else rec.country)
        vals = (rec.ip, country or "\u2014", rec.domain or "(no name resolved)",
               ports, protos, who, rec.packets, first_txt, last_txt)
        iid = self.remote_iids.get(ip)
        if iid:
            try:
                self.remotetree.item(iid, values=vals); return
            except tk.TclError:
                pass
        try:
            iid = self.remotetree.insert("", "end", values=vals)
            self.remote_iids[ip] = iid
        except tk.TclError:
            pass

    def _redraw_website_row(self, key):
        rec = self.websites.get(key)
        if not rec:
            return
        ips = ", ".join(sorted(rec.resolved_ips)[:2])
        who = ", ".join(self._short_device_name_by_key(k)
                        for k in sorted(rec.devices)[:3]) or "—"
        note = DOH_HOSTS.get(key, "")
        if rec.registrable and rec.registrable != rec.domain:
            note = (note + "  " if note else "") + \
                f"(part of {rec.registrable})"
        first_txt = time.strftime("%H:%M:%S", time.localtime(rec.first_seen))
        last_txt = time.strftime("%H:%M:%S", time.localtime(rec.last_seen))
        iid = self.website_iids.get(key)
        vals = (rec.domain, ips, who, rec.requests, first_txt, last_txt,
               note.strip())
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
        if n:
            return n
        dev = self._device_for_ip(ip)
        return (dev and dev.display_name()) or ip

    def _short_device_name_by_key(self, key):
        dev = self.registry.by_key.get(key)
        if not dev:
            return key
        if dev.ip and dev.ip in self.my_ips:
            return "This computer"
        if dev.ip and dev.ip == self.gateway_ip:
            return "Router"
        return dev.display_name()

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
        while len(self.iids) > self.max_rows:
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
        guidance = self.config.get("general.beginner_explanations", True)
        def body(s):
            if guidance:
                t.insert("end", "    " + s + "\n", "body")
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
        if self.gateway_ip and len(self.registry.gw_macs) > 1:
            bad(f"Your router's address has answered from "
                f"{len(self.registry.gw_macs)} different MAC addresses. "
                f"That can happen after a router reboot or firmware "
                f"update, but it's also the classic sign of ARP spoofing "
                f"— a device on your Wi-Fi pretending to be your router "
                f"so it can see your traffic.")
            body("If you didn't just restart your router, disconnect from "
                 "this Wi-Fi and check your router's admin page from a "
                 "device you trust.")
        elif self.gateway_ip:
            good("Your router's address has stayed consistent — no signs "
                 "of ARP spoofing so far.")
        else:
            dim("Watching for this once I know where your router is.")
        odd = {ip: macs for ip, macs in self.registry.ip_macs.items()
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
        if not self.config.get("dns.detect_encrypted_dns", True):
            dim("Encrypted-DNS detection is turned off in Settings.")
        elif self.doh_seen:
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
        if not self.registry.by_key:
            dim("No local devices seen yet.")
        else:
            unknown = [d for d in self.registry.by_key.values()
                      if d.type == "unknown" and not d.vendor]
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
                 f"{len(self.registry.by_key)} device(s), "
                 f"and {len(self.websites)} website(s).")
        t.config(state="disabled")

    # ---------- utils ---------------------------------------------------
    def clear(self):
        if self.config.get("general.confirm_before_clear", False):
            if not messagebox.askyesno(
                    "Clear everything?",
                    "This clears all captured packets, devices, websites, "
                    "and alerts from this session. Continue?"):
                return
        self.tree.delete(*self.tree.get_children())
        self.devtree.delete(*self.devtree.get_children())
        self.sitetree.delete(*self.sitetree.get_children())
        if hasattr(self, "remotetree"):
            self.remotetree.delete(*self.remotetree.get_children())
        if hasattr(self, "alerttree"):
            self.alerttree.delete(*self.alerttree.get_children())
        self.feed.delete(*self.feed.get_children())
        self.all_rows.clear()
        self.iids.clear(); self.rows_by_iid.clear()
        self.registry = DeviceRegistry(self.gateway_ip, self.my_ips,
                                       self.config)
        self.device_iids.clear()
        self.websites.clear(); self.website_iids.clear()
        self.ip_to_domain.clear()
        self.remote_hosts.clear(); self.remote_iids.clear()
        self.alert_engine = AlertEngine(self.config)
        self.alert_iids.clear()
        self.dns_servers.clear(); self.doh_seen.clear()
        self.dhcp_servers.clear()
        self._spoof_warned = False
        self._feed_buffer.clear()
        self._discovering_until = time.time() + 60
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
            initialdir=self._dialog_dir(),
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

    # ---------- export system (Section 14) --------------------------------
    def _open_export_menu(self):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Current view as CSV",
                         command=lambda: self._export_csv(current_view=True))
        menu.add_command(label="Everything as CSV",
                         command=lambda: self._export_csv(current_view=False))
        menu.add_separator()
        menu.add_command(label="Everything as JSON",
                         command=self._export_json)
        menu.add_separator()
        menu.add_command(label="Packets as .pcap", command=self.save_pcap)
        try:
            x = self.root.winfo_pointerx()
            y = self.root.winfo_pointery()
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()

    def _export_rows(self, current_view):
        return [d for d in self.all_rows if self._matches(d)] \
            if current_view else list(self.all_rows)

    def _export_csv(self, current_view):
        rows = self._export_rows(current_view)
        if not rows:
            messagebox.showinfo("Export CSV", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            initialdir=self._dialog_dir(),
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["time", "protocol", "src_ip", "src_mac",
                          "dst_ip", "dst_mac", "sport", "dport", "text"])
                for d in rows:
                    w.writerow([
                        datetime.fromtimestamp(d["time"]).strftime(
                            "%Y-%m-%d %H:%M:%S"),
                        d.get("proto", ""), d.get("src_ip", ""),
                        d.get("src_mac", ""), d.get("dst_ip", ""),
                        d.get("dst_mac", ""), d.get("sport", "") or "",
                        d.get("dport", "") or "", d.get("text", "")])
        except Exception as e:
            messagebox.showerror("Export error", str(e))
            return
        self.status_var.set(f"Exported {len(rows)} rows to {path}")

    def _session_payload(self):
        devices = []
        for dev in self.registry.by_key.values():
            devices.append({
                "key": dev.key, "ip": dev.ip, "mac": dev.mac,
                "vendor": dev.vendor, "hostname": dev.display_name(),
                "type": dev.type, "confidence": dev.confidence,
                "score": dev.score, "state": dev.state,
                "evidence": dev.evidence_summary(),
                "first_seen": dev.first_seen, "last_seen": dev.last_seen,
                "packets": dev.packets, "bytes": dev.bytes_up,
                "randomized_mac": dev.randomized_mac,
            })
        websites = []
        for rec in self.websites.values():
            websites.append({
                "domain": rec.domain, "registrable": rec.registrable,
                "resolved_ips": sorted(rec.resolved_ips),
                "requests": rec.requests, "sources": sorted(rec.sources),
                "first_seen": rec.first_seen, "last_seen": rec.last_seen,
            })
        remote_hosts = []
        for rec in self.remote_hosts.values():
            remote_hosts.append({
                "ip": rec.ip, "domain": rec.domain,
                "ports": sorted(rec.ports), "protocols": sorted(rec.protocols),
                "packets": rec.packets, "bytes": rec.bytes_total,
                "country": rec.country, "country_name": rec.country_name,
            })
        alerts = []
        for aid in self.alert_engine.order:
            a = self.alert_engine.alerts[aid]
            alerts.append({
                "severity": a.severity, "kind": a.kind, "reason": a.reason,
                "observed": a.observed, "interpretation": a.interpretation,
                "possible_explanations": a.possible_explanations,
                "when": a.when,
            })
        return {"exported_at": time.time(), "packet_count": self.count,
               "devices": devices, "websites": websites,
               "remote_hosts": remote_hosts, "alerts": alerts}

    def _export_json(self):
        try:
            payload = self._session_payload()
        except Exception as e:
            messagebox.showerror("Export error", str(e))
            return
        path = filedialog.asksaveasfilename(
            initialdir=self._dialog_dir(),
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception as e:
            messagebox.showerror("Export error", str(e))
            return
        self.status_var.set(f"Exported full session data to {path}")

    # ---------- session management (Section 38) ----------------------------
    def _open_session_menu(self):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="New session (stop \u2192 clear)",
                         command=self._new_session)
        menu.add_command(label="Save session\u2026", command=self._save_session)
        menu.add_command(label="Load session\u2026", command=self._load_session)
        try:
            x = self.root.winfo_pointerx()
            y = self.root.winfo_pointery()
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()

    def _new_session(self):
        self.stop()
        self.clear()
        self._session_loaded_note = ""

    def _save_session(self):
        path = filedialog.asksaveasfilename(
            initialdir=self._dialog_dir(),
            defaultextension=".mwsession.json",
            filetypes=[("MiniWireshark session", "*.json"),
                      ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._session_payload(), f, indent=2, default=str)
        except Exception as e:
            messagebox.showerror("Save session error", str(e))
            return
        self.status_var.set(f"Session saved to {path}")

    def _load_session(self):
        path = filedialog.askopenfilename(
            initialdir=self._dialog_dir(),
            filetypes=[("MiniWireshark session", "*.json"),
                      ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as e:
            messagebox.showerror(
                "Load session error",
                f"I couldn't read that file: {e}")
            return
        self.stop()
        self.clear()
        try:
            for dd in payload.get("devices", []):
                dev = DeviceRecord(key=dd.get("key") or dd.get("mac") or
                                   f"ip:{dd.get('ip','')}")
                dev.ip = dd.get("ip", ""); dev.mac = dd.get("mac", "")
                dev.vendor = dd.get("vendor", "")
                dev.hostname = dd.get("hostname", "")
                dev.type = dd.get("type", "unknown")
                dev.confidence = dd.get("confidence", CONFIDENCE_UNCONFIRMED)
                dev.score = dd.get("score", 0)
                dev.state = STATE_EXPIRED  # loaded devices are historical
                dev.first_seen = dd.get("first_seen", time.time())
                dev.last_seen = dd.get("last_seen", time.time())
                dev.last_confirmed = dev.last_seen
                dev.packets = dd.get("packets", 0)
                dev.bytes_up = dd.get("bytes", 0)
                dev.randomized_mac = dd.get("randomized_mac", False)
                self.registry.by_key[dev.key] = dev
                if dev.ip:
                    self.registry.ip_to_key[dev.ip] = dev.key
                self._redraw_device_row(dev.key)
            for wd in payload.get("websites", []):
                rec = WebsiteRecord(domain=wd["domain"],
                                    registrable=wd.get("registrable", ""),
                                    first_seen=wd.get("first_seen", time.time()))
                rec.resolved_ips = set(wd.get("resolved_ips", []))
                rec.requests = wd.get("requests", 0)
                rec.sources = set(wd.get("sources", []))
                rec.last_seen = wd.get("last_seen", time.time())
                self.websites[rec.domain] = rec
                self._redraw_website_row(rec.domain)
            for rd in payload.get("remote_hosts", []):
                rec = RemoteHostRecord(ip=rd["ip"], domain=rd.get("domain", ""))
                rec.ports = set(rd.get("ports", []))
                rec.protocols = set(rd.get("protocols", []))
                rec.packets = rd.get("packets", 0)
                rec.bytes_total = rd.get("bytes", 0)
                rec.country = rd.get("country", "")
                rec.country_name = rd.get("country_name", "")
                self.remote_hosts[rec.ip] = rec
                self._redraw_remote_row(rec.ip)
            for ad in payload.get("alerts", []):
                a = Alert(id=uuid.uuid4().hex[:8], kind=ad.get("kind", ""),
                          severity=ad.get("severity", "INFO"), device_key="",
                          reason=ad.get("reason", ""),
                          observed=ad.get("observed", ""),
                          interpretation=ad.get("interpretation", ""),
                          possible_explanations=ad.get(
                              "possible_explanations", ""),
                          when=ad.get("when", time.time()))
                self.alert_engine.alerts[a.id] = a
                self.alert_engine.order.append(a.id)
                self._add_alert_row(a)
        except Exception as e:
            messagebox.showerror(
                "Load session error",
                f"That file didn't look like a MiniWireshark session: {e}")
            return
        when_txt = time.strftime(
            "%Y-%m-%d %H:%M", time.localtime(payload.get("exported_at",
                                                          time.time())))
        self._session_loaded_note = f"{os.path.basename(path)} ({when_txt})"
        self._set_banner(
            f"\U0001F4C2  Loaded a saved session from "
            f"{self._session_loaded_note} \u2014 this is NOT live. Click "
            f"“Start watching” to resume live capture.", kind="warn")
        self.status_var.set(
            f"\U0001F4C2 Viewing saved session: {self._session_loaded_note} "
            f"(not live)")
        self._redraw_dashboard()
        self._redraw_map()

    # ---------- global search (Section 31) --------------------------------
    def _run_global_search(self):
        q = self.search_var.get().strip().lower()
        if not q:
            return
        hits = []
        for dev in self.registry.by_key.values():
            hay = " ".join([dev.display_name(), dev.ip, dev.mac,
                           dev.vendor]).lower()
            if q in hay:
                hits.append(f"[DEVICE] {dev.display_name()}  ({dev.ip or dev.mac})")
        for rec in self.websites.values():
            if q in rec.domain.lower():
                hits.append(f"[WEBSITE] {rec.domain}")
        for rec in self.remote_hosts.values():
            if q in rec.ip or q in (rec.domain or "").lower():
                hits.append(f"[REMOTE HOST] {rec.ip}"
                           f"{'  ' + rec.domain if rec.domain else ''}")
        for aid in self.alert_engine.order:
            a = self.alert_engine.alerts[aid]
            if q in a.reason.lower():
                hits.append(f"[ALERT] {a.reason}")
        win = tk.Toplevel(self.root)
        win.title(f"Search results for \u201c{self.search_var.get()}\u201d")
        win.geometry("440x360")
        win.configure(bg=self.theme["tab_bg"])
        lb = tk.Listbox(win, bg=self.theme["text_bg"], fg=self.theme["text_fg"],
                        font=("TkDefaultFont", 10))
        lb.pack(fill="both", expand=True, padx=10, pady=10)
        if not hits:
            lb.insert("end", "No matches found.")
        for h in hits[:200]:
            lb.insert("end", h)

    # ---------- settings dialog (Section 22/23/49) -------------------------
    def _open_settings(self, page=None):
        """Open Settings (or bring the open one forward)."""
        win = getattr(self, "_settings_win", None)
        if win is not None and win.alive():
            win.win.lift()
            win.win.focus_force()
            if page:
                win._go(page)
            return win
        self._settings_win = SettingsWindow(self, page or "general")
        return self._settings_win

    def _on_close(self):
        self.stop(); self.geoip.stop(); self.root.destroy()


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