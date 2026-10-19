# ============================================================================
#  2d.  Layer 2 — the private Python runtime (RuntimeManager)
#
#  "Update" here always means "the newest versions THIS release of
#  MiniWireshark has verified": every download is checked against a SHA-256
#  fingerprint written into this file (and Windows installers against the
#  Python Software Foundation's signature). Nothing is ever installed into
#  your own Python, PATH or system folders.
# ============================================================================
RUNTIME_PYTHON = "3.14.2"
RUNTIME_PBS_TAG = "20260127"
RUNTIME_PBS_BASE = ("https://github.com/astral-sh/python-build-standalone/"
                    "releases/download/")
# python-build-standalone "install_only_stripped" builds (relocatable, no
# admin rights, include Tk). SHA-256 pinned per platform.
RUNTIME_SOURCES = {
    ("windows", "x86_64"): (
        "cpython-3.14.2+20260127-x86_64-pc-windows-msvc-install_only_"
        "stripped.tar.gz",
        "42638ce9bd8c177010c44c7a6a6fb3e1dc0b04ea372089036c689ccb57dc0d09"),
    ("windows", "aarch64"): (
        "cpython-3.14.2+20260127-aarch64-pc-windows-msvc-install_only_"
        "stripped.tar.gz",
        "4780ac64fcf4b3dfd181f86ae87c9dff43d3fa804c5f8d97091298f2d87e19cd"),
    ("windows", "x86"): (
        "cpython-3.14.2+20260127-i686-pc-windows-msvc-install_only_"
        "stripped.tar.gz",
        "1c68b7e4456ba7acfb26d6a0202fb89db63fca8cfab753c742c69b5f3d643ec4"),
    ("macos", "aarch64"): (
        "cpython-3.14.2+20260127-aarch64-apple-darwin-install_only_"
        "stripped.tar.gz",
        "2f82ed0cf902c8a2863a3fc5864909645c761e4e0a96525850c9ef8f7e3b79e7"),
    ("macos", "x86_64"): (
        "cpython-3.14.2+20260127-x86_64-apple-darwin-install_only_"
        "stripped.tar.gz",
        "51e886261fb79f64079b20181a7f8adfca738f2b2882882e981b67a165e1809b"),
    ("linux", "x86_64"): (
        "cpython-3.14.2+20260127-x86_64-unknown-linux-gnu-install_only_"
        "stripped.tar.gz",
        "c2926d6707f4339e3bf30e90437b387712b47e60e9e55bff1dcb36bf7688b01d"),
    ("linux", "aarch64"): (
        "cpython-3.14.2+20260127-aarch64-unknown-linux-gnu-install_only_"
        "stripped.tar.gz",
        "1d243bfab134c9fd3e099780a811079d8c6158283bddde65de2bc5f6eda74f7c"),
}
# Windows fallback when the Visual C++ runtime is missing: the official
# python.org installer (per-user, PATH/launcher/associations off), accepted
# only with a valid Python Software Foundation signature.
RUNTIME_PYORG_WINDOWS = {
    "x86_64": "https://www.python.org/ftp/python/3.14.2/"
              "python-3.14.2-amd64.exe",
    "aarch64": "https://www.python.org/ftp/python/3.14.2/"
               "python-3.14.2-arm64.exe",
}
PSF_SIGNER = "Python Software Foundation"

# Hash-pinned wheels for the private runtime (cp314). Generated at release
# time from PyPI (see make_runtime_lock()). Missing entries = not available
# for that platform; required ones block the install, optional ones just
# switch their feature off.
RUNTIME_LOCK = {
    "scapy": {"version": "2.8.0", "required": True, "any": (
        "scapy-2.8.0-py3-none-any.whl",
        "abf855145ee829a42b2eb28983cd6a0a52b12a31d3f861cb7be36791195ed9aa")},
    "psutil": {"version": "7.2.2", "required": False,
               "win_amd64": "eb7e81434c8d223ec4a219b5fc1c47d0417b12be7ea866"
                            "e24fb5ad6e84b3d988",
               "win_arm64": "8c233660f575a5a89e6d4cb65d9f938126312bca76d8fe"
                            "087b947b3a1aaac9ee",
               "macosx_arm64": "1a7b04c10f32cc88ab39cbf606e117fd74721c831c98"
                               "a27dc04578deb0c16979",
               "macosx_x86_64": "ed0cace939114f62738d808fdcecd4c869222507e26"
                                "6e574799e9c0faa17d486",
               "linux_x86_64": "076a2d2f923fd4821644f5ba89f059523da90dc9014e"
                               "85f8e45a5774ca5bc6f9",
               "linux_aarch64": "b0726cecd84f9474419d67252add4ac0cd9811b04d6"
                                "1123054b9fb6f57df6e9e"},
    "cryptography": {"version": "50.0.2", "required": False,
                     "win_amd64": "7afa5a6602a9f29af1f3a2965f831bae7c9d5d597"
                                  "b7cbb716d41ab3b7d89879c",
                     "macosx_arm64": "fa8f5efb344d6908a1ce62f4a24e2e5780f825"
                                     "d6f53f5f50ec5ffacac72936cb",
                     "linux_x86_64": "630ebfea3bf689d075f82316324ff7433dc447"
                                     "fe6bc1bfc76524b74b4a9567d2",
                     "linux_aarch64": "79def8d059362e7831389ed3be0ecdf58a893"
                                      "86e1271e35dd9f5af84e81bffd0"},
    "cffi": {"version": "2.1.1", "required": False, "needed_by":
             "cryptography",
             "win_amd64": "3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2"
                          "c7016b8432fde48",
             "win_arm64": "ab36d55f9ed2d067327667c2fea18dda018eb628dd6347aa0"
                          "1dda6cf1f5d3836",
             "macosx_arm64": "661c298b4821edebead0c91edd2b00374d67ad7c5a1f7a"
                             "91d4442633b79d6a72",
             "macosx_x86_64": "d28630f5854ab07ab1fd4aba756de52326c82e6be15d4"
                              "14b12793f1975048b54",
             "linux_x86_64": "b0431303acaea1089ad4b3e9ce4e6518193def1118d407"
                             "3ca848635ee4ea2e96",
             "linux_aarch64": "58acb8ab8e295e6c5ea12f888cbb13cf21511ef2a3303a"
                              "23f4325c29d17fe5c1"},
    "pycparser": {"version": "3.11", "required": False, "needed_by": "cffi",
                  "any": ("pycparser-3.11-py3-none-any.whl",
                          "51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260"
                          "186c541e1729cd80")},
}


def runtime_platform():
    """('windows'|'macos'|'linux', 'x86_64'|'aarch64'|'x86')."""
    sysname = "windows" if IS_WINDOWS else "macos" if IS_MAC else \
        "linux" if sys.platform.startswith("linux") else sys.platform
    m = (platform.machine() or "").lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "x64": "x86_64",
            "arm64": "aarch64", "aarch64": "aarch64", "armv8": "aarch64",
            "i386": "x86", "i686": "x86", "x86": "x86"}.get(m, m)
    return sysname, arch


def wheel_platform_tag(plat=None):
    sysname, arch = plat or runtime_platform()
    if sysname == "windows":
        return {"x86_64": "win_amd64", "aarch64": "win_arm64"}.get(arch, "")
    if sysname == "macos":
        return {"x86_64": "macosx_x86_64", "aarch64": "macosx_arm64"}.get(
            arch, "")
    return {"x86_64": "linux_x86_64", "aarch64": "linux_aarch64"}.get(arch,
                                                                      "")


def lock_requirements(plat_tag, lock=None):
    """→ (requirements.txt text, [(package, required)], [skipped]).
    Each line pins version + every acceptable hash for this platform."""
    lock = lock or RUNTIME_LOCK
    lines, pkgs, skipped = [], [], []
    for name, spec in lock.items():
        h = None
        if "any" in spec:
            h = spec["any"][1]
        elif plat_tag in spec:
            h = spec[plat_tag]
        if not h:
            skipped.append(name)
            continue
        dep = spec.get("needed_by")
        if dep and dep in skipped:
            skipped.append(name)
            continue
        lines.append(f"{name}=={spec['version']} --hash=sha256:{h}")
        pkgs.append((name, bool(spec.get("required"))))
    return "\n".join(lines) + "\n", pkgs, skipped


def lock_fingerprint(lock=None):
    raw = json.dumps(lock or RUNTIME_LOCK, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def sha256_file(path, bufsize=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


class RuntimeError_(Exception):
    """A runtime step failed. `kind` selects the friendly explanation."""

    def __init__(self, kind, detail=""):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail


# Friendly error taxonomy (shown by the installer and the Repair report)
RUNTIME_ERRORS = {
    "offline": ("No Internet connection",
                "Check that this computer is online, then try again. "
                "MiniWireshark keeps working on your current Python "
                "meanwhile."),
    "proxy": ("Something between you and the Internet blocked the download",
              "A company proxy, firewall or antivirus may be intercepting "
              "secure downloads. Try another network, or allow downloads "
              "from github.com and pypi.org."),
    "fingerprint": ("The downloaded file didn't match its fingerprint",
                    "It was deleted without being used. This usually means "
                    "a broken download or something interfering with it; "
                    "try again later."),
    "signature": ("The installer wasn't signed by the Python Software "
                  "Foundation", "It was deleted without being run."),
    "disk": ("Not enough free disk space",
             "About 250 MB are needed in the data folder. Free some space "
             "and try again."),
    "permission": ("No permission to write in the data folder",
                   "Run MiniWireshark from a folder you can write to, or "
                   "set MINIWIRESHARK_DATA to one."),
    "quarantine": ("A security program removed or blocked a file",
                   "Your antivirus may have quarantined part of the private "
                   "Python. Restore it or add an exception for the "
                   "MiniWireshark data folder, then click Repair."),
    "tk": ("The private Python has no graphical toolkit",
           "This build can't show windows on this computer; MiniWireshark "
           "will keep using your current Python."),
    "selftest": ("The new environment failed its self-test",
                 "It was not switched on. Your previous setup keeps "
                 "working; details are in the log."),
    "unsupported": ("This computer's processor/OS isn't supported by the "
                    "private Python", "MiniWireshark keeps using your "
                    "current Python."),
    "cancelled": ("Cancelled", "Nothing was changed."),
    "pip": ("Installing a component failed",
            "Check the details; Repair will retry from the downloaded "
            "copies."),
    "other": ("Something unexpected went wrong", "See the details."),
}


def classify_runtime_error(exc):
    """Map an exception to a RUNTIME_ERRORS kind."""
    if isinstance(exc, RuntimeError_):
        return exc.kind
    text = f"{type(exc).__name__} {exc}".lower()
    if isinstance(exc, PermissionError) or "permission denied" in text or \
            "access is denied" in text:
        return "permission"
    if "no space" in text or "disk full" in text or "errno 28" in text:
        return "disk"
    if "certificate" in text or "ssl" in text or "proxy" in text or \
            "407" in text:
        return "proxy"
    if isinstance(exc, (urllib.error.URLError, _socket.timeout,
                        ConnectionError)) or "getaddrinfo" in text or \
            "timed out" in text or "name or service" in text:
        return "offline"
    return "other"


class RuntimeManager:
    """Installs, checks, repairs, rolls back and removes the private
    Python. All long steps report progress through `progress(stage,
    fraction, text, extra)` and honour `cancel()`."""

    STAGES = ("Check", "Download", "Verify", "Unpack", "Environment",
              "Packages", "Self-test", "Switch")

    def __init__(self, root_dir=None, script=None):
        self.root = root_dir or RUNTIME_DIR
        self.script = script or SCRIPT_PATH
        self.cache = os.path.join(self.root, "cache")
        self.wheels = os.path.join(self.root, "wheels")
        self.log_lines = deque(maxlen=400)

    # ---- facts -------------------------------------------------------------------
    def plan(self):
        plat = runtime_platform()
        src = RUNTIME_SOURCES.get(plat)
        tag = wheel_platform_tag(plat)
        _req, pkgs, skipped = lock_requirements(tag)
        vcr = True
        if plat[0] == "windows":
            sd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                              "System32")
            vcr = os.path.exists(os.path.join(sd, "vcruntime140.dll"))
        return {"platform": plat, "source": src, "wheel_tag": tag,
                "packages": pkgs, "skipped": skipped,
                "python": RUNTIME_PYTHON, "dir": self.root,
                "download_mb": 30, "disk_mb": 120,
                "use_pyorg": plat[0] == "windows" and not vcr,
                "supported": bool(src) and bool(tag)}

    def describe(self):
        p = self.plan()
        if not p["supported"]:
            return ("A private Python isn't available for this computer "
                    f"({p['platform'][0]} {p['platform'][1]}); MiniWireshark "
                    "uses the Python it was started with.")
        names = ", ".join(n for n, _r in p["packages"])
        return (f"MiniWireshark can set up its own private Python "
                f"{p['python']} so it runs the same on every computer.\n\n"
                f"• Download: about {p['download_mb']} MB from GitHub "
                f"(python-build-standalone) plus {names} from PyPI.\n"
                f"• Disk: about {p['disk_mb']} MB, all inside\n  {p['dir']}\n"
                f"• Every file is checked against a fingerprint built into "
                f"MiniWireshark before it is used.\n"
                f"• Your own Python, PATH and system settings are never "
                f"changed. Remove it any time from Settings → Diagnostics → "
                f"Runtime Manager.")

    def status(self):
        st = runtime_state_read()
        env = runtime_env(st)
        cur = env or {}
        return {"state": st, "current": st.get("current", ""),
                "previous": st.get("previous", ""),
                "python": cur.get("python", ""),
                "version": cur.get("version", ""),
                "healthy": runtime_healthy(env),
                "running_inside": bool(env) and _same_interpreter(
                    cur.get("python", ""), sys.executable),
                "lock": cur.get("lock", ""),
                "lock_current": cur.get("lock") == lock_fingerprint(),
                "declined": bool(st.get("declined")),
                "pending_starts": int(st.get("pending_starts", 0)),
                "rolled_back": st.get("rolled_back"),
                "last_error": st.get("last_error", ""),
                "pending_switch": st.get("pending_switch", "")}

    def _log(self, text):
        self.log_lines.append(f"{time.strftime('%H:%M:%S')} {text}")
        LOG.info("runtime: %s", text)

    # ---- download with resume, speed and cancel --------------------------------
    def download(self, url, dest, expected_sha=None, progress=None,
                 cancel=lambda: False, size_hint=0):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if expected_sha and os.path.exists(dest) and \
                sha256_file(dest) == expected_sha:
            self._log(f"cached: {os.path.basename(dest)}")
            return dest
        part = dest + ".part"
        have = os.path.getsize(part) if os.path.exists(part) else 0
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
        if have:
            req.add_header("Range", f"bytes={have}-")
        t0, last = time.time(), 0.0
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                if have and getattr(r, "status", 200) != 206:
                    have = 0                       # server ignored Range
                total = int(r.headers.get("Content-Length") or 0) + have
                total = total or size_hint
                mode = "ab" if have else "wb"
                got = have
                with open(part, mode) as f:
                    while True:
                        if cancel():
                            raise RuntimeError_("cancelled")
                        chunk = r.read(256 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        got += len(chunk)
                        now = time.time()
                        if progress and now - last > 0.2:
                            last = now
                            speed = (got - have) / max(0.001, now - t0)
                            eta = (total - got) / speed if speed and total \
                                else 0
                            progress("Download", got / total if total
                                     else 0.0,
                                     f"{got / 1e6:.1f} of "
                                     f"{total / 1e6:.1f} MB",
                                     {"speed": speed, "eta": eta})
        except RuntimeError_:
            raise
        except (OSError, urllib.error.URLError) as e:
            raise RuntimeError_(classify_runtime_error(e), str(e))
        if expected_sha:
            if progress:
                progress("Verify", 0.5, "Checking the fingerprint…", {})
            actual = sha256_file(part)
            if actual != expected_sha:
                with contextlib.suppress(OSError):
                    os.remove(part)
                raise RuntimeError_("fingerprint",
                                    f"expected {expected_sha}, got {actual}")
        os.replace(part, dest)
        return dest

    # ---- unpack (refuses unsafe archive paths) ----------------------------------
    @staticmethod
    def safe_extract(archive, dest):
        import tarfile
        os.makedirs(dest, exist_ok=True)
        root = os.path.realpath(dest)
        with tarfile.open(archive, "r:*") as tf:
            members = []
            for m in tf.getmembers():
                target = os.path.realpath(os.path.join(dest, m.name))
                if not (target == root or target.startswith(root + os.sep)):
                    raise RuntimeError_("other", f"unsafe path {m.name}")
                if m.issym() or m.islnk():
                    link = os.path.realpath(os.path.join(
                        os.path.dirname(target), m.linkname))
                    if not link.startswith(root + os.sep):
                        raise RuntimeError_("other", f"unsafe link {m.name}")
                if m.isdev():
                    continue
                members.append(m)
            if sys.version_info >= (3, 12):
                tf.extractall(dest, members=members, filter="tar")
            else:
                tf.extractall(dest, members=members)

    @staticmethod
    def find_python(env_dir):
        cands = [os.path.join(env_dir, "python", "python.exe"),
                 os.path.join(env_dir, "python", "bin", "python3"),
                 os.path.join(env_dir, "python", "install", "bin",
                              "python3"),
                 os.path.join(env_dir, "python.exe"),
                 os.path.join(env_dir, "bin", "python3")]
        for c in cands:
            if os.path.isfile(c):
                return c
        return ""

    def _run(self, cmd, timeout=600, cancel=lambda: False):
        self._log("$ " + " ".join(os.path.basename(c) if i == 0 else c
                                  for i, c in enumerate(cmd)))
        env = dict(os.environ)
        for k in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
            env.pop(k, None)
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        env["PYTHONNOUSERSITE"] = "1"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, env=env,
                             creationflags=getattr(subprocess,
                                                   "CREATE_NO_WINDOW", 0))
        out = []
        t_end = time.time() + timeout
        while True:
            if cancel():
                p.kill()
                raise RuntimeError_("cancelled")
            try:
                o, _ = p.communicate(timeout=0.5)
                out.append(o or "")
                break
            except subprocess.TimeoutExpired:
                if time.time() > t_end:
                    p.kill()
                    raise RuntimeError_("other", f"timed out: {cmd[1:3]}")
        text = "".join(out)
        for ln in text.splitlines()[-30:]:
            self._log("  " + ln)
        return p.returncode, text

    # ---- the install --------------------------------------------------------------
    def provision(self, progress=None, cancel=lambda: False,
                  base_python=None):
        """Build a NEW environment next to any existing one, test it and
        record it. Switching happens immediately when nothing is running
        from the old one, otherwise on the next start. Returns env id."""
        prog = progress or (lambda *a: None)
        plan = self.plan()
        prog("Check", 0.0, "Checking this computer…", {})
        if not plan["supported"]:
            raise RuntimeError_("unsupported", str(plan["platform"]))
        free = shutil.disk_usage(PATHS.data).free if hasattr(
            shutil, "disk_usage") else 1 << 40
        if free < 300 * 1024 * 1024:
            raise RuntimeError_("disk", f"{free // (1024 * 1024)} MB free")
        env_id = time.strftime("cp314-%Y%m%d-%H%M%S")
        env_dir = os.path.join(self.root, env_id)
        try:
            exe = ""
            if base_python and self._usable_base(base_python):
                prog("Unpack", 0.2, "Reusing the Python 3.14 already on "
                     "this computer (it is not modified)…", {})
                exe = self._venv_from(base_python, env_dir, cancel)
            if not exe:
                name, sha = plan["source"]
                archive = os.path.join(self.cache, name)
                url = RUNTIME_PBS_BASE + RUNTIME_PBS_TAG + "/" + \
                    urllib.request.quote(name)
                self.download(url, archive, sha, prog, cancel,
                              size_hint=plan["download_mb"] * 1024 * 1024)
                prog("Verify", 1.0, "Fingerprint OK", {})
                prog("Unpack", 0.1, "Unpacking the private Python…", {})
                self.safe_extract(archive, env_dir)
                exe = self.find_python(env_dir)
            if not exe:
                raise RuntimeError_("quarantine", "python executable missing")
            prog("Environment", 0.3, "Checking the new Python…", {})
            rc, out = self._run([exe, "-c",
                                 "import sys, tkinter, sqlite3, ssl; "
                                 "print(sys.version.split()[0], "
                                 "tkinter.TkVersion)"], 120, cancel)
            if rc != 0:
                kind = "tk" if "tkinter" in out or "_tkinter" in out \
                    else "quarantine"
                raise RuntimeError_(kind, out[-400:])
            version = out.split()[0] if out.split() else "?"
            self.install_packages(exe, prog, cancel)
            prog("Self-test", 0.1, "Running MiniWireshark's self-test in "
                 "the new environment…", {})
            ok, text = self.self_test(exe, cancel)
            if not ok:
                raise RuntimeError_("selftest", text[-600:])
        except BaseException:
            self._log("install failed; removing the half-built "
                      "environment")
            shutil.rmtree(env_dir, ignore_errors=True)
            raise
        prog("Switch", 0.5, "Switching to the new environment…", {})
        state = runtime_state_read()
        envs = dict(state.get("envs") or {})
        envs[env_id] = {"python": exe, "version": version,
                        "lock": lock_fingerprint(), "selftest_ok": True,
                        "created": time.time(), "dir": env_dir}
        state["envs"] = envs
        busy = state.get("current") and _same_interpreter(
            (runtime_env(state) or {}).get("python", ""), sys.executable)
        if busy:
            state["pending_switch"] = env_id       # applied at next start
        else:
            state["previous"] = state.get("current", "")
            state["current"] = env_id
            state["pending_starts"] = 0
        state["declined"] = False
        state["last_error"] = ""
        runtime_state_write(state)
        self.prune_old()
        prog("Switch", 1.0, "Done", {})
        return env_id

    def _usable_base(self, exe):
        try:
            r = subprocess.run([exe, "-c", "import sys, tkinter, venv; "
                                "print(sys.version_info[:2])"],
                               capture_output=True, text=True, timeout=30)
            return r.returncode == 0 and "(3, 14)" in r.stdout
        except (OSError, subprocess.SubprocessError):
            return False

    def _venv_from(self, base, env_dir, cancel):
        rc, _ = self._run([base, "-m", "venv", "--without-pip", env_dir],
                          300, cancel)
        if rc != 0:
            return ""
        exe = os.path.join(env_dir, "Scripts", "python.exe") if IS_WINDOWS \
            else os.path.join(env_dir, "bin", "python3")
        if not os.path.isfile(exe):
            return ""
        rc, _ = self._run([exe, "-m", "ensurepip", "--default-pip"], 300,
                          cancel)
        return exe if rc == 0 else ""

    def install_packages(self, exe, progress=None, cancel=lambda: False,
                         offline_only=False, force=False):
        prog = progress or (lambda *a: None)
        tag = wheel_platform_tag()
        req_text, pkgs, skipped = lock_requirements(tag)
        os.makedirs(self.wheels, exist_ok=True)
        req = os.path.join(self.root, "requirements.lock.txt")
        with open(req, "w", encoding="utf-8") as f:
            f.write(req_text)
        if not offline_only:
            prog("Packages", 0.1, "Downloading verified components…", {})
            rc, out = self._run([exe, "-m", "pip", "download",
                                 "--require-hashes", "--only-binary=:all:",
                                 "--no-deps", "-d", self.wheels, "-r", req],
                                900, cancel)
            if rc != 0:
                kind = "fingerprint" if "HASHES" in out.upper() and \
                    "MATCH" in out.upper() else classify_runtime_error(
                        OSError(out[-300:]))
                if kind == "other":
                    kind = "pip"
                raise RuntimeError_(kind, out[-600:])
        prog("Packages", 0.6, "Installing components…", {})
        cmd = [exe, "-m", "pip", "install", "--require-hashes",
               "--only-binary=:all:", "--no-deps", "--no-index",
               "--find-links", self.wheels, "-r", req]
        if force:
            cmd.insert(4, "--force-reinstall")
        rc, out = self._run(cmd, 900, cancel)
        if rc != 0:
            raise RuntimeError_("pip", out[-600:])
        prog("Packages", 1.0, "Components installed"
             + (f" (not available here: {', '.join(skipped)})"
                if skipped else ""), {})
        return pkgs, skipped

    def self_test(self, exe, cancel=lambda: False):
        try:
            rc, out = self._run([exe, self.script, SELF_TEST_FLAG,
                                 "--quick"], 600, cancel)
        except RuntimeError_ as e:
            if e.kind == "cancelled":
                raise
            return False, str(e)
        return rc == 0, out

    # ---- maintenance --------------------------------------------------------------
    def repair(self, progress=None, cancel=lambda: False):
        """Reinstall components from the downloaded copies (no network when
        the cache is complete), re-test, and re-record the environment.
        Rebuilds from the cached archive if the interpreter itself is
        damaged."""
        prog = progress or (lambda *a: None)
        st = runtime_state_read()
        env = runtime_env(st)
        if not env or not os.path.isfile(env.get("python", "")):
            prog("Check", 0.2, "The private Python is missing or damaged — "
                 "rebuilding it…", {})
            return self.provision(prog, cancel), "rebuilt"
        exe = env["python"]
        prog("Check", 0.5, "Checking installed components…", {})
        try:
            self.install_packages(exe, prog, cancel, offline_only=True,
                                  force=True)
            how = "reinstalled from the downloaded copies"
        except RuntimeError_ as e:
            if e.kind == "cancelled":
                raise
            self.install_packages(exe, prog, cancel, force=True)
            how = "downloaded again and reinstalled"
        ok, text = self.self_test(exe, cancel)
        st = runtime_state_read()
        env = runtime_env(st)
        if env is not None:
            env["selftest_ok"] = ok
            env["lock"] = lock_fingerprint()
            env["repaired"] = time.time()
            runtime_state_write(st)
        if not ok:
            raise RuntimeError_("selftest", text[-600:])
        return st.get("current"), how

    def rollback(self):
        st = runtime_state_read()
        prev = runtime_env(st, st.get("previous"))
        if not runtime_healthy(prev):
            return False
        st["current"], st["previous"] = st.get("previous"), st.get("current")
        st["pending_starts"] = 0
        runtime_state_write(st)
        return True

    def apply_pending_switch(self):
        st = runtime_state_read()
        nxt = st.get("pending_switch")
        if not nxt or not runtime_healthy(runtime_env(st, nxt)):
            return False
        st["previous"], st["current"] = st.get("current", ""), nxt
        st["pending_switch"] = ""
        st["pending_starts"] = 0
        runtime_state_write(st)
        return True

    def decline(self):
        st = runtime_state_read()
        st["declined"] = True
        st["declined_at"] = time.time()
        runtime_state_write(st)

    def remove(self):
        """Delete every private runtime (the next start uses the Python
        MiniWireshark was started with)."""
        st = runtime_state_read()
        running = st.get("current") and _same_interpreter(
            (runtime_env(st) or {}).get("python", ""), sys.executable)
        if running:
            st["remove_pending"] = True
            st["current"] = ""
            runtime_state_write(st)
            return "on-exit"
        shutil.rmtree(self.root, ignore_errors=True)
        return "removed"

    def prune_old(self, keep_days=7):
        st = runtime_state_read()
        keep = {st.get("current"), st.get("previous"),
                st.get("pending_switch")}
        envs = dict(st.get("envs") or {})
        changed = False
        for eid, env in list(envs.items()):
            if eid in keep:
                continue
            if time.time() - float(env.get("created", 0)) > keep_days * 86400:
                shutil.rmtree(env.get("dir") or os.path.join(self.root, eid),
                              ignore_errors=True)
                envs.pop(eid, None)
                changed = True
        if changed:
            st["envs"] = envs
            runtime_state_write(st)

    def export_offline_kit(self, folder):
        """Copy the verified archive and wheels to `folder` so another
        computer can install without Internet."""
        os.makedirs(folder, exist_ok=True)
        n = 0
        for d in (self.cache, self.wheels):
            if os.path.isdir(d):
                for name in os.listdir(d):
                    if name.endswith((".tar.gz", ".whl", ".exe")):
                        shutil.copy2(os.path.join(d, name), folder)
                        n += 1
        atomic_write_json(os.path.join(folder, "miniwireshark-kit.json"),
                          {"python": RUNTIME_PYTHON, "lock": RUNTIME_LOCK,
                           "sources": {f"{k[0]}-{k[1]}": v for k, v in
                                       RUNTIME_SOURCES.items()}})
        return n

    def import_offline_kit(self, folder):
        """Use a kit folder as the download cache (fingerprints are still
        checked before anything is used)."""
        n = 0
        os.makedirs(self.cache, exist_ok=True)
        os.makedirs(self.wheels, exist_ok=True)
        for name in os.listdir(folder):
            src = os.path.join(folder, name)
            if name.endswith(".whl"):
                shutil.copy2(src, self.wheels)
                n += 1
            elif name.endswith(".tar.gz"):
                shutil.copy2(src, self.cache)
                n += 1
        return n

    def check_newer_python(self, timeout=15):
        """Explicit, online: is there a newer python-build-standalone
        release than the one this version of MiniWireshark verified?
        Sends one ordinary request to api.github.com."""
        url = ("https://api.github.com/repos/astral-sh/"
               "python-build-standalone/releases/latest")
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME,
                                                   "Accept":
                                                   "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(2_000_000).decode("utf-8", "replace"))
        names = [a.get("name", "") for a in data.get("assets", [])]
        vers = set()
        for n in names:
            m = re.match(r"cpython-(3\.\d+\.\d+)\+", n)
            if m:
                vers.add(m.group(1))
        newest = max(vers, key=_version_tuple) if vers else ""
        same_minor = max((v for v in vers if v.startswith("3.14.")),
                         key=_version_tuple, default="")
        return {"tag": data.get("tag_name", ""), "newest": newest,
                "newest_314": same_minor, "verified": RUNTIME_PYTHON,
                "newer": bool(same_minor) and
                _version_tuple(same_minor) > _version_tuple(RUNTIME_PYTHON)}


def make_runtime_lock(packages=("scapy", "psutil", "cryptography", "cffi",
                                "pycparser")):
    """Release tooling: build RUNTIME_LOCK from PyPI's JSON API (needs
    Internet). Prints a dict to paste into the file."""
    tags = {"win_amd64": r"win_amd64", "win_arm64": r"win_arm64",
            "macosx_arm64": r"macosx_\d+_\d+_(arm64|universal2)",
            "macosx_x86_64": r"macosx_\d+_\d+_(x86_64|universal2)",
            "linux_x86_64": r"manylinux.*x86_64",
            "linux_aarch64": r"manylinux.*aarch64"}
    out = {}
    for pkg in packages:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json",
                                    timeout=30) as r:
            d = json.load(r)
        ver = d["info"]["version"]
        spec = {"version": ver, "required": pkg == "scapy"}
        for f in d["releases"][ver]:
            fn = f["filename"]
            if fn.endswith("-none-any.whl"):
                spec["any"] = (fn, f["digests"]["sha256"])
                break
            for tag, pat in tags.items():
                parts = fn.split("-")
                if len(parts) < 5 or not re.search(pat, fn) or \
                        "musllinux" in fn:
                    continue
                if parts[2] == "cp314" or parts[3] == "abi3":
                    spec.setdefault(tag, f["digests"]["sha256"])
        out[pkg] = spec
    return out


