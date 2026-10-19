def abi_tag(version=None, plat=None):
    """'cp312-win_amd64': one private packages folder per Python version
    and platform, so binary packages never mix after a Python upgrade."""
    import sysconfig
    v = version or sys.version_info[:2]
    p = plat or sysconfig.get_platform()
    p = re.sub(r"[^A-Za-z0-9]+", "_", p).strip("_").lower()
    return f"cp{v[0]}{v[1]}-{p}"


PKG_ROOT = os.path.join(PATHS.data, "site")
PKG_DIR = os.path.join(PKG_ROOT, abi_tag())

# Pure-Python wheels installed without pip: download, check the SHA-256
# written here, unzip. (scapy is pure Python, so the capture engine never
# needs pip.) Pip wheels let a Python without pip run pip from the wheel.
PURE_WHEELS = {
    "scapy": ("2.8.0", "scapy-2.8.0-py3-none-any.whl",
              "abf855145ee829a42b2eb28983cd6a0a52b12a31d3f861cb7be36791195ed9aa",
              2_762_122),
}
PIP_WHEELS = {
    "old": ("24.3.1", "pip-24.3.1-py3-none-any.whl",
            "3790624780082365f47549d032f3770eeb2b1e8bd1f7b2e02dace1afa361b4ed"),
    "new": ("25.2", "pip-25.2-py3-none-any.whl",
            "6d67a2b4e7f14d8b31b8b52648866fa717f45a1eb70e83002f4331d07e953717"),
}
# Optional binary packages: exact versions, installed only when you ask
# (Settings → Components); pip checks PyPI's own hashes.
OPTIONAL_PACKAGES = {
    "psutil": {"version": "7.2.2", "import": "psutil", "size_mb": 0.5,
               "license": "BSD-3-Clause",
               "benefit": "Shows which program on this computer owns each "
                          "connection; adapter link status; CPU-aware "
                          "performance mode."},
    "cryptography": {"version": "50.0.2", "version_py38": "46.0.3",
                     "import": "cryptography",
                     "size_mb": 4.5, "license": "Apache-2.0 or BSD",
                     "benefit": "Reads HTTP/3 (QUIC) site names about 50x "
                                "faster than the built-in pure-Python "
                                "code."},
}


def optional_version(key, version=None):
    spec = OPTIONAL_PACKAGES[key]
    v = tuple(version or sys.version_info[:2])
    if v < (3, 9) and spec.get("version_py38"):
        return spec["version_py38"]
    return spec["version"]


def pypi_file_url(filename):
    """files.pythonhosted.org serves every release file at a predictable
    path (it redirects to the hashed location)."""
    name = filename.split("-", 1)[0].lower().replace("_", "-")
    pytag = filename[:-4].split("-")[-3] if filename.endswith(".whl") \
        else "source"
    return (f"https://files.pythonhosted.org/packages/{pytag}/{name[0]}/"
            f"{name}/{filename}")


def fetch_to_file(url, dest, expected_sha=None, feature="packages",
                  progress=None, cancel=lambda: False, size_hint=0,
                  max_bytes=200 * 1024 * 1024, timeout=60):
    """Download behind the outbound gate: resumable, capped in size,
    cancellable, checked against a SHA-256 when one is given. Writes
    dest only when everything checked out. Raises RuntimeError_."""
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    if expected_sha and os.path.exists(dest) and \
            sha256_file(dest) == expected_sha:
        return dest
    part = dest + ".part"
    have = os.path.getsize(part) if (expected_sha and
                                     os.path.exists(part)) else 0
    req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
    if have:
        req.add_header("Range", f"bytes={have}-")
    t0, last = time.time(), 0.0
    try:
        with net_urlopen(feature, req, timeout,
                         os.path.basename(dest)) as r:
            if have and getattr(r, "status", 200) != 206:
                have = 0
            total = int(r.headers.get("Content-Length") or 0) + have
            total = total or size_hint
            if total and total > max_bytes:
                raise RuntimeError_("other", f"{total} bytes is more than "
                                             f"the {max_bytes} limit")
            got = have
            with open(part, "ab" if have else "wb") as f:
                while True:
                    if cancel():
                        raise RuntimeError_("cancelled")
                    chunk = r.read(256 * 1024)
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > max_bytes:
                        raise RuntimeError_("other", "download larger than "
                                                     "its limit")
                    f.write(chunk)
                    now = time.time()
                    if progress and now - last > 0.2:
                        last = now
                        speed = (got - have) / max(0.001, now - t0)
                        eta = (total - got) / speed if speed and total \
                            else 0
                        progress("Download", got / total if total else 0.0,
                                 f"{got / 1e6:.1f} of {total / 1e6:.1f} MB",
                                 {"speed": speed, "eta": eta})
    except RuntimeError_:
        raise
    except (OSError, urllib.error.URLError) as e:
        raise RuntimeError_(classify_runtime_error(e), str(e))
    if expected_sha:
        actual = sha256_file(part)
        if actual != expected_sha:
            with contextlib.suppress(OSError):
                os.remove(part)
            raise RuntimeError_("fingerprint",
                                f"expected {expected_sha}, got {actual}")
    os.replace(part, dest)
    return dest


class PrivatePackages:
    """MiniWireshark's own packages folder, one per Python version and
    platform, added to sys.path at startup. Installing here never touches
    the system Python: pure-Python wheels are unzipped after a SHA-256
    check; binary packages go through `pip install --target` run by this
    same Python (or by pip straight from its pinned wheel when this Python
    has no pip). Each package is swapped in atomically and the previous
    copy is kept until the new one imports."""

    def __init__(self, root=None, cache=None, python=None):
        self.root = root or PKG_DIR
        self.cache = cache or os.path.join(PATHS.cache, "wheels")
        self.python = python or sys.executable
        self.manifest_path = os.path.join(self.root, "mw-packages.json")

    # ---- state -----------------------------------------------------------
    def manifest(self):
        m = read_json(self.manifest_path, None)
        if not isinstance(m, dict) or not isinstance(m.get("packages"),
                                                     dict):
            m = {"packages": {}}
        return m

    def _save(self, m):
        os.makedirs(self.root, exist_ok=True)
        atomic_write_json(self.manifest_path, m)

    def installed(self):
        return dict(self.manifest()["packages"])

    def activate(self):
        """Put the folder on sys.path (after the script's own folder)."""
        if os.path.isdir(self.root) and self.root not in sys.path:
            sys.path.insert(1 if sys.path else 0, self.root)
            importlib.invalidate_caches()
            return True
        return False

    def size_bytes(self):
        total = 0
        for dp, _dn, fn in os.walk(self.root):
            for n in fn:
                with contextlib.suppress(OSError):
                    total += os.path.getsize(os.path.join(dp, n))
        return total

    # ---- install ---------------------------------------------------------
    @staticmethod
    def _safe_names(zf):
        for info in zf.infolist():
            n = info.filename.replace("\\", "/")
            if n.startswith("/") or re.match(r"^[A-Za-z]:", n) or \
                    any(part == ".." for part in n.split("/")):
                raise RuntimeError_("other", f"unsafe path in wheel: {n}")
        return [i.filename for i in zf.infolist()]

    def install_wheel_file(self, path, source="", sha=""):
        """Unzip a pure-Python wheel into the folder, atomically per
        top-level entry. Returns (name, version)."""
        import zipfile
        os.makedirs(self.root, exist_ok=True)
        staging = os.path.join(self.root, f".staging-{uuid.uuid4().hex[:8]}")
        try:
            with zipfile.ZipFile(path) as zf:
                names = self._safe_names(zf)
                dist = sorted({n.split("/")[0] for n in names
                               if n.split("/")[0].endswith(".dist-info")})
                if len(dist) != 1:
                    raise RuntimeError_("other", "not a wheel (no single "
                                                 ".dist-info folder)")
                zf.extractall(staging)
            m = re.match(r"(.+?)-([^-]+)\.dist-info$", dist[0])
            name, version = (m.group(1), m.group(2)) if m else \
                (dist[0], "?")
            self._merge(staging, name, version, source, sha)
            return name, version
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _merge(self, staging, name, version, source, sha):
        """Move each top-level entry of staging into the folder, replacing
        older copies; the manifest records which entries belong to whom."""
        m = self.manifest()
        key = name.lower().replace("_", "-")
        old_entries = (m["packages"].get(key) or {}).get("entries", [])
        entries = sorted(os.listdir(staging))
        backup = os.path.join(self.root, f".old-{uuid.uuid4().hex[:8]}")
        os.makedirs(backup, exist_ok=True)
        moved = []
        try:
            for e in set(entries) | set(old_entries):
                cur = os.path.join(self.root, e)
                if os.path.lexists(cur):
                    os.replace(cur, os.path.join(backup, e))
                    moved.append(e)
            for e in entries:
                os.replace(os.path.join(staging, e),
                           os.path.join(self.root, e))
        except OSError:
            for e in entries:                      # roll back
                with contextlib.suppress(OSError):
                    p = os.path.join(self.root, e)
                    if os.path.isdir(p) and not os.path.islink(p):
                        shutil.rmtree(p)
                    elif os.path.lexists(p):
                        os.remove(p)
            for e in moved:
                with contextlib.suppress(OSError):
                    os.replace(os.path.join(backup, e),
                               os.path.join(self.root, e))
            raise
        finally:
            shutil.rmtree(backup, ignore_errors=True)
        m["packages"][key] = {"version": version, "entries": entries,
                              "source": source, "sha256": sha,
                              "installed": time.time()}
        self._save(m)
        importlib.invalidate_caches()

    def install_pure(self, key, progress=None, cancel=lambda: False):
        version, filename, sha, size = PURE_WHEELS[key]
        dest = os.path.join(self.cache, filename)
        fetch_to_file(pypi_file_url(filename), dest, sha, "packages",
                      progress, cancel, size_hint=size,
                      max_bytes=max(4 * size, 8 << 20))
        return self.install_wheel_file(dest, source=pypi_file_url(filename),
                                       sha=sha)

    def pip_command(self, specs, target):
        """The pip command line (never --user, never into the system)."""
        base = ["install", "--target", target, "--only-binary=:all:",
                "--no-input", "--disable-pip-version-check",
                "--no-warn-script-location", "--upgrade"] + list(specs)
        if self._has_pip():
            return [self.python, "-m", "pip"] + base
        wheel = self._pip_wheel()
        return [self.python, os.path.join(wheel, "pip")] + base

    def _has_pip(self):
        try:
            r = subprocess.run([self.python, "-m", "pip", "--version"],
                               capture_output=True, text=True, timeout=30)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _pip_wheel(self, progress=None, cancel=lambda: False):
        old = sys.version_info[:2] < (3, 9) if self.python == \
            sys.executable else False
        version, filename, sha = PIP_WHEELS["old" if old else "new"]
        dest = os.path.join(self.cache, filename)
        fetch_to_file(pypi_file_url(filename), dest, sha, "packages",
                      progress, cancel, max_bytes=8 << 20)
        return dest

    def pip_install(self, key, progress=None, cancel=lambda: False,
                    timeout=900):
        """Install one optional package (and its dependencies) with pip
        into a staging folder, then swap it in."""
        ver = optional_version(key)
        staging = os.path.join(self.root, f".staging-{uuid.uuid4().hex[:8]}")
        os.makedirs(staging, exist_ok=True)
        try:
            outbound("packages", "https", "pypi.org",
                     f"pip install {key}=={ver}")
            cmd = self.pip_command([f"{key}=={ver}"], staging)
            if progress:
                progress("Packages", 0.2, f"Installing {key} {ver}…", {})
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout)
            except subprocess.TimeoutExpired:
                raise RuntimeError_("network", f"pip took more than "
                                               f"{timeout} s")
            if r.returncode != 0:
                raise RuntimeError_("pip", ((r.stdout or "") +
                                            (r.stderr or ""))[-800:])
            dists = sorted(d for d in os.listdir(staging)
                           if d.endswith(".dist-info"))
            # one manifest entry per installed distribution
            groups = self._group_by_dist(staging, dists)
            for dname, (version, entries) in groups.items():
                sub = os.path.join(staging, f".one-{dname}")
                os.makedirs(sub, exist_ok=True)
                for e in entries:
                    os.replace(os.path.join(staging, e),
                               os.path.join(sub, e))
                self._merge(sub, dname, version, "pypi.org (pip)", "")
            return ver
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    @staticmethod
    def _group_by_dist(staging, dists):
        """dist name → (version, top-level entries) using RECORD files."""
        out = {}
        claimed = set()
        for d in dists:
            m = re.match(r"(.+?)-([^-]+)\.dist-info$", d)
            name, version = (m.group(1), m.group(2)) if m else (d, "?")
            entries = {d}
            rec = os.path.join(staging, d, "RECORD")
            with contextlib.suppress(OSError):
                with open(rec, encoding="utf-8", errors="replace") as f:
                    for row in csv.reader(f):
                        if row and row[0]:
                            top = row[0].replace("\\", "/").split("/")[0]
                            if top and top != ".." and \
                                    os.path.lexists(os.path.join(staging,
                                                                 top)):
                                entries.add(top)
            entries -= claimed
            claimed |= entries
            out[name] = (version, sorted(entries))
        rest = [e for e in os.listdir(staging)
                if e not in claimed and not e.startswith(".")]
        if rest and out:
            first = next(iter(out))
            v, ents = out[first]
            out[first] = (v, sorted(set(ents) | set(rest)))
        return out

    # ---- remove ----------------------------------------------------------
    def remove(self, key):
        m = self.manifest()
        key = key.lower().replace("_", "-")
        info = m["packages"].pop(key, None)
        if not info:
            return False
        for e in info.get("entries", []):
            p = os.path.join(self.root, e)
            with contextlib.suppress(OSError):
                if os.path.isdir(p) and not os.path.islink(p):
                    shutil.rmtree(p)
                elif os.path.lexists(p):
                    os.remove(p)
        self._save(m)
        importlib.invalidate_caches()
        return True

    def reset(self):
        """Delete the whole folder (all private packages)."""
        if self.root in sys.path:
            sys.path.remove(self.root)
        shutil.rmtree(self.root, ignore_errors=True)
        importlib.invalidate_caches()


PRIVATE_PACKAGES = PrivatePackages()
PRIVATE_PACKAGES.activate()
