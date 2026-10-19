    # ---- environment diagnostics (component by component) -----------------------
    COMPONENT_MODULES = {"scapy": "scapy", "psutil": "psutil",
                         "cryptography": "cryptography", "cffi": "cffi",
                         "pycparser": "pycparser"}
    PROBE = (
        "import json, sys, importlib\n"
        "out = {'python': sys.version.split()[0], 'exe': sys.executable}\n"
        "try:\n"
        "    import importlib.metadata as md\n"
        "except ImportError:\n"
        "    md = None\n"
        "def ver(d):\n"
        "    try:\n"
        "        return md.version(d) if md else ''\n"
        "    except Exception:\n"
        "        return ''\n"
        "out['pip'] = ver('pip')\n"
        "try:\n"
        "    import tkinter\n"
        "    out['tk'] = str(tkinter.TkVersion)\n"
        "except Exception:\n"
        "    out['tk'] = ''\n"
        "try:\n"
        "    import ssl\n"
        "    out['ssl'] = ssl.OPENSSL_VERSION\n"
        "except Exception:\n"
        "    out['ssl'] = ''\n"
        "pk = {}\n"
        "for dist, mod in json.loads(sys.argv[1]).items():\n"
        "    r = {'version': ver(dist), 'import': False, 'error': ''}\n"
        "    try:\n"
        "        importlib.import_module(mod)\n"
        "        r['import'] = True\n"
        "    except Exception as e:\n"
        "        r['error'] = (type(e).__name__ + ': ' + str(e))[:200]\n"
        "    pk[dist] = r\n"
        "out['packages'] = pk\n"
        "print('MWPROBE' + json.dumps(out))\n")

    def _is_private(self, exe):
        try:
            root = os.path.realpath(self.root)
            return os.path.realpath(exe).startswith(root + os.sep)
        except (OSError, ValueError):
            return False

    def _env_for(self, exe):
        env = dict(os.environ)
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        if self._is_private(exe):
            for k in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
                env.pop(k, None)
            env["PYTHONNOUSERSITE"] = "1"
        return env

    def components(self, exe=None, timeout=180):
        """Each component in `exe` (default: the Python running now):
        installed version, whether it loads, plus pip / Tk / SSL."""
        exe = exe or sys.executable
        try:
            r = subprocess.run(
                [exe, "-c", self.PROBE, json.dumps(self.COMPONENT_MODULES)],
                capture_output=True, text=True, timeout=timeout,
                env=self._env_for(exe),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as e:
            return {"error": f"could not start {exe}: {e}", "packages": {}}
        for line in (r.stdout or "").splitlines():
            if line.startswith("MWPROBE"):
                try:
                    return json.loads(line[7:])
                except ValueError:
                    break
        return {"error": ((r.stderr or r.stdout or "no output")[-400:]),
                "packages": {}}

    def pip_check(self, exe=None, timeout=180):
        """`pip check`: packages whose requirements are missing or in
        conflict. → (ok, [problem lines])."""
        exe = exe or sys.executable
        try:
            r = subprocess.run([exe, "-m", "pip", "check"],
                               capture_output=True, text=True,
                               timeout=timeout, env=self._env_for(exe),
                               creationflags=getattr(
                                   subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as e:
            return False, [f"pip could not run: {e}"]
        lines = [ln.strip() for ln in (r.stdout or "").splitlines()
                 if ln.strip() and "no broken requirements" not in
                 ln.lower()]
        if r.returncode != 0 and not lines:
            lines = [(r.stderr or "pip check failed").strip()[-300:]]
        return r.returncode == 0, lines

    def update_pip(self, exe, progress=None, cancel=lambda: False):
        """Bring pip up to date INSIDE the private Python only: first from
        the copy bundled with Python (offline), then from PyPI. Your own
        Python's pip is never touched. → (old, new)."""
        if not self._is_private(exe):
            raise RuntimeError_("other", "pip is only updated inside "
                                         "MiniWireshark's private Python")
        prog = progress or (lambda *a: None)
        old = self.components(exe).get("pip", "")
        prog("Packages", 0.2, "Updating pip from the copy bundled with "
             "Python…", {})
        self._run([exe, "-m", "ensurepip", "--upgrade"], 300, cancel)
        prog("Packages", 0.6, "Asking PyPI for the newest pip…", {})
        rc, out = self._run([exe, "-m", "pip", "install", "--upgrade",
                             "--only-binary=:all:", "pip"], 300, cancel)
        if rc != 0:
            self._log("pip could not be updated online (kept the bundled "
                      "version)")
        new = self.components(exe).get("pip", "")
        prog("Packages", 1.0, f"pip {new or '?'}", {})
        return old, new

    @staticmethod
    def component_rows(info, lock=None, pip_problems=()):
        """→ [(name, installed, verified, status, severity)] for display
        and tests; severity: ok | warn | bad."""
        lock = lock or RUNTIME_LOCK
        rows = []
        if info.get("error") and not info.get("packages"):
            return [("Python", "", "", "Could not be checked: " +
                     info["error"][-200:], "bad")]
        rows.append(("Python", info.get("python", ""), RUNTIME_PYTHON,
                     "OK" if _version_tuple(info.get("python", "")) >= (3, 8)
                     else "Too old", "ok"))
        rows.append(("Graphical toolkit (Tk)", info.get("tk", ""), "",
                     "OK" if info.get("tk") else "Missing",
                     "ok" if info.get("tk") else "bad"))
        rows.append(("pip", info.get("pip", ""), "",
                     "OK" if info.get("pip") else "Missing (Repair adds it)",
                     "ok" if info.get("pip") else "warn"))
        broken = " ".join(pip_problems).lower()
        for name, spec in lock.items():
            r = (info.get("packages") or {}).get(name, {})
            have, want = r.get("version", ""), spec.get("version", "")
            if not have:
                st, sev = ("Missing" + (" — needed" if spec.get("required")
                                        else " (optional feature off)"),
                           "bad" if spec.get("required") else "warn")
            elif not r.get("import"):
                st, sev = "Installed but won't load: " + r.get(
                    "error", "")[:120], "bad"
            elif name.lower() in broken:
                st, sev = "Conflicting requirements (Repair fixes it)", "bad"
            elif have != want:
                st, sev = (f"Works; a different version than the one this "
                           f"release verified ({want})", "warn")
            else:
                st, sev = "OK — the verified version", "ok"
            rows.append((name, have, want, st, sev))
        return rows

    def diagnose(self, exe=None):
        """Full environment report as text (used by Diagnostics, the
        Runtime Manager and the debug bundle)."""
        exe = exe or sys.executable
        info = self.components(exe)
        ok, problems = self.pip_check(exe) if info.get("pip") else \
            (True, [])
        rows = self.component_rows(info, pip_problems=problems)
        mark = {"ok": "✔", "warn": "⚠", "bad": "✖"}
        lines = [f"Environment: {exe}"
                 + ("  (MiniWireshark's private Python)"
                    if self._is_private(exe) else "")]
        if info.get("ssl"):
            lines.append(f"Secure connections: {info['ssl']}")
        for name, have, want, st, sev in rows:
            lines.append(f"{mark[sev]} {name:<22} {have or '—':<10} {st}")
        if problems:
            lines.append("pip check found:")
            lines += ["   " + p for p in problems[:20]]
        else:
            lines.append("✔ pip check: no missing or conflicting "
                         "requirements.")
        worst = "bad" if any(r[4] == "bad" for r in rows) or (
            problems and any(n in " ".join(problems).lower()
                             for n in RUNTIME_LOCK)) else \
            "warn" if any(r[4] == "warn" for r in rows) else "ok"
        return {"text": "\n".join(lines), "rows": rows, "worst": worst,
                "pip_problems": problems, "info": info}

    # ---- a newer compatible Python, installed side by side on request -------------
    def newer_python_source(self, info=None, release=None, timeout=20):
        """If GitHub has a newer Python 3.14.x build for this computer,
        return {version, name, sha, tag, url}. The fingerprint comes from
        GitHub's own checksum for that file (not built into this release),
        so the new Python is only used after the self-test passes in it."""
        plat = runtime_platform()
        cur = RUNTIME_SOURCES.get(plat)
        if not cur:
            return None
        rel = release
        if rel is None:
            url = ("https://api.github.com/repos/astral-sh/"
                   "python-build-standalone/releases/latest")
            req = urllib.request.Request(url, headers={
                "User-Agent": APP_NAME, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                rel = json.loads(r.read(16_000_000).decode("utf-8",
                                                           "replace"))
        tag = rel.get("tag_name", "")
        assets = list(rel.get("assets") or [])
        suffix = cur[0].split("-", 2)[2]       # e.g. x86_64-…-stripped.tar.gz
        best = None
        for a in assets:
            n = a.get("name", "")
            m = re.match(r"cpython-(3\.14\.\d+)\+(\d+)-(.+)$", n)
            if not m or m.group(3) != suffix:
                continue
            if best is None or _version_tuple(m.group(1)) > \
                    _version_tuple(best[0]):
                best = (m.group(1), n, a)
        if best is None or _version_tuple(best[0]) <= \
                _version_tuple(RUNTIME_PYTHON):
            return None
        digest = str(best[2].get("digest") or "")
        sha = digest.split(":", 1)[1] if digest.startswith("sha256:") \
            else ""
        if not re.match(r"^[0-9a-f]{64}$", sha):
            return None                  # no checksum published: don't offer
        return {"version": best[0], "name": best[1], "sha": sha,
                "tag": tag, "url": best[2].get("browser_download_url") or
                RUNTIME_PBS_BASE + tag + "/" + urllib.request.quote(
                    best[1])}
