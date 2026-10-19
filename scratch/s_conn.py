# ============================================================================
#  10.  Connected helpers (optional, for power users): Pi-hole and AdGuard
#       Home. Read-only: MiniWireshark only ASKS them for their query log
#       and device names. What they say is "Reported" evidence — shown
#       beside what was observed on the wire, never added to it.
# ============================================================================
class CredentialVault:
    """Where connector passwords live: Windows DPAPI, the macOS Keychain,
    the Linux Secret Service (secret-tool), or — when none exists — a file
    only your user account can read. Never in settings, logs or bundles."""

    SERVICE = "MiniWireshark"

    def __init__(self, path=None):
        self.path = path or os.path.join(PATHS.data, "vault.json")
        self.backend = self._pick()

    def _pick(self):
        if IS_WINDOWS:
            return "dpapi"
        if sys.platform == "darwin" and shutil.which("security"):
            return "keychain"
        if shutil.which("secret-tool") and os.environ.get(
                "DBUS_SESSION_BUS_ADDRESS"):
            return "secret-service"
        return "file"

    def describe(self):
        return {"dpapi": "Windows data protection (only your account can "
                         "unlock it)",
                "keychain": "the macOS Keychain",
                "secret-service": "your desktop's keyring",
                "file": "a private file only your user account can read "
                        "(this system has no keyring)"}[self.backend]

    def _file(self):
        d = read_json(self.path, {}) or {}
        return d if isinstance(d, dict) else {}

    def _write_file(self, d):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        atomic_write_json(self.path, d)
        with contextlib.suppress(OSError):
            os.chmod(self.path, 0o600)

    @staticmethod
    def _dpapi(data, protect=True):
        import ctypes.wintypes as wt

        class BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]
        buf = ctypes.create_string_buffer(data, len(data))
        inp = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(
            ctypes.c_char)))
        out = BLOB()
        fn = ctypes.windll.crypt32.CryptProtectData if protect else \
            ctypes.windll.crypt32.CryptUnprotectData
        ok = fn(ctypes.byref(inp), None, None, None, None, 0,
                ctypes.byref(out))
        if not ok:
            raise OSError("Windows data protection refused")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    def set(self, cid, secret):
        register_secret(secret)
        if self.backend == "keychain":
            r = subprocess.run(["security", "add-generic-password", "-U",
                                "-a", cid, "-s", self.SERVICE, "-w", secret],
                               capture_output=True, timeout=20)
            if r.returncode == 0:
                return True
        elif self.backend == "secret-service":
            r = subprocess.run(["secret-tool", "store", "--label",
                                f"{self.SERVICE} {cid}", "service",
                                self.SERVICE, "account", cid],
                               input=secret.encode(), capture_output=True,
                               timeout=20)
            if r.returncode == 0:
                return True
        d = self._file()
        if self.backend == "dpapi":
            d[cid] = {"dpapi": base64.b64encode(self._dpapi(
                secret.encode())).decode()}
        else:
            d[cid] = {"plain": base64.b64encode(secret.encode()).decode()}
        self._write_file(d)
        return True

    def get(self, cid):
        val = None
        try:
            if self.backend == "keychain":
                r = subprocess.run(["security", "find-generic-password",
                                    "-a", cid, "-s", self.SERVICE, "-w"],
                                   capture_output=True, text=True,
                                   timeout=20)
                if r.returncode == 0:
                    val = r.stdout.rstrip("\\n")
            elif self.backend == "secret-service":
                r = subprocess.run(["secret-tool", "lookup", "service",
                                    self.SERVICE, "account", cid],
                                   capture_output=True, text=True,
                                   timeout=20)
                if r.returncode == 0 and r.stdout:
                    val = r.stdout.rstrip("\\n")
            if val is None:
                ent = self._file().get(cid) or {}
                if "dpapi" in ent and IS_WINDOWS:
                    val = self._dpapi(base64.b64decode(ent["dpapi"]),
                                      protect=False).decode()
                elif "plain" in ent:
                    val = base64.b64decode(ent["plain"]).decode()
        except (OSError, ValueError, subprocess.SubprocessError):
            val = None
        if val:
            register_secret(val)
        return val

    def delete(self, cid):
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            if self.backend == "keychain":
                subprocess.run(["security", "delete-generic-password", "-a",
                                cid, "-s", self.SERVICE], capture_output=True,
                               timeout=20)
            elif self.backend == "secret-service":
                subprocess.run(["secret-tool", "clear", "service",
                                self.SERVICE, "account", cid],
                               capture_output=True, timeout=20)
        d = self._file()
        if d.pop(cid, None) is not None:
            self._write_file(d)


class ConnectorError(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind          # auth | tls | network | api | refused


def connector_http(method, url, headers=None, body=None, pin="",
                   verify=True, timeout=10.0):
    """One HTTP(S) request to a helper on your network, through the
    outbound gate. `pin` = the SHA-256 of a self-signed certificate you
    accepted. → (status, headers dict, body bytes)."""
    import http.client
    import ssl
    parts = urllib.parse.urlsplit(url)
    host, port = parts.hostname or "", parts.port
    path = (parts.path or "/") + (("?" + parts.query) if parts.query
                                  else "")
    outbound("connector", parts.scheme, f"{host}:{port or ''}".rstrip(":"),
             f"{method} {parts.path or '/'}")
    try:
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            if pin or not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port or 443,
                                               timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port or 80,
                                              timeout=timeout)
        conn.request(method, path, body=body, headers=dict(
            {"User-Agent": APP_NAME, "Accept": "application/json"},
            **(headers or {})))
        if parts.scheme == "https" and pin:
            der = conn.sock.getpeercert(binary_form=True) or b""
            if hashlib.sha256(der).hexdigest() != pin.lower():
                conn.close()
                raise ConnectorError("tls", "The helper's certificate "
                                            "changed since you accepted it.")
        resp = conn.getresponse()
        data = resp.read(16 * 1024 * 1024)
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, hdrs, data
    except ssl.SSLCertVerificationError as e:
        raise ConnectorError("tls", f"The certificate isn't trusted ({e."
                                    f"verify_message}). If this is your own "
                                    f"Pi-hole/AdGuard with its built-in "
                                    f"certificate, choose “Trust this "
                                    f"certificate”.")
    except ConnectorError:
        raise
    except OutboundBlocked as e:
        raise ConnectorError("refused", str(e))
    except (OSError, http.client.HTTPException) as e:
        raise ConnectorError("network", f"Couldn't reach {host}: {e}")


def connector_cert_fingerprint(url, timeout=8.0):
    """SHA-256 of the certificate a helper presents (for “Trust this
    certificate”)."""
    import ssl
    parts = urllib.parse.urlsplit(url)
    outbound("connector", "tls", parts.hostname or "", "read certificate")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with _socket.create_connection((parts.hostname, parts.port or 443),
                                   timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=parts.hostname) as tls:
            der = tls.getpeercert(binary_form=True) or b""
    return hashlib.sha256(der).hexdigest()


class Connector:
    kind, title = "", ""
    PATH_HINT = ""

    def __init__(self, spec, vault):
        self.spec = dict(spec)
        self.id = spec["id"]
        self.name = spec.get("name") or self.title
        self.url = spec.get("url", "").rstrip("/")
        self.vault = vault
        self.pin = spec.get("pin", "")
        self.verify = bool(spec.get("verify", True))

    def _get(self, path, headers=None, method="GET", body=None):
        st, hd, data = connector_http(method, self.url + path, headers, body,
                                      self.pin, self.verify)
        return st, hd, data

    @staticmethod
    def _json(data):
        try:
            return json.loads(data.decode("utf-8", "replace") or "null")
        except ValueError:
            raise ConnectorError("api", "The helper answered something that "
                                        "isn't JSON — is this the right "
                                        "address?")

    def test(self):
        raise NotImplementedError

    def fetch(self, since, limit=5000):
        raise NotImplementedError

    def close(self):
        pass


class PiHoleConnector(Connector):
    """Pi-hole v6 REST API: POST /api/auth (password or app password) →
    session ID in the X-FTL-SID header; GET /api/queries and
    /api/network/devices; DELETE /api/auth when done."""

    kind, title = "pihole", "Pi-hole"
    PATH_HINT = "http://pi.hole or https://192.168.1.2"

    def __init__(self, spec, vault):
        super().__init__(spec, vault)
        self.sid = ""
        self.sid_until = 0.0

    def _login(self):
        if self.sid and time.time() < self.sid_until - 30:
            return
        pw = self.vault.get(self.id) or ""
        st, _h, data = self._get("/api/auth", {"Content-Type":
                                               "application/json"}, "POST",
                                 json.dumps({"password": pw}).encode())
        if st == 401:
            raise ConnectorError("auth", "Pi-hole refused the password. Use "
                                         "your Pi-hole password or an app "
                                         "password (Settings → Web "
                                         "interface / API).")
        if st == 404:
            raise ConnectorError("api", "No Pi-hole v6 API at this address "
                                        "(Pi-hole 5 isn't supported).")
        if st >= 400:
            raise ConnectorError("api", f"Pi-hole answered HTTP {st}.")
        sess = (self._json(data) or {}).get("session") or {}
        if not sess.get("valid"):
            raise ConnectorError("auth", "Pi-hole didn't accept the "
                                         "password.")
        self.sid = sess.get("sid") or ""
        if self.sid:
            register_secret(self.sid)
        self.sid_until = time.time() + float(sess.get("validity") or 300)

    def _api(self, path):
        self._login()
        hd = {"X-FTL-SID": self.sid} if self.sid else {}
        st, _h, data = self._get(path, hd)
        if st == 401:
            self.sid = ""
            self._login()
            hd = {"X-FTL-SID": self.sid} if self.sid else {}
            st, _h, data = self._get(path, hd)
        if st >= 400:
            raise ConnectorError("api", f"Pi-hole answered HTTP {st} for "
                                        f"{path.split('?')[0]}.")
        return self._json(data)

    def test(self):
        info = self._api("/api/info/version")
        ver = ""
        with contextlib.suppress(AttributeError, TypeError, KeyError):
            ver = info["version"]["core"]["local"]["version"]
        return f"Connected to Pi-hole {ver}".strip()

    def fetch(self, since, limit=5000):
        out = {"lookups": [], "devices": []}
        until = time.time() + 60
        q = self._api(f"/api/queries?from={int(since)}&until={int(until)}"
                      f"&length={int(limit)}")
        for r in (q or {}).get("queries") or []:
            try:
                ts = float(r.get("time") or 0)
                cl = r.get("client") or {}
                status = str(r.get("status") or "")
                rep = r.get("reply") or {}
                ms = rep.get("time")
                out["lookups"].append({
                    "ts": ts, "client": str(cl.get("ip") or ""),
                    "client_name": str(cl.get("name") or ""),
                    "domain": str(r.get("domain") or "").lower().strip("."),
                    "type": str(r.get("type") or ""),
                    "blocked": status in PIHOLE_BLOCKED,
                    "status": status,
                    "ms": float(ms) * 1000.0 if isinstance(
                        ms, (int, float)) and ms < 60 else None})
            except (TypeError, ValueError, AttributeError):
                continue
        d = self._api("/api/network/devices?max_devices=500&"
                      "max_addresses=8")
        for dev in (d or {}).get("devices") or []:
            ips = [(a.get("ip") or "", a.get("name") or "")
                   for a in dev.get("ips") or [] if isinstance(a, dict)]
            out["devices"].append({
                "mac": str(dev.get("hwaddr") or "").lower(),
                "ips": [i for i, _n in ips if i],
                "names": [n for _i, n in ips if n],
                "vendor": dev.get("macVendor") or "",
                "last": float(dev.get("lastQuery") or 0)})
        return out

    def close(self):
        if self.sid:
            with contextlib.suppress(ConnectorError):
                self._get("/api/auth", {"X-FTL-SID": self.sid}, "DELETE")
            self.sid = ""


PIHOLE_BLOCKED = {"GRAVITY", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP",
                  "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
                  "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
                  "SPECIAL_DOMAIN", "DBBUSY", "EXTERNAL_BLOCKED_EDE15"}


class AdGuardConnector(Connector):
    """AdGuard Home (/control API, HTTP Basic auth): GET /control/status,
    /control/querylog and /control/clients."""

    kind, title = "adguard", "AdGuard Home"
    PATH_HINT = "http://192.168.1.2:3000 or https://adguard.home"

    def _auth(self):
        user = self.spec.get("username", "")
        pw = self.vault.get(self.id) or ""
        if not user and not pw:
            return {}
        tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
        register_secret(tok)
        return {"Authorization": "Basic " + tok}

    def _api(self, path):
        st, _h, data = self._get("/control" + path, self._auth())
        if st in (401, 403):
            raise ConnectorError("auth", "AdGuard Home refused the user name "
                                         "or password.")
        if st == 404:
            raise ConnectorError("api", "No AdGuard Home API at this "
                                        "address.")
        if st >= 400:
            raise ConnectorError("api", f"AdGuard Home answered HTTP {st}.")
        return self._json(data)

    def test(self):
        st = self._api("/status") or {}
        return f"Connected to AdGuard Home {st.get('version', '')}".strip()

    @staticmethod
    def _ts(text):
        # "2024-05-01T12:00:00.123456789Z" or with an offset
        m = re.match(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?"
                     r"(Z|[+-]\d\d:\d\d)?", str(text or ""))
        if not m:
            return 0.0
        import calendar
        secs = calendar.timegm(tuple(int(m.group(i)) for i in range(1, 7)))
        frac = float("0" + m.group(7)[:7]) if m.group(7) else 0.0
        tz = m.group(8) or "Z"
        if tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            secs -= sign * (int(tz[1:3]) * 3600 + int(tz[4:6]) * 60)
        return secs + frac

    def fetch(self, since, limit=5000):
        out = {"lookups": [], "devices": []}
        older = ""
        while len(out["lookups"]) < limit:
            q = self._api("/querylog?limit=500" + (
                "&older_than=" + urllib.parse.quote(older) if older else ""))
            rows = (q or {}).get("data") or []
            if not rows:
                break
            stop = False
            for r in rows:
                ts = self._ts(r.get("time"))
                if ts and ts < since:
                    stop = True
                    break
                qn = (r.get("question") or {})
                ci = r.get("client_info") or {}
                reason = str(r.get("reason") or "")
                ms = None
                with contextlib.suppress(TypeError, ValueError):
                    ms = float(r.get("elapsedMs"))
                out["lookups"].append({
                    "ts": ts, "client": str(r.get("client") or ""),
                    "client_name": str(ci.get("name") or ""),
                    "domain": str(qn.get("name") or "").lower().strip("."),
                    "type": str(qn.get("type") or ""),
                    "blocked": reason.startswith("Filtered") and
                    "NotFiltered" not in reason,
                    "status": reason, "ms": ms})
            older = (q or {}).get("oldest") or ""
            if stop or not older or len(rows) < 500:
                break
        with contextlib.suppress(ConnectorError):
            cl = self._api("/clients") or {}
            for c in cl.get("clients") or []:
                ids = [str(x) for x in c.get("ids") or []]
                out["devices"].append({
                    "mac": next((x.lower() for x in ids
                                 if re.match(r"^[0-9a-fA-F:]{17}$", x)), ""),
                    "ips": [x for x in ids if ip_obj(x) is not None],
                    "names": [c.get("name")] if c.get("name") else [],
                    "vendor": "", "last": 0.0})
        return out


CONNECTOR_KINDS = {"pihole": PiHoleConnector, "adguard": AdGuardConnector}


class ConnectorManager:
    """Polls each enabled helper in the background (about once a minute)
    and hands the results to the app on the Tk thread."""

    def __init__(self, specs, vault, deliver, interval=60.0):
        self.vault = vault
        self.deliver = deliver
        self.interval = interval
        self.status = {}
        self.conns = {}
        self.cursor = {}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self.update(specs)

    def update(self, specs):
        live = {}
        for sp in specs or []:
            cls = CONNECTOR_KINDS.get(sp.get("kind"))
            if cls is None or not sp.get("id"):
                continue
            old = self.conns.get(sp["id"])
            if old is not None and old.spec == sp:
                live[sp["id"]] = old
                continue
            if old is not None:
                old.close()
            live[sp["id"]] = cls(sp, self.vault)
            self.status.setdefault(sp["id"], {"state": "waiting",
                                              "message": "Not asked yet.",
                                              "last_ok": 0.0, "lookups": 0,
                                              "devices": 0})
        for cid, c in self.conns.items():
            if cid not in live:
                c.close()
                self.status.pop(cid, None)
        self.conns = live
        self._wake.set()

    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="connectors")
            self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        for c in list(self.conns.values()):
            c.close()

    def poll_now(self):
        self._wake.set()

    def poll_once(self, cid):
        c = self.conns.get(cid)
        if c is None or not c.spec.get("enabled", True):
            return None
        st = self.status.setdefault(cid, {})
        since = self.cursor.get(cid) or (time.time() - 3600)
        try:
            res = c.fetch(since)
            newest = max((x["ts"] for x in res["lookups"]), default=0.0)
            if newest:
                self.cursor[cid] = newest + 0.000001
            st.update({"state": "ok", "last_ok": time.time(),
                       "message": f"{len(res['lookups'])} new lookups, "
                                  f"{len(res['devices'])} devices.",
                       "lookups": st.get("lookups", 0) +
                       len(res["lookups"]),
                       "devices": len(res["devices"])})
            self.deliver(c, res)
            return res
        except ConnectorError as e:
            st.update({"state": e.kind, "message": str(e)})
        except Exception as e:                       # noqa: BLE001
            LOG.exception("connector %s", c.name)
            st.update({"state": "api", "message": f"Unexpected answer: "
                                                  f"{type(e).__name__}"})
        return None

    def _run(self):
        while not self._stop.is_set():
            for cid in list(self.conns):
                if self._stop.is_set():
                    break
                if LEDGER.killed:
                    self.status.setdefault(cid, {}).update(
                        {"state": "refused",
                         "message": "Paused by the kill switch."})
                    continue
                self.poll_once(cid)
            self._wake.wait(self.interval)
            self._wake.clear()


