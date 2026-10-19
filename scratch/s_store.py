# ---- optional local history (SQLite) ----------------------------------------
HISTORY_RETENTION = {"Session only": 0, "7 days": 7, "30 days": 30,
                     "90 days": 90, "Custom": None}
STORE_SCHEMA_VERSION = 3

# Numbered migrations. Each runs inside one transaction; a crash rolls it
# back and the next start retries. The file is copied to .vN.bak first.
STORE_MIGRATIONS = {
    1: """
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS devices(key TEXT PRIMARY KEY, data TEXT,
        first_seen REAL, last_seen REAL);
    CREATE TABLE IF NOT EXISTS presence(device_key TEXT, start REAL,
        end REAL, PRIMARY KEY(device_key, start));
    CREATE TABLE IF NOT EXISTS traffic(device_key TEXT, day TEXT,
        bytes_up INTEGER, bytes_down INTEGER, packets INTEGER,
        PRIMARY KEY(device_key, day));
    CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, kind TEXT,
        severity TEXT, device_key TEXT, reason TEXT, at REAL);
    CREATE TABLE IF NOT EXISTS domains(domain TEXT, day TEXT,
        requests INTEGER, bytes INTEGER, PRIMARY KEY(domain, day));
    CREATE TABLE IF NOT EXISTS baselines(device_key TEXT PRIMARY KEY,
        data TEXT, updated REAL);
    """,
    2: """
    CREATE TABLE IF NOT EXISTS migration_log(version INTEGER, phase TEXT,
        at REAL);
    CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY,
        started REAL, ended REAL, source TEXT, iface TEXT, network TEXT,
        app_version TEXT);
    CREATE TABLE IF NOT EXISTS observations(ts REAL, session INTEGER,
        kind INTEGER, subject TEXT, data TEXT, pkt INTEGER);
    CREATE INDEX IF NOT EXISTS obs_subject ON observations(subject, ts);
    CREATE INDEX IF NOT EXISTS obs_kind ON observations(kind, ts);
    CREATE TABLE IF NOT EXISTS resolutions(ts REAL, session INTEGER,
        device TEXT, domain TEXT, ip TEXT);
    CREATE INDEX IF NOT EXISTS res_ip ON resolutions(ip, ts);
    CREATE INDEX IF NOT EXISTS res_domain ON resolutions(domain, ts);
    CREATE TABLE IF NOT EXISTS flows(session INTEGER, fid INTEGER,
        start REAL, end REAL, device TEXT, remote TEXT, port INTEGER,
        transport TEXT, app TEXT, domain TEXT, assoc TEXT,
        bytes_out INTEGER, bytes_in INTEGER, packets INTEGER,
        PRIMARY KEY(session, fid));
    CREATE INDEX IF NOT EXISTS flows_device ON flows(device, start);
    CREATE INDEX IF NOT EXISTS flows_remote ON flows(remote, start);
    CREATE TABLE IF NOT EXISTS site_ties(session INTEGER, device TEXT,
        domain TEXT, assoc TEXT, first REAL, last REAL, n INTEGER,
        PRIMARY KEY(session, device, domain));
    CREATE INDEX IF NOT EXISTS ties_domain ON site_ties(domain, last);
    """,
    3: """
    CREATE TABLE IF NOT EXISTS events(ts REAL, session INTEGER, kind TEXT,
        severity TEXT, text TEXT, ref_kind TEXT, ref_id TEXT,
        device TEXT);
    CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
    CREATE INDEX IF NOT EXISTS events_kind ON events(kind, ts);
    CREATE INDEX IF NOT EXISTS events_device ON events(device, ts);
    CREATE TABLE IF NOT EXISTS packet_segments(session INTEGER,
        first_no INTEGER, last_no INTEGER, t0 REAL, t1 REAL, path TEXT,
        bytes INTEGER, linktype INTEGER,
        PRIMARY KEY(session, first_no));
    """,
}


class Store:
    """Durable, optional history in one SQLite file (WAL mode).

    • One writer thread owns the only write connection; callers hand over
      small batches (observations, lookups, connections, site ties,
      timeline events) about once a second.
    • Readers open their own read-only connections, so a history query
      never blocks capture or the writer.
    • Numbered migrations with a .vN.bak copy first; a nightly .bak copy;
      integrity check at open with automatic recovery from the backup.
    • No packet payloads are ever stored here (the optional packet ring
      keeps raw packets in separate files, off by default)."""

    def __init__(self, path, session_id=None, meta=None):
        self.path = path
        self.session = session_id if session_id is not None else \
            int(time.time())
        self.meta = dict(meta or {})
        self.q = queue.Queue(maxsize=400)
        self.error = ""
        self.recovered = ""
        self.written = Counter()
        self.dropped_batches = 0
        self._stop = False
        self._ready = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="history-writer")
        self._thread.start()
        self._ready.wait(10)

    # ---- opening, migrations, recovery ---------------------------------------
    def _check_integrity(self):
        if not os.path.exists(self.path):
            return
        bad = ""
        try:
            con = sqlite3.connect(self.path, timeout=10)
            row = con.execute("PRAGMA quick_check").fetchone()
            con.close()
            if not row or row[0] != "ok":
                bad = str(row[0] if row else "no answer")
        except sqlite3.DatabaseError as e:
            bad = str(e)
        if not bad:
            return
        aside = f"{self.path}.corrupt-{int(time.time())}"
        with contextlib.suppress(OSError):
            os.replace(self.path, aside)
        for suffix in ("-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.remove(self.path + suffix)
        bak = self.path + ".bak"
        if os.path.exists(bak):
            with contextlib.suppress(OSError):
                shutil.copyfile(bak, self.path)
            self.recovered = (f"The history file was damaged ({bad}); it was "
                              f"set aside and last night's backup was "
                              f"restored.")
        else:
            self.recovered = (f"The history file was damaged ({bad}); it was "
                              f"set aside and a new one was started.")
        LOG.warning("history: %s", self.recovered)

    def _connect(self):
        self._check_integrity()
        con = sqlite3.connect(self.path, timeout=15)
        with contextlib.suppress(sqlite3.Error):
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
        con.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, "
                    "v TEXT)")
        row = con.execute("SELECT v FROM meta WHERE k='schema'").fetchone()
        ver = int(row[0]) if row and str(row[0]).isdigit() else 0
        if ver < STORE_SCHEMA_VERSION and ver > 0:
            with contextlib.suppress(OSError):
                con.commit()
                shutil.copyfile(self.path, f"{self.path}.v{ver}.bak")
        for v in range(ver + 1, STORE_SCHEMA_VERSION + 1):
            self._migrate(con, v)
        con.execute("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?,?,?)",
                    (self.session, time.time(), None,
                     self.meta.get("source", ""), self.meta.get("iface", ""),
                     self.meta.get("network", ""), SCRIPT_VERSION))
        con.commit()
        return con

    @staticmethod
    def _migrate(con, version):
        try:
            con.execute("BEGIN")
            if version >= 2:
                con.execute("CREATE TABLE IF NOT EXISTS migration_log("
                            "version INTEGER, phase TEXT, at REAL)")
                con.execute("INSERT INTO migration_log VALUES(?,?,?)",
                            (version, "start", time.time()))
            for stmt in STORE_MIGRATIONS[version].split(";"):
                if stmt.strip():
                    con.execute(stmt)
            con.execute("INSERT OR REPLACE INTO meta VALUES('schema', ?)",
                        (str(version),))
            if version >= 2:
                con.execute("INSERT INTO migration_log VALUES(?,?,?)",
                            (version, "done", time.time()))
            con.execute("COMMIT")
        except sqlite3.Error:
            with contextlib.suppress(sqlite3.Error):
                con.execute("ROLLBACK")
            raise

    def _backup_if_due(self, con):
        bak = self.path + ".bak"
        try:
            age = time.time() - os.path.getmtime(bak)
        except OSError:
            age = 1e9
        if age < 20 * 3600:
            return
        try:
            dst = sqlite3.connect(bak + ".tmp")
            con.backup(dst)
            dst.close()
            os.replace(bak + ".tmp", bak)
        except (sqlite3.Error, OSError) as e:
            LOG.info("history backup skipped: %s", e)

    # ---- writer thread -------------------------------------------------------------
    def _run(self):
        try:
            con = self._connect()
        except sqlite3.Error as e:
            self.error = str(e)
            LOG.warning("history db unavailable: %s", e)
            self._ready.set()
            return
        self._ready.set()
        self._backup_if_due(con)
        last_backup_check = time.time()
        while True:
            try:
                job = self.q.get(timeout=1.0)
            except queue.Empty:
                self._idle.set()
                if self._stop:
                    break
                if time.time() - last_backup_check > 3600:
                    last_backup_check = time.time()
                    self._backup_if_due(con)
                continue
            if job is None:
                break
            self._idle.clear()
            for attempt in range(3):
                try:
                    job(con)
                    con.commit()
                    break
                except sqlite3.OperationalError as e:
                    self.error = str(e)
                    with contextlib.suppress(sqlite3.Error):
                        con.rollback()
                    if "locked" not in str(e) or attempt == 2:
                        LOG.warning("history write failed: %s", e)
                        break
                    time.sleep(0.2 * (attempt + 1))
                except sqlite3.Error as e:
                    self.error = str(e)
                    with contextlib.suppress(sqlite3.Error):
                        con.rollback()
                    LOG.warning("history write failed: %s", e)
                    break
            if self.q.empty():
                self._idle.set()
        with contextlib.suppress(sqlite3.Error):
            con.execute("UPDATE sessions SET ended=? WHERE id=?",
                        (time.time(), self.session))
            con.commit()
            con.close()
        self._idle.set()

    def submit(self, job):
        if self.error and not self._thread.is_alive():
            return False
        try:
            self._idle.clear()
            self.q.put_nowait(job)
            return True
        except queue.Full:
            self.dropped_batches += 1
            if self.q.empty():
                self._idle.set()
            return False

    def flush_now(self, timeout=5.0):
        """Wait until everything handed over so far is on disk."""
        t_end = time.time() + timeout
        while time.time() < t_end:
            if self.q.empty() and self._idle.wait(0.05):
                if self.q.empty():
                    return True
        return False

    def stop(self, wait=0.0):
        self._stop = True
        with contextlib.suppress(queue.Full):
            self.q.put_nowait(None)
        if wait:
            self._thread.join(wait)

    # ---- batched writes ------------------------------------------------------------
    def write_observations(self, obs):
        if not obs:
            return True
        sess = self.session
        rows = [(o[1], sess, OBS_KIND_CODES.get(o[2], 0), o[3],
                 json.dumps(o[4], separators=(",", ":"), default=str)
                 if o[4] else "", o[5]) for o in obs]

        def job(con):
            con.executemany("INSERT INTO observations VALUES(?,?,?,?,?,?)",
                            rows)
            self.written["observations"] += len(rows)
        return self.submit(job)

    def write_resolutions(self, res):
        if not res:
            return True
        sess = self.session
        rows = [(ts, sess, dev, dom, ip) for ts, dev, dom, ip in res]

        def job(con):
            con.executemany("INSERT INTO resolutions VALUES(?,?,?,?,?)",
                            rows)
            self.written["resolutions"] += len(rows)
        return self.submit(job)

    def write_flows(self, flows):
        if not flows:
            return True
        sess = self.session
        rows = [(sess, f.fid, f.first_seen, f.last_seen, f.device_key,
                 f.remote_ip, f.remote_port or 0, f.transport, f.app,
                 f.domain, f.assoc, f.bytes_out, f.bytes_in, f.packets)
                for f in flows]

        def job(con):
            con.executemany("INSERT OR REPLACE INTO flows VALUES"
                            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self.written["flows"] += len(rows)
        return self.submit(job)

    def write_site_ties(self, ties):
        """ties: iterable of (device, domain, [assoc, first, last, n])."""
        sess = self.session
        rows = [(sess, dev, dom, t[0], t[1], t[2], t[3])
                for dev, dom, t in ties]
        if not rows:
            return True

        def job(con):
            con.executemany("INSERT OR REPLACE INTO site_ties VALUES"
                            "(?,?,?,?,?,?,?)", rows)
            self.written["site_ties"] += len(rows)
        return self.submit(job)

    def write_events(self, events):
        if not events:
            return True
        sess = self.session
        rows = []
        for e in events:
            ref = e.get("ref") or (None, None)
            if not isinstance(ref, (list, tuple)) or len(ref) != 2:
                ref = (None, None)
            rows.append((e["when"], sess, e.get("kind", ""),
                         e.get("severity", "INFO"), e.get("text", ""),
                         ref[0], None if ref[1] is None else str(ref[1]),
                         e.get("device", "")))

        def job(con):
            con.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)",
                            rows)
            self.written["events"] += len(rows)
        return self.submit(job)

    def write_segment(self, first_no, last_no, t0, t1, path, nbytes, lt):
        sess = self.session

        def job(con):
            con.execute("INSERT OR REPLACE INTO packet_segments VALUES"
                        "(?,?,?,?,?,?,?,?)", (sess, first_no, last_no, t0,
                                              t1, path, nbytes, lt))
        return self.submit(job)

    def write_snapshot(self, snap):
        """3.0-compatible summary snapshot (devices, alerts, domains…)."""
        def job(con):
            day = time.strftime("%Y-%m-%d")
            for key, data, fs, ls, presence, tr in snap["devices"]:
                con.execute("INSERT OR REPLACE INTO devices VALUES(?,?,?,?)",
                            (key, json.dumps(data, default=str), fs, ls))
                for start, end in presence:
                    con.execute("INSERT OR REPLACE INTO presence "
                                "VALUES(?,?,?)", (key, start, end))
                con.execute("INSERT OR REPLACE INTO traffic "
                            "VALUES(?,?,?,?,?)", (key, day) + tuple(tr))
            for a in snap["alerts"]:
                con.execute("INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?)",
                            a)
            for dom, req, b in snap["domains"]:
                con.execute("INSERT OR REPLACE INTO domains "
                            "VALUES(?,?,?,?)", (dom, day, req, b))
            for key, data in snap["baselines"]:
                con.execute("INSERT OR REPLACE INTO baselines VALUES(?,?,?)",
                            (key, json.dumps(data), time.time()))
        return self.submit(job)

    def prune(self, days):
        if not days:
            return False
        cutoff = time.time() - days * 86400
        cday = time.strftime("%Y-%m-%d", time.localtime(cutoff))

        def job(con):
            con.execute("DELETE FROM presence WHERE start < ?", (cutoff,))
            con.execute("DELETE FROM alerts WHERE at < ?", (cutoff,))
            con.execute("DELETE FROM traffic WHERE day < ?", (cday,))
            con.execute("DELETE FROM domains WHERE day < ?", (cday,))
            con.execute("DELETE FROM devices WHERE last_seen < ?", (cutoff,))
            for t, col in (("observations", "ts"), ("resolutions", "ts"),
                           ("flows", "end"), ("site_ties", "last"),
                           ("events", "ts")):
                con.execute(f"DELETE FROM {t} WHERE {col} < ?", (cutoff,))
            con.execute("DELETE FROM sessions WHERE ended IS NOT NULL AND "
                        "ended < ?", (cutoff,))
        return self.submit(job)

    def clear(self, device_key=None):
        def job(con):
            if device_key:
                for t, col in (("devices", "key"), ("presence", "device_key"),
                               ("traffic", "device_key"),
                               ("alerts", "device_key"),
                               ("baselines", "device_key"),
                               ("observations", "subject"),
                               ("resolutions", "device"),
                               ("flows", "device"), ("site_ties", "device"),
                               ("events", "device")):
                    con.execute(f"DELETE FROM {t} WHERE {col}=?",
                                (device_key,))
            else:
                for t in ("devices", "presence", "traffic", "alerts",
                          "domains", "baselines", "observations",
                          "resolutions", "flows", "site_ties", "events",
                          "packet_segments"):
                    con.execute(f"DELETE FROM {t}")
                con.commit()
                con.execute("VACUUM")
        return self.submit(job)

    # ---- reads (own read-only connection each time) ------------------------
    def _reader(self):
        uri = "file:" + urllib.request.pathname2url(
            os.path.abspath(self.path)) + "?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=5)
        con.execute("PRAGMA query_only=ON")
        return con

    def query(self, sql, args=(), limit=None):
        """Read-only query. Returns rows, or [] if the file can't be read
        (the error is kept in .error)."""
        if not sql.lstrip().upper().startswith(("SELECT", "WITH")):
            raise ValueError("read-only queries only")
        try:
            con = self._reader()
            try:
                cur = con.execute(sql, args)
                return cur.fetchmany(limit) if limit else cur.fetchall()
            finally:
                con.close()
        except sqlite3.Error as e:
            self.error = str(e)
            return []

    def observations(self, subject, limit=200, since=0.0):
        rows = self.query("SELECT ts, kind, data, pkt, session FROM "
                          "observations WHERE subject=? AND ts>=? ORDER BY "
                          "ts DESC LIMIT ?", (subject, since, limit))
        out = []
        for ts, kind, data, pkt, sess in rows:
            try:
                d = json.loads(data) if data else {}
            except ValueError:
                d = {}
            out.append((ts, OBS_CODE_KINDS.get(kind, "?"), d, pkt, sess))
        return out

    def counts(self):
        out = {}
        for t in ("observations", "resolutions", "flows", "site_ties",
                  "events", "sessions", "devices"):
            r = self.query(f"SELECT COUNT(*) FROM {t}")
            out[t] = r[0][0] if r else 0
        return out

    def schema_version(self):
        r = self.query("SELECT v FROM meta WHERE k='schema'")
        return int(r[0][0]) if r and str(r[0][0]).isdigit() else 0

    def load_baselines(self):
        out = {}
        for key, data in self.query("SELECT device_key, data FROM "
                                    "baselines"):
            with contextlib.suppress(ValueError):
                out[key] = json.loads(data)
        return out

    def known_device_rows(self, limit=500):
        rows = []
        for key, data, fs, ls in self.query(
                "SELECT key, data, first_seen, last_seen FROM devices "
                "ORDER BY last_seen DESC LIMIT ?", (limit,)):
            with contextlib.suppress(ValueError):
                rows.append((key, json.loads(data), fs, ls))
        return rows

    def size_bytes(self):
        total = 0
        for suffix in ("", "-wal", "-journal"):
            with contextlib.suppress(OSError):
                total += os.path.getsize(self.path + suffix)
        return total


HistoryStore = Store          # 3.0 name


def bench_store(n=100000):
    tmp = tempfile.mkdtemp()
    st = Store(os.path.join(tmp, "b.sqlite3"))
    obs = [(i, 1700000000.0 + i * 0.01, "dns_answer", f"dev{i % 50}",
            {"domain": f"d{i % 900}.example", "ip": "93.184.215.14"}, i)
           for i in range(n)]
    t0 = time.perf_counter()
    for k in range(0, n, 5000):
        while not st.write_observations(obs[k:k + 5000]):
            time.sleep(0.01)
    st.flush_now(60)
    dt = time.perf_counter() - t0
    size = st.size_bytes()
    st.stop(5)
    shutil.rmtree(tmp, ignore_errors=True)
    return {"store_obs_per_s": n / dt, "store_bytes_per_obs": size / n}


