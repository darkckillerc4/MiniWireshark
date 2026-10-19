def timeline_sql(category="All types", severity="All", device=None, q="",
                 since=0.0, until=None, before=None, limit=200,
                 session=None):
    """The Timeline's filters compiled to one read-only SQL query over the
    events table (same meaning as the in-memory filter)."""
    where, args = ["ts >= ?"], [since]
    if until is not None:
        where.append("ts <= ?")
        args.append(until)
    if before is not None:
        where.append("ts < ?")
        args.append(before)
    if severity and severity != "All":
        where.append("severity = ?")
        args.append(severity)
    if category and category != "All types":
        kinds = [k for k, c in TIMELINE_CATEGORY.items() if c == category]
        if category == "Devices":
            # anything not explicitly categorised counts as a device event
            other = [k for k in TIMELINE_CATEGORY]
            where.append("(kind IN (%s) OR kind NOT IN (%s))" % (
                ",".join("?" * len(kinds)), ",".join("?" * len(other))))
            args += kinds + other
        else:
            where.append("kind IN (%s)" % ",".join("?" * len(kinds)))
            args += kinds
    if device:
        where.append("device = ?")
        args.append(device)
    if q:
        where.append("(LOWER(text) LIKE ? OR LOWER(kind) LIKE ?)")
        like = "%" + q.lower().replace("%", "").replace("_", "") + "%"
        args += [like, like]
    if session is not None:
        where.append("session = ?")
        args.append(session)
    sql = ("SELECT ts, kind, severity, text, ref_kind, ref_id, device, "
           "session FROM events WHERE " + " AND ".join(where) +
           " ORDER BY ts DESC LIMIT ?")
    args.append(int(limit))
    return sql, args


def store_events_page(store, before=None, limit=200, **filters):
    """One page of timeline events (newest first) as timeline dicts."""
    sql, args = timeline_sql(before=before, limit=limit, **filters)
    out = []
    for ts, kind, sev, text, rk, rid, dev, sess in store.query(sql, args):
        ref = (rk, rid) if rk else None
        if ref and rk == "flow":
            with contextlib.suppress(TypeError, ValueError):
                ref = (rk, int(rid))
        out.append({"when": ts, "kind": kind, "severity": sev,
                    "text": text, "ref": ref, "device": dev or "",
                    "session": sess, "live": False})
    return out


def store_sessions(store, limit=60):
    rows = store.query("SELECT id, started, ended, source, iface, network "
                       "FROM sessions ORDER BY started DESC LIMIT ?",
                       (limit,))
    return [{"id": r[0], "started": r[1], "ended": r[2], "source": r[3],
             "iface": r[4], "network": r[5]} for r in rows]


def session_label(s):
    end = fmt_clock(s["ended"]) if s.get("ended") else "running"
    net = f" · {s['network']}" if s.get("network") else ""
    return (f"{fmt_clock(s['started'], True)} → {end}{net} "
            f"[#{s['id']}]")


def session_profile(store, sid):
    """Devices, websites and event counts recorded for one session."""
    devices = {}
    for subj, data in store.query(
            "SELECT subject, data FROM observations WHERE session=? AND "
            "kind IN (?,?,?,?,?) LIMIT 50000",
            (sid, OBS_KIND_CODES["dhcp_request"], OBS_KIND_CODES["dhcp_ack"],
             OBS_KIND_CODES["mdns"], OBS_KIND_CODES["arp_reply"],
             OBS_KIND_CODES["nbns"])):
        name = devices.get(subj, "")
        if not name and data:
            with contextlib.suppress(ValueError, TypeError):
                d = json.loads(data)
                name = d.get("hostname") or d.get("name") or ""
        devices[subj] = name
    for (subj,) in store.query("SELECT DISTINCT subject FROM observations "
                               "WHERE session=? AND subject NOT LIKE 'site:%' "
                               "AND subject NOT LIKE 'flow:%' LIMIT 20000",
                               (sid,)):
        devices.setdefault(subj, "")
    sites = {}
    for dom, assoc in store.query("SELECT domain, assoc FROM site_ties "
                                  "WHERE session=?", (sid,)):
        root = registrable_domain(dom)
        sites[root] = better_assoc(assoc, sites.get(root, ""))
    kinds = dict(store.query("SELECT kind, COUNT(*) FROM events WHERE "
                             "session=? GROUP BY kind", (sid,)))
    return {"devices": devices, "sites": sites, "events": kinds}


def compare_sessions(store, a, b):
    """What differs between session a (older) and b (newer)."""
    pa, pb = session_profile(store, a), session_profile(store, b)
    da, db = set(pa["devices"]), set(pb["devices"])
    sa, sb = set(pa["sites"]), set(pb["sites"])
    return {"new_devices": sorted(db - da), "gone_devices": sorted(da - db),
            "both_devices": sorted(da & db),
            "new_sites": sorted(sb - sa), "gone_sites": sorted(sa - sb),
            "names": {**pa["devices"], **pb["devices"]},
            "events_a": pa["events"], "events_b": pb["events"]}


class PacketRing:
    """Optional on-disk history of raw packets: pcap segments in the data
    folder, oldest deleted first so it never exceeds its size cap. Lets a
    proof chip open a packet that has already left memory. Off by
    default; never uploaded."""

    SEGMENT_BYTES = 8 * 1024 * 1024

    def __init__(self, folder, cap_mb=200, store=None, session=0):
        self.folder = folder
        self.cap = max(20, int(cap_mb)) * 1024 * 1024
        self.store = store
        self.session = session
        self.epoch = 0
        self.q = queue.Queue(maxsize=50000)
        self.dropped = 0
        self.written = 0
        self.index = []       # [first_no, last_no, path, epoch, bytes]
        self._seg = None
        self._stop = False
        os.makedirs(folder, exist_ok=True)
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="packet-ring")
        self._thread.start()

    def new_epoch(self):
        """Packet numbers restart (Clear / new model): keep segments apart."""
        try:
            self.q.put_nowait(("epoch",))
        except queue.Full:
            self.dropped += 1

    def put(self, no, raw, ts, lt):
        try:
            self.q.put_nowait((no, raw, ts, lt))
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def _open(self, no, ts, lt):
        name = f"seg-{self.session}-{self.epoch}-{no:012d}.pcap"
        path = os.path.join(self.folder, name)
        f = open(path, "wb")
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, lt))
        self._seg = {"f": f, "path": path, "first": no, "last": no - 1,
                     "t0": ts, "t1": ts, "lt": lt, "bytes": 24}

    def _close(self):
        seg, self._seg = self._seg, None
        if seg is None:
            return
        with contextlib.suppress(OSError):
            seg["f"].close()
        if seg["last"] < seg["first"]:
            with contextlib.suppress(OSError):
                os.remove(seg["path"])
            return
        self.index.append([seg["first"], seg["last"], seg["path"],
                           self.epoch, seg["bytes"]])
        if self.store is not None:
            self.store.write_segment(seg["first"], seg["last"], seg["t0"],
                                     seg["t1"], seg["path"], seg["bytes"],
                                     seg["lt"])
        self._enforce_cap()

    def _enforce_cap(self):
        total = sum(e[4] for e in self.index)
        while self.index and total > self.cap:
            old = self.index.pop(0)
            total -= old[4]
            with contextlib.suppress(OSError):
                os.remove(old[2])

    def _run(self):
        while True:
            try:
                item = self.q.get(timeout=0.5)
            except queue.Empty:
                if self._stop:
                    break
                continue
            if item is None:
                break
            try:
                if item[0] == "epoch":
                    self._close()
                    self.epoch += 1
                    continue
                no, raw, ts, lt = item
                seg = self._seg
                if seg is None or seg["lt"] != lt or no != seg["last"] + 1 \
                        or seg["bytes"] > self.SEGMENT_BYTES:
                    self._close()
                    self._open(no, ts, lt)
                    seg = self._seg
                sec = int(ts)
                usec = int(round((ts - sec) * 1e6)) % 1000000
                seg["f"].write(struct.pack("<IIII", sec, usec, len(raw),
                                           len(raw)))
                seg["f"].write(raw)
                seg["last"], seg["t1"] = no, ts
                seg["bytes"] += 16 + len(raw)
                self.written += 1
            except OSError as e:
                LOG.warning("packet history: %s", e)
                with contextlib.suppress(Exception):
                    self._seg["f"].close()
                self._seg = None
        self._close()

    def flush(self):
        """Make everything written so far readable (closes the segment)."""
        try:
            self.q.put(("epoch_flush",), timeout=1)
        except queue.Full:
            return False
        return True

    def find(self, no, epoch=None):
        """(raw, ts, linktype) of packet `no` from disk, or None."""
        epoch = self.epoch if epoch is None else epoch
        seg = self._seg
        if seg is not None and seg["first"] <= no <= seg["last"]:
            with contextlib.suppress(OSError):
                seg["f"].flush()
            candidates = [[seg["first"], seg["last"], seg["path"], epoch, 0]]
        else:
            candidates = [e for e in reversed(self.index)
                          if e[3] == epoch and e[0] <= no <= e[1]]
        for first, _last, path, _ep, _b in candidates:
            try:
                for i, frame in enumerate(iter_raw_capture(path)):
                    if first + i == no:
                        return frame
            except (OSError, ValueError, struct.error):
                continue
        return None

    def size_bytes(self):
        return sum(e[4] for e in self.index) + (
            self._seg["bytes"] if self._seg else 0)

    def stop(self, wait=3.0):
        self._stop = True
        with contextlib.suppress(queue.Full):
            self.q.put_nowait(None)
        if wait:
            self._thread.join(wait)


