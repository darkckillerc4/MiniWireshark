"""V5.0.1: bug fixes and the small additions (expert list, copy as filter,
follow stream, row colours, go to packet, time format)."""
P = "/home/claude/mw/miniwireshark.py"
s = open(P, encoding="utf8").read()


def rep(old, new, cnt=1):
    global s
    n = s.count(old)
    assert n == cnt, (n, old[:120])
    s = s.replace(old, new)


# ---- 1. durations under a second ------------------------------------------
rep('''def human_duration(sec):
    sec = int(max(0, sec or 0))
    if sec < 60:''', '''def human_duration(sec):
    try:
        raw = max(0.0, float(sec or 0))
    except (TypeError, ValueError):
        raw = 0.0
    if 0 < raw < 1:
        return "<1s"            # was "0s" for a connection that lasted 0.4 s
    sec = int(raw)
    if sec < 60:''')

# ---- 2. footer: French puts a space before the colon -------------------------
rep('''f"{' · ' + tr('blind spots') + ': ' + str(len(spots)) if spots else ''}"''',
    '''f"{' · ' + tr('blind spots:') + ' ' + str(len(spots)) if spots else ''}"''')

# ---- 3. worker: survive pythonw (no sys.stdin / sys.stdout) and keep stray
#         prints off the result pipe ------------------------------------------
rep('''    inp = inp or sys.stdin.buffer
    out = out or sys.stdout.buffer
    an = DeepAnalyzer()''', '''    if inp is None:
        inp = getattr(sys.stdin, "buffer", None) or os.fdopen(0, "rb")
    if out is None:
        out = getattr(sys.stdout, "buffer", None) or os.fdopen(1, "wb")
        # anything a library prints from now on goes to stderr, never into
        # the binary result stream
        sys.stdout = sys.stderr if sys.stderr is not None else \\
            open(os.devnull, "w")
    an = DeepAnalyzer()''')

# ---- 4. CSV exports: a cell that starts with = + - @ is not run as a formula --
rep('''def copy_to_clipboard(app, text):''', '''class _SafeCsv:
    """csv.writer whose text cells can never start a spreadsheet formula
    (device names, DHCP host names and packet text come from the
    network)."""

    BAD = ("=", "+", "-", "@", "\\t", "\\r")

    def __init__(self, f):
        self.w = csv.writer(f)

    @classmethod
    def cell(cls, v):
        if isinstance(v, str) and v.startswith(cls.BAD):
            return "'" + v
        return v

    def writerow(self, row):
        return self.w.writerow([self.cell(v) for v in row])


def safe_csv_writer(f):
    return _SafeCsv(f)


def copy_to_clipboard(app, text):''')
rep('''                w = csv.writer(f)
                w.writerow(["no", "time", "protocol",''',
    '''                w = safe_csv_writer(f)
                w.writerow(["no", "time", "protocol",''')
rep('''                w = csv.writer(f)
                w.writerow(["name", "class", "ip",''',
    '''                w = safe_csv_writer(f)
                w.writerow(["name", "class", "ip",''')
rep('''                w = csv.writer(f)
                w.writerow(["id", "device", "transport",''',
    '''                w = safe_csv_writer(f)
                w.writerow(["id", "device", "transport",''')

# ---- 5. filter language: expert.group / expert.message; frame.time_relative
#         (it was listed but always empty) -----------------------------------
rep('''    "expert.severity": "severity", "frame.time_relative": "float",
    "tcp.stream": "int"}
''', '''    "expert.severity": "severity", "frame.time_relative": "float",
    "tcp.stream": "int", "expert.group": "str", "expert.message": "str"}
SPECIAL_DESC = {
    "frame.number": "Packet number",
    "ip.addr": "IPv4 address, either direction",
    "ipv6.addr": "IPv6 address, either direction",
    "tcp.port": "TCP port, either direction",
    "udp.port": "UDP port, either direction",
    "eth.addr": "MAC address, either direction",
    "expert.severity": "Worst expert finding on the packet (chat, note, "
                       "warning, error)",
    "expert.group": "Expert finding group (Sequence, Malformed, Protocol, "
                    "Security, Checksum, Response code)",
    "expert.message": "Expert finding text",
    "frame.time_relative": "Seconds since the first packet",
    "tcp.stream": "Connection number"}


def conversation_filter(src, dst, sport=None, dport=None, transport=None,
                        ipver=None, src_mac="", dst_mac=""):
    """The field expression for one conversation (both directions)."""
    parts = []
    fam = "ip" if ipver == 4 else "ipv6" if ipver == 6 else None
    if fam is None and src and dst:
        fam = "ipv6" if ":" in src else "ip" if "." in src else None
    if fam and src and dst:
        parts += [f"{fam}.addr == {src}", f"{fam}.addr == {dst}"]
    elif src_mac and dst_mac:
        parts += [f"eth.addr == {src_mac}", f"eth.addr == {dst_mac}"]
    tr = (transport or "").lower()
    if tr in ("tcp", "udp") and sport is not None and dport is not None:
        parts += [f"{tr}.port == {sport}", f"{tr}.port == {dport}"]
    return " and ".join(parts)


def address_filter(addr):
    """The field expression for one address (either direction)."""
    if not addr:
        return ""
    if re.match(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", addr, re.I):
        return f"eth.addr == {addr}"
    return f"{'ipv6' if ':' in addr else 'ip'}.addr == {addr}"


def filter_quote(text):
    return '"' + str(text).replace("\\\\", " ").replace('"', '\\\\"') + '"'
''')
rep('''    def _values(self, field):
        if field == "expert.severity":
            return lambda d, c: c.expert_severities(d)
''', '''    def _values(self, field):
        if field == "expert.severity":
            return lambda d, c: c.expert_severities(d)
        if field in ("expert.group", "expert.message"):
            i = 1 if field == "expert.group" else 2
            return lambda d, c: c.expert_info(d, i)
        if field == "frame.time_relative":
            return lambda d, c: [round(d["time"] - c.time_zero(), 6)] if \\
                d.get("time") is not None else []
''')
rep('''                elif k in SPECIAL_FIELDS:
                    ftype, desc = SPECIAL_FIELDS[k], "Either direction / " \\
                        "special"''', '''                elif k in SPECIAL_FIELDS:
                    ftype, desc = SPECIAL_FIELDS[k], SPECIAL_DESC.get(
                        k, "Either direction / special")''')
rep('''    def expert_severities(self, d):
        store = self.app.deep.store
        ver, idx = self._sev
        if ver != store.version:
            idx = {}
            with store.lock:
                for f in store.findings:
                    idx.setdefault(f[0], []).append(f[2])
            self._sev = (store.version, idx)
        return idx.get(d.get("no"), [])
''', '''    def _expert_index(self):
        store = self.app.deep.store
        ver, idx = self._sev
        if ver != store.version:
            idx = {}
            with store.lock:
                for f in store.findings:
                    idx.setdefault(f[0], []).append((f[2], f[3], f[4]))
            self._sev = (store.version, idx)
        return idx

    def expert_severities(self, d):
        return [x[0] for x in self._expert_index().get(d.get("no"), ())]

    def expert_info(self, d, i):
        """i = 0 severity, 1 group, 2 message."""
        return [x[i] for x in self._expert_index().get(d.get("no"), ())]

    def worst_expert(self, d):
        """'error', 'warn' or None — for row colours."""
        sev = self.expert_severities(d)
        if not sev:
            return None
        best = max(EXPERT_RANK.get(x, 0) for x in sev)
        return "error" if best >= 3 else "warn" if best == 2 else None

    def time_zero(self):
        """frame.time_relative counts from the first packet of the
        session (or the oldest one still in memory)."""
        t0 = getattr(self.app.model.metrics, "first_ts", 0) or 0
        rows = self.app.all_rows
        if rows and (not t0 or rows[0]["time"] < t0):
            t0 = rows[0]["time"]
        return t0
''')

# ---- 6. packet list: time format, expert colours, conversation filters ------
rep('''        self.ind_var = DisplayVar(value="Display filter: showing "
                                          "everything")''', '''        self.lbl(stat, "Time:").pack(side="left", padx=(12, 2))
        self.time_var = tk.StringVar(value=app.config.get(
            "capture.time_format", "Time of day"))
        tb = ttk.Combobox(stat, textvariable=self.time_var, width=17,
                          state="readonly", values=list(TIME_FORMATS))
        tb.pack(side="left")
        tb.bind("<<ComboboxSelected>>", lambda e: self._time_format())
        self.xcolor_var = tk.BooleanVar(value=app.config.get(
            "capture.color_expert", True))
        ttk.Checkbutton(stat, text="Colour expert findings",
                        variable=self.xcolor_var,
                        command=self._xcolor).pack(side="left", padx=(8, 0))
        self.ind_var = DisplayVar(value="Display filter: showing "
                                          "everything")''')
rep('''    def _values(self, d):
        app = self.app
        return (d["no"], "★" if d["no"] in app.bookmarks else "",
                datetime.fromtimestamp(d["time"]).strftime("%H:%M:%S.%f")[:-3],
                app.disp_addr(d["src_ip"], d["src_mac"]),''', '''    def _time_format(self):
        self.app.config.set("capture.time_format", self.time_var.get())
        self.app.config.save()
        self.render()

    def _xcolor(self):
        self.app.config.set("capture.color_expert", self.xcolor_var.get())
        self.app.config.save()
        self.render()

    def time_text(self, d, prev=None):
        """The Time column in the chosen format."""
        fmt = self.time_var.get() if hasattr(self, "time_var") else \\
            "Time of day"
        return format_packet_time(d["time"], fmt, self.ctx.time_zero(),
                                  prev["time"] if prev else None)

    def _values(self, d, prev=None):
        app = self.app
        return (d["no"], "★" if d["no"] in app.bookmarks else "",
                self.time_text(d, prev),
                app.disp_addr(d["src_ip"], d["src_mac"]),''')
rep('''            bm = self.app.bookmarks
            sel_iid = None
            for iid, d in zip(self.slots, rows):
                tags = (d["tag"],) + (("marked",) if d["no"] in bm else ())
                tree.item(iid, values=self._values(d), tags=tags)''', '''            bm = self.app.bookmarks
            sel_iid = None
            xcol = self.xcolor_var.get()
            for k, (iid, d) in enumerate(zip(self.slots, rows)):
                i = self.top + k
                prev = m[i - 1] if i > 0 else None
                x = self.ctx.worst_expert(d) if xcol else None
                tags = ((f"x_{x}",) if x else (d["tag"],)) + (
                    ("marked",) if d["no"] in bm else ())
                tree.item(iid, values=self._values(d, prev), tags=tags)''')
rep('''            self.tree.tag_configure("marked", background=PALETTES[
                palette_name(self.app.theme_name, self.app.high_contrast)
            ].get("#fff2a8", "#fff2a8"))
''', '''            self.tree.tag_configure("marked", background=PALETTES[
                palette_name(self.app.theme_name, self.app.high_contrast)
            ].get("#fff2a8", "#fff2a8"))
        # created after "marked" so a bookmark still shows on top
        for tag, (fg, bg) in EXPERT_ROW_COLORS.items():
            table = PALETTES[palette_name(self.app.theme_name,
                                          self.app.high_contrast)]
            with contextlib.suppress(tk.TclError):
                self.tree.tag_configure(tag, foreground=table.get(fg, fg),
                                        background=table.get(bg, bg))
''')
rep('''        devs = list(self.ctx.device_keys(d))
        names = [n for n in self.ctx.names(d) if "." in n]
        items = [("Follow stream", lambda: app.follow_stream(
                     d.get("flow_id")), bool(d.get("flow_id"))),''', '''        devs = list(self.ctx.device_keys(d))
        names = [n for n in self.ctx.names(d) if "." in n]
        conv = conversation_filter(d["src_ip"], d["dst_ip"], d["sport"],
                                   d["dport"], d.get("transport"),
                                   d.get("ipver"), d["src_mac"],
                                   d["dst_mac"])
        a_src = address_filter(d["src_ip"] or d["src_mac"])
        a_dst = address_filter(d["dst_ip"] or d["dst_mac"])
        items = [("Follow stream", lambda: app.follow_stream(
                     d.get("flow_id")), bool(d.get("flow_id"))),
                 ("Filter on this conversation",
                  lambda: app.apply_filter(conv), bool(conv)),
                 ("Copy conversation as filter",
                  lambda: copy_to_clipboard(app, conv), bool(conv)),
                 ("Copy source as filter",
                  lambda: copy_to_clipboard(app, a_src), bool(a_src)),
                 ("Copy destination as filter",
                  lambda: copy_to_clipboard(app, a_dst), bool(a_dst)),
                 None,''')

# module-level helpers for the packet list (before the PacketsTab class)
rep('''class PacketsTab(BaseTab):
    name, label_key, advanced = "packets", "tab_raw", True''', '''TIME_FORMATS = ("Time of day", "Seconds since start",
                "Since previous shown")
EXPERT_ROW_COLORS = {"x_error": ("#8a1a08", "#fbe9e7"),
                     "x_warn": ("#7a4a00", "#fff4e0")}


def format_packet_time(ts, fmt, t0=0.0, prev=None):
    """Time column: clock time, seconds since the first packet, or the
    gap since the previous packet in the list (like Wireshark's View →
    Time Display Format)."""
    if fmt == "Seconds since start":
        return f"{max(0.0, ts - (t0 or ts)):.6f}"
    if fmt == "Since previous shown":
        return f"{max(0.0, ts - prev):.6f}" if prev is not None else \\
            "0.000000"
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


class PacketsTab(BaseTab):
    name, label_key, advanced = "packets", "tab_raw", True''')

# ---- 7. Conversations / Endpoints: right-click filters ----------------------
rep('''            self._conv[iid] = f.fid
        tree.bind("<Double-1>", lambda e: self._open_conv(tree))''', '''            self._conv[iid] = f.fid
        tree.bind("<Double-1>", lambda e: self._open_conv(tree))
        tree.bind("<Button-3>", lambda e: self._conv_menu(tree, e))
        tree.bind("<Button-2>", lambda e: self._conv_menu(tree, e))''')
rep('''    def _open_conv(self, tree):
        sel = tree.selection()
        fid = self._conv.get(sel[0]) if sel else None
        if fid:
            self.app.follow_stream(fid)
''', '''    def _open_conv(self, tree):
        sel = tree.selection()
        fid = self._conv.get(sel[0]) if sel else None
        if fid:
            self.app.follow_stream(fid)

    def conv_filter(self, fid):
        f = self.app.model.flows.get(fid)
        if f is None:
            return f"stream:{fid}"
        return conversation_filter(f.local_ip, f.remote_ip, f.local_port,
                                   f.remote_port, f.transport) or \\
            f"stream:{fid}"

    def _conv_menu(self, tree, e):
        iid = tree.identify_row(e.y)
        fid = self._conv.get(iid)
        if not fid:
            return
        tree.selection_set(iid)
        expr = self.conv_filter(fid)
        app = self.app
        popup_menu(app, e, [
            ("Follow stream", lambda: app.follow_stream(fid)),
            ("Filter on this conversation", lambda: app.apply_filter(expr)),
            ("Exclude this conversation",
             lambda: app.apply_filter(f"not ({expr})")),
            ("Copy as filter", lambda: copy_to_clipboard(app, expr))])
''')
rep('''            self._ep[iid] = key
        tree.bind("<Double-1>", lambda e: self._open_ep(tree))''', '''            self._ep[iid] = key
            self._ep_addr[iid] = ip
        tree.bind("<Double-1>", lambda e: self._open_ep(tree))
        tree.bind("<Button-3>", lambda e: self._ep_menu(tree, e))
        tree.bind("<Button-2>", lambda e: self._ep_menu(tree, e))''')
rep('''        m = self.app.model
        self._ep = {}
        for ip, (pk, tx, rx) in sorted(''', '''        m = self.app.model
        self._ep, self._ep_addr = {}, {}
        for ip, (pk, tx, rx) in sorted(''')
rep('''    def _open_ep(self, tree):
        sel = tree.selection()
        k = self._ep.get(sel[0]) if sel else None
        if k:
            self.app.goto(*k)
''', '''    def _open_ep(self, tree):
        sel = tree.selection()
        k = self._ep.get(sel[0]) if sel else None
        if k:
            self.app.goto(*k)

    def _ep_menu(self, tree, e):
        iid = tree.identify_row(e.y)
        ip = self._ep_addr.get(iid)
        if not ip:
            return
        tree.selection_set(iid)
        expr = address_filter(ip)
        app, k = self.app, self._ep.get(iid)
        popup_menu(app, e, [
            ("Filter on this address", lambda: app.apply_filter(expr)),
            ("Exclude this address",
             lambda: app.apply_filter(f"not {expr}")),
            ("Copy as filter", lambda: copy_to_clipboard(app, expr)),
            None,
            ("Go to device" if k and k[0] == "device" else "Go to host",
             lambda: app.goto(*k), bool(k))])
''')

# ---- 8. app: apply_filter, go to packet ----------------------------------
rep('''    def address_label(self, ip):
        """Device name for a local address, else the address."""''', '''    def apply_filter(self, expr):
        """Packets list filtered by a field expression (switches to the
        advanced view when needed, as Wireshark's Apply as Filter)."""
        if self.beginner_mode:
            self.mode_ui_var.set("Advanced")
            self._on_ui_mode_change()
        tab = self._select_tab("packets")
        tab.show_subview("Packets")
        tab.set_expression(expr)
        return tab

    def go_to_packet(self, no=None):
        """Ctrl+G: jump to a packet number."""
        if no is None:
            text = ask_text(self, "Go to packet", "Packet number:")
            if not text:
                return None
            try:
                no = int(text.strip().lstrip("#"))
            except ValueError:
                self._set_banner(f"“{text.strip()}” is not a packet number.",
                                 kind="warn")
                return False
        return self.jump_to_packet(no)

    def address_label(self, ip):
        """Device name for a local address, else the address."""''')
rep('''    "palette": "<Control-k>",
}''', '''    "palette": "<Control-k>", "goto_packet": "<Control-g>",
}''')
rep('''            "palette": lambda e=None: self.open_palette(),
        }''', '''            "palette": lambda e=None: self.open_palette(),
            "goto_packet": lambda e=None: self.go_to_packet(),
        }''')
rep('''             {"key": "shortcuts.palette", "type": "shortcut",
              "label": "Go to anything (command palette)"},''', '''             {"key": "shortcuts.palette", "type": "shortcut",
              "label": "Go to anything (command palette)"},
             {"key": "shortcuts.goto_packet", "type": "shortcut",
              "label": "Go to packet number"},''')
rep('''                ("Show / hide the inspector", self.toggle_inspector),''',
    '''                ("Show / hide the inspector", self.toggle_inspector),
                ("Go to packet…", self.go_to_packet),''')
rep('''        "capture": {"max_stored_events": 5000, "promiscuous": True,
                    "auto_select_interface": True,
                    "preferred_interface": "", "follow_newest": True},''',
    '''        "capture": {"max_stored_events": 5000, "promiscuous": True,
                    "auto_select_interface": True,
                    "preferred_interface": "", "follow_newest": True,
                    "time_format": "Time of day", "color_expert": True},''')

open(P, "w", encoding="utf8").write(s)
print("ok part A")
