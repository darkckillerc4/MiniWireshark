"""V5.0.1 part B: Follow stream (save, previous/next, direction, filter,
hex view redacted too) and the Expert list (show these packets, export,
copy as filter)."""
P = "/home/claude/mw/miniwireshark.py"
s = open(P, encoding="utf8").read()


def rep(old, new, cnt=1):
    global s
    n = s.count(old)
    assert n == cnt, (n, old[:120])
    s = s.replace(old, new)


a = s.index("class StreamsView(_SubView):")
b = s.index("class ExchangesView(_SubView):")
NEW_STREAMS = r'''STREAM_DIRECTIONS = ("Both directions", "Client → server",
                     "Server → client")


def stream_segments(res, redact=True, hexmode=False,
                    direction="Both directions"):
    """[(text, kind, packet no)]; kind is 0 (client), 1 (server) or
    "gap". The window shows exactly this and Save as… writes exactly
    this, so what you save is what you saw. A redacted stream stays
    redacted in Hex too (5.0.0 showed the raw bytes there)."""
    out = []
    want = {"Client → server": 0, "Server → client": 1}.get(direction)
    for d, off, data, no in res.chunks:
        if want is not None and d != want:
            continue
        if data is None:
            out.append((f"\n[… bytes {off}–{no} of "
                        f"{'the client' if d == 0 else 'the server'}"
                        f" side were never captured …]\n", "gap", None))
            continue
        if redact:
            body = "".join(redact_stream_line(line, res) + "\n"
                           for line in data.splitlines(True))
            if hexmode:
                body = hex_dump_lines(body.encode("utf-8")) + "\n"
        elif hexmode:
            body = hex_dump_lines(data) + "\n"
        else:
            body = data.decode("utf-8", "replace")
            body = "".join(ch if ch.isprintable() or ch in "\r\n\t"
                           else "." for ch in body)
        out.append((body, d, no))
    return out


def stream_text(res, redact=True, hexmode=False,
                direction="Both directions"):
    """The followed stream as plain text, with a short header."""
    c, sv = res.client, res.server
    head = (f"{res.transport} stream {c[0]}:{c[1]} ↔ {sv[0]}:{sv[1]} · "
            f"{direction}" + (" · redacted (mail, web or login protocol)"
                              if redact and res.sensitive() else "") +
            "\n" + "=" * 72 + "\n")
    return head + "".join(t for t, _k, _n in stream_segments(
        res, redact and res.sensitive(), hexmode, direction))


class StreamsView(_SubView):
    """Follow one connection: both directions in colour, gaps marked,
    retransmissions folded, sensitive protocols redacted by default."""

    def build(self):
        b = self.bar()
        self.label(b, "Connection:").pack(side="left")
        self.flow_var = tk.StringVar()
        ttk.Button(b, text="◀", width=3,
                   command=lambda: self.step(-1)).pack(side="left",
                                                       padx=(4, 0))
        self.box = ttk.Combobox(b, textvariable=self.flow_var, width=56,
                                state="readonly")
        self.box.pack(side="left", padx=2)
        ttk.Button(b, text="▶", width=3,
                   command=lambda: self.step(1)).pack(side="left",
                                                      padx=(0, 8))
        self.box.bind("<Button-1>", lambda e: self.box.configure(
            values=self.choices()), add="+")
        self.box.bind("<<ComboboxSelected>>", lambda e: self.show())
        self.mode_var = tk.StringVar(value="Text")
        for m in ("Text", "Hex"):
            ttk.Radiobutton(b, text=m, value=m, variable=self.mode_var,
                            command=self.render).pack(side="left")
        self.dir_var = tk.StringVar(value=STREAM_DIRECTIONS[0])
        db = ttk.Combobox(b, textvariable=self.dir_var, width=16,
                          state="readonly", values=list(STREAM_DIRECTIONS))
        db.pack(side="left", padx=(8, 0))
        db.bind("<<ComboboxSelected>>", lambda e: self.render())
        self.raw_btn = ttk.Button(b, text="Show raw text…",
                                  command=self.ask_raw)
        b2 = self.bar()
        self.label(b2, "Find:").pack(side="left")
        self.find_var = tk.StringVar()
        fe = ttk.Entry(b2, textvariable=self.find_var, width=24)
        fe.pack(side="left", padx=(4, 6))
        fe.bind("<Return>", lambda e: self.find())
        ttk.Button(b2, text="Find", command=self.find).pack(side="left")
        ttk.Button(b2, text="Filter on this stream",
                   command=self.filter_on).pack(side="left", padx=(10, 0))
        ttk.Button(b2, text="Save as…",
                   command=self.save_as).pack(side="left", padx=4)
        self.info = self.label(b2, "", muted=True)
        self.info.pack(side="left", padx=10)
        f = tk.Frame(self.frame, bg=WHITE)
        f.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.txt = tk.Text(f, wrap="char", font=self.app.mono, bg=WHITE,
                           fg="#222222", relief="flat", highlightthickness=0,
                           padx=6, pady=6, cursor="arrow")
        vs = ttk.Scrollbar(f, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=vs.set, state="disabled")
        self.txt.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.result = None
        self.flow_id = None
        self.on_theme()

    def on_theme(self):
        t = self.app.theme
        with contextlib.suppress(tk.TclError):
            self.txt.tag_configure("d0", foreground=t["accent"])
            self.txt.tag_configure("d1", foreground=t["warn_fg"])
            self.txt.tag_configure("gap", foreground=t["muted_fg"],
                                   font=("TkDefaultFont", 9, "italic"))
            self.txt.tag_configure("found", background=t["border"])

    def _flows(self):
        ids = {d.get("flow_id") for d in self.app.all_rows
               if d.get("flow_id")}
        return [f for f in (self.app.model.flows.get(i) for i in ids)
                if f is not None and f.transport in ("TCP", "UDP")]

    def choices(self):
        out = []
        for f in sorted(self._flows(), key=lambda f: -(f.last_seen or 0)):
            out.append(f"#{f.fid}  {f.local_ip}:{f.local_port} ↔ "
                       f"{f.domain or f.remote_ip}:{f.remote_port}  "
                       f"{f.transport} {f.service or ''}".strip())
            if len(out) >= 400:
                break
        return out

    def step(self, delta):
        """◀ / ▶: the previous or next connection by number (Wireshark's
        stream index spinner)."""
        ids = sorted(f.fid for f in self._flows())
        if not ids:
            return None
        cur = self.flow_id
        if cur is None:
            fid = ids[0] if delta > 0 else ids[-1]
        else:
            i = bisect.bisect_left(ids, cur)
            if delta > 0:
                i = i + 1 if i < len(ids) and ids[i] == cur else i
            else:
                i -= 1
            if not 0 <= i < len(ids):
                return None
            fid = ids[i]
        self.open_flow(fid)
        return fid

    def open_flow(self, fid):
        f = self.app.model.flows.get(fid)
        self.flow_var.set(f"#{fid}" + (f"  {f.local_ip}:{f.local_port} ↔ "
                                       f"{f.domain or f.remote_ip}:"
                                       f"{f.remote_port}" if f else ""))
        self.show()

    def show(self):
        m = re.match(r"#(\d+)", self.flow_var.get())
        if not m:
            return
        self.flow_id = int(m.group(1))
        self.result = follow_stream(self.app.all_rows, self.flow_id)
        self.render()

    def ask_raw(self):
        if messagebox.askyesno(
                "Show raw text",
                "This connection can contain passwords, cookies or private "
                "mail. The raw text stays in this window only and is never "
                "saved unless you export the packets yourself. Show it for "
                "this session?", parent=self.app.root):
            self.app.raw_streams_ok = True
            self.render()

    def redacting(self):
        r = self.result
        return bool(r is not None and r.sensitive() and
                    not getattr(self.app, "raw_streams_ok", False))

    def render(self):
        r = self.result
        txt = self.txt
        txt.configure(state="normal")
        txt.delete("1.0", "end")
        for tag in txt.tag_names():
            if tag.startswith("p_"):
                txt.tag_delete(tag)
        with contextlib.suppress(tk.TclError):
            self.raw_btn.pack_forget()
        if r is None or not r.chunks:
            txt.insert("end", "Pick a connection (or right-click a packet → "
                       "Follow stream). Only packets still in memory can be "
                       "shown.")
            txt.configure(state="disabled")
            self.info.configure(text="")
            return
        redact = self.redacting()
        if redact:
            self.raw_btn.pack(side="left", padx=(8, 0))
        sizes = [0, 0]
        for d, _o, data, _n in r.chunks:
            if data is not None:
                sizes[d] += len(data)
        for i, (body, kind, no) in enumerate(stream_segments(
                r, redact, self.mode_var.get() == "Hex", self.dir_var.get())):
            if kind == "gap":
                txt.insert("end", body, ("gap",))
                continue
            ptag = f"p_{i}"
            txt.tag_bind(ptag, "<Double-1>", lambda e, n=no: self.jump(n))
            txt.insert("end", body, (f"d{kind}", ptag))
        txt.configure(state="disabled")
        c, s = r.client, r.server
        self.info.configure(text=(
            f"{r.transport} {c[0]}:{c[1]} → {s[0]}:{s[1]} · client sent "
            f"{sizes[0]:,} B, server sent {sizes[1]:,} B"
            + (f" · {r.retrans} repeated segment(s) folded" if r.retrans
               else "")
            + (" · redacted (mail, web or login protocol)" if redact else "")
            + " · double-click text to open its packet"))

    def filter_on(self):
        if self.flow_id:
            self.app.apply_filter(f"stream:{self.flow_id}")

    def save_as(self, path=None):
        """Save the stream as text. Mail, web and login streams are
        always saved redacted, even when the raw text is shown."""
        r = self.result
        if r is None or not r.chunks:
            self.app._set_banner("Pick a connection to follow first.",
                                 kind="warn")
            return None
        if path is None:
            path = self.app._ask_save(".txt", [("Text files", "*.txt"),
                                               ("All files", "*.*")],
                                      f"stream-{self.flow_id}.txt")
        if not path:
            return None
        text = stream_text(r, True, self.mode_var.get() == "Hex",
                           self.dir_var.get())
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
        except OSError as e:
            messagebox.showerror("Save error", str(e), parent=self.app.root)
            return None
        self.app._set_banner(
            f"Saved connection #{self.flow_id} to {path}" +
            (" (redacted: mail, web or login protocol)." if r.sensitive()
             else "."))
        return path

    def find(self):
        q = self.find_var.get()
        txt = self.txt
        txt.tag_remove("found", "1.0", "end")
        if not q:
            return 0
        n, pos = 0, "1.0"
        first = None
        while True:
            pos = txt.search(q, pos, nocase=True, stopindex="end")
            if not pos:
                break
            end = f"{pos}+{len(q)}c"
            txt.tag_add("found", pos, end)
            first = first or pos
            pos = end
            n += 1
        if first:
            txt.see(first)
        return n

    def reset(self):
        self.result = None
        self.flow_id = None
        with contextlib.suppress(tk.TclError):
            self.render()


'''
s = s[:a] + NEW_STREAMS + s[b:]

# ---- Expert list ------------------------------------------------------------
rep('''class ExpertView(_SubView):
    """Expert findings, grouped so repeats count instead of flooding."""
''', '''def expert_group_filter(g):
    """A field expression that shows the packets of one finding group."""
    sev = {"warn": "warning"}.get(g["sev"], g["sev"])
    expr = (f"expert.severity == {sev} and expert.group == "
            f"{filter_quote(g['group'])}")
    prefix = re.split(r"\\d", g["summary"])[0].strip(" :(-,#")
    if len(prefix) >= 4:
        expr += f" and expert.message contains {filter_quote(prefix)}"
    return expr


def write_expert_csv(f, findings):
    """Findings as CSV: packet, time, severity, group, finding, field."""
    w = safe_csv_writer(f)
    w.writerow(["packet", "time", "severity", "group", "finding", "field"])
    n = 0
    for x in findings:
        w.writerow([x[0] or "", datetime.fromtimestamp(x[1]).strftime(
            "%Y-%m-%d %H:%M:%S.%f")[:-3] if x[1] else "",
            {"warn": "warning"}.get(x[2], x[2]), x[3], x[4], x[5] or ""])
        n += 1
    return n


class ExpertView(_SubView):
    """Expert findings, grouped so repeats count instead of flooding."""
''')
rep('''        box.bind("<<ComboboxSelected>>", lambda e: self.refresh(force=True))
        self.hint = self.label(b, "", muted=True)
        self.hint.pack(side="left", padx=8)
        pw = ttk.PanedWindow(self.frame, orient="vertical")''', '''        box.bind("<<ComboboxSelected>>", lambda e: self.refresh(force=True))
        ttk.Button(b, text="Show these packets",
                   command=self.show_packets).pack(side="left", padx=(4, 0))
        ttk.Button(b, text="Export CSV…",
                   command=self.export_csv).pack(side="left", padx=4)
        self.hint = self.label(b, "", muted=True)
        self.hint.pack(side="left", padx=8)
        pw = ttk.PanedWindow(self.frame, orient="vertical")''')
rep('''        self.tree.bind("<<TreeviewSelect>>", self._select)
        self.tree.bind("<Double-1>", self._open)
        self.detail = tk.Label(pw,''', '''        self.tree.bind("<<TreeviewSelect>>", self._select)
        self.tree.bind("<Double-1>", self._open)
        self.tree.bind("<Button-3>", self._menu)
        self.tree.bind("<Button-2>", self._menu)
        self.detail = tk.Label(pw,''')
rep('''        rank = {"All": 3, "Note and above": 2, "Warning and above": 1,
                "Errors": 0}.get(self.sev_var.get(), 2)
        gs = self.grouped(fs, rank)''', '''        rank = self.rank()
        gs = self.grouped(fs, rank)''')
rep('''    def _open(self, _e=None):
        sel = self.tree.selection()
        g = self.groups.get(sel[0]) if sel else None
        if g:
            self.jump(g["first"])


class StatisticsView(_SubView):''', '''    def _open(self, _e=None):
        sel = self.tree.selection()
        g = self.groups.get(sel[0]) if sel else None
        if g:
            self.jump(g["first"])

    def rank(self):
        return {"All": 3, "Note and above": 2, "Warning and above": 1,
                "Errors": 0}.get(self.sev_var.get(), 2)

    def selected(self):
        sel = self.tree.selection()
        return self.groups.get(sel[0]) if sel else None

    def show_packets(self, g=None):
        """Packets list filtered to the selected group (or to every packet
        with a finding at the chosen level)."""
        g = g or self.selected()
        if g:
            expr = expert_group_filter(g)
        else:
            expr = "expert.severity >= " + {
                3: "chat", 2: "note", 1: "warning", 0: "error"}[self.rank()]
        self.app.apply_filter(expr)
        return expr

    def visible_findings(self):
        store = self.app.deep.store
        rank = self.rank()
        with store.lock:
            fs = list(store.findings)
        return [f for f in fs if self.SEV_ORDER.get(f[2], 3) <= rank]

    def export_csv(self, path=None):
        fs = self.visible_findings()
        if not fs:
            self.app._set_banner("No expert findings to export at this "
                                 "level.", kind="warn")
            return None
        if path is None:
            path = self.app._ask_save(".csv", [("CSV files", "*.csv")],
                                      "expert-findings.csv")
        if not path:
            return None
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                n = write_expert_csv(f, fs)
        except OSError as e:
            messagebox.showerror("Export error", str(e),
                                 parent=self.app.root)
            return None
        self.app._set_banner(f"Exported {n:,} expert findings to {path}.")
        return path

    def _menu(self, e):
        iid = self.tree.identify_row(e.y)
        g = self.groups.get(iid)
        if not g:
            return
        self.tree.selection_set(iid)
        app = self.app
        expr = expert_group_filter(g)
        popup_menu(app, e, [
            ("Open the first packet", lambda: self.jump(g["first"]),
             bool(g["first"])),
            ("Open the last packet", lambda: self.jump(g["last"]),
             bool(g["last"])),
            ("Show these packets", lambda: self.show_packets(g)),
            ("Copy as filter", lambda: copy_to_clipboard(app, expr)),
            ("Copy finding", lambda: copy_to_clipboard(
                app, f"{g['group']}: {g['summary']} (×{g['count']})"))])


class StatisticsView(_SubView):''')
open(P, "w", encoding="utf8").write(s)
print("ok part B")
