class LoaderWindow(tk.Frame):
    """Runtime Manager & Welcome Center.

    One window that (1) checks and, with your consent, installs or repairs
    everything MiniWireshark needs — with named stages, real progress,
    speed and time left, a safe Cancel and plain-English errors — and
    (2) then turns into the Welcome Center: Start Monitoring, Try Demo
    Mode, Quick Start Guide and Diagnostics. Reopened from Settings it runs
    in maintenance mode (repair, update, roll back, remove, export).

    Worker threads talk to it only through post_*() and ask(), which are
    thread-safe (a queue drained on the Tk thread)."""

    WHATS_NEW = (
        ("\U0001F50E", "Evidence you can check",
         "Every statement says how it's known (◉ observed, ◎ correlated, "
         "◌ inferred) and links to the packets behind it. Press F2 for the "
         "Inspector."),
        ("⚡", "Ten times faster capture",
         "A new capture pipeline keeps up with busy networks without "
         "freezing the window."),
        ("\U0001F6E1", "Quiet on new networks",
         "Networks you haven't marked as yours start in Quiet Mode — "
         "nothing is sent until you trust them."),
        ("\U0001F552", "History and “what changed”",
         "Optional history keeps evidence across restarts and tells you "
         "what's new since yesterday."),
        ("\U0001F6E0", "One-click Repair",
         "Something wrong? Settings → Repair MiniWireshark checks and "
         "fixes the usual problems for you."),
    )

    def __init__(self, master, config=None, mode="startup"):
        self.config = config
        theme = (config.get("appearance.theme", "Light") if config
                 else "Light")
        hc = bool(config.get("appearance.high_contrast", False)) if config \
            else False
        try:
            self.t = THEMES[palette_name(theme, hc)]
        except (KeyError, NameError):
            self.t = None
        t = self.t or {}
        self.bg = t.get("window_bg", "#f4f5f7")
        self.card_bg = t.get("card_bg", "#f6f7fa")
        self.fg = t.get("text_fg", "#222222")
        self.muted = t.get("muted_fg", "#666666")
        self.accent = t.get("accent", "#2b7de9")
        super().__init__(master, bg=self.bg)
        self.mode = mode
        self.q = queue.Queue()
        self.details_var = tk.BooleanVar(value=False)
        self.cancel_requested = False
        self.handoff = False
        self.choice = None
        self.stage_state = {}
        self._build()

    # ---- layout ------------------------------------------------------------------
    def _build(self):
        hdr = tk.Frame(self, bg="#2b3a55", padx=18, pady=12)
        hdr.pack(fill="x")
        left = tk.Frame(hdr, bg="#2b3a55")
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text=f"MiniWireshark {SCRIPT_VERSION}", fg="white",
                 bg="#2b3a55", font=("TkDefaultFont", 16, "bold")).pack(
            anchor="w")
        self.sub_var = tk.StringVar(
            value="Runtime Manager — checking everything is ready"
            if self.mode == "maintenance" else
            "Getting everything ready — quick after the first time")
        tk.Label(left, textvariable=self.sub_var, fg="#c8d2e0",
                 bg="#2b3a55").pack(anchor="w")
        self.health_lbl = tk.Label(hdr, text="● Checking", fg="#2b3a55",
                                   bg="#c8d2e0", padx=10, pady=4,
                                   font=("TkDefaultFont", 10, "bold"))
        self.health_lbl.pack(side="right")
        body = tk.Frame(self, bg=self.bg, padx=18, pady=10)
        body.pack(fill="both", expand=True)
        self.body = body
        stages = tk.Frame(body, bg=self.bg)
        stages.pack(fill="x", pady=(0, 6))
        self.stage_lbls = {}
        for i, name in enumerate(RuntimeManager.STAGES):
            lb = tk.Label(stages, text=f"○ {name}", bg=self.bg, fg=self.muted,
                          font=("TkDefaultFont", 9))
            lb.pack(side="left", padx=(0, 4))
            if i < len(RuntimeManager.STAGES) - 1:
                tk.Label(stages, text="›", bg=self.bg,
                         fg=self.muted).pack(side="left", padx=(0, 4))
            self.stage_lbls[name] = lb
        self.status_var = tk.StringVar(value="Starting …")
        tk.Label(body, textvariable=self.status_var, bg=self.bg, fg=self.fg,
                 font=("TkDefaultFont", 11, "bold"), anchor="w",
                 justify="left", wraplength=600).pack(fill="x")
        self.progress = ttk.Progressbar(body, mode="determinate",
                                        maximum=100)
        self.progress.pack(fill="x", pady=(6, 2))
        self.speed_var = tk.StringVar(value="")
        tk.Label(body, textvariable=self.speed_var, bg=self.bg,
                 fg=self.muted, anchor="w").pack(fill="x")
        self.card = tk.Frame(body, bg=self.bg)
        self.card.pack(fill="both", expand=True, pady=(6, 4))
        bar = tk.Frame(body, bg=self.bg)
        bar.pack(fill="x")
        tk.Checkbutton(bar, text="Show technical details",
                       variable=self.details_var, bg=self.bg, fg=self.fg,
                       selectcolor=self.card_bg, activebackground=self.bg,
                       command=self._toggle_details).pack(side="left")
        self.cancel_btn = ttk.Button(bar, text="Cancel",
                                     command=self._cancel)
        self.copy_btn = ttk.Button(bar, text="Copy details",
                                   command=self._copy_details)
        self.copy_btn.pack(side="right")
        self.logf = tk.Frame(body, bg=self.card_bg, bd=1, relief="solid")
        self.log = tk.Text(self.logf, height=8, bg=self.card_bg, fg=self.fg,
                           relief="flat", font=("TkFixedFont", 9),
                           state="disabled", wrap="word", padx=8, pady=6)
        vs = ttk.Scrollbar(self.logf, orient="vertical",
                           command=self.log.yview)
        self.log.configure(yscrollcommand=vs.set)
        self.log.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        t = self.t or {}
        self.log.tag_configure("step", font=("TkFixedFont", 9, "bold"))
        self.log.tag_configure("ok", foreground=t.get("good_fg", "#0b6b3a"))
        self.log.tag_configure("err", foreground=t.get("danger_fg",
                                                       "#a01a08"))
        self.log.tag_configure("warn", foreground=t.get("warn_fg",
                                                        "#8a5a00"))
        self.log.tag_configure("detail", foreground=self.muted)
        self.footer = tk.Label(self, text="Please wait …",
                               bg=t.get("side_bg", "#e3e6eb"), fg=self.fg,
                               anchor="w", padx=12, pady=5)
        self.footer.pack(side="bottom", fill="x")

    def _toggle_details(self):
        if self.details_var.get():
            self.logf.pack(fill="both", expand=True, pady=(4, 0))
        else:
            self.logf.pack_forget()

    def _cancel(self):
        self.cancel_requested = True
        self.post_status("Cancelling safely — nothing half-done is kept…")

    def _copy_details(self):
        try:
            text = self.log.get("1.0", "end")
            self.clipboard_clear()
            self.clipboard_append(mask_sensitive(text))
            self.post_footer("Details copied (addresses masked).")
        except tk.TclError:
            pass

    def _clear_card(self):
        for w in self.card.winfo_children():
            w.destroy()

    def _card_frame(self, title, text=""):
        self._clear_card()
        f = tk.Frame(self.card, bg=self.card_bg, padx=14, pady=10,
                     highlightthickness=1,
                     highlightbackground=(self.t or {}).get("border",
                                                            "#e0e2e8"))
        f.pack(fill="both", expand=True)
        tk.Label(f, text=title, bg=self.card_bg, fg=self.fg,
                 font=("TkDefaultFont", 12, "bold"), anchor="w",
                 justify="left", wraplength=620).pack(fill="x")
        if text:
            tk.Label(f, text=text, bg=self.card_bg, fg=self.fg, anchor="w",
                     justify="left", wraplength=620).pack(fill="x",
                                                          pady=(6, 8))
        return f

    # ---- thread-safe API (any thread) --------------------------------------------
    def post_log(self, t, tag=None):
        self.q.put(("log", t, tag))
        if tag in ("err", "warn"):
            LOG.warning("bootstrap: %s", t)
        else:
            LOG.info("bootstrap: %s", t.strip())

    def post_status(self, t):
        self.q.put(("status", t))

    def post_progress(self, p):
        self.q.put(("progress", p))

    def post_footer(self, t):
        self.q.put(("footer", t))

    def post_stage(self, name, state):
        self.q.put(("stage", name, state))

    def post_speed(self, text):
        self.q.put(("speed", text))

    def post_health(self, kind):
        self.q.put(("health", kind))

    def runtime_progress(self, stage, frac, text, extra):
        """Adapter for RuntimeManager progress callbacks."""
        order = RuntimeManager.STAGES
        if stage in order:
            for s in order[:order.index(stage)]:
                if self.stage_state.get(s) not in ("done", "skip", "fail"):
                    self.post_stage(s, "skip" if s not in self.stage_state
                                    else "done")
            self.post_stage(stage, "done" if frac >= 1.0 else "active")
            base = order.index(stage) / len(order)
            self.post_progress(int(100 * (base + frac / len(order))))
        self.post_status(text)
        sp = extra.get("speed") if extra else None
        if sp:
            eta = extra.get("eta") or 0
            self.post_speed(f"{sp / 1e6:.1f} MB/s · about "
                            f"{human_duration(eta) if eta else '—'} left")
        elif stage != "Download":
            self.post_speed("")

    def ask(self, kind, **kw):
        """Ask the person something from a worker thread; blocks until they
        answer. Returns the chosen answer string."""
        ev = threading.Event()
        box = [None]
        self.q.put(("ask", kind, kw, ev, box))
        while not ev.wait(0.2):
            if not self.winfo_exists():
                return "cancel"
        return box[0]

    # ---- Tk thread ---------------------------------------------------------------------
    def pump(self):
        while True:
            try:
                it = self.q.get_nowait()
            except queue.Empty:
                break
            k = it[0]
            try:
                if k == "log":
                    self.log.config(state="normal")
                    self.log.insert("end", it[1] + "\n", it[2] or ())
                    self.log.see("end")
                    self.log.config(state="disabled")
                elif k == "status":
                    self.status_var.set(it[1])
                elif k == "progress":
                    self.progress["value"] = it[1]
                elif k == "footer":
                    self.footer.config(text=it[1])
                elif k == "speed":
                    self.speed_var.set(it[1])
                elif k == "stage":
                    self._set_stage(it[1], it[2])
                elif k == "health":
                    self._set_health(it[1])
                elif k == "ask":
                    self._show_question(*it[1:])
            except tk.TclError:
                pass
        try:
            self.update_idletasks()
            self.update()
        except tk.TclError:
            pass

    def _set_stage(self, name, state):
        self.stage_state[name] = state
        lb = self.stage_lbls.get(name)
        if lb is None:
            return
        t = self.t or {}
        glyph, color = {"active": ("●", self.accent),
                        "done": ("✔", t.get("good_fg", "#0b6b3a")),
                        "fail": ("✖", t.get("danger_fg", "#a01a08")),
                        "skip": ("–", self.muted)}.get(state,
                                                       ("○", self.muted))
        lb.configure(text=f"{glyph} {name}", fg=color,
                     font=("TkDefaultFont", 9,
                           "bold" if state == "active" else "normal"))

    def _set_health(self, kind):
        t = self.t or {}
        text, bg, fg = {
            "healthy": ("✔ Healthy", t.get("mode_active_bg", "#e6f4ea"),
                        t.get("mode_active_fg", "#0b6b3a")),
            "repair": ("⚠ Needs repair", t.get("warn_bg", "#fff5e0"),
                       t.get("warn_fg", "#8a5a00")),
            "degraded": ("◐ Degraded", t.get("warn_bg", "#fff5e0"),
                         t.get("warn_fg", "#8a5a00")),
            "failed": ("✖ Problem", t.get("danger_bg", "#fbe9e7"),
                       t.get("danger_fg", "#8a1a08"))}.get(
            kind, ("● Checking", "#c8d2e0", "#2b3a55"))
        self.health_lbl.configure(text=text, bg=bg, fg=fg)

    def _show_question(self, kind, kw, ev, box):
        def answer(value):
            box[0] = value
            self._clear_card()
            ev.set()
        if kind == "consent":
            f = self._card_frame("Set up MiniWireshark's own Python? "
                                 "(recommended)", kw.get("text", ""))
            row = tk.Frame(f, bg=self.card_bg)
            row.pack(fill="x", pady=(4, 0))
            b = ttk.Button(row, text="Install private Python",
                           style="Accent.TButton",
                           command=lambda: answer("install"))
            b.pack(side="left")
            ttk.Button(row, text="Use my current Python",
                       command=lambda: answer("this")).pack(side="left",
                                                           padx=8)
            ttk.Button(row, text="Exit", command=lambda: answer("cancel")
                       ).pack(side="right")
            b.focus_set()
        elif kind == "error":
            title, what = RUNTIME_ERRORS.get(kw.get("err", "other"),
                                             RUNTIME_ERRORS["other"])
            f = self._card_frame("✖ " + title, what)
            det = kw.get("detail", "")
            if det:
                tk.Label(f, text=det[-300:], bg=self.card_bg, fg=self.muted,
                         anchor="w", justify="left", wraplength=620,
                         font=("TkFixedFont", 8)).pack(fill="x")
            row = tk.Frame(f, bg=self.card_bg)
            row.pack(fill="x", pady=(8, 0))
            ttk.Button(row, text="Try again", style="Accent.TButton",
                       command=lambda: answer("retry")).pack(side="left")
            ttk.Button(row, text=kw.get("continue_text",
                                        "Continue with my current Python"),
                       command=lambda: answer("continue")).pack(
                side="left", padx=8)
            ttk.Button(row, text="Copy details",
                       command=self._copy_details).pack(side="right")
            self._set_health("failed")
        elif kind == "pip_system":
            f = self._card_frame(
                "Install into your system Python?",
                "Your Python is managed by the operating system, which "
                "normally doesn't want programs to add packages to it. I "
                "can still install the capture engine (scapy) there with "
                "pip's “--break-system-packages” option. A safer choice "
                "is the private Python (Settings → Repair). Install into "
                "your system Python anyway?")
            row = tk.Frame(f, bg=self.card_bg)
            row.pack(fill="x")
            ttk.Button(row, text="Yes, install it",
                       command=lambda: answer("yes")).pack(side="left")
            ttk.Button(row, text="No", command=lambda: answer("no")).pack(
                side="left", padx=8)
        else:
            f = self._card_frame(kw.get("title", "Question"),
                                 kw.get("text", ""))
            row = tk.Frame(f, bg=self.card_bg)
            row.pack(fill="x")
            for label, value in kw.get("buttons", [("OK", "ok")]):
                ttk.Button(row, text=label,
                           command=lambda v=value: answer(v)).pack(
                    side="left", padx=(0, 8))

    def show_install_controls(self, on):
        try:
            if on:
                self.cancel_btn.pack(side="right", padx=8)
            else:
                self.cancel_btn.pack_forget()
        except tk.TclError:
            pass

    def show_fatal(self, m):
        self.post_status("Setup could not finish")
        self.post_health("failed")
        self.post_log("", None)
        self.post_log(m, "err")
        self.post_footer("Close this window to exit. Details are in the "
                         "log: " + PATHS.log_file)
        self.pump()
        try:
            f = self._card_frame("✖ Setup could not finish", m[-900:])
            ttk.Button(f, text="Copy details",
                       command=self._copy_details).pack(anchor="w")
        except tk.TclError:
            pass

    # ---- Welcome Center ----------------------------------------------------------
    def show_welcome(self, summary="", health="healthy", first_time=False):
        """Turn into the Welcome Center and wait for a choice. Returns
        "monitor", "demo", "guide", "diagnostics", "repair" or "exit"."""
        self.choice = None
        for w in (self.progress,):
            with contextlib.suppress(tk.TclError):
                w.pack_forget()
        for lb in self.stage_lbls.values():
            with contextlib.suppress(tk.TclError):
                lb.master.pack_forget()
                break
        self.speed_var.set("")
        self._set_health(health)
        self.sub_var.set("Welcome — your network, explained in plain "
                         "English")
        self.status_var.set("Welcome back!" if not first_time else
                            "Welcome to MiniWireshark 4!")
        self._clear_card()
        top = tk.Frame(self.card, bg=self.bg)
        top.pack(fill="both", expand=True)
        tiles = tk.Frame(top, bg=self.bg)
        tiles.pack(fill="x")
        spec = (("monitor", "▶", "Start Monitoring",
                 "Pick the best network card and start watching."),
                ("demo", "\U0001F3AE", "Try Demo Mode",
                 "Explore with simulated data. Nothing real is shown."),
                ("guide", "\U0001F4D6", "Quick Start Guide",
                 "Five short steps through the important parts."),
                ("diagnostics", "\U0001FA7A", "Diagnostics",
                 "Check the setup, capture driver and environment."))
        first_tile = None
        for i, (key, icon, title, text) in enumerate(spec):
            tile = tk.Frame(tiles, bg=self.card_bg, padx=12, pady=10,
                            cursor="hand2", takefocus=1,
                            highlightthickness=2,
                            highlightbackground=self.accent if i == 0
                            else (self.t or {}).get("border", "#e0e2e8"),
                            highlightcolor=self.accent)
            tile.grid(row=0, column=i, sticky="nsew", padx=4)
            tiles.columnconfigure(i, weight=1)
            a = tk.Label(tile, text=f"{icon}  {title}", bg=self.card_bg,
                         fg=self.fg, font=("TkDefaultFont", 11, "bold"),
                         anchor="w")
            a.pack(anchor="w")
            b = tk.Label(tile, text=text, bg=self.card_bg, fg=self.muted,
                         wraplength=135, justify="left", anchor="w")
            b.pack(anchor="w", pady=(4, 0))
            for w in (tile, a, b):
                w.bind("<Button-1>", lambda e, k=key: self._choose(k))
            tile.bind("<Return>", lambda e, k=key: self._choose(k))
            tile.bind("<space>", lambda e, k=key: self._choose(k))
            if first_tile is None:
                first_tile = tile
        news = tk.Frame(top, bg=self.card_bg, padx=12, pady=8)
        news.pack(fill="both", expand=True, pady=(10, 0))
        tk.Label(news, text="What's new in 4.0", bg=self.card_bg,
                 fg=self.fg, font=("TkDefaultFont", 10, "bold"),
                 anchor="w").pack(fill="x")
        for icon, title, text in self.WHATS_NEW:
            tk.Label(news, text=f"{icon}  {title} — {text}",
                     bg=self.card_bg, fg=self.fg, anchor="w",
                     justify="left", wraplength=640).pack(fill="x",
                                                          pady=1)
        bottom = tk.Frame(top, bg=self.bg)
        bottom.pack(fill="x", pady=(8, 0))
        if summary:
            tk.Label(bottom, text=summary, bg=self.bg, fg=self.muted,
                     anchor="w", justify="left", wraplength=640).pack(
                fill="x")
        row = tk.Frame(bottom, bg=self.bg)
        row.pack(fill="x", pady=(4, 0))
        self.show_welcome_var = tk.BooleanVar(
            value=bool(self.config.get("general.show_welcome", True))
            if self.config else True)
        tk.Checkbutton(row, text="Show the Welcome Center at startup",
                       variable=self.show_welcome_var, bg=self.bg,
                       fg=self.fg, selectcolor=self.card_bg,
                       activebackground=self.bg).pack(side="left")
        rep = tk.Label(row, text="Something wrong? Repair…", bg=self.bg,
                       fg=self.accent, cursor="hand2",
                       font=("TkDefaultFont", 10, "underline"))
        rep.pack(side="right")
        rep.bind("<Button-1>", lambda e: self._choose("repair"))
        self.footer.config(text="Enter = Start Monitoring · Tab moves "
                                "between choices · new networks start in "
                                "Quiet Mode")
        self.winfo_toplevel().bind("<Return>",
                                   lambda e: self._choose("monitor"))
        self.winfo_toplevel().protocol("WM_DELETE_WINDOW",
                                       lambda: self._choose("exit"))
        if first_tile is not None:
            first_tile.focus_set()
        while self.choice is None:
            try:
                self.update()
            except tk.TclError:
                return "exit"
            time.sleep(0.01)
        with contextlib.suppress(tk.TclError):
            self.winfo_toplevel().unbind("<Return>")
        if self.config is not None:
            self.config.set("general.show_welcome",
                            bool(self.show_welcome_var.get()))
            self.config.set("general.welcome_version", SCRIPT_VERSION)
            self.config.save()
        return self.choice

    def _choose(self, key):
        self.choice = key


def mask_sensitive(text):
    """Mask IPv4/IPv6 and MAC addresses in shareable text (debug bundles,
    copied details). Keeps the first part so different addresses stay
    distinguishable."""
    text = re.sub(r"\b([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                  r"[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}"
                  r"[:-][0-9a-fA-F]{2}\b", r"\1:\2:xx:xx:xx:xx", text)
    text = re.sub(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b",
                  r"\1.\2.x.x", text)
    text = re.sub(r"\b([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):"
                  r"[0-9a-fA-F:]{2,}\b", r"\1:\2:…", text)
    return text


