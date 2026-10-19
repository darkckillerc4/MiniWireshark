# ---- Inspector (docked evidence pane, F2) -------------------------------------
class Inspector:
    """Shows the selected device / website / remote host / connection /
    alert as a list of claims, each with its evidence level and clickable
    proof chips (#packet numbers) that open the packet behind it."""

    WIDTH = 360

    def __init__(self, app, parent):
        self.app = app
        self.frame = tk.Frame(parent, bg=WHITE, width=self.WIDTH)
        head = tk.Frame(self.frame, bg=WHITE, padx=10, pady=6)
        head.pack(fill="x")
        self.title_var = tk.StringVar(value="Inspector")
        tk.Label(head, textvariable=self.title_var, bg=WHITE, fg="#2b3a56",
                 font=("TkDefaultFont", 11, "bold"), anchor="w",
                 justify="left", wraplength=self.WIDTH - 40).pack(
            side="left", fill="x", expand=True)
        close = tk.Label(head, text="✕", bg=WHITE, fg="#666666",
                         cursor="hand2")
        close.pack(side="right")
        close.bind("<Button-1>", lambda e: app.toggle_inspector(False))
        Tooltip(close, "Hide the inspector (F2 shows it again)")
        body = tk.Frame(self.frame, bg=WHITE)
        body.pack(fill="both", expand=True, padx=(8, 4))
        self.txt = tk.Text(body, wrap="word", bg=WHITE, fg="#222222",
                           relief="flat", highlightthickness=0, padx=4,
                           pady=4, cursor="arrow", width=40,
                           font=("TkDefaultFont", 10))
        vs = ttk.Scrollbar(body, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=vs.set, state="disabled")
        self.txt.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.legend = tk.Label(
            self.frame, text="◉ observed  ◈ reported  ◎ correlated  "
                             "◌ inferred  ? unknown", bg=WHITE,
            fg="#666666", font=("TkDefaultFont", 8), anchor="w")
        self.legend.pack(fill="x", padx=10, pady=(0, 6))
        self.current = None
        self._chip = 0
        self.on_theme()
        self._empty()

    # ---- rendering helpers
    def on_theme(self):
        t = self.app.theme
        with contextlib.suppress(tk.TclError):
            self.txt.configure(bg=t["tab_bg"], fg=t["text_fg"],
                               insertbackground=t["text_fg"])
            self.txt.tag_configure("h", font=("TkDefaultFont", 10, "bold"),
                                   foreground=t["text_fg"], spacing1=6)
            self.txt.tag_configure("muted", foreground=t["muted_fg"],
                                   font=("TkDefaultFont", 9))
            self.txt.tag_configure("chip", foreground=t["accent"],
                                   underline=True,
                                   font=("TkDefaultFont", 9))
            self.txt.tag_configure("link", foreground=t["accent"],
                                   underline=True)
            self.txt.tag_configure("warn", foreground=t["warn_fg"])
            self.txt.tag_configure("good", foreground=t["good_fg"])

    def _begin(self, title):
        self.title_var.set(title)
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        for tag in self.txt.tag_names():
            if tag.startswith("c_"):
                self.txt.tag_delete(tag)

    def _end(self):
        self.txt.configure(state="disabled")

    def _w(self, text, *tags):
        self.txt.insert("end", text, tags)

    def _clickable(self, text, fn, base="link"):
        self._chip += 1
        tag = f"c_{self._chip}"
        self.txt.insert("end", text, (base, tag))
        self.txt.tag_bind(tag, "<Button-1>", lambda e: fn())
        self.txt.tag_bind(tag, "<Enter>",
                          lambda e: self.txt.configure(cursor="hand2"))
        self.txt.tag_bind(tag, "<Leave>",
                          lambda e: self.txt.configure(cursor="arrow"))

    def _claim(self, label, value, level, why=""):
        self._w(f"{LEVEL_GLYPH.get(level, '?')} {label}: ", "h")
        self._w(f"{value}\n")
        if why:
            self._w(f"   {why}\n", "muted")

    def _chips(self, obs, limit=5):
        obs = [o for o in obs if o[5]][-limit:]
        if not obs:
            return
        self._w("   proof: ", "muted")
        for o in obs:
            no = o[5]
            self._clickable(f"#{no}", lambda n=no: self.app.jump_to_packet(n),
                            "chip")
            self._w(f" {OBS_KIND_TEXT.get(o[2], o[2])} "
                    f"{fmt_clock(o[1])}   ", "muted")
        self._w("\n")

    def _empty(self):
        self._begin("Inspector")
        self._w("Select a device, website, connection or alert to see "
                "what MiniWireshark knows about it — and how it knows.\n\n",
                "muted")
        self._w("Every statement carries a mark:\n", "muted")
        for lv in (LV_OBSERVED, LV_REPORTED, LV_CORRELATED, LV_INFERRED,
                   LV_UNKNOWN):
            self._w(f"{LEVEL_GLYPH[lv]} {LEVEL_WORD[lv]}", "h")
            self._w(f" — {LEVEL_HELP[lv]}\n", "muted")
        self._end()

    # ---- entry point
    def show(self, kind, key):
        self.current = (kind, key)
        fn = {"device": self._show_device, "website": self._show_website,
              "remote": self._show_remote, "flow": self._show_flow,
              "alert": self._show_alert}.get(kind)
        try:
            if fn is None or not fn(key):
                self._empty()
        except tk.TclError:
            pass

    def refresh(self):
        if self.current:
            self.show(*self.current)

    # ---- entity views
    def _show_device(self, key):
        m = self.app.model
        dev = m.registry.by_key.get(m.registry.resolve(key))
        if dev is None:
            return False
        self._begin(f"{DEVICE_ICONS.get(dev.type, '❓')} "
                    f"{dev.display_name()}")
        for label, value, level, why, kinds in device_claims(m, dev):
            self._claim(label, value, level, why)
            if kinds:
                self._chips(m.observations_for(dev.key, kinds))
        sites = []
        for dom in dev.websites:
            w = m.websites.get(dom)
            if w is not None:
                sites.append((ASSOC_RANK.get(w.ties.get(dev.key, [""])[0], 0),
                              dom, w.ties.get(dev.key, [""])[0]))
        if sites:
            self._w("\nWebsites\n", "h")
            for _r, dom, a in sorted(sites, reverse=True)[:12]:
                self._w(f"  {assoc_label(a)}  ")
                self._clickable(dom, lambda d=dom: self.app.inspect(
                    "website", d))
                self._w("\n")
        if dev.merge_history:
            self._w("\nMerged identities: ", "h")
            self._w(", ".join(h.get("key", "?") for h in dev.merge_history)
                    + "\n", "muted")
        held = m.registry.bindings.history(dev.ip) if dev.ip else []
        if len(held) > 1:
            self._w("\nThis address over time\n", "h")
            for owner, start, end, src in held[-4:]:
                who = "this device" if owner in (dev.mac, dev.key) else owner
                self._w(f"  {fmt_clock(start)}–"
                        f"{fmt_clock(end) if end else 'now'}  {who} "
                        f"({src})\n", "muted")
        self._w("\n")
        self._clickable("Open full details…",
                        lambda: self.app.show_device(dev.key))
        self._w("    ")
        self._clickable("Show its packets", lambda: self.app.goto(
            "packets", f'device:"{dev.ip or dev.mac}"'))
        self._end()
        return True

    def _show_website(self, dom):
        m = self.app.model
        w = m.websites.get(dom)
        if w is None:
            return False
        self._begin(f"\U0001F30D {w.domain}")
        self._claim("Best evidence", ASSOC_TEXT.get(w.best_assoc, "unknown"),
                    ASSOC_LEVEL.get(w.best_assoc, LV_UNKNOWN),
                    "A lookup alone doesn't prove a visit; HTTPS shows "
                    "only the site name, never the page.")
        self._w("\nDevices\n", "h")
        obs = m.observations_for("site:" + dom)
        for dev_key, t in sorted(w.ties.items(),
                                 key=lambda kv: -ASSOC_RANK.get(kv[1][0],
                                                                0))[:15]:
            self._w(f"  {assoc_label(t[0])}  ")
            self._clickable(self.app.short_device_name(dev_key),
                            lambda k=dev_key: self.app.inspect("device", k))
            self._w(f"  ×{t[3]}\n", "muted")
            self._chips([o for o in obs if o[3] == dev_key], 3)
        if not w.ties:
            self._w("  (no device tied to it — e.g. the router's own "
                    "lookup)\n", "muted")
        self._claim("Server addresses",
                    ", ".join(sorted(w.resolved_ips)[:6]) or "—",
                    LV_OBSERVED if w.resolved_ips else LV_UNKNOWN,
                    "From DNS answers or the connection itself.")
        self._claim("Encryption", w.encryption_text(),
                    LV_OBSERVED if (w.encrypted or w.cleartext)
                    else LV_UNKNOWN)
        self._w("\n")
        self._clickable("Open full details…",
                        lambda: self.app.show_website(dom))
        self._end()
        return True

    def _show_remote(self, ip):
        m = self.app.model
        r = m.remote_hosts.get(ip)
        if r is None:
            return False
        self._begin(f"☁️ {ip}")
        names = list(m.ip_to_domains.get(ip) or ())
        self._claim("Names for this address",
                    ", ".join(names[-5:]) or "none seen",
                    LV_CORRELATED if names else LV_UNKNOWN,
                    "Names come from DNS answers and secure-connection "
                    "names; shared (CDN) addresses serve many sites.")
        self._claim("Never a local device", "it's on the Internet",
                    LV_OBSERVED, "Public addresses are kept separate from "
                    "your devices.")
        if r.country or r.asn:
            self._claim("Location / provider",
                        f"{r.country_name or r.country} {r.org}".strip(),
                        LV_REPORTED, f"From {r.geo_source or 'a database'};"
                        f" an estimate.")
        self._claim("Traffic", f"↑{_human_bytes(r.bytes_out)} "
                               f"↓{_human_bytes(r.bytes_in)} · "
                               f"{r.connections} connections", LV_OBSERVED)
        self._w("\nDevices\n", "h")
        for k in sorted(r.devices)[:12]:
            self._w("  ")
            self._clickable(self.app.short_device_name(k),
                            lambda kk=k: self.app.inspect("device", kk))
            self._w("\n")
        self._w("\n")
        self._clickable("Open full details…",
                        lambda: self.app.show_remote(ip))
        self._end()
        return True

    def _show_flow(self, fid):
        m = self.app.model
        f = m.flows.get(fid)
        if f is None:
            return False
        self._begin(f"\U0001F517 Connection #{f.fid}")
        self._claim("Device", self.app.short_device_name(f.device_key)
                    if f.device_key else f.local_ip,
                    LV_OBSERVED if f.device_key else LV_UNKNOWN,
                    f"{f.local_ip}:{f.local_port}")
        self._claim("Other side", f"{f.remote_ip}:{f.remote_port}",
                    LV_OBSERVED)
        if f.domain:
            self._claim("Website", f"{f.domain} — "
                        f"{ASSOC_TEXT.get(f.assoc, f.domain_conf)}",
                        ASSOC_LEVEL.get(f.assoc, LV_INFERRED),
                        f.domain_conf)
        else:
            self._claim("Website", "unknown", LV_UNKNOWN,
                        "No name was visible and no lookup preceded it.")
        purpose_lvl = LV_OBSERVED if f.interp_conf == "Observed" else \
            LV_INFERRED
        self._claim("Purpose", f.purpose(), purpose_lvl, f.interp_conf or "")
        self._claim("Encryption", f.encryption_text(),
                    LV_OBSERVED if f.encrypted in ("yes", "no")
                    else LV_INFERRED)
        self._claim("Traffic", f"↑{_human_bytes(f.bytes_out)} "
                               f"↓{_human_bytes(f.bytes_in)} · "
                               f"{f.packets} packets · {f.status_text()}",
                    LV_OBSERVED)
        self._chips(m.observations_for(f"flow:{f.fid}"), 3)
        self._w("\n")
        self._clickable("Show its packets", lambda: self.app.goto(
            "packets", f"stream:{f.fid}"))
        self._end()
        return True

    def _show_alert(self, aid):
        m = self.app.model
        a = m.alerts.alerts.get(aid)
        if a is None:
            return False
        self._begin(f"{MiniWireshark.SEVERITY_ICON.get(a.severity, '')} "
                    f"{a.reason}")
        self._claim("What was observed", a.observed, LV_OBSERVED)
        self._claim("What it might mean", a.interpretation, LV_INFERRED,
                    f"Confidence: {a.confidence}. {a.why}")
        self._claim("Innocent explanations", a.possible_explanations,
                    LV_INFERRED)
        if a.evidence:
            self._w("\nEvidence\n", "h")
            for e in a.evidence[-8:]:
                self._w(f"  • {e}\n", "muted")
        if a.device_key:
            self._w("\n")
            self._clickable("Go to the device", lambda: self.app.inspect(
                "device", a.device_key))
        self._end()
        return True


