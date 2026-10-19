# ---- Sources (where the information comes from) -----------------------------
class SourcesTab(BaseTab):
    name, label_key, advanced = "sources", "tab_sources", True

    def build(self):
        self.header("\U0001F50C  Sources — where MiniWireshark's information "
                    "comes from. What this computer sees itself is "
                    "“Observed”; what a connected helper tells it is "
                    "“Reported”, shown beside it and never added to it.",
                    "Optional: connect your Pi-hole or AdGuard Home to see "
                    "the lookups of devices this computer can't hear. "
                    "Read-only — nothing is ever changed on them.")
        bar = self.toolbar()
        ttk.Button(bar, text="Add Pi-hole…", command=lambda:
                   self.app.connector_dialog(kind="pihole")).pack(side="left")
        ttk.Button(bar, text="Add AdGuard Home…", command=lambda:
                   self.app.connector_dialog(kind="adguard")).pack(
            side="left", padx=6)
        self.edit_btn = ttk.Button(bar, text="Edit…", command=self._edit)
        self.edit_btn.pack(side="left", padx=(18, 0))
        ttk.Button(bar, text="Ask now", command=self._poll).pack(
            side="left", padx=6)
        ttk.Button(bar, text="Pause / resume", command=self._toggle).pack(
            side="left")
        ttk.Button(bar, text="Remove", command=self._remove).pack(
            side="left", padx=6)
        wrap, self.tree = make_tree(self.frame, [
            ("source", "Source", 260, "w", True),
            ("kind", "Gives", 230, "w", False),
            ("level", "Evidence", 100, "w", False),
            ("state", "Status", 150, "w", False),
            ("last", "Last update", 100, "center", False),
            ("detail", "Details", 380, "w", True)])
        self.tree.configure(height=8)
        wrap.pack(fill="x", padx=6, pady=(0, 6))
        self.tree.bind("<Double-1>", lambda e: self._edit())
        self.lbl(self.frame, "Reported vs observed", muted=False,
                 font=("TkDefaultFont", 11, "bold")).pack(anchor="w",
                                                          padx=10)
        self.recon = tk.Text(self.frame, height=10, wrap="word",
                             bg=self.t["text_bg"], fg=self.t["text_fg"],
                             relief="flat", padx=10, pady=8,
                             highlightthickness=0)
        self.recon.pack(fill="both", expand=True, padx=6, pady=(2, 6))

    def _sel(self):
        sel = self.tree.selection()
        if sel and sel[0].startswith("c:"):
            return sel[0][2:]
        return None

    def _edit(self):
        cid = self._sel()
        if cid:
            self.app.connector_dialog(cid=cid)

    def _poll(self):
        if self.app.connectors is not None:
            self.app.connectors.poll_now()
            self.app._set_banner("Asking the connected helpers…")

    def _toggle(self):
        cid = self._sel()
        if cid:
            self.app.connector_set(cid, toggle_enabled=True)

    def _remove(self):
        cid = self._sel()
        if cid and messagebox.askyesno(
                "Remove helper", "Remove this connection? Its password is "
                "deleted too. What it reported this session stays visible "
                "until you clear.", parent=self.app.root):
            self.app.connector_remove(cid)

    def refresh(self):
        if not self.is_visible():
            return
        app, m = self.app, self.model
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        v = m.vantage.classify(offline=app.data_mode in ("offline",
                                                         "session"))
        self.tree.insert("", "end", iid="cap", values=(
            "This computer's network card", "Packets on the wire",
            "◉ Observed", {"live": "✔ Watching", "idle": "Stopped"}.get(
                app.data_mode, app.data_mode), "now" if app.data_mode ==
            "live" else "—", VANTAGE_TEXT.get(v, ("",))[0]))
        pm = app.procmap
        bits = []
        if pm.available:
            bits.append("programs" + (" (some need admin)"
                                      if pm.needs_admin else ""))
        if app.arp_cache:
            bits.append(f"ARP cache ({len(app.arp_cache)} entries)")
        if app.wifi.last:
            bits.append("Wi-Fi link")
        self.tree.insert("", "end", iid="os", values=(
            "This computer's operating system",
            "Programs, listening ports, ARP cache, Wi-Fi",
            "◉ Observed", "✔ Available" if bits else "—",
            fmt_clock(pm.at) if pm.at else "—", ", ".join(bits) or
            "Needs live capture" + ("" if pm.available else
                                    " and the optional psutil component")))
        st_all = app.connectors.status if app.connectors else {}
        for sp in app.config.get("connectors.list", []) or []:
            st = st_all.get(sp["id"], {})
            state = st.get("state", "waiting")
            label = {"ok": "✔ Connected", "auth": "✖ Wrong password",
                     "tls": "✖ Certificate", "network": "✖ Unreachable",
                     "api": "✖ Unexpected answer",
                     "refused": "⏸ Kill switch",
                     "waiting": "… Waiting"}.get(state, state)
            if not sp.get("enabled", True):
                label = "⏸ Paused"
            kind = CONNECTOR_KINDS.get(sp.get("kind"))
            self.tree.insert("", "end", iid="c:" + sp["id"], values=(
                f"{sp.get('name') or (kind.title if kind else '?')} — "
                f"{sp.get('url', '')}",
                "Lookups and device names of every client",
                "◈ Reported", label,
                fmt_clock(st["last_ok"]) if st.get("last_ok") else "—",
                st.get("message", "")))
        with contextlib.suppress(tk.TclError):
            if sel:
                self.tree.selection_set(sel)
        self.recon.configure(state="normal")
        self.recon.delete("1.0", "end")
        self.recon.insert("end", app.reconciliation_text())
        self.recon.configure(state="disabled")

    def on_theme(self):
        with contextlib.suppress(tk.TclError, AttributeError):
            self.recon.configure(bg=self.t["text_bg"], fg=self.t["text_fg"])


