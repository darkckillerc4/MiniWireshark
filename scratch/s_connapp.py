    # ---- connected helpers (Pi-hole / AdGuard Home) -------------------------
    def _start_connectors(self):
        specs = self.config.get("connectors.list", []) or []
        if self.connectors is None:
            if not specs:
                return
            self.connectors = ConnectorManager(
                specs, self.vault, self._connector_result,
                float(self.config.get("connectors.interval", 60)))
            self.connectors.start()
        else:
            self.connectors.update(specs)

    def _connector_result(self, conn, res):
        """Called on the connector thread: hand over to the Tk thread."""
        self._async_results.put(lambda: self._apply_connector(conn, res))

    def _apply_connector(self, conn, res):
        if self.data_mode != "live":
            return              # helpers describe the live network only
        rep = self.model.apply_reported(conn.name, res)
        if rep and rep["lookups"] and not getattr(self, "_conn_told", None):
            self._conn_told = True
            self.model.push_timeline(
                "network", "INFO", f"{conn.name} connected: reporting "
                f"lookups for {len(rep['devices'])} device(s)")
        with contextlib.suppress(Exception):
            if "sources" in self.tabs:
                self.tabs["sources"].refresh()

    def connector_set(self, cid, toggle_enabled=False, **changes):
        specs = [dict(x) for x in self.config.get("connectors.list", [])
                 or []]
        for sp in specs:
            if sp["id"] == cid:
                if toggle_enabled:
                    sp["enabled"] = not sp.get("enabled", True)
                sp.update(changes)
        self.config.set("connectors.list", specs)
        self.config.save()
        self._start_connectors()
        with contextlib.suppress(Exception):
            self.tabs["sources"].refresh()

    def connector_remove(self, cid):
        specs = [x for x in self.config.get("connectors.list", []) or []
                 if x.get("id") != cid]
        self.config.set("connectors.list", specs)
        self.config.save()
        self.vault.delete(cid)
        self._start_connectors()
        with contextlib.suppress(Exception):
            self.tabs["sources"].refresh()

    def connector_save(self, spec, password=None):
        """Add or update a helper; the password goes to the vault."""
        specs = [dict(x) for x in self.config.get("connectors.list", [])
                 or []]
        if not spec.get("id"):
            spec["id"] = "c-" + uuid.uuid4().hex[:10]
        specs = [x for x in specs if x.get("id") != spec["id"]] + [spec]
        if password:
            self.vault.set(spec["id"], password)
        self.config.set("connectors.list", specs)
        self.config.save()
        self._start_connectors()
        return spec["id"]

    def reconciliation_text(self):
        m = self.model
        if not m.reported:
            return ("No helper connected. Observed lookups so far: "
                    f"{m.dns.queries} (only the ones that crossed this "
                    f"computer's network card).")
        lines = []
        mine_dev = {k for k, s in m.dns.device_servers.items() if s}
        for src, rep in m.reported.items():
            unseen = len(rep["unseen_clients"])
            lines.append(
                f"{src} reported {rep['lookups']} lookups from "
                f"{len(rep['devices'])} device(s) you can see"
                + (f" and {unseen} address(es) never seen on the wire"
                   if unseen else "") + f"; {rep['blocked']} were blocked.")
            lines.append(
                f"    This computer itself observed {m.dns.queries} lookups "
                f"from {len(mine_dev)} device(s). The two are not added "
                f"together: they overlap, and the helper also counts "
                f"devices this computer can't hear.")
            top = ", ".join(f"{d} ({n})" for d, n in
                            rep["domains"].most_common(8))
            if top:
                lines.append(f"    Most looked up (reported): {top}.")
            if rep["named"]:
                lines.append(f"    Names it supplied for {rep['named']} "
                             f"device(s) are marked as Reported.")
        return "\n".join(lines)

    def connector_dialog(self, kind=None, cid=None):
        """Add or edit a Pi-hole / AdGuard Home connection."""
        t = self.theme
        spec = {}
        if cid:
            spec = next((dict(x) for x in self.config.get(
                "connectors.list", []) or [] if x["id"] == cid), {})
            kind = spec.get("kind", kind)
        cls = CONNECTOR_KINDS.get(kind or "pihole")
        win = tk.Toplevel(self.root)
        win.title(("Edit " if cid else "Add ") + cls.title)
        win.geometry("600x470")
        win.configure(bg=t["tab_bg"])
        win.transient(self.root)
        body = tk.Frame(win, bg=t["tab_bg"], padx=16, pady=12)
        body.pack(fill="both", expand=True)
        tk.Label(body, text=f"Connect your {cls.title} (read-only)",
                 bg=t["tab_bg"], fg=t["text_fg"],
                 font=("TkDefaultFont", 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w")
        tk.Label(body, text="MiniWireshark only reads its query log and "
                            "device names, about once a minute. Nothing is "
                            "changed on it. The password is kept in "
                            f"{self.vault.describe()}.",
                 bg=t["tab_bg"], fg=t["muted_fg"], wraplength=560,
                 justify="left").grid(row=1, column=0, columnspan=2,
                                      sticky="w", pady=(2, 10))
        name_v = tk.StringVar(value=spec.get("name", cls.title))
        url_v = tk.StringVar(value=spec.get("url", ""))
        user_v = tk.StringVar(value=spec.get("username", ""))
        pw_v = tk.StringVar()
        ver_v = tk.BooleanVar(value=spec.get("verify", True))
        rows = [("Name:", name_v), ("Address:", url_v)]
        if kind == "adguard":
            rows.append(("User name:", user_v))
        rows.append(("Password" + (" or app password" if kind == "pihole"
                                   else "") + ":", pw_v))
        for i, (lab, var) in enumerate(rows, 2):
            tk.Label(body, text=lab, bg=t["tab_bg"], fg=t["text_fg"]).grid(
                row=i, column=0, sticky="w", pady=3)
            e = ttk.Entry(body, textvariable=var, width=46,
                          show="•" if var is pw_v else "")
            e.grid(row=i, column=1, sticky="we", pady=3)
        r = len(rows) + 2
        tk.Label(body, text=f"e.g. {cls.PATH_HINT}" + (
            "  (leave the password empty to keep the saved one)" if cid
            else ""), bg=t["tab_bg"], fg=t["muted_fg"]).grid(
            row=r, column=1, sticky="w")
        ttk.Checkbutton(body, text="Check the certificate (https)",
                        variable=ver_v).grid(row=r + 1, column=1,
                                             sticky="w", pady=(6, 0))
        msg = tk.Label(body, text="", bg=t["tab_bg"], fg=t["text_fg"],
                       wraplength=560, justify="left")
        msg.grid(row=r + 2, column=0, columnspan=2, sticky="w", pady=8)
        pin = {"value": spec.get("pin", "")}
        trust_btn = ttk.Button(body, text="Trust this certificate")

        def current_spec():
            url = url_v.get().strip().rstrip("/")
            if url and "://" not in url:
                url = "http://" + url
            return {"id": spec.get("id", ""), "kind": kind,
                    "name": name_v.get().strip() or cls.title, "url": url,
                    "username": user_v.get().strip(),
                    "verify": ver_v.get(), "pin": pin["value"],
                    "enabled": spec.get("enabled", True)}

        class _Typed:
            def __init__(self, vault, typed):
                self.vault, self.typed = vault, typed

            def get(self, cid_):
                return self.typed or self.vault.get(cid_)

        def warn_http(sp):
            if sp["url"].startswith("http://") and (pw_v.get() or cid):
                return ("\n⚠ This address is plain http: the password "
                        "crosses your network unencrypted. Prefer https:// "
                        "if your helper offers it.")
            return ""

        def test():
            sp = current_spec()
            if not sp["url"]:
                msg.configure(text="Type the address first.")
                return
            msg.configure(text="Testing…", fg=t["text_fg"])
            trust_btn.grid_forget()
            typed = pw_v.get()

            def work():
                c = cls(dict(sp, id=sp["id"] or "test"),
                        _Typed(self.vault, typed))
                try:
                    text, ok, kind_ = c.test(), True, ""
                except ConnectorError as e:
                    text, ok, kind_ = str(e), False, e.kind
                finally:
                    c.close()
                self._async_results.put(lambda: show(text, ok, kind_, sp))
            threading.Thread(target=work, daemon=True).start()

        def show(text, ok, kind_, sp):
            with contextlib.suppress(tk.TclError):
                msg.configure(text=("✔ " if ok else "✖ ") + text +
                              warn_http(sp),
                              fg=t["good_fg"] if ok else t["danger_fg"])
                if kind_ == "tls":
                    trust_btn.grid(row=r + 3, column=1, sticky="w")

        def trust():
            sp = current_spec()

            def work():
                try:
                    fp = connector_cert_fingerprint(sp["url"])
                except (OSError, ValueError) as e:
                    self._async_results.put(lambda: msg.configure(
                        text=f"✖ Couldn't read the certificate: {e}"))
                    return

                def ask():
                    if messagebox.askyesno(
                            "Trust this certificate?",
                            f"The helper at {sp['url']} presents a "
                            f"certificate with fingerprint\n\n{fp}\n\n"
                            f"Only trust it if this is your own device. "
                            f"MiniWireshark will refuse to connect if it "
                            f"ever changes.", parent=win):
                        pin["value"] = fp
                        test()
                self._async_results.put(ask)
            threading.Thread(target=work, daemon=True).start()
        trust_btn.configure(command=trust)

        def save():
            sp = current_spec()
            if not sp["url"]:
                msg.configure(text="Type the address first.")
                return
            self.connector_save(sp, pw_v.get() or None)
            win.destroy()
            with contextlib.suppress(Exception):
                self._select_tab("sources").refresh()
        btns = tk.Frame(win, bg=t["tab_bg"], padx=16, pady=10)
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(
            side="right")
        ttk.Button(btns, text="Save", style="Accent.TButton",
                   command=save).pack(side="right", padx=6)
        ttk.Button(btns, text="Test", command=test).pack(side="left")
        body.columnconfigure(1, weight=1)
        self._connector_win = win
        win._mw_test, win._mw_save = test, save
        win._mw_vars = {"name": name_v, "url": url_v, "user": user_v,
                        "pw": pw_v, "verify": ver_v, "msg": msg}
        return win

