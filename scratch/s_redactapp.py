    # ---- redaction preview and inventory (M12) ----------------------------------
    def make_redactor(self, options=None):
        nets = [p.get("name", "") for p in
                (self.networks.all() if hasattr(self.networks, "all")
                 else [])]
        nets += [p.get("ssid", "") for p in
                 (self.networks.all() if hasattr(self.networks, "all")
                  else [])]
        r = Redactor(self.model, options)
        for n in nets:
            r._add_name(n, "networks")
        w = self.wifi.last or {}
        if w.get("ssid"):
            r._add_name(w["ssid"], "networks")
        return r

    def inventory_document(self):
        rows = inventory_rows(self.model, self.device_label)
        net = self.network_name()
        sub = (f"{net} · " if net else "") + \
            f"generated {fmt_clock(time.time(), True)}"
        return inventory_html(rows, "Device inventory", sub)

    def export_inventory(self):
        self.redaction_preview("Device inventory", self.inventory_document(),
                               "device-inventory.html", redact=False)

    def export_shareable(self):
        self.redaction_preview("Shareable network report",
                               ReportBuilder(self).build("full"),
                               "network-report-redacted.html", redact=True)

    def redaction_preview(self, title, content, filename, redact=True):
        """Side by side: what you have, and what will be saved. Options
        re-render the right side; the original is never changed."""
        t = self.theme
        win = tk.Toplevel(self.root)
        win.title(f"{title} — preview")
        win.geometry("1100x700")
        win.configure(bg=t["tab_bg"])
        bar = tk.Frame(win, bg=t["tab_bg"], padx=12, pady=8)
        bar.pack(fill="x")
        on = tk.BooleanVar(value=redact)
        opts = {k: tk.BooleanVar(value=(k != "sites")) for k in
                REDACT_OPTIONS}
        ttk.Checkbutton(bar, text="Hide personal details before saving",
                        variable=on, command=lambda: render()).pack(
            side="left")
        sub = tk.Frame(win, bg=t["tab_bg"], padx=30)
        sub.pack(fill="x")
        for k, label in REDACT_OPTIONS.items():
            ttk.Checkbutton(sub, text=label, variable=opts[k],
                            command=lambda: render()).pack(side="left",
                                                           padx=(0, 10))
        info = tk.Label(win, text="", bg=t["tab_bg"], fg=t["muted_fg"],
                        anchor="w")
        info.pack(fill="x", padx=12)
        panes = tk.Frame(win, bg=t["tab_bg"])
        panes.pack(fill="both", expand=True, padx=12, pady=6)
        texts = []
        for i, head in enumerate(("Your data (not changed)",
                                  "What will be saved")):
            col = tk.Frame(panes, bg=t["tab_bg"])
            col.grid(row=0, column=i, sticky="nsew", padx=(0, 6) if i == 0
                     else (6, 0))
            panes.columnconfigure(i, weight=1)
            tk.Label(col, text=head, bg=t["tab_bg"], fg=t["text_fg"],
                     font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
            tx = tk.Text(col, wrap="word", bg=t["text_bg"], fg=t["text_fg"],
                         relief="flat", font=("TkDefaultFont", 9),
                         highlightthickness=0)
            tx.pack(fill="both", expand=True)
            texts.append(tx)
        panes.rowconfigure(0, weight=1)
        texts[0].insert("end", html_to_preview_text(content)
                        if content.lstrip().startswith("<") else content)
        texts[0].configure(state="disabled")
        state = {"out": content, "red": None}

        def render():
            if on.get():
                red = self.make_redactor({k: v.get()
                                          for k, v in opts.items()})
                out = red.text(content)
                info.configure(text=red.summary())
                state["red"] = red
            else:
                out = content
                info.configure(text="Saved exactly as shown on the left.")
                state["red"] = None
            state["out"] = out
            tx = texts[1]
            tx.configure(state="normal")
            tx.delete("1.0", "end")
            tx.insert("end", html_to_preview_text(out)
                      if out.lstrip().startswith("<") else out)
            tx.configure(state="disabled")

        def save():
            ext = os.path.splitext(filename)[1] or ".html"
            path = self._ask_save(ext, [("Web page", "*.html")] if ext ==
                                  ".html" else [("All files", "*.*")],
                                  filename)
            if not path:
                return
            try:
                atomic_write_text(path, state["out"])
            except OSError as e:
                messagebox.showerror("Export", str(e), parent=win)
                return
            self._set_banner(f"\U0001F4C4  Saved: {path}", kind="good")
            win.destroy()
        btns = tk.Frame(win, bg=t["tab_bg"], padx=12, pady=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(
            side="right")
        ttk.Button(btns, text="Save…", style="Accent.TButton",
                   command=save).pack(side="right", padx=6)
        render()
        win._mw_state, win._mw_opts, win._mw_on, win._mw_render = \
            state, opts, on, render
        return win

