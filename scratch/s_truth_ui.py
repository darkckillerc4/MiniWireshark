    # ---- truth UI (inspector, coverage) --------------------------------------
    def inspect(self, kind, key):
        if not self.inspector_visible:
            self.toggle_inspector(True)
        self.inspector.show(kind, key)

    def toggle_inspector(self, show=None, _e=None):
        show = (not self.inspector_visible) if show is None else bool(show)
        try:
            if show and not self.inspector_visible:
                self.body.add(self.inspector.frame, weight=1)
            elif not show and self.inspector_visible:
                self.body.forget(self.inspector.frame)
        except tk.TclError:
            return
        self.inspector_visible = show
        self.config.set("appearance.inspector", show)
        self.config.save()

    def jump_to_packet(self, no):
        """Open the Packets tab on packet `no` (the proof behind a claim)."""
        if self.beginner_mode:
            self.mode_ui_var.set("Advanced")
            self._on_ui_mode_change()
        tab = self._select_tab("packets")
        if tab.select_no(no):
            return True
        self._set_banner(f"Packet #{no} is no longer in memory (only the "
                         f"newest {self.max_rows} are kept). Turn on the "
                         f"packet history in Settings → History to keep "
                         f"older packets on disk.", kind="warn")
        return False

    def _bind_inspector(self):
        def handler(tab):
            def on_select(_e=None):
                tgt = tab.inspect_target()
                if tgt and self.inspector_visible:
                    self.inspector.show(*tgt)
            return on_select
        for tab in self.tabs.values():
            if hasattr(tab, "inspect_target") and hasattr(tab, "tree"):
                tab.tree.bind("<<TreeviewSelect>>", handler(tab), add="+")

    def coverage(self):
        return coverage_rows(self.model, self.data_mode, self.active_mode())

    def open_coverage(self):
        m = self.model
        v = m.vantage.classify(offline=self.data_mode in ("offline",
                                                          "session"))
        head, text = VANTAGE_TEXT[v]
        sections = [("From this computer", f"{head}. {text}\n\nShare of "
                     f"traffic between OTHER devices: "
                     f"{m.vantage.share_third() * 100:.1f}% "
                     f"({m.vantage.frames} frames measured).")]
        for q, a, lvl, why in self.coverage():
            sections.append((f"{LEVEL_GLYPH[lvl]} {q}", f"{a}\n{why}"))
        spots = blind_spots(m, self.data_mode, self.active_mode())
        if spots:
            sections.append(("Blind spots right now",
                             "\n".join(f"• {s}" for s in spots)))
        sections.append(("How to see more",
                         "• Connect your Pi-hole or AdGuard Home (Settings → "
                         "Sources) to see every device's lookups.\n"
                         "• A managed switch with a mirror port shows "
                         "everything on the wire.\n"
                         "• Not seeing something never means it didn't "
                         "happen."))
        DetailDialog(self, "What can I see from here?", sections,
                     size="680x560")

    def footer_text(self):
        v = self.model.vantage.classify(
            offline=self.data_mode in ("offline", "session"))
        spots = blind_spots(self.model, self.data_mode, self.active_mode())
        return (f"{VANTAGE_TEXT[v][0]}"
                f"{' · blind spots: ' + str(len(spots)) if spots else ''}"
                f"  ·  ◉ observed ◎ correlated ◌ inferred ? unknown  "
                f"·  F2 inspector")

