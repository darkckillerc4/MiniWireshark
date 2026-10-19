    # ---- networks and consent (section 7b) ---------------------------------------
    def active_mode(self):
        """True only when you allow active probes AND the current network
        is one you've said is yours. A network seen for the first time
        starts quiet."""
        if not self.config.get("mode.active_scanning", True):
            return False
        prof = self.network_profile
        return bool(prof and prof.get("trusted"))

    def network_name(self):
        prof = self.network_profile
        return prof.get("name", "") if prof else ""

    def _identify_network_async(self, attempt=0):
        if self.data_mode != "live":
            return
        gw = self.model.gateway_ip
        nets = [n for n in self.model.local_nets if n.version == 4]
        my_ip = next(iter(sorted(self.real_identity[1])), "")
        subnet = ""
        if nets:
            subnet = str(nets[0])
        elif my_ip:
            subnet = str(ipaddress.ip_network(f"{my_ip}/24", strict=False))
        seen_gw_mac = ""
        gdev = self.model.registry.by_key.get(
            self.model.registry.ip_to_key.get(gw, "")) if gw else None
        if gdev is not None and gdev.mac:
            seen_gw_mac = gdev.mac

        def work():
            mac = seen_gw_mac or os_neighbor_mac(gw)
            ssid = current_ssid()
            self._async_results.put(lambda: self._on_network_known(
                mac, subnet, ssid, attempt))
        threading.Thread(target=work, daemon=True,
                         name="network-id").start()

    def _on_network_known(self, router_mac, subnet, ssid, attempt):
        if self.data_mode != "live":
            return
        if not router_mac and attempt < 6:
            # the router hasn't spoken yet; listen a little longer
            self.root.after(10000, lambda: self._identify_network_async(
                attempt + 1))
            return
        fp = network_fingerprint(router_mac or "unknown", subnet)
        first_ever = self.networks.fresh_install and \
            not self.networks.data["networks"]
        prof, new = self.networks.seen(fp, router_mac, subnet, ssid)
        auto_trusted = False
        if new and first_ever and self.config.get("mode.active_scanning",
                                                  True) and \
                self.config.get("general.upgraded_from_3", False):
            # you used Active Scanning on this computer before 4.0
            self.networks.set_trusted(fp, True)
            auto_trusted = True
        changed = fp != self.network_fp
        self.network_fp = fp
        self.network_profile = self.networks.get(fp)
        self.model.registry.network_id = fp
        self.model.network_id = fp
        for dev in self.model.registry.by_key.values():
            if dev.live and not dev.network_id:
                dev.network_id = fp
        if changed:
            name = self.network_name()
            if new and not auto_trusted:
                self.model.push_timeline(
                    "network", "INFO", f"New network: {name} — Quiet Mode "
                    f"until you say it's yours")
                self._set_banner(
                    f"\U0001F6E1  This looks like a network I haven't seen "
                    f"before (“{name}”). I'm only listening. If it's your "
                    f"own network, click “Trust this network” above to let "
                    f"me look for quiet devices too.", kind="warn")
            else:
                self.model.push_timeline("network", "INFO",
                                         f"You are on {name}")
                if auto_trusted:
                    self._set_banner(
                        f"\U0001F3E0  I remembered “{name}” as your own "
                        f"network (Active Scanning was on before). New "
                        f"networks will start in Quiet Mode.")
        self._restyle_mode_banner()
        if self.active_mode():
            self._start_lan_scanner()
        else:
            self._stop_lan_scanner()

    def trust_network(self, trusted=True, fp=None):
        fp = fp or self.network_fp
        if not fp:
            return
        self.networks.set_trusted(fp, trusted)
        if fp == self.network_fp:
            self.network_profile = self.networks.get(fp)
            if trusted and not self.config.get("mode.active_scanning",
                                               True):
                self.config.set("mode.active_scanning", True)
                self.config.save()
            self.model.push_timeline(
                "network", "INFO", f"{self.network_name()} marked as "
                f"{'your network (active scanning allowed)' if trusted else 'not trusted (quiet)'}")
            self._restyle_mode_banner()
            if self.active_mode():
                self._start_lan_scanner()
                if self.prober:
                    self.prober.run_now.set()
            else:
                self._stop_lan_scanner()

    def _stop_lan_scanner(self):
        if self.lan_scanner is not None:
            self.lan_scanner.stop_flag = True
            self.lan_scanner = None

    def open_networks_dialog(self, parent=None):
        win = tk.Toplevel(parent or self.root)
        win.title("Your networks")
        win.geometry("720x380")
        win.transient(parent or self.root)
        t = self.theme
        win.configure(bg=t["card_bg"])
        tk.Label(win, text="Networks MiniWireshark has seen. Active scanning "
                           "(discovery probes and health checks) only runs on "
                           "networks you trust.", bg=t["card_bg"],
                 fg=t["text_fg"], wraplength=680, justify="left",
                 anchor="w").pack(fill="x", padx=12, pady=(10, 4))
        wrap, tree = make_tree(win, [
            ("name", "Name", 200, "w", True),
            ("trusted", "Trusted", 80, "center", False),
            ("subnet", "Subnet", 130, "w", False),
            ("router", "Router MAC", 140, "w", False),
            ("last", "Last seen", 120, "w", False)], bg=t["card_bg"])
        wrap.pack(fill="both", expand=True, padx=12, pady=4)
        rows = IidMap()

        def fill():
            tree.delete(*tree.get_children())
            rows.clear()
            for fp, p in self.networks.all():
                here = " (here)" if fp == self.network_fp else ""
                rows[fp] = tree.insert("", "end", values=(
                    p.get("name", "?") + here,
                    "✔ yes" if p.get("trusted") else "✖ no",
                    p.get("subnet", ""), p.get("router_mac", ""),
                    fmt_clock(p.get("last_seen", 0), True)))

        def sel():
            s = tree.selection()
            return key_for_iid(rows, s[0]) if s else None

        def toggle():
            fp = sel()
            if fp:
                p = self.networks.get(fp)
                self.trust_network(not p.get("trusted"), fp)
                fill()

        def rename():
            fp = sel()
            if fp:
                name = ask_text(self, "Rename network", "Name:",
                                self.networks.get(fp).get("name", ""),
                                parent=win)
                if name:
                    self.networks.rename(fp, name)
                    if fp == self.network_fp:
                        self.network_profile = self.networks.get(fp)
                        self._restyle_mode_banner()
                    fill()

        def forget():
            fp = sel()
            if fp and fp != self.network_fp and messagebox.askyesno(
                    "Forget network", "Forget this network? If you join it "
                    "again it starts in Quiet Mode.", parent=win):
                self.networks.forget(fp)
                fill()
        bar = tk.Frame(win, bg=t["card_bg"])
        bar.pack(fill="x", padx=12, pady=(4, 10))
        ttk.Button(bar, text="Trust / untrust", command=toggle).pack(
            side="left")
        ttk.Button(bar, text="Rename…", command=rename).pack(side="left",
                                                             padx=6)
        ttk.Button(bar, text="Forget", command=forget).pack(side="left")
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")
        fill()
        return win

    # ---- corrections (undoable) ---------------------------------------------------
    def _apply_correction_result(self, keys, banner=""):
        for k in keys:
            dev = self.model.registry.by_key.get(k)
            if dev is not None and dev.live:
                self._labels_changed(dev)
            else:
                self.model.dirty_devices.add(k)
        if keys:
            self.tabs["devices"].rebuild()
        if banner and keys:
            self._set_banner(banner)

    def undo_last_correction(self, _e=None):
        e = self.model.journal.last_undoable()
        if e is None:
            self._set_banner("Nothing to undo — you haven't changed any "
                             "device identities in this session.")
            return
        what = self.model.journal.describe(e, self.short_device_name)
        keys = self.model.undo_correction(e["id"])
        self._apply_correction_result(keys, f"↶  Undone: {what}")
        if not keys:
            self._set_banner(f"Couldn't undo “{what}” (the devices "
                             f"involved changed since).", kind="warn")

    def open_corrections(self, parent=None):
        win = tk.Toplevel(parent or self.root)
        win.title("Your identity corrections")
        win.geometry("760x380")
        t = self.theme
        win.configure(bg=t["card_bg"])
        tk.Label(win, text="Everything you changed about device identities "
                           "in this session. Undo any of them; the packets "
                           "and observations themselves are never changed.",
                 bg=t["card_bg"], fg=t["text_fg"], wraplength=720,
                 justify="left", anchor="w").pack(fill="x", padx=12,
                                                  pady=(10, 4))
        wrap, tree = make_tree(win, [
            ("when", "When", 90, "center", False),
            ("what", "What", 520, "w", True),
            ("state", "State", 90, "center", False)], bg=t["card_bg"])
        wrap.pack(fill="both", expand=True, padx=12, pady=4)
        rows = IidMap()

        def fill():
            tree.delete(*tree.get_children())
            rows.clear()
            for e in reversed(self.model.journal.entries):
                rows[e["id"]] = tree.insert("", "end", values=(
                    fmt_clock(e["ts"]),
                    self.model.journal.describe(e, self.short_device_name),
                    "undone" if e["undone"] else "active"))

        def undo():
            s = tree.selection()
            eid = key_for_iid(rows, s[0]) if s else None
            if eid is None:
                return
            keys = self.model.undo_correction(eid)
            self._apply_correction_result(keys, "↶  Undone.")
            fill()
        bar = tk.Frame(win, bg=t["card_bg"])
        bar.pack(fill="x", padx=12, pady=(4, 10))
        ttk.Button(bar, text="Undo selected", command=undo).pack(side="left")
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")
        fill()
        return win

