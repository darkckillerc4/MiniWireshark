    # ---- Map v3: layers, saved positions, evidence-styled edges, fast
    #      pan/zoom, keyboard and a list twin -----------------------------------
    KIND_ORDER = ("router", "computer", "this-pc", "phone", "tablet", "tv",
                  "speaker", "console", "printer", "camera", "iot",
                  "unknown")

    def _ui_scale(self):
        try:
            return max(1.0, float(self.c.tk.call("tk", "scaling")) / 1.333)
        except (tk.TclError, ValueError):
            return 1.0

    def _positions_store(self):
        allpos = self.app.config.get("map.positions", {}) or {}
        return allpos.get(self.app.network_fp or "default", {})

    def _save_position(self, key, fx, fy):
        allpos = dict(self.app.config.get("map.positions", {}) or {})
        net = self.app.network_fp or "default"
        cur = dict(allpos.get(net, {}))
        cur[key] = [round(fx, 4), round(fy, 4)]
        if len(cur) > 2000:
            cur = dict(list(cur.items())[-2000:])
        allpos[net] = cur
        self.app.config.set("map.positions", allpos)
        self.app.config.save()

    def layout_topology(self, devs, w, h):
        """Deterministic ring layout grouped by kind (sectors), for any
        number of devices; positions you dragged are kept."""
        cx, cy = w * 0.36, h / 2
        base_r = max(80, min(h, w * 0.6) * 0.40)
        saved = self._positions_store()
        order = sorted(devs, key=lambda d: (
            self.KIND_ORDER.index(d.type) if d.type in self.KIND_ORDER
            else len(self.KIND_ORDER), d.display_name().lower(), d.key))
        pos, i, ring = {}, 0, 0
        n = len(order)
        while i < n:
            cap = 14 + 10 * ring
            chunk = order[i:i + cap]
            rr = base_r * (0.55 + 0.28 * ring) if n > 14 else base_r * 0.72
            for j, d in enumerate(chunk):
                ang = 2 * math.pi * j / max(len(chunk), 1) - math.pi / 2 + \
                    ring * 0.21
                pos[d.key] = (cx + rr * math.cos(ang), cy + rr * math.sin(
                    ang))
            i += cap
            ring += 1
        for k, (fx, fy) in saved.items():
            if k in pos:
                pos[k] = (fx * w, fy * h)
        return pos, (cx, cy), base_r * (0.55 + 0.28 * max(ring - 1, 0)) \
            if n > 14 else base_r

    def _topology(self, w, h):
        t, m = self.t, self.model
        ui = self._ui_scale()
        devs = sorted(self._devices(), key=lambda d: d.display_name())
        gw = m.gateway_ip
        devs = [d for d in devs if d.ip != gw or not gw][:400]
        pos, (cx, cy), radius = self.layout_topology(devs, w, h)
        self._pos = pos
        X0, Y0 = self.P(cx, cy)
        R0 = radius * self.scale * 1.08
        self.c.create_oval(X0 - R0, Y0 - R0, X0 + R0, Y0 + R0,
                           outline=t["muted_fg"], dash=(4, 3),
                           tags=("deco",))
        self.c.create_text(X0, Y0 - R0 - 12, text="YOUR LOCAL NETWORK",
                           fill=t["muted_fg"], tags=("deco",),
                           font=("TkDefaultFont", int(9 * ui), "bold"))
        sel_key = self.selected[1] if self.selected and \
            self.selected[0] == "device" else None
        alerted = {a.device_key for a in m.alerts.alerts.values()
                   if a.severity in ("WARNING", "DANGER") and
                   not getattr(a, "acknowledged", False)} \
            if self.ov_alerts.get() else set()
        now = m.now()
        sw = m.switch_summary(now)
        me = m.my_device_key()
        sw_pos = None
        if sw and self.layer_switch.get():
            sw_pos = (cx - radius * 0.35, cy + radius * 0.35)
        traffic = self.ov_traffic.get()
        self._list_rows = []
        for dev in devs:
            x, y = pos[dev.key]
            weight = (dev.bytes_up + dev.bytes_down) if traffic else 0
            hi = dev.key == sel_key
            if sw_pos and dev.key == me:
                # an Observed physical link: the switch said so (LLDP/CDP)
                self._line(self.P(*sw_pos), self.P(x, y), weight, hi=hi,
                           tag=f"e:{dev.key}")
                via = (f"switch {sw['system'] or sw['chassis']} port "
                       f"{sw['port_desc'] or sw['port']} (◉ LLDP/CDP)")
            else:
                # logical only: we know it uses the router, not the path
                self._line(self.P(cx, cy), self.P(x, y), weight,
                           dash=(5, 4), hi=hi, tag=f"e:{dev.key}")
                via = "router (◌ logical — the physical path isn't visible)"
            hollow = dev.live and dev.state not in (STATE_ACTIVE, STATE_IDLE)
            letter = dev.confidence[:1] if dev.confidence != \
                CONFIDENCE_UNCONFIRMED else "?"
            info = (f"{dev.class_confidence} {dev.device_class}".strip() +
                    f" · {dev.ip or dev.mac} · "
                    f"{dev.confidence} confidence · "
                    f"{STATE_LABEL.get(dev.state, dev.state)} · "
                    f"↑{_human_bytes(dev.bytes_up)} "
                    f"↓{_human_bytes(dev.bytes_down)}")
            label = f"{DEVICE_ICONS.get(dev.type, '')} " \
                    f"{self.app.device_label(dev)}"
            X, Y = self._node(x, y, 10 * ui, self._conf_color(dev.confidence),
                              "device", dev.key, label, info, hollow=hollow,
                              letter=letter, show_label=len(devs) <= 60 or
                              hi)
            R = 10 * ui * max(0.7, min(1.6, self.scale))
            if dev.key in alerted:
                self.c.create_oval(X - R - 5, Y - R - 5, X + R + 5, Y + R + 5,
                                   outline=t["danger_fg"], width=2,
                                   tags=(f"n:{dev.key}", "ov"))
            if self.ov_new.get() and now - dev.first_seen < 3600 and \
                    dev.live:
                self.c.create_text(X + R + 4, Y - R - 4, text="★",
                                   fill=t["warn_fg"],
                                   tags=(f"n:{dev.key}", "ov"),
                                   font=("TkDefaultFont", int(10 * ui)))
            self._list_rows.append((dev.key, label.strip(),
                                    f"{dev.class_confidence} "
                                    f"{dev.device_class}".strip(),
                                    dev.ip or dev.mac, via,
                                    STATE_LABEL.get(dev.state, dev.state),
                                    LEVEL_WORD.get(device_weakest(m, dev),
                                                   "")))
        if sw_pos:
            self._line(self.P(*sw_pos), self.P(cx, cy), 0, dash=(5, 4),
                       tag="e:switch")
            name = sw["system"] or sw["chassis"]
            self._node(sw_pos[0], sw_pos[1], 12 * ui, t["node_router"],
                       "switch", name, f"\U0001F500 {name}",
                       f"Switch (announced itself via {sw['proto']}) · "
                       f"this computer is on port "
                       f"{sw['port_desc'] or sw['port']}"
                       + (f", VLAN {sw['vlan']}" if sw["vlan"] else ""),
                       letter="S")
        self._node(cx, cy, 18 * ui, t["node_router"], "router", "router",
                   "Your router", gw or "router address not known yet",
                   letter="R")
        remotes = []
        if self.layer_internet.get():
            remotes = sorted(m.remote_hosts.values(),
                             key=lambda r: -r.bytes_total)[:8]
            if sel_key:
                remotes = [r for r in remotes if sel_key in r.devices] or \
                    remotes
        rx = cx + radius + max(90, (w - cx - radius) * 0.55)
        X, _ = self.P(rx, 0)
        if remotes:
            self.c.create_text(X, self.P(0, cy - len(remotes) * 14 - 24)[1],
                               text="INTERNET (outside your network)",
                               fill=t["muted_fg"], tags=("deco",),
                               font=("TkDefaultFont", int(9 * ui), "bold"))
        for i, r in enumerate(remotes):
            ry = cy + (i - (len(remotes) - 1) / 2) * 30 * ui
            hi = bool(sel_key and sel_key in r.devices)
            self._line(self.P(cx + radius, cy), self.P(rx, ry),
                       r.bytes_total if traffic else 0, dash=(2, 2), hi=hi)
            label = r.domain or r.ip
            self._node(rx, ry, 7 * ui, t["node_remote"], "remote", r.ip,
                       label, f"{r.ip} · "
                       f"{r.location_text() or 'location unknown'} · "
                       f"{_human_bytes(r.bytes_total)}")
        if not devs and not remotes:
            self.c.create_text(20, 20, anchor="nw", fill=t["muted_fg"],
                               text="Nothing to show yet — start watching "
                                    "and browse for a bit.")
        self.c.create_text(10, h - 10, anchor="sw", fill=t["muted_fg"],
                           tags=("legend",),
                           font=("TkDefaultFont", int(8 * ui)),
                           text="Letters = confidence (H M L ?) · hollow = "
                                "offline · ─ seen (switch said so) · "
                                "┄ logical (inferred) · ★ new this hour · "
                                "red ring = open alert · drag a device to "
                                "place it")

    def _fast_pan(self, dx, dy):
        """Pan by moving what is drawn (one Tcl call), not redrawing."""
        self.c.move("all", dx, dy)
        self.c.move("legend", -dx, -dy)
        self._schedule_full_redraw()

    def _fast_zoom(self, f, cx=None, cy=None):
        new = max(0.4, min(3.0, self.scale * f))
        f = new / self.scale
        if abs(f - 1) < 1e-6:
            return
        w, h = self.c.winfo_width(), self.c.winfo_height()
        cx = w / 2 if cx is None else cx
        cy = h / 2 if cy is None else cy
        self.c.scale("all", cx, cy, f, f)
        # keep P() in step with what is on screen
        self.ox = (self.ox + w / 2 - cx) * f + cx - w / 2
        self.oy = (self.oy + h / 2 - cy) * f + cy - h / 2
        self.scale = new
        self._schedule_full_redraw()

    def _schedule_full_redraw(self, ms=180):
        if getattr(self, "_redraw_job", None):
            with contextlib.suppress(tk.TclError):
                self.c.after_cancel(self._redraw_job)
        self._redraw_job = self.c.after(ms, lambda: self.redraw(force=True))

    def _key(self, e):
        k = e.keysym
        step = 40
        if k in ("Left", "Right", "Up", "Down"):
            dx = {"Left": step, "Right": -step}.get(k, 0)
            dy = {"Up": step, "Down": -step}.get(k, 0)
            self.ox += dx
            self.oy += dy
            self._fast_pan(dx, dy)
        elif k in ("plus", "equal", "KP_Add"):
            self._fast_zoom(1.25)
        elif k in ("minus", "KP_Subtract"):
            self._fast_zoom(0.8)
        elif k in ("0", "Home"):
            self.reset_view()
        elif k in ("Tab", "ISO_Left_Tab"):
            rows = getattr(self, "_list_rows", [])
            if rows:
                keys = [r[0] for r in rows]
                cur = self.selected[1] if self.selected and \
                    self.selected[0] == "device" else None
                i = keys.index(cur) if cur in keys else -1
                i = (i + (-1 if e.state & 1 or k == "ISO_Left_Tab" else 1)) \
                    % len(keys)
                self.selected = ("device", keys[i])
                r = rows[i]
                self.info_var.set(f"Selected: {r[1]} — {r[2]} · {r[3]} · "
                                  f"via {r[4]} (Enter for details)")
                self.redraw(force=True)
        elif k in ("Return", "KP_Enter"):
            if self.selected:
                self._open(*self.selected)
        else:
            return None
        return "break"

    def toggle_list(self):
        """The list twin: the same nodes as a table (screen readers,
        keyboard users, very big networks)."""
        if self.list_wrap.winfo_ismapped():
            self.list_wrap.pack_forget()
            self.c.pack(fill="both", expand=True, padx=10, pady=6)
            self.list_btn.configure(text="List view")
            self.redraw(force=True)
            return False
        self.c.pack_forget()
        self.list_wrap.pack(fill="both", expand=True, padx=10, pady=6)
        self.list_btn.configure(text="Map view")
        self.fill_list()
        return True

    def fill_list(self):
        if not getattr(self, "_list_rows", None):
            self.redraw(force=True)
        tv = self.list_tree
        tv.delete(*tv.get_children())
        for key, name, kind, addr, via, state, lvl in getattr(
                self, "_list_rows", []):
            tv.insert("", "end", iid="d:" + key,
                      values=(name, kind, addr, via, state, lvl))
