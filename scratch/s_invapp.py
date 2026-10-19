    # ---- guided investigations (M11) -----------------------------------------
    def collect_slow_facts(self, window=600):
        m = self.model
        now = m.now()
        live = self.data_mode == "live"
        wp = self._wifi_view()
        f = {"wifi": dict(wp.last) if wp is not None and wp.last else None,
             "wired": bool(m.switch_summary(now)),
             "health": dict(m.health) if live else {},
             "dns_slow_ms": float(self.config.get("dns.slow_ms", 800)),
             "dns_encrypted": bool(m.dns.encrypted_seen),
             "vpn": bool(m.vpn.get("iface") or m.vpn.get("endpoint")),
             "vantage": m.vantage.classify(
                 offline=self.data_mode in ("offline", "session"))}
        f["dns_median_ms"], f["dns_n"] = m.dns.median_latency(now)
        f["dns_fail_rate"], _nq = m.dns.failure_rate(now)
        f["rtt_median_ms"], f["rtt_p90"], f["rtt_n"] = m.rtt_stats(now)
        tcp = [x for x in m.flows.all_flows() if x.transport == "TCP"]
        pk = sum(x.packets for x in tcp)
        f["tcp_packets"] = pk
        f["retrans_pct"] = (sum(x.retrans for x in tcp) / pk) if pk else None
        progs, others = Counter(), Counter()
        mine = set(m.my_ips)
        me = m.my_device_key()
        for x in m.flows.all_flows():
            if now - x.last_seen > window:
                continue
            rate = x.total_bytes / max(5.0, min(window, x.duration or 5.0))
            if x.process and x.local_ip in mine:
                progs[x.process] += rate
            elif x.device_key and x.device_key != me:
                others[x.device_key] += rate
        f["this_pc_top"] = progs.most_common(3)
        if others:
            k, r = others.most_common(1)[0]
            f["other_top"] = (self.short_device_name(k), r)
        return f

    def collect_bandwidth_facts(self, window=600):
        m = self.model
        now = m.now()
        per, unatt = Counter(), 0
        for x in m.flows.all_flows():
            if now - x.last_seen > window:
                continue
            if x.device_key:
                per[x.device_key] += x.total_bytes
            else:
                unatt += x.total_bytes
        return {"devices": [(self.short_device_name(k), b, LV_OBSERVED)
                            for k, b in per.items()],
                "unattributed": unatt, "window_text": human_duration(window),
                "vantage": m.vantage.classify(
                    offline=self.data_mode in ("offline", "session"))}

    def investigate(self, which="slow"):
        """Open the guided investigation window."""
        t = self.theme
        win = tk.Toplevel(self.root)
        win.title("Why is my Internet slow?" if which == "slow" else
                  "What is using my bandwidth?")
        win.geometry("760x640")
        win.configure(bg=t["tab_bg"])
        top = tk.Frame(win, bg=t["tab_bg"], padx=14, pady=10)
        top.pack(fill="x")
        tk.Label(top, text=win.title(), bg=t["tab_bg"], fg=t["text_fg"],
                 font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        sub = tk.Label(top, text="", bg=t["tab_bg"], fg=t["muted_fg"],
                       wraplength=720, justify="left")
        sub.pack(anchor="w")
        outer, inner = make_scrollable(win, t["tab_bg"])
        outer.pack(fill="both", expand=True, padx=8)
        inner.configure(bg=t["tab_bg"])
        result = {"text": ""}

        def run():
            for w in inner.winfo_children():
                w.destroy()
            if which == "slow":
                hyps = investigate_slow(self.collect_slow_facts())
                result["hyps"] = hyps
                v = self.model.vantage.classify(
                    offline=self.data_mode in ("offline", "session"))
                sub.configure(text="A ranked list of explanations with the "
                                   "evidence for and against each. It is "
                                   "not a verdict: the top one is the best "
                                   "fit for what this computer can see "
                                   f"({VANTAGE_TEXT.get(v, ('',))[0]}).")
                lines = []
                for h in hyps:
                    color = {"Likely": t["danger_fg"],
                             "Possible": t["warn_fg"],
                             "Can't tell": t["info_fg"],
                             "Unlikely": t["good_fg"]}[h["status"]]
                    card = tk.Frame(inner, bg=t["card_bg"], padx=12, pady=8,
                                    highlightthickness=1,
                                    highlightbackground=t["border"])
                    card.pack(fill="x", pady=4, padx=4)
                    head = tk.Frame(card, bg=t["card_bg"])
                    head.pack(fill="x")
                    tk.Label(head, text=h["status"], bg=t["card_bg"],
                             fg=color, width=11, anchor="w",
                             font=("TkDefaultFont", 10, "bold")).pack(
                        side="left")
                    tk.Label(head, text=h["title"], bg=t["card_bg"],
                             fg=t["text_fg"], anchor="w",
                             font=("TkDefaultFont", 11, "bold")).pack(
                        side="left")
                    for pre, items in (("For: ", h["for"]),
                                       ("Against: ", h["against"])):
                        for it in items:
                            tk.Label(card, text=pre + it, bg=t["card_bg"],
                                     fg=t["text_fg"], anchor="w",
                                     justify="left", wraplength=640).pack(
                                fill="x")
                    if h["fix"] and h["status"] != "Unlikely":
                        tk.Label(card, text="What to try: " + h["fix"],
                                 bg=t["card_bg"], fg=t["muted_fg"],
                                 anchor="w", justify="left",
                                 wraplength=640).pack(fill="x", pady=(2, 0))
                    lines.append(f"[{h['status']}] {h['title']}\n" + "".join(
                        f"   for: {x}\n" for x in h["for"]) + "".join(
                        f"   against: {x}\n" for x in h["against"]) +
                        (f"   try: {h['fix']}\n" if h["fix"] else ""))
                result["text"] = "\n".join(lines)
            else:
                res = investigate_bandwidth(self.collect_bandwidth_facts())
                result["bw"] = res
                sub.configure(text="Counted from connections active in the "
                                   "last 10 minutes, by device. Bytes that "
                                   "can't be tied to a device are shown "
                                   "separately — never guessed.")
                tk.Label(inner, text=res["conclusion"], bg=t["tab_bg"],
                         fg=t["text_fg"], wraplength=700, justify="left",
                         font=("TkDefaultFont", 11, "bold")).pack(
                    anchor="w", pady=(4, 8), padx=4)
                for line in res["rows"]:
                    tk.Label(inner, text=line, bg=t["tab_bg"],
                             fg=t["text_fg"], anchor="w", justify="left",
                             wraplength=700).pack(fill="x", padx=4)
                if res["unattributed"]:
                    tk.Label(inner, text=f"? {_human_bytes(res['unattributed'])}"
                                         f" not tied to any device",
                             bg=t["tab_bg"], fg=t["muted_fg"],
                             anchor="w").pack(fill="x", padx=4)
                result["text"] = res["conclusion"] + "\n" + "\n".join(
                    res["rows"])
        bar = tk.Frame(win, bg=t["tab_bg"], padx=14, pady=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="Run again", command=run).pack(side="left")
        ttk.Button(bar, text="Copy result", command=lambda:
                   copy_to_clipboard(self, result["text"])).pack(
            side="left", padx=6)
        ttk.Button(bar, text="Close", command=win.destroy).pack(
            side="right")
        run()
        win._mw_result = result
        return win

