    # ---- one-click Repair, Runtime Manager, Quick Start (M6b) ----------------------
    def _on_tk(self, fn, timeout=120):
        """Run fn on the Tk thread from a worker and wait for its result."""
        ev = threading.Event()
        box = [None]

        def run():
            try:
                box[0] = fn()
            finally:
                ev.set()
        self._async_results.put(run)
        ev.wait(timeout)
        return box[0]

    def repair_everything(self, parent=None):
        """The big friendly Repair button: checks and fixes the usual
        problems, then says in plain words what it found and fixed."""
        if getattr(self, "_repair_win", None) is not None:
            with contextlib.suppress(tk.TclError):
                self._repair_win.lift()
                return
        t = self.theme
        win = tk.Toplevel(parent or self.root)
        self._repair_win = win
        win.title("Repair MiniWireshark")
        win.geometry("640x460")
        win.configure(bg=t["card_bg"])
        win.transient(parent or self.root)
        tk.Label(win, text="\U0001F6E0  Repair MiniWireshark", bg=t["card_bg"],
                 fg=t["text_fg"], font=("TkDefaultFont", 13, "bold"),
                 anchor="w").pack(fill="x", padx=14, pady=(12, 2))
        tk.Label(win, text="I'm checking the usual suspects and fixing what "
                           "I can. Your captured data and settings stay as "
                           "they are.", bg=t["card_bg"], fg=t["muted_fg"],
                 anchor="w", justify="left", wraplength=600).pack(
            fill="x", padx=14)
        lst = tk.Frame(win, bg=t["card_bg"])
        lst.pack(fill="both", expand=True, padx=14, pady=10)
        rows = {}
        for key, title in REPAIR_STEPS:
            r = tk.Frame(lst, bg=t["card_bg"])
            r.pack(fill="x", pady=2)
            icon = tk.Label(r, text="○", bg=t["card_bg"], fg=t["muted_fg"],
                            width=2, font=("TkDefaultFont", 11))
            icon.pack(side="left")
            tk.Label(r, text=title, bg=t["card_bg"], fg=t["text_fg"],
                     anchor="w", width=34).pack(side="left")
            msg = tk.Label(r, text="", bg=t["card_bg"], fg=t["muted_fg"],
                           anchor="w", justify="left", wraplength=330)
            msg.pack(side="left", fill="x", expand=True)
            rows[key] = (icon, msg)
        bar = tk.Frame(win, bg=t["card_bg"])
        bar.pack(fill="x", padx=14, pady=(0, 12))
        summary = tk.Label(bar, text="Working…", bg=t["card_bg"],
                           fg=t["text_fg"], anchor="w",
                           font=("TkDefaultFont", 10, "bold"))
        summary.pack(side="left", fill="x", expand=True)
        close = ttk.Button(bar, text="Close", command=win.destroy,
                           state="disabled")
        close.pack(side="right")

        def on_close(_e=None):
            self._repair_win = None
        win.bind("<Destroy>", lambda e: on_close() if e.widget is win
                 else None)
        glyph = {"ok": ("✔", t["good_fg"]), "fixed": ("\U0001F527",
                                                      t["accent"]),
                 "failed": ("✖", t["danger_fg"]),
                 "skipped": ("–", t["muted_fg"]),
                 "busy": ("●", t["accent"])}

        def show(key, status, text):
            def ui():
                icon, msg = rows[key]
                g, c = glyph.get(status, ("?", t["muted_fg"]))
                with contextlib.suppress(tk.TclError):
                    icon.configure(text=g, fg=c)
                    msg.configure(text=text)
            self._async_results.put(ui)

        def work():
            results = []
            for key, _title in REPAIR_STEPS:
                show(key, "busy", "checking…")
                try:
                    status, text = getattr(self, f"_repair_{key}")()
                except Exception as e:               # noqa: BLE001
                    LOG.exception("repair step %s", key)
                    status, text = "failed", f"{type(e).__name__}: {e}"
                results.append((key, status, text))
                show(key, status, text)
            fixed = sum(1 for r in results if r[1] == "fixed")
            failed = sum(1 for r in results if r[1] == "failed")
            text = ("Everything looks good — nothing needed fixing."
                    if not fixed and not failed else
                    f"Fixed {fixed} thing{'s' if fixed != 1 else ''}"
                    + (f"; {failed} couldn't be fixed (details on each "
                       f"line)." if failed else "."))
            LOG.info("repair finished: %s", results)
            self.last_repair = (time.time(), results)

            def done():
                with contextlib.suppress(tk.TclError):
                    summary.configure(text=text)
                    close.configure(state="normal")
                self._set_banner("\U0001F6E0  Repair: " + text,
                                 kind="bad" if failed else "good")
            self._async_results.put(done)
        threading.Thread(target=work, daemon=True, name="repair").start()
        return win

    def _repair_components(self):
        mgr = RuntimeManager()
        st = mgr.status()
        if st["running_inside"]:
            _eid, how = mgr.repair()
            return "fixed", f"Private Python components {how}; self-test " \
                            f"passed."
        missing = []
        for dep in DEPENDENCY_MANIFEST:
            if not _module_ok(dep["import"]):
                missing.append(dep)
        if not missing:
            note = ""
            if st["declined"] and mgr.plan()["supported"]:
                s2 = runtime_state_read()
                s2["declined"] = False
                runtime_state_write(s2)
                note = (" The private Python will be offered again next "
                        "time you start MiniWireshark.")
            return ("ok" if not note else "fixed"), \
                "All components import correctly." + note
        PIP_ASK[0] = lambda: bool(self._on_tk(lambda: messagebox.askyesno(
            "Repair", "Your Python is managed by the operating system. "
            "Install the missing components into it anyway "
            "(--break-system-packages)?", parent=self.root)))
        try:
            msgs = []
            for dep in missing:
                ok, err = _pip_install(dep["pip"], timeout=600)
                msgs.append(f"{dep['pip']} {'installed' if ok else 'failed'}")
        finally:
            PIP_ASK[0] = None
        bad = [m for m in msgs if m.endswith("failed")]
        return ("failed" if bad else "fixed"), "; ".join(msgs) + \
            (" — restart MiniWireshark to use them." if not bad else "")

    def _repair_reference(self):
        bad, fixed = [], []
        for r in self.data.resources():
            dest, _meta = self.data._paths(r)
            if not os.path.exists(dest):
                continue
            if not self.data._verify_and_load(r):
                bad.append(r.key)
        if not bad:
            return "ok", "Reference lists are intact."
        self.data.start(force=True)
        fixed = bad
        return "fixed", (f"{', '.join(fixed)}: damaged copy removed and "
                         f"downloading again.")

    def _repair_history(self):
        if self.history is None:
            if os.path.exists(PATHS.history_db):
                return "skipped", "History is off (an old file exists)."
            return "skipped", "History is off."
        try:
            con = sqlite3.connect(PATHS.history_db, timeout=10)
            row = con.execute("PRAGMA quick_check").fetchone()
            con.close()
            ok = bool(row) and row[0] == "ok"
        except sqlite3.DatabaseError:
            ok = False
        if ok:
            return "ok", "The history database is healthy."
        old = self.history

        def reopen():
            old.stop(wait=5)
            self.history = self._open_store()
            return self.history.recovered
        msg = self._on_tk(reopen)
        return "fixed", msg or "The history database was rebuilt."

    def _repair_settings(self):
        bak = self.config.path + ".bak"
        if self.config.warning and os.path.exists(bak):
            restored = AppConfig(path=bak)
            if not restored.warning:
                self.config.data = restored.data
                self.config.warning = ""
                self.config.save()
                return "fixed", "Your settings were restored from the backup."
        try:
            if os.path.exists(self.config.path):
                with open(self.config.path, encoding="utf-8") as f:
                    json.load(f)
        except (OSError, ValueError):
            self.config.save()
            return "fixed", "The settings file was damaged and was rewritten."
        return "ok", "Settings file is fine."

    def _repair_capture(self):
        def act():
            was = self.sniffer is not None
            self.refresh_adapters()
            if was:
                self._stop_capture_only()
                return self._start_capture(
                    [self.current_iface_label] + list(
                        self.iface_box["values"])[:3], keep_data=True)
            return None
        res = self._on_tk(act)
        n = len(self.iface_map)
        if IS_WINDOWS and not _npcap_present():
            return "failed", ("The capture driver (Npcap) is missing — "
                              "restart MiniWireshark and it will offer to "
                              "install it.")
        if res is None:
            return "ok", f"Network cards re-detected ({n} found)."
        return ("fixed" if res else "failed"), (
            f"Re-detected {n} network cards and restarted the capture."
            if res else "The capture engine couldn't restart; see "
                        "Diagnostics.")

    def _repair_selftest(self):
        try:
            r = subprocess.run([sys.executable, SCRIPT_PATH, SELF_TEST_FLAG,
                                "--quick"], capture_output=True, text=True,
                               timeout=600, creationflags=getattr(
                                   subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as e:
            return "failed", str(e)
        tail = (r.stdout or "").strip().splitlines()[-1:] or ["?"]
        return ("ok" if r.returncode == 0 else "failed"), tail[0]

    # ---- Runtime Manager (maintenance mode) --------------------------------------
    def runtime_status_text(self):
        mgr = RuntimeManager()
        st = mgr.status()
        lines = []
        if st["running_inside"]:
            lines.append(f"Running on MiniWireshark's private Python "
                         f"{platform.python_version()} ({st['python']}).")
        elif st["healthy"]:
            lines.append("A private Python is installed but this window "
                         "runs on another Python.")
        else:
            lines.append(f"Running on Python {platform.python_version()} "
                         f"({sys.executable}). No private Python"
                         + (" (you declined it)." if st["declined"] else "."))
        lines.append("Components verified by this release: " + ", ".join(
            f"{k} {v['version']}" for k, v in RUNTIME_LOCK.items()))
        if st["healthy"] and not st["lock_current"]:
            lines.append("⚠ The private Python was built for an older "
                         "MiniWireshark — Repair / Update brings it up to "
                         "date.")
        if st["previous"]:
            lines.append(f"Previous environment kept for rollback: "
                         f"{st['previous']}.")
        if st["pending_switch"]:
            lines.append("A rebuilt environment will be used from the next "
                         "start.")
        lt = LAUNCH_TIMES.get("ready")
        if lt:
            lines.append(f"Last launch: ready in {lt * 1000:.0f} ms "
                         f"(budget 200 ms for the launcher itself).")
        return "\n".join(lines)

    def open_runtime_manager(self, parent=None):
        """Settings → Diagnostics → Runtime Manager: the installer window
        reopened in maintenance mode."""
        win = tk.Toplevel(parent or self.root)
        win.title("Runtime Manager")
        win.geometry("760x640")
        win.transient(parent or self.root)
        lw = LoaderWindow(win, self.config, mode="maintenance")
        lw.pack(fill="both", expand=True)
        win.configure(bg=lw.bg)
        mgr = RuntimeManager()
        st = mgr.status()
        lw.status_var.set("Runtime Manager")
        lw._set_health("healthy" if st["running_inside"] and
                       st["lock_current"] else
                       "repair" if st["healthy"] else "degraded")
        f = lw._card_frame("Your MiniWireshark environment",
                           self.runtime_status_text())
        busy = {"on": False}

        def run(label, fn, done_text=None):
            if busy["on"]:
                return
            busy["on"] = True
            lw.cancel_requested = False
            lw.show_install_controls(True)
            lw.post_status(label + "…")

            def work():
                try:
                    res = fn()
                    msg = done_text(res) if done_text else "Done."
                    lw.post_status("✔ " + msg)
                    lw.post_health("healthy")
                except Exception as e:               # noqa: BLE001
                    kind = classify_runtime_error(e)
                    title, what = RUNTIME_ERRORS.get(kind,
                                                     RUNTIME_ERRORS["other"])
                    lw.post_status(f"✖ {title}. {what}")
                    lw.post_log(str(e), "err")
                    lw.post_health("failed")
                finally:
                    busy["on"] = False
                    lw.show_install_controls(False)
                for line in list(mgr.log_lines)[-40:]:
                    lw.post_log(line, "detail")
            threading.Thread(target=work, daemon=True,
                             name="runtime-manager").start()

        def rebuild():
            return mgr.provision(lw.runtime_progress,
                                 lambda: lw.cancel_requested,
                                 base_python=_find_local_python314())

        def repair_or_build():
            if mgr.status()["healthy"]:
                return mgr.repair(lw.runtime_progress,
                                  lambda: lw.cancel_requested)
            return rebuild(), "installed"

        def newer():
            info = mgr.check_newer_python()
            if info["newer"]:
                return (f"Python {info['newest_314']} exists (this release "
                        f"verified {info['verified']}). MiniWireshark moves "
                        f"to it in a future update, after testing it.")
            return (f"You have the newest Python this release verified "
                    f"({info['verified']}); newest published: "
                    f"{info['newest'] or 'unknown'}.")

        def self_test():
            exe = mgr.status()["python"] or sys.executable
            ok, text = mgr.self_test(exe, lambda: lw.cancel_requested)
            lw.post_log(text[-3000:], "detail")
            if not ok:
                raise RuntimeError_("selftest", text[-300:])
            return text.strip().splitlines()[-1] if text.strip() else "ok"

        def remove():
            if not self._on_tk(lambda: messagebox.askyesno(
                    "Remove private Python", "Delete MiniWireshark's private "
                    "Python? MiniWireshark will use the Python it was "
                    "started with until you install it again.",
                    parent=win)):
                return "Kept."
            return mgr.remove()
        actions = [
            ("\U0001F6E0 Repair / Update Environment", lambda: run(
                "Repairing", repair_or_build,
                lambda r: f"Environment {r[1]}." if isinstance(r, tuple)
                else "Done.")),
            ("Rebuild side by side", lambda: run(
                "Rebuilding", rebuild,
                lambda eid: f"New environment {eid} ready (used from the "
                            f"next start if this one is running).")),
            ("Check for newer Python", lambda: run(
                "Asking GitHub for the newest Python build", newer,
                lambda m: m)),
            ("Run self-test", lambda: run("Running the self-test", self_test,
                                          lambda m: f"Self-test: {m}")),
            ("Roll back", lambda: run(
                "Rolling back", mgr.rollback,
                lambda ok: "Switched to the previous environment (used "
                           "from the next start)." if ok else
                "There is no previous environment to roll back to.")),
            ("Remove private Python", lambda: run(
                "Removing", remove,
                lambda r: {"removed": "Removed.",
                           "on-exit": "Removed from the next start."}.get(
                    r, str(r)))),
            ("Export debug bundle…", lambda: self.export_debug_bundle(win)),
            ("Offline kit…", lambda: self._offline_kit(win, mgr)),
        ]
        grid = tk.Frame(f, bg=lw.card_bg)
        grid.pack(fill="x", pady=(6, 0))
        for i, (label, cmd) in enumerate(actions):
            ttk.Button(grid, text=label, command=cmd,
                       style="Accent.TButton" if i == 0 else "TButton").grid(
                row=i // 3, column=i % 3, sticky="ew", padx=3, pady=3)
        for c in range(3):
            grid.columnconfigure(c, weight=1)
        tk.Label(f, text="“Update” here means the newest versions THIS "
                         "release of MiniWireshark has verified — never "
                         "whatever is newest online. Nothing outside "
                         "MiniWireshark's data folder is changed.",
                 bg=lw.card_bg, fg=lw.muted, wraplength=680, justify="left",
                 anchor="w").pack(fill="x", pady=(8, 0))

        def tick():
            if not lw.winfo_exists():
                return
            lw.pump()
            win.after(100, tick)
        tick()
        return win

    def _offline_kit(self, parent, mgr):
        folder = filedialog.askdirectory(parent=parent,
                                         title="Folder for the offline kit")
        if not folder:
            return
        if os.path.exists(os.path.join(folder, "miniwireshark-kit.json")):
            n = mgr.import_offline_kit(folder)
            messagebox.showinfo("Offline kit", f"Imported {n} verified "
                                f"files. Repair / Update can now work "
                                f"without Internet.", parent=parent)
        else:
            n = mgr.export_offline_kit(folder)
            messagebox.showinfo("Offline kit", f"Saved {n} files to "
                                f"{folder}. Copy the folder to a computer "
                                f"without Internet and choose it here.",
                                parent=parent)

    def debug_bundle_text(self, masked=True):
        parts = [f"MiniWireshark {SCRIPT_VERSION} debug bundle",
                 time.strftime("%Y-%m-%d %H:%M:%S"), "",
                 "== Diagnostics ==", DiagnosticsWindow.collect(self), "",
                 "== Runtime ==", self.runtime_status_text(),
                 json.dumps({k: v for k, v in RuntimeManager().status()
                             .items() if k != "state"}, default=str,
                            indent=1), "",
                 "== Settings (no secrets are stored in settings) ==",
                 json.dumps(self.config.data, indent=1, default=str)[:20000],
                 "", "== Log (newest last) =="]
        try:
            with open(PATHS.log_file, encoding="utf-8",
                      errors="replace") as f:
                parts.append(f.read()[-60000:])
        except OSError:
            parts.append("(no log)")
        text = "\n".join(parts)
        return mask_sensitive(text) if masked else text

    def export_debug_bundle(self, parent=None):
        """Logs, diagnostics and runtime state — never packets. Addresses
        are masked by default; you see a preview before anything is
        saved."""
        parent = parent or self.root
        t = self.theme
        win = tk.Toplevel(parent)
        win.title("Export debug bundle")
        win.geometry("760x560")
        win.configure(bg=t["card_bg"])
        mask_var = tk.BooleanVar(value=True)
        tk.Label(win, text="Preview — this is exactly what will be saved. "
                           "It never contains packets or captured contents.",
                 bg=t["card_bg"], fg=t["text_fg"], anchor="w").pack(
            fill="x", padx=12, pady=(10, 4))
        txt = tk.Text(win, wrap="none", bg=t["tab_bg"], fg=t["text_fg"],
                      font=("TkFixedFont", 8))
        txt.pack(fill="both", expand=True, padx=12)

        def fill():
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.insert("end", self.debug_bundle_text(mask_var.get()))
            txt.configure(state="disabled")
        bar = tk.Frame(win, bg=t["card_bg"])
        bar.pack(fill="x", padx=12, pady=8)
        tk.Checkbutton(bar, text="Mask IP and hardware addresses "
                                 "(recommended)", variable=mask_var,
                       command=fill, bg=t["card_bg"], fg=t["text_fg"],
                       selectcolor=t["tab_bg"],
                       activebackground=t["card_bg"]).pack(side="left")

        def save():
            path = filedialog.asksaveasfilename(
                parent=win, defaultextension=".zip",
                initialfile=time.strftime("miniwireshark-debug-%Y%m%d-%H%M"
                                          ".zip"),
                filetypes=[("Zip archive", "*.zip")])
            if not path:
                return
            import zipfile
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("debug.txt", self.debug_bundle_text(
                    mask_var.get()))
            messagebox.showinfo("Debug bundle", f"Saved to {path}",
                                parent=win)
            win.destroy()
        ttk.Button(bar, text="Save…", command=save,
                   style="Accent.TButton").pack(side="right")
        ttk.Button(bar, text="Cancel", command=win.destroy).pack(
            side="right", padx=6)
        fill()
        return win

    # ---- Quick Start Guide ------------------------------------------------------
    def open_quick_start(self):
        t = self.theme
        win = tk.Toplevel(self.root)
        win.title("Quick Start Guide")
        win.geometry("620x420")
        win.configure(bg=t["card_bg"])
        win.transient(self.root)
        state = {"i": 0}
        title = tk.Label(win, bg=t["card_bg"], fg=t["text_fg"],
                         font=("TkDefaultFont", 13, "bold"), anchor="w")
        title.pack(fill="x", padx=16, pady=(14, 4))
        body = tk.Label(win, bg=t["card_bg"], fg=t["text_fg"], anchor="nw",
                        justify="left", wraplength=580)
        body.pack(fill="both", expand=True, padx=16)
        dots = tk.Label(win, bg=t["card_bg"], fg=t["muted_fg"])
        dots.pack()
        bar = tk.Frame(win, bg=t["card_bg"])
        bar.pack(fill="x", padx=16, pady=12)

        def render():
            i = state["i"]
            step = QUICK_START[i]
            title.configure(text=f"{i + 1}. {step[0]}")
            body.configure(text=step[1])
            dots.configure(text="  ".join("●" if j == i else "○"
                                          for j in range(len(QUICK_START))))
            back.configure(state="normal" if i else "disabled")
            nxt.configure(text="Finish" if i == len(QUICK_START) - 1
                          else "Next ›")

        def show_me():
            step = QUICK_START[state["i"]]
            self.goto(step[2])
            self._set_banner("\U0001F4D6  " + step[3])

        def go(d):
            j = state["i"] + d
            if j >= len(QUICK_START):
                win.destroy()
                return
            state["i"] = max(0, j)
            render()
        back = ttk.Button(bar, text="‹ Back", command=lambda: go(-1))
        back.pack(side="left")
        ttk.Button(bar, text="Show me", command=show_me).pack(side="left",
                                                              padx=8)
        nxt = ttk.Button(bar, text="Next ›", style="Accent.TButton",
                         command=lambda: go(1))
        nxt.pack(side="right")
        render()
        return win

