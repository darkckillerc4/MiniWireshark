P = "/home/claude/mw/miniwireshark.py"
src = open(P, encoding="utf8").read()


def rep(old, new, cnt=1):
    global src
    n = src.count(old)
    assert n == cnt, (old[:80], n)
    src = src.replace(old, new)


# ---- runtime status text ---------------------------------------------------
a = src.index('''    def runtime_status_text(self):
        mgr = RuntimeManager()''')
b = src.index('''    def open_runtime_manager(self, parent=None):''')
src = src[:a] + '''    def runtime_status_text(self):
        mgr = RuntimeManager()
        st = mgr.status()
        state = runtime_state_read()
        env = runtime_env(state) or {}
        lines = []
        if st["running_inside"]:
            lines.append(f"Running on MiniWireshark's managed Python "
                         f"{platform.python_version()} ({st['python']}).")
        else:
            lines.append(f"Running on Python {platform.python_version()} "
                         f"({sys.executable}) — the Python that started "
                         f"MiniWireshark. It is never modified.")
            if env.get("handshake_failed"):
                lines.append(f"⚠ A managed Python is installed, but its "
                             f"window didn't come up last time "
                             f"({env.get('handshake_error', '?')}). It is "
                             f"not used until Repair / Update or Rebuild.")
            elif st["healthy"] and state.get("prefer") == "managed":
                lines.append("A managed Python is installed and chosen; it "
                             "starts from the next launch (after its window "
                             "reports back).")
            elif st["healthy"]:
                lines.append("A managed Python is installed but not chosen "
                             "(tick “Start in the managed Python” below to "
                             "use it).")
        pk = PRIVATE_PACKAGES.installed()
        lines.append(f"Private packages folder ({abi_tag()}): " + (
            ", ".join(f"{k} {v.get('version', '?')}" for k, v in
                      sorted(pk.items())) if pk else "empty"))
        if HANDOFF_NOTE[0]:
            lines.append("⚠ " + HANDOFF_NOTE[0])
        if CAPTURE_LIMITED[0]:
            lines.append("⚠ " + CAPTURE_LIMITED[0])
        if st["healthy"] and not st["lock_current"]:
            lines.append("⚠ The managed Python was built for an older "
                         "MiniWireshark — Repair / Update brings it up to "
                         "date.")
        if st["previous"]:
            lines.append(f"Previous managed environment kept for rollback: "
                         f"{st['previous']}.")
        if st["pending_switch"]:
            lines.append("A rebuilt environment will be used from the next "
                         "start.")
        lt = LAUNCH_TIMES.get("ready")
        if lt:
            lines.append(f"Last launch: ready in {lt * 1000:.0f} ms.")
        return "\\n".join(lines)

''' + src[b:]

# ---- Runtime Manager: repair works without a managed Python ---------------
rep('''        def repair_or_build():
            """Repair / Update: reinstall the verified components, restore
            and update pip, fix conflicts, re-test, then report."""
            if not mgr.status()["healthy"]:
                if not ask("Install the private Python?",
                           mgr.describe() + "\\n\\nInstall it now?"):
                    return None, "kept as it is"
                return rebuild(), "installed"
            eid, how = mgr.repair(lw.runtime_progress, cancel)''',
    '''        def repair_or_build():
            """Repair / Update: on this Python, repair the private packages
            folder; with a managed Python, also reinstall its verified
            components, update its pip, re-test, then report."""
            state = runtime_state_read()
            env = runtime_env(state)
            if env and env.get("handshake_failed"):
                env.pop("handshake_failed", None)    # try it once more
                env.pop("handshake_error", None)
                runtime_state_write(state)
            if not mgr.status()["healthy"]:
                status, msg = self._repair_components()
                lw.post_log(msg, "ok" if status != "failed" else "err")
                if status == "failed":
                    raise RuntimeError_("pip", msg)
                return None, msg
            eid, how = mgr.repair(lw.runtime_progress, cancel)''')
rep('''            ("\\U0001F6E0 Repair / Update Environment", lambda: run(
                "Repairing and updating", repair_or_build,
                lambda r: f"Environment {r[1]}." if isinstance(r, tuple)
                else "Done.")),''', '''            ("\\U0001F6E0 Repair / Update Environment", lambda: run(
                "Repairing and updating", repair_or_build,
                lambda r: (r[1] if r[0] is None else f"Environment {r[1]}.")
                if isinstance(r, tuple) else "Done.")),''')
rep('''        def rebuild():
            return mgr.provision(lw.runtime_progress, cancel,
                                 base_python=_find_local_python314())''',
    '''        def choose_managed():
            s = runtime_state_read()
            s["prefer"] = "managed"
            runtime_state_write(s)
            lw.q.put(("call", lambda: pref.set(True)))

        def rebuild():
            eid = mgr.provision(lw.runtime_progress, cancel,
                                base_python=_find_local_python314())
            choose_managed()
            return eid''')
rep('''            eid = mgr.provision(lw.runtime_progress, cancel, source=src)
            return (f"Python {src['version']} installed and tested "
                    f"({eid}). It is used from the next start.")''',
    '''            eid = mgr.provision(lw.runtime_progress, cancel, source=src)
            choose_managed()
            return (f"Python {src['version']} installed and tested "
                    f"({eid}). It is used from the next start, once its "
                    f"window reports back.")''')
rep('''            ("Rebuild side by side", lambda: run(''',
    '''            ("Get / rebuild managed Python", lambda: run(''')
rep('''            ("Remove private Python", lambda: run(''',
    '''            ("Remove managed Python", lambda: run(''')
rep('''            if not ask("Remove private Python", "Delete MiniWireshark's "
                       "private Python? MiniWireshark will use the Python it "
                       "was started with until you install it again."):''',
    '''            if not ask("Remove managed Python", "Delete MiniWireshark's "
                       "managed Python? MiniWireshark will use the Python it "
                       "was started with (and its private packages "
                       "folder)."):''')
rep('''        tk.Label(f, text="Repair / Update installs the versions THIS "
                         "release of MiniWireshark verified, and updates pip "
                         "inside the private Python. A newer Python is only "
                         "installed when you ask, after GitHub's checksum and "
                         "the self-test pass. Nothing outside MiniWireshark's "
                         "data folder is changed.",
                 bg=lw.card_bg, fg=lw.muted, wraplength=680, justify="left",
                 anchor="w").pack(fill="x", pady=(8, 0))''',
    '''        pref = tk.BooleanVar(value=runtime_state_read().get("prefer") ==
                             "managed")

        def set_pref():
            s = runtime_state_read()
            s["prefer"] = "managed" if pref.get() else "auto"
            runtime_state_write(s)
        cb = tk.Checkbutton(
            f, text="Start in the managed Python (used only after its "
                    "window reports back; otherwise the Python you started "
                    "with)", variable=pref, command=set_pref,
            bg=lw.card_bg, fg=lw.fg, selectcolor=lw.card_bg,
            activebackground=lw.card_bg, anchor="w", justify="left",
            wraplength=660)
        cb.pack(fill="x", pady=(8, 0))
        if not runtime_env(runtime_state_read()):
            cb.configure(state="disabled")
        self._rm_pref = pref
        tk.Label(f, text="Repair / Update fixes the private packages folder "
                         "(the capture engine is reinstalled from a "
                         "fingerprinted file) and, if you have a managed "
                         "Python, reinstalls its verified components and "
                         "updates its pip. A newer Python is only installed "
                         "when you ask. Nothing outside MiniWireshark's data "
                         "folder is changed.",
                 bg=lw.card_bg, fg=lw.muted, wraplength=680, justify="left",
                 anchor="w").pack(fill="x", pady=(8, 0))''')

# ---- Diagnostics: startup history -----------------------------------------
rep('''                           (row3, (("Check environment", self.check_env),
                                   ("Runtime Manager…", lambda:
                                    app.open_runtime_manager(self.win)),''',
    '''                           (row3, (("Check environment", self.check_env),
                                   ("Startup history…", lambda:
                                    app.open_boot_history(self.win)),
                                   ("Runtime Manager…", lambda:
                                    app.open_runtime_manager(self.win)),''')
rep('''    def debug_bundle_text(self, masked=True):
        parts = [f"MiniWireshark {SCRIPT_VERSION} debug bundle",
                 time.strftime("%Y-%m-%d %H:%M:%S"), "",
                 "== Diagnostics ==", DiagnosticsWindow.collect(self), "",''',
    '''    def boot_history_text(self, n=10):
        rs = BootReceipt.recent(n=n)
        if not rs:
            return "No startup records yet."
        out = [f"Last {len(rs)} starts, newest first (folder: {BOOT_DIR})",
               ""]
        for r in rs:
            out.append(BootReceipt.summary(r))
            for s in (r.get("steps") or [])[:40]:
                mark = "✔" if s.get("ok") else "✖"
                extra = s.get("error") or s.get("detail") or ""
                out.append(f"      {s.get('at', 0):7.2f}s {mark} "
                           f"{s.get('name')}"
                           + (f" — {extra[:160]}" if extra else ""))
            out.append("")
        return "\\n".join(out)

    def open_boot_history(self, parent=None):
        """Diagnostics → Startup history: what each recent start did."""
        t = self.theme
        win = tk.Toplevel(parent or self.root)
        win.title("Startup history")
        win.geometry("820x560")
        win.configure(bg=t["card_bg"])
        tk.Label(win, text="Each start of MiniWireshark writes what it did "
                           "and how long it took. If starting ever fails, "
                           "this shows where — copy it if you ask for help "
                           "(it contains no network data).",
                 bg=t["card_bg"], fg=t["text_fg"], anchor="w",
                 justify="left", wraplength=780).pack(fill="x", padx=12,
                                                      pady=(10, 4))
        txt = tk.Text(win, wrap="none", bg=t["tab_bg"], fg=t["text_fg"],
                      font=self.mono, relief="flat", padx=8, pady=6)
        txt.pack(fill="both", expand=True, padx=12)
        text = self.boot_history_text()
        txt.insert("1.0", text)
        txt.configure(state="disabled")
        bar = tk.Frame(win, bg=t["card_bg"])
        bar.pack(fill="x", padx=12, pady=8)

        def copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(mask_sensitive(text))
            self._set_banner("📋  Copied to the clipboard.")
        ttk.Button(bar, text="Copy", command=copy).pack(side="left")
        ttk.Button(bar, text="Open folder", command=lambda: _open_path(
            BOOT_DIR)).pack(side="left", padx=6)
        ttk.Button(bar, text="Close", command=win.destroy).pack(
            side="right")
        win._mw_text = text
        return win

    def debug_bundle_text(self, masked=True):
        parts = [f"MiniWireshark {SCRIPT_VERSION} debug bundle",
                 time.strftime("%Y-%m-%d %H:%M:%S"), "",
                 "== Diagnostics ==", DiagnosticsWindow.collect(self), "",
                 "== Startup history ==", self.boot_history_text(5), "",''')

# ---- --boot-check -----------------------------------------------------------
rep('''if __name__ == "__main__":
    if SELF_TEST_MODE:''', '''BOOT_TESTS = ("test_boot_receipts_and_crash_loop",
              "test_v5_handoff_policy_and_handshake",
              "test_private_packages_folder", "test_safe_mode_overrides",
              "t_runtime_state_and_handoff")


def boot_check(out=print):
    """`--boot-check`: what this computer offers MiniWireshark at startup,
    the recent startup records, and the startup tests. Exit code 0 when the
    app can open its window here."""
    setup_logging()
    ok_all = True
    out(f"MiniWireshark {SCRIPT_VERSION} boot check")
    out(f"  Python      {platform.python_version()} ({sys.executable})")
    suitable, why = system_python_suitable()
    out(f"  Suitable    {'yes' if suitable else 'no — ' + why}")
    try:
        r = tk.Tk()
        r.withdraw()
        r.update()
        r.destroy()
        out(f"  Window      ok (Tk {tk.TkVersion})")
    except Exception as e:                           # noqa: BLE001
        ok_all = False
        out(f"  Window      FAILED: {type(e).__name__}: {e}")
    dep = next(d for d in DEPENDENCY_MANIFEST if d["required"])
    ready, info = _required_ready(dep)
    out(f"  scapy       {info if ready else 'missing — ' + info}")
    for d in DEPENDENCY_MANIFEST:
        if not d["required"]:
            out(f"  {d['key']:<11} {_module_version(d['import']) or 'not installed (optional)'}")
    out(f"  Packages    {PKG_DIR}: "
        f"{', '.join(sorted(PRIVATE_PACKAGES.installed())) or 'empty'}")
    out(f"  Driver      {'present' if _npcap_present() else 'Npcap missing'}"
        f" · admin: {'yes' if is_admin() else 'no'}")
    out(f"  Data folder {PATHS.data} "
        f"({'writable' if _dir_writable(PATHS.data) else 'NOT writable'})")
    if not _dir_writable(PATHS.data):
        ok_all = False
    st = RuntimeManager().status()
    env = runtime_env(runtime_state_read()) or {}
    out(f"  Managed     {'installed' if env else 'none'}"
        + (f", window failed: {env.get('handshake_error')}"
           if env.get("handshake_failed") else "")
        + (", chosen" if runtime_state_read().get("prefer") == "managed"
           else ""))
    out("")
    out("Recent starts:")
    for r in BootReceipt.recent(n=5):
        out("  " + BootReceipt.summary(r).replace("\\n", "\\n  "))
    out("")
    out("Startup tests:")
    tmp = tempfile.mkdtemp(prefix="mw_bootcheck_")
    ctx = TestContext(tmp, scapy_ok=ready)
    failed = 0
    for fn, _slow in SELF_TESTS:
        if fn.__name__ not in BOOT_TESTS:
            continue
        t0 = time.perf_counter()
        try:
            fn(ctx)
            out(f"  [PASS] {fn.__name__} "
                f"({(time.perf_counter() - t0) * 1000:.0f} ms)")
        except Exception as e:                       # noqa: BLE001
            failed += 1
            out(f"  [FAIL] {fn.__name__}: {type(e).__name__}: {e}")
    shutil.rmtree(tmp, ignore_errors=True)
    out("")
    out("Result: " + ("ready to start" if ok_all and not failed else
                      "problems found (see above)"))
    return 0 if ok_all and not failed else 1


if __name__ == "__main__":
    if BOOT_CHECK_MODE:
        sys.exit(boot_check())
    if SELF_TEST_MODE:''')
open(P, "w", encoding="utf8").write(src)
print("m1 ui applied")
