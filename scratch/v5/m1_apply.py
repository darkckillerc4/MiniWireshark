import re
P = "/home/claude/mw/miniwireshark.py"
S = "/home/claude/mw/scratch/v5/"
src = open(P, encoding="utf8").read()


def rep(old, new, cnt=1):
    global src
    n = src.count(old)
    assert n == cnt, (old[:80], n)
    src = src.replace(old, new)


def cut(start, end_marker):
    """Remove from `start` (inclusive) up to `end_marker` (exclusive)."""
    global src
    a = src.index(start)
    b = src.index(end_marker, a)
    src = src[:a] + src[b:]


# --- 1. remove V4 runtime_handoff; insert boot block + new hand-off -------
cut("def runtime_handoff(argv=None, environ=None, execute=True):\n",
    "def runtime_confirm_started():")
boot = open(S + "m1_boot.py", encoding="utf8").read()
handoff = open(S + "m1_handoff.py", encoding="utf8").read()
rep("""def needs_elevation():
    \"\"\"Least privilege""", boot.lstrip("\n") + "\n\n" + handoff + "\n\n" +
    """def needs_elevation():
    \"\"\"Least privilege""")

# --- 2. runtime_healthy ignores a runtime whose window never came up ------
rep("""    exe = env.get("python", "")
    return bool(exe and os.path.isfile(exe) and env.get("selftest_ok"))""",
    """    exe = env.get("python", "")
    return bool(exe and os.path.isfile(exe) and env.get("selftest_ok")
                and not env.get("handshake_failed"))""")

# --- 3. elevation keeps the hand-off arguments --------------------------
rep("""    extra = [a for a in sys.argv[1:] if a != ELEVATED_FLAG]""",
    """    extra = [a for a in sys.argv[1:] if a != ELEVATED_FLAG] + \\
        list(_HANDOFF_ARGS) + ([SAFE_FLAG] if SAFE_MODE else [])""")
rep('''                  "MINIWIRESHARK_DATA", "MINIWIRESHARK_CONFIG", "MW_STAGE",
                  "MINIWIRESHARK_NO_RUNTIME")''', '''                  "MINIWIRESHARK_DATA", "MINIWIRESHARK_CONFIG", "MW_STAGE",
                  "MINIWIRESHARK_NO_RUNTIME", "MW_READY_FILE")''')

# --- 4. import-time start: receipt, Safe Mode, hand-off, elevation -------
rep('''TOOL_MODE = SELF_TEST_MODE or GUI_TEST_MODE or BENCH_MODE or RELEASE_MODE''',
    '''BOOT_CHECK_MODE = BOOT_CHECK_FLAG in sys.argv
TOOL_MODE = SELF_TEST_MODE or GUI_TEST_MODE or BENCH_MODE or \\
    RELEASE_MODE or BOOT_CHECK_MODE''')
rep('''if __name__ == "__main__" and not TOOL_MODE and not _ELEV:
    runtime_handoff()          # re-launches in the private Python if healthy
''', '''if __name__ == "__main__" and not TOOL_MODE:
    BOOT = BootReceipt()
    if not SAFE_MODE and crash_loop_detected(BootReceipt.recent(),
                                             BOOT.path):
        SAFE_MODE = True
        SAFE_REASON[0] = ("The last two starts didn't reach the main "
                          "window, so this start uses Safe Mode.")
    BOOT.mark(safe_mode=SAFE_MODE)
    boot_step("launch", True, f"Python {platform.python_version()} "
                              f"({'app' if MW_STAGE else 'launcher'})")

if __name__ == "__main__" and not TOOL_MODE and not _ELEV:
    runtime_handoff()          # managed Python only when chosen or needed
''')
rep('''        NO_ELEVATE_FLAG not in sys.argv and needs_elevation():
    if _relaunch_elevated():''', '''        NO_ELEVATE_FLAG not in sys.argv and needs_elevation():
    if BOOT is not None:
        BOOT.mark(outcome="elevated")
    if _relaunch_elevated():''')
rep('''        "The program will now close.")
    sys.exit(1)''', '''        "The program will now close.")
    if BOOT is not None:
        BOOT.mark(outcome="fatal")
        boot_step("elevation", False, "administrator rights refused")
    sys.exit(1)''')

# --- 5. pip into the system is gone; private packages instead -----------
a = src.index("PIP_ASK = [None]     # callable() -> bool: may we use")
b = src.index("def _scapy_version():")
src = src[:a] + open(S + "m1_pkgs.py", encoding="utf8").read() + \
    "\n\n" + src[b:]
rep('''    "release": "Release tooling (developers only)",''',
    '''    "release": "Release tooling (developers only)",
    "packages": "Components and packages (downloads you approved)",''')

# --- 6. bootstrap steps --------------------------------------------------
a = src.index("def step_pip(l, state):")
b = src.index("def _cap(text):")
src = src[:a] + src[b:]
STEPS = open(S + "m1_steps.py", encoding="utf8").read()
STEP_RUNTIME, REST = STEPS.split("def _required_ready", 1)
REST = "def _required_ready" + REST
a = src.index("def _ensure_dependency(l, state, dep):")
b = src.index("def step_npcap(l, state):")
src = src[:a] + REST + "\n\n" + src[b:]
a = src.index("def step_runtime(l, state):\n    \"\"\"The private Python: use")
b = src.index("def _find_local_python314():")
src = src[:a] + STEP_RUNTIME.rstrip() + "\n\n\n" + src[b:]
rep('''    ("Checking for MiniWireshark's private Python", step_runtime, 2),
    ("Checking Python", step_python, 1),
    ("Checking the graphical toolkit", step_tkinter, 1),
    ("Checking the package installer", step_pip, 1),
    ("Preparing the packet capture engine", step_dependencies, 8),''',
    '''    ("Checking Python", step_python, 1),
    ("Checking which Python to use", step_runtime, 1),
    ("Checking the graphical toolkit", step_tkinter, 1),
    ("Preparing the packet capture engine", step_dependencies, 8),''')
rep('''            try:
                ok, msg = fn(loader, state)
            except Exception as e:                   # noqa: BLE001
                LOG.exception("bootstrap step %s", title)
                ok, msg = False, f"{type(e).__name__}: {e}"''',
    '''            try:
                ok, msg = fn(loader, state)
                boot_step(title, ok, msg)
            except Exception as e:                   # noqa: BLE001
                LOG.exception("bootstrap step %s", title)
                ok, msg = False, f"{type(e).__name__}: {e}"
                boot_step(title, False, error=e)''')
rep('''                            f"works, but the private Python "
                            f"{RUNTIME_PYTHON} is recommended.")''',
    '''                            f"works; Settings → Diagnostics → Runtime "
                            f"Manager can add a managed Python "
                            f"{RUNTIME_PYTHON} if you want one.")''')
rep('''        return "ageing", (f"You're running {name} (security fixes until "
                          f"{eol}). The private Python {RUNTIME_PYTHON} is "
                          f"faster and is what MiniWireshark is tested on.")''',
    '''        return "ageing", (f"You're running {name} (security fixes until "
                          f"{eol}). It works fine; a managed Python "
                          f"{RUNTIME_PYTHON} is available in the Runtime "
                          f"Manager if you want one.")''')

# --- 7. loader: the system-pip question is gone --------------------------
a = src.index('''        elif kind == "pip_system":''')
b = src.index('''        else:
            f = self._card_frame(kw.get("title", "Question"),''')
src = src[:a] + src[b:]

# --- 8. AppConfig runtime overrides (Safe Mode) ---------------------------
rep('''    def get(self, dotted, default=None):
        section, _, key = dotted.partition(".")
        return self.data.get(section, {}).get(key, default)''',
    '''    def get(self, dotted, default=None):
        ov = getattr(self, "overrides", None)
        if ov and dotted in ov:
            return ov[dotted]
        section, _, key = dotted.partition(".")
        return self.data.get(section, {}).get(key, default)''')
rep('''    def set(self, dotted, value):
        section, _, key = dotted.partition(".")
        self.data.setdefault(section, {})[key] = value''',
    '''    def set(self, dotted, value):
        ov = getattr(self, "overrides", None)
        if ov:
            ov.pop(dotted, None)          # an explicit change wins
        section, _, key = dotted.partition(".")
        self.data.setdefault(section, {})[key] = value''')

# --- 9. main(): receipts, ready signal, limited mode, notices -------------
rep('''    if MW_STAGE == "app":
        RuntimeManager().apply_pending_switch()
    cfg = AppConfig()''', '''    if MW_STAGE == "app":
        RuntimeManager().apply_pending_switch()
    cfg = AppConfig()
    if SAFE_MODE:
        cfg.overrides = dict(SAFE_MODE_OVERRIDES)
        LOG.warning("Safe Mode: %s", SAFE_REASON[0])''')
rep('''    root.configure(background=loader.bg)
    root.update()
    PIP_ASK[0] = lambda: loader.ask("pip_system") == "yes"

    ok, err = run_bootstrap(loader)
    PIP_ASK[0] = None
    if not ok:
        loader.show_fatal(err)
        root.mainloop()
        return''', '''    root.configure(background=loader.bg)
    root.update()
    boot_step("window", True, f"Tk {tk.TkVersion}")
    if BOOT is not None:
        BOOT.mark(reached_window=True)
    signal_ready()

    ok, err = run_bootstrap(loader)
    if not ok:
        if BOOT is not None:
            BOOT.mark(outcome="fatal")
        loader.show_fatal(err)
        root.mainloop()
        return''')
rep('''    try:
        load_scapy()
    except Exception as e:                           # noqa: BLE001
        LOG.exception("scapy import")
        loader.show_fatal(f"Could not load the capture engine (scapy): {e}\\n\\n"
                          f"{traceback.format_exc()}")
        root.mainloop()
        return''', '''    if not CAPTURE_LIMITED[0]:
        try:
            if os.environ.get("MW_FAKE_NO_SCAPY"):
                raise ImportError("scapy disabled for a test")
            load_scapy()
            boot_step("capture engine", True, _scapy_version() or "")
        except Exception as e:                       # noqa: BLE001
            LOG.exception("scapy import")
            CAPTURE_LIMITED[0] = (f"The capture engine (scapy) didn't load "
                                  f"({type(e).__name__}: {str(e)[:160]}). "
                                  f"Live capture is off; Demo Mode and "
                                  f"opening capture files still work. "
                                  f"Settings → Repair can fix it.")
            boot_step("capture engine", False, error=e)''')
rep('''    elif cfg.get("general.show_welcome", True) or first_time:
        health = "healthy"
        st = RuntimeManager().status()
        if not st["running_inside"] and RuntimeManager().plan()[
                "supported"] and NO_RUNTIME_FLAG not in sys.argv:
            health = "degraded"
        summary = welcome_summary(cfg)
        action = loader.show_welcome(summary, health, first_time)
        if action == "exit":
            with contextlib.suppress(tk.TclError):
                root.destroy()
            return''', '''    elif cfg.get("general.show_welcome", True) or first_time or \\
            startup_notice():
        health = "healthy"
        if CAPTURE_LIMITED[0] or HANDOFF_NOTE[0] or SAFE_MODE:
            health = "degraded"
        summary = welcome_summary(cfg)
        action = loader.show_welcome(summary, health, first_time,
                                     notice=startup_notice())
        if action == "exit":
            if BOOT is not None:
                BOOT.mark(outcome="user_exit")
            with contextlib.suppress(tk.TclError):
                root.destroy()
            return''')
rep('''        MiniWireshark(root, gw, my_ips, my_macs, default_iface_name,
                      config=cfg, start_action=action)
    except Exception:                                # noqa: BLE001
        text = traceback.format_exc()
        LOG.error("startup error:\\n%s", text)''', '''        MiniWireshark(root, gw, my_ips, my_macs, default_iface_name,
                      config=cfg, start_action=action)
        boot_step("main window", True, f"{time.perf_counter() - _T_START:.2f}"
                                       f" s after launch")
        if BOOT is not None:
            BOOT.mark(reached_main_window=True)
    except Exception as e:                           # noqa: BLE001
        text = traceback.format_exc()
        LOG.error("startup error:\\n%s", text)
        boot_step("main window", False, error=e)
        if BOOT is not None:
            BOOT.mark(outcome="fatal")''')
rep('''    root.mainloop()
    LOG.info("MiniWireshark closed")''', '''    root.mainloop()
    if BOOT is not None:
        BOOT.mark(outcome="closed")
    LOG.info("MiniWireshark closed")''')
rep('''    except Exception:                                # noqa: BLE001
        LOG.exception("fatal error")
        _fatal_dialog("MiniWireshark stopped unexpectedly",''',
    '''    except Exception as e:                           # noqa: BLE001
        LOG.exception("fatal error")
        boot_step("crash", False, error=e)
        if BOOT is not None:
            BOOT.mark(outcome="crashed")
        _fatal_dialog("MiniWireshark stopped unexpectedly",''')
rep('''def welcome_summary(cfg):''', '''SAFE_MODE_OVERRIDES = {
    "general.auto_start_capture": False,
    "history.enabled": False,
    "connectors.list": [],
    "updates.check_automatically": False,
    "privacy.auto_download_reference": False,
}


def startup_notice():
    """Plain words for anything unusual about this start (or "")."""
    parts = []
    if SAFE_MODE:
        parts.append("🛟 Safe Mode — " + (SAFE_REASON[0] or "") +
                     " Automatic capture, history, helpers and downloads "
                     "are off for this session. Repair checks the usual "
                     "causes.")
    if HANDOFF_NOTE[0]:
        parts.append("⚠ " + HANDOFF_NOTE[0])
    if CAPTURE_LIMITED[0]:
        parts.append("⚠ " + CAPTURE_LIMITED[0])
    return "\\n".join(parts)


def welcome_summary(cfg):''')
rep('''    st = RuntimeManager().status()
    if st["running_inside"]:
        parts.append(f"Private Python {platform.python_version()}")
    else:
        parts.append(f"Python {platform.python_version()}")''',
    '''    st = RuntimeManager().status()
    if st["running_inside"]:
        parts.append(f"Managed Python {platform.python_version()}")
    else:
        parts.append(f"Python {platform.python_version()}")
    pk = PRIVATE_PACKAGES.installed()
    if pk:
        parts.append(f"{len(pk)} private package"
                     f"{'s' if len(pk) != 1 else ''}")''')
open(P, "w", encoding="utf8").write(src)
print("m1 applied")

# --- 10. Welcome Center shows why this start is unusual -------------------
src = open(P, encoding="utf8").read()
rep('''    def show_welcome(self, summary="", health="healthy", first_time=False):''',
    '''    def show_welcome(self, summary="", health="healthy", first_time=False,
                     notice=""):''')
rep('''        top = tk.Frame(self.card, bg=self.bg)
        top.pack(fill="both", expand=True)
        tiles = tk.Frame(top, bg=self.bg)''', '''        top = tk.Frame(self.card, bg=self.bg)
        top.pack(fill="both", expand=True)
        if notice:
            self.notice_lbl = tk.Label(
                top, text=notice, bg=self.card_bg, fg=self.warn,
                anchor="w", justify="left", wraplength=680, padx=10, pady=8,
                highlightthickness=1, highlightbackground=self.warn)
            self.notice_lbl.pack(fill="x", pady=(0, 8))
        tiles = tk.Frame(top, bg=self.bg)''')
open(P, "w", encoding="utf8").write(src)
print("m1 welcome applied")
