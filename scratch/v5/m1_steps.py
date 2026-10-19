def step_runtime(l, state):
    """V5: run on this Python whenever it can run the app. The managed
    Python is never offered as a blocking question at startup; it lives in
    the Runtime Manager (and is used only after its window reports back)."""
    if MW_STAGE == "app":
        mgr = RuntimeManager()
        st = mgr.status()
        if st["running_inside"]:
            l.post_health("healthy" if st["lock_current"] else "repair")
            return True, (f"Running on MiniWireshark's managed Python "
                          f"{platform.python_version()}.")
        return True, "Running on this Python."
    if HANDOFF_NOTE[0]:
        l.post_log("  " + HANDOFF_NOTE[0], "warn")
        l.post_health("degraded")
        return True, (f"Using this Python {platform.python_version()} (the "
                      f"managed Python could not start — details in "
                      f"Diagnostics → Startup history).")
    age, note = python_age()
    if age != "current":
        l.post_log("  " + note, "warn")
    return True, f"Running on this Python {platform.python_version()}."


def _required_ready(dep):
    name = dep["import"]
    if not _module_ok(name):
        return False, "not installed"
    ver = _module_version(name)
    if dep.get("min_version") and _version_tuple(ver) and \
            _version_tuple(ver) < dep["min_version"]:
        return False, f"version {ver} is older than needed"
    return True, ver


CAPTURE_LIMITED = [""]      # why live capture is unavailable (if it is)


def step_dependencies(l, state):
    """The capture engine (scapy) is the only thing needed to capture; it
    is pure Python, so it installs into the private packages folder from a
    fingerprinted file, without pip and without touching this Python.
    Optional packages are only imported if present (Settings → Components
    installs them when you ask)."""
    for dep in DEPENDENCY_MANIFEST:
        if not dep["required"]:
            OPTIONAL_MODULES[dep["key"]] = None
            if not SAFE_MODE and _module_ok(dep["import"]):
                with contextlib.suppress(Exception):
                    OPTIONAL_MODULES[dep["key"]] = importlib.import_module(
                        dep["import"])
            continue
        ok, info = _required_ready(dep)
        if ok:
            l.post_log(f"  {_cap(dep['friendly'])} {info} is ready.", "ok")
            continue
        if state.recent_attempts("pkg:" + dep["key"], 24 * 3600) >= 3:
            CAPTURE_LIMITED[0] = (f"{_cap(dep['friendly'])} is {info}, and "
                                  f"installing it already failed 3 times "
                                  f"today.")
            l.post_log("  " + CAPTURE_LIMITED[0], "warn")
            continue
        state.note_attempt("pkg:" + dep["key"])
        l.post_log(f"  Installing {dep['friendly']} into MiniWireshark's "
                   f"own packages folder (this Python is not changed) …",
                   None)
        version, filename, _sha, size = PURE_WHEELS[dep["key"]]
        l.post_log(f"  {filename} ({size / 1e6:.1f} MB) from "
                   f"files.pythonhosted.org, fingerprint-checked", "detail")

        def prog(stage, frac, text, extra, _l=l):
            speed = extra.get("speed") if extra else None
            _l.post_footer(f"{dep['friendly'].capitalize()}: {text}"
                           + (f" — {speed / 1e6:.1f} MB/s" if speed else ""))
        try:
            PRIVATE_PACKAGES.install_pure(dep["key"], prog,
                                          lambda: l.cancel_requested)
            PRIVATE_PACKAGES.activate()
            importlib.invalidate_caches()
        except Exception as e:                       # noqa: BLE001
            kind = getattr(e, "kind", "") or classify_runtime_error(e)
            CAPTURE_LIMITED[0] = (f"Couldn't install {dep['friendly']} "
                                  f"({kind}: {str(e)[:160]}). Live capture "
                                  f"is off; Demo Mode and opening capture "
                                  f"files still work.")
            l.post_log("  " + CAPTURE_LIMITED[0], "warn")
            boot_step("install " + dep["key"], False, error=e)
            continue
        ok, info = _required_ready(dep)
        if ok:
            l.post_log(f"  {_cap(dep['friendly'])} {info} installed.", "ok")
            boot_step("install " + dep["key"], True, info)
        else:
            CAPTURE_LIMITED[0] = (f"{_cap(dep['friendly'])} was downloaded "
                                  f"but does not load ({info}).")
            l.post_log("  " + CAPTURE_LIMITED[0], "warn")
            boot_step("install " + dep["key"], False, info)
    if CAPTURE_LIMITED[0]:
        l.post_health("degraded")
        return True, "Starting without live capture (see above)."
    return True, ""
