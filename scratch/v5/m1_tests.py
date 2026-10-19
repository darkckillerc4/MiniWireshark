@self_test(slow=False)
def test_boot_receipts_and_crash_loop(ctx):
    """V5 startup: every start leaves a receipt; two failed starts in a row
    turn on Safe Mode; a closed Welcome Center or a hand-off is no
    failure; receipts are pruned to the newest ten."""
    d = ctx.path("boot")
    r = BootReceipt(directory=d, argv=["--demo", READY_ARG + "x"])
    r.step("window", True, "Tk 8.6")
    r.step("capture engine", False, error=ImportError("no scapy"))
    data = read_json(r.path)
    assert data["argv"] == ["--demo"], data["argv"]
    assert data["steps"][1]["error"].startswith("ImportError"), data
    assert "failed at: capture engine" in BootReceipt.summary(data)
    r.mark(outcome="closed", reached_main_window=True)
    assert read_json(r.path)["outcome"] == "closed"

    def fake(name, outcome, main=False, pid=999999999, age=0):
        p = os.path.join(d, f"boot-{name}.json")
        atomic_write_json(p, {"kind": "start", "outcome": outcome,
                              "reached_main_window": main, "pid": pid,
                              "steps": [{"name": "window", "ok": True}],
                              "started": time.time() - age})
        t = time.time() - age
        os.utime(p, (t, t))
        return p
    shutil.rmtree(d)
    fake("a", "closed", True, age=30)
    fake("b", "crashed", age=20)
    cur = fake("c", "running", pid=os.getpid(), age=0)
    assert not crash_loop_detected(BootReceipt.recent(d), cur)
    fake("d", "running", age=10)               # died without a word
    assert crash_loop_detected(BootReceipt.recent(d), cur)
    fake("e", "user_exit", age=5)              # closed the Welcome Center
    assert not crash_loop_detected(BootReceipt.recent(d), cur)
    fake("f", "running", pid=os.getpid(), age=4)   # still running here
    fake("g", "fatal", age=3)
    assert not crash_loop_detected(BootReceipt.recent(d), cur)
    for i in range(14):
        fake(f"z{i:02d}", "closed", True, age=100 + i)
    BootReceipt(directory=d).prune()
    assert len(BootReceipt.files(d)) == BootReceipt.KEEP


@self_test(slow=False)
def test_v5_handoff_policy_and_handshake(ctx):
    """The managed Python is used only when chosen or needed, and only
    after its window reports back; a child that crashes or hangs is
    stopped, remembered, and this Python carries on."""
    assert system_python_suitable((3, 7), True)[0] is False
    assert system_python_suitable((3, 12), False) == \
        (False, "this Python has no graphical toolkit (Tk)")
    assert system_python_suitable((3, 12), True) == (True, "")
    # handshake outcomes, with real child processes
    rf = ctx.path("ready-ok")
    p = subprocess.Popen([sys.executable, "-c",
                          f"import time; time.sleep(0.2); "
                          f"open({rf!r}, 'w').write('READY'); "
                          f"time.sleep(0.5)"])
    assert wait_for_handshake(p, rf, timeout=10)[0] == "ready"
    p.wait(5)
    p = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert wait_for_handshake(p, ctx.path("never"), timeout=10) == \
        ("exited", 3)
    p = subprocess.Popen([sys.executable, "-c", "import time; "
                                               "time.sleep(30)"])
    t0 = time.monotonic()
    res = wait_for_handshake(p, ctx.path("never2"), timeout=0.6)
    assert res == ("timeout", None) and time.monotonic() - t0 < 5, res
    p.kill()
    p.wait(5)
    # a child that exits 0 (handed to an elevated copy) gets more time
    rf2 = ctx.path("ready-late")
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    threading.Timer(0.8, lambda: open(rf2, "w").write("READY")).start()
    assert wait_for_handshake(p, rf2, timeout=0.3,
                              elevation_timeout=10)[0] == "ready"
    # the whole hand-off with a fake managed Python that crashes
    old = _with_runtime_dir(ctx)
    old_boot = globals()["BOOT_DIR"]
    globals()["BOOT_DIR"] = ctx.path("bootdir")
    try:
        crash = ctx.path("crash_python.py")
        with open(crash, "w") as f:
            f.write("import sys; print('boom: no Tk here'); sys.exit(5)\n")
        launcher = ctx.path("fake_python")
        if IS_WINDOWS:
            launcher = sys.executable
        else:
            with open(launcher, "w") as f:
                f.write(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                        f"{shlex.quote(crash)}\n")
            os.chmod(launcher, 0o755)
        runtime_state_write({"current": "a", "prefer": "managed", "envs": {
            "a": {"python": launcher, "selftest_ok": True,
                  "version": "3.14.2"}}})
        HANDOFF_NOTE[0] = ""
        if not IS_WINDOWS:
            assert runtime_handoff([], {}, True, suitable=(True, ""),
                                   timeout=10) is None
            st = runtime_state_read()
            assert st["envs"]["a"].get("handshake_failed"), st
            assert "stopped with code 5" in HANDOFF_NOTE[0], HANDOFF_NOTE
            assert not runtime_healthy(runtime_env(st))
            # remembered: the next start does not try again
            assert runtime_handoff([], {}, False, suitable=(True, "")) \
                is None
        # policy: a healthy managed Python is skipped when this Python
        # works and you did not choose it
        runtime_state_write({"current": "b", "envs": {
            "b": {"python": launcher, "selftest_ok": True}}})
        assert runtime_handoff([], {}, False, suitable=(True, "")) is None
        assert runtime_handoff(["--x"], {}, False,
                               suitable=(False, "no Tk"))[:2] == \
            [launcher, SCRIPT_PATH]
    finally:
        HANDOFF_NOTE[0] = ""
        globals()["BOOT_DIR"] = old_boot
        _restore_runtime_dir(old)


def _fake_wheel(path, name, version, files):
    import zipfile
    with zipfile.ZipFile(path, "w") as zf:
        for rel, body in files.items():
            zf.writestr(rel, body)
        zf.writestr(f"{name}-{version}.dist-info/METADATA",
                    f"Name: {name}\nVersion: {version}\n")
        zf.writestr(f"{name}-{version}.dist-info/RECORD", "")
    return path


@self_test(slow=False)
def test_private_packages_folder(ctx):
    """Packages go into MiniWireshark's own folder: swapped in atomically,
    importable, removable, and never through the system Python's pip."""
    root = ctx.path("site")
    pp = PrivatePackages(root=root, cache=ctx.path("wheels"))
    w1 = _fake_wheel(ctx.path("mwfakepkg-1.0-py3-none-any.whl"),
                     "mwfakepkg", "1.0",
                     {"mwfakepkg/__init__.py": "VERSION = '1.0'\n"})
    assert pp.install_wheel_file(w1) == ("mwfakepkg", "1.0")
    assert pp.activate() and root in sys.path
    try:
        import mwfakepkg                               # noqa: F401
        assert sys.modules["mwfakepkg"].VERSION == "1.0"
        w2 = _fake_wheel(ctx.path("mwfakepkg-2.0-py3-none-any.whl"),
                         "mwfakepkg", "2.0",
                         {"mwfakepkg/__init__.py": "VERSION = '2.0'\n",
                          "mwfakepkg/extra.py": "X = 1\n"})
        pp.install_wheel_file(w2)
        assert pp.installed()["mwfakepkg"]["version"] == "2.0"
        assert sorted(pp.installed()["mwfakepkg"]["entries"]) == \
            ["mwfakepkg", "mwfakepkg-2.0.dist-info"]
        assert not os.path.exists(os.path.join(
            root, "mwfakepkg-1.0.dist-info")), os.listdir(root)
        assert pp.verify() == []
        shutil.rmtree(os.path.join(root, "mwfakepkg"))
        assert pp.verify() == ["mwfakepkg"]
        assert pp.remove("mwfakepkg") and pp.installed() == {}
        bad = _fake_wheel(ctx.path("evil-1.0-py3-none-any.whl"), "evil",
                          "1.0", {"../escape.py": "x = 1\n"})
        try:
            pp.install_wheel_file(bad)
            raise AssertionError("unsafe wheel accepted")
        except RuntimeError_:
            pass
        assert not os.path.exists(ctx.path("escape.py"))
        assert not [n for n in os.listdir(root) if n.startswith(".")]
    finally:
        sys.modules.pop("mwfakepkg", None)
        with contextlib.suppress(ValueError):
            sys.path.remove(root)
    # the pip command: own folder only, binary wheels, never --user
    cmd = pp.pip_command(["psutil==7.2.2"], ctx.path("stage"))
    joined = " ".join(cmd)
    assert "--target" in cmd and "--only-binary=:all:" in cmd, cmd
    assert "--user" not in cmd and "break-system" not in joined, cmd
    src = inspect.getsource(PrivatePackages) + \
        inspect.getsource(step_dependencies)
    assert "break-system" not in src and '"--user"' not in src
    assert pypi_file_url("scapy-2.8.0-py3-none-any.whl") == (
        "https://files.pythonhosted.org/packages/py3/s/scapy/"
        "scapy-2.8.0-py3-none-any.whl")
    assert abi_tag((3, 12), "win-amd64") == "cp312-win_amd64"
    assert abi_tag((3, 9), "macosx-11.0-arm64") == "cp39-macosx_11_0_arm64"
    assert optional_version("cryptography", (3, 8)) == "46.0.3"
    assert optional_version("cryptography", (3, 13)) == "50.0.2"
    # a fingerprint mismatch never leaves a file behind
    srcf = ctx.path("blob.bin")
    with open(srcf, "wb") as f:
        f.write(b"x" * 1000)
    try:
        fetch_to_file("file://" + urllib.request.pathname2url(srcf),
                      ctx.path("dl/blob.bin"), "0" * 64, "packages")
        raise AssertionError("bad fingerprint accepted")
    except RuntimeError_ as e:
        assert e.kind == "fingerprint", e.kind
    assert not os.path.exists(ctx.path("dl/blob.bin"))
    ok = fetch_to_file("file://" + urllib.request.pathname2url(srcf),
                       ctx.path("dl/blob2.bin"), sha256_file(srcf),
                       "packages")
    assert os.path.getsize(ok) == 1000
    try:
        fetch_to_file("file://" + urllib.request.pathname2url(srcf),
                      ctx.path("dl/blob3.bin"), None, "packages",
                      max_bytes=100)
        raise AssertionError("size cap ignored")
    except RuntimeError_:
        pass


@self_test(slow=False)
def test_safe_mode_overrides(ctx):
    """Safe Mode switches risky things off for one session without
    changing your saved settings; anything you change explicitly wins."""
    c = ctx.cfg({"general.auto_start_capture": True,
                 "history.enabled": True})
    c.overrides = dict(SAFE_MODE_OVERRIDES)
    assert c.get("general.auto_start_capture") is False
    assert c.get("history.enabled") is False
    assert c.data["general"]["auto_start_capture"] is True   # unchanged
    c.set("history.enabled", True)
    assert c.get("history.enabled") is True
    old = (SAFE_MODE, HANDOFF_NOTE[0], CAPTURE_LIMITED[0])
    try:
        globals()["SAFE_MODE"] = True
        SAFE_REASON[0] = "test"
        CAPTURE_LIMITED[0] = "no scapy"
        n = startup_notice()
        assert "Safe Mode" in n and "no scapy" in n, n
    finally:
        globals()["SAFE_MODE"] = old[0]
        HANDOFF_NOTE[0], CAPTURE_LIMITED[0] = old[1], old[2]
        SAFE_REASON[0] = ""


