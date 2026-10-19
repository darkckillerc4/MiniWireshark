def _with_runtime_dir(ctx):
    """Point the runtime state at a temp folder for a test."""
    g = globals()
    old = (g["RUNTIME_DIR"], g["RUNTIME_STATE"])
    d = ctx.path(f"rt_{uuid.uuid4().hex[:6]}")
    g["RUNTIME_DIR"], g["RUNTIME_STATE"] = d, os.path.join(d, "state.json")
    return old


def _restore_runtime_dir(old):
    globals()["RUNTIME_DIR"], globals()["RUNTIME_STATE"] = old


@self_test()
def t_runtime_state_and_handoff(ctx):
    old = _with_runtime_dir(ctx)
    try:
        assert runtime_state_read() == {}
        fake = ctx.path("fake_python")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\n")
        prev = ctx.path("prev_python")
        with open(prev, "w") as f:
            f.write("#!/bin/sh\n")
        st = runtime_state_write({"current": "a", "previous": "b", "envs": {
            "a": {"python": fake, "selftest_ok": True},
            "b": {"python": prev, "selftest_ok": True}}})
        assert runtime_state_read()["current"] == "a"
        # tampering invalidates the state
        raw = read_json(RUNTIME_STATE)
        raw["current"] = "b"
        atomic_write_json(RUNTIME_STATE, raw)
        assert runtime_state_read() == {}
        runtime_state_write({k: v for k, v in st.items()
                             if k != "checksum"})
        env = {}
        assert runtime_handoff(["x"], {"MW_STAGE": "app"}, False) is None
        assert runtime_handoff(["--no-runtime"], env, False) is None
        cmd = runtime_handoff(["--demo"], env, False)
        assert cmd == [fake, SCRIPT_PATH, "--demo"], cmd
        assert runtime_state_read()["pending_starts"] == 1
        runtime_handoff([], env, False)            # 2 unconfirmed starts
        cmd = runtime_handoff([], env, False)      # → roll back to "b"
        s2 = runtime_state_read()
        assert cmd[0] == prev and s2["current"] == "b" and \
            s2["rolled_back"]["from"] == "a", (cmd, s2)
        globals()["MW_STAGE"] = "app"
        try:
            assert runtime_confirm_started()
        finally:
            globals()["MW_STAGE"] = ""
        assert runtime_state_read()["pending_starts"] == 0
        os.remove(prev)                            # broken runtime file
        assert runtime_handoff([], env, False) is None
    finally:
        _restore_runtime_dir(old)


@self_test()
def t_runtime_lock_and_platforms(ctx):
    req, pkgs, skipped = lock_requirements("win_amd64")
    names = [p for p, _r in pkgs]
    assert names == ["scapy", "psutil", "cryptography", "cffi",
                     "pycparser"], names
    assert all("--hash=sha256:" in ln for ln in req.strip().splitlines())
    req, pkgs, skipped = lock_requirements("macosx_x86_64")
    assert "cryptography" in skipped and "cffi" in skipped and \
        "pycparser" in skipped and ("scapy", True) in pkgs
    for (sysname, arch), (name, sha) in RUNTIME_SOURCES.items():
        assert re.match(r"^[0-9a-f]{64}$", sha) and RUNTIME_PYTHON in name
        assert RUNTIME_PBS_TAG in name and name.endswith(".tar.gz")
    for spec in RUNTIME_LOCK.values():
        for k, v in spec.items():
            if k.startswith(("win_", "macosx_", "linux_")):
                assert re.match(r"^[0-9a-f]{64}$", v), (k, v)
    deps = {d["key"] for d in DEPENDENCY_MANIFEST}
    assert deps <= set(RUNTIME_LOCK), "manifest and lock disagree"
    assert wheel_platform_tag(("windows", "x86_64")) == "win_amd64"
    assert wheel_platform_tag(("linux", "aarch64")) == "linux_aarch64"
    assert len(lock_fingerprint()) == 16


@self_test()
def t_runtime_download_extract_errors(ctx):
    import http.server
    import tarfile
    payload = os.urandom(300_000)
    srv_dir = ctx.path("srv")
    os.makedirs(srv_dir, exist_ok=True)
    with open(os.path.join(srv_dir, "blob.bin"), "wb") as f:
        f.write(payload)

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=srv_dir, **k)

        def log_message(self, *a):
            pass
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        mgr = RuntimeManager(ctx.path("rtm"))
        sha = hashlib.sha256(payload).hexdigest()
        dest = os.path.join(mgr.cache, "blob.bin")
        os.makedirs(mgr.cache, exist_ok=True)
        with open(dest + ".part", "wb") as f:      # resume from 100 kB
            f.write(payload[:100_000])
        seen = []
        url = f"http://127.0.0.1:{port}/blob.bin"
        mgr.download(url, dest, sha, lambda *a: seen.append(a[0]))
        assert sha256_file(dest) == sha and "Verify" in seen
        os.remove(dest)
        try:
            mgr.download(url, dest, "0" * 64)
            raise AssertionError("bad fingerprint accepted")
        except RuntimeError_ as e:
            assert e.kind == "fingerprint"
        assert not os.path.exists(dest) and not os.path.exists(
            dest + ".part")
        try:
            mgr.download(url, dest, sha, cancel=lambda: True)
            raise AssertionError("cancel ignored")
        except RuntimeError_ as e:
            assert e.kind == "cancelled"
    finally:
        httpd.shutdown()
    evil = ctx.path("evil.tar.gz")
    with tarfile.open(evil, "w:gz") as tf:
        info = tarfile.TarInfo("../escape.txt")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"hi"))
    try:
        RuntimeManager.safe_extract(evil, ctx.path("x"))
        raise AssertionError("path traversal accepted")
    except RuntimeError_:
        pass
    assert not os.path.exists(ctx.path("escape.txt"))
    assert classify_runtime_error(PermissionError("x")) == "permission"
    assert classify_runtime_error(OSError("[Errno 28] No space left")) == \
        "disk"
    assert classify_runtime_error(urllib.error.URLError("getaddrinfo")) == \
        "offline"
    assert classify_runtime_error(OSError("SSL: CERTIFICATE_VERIFY_FAILED")
                                  ) == "proxy"
    assert set(RUNTIME_ERRORS) >= {"offline", "proxy", "fingerprint",
                                   "disk", "permission", "quarantine", "tk",
                                   "signature", "selftest"}


@self_test()
def t_mask_sensitive(ctx):
    s = ("dev 192.168.1.23 mac da:a1:19:23:45:67 v6 2a01:e0a:1f:2c0::23 "
         "gw 10.0.0.1")
    m = mask_sensitive(s)
    assert "192.168.1.23" not in m and "da:a1:19:23:45:67" not in m
    assert "2a01:e0a:1f:2c0::23" not in m and "10.0.0.1" not in m
    assert "192.168.x.x" in m and "da:a1:xx" in m


@self_test()
def t_least_privilege(ctx):
    src = inspect.getsource(needs_elevation)
    assert "_npcap_admin_only" in src
    if not IS_WINDOWS and not is_admin():
        assert needs_elevation()

