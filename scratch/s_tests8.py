@self_test()
def t_python_age(ctx):
    a, note = python_age((3, 9), today="2026-10")
    assert a == "outdated" and "stopped receiving security fixes" in note
    a, note = python_age((3, 10), today="2026-10")
    assert a == "outdated", note                 # ends this month
    a, note = python_age((3, 11), today="2026-10")
    assert a == "ageing" and "2027-10" in note
    assert python_age((3, 14), today="2026-10")[0] == "current"
    assert python_age((3, 16), today="2026-10")[0] == "current"
    assert python_age((3, 6), today="2026-10")[0] == "outdated"


@self_test()
def t_component_rows(ctx):
    lock = {"scapy": {"version": "2.8.0", "required": True},
            "psutil": {"version": "7.2.2", "required": False},
            "cryptography": {"version": "50.0.2", "required": False},
            "cffi": {"version": "2.1.1", "required": False,
                     "needed_by": "cryptography"}}
    info = {"python": "3.14.2", "tk": "9.0", "pip": "25.3", "packages": {
        "scapy": {"version": "2.8.0", "import": True},
        "psutil": {"version": "", "import": False},
        "cryptography": {"version": "41.0.7", "import": True},
        "cffi": {"version": "", "import": False}}}
    rows = {r[0]: r for r in RuntimeManager.component_rows(info, lock)}
    assert rows["scapy"][4] == "ok" and "verified" in rows["scapy"][3]
    assert rows["psutil"][4] == "warn" and "optional" in rows["psutil"][3]
    assert rows["cryptography"][4] == "warn" and "50.0.2" in \
        rows["cryptography"][3]
    assert rows["cffi"][4] == "ok" and "helper" in rows["cffi"][3]
    info["packages"]["scapy"] = {"version": "2.8.0", "import": False,
                                 "error": "ImportError: libpcap"}
    rows = {r[0]: r for r in RuntimeManager.component_rows(info, lock)}
    assert rows["scapy"][4] == "bad" and "won't load" in rows["scapy"][3]
    info["packages"]["scapy"] = {"version": "", "import": False}
    rows = {r[0]: r for r in RuntimeManager.component_rows(info, lock)}
    assert rows["scapy"][4] == "bad" and "needed" in rows["scapy"][3]
    info["packages"]["scapy"] = {"version": "2.8.0", "import": True}
    rows = {r[0]: r for r in RuntimeManager.component_rows(
        info, lock, pip_problems=["scapy 2.8.0 requires foo, which is not "
                                  "installed."])}
    assert rows["scapy"][4] == "bad" and "Conflict" in rows["scapy"][3]
    info["tk"] = ""
    rows = {r[0]: r for r in RuntimeManager.component_rows(info, lock)}
    assert rows["Graphical toolkit (Tk)"][4] == "bad"
    rows = RuntimeManager.component_rows({"error": "boom", "packages": {}})
    assert rows[0][4] == "bad" and "boom" in rows[0][3]


@self_test(slow=True)
def t_environment_diagnose(ctx):
    """The real component check on the Python running the self-test."""
    mgr = RuntimeManager(root_dir=ctx.path("rtdiag"))
    rep = mgr.diagnose(sys.executable)
    names = [r[0] for r in rep["rows"]]
    assert names[:3] == ["Python", "Graphical toolkit (Tk)", "pip"], names
    assert set(RUNTIME_LOCK) <= set(names)
    sc = next(r for r in rep["rows"] if r[0] == "scapy")
    assert sc[1] and sc[4] != "bad", sc        # the self-test needs scapy
    assert "pip check" in rep["text"] or rep["pip_problems"]
    assert rep["info"]["python"] == platform.python_version()
    try:
        mgr.update_pip(sys.executable)
        raise AssertionError("system pip must never be updated")
    except RuntimeError_:
        pass
    return rep["worst"]


@self_test()
def t_newer_python_source(ctx):
    mgr = RuntimeManager(root_dir=ctx.path("rtnew"))
    plat = runtime_platform()
    if plat not in RUNTIME_SOURCES:
        return "skip"
    suffix = RUNTIME_SOURCES[plat][0].split("-", 2)[2]
    sha = "ab" * 32

    def rel(*assets):
        return {"tag_name": "20261013", "assets": list(assets)}

    def asset(ver, suf=suffix, digest="sha256:" + sha, tag="20261013"):
        n = f"cpython-{ver}+{tag}-{suf}"
        return {"name": n, "digest": digest,
                "browser_download_url": "https://github.com/x/" + n}
    got = mgr.newer_python_source(release=rel(
        asset("3.14.1"), asset("3.14.4"), asset("3.14.3"),
        asset("3.15.0"), asset("3.14.9", suf="other-target.tar.gz")))
    assert got and got["version"] == "3.14.4" and got["sha"] == sha, got
    assert got["name"].endswith(suffix) and got["url"].endswith(got["name"])
    # no published checksum → never offered
    assert mgr.newer_python_source(release=rel(asset("3.14.4",
                                                     digest=""))) is None
    assert mgr.newer_python_source(release=rel(asset(
        "3.14.4", digest="sha256:nothex"))) is None
    # nothing newer than the verified one
    assert mgr.newer_python_source(release=rel(asset(RUNTIME_PYTHON),
                                               asset("3.14.1"))) is None
    # a newer minor (3.15) is not offered as a drop-in replacement
    assert mgr.newer_python_source(release=rel(asset("3.15.1"))) is None
