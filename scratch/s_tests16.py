@self_test()
def t_ed25519_rfc8032(ctx):
    """RFC 8032 §7.1 test vectors 1 and 2, pure Python and library."""
    for sk, msg, pk, sig in (
            ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
             b"", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
             "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
             b"\x72",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
             "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")):
        sk, pk, sig = bytes.fromhex(sk), bytes.fromhex(pk), bytes.fromhex(sig)
        assert ed25519_public_key(sk) == pk
        assert ed25519_sign(sk, msg) == sig
        assert _ed25519_verify_py(pk, msg, sig) and ed25519_verify(pk, msg,
                                                                  sig)
        bad = sig[:10] + bytes([sig[10] ^ 1]) + sig[11:]
        assert not _ed25519_verify_py(pk, msg, bad)
        assert not ed25519_verify(pk, msg + b"x", sig)


@self_test()
def t_signed_updates_and_packs(ctx):
    k_old, k_new, k_evil = os.urandom(32), os.urandom(32), os.urandom(32)
    trusted = {"new": ed25519_public_key(k_new).hex()}
    script = ("# MiniWireshark\nSCRIPT_VERSION = \"9.9.9\"\n"
              "def main():\n    pass\n" + "#" * 60000).encode()
    man = make_release_manifest(script, "9.9.9", {"old": k_old,
                                                  "new": k_new})
    # key rotation: signed by old + new, only the new one is trusted
    assert check_release(man, script, "4.0.0", trusted)["version"] == "9.9.9"

    def refused(fn, word):
        try:
            fn()
        except UpdateRefused as e:
            assert word in str(e), (word, str(e))
            return
        raise AssertionError(f"accepted ({word})")
    evil = make_release_manifest(script, "9.9.9", {"new": k_evil})
    refused(lambda: check_release(evil, script, "4.0.0", trusted),
            "isn't signed")
    refused(lambda: check_release(man, script[:-100], "4.0.0", trusted),
            "incomplete")
    tampered = script[:-1] + b"!"
    refused(lambda: check_release(man, tampered, "4.0.0", trusted),
            "fingerprint")
    old = make_release_manifest(script, "3.9.0", {"new": k_new})
    refused(lambda: check_release(old, script, "4.0.0", trusted),
            "downgrades")
    forged = dict(man, version="10.0.0")
    refused(lambda: check_release(forged, script, "4.0.0", trusted),
            "isn't signed")
    refused(lambda: check_release(man, script, "4.0.0", {}), "check-only")
    # data packs: signed ones apply, unsigned ones don't
    pack = sign_manifest({"kind": "datapack", "pack": "services",
                          "version": "1", "data": {"40404": "Test svc"}},
                         {"new": k_new})
    had = PORT_SERVICES.get(40404)
    try:
        assert apply_data_pack(pack, trusted) == 1
        assert PORT_SERVICES[40404] == "Test svc"
    finally:
        if had is None:
            PORT_SERVICES.pop(40404, None)
        else:
            PORT_SERVICES[40404] = had
    unsigned = dict(pack, signatures=[])
    refused(lambda: apply_data_pack(unsigned, trusted), "isn't signed")
    refused(lambda: apply_data_pack(man, trusted), "Not a MiniWireshark")
    # install + automatic rollback after starts that never confirm
    d = ctx.path(f"upd_{uuid.uuid4().hex[:6]}")
    os.makedirs(d)
    cur = os.path.join(d, "miniwireshark.py")
    with open(cur, "wb") as f:
        f.write(b"# MiniWireshark old\ndef main():\n    pass\n" + b"#" * 60000)
    marker = os.path.join(d, "marker.json")
    apply_self_update(script, "9.9.9", cur, marker)
    assert open(cur, "rb").read() == script and os.path.exists(marker)
    assert rollback_update_if_needed(script_path=cur, marker_path=marker) \
        == ""                                     # 1st start: wait
    rollback_update_if_needed(script_path=cur, marker_path=marker)
    msg = rollback_update_if_needed(script_path=cur, marker_path=marker)
    assert "restored" in msg and b"old" in open(cur, "rb").read()
    assert not os.path.exists(marker)
    # release tooling end to end
    kf = os.path.join(d, "release.key")
    assert release_tool(["--make-release-key", kf, "--key-id", "t1"]) == 0
    kd = json.load(open(kf))
    assert release_tool(["--sign-release", cur, "--key", kf, "--version",
                         "9.9.10"]) == 0
    man2 = read_json(os.path.join(d, MANIFEST_NAME))
    body = verify_manifest(man2, {"t1": ed25519_public_key(
        bytes.fromhex(kd["secret"])).hex()})
    assert body["sha256"] == hashlib.sha256(open(cur, "rb").read()) \
        .hexdigest()
