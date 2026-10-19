@self_test()
def t_quic_rfc9001_vectors(ctx):
    """RFC 9001 Appendix A.1 keys and A.2 header-protection mask; FIPS-197
    AES; the pure-Python GCM against `cryptography` when installed."""
    dcid = bytes.fromhex("8394c8f03e515708")
    k, iv, hp = quic_initial_keys(dcid)
    assert k.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"
    k, iv, hp = quic_initial_keys(dcid, side="server")
    assert k.hex() == "cf3a5331653c364c88f0f379b6067e37"
    assert iv.hex() == "0ac1493ca1905853b0bba03e"
    assert hp.hex() == "c206b8d9b9f0f37644430b490eeaa314"
    mask = aes128_ecb_encrypt(bytes.fromhex(
        "9f50449e04a0e810283a1e9933adedd2"),
        bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b"))
    assert mask[:5].hex() == "437b9aec36", mask.hex()
    assert aes128_ecb_encrypt(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == \
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    # GCM: NIST test case 4-style round trip and tamper detection
    key, nonce = bytes(range(16)), bytes(range(12))
    for n in (0, 15, 16, 33, 1000):
        data = bytes((i * 7) & 0xff for i in range(n))
        sealed = _aes_gcm_py(key, nonce, data, b"hdr", decrypt=False)
        assert _aes_gcm_py(key, nonce, sealed, b"hdr") == data
        bad = sealed[:-1] + bytes([sealed[-1] ^ 1])
        assert _aes_gcm_py(key, nonce, bad, b"hdr") is None
        assert _aes_gcm_py(key, nonce, sealed, b"other") is None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return "pure Python only"
    for n in (0, 1, 17, 1162):
        data = os.urandom(n)
        assert AESGCM(key).encrypt(nonce, data, b"a") == \
            _aes_gcm_py(key, nonce, data, b"a", decrypt=False)
    return "pure Python = cryptography"


def _quic_frames(sni, rip="93.184.215.14", src=("192.168.1.23",
                                                "da:a1:19:23:45:67"),
                 split=False, version=QUIC_V1, ech=False, sport=51000,
                 dcid=b"\x11\x22\x33\x44\x55\x66\x77\x88", t0=1000.0):
    ch = tls_client_hello(sni, ech=ech, pad_ext=1500 if split else 0)
    pkts = []
    if split:
        a, b = 600, 1100
        f1 = (b"\x06" + _quic_varint_enc(a) + _quic_varint_enc(b - a) +
              ch[a:b] + b"\x06" + _quic_varint_enc(0) +
              _quic_varint_enc(a) + ch[:a])          # out of order, on purpose
        f2 = b"\x06" + _quic_varint_enc(b) + _quic_varint_enc(
            len(ch) - b) + ch[b:]
        pkts.append(quic_build_initial(dcid, b"\x01", b"", 0, version,
                                       frames=f1))
        pkts.append(quic_build_initial(dcid, b"\x01", b"", 1, version,
                                       frames=f2))
    else:
        pkts.append(quic_build_initial(dcid, b"\x01", ch, 0, version))
    out = []
    for i, q in enumerate(pkts):
        e = Ether(src=src[1], dst=ScenarioBuilder.GW[1]) / \
            IP(src=src[0], dst=rip) / UDP(sport=sport, dport=443) / Raw(q)
        out.append((bytes(e), t0 + i * 0.01, 1))
    return out


@self_test()
def t_quic_initial_names(ctx):
    """HTTP/3 first packets: the site name is read the same way by both
    decoders, also when the ClientHello spans two packets with shuffled
    frames, for QUIC v2, and with ECH flagged; bad packets give nothing."""
    if not ctx.scapy_ok:
        return "skip"
    cases = [("www.example.com", {}), ("video.example.net",
                                       {"split": True}),
             ("v2.example.org", {"version": QUIC_V2}),
             ("cover.example.com", {"ech": True})]
    for sni, kw in cases:
        frames = _quic_frames(sni, **kw)
        for name, dec in (("fast", lambda r, t, lt, ra: _fast_decode(
                r, t, lt, ra)), ("scapy", lambda r, t, lt, ra:
                                 decode_packet(Ether(r), reasm=ra))):
            ra = TlsReassembler()
            got = [dec(r, t, lt, ra) for r, t, lt in frames]
            last = got[-1]
            assert last["proto"] == "QUIC", (name, last["proto"])
            assert last["tls"] and last["tls"]["sni"] == sni, \
                (name, sni, last["tls"], last["text"])
            assert last["tls"]["via"] == "quic"
            assert (last["tls"]["quic_version"] == "v2") == \
                (kw.get("version") == QUIC_V2)
            assert bool(last["tls"]["ech"]) == bool(kw.get("ech"))
            assert sni in last["text"] and sni in last["dns_names"]
            if kw.get("split"):
                assert got[0]["tls"] is None   # half a ClientHello: wait
            # a retransmitted first packet is not read twice
            again = dec(frames[0][0], frames[0][1] + 1, 1, ra)
            assert again["tls"] is None
    # tampered packet (bad tag) and garbage give no name, no crash
    raw = bytearray(_quic_frames("x.example.com")[0][0])
    raw[-5] ^= 0x40
    d = _fast_decode(bytes(raw), 1.0, 1, TlsReassembler())
    assert d["proto"] == "QUIC" and d["tls"] is None
    rng = random.Random(5)
    ra = TlsReassembler()
    base = _quic_frames("y.example.com")[0][0]
    for _ in range(200):
        b = bytearray(base)
        for _k in range(rng.randint(1, 8)):
            b[rng.randrange(42, len(b))] = rng.randrange(256)
        d = _fast_decode(bytes(b), 2.0, 1, ra)
        assert d["proto"] == "QUIC"
    # turned off in Settings → nothing is read
    QUIC_NAMES["enabled"] = False
    try:
        d = _fast_decode(_quic_frames("z.example.com")[0][0], 3.0, 1,
                         TlsReassembler())
        assert d["tls"] is None and "encrypted" in d["text"]
    finally:
        QUIC_NAMES["enabled"] = True
    # budget: a flood of fake Initials is capped per second
    rd = QuicInitialReader(budget=5)
    for i in range(50):
        rd.feed(("a", i), base, 10.0)
    assert rd.decrypted + rd.failed <= 5 and rd.skipped >= 45
    # the model files the name as a connection, labelled as QUIC
    m = scenario_model(ctx.cfg(), ctx.frames() + _quic_frames(
        "h3.example.com", t0=ctx.frames()[-1][1] + 1))
    w = m.websites.get("h3.example.com")
    assert w is not None and "QUIC first packet" in w.sources, \
        (w and w.sources)
    ph = ScenarioBuilder.PHONE[1]
    dev = m.device_for(ScenarioBuilder.PHONE[0], ph)
    assert dev is not None and w.ties.get(dev.key, [""])[0] in (
        AS_CONNECTED, AS_CONNECTED_LOOKUP), w.ties
