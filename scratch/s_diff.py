DIFF_FIELDS = ("proto", "tag", "text", "src", "dst", "src_ip", "dst_ip",
               "src_mac", "dst_mac", "ttl", "ttl_int", "sport", "dport",
               "ipver", "transport", "tcp_flags", "seq", "payload_len",
               "dns_names", "doh_hint", "plain_dns", "type_hint",
               "dhcp_msgtype", "arp_op", "dhcp_yiaddr", "dhcp_hostname",
               "dhcp_client_mac", "dhcp", "dns", "tls", "nd", "ssdp",
               "mdns", "http_host", "service", "service_port", "app_conf",
               "encrypted", "cleartext", "multicast", "l2_bcast", "learns",
               "length")


def decoder_differences(frames):
    """Compare fast_decode() with the scapy decoder frame by frame."""
    out = []
    ra, rb = TlsReassembler(), TlsReassembler()
    for i, (raw, ts, lt) in enumerate(frames):
        try:
            a = _fast_decode(raw, ts, lt, ra)
        except (NeedDeepParse, struct.error, IndexError, ValueError):
            continue                     # declined: scapy handles it anyway
        pkt = Ether(raw)
        pkt.time = ts
        b = decode_packet(pkt, reasm=rb)
        for k in DIFF_FIELDS:
            va, vb = a.get(k), b.get(k)
            if k in ("dns", "mdns") and va and vb:
                va = dict(va)
                vb = dict(vb)
            if va != vb:
                out.append(f"frame {i} {a['proto']}: {k}: fast={va!r} "
                           f"scapy={vb!r}")
    return out


@self_test()
def t_fast_decoder_matches_scapy(ctx):
    if not ctx.scapy_ok:
        return "skip"
    frames = ctx.frames() + ScenarioBuilder().busy_mix(300)
    diffs = decoder_differences(frames)
    assert not diffs, f"{len(diffs)} differences, e.g. " + \
        " | ".join(diffs[:4])
    declined = 0
    for raw, ts, lt in frames:
        try:
            _fast_decode(raw, ts, lt, TlsReassembler())
        except (NeedDeepParse, struct.error, IndexError, ValueError):
            declined += 1
    assert declined <= len(frames) * 0.02, f"declined {declined}"


@self_test(slow=True)
def t_fast_decoder_fuzz(ctx):
    if not ctx.scapy_ok:
        return "skip"
    rng = random.Random(5)
    frames = ctx.frames()
    for i in range(4000):
        raw = bytearray(frames[rng.randrange(len(frames))][0])
        for _ in range(rng.randint(1, 5)):
            if raw and rng.random() < 0.6:
                raw[rng.randrange(len(raw))] = rng.randrange(256)
            elif len(raw) > 2:
                del raw[rng.randrange(1, len(raw)):]
        d = fast_decode(bytes(raw), 1.0 + i)     # must never raise
        assert isinstance(d, dict) and "proto" in d


