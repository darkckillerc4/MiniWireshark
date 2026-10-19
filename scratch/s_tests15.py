@self_test()
def t_redaction_no_leaks(ctx):
    """Every original address, hardware address and name is replaced,
    consistently, and the pseudonyms come from documentation ranges."""
    if not ctx.scapy_ok:
        return "skip"
    m = scenario_model(ctx.cfg(), ctx.frames())
    S = ScenarioBuilder
    d = m.device_for(S.PHONE[0], S.PHONE[1])
    d.alias, d.notes = "Kid's phone", "bought in May"
    rows = inventory_rows(m)
    text = "\n".join(" | ".join(str(v) for v in r.values()) for r in rows)
    text += "\nDNS answer 93.184.215.14 for www.example.com; " \
            "fe80::21e:58ff:feaa:1; network “HomeNet”."
    red = Redactor(m)
    red._add_name("HomeNet", "networks")
    out = red.text(text)
    originals = set()
    for dev in m.registry.by_key.values():
        originals |= {dev.ip, dev.mac, dev.alias, dev.notes, dev.hostname,
                      dev.dhcp_hostname, dev.mdns_name}
        originals |= set(dev.ipv6)
    originals |= {"93.184.215.14", "HomeNet", "fe80::21e:58ff:feaa:1"}
    leaks = sorted(o for o in originals if o and len(o) >= 3 and
                   o.lower() in out.lower())
    assert not leaks, leaks
    assert "Kid's phone" not in out and "Device " in out
    # consistent: the same original always gets the same pseudonym
    assert red.text(S.PHONE[0]) == red.text(S.PHONE[0])
    assert red.text(S.PHONE[0]).startswith("192.0.2.")
    assert red.text("93.184.215.14").startswith("198.51.100.")
    assert red.text(S.PHONE[1]).startswith("02:00:00:00:")
    assert "www.example.com" in out                  # public names kept…
    red2 = Redactor(m, {"sites": True})
    assert "www.example.com" not in red2.text(text)  # …unless asked
    # turning an option off keeps that kind of data
    keep = Redactor(m, {"addresses": False}).text(S.PHONE[0])
    assert keep == S.PHONE[0]
    html_doc = inventory_html(rows)
    assert html_doc.startswith("<!doctype html>") and "@media print" in \
        html_doc and len(rows) == len(m.registry.by_key)
    assert S.PHONE[0] in html_to_preview_text(html_doc)
