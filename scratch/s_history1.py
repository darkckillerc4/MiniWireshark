# ============================================================================
#  14c.  History views — what changed, sessions, packet history
# ============================================================================
CHANGE_PERIODS = {"Last hour": 3600, "Last 24 hours": 86400,
                  "Last 7 days": 7 * 86400, "Since this session started":
                  None}


def change_digest(model, store=None, since=0.0, until=None):
    """What changed between `since` and `until`: new / returning / gone
    devices, first-seen websites, address and DNS changes, network events
    and warnings. In-memory data first; older periods come from the
    history store (if enabled)."""
    until = until or model.now()
    reg = model.registry
    own = set(model.my_ips) | {model.gateway_ip}
    out = {"since": since, "until": until, "new_devices": [],
           "returned": [], "left": [], "new_sites": [], "ip_changes": [],
           "dns_changes": [], "network": [], "alerts": [], "from_store": 0}
    for d in reg.by_key.values():
        if not d.live or not (since <= d.first_seen <= until):
            continue
        if d.ip in own or (d.mac and d.mac in model.my_macs):
            continue
        out["new_devices"].append((d.first_seen, d.key, d.display_name()))
    first_by_root = {}
    for w in model.websites.values():
        r = w.registrable or w.domain
        if r not in first_by_root or w.first_seen < first_by_root[r][0]:
            first_by_root[r] = (w.first_seen, w)
    for r, (fs, w) in first_by_root.items():
        if since <= fs <= until and w.live:
            out["new_sites"].append((fs, r, sorted(w.devices)[:3],
                                     w.best_assoc))
    kinds = {"device back": "returned", "device left": "left",
             "ip changed": "ip_changes", "dns change": "dns_changes",
             "network": "network", "interface": "network",
             "rogue router": "network", "internet": "network"}
    for e in model.timeline:
        k = kinds.get(e.get("kind"))
        if k and since <= e["when"] <= until:
            out[k].append((e["when"], e.get("device", ""), e["text"]))
    for a in model.alerts.alerts.values():
        if a.severity in ("WARNING", "DANGER") and \
                since <= a.first_seen <= until:
            out["alerts"].append((a.first_seen, a.severity, a.reason))
    if store is not None:
        known_new = {k for _t, k, _n in out["new_devices"]}
        rows = store.query(
            "SELECT ts, kind, severity, text, device FROM events WHERE "
            "ts>=? AND ts<=? AND session<>? ORDER BY ts LIMIT 5000",
            (since, until, getattr(store, "session", -1)))
        out["from_store"] = len(rows)
        for ts, kind, sev, text, dev in rows:
            k = kinds.get(kind)
            if kind == "new device" and dev not in known_new:
                out["new_devices"].append((ts, dev, text))
                known_new.add(dev)
            elif kind == "website":
                out["new_sites"].append((ts, text.replace(
                    "First visit to ", ""), [dev] if dev else [], ""))
            elif k:
                out[k].append((ts, dev, text))
            elif kind == "alert" and sev in ("WARNING", "DANGER"):
                out["alerts"].append((ts, sev, text))
    for k in ("new_devices", "returned", "left", "new_sites", "ip_changes",
              "dns_changes", "network", "alerts"):
        out[k].sort(key=lambda t: t[0])
    return out


def digest_summary(dg):
    parts = []
    for key, one, many in (("new_devices", "new device", "new devices"),
                           ("new_sites", "new website", "new websites"),
                           ("left", "device left", "devices left"),
                           ("alerts", "warning", "warnings")):
        n = len(dg[key])
        if n:
            parts.append(f"{n} {one if n == 1 else many}")
    return " · ".join(parts) if parts else "Nothing new."


