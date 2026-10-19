# ============================================================================
#  12d.  Insights: narratives that cannot overclaim, periodicity, episodes
#        and guided investigations (a hypothesis board, never a verdict)
# ============================================================================
class NarrativeRefused(ValueError):
    """A template was given a claim weaker than its slot accepts."""


class C:
    """A claim used to fill a narrative slot: a value with its level."""
    __slots__ = ("value", "level", "proof")

    def __init__(self, value, level, proof=""):
        self.value, self.level, self.proof = value, level, proof

    def __repr__(self):
        return f"C({self.value!r}, {self.level})"


# How strong each level is when a sentence states it as fact.
LEVEL_STRENGTH = {LV_OBSERVED: 4, LV_REPORTED: 3, LV_CORRELATED: 2,
                  LV_INFERRED: 1, LV_UNKNOWN: 0}
VERBS = {
    "made": {LV_OBSERVED: "made", LV_REPORTED: "was reported to make",
             LV_CORRELATED: "appears to have made",
             LV_INFERRED: "may have made"},
    "is": {LV_OBSERVED: "is", LV_REPORTED: "is reported to be",
           LV_CORRELATED: "appears to be", LV_INFERRED: "may be"},
    "used": {LV_OBSERVED: "used", LV_REPORTED: "was reported to use",
             LV_CORRELATED: "appears to have used",
             LV_INFERRED: "may have used"},
    "contacts": {LV_OBSERVED: "contacts", LV_REPORTED: "reportedly contacts",
                 LV_CORRELATED: "appears to contact",
                 LV_INFERRED: "may contact"},
}


class NarrativeTemplate:
    """Text with {slot} and {verb:NAME} markers. Each slot lists the
    levels it accepts; the verb is conjugated by the WEAKEST level among
    the slots, and the sentence carries that level's glyph. A missing
    required slot means nothing is rendered."""

    def __init__(self, key, text, slots, optional=()):
        self.key, self.text = key, text
        self.slots = dict(slots)          # name → set of accepted levels
        self.optional = set(optional)

    def render(self, **claims):
        vals, weakest = {}, LV_OBSERVED
        for name, allowed in self.slots.items():
            c = claims.get(name)
            if c is None or c.value in (None, ""):
                if name in self.optional:
                    vals[name] = ""
                    continue
                return None                  # empty required slot
            if not isinstance(c, C):
                raise NarrativeRefused(f"slot {name} needs a claim")
            if c.level not in allowed:
                raise NarrativeRefused(
                    f"{self.key}: slot {name} accepts "
                    f"{sorted(allowed)}, got {c.level}")
            vals[name] = c.value
            if LEVEL_STRENGTH[c.level] < LEVEL_STRENGTH[weakest]:
                weakest = c.level
        text = re.sub(r"\{verb:(\w+)\}", lambda m: VERBS[m.group(1)][weakest],
                      self.text)
        text = text.format(**vals)
        return LEVEL_GLYPH[weakest] + " " + _cap(text.strip()), weakest


_ALL = {LV_OBSERVED, LV_REPORTED, LV_CORRELATED, LV_INFERRED}
_SEEN = {LV_OBSERVED, LV_REPORTED}
NARRATIVES = {t.key: t for t in (
    NarrativeTemplate("connections",
                      "{device} {verb:made} {count} connections to "
                      "{destination} over {duration}.",
                      {"device": _ALL, "count": _SEEN, "destination": _ALL,
                       "duration": _SEEN}),
    NarrativeTemplate("periodic",
                      "{device} {verb:contacts} {destination} about every "
                      "{period} ({repeats} times).",
                      {"device": _ALL, "destination": _ALL,
                       "period": {LV_CORRELATED, LV_OBSERVED},
                       "repeats": _SEEN}),
    NarrativeTemplate("bandwidth",
                      "{device} {verb:used} {amount} in the last {window}"
                      "{share}.",
                      {"device": _ALL, "amount": _SEEN, "window": _SEEN,
                       "share": _ALL}, optional=("share",)),
    NarrativeTemplate("shape",
                      "Pattern looks like {shape} ({detail}).",
                      {"shape": {LV_INFERRED}, "detail": _SEEN}),
    NarrativeTemplate("program",
                      "{program} on this computer {verb:is} using "
                      "{rate}.",
                      {"program": {LV_OBSERVED}, "rate": _SEEN}),
)}


def narrate(key, **claims):
    """Render a narrative or None (missing data). Raises NarrativeRefused
    when a claim is weaker than the sentence would state."""
    got = NARRATIVES[key].render(**claims)
    return got[0] if got else None


# ---- periodicity: "contacts X about every 60 s" ----------------------------
PERIOD_BUCKETS = (5, 10, 20, 40, 75, 150, 300, 600, 1200, 2400, 4800,
                  float("inf"))


def detect_periodic(starts, min_repeats=10, share=0.7):
    """Connection start times → (period seconds, repeats) when most
    intervals fall in one log-scale bucket, else None."""
    ts = sorted(starts)
    if len(ts) < min_repeats + 1:
        return None
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 1.0]
    if len(gaps) < min_repeats:
        return None
    buckets = Counter()
    for g in gaps:
        for i, edge in enumerate(PERIOD_BUCKETS):
            if g < edge:
                buckets[i] += 1
                break
    idx, n = buckets.most_common(1)[0]
    if n < min_repeats or n / len(gaps) < share:
        return None
    lo = PERIOD_BUCKETS[idx - 1] if idx else 0
    inside = [g for g in gaps if lo <= g < PERIOD_BUCKETS[idx]]
    return statistics.median(inside), n


def human_period(sec):
    if sec < 90:
        return f"{sec:.0f} s"
    if sec < 5400:
        return f"{sec / 60:.0f} min"
    return f"{sec / 3600:.1f} h"


def periodic_findings(model, min_repeats=10):
    """[(device_key, destination, period, repeats, narrative)]."""
    out = []
    reg = model.registry
    for (dev_key, remote), starts in list(model.flow_starts.items()):
        got = detect_periodic(starts, min_repeats)
        if not got:
            continue
        period, n = got
        names = model.ip_to_domains.get(remote)
        dest = next(reversed(names)) if names else remote
        dev = reg.by_key.get(reg.resolve(dev_key))
        text = narrate("periodic",
                       device=C(dev.display_name() if dev else dev_key,
                                LV_OBSERVED),
                       destination=C(dest, LV_OBSERVED if not names else
                                     LV_CORRELATED),
                       period=C(human_period(period), LV_CORRELATED),
                       repeats=C(n + 1, LV_OBSERVED))
        out.append((dev_key, dest, period, n + 1, text))
    out.sort(key=lambda r: -r[3])
    return out


# ---- episodes: bursts of related events under one headline -----------------
EPISODE_RULES = (
    ("reconnect_wave",
     lambda evs: sum(1 for e in evs if e["kind"] in ("device back",
                                                     "dhcp lease",
                                                     "new device")) >= 3,
     lambda evs: (f"{sum(1 for e in evs if e['kind'] in ('device back', 'dhcp lease', 'new device'))} "
                  f"devices (re)joined within "
                  f"{human_duration(evs[-1]['when'] - evs[0]['when'])}"),
     "the router or the Wi-Fi restarted (or the power came back)",
     LV_INFERRED),
    ("drop_wave",
     lambda evs: sum(1 for e in evs if e["kind"] == "device left") >= 3,
     lambda evs: (f"{sum(1 for e in evs if e['kind'] == 'device left')} "
                  f"devices went offline together"),
     "a Wi-Fi drop, a power cut or devices going to sleep at the same "
     "time", LV_INFERRED),
    ("network_change",
     lambda evs: any(e["kind"] in ("network", "interface", "internet",
                                   "wifi") for e in evs) and len(evs) >= 2,
     lambda evs: next(e["text"] for e in evs if e["kind"] in (
         "network", "interface", "internet", "wifi")),
     "a change of network or connection", LV_OBSERVED),
    ("browsing_burst",
     lambda evs: len({e.get("device") for e in evs
                      if e["kind"] == "website"}) == 1 and
     sum(1 for e in evs if e["kind"] == "website") >= 4,
     lambda evs: (f"{sum(1 for e in evs if e['kind'] == 'website')} new "
                  f"websites in a short burst"),
     "one page or app loading many services", LV_OBSERVED),
)


def build_episodes(events, window=120.0, min_events=2):
    """Group time-ordered timeline events: a new episode starts after
    `window` seconds of quiet. → [{"start", "end", "events", "headline",
    "cause", "level", "rule"}] (single events are left alone)."""
    evs = sorted(events, key=lambda e: e["when"])
    groups, cur = [], []
    for e in evs:
        if cur and e["when"] - cur[-1]["when"] > window:
            groups.append(cur)
            cur = []
        cur.append(e)
    if cur:
        groups.append(cur)
    out = []
    for g in groups:
        if len(g) < min_events:
            continue
        ep = {"start": g[0]["when"], "end": g[-1]["when"], "events": g,
              "headline": f"{len(g)} related events", "cause": "",
              "level": LV_INFERRED, "rule": ""}
        for rule, match, head, cause, lvl in EPISODE_RULES:
            try:
                if match(g):
                    ep.update(headline=head(g), cause=cause, level=lvl,
                              rule=rule)
                    break
            except (StopIteration, KeyError):
                continue
        out.append(ep)
    return out


# ---- guided investigations --------------------------------------------------
HYP_STATUS_ORDER = {"Likely": 3, "Possible": 2, "Can't tell": 1,
                    "Unlikely": 0}


def _hyp(key, title, score, status, why_for=(), why_against=(), fix=""):
    return {"key": key, "title": title, "score": float(score),
            "status": status, "for": list(why_for),
            "against": list(why_against), "fix": fix}


def investigate_slow(f):
    """“Why is my Internet slow?” → ranked hypotheses (a board, not a
    verdict). `f` = facts gathered by the app (see collect_slow_facts).
    “Can't tell from here” is a valid answer and comes first when nothing
    visible explains the slowness."""
    H = []
    w = f.get("wifi")
    if w and w.get("rssi") is not None:
        r = w["rssi"]
        if r < -75:
            H.append(_hyp("wifi", "Weak Wi-Fi on this computer", 0.92,
                          "Likely", [f"◉ Signal {r:.0f} dBm (weak)"],
                          fix="Move closer to the router, remove obstacles, "
                              "or use 5 GHz / a cable."))
        elif r < -67:
            H.append(_hyp("wifi", "Weak Wi-Fi on this computer", 0.5,
                          "Possible", [f"◉ Signal {r:.0f} dBm (fair)"],
                          fix="Moving closer usually helps."))
        else:
            H.append(_hyp("wifi", "Weak Wi-Fi on this computer", 0.05,
                          "Unlikely", (), [f"◉ Signal {r:.0f} dBm (good)"]))
    elif f.get("wired"):
        H.append(_hyp("wifi", "Weak Wi-Fi on this computer", 0.0,
                      "Unlikely", (), ["◉ This computer uses a cable"]))
    h = f.get("health") or {}
    if "gateway_ok" in h:
        if not h["gateway_ok"]:
            H.append(_hyp("router", "The router isn't answering", 0.9,
                          "Likely", ["◉ The router didn't answer the "
                                     "check"],
                          fix="Restart the router; check its cables."))
        elif (h.get("gateway_ms") or 0) > 50:
            H.append(_hyp("router", "The router is slow to answer", 0.55,
                          "Possible", [f"◉ Router answered in "
                                       f"{h['gateway_ms']:.0f} ms"],
                          fix="The router may be overloaded; restart it."))
        else:
            H.append(_hyp("router", "The router is slow or down", 0.05,
                          "Unlikely", (), [f"◉ Router answered in "
                                           f"{h.get('gateway_ms') or 0:.0f} "
                                           f"ms"]))
    dm, fr, dn = f.get("dns_median_ms"), f.get("dns_fail_rate") or 0, \
        f.get("dns_n") or 0
    slow = f.get("dns_slow_ms", 800)
    if dn >= 5 and (fr >= 0.3 or (dm or 0) >= slow):
        H.append(_hyp("dns", "Slow or failing website lookups (DNS)", 0.85,
                      "Likely", [f"◉ Typical lookup {dm or 0:.0f} ms" +
                                 (f", {fr:.0%} failed" if fr else "")],
                      fix="Try another DNS server (in the router or this "
                          "computer's settings)."))
    elif dn >= 5 and (dm or 0) >= 250:
        H.append(_hyp("dns", "Slow website lookups (DNS)", 0.45,
                      "Possible", [f"◉ Typical lookup {dm:.0f} ms"]))
    elif dn >= 5:
        H.append(_hyp("dns", "Slow website lookups (DNS)", 0.05, "Unlikely",
                      (), [f"◉ Typical lookup {dm or 0:.0f} ms over {dn} "
                           f"lookups"]))
    elif f.get("dns_encrypted"):
        H.append(_hyp("dns", "Slow website lookups (DNS)", 0.0,
                      "Can't tell", (), ["Lookups are encrypted, so they "
                                         "can't be timed"]))
    rtt, rn = f.get("rtt_median_ms"), f.get("rtt_n") or 0
    local_ok = not any(x["key"] in ("wifi", "router") and
                       x["status"] in ("Likely", "Possible") for x in H)
    if rn >= 5 and rtt is not None:
        if rtt >= 200:
            H.append(_hyp("isp", "Delay beyond your router (Internet "
                                 "provider or the sites themselves)",
                          0.75 if local_ok else 0.4,
                          "Likely" if local_ok else "Possible",
                          [f"◉ Connections take {rtt:.0f} ms to open"] +
                          (["◉ Wi-Fi and router look fine"] if local_ok
                           else []),
                          fix="Test at another time; if it persists, "
                              "contact your Internet provider."))
        elif rtt >= 100:
            H.append(_hyp("isp", "Delay beyond your router", 0.3,
                          "Possible", [f"◉ Connections take {rtt:.0f} ms "
                                       f"to open"]))
        else:
            H.append(_hyp("isp", "Delay beyond your router", 0.05,
                          "Unlikely", (), [f"◉ Connections open in "
                                           f"{rtt:.0f} ms"]))
    rp = f.get("retrans_pct")
    if rp is not None and (f.get("tcp_packets") or 0) > 500:
        wifi_weak = any(x["key"] == "wifi" and x["status"] == "Likely"
                        for x in H)
        if rp >= 0.06:
            H.append(_hyp("loss", "Packets getting lost on the way",
                          0.5 if wifi_weak else 0.7,
                          "Possible" if wifi_weak else "Likely",
                          [f"◉ {rp:.1%} of data was re-sent"] +
                          (["◎ Consistent with the weak Wi-Fi"]
                           if wifi_weak else [])))
        elif rp >= 0.02:
            H.append(_hyp("loss", "Packets getting lost on the way", 0.35,
                          "Possible", [f"◉ {rp:.1%} of data was re-sent"]))
        else:
            H.append(_hyp("loss", "Packets getting lost", 0.05, "Unlikely",
                          (), [f"◉ Only {rp:.1%} re-sent"]))
    top = f.get("this_pc_top") or []
    if top:
        prog, rate = top[0][0], top[0][1]
        if rate >= 2e6:
            H.append(_hyp("local_hog", f"{prog} on this computer is using "
                                       f"most of the connection", 0.65,
                          "Possible", [narrate(
                              "program", program=C(prog, LV_OBSERVED),
                              rate=C(_human_bytes(rate) + "/s",
                                     LV_OBSERVED))],
                          fix=f"Pause {prog}'s downloads or updates and "
                              f"try again."))
    other = f.get("other_top")
    if f.get("vantage") in ("mirror", "partial") and other:
        name, rate = other
        if rate >= 2e6:
            H.append(_hyp("other_hog", f"{name} is using a lot of the "
                                       f"connection", 0.6, "Possible",
                          [f"◉ {_human_bytes(rate)}/s right now"],
                          fix=f"Check what {name} is doing (streaming, "
                              f"backups, updates)."))
    elif f.get("vantage") == "endpoint":
        H.append(_hyp("other_hog", "Another device using the connection",
                      0.0, "Can't tell", (),
                      ["From this computer, other devices' traffic isn't "
                       "visible (it goes straight to the router)."]))
    if f.get("vpn"):
        H.append(_hyp("vpn", "The VPN adds a detour", 0.3, "Possible",
                      ["◉ A VPN is active"],
                      fix="Try once with the VPN off to compare."))
    best = max((x["score"] for x in H if x["status"] in ("Likely",
                                                         "Possible")),
               default=0.0)
    if best < 0.5:
        H.append(_hyp("cant_tell", "Can't tell from here", 0.49,
                      "Can't tell",
                      ["Nothing this computer can see explains it right "
                       "now."],
                      fix="Check again while it's slow, or connect a "
                          "Pi-hole / use a mirror port to see more. The "
                          "router's own Internet line isn't visible from "
                          "here."))
    H.sort(key=lambda x: (-x["score"], -HYP_STATUS_ORDER[x["status"]]))
    return H


def investigate_bandwidth(f):
    """“What is using my bandwidth?” — totals per device by the evidence
    level trusted, the unattributed share, and the blind spot."""
    rows = sorted(f.get("devices") or [], key=lambda r: -r[1])
    total = sum(r[1] for r in rows) + (f.get("unattributed") or 0)
    out = {"rows": [], "unattributed": f.get("unattributed") or 0,
           "total": total, "vantage": f.get("vantage"), "conclusion": ""}
    for name, nbytes, level in rows[:12]:
        share = f" ({nbytes / total:.0%} of what I can see)" if total else ""
        out["rows"].append(narrate(
            "bandwidth", device=C(name, LV_OBSERVED),
            amount=C(_human_bytes(nbytes), level),
            window=C(f.get("window_text", "few minutes"), LV_OBSERVED),
            share=C(share, LV_OBSERVED)))
    if f.get("vantage") == "endpoint":
        out["conclusion"] = (
            "Can't tell from here for other devices: this computer only "
            "sees its own traffic. "
            + (f"{rows[0][0]} is the biggest user I can see." if rows
               else "") + " Your router's status page, a Pi-hole, or a "
            "mirror port can show the others.")
    elif not rows:
        out["conclusion"] = "Not enough traffic yet."
    else:
        top = rows[0]
        share = top[1] / total if total else 0
        out["conclusion"] = (
            f"{top[0]} is using the most ({share:.0%} of what I can see)."
            if share >= 0.4 else
            "No single device stands out; the usage is spread out.")
        if out["unattributed"] and total and \
                out["unattributed"] / total >= 0.2:
            out["conclusion"] += (f" {out['unattributed'] / total:.0%} of "
                                  f"the traffic couldn't be tied to a "
                                  f"device.")
    return out


