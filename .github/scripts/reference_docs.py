#!/usr/bin/env python3
"""Writes the reference pages from the tables in miniwireshark.py.

* docs/ALERTS.md: every alert the app can raise, in the words the app
  shows: its severity, why it is flagged, what it usually means and what
  to check.
* docs/FIELDS.md: every protocol and field the packet filter knows, with
  its type and meaning.

The tables are read with the ast module, so the app is not imported or run.

    python .github/scripts/reference_docs.py           # rewrite the pages
    python .github/scripts/reference_docs.py --check   # fail if out of date

CI runs --check, so the pages can't drift from the app.
"""
import ast
import sys

SOURCE = "miniwireshark.py"
SEVERITY_ORDER = {"DANGER": 0, "WARNING": 1, "INFO": 2}
SEVERITY_WORD = {"DANGER": "Danger", "WARNING": "Warning", "INFO": "Info"}


def read_tables(path):
    """ALERT_TYPES, ALERT_META, ALERT_CHECKLIST (with its later .update and
    .setdefault calls) and ALERT_MEANS, as plain Python values."""
    tree = ast.parse(open(path, encoding="utf-8").read(), path)
    tables = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                isinstance(node.targets[0], ast.Name) and \
                node.targets[0].id in ("ALERT_TYPES", "ALERT_META",
                                       "ALERT_CHECKLIST", "ALERT_MEANS"):
            tables[node.targets[0].id] = ast.literal_eval(node.value)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            f = call.func
            if isinstance(f, ast.Attribute) and \
                    isinstance(f.value, ast.Name) and \
                    f.value.id == "ALERT_CHECKLIST":
                args = [ast.literal_eval(a) for a in call.args]
                if f.attr == "update":
                    tables["ALERT_CHECKLIST"].update(args[0])
                elif f.attr == "setdefault":
                    tables["ALERT_CHECKLIST"].setdefault(args[0], args[1])
    missing = {"ALERT_TYPES", "ALERT_META", "ALERT_CHECKLIST",
               "ALERT_MEANS"} - set(tables)
    if missing:
        raise SystemExit(f"alerts_doc: not found in {path}: "
                         f"{', '.join(sorted(missing))}")
    return tables


def render(t):
    types, meta = t["ALERT_TYPES"], t["ALERT_META"]
    checks, means = t["ALERT_CHECKLIST"], t["ALERT_MEANS"]
    kinds = sorted(types, key=lambda k: (SEVERITY_ORDER.get(types[k][1], 9),
                                         types[k][0].lower()))
    out = [
        "<!-- Written by .github/scripts/reference_docs.py from the alert tables "
        "in miniwireshark.py. Edit the tables, then run the script; CI "
        "fails when this page is out of date. -->",
        "",
        "# Alerts reference",
        "",
        "Every alert MiniWireshark can raise, in the words the app uses. "
        "An alert means *worth a look*, not *hacked*. **Danger** is kept "
        "for strong, specific evidence, never for \"unusual\" alone.",
        "",
        "Each alert in the app also shows what was seen, the evidence "
        "behind it and a confidence. You can turn each kind off or change "
        "its threshold in **Settings → Alerts**, and snooze it from the "
        "alert itself. Alerts "
        "that compare against \"normal\" wait until the device has a "
        "baseline. See [Features](FEATURES.md#is-anything-wrong) for how "
        "that works.",
        "",
        f"There are {len(kinds)} kinds:",
        "",
        "| Alert | Severity |",
        "|---|---|",
    ]
    for k in kinds:
        name, sev = types[k]
        out.append(f"| [{name}](#{anchor(name)}) | "
                   f"{SEVERITY_WORD.get(sev, sev)} |")
    for k in kinds:
        name, sev = types[k]
        line = f"**Severity:** {SEVERITY_WORD.get(sev, sev)}"
        if k in meta:
            line += f" · **Usual confidence:** {meta[k][0]}"
        out += ["", f"## {name}", "", line]
        if k in meta:
            out += ["", f"**Why it is flagged:** {meta[k][1]}"]
        if k in means:
            out += ["", f"**What it usually means:** {means[k]}"]
        if checks.get(k):
            out += ["", "**What to check:**", ""]
            out += [f"{i}. {s}" for i, s in enumerate(checks[k], 1)]
    out += ["", "## Something here is wrong",  "",
            "If an alert fired when it shouldn't have, or the advice didn't "
            "help, please [open an issue](https://github.com/darkckillerc4/"
            "MiniWireshark/issues/new/choose). Attach a debug bundle from "
            "**Diagnostics**: it masks addresses and secrets.", ""]
    return "\n".join(out)


def anchor(title):
    keep = []
    for ch in title.lower():
        if ch.isalnum() or ch in "-_":
            keep.append(ch)
        elif ch == " ":
            keep.append("-")
    return "".join(keep)


def read_fields(path):
    """The declare_fields(...) calls, FILTER_OPS, FILTER_PORT_PROTOS,
    SPECIAL_FIELDS and SPECIAL_DESC."""
    tree = ast.parse(open(path, encoding="utf-8").read(), path)
    protos, named = [], {}
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) \
                and isinstance(node.value.func, ast.Name) and \
                node.value.func.id == "declare_fields":
            protos.append(tuple(ast.literal_eval(a)
                                for a in node.value.args))
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                isinstance(node.targets[0], ast.Name) and \
                node.targets[0].id in ("FILTER_OPS", "FILTER_PORT_PROTOS",
                                       "FILTER_PROTOCOLS", "SPECIAL_FIELDS",
                                       "SPECIAL_DESC"):
            named[node.targets[0].id] = ast.literal_eval(node.value)
    missing = {"FILTER_OPS", "FILTER_PORT_PROTOS", "FILTER_PROTOCOLS",
               "SPECIAL_FIELDS", "SPECIAL_DESC"} - set(named)
    if missing or not protos:
        raise SystemExit(f"reference_docs: field tables not found in {path}")
    return protos, named


TYPE_WORD = {"int": "number", "float": "number", "hex": "number (hex)",
             "str": "text", "bytes": "bytes", "bool": "true or false",
             "mac": "MAC address", "ipv4": "IPv4 address",
             "ipv6": "IPv6 address", "severity": "severity"}


def cell(text):
    return str(text).replace("|", "\\|")


def render_fields(protos, named):
    total = sum(len(f) for _p, _t, f in protos)
    ops = " ".join(f"`{o}`" for o in named["FILTER_OPS"])
    out = [
        "<!-- Written by .github/scripts/reference_docs.py from the field "
        "tables in miniwireshark.py. Edit the tables, then run the script; "
        "CI fails when this page is out of date. -->",
        "",
        "# Packet filter fields",
        "",
        "Every field the **Packets** tab's field filter understands, "
        f"grouped by protocol: {len(protos)} protocols and {total} fields, "
        f"plus {len(named['SPECIAL_FIELDS'])} shortcut fields. The same "
        "names appear in the packet details tree, so you can also "
        "right-click a value there and choose **Copy as filter**. For the "
        "friendly search tokens (`site:`, `port:` …) see "
        "[Filtering](USER-GUIDE.md#filtering).",
        "",
        "## How to write a filter",
        "",
        f"- Compare a field with a value: {ops}. `contains` matches part "
        "of a text value. Put text in double quotes.",
        "- Combine with `and` (`&&`), `or` (`||`) and `not` (`!`), and use "
        "parentheses.",
        "- A protocol name alone keeps the packets that have it, for "
        "example `dns`, `tls` or `arp`. The names that work this way are "
        + ", ".join(f"`{n}`" for n in sorted(named["FILTER_PROTOCOLS"]))
        + ", and the port-based names below.",
        "- A filter that doesn't parse shows the reason and changes "
        "nothing. Filters only choose what is shown; they never change "
        "what is captured.",
        "",
        "```",
        "ip.src == 192.168.1.20 && tcp.port == 443",
        "dns.qry.name contains \"example\"",
        "tls and not ip.dst == 10.0.0.1",
        "frame.len > 1000 or expert.severity >= warning",
        "```",
        "",
        "## Shortcut fields",
        "",
        "These match either direction, or describe the packet as a whole.",
        "",
        "| Field | Type | Meaning |",
        "|---|---|---|",
    ]
    for key, ftype in named["SPECIAL_FIELDS"].items():
        out.append(f"| `{key}` | {TYPE_WORD.get(ftype, ftype)} | "
                   f"{cell(named['SPECIAL_DESC'].get(key, ''))} |")
    ports = named["FILTER_PORT_PROTOS"]
    out += ["", "## Protocols known by port", "",
            "These names work alone as a filter. They match the usual "
            "ports, so a service on another port is not matched.", "",
            "| Name | Ports |", "|---|---|"]
    for name in sorted(ports):
        out.append(f"| `{name}` | "
                   f"{', '.join(str(p) for p in sorted(ports[name]))} |")
    out += ["", "## Fields by protocol", ""]
    out += [f"- [{title}](#{anchor(title)})" for _k, title, _f in protos]
    for key, title, fields in protos:
        if key in named["FILTER_PROTOCOLS"]:
            intro = f"Filter on the protocol alone with `{key}`."
        else:
            intro = ("This layer has no filter name of its own; filter "
                     "on its fields.")
        out += ["", f"## {title}", "", intro, "",
                "| Field | Type | Meaning |", "|---|---|---|"]
        for fkey, ftype, unit, desc in fields:
            kind = TYPE_WORD.get(ftype, ftype)
            if unit:
                kind += f", in {unit}"
            out.append(f"| `{fkey}` | {kind} | {cell(desc)} |")
    out.append("")
    return "\n".join(out)


def pages():
    protos, named = read_fields(SOURCE)
    return {"docs/ALERTS.md": render(read_tables(SOURCE)),
            "docs/FIELDS.md": render_fields(protos, named)}


def main(argv):
    stale = []
    for target, text in pages().items():
        if "--check" in argv:
            try:
                current = open(target, encoding="utf-8").read()
            except OSError:
                current = ""
            if current != text:
                stale.append(target)
            continue
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"wrote {target}")
    if stale:
        print(f"Out of date: {', '.join(stale)}. Run: python "
              ".github/scripts/reference_docs.py")
        return 1
    if "--check" in argv:
        print("The reference pages match the tables in miniwireshark.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
