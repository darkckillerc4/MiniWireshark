#!/usr/bin/env python3
"""Per-region line coverage of the self-test, with no extra packages.

    python3.12+ .github/scripts/coverage_regions.py [miniwireshark.py [ARGS]] [--out cov.md]

Runs `miniwireshark.py ARGS` (default --self-test; --gui-test also works)
in this process under sys.monitoring (Python 3.12+), then reports
executed / executable lines for every top-level class and function,
worst first. Work done in child processes is not counted, so the numbers
are a floor. Tests that read their own source with inspect fail here
(the code is exec'd), so expect a few harness-only failures.
"""
import ast
import os
import sys


def executable_lines(code):
    lines, todo = set(), [code]
    while todo:
        c = todo.pop()
        lines.update(ln for _, _, ln in c.co_lines() if ln)
        todo.extend(k for k in c.co_consts if hasattr(k, "co_lines"))
    return lines


def regions(src):
    """(name, first, last) for each top-level def/class; methods are
    reported under their class."""
    out = []
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            out.append((node.name, node.lineno, node.end_lineno))
    return out


def main():
    args = [a for a in sys.argv[1:] if a != "--out"]
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv \
        else None
    if out in args:
        args.remove(out)
    path = os.path.abspath(args[0] if args else "miniwireshark.py")
    with open(path, "rb") as f:
        src = f.read()
    code = compile(src, path, "exec")
    want = executable_lines(code)
    hit = set()
    mon = sys.monitoring
    tool = mon.COVERAGE_ID

    def on_line(c, line):
        if c.co_filename == path:
            hit.add(line)
        return mon.DISABLE        # each line is reported once: cheap

    mon.use_tool_id(tool, "coverage_regions")
    mon.register_callback(tool, mon.events.LINE, on_line)
    mon.set_events(tool, mon.events.LINE)
    sys.argv = [path] + (args[1:] or ["--self-test"])   # e.g. --gui-test
    rc = 0

    def no_hard_exit(code=0):     # the app ends with os._exit: report first
        raise SystemExit(code)
    os._exit = no_hard_exit
    try:
        exec(code, {"__name__": "__main__", "__file__": path})
    except SystemExit as e:
        rc = e.code or 0
    finally:
        mon.set_events(tool, 0)
        mon.free_tool_id(tool)
    rows = []
    for name, a, b in regions(src.decode("utf-8", "replace")):
        lines = {ln for ln in want if a <= ln <= b}
        if lines:
            n = len(lines & hit)
            rows.append((n / len(lines), name, a, n, len(lines)))
    rows.sort()
    total = len(want & hit) / len(want)
    text = [f"# Self-test line coverage: {total:.1%} "
            f"({len(want & hit):,} of {len(want):,} lines; self-test exit "
            f"{rc})", "", "| Region | Line | Covered | Lines |",
            "|---|---|---|---|"]
    text += [f"| {name} | {a} | {p:.0%} | {n}/{t} |"
             for p, name, a, n, t in rows]
    report = "\n".join(text) + "\n"
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(report)
    sys.__stdout__.write(text[0] + "\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
