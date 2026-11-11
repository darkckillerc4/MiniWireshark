"""BISECT-JOB (5.3.4 CI round 5): remove before release, with the
text-size-bisect job in ci.yml.

Runs only the GUI test's text-size step (MW_GUI_ONLY) of each commit
given, interleaved: A B C, A B C, A B C, so each commit sees the same
runner at about the same time. Prints the busy and freeze numbers per run
and a table per commit. Never fails: it measures."""
import os
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

STEP = "Windows run: a text-size"
ROUNDS = 3
PAT = re.compile(r"text-size change: busy \[([^\]]*)\] ms, longest "
                 r"freeze \[([^\]]*)\] ms")
KEEP = ("text-size change:", "main thread,", "inside update()",
        "callbacks over", "[FAIL]", "Traceback", "Error")


def nums(text):
    return [float(x) for x in text.split(",") if x.strip()]


def main(commits):
    base = Path(os.environ.get("RUNNER_TEMP") or tempfile.mkdtemp())
    base = base / "text-size-bisect"
    names = [c[:7] for c in commits]
    for c, n in zip(commits, names):
        d = base / n
        d.mkdir(parents=True, exist_ok=True)
        src = subprocess.check_output(["git", "show", c + ":miniwireshark.py"])
        (d / "miniwireshark.py").write_bytes(src)
    tk = subprocess.run([sys.executable, "-c", "import tkinter; print("
                         "tkinter.Tcl().eval('info patchlevel'))"],
                        capture_output=True, text=True).stdout.strip()
    print("Python %s, Tcl/Tk %s" % (sys.version.split()[0], tk), flush=True)
    runs = {n: [] for n in names}
    for rnd in range(1, ROUNDS + 1):
        for n in names:
            d = base / n
            env = dict(os.environ, MW_GUI_ONLY=STEP, PYTHONIOENCODING="utf-8",
                       MINIWIRESHARK_DATA=str(d / ("data%d" % rnd)),
                       MINIWIRESHARK_CONFIG=str(d / ("config%d.json" % rnd)))
            try:
                p = subprocess.run(
                    [sys.executable, "-X", "faulthandler", "miniwireshark.py",
                     "--gui-test"], cwd=str(d), env=env, capture_output=True,
                    text=True, encoding="utf-8", errors="replace",
                    timeout=900)
                out = p.stdout + p.stderr
            except subprocess.TimeoutExpired as e:
                out = "timed out: %s" % e
            print("== round %d, %s" % (rnd, n), flush=True)
            for line in out.splitlines():
                if any(k in line for k in KEEP):
                    print("  " + line.strip()[:400], flush=True)
            m = PAT.search(out)
            if m:
                runs[n].append((nums(m.group(1)), nums(m.group(2))))
    rows = ["| commit | runs | busy ms, each run | busy median | busy min "
            "| freeze median |", "|---|---|---|---|---|---|"]
    for n in names:
        busy = [b for bs, _f in runs[n] for b in bs]
        frz = [f for _b, fs in runs[n] for f in fs]
        if not busy:
            rows.append("| %s | 0 | (no numbers) | | | |" % n)
            continue
        rows.append("| %s | %d | %s | %.1f | %.1f | %.1f |" % (
            n, len(busy), " / ".join(", ".join("%.0f" % b for b in bs)
                                     for bs, _f in runs[n]),
            statistics.median(busy), min(busy), statistics.median(frz)))
    table = "\n".join(rows)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### Text-size change, Python %s, Tk %s\n\n%s\n" % (
                sys.version.split()[0], tk, table))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
