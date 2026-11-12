"""BISECT-JOB (5.3.4 CI round 5): remove before release, with the
text-size-bisect job in ci.yml.

Runs only the GUI test's text-size step (MW_GUI_ONLY) of each commit
given, interleaved: A B C, A B C, A B C, so each commit sees the same
runner at about the same time. Prints the busy and freeze numbers per run
and a table per commit. With two or more commits it is also a regression
guard, and fails (exit 1) when the last commit's median busy time is over
GUARD x the first commit's on the same runner, or when either has no
numbers. The first commit is a reference, not a target: it was already
slow, so the guard catches a step back, not a slow change."""
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


# audit 2026-11-12 (#18): 0.85 -> 0.80. Measured in 16 bisect jobs
# (windows-latest, Python 3.12 and 3.14, Nov 11-12): 0.65 to 0.73.
GUARD = 0.80


def judge(ref, head, ref_name="ref", head_name="head"):
    """(failed 0/1, verdict line) for the busy runs of the reference and
    the head commit."""
    if not ref or not head:
        return 1, "FAIL: no numbers for %s or %s" % (ref_name, head_name)
    ratio = statistics.median(head) / statistics.median(ref)
    failed = int(ratio > GUARD)
    return failed, "%s: %s is %.2f x %s (limit %.2f)" % (
        "FAIL" if failed else "PASS", head_name, ratio, ref_name, GUARD)


def self_check():
    """`--self-check` (run by CI before the measurement): the guard passes
    what was measured and fails a step back. -> 0 when it holds."""
    ref = [360.0, 365.0, 355.0, 350.0, 370.0, 362.0]
    cases = (
        ([r * 0.73 for r in ref], 0),   # the slowest ratio measured
        ([r * 0.82 for r in ref], 1),   # passed the old 0.85 guard
        ([r * 1.0 for r in ref], 1),    # the round 4-5 savings undone
        ([], 1),                        # no numbers
    )
    bad = 0
    for head, want in cases:
        got, line = judge(ref, head)
        print("%s (want %s)" % (line, "FAIL" if want else "PASS"))
        bad += got != want
    print("self-check %s" % ("failed" if bad else "passed"))
    return int(bool(bad))


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
    # regression guard (5.3.4): the head commit, last, must stay at most
    # GUARD x the first (reference) commit's median busy on the same
    # runner. Measured: 0.65 to 0.75 of f0c5932; undoing the round 4-5
    # savings would bring it back to about 1.0.
    verdict = ""
    ref = [b for bs, _f in runs[names[0]] for b in bs]
    head = [b for bs, _f in runs[names[-1]] for b in bs]
    failed = 0
    if len(names) > 1:
        failed, verdict = judge(ref, head, names[0], names[-1])
        print(verdict)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### Text-size change, Python %s, Tk %s\n\n%s\n" % (
                sys.version.split()[0], tk, table))
            f.write("\n%s\n" % verdict)
    return failed


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-check"]:
        sys.exit(self_check())
    sys.exit(main(sys.argv[1:]))
