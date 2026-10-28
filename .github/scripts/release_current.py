#!/usr/bin/env python3
"""Publish the version on main as a GitHub release, then record it.

Run by .github/workflows/release.yml on every push to main.
  1. Read SCRIPT_VERSION from miniwireshark.py.
  2. Stop quietly unless CHANGELOG.md has a "## [<version>]" section
     (an "[Unreleased]" heading means the version isn't finished) and no
     release v<version> exists yet.
  3. Create tag and release v<version> on this commit, attach
     miniwireshark-<version>.py and its .sha256. Notes come from
     .github/release-notes/v<version>.md, or else the changelog section.
  4. Record it: archive manifest, docs/VERSIONS.md, README badge and
     version table. The workflow commits these files back to main.
A version with "-" in it (5.3.0-rc.1, 6.0.0-dev) is a pre-release.
Needs: git, gh, GH_TOKEN. --dry-run prints what it would do.
"""
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                               text=True).strip()
REPO_URL = "https://github.com/darkckillerc4/MiniWireshark"
DRY = "--dry-run" in sys.argv


def path(*parts):
    return os.path.join(ROOT, *parts)


def read(*parts):
    with open(path(*parts), encoding="utf-8") as f:
        return f.read()


def write(text, *parts):
    with open(path(*parts), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def changelog_section(changelog, version):
    """(date, body) of "## [version] — date", or None."""
    m = re.search(r"^## \[" + re.escape(version) + r"\][^\n\d]*(\d{4}-\d{2}-\d{2})?[^\n]*\n"
                  r"(.*?)(?=^## \[|\Z)", changelog, re.M | re.S)
    if not m:
        return None
    return m.group(1) or datetime.date.today().isoformat(), m.group(2).strip()


def summary_line(body):
    """The section's first sentence, for the README table."""
    for para in body.split("\n\n"):
        para = para.strip()
        if para and not para.startswith(("-", "*", "#", ">")):
            return para.split(". ")[0].rstrip(".")
    first = re.sub(r"^[-*]\s*", "", body.strip().splitlines()[0])
    return re.sub(r"[*`]", "", first).split(". ")[0].rstrip(".")


def release_exists(tag):
    r = subprocess.run(["gh", "release", "view", tag], capture_output=True)
    return r.returncode == 0


def record(version, date, body, digest, lines, commit):
    """Update the manifest, version index and README for the new release."""
    tag = "v" + version
    pre = "-" in version
    asset = f"miniwireshark-{version}.py"

    manifest = json.loads(read(".github", "archive-releases.json"))
    if not any(e["tag"] == tag for e in manifest["releases"]):
        if not pre:
            for e in manifest["releases"]:
                e.pop("latest", None)
        entry = {"tag": tag, "title": f"MiniWireshark {version}",
                 "target": commit[:7], "source": f"{commit[:7]}:miniwireshark.py",
                 "asset": asset, "sha256": digest, "prerelease": pre}
        if not pre:
            entry["latest"] = True
        manifest["releases"].append(entry)
        rows = ",\n".join("    " + json.dumps(e) for e in manifest["releases"])
        head = json.dumps({k: v for k, v in manifest.items() if k != "releases"})[1:-1]
        write("{\n  " + head + ",\n  \"releases\": [\n" + rows + "\n  ]\n}\n",
              ".github", "archive-releases.json")

    versions = read("docs", "VERSIONS.md")
    if f"releases/tag/{tag})" not in versions:
        link = f"[{tag}]({REPO_URL}/releases/tag/{tag})" + (" (pre-release)" if pre else "")
        name = version if pre else f"**{version}** (latest)"
        row = f"| {name} | {link} | {lines:,} | `{digest}` | `{commit[:7]}` |\n"
        if not pre:
            versions = re.sub(r"^\| \*\*([^*]+)\*\* \(latest\) \|", r"| \1 |", versions, flags=re.M)
        versions = re.sub(r"(^\|---[^\n]*\n)", lambda m: m.group(1) + row, versions, count=1, flags=re.M)
        write(versions, "docs", "VERSIONS.md")

    if pre:
        return
    readme = read("README.md")
    readme = re.sub(r'alt="Latest release [^"]+" src="https://img\.shields\.io/badge/release-[^-"]+-',
                    f'alt="Latest release {version}" src="https://img.shields.io/badge/release-{version}-',
                    readme)
    if f"| **{version}** (latest) |" not in readme:
        readme = re.sub(r"^\| \*\*([^*]+)\*\* \(latest\) \|", r"| \1 |", readme, flags=re.M)
        row = f"| **{version}** (latest) | {date} | {summary_line(body)} |\n"
        readme = re.sub(r"(^\| Version \| Date \| Highlights \|\n\|[^\n]*\n)",
                        lambda m: m.group(1) + row, readme, count=1, flags=re.M)
    write(readme, "README.md")


def main():
    src = read("miniwireshark.py")
    m = re.search(r'^SCRIPT_VERSION = "([^"]+)"', src, re.M)
    if not m:
        sys.exit("SCRIPT_VERSION not found in miniwireshark.py")
    version = m.group(1)
    tag = "v" + version
    section = changelog_section(read("CHANGELOG.md"), version)
    if section is None:
        print(f"{version}: no '## [{version}]' section in CHANGELOG.md yet, "
              "so it isn't released. Nothing to do.")
        return
    if not DRY and release_exists(tag):
        print(f"{tag} is already released. Nothing to do.")
        return
    date, body = section
    with open(path("miniwireshark.py"), "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    lines = data.count(b"\n")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()

    work = tempfile.mkdtemp(prefix="mw-release-")
    asset = os.path.join(work, f"miniwireshark-{version}.py")
    with open(asset, "wb") as f:
        f.write(data)
    with open(asset + ".sha256", "w", encoding="ascii") as f:
        f.write(f"{digest}  miniwireshark-{version}.py\n")
    notes_file = path(".github", "release-notes", tag + ".md")
    if os.path.exists(notes_file):
        notes = read(".github", "release-notes", tag + ".md")
    else:
        notes = (f"MiniWireshark **{version}** ({lines:,} lines).\n\n{body}\n\n---\n"
                 "**Run it:** download the `.py` file and run `python <file>` "
                 "(Python 3.8+ with Tk). Check the download against the attached "
                 f"`.sha256` file:\n\n```\n{digest}  miniwireshark-{version}.py\n```\n")
        notes_file = os.path.join(work, "notes.md")
        with open(notes_file, "w", encoding="utf-8") as f:
            f.write(notes)
    pre = "-" in version
    cmd = ["gh", "release", "create", tag, asset, asset + ".sha256",
           "--target", commit, "--title", f"MiniWireshark {version}",
           "--notes-file", notes_file, "--latest=" + ("false" if pre else "true")]
    if pre:
        cmd.append("--prerelease")
    print(" ".join(cmd))
    print(f"sha256 {digest}, {lines:,} lines, commit {commit[:7]}")
    if not DRY:
        subprocess.run(cmd, check=True)
    record(version, date, body, digest, lines, commit)
    print(f"recorded {tag} in the manifest, docs/VERSIONS.md and README.md")


if __name__ == "__main__":
    main()
