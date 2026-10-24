#!/usr/bin/env python3
"""Publish every archived MiniWireshark version as a GitHub release.

Run by .github/workflows/publish-archive-releases.yml (manual trigger).
For each entry in .github/archive-releases.json, oldest first:
  1. take the file from legacy/ or from git history (<commit>:<path>),
  2. check its SHA-256 against the manifest (stops on any mismatch),
  3. create the tag and the release with notes from .github/release-notes/
     and attach the file plus a .sha256 file.
Releases that already exist are left alone, so the job can be re-run.
Needs: git with full history (fetch-depth: 0), gh, GH_TOKEN.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                               text=True).strip()
MANIFEST = os.path.join(ROOT, ".github", "archive-releases.json")
NOTES = os.path.join(ROOT, ".github", "release-notes")
DRY = "--dry-run" in sys.argv


def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)


def file_bytes(source):
    if ":" in source and not os.path.exists(os.path.join(ROOT, source)):
        return subprocess.check_output(["git", "show", source], cwd=ROOT)
    with open(os.path.join(ROOT, source), "rb") as f:
        return f.read()


def release_exists(tag):
    r = subprocess.run(["gh", "release", "view", tag], capture_output=True)
    return r.returncode == 0


def main():
    with open(MANIFEST, encoding="utf-8") as f:
        entries = json.load(f)["releases"]
    work = tempfile.mkdtemp(prefix="mw-archive-")
    # verify everything first: nothing is published unless all files match
    staged = []
    for e in entries:
        data = file_bytes(e["source"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != e["sha256"]:
            sys.exit(f"{e['tag']}: sha256 {digest} != manifest {e['sha256']}")
        asset = os.path.join(work, e["asset"])
        with open(asset, "wb") as f:
            f.write(data)
        with open(asset + ".sha256", "w", encoding="ascii") as f:
            f.write(f"{digest}  {e['asset']}\n")
        target = subprocess.check_output(
            ["git", "rev-parse", e["target"] + "^{commit}"], cwd=ROOT,
            text=True).strip()
        staged.append((e, asset, target))
        print(f"verified {e['tag']:<14} {e['asset']:<30} {digest[:16]}")
    for e, asset, target in staged:
        if release_exists(e["tag"]):
            print(f"skip {e['tag']} (already released)")
            continue
        notes = os.path.join(NOTES, e["tag"] + ".md")
        cmd = ["gh", "release", "create", e["tag"], asset, asset + ".sha256",
               "--target", target, "--title", e["title"],
               "--notes-file", notes,
               "--latest=" + ("true" if e.get("latest") else "false")]
        if e.get("prerelease"):
            cmd.append("--prerelease")
        print(" ".join(cmd))
        if not DRY:
            run(*cmd)


if __name__ == "__main__":
    main()
