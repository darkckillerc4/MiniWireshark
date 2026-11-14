#!/usr/bin/env python3
"""Docs check for the repository's Markdown pages.

Fails CI when a tracked Markdown file has:

* a relative link to a file that does not exist;
* a link to a heading (#anchor) that the target page does not have;
* an image that does not exist, or an image with no alt text in the
  README and docs pages (screen readers need it);
* trailing spaces, tabs, Windows line endings or a missing final newline.

External links (http, https, mailto) are not fetched, so the check needs no
network. Run it from the repository root. It prints path:line: reason for
each finding and exits 1 when there is any. Plans under docs/plans are
working notes and are only checked for links.
"""
import os
import re
import subprocess
import sys
import unicodedata

LINK = re.compile(r"(!?)\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_SRC = re.compile(r"<(img|a)\b[^>]*\b(src|href)=\"([^\"]+)\"", re.I)
HTML_ALT = re.compile(r"\balt=\"", re.I)
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")
EXPLICIT_ANCHOR = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"", re.I)


def slug(text):
    """GitHub's heading anchor: lower case, markup removed, spaces to
    hyphens, punctuation other than hyphens and underscores dropped."""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "").replace("*", "")
    text = text.strip().lower()
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "-_" or ch.isalnum():
            out.append(ch)
        elif ch == " ":
            out.append("-")
        elif cat.startswith(("L", "N")):
            out.append(ch)
    return "".join(out)


def anchors(path, cache={}):
    if path not in cache:
        found, seen, fenced = set(), {}, False
        with open(path, encoding="utf-8") as f:
            for line in f:
                if FENCE.match(line):
                    fenced = not fenced
                    continue
                if fenced:
                    continue
                found.update(EXPLICIT_ANCHOR.findall(line))
                m = HEADING.match(line)
                if m:
                    s = slug(m.group(2))
                    n = seen.get(s, 0)
                    seen[s] = n + 1
                    found.add(s if n == 0 else f"{s}-{n}")
        cache[path] = found
    return cache[path]


def tracked_markdown():
    out = subprocess.run(["git", "ls-files", "-z", "*.md"],
                         capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def check_target(src, target, line_no, is_image):
    found = []
    if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
        return found  # http, https, mailto: not fetched
    path_part, _, frag = target.partition("#")
    if path_part:
        dest = os.path.normpath(os.path.join(os.path.dirname(src),
                                             path_part))
        if not os.path.exists(dest):
            what = "image" if is_image else "link"
            return [(src, line_no, f"{what} to a missing file: {target}")]
    else:
        dest = src
    if frag and dest.endswith(".md") and os.path.isfile(dest):
        if frag.lower() not in anchors(dest):
            found.append((src, line_no, f"link to a missing heading: "
                                        f"{target}"))
    return found


def check_file(path):
    found = []
    strict = True
    with open(path, "rb") as f:
        raw = f.read()
    if strict:
        if b"\r\n" in raw:
            found.append((path, 0, "Windows line endings (CRLF)"))
        if raw and not raw.endswith(b"\n"):
            found.append((path, 0, "no newline at the end of the file"))
    fenced = False
    for n, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if strict and line != line.rstrip(" \t"):
            found.append((path, n, "trailing spaces or tabs"))
        if fenced:
            continue
        code_free = re.sub(r"`[^`]*`", "", line)
        for bang, text, target in LINK.findall(code_free):
            found += check_target(path, target, n, bool(bang))
            if strict and bang and not text.strip() and \
                    not path.startswith(".github/"):
                found.append((path, n, "image with no alt text"))
        for m in HTML_SRC.finditer(code_free):
            tag, _, target = m.groups()
            found += check_target(path, target, n, tag.lower() == "img")
            if strict and tag.lower() == "img":
                tag_text = code_free[m.start():code_free.find(">", m.start())]
                if not HTML_ALT.search(tag_text):
                    found.append((path, n, "image with no alt attribute"))
    return found


def main():
    findings = []
    for path in tracked_markdown():
        findings += check_file(path)
    for path, n, why in findings:
        print(f"{path}:{n}: {why}")
    if findings:
        print(f"\nDocs check: {len(findings)} finding(s).")
        return 1
    print("Docs check: every link, heading and image is in place.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
