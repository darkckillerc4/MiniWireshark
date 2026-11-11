#!/usr/bin/env python3
"""Privacy check for the public repository.

MiniWireshark's repository is public, so anything committed is public
forever. This check fails CI when a tracked file contains something that
should never be published:

* captured network data or personal app data (sessions, captures, logs,
  the settings file, the networks and listening files);
* credentials (private keys and the common API-token formats);
* personal email addresses (webmail providers; example.* is fine);
* the developer's own folder on their PC;
* words on a private blocklist (personal names, the PC's name). The
  blocklist holds SHA-256 hashes of lower-case words, so this file does
  not publish the very words it protects. Add a word with:
      python .github/scripts/privacy_check.py --hash "word"

Run it with no arguments from the repository root. It prints each
finding as path:line: reason and exits 1 when there is any.
"""
import hashlib
import re
import subprocess
import sys

# Files that hold a user's own data. None of them belong in the repo.
BLOCKED_FILES = [
    (re.compile(r"\.mwsession(\.json)?$", re.I), "a saved session"),
    (re.compile(r"\.(pcap|pcapng|cap)$", re.I), "a packet capture"),
    (re.compile(r"(^|/)miniwireshark_config\.json(\.bak)?$", re.I),
     "the settings file"),
    (re.compile(r"(^|/)miniwireshark_data/", re.I), "the app's data folder"),
    (re.compile(r"(^|/)(networks|listening)\.json$", re.I),
     "a list of the networks or services seen"),
    (re.compile(r"\.log$", re.I), "a log file"),
    (re.compile(r"\.(pem|key|p12|pfx)$", re.I), "a key file"),
    (re.compile(r"(^|/)\.env$", re.I), "an environment file"),
]

SECRETS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "an AWS access key"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
     "a GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "a GitHub token"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "an Anthropic API key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "an API key"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "a Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "a Google API key"),
]

PERSONAL_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(gmail|googlemail|outlook|hotmail|live|msn|"
    r"yahoo|ymail|icloud|me|mac|aol|proton|protonmail|pm|gmx|mail|"
    r"videotron|sympatico|bell|rogers)\.[A-Za-z.]{2,}\b", re.I)

# The developer's own working folder on their PC.
LOCAL_FOLDER = re.compile(r"\b[A-Za-z]:[\\/]+!MiniWireshark\b", re.I)

# SHA-256 of lower-case words that must never appear (names, PC names).
BLOCKED_WORD_HASHES = {
    "d1ebabeb2345b17782c13cff68eeaac2480eac80bc6a1810b9a991dd2dbb524f",
    "7b0cdcd93f26eb13bab982633f76f8fd9ca7604d4d2a55a85da6b3f8c917493c",
    "bad7af7eb1c7efaa276088a82824338615cce595fc15d3349c943efd16e0db4a",
    "517a9a3638b376ef241897b9c389ea7d05c857711e88c59ddf75c21576394323",
    "be00770c04b59f94910de11bcfa0ecd800b4152870ded76be59f3ba12af4b38d",
}

WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{2,}")

# This file describes the patterns, so it is not scanned for them.
SELF = ".github/scripts/privacy_check.py"


def word_hash(word):
    return hashlib.sha256(word.lower().encode("utf-8")).hexdigest()


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True,
                         check=True).stdout
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def check_text(path, text):
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        for rx, why in SECRETS:
            if rx.search(line):
                found.append((path, n, why))
        if PERSONAL_EMAIL.search(line):
            found.append((path, n, "a personal email address"))
        if LOCAL_FOLDER.search(line):
            found.append((path, n, "a folder on the developer's PC"))
        for w in WORD.findall(line):
            for part in {w, *re.split(r"[_-]", w)}:
                if len(part) > 2 and word_hash(part) in BLOCKED_WORD_HASHES:
                    found.append((path, n, "a word on the private blocklist"))
    return found


def main(argv):
    if len(argv) == 3 and argv[1] == "--hash":
        print(word_hash(argv[2]))
        return 0
    findings = []
    for path in tracked_files():
        for rx, why in BLOCKED_FILES:
            if rx.search(path):
                findings.append((path, 0, why))
        if path == SELF:
            continue
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        if b"\0" in raw[:8192]:
            continue  # binary file
        findings += check_text(path, raw.decode("utf-8", "replace"))
    for path, n, why in findings:
        print(f"{path}:{n}: {why}")
    if findings:
        print(f"\nPrivacy check: {len(findings)} finding(s). The repository "
              "is public; remove these before merging.")
        return 1
    print("Privacy check: nothing personal or secret found.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
