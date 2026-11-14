# Contributing to MiniWireshark

Thanks for helping. A few rules keep an 89,000-line single-file app healthy.

## House rules

1. **One file.** The application stays in `miniwireshark.py`. Every region starts with a banner (`# ====` then `#  <id>.  <title>`), and the docstring's table of contents must list it; a self-test checks this.
2. **No new dependencies** without a stated reason. Optional packages are installed into MiniWireshark's private folder, never into the system Python.
3. **Every fix comes with a regression test** in the self-test (region 20b) or the GUI test (region 20c).
4. **Privacy defaults never get weaker.** Everything that sends traffic goes through `outbound()`. Secrets are dropped inside parsers.
5. **The window must not freeze.** Slow work belongs on a worker thread or in a background job. The benchmark budgets (`--bench-gui`) must still pass.
6. **Python 3.8+** must keep working (`vermin` reports 3.7 as the syntax floor).

## Before opening a pull request

```bash
python -m py_compile miniwireshark.py
python miniwireshark.py --self-test
xvfb-run -a python miniwireshark.py --gui-test     # if you touched the window
python -m pyflakes miniwireshark.py               # no new findings
python .github/scripts/privacy_check.py           # nothing personal or secret
python .github/scripts/docs_check.py              # links, headings, images
python .github/scripts/reference_docs.py --check  # alert and field pages
```

If you change an alert's text or a packet field, run `python .github/scripts/reference_docs.py` to rewrite [docs/ALERTS.md](docs/ALERTS.md) and [docs/FIELDS.md](docs/FIELDS.md). CI fails when they are out of date. The repository's `.editorconfig` keeps line endings and whitespace the way the docs check expects.

The repository is public. Commit with your GitHub no-reply address (GitHub → Settings → Emails → *Keep my email addresses private*); CI checks the addresses on a pull request's commits.

Use private data folders for test runs, so you never mix test data with your own:

```bash
MINIWIRESHARK_DATA=/tmp/mw-data MINIWIRESHARK_CONFIG=/tmp/mw-config.json python miniwireshark.py --self-test
```

Never commit captures, sessions, logs or `miniwireshark_config.json`. They can contain your network's addresses, and `.gitignore` already excludes them.

## Reporting bugs

Use the issue templates. A **debug bundle** from the Diagnostics window masks addresses and secrets and is the most useful thing you can attach.

## Releasing

Releases are automatic. While you work, collect changes under a `## [Unreleased] — x.y.z` heading at the top of `CHANGELOG.md`; the Release workflow skips a version whose heading still says Unreleased. To release, set `SCRIPT_VERSION` in `miniwireshark.py`, change the heading to `## [x.y.z] — YYYY-MM-DD`, and merge to `main`. The **Release** workflow publishes the `.py` file and its `.sha256`, and records the version in the README and [docs/VERSIONS.md](docs/VERSIONS.md). Notes come from `.github/release-notes/vx.y.z.md` if you write one, otherwise from the changelog.
