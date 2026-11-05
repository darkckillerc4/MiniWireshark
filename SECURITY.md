# Security policy

MiniWireshark reads network traffic, so security and privacy problems are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private reporting instead: open the **Security** tab, then **Report a vulnerability**. If that isn't available, contact the maintainer through their GitHub profile.

Please include:

- The MiniWireshark version (*Help → About*, or the first line of `--self-test`), your OS and your Python version.
- What happens and how to reproduce it.
- Any data that could leak. **Do not attach real packet captures or logs that contain your network's addresses or credentials.** Use Demo Mode or the built-in redaction (shareable reports with pseudonyms) instead.

## Scope

In scope:

- Anything that could send data off the computer without going through the outbound gate.
- Leaks of credentials or message bodies into reports, sessions, logs, history or the clipboard.
- Unsafe update or data-pack verification (Ed25519 signatures).
- An update check that follows a link off GitHub, or a way to make the app show or open a download page other than `https://github.com/<source>/releases/tag/<version>`.
- Privilege problems in the Windows elevation and Npcap install path, the Linux and macOS capture-permission prompt, and the data folder's ownership and permission checks.

Out of scope: monitoring a network you are not allowed to monitor. MiniWireshark is a defensive tool for your own networks.

## Where updates come from

Official releases are published only at <https://github.com/darkckillerc4/MiniWireshark/releases>. Copies offered on other sites may be fake or changed.

- By default MiniWireshark checks that page **once a day**: one request to `api.github.com` for the latest release number. Nothing about you, your computer or your network is sent. It goes through the outbound gate, so the kill switch stops it, and it does not run in Safe Mode or while you work offline (a capture file, a saved session or the demo). Turn it off in **Settings → Updates & Dependencies**.
- Any link in GitHub's answer is used only when it is `https` on `github.com`, `api.github.com`, `objects.githubusercontent.com` or `release-assets.githubusercontent.com`; anything else is ignored and logged. The page you are shown is built by the app from the source and the version number.
- You can type another `owner/name` source. Settings and every update message then say *Unofficial update source*.
- Nothing is installed unless it is signed with a release key built into your copy. Without one, you are told that a new version is out and download it yourself from the official page.

## Supported versions

Only the latest release receives fixes. Older versions are kept on the Releases page for reference.
