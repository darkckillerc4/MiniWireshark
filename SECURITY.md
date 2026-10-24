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
- Privilege problems in the Windows elevation and Npcap install path.

Out of scope: monitoring a network you are not allowed to monitor. MiniWireshark is a defensive tool for your own networks.

## Supported versions

Only the latest release receives fixes. Older versions are kept on the Releases page for reference.
