# Version index

Every MiniWireshark release is a single Python file. The table lists each archived version with its SHA-256 checksum, so any copy can be checked with `sha256sum` (Linux/macOS) or `Get-FileHash -Algorithm SHA256` (Windows PowerShell).

| Version | Release | Lines | SHA-256 | Source |
|---|---|---:|---|---|
| **5.1.2** (latest) | [v5.1.2](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.1.2) | 66,318 | `2adadab93ce4f86938cd45e82be2f824163090fc660732b21ce8048efe327534` | `304948d` |
| 5.1.2-rc.5 | [v5.1.2-rc.5](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.1.2-rc.5) (pre-release) | 64,605 | `6ac76e5e6655b66205cccba6100bfe1f23ba899b3e35e92797a0f0df23c11ff7` | `759be4b` |
| 5.0.2 | [v5.0.2](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.2) | 52,410 | `77c1909a1451db4d1a60fd5a520a09be5df182ed8f4314cedcc85f7746bb6f67` | `49471fe` |
| 5.0.1 | [v5.0.1](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.1) | 50,509 | `f55e195e21610e18d8b0b4c8f80e5bf74fd19d6840aedc54c6a4b02aa87cb93b` | `f1f0e24` |
| 5.0.0 | [v5.0.0](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.0) | 49,659 | `a3611b403590bc241cb226e7b128291e7520ae2d89575744ed6f81b7fd7b809d` | `fa4f89c` |
| 4.0.0 | [v4.0.0](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v4.0.0) | 36,960 | `c9ee1c75f7daae3adfcc8d488493b3f1c1f5bce27742722db29fa82283ed4ec9` | `a1a49f7` |
| 4.0.0-dev | [v4.0.0-dev](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v4.0.0-dev) (pre-release) | 28,610 | `0e4ec9d95ed292e8db9e9e11efd8a6dd06cde304a0b43f0aa76535f744564aea` | `c276fbb` |
| 3.0.0 | [v3.0.0](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v3.0.0) | 18,715 | `278e8b1ea368315307875456f31bbb5917dcca55c837002891c6fa3f6cdfb871` | `786f4a0` |
| 2.0.0 | [v2.0.0](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v2.0.0) | 7,267 | `950c342063a9c79026836fade381cd4b9abadfaf62f182f51f5ac6872c2879e8` | [`legacy/`](../legacy/miniwireshark-2.0.0.py) |
| 1.x | [v1.0.0](https://github.com/darkckillerc4/MiniWireshark/releases/tag/v1.0.0) | 2,726 | `01c01cf7d954f71e0e6e4cfeef4fd5cb47699e44226fbd0cfab289058116ebf0` | [`legacy/`](../legacy/miniwireshark-1.0.0.py) |

The checksums match the owner's offline archive (`All_MiniWireshark_Version`).

- Versions 1.x and 2.0.0 come from before this repository's history; their files are in [`legacy/`](../legacy/).
- Every other version is taken straight from the listed commit.

## How the releases are published

All ten versions are published on the [releases page](https://github.com/darkckillerc4/MiniWireshark/releases), each with its `.py` file and a `.sha256` file. 5.1.2 is marked *latest*; 4.0.0-dev and 5.1.2-rc.5 are pre-releases.

They were created by the **Publish archived releases** workflow, which only runs when started by hand:

1. Open **Actions → Publish archived releases → Run workflow** on `main`.
2. Optionally tick **dry run** first: it checks every file against the checksums above and prints what it would publish.
3. Run it for real. It checks every file first and publishes nothing if one doesn't match. Then it creates each tag and release, oldest first.

Releases that already exist are skipped, so the workflow can be run again safely, for example after adding a new version. The list lives in [`.github/archive-releases.json`](../.github/archive-releases.json), and the notes in [`.github/release-notes/`](../.github/release-notes/).

### Adding a new version

1. Add an entry to `.github/archive-releases.json` with its tag, commit, source path and SHA-256.
2. Add its notes as `.github/release-notes/<tag>.md`, and move `"latest": true` to it.
3. Add a row to the table above and a section to the [changelog](../CHANGELOG.md).
4. After the change is merged, run the workflow.
