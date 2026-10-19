import json, urllib.request, re
PLATS = {"win_amd64": [r"win_amd64"], "win_arm64": [r"win_arm64"],
         "macosx_arm64": [r"macosx_\d+_\d+_(arm64|universal2)"],
         "macosx_x86_64": [r"macosx_\d+_\d+_(x86_64|universal2)"],
         "linux_x86_64": [r"manylinux.*x86_64"], "linux_aarch64": [r"manylinux.*aarch64"]}
def pick(files, plat):
    pats = PLATS[plat]
    cands = []
    for f in files:
        fn = f["filename"]
        if not fn.endswith(".whl"): continue
        if "-none-any" in fn: cands.append((0, fn, f)); continue
        if not any(re.search(p, fn) for p in pats): continue
        tag = fn.split("-")[2:4]
        py, abi = tag[0], tag[1]
        ok = py == "cp314" and abi in ("cp314",) or abi == "abi3"
        if "t-" in fn.split("-")[3] or abi.endswith("t"): continue
        if not ok: continue
        score = 2 if py == "cp314" else 1
        if "musllinux" in fn: continue
        cands.append((score, fn, f))
    cands.sort(key=lambda c: (-c[0], c[1]))
    return cands[0][2] if cands else None
out = {}
for pkg in ("scapy", "psutil", "cryptography", "cffi", "pycparser"):
    d = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30))
    ver = d["info"]["version"]
    files = d["releases"][ver]
    out[pkg] = {"version": ver}
    for plat in PLATS:
        f = pick(files, plat)
        out[pkg][plat] = (f["filename"], f["digests"]["sha256"]) if f else None
print(json.dumps(out, indent=1))
