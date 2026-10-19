P = "/home/claude/mw/miniwireshark.py"
src = open(P, encoding="utf8").read()
def rep(old, new, cnt=1):
    global src
    n = src.count(old); assert n == cnt, (old[:80], n); src = src.replace(old, new)
a = src.index("        missing = []\n        for dep in DEPENDENCY_MANIFEST:\n            if not _module_ok(dep[\"import\"]):")
b = src.index("    def _repair_reference(self):")
src = src[:a] + '''        msgs, bad = [], []
        for key in PRIVATE_PACKAGES.verify():
            if key in PURE_WHEELS:
                continue                       # reinstalled just below
            PRIVATE_PACKAGES.remove(key)
            msgs.append(f"{key}: damaged, removed (reinstall it from "
                        f"Settings → Components)")
        for dep in DEPENDENCY_MANIFEST:
            if not dep["required"]:
                continue
            ok, info = _required_ready(dep)
            if ok and dep["key"] not in PRIVATE_PACKAGES.verify():
                continue
            try:
                PRIVATE_PACKAGES.install_pure(dep["key"])
                PRIVATE_PACKAGES.activate()
                ok, info = _required_ready(dep)
            except Exception as e:                   # noqa: BLE001
                ok, info = False, f"{type(e).__name__}: {str(e)[:160]}"
            (msgs if ok else bad).append(
                f"{dep['pip']} {'installed into the private packages '
                                'folder' if ok else 'failed: ' + info}")
        missing_opt = [d["pip"] for d in DEPENDENCY_MANIFEST
                       if not d["required"] and not _module_ok(d["import"])]
        if not msgs and not bad:
            return "ok", ("All components import correctly." +
                          (f" Optional, not installed: "
                           f"{', '.join(missing_opt)} (Settings → "
                           f"Components)." if missing_opt else ""))
        return ("failed" if bad else "fixed"), "; ".join(msgs + bad) + \\
            (" — restart MiniWireshark to use them." if not bad else "")

''' + src[b:]
a = src.index("        def work():\n            msgs = []\n            for dep in DEPENDENCY_MANIFEST:\n                ok, err = _pip_install(")
b = src.index("            npcap = \"\"\n            if IS_WINDOWS and not _npcap_present():")
src = src[:a] + '''        def work():
            msgs = []
            for dep in DEPENDENCY_MANIFEST:
                try:
                    if dep["key"] in PURE_WHEELS:
                        _n, ver = PRIVATE_PACKAGES.install_pure(dep["key"])
                    elif dep["key"] in PRIVATE_PACKAGES.installed():
                        ver = PRIVATE_PACKAGES.pip_install(dep["key"])
                    else:
                        msgs.append(f"{dep['pip']}: optional, not "
                                    f"installed (Settings → Components)")
                        continue
                    msgs.append(f"{dep['pip']} {ver}: ok")
                except Exception as e:               # noqa: BLE001
                    msgs.append(f"{dep['pip']}: failed ({str(e)[-160:]})")
''' + src[b:]
rep('''                "Reinstall/upgrade the packet capture engine (scapy) and "
                "optional helpers now? This needs an Internet connection and "
                "may take a minute. MiniWireshark keeps running.",''',
    '''                "Reinstall the packet capture engine (scapy) and the "
                "optional packages you installed, into MiniWireshark's own "
                "packages folder? This needs an Internet connection and "
                "may take a minute. Your Python is not changed. "
                "MiniWireshark keeps running.",''')
rep('''    def reset(self):
        """Delete the whole folder (all private packages)."""''', '''    def verify(self):
        """Names whose files are missing from the folder."""
        bad = []
        for key, info in self.installed().items():
            entries = info.get("entries") or []
            if not entries or not all(os.path.lexists(
                    os.path.join(self.root, e)) for e in entries):
                bad.append(key)
        return bad

    def reset(self):
        """Delete the whole folder (all private packages)."""''')
# drop _pip_available (unused) and stale catalog lines
a = src.index("def _pip_available():")
b = src.index("\n\n\n", a) + 3
src = src[:a] + src[b:]
import re
for start in ("Your Python is managed by the operating system, which normally doesn't want",
              "Your Python is managed by the operating system. Install the missing components"):
    a = src.index(start); b = src.index("\n", a) + 1
    src = src[:a] + src[b:]
open(P, "w", encoding="utf8").write(src)
print("m1b applied")
