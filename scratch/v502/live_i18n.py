"""French/Spanish check of texts that only appear while capturing live."""
import os
import sys
import re
import tempfile
import importlib.util

LANG = sys.argv[1] if len(sys.argv) > 1 else "fr"
os.environ["MINIWIRESHARK_DATA"] = tempfile.mkdtemp()
sys.argv = ["mw", "--gui-test"]
spec = importlib.util.spec_from_file_location(
    "mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec)
sys.modules["mw"] = mw
spec.loader.exec_module(mw)
mw.setup_logging()
mw._patch_dialogs_for_tests()
cfg = mw.AppConfig(path=os.path.join(tempfile.mkdtemp(), "c.json"))
cfg.set("general.auto_start_capture", False)
cfg.set("general.language", {"fr": "Français", "es": "Español"}[LANG])
root = mw.tk.Tk()
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
app._apply_runtime_settings()
tr = mw.translate_text
EN = re.compile(r"\b(the|is|are|and|watching|sending|network|devices?|"
                r"packets?|websites?|open|connections?|nothing|only|"
                r"listening|checking|before|haven't|yours|marked|busy|"
                r"slower|screen|refresh|quietly|looking|other|switched|"
                r"automatically|didn't|work|this|that|from|your)\b", re.I)
found = []


def chk(where, text):
    out = tr(text) if isinstance(text, str) else text
    for line in str(out).split("\n"):
        if EN.search(line) and line.strip():
            found.append((where, line[:160]))


class FakeSniffer:
    running = True
    exception = None


app.data_mode = "live"
app.current_iface_label = "eth0"
app.sniffer = FakeSniffer()
app.count = 1234
chk("status", app.status_text())
for prof in (None, {"name": "Maison", "trusted": False},
             {"name": "Maison", "trusted": True}):
    app.network_profile = prof
    app._restyle_mode_banner()
    chk(f"mode banner {prof}", app.mode_lbl.cget("text"))
    chk(f"mode button {prof}", app.mode_toggle_btn.cget("text"))
app.config.set("mode.active_scanning", False)
app._restyle_mode_banner()
chk("mode banner quiet", app.mode_lbl.cget("text"))
chk("footer", app.footer_text())
st, _bg, _fg = app.network_state_text()
chk("network state", st)
for k, (kind, title, fix, *_r) in getattr(mw, "CAPTURE_FAULTS",
                                          {}).items():
    chk(f"fault {k} title", title)
    chk(f"fault {k} fix", fix)
for k, v in app.health_summary().items():
    chk(f"health {k}", v[0])
    chk(f"health {k} text", v[1])
chk("banner start", "👀  Watching “eth0”. I'm in Quiet Mode, so I'm only "
                    "listening. ")
chk("banner start2", "👀  Watching “eth0”. I'm also quietly looking for "
                     "other devices on your network. ")
chk("banner switched", "👀  “eth1” didn't work, so I switched to “eth0” "
                       "automatically.")
app.sniffer = None
app.data_mode = "idle"
for line in sorted(set(found)):
    print(" | ".join(line))
print("total", len(set(found)))
