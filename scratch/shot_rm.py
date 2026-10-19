import os, sys, time, subprocess, tempfile
os.environ["MINIWIRESHARK_DATA"] = "/tmp/claude-0/rt314data"
sys.argv = ["mw", "--gui-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging(); mw.load_scapy(); mw._patch_dialogs_for_tests()
tmp = tempfile.mkdtemp()
cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
root = mw.tk.Tk(); root.geometry("1400x900")
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
w = app.open_runtime_manager(); w.geometry("+20+20")
mw._gui_pump(root, 8)
subprocess.run(["import", "-window", "root", os.environ["OUT"]])
d = app.open_diagnostics() if hasattr(app, "open_diagnostics") else None
mw._gui_pump(root, 6)
subprocess.run(["import", "-window", "root", os.environ["OUT2"]])
app._on_close()
