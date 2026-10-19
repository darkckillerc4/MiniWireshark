import os, sys, time, subprocess, tempfile
tmp = tempfile.mkdtemp(); os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging(); mw.load_scapy(); mw._patch_dialogs_for_tests()
cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
cfg.set("appearance.theme", os.environ.get("THEME","Light"))
root = mw.tk.Tk(); root.geometry("1580x980+0+0")
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
app.start_demo()
mw._gui_pump(root, 12)
app.mode_ui_var.set("Advanced"); app._on_ui_mode_change()
app._select_tab(os.environ.get("TAB","health"))
mw._gui_pump(root, 2.5)
subprocess.run(["import", "-window", "root", os.environ["OUT"]])
app._on_close()
