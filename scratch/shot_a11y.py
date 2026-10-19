import os, sys, time, subprocess, tempfile
tmp = tempfile.mkdtemp(); os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging(); mw.load_scapy(); mw._patch_dialogs_for_tests()
cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
cfg.set("accessibility.colorblind", "Red-green — deuteranopia (most common)")
cfg.set("appearance.theme", "Dark")
mw.set_colorblind_mode(cfg.get("accessibility.colorblind"))
root = mw.tk.Tk(); root.geometry("1580x980+0+0")
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
app.start_demo(); mw._gui_pump(root, 10)
app._select_tab("health"); mw._gui_pump(root, 1.5)
subprocess.run(["import", "-window", "root", os.environ["OUT"]])
app._open_settings("accessibility")
mw._gui_pump(root, 0.5)
mw._gui_pump(root, 1)
subprocess.run(["import", "-window", "root", os.environ["OUT2"]])
app._on_close()
