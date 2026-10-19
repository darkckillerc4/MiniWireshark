import os, sys, time, subprocess, tempfile
tmp = tempfile.mkdtemp(); os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging(); mw.load_scapy(); mw._patch_dialogs_for_tests()
cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
theme = os.environ.get("THEME", "Light")
cfg.set("appearance.theme", theme)
cfg.set("appearance.beginner_mode", os.environ.get("MODE","Beginner")=="Beginner")
root = mw.tk.Tk()
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
ident = mw.scenario_identity()
m = app._new_model(identity=ident[:3]); m.set_identity(local_nets=ident[3]); app.replace_model(m)
app.data_mode = "live"
sink = app.lossless_sink()
for raw, _t, lt in mw.ScenarioBuilder().home_network(): sink(raw, time.time(), lt)
mw._gui_pump(root, 2.5)
tab = os.environ.get("TAB", "dash")
app._select_tab(tab)
if tab == "devices":
    app.tabs["devices"].rebuild(); app.tabs["devices"].select(mw.ScenarioBuilder.PHONE[1])
mw._gui_pump(root, 1.5)
root.update()
wid = root.winfo_id()
subprocess.run(["import", "-window", "root", os.environ.get("OUT", "/tmp/shot.png")])
app._on_close()
