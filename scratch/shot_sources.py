import os, sys, time, subprocess, tempfile
tmp = tempfile.mkdtemp(); os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging(); mw.load_scapy(); mw._patch_dialogs_for_tests()
cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
root = mw.tk.Tk(); root.geometry("1580x980+0+0")
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
httpd, url, calls, t0 = mw._fake_helper("pihole")
ident = mw.scenario_identity(); m = app._new_model(identity=ident[:3]); m.set_identity(local_nets=ident[3]); app.replace_model(m)
app.data_mode = "live"
sink = app.lossless_sink()
for raw, _t, lt in mw.ScenarioBuilder().home_network(): sink(raw, time.time(), lt)
mw._gui_pump(root, 2)
app.vault.backend="file"
app.connector_save({"kind":"pihole","name":"Pi-hole","url":url,"verify":True,"enabled":True}, "s3cret-Pw!")
app.connectors.poll_now()
mw._gui_pump(root, 3)
app.mode_ui_var.set("Advanced"); app._on_ui_mode_change()
app._select_tab(os.environ.get("TAB","sources")); mw._gui_pump(root, 1.5)
subprocess.run(["import", "-window", "root", os.environ["OUT"]])
w = app.connector_dialog(kind="adguard"); w.geometry("+500+200"); mw._gui_pump(root, 1)
subprocess.run(["import", "-window", "root", os.environ["OUT2"]])
app._on_close(); httpd.shutdown()
