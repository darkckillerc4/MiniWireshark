import os, sys, subprocess, tempfile
tmp = tempfile.mkdtemp(); os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging(); mw.load_scapy(); mw._patch_dialogs_for_tests()
LOC=os.environ.get("LOC","fr"); OUT=os.environ["OUT"]
mw.set_locale(LOC)
cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False); cfg.set("general.language", mw.LOCALE_NAMES[LOC])
# welcome
r0 = mw.tk.Tk(); r0.geometry("760x680+0+0"); mw.base_ttk_style()
lw = mw.LoaderWindow(r0, cfg); lw.pack(fill="both", expand=True); r0.configure(background=lw.bg)
def snap():
    subprocess.run(["import", "-window", "root", OUT+"_welcome.png"]); lw.choice = "exit"
r0.after(2000, snap)
lw.show_welcome(summary="", health="healthy", first_time=True); r0.destroy()
root = mw.tk.Tk(); root.geometry("1500x940+0+0")
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
app.start_demo(); mw._gui_pump(root, 8)
subprocess.run(["import", "-window", "root", OUT+"_dash.png"])
app._select_tab("health"); mw._gui_pump(root, 1)
subprocess.run(["import", "-window", "root", OUT+"_health.png"])
app._open_settings("general"); mw._gui_pump(root, 1)
subprocess.run(["import", "-window", "root", OUT+"_settings.png"])
os._exit(0)
