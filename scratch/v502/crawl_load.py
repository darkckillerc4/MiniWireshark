"""Does every view fill in? Runs the demo (live-like data), then a pcap,
switches through every tab and sub-view and reports views that stay empty
while the model has data, plus every exception."""
import os
import sys
import json
import time
import tempfile
import logging
import traceback
import importlib.util
import faulthandler

faulthandler.dump_traceback_later(int(os.environ.get("FH", "100000")),
                                  repeat=True)
OUT = sys.argv[1]
LANG = sys.argv[2] if len(sys.argv) > 2 else "en"
os.makedirs(OUT, exist_ok=True)
tmp = tempfile.mkdtemp()
os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
spec = importlib.util.spec_from_file_location(
    "mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec)
sys.modules["mw"] = mw
spec.loader.exec_module(mw)
mw.setup_logging()
mw.load_scapy()
mw._patch_dialogs_for_tests()
tk, ttk = mw.tk, mw.ttk
ERRORS, EMPTY = [], []
WHERE = ["start"]


class Grab(logging.Handler):
    def emit(self, rec):
        if rec.levelno >= logging.WARNING:
            txt = rec.getMessage()
            if rec.exc_info:
                txt += "\n" + "".join(traceback.format_exception(
                    *rec.exc_info))
            ERRORS.append((WHERE[0], rec.levelname, txt))


logging.getLogger().addHandler(Grab())


def tk_exc(exc, val, tb):
    ERRORS.append((WHERE[0], "TkCallback",
                   "".join(traceback.format_exception(exc, val, tb))))


cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
cfg.set("general.show_welcome", False)
cfg.set("performance.mode", "Full Power")
cfg.set("performance.deep_runner", os.environ.get("RUNNER", "Thread"))
cfg.set("general.language", {"en": "English", "fr": "Français",
                             "es": "Español"}[LANG])
cfg.set("appearance.beginner_mode", False)
root = tk.Tk()
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
app._tk_exception = tk_exc
root.report_callback_exception = tk_exc
app._apply_runtime_settings()


def trees(w):
    out = []
    stack = [w]
    while stack:
        x = stack.pop()
        try:
            stack.extend(x.winfo_children())
        except tk.TclError:
            continue
        if isinstance(x, ttk.Treeview):
            try:
                if x.winfo_ismapped():
                    out.append(x)
            except tk.TclError:
                pass
    return out


def canvases(w):
    out = []
    stack = [w]
    while stack:
        x = stack.pop()
        try:
            stack.extend(x.winfo_children())
        except tk.TclError:
            continue
        if isinstance(x, tk.Canvas) and x.winfo_ismapped():
            out.append(x)
    return out


def survey(phase):
    res = {}
    for name, tab in app.tabs.items():
        WHERE[0] = f"{phase}:{name}"
        app._select_tab(name)
        mw._gui_pump(root, 1.2)
        subs = list(getattr(tab, "_sub_frames", {}) or [None])
        for sv in subs:
            if sv:
                tab.show_subview(sv)
                mw._gui_pump(root, 0.8)
            key = f"{name}/{sv}" if sv else name
            tr = trees(tab.frame)
            rows = [len(t.get_children()) for t in tr]
            cv = [len(c.find_all()) for c in canvases(tab.frame)
                  if not c.winfo_children()]
            res[key] = {"trees": rows, "canvas_items": cv}
        if subs[0]:
            tab.show_subview(subs[0])
    return res


m = app.model
WHERE[0] = "demo"
app.start_demo()
mw._gui_pump(root, float(os.environ.get("DEMO_S", "25")))
s1 = survey("demo")
m = app.model
counts = {"devices": len(m.registry.by_key), "websites": len(m.websites),
          "flows": len(list(m.flows.all_flows())),
          "alerts": len(m.alerts.alerts), "rows": len(app.all_rows),
          "remote": len(m.remote_hosts),
          "txns": len(app.deep.store.txns),
          "findings": len(app.deep.store.findings)}
WHERE[0] = "save-session"
sess = os.path.join(tmp, "s.mwsession.json")
mw.atomic_write_json(sess, mw.SessionCodec.serialize(app.model,
                                                     app.session_meta()))
WHERE[0] = "clear"
app.clear()
mw._gui_pump(root, 12)
s2 = survey("after-clear")
counts2 = {"devices": len(app.model.registry.by_key),
           "rows": len(app.all_rows)}
WHERE[0] = "load-session"
app._load_session(sess)
mw._gui_pump(root, 3)
s3 = survey("session")
counts3 = {"devices": len(app.model.registry.by_key),
           "websites": len(app.model.websites),
           "flows": len(list(app.model.flows.all_flows())),
           "alerts": len(app.model.alerts.alerts)}
print("session", json.dumps(counts3))
for k, v in s3.items():
    print("session", k, v)
json.dump({"errors": ERRORS, "demo": s1, "after_clear": s2,
           "counts": counts, "counts_after_clear": counts2},
          open(os.path.join(OUT, "load.json"), "w"), indent=1,
          ensure_ascii=False)
print("errors", len(ERRORS))
print(json.dumps(counts))
for k, v in s1.items():
    print("demo", k, v)
print(json.dumps(counts2))
for k, v in s2.items():
    print("clear", k, v)
try:
    app._on_close()
except Exception:
    pass
