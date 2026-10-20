"""V5.0.2 bug hunt: drive every screen, record every exception and every
layout defect (clipped text, overlapping widgets, overlapping canvas text,
cut-off headings, notebook tabs that do not fit), and take screenshots.

usage: xvfb-run -a -s "-screen 0 1920x1080x24" python3.12 crawl.py \
           OUT_DIR LANG THEME WxH TEXTSIZE MODE [shots]
"""
import os
import sys
import json
import time
import tempfile
import logging
import traceback
import subprocess
import importlib.util
import faulthandler
faulthandler.dump_traceback_later(int(os.environ.get("FH", "100000")), repeat=True)

OUT, LANG, THEME, SIZE, TSIZE, MODE = sys.argv[1:7]
TSIZE = TSIZE.replace("_", " ")
SHOTS = len(sys.argv) > 7 and sys.argv[7] == "shots"
W, H = (int(x) for x in SIZE.split("x"))
os.makedirs(OUT, exist_ok=True)
tmp = tempfile.mkdtemp()
os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
spec = importlib.util.spec_from_file_location(
    "mw", os.environ.get("MW", "/home/claude/mw/miniwireshark.py"))
mw = importlib.util.module_from_spec(spec)
sys.modules["mw"] = mw
spec.loader.exec_module(mw)
mw.setup_logging()
mw.load_scapy()
mw._patch_dialogs_for_tests()
mw.filedialog.asksaveasfilename = lambda *a, **k: ""
tk, ttk = mw.tk, mw.ttk
tkfont = __import__("tkinter.font", fromlist=["font"])

ERRORS = []          # (where, kind, text)
ISSUES = []          # (where, kind, detail)
WHERE = ["startup"]


class Grab(logging.Handler):
    def emit(self, rec):
        if rec.levelno >= logging.WARNING:
            txt = rec.getMessage()
            if rec.exc_info:
                txt += "\n" + "".join(traceback.format_exception(
                    *rec.exc_info))
            ERRORS.append((WHERE[0], rec.levelname, txt))


logging.getLogger().addHandler(Grab())
logging.getLogger("miniwireshark").addHandler(Grab()) \
    if logging.getLogger("miniwireshark").propagate is False else None


def tk_exc(exc, val, tb):
    ERRORS.append((WHERE[0], "TkCallback",
                   "".join(traceback.format_exception(exc, val, tb))))


cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
cfg.set("general.show_welcome", False)
cfg.set("performance.mode", "Full Power")
cfg.set("performance.deep_runner", "Thread")
cfg.set("general.language", {"en": "English", "fr": "Français",
                             "es": "Español"}[LANG])
cfg.set("appearance.theme", THEME)
cfg.set("appearance.text_size", TSIZE)
cfg.set("appearance.beginner_mode", MODE == "beginner")
cfg.set("appearance.inspector", False)
root = tk.Tk()
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
app._tk_exception = tk_exc
root.report_callback_exception = tk_exc
app._apply_runtime_settings()
fr = mw.ScenarioBuilder().home_network() + \
    mw.ScenarioBuilder(t0=mw.SCENARIO_T0 + 2000).protocol_exchanges() + \
    mw.ScenarioBuilder(t0=mw.SCENARIO_T0 + 3000).mail_sessions()
pcap = os.path.join(tmp, "s.pcap")
mw.write_raw_pcap(pcap, fr)
WHERE[0] = "import"
app.import_pcap_path(pcap)
mw._gui_pump(root, 8)
app.deep.drain(20)
app.deep.flush(final=True)
mw._gui_pump(root, 1.5)

TEXTY = {"Label", "TLabel", "Button", "TButton", "Checkbutton",
         "TCheckbutton", "Radiobutton", "TRadiobutton", "Menubutton",
         "TMenubutton"}


def rect(w):
    return (w.winfo_rootx(), w.winfo_rooty(), w.winfo_width(),
            w.winfo_height())


def inter(a, b):
    x = max(a[0], b[0])
    y = max(a[1], b[1])
    x2 = min(a[0] + a[2], b[0] + b[2])
    y2 = min(a[1] + a[3], b[1] + b[3])
    return max(0, x2 - x) * max(0, y2 - y)


def wname(w):
    try:
        t = w.cget("text")
    except Exception:
        t = ""
    return f"{w.winfo_class()}[{str(t)[:50]!r}]@{str(w)[-40:]}"


def in_scroller(w):
    """Inside a canvas-window (scrolled frame) or a Text window."""
    p = w.master
    while p is not None:
        if isinstance(p, (tk.Canvas, tk.Text)):
            return True
        p = p.master
    return False


def visible_rect(w):
    """The part of w not clipped by its ancestors (up to the toplevel)."""
    r = rect(w)
    x, y, x2, y2 = r[0], r[1], r[0] + r[2], r[1] + r[3]
    p = w.master
    while p is not None:
        pr = rect(p)
        x, y = max(x, pr[0]), max(y, pr[1])
        x2, y2 = min(x2, pr[0] + pr[2]), min(y2, pr[1] + pr[3])
        if isinstance(p, (tk.Tk, tk.Toplevel)):
            break
        p = p.master
    return (x, y, max(0, x2 - x), max(0, y2 - y))


def text_of(w):
    try:
        t = str(w.cget("text"))
    except Exception:
        t = ""
    if not t:
        try:
            v = w.cget("textvariable")
            if v:
                t = str(w.getvar(v))
        except Exception:
            pass
    return t


def font_of(w, default="TkDefaultFont"):
    try:
        f = w.cget("font")
        if f:
            return tkfont.Font(root=root, font=f)
    except Exception:
        pass
    try:
        st = w.cget("style") or w.winfo_class()
        f = ttk.Style().lookup(st, "font")
        if f:
            return tkfont.Font(root=root, font=f)
    except Exception:
        pass
    return tkfont.nametofont(default)


def check(top, where):
    out = []
    stack = [top]
    while stack:
        w = stack.pop()
        try:
            if not w.winfo_ismapped() or not w.winfo_viewable():
                continue
            kids = [c for c in w.winfo_children()
                    if not isinstance(c, (tk.Toplevel, tk.Menu))]
        except tk.TclError:
            continue
        stack.extend(kids)
        cls = w.winfo_class()
        # 1. text widgets: clipped by their own size or by an ancestor
        if cls in TEXTY:
            t = text_of(w)
            if t.strip():
                r = rect(w)
                rw, rh = w.winfo_reqwidth(), w.winfo_reqheight()
                if r[2] > 1 and r[2] < rw - 3:
                    out.append(("clipped-width", wname(w),
                                f"{r[2]} < {rw}"))
                if r[3] > 1 and r[3] < rh - 3:
                    out.append(("clipped-height", wname(w),
                                f"{r[3]} < {rh}"))
                if not in_scroller(w):
                    v = visible_rect(w)
                    if r[2] > 4 and v[2] < r[2] - 3:
                        out.append(("cut-by-parent-x", wname(w),
                                    f"visible {v[2]} of {r[2]}"))
                    if r[3] > 4 and v[3] < r[3] - 3 and v[3] > 0:
                        out.append(("cut-by-parent-y", wname(w),
                                    f"visible {v[3]} of {r[3]}"))
                    if v[2] == 0 and r[2] > 4:
                        out.append(("hidden-off-parent", wname(w), ""))
                # wraplength wider than the widget → right side cut
                try:
                    wl = int(float(str(w.cget("wraplength")) or 0))
                except Exception:
                    wl = 0
                if False:
                    out.append(("wraplength>width", wname(w),
                                f"wrap {wl} > width {r[2]}"))
        # 2. sibling overlap
        if len(kids) > 1 and cls not in ("TPanedwindow", "Panedwindow",
                                         "TNotebook", "Canvas", "Text"):
            rs = []
            for c in kids:
                try:
                    if c.winfo_ismapped() and c.winfo_manager() in (
                            "pack", "grid", "place"):
                        rs.append((c, rect(c)))
                except tk.TclError:
                    pass
            for i in range(len(rs)):
                for j in range(i + 1, len(rs)):
                    a, b = rs[i][1], rs[j][1]
                    if a[2] * a[3] == 0 or b[2] * b[3] == 0:
                        continue
                    area = inter(a, b)
                    if area > 6:
                        out.append(("overlap", wname(rs[i][0]),
                                    f"with {wname(rs[j][0])} ({area}px²)"))
        # 3. canvas text overlaps
        if cls == "Canvas":
            try:
                items = [i for i in w.find_all()
                         if w.type(i) == "text" and
                         str(w.itemcget(i, "state")) != "hidden" and
                         w.itemcget(i, "text").strip()]
                boxes = [(i, w.bbox(i)) for i in items]
                boxes = [(i, b) for i, b in boxes if b]
                cw, ch = w.winfo_width(), w.winfo_height()
                sr = str(w.cget("scrollregion"))
                for k in range(len(boxes)):
                    i, b = boxes[k]
                    if not sr and (b[2] > cw + 2 or b[0] < -2):
                        out.append(("canvas-text-cut", f"{wname(w)}",
                                    repr(w.itemcget(i, "text")[:40])))
                    for m in range(k + 1, len(boxes)):
                        j, c = boxes[m]
                        ov = inter((b[0], b[1], b[2] - b[0], b[3] - b[1]),
                                   (c[0], c[1], c[2] - c[0], c[3] - c[1]))
                        if ov > 12:
                            out.append(("canvas-text-overlap", wname(w),
                                        f"{w.itemcget(i, 'text')[:30]!r} × "
                                        f"{w.itemcget(j, 'text')[:30]!r}"))
            except tk.TclError:
                pass
        # 4. treeview headings cut
        if cls == "Treeview":
            try:
                hf = tkfont.nametofont("TkHeadingFont")
                cols = list(w["columns"])
                show = str(w.cget("show"))
                if "tree" in show:
                    cols = ["#0"] + cols
                disp = w["displaycolumns"]
                if disp and disp[0] != "#all":
                    cols = [c for c in cols if c == "#0" or c in disp]
                for c in cols:
                    txt = str(w.heading(c, "text"))
                    cwid = int(w.column(c, "width"))
                    if txt and hf.measure(txt) + 10 > cwid:
                        out.append(("heading-cut", wname(w),
                                    f"{txt!r} needs {hf.measure(txt) + 10}"
                                    f" has {cwid}"))
            except tk.TclError:
                pass
        # 5. notebook tabs that do not fit
        if cls == "TNotebook" and str(w.cget("style")) != "Main.TNotebook":
            try:
                f = font_of(w, "TkDefaultFont")
                need = sum(f.measure(str(w.tab(t, "text"))) + 18
                           for t in w.tabs()
                           if str(w.tab(t, "state")) != "hidden")
                if need > w.winfo_width() + 2:
                    out.append(("tabs-overflow", wname(w),
                                f"need {need} have {w.winfo_width()}"))
            except tk.TclError:
                pass
        # 6. read-only combobox value wider than the box
        if cls == "TCombobox":
            try:
                t = w.get()
                f = font_of(w)
                if t and f.measure(t) + 26 > w.winfo_width() > 1:
                    out.append(("combo-cut", wname(w),
                                f"{t[:40]!r} {f.measure(t) + 26} > "
                                f"{w.winfo_width()}"))
            except tk.TclError:
                pass
    for kind, who, detail in out:
        ISSUES.append((where, kind, f"{who} {detail}"))
    return out


def toplevels():
    res = []
    stack = [root]
    while stack:
        w = stack.pop()
        for c in w.winfo_children():
            if isinstance(c, tk.Toplevel):
                res.append(c)
            stack.append(c)
    return res


SHOT_N = [0]


def shot(top, name):
    if not SHOTS:
        return
    try:
        top.update_idletasks()
        top.update()
        wid = top.winfo_id()
        frame = top.wm_frame() if hasattr(top, "wm_frame") else wid
        SHOT_N[0] += 1
        fn = os.path.join(OUT, f"{SHOT_N[0]:03d}_{name}.png".replace(
            "/", "_").replace(" ", "_").replace(":", ""))
        x, y, w, h = top.winfo_rootx(), top.winfo_rooty(), \
            top.winfo_width(), top.winfo_height()
        subprocess.run(["import", "-window", "root", "-crop",
                        f"{w}x{h}+{x}+{y}", fn], check=False,
                       timeout=20)
    except Exception as e:
        ERRORS.append((name, "shot", repr(e)))


def visit(name, action, top=None, pump=0.4, keep=False):
    WHERE[0] = name
    before = set(map(str, toplevels()))
    try:
        res = action()
    except Exception:
        ERRORS.append((name, "action", traceback.format_exc()))
        res = None
    mw._gui_pump(root, pump)
    new = [t for t in toplevels() if str(t) not in before]
    tops = new or [top or root]
    for t in tops:
        try:
            check(t, name)
            shot(t, name)
        except tk.TclError:
            pass
    if not keep:
        for t in new:
            try:
                t.destroy()
            except tk.TclError:
                pass
        mw._gui_pump(root, 0.05)
    return res


# ---------------------------------------------------------------------------
tabs = app.tabs
for name, tab in tabs.items():
    if getattr(tab, "advanced", False) and MODE == "beginner":
        continue
    visit(f"tab:{name}", lambda n=name: app._select_tab(n))
    subs = list(getattr(tab, "_sub_frames", {}) or [])
    for s in subs[1:]:
        visit(f"tab:{name}/{s}", lambda t=tab, s=s: t.show_subview(s))
        if name == "packets" and s == "Statistics":
            for k in mw.StatisticsView.KINDS:
                def stat(k=k):
                    tab.stats.kind_var.set(k)
                    tab.stats.refresh(force=True)
                visit(f"tab:packets/Statistics/{k}", stat)
    if subs:
        tab.show_subview(subs[0])

if MODE != "beginner":
    pt = app._select_tab("packets")
    pt.show_subview("Packets")
    row = next((d for d in app.all_rows if d.get("raw") and d.get("sport")),
               None)
    if row:
        visit("packets:selected", lambda: pt.select_no(row["no"]))
        for i, nb_tab in enumerate(("Text dump", "Hex dump")):
            pass
        visit("packets:follow", lambda: app.follow_stream(row["flow_id"]))
    visit("packets:fields", pt.open_fields)

m = app.model
devs = list(m.registry.by_key.values())
for d in devs[:4]:
    visit(f"device:{d.key}", lambda k=d.key: app.show_device(k))
sites = list(getattr(m, "websites", {}) or {})[:2]
for s in sites:
    visit(f"website:{s}", lambda s=s: app.show_website(s))
flows = list(m.flows.all_flows())[:3] if hasattr(m.flows, "all_flows") \
    else []
for f in flows:
    visit(f"flow:{f.fid}", lambda f=f: app.show_flow(f.fid))
rh = list(getattr(m, "remote_hosts", {}) or {})[:2]
for ip in rh:
    visit(f"remote:{ip}", lambda ip=ip: app.show_remote(ip))
for aid in list(m.alerts.alerts)[:3]:
    visit(f"alert:{aid}", lambda a=aid: app.show_alert(a))

for pid in [p["id"] for p in mw.SETTINGS_PAGES]:
    def opn(pid=pid):
        return app._open_settings(pid)
    visit(f"settings:{pid}", opn)

for fn in ("open_diagnostics", "open_storage", "open_privacy_posture",
           "open_components_center", "open_palette", "open_changes",
           "open_coverage", "open_networks_dialog", "open_corrections",
           "open_ledger", "open_runtime_manager", "open_boot_history",
           "open_quick_start", "export_shareable", "export_inventory",
           "open_compare"):
    f = getattr(app, fn, None)
    if f is not None:
        visit(f"dialog:{fn}", f)

# the window itself after everything
visit("main:final", lambda: app._select_tab("dash"))

json.dump({"errors": ERRORS, "issues": ISSUES,
           "config": [LANG, THEME, SIZE, TSIZE, MODE]},
          open(os.path.join(OUT, "result.json"), "w"), ensure_ascii=False,
          indent=1)
print("errors", len(ERRORS), "issues", len(ISSUES))
try:
    app._on_close()
except Exception:
    pass
