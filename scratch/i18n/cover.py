import os, sys, re, json, tempfile
tmp = tempfile.mkdtemp(); os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--gui-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
tk=mw.tk; ttk=mw.ttk
LOC=os.environ.get("LOC","fr")
miss=set()
def chk(s):
    if isinstance(s,str) and re.search(r"[A-Za-z]{2}",s) and mw.translate_text(s,LOC) == s:
        miss.add(s)
# static
for p in mw.SETTINGS_PAGES:
    for k in ("title","blurb"): chk(p.get(k))
    for sec in p.get("sections",[]):
        chk(sec.get("title"))
        for c in sec.get("controls",[]):
            for k in ("label","help","suffix","unit","text"): chk(c.get(k))
            ch=c.get("choices")
            if isinstance(ch,(list,tuple)):
                for x in ch: chk(x)
for s in mw.STRINGS["en"].values(): chk(s)
for q in mw.QUICK_START: chk(q[0]); chk(q[1]); chk(q[3])
for w in mw.LoaderWindow.WHATS_NEW: chk(w[1]); chk(w[2])
for s in mw.RuntimeManager.STAGES: chk(s)
for k,v in mw.REPAIR_STEPS: chk(v)
for v in mw.DATA_MODE_TEXT.values(): chk(v)
static=set(miss); miss.clear()
# runtime walk
mw.setup_logging(); mw.load_scapy(); mw._patch_dialogs_for_tests()
mw.set_locale(LOC)
cfg = mw.AppConfig(path=os.path.join(tmp, "c.json"))
cfg.set("general.auto_start_capture", False)
cfg.set("general.language", mw.LOCALE_NAMES[LOC])
root = mw.tk.Tk(); root.geometry("1580x980+0+0")
app = mw.MiniWireshark(root, "", set(), set(), "", config=cfg)
app.start_demo(); mw._gui_pump(root, 6)
def walk(r):
    st=[r]
    while st:
        w=st.pop()
        try: st.extend(w.winfo_children())
        except tk.TclError: continue
        try:
            if isinstance(w,(tk.Tk,tk.Toplevel)): miss_add(w.title())
            if isinstance(w,tk.Menu):
                e=w.index("end")
                for i in range(0 if e is None else e+1):
                    if w.type(i) in ("command","cascade","checkbutton","radiobutton"): miss_add(w.entrycget(i,"label"))
                continue
            if isinstance(w,ttk.Notebook):
                for t in w.tabs(): miss_add(w.tab(t,"text"))
            elif isinstance(w,ttk.Treeview):
                for c in ("#0",)+tuple(w["columns"]): miss_add(w.heading(c,"text"))
            elif isinstance(w,tk.Canvas):
                for it in w.find_all():
                    if w.type(it)=="text": miss_add(w.itemcget(it,"text"))
            if getattr(w, "_mw_i18n", None):
                for v in w._mw_i18n["values"]: miss_add("[combo] "+v) if mw.translate_text(v,LOC)==v and re.search(r"[A-Za-z]{2}",v) else None
            if "text" in w.keys():
                miss_add(w.cget("text"))
        except (tk.TclError,TypeError): pass
def miss_add(s):
    s=str(s)
    if s.startswith("[combo] "): miss.add(s); return
    if re.search(r"[A-Za-z]{2}",s) and s not in mw.I18N_REVERSE and mw.translate_text(s,LOC)==s:
        miss.add(s)
for tab in list(app.tabs):
    try: app._select_tab(tab); mw._gui_pump(root,0.4)
    except Exception as e: print("tab",tab,e)
    walk(root)
app._open_settings("general"); mw._gui_pump(root,0.5)
sw=app._settings_win
for p in mw.SETTINGS_PAGES:
    sw.show_page(p["id"]); mw._gui_pump(root,0.2); walk(root)
for fn in ("open_diagnostics","open_quick_start","open_ledger","repair_everything","open_runtime_manager"):
    try: getattr(app,fn)(); mw._gui_pump(root,1.0); walk(root)
    except Exception as e: print(fn,"ERR",e)
for which in ("slow","bandwidth"):
    try: app.investigate(which); mw._gui_pump(root,1.0); walk(root)
    except Exception as e: print("inv",e)
json.dump({"static":sorted(static),"runtime":sorted(miss)},open("/home/claude/mw/scratch/i18n/miss_%s.json"%LOC,"w"),ensure_ascii=False,indent=0)
print(len(static),len(miss))
os._exit(0)
