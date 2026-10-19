import ast,sys,re,json,importlib.util,os
os.environ["MINIWIRESHARK_DATA"]="/tmp/mwscan"; sys.argv=["mw","--gui-test"]
spec=importlib.util.spec_from_file_location("mw","/home/claude/mw/miniwireshark.py")
mw=importlib.util.module_from_spec(spec); sys.modules["mw"]=mw; spec.loader.exec_module(mw)
src=open("/home/claude/mw/miniwireshark.py",encoding="utf8").read()
t=ast.parse(src)
# skip test functions
skip=set()
for n in t.body:
    if isinstance(n,ast.FunctionDef) and (n.name.startswith(("test_","_gs_","gui_test","self_test","run_self","bench","release"))): skip.add(n)
KEYS={"text","label","title","message","detail"}
FUN={"showinfo","showwarning","showerror","askyesno","askokcancel","askyesnocancel","askquestion","askretrycancel","askstring","askinteger","asksaveasfilename","askopenfilename","askdirectory","_set_banner","header","lbl","Tooltip","title","wm_title","add_command","add_cascade","add_checkbutton","add_radiobutton","section","_section"}
out=set()
def visit(node):
    for n in ast.walk(node):
        if isinstance(n,ast.Call):
            f=n.func; name=getattr(f,"attr",None) or getattr(f,"id",None)
            vals=[]
            for k in n.keywords:
                if k.arg in KEYS and isinstance(k.value,ast.Constant) and isinstance(k.value.value,str): vals.append(k.value.value)
            if name in FUN:
                for a in n.args[:2]:
                    if isinstance(a,ast.Constant) and isinstance(a.value,str): vals.append(a.value)
            for v in vals:
                if re.search(r"[A-Za-z]{3}",v): out.add(v)
for n in t.body:
    if n in skip: continue
    visit(n)
miss=sorted(s for s in out if mw._i18n_lookup(s,mw.I18N["fr"],"fr") is None and not re.fullmatch(r"[^A-Za-z]*[A-Za-z0-9.+_/-]+[^A-Za-z]*",s))
print(len(out),len(miss))
json.dump(miss,open("/home/claude/mw/scratch/i18n/static_miss.json","w"),ensure_ascii=False,indent=0)
