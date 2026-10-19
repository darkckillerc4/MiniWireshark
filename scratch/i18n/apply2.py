P="/home/claude/mw/miniwireshark.py"
src=open(P,encoding="utf8").read()
def rep(old,new,cnt=1):
    global src
    n=src.count(old); assert n==cnt,(old[:70],n); src=src.replace(old,new)
rep('''              "help": "Only English exists today. The app is built so more "
                      "languages can be added without changing any code."},''',
'''              "help": "The language of every window, menu and message. "
                      "English, French and Spanish are included."},''')
rep('''    def _apply_locale(self):
        try:''','''    def _apply_locale(self):
        shown = getattr(self, "_locale_shown", "en")
        if shown != CURRENT_LOCALE:
            self._locale_shown = CURRENT_LOCALE
            i18n_retranslate(self.root)
        try:''')
rep('''    set_colorblind_mode(cfg.get("accessibility.colorblind", "Off"))
    root = tk.Tk()''','''    set_colorblind_mode(cfg.get("accessibility.colorblind", "Off"))
    set_locale(cfg.get("general.language", "English"))
    root = tk.Tk()''')
rep('''            tile.grid(row=0, column=i, sticky="nsew", padx=4)
            tiles.columnconfigure(i, weight=1)
            a = tk.Label(tile, text=f"{icon}  {title}", bg=self.card_bg,
                         fg=self.fg, font=("TkDefaultFont", 11, "bold"),
                         anchor="w")''','''            tile.grid(row=0, column=i, sticky="nsew", padx=4)
            tiles.columnconfigure(i, weight=1, uniform="tile")
            a = tk.Label(tile, text=f"{icon}  {translate_text(title)}",
                         bg=self.card_bg, fg=self.fg, wraplength=150,
                         font=("TkDefaultFont", 11, "bold"),
                         anchor="w", justify="left")''')
rep('''            tk.Label(news, text=f"{icon}  {title} — {text}",''',
'''            tk.Label(news, text=f"{icon}  {translate_text(title)} — "
                               f"{translate_text(text)}",''')
rep('''        self.footer.config(text="Enter = Start Monitoring · Tab moves "
                                "between choices · new networks start in "
                                "Quiet Mode")''','''        self.footer.config(text="Enter = Start Monitoring · Tab moves "
                                "between choices · new networks start in "
                                "Quiet Mode", wraplength=720,
                           justify="left")''')
open(P,"w",encoding="utf8").write(src); print("ok")
src=open(P,encoding="utf8").read()
import re
pats=[r"self\.sub_var = tk\.StringVar\(", r"self\.status_var = tk\.StringVar\(value=\"Starting …\"\)",
 r"self\.speed_var = tk\.StringVar\(value=\"\"\)", r"self\.geo_var = tk\.StringVar\(",
 r"self\.title_var = tk\.StringVar\(value=\"Inspector\"\)", r"self\.state_var = tk\.StringVar\(value=\"Getting started …\"\)",
 r"self\.status_var = tk\.StringVar\(\)", r"self\.info_var = tk\.StringVar\(", r"self\.note_var = tk\.StringVar\(\)",
 r"self\.err_var = tk\.StringVar\(\)", r"self\.ind_var = tk\.StringVar\(", r"self\.count_var = tk\.StringVar\(\)",
 r"self\.status_var = tk\.StringVar\(\n", r"self\.footer_var = tk\.StringVar\(", r"sum_var = tk\.StringVar\(\)",
 r"self\.result_var = tk\.StringVar\(\)", r"            v = tk\.StringVar\(value=\"—\"\)\n            vl = tk\.Label\(card"]
total=0
for p in pats:
    new_src,n=re.subn(p,lambda m:m.group(0).replace("tk.StringVar(","DisplayVar("),src)
    assert n>=1,(p,n); total+=n; src=new_src
print("displayvars",total)
open(P,"w",encoding="utf8").write(src)
src=open(P,encoding="utf8").read()
t=open("/home/claude/mw/scratch/i18n/tests.py",encoding="utf8").read()
rep("def bench_report(seconds=2.0):", t+"def bench_report(seconds=2.0):")
g=open("/home/claude/mw/scratch/i18n/gui_step.py",encoding="utf8").read()
rep('@gui_test_step("network consent: new network is quiet until trusted")', g+'@gui_test_step("network consent: new network is quiet until trusted")')
rep('''                                values=("Beginner", "Advanced"), width=9,''','''                                values=("Beginner", "Advanced"), width=12,''')
open(P,"w",encoding="utf8").write(src); print("tests in")
src=open(P,encoding="utf8").read()
rep('''        ttk.Button(bar, text="Session ▾",
                   command=self._open_session_menu).pack(side="right")
        ttk.Button(bar, text="Export ▾",
                   command=self._open_export_menu).pack(side="right",
                                                        padx=(0, 6))
        self.clear_btn = ttk.Button(bar, text=tr("btn_clear"),
                                    command=self.clear)''','''        ttk.Button(bar, text="Session ▾", width=-8,
                   command=self._open_session_menu).pack(side="right")
        ttk.Button(bar, text="Export ▾", width=-8,
                   command=self._open_export_menu).pack(side="right",
                                                        padx=(0, 6))
        self.clear_btn = ttk.Button(bar, text=tr("btn_clear"), width=-8,
                                    command=self.clear)''')
rep('''        self.iface_box = ttk.Combobox(bar, textvariable=self.iface_var,
                                      width=30, state="readonly")''','''        self.iface_box = ttk.Combobox(bar, textvariable=self.iface_var,
                                      width=26, state="readonly")''')
open(P,"w",encoding="utf8").write(src); print("bar")
src=open(P,encoding="utf8").read()
rep('''            tk.Label(row, text=title, bg="#f6f7fa", fg="#222222", width=26,
                     anchor="w", font=("TkDefaultFont", 10, "bold")).pack(
                side="left")''','''            tk.Label(row, text=title, bg="#f6f7fa", fg="#222222", width=26,
                     anchor="w", justify="left", wraplength=210,
                     font=("TkDefaultFont", 10, "bold")).pack(side="left")''')
open(P,"w",encoding="utf8").write(src); print("health")
src=open(P,encoding="utf8").read()
rep('''        """Grey hint text inside an empty entry that vanishes on focus."""
        state = {"on": False}''','''        """Grey hint text inside an empty entry that vanishes on focus."""
        state = {"on": False}
        text = translate_text(text)''')
open(P,"w",encoding="utf8").write(src); print("placeholder")
