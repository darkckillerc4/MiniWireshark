import sys
P="/home/claude/mw/miniwireshark.py"
src=open(P,encoding="utf8").read()
def rep(old,new,cnt=1):
    global src
    n=src.count(old); assert n==cnt,(old[:60],n); src=src.replace(old,new)
rows=[]
for f in sys.argv[1:]:
    for l in open(f,encoding="utf8"):
        l=l.rstrip("\n")
        if not l: continue
        p=l.split("\t"); assert len(p)==3,l
        rows.append(" ¦ ".join(p))
cat="\n".join(rows)
assert '"""' not in cat and "\\" not in cat
block=open("/home/claude/mw/scratch/i18n/code_block.py",encoding="utf8").read().replace("@@CATALOG@@",cat)
if "I18N_CATALOG = " in src:
    a=src.index('I18N_CATALOG = """\\\n'); b=src.index('\n"""\n',a)
    src=src[:a]+'I18N_CATALOG = """\\\n'+cat+src[b:]
else:
    rep('''LOCALE_NAMES = {"en": "English"}   # display name -> add more as they're built''',
        '''LOCALE_NAMES = {"en": "English", "fr": "Fran\\u00e7ais", "es": "Espa\\u00f1ol"}''')
    rep('''def set_locale(name):
    global CURRENT_LOCALE
    for code, display in LOCALE_NAMES.items():
        if display == name:
            CURRENT_LOCALE = code
            return
    CURRENT_LOCALE = "en"
''','''def set_locale(name):
    """Accepts a display name ("Français") or a code ("fr"); anything else
    means English. Returns the code now in use."""
    global CURRENT_LOCALE
    for code, display in LOCALE_NAMES.items():
        if name in (display, code):
            CURRENT_LOCALE = code
            return code
    CURRENT_LOCALE = "en"
    return "en"
'''+block+"\n\ninstall_i18n_hooks()\n")
open(P,"w",encoding="utf8").write(src)
print("ok")
