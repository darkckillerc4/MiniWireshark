

# ---------------------------------------------------------------------------
# Languages: English, French, Spanish
# ---------------------------------------------------------------------------
# The program is written in English. Every visible label, button, menu,
# tab, column heading, window title and message box passes through one hook
# (installed below on tkinter itself), which looks the English text up in
# this catalog. A label with a leading icon or a trailing ":" "…" "›" is
# matched on its words, so "▶  Start watching" and "Start watching" share
# one entry. Anything not in the catalog (device names, websites, numbers,
# reports built from live data) is shown as it is — a missing translation
# never breaks or hides anything.
#
# One line per string: English ¦ French ¦ Spanish (⏎ marks a line break).
I18N_SEP = " \u00a6 "
I18N_CATALOG = """\
@@CATALOG@@
"""

I18N = {"fr": {}, "es": {}}
I18N_LOCALES = ("en", "fr", "es")


def _i18n_load(text=None):
    """Parse the catalog. Returns a list of problems (empty when clean) so
    the self-test can check it; the tables are filled either way."""
    problems = []
    tables = {"fr": {}, "es": {}}
    for n, line in enumerate((text or I18N_CATALOG).splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(I18N_SEP)
        if len(parts) != 3 or not all(p.strip() for p in parts):
            problems.append(f"line {n}: needs English ¦ French ¦ Spanish")
            continue
        en, fr, es = (p.replace("\u23ce", "\n") for p in parts)
        if en in tables["fr"]:
            problems.append(f"line {n}: duplicate entry {en!r}")
        for code, val in (("fr", fr), ("es", es)):
            if set(re.findall(r"\{\w*\}", en)) != \
                    set(re.findall(r"\{\w*\}", val)):
                problems.append(f"line {n}: placeholders differ in {code}")
            tables[code][en] = val
    I18N["fr"], I18N["es"] = tables["fr"], tables["es"]
    return problems


_i18n_load()

# Dynamic strings: (English pattern, French, Spanish); groups are kept.
I18N_PATTERNS = [
    (r"(\d[\d,]*) shown", r"\1 affichés", r"\1 mostrados"),
    (r"(\d[\d,]*) of (\d[\d,]*) shown", r"\1 sur \2 affichés",
     r"\1 de \2 mostrados"),
    (r"(\d[\d,]*) shown · (\d[\d,]*) in memory",
     r"\1 affichés · \2 en mémoire", r"\1 mostrados · \2 en memoria"),
    (r"(\d[\d,]*) events? this session", r"\1 événements cette session",
     r"\1 eventos en esta sesión"),
    (r"(\d[\d,]*) devices?", r"\1 appareils", r"\1 dispositivos"),
    (r"(\d[\d,]*) websites?", r"\1 sites web", r"\1 sitios web"),
    (r"(\d[\d,]*) sites?", r"\1 sites", r"\1 sitios"),
    (r"(\d[\d,]*) hits?", r"\1 visites", r"\1 visitas"),
    (r"(\d[\d,]*) connections?", r"\1 connexions", r"\1 conexiones"),
    (r"(\d[\d,]*) alerts?", r"\1 alertes", r"\1 alertas"),
    (r"(\d[\d,]*) packets?", r"\1 paquets", r"\1 paquetes"),
    (r"(\d[\d,]*) online", r"\1 en ligne", r"\1 conectados"),
    (r"(\d[\d,]*) sent · (\d[\d,]*) blocked", r"\1 envoyés · \2 bloqués",
     r"\1 enviados · \2 bloqueados"),
    (r"(\d+) new devices? · (\d+) new websites?(\s+)\(click for details\)",
     r"\1 nouveaux appareils · \2 nouveaux sites\3(cliquez pour les détails)",
     r"\1 dispositivos nuevos · \2 sitios nuevos\3(clic para detalles)"),
    (r"Help / About — MiniWireshark (\S+)", r"Aide / À propos — MiniWireshark \1",
     r"Ayuda / Acerca de — MiniWireshark \1"),
    (r"Network cards re-detected \((\d+) found\)\.",
     r"Cartes réseau redétectées (\1 trouvées).",
     r"Tarjetas de red detectadas de nuevo (\1 encontradas)."),
    (r"Step (\d+) of (\d+)", r"Étape \1 sur \2", r"Paso \1 de \2"),
    (r"Examples:(\s+.+)", r"Exemples :\1", r"Ejemplos:\1"),
    # explanations built from live measurements
    (r"What to try: (.+)", "À essayer : {t1}", "Qué probar: {t1}"),
    (r"For: (.+)", "Pour : {t1}", "A favor: {t1}"),
    (r"Against: (.+)", "Contre : {t1}", "En contra: {t1}"),
    (r"Likely culprit: (.+?) — (.+)", "Cause probable : {t1} — {t2}",
     "Causa probable: {t1} — {t2}"),
    (r"Signal (-?\d+) dBm \((\w+)\)", r"Signal \1 dBm ({t2})",
     r"Señal \1 dBm ({t2})"),
    (r"(-?\d+) dBm \((\w+)\), link (.+?), channel (.+?)\. (.+)",
     r"\1 dBm ({t2}), lien \3, canal \4. {t5}",
     r"\1 dBm ({t2}), enlace \3, canal \4. {t5}"),
    (r"Router answered in (\d+) ms", r"La box a répondu en \1 ms",
     r"El router respondió en \1 ms"),
    (r"Typical lookup (\d+) ms over (\d+) lookups",
     r"Recherche habituelle \1 ms sur \2 recherches",
     r"Búsqueda típica \1 ms en \2 búsquedas"),
    (r"Typical lookup (\d+) ms, (\S+) failed",
     r"Recherche habituelle \1 ms, \2 en échec",
     r"Búsqueda típica \1 ms, \2 fallidas"),
    (r"Typical lookup (\d+) ms", r"Recherche habituelle \1 ms",
     r"Búsqueda típica \1 ms"),
    (r"Typical lookup (\d+) ms over (\d+) recent lookups; (\S+) failed\.",
     r"Recherche habituelle \1 ms sur \2 recherches récentes ; \3 en échec.",
     r"Búsqueda típica \1 ms en \2 búsquedas recientes; \3 fallidas."),
    (r"Connections take (\d+) ms to open",
     r"Les connexions mettent \1 ms à s'ouvrir",
     r"Las conexiones tardan \1 ms en abrirse"),
    (r"Connections open in (\d+) ms", r"Les connexions s'ouvrent en \1 ms",
     r"Las conexiones se abren en \1 ms"),
    (r"(\S+) of data was re-sent", r"\1 des données ont été renvoyées",
     r"se reenvió el \1 de los datos"),
    (r"Only (\S+) re-sent", r"Seulement \1 renvoyées",
     r"Solo se reenvió el \1"),
    (r"Typical (\d+) ms, slowest tenth (\d+) ms, from (\d+) connection "
     r"handshakes \(measured passively\)\.",
     r"Habituel \1 ms, dixième le plus lent \2 ms, sur \3 ouvertures de "
     r"connexion (mesure passive).",
     r"Típico \1 ms, la décima parte más lenta \2 ms, de \3 aperturas de "
     r"conexión (medido pasivamente)."),
    (r"(.+) is using the most \((\d+%) of what I can see\)\.",
     r"{t1} utilise le plus (\2 de ce que je vois).",
     r"{t1} es el que más usa (\2 de lo que veo)."),
    (r"(.+) used (.+) in the last (.+) \((\d+%) of what I can see\)\.",
     r"{t1} a utilisé \2 ces dernières \3 (\4 de ce que je vois).",
     r"{t1} usó \2 en los últimos \3 (\4 de lo que veo)."),
    (r"Data is arriving from the Internet \((.+) so far\), so it's "
     r"reachable\.",
     r"Des données arrivent d'Internet (\1 jusqu'ici) : il est joignable.",
     r"Llegan datos de Internet (\1 hasta ahora), así que es accesible."),
    (r"Your router \((.+)\) is visible on the network \(passive\)\.",
     r"Votre box (\1) est visible sur le réseau (passif).",
     r"Su router (\1) es visible en la red (pasivo)."),
    (r"One DHCP server \((.+)\)\.", r"Un seul serveur DHCP (\1).",
     r"Un solo servidor DHCP (\1)."),
    (r"(.+) on this computer is using most of the connection",
     r"\1 sur cet ordinateur utilise l'essentiel de la connexion",
     r"\1 en este equipo usa casi toda la conexión"),
    (r"Pause (.+)'s downloads or updates and try again\.",
     r"Mettez en pause les téléchargements ou mises à jour de \1 et "
     r"réessayez.",
     r"Pause las descargas o actualizaciones de \1 y vuelva a probar."),
    (r"(.+) is using a lot of the connection",
     r"{t1} utilise une grande part de la connexion",
     r"{t1} usa gran parte de la conexión"),
    (r"Check what (.+) is doing \(streaming, backups, updates\)\.",
     r"Vérifiez ce que fait {t1} (streaming, sauvegardes, mises à jour).",
     r"Compruebe qué hace {t1} (streaming, copias de seguridad, "
     r"actualizaciones)."),
    (r"(.+)/s right now", r"\1/s en ce moment", r"\1/s ahora mismo"),
    (r"(\d+)\. (.+)", None, None),         # numbered title: translate rest
]
_I18N_PATTERNS_RX = [(re.compile(r"\A" + p + r"\Z", re.S), fr, es)
                     for p, fr, es in I18N_PATTERNS]
_I18N_CORE = re.compile(
    r"\A([^A-Za-z0-9\u00c0-\u024f\u201c\"(\u00bf\u00a1]*)(.*?)"
    r"((?:\.\.\.|[\s:\u2026\u25be\u203a])*)\Z", re.S)
I18N_REVERSE = {}          # shown translation -> English source
_I18N_CACHE = {}


def _i18n_lookup(s, table, loc):
    hit = table.get(s)
    if hit is not None:
        return hit
    tries = [("", s, "")]
    m = _I18N_CORE.match(s)
    if m and m.group(2) and (m.group(1) or m.group(3)):
        tries.append((m.group(1), m.group(2), m.group(3)))
        hit = table.get(m.group(2))
        if hit is not None:
            return m.group(1) + hit + m.group(3)
    for pre, core, post in tries:
        for rx, fr, es in _I18N_PATTERNS_RX:
            mm = rx.match(core)
            if not mm:
                continue
            tpl = fr if loc == "fr" else es
            if tpl is None:              # numbered title: "3. Something"
                rest = _i18n_lookup(mm.group(2), table, loc)
                if rest is None:
                    break
                return f"{pre}{mm.group(1)}. {rest}{post}"
            out = mm.expand(tpl)
            if "{t" in out:              # {tN}: group N, itself translated
                for i, g in enumerate(mm.groups(), 1):
                    tok = "{t%d}" % i
                    if tok in out:
                        sub = g or ""
                        if sub:
                            sub = _i18n_lookup(sub, table, loc) or sub
                        out = out.replace(tok, sub)
            return pre + out + post
    # "Title — explanation": both halves known
    for pre, core, post in tries:
        if " \u2014 " in core:
            a, b = core.split(" \u2014 ", 1)
            ta, tb = table.get(a), _i18n_lookup(b, table, loc)
            if ta is not None and tb is not None:
                return f"{pre}{ta} \u2014 {tb}{post}"
    return None


def translate_text(s, locale=None):
    """English UI text -> the current language (unchanged when English,
    unknown, or not text)."""
    loc = locale or CURRENT_LOCALE
    if loc == "en" or not isinstance(s, str) or not s or len(s) > 2000:
        return s
    table = I18N.get(loc)
    if not table:
        return s
    key = (loc, s)
    out = _I18N_CACHE.get(key)
    if out is None:
        out = _i18n_lookup(s, table, loc)
        if out is None:
            out = s
        if len(_I18N_CACHE) > 20000:
            _I18N_CACHE.clear()
        _I18N_CACHE[key] = out
        if out is not s:
            if len(I18N_REVERSE) > 50000:
                I18N_REVERSE.clear()
            I18N_REVERSE[out] = s
    return out


def untranslate_text(s):
    """Shown text -> its English source (unchanged when not a translation)."""
    if not isinstance(s, str):
        return s
    return I18N_REVERSE.get(s, s)


_I18N_KEYS = ("text", "label", "message", "detail", "title")
_I18N_HOOKED = []


def _i18n_cnf(cnf):
    if not cnf:
        return cnf
    hit = [k for k in _I18N_KEYS if isinstance(cnf.get(k), str)]
    if not hit:
        return cnf
    cnf = dict(cnf)
    for k in hit:
        cnf[k] = translate_text(cnf[k])
    return cnf


def _i18n_fit_heading(tree, column, text):
    """Widen a table column so a longer translated heading isn't cut."""
    try:
        need = tkfont.nametofont("TkHeadingFont").measure(text) + 18
        if int(tree.column(column, "width")) < need:
            tree.column(column, width=need)
    except (tk.TclError, ValueError, TypeError):
        pass


def install_i18n_hooks():
    """Route every widget's visible text through translate_text(). Costs one
    comparison per call while the language is English."""
    if _I18N_HOOKED:
        return
    orig_options = tk.Misc._options

    def _options(self, cnf, kw=None):
        if CURRENT_LOCALE != "en":
            try:
                merged = tk._cnfmerge((cnf, kw)) if kw else tk._cnfmerge(cnf)
            except (TypeError, AttributeError):
                return orig_options(self, cnf, kw)
            if isinstance(merged, dict):
                return orig_options(self, _i18n_cnf(merged))
        return orig_options(self, cnf, kw)
    tk.Misc._options = _options

    orig_title = tk.Wm.wm_title

    def wm_title(self, string=None):
        if string is not None and CURRENT_LOCALE != "en":
            string = translate_text(string)
        return orig_title(self, string)
    tk.Wm.wm_title = tk.Wm.title = wm_title

    def wrap_kw(cls, name):
        orig = getattr(cls, name)

        def method(self, *a, **kw):
            if CURRENT_LOCALE != "en" and isinstance(kw.get("text"), str):
                src = kw["text"]
                kw["text"] = translate_text(src)
                if kw["text"] != src and name == "heading" and a:
                    out = orig(self, *a, **kw)
                    _i18n_fit_heading(self, a[0], kw["text"])
                    return out
            return orig(self, *a, **kw)
        method.__doc__ = orig.__doc__
        setattr(cls, name, method)
    for cls, name in ((ttk.Notebook, "add"), (ttk.Notebook, "insert"),
                      (ttk.Notebook, "tab"), (ttk.Treeview, "heading")):
        wrap_kw(cls, name)

    orig_column = ttk.Treeview.column

    def column(self, col, option=None, **kw):
        out = orig_column(self, col, option, **kw)
        if kw.get("width") is not None and CURRENT_LOCALE != "en":
            try:
                text = self.heading(col, "text")
            except tk.TclError:
                text = ""
            if text and text != untranslate_text(text):
                _i18n_fit_heading(self, col, text)
        return out
    column.__doc__ = orig_column.__doc__
    ttk.Treeview.column = column

    # read-only drop-downs: the program's variable keeps the English value,
    # the box shows (and accepts) the current language
    orig_combo = ttk.Combobox.__init__

    def combo_init(self, master=None, **kw):
        var, vals = kw.get("textvariable"), kw.get("values")
        if not (isinstance(var, tk.StringVar) and
                not isinstance(var, DisplayVar) and
                isinstance(vals, (list, tuple)) and vals and
                all(isinstance(v, str) for v in vals) and
                str(kw.get("state", "")) == "readonly"):
            return orig_combo(self, master, **kw)
        info = {"var": var, "values": list(vals)}
        shown = tk.StringVar(master, value=translate_text(var.get()))
        info["shown"] = shown

        def to_var(*_):
            val = shown.get()
            for v in info["values"]:
                if translate_text(v) == val:
                    val = v
                    break
            if var.get() != val:
                var.set(val)

        def to_shown(*_):
            val = translate_text(var.get())
            if shown.get() != val:
                shown.set(val)
        shown.trace_add("write", to_var)
        var.trace_add("write", to_shown)
        kw["textvariable"] = shown
        kw["values"] = [translate_text(v) for v in vals]
        width = kw.get("width")
        if isinstance(width, int) and width > 0:
            kw["width"] = max(width, max(len(v) for v in kw["values"]) + 1)
        orig_combo(self, master, **kw)
        self._mw_i18n = info
    combo_init.__doc__ = orig_combo.__doc__
    ttk.Combobox.__init__ = combo_init
    _I18N_HOOKED.append(True)


def i18n_retranslate(root):
    """Re-label every open window after the language changes: each shown
    text goes back to its English source and through the hook again."""
    count = 0
    stack = [root]
    while stack:
        w = stack.pop()
        try:
            stack.extend(w.winfo_children())
        except tk.TclError:
            continue
        try:
            if isinstance(w, (tk.Tk, tk.Toplevel)):
                w.title(untranslate_text(w.title()))
            if isinstance(w, tk.Menu):
                end = w.index("end")
                for i in range(0 if end is None else end + 1):
                    if w.type(i) in ("command", "cascade", "checkbutton",
                                     "radiobutton"):
                        lab = w.entrycget(i, "label")
                        w.entryconfigure(i, label=untranslate_text(lab))
                continue
            if isinstance(w, ttk.Notebook):
                for t in w.tabs():
                    w.tab(t, text=untranslate_text(w.tab(t, "text")))
            elif isinstance(w, ttk.Combobox) and \
                    getattr(w, "_mw_i18n", None):
                info = w._mw_i18n
                w.configure(values=[translate_text(v)
                                    for v in info["values"]])
                info["shown"].set(translate_text(info["var"].get()))
            elif isinstance(w, ttk.Treeview):
                for c in ("#0",) + tuple(w["columns"]):
                    w.heading(c, text=untranslate_text(w.heading(c, "text")))
            elif isinstance(w, tk.Canvas):
                for item in w.find_all():
                    if w.type(item) == "text":
                        w.itemconfigure(item, text=untranslate_text(
                            w.itemcget(item, "text")))
            keys = w.keys()
            if "text" in keys and "textvariable" in keys and \
                    not str(w.cget("textvariable")):
                cur = w.cget("text")
                if isinstance(cur, str) and cur:
                    w.configure(text=untranslate_text(cur))
                    count += 1
        except (tk.TclError, TypeError, ValueError):
            continue
    return count


class DisplayVar(tk.StringVar):
    """A StringVar for text that is only shown (status lines, card values):
    whatever is set is shown in the current language. Never use it for a
    value the program reads back as a setting."""

    def __init__(self, master=None, value=None, name=None):
        super().__init__(master, translate_text(value)
                         if isinstance(value, str) else value, name)

    def set(self, value):
        return super().set(translate_text(value)
                           if isinstance(value, str) else value)
