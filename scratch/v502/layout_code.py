# ---- V5.0.2: layout that survives small screens, long translations and
#      large text ---------------------------------------------------------------
#  Three generic pieces, all installed once at start-up:
#   · FlowLayout: a row of buttons/fields that wraps onto a second line when
#     the window is too narrow, instead of squeezing the last widgets down
#     to nothing (Tk's pack never wraps).
#   · autowrap: every label created with a wraplength re-wraps to the width
#     it actually gets, so its right side is never cut off.
#   · headings: a table heading is never narrower than its text.
_SMALL_CLASSES = {"TButton", "Button", "Label", "TLabel", "TCheckbutton",
                  "Checkbutton", "TRadiobutton", "Radiobutton", "TEntry",
                  "Entry", "TCombobox", "TMenubutton", "Menubutton",
                  "TSpinbox", "Spinbox"}
_INPUT_CLASSES = {"TEntry", "Entry", "TCombobox", "TSpinbox", "Spinbox"}


def _pad_pair(v):
    try:
        if isinstance(v, (tuple, list)):
            a = [int(float(str(x))) for x in v]
        else:
            a = [int(float(x)) for x in str(v).split()]
    except (TypeError, ValueError):
        return 0, 0
    if not a:
        return 0, 0
    return (a[0], a[1]) if len(a) > 1 else (a[0], a[0])


class FlowLayout:
    """Lays out a frame's children left to right and wraps them onto more
    rows when the frame is narrower than they need. Children keep using
    pack()/pack_forget(): the hooks below route those calls here."""

    def __init__(self, frame):
        self.f = frame
        self.items = []          # dicts: w, side, padx, pady, expand
        self._job = None
        self._last = None
        frame._mw_flow = self
        for w in frame.pack_slaves():
            info = _ORIG_PACK["info"](w)
            self.items.append(self._item(w, info))
            _ORIG_PACK["forget"](w)
        frame.bind("<Configure>", self._on_conf, add="+")
        for it in self.items:
            self._watch(it["w"])
        self.schedule()

    @staticmethod
    def _item(w, info):
        return {"w": w, "side": str(info.get("side", "left")),
                "padx": _pad_pair(info.get("padx", 0)),
                "pady": _pad_pair(info.get("pady", 0)),
                "expand": str(info.get("expand", 0)) in ("1", "True",
                                                         "true", "yes"),
                "shown": True}

    def _watch(self, w):
        if not getattr(w, "_mw_flow_watched", False):
            w._mw_flow_watched = True
            w.bind("<Configure>", lambda e: self.schedule(), add="+")

    def _on_conf(self, e):
        if (e.width, e.height) != self._last:
            self.schedule()

    def schedule(self):
        if self._job is None:
            try:
                self._job = self.f.after_idle(self.relayout)
            except (tk.TclError, RuntimeError):
                self._job = None

    def find(self, w):
        for it in self.items:
            if it["w"] is w:
                return it
        return None

    def pack_child(self, w, kw):
        it = self.find(w)
        info = {"side": kw.get("side", it["side"] if it else "left"),
                "padx": kw.get("padx", 0), "pady": kw.get("pady", 0),
                "expand": kw.get("expand", 0)}
        new = self._item(w, info)
        if it is not None:
            self.items.remove(it)
        ref = kw.get("before") or kw.get("after")
        pos = len(self.items)
        if ref is not None:
            for i, x in enumerate(self.items):
                if x["w"] is ref:
                    pos = i if kw.get("before") is not None else i + 1
                    break
        self.items.insert(pos, new)
        self._watch(w)
        self.schedule()

    def hide(self, w):
        it = self.find(w)
        if it is not None:
            it["shown"] = False
            with contextlib.suppress(tk.TclError):
                w.place_forget()
            self.schedule()

    def _units(self, items):
        """Keep a "Label:" together with the field after it."""
        units, i = [], 0
        while i < len(items):
            it = items[i]
            if i + 1 < len(items):
                nxt = items[i + 1]
                try:
                    lab = it["w"].winfo_class() in ("Label", "TLabel") and \
                        str(it["w"].cget("text")).rstrip().endswith(
                            (":", "：")) and \
                        nxt["w"].winfo_class() in _INPUT_CLASSES
                except tk.TclError:
                    lab = False
                if lab:
                    units.append([it, nxt])
                    i += 2
                    continue
            units.append([it])
            i += 1
        return units

    @staticmethod
    def _wid(it):
        w = it["w"]
        return w.winfo_reqwidth() + it["padx"][0] + it["padx"][1]

    def relayout(self):
        self._job = None
        f = self.f
        try:
            if not f.winfo_exists():
                return
            items = [it for it in self.items if it["shown"] and
                     it["w"].winfo_exists()]
            natural = sum(self._wid(it) for it in items)
            W = f.winfo_width()
            if W <= 1:
                W = natural
            lefts = [it for it in items if it["side"] != "right"]
            rights = [it for it in items if it["side"] == "right"]
            rows = [[]]          # each: list of (it, x, w)
            x = 0
            for unit in self._units(lefts):
                uw = sum(self._wid(it) for it in unit)
                flex = [it for it in unit if it["expand"]]
                if x > 0 and x + uw > W and not flex:
                    rows.append([])
                    x = 0
                for it in unit:
                    wd = self._wid(it)
                    rows[-1].append([it, x, wd])
                    x += wd
            # right-hand items, the first packed is the right-most
            left_end = x
            xr = W
            for it in rights:
                wd = self._wid(it)
                if xr - wd < left_end and (xr < W or left_end > 0):
                    rows.append([])
                    left_end, xr = 0, W
                xr -= wd
                rows[-1].append([it, xr, wd])
            # an expanding item takes what is left of its row; anything
            # wider than the frame is clamped to it
            for row in rows:
                used = sum(r[2] for r in row)
                flex = [r for r in row if r[0]["expand"]]
                if flex and W > used:
                    extra = (W - used) // len(flex)
                    shift = 0
                    for r in sorted((r for r in row
                                     if r[0]["side"] != "right"),
                                    key=lambda r: r[1]):
                        r[1] += shift
                        if r in flex:
                            r[2] += extra
                            shift += extra
                elif flex and used > W:
                    over = used - W
                    for r in flex:
                        cut = min(over, max(0, r[2] - 120))
                        r[2] -= cut
                        over -= cut
                    xx = 0
                    for r in sorted((r for r in row
                                     if r[0]["side"] != "right"),
                                    key=lambda r: r[1]):
                        r[1] = xx
                        xx += r[2]
            y = 0
            for row in rows:
                if not row:
                    continue
                h = max(r[0]["w"].winfo_reqheight() + sum(r[0]["pady"])
                        for r in row)
                for it, rx, wd in row:
                    w = it["w"]
                    inner = wd - it["padx"][0] - it["padx"][1]
                    clamp = min(inner, W - it["padx"][0] - it["padx"][1])
                    kw = {"x": max(0, rx) + it["padx"][0],
                          "y": y + it["pady"][0] + max(
                              0, (h - sum(it["pady"]) -
                                  w.winfo_reqheight()) // 2)}
                    if it["expand"] or clamp < w.winfo_reqwidth():
                        kw["width"] = max(20, clamp)
                        w._mw_flex = True
                    else:
                        w._mw_flex = False
                    _ORIG_PLACE(w, **kw)
                    with contextlib.suppress(tk.TclError):
                        w.lift()
                y += h
            self._last = (f.winfo_width(), y)
            if _int(f.cget("height")) != y or \
                    _int(f.cget("width")) != natural:
                f.configure(height=max(1, y), width=max(1, natural))
            self._last = (f.winfo_width(), f.winfo_height())
        except tk.TclError:
            pass


_ORIG_PACK = {}
_ORIG_PLACE = None


def _int(v):
    try:
        return int(float(str(v) or 0))
    except (TypeError, ValueError):
        return 0


def _flow_of(w, kw=None):
    m = (kw or {}).get("in_") or (kw or {}).get("in") or w.master
    return getattr(m, "_mw_flow", None)


def install_layout_hooks():
    global _ORIG_PLACE
    if _ORIG_PACK:
        return
    _ORIG_PACK["configure"] = tk.Pack.pack_configure
    _ORIG_PACK["forget"] = tk.Pack.pack_forget
    _ORIG_PACK["info"] = tk.Pack.pack_info
    _ORIG_PLACE = tk.Place.place_configure

    def pack_configure(self, cnf={}, **kw):
        kw = dict(tk._cnfmerge((cnf, kw))) if cnf else kw
        fl = _flow_of(self, kw)
        if fl is not None and kw.get("side", "left") in ("left", "right"):
            fl.pack_child(self, kw)
            return None
        return _ORIG_PACK["configure"](self, **kw)

    def pack_forget(self):
        fl = _flow_of(self)
        if fl is not None and fl.find(self) is not None:
            return fl.hide(self)
        return _ORIG_PACK["forget"](self)
    tk.Pack.pack_configure = tk.Pack.pack = pack_configure
    tk.Pack.pack_forget = tk.Pack.forget = pack_forget
    for cls in (tk.Widget,):
        cls.pack = cls.pack_configure = pack_configure
        cls.pack_forget = pack_forget
        cls.forget = pack_forget

    # labels with a wraplength re-wrap to the width they really get
    orig_options = tk.Misc._options

    def _options(self, cnf, kw=None):
        out = orig_options(self, cnf, kw)
        if isinstance(self, (tk.Label, ttk.Label)) and \
                not getattr(self, "_mw_wrapping", False):
            try:
                merged = tk._cnfmerge((cnf, kw)) if kw else cnf
                wl = merged.get("wraplength") if isinstance(merged,
                                                            dict) else None
            except (TypeError, AttributeError):
                wl = None
            if wl not in (None, "", 0, "0"):
                try:
                    self._mw_wrap0 = int(float(str(wl)))
                except (TypeError, ValueError):
                    self._mw_wrap0 = 0
                if self._mw_wrap0 > 0 and not getattr(
                        self, "_mw_autowrap", False):
                    self._mw_autowrap = True
                    self.bind("<Configure>", _autowrap, add="+")
        return out
    tk.Misc._options = _options

    # table headings are never narrower than their text
    orig_heading = ttk.Treeview.heading

    def heading(self, column, option=None, **kw):
        out = orig_heading(self, column, option, **kw)
        if isinstance(kw.get("text"), str) and kw["text"]:
            fit_heading(self, column)
        return out
    heading.__doc__ = orig_heading.__doc__
    ttk.Treeview.heading = heading
    orig_column = ttk.Treeview.column

    def column(self, col, option=None, **kw):
        out = orig_column(self, col, option, **kw)
        if kw.get("width") is not None:
            fit_heading(self, col)
        return out
    column.__doc__ = orig_column.__doc__
    ttk.Treeview.column = column


def fit_heading(tree, col):
    try:
        text = str(tree.heading(col, "text") or "")
        if not text:
            return
        need = tkfont.nametofont("TkHeadingFont").measure(text) + 20
        if int(tree.column(col, "width")) < need:
            tree.column(col, width=need, minwidth=min(need, 60))
    except (tk.TclError, ValueError, TypeError, RuntimeError):
        pass


def fit_all_headings(root):
    for tree in _walk_class(root, ttk.Treeview):
        try:
            cols = ("#0",) + tuple(tree["columns"])
        except tk.TclError:
            continue
        for c in cols:
            fit_heading(tree, c)


def _walk_class(root, cls):
    stack = [root]
    while stack:
        w = stack.pop()
        try:
            stack.extend(w.winfo_children())
        except tk.TclError:
            continue
        if isinstance(w, cls):
            yield w


def _label_pad(w):
    try:
        if isinstance(w, ttk.Label):
            return 8
        return 2 * int(float(str(w.cget("padx")))) + \
            2 * int(float(str(w.cget("bd")))) + 6
    except (tk.TclError, ValueError):
        return 8


def _is_flexible(w):
    """Its width comes from the layout, not from its own text."""
    try:
        if getattr(w, "_mw_flex", False):
            return True
        mgr = w.winfo_manager()
        if mgr == "pack":
            info = _ORIG_PACK["info"](w)
            return str(info.get("fill")) in ("x", "both")
        if mgr == "grid":
            st = str(w.grid_info().get("sticky", ""))
            return "e" in st and "w" in st
    except (tk.TclError, KeyError):
        pass
    return False


def _autowrap(e):
    w = e.widget
    try:
        orig = getattr(w, "_mw_wrap0", 0)
        if orig <= 0 or e.width <= 30:
            return
        cur = int(float(str(w.cget("wraplength")) or 0))
        pad = _label_pad(w)
        room = max(40, e.width - pad)
        new = cur
        if _is_flexible(w):
            new = room                    # use exactly the width it has
        elif w.winfo_reqwidth() > e.width + 2:
            new = room                    # clipped: wrap tighter
        elif cur < orig and e.width > w.winfo_reqwidth() + 16:
            new = min(orig, room)         # room again: back towards orig
        if abs(new - cur) > 3:
            w._mw_wrapping = True
            try:
                w.configure(wraplength=new)
            finally:
                w._mw_wrapping = False
    except (tk.TclError, ValueError):
        pass


_FLOW_SKIP = set()


def make_flow(frame):
    """Turn a row of packed widgets into a wrapping row (idempotent)."""
    if getattr(frame, "_mw_flow", None) is None:
        FlowLayout(frame)
    return frame._mw_flow


def _flow_candidate(frame):
    if getattr(frame, "_mw_flow", None) is not None or \
            getattr(frame, "_mw_noflow", False):
        return False
    try:
        slaves = frame.pack_slaves()
        if len(slaves) < 2:
            return False
        if frame.grid_slaves() or frame.place_slaves():
            return False
        small = 0
        for w in slaves:
            info = _ORIG_PACK["info"](w)
            if str(info.get("side")) not in ("left", "right"):
                return False
            if str(info.get("fill")) in ("y", "both"):
                return False
            cls = w.winfo_class()
            if cls in _SMALL_CLASSES:
                small += cls not in ("Label", "TLabel")
                continue
            if cls in ("Frame", "TFrame"):
                kids = w.winfo_children()
                if kids and all(k.winfo_class() in _SMALL_CLASSES
                                for k in kids):
                    small += 1
                    continue
            return False
        return small >= 1
    except (tk.TclError, KeyError):
        return False


def auto_flow(root):
    """Make every toolbar-like row under `root` wrap when needed."""
    n = 0
    for fr in list(_walk_class(root, tk.Frame)) + \
            list(_walk_class(root, ttk.Frame)):
        if _flow_candidate(fr):
            make_flow(fr)
            n += 1
    return n
