    # ---- rows (virtual table: only the visible rows exist as Treeview
    #      items; the scrollbar, wheel and keys move a window over
    #      self.matched, which holds the filtered rows in view order)
    def _values(self, d):
        app = self.app
        return (d["no"], "★" if d["no"] in app.bookmarks else "",
                datetime.fromtimestamp(d["time"]).strftime("%H:%M:%S.%f")[:-3],
                app.disp_addr(d["src_ip"], d["src_mac"]),
                app.disp_addr(d["dst_ip"], d["dst_mac"]), d["proto"],
                d["length"], d.get("flow_id") or "", d["text"])

    def _keep(self, d):
        try:
            return self.filter.match(d, self.ctx)
        except Exception:                            # noqa: BLE001
            return True

    def _count(self):
        self.count_var.set(f"{len(self.matched)} shown · "
                           f"{len(self.app.all_rows)} in memory")

    def add_rows(self, rows):
        if self.paused or not self.is_visible():
            self._dirty = True
            return
        self.ctx._alert_cache = None
        new = [d for d in rows if self._keep(d)]
        if new:
            self.matched.extend(new)
            if self.sort_col is not None:
                self._resort()
        self._trim()
        if new and self.follow_var.get() and self.sort_col is None:
            self.top = max(0, len(self.matched) - self._nslots())
        self.render()
        self._count()

    def _bisect_no(self, no):
        """First index in self.matched (in packet order) with number ≥ no."""
        m = self.matched
        lo, hi = 0, len(m)
        while lo < hi:
            mid = (lo + hi) // 2
            if m[mid]["no"] < no:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _trim(self):
        """Drop rows that have left memory (or exceed the row limit)."""
        rows = self.app.all_rows
        m = self.matched
        if not rows:
            if m:
                self.matched, self.top = [], 0
            return
        lo_no = rows[0]["no"]
        limit = self.app.max_rows
        if self.sort_col is None:
            k = max(self._bisect_no(lo_no), len(m) - limit)
            if k > 0:
                del m[:k]
                self.top = max(0, self.top - k)
        elif m and (len(m) > limit or min(d["no"] for d in m) < lo_no):
            self.matched = [d for d in m if d["no"] >= lo_no]

    def index_of_no(self, no):
        if no is None:
            return None
        m = self.matched
        if self.sort_col is None:
            i = self._bisect_no(no)
            return i if i < len(m) and m[i]["no"] == no else None
        for i, d in enumerate(m):
            if d["no"] == no:
                return i
        return None

    def _row_height(self):
        if self.rowh:
            return self.rowh
        if self.slots:
            with contextlib.suppress(tk.TclError):
                bb = self.tree.bbox(self.slots[0])
                if bb and bb[3] > 4:
                    self.rowh, self.head_h = bb[3], bb[1]
                    return self.rowh
        return None

    def _nslots(self):
        try:
            h = self.tree.winfo_height()
        except tk.TclError:
            return 14
        if h <= 1:
            return 14
        rh = self._row_height() or 20
        return max(1, (h - (self.head_h or 24)) // rh)

    def render(self):
        """Show self.matched[top : top + visible rows] in the slot items."""
        if self._rendering:
            return
        self._rendering = True
        tree = self.tree
        try:
            m = self.matched
            n = self._nslots()
            total = len(m)
            self.top = max(0, min(self.top, total - n))
            rows = m[self.top:self.top + n]
            while len(self.slots) < len(rows):
                self.slots.append(tree.insert("", "end", values=()))
            while len(self.slots) > len(rows):
                tree.delete(self.slots.pop())
            bm = self.app.bookmarks
            sel_iid = None
            for iid, d in zip(self.slots, rows):
                tags = (d["tag"],) + (("marked",) if d["no"] in bm else ())
                tree.item(iid, values=self._values(d), tags=tags)
                if d["no"] == self.sel_no:
                    sel_iid = iid
            self.slot_rows = dict(zip(self.slots, rows))
            cur = tree.selection()
            if sel_iid is not None:
                if tuple(cur) != (sel_iid,):
                    tree.selection_set(sel_iid)
            elif cur:
                tree.selection_remove(*cur)
            tree.yview_moveto(0)
            if total:
                self.vbar.set(self.top / total,
                              min(1.0, (self.top + len(rows)) / total))
            else:
                self.vbar.set(0.0, 1.0)
            if self.rowh is None and self.slots:
                if self._row_height() and len(rows) == n and \
                        self._nslots() != n:
                    self._rendering = False
                    self.render()
        except tk.TclError:
            pass
        finally:
            self._rendering = False

    def _yscroll(self, *args):
        if not args:
            return
        n = self._nslots()
        total = len(self.matched)
        before = self.top
        try:
            if args[0] == "moveto":
                self.top = int(float(args[1]) * total + 0.5)
            elif args[0] == "scroll":
                amt = int(float(args[1]))
                self.top += amt * (max(1, n - 1) if str(args[2]).startswith(
                    "page") else 1)
        except (ValueError, IndexError):
            return
        self.top = max(0, min(self.top, total - n))
        if self.top < before and self.follow_var.get():
            self.follow_var.set(False)       # the user scrolled back
        self.render()

    def _wheel(self, e):
        if getattr(e, "num", 0) == 4:
            step = -3
        elif getattr(e, "num", 0) == 5:
            step = 3
        else:
            d = getattr(e, "delta", 0)
            if not d:
                return "break"
            step = -3 if d > 0 else 3
            if abs(d) >= 240:                # fast wheels report multiples
                step *= min(5, abs(d) // 120)
        self._yscroll("scroll", step, "units")
        return "break"

    def _key(self, e):
        m = self.matched
        if not m:
            return "break"
        n = self._nslots()
        i = self.index_of_no(self.sel_no)
        if i is None:
            i = self.top - 1 if e.keysym in ("Down", "Next") else self.top
        i = {"Up": i - 1, "Down": i + 1, "Prior": i - (n - 1),
             "Next": i + (n - 1), "Home": 0,
             "End": len(m) - 1}.get(e.keysym, i)
        i = max(0, min(i, len(m) - 1))
        self.sel_no = m[i]["no"]
        if i < self.top:
            self.top = i
        elif i >= self.top + n:
            self.top = i - n + 1
        if i < len(m) - 1 and self.follow_var.get():
            self.follow_var.set(False)
        self.render()
        self._on_select()
        return "break"

    SORTERS = {
        "no": lambda tab, d: d["no"],
        "mark": lambda tab, d: (d["no"] in tab.app.bookmarks, d["no"]),
        "time": lambda tab, d: (d["time"], d["no"]),
        "src": lambda tab, d: (tab.app.disp_addr(d["src_ip"], d["src_mac"])
                               .lower(), d["no"]),
        "dst": lambda tab, d: (tab.app.disp_addr(d["dst_ip"], d["dst_mac"])
                               .lower(), d["no"]),
        "proto": lambda tab, d: (d["proto"], d["no"]),
        "length": lambda tab, d: (d["length"], d["no"]),
        "stream": lambda tab, d: (d.get("flow_id") or 0, d["no"]),
        "info": lambda tab, d: (d["text"].lower(), d["no"]),
    }

    def _resort(self):
        if self.sort_col is None:
            self.matched.sort(key=lambda d: d["no"])
            return
        fn = self.SORTERS.get(self.sort_col, self.SORTERS["no"])
        self.matched.sort(key=lambda d: fn(self, d), reverse=self.sort_rev)

    def _sort_by(self, col):
        """Click a heading: sort by it; click again to reverse. Sorting by
        No. ascending returns to the normal (live) order."""
        if self.sort_col == col or (self.sort_col is None and col == "no"):
            self.sort_rev = not self.sort_rev
            self.sort_col = col
        else:
            self.sort_col, self.sort_rev = col, False
        if self.sort_col == "no" and not self.sort_rev:
            self.sort_col = None
        if self.sort_col is not None:
            self.follow_var.set(False)
        self._resort()
        for c in self.tree["columns"]:
            with contextlib.suppress(tk.TclError):
                txt = self.tree.heading(c, "text").rstrip(" ▲▼")
                if c == (self.sort_col or ""):
                    txt += " ▼" if self.sort_rev else " ▲"
                self.tree.heading(c, text=txt)
        i = self.index_of_no(self.sel_no)
        n = self._nslots()
        self.top = max(0, i - n // 2) if i is not None else 0
        self.render()

    def refresh(self):
        if self._dirty and not self.paused and self.is_visible():
            self._dirty = False
            self.rebuild()

    def rebuild(self):
        self._dirty = False
        self.ctx._alert_cache = None
        rows = self.app.all_rows
        m = [d for d in rows if self._keep(d)]
        if len(m) > self.app.max_rows:
            m = m[-self.app.max_rows:]
        self.matched = m
        if self.sort_col is not None:
            self._resort()
        n = self._nslots()
        if self.follow_var.get() and self.sort_col is None:
            self.top = max(0, len(m) - n)
        else:
            i = self.index_of_no(self.sel_no)
            if i is not None and not (self.top <= i < self.top + n):
                self.top = max(0, i - n // 2)
        self.render()
        self._count()

    def refresh_names(self):
        self.render()

    # ---- details
    def _selected_row(self):
        sel = self.tree.selection()
        d = self.slot_rows.get(sel[0]) if sel else None
        if d is not None:
            return d
        i = self.index_of_no(self.sel_no)
        return self.matched[i] if i is not None else None

    def _on_select(self, _e=None):
        sel = self.tree.selection()
        d = self.slot_rows.get(sel[0]) if sel else None
        if d is None:
            i = self.index_of_no(self.sel_no)
            d = self.matched[i] if i is not None else None
        if not d:
            return
        self.sel_no = d["no"]
        if self._detail_no == d["no"]:
            return
        self._detail_no = d["no"]
