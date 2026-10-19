@self_test()
def t_colorblind_modes(ctx):
    """Each colour-blind mode keeps good / warning / danger far apart for
    that kind of vision (simulated) and for normal vision, keeps text
    readable, and palettes stay one-to-one so switching is lossless."""
    for (mode, dark), trip in CVD_TRIPLES.items():
        base = "Dark" if dark else "Light"
        for hc in (False, True):
            th = THEMES[palette_name(base, hc, mode)]
            cols = [th["good_fg"], th["warn_fg"], th["danger_fg"]]
            assert cols == list(trip) or hc, (mode, dark, cols)
            for vision in (mode, ""):
                worst = min(cvd_delta(a, b, vision) for i, a in
                            enumerate(cols) for b in cols[i + 1:])
                assert worst >= 25, (mode, dark, hc, vision, worst)
            for c in cols:
                assert wcag_contrast(c, th["tab_bg"]) >= 4.5, \
                    (mode, dark, hc, c, th["tab_bg"])
    # the default palette is the problem being solved: red/green collide
    light = THEMES["Light"]
    assert cvd_delta(light["warn_fg"], light["danger_fg"], "deutan") < 15
    for name, tbl in PALETTES.items():
        vals = list(tbl.values())
        assert len(vals) == len(set(vals)), f"{name} is not one-to-one"
    keys = set(THEMES["Light"])
    for name, th in THEMES.items():
        assert set(th) == keys, name
    assert set_colorblind_mode("Red-green — protanopia") == "protan"
    assert palette_name("Dark", True) == "Dark HC protan"
    assert set_colorblind_mode("Off") == "" and palette_name(
        "Light", False) == "Light"
