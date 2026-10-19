@self_test(slow=False)
def test_i18n_catalog(ctx):
    """Languages: the catalog parses cleanly and covers every fixed string
    of the setup window, Welcome Center, Settings, tour and banners."""
    assert _i18n_load() == [], _i18n_load()
    assert len(I18N["fr"]) == len(I18N["es"]) >= 700, len(I18N["fr"])
    must = []
    for p in SETTINGS_PAGES:
        must += [p.get("title"), p.get("blurb")]
        for sec in p.get("sections", []):
            must.append(sec.get("title"))
            for c in sec.get("controls", []):
                must += [c.get("label"), c.get("help")]
                if isinstance(c.get("choices"), (list, tuple)):
                    must += list(c["choices"])
    must += list(STRINGS["en"].values())
    for q in QUICK_START:
        must += [q[0], q[1], q[3]]
    for _icon, title, text in LoaderWindow.WHATS_NEW:
        must += [title, text]
    must += list(RuntimeManager.STAGES) + [v for _k, v in REPAIR_STEPS]
    must += list(DATA_MODE_TEXT.values())
    tech = {"DNS", "MB", "ms", "MiniWireshark"}
    for loc in ("fr", "es"):
        missing = sorted({s for s in must if isinstance(s, str) and s and
                          re.sub(r"^[^A-Za-z]+", "", s).strip() not in tech and
                          re.search(r"[A-Za-z]{2}", s) and
                          _i18n_lookup(s, I18N[loc], loc) is None})
        assert not missing, (loc, missing[:8])
    # icons and punctuation around a label survive; numbers are kept
    assert translate_text("▶  Start watching", "fr") == \
        "▶  Commencer à observer"
    assert translate_text("Network card:", "es") == "Tarjeta de red:"
    assert translate_text("1,204 shown", "fr") == "1,204 affichés"
    assert translate_text("3. The Dashboard", "es") == "3. El panel"
    assert translate_text("For: ◉ Signal -80 dBm (weak)", "fr") == \
        "Pour : ◉ Signal -80 dBm (faible)"
    assert translate_text("Start watching", "en") == "Start watching"
    assert translate_text("my-laptop", "fr") == "my-laptop"   # data stays
    assert untranslate_text(translate_text("Devices", "fr")) == "Devices"
    try:
        assert set_locale("Español") == "es" and CURRENT_LOCALE == "es"
        assert set_locale("fr") == "fr"
        assert set_locale("Klingon") == "en"
    finally:
        set_locale("English")
    assert set(LOCALE_NAMES) == set(I18N_LOCALES)


