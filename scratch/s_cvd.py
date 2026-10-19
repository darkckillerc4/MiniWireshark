

# ---- Colour-blind modes (Settings → Accessibility) --------------------------
# The three most common kinds of colour blindness. Each mode recolours the
# meaning-carrying colours (good / warning / danger, charts, confidence,
# the map) so they stay distinct for that kind of vision; surfaces and
# greys are unchanged. Every status also keeps its icon and word, so colour
# is never the only signal. The chosen triples were picked by simulating
# each kind of vision (Machado et al. 2009) — a self-test re-checks them.
CVD_LABELS = {"Off": "",
              "Red-green — deuteranopia (most common)": "deutan",
              "Red-green — protanopia": "protan",
              "Blue-yellow — tritanopia": "tritan"}
CVD_STATE = {"mode": ""}
CVD_TRIPLES = {
    # (mode, dark): good, warn, danger
    ("deutan", False): ("#1e74ae", "#a36a00", "#760a31"),
    ("deutan", True): ("#1aacff", "#ffb81a", "#f15a91"),
    ("protan", False): ("#1e74ae", "#a36a00", "#80001c"),
    ("protan", True): ("#4dbfff", "#eee12a", "#f56c56"),
    ("tritan", False): ("#1e8385", "#805800", "#cc002c"),
    ("tritan", True): ("#4dffce", "#c8b45a", "#ff4d73"),
}
# canonical (light) colours that carry a meaning → which role they play
CVD_ROLES = {"#0b6b3a": "good", "#8a5a00": "warn", "#8a1a08": "danger",
             "#a01a08": "danger", "#a05608": "warn", "#e07b00": "warn"}
# Machado, Oliveira & Fernandes (2009), severity 1.0, linear RGB
CVD_MATRICES = {
    "protan": ((0.152286, 1.052583, -0.204868),
               (0.114503, 0.786281, 0.099216),
               (-0.003882, -0.048116, 1.051998)),
    "deutan": ((0.367322, 0.860646, -0.227968),
               (0.280085, 0.672501, 0.047413),
               (-0.011820, 0.042940, 0.968881)),
    "tritan": ((1.255528, -0.076749, -0.178779),
               (-0.078411, 0.930809, 0.147602),
               (0.004733, 0.691367, 0.303900)),
}


def _srgb_lin(c):
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def cvd_lab(hexcol, mode=""):
    """CIE Lab of a colour as seen with `mode` colour vision ("" = normal)."""
    r, g, b = (_srgb_lin(c / 255.0) for c in _hex_rgb(hexcol))
    if mode:
        m = CVD_MATRICES[mode]
        r, g, b = (max(0.0, min(1.0, m[i][0] * r + m[i][1] * g +
                                m[i][2] * b)) for i in range(3))
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

    def f(t):
        return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116
    return 116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))


def cvd_delta(a, b, mode=""):
    return math.dist(cvd_lab(a, mode), cvd_lab(b, mode))


def wcag_contrast(a, b):
    def lum(h):
        r, g, bb = (_srgb_lin(c / 255.0) for c in _hex_rgb(h))
        return 0.2126 * r + 0.7152 * g + 0.0722 * bb
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _cvd_shift(hexcol, mode, dark):
    """Move a saturated colour's hue to the mode's safe colour for its
    role (green → good, red → danger, amber → warn), keeping lightness."""
    import colorsys
    r, g, b = (c / 255.0 for c in _hex_rgb(hexcol))
    h, l_, s = colorsys.rgb_to_hls(r, g, b)
    if s < 0.25 or l_ < 0.06 or l_ > 0.97:
        return hexcol
    deg = h * 360
    role = "good" if 75 <= deg < 170 else "danger" if (
        deg >= 340 or deg < 15) else "warn" if 15 <= deg < 60 else ""
    if not role:
        return hexcol
    tgt = CVD_TRIPLES[(mode, dark)][("good", "warn", "danger").index(role)]
    th, _tl, ts = colorsys.rgb_to_hls(*(c / 255.0 for c in _hex_rgb(tgt)))
    r, g, b = colorsys.hls_to_rgb(th, l_, max(ts * 0.9, min(s, ts)))
    return _rgb_hex(r * 255, g * 255, b * 255)


def _build_cvd_palettes():
    taken = {}                       # palette value → canonical colour
    for tbl in PALETTES.values():
        for canon, val in tbl.items():
            taken.setdefault(val, canon)
    for canon in LIGHT_TO_DARK_HEX:
        taken.setdefault(canon, canon)

    def unique(h, canon):
        r, g, b = _hex_rgb(h)
        while taken.get(h, canon) != canon:
            b = (b + 1) % 256
            h = _rgb_hex(r, g, b)
        taken[h] = canon
        return h
    for base in ("Light", "Dark", "Light HC", "Dark HC"):
        dark = base.startswith("Dark")
        for mode in ("deutan", "protan", "tritan"):
            src = PALETTES[base]
            tbl = {}
            for canon in LIGHT_TO_DARK_HEX:
                role = CVD_ROLES.get(canon)
                if role:
                    val = CVD_TRIPLES[(mode, dark)][
                        ("good", "warn", "danger").index(role)]
                else:
                    val = _cvd_shift(src.get(canon, canon), mode, dark)
                tbl[canon] = unique(val, canon)
            name = f"{base} {mode}"
            PALETTES[name] = tbl
            for canon, val in tbl.items():
                if val != canon:
                    _CANON[val] = canon
            out = {}
            for k, v in THEMES[base].items():
                c = _CANON.get(v, v)
                out[k] = tbl.get(c) or _cvd_shift(v, mode, dark)
            THEMES[name] = out


_build_cvd_palettes()


def set_colorblind_mode(label_or_code):
    code = CVD_LABELS.get(label_or_code, label_or_code or "")
    CVD_STATE["mode"] = code if code in ("deutan", "protan",
                                         "tritan") else ""
    return CVD_STATE["mode"]
