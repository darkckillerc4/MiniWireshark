P = "/home/claude/mw/miniwireshark.py"
src = open(P, encoding="utf8").read()
PATS = r'''
    # ---- V5.0.1: health info block and runtime status, line by line
    (r"Network card : (.*)", r"Carte réseau   : \1", r"Tarjeta de red : \1"),
    (r"This computer: (.*)", r"Cet ordinateur : \1", r"Este equipo    : \1"),
    (r"Subnet\(s\)    : (.*)", r"Sous-réseau(x) : \1",
     r"Subred(es)     : \1"),
    (r"Router       : (.*)", r"Box / routeur  : \1", r"Router         : \1"),
    (r"DNS servers  : (.*)", r"Serveurs DNS   : \1",
     r"Servidores DNS : \1"),
    (r"IPv6 prefix  : (.*)", r"Préfixe IPv6   : \1",
     r"Prefijo IPv6   : \1"),
    (r"Why this card: (.*)", r"Pourquoi cette carte : {t1}",
     r"Por qué esta tarjeta: {t1}"),
    (r"Wi-Fi        : (.*)", r"Wi-Fi          : \1", r"Wi-Fi          : \1"),
    (r"Switch port  : (.*)", r"Port du switch : \1",
     r"Puerto del switch: \1"),
    (r"Running on Python (\S+) \((.+)\) — the Python that started "
     r"MiniWireshark\. It is never modified\.",
     r"Exécuté avec Python \1 (\2) — le Python qui a lancé MiniWireshark. "
     r"Il n'est jamais modifié.",
     r"Ejecutándose con Python \1 (\2) — el Python que inició "
     r"MiniWireshark. Nunca se modifica."),
    (r"Running on MiniWireshark's managed Python (\S+) \((.+)\)\.",
     r"Exécuté avec le Python géré de MiniWireshark \1 (\2).",
     r"Ejecutándose con el Python gestionado de MiniWireshark \1 (\2)."),
    (r"Private packages folder \((.+)\): empty",
     r"Dossier des paquets privés (\1) : vide",
     r"Carpeta de paquetes privados (\1): vacía"),
    (r"Private packages folder \((.+)\): (.+)",
     r"Dossier des paquets privés (\1) : \2",
     r"Carpeta de paquetes privados (\1): \2"),
'''
anchor = '''    # ---- V5.0.1
'''
assert src.count(anchor) == 1
src = src.replace(anchor, PATS.strip("\n") + "\n" + anchor)
old = '''    def __init__(self, master=None, value=None, name=None):
        super().__init__(master, translate_text(value)
                         if isinstance(value, str) else value, name)

    def set(self, value):
        return super().set(translate_text(value)
                           if isinstance(value, str) else value)
'''
new = '''    @staticmethod
    def shown(value):
        if not isinstance(value, str):
            return value
        out = translate_text(value)
        if out == value and "\\n" in value:     # an info block: line by line
            out = translate_lines(value)
        return out

    def __init__(self, master=None, value=None, name=None):
        super().__init__(master, self.shown(value), name)

    def set(self, value):
        return super().set(self.shown(value))
'''
assert src.count(old) == 1
src = src.replace(old, new)
open(P, "w", encoding="utf8").write(src)
print("ok")
