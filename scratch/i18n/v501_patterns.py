P = "/home/claude/mw/miniwireshark.py"
src = open(P, encoding="utf8").read()
PATS = r'''
    # ---- V5.0.1
    (r"What's new in (\d+\.\d+)", r"Nouveautés de la \1",
     r"Novedades de la \1"),
    (r"“(.+)” is not a packet number\.",
     r"« \1 » n'est pas un numéro de paquet.",
     r"«\1» no es un número de paquete."),
    (r"Saved connection #(\d+) to (.+?) \(redacted: mail, web or login "
     r"protocol\)\.",
     r"Connexion n° \1 enregistrée dans \2 (masquée : messagerie, web ou "
     r"protocole de connexion).",
     r"Conexión n.º \1 guardada en \2 (ocultada: correo, web o protocolo "
     r"de inicio de sesión)."),
    (r"Saved connection #(\d+) to (.+)\.",
     r"Connexion n° \1 enregistrée dans \2.",
     r"Conexión n.º \1 guardada en \2."),
    (r"Exported ([\d,]+) expert findings to (.+)\.",
     r"\1 constats d'expert exportés dans \2.",
     r"\1 hallazgos de experto exportados a \2."),
'''
anchor = '''    # V5 teach-once device types'''
assert src.count(anchor) == 1
src = src.replace(anchor, PATS.strip("\n") + "\n" + anchor)
open(P, "w", encoding="utf8").write(src)
print("patterns ok")
