P = "/home/claude/mw/miniwireshark.py"
src = open(P, encoding="utf8").read()
PATS = r'''
    # ---- V5.0.2: live status pieces
    (r"👀 Watching “(.+)”\.", r"👀 Observation de « \1 ».",
     r"👀 Observando «\1»."),
    (r"👀  Watching “(.+)”\.", r"👀  Observation de « \1 ».",
     r"👀  Observando «\1»."),
    (r"👀  “(.+)” didn't work, so I switched to “(.+)” automatically\.",
     r"👀  « \1 » n'a pas fonctionné, je suis passé automatiquement à "
     r"« \2 ».",
     r"👀  «\1» no funcionó, así que cambié automáticamente a «\2»."),
    (r"Picked because (.+)\.", r"Choisie parce que \1.",
     r"Elegida porque \1."),
    (r"Picked because (.+)", r"Choisie parce que \1", r"Elegida porque \1"),
    (r"([\d,]+) packets", r"\1 paquets", r"\1 paquetes"),
    (r"1 packet", r"1 paquet", r"1 paquete"),
    (r"([\d,]+) devices", r"\1 appareils", r"\1 dispositivos"),
    (r"1 device", r"1 appareil", r"1 dispositivo"),
    (r"([\d,]+) websites", r"\1 sites web", r"\1 sitios web"),
    (r"1 website", r"1 site web", r"1 sitio web"),
    (r"([\d,]+) open connections", r"\1 connexions ouvertes",
     r"\1 conexiones abiertas"),
    (r"1 open connection", r"1 connexion ouverte", r"1 conexión abierta"),
    (r"Network: (.+)\.", r"Réseau : \1.", r"Red: \1."),
    (r"🔵 QUIET MODE — “(.+)” is a network you haven't marked as yours, so "
     r"MiniWireshark is only listening and sends nothing\.",
     r"🔵 MODE DISCRET — « \1 » est un réseau que vous n'avez pas marqué "
     r"comme le vôtre : MiniWireshark écoute seulement et n'envoie rien.",
     r"🔵 MODO SILENCIOSO — «\1» es una red que no ha marcado como suya, así "
     r"que MiniWireshark solo escucha y no envía nada."),
    (r"it has a usable address \((.+)\)", r"elle a une adresse utilisable "
     r"(\1)", r"tiene una dirección utilizable (\1)"),
'''
anchor = "I18N_PATTERNS = [\n"
assert src.count(anchor) == 1
src = src.replace(anchor, anchor + PATS.strip("\n") + "\n")
open(P, "w", encoding="utf8").write(src)
print("ok")
