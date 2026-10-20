P = "/home/claude/mw/miniwireshark.py"
src = open(P, encoding="utf8").read()
PATS = r'''
    # ---- V5.0.2
    (r"Welcome to MiniWireshark (\d+)!", r"Bienvenue dans MiniWireshark \1 !",
     r"¡Bienvenido a MiniWireshark \1!"),
'''
anchor = "I18N_PATTERNS = [\n"
assert src.count(anchor) == 1
src = src.replace(anchor, anchor + PATS.strip("\n") + "\n")
open(P, "w", encoding="utf8").write(src)
print("ok")
