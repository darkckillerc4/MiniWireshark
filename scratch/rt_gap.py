import os, sys, time
os.environ["MINIWIRESHARK_DATA"] = "/tmp/claude-0/rt314data"
sys.argv = ["mw", "--self-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging()
mgr = mw.RuntimeManager()
st = mgr.status(); exe = st["python"]; print("private:", exe, st["healthy"])
t=time.time(); rep = mgr.diagnose(exe); print(rep["text"]); print(rep["worst"], f"{time.time()-t:.1f}s")
print("system:"); print(mgr.diagnose(sys.executable)["text"])
t=time.time(); print("pip:", mgr.update_pip(exe)); print(f"{time.time()-t:.1f}s")
try:
    mgr.update_pip(sys.executable); print("BAD: system pip touched")
except mw.RuntimeError_ as e: print("refused system pip:", e)
t=time.time(); print("repair:", mgr.repair(lambda *a: print("  ", a[0], a[2]))); print(f"{time.time()-t:.1f}s", mgr.last_pip_problems)
try:
    print("newer:", mgr.newer_python_source())
except Exception as e: print("newer: offline here:", type(e).__name__, e)
