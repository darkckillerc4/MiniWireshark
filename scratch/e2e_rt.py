import os, sys, time, tempfile
tmp = tempfile.mkdtemp(); os.environ["MINIWIRESHARK_DATA"] = tmp
sys.argv = ["mw", "--self-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging()
mgr = mw.RuntimeManager()
def prog(stage, frac, text, extra): print(f"  [{stage} {frac:.0%}] {text} {extra}", flush=True)
print("== 1. full install from the pinned download")
t = time.time()
eid = mgr.provision(prog)
print("  env", eid, "in", round(time.time()-t), "s")
print("  log tail:", list(mgr.log_lines)[-4:])
st = mgr.status(); print("  healthy:", st["healthy"], st["python"])
print("  handoff cmd:", mw.runtime_handoff([], {}, False))
print("== 3. repair offline from cache")
print("  ", mgr.repair(prog))
print("== 4. remove")
print("  ", mgr.remove(), os.path.exists(mw.RUNTIME_DIR))
