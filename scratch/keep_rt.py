import os, sys
os.environ["MINIWIRESHARK_DATA"] = "/tmp/claude-0/rt314data"
sys.argv = ["mw", "--self-test"]
import importlib.util
spec = importlib.util.spec_from_file_location("mw", "/home/claude/mw/miniwireshark.py")
mw = importlib.util.module_from_spec(spec); sys.modules["mw"] = mw; spec.loader.exec_module(mw)
mw.setup_logging()
mgr = mw.RuntimeManager()
if not mgr.status()["healthy"]:
    mgr.provision(lambda *a: None)
print(mgr.status()["python"])
