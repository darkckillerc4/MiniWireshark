import sys, os, tempfile
os.environ["MINIWIRESHARK_DATA"]=tempfile.mkdtemp()
sys.argv=["x","--self-test"]
import importlib.util
spec=importlib.util.spec_from_file_location("mw","/home/claude/mw/miniwireshark.py")
mw=importlib.util.module_from_spec(spec); sys.modules["mw"]=mw; spec.loader.exec_module(mw)
mw.load_scapy()
ctx=mw.TestContext(tempfile.mkdtemp(), True)
for fn,_s in mw.SELF_TESTS:
    if any(k in fn.__name__ for k in os.environ.get("T","").split(",")):
        print(fn.__name__, fn(ctx))
