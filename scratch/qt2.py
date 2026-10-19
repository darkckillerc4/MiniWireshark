import sys, os, tempfile
os.environ["MINIWIRESHARK_DATA"]="/tmp/claude-0/qtdata"
sys.argv=["x","--self-test"]
import importlib.util
spec=importlib.util.spec_from_file_location("mw","/home/claude/mw/miniwireshark.py")
mw=importlib.util.module_from_spec(spec); sys.modules["mw"]=mw; spec.loader.exec_module(mw)
mw.load_scapy()
mw._QUIC_CRYPTO=(mw.aes128_ecb_encrypt, lambda k,n,d,a: mw._aes_gcm_py(k,n,d,a,True), "pure Python")
ctx=mw.TestContext(tempfile.mkdtemp(), True)
print("budget", mw.QuicInitialReader().budget)
for fn,_s in mw.SELF_TESTS:
    if "quic" in fn.__name__:
        print(fn.__name__, fn(ctx))
