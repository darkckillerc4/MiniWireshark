import sys, os
os.environ["MINIWIRESHARK_DATA"]="/tmp/claude-0/qtdata"
sys.argv=["x","--self-test"]
import importlib.util, time
spec=importlib.util.spec_from_file_location("mw","/home/claude/mw/miniwireshark.py")
mw=importlib.util.module_from_spec(spec); sys.modules["mw"]=mw; spec.loader.exec_module(mw)
sk=bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
pk=mw.ed25519_public_key(sk); print(pk.hex())
sig=mw.ed25519_sign(sk,b""); print(sig.hex())
t=time.time(); print(mw._ed25519_verify_py(pk,b"",sig), time.time()-t)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k=Ed25519PrivateKey.from_private_bytes(sk); print(k.sign(b"").hex()==sig.hex())
sk2=bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
print(mw.ed25519_public_key(sk2).hex(), mw.ed25519_sign(sk2, bytes([0x72])).hex())
