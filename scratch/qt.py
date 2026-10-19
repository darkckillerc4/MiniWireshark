import sys, os, time
os.environ["MINIWIRESHARK_DATA"]="/tmp/claude-0/qtdata"
sys.argv=["x","--self-test"]
import importlib.util
spec=importlib.util.spec_from_file_location("mw","/home/claude/mw/miniwireshark.py")
mw=importlib.util.module_from_spec(spec); sys.modules["mw"]=mw; spec.loader.exec_module(mw)
dcid=bytes.fromhex("8394c8f03e515708")
k,iv,hp=mw.quic_initial_keys(dcid)
print(k.hex(), iv.hex(), hp.hex())
assert k.hex()=="1f369613dd76d5467730efcbe3b1a22d"
assert iv.hex()=="fa044b2f42a3fd3b46fb255c"
assert hp.hex()=="9f50449e04a0e810283a1e9933adedd2"
ks=mw.quic_initial_keys(dcid, side="server"); print([x.hex() for x in ks])
m=mw.aes128_ecb_encrypt(hp, bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b"))
print("mask", m.hex()[:10]); assert m.hex()[:10]=="437b9aec36"
# FIPS-197 C.1 AES-128 vector
print(mw.aes128_ecb_encrypt(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), bytes.fromhex("00112233445566778899aabbccddeeff")).hex())
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os as o
for n in (0,1,15,16,17,100,1162):
    key=o.urandom(16); nonce=o.urandom(12); data=o.urandom(n); aad=o.urandom(23)
    a=AESGCM(key).encrypt(nonce,data,aad); b=mw._aes_gcm_py(key,nonce,data,aad,decrypt=False)
    assert a==b,(n)
    assert mw._aes_gcm_py(key,nonce,a,aad)==data
    assert mw._aes_gcm_py(key,nonce,a[:-1]+bytes([a[-1]^1]),aad) is None
print("gcm ok")
ch=mw.tls_client_hello("www.example.com")
pkt=mw.quic_build_initial(dcid, b"\x01\x02", ch)
print(len(pkt))
r=mw.QuicInitialReader(); print(r.feed(("a",1),pkt,1.0))
for impl in ("crypto","pure"):
    if impl=="pure":
        mw._QUIC_CRYPTO=(mw.aes128_ecb_encrypt, lambda k,n,d,a: mw._aes_gcm_py(k,n,d,a,True), "pure")
    t=time.time(); 
    for i in range(50): mw.quic_decrypt_initial(pkt)
    print(impl, (time.time()-t)/50*1000, "ms/packet")
rd=mw.QuicInitialReader(budget=5)
for i in range(50): rd.feed(("a",i), pkt, 10.0)
print(rd.decrypted, rd.failed, rd.skipped, rd._window)
