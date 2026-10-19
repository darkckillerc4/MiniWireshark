import sys, os
os.environ["MINIWIRESHARK_DATA"]="/home/claude/mw/scratch/data"
sys.argv=["x","--self-test"]
import importlib.util
spec=importlib.util.spec_from_file_location("mw","/home/claude/mw/miniwireshark.py")
mw=importlib.util.module_from_spec(spec); sys.modules["mw"]=mw; spec.loader.exec_module(mw)
mw.load_scapy()
import time
t=time.time(); fr=mw.ScenarioBuilder().home_network(); print(len(fr),"frames", time.time()-t)
c=mw.AppConfig(path="/tmp/x_cfg.json")
m=mw.scenario_model(c, fr)
print(mw.golden_checks(m))
for d in m.registry.by_key.values(): print(d.key, d.ip, d.display_name(), d.device_class, sorted(d.ipv6))
