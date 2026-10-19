exec(open("/home/claude/mw/scratch/t_scn.py").read().split("import time")[0])
fr=mw.ScenarioBuilder().home_network()
c=mw.AppConfig(path="/tmp/x_cfg2.json")
m=mw.NetworkModel(c,"",set(),set()); m.use_packet_clock=True
mw.replay_frames(m, fr)
gw=m.infer_gateway(); m.set_identity(gateway_ip=gw); m.tick()
m._classify_dirty |= set(m.registry.by_key); m._classify()
print(mw.golden_checks(m))
for d in m.registry.by_key.values(): print(d.key, d.ip, d.display_name(), d.device_class, d.services, d.class_reasons[:3])
