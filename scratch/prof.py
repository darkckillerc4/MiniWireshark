exec(open("/home/claude/mw/scratch/t_scn.py").read().split("import time")[0])
import cProfile, pstats, tempfile, os
fr=mw.ScenarioBuilder().busy_mix(20000)
cfg=mw.AppConfig(path=os.path.join(tempfile.mkdtemp(),"c.json"))
m=mw.NetworkModel(cfg,*mw.scenario_identity()[:3]); m.set_identity(local_nets=mw.scenario_identity()[3]); m.use_packet_clock=True
dec=mw.default_frame_decoder(m)
ds=[dec(*f) for f in fr[:8000]]
pr=cProfile.Profile(); pr.enable()
for d in ds: m.ingest(d)
pr.disable()
pstats.Stats(pr).sort_stats("tottime").print_stats(18)
