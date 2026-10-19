exec(open("/home/claude/mw/scratch/t_scn.py").read().split("import time")[0])
import time, tempfile, os
tmp=tempfile.mkdtemp(); st=mw.Store(os.path.join(tmp,"b.sqlite3"))
n=20000
obs=[(i, 1700000000.0+i*0.01, "dns_answer", f"dev{i%50}", {"domain": f"d{i%900}.example","ip":"93.184.215.14"}, i) for i in range(n)]
t=time.perf_counter()
for k in range(0,n,5000):
    print("submit", st.write_observations(obs[k:k+5000]), time.perf_counter()-t)
print("flush", st.flush_now(5), time.perf_counter()-t)
print(st.counts())
import faulthandler, sys
faulthandler.dump_traceback(sys.stdout, all_threads=True)
print(st.error, st.q.qsize(), st._thread.is_alive())
