exec(open("/home/claude/mw/scratch/t_scn.py").read().split("import time")[0])
import time, tempfile, os
tmp=tempfile.mkdtemp(); st=mw.Store(os.path.join(tmp,"b.sqlite3"))
n=20000
obs=[(i, 1700000000.0+i*0.01, "dns_answer", f"dev{i%50}", {"domain": f"d{i%900}.example","ip":"93.184.215.14"}, i) for i in range(n)]
orig=st.submit
def sub(job):
    def timed(con, job=job):
        t=time.time(); job(con); print("job", time.time()-t, flush=True)
    return orig(timed)
st.submit=sub
t=time.perf_counter()
for k in range(0,5000,5000):
    st.write_observations(obs[k:k+5000])
print("flush", st.flush_now(20), time.perf_counter()-t)
