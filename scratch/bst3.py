exec(open("/home/claude/mw/scratch/t_scn.py").read().split("import time")[0])
import time, tempfile, os, sqlite3, json
tmp=tempfile.mkdtemp(); p=os.path.join(tmp,"b.sqlite3")
st=mw.Store(p)
n=5000
obs=[(i, 1700000000.0+i*0.01, "dns_answer", f"dev{i%50}", {"domain": f"d{i%900}.example","ip":"93.184.215.14"}, i) for i in range(n)]
rows = [(o[1], 1, 6, o[3], json.dumps(o[4]), o[5]) for o in obs]
def job(con):
    t=time.time()
    for k in range(0,5000,500):
        con.executemany("INSERT INTO observations VALUES(?,?,?,?,?,?)", rows[k:k+500])
        print(k, time.time()-t, flush=True)
st.submit(job); st.flush_now(30)
