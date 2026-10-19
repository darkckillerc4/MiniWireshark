exec(open("/home/claude/mw/scratch/t_scn.py").read().split("import time")[0])
import time, tempfile, os, sqlite3
tmp=tempfile.mkdtemp(); p=os.path.join(tmp,"b.sqlite3")
st=mw.Store(p)
def job(con):
    print("iso", repr(con.isolation_level), con.in_transaction)
    t=time.time()
    con.executemany("INSERT INTO observations VALUES(?,?,?,?,?,?)", [(1.0,1,1,"d","{}",i) for i in range(2000)])
    print("exec", time.time()-t)
st.submit(job); st.flush_now(30)
