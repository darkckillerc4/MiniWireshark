p='/home/claude/mw/miniwireshark.py'; s=open(p).read()
def rep(old,new,cnt=1):
    global s
    assert s.count(old)==cnt, (s.count(old), old[:90])
    s=s.replace(old,new)
exec(open('/home/claude/mw/scratch/store_edits.py').read())
open(p,'w').write(s)
