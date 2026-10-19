import json,re,html,sys
d=json.loads(open(sys.argv[1]).read())["data"]; x=d["xml"]
out=[]
for m in re.finditer(r"<(paragraph|li|row)\b([^>]*)>(.*?)</\1>", x, re.S):
    attrs=m.group(2); body=m.group(3)
    body=re.sub(r"</cell>"," | ",body)
    t=html.unescape(re.sub(r"<[^>]+>","",body))
    h=re.search(r"heading='(\d)'",attrs)
    out.append(("#"*int(h.group(1))+" " if h else "")+t)
open("/home/claude/mw/scratch/plan.md","a").write("\n".join(out)+"\n")
print(len(out), d.get("next"), d.get("complete"))
