import sys,re,collections
# compare objdump (od.tsv: addr len mnem ops) with ghidra (addr len text)
XR={'xr1':'mdrq','xr2':'mcrh','xr3':'mcrl','xr4':'mcvf'}
def num(t):
    t=t.group(0)
    v=int(t,0) if not t.startswith('-') else -int(t[1:],0)
    return str(v & 0xffffffff)
def norm(s):
    s=s.replace(' ','')
    s=re.sub(r'\bxr[1-4]\b',lambda m:XR[m.group(0)],s)
    s=re.sub(r'-?0x[0-9a-fA-F]+|-?\b\d+\b',num,s)
    return s
od={}
for line in open(sys.argv[1]):
    a,l,mn,ops=line.rstrip('\n').split('\t')
    od[a]=(int(l),mn,ops)
bad=collections.Counter; ex={}
n=ok=0
for line in open(sys.argv[2]):
    a,l,txt=line.rstrip('\n').split('\t',2)
    if a not in od: continue
    n+=1
    ol,mn,ops=od[a]
    gmn,_,gops=txt.partition(' ')
    if mn=='unknown':
        key=('unknown', gmn if l!='0' else '??')
        if l=='0': ok+=1; continue
    elif int(l)!=ol or gmn!=mn or norm(gops)!=norm(ops):
        key=(mn,gmn,'len' if int(l)!=ol else 'ops')
    else:
        ok+=1; continue
    bad[key]+=1
    ex.setdefault(key,(a,ol,mn,ops,l,txt))
print('compared',n,'ok',ok,'bad',n-ok)
for k,c in bad.most_common(60):
    print(c,k,ex[k])
