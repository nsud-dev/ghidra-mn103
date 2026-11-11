import sys,re
# objdump -D listing -> addr \t length \t mnemonic \t operands
out=open(sys.argv[2],'w')
cur=None
for line in open(sys.argv[1]):
    if not line[:1].isalnum or ':\t' not in line: continue
    p=line.rstrip('\n').split('\t')
    a=p[0].rstrip(':')
    if not re.fullmatch(r'[0-9a-f]+',a): continue
    nb=len(p[1].split)
    if len(p)>=3 and p[2].strip:
        if cur: out.write('%s\t%d\t%s\t%s\n'%tuple(cur))
        cur=[a,nb,p[2].strip,p[3].strip if len(p)>3 else '']
    else:
        if cur: cur[1]+=nb
if cur: out.write('%s\t%d\t%s\t%s\n'%tuple(cur))
