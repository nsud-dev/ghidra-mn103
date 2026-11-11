import sys,subprocess,re
D,pc=sys.argv[1],int(sys.argv[2],16)
nm=subprocess.run(['~/work/mn103/mn10300-elf/bin/nm','-n',D+'/tests.o'],capture_output=True,text=True).stdout
last=None
for l in nm.split('\n'):
    p=l.split
    if len(p)==3 and re.fullmatch(r'T\d+',p[2]) and int(p[0],16)<=pc: last=int(p[2][1:])
t=[x.rstrip('\n').split('\t') for x in open(D+'/tests.tsv')][last]
ops=t[3]
s=re.sub(r'\b[dar]\d\b','R',ops); s=re.sub(r'-?0x[0-9a-f]+|-?\b\d+\b','N',s)
print(t[2]+' '+s)
