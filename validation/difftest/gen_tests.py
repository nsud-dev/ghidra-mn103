#!/usr/bin/env python3
"""Build a differential test program: one instruction per test, run under the GDB mn10300 sim (am33-2)
and under Ghidra's p-code emulator with the generated SLEIGH, then compare registers, flags and memory.

usage: gen_tests.py fuzz_od.tsv fuzz.bin outdir [per_shape]
"""
import sys, re, random, collections, os, subprocess

OD, BIN, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
PER = int(sys.argv[4]) if len(sys.argv) > 4 else 25
BASE = 0x60021020
data = open(BIN, 'rb').read
random.seed(7)

SKIP = re.compile(r'^(b..|bra|bnc|bns|bvc|bvs|l..|lra|setlb|call|calls|jmp|ret|retf|rets|rti|rtm|trap|syscall|break|nop|movm|unknown'
                  r'|udf\d+|udfu\d+|f.*|itof|ftoi|ftod|dtof|getx|putx|getchx|getclx|dcpf|mcst.*|mac.*|dmach.*|dmulh.*|bsch|.*_l..|.*_lra|.*dmach.*)$')
SYSREG = re.compile(r'\b(usp|ssp|msp|epsw|pc|mdrq|mcrh|mcrl|mcvf|xr\d+|sp)\b')

def shape(ops):
    s = re.sub(r'\b[dar]\d\b', 'R', ops)
    s = re.sub(r'-?0x[0-9a-f]+|-?\b\d+\b', 'N', s)
    return s

EXCL = set(l.strip for l in open(os.path.join(OUT, 'exclude.txt'))) if os.path.exists(os.path.join(OUT, 'exclude.txt')) else set
pool = collections.defaultdict(list)
for line in open(OD):
    a, l, mn, ops = line.rstrip('\n').split('\t')
    if SKIP.match(mn): continue
    if '%s %s' % (mn, shape(ops)) in EXCL: continue
    if SYSREG.search(ops): continue
    mem = '(' in ops
    if mem:
        # only register-based addressing with small displacements; no index forms, no absolute addresses
        inner = re.findall(r'\(([^)]*)\)', ops)[0]
        parts = inner.replace('+', '').split(',')
        regs = [p for p in parts if re.fullmatch(r'[dar]\d', p)]
        nums = [p for p in parts if not re.fullmatch(r'[dar]\d', p)]
        if len(regs) != 1: continue
        if any(abs(int(n, 0)) > 0x300 for n in nums if n): continue
    if mn in ('div', 'divu'): pass
    key = (mn, shape(ops))
    pool[key].append((int(a, 16), int(l), mn, ops))

tests = []
for key, lst in sorted(pool.items):
    for a, l, mn, ops in random.sample(lst, min(PER, len(lst))):
        tests.append((a, l, mn, ops))
print(len(tests), 'tests from', len(pool), 'shapes', file=sys.stderr)

REGS = ['d0', 'd1', 'd2', 'd3', 'a0', 'a1', 'a2', 'a3', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7']
OUTB = 0x03800000          # register dump area (sim)
REC = 4 * 20
REGION0 = 0x01000000        # per-test 4 KB data regions
SPV = 0x00700000

def pattern(addr):
    return ((addr * 2654435761) >> 13) & 0xff

os.makedirs(OUT, exist_ok=True)
asm = ['\t.am33_2', '\t.text', '\t.global _start', '_start:']
meta = open(os.path.join(OUT, 'tests.tsv'), 'w')
for i, (a, l, mn, ops) in enumerate(tests):
    region = REGION0 + i * 0x1000
    mem = '(' in ops
    vals = {}
    for r in REGS:
        if mem:
            vals[r] = region + 0x400 + 4 * random.randrange(0x100)
        elif mn in ('div', 'divu') and random.random < 0.7:
            vals[r] = random.choice([random.getrandbits(32), random.getrandbits(16), random.getrandbits(8) + 1])
        else:
            vals[r] = random.choice([random.getrandbits(32), random.getrandbits(8), (-random.getrandbits(8)) & 0xffffffff,
                                     0, 0x80000000, 0x7fffffff, 0xffffffff, random.getrandbits(16)])
    mdr = random.getrandbits(32) if mn not in ('div', 'divu') else random.choice([0, random.getrandbits(8), random.getrandbits(32)])
    flags = random.getrandbits(4)
    vals['mdr'] = mdr; vals['psw'] = 0x100000 | flags; vals['sp'] = SPV
    insn = data[a - BASE:a - BASE + l]
    asm.append('# test %d: %s %s' % (i, mn, ops))
    asm.append('T%d:' % i)
    asm.append('\tmov 0x%x,a0' % SPV); asm.append('\tmov a0,sp')
    asm.append('\tmov 0x%x,d0' % mdr); asm.append('\tmov d0,mdr')
    asm.append('\tmov 0x%x,d0' % vals['psw'])
    for r in REGS[8:]: asm.append('\tmov 0x%x,%s' % (vals[r], r))
    for r in REGS[4:8]: asm.append('\tmov 0x%x,%s' % (vals[r], r))
    for r in REGS[1:4]: asm.append('\tmov 0x%x,%s' % (vals[r], r))
    asm.append('\tmov d0,psw')
    asm.append('\tmov 0x%x,d0' % vals['d0'])
    asm.append('\t.byte ' + ','.join('0x%02x' % b for b in insn))
    o = OUTB + i * REC
    for k, r in enumerate(REGS[:8]): asm.append('\tmov %s,(0x%x)' % (r, o + 4 * k))
    for k, r in enumerate(REGS[8:]):
        asm.append('\tmov %s,d0' % r); asm.append('\tmov d0,(0x%x)' % (o + 32 + 4 * k))
    asm.append('\tmov psw,d0'); asm.append('\tmov d0,(0x%x)' % (o + 64))
    asm.append('\tmov mdr,d0'); asm.append('\tmov d0,(0x%x)' % (o + 68))
    asm.append('\tmov sp,a0'); asm.append('\tmov a0,(0x%x)' % (o + 72))
    meta.write('%d\t%x\t%s\t%s\t%s\t%s\t%x\n' % (i, a, mn, ops, insn.hex, ' '.join('%s=%x' % (k, v) for k, v in vals.items), region))
# write(1, OUTB, n*REC); write(1, REGION0, n*4096); exit(0)
def sys_write(addr, n):
    return ['\tmov 0x%x,a0' % SPV, '\tmov a0,sp', '\tmov 0x%x,d0' % addr, '\tmov d0,(12,sp)', '\tmov 0x%x,d0' % n, '\tmov d0,(16,sp)',
            '\tmov 5,d0', '\tmov 1,d1', '\t.byte 0xf0,0xc0']
asm += sys_write(OUTB, len(tests) * REC)
asm += sys_write(REGION0, len(tests) * 0x1000)
asm += ['\tmov 1,d0', '\tmov 0,d1', '\t.byte 0xf0,0xc0']
# initial memory: deterministic pattern in each region (assembled as data at the region addresses)
pat = bytes(pattern(REGION0 + k) for k in range(len(tests) * 0x1000))
open(os.path.join(OUT, 'regions.bin'), 'wb').write(pat)
asm += ['\t.org 0x%x' % REGION0, '\t.incbin "%s"' % os.path.join(OUT, 'regions.bin')]
open(os.path.join(OUT, 'tests.s'), 'w').write('\n'.join(asm) + '\n')
meta.close
