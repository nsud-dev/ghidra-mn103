#!/usr/bin/env python3
"""Compare GDB sim results (sim.out) with Ghidra emulator results (emu.tsv). usage: compare_emu.py dir"""
import sys, struct, zlib, collections, re
D = sys.argv[1]
tests = [l.rstrip('\n').split('\t') for l in open(D + '/tests.tsv')]
n = len(tests)
raw = open(D + '/sim.out', 'rb').read
REC = 80
REGS = ['d0', 'd1', 'd2', 'd3', 'a0', 'a1', 'a2', 'a3', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7']
emu = {}
for l in open(D + '/emu.tsv'):
    p = l.rstrip('\n').split('\t')
    emu[p[0]] = p[1:]
bad = collections.Counter; ex = {}
okc = 0; skipped = 0
def shape(ops):
    s = re.sub(r'\b[dar]\d\b', 'R', ops)
    return re.sub(r'-?0x[0-9a-f]+|-?\b\d+\b', 'N', s)
for i, t in enumerate(tests):
    w = struct.unpack('<20I', raw[i * REC:(i + 1) * REC])
    region = raw[n * REC + i * 0x1000: n * REC + (i + 1) * 0x1000]
    sim = {r: w[k] for k, r in enumerate(REGS)}
    sim['flags'] = w[16] & 0xf; sim['mdr'] = w[17]; sim['sp'] = w[18]
    sim['mem'] = zlib.crc32(region) & 0xffffffff
    if '_' in t[2]:
        p = t[3].split(',')
        if len(p) == 4 and p[1] == p[3]:
            skipped += 1; continue          # dual op with both destinations equal: invalid encoding (sim requires Rn1 != Rn2)
    e = emu.get(t[0])
    key = (t[2], shape(t[3]))
    if e is None or e[0].startswith('E'):
        bad[key + ('emu-error')] += 1; ex.setdefault(key + ('emu-error'), (t, e)); continue
    g = {r: int(e[k], 16) for k, r in enumerate(REGS)}
    g['flags'] = int(e[16], 16); g['mdr'] = int(e[17], 16); g['sp'] = int(e[18], 16); g['mem'] = int(e[19], 16)
    diffs = [k for k in sim if sim[k] != g[k]]
    if not diffs:
        okc += 1; continue
    k2 = key + (','.join(diffs))
    bad[k2] += 1
    if k2 not in ex:
        init = dict(kv.split('=') for kv in t[5].split)
        ex[k2] = (t[:5], {d: ('init ' + init.get(d, '?'), 'sim %x' % sim[d], 'ghidra %x' % g[d]) for d in diffs})
print('tests', n, 'skipped (invalid dual-op encodings)', skipped, 'agree', okc, 'differ', n - okc - skipped)
for k, c in sorted(bad.items, key=lambda x: -x[1]):
    print(c, k, ex[k])
