#!/usr/bin/env python3
"""Generate a Ghidra SLEIGH spec for the Panasonic MN103 / AM33 / AM33-2 from the
binutils opcode table (opcodes/m10300-opc.c, dumped to table.json by dump.c).

Decoding follows binutils' print_insn_mn10300 exactly:
  * instruction length comes from the first byte (and byte 1 for 0xfe), as in print_insn_mn10300;
  * the first table entry whose mask/opcode matches and whose format length equals that length wins
    (we turn table order into disjoint bit patterns, so SLEIGH never has to choose);
  * operand bits are traced through the same insn/extension shuffling the disassembler does.
Semantics follow the GDB simulator (sim/mn10300/*.igen).

usage: gen.py table.json opc.c outdir
"""
import json, re, sys, collections, os

TABLE, OPC_C, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
T = json.load(open(TABLE))
OPERANDS = T['operands']
src = open(OPC_C).read
OPNAMES = ['UNUSED'] + [m.group(1) for m in re.finditer(r'#define\s+(\w+)\s*\(\s*(\w+)\s*\+\s*1\s*\)', src)]

F_DREG, F_AREG, F_SP, F_PSW, F_MDR, F_SIGNED, F_PROMOTE, F_PAREN = 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80
F_REPEATED, F_EXTENDED, F_SPLIT, F_REGLIST, F_PCREL, F_MEMADDR = 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000
F_USP, F_SSP, F_MSP, F_PC, F_EPSW, F_RREG, F_XRREG, F_PLUS, F_24 = 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000
F_FS, F_FD, F_FPCR = 0x1000000, 0x2000000, 0x4000000

FMT = dict(S0=1, S1=2, S2=3, S4=4, S6=5, D0=6, D1=7, D2=8, D4=9, D5=10, D6=11, D7=12, D8=13, D9=14, D10=15, D3=16)
FMTN = {v: k for k, v in FMT.items}
AM30, AM33, AM33_2 = 300, 330, 332

def mysize(fmt):
    f = FMTN[fmt]
    return {'S0': 1, 'S1': 2, 'D0': 2, 'S2': 3, 'D1': 3, 'S4': 5, 'D2': 4, 'D3': 5, 'D4': 6, 'D6': 3,
            'D7': 4, 'D10': 4, 'D8': 6, 'D9': 7}.get(f, 7)

def consume(b0, b1=0):
    """print_insn_mn10300's length decision."""
    i = b0
    if ((i & 0xf3) == 0x00 or (i & 0xf0) == 0x10 or (i & 0xfc) == 0x3c or (i & 0xf3) == 0x41
            or (i & 0xf3) == 0x40 or (i & 0xfc) == 0x50 or (i & 0xfc) == 0x54 or (i & 0xf0) == 0x60
            or (i & 0xf0) == 0x70
            or ((i & 0xf0) in (0x80, 0x90, 0xa0, 0xb0) and (i & 0x0c) >> 2 != (i & 0x03))
            or i == 0xcb or (i & 0xfc) in (0xd0, 0xd4, 0xd8) or (i & 0xf0) == 0xe0 or i == 0xff):
        return 1
    if ((i & 0xf0) in (0x80, 0x90, 0xa0, 0xb0) or (i & 0xfc) in (0x20, 0x28) or (i & 0xf3) in (0x43, 0x42)
            or (i & 0xfc) in (0x58, 0x5c) or ((i & 0xf0) == 0xc0 and i not in (0xcb, 0xcc, 0xcd))
            or i in (0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6)):
        return 2
    if (i in (0xf8, 0xcc, 0xf9, 0xde, 0xdf) or (i & 0xf3) in (0x01, 0x02, 0x03)
            or (i & 0xfc) in (0x24, 0x2c, 0x30, 0x34, 0x38)):
        return 3
    if i in (0xfa, 0xf7, 0xfb):
        return 4
    if i in (0xcd, 0xdc):
        return 5
    if i in (0xfd, 0xfc):
        return 6
    if i == 0xfe and (b1 & 0xf8) == 0x80:
        return 5
    return 7

# ---------------------------------------------------------------- symbolic bit vectors
# A value is a list of 32 entries, index = bit number; entry None (zero) or (byte, bit).
def sv_zero:
    return [None] * 32
def sv_getb(start, n):
    v = sv_zero
    for k in range(n):
        for b in range(8):
            v[(n - 1 - k) * 8 + b] = (start + k, b)
    return v
def sv_getl(start, n):
    v = sv_zero
    for k in range(n):
        for b in range(8):
            v[k * 8 + b] = (start + k, b)
    return v
def sv_and(v, m):
    return [v[i] if (m >> i) & 1 else None for i in range(32)]
def sv_or(a, b):
    r = []
    for x, y in zip(a, b):
        assert x is None or y is None, 'overlapping or'
        r.append(x if x is not None else y)
    return r
def sv_shl(v, n):
    return [v[i - n] if 0 <= i - n < 32 else None for i in range(32)]
def sv_shr(v, n):
    return [v[i + n] if 0 <= i + n < 32 else None for i in range(32)]

def reconstruct(op, size):
    """Mirror of disassemble: returns (insn, extension, extra_shift)."""
    name, opcode, mask, nomatch, fmt, mach, ops = op
    f = FMTN[fmt]
    if size == 1: insn = sv_getb(0, 1)
    elif size == 2: insn = sv_getb(0, 2)
    elif size == 3: insn = sv_or(sv_shl(sv_getb(0, 2), 8), sv_getb(2, 1))
    else: insn = sv_getb(0, 4)
    ext = sv_zero
    if f in ('D1', 'S1'): xs = 8
    elif f in ('D2', 'D4', 'S2', 'S4', 'S6', 'D5'): xs = 16
    elif f in ('D7', 'D8', 'D9'): xs = 8
    else: xs = 0
    if size in (1, 2):
        pass
    elif size == 3 and (f == 'D1' or opcode in (0xdf0000, 0xde0000)):
        pass
    elif size == 3 and f == 'D6':
        pass
    elif size == 3:
        insn = sv_or(sv_and(insn, 0xff0000), sv_getl(1, 2))
    elif size == 4 and opcode in (0xfaf80000, 0xfaf00000, 0xfaf40000):
        pass
    elif size == 4 and f in ('D7', 'D10'):
        pass
    elif size == 4:
        insn = sv_or(sv_and(insn, 0xffff0000), sv_getl(2, 2))
    elif size == 5 and opcode == 0xdc000000:
        temp = sv_getl(1, 4)
        insn = sv_or(sv_and(insn, 0xff000000), sv_shr(sv_and(temp, 0xffffff00), 8))
        ext = sv_and(temp, 0xff)
    elif size == 5 and f == 'D3':
        insn = sv_or(sv_and(insn, 0xffff0000), sv_getl(2, 2))
        ext = sv_getl(4, 1)
    elif size == 5:
        temp = sv_getl(1, 2)
        insn = sv_or(sv_and(insn, 0xff0000ff), sv_shl(temp, 8))
        ext = sv_getl(4, 1)
    elif size == 6 and f == 'D8':
        insn = sv_or(sv_and(insn, 0xffffff00), sv_getl(5, 1))
        ext = sv_getl(3, 2)
    elif size == 6:
        temp = sv_getl(2, 4)
        insn = sv_or(sv_and(insn, 0xffff0000), sv_and(sv_shr(temp, 16), 0xffff))
        ext = sv_and(temp, 0xffff)
    elif size == 7 and f == 'D9':
        insn = sv_and(insn, 0xffffff00)
        e = sv_getl(3, 4)
        insn = sv_or(insn, sv_shr(sv_and(e, 0xff000000), 24))
        ext = sv_and(e, 0xffffff)
    elif size == 7 and opcode == 0xdd000000:
        temp = sv_getl(1, 4)
        insn = sv_or(sv_and(insn, 0xff000000), sv_and(sv_shr(temp, 8), 0xffffff))
        ext = sv_or(sv_shl(sv_and(temp, 0xff), 16), sv_getb(5, 2))
    elif size == 7:
        temp = sv_getl(2, 4)
        insn = sv_or(sv_and(insn, 0xffff0000), sv_and(sv_shr(temp, 16), 0xffff))
        ext = sv_or(sv_shl(sv_and(temp, 0xffff), 8), sv_getl(6, 1))
    return insn, ext, xs

def m(n):
    return (1 << n) - 1

def operand_bits(opidx, insn, ext, xs):
    """Return (kind, bits msb-first, signed) for one operand, mirroring the print loop."""
    bits_, shift, flags = OPERANDS[opidx]
    if flags & (F_DREG | F_AREG | F_RREG | F_XRREG):
        v = sv_and(sv_shr(insn, shift + xs), m(bits_))
        n = bits_
    elif flags & F_SPLIT:
        hi = sv_shl(sv_and(insn, m(bits_)), 32 - bits_)
        lo = sv_and(sv_shr(ext, shift), m(32 - bits_))
        v = sv_or(hi, lo); n = 32
    elif flags & F_24:
        hi = sv_shl(sv_and(insn, m(bits_)), 24 - bits_)
        lo = sv_and(sv_shr(ext, shift), m(24 - bits_))
        v = sv_or(hi, lo); n = 24
    elif flags & (F_FS | F_FD):
        if bits_ == 5:
            if shift >= 0:
                shl_low = shift; shl_high = 8 + (8 & shl_low) + (shl_low & 4) // 4
            else:
                shl_low = -shift; shl_high = shl_low // 4
            mlow, mhigh, shr_high = 0x0f, 0x10, 4
        else:
            shl_low = -shift; shl_high = 0; mlow, mhigh, shr_high = 0x03, 0x04, 2
        v = sv_or(sv_and(sv_shl(sv_shr(insn, shl_high), shr_high), mhigh), sv_and(sv_shr(insn, shl_low), mlow))
        n = 5 if bits_ == 5 else 3
    elif flags & F_EXTENDED:
        v = sv_and(sv_shr(ext, shift), m(bits_)); n = bits_
    else:
        v = sv_and(sv_shr(insn, shift), m(bits_)); n = bits_
    signed = bool(flags & F_SIGNED)
    return [v[i] for i in range(n - 1, -1, -1)], signed

# ---------------------------------------------------------------- cubes (mask, value) over first 4 bytes BE
def cube_inter(a, b):
    (ma, va), (mb, vb) = a, b
    if ma & mb & (va ^ vb): return None
    return (ma | mb, (va & ma) | (vb & mb))
def cube_sub(a, b):
    if cube_inter(a, b) is None: return [a]
    ma, va = a; mb, vb = b
    out = []
    free = mb & ~ma
    cm, cv = ma, va
    for bit in range(31, -1, -1):
        if (free >> bit) & 1:
            out.append((cm | (1 << bit), (cv & ~(1 << bit)) | ((~vb) & (1 << bit))))
            cm |= 1 << bit; cv = (cv & ~(1 << bit)) | (vb & (1 << bit))
    return out
def cube_merge(cs):
    cs = set(cs)
    changed = True
    while changed:
        changed = False
        bym = collections.defaultdict(set)
        for c in cs: bym[c[0]].add(c[1])
        for mk, vals in bym.items:
            for v in list(vals):
                if v not in vals: continue
                for bit in range(32):
                    if (mk >> bit) & 1:
                        w = v ^ (1 << bit)
                        if w in vals and w != v:
                            vals.discard(v); vals.discard(w)
                            nm = mk & ~(1 << bit)
                            cs.discard((mk, v)); cs.discard((mk, w))
                            cs.add((nm, v & nm))
                            changed = True
                            break
                if changed: break
            if changed: break
    return sorted(cs)

def first_byte_cubes(size):
    """Cubes (over 32-bit BE prefix) of first bytes for which print_insn picks this size."""
    cs = []
    for b0 in range(256):
        if b0 == 0xfe:
            if size == 5: cs.append((0xfff80000, 0xfe800000))
            elif size == 7: cs += cube_sub((0xff000000, 0xfe000000), (0xfff80000, 0xfe800000))
            continue
        if consume(b0) == size:
            cs.append((0xff000000, b0 << 24))
    return cs

# ---------------------------------------------------------------- operand parsing
REGNAMES_R = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'a0', 'a1', 'a2', 'a3', 'd0', 'd1', 'd2', 'd3']
REGNAMES_XR = ['sp', 'mdrq', 'mcrh', 'mcrl', 'mcvf', 'xr5', 'xr6', 'xr7', 'xr8', 'xr9', 'xr10', 'xr11', 'xr12', 'xr13', 'xr14', 'xr15']
FIELDS = collections.defaultdict(dict)   # byte -> {fieldname: (lo, hi, signed)}
ATTACH = collections.defaultdict(list)   # regset -> [fieldnames]
SUBTABLES = {}                           # name -> text
SUB_ORDER = []

def field(byte, lo, hi, suffix='', signed=False):
    if lo == 0 and hi == 7 and not suffix and not signed: return 'b%d' % byte
    nm = 'f%d_%d_%d%s' % (byte, lo, hi, suffix)
    FIELDS[byte][nm] = (lo, hi, signed)
    return nm

def runs(bits):
    """bits msb-first -> list of ('f', byte, lo, hi) or ('z', n)."""
    out = []
    for b in bits:
        if b is None:
            if out and out[-1][0] == 'z': out[-1] = ('z', out[-1][1] + 1)
            else: out.append(('z', 1))
        else:
            byte, bit = b
            if out and out[-1][0] == 'f' and out[-1][1] == byte and out[-1][2] == bit + 1:
                out[-1] = ('f', byte, bit, out[-1][3])
            else:
                out.append(('f', byte, bit, bit))
    return out

CUR_SIZE = None
def tok_prefix(maxbyte, uses, pad=True):
    if pad and CUR_SIZE is not None: maxbyte = max(maxbyte, CUR_SIZE - 1)
    """Pattern t0;t1;...;t{maxbyte} where 'uses' maps byte->list of fieldnames to mention."""
    parts = []
    for k in range(maxbyte + 1):
        fs = uses.get(k, [])
        parts.append(' & '.join(fs) if fs else 'b%d' % k)
    return ' ; '.join(parts)

def add_sub(name, text):
    if name not in SUBTABLES:
        SUBTABLES[name] = text; SUB_ORDER.append(name)
    return name

def value_expr(bits):
    """Disassembly-time expression for an unsigned value made of these bits. Returns (expr, uses, nbits)."""
    rs = runs(bits)
    total = len(bits)
    pos = total
    terms = []; uses = collections.defaultdict(list)
    for r in rs:
        if r[0] == 'z':
            pos -= r[1]; continue
        _, byte, lo, hi = r
        w = hi - lo + 1
        pos -= w
        fn = field(byte, lo, hi)
        uses[byte].append(fn)
        terms.append('(%s << %d)' % (fn, pos) if pos else fn)
    return (' | '.join(terms) if terms else '0'), uses, total

def reg_operand(bits, regset):
    rs = runs(bits)
    assert len(rs) == 1 and rs[0][0] == 'f', (bits, regset)
    _, byte, lo, hi = rs[0]
    suffix = {'D': 'D', 'A': 'A', 'R': 'R', 'XR': 'X'}[regset]
    fn = field(byte, lo, hi, suffix)
    if fn not in ATTACH[regset]: ATTACH[regset].append(fn)
    return fn, byte

def fp_operand(bits, kind):
    """FS/FD register made of non-contiguous bits: subtable with one constructor per register."""
    key = '%s_%s_L%d' % (kind, '_'.join('%d%d' % b for b in bits), CUR_SIZE)
    name = 'op' + key.replace('-', 'm')
    if name in SUBTABLES: return name
    rs = runs(bits)
    lines = []
    maxbyte = max(b[0] for b in bits if b)
    for val in range(1 << len(bits)):
        uses = collections.defaultdict(list)
        pos = len(bits)
        for r in rs:
            _, byte, lo, hi = r
            w = hi - lo + 1; pos -= w
            fn = field(byte, lo, hi)
            uses[byte].append('%s=%d' % (fn, (val >> pos) & m(w)))
        if kind == 'FD':
            if val & 1 and len(bits) == 5:
                continue      # odd fd numbers are not valid register pairs
            reg = 'fd%d' % val
        else:
            reg = 'fs%d' % val
        lines.append('%s: "%s" is %s { export %s; }' % (name, reg, tok_prefix(maxbyte, uses), reg))
    return add_sub(name, '\n'.join(lines))

def imm_operand(bits, signed, kind):
    """kind: 'imm' (constant), 'rel' (pc-relative code address), 'abs' (absolute address constant)."""
    expr, uses, n = value_expr(bits)
    key = '%s%s_%s_L%d' % (kind, 's' if signed else '', '_'.join('%d%d' % b if b else 'z' for b in bits), CUR_SIZE)
    name = 'op_' + key
    if name in SUBTABLES: return name
    maxbyte = max(b[0] for b in bits if b)
    e = '(%s)' % expr
    if signed and n < 64:
        e = '((%s ^ 0x%x) - 0x%x)' % (e, 1 << (n - 1), 1 << (n - 1))
    if kind == 'rel':
        e = '((inst_start + %s) & 0xffffffff)' % e
        exp = 'export *:4 v;'
    else:
        exp = 'export *[const]:4 v;'
    acts = ['v = %s + 0;' % e]
    uses2 = {k: list(dict.fromkeys(v)) for k, v in uses.items}
    txt = '%s: v is %s [ %s ] { %s }' % (name, tok_prefix(maxbyte, uses2), ' '.join(acts), exp)
    return add_sub(name, txt)

def reglist_bits(bits):
    rs = runs(bits)
    assert len(rs) == 1 and rs[0][0] == 'f' and rs[0][3] - rs[0][2] == 7
    return rs[0][1]

class Op:
    def __init__(self, kind, sym=None, signed=False, items=None, plus=False):
        self.kind, self.sym, self.signed, self.items, self.plus = kind, sym, signed, items, plus
    def __repr__(self):
        return '%s:%s' % (self.kind, self.sym)

def build_operands(op, size):
    global CUR_SIZE
    CUR_SIZE = size
    """Returns (display string, list of logical Op, operand subtable names used in pattern, raw byte map)."""
    name, opcode, mask, nomatch, fmt, mach, ops = op
    insn, ext, xs = reconstruct(op, size)
    disp = []
    logical = []
    stack = None          # inside parens
    pattern_syms = []
    nocomma = True; paren = False
    for oi in ops:
        bits_, shift, flags = OPERANDS[oi]
        if flags & F_PLUS: nocomma = True
        # comma logic as in the C printer
        if not nocomma and (not paren or not (flags & F_PAREN)):
            disp.append(',')
        nocomma = False
        o = None
        if flags & (F_DREG | F_AREG | F_RREG | F_XRREG):
            bits, _ = operand_bits(oi, insn, ext, xs)
            rs = 'D' if flags & F_DREG else 'A' if flags & F_AREG else 'R' if flags & F_RREG else 'XR'
            fn, byte = reg_operand(bits, rs)
            sub = 'reg_%s_L%d' % (fn, size)
            add_sub(sub, '%s: %s is %s { export %s; }' % (sub, fn, tok_prefix(byte, {byte: [fn]}), fn))
            o = Op(rs, sub); disp.append(sub); pattern_syms.append(sub)
        elif flags & (F_FS | F_FD):
            bits, _ = operand_bits(oi, insn, ext, xs)
            sub = fp_operand(bits, 'FS' if flags & F_FS else 'FD')
            o = Op('FS' if flags & F_FS else 'FD', sub); disp.append(sub); pattern_syms.append(sub)
        elif flags & F_SP: o = Op('SP', 'sp'); disp.append('"sp"')
        elif flags & F_PSW: o = Op('PSW', 'psw'); disp.append('"psw"')
        elif flags & F_MDR: o = Op('MDR', 'mdr'); disp.append('"mdr"')
        elif flags & F_FPCR: o = Op('FPCR', 'fpcr'); disp.append('"fpcr"')
        elif flags & F_USP: o = Op('USP', 'usp'); disp.append('"usp"')
        elif flags & F_SSP: o = Op('SSP', 'ssp'); disp.append('"ssp"')
        elif flags & F_MSP: o = Op('MSP', 'msp'); disp.append('"msp"')
        elif flags & F_PC: o = Op('PC', 'pc'); disp.append('"pc"')
        elif flags & F_EPSW: o = Op('EPSW', 'epsw'); disp.append('"epsw"')
        elif flags & F_PLUS:
            disp.append('+')
            if stack is not None: stack.append(Op('PLUS'))
            continue
        elif flags & F_PAREN:
            if paren:
                disp.append(')')
                logical.append(Op('MEM', items=stack)); stack = None
            else:
                disp.append('('); nocomma = True; stack = []
            paren = not paren
            continue
        elif flags & F_REGLIST:
            bits, _ = operand_bits(oi, insn, ext, xs)
            byte = reglist_bits(bits)
            o = Op('REGS', byte); disp.append('RLIST%d' % byte)
        else:
            bits, signed = operand_bits(oi, insn, ext, xs)
            kind = 'rel' if flags & F_PCREL else 'abs' if flags & F_MEMADDR else 'imm'
            sub = imm_operand(bits, signed, kind)
            o = Op(kind.upper, sub, signed); o.nbits = len(bits); disp.append(sub); pattern_syms.append(sub)
        if stack is not None: stack.append(o)
        else: logical.append(o)
    return disp, logical, pattern_syms

# ---------------------------------------------------------------- semantics
COND = {
    'eq': 'Z', 'ne': '!Z', 'gt': '!(Z || (N != V))', 'ge': '!(N != V)', 'le': '(Z || (N != V))', 'lt': '(N != V)',
    'hi': '!(C || Z)', 'cc': '!C', 'ls': '(C || Z)', 'cs': 'C', 'vc': '!V', 'vs': 'V', 'nc': '!N', 'ns': 'N', 'ra': '1',
}
FCOND = {
    'eq': 'fccE', 'ne': '(fccU || fccL || fccG)', 'gt': 'fccG', 'ge': '(fccG || fccE)', 'lt': 'fccL', 'le': '(fccL || fccE)',
    'uo': 'fccU', 'lg': '(fccL || fccG)', 'leg': '(fccL || fccE || fccG)', 'ug': '(fccU || fccG)', 'uge': '(fccU || fccG || fccE)',
    'ul': '(fccU || fccL)', 'ule': '(fccU || fccL || fccE)', 'ue': '(fccU || fccE)',
}
PSEUDO = set

class Unsupported(Exception):
    pass

def rd(o):
    """Read expression for a simple operand."""
    k = o.kind
    if k in ('D', 'A', 'R', 'XR', 'IMM', 'ABS', 'FS', 'FD'): return o.sym
    if k == 'SP': return 'sp'
    if k == 'PSW': return 'getpsw'
    if k in ('MDR', 'USP', 'SSP', 'MSP', 'EPSW', 'FPCR'): return o.sym
    if k == 'PC': return 'inst_start'
    raise Unsupported(k)

def wr(o, val):
    k = o.kind
    if k == 'PSW': return 'setpsw(%s);' % val
    if k == 'PC': raise Unsupported('write pc')
    return '%s = %s;' % (rd(o), val)

ACCESS = {'mov': 4, 'movbu': 1, 'movhu': 2, 'fmov': None, 'dcpf': 1}

def mem_ea(mem, size):
    """Return (pcode prelude, ea expr, post-increment pcode)."""
    its = [i for i in mem.items if i.kind != 'PLUS']
    plus = any(i.kind == 'PLUS' for i in mem.items)
    pre = ''; post = ''
    if len(its) == 1:
        a = its[0]
        if a.kind == 'ABS': ea = a.sym
        else: ea = rd(a)
        if plus: post = '%s = %s + %d;' % (rd(a), rd(a), size)
        return pre, ea, post
    if plus:
        # (Rm+,imm)
        base, inc = its
        if getattr(inc, 'nbits', 32) == 24 and not inc.signed:
            return '', rd(base), 'local inc:4 = sext(%s:3); %s = %s + inc;' % (rd(inc), rd(base), rd(base))
        return '', rd(base), '%s = %s + %s;' % (rd(base), rd(base), rd(inc))
    a, b = its
    return '', '(%s + %s)' % (rd(a), rd(b)), ''

def sem_mov(name, ops):
    size = ACCESS[name]
    a, b = ops
    if a.kind == 'MEM' and b.kind == 'MEM': raise Unsupported('mem-mem')
    if a.kind == 'MEM':
        pre, ea, post = mem_ea(a, size)
        val = '*:4 %s' % ea if size == 4 else 'zext(*:%d %s)' % (size, ea)
        return '%s local ea:4 = %s; %s %s' % (pre, ea, wr(b, ('*:4 ea' if size == 4 else 'zext(*:%d ea)' % size)), post)
    if b.kind == 'MEM':
        pre, ea, post = mem_ea(b, size)
        src = rd(a)
        if size == 4: st = '*:4 ea = %s;' % src
        else: st = 'local tmp:4 = %s; *:%d ea = tmp:%d;' % (src, size, size)
        return '%s local ea:4 = %s; %s %s' % (pre, ea, st, post)
    # register / immediate moves
    if b.kind == 'PSW': return 'setpsw(%s);' % rd(a)
    return wr(b, rd(a))

def flags_logic(r):
    return 'Z = (%s == 0); N = (%s s< 0); C = 0; V = 0;' % (r, r)

def sem_alu(name, ops):
    """Two- and three-operand integer ALU ops (sim genericAdd/Sub/Cmp etc.)."""
    if len(ops) == 3:
        s1, s2, d = rd(ops[0]), rd(ops[1]), ops[2]
        if name in ('add'):
            return 'local a:4 = %s; local b:4 = %s; local r:4 = a + b; C = carry(a, b); V = scarry(a, b); %s Z = (r == 0); N = (r s< 0);' % (s1, s2, wr(d, 'r'))
        if name == 'addc':
            return 'local a:4 = %s; local b:4 = %s; local r:4 = a + b + zext(C); C = carry(a, b) || carry(a + b, zext(C)); V = scarry(a, b); %s Z = Z && (r == 0); N = (r s< 0);' % (s1, s2, wr(d, 'r'))
        if name == 'sub':   # Rd = Rn - Rm
            return 'local a:4 = %s; local b:4 = %s; local r:4 = b - a; C = b < a; V = sborrow(b, a); %s Z = (r == 0); N = (r s< 0);' % (s1, s2, wr(d, 'r'))
        if name == 'subc':
            return 'local a:4 = %s; local b:4 = %s; local r:4 = b - a - zext(C); C = (b < a) || ((b - a) < zext(C)); V = sborrow(b, a); %s Z = Z && (r == 0); N = (r s< 0);' % (s1, s2, wr(d, 'r'))
        if name in ('and', 'or', 'xor'):
            opx = {'and': '&', 'or': '|', 'xor': '^'}[name]
            return 'local r:4 = %s %s %s; %s %s' % (s1, opx, s2, wr(d, 'r'), flags_logic('r'))
        if name in ('asl', 'asr', 'lsr'):   # Rd = Rn shift Rm
            opx = {'asl': '<<', 'asr': 's>>', 'lsr': '>>'}[name]
            cpart = '' if name == 'asl' else ' C = (sh != 0) && (((b >> (sh - 1)) & 1) != 0);'
            return 'local sh:4 = %s & 31; local b:4 = %s; local r:4 = b %s sh;%s %s Z = (r == 0); N = (r s< 0);' % (s1, s2, opx, cpart, wr(d, 'r'))
        raise Unsupported(name)
    s, d = ops
    S, D = rd(s), rd(d)
    if name == 'add':
        if d.kind == 'SP': return 'sp = sp + %s;' % S
        return 'local a:4 = %s; local b:4 = %s; local r:4 = a + b; C = carry(a, b); V = scarry(a, b); %s Z = (r == 0); N = (r s< 0);' % (S, D, wr(d, 'r'))
    if name == 'addc':
        return 'local a:4 = %s; local b:4 = %s; local r:4 = a + b + zext(C); C = carry(a, b) || carry(a + b, zext(C)); V = scarry(a, b); %s Z = Z && (r == 0); N = (r s< 0);' % (S, D, wr(d, 'r'))
    if name == 'sub':
        return 'local a:4 = %s; local b:4 = %s; local r:4 = b - a; C = b < a; V = sborrow(b, a); %s Z = (r == 0); N = (r s< 0);' % (S, D, wr(d, 'r'))
    if name == 'subc':
        return 'local a:4 = %s; local b:4 = %s; local r:4 = b - a - zext(C); C = (b < a) || ((b - a) < zext(C)); V = sborrow(b, a); %s Z = Z && (r == 0); N = (r s< 0);' % (S, D, wr(d, 'r'))
    if name == 'cmp':
        return 'local a:4 = %s; local b:4 = %s; local r:4 = b - a; C = b < a; V = sborrow(b, a); Z = (r == 0); N = (r s< 0);' % (S, D)
    if name in ('and', 'or', 'xor'):
        opx = {'and': '&', 'or': '|', 'xor': '^'}[name]
        if d.kind == 'PSW': return 'setpsw(getpsw %s %s);' % (opx, S)
        if d.kind == 'EPSW': return 'epsw = epsw %s %s;' % (opx, S)
        return 'local r:4 = %s %s %s; %s %s' % (D, opx, S, wr(d, 'r'), flags_logic('r'))
    if name in ('asl', 'asr', 'lsr'):
        opx = {'asl': '<<', 'asr': 's>>', 'lsr': '>>'}[name]
        cpart = '' if name == 'asl' else ' C = (sh != 0) && (((b >> (sh - 1)) & 1) != 0);'
        return 'local sh:4 = %s & 31; local b:4 = %s; local r:4 = b %s sh;%s %s Z = (r == 0); N = (r s< 0);' % (S, D, opx, cpart, wr(d, 'r'))
    if name in ('mul', 'mulu'):
        ext = 'sext' if name == 'mul' else 'zext'
        pre = ''
        if s.kind == 'IMM' and getattr(s, 'nbits', 32) == 24 and not s.signed:
            pre = 'local im:4 = sext(%s:3); ' % S; S = 'im'   # the sim sign-extends imm24 for mul and mulu alike
        return pre + 'local p:8 = %s(%s) * %s(%s); %s mdr = p(4); Z = (p:4 == 0); N = (p:4 s< 0); C = 0; V = 0;' % (ext, D, ext, S, wr(d, 'p:4'))
    if name in ('div', 'divu'):
        if name == 'div':
            return ('local num:8 = (zext(mdr) << 32) | zext(%s); local den:8 = sext(%s); local q:8 = num s/ den; local rm:8 = num s%% den; '
                    'mdr = rm:4; %s Z = (q:4 == 0); N = (q:4 s< 0); V = (den == 0); C = 0;' % (D, S, wr(d, 'q:4')))
        return ('local num:8 = (zext(mdr) << 32) | zext(%s); local den:8 = zext(%s); local q:8 = num / den; local rm:8 = num %% den; '
                'mdr = rm:4; %s Z = (q:4 == 0); N = (q:4 s< 0); V = (den == 0); C = 0;' % (D, S, wr(d, 'q:4')))
    if name == 'btst':
        return 'local r:4 = %s & %s; %s' % (D, S, flags_logic('r'))
    raise Unsupported(name)

def sem_unary(name, ops):
    d = ops[-1]; D = rd(d)
    if name == 'clr': return '%s Z = 1; N = 0; C = 0; V = 0;' % wr(d, '0')
    if name == 'inc':
        if d.kind == 'A': return '%s = %s + 1;' % (D, D)
        return 'local b:4 = %s; local r:4 = b + 1; C = carry(b, 1); V = scarry(b, 1); %s Z = (r == 0); N = (r s< 0);' % (D, wr(d, 'r'))
    if name == 'inc4': return '%s = %s + 4;' % (D, D)
    if name == 'not': return 'local r:4 = ~%s; %s %s' % (D, wr(d, 'r'), flags_logic('r'))
    if name == 'asl2': return 'local r:4 = %s << 2; %s Z = (r == 0); N = (r s< 0);' % (D, wr(d, 'r'))
    if name == 'asl': return 'local r:4 = %s << 1; %s Z = (r == 0); N = (r s< 0);' % (D, wr(d, 'r'))
    if name in ('asr', 'lsr'):
        opx = 's>>' if name == 'asr' else '>>'
        return 'local b:4 = %s; C = (b & 1) != 0; local r:4 = b %s 1; %s Z = (r == 0); N = (r s< 0);' % (D, opx, wr(d, 'r'))
    if name == 'ror': return 'local b:4 = %s; local r:4 = (b >> 1) | (zext(C) << 31); C = (b & 1) != 0; %s Z = (r == 0); N = (r s< 0); V = 0;' % (D, wr(d, 'r'))
    if name == 'rol': return 'local b:4 = %s; local r:4 = (b << 1) | zext(C); C = (b s< 0); %s Z = (r == 0); N = (r s< 0); V = 0;' % (D, wr(d, 'r'))
    if name == 'ext': return 'mdr = %s s>> 31;' % D
    if name in ('extb', 'extbu', 'exth', 'exthu'):
        s = rd(ops[0])
        e = {'extb': 'sext(%s:1)', 'extbu': 'zext(%s:1)', 'exth': 'sext(%s:2)', 'exthu': 'zext(%s:2)'}[name] % s
        return wr(d, e)
    raise Unsupported(name)

def pseudo(nm, args, dst=None):
    PSEUDO.add(nm)
    call = '%s(%s)' % (nm, ', '.join(args))
    return '%s = %s;' % (dst, call) if dst else '%s;' % call

def sem_dual(name, ops):
    a, b = name.split('_')
    # operands: src1, dst1, src2, dst2 (src may be imm)
    s1, d1, s2, d2 = ops
    def one(op, s, d, tag):
        S, D = rd(s), rd(d)
        if op == 'add': return 'local res%s:4 = %s + %s;' % (tag, D, S), D
        if op == 'sub': return 'local res%s:4 = %s - %s;' % (tag, D, S), D
        if op == 'mov': return 'local res%s:4 = %s;' % (tag, S), D
        if op == 'and': return 'local res%s:4 = %s & %s;' % (tag, D, S), D
        if op == 'or': return 'local res%s:4 = %s | %s;' % (tag, D, S), D
        if op == 'xor': return 'local res%s:4 = %s ^ %s;' % (tag, D, S), D
        if op == 'asr': return 'local res%s:4 = %s s>> (%s & 31);' % (tag, D, S), D
        if op == 'lsr': return 'local res%s:4 = %s >> (%s & 31);' % (tag, D, S), D
        if op == 'asl': return 'local res%s:4 = %s << (%s & 31);' % (tag, D, S), D
        if op == 'cmp':
            return 'local ca%s:4 = %s; local cb%s:4 = %s; local cr%s:4 = cb%s - ca%s;' % (tag, S, tag, D, tag, tag, tag), None
        if op == 'sat16':
            return ('local sv%s:4 = %s; local sh%s = sv%s s> 0x7fff; local sl%s = sv%s s< 0xffff8000; '
                    'local res%s:4 = (zext(sh%s) * 0x7fff) + (zext(sl%s) * 0xffff8000) + (zext(!sh%s && !sl%s) * sv%s);' % ((tag, S) + (tag) * 10)), D
        if op == 'swhw': return 'local res%s:4 = (%s << 16) | (%s >> 16);' % (tag, S, S), D
        if op == 'dmach': return 'local res%s:4 = dmach(%s, %s);' % (tag, S, D), D
        raise Unsupported(op)
    if a in ('sat16', 'dmach') or b in ('sat16', 'dmach'):
        PSEUDO.add('dmach')
    p1, w1 = one(a, s1, d1, '1')
    p2, w2 = one(b, s2, d2, '2')
    out = p1 + ' ' + p2
    if w1: out += ' %s = res1;' % w1
    if w2: out += ' %s = res2;' % w2
    for tag, op in (('1', a), ('2', b)):
        if op == 'cmp':
            out += ' Z = (cr{t} == 0); N = (cr{t} s< 0); C = cb{t} < ca{t}; V = sborrow(cb{t}, ca{t});'.format(t=tag)
    return out

def sem_lcc_mem(name, ops):
    """mov_Lcc (Rm+,imm),Rn: load with post-increment, then loop-branch."""
    mov, cc = name.split('_')
    mem, d = ops
    pre, ea, post = mem_ea(mem, 4)
    c = COND[cc[1:]]
    br = 'goto lartgt;' if cc == 'lra' else 'if (%s) goto lartgt;' % c
    return '%s local ea:4 = %s; %s %s %s' % (pre, ea, wr(d, '*:4 ea'), post, br)

def reglist_name(byte, mode, size=None):
    return 'RL%s%d_L%d' % (mode, byte, size or CUR_SIZE)

def sem(name, ops, size):
    if name in ('mov', 'movbu', 'movhu') and len(ops) == 2: return sem_mov(name, ops)
    if name == 'movu': return wr(ops[1], rd(ops[0]))
    if name in ('add', 'addc', 'sub', 'subc', 'cmp', 'and', 'or', 'xor', 'mul', 'mulu', 'div', 'divu') and len(ops) in (2, 3):
        return sem_alu(name, ops)
    if name in ('asl', 'asr', 'lsr') and len(ops) in (2, 3): return sem_alu(name, ops)
    if name in ('mul', 'mulu') and len(ops) == 4:
        ext = 'sext' if name == 'mul' else 'zext'
        return 'local p:8 = %s(%s) * %s(%s); %s %s Z = (p == 0); N = (p s< 0);' % (ext, rd(ops[0]), ext, rd(ops[1]), wr(ops[3], 'p:4'), wr(ops[2], 'p(4)'))
    if name in ('clr', 'inc', 'inc4', 'not', 'asl2', 'asl', 'asr', 'lsr', 'ror', 'rol', 'ext', 'extb', 'extbu', 'exth', 'exthu'):
        return sem_unary(name, ops)
    if name == 'btst':
        if ops[1].kind == 'MEM':
            pre, ea, post = mem_ea(ops[1], 1)
            return 'local ea:4 = %s; local r:1 = *:1 ea & %s:1; Z = (r == 0); N = 0; C = 0; V = 0;' % (ea, rd(ops[0]))
        return sem_alu(name, ops)
    if name in ('bset', 'bclr'):
        pre, ea, post = mem_ea(ops[1], 1)
        mk = rd(ops[0])
        newv = 'b | %s:1' % mk if name == 'bset' else 'b & ~(%s:1)' % mk
        return 'local ea:4 = %s; local b:1 = *:1 ea; Z = ((b & %s:1) == 0); N = 0; C = 0; V = 0; *:1 ea = %s;' % (ea, mk, newv)
    if name[0] == 'b' and name[1:] in COND and len(ops) == 1:
        if name == 'bra': return 'goto %s;' % rd_rel(ops[0])
        return 'if (%s) goto %s;' % (COND[name[1:]], rd_rel(ops[0]))
    if name.startswith('fb') and name[2:] in FCOND:
        return 'if (%s) goto %s;' % (FCOND[name[2:]], rd_rel(ops[0]))
    if name[0] == 'l' and name[1:] in COND and not ops:
        if name == 'lra': return 'goto lartgt;'
        return 'if (%s) goto lartgt;' % COND[name[1:]]
    if name.startswith('fl') and name[2:] in FCOND and not ops:
        return 'if (%s) goto lartgt;' % FCOND[name[2:]]
    if name == 'setlb':
        return 'local n:4 = inst_next; lir = *:4 n; lar = n;'
    if name == 'jmp':
        o = ops[0]
        if o.kind == 'MEM': return 'goto [%s];' % rd(o.items[0])
        return 'goto %s;' % rd_rel(o)
    if name == 'call':
        return 'mdr = inst_next; call %s;' % rd_rel(ops[0])
    if name == 'calls':
        o = ops[0]
        if o.kind == 'MEM': return 'mdr = inst_next; *:4 sp = inst_next; call [%s];' % rd(o.items[0])
        return 'mdr = inst_next; *:4 sp = inst_next; call %s;' % rd_rel(o)
    if name in ('ret', 'retf'):
        rl, imm = ops
        body = 'sp = sp + %s; build %s;' % (rd(imm), reglist_name(rl.sym, 'ret'))
        if name == 'ret': return body + ' return [*:4 sp];'
        return body + ' return [mdr];'
    if name == 'rets': return 'return [*:4 sp];'
    if name == 'rti': return 'setpsw(zext(*:2 sp)); local t:4 = *:4 (sp + 4); sp = sp + 8; return [t];'
    if name == 'rtm': return pseudo('rtm', []) + ' return [mdr];'
    if name == 'movm':
        a, b = ops
        if a.kind == 'REGS':   # push
            base = b.items[0].kind.lower
            return 'build %s;' % reglist_name(a.sym, 'push' + base)
        base = a.items[0].kind.lower
        return 'build %s;' % reglist_name(b.sym, 'pop' + base)
    if name == 'nop': return ''
    if name == 'break': return pseudo('breakpoint', [])
    if name == 'trap': return 'mdr = inst_next; ' + pseudo('trap', [])
    if name == 'syscall':
        return pseudo('syscall', [rd(ops[0])] if ops else ['0:4'])
    if name in ('swap', 'swaph', 'swhw', 'sat16', 'sat24'):
        s, d = rd(ops[0]), ops[1]
        if name == 'swap':
            e = '((%s & 0xff) << 24) | ((%s & 0xff00) << 8) | ((%s >> 8) & 0xff00) | (%s >> 24)' % ((s) * 4)
        elif name == 'swaph':
            e = '((%s & 0x00ff00ff) << 8) | ((%s >> 8) & 0x00ff00ff)' % (s, s)
        elif name == 'swhw':
            e = '(%s << 16) | (%s >> 16)' % (s, s)
        elif name == 'sat16':
            return ('local v:4 = %s; local r:4 = v; if (v s< 0x7fff) goto <a>; r = 0x7fff; goto <d>; <a> if (v s> 0xffff8000) goto <d>; r = 0xffff8000; '
                    '<d> %s Z = (r == 0); N = ((r & 0x8000) != 0);' % (s, wr(d, 'r')))
        else:
            return ('local v:4 = %s; local r:4 = v; if (v s< 0x7fffff) goto <a>; r = 0x7fffff; goto <d>; <a> if (v s> 0xff800000) goto <d>; r = 0xff800000; '
                    '<d> %s Z = (r == 0); N = ((r & 0x800000) != 0);' % (s, wr(d, 'r')))
        return wr(d, e)
    if name.startswith('udf'):
        # Unknown extension-unit ops. udf00 behaves like a 32-bit signed multiply in this firmware
        # (e.g. 'udf00 -1,d0' after a sign test, 'udf00 d0,d2; ext d2; div d0,d2'), but that is inferred.
        s, d = ops
        if name in ('udf00', 'udfu00', 'udf01', 'udfu01'):
            # Inferred from this firmware, not documented: udf00/udfu00 and udf01/udfu01 act as a 32-bit
            # multiply (udfu01 20,d0 before indexing a 20-byte array; udf00 -1,d0 to negate; udf00 d0,d2; ext d2;
            # div d0,d2 as a*b/c). Only the low 32 bits are modelled; flags and MDR are left alone.
            return '%s = %s * %s;' % (rd(d), rd(d), rd(s))
        return pseudo(name, [rd(s), rd(d)], rd(d))
    if name == 'bsch':
        return pseudo('bsch', [rd(o) for o in ops[:-1]] + [rd(ops[-1])], rd(ops[-1])) + ' C = ' + rd(ops[-1]) + ' != 0;'
    if name in ('mac', 'macu', 'macb', 'macbu', 'mach', 'machu', 'dmach', 'dmachu', 'dmulh', 'dmulhu', 'mcste', 'mcst9', 'mcst48'):
        args = [rd(o) for o in ops]
        if name in ('mcste', 'mcst9', 'mcst48', 'dmulh', 'dmulhu') or (name.startswith('dmach') and len(ops) == 3):
            return pseudo(name, args, rd(ops[-1]))
        return pseudo(name, args)
    if name in ('getx', 'getchx', 'getclx'): return pseudo(name, [], rd(ops[0]))
    if name == 'putx': return pseudo(name, [rd(ops[0])])
    if name == 'dcpf':
        pre, ea, post = mem_ea(ops[0], 1)
        return pseudo('dcpf', [ea])
    if '_' in name:
        a, b = name.split('_')
        if a == 'mov' and b[0] == 'l' and b[1:] in COND: return sem_lcc_mem(name, ops)
        if b == 'mov' and a[0] == 'l' and a[1:] in COND: raise Unsupported(name)
        return sem_dual(name, ops)
    if name.startswith('f') or name in ('itof', 'ftoi', 'ftod', 'dtof'):
        return sem_fp(name, ops)
    raise Unsupported(name)

def rd_rel(o):
    assert o.kind == 'REL', o
    return o.sym

def sem_fp(name, ops):
    if name == 'fmov':
        a, b = ops
        sz = 8 if 'FD' in (a.kind, b.kind) else 4
        if a.kind == 'MEM':
            pre, ea, post = mem_ea(a, sz)
            return 'local ea:4 = %s; %s = *:%d ea; %s' % (ea, rd(b), sz, post)
        if b.kind == 'MEM':
            pre, ea, post = mem_ea(b, sz)
            return 'local ea:4 = %s; *:%d ea = %s; %s' % (ea, sz, rd(a), post)
        if b.kind == 'FPCR': return 'setfpcr(%s);' % rd(a)
        if a.kind == 'FPCR': return '%s = getfpcr;' % rd(b)
        return '%s = %s;' % (rd(b), rd(a))
    if name in ('fabs', 'fneg', 'fsqrt', 'frsqrt'):
        s = rd(ops[0]); d = rd(ops[-1])
        e = {'fabs': 'abs(%s)', 'fneg': 'f- %s', 'fsqrt': 'sqrt(%s)'}.get(name)
        if name == 'frsqrt':
            one = 'int2float(1:4)' if ops[0].kind == 'FS' else 'int2float(1:8)'
            return '%s = %s f/ sqrt(%s);' % (d, one, s)
        return '%s = %s;' % (d, e % s)
    if name in ('fadd', 'fsub', 'fmul', 'fdiv'):
        opx = {'fadd': 'f+', 'fsub': 'f-', 'fmul': 'f*', 'fdiv': 'f/'}[name]
        if len(ops) == 2:   # FSm,FSn: FSn = FSn op FSm
            return '%s = %s %s %s;' % (rd(ops[1]), rd(ops[1]), opx, rd(ops[0]))
        a, b, d = ops        # Sm1,Sm2,Sn: Sn = Sm2 op Sm1 (fpu_sub(&Sm2,&Sm1,&Sn)); imm32,FSm,FSn likewise
        if ops[0].kind == 'IMM':
            return 'local im:4 = %s; %s = %s %s im;' % (rd(a), rd(d), rd(b), opx)
        return '%s = %s %s %s;' % (rd(d), rd(b), opx, rd(a))
    if name in ('fmadd', 'fmsub', 'fnmadd', 'fnmsub'):
        a, b, c, d = map(rd, ops)
        e = {'fmadd': '(%s f* %s) f+ %s', 'fmsub': '(%s f* %s) f- %s', 'fnmadd': 'f- ((%s f* %s) f+ %s)', 'fnmsub': 'f- ((%s f* %s) f- %s)'}[name] % (a, b, c)
        return '%s = %s;' % (d, e)
    if name == 'fcmp':
        a, b = ops   # fcmp FSm,FSn compares FSn with FSm; fcmp imm32,FSm compares FSm with imm
        x, y = rd(b), rd(a)
        return ('local x = %s; local y = %s; fccU = nan(x) || nan(y); fccE = !fccU && (x f== y); fccL = !fccU && (x f< y); fccG = !fccU && (y f< x);' % (x, y))
    if name == 'itof': return '%s = int2float(%s);' % (rd(ops[1]), rd(ops[0]))
    if name == 'ftoi': return '%s = trunc(%s);' % (rd(ops[1]), rd(ops[0]))
    if name in ('ftod', 'dtof'): return '%s = float2float(%s);' % (rd(ops[1]), rd(ops[0]))
    raise Unsupported(name)

# ---------------------------------------------------------------- main generation
def main:
    entries = []
    claimed = collections.defaultdict(list)    # size -> list of cubes already taken
    first_bytes = {s: first_byte_cubes(s) for s in range(1, 8)}
    cons = []
    stats = collections.Counter
    for idx, op in enumerate(T['opcodes']):
        name, opcode, mask, nomatch, fmt, mach, ops = op
        if mach == AM30: continue
        size = mysize(fmt)
        w = 8 * min(size, 4)
        sh = 32 - w
        base = (mask << sh & 0xffffffff, opcode << sh & 0xffffffff)
        mine = []
        for fb in first_bytes[size]:
            c = cube_inter(base, fb)
            if c: mine.append(c)
        for prev in claimed[size]:
            nxt = []
            for c in mine: nxt += cube_sub(c, prev)
            mine = nxt
            if not mine: break
        if not mine:
            stats['shadowed'] += 1
            continue
        claimed[size].append(base)
        mine = cube_merge(mine)
        try:
            disp, logical, psyms = build_operands(op, size)
            body = sem(name, logical, size)
            if 'getpsw' in body:
                body = 'local pv:4 = (psw & 0xfffffff0) | zext(Z) | (zext(N) << 1) | (zext(C) << 2) | (zext(V) << 3); ' + body.replace('getpsw', 'pv')
            if 'getfpcr' in body:
                body = 'local fv:4 = (fpcr & 0xffc3ffff) | (zext(fccL) << 21) | (zext(fccG) << 20) | (zext(fccE) << 19) | (zext(fccU) << 18); ' + body.replace('getfpcr', 'fv')
        except Unsupported as e:
            stats['unsupported'] += 1
            print('unsupported', name, e, file=sys.stderr)
            body = pseudo('unimpl_' + name.replace('_', ''), [])
            try:
                disp, logical, psyms = build_operands(op, size)
            except Exception:
                raise
        extra_action = ''
        if name == 'call':
            # frame info for the callee entry, see the ^instruction wrapper
            rpos, ipos = (3, 4) if size == 5 else (5, 6)
            extra_action = '[ ctx_regs = b%d; ctx_frame = b%d; ctx_entry = 1; globalset(%s, ctx_regs); globalset(%s, ctx_frame); globalset(%s, ctx_entry); ]' % (rpos, ipos, logical[0].sym, logical[0].sym, logical[0].sym)
        if name == 'setlb':
            extra_action = '[ lar_ctx = inst_start + 1; globalset(inst_next, lar_ctx); ]'
        for c in mine:
            cmask, cval = c
            uses = collections.defaultdict(list)
            for k in range(min(size, 4)):
                bm = (cmask >> (24 - 8 * k)) & 0xff
                bv = (cval >> (24 - 8 * k)) & 0xff
                bit = 0
                while bit < 8:
                    if (bm >> bit) & 1:
                        lo = bit
                        while bit < 8 and (bm >> bit) & 1: bit += 1
                        hi = bit - 1
                        if lo == 0 and hi == 7: fn = 'b%d' % k
                        else: fn = field(k, lo, hi)
                        uses[k].append('%s=0x%x' % (fn, (bv >> lo) & m(hi - lo + 1)))
                    else:
                        bit += 1
            pat = '(' + tok_prefix(size - 1, uses) + ')'
            for s in dict.fromkeys(psyms): pat += ' & ' + s
            dtext = ''.join(' ' + d + ' ' if d not in ',+' else d for d in disp).strip
            dtext = re.sub(r'\s+', ' ', dtext)
            dtext = dtext.replace(' (', '(').replace('( ', '(').replace(' )', ')').replace(' ,', ',').replace(', ', ',')
            dtext = dtext.replace(' +', '+').replace('+ ', '+')
            # reg list placeholders
            rl = re.findall(r'RLIST(\d)', dtext)
            for r in rl:
                rn = reglist_name(int(r), 'disp', size)
                dtext = dtext.replace('RLIST' + r, rn)
                pat += ' & ' + rn
                need_reglist(int(r), 'disp', size)
            for mode in re.findall(r'build RL(\w+?)(\d)_L(\d);', body):
                pat += ' & ' + reglist_name(int(mode[1]), mode[0], size)
                need_reglist(int(mode[1]), mode[0], size)
            mn = name
            if 'lartgt' in body:
                # no setlb seen on the way: indirect branch via the LAR register
                cons.append(':%s %s is %s & lar_ctx=0 %s { %s }' % (mn, dtext, pat, extra_action, re.sub(r'if \((.*)\) goto lartgt;', r'if (!(\1)) goto inst_next; goto [lar];', body).replace('goto lartgt;', 'goto [lar];')))
                pat += ' & lartgt'
            cons.append(':%s %s is %s %s { %s }' % (mn, dtext, pat, extra_action, body))
            stats['constructors'] += 1
        stats['entries'] += 1
    write_spec(cons, stats)

REGLISTS = set
def need_reglist(byte, mode, size):
    REGLISTS.add((byte, mode, size))

def reglist_text(byte, mode, size):
    """mode: disp | pushsp | popsp | pushusp | popusp | ret."""
    global CUR_SIZE
    CUR_SIZE = size
    name = reglist_name(byte, mode, size)
    lines = []
    for v in range(256):
        names = []
        if v & 0x80: names.append('d2')
        if v & 0x40: names.append('d3')
        if v & 0x20: names.append('a2')
        if v & 0x10: names.append('a3')
        if v & 0x08: names.append('other')
        if v & 0x04: names.append('exreg0')
        if v & 0x02: names.append('exreg1')
        if v & 0x01: names.append('exother')
        d = '[' + ','.join(names) + ']'
        body = ''
        base = 'usp' if mode.endswith('usp') else 'sp'
        if mode.startswith('push'):
            body = push_regs(v, base, update=True)
        elif mode.startswith('pop'):
            body = pop_regs(v, base)
        elif mode == 'ret':
            body = ret_regs(v)
        pat = tok_prefix(byte, {byte: ['b%d=0x%x' % (byte, v)]})
        lines.append('%s: "%s" is %s { %s }' % (name, d, pat, body))
    return '\n'.join(lines)

def save_order(v):
    """Registers in the order the sim stores them (descending addresses)."""
    out = []
    if v & 0x4: out += ['r2', 'r3']
    if v & 0x2: out += ['r4', 'r5', 'r6', 'r7']
    if v & 0x1: out += ['r0', 'r1', None, None, None, None]
    if v & 0x80: out.append('d2')
    if v & 0x40: out.append('d3')
    if v & 0x20: out.append('a2')
    if v & 0x10: out.append('a3')
    if v & 0x8: out += ['d0', 'd1', 'a0', 'a1', 'mdr', 'lir', 'lar', None]
    return out

def push_regs(v, base, update):
    """movm regs,(sp) / call saves: each register stored at successively lower words below base."""
    regs = save_order(v)
    parts = ['local p:4 = %s;' % base]
    for r in regs:
        parts.append('p = p - 4;')
        if r: parts.append('*:4 p = %s;' % r)
    if update: parts.append('%s = p;' % base)
    return ' '.join(parts)

def pop_regs(v, base):
    """movm (sp),regs: reverse of push."""
    regs = save_order(v)
    parts = ['local p:4 = %s;' % base]
    for r in reversed(regs):
        if r: parts.append('%s = *:4 p;' % r)
        parts.append('p = p + 4;')
    parts.append('%s = p;' % base)
    return ' '.join(parts)

def ret_regs(v):
    """ret/retf: after sp += imm8, registers are at sp-4, sp-8, ... in save order."""
    regs = save_order(v)
    parts = []
    off = 0
    for r in regs:
        off += 4
        if r: parts.append('%s = *:4 (sp - %d);' % (r, off))
    return ' '.join(parts)

def entry_text:
    """Callee-entry frame setup implied by 'call label,[regs],imm8' (context set at the target)."""
    lines = []
    for v in range(256):
        body = '*:4 sp = mdr; ' + push_regs(v, 'sp', update=False) + ' sp = sp - zext(ctx_frame:1);'
        lines.append('entrysave: is en_regs=0x%x & en_frame { %s }' % (v, body.replace('zext(ctx_frame:1)', 'en_frame')))
    return '\n'.join(lines)

def write_spec(cons, stats):
    os.makedirs(OUT, exist_ok=True)
    L = []
    L.append('# MN103 / AM33 / AM33-2 (Panasonic MN10300 family) -- GENERATED by gen.py from the binutils')
    L.append('# opcode table (m10300-opc.c) and the GDB simulator semantics. Do not edit by hand.')
    L.append('define endian=little;')
    L.append('define alignment=1;')
    L.append('define space ram type=ram_space size=4 default;')
    L.append('define space register type=register_space size=4;')
    L.append('define register offset=0x00 size=4 [ d0 d1 d2 d3 a0 a1 a2 a3 sp pc mdr psw lir lar mdrq mcrh mcrl mcvf usp ssp msp epsw fpcr ];')
    L.append('define register offset=0x60 size=4 [ r0 r1 r2 r3 r4 r5 r6 r7 xr5 xr6 xr7 xr8 xr9 xr10 xr11 xr12 xr13 xr14 xr15 ];')
    L.append('define register offset=0x100 size=1 [ Z N C V fccL fccG fccE fccU ];')
    L.append('define register offset=0x200 size=4 [ %s ];' % ' '.join('fs%d' % i for i in range(32)))
    L.append('define register offset=0x200 size=8 [ %s ];' % ' '.join('fd%d' % (2 * i) for i in range(16)))
    L.append('define register offset=0x300 size=16 [ contextreg ];')
    L.append('define context contextreg')
    L.append('  phase=(0,0)')
    L.append('  ctx_entry=(1,1) noflow')
    L.append('  ctx_regs=(2,9) noflow')
    L.append('  ctx_frame=(10,17) noflow')
    # copies taken at the entry instruction before its own action runs: a call at a function entry rewrites
    # ctx_regs/ctx_frame (for its own target) and must not change the entry frame of the function it starts
    L.append('  en_regs=(18,25) noflow')
    L.append('  en_frame=(32,39) noflow')
    L.append('  lar_ctx=(64,95)')
    L.append(';')
    for k in range(7):
        fl = ['b%d=(0,7)' % k]
        for nm, (lo, hi, sg) in sorted(FIELDS[k].items):
            fl.append('%s=(%d,%d)%s' % (nm, lo, hi, ' signed' if sg else ''))
        L.append('define token t%d (8) %s;' % (k, ' '.join(fl)))
    regsets = {'D': ['d0', 'd1', 'd2', 'd3'], 'A': ['a0', 'a1', 'a2', 'a3'], 'R': REGNAMES_R, 'XR': REGNAMES_XR}
    for rs, fns in ATTACH.items:
        regs = regsets[rs]
        L.append('attach variables [ %s ] [ %s ];' % (' '.join(fns), ' '.join(regs)))
    for p in sorted(PSEUDO):
        L.append('define pcodeop %s;' % p)
    L.append('''
macro setpsw(v) { psw = v; Z = (v & 1) != 0; N = (v & 2) != 0; C = (v & 4) != 0; V = (v & 8) != 0; }

macro setfpcr(v) { fpcr = v; fccL = (v & 0x200000) != 0; fccG = (v & 0x100000) != 0; fccE = (v & 0x80000) != 0; fccU = (v & 0x40000) != 0; }

# loop target from setlb (context flows from the setlb to following code); Lcc with lar_ctx=0 branch indirect via LAR
lartgt: loc is lar_ctx [ loc = lar_ctx + 0; ] { export *:4 loc; }
''')
    L.append(entry_text)
    for name in SUB_ORDER:
        L.append(SUBTABLES[name])
    for byte, mode, size in sorted(REGLISTS):
        L.append(reglist_text(byte, mode, size))
    L.append(':^instruction is phase=0 & ctx_entry=1 & entrysave & instruction [ phase=1; en_regs = ctx_regs; en_frame = ctx_frame; ] { build entrysave; build instruction; }')
    L.append(':^instruction is phase=0 & instruction [ phase=1; ] { build instruction; }')
    L.append('with : phase=1 {')
    L += cons
    L.append('}')
    txt = '\n'.join(L) + '\n'
    out = txt.split('\n')
    open(os.path.join(OUT, 'mn103.slaspec'), 'w').write('\n'.join(out))
    print(dict(stats), file=sys.stderr)

main
