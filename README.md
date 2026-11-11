# Ghidra processor module: Panasonic MN103 / AM33 / AM33-2

Built 2026-10-21 for the E-M5 III firmware work (notes: [olympus-firmware-notes](https://github.com/nsud-dev/olympus-firmware-notes)). Ghidra ships no MN10300-family module; this one
disassembles and decompiles block0 of `OLY_E_137_1700_0000_0000.BIN`. Analysis only: nothing here
writes or builds firmware.

Language id: `MN103:LE:32:AM33-2` (little-endian, 32-bit, AM33-2 instruction set incl. FPU and the
AM33 DSP/dual ops). Tested with Ghidra 11.4.2 (Java 21).

## Install on a desktop Ghidra

1. Copy the `MN103` folder into `<ghidra install>/Ghidra/Processors/` (next to `ARM`, `x86`, ...).
2. Restart Ghidra. `MN103` now appears in the language list on import.
   If a different Ghidra version refuses `mn103.sla`, rebuild it:
   `<ghidra>/support/sleigh <ghidra>/Ghidra/Processors/MN103/data/languages/mn103.slaspec`
3. The scripts in `MN103/ghidra_scripts` show up in the Script Manager under category **MN103**.

## Import block0

Headless, one command (from this folder). It needs python3 and `olyfw.py` from
[olympus-firmware-notes](https://github.com/nsud-dev/olympus-firmware-notes) (`tools/olyfw.py`): clone that repo
next to this one, or set `OLYFW=/path/to/olyfw.py`.

```sh
./import_block0.sh /path/to/ghidra_11.4.2_PUBLIC /path/to/projects            # ~5 min, no auto-analysis
./import_block0.sh /path/to/ghidra_11.4.2_PUBLIC /path/to/projects --analyze  # plus Ghidra auto-analysis, ~42 min
```
It unpacks block0, imports it as a raw binary at **0x60021020**, adds an uninitialized RAM block at
0x62000000 (size 32 MB is an assumption, so globals get labels and xrefs), creates all 102k
functions and labels from `../symbols/symbols.csv`, then runs `MN103FixCallFrames` (below).
Open `em5iii.gpr` in Ghidra afterwards.

By hand in the GUI: File > Import File on the unpacked `block0_*.bin`, format **Raw Binary**, language
`MN103:LE:32:AM33-2`, Options > Base Address `60021020`. Then run `MN103AddRamBlock`,
`MN103LoadSymbols` (pick `symbols/symbols.csv`), auto-analyze if you like, and finally `MN103FixCallFrames`.

**Rerun `MN103FixCallFrames` after any (re-)analysis or after disassembling new code.** It is safe to rerun.

## Things specific to this CPU that the module handles

- **Callee frame in the call instruction.** `call label,[d2,d3,a2],24` saves the *callee's* registers
  and allocates its 24-byte frame. The module treats that as entry code of the callee: the call sets
  context (`ctx_entry/ctx_regs/ctx_frame`) at its target, and the target's first instruction carries the
  register saves and `sp -= frame` in its p-code. `ret [regs],N` / `retf` undo it. That keeps stack
  locals and stack arguments where the decompiler expects them. If a function was disassembled before
  any of its callers, its entry lacks that context: `MN103FixCallFrames` sets it at every call target
  and re-disassembles. (On block0: 62,832 call targets; 4 are called with two different frame sizes.)
- **Hardware loops.** `setlb` + `Lcc` (`lne`, `llt`, ...) branch to the instruction after the last
  `setlb`. The module carries that address forward as flowing context, so loops decompile as normal
  `do { } while` loops. If no `setlb` is seen on the way, `Lcc` falls back to an indirect jump via `lar`.
- **Calling convention** (read off the code, not from a Panasonic document): arguments in d0, d1
  (integers) and a0, a1 (pointers), more on the stack from (sp+4) at the callee's entry, return in d0
  (or a0 for pointers). d2, d3, a2, a3 and r4-r7 are callee-saved. Ghidra numbers parameters in the order
  d0, d1, a0, a1, so `memcpy(a0 dst, a1 src, d0 len)` shows up as `memcpy(len, dst, src)` until you edit
  its signature. Functions called without a known prototype often pick up a0/a1 as extra parameters.
- **udf00/udfu00, udf01/udfu01** (Panasonic user-defined ops) are modelled as a 32-bit multiply. That is
  inferred from use in this firmware (`udfu01 20,d0` before indexing a 20-byte array, `udf00 -1,d0` to
  negate, `udf00 d0,d2; ext d2; div d0,d2` as a*b/c), not documented. Other udfNN ops, the DSP
  accumulator ops (mac*, dmach*, dmulh*, mcste, mcst9/48), bsch, getx/putx, dcpf, trap, syscall, rtm and
  break are p-code pseudo-ops (shown as calls like `mac(...)`).
- Register names follow objdump, except the AM33 extended registers xr1-xr4, which are named for
  what they are: `mdrq`, `mcrh`, `mcrl`, `mcvf`. psw flags are separate registers `Z N C V`; the FPU
  condition codes are `fccL fccG fccE fccU`.

## How it was built and checked

`generator/gen.py` writes `mn103.slaspec` from the binutils 2.42 opcode table (`table.json`, dumped from
`opcodes/m10300-opc.c` by `dump.c`). It copies binutils' disassembler exactly: instruction length from the
first byte (as `print_insn_mn10300`), first matching table entry wins (turned into non-overlapping bit
patterns), operand bits traced through binutils' byte shuffling. Semantics follow the GDB simulator
(`sim/mn10300/*.igen`, gdb 15.1). Regenerate with `python3 gen.py table.json m10300-opc.c out/`.

| check | result |
|---|---|
| Decode every position objdump decodes in block0 (`objdump -D -m am33-2`), compare length + mnemonic + operands | **14,086,364 of 14,086,364 identical** (incl. every `unknown`) |
| Same on 5 MB of random bytes (every first-two-byte combination x6, plus 2 MB random) | **3,164,334 of 3,164,334 identical** |
| Run 4,489 single instructions (241 operand shapes: ALU, shifts, mul/div, ext, moves, loads/stores, AM33 3- and 4-operand and dual ops) in the GDB simulator and in Ghidra's p-code emulator; compare all registers, flags, mdr, sp, memory | **4,250 agree.** All 239 differences trace to simulator bugs: sat16 and the sat16_* dual ops compare signed values as unsigned (sim saturates 0 to 0xffff8000); swhw_add is coded as XOR in the sim; asr takes C from bit 0 before the shift; addc/subc/3-operand sub carry and overflow formulas; one `ext` with mismatched repeated register fields; one divide by zero. 188 dual ops with both destinations the same register were skipped (invalid encodings, the sim rejects them) |
| Import whole block0 with symbols, decompile known functions | `validation/decompiler-samples.c`: USB mode mapping, PID descriptor dispatch, timers, focus-stack check, shooting-state chooser, boot section loader, image-processor job routing |

Divide by zero is not modelled (p-code divides; hardware sets V and returns 0xff). The FPU ops are
modelled with Ghidra float ops but were not run against the simulator.

`validation/` has the scripts: `DecodeAt.java` + `parse_od.py` + `compare.py` (decode check),
`difftest/` (simulator test generator, run loop, comparison and the full result list),
`MN103EmuTests.java` (the Ghidra side). The simulator was built from the Ubuntu gdb 15.1 source
(`configure --target=mn10300-elf --enable-sim`, `make MAKEINFO=true all-sim`).

## Scripts

| script | what |
|---|---|
| `MN103LoadSymbols` | args `symbols.csv [lo hi]`: creates functions (with the note as plate comment) and labels |
| `MN103FixCallFrames` | sets callee-entry frame context at every call target, re-disassembles entries |
| `MN103AddRamBlock` | args `[start len]`, default 0x62000000 0x02000000: uninitialized RAM for globals |
| `MN103Decompile` | args `out.c [-create] name|0xaddr|@list ...`: write decompiled C for functions (`-create` makes missing functions) |
| `MN103InferParams` | args `[-all] [-keep] name|0xaddr|@list ...`: infer parameters from use with the real d/a register storage and commit them, callees first, so calls show their arguments (Ghidra's own numbering d0,d1,a0,a1 puts two dummy parameters in front of a pointer-only function and drops a0 arguments at call sites) |
| `MN103Annotate` | args `types.h annotations.txt outdir [archive.gdt]`: apply a C header (types, prototypes with `__a0`-style register pins) and a names/comments file, write commented C per source file and a type archive. Used by `../decomp/liveND/` and `../decomp/hhhr/` |
| `MN103RecoverSwitches` | args `name|0xaddr|@list ...`: take the decompiler's jump tables, disassemble the case targets and add the computed-jump references (what auto-analysis would do). Run it twice for nested switches |

## Fixes after the first version (2026-10-21)

- A call instruction that is itself the first instruction of a function overwrote that function's own entry
  frame (the call's frame went into the same context fields), so locals of such functions were off. The entry
  frame is now copied into separate fields (`en_regs/en_frame`) before the instruction's own action runs.
  Re-import (or clear and re-disassemble) projects made with the earlier `.sla`.
- `Lcc`/`lra` decoded with no known `setlb` (mostly data decoded as code) branched "directly" to the LAR
  register, which crashed two auto-analysis passes ("Not a valid Address"). It is now an indirect branch.

## Fixes found during the HHHR decompile (2026-10-22)

These are about how a project is prepared, not the `.sla`, so there's no need to re-import:

- **Switch tables** in a project imported with `-noanalysis` stay unrecovered. The decompiler then decodes
  the case blocks on the fly with the wrong context, and every case shows bogus stack pushes
  (`puVar3[-4] = ...`). Run `MN103RecoverSwitches` on the functions you decompile. The Live ND closure had
  11 such tables, though none in the 180 functions written out.
- **Call frames of functions whose callers were never disassembled.** `MN103FixCallFrames` only sees call
  instructions that exist. A function reached only from code that was never disassembled gets no entry
  frame, and its locals show up as `stack0x0000000c`. Fix: create the callers first (both decompile builds
  now do this with `inputs/callers.lst`), then rerun `MN103FixCallFrames`.

## Known limits

- Functions found only by the symbol table's detector include some data tables misread as code
  (see `../symbols/README.md`); 343 call targets fall inside other instructions and were skipped.
- Pointer-in-a vs integer-in-d argument order is not expressible in a Ghidra prototype; edit signatures
  of hot functions (memcpy/memset/dbg_trace_log) by hand.
- Functions with two entries (X: `movm` + `add` for indirect `calls`, X+5: the `call` target) decompile
  correctly from X+5; X runs the callee frame twice.
- 0x47001024 memcpy and 0x47001130 memset live outside block0; the loader gives them an empty block so
  calls resolve to named functions.
