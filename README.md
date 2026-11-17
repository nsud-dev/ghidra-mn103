# ghidra-mn103

A Ghidra processor module for the Panasonic MN103 family (MN10300, AM33 and AM33-2), with decompiler support.

Ghidra doesn't support these CPUs out of the box. They show up in Panasonic-designed chips, including the ones in
Olympus cameras like the E-M5 Mark III, where an MN103 core runs most of the camera. I wrote this to read that
firmware, but nothing in the module is specific to cameras.

What's here:

- Disassembly that matches GNU objdump, instruction for instruction
- Decompiler output that copes with the MN103's quirks (call frames set up by the caller, hardware loops, its calling
  convention)
- Ghidra scripts for loading symbols, fixing call frames, recovering switch tables and batch decompiling
- The generator that builds the SLEIGH spec from the binutils opcode table, and the tests used to check it

Tested with Ghidra 11.4.2 on Java 21; the CI build also runs on the newest Ghidra release. The language ID is
`MN103:LE:32:AM33-2`.

## Installing

1. Copy the `MN103` folder into `<ghidra>/Ghidra/Processors/`.
2. Restart Ghidra. MN103 now appears in the language list when you import a file.
3. The scripts show up in the Script Manager under MN103.

The compiled `mn103.sla` isn't checked in. Ghidra normally builds it the first time you use the language. If it
doesn't, build it yourself:

```sh
<ghidra>/support/sleigh <ghidra>/Ghidra/Processors/MN103/data/languages/mn103.slaspec
```

## Loading a binary

In the GUI: File > Import File, format **Raw Binary**, language `MN103:LE:32:AM33-2`, and set the base address under
Options. Then:

1. Run `MN103AddRamBlock` if you want labels and xrefs for globals in RAM.
2. Run `MN103LoadSymbols` if you have a symbol list.
3. Run auto-analysis if you want it.
4. Run `MN103FixCallFrames`.

Run `MN103FixCallFrames` again after any analysis, or after disassembling new code. It's safe to run as often as you
like.

### Olympus E-M5 Mark III firmware

`import_block0.sh` does all of the above headless for the E-M5 III. It unpacks block0 from your own copy of the stock
firmware and imports it at `0x60021020`:

```sh
./import_block0.sh /path/to/ghidra /path/to/projects FIRMWARE.BIN            # about 5 minutes
./import_block0.sh /path/to/ghidra /path/to/projects FIRMWARE.BIN --analyze  # about 40 minutes, with auto-analysis
```

It needs `olyfw.py` from [olympus-firmware-notes](https://github.com/nsud-dev/olympus-firmware-notes). Clone that repo
next to this one, or point `OLYFW` at the script.

## MN103 quirks the module handles

**The caller sets up the callee's frame.** Code from Panasonic's compiler, which built the Olympus firmware, doesn't
build its stack frame in the function. The call does it: `call label,[d2,d3,a2],24` saves the callee's registers and
allocates its 24-byte frame, and `ret`/`retf` undo it. Treated as part of the caller, this makes the decompiler lose
track of the stack in every function, so arguments and locals show up as unknown registers. This module treats it as part of
the callee's entry, so stack locals and arguments land where the decompiler expects them. The call passes that
information to the callee through context, so a function disassembled before any of its callers misses it.
`MN103FixCallFrames` fixes that; run it after analysis. For a function with no direct call (reached through a table),
it takes the frame from the function's own `ret`/`retf`, which undo exactly what the call set up.

**Hardware loops.** `setlb` marks a loop start and the `Lcc` instructions (`lne`, `llt` and so on) branch back to it.
The module tracks the loop start, so these decompile as ordinary `do { } while` loops.

**Calling convention.** I worked this out from the code, not from a Panasonic document. Integer arguments go in d0
and d1, pointers in a0 and a1, and the rest on the stack. Results come back in d0, or a0 for pointers. d2, d3, a2, a3
and r4 to r7 are callee-saved. Ghidra can't express "integers in d, pointers in a" in one prototype, so
`memcpy(a0 dst, a1 src, d0 len)` shows up as `memcpy(len, dst, src)` until you fix its signature by hand.

**Undocumented ops.** `udf00`/`udfu00` and `udf01`/`udfu01` are modelled as a 32-bit multiply. That's a guess from how
the firmware uses them, not from documentation. The DSP accumulator ops and a few system instructions are left as
named pseudo-ops, so they show up as calls like `mac(...)`.

Register names follow objdump, except AM33's xr1 to xr4, which are named `mdrq`, `mcrh`, `mcrl` and `mcvf` after what
they hold.

## How it was built

`generator/gen.py` writes `mn103.slaspec` from the binutils 2.42 opcode table (`table.json`, dumped from
`opcodes/m10300-opc.c` by `dump.c`). Decoding follows binutils exactly. The instruction semantics follow the GDB
simulator (gdb 15.1), except where the MN1030 instruction definitions say otherwise: the carry flag of `asr`/`lsr`,
the zero flag of `addc`/`subc`, and divide overflow. To regenerate:

```sh
python3 gen.py table.json m10300-opc.c out/
```

## What it's verified against

- **Decoding, against GNU objdump 2.42.** Every position objdump decodes in the E-M5 Mark III's 25 MB main firmware
  block, 14,086,364 instructions, decodes identically, and so do 3,164,334 instructions from 5 MB of random bytes
  (`validation/DecodeAt.java`, `parse_od.py`, `compare.py`).
- **Semantics, against the GDB simulator.** 4,489 single instructions, taken from the firmware with random register
  values, ran in both the simulator and Ghidra's p-code emulator, comparing registers, flags and memory. 4,250 agreed.
  The 239 differences are listed in `validation/difftest/result-sim-vs-ghidra.txt`. Most come from simulator bugs
  (saturating ops, `swhw_add`, some overflow flags). The `asr`/`lsr` carry and `addc`/`subc` zero-flag cases were module
  errors and are fixed.
- **Hand-computed cases.** `validation/emu_cases.txt` holds single-instruction cases with expected values worked out by
  hand (shift carry, add/subtract with carry, divide, divide overflow and divide by zero), plus one case with a wrong
  expectation that must fail. `MN103CaseTests.java` runs them in Ghidra's emulator.
- **Builds and runs.** On every push, CI (`.github/workflows/build.yml`) compiles the SLEIGH spec and every script on
  Ghidra 11.4.2 and the newest Ghidra release, then runs the emulator cases.
- **Decompiling real code.** `validation/decompile_check.sh` imports the E-M5 III 1.7 main block with Ghidra's
  auto-analysis, runs `MN103FixCallFrames` and decompiles the 40 functions in `validation/decompile_funcs.txt` (spread
  over the block, 120 to 500 bytes each, taken from functions whose boundaries were confirmed). All 40 decompile, with
  no `unaff_*` registers and no bad instructions. The decompiler leaves 29 references to unresolved inputs (`in_*`) in
  7 functions. All of them are real arguments that Ghidra's prototype doesn't list: a pointer passed in a1 without
  one in a0, or a stack argument (see Doesn't work). About 14 minutes on 4 cores with Ghidra 11.4.2. You need your own
  copy of the stock firmware to run it.

## Scripts

| script | what it does |
|---|---|
| `MN103LoadSymbols` | creates functions and labels from a CSV symbol list |
| `MN103FixCallFrames` | sets up callee frames at every call target and re-disassembles the entries |
| `MN103AddRamBlock` | adds an uninitialised RAM block for globals (default 32 MB at `0x62000000`) |
| `MN103Decompile` | writes decompiled C for a list of functions |
| `MN103InferParams` | infers parameters from how registers are used, so call sites show their arguments |
| `MN103RecoverSwitches` | recovers switch tables in projects imported without auto-analysis |
| `MN103Annotate` | applies a C header and a names and comments file, then writes commented C |

`export_headless.sh` runs a batch decompile. Its optional CSV inputs come from tools that aren't published here.

## Doesn't work

- Left as named pseudo-ops, so they show up as calls such as `mac(...)`: the multiply-accumulate family (`mac`,
  `macu`, `macb`, `mach`, `dmach` and their variants), `dmulh`/`dmulhu`, `bsch`, `mcst9`/`mcst48`/`mcste`,
  `getchx`/`getclx`, the `udf` instructions other than `udf00`/`udf01`, and the system instructions.
- Ghidra prototypes can't express the d/a register split, so functions that take both integers and pointers need
  their signatures edited by hand. Until then, a pointer argument in a1 (with nothing in a0) and stack arguments show
  up as `in_a1` and `in_stack_*`. `MN103InferParams` doesn't fix these cases yet.
- Functions with two entry points decompile correctly from the second one only.

## Unverified

- `udf00`/`udfu00` and `udf01`/`udfu01` are modelled as a 32-bit multiply, a guess from how the firmware uses them.
- `sat16`, `sat24`, `swap`, `swaph` and `swhw` are modelled from the simulator's descriptions, but the simulator's
  own results disagree with them in some saturating cases (see the difftest list), so neither is confirmed.
- FPU ops are modelled but weren't tested against the simulator or hardware.
- After a divide by zero or a divide overflow, the module leaves the dividend and MDR unchanged. What the hardware
  leaves there isn't documented.
- The flags of the three- and four-operand AM33 forms are modelled like the two-operand forms.
- D10 dual operations whose two destinations are the same register are undefined; the module decodes them anyway.
- Nothing has been checked on hardware other than through the firmware it runs.

## Related work

Other Ghidra modules for this CPU family:
[michaelbrandi/ghidra-mn103-extension](https://github.com/michaelbrandi/ghidra-mn103-extension) and its fork
[aleph-void/ghidra-mn103-extension](https://github.com/aleph-void/ghidra-mn103-extension) (`ghidra-rare` branch,
Apache-2.0: MN10300, AM33 and AM33-2, ELF loading, semantics from the MN1030 manual and compiled C), and
[txt231/GhidraMn10300](https://github.com/txt231/GhidraMn10300). The `ghidra-rare` module covers the three
machine variants as separate languages, loads ELF files with relocations and DWARF, targets Ghidra 12, and documents
its semantics sources in detail. Nothing from these modules is in this one.

## AI disclosure

To get this into people's hands, much of the documentation, including this README, was written by an AI assistant
(Anthropic's Claude). I am working to replace that writing with my own, as I believe that will make the repositories
more entertaining and readable.

The module, generator, scripts and tests were written with help from the same assistant, with me directing it,
reviewing the results and testing on real firmware. The test results above are what actually came out of the runs. If
something looks wrong, please open an issue.

## Licence

GPL-3.0-or-later, because the SLEIGH spec is generated from the GNU binutils 2.42 opcode table (Copyright (C) Free
Software Foundation, Inc.) and the semantics follow the GDB simulator, both GPL-3.0-or-later. Thanks to the binutils and
GDB developers. The full licence text is in [COPYING](COPYING); [LICENSE.md](LICENSE.md) says which parts are derived.
