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

Tested with Ghidra 11.4.2 on Java 21 and Ghidra 12.2 on Java 25; the CI build also runs on the newest Ghidra release.
The language ID is
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

The import also splits the image into the parts the camera loads separately, adds the uncached view of memory, and
names the peripheral registers (see the scripts below). Those steps take a few seconds.

### Other bodies

The OM-5, OM-5 II, E-M1 III and OM-1 use the same base address. Pass the main block image instead of the firmware file,
and a name for the program:

```sh
NAME=om5 ./import_block0.sh /path/to/ghidra /path/to/projects om5_block0.bin
```

A file ending in `.bin` is imported as it is. Some bodies store parts of the main block compressed (the OM-5 and the
E-M1 III do). Expand those parts first, or the code there won't decode. For the OM-1 add `REGS=none`, because its
power block is laid out differently.

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
and r4 to r7 are callee-saved. With the default compiler spec Ghidra numbers parameters d0, d1, a0, a1, so
`memcpy(a0 dst, a1 src, d0 len)` shows up as `memcpy(len, dst, src)` until you fix its signature by hand. The second
compiler spec, `ptrregs` ("cc103, pointers in a0/a1" in the import dialog, `-cspec ptrregs` headless), marks a0 and
a1 as pointer registers, so a signature you type lands in the right registers on its own: `memcpy(a0 dst, a1 src, d0
len)`, `memset(a0 dst, d0 byte, d1 len)`, pointer results in a0. Parameters the decompiler finds by itself are then
listed pointers first. A third pointer argument goes to d0, as the Panasonic compiler manual describes, although the
camera code I checked never does that.

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
  hand, 62 of them: add, subtract and compare flags, multiply and divide (including overflow and divide by zero), shift
  carry, rotates through carry, sign and zero extension, loads and stores in little-endian memory, `bset`/`bclr` in
  memory, `movm` push and pop, `calls`/`rets`, a `setlb`/`lne` loop, an AM33 dual op whose halves overlap, and the
  byte-swap instructions. Two more cases have a wrong expectation and must fail. `MN103CaseTests.java` runs them in
  Ghidra's emulator. `CallingConventionTest.java` checks where typed parameters land with the `ptrregs` spec.
- **Builds and runs.** On every push, CI (`.github/workflows/build.yml`) compiles the SLEIGH spec and every script on
  Ghidra 11.4.2 and the newest Ghidra release, then runs the emulator cases and the calling-convention check.
- **Decompiling real code.** `validation/decompile_check.sh` imports the E-M5 III 1.7 main block with Ghidra's
  auto-analysis, runs `MN103FixCallFrames` and decompiles the 40 functions in `validation/decompile_funcs.txt` (spread
  over the block, 120 to 500 bytes each, taken from functions whose boundaries were confirmed). All 40 decompile, with
  no `unaff_*` registers and no bad instructions at any stage. It counts the unresolved inputs (`in_*`) three times:
  29 right after auto-analysis, 15 once the callers that auto-analysis never reached are disassembled and the call
  frames are set again, and 0 after `MN103InferParams`. With the `ptrregs` spec (`CSPEC=ptrregs`) the second count is
  already 0. Ghidra 12.2 gives the same final counts. About 14 minutes on 4 cores. You need your own copy of the stock
  firmware to run it. The next section says what the counts mean.

## Reading the decompile check

Ghidra's decompiler gives a value it can't explain a name that says where it came from. Seeing these names in a
decompile doesn't by itself mean the processor module is wrong; each one points at something specific.

- **`in_<register>` and `in_stack_<offset>`**: the function reads a register or stack slot it never wrote, and the
  decompiler hasn't counted it as a parameter. In this firmware there are two causes, both handled:
  - *No call frame yet.* On this CPU the caller's `call` instruction saves the callee's registers and reserves its
    stack frame (see "The caller sets up the callee's frame" above). If auto-analysis never disassembled any caller of
    a function, the function has no frame, so its stack offsets are off by the frame size and ordinary locals show up
    as `in_stack_*`. In the check, 12 of the 40 functions start like this. `MN103Decompile` puts a comment at the top of
    such a function. Disassemble one of its callers (or import with a function list), run `MN103FixCallFrames` again
    and decompile again. Step 2 of the check does this with `validation/DisassembleCallers.java`.
  - *Parameter order.* Ghidra's parameter model takes d0, d1, a0 and a1 in that fixed order. When a function
    overwrites d0 before it reads a pointer argument in a1, the decompiler drops a1 and shows it as `in_a1`.
    `MN103InferParams` adds such registers as parameters (step 3).
- **`unaff_<register>`**: a callee-saved register (d2, d3, a2, a3, r4 to r7) read before the function saved or wrote
  it. Compiled functions in this firmware don't do that once their frame is set, so the check finds none. Many of
  them in one function mean the bytes being decompiled are probably data, not code.
- **`halt_baddata`**: the decompiler reached bytes that aren't a valid instruction. In firmware this almost always
  means data decoded as code: a table or a string inside what was taken to be a function.

An earlier version of the check reported 63 `unaff_*` (40 of them `a3`) and one `halt_baddata`. All of them came from
two sample addresses that turned out to be data: one inside a table of floating-point numbers, one in a block of
text. The instruction the decompiler stopped at (bytes `f1 ff`) isn't valid MN103 for binutils either. `a3` is an
ordinary callee-saved address register in this code, not a global base pointer. The sample now uses functions whose
boundaries were confirmed.

What stays a real limit: Ghidra decompiles what auto-analysis has disassembled. Code reached only through tables or
from code that isn't disassembled yet needs a function list or a manual disassembly before its call frames and
parameters are right.

## Scripts

| script | what it does |
|---|---|
| `MN103LoadSymbols` | creates functions and labels from a CSV symbol list |
| `MN103FixCallFrames` | sets up callee frames at every call target and re-disassembles the entries |
| `MN103AddRamBlock` | adds an uninitialised RAM block for globals (default 32 MB at `0x62000000`) |
| `MN103SectionBlocks` | splits the main block into the boot part and sections 1 to 10, read from the firmware's own section table, and adds the uncached view at `0xa0000000` |
| `MN103LabelRegisters` | creates and names peripheral registers from a list, by default `data/registers/e144-family.csv` (power block, debug serial port, lock bits, doorbells, pads, shared memory) |
| `MN103VscNames` | names the display controller registers from the firmware's own name table, so no names ship with the module |
| `MN103SetCompilerSpec` | switches the open program between the `default` and `ptrregs` compiler specs and keeps the listing |
| `MN103Decompile` | writes decompiled C for a list of functions, with a comment on any function that has no call frame yet |
| `MN103InferParams` | infers parameters from how registers are used, including a pointer in a1 that Ghidra's fixed order drops, so call sites show their arguments |
| `MN103RecoverSwitches` | recovers switch tables in projects imported without auto-analysis |
| `MN103Annotate` | applies a C header and a names and comments file, then writes commented C |
| `MN103LensInfo` | builds a `lens_info_t` structure from a field-map CSV (offset, type, count, name, comment) and applies it to the lens record pointer and its getter. The CSV is not published. The field offsets are on the lens communication page in the notes. |

`export_headless.sh` runs a batch decompile. Its optional CSV inputs come from tools that aren't published here.

## Doesn't work

- Left as named pseudo-ops, so they show up as calls such as `mac(...)`: the multiply-accumulate family (`mac`,
  `macu`, `macb`, `mach`, `dmach` and their variants), `dmulh`/`dmulhu`, `bsch`, `mcst9`/`mcst48`/`mcste`,
  `getchx`/`getclx`, the `udf` instructions other than `udf00`/`udf01`, and the system instructions.
- With the default compiler spec, prototypes can't express the d/a register split. `MN103InferParams` writes
  signatures with the right registers for the functions you give it, and the `ptrregs` spec places typed signatures
  correctly.
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
