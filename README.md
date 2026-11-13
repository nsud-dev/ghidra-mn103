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

Tested with Ghidra 11.4.2 on Java 21. The language ID is `MN103:LE:32:AM33-2`.

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

**The caller sets up the callee's frame.** `call label,[d2,d3,a2],24` saves the callee's registers and allocates its
24-byte stack frame. The module treats that as part of the callee's entry, so stack locals and arguments land where
the decompiler expects them. `ret` and `retf` undo it. If a function gets disassembled before any of its callers, it
misses this, which is what `MN103FixCallFrames` fixes.

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

## How it was built and tested

`generator/gen.py` writes `mn103.slaspec` from the binutils 2.42 opcode table (`table.json`, dumped from
`opcodes/m10300-opc.c` by `dump.c`). Decoding follows binutils exactly, and the instruction semantics follow the GDB
simulator (gdb 15.1). To regenerate:

```sh
python3 gen.py table.json m10300-opc.c out/
```

The tests:

- **Decoding.** Every position objdump decodes in a 25 MB firmware block, 14,086,364 instructions, decodes
  identically. So do 3,164,334 instructions from 5 MB of random bytes.
- **Semantics.** I ran 4,489 single instructions in both the GDB simulator and Ghidra's p-code emulator and compared
  registers, flags and memory. 4,250 agree. Every one of the 239 differences traced back to a bug in the simulator,
  not the module: saturating ops, `swhw_add`, some carry and overflow flags. The full list is in
  `validation/difftest/result-sim-vs-ghidra.txt`.

The scripts for both checks are in `validation/`.

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

## Known limits

- Divide by zero isn't modelled. The hardware sets V and returns `0xff`.
- FPU ops are modelled but weren't tested against the simulator.
- Ghidra prototypes can't express the d/a register split, so hot functions need their signatures edited by hand.
- Functions with two entry points decompile correctly from the second one only.

## AI disclosure

To get this into people's hands, much of the documentation, including this README, was written by an AI assistant
(Anthropic's Claude). I am working to replace that writing with my own, as I believe that will make the repositories
more entertaining and readable.

The module, generator, scripts and tests were written with help from the same assistant, with me directing it,
reviewing the results and testing on real firmware. The test results above are what actually came out of the runs. If
something looks wrong, please open an issue.

## Licence

GPL-3.0-or-later, because the SLEIGH spec is generated from the GNU binutils opcode table and the semantics follow the
GNU simulator. See [COPYING](COPYING).
