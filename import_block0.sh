#!/bin/sh
# Headless import of E-M5 III block0 into a Ghidra project with the MN103 language and call-frame fix-up.
# Analysis only: nothing here writes firmware.
#
# usage: import_block0.sh GHIDRA_INSTALL_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]
#   FIRMWARE.BIN: your own copy of the stock E-M5 III firmware (e.g. firmware 1.7)
#   --analyze also runs Ghidra's auto-analysis (slow on 25 MB; see README)
#   FIRMWARE.BIN may also be a main block image you already have (a .bin file, not .BIN): it is imported as it is.
#     For bodies whose main block has compressed sections (OM-5, E-M1 III), pass the expanded image.
#   NAME=<project program name> (default em5iii), e.g. NAME=om5
#   REGS=<register list CSV> or REGS=none (default: the module's E-M5 III family list; use none for the OM-1)
#   SYMBOLS=/path/symbols.csv (optional): create functions and labels from a CSV (addr,name,... as MN103LoadSymbols reads)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
# olyfw.py comes from https://github.com/nsud-dev/olympus-firmware-notes (tools/olyfw.py).
# Set OLYFW=/path/to/olyfw.py, or clone that repo next to this one.
OLYFW=${OLYFW:-$HERE/../olympus-firmware-notes/tools/olyfw.py}
case "$3" in *.bin) ;; *) [ -f "$OLYFW" ] || { echo "olyfw.py not found: set OLYFW=/path/to/olyfw.py (from github.com/nsud-dev/olympus-firmware-notes)"; exit 1; } ;; esac
G=${1:?usage: import_block0.sh GHIDRA_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]}
P=${2:?usage: import_block0.sh GHIDRA_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]}
BIN=${3:?usage: import_block0.sh GHIDRA_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]}
ANALYZE=-noanalysis
[ "$4" = "--analyze" ] && ANALYZE=
[ -d "$G/Ghidra/Processors/MN103" ] || { echo "install the MN103 module first: cp -r $HERE/MN103 $G/Ghidra/Processors/"; exit 1; }
W=$(mktemp -d)
case "$BIN" in
  *.bin) cp "$BIN" "$W/e5_block0.bin" ;;
  *) python3 "$OLYFW" unpack "$BIN" "$W/unpacked" >/dev/null
     cp "$(ls "$W"/unpacked/block0_*.bin)" "$W/e5_block0.bin" ;;
esac
mkdir -p "$P"
NAME=${NAME:-em5iii}
REG="-preScript MN103LabelRegisters.java"
[ -n "$REGS" ] && REG="-preScript MN103LabelRegisters.java $REGS"
[ "$REGS" = none ] && REG=
SYM=
[ -n "$SYMBOLS" ] && SYM="-preScript MN103LoadSymbols.java $SYMBOLS"
"$G/support/analyzeHeadless" "$P" "$NAME" -import "$W/e5_block0.bin" -overwrite \
  -processor MN103:LE:32:AM33-2 -loader BinaryLoader -loader-baseAddr 0x60021020 $ANALYZE \
  -scriptPath "$HERE/MN103/ghidra_scripts" \
  -preScript MN103AddRamBlock.java \
  -preScript MN103SectionBlocks.java \
  $REG \
  -preScript MN103VscNames.java \
  $SYM \
  -preScript MN103FixCallFrames.java \
  -postScript MN103FixCallFrames.java
rm -rf "$W"
echo "project: $P/$NAME.gpr"
