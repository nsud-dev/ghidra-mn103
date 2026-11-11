#!/bin/sh
# Headless import of E-M5 III block0 into a Ghidra project with the MN103 language and call-frame fix-up.
# Analysis only: nothing here writes firmware.
#
# usage: import_block0.sh GHIDRA_INSTALL_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]
#   FIRMWARE.BIN: your own copy of the stock E-M5 III firmware (e.g. firmware 1.7)
#   --analyze also runs Ghidra's auto-analysis (slow on 25 MB; see README)
#   SYMBOLS=/path/symbols.csv (optional): create functions and labels from a CSV (addr,name,... as MN103LoadSymbols reads)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
# olyfw.py comes from https://github.com/nsud-dev/olympus-firmware-notes (tools/olyfw.py).
# Set OLYFW=/path/to/olyfw.py, or clone that repo next to this one.
OLYFW=${OLYFW:-$HERE/../olympus-firmware-notes/tools/olyfw.py}
[ -f "$OLYFW" ] || { echo "olyfw.py not found: set OLYFW=/path/to/olyfw.py (from github.com/nsud-dev/olympus-firmware-notes)"; exit 1; }
G=${1:?usage: import_block0.sh GHIDRA_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]}
P=${2:?usage: import_block0.sh GHIDRA_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]}
BIN=${3:?usage: import_block0.sh GHIDRA_DIR PROJECT_DIR FIRMWARE.BIN [--analyze]}
ANALYZE=-noanalysis
[ "$4" = "--analyze" ] && ANALYZE=
[ -d "$G/Ghidra/Processors/MN103" ] || { echo "install the MN103 module first: cp -r $HERE/MN103 $G/Ghidra/Processors/"; exit 1; }
W=$(mktemp -d)
python3 "$OLYFW" unpack "$BIN" "$W/unpacked" >/dev/null
B0=$(ls "$W"/unpacked/block0_*.bin)
cp "$B0" "$W/e5_block0.bin"
mkdir -p "$P"
SYM=
[ -n "$SYMBOLS" ] && SYM="-preScript MN103LoadSymbols.java $SYMBOLS"
"$G/support/analyzeHeadless" "$P" em5iii -import "$W/e5_block0.bin" -overwrite \
  -processor MN103:LE:32:AM33-2 -loader BinaryLoader -loader-baseAddr 0x60021020 $ANALYZE \
  -scriptPath "$HERE/MN103/ghidra_scripts" \
  -preScript MN103AddRamBlock.java \
  $SYM \
  -preScript MN103FixCallFrames.java \
  -postScript MN103FixCallFrames.java
rm -rf "$W"
echo "project: $P/em5iii.gpr"
