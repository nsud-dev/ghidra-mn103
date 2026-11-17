#!/bin/sh
# Decompile check on real firmware: import the E-M5 III 1.7 main block (block0, unpacked from your own copy of the
# stock firmware with olyfw.py), run Ghidra's auto-analysis and MN103FixCallFrames, then decompile the 40 functions in
# decompile_funcs.txt (spread over the block, 120-500 bytes each) and count what the decompiler couldn't resolve.
# Analysis only: nothing here writes firmware. Takes about as long as import_block0.sh --analyze.
#
# usage: decompile_check.sh GHIDRA_DIR BLOCK0.bin [WORKDIR]
set -e
G=$1; B=$2; W=${3:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$W/proj"
"$G/support/analyzeHeadless" "$W/proj" check -import "$B" -processor MN103:LE:32:AM33-2 -loader BinaryLoader \
  -loader-baseAddr 0x60021020 -scriptPath "$HERE/../MN103/ghidra_scripts" \
  -postScript MN103FixCallFrames.java \
  -postScript MN103Decompile.java "$W/out.c" -create "@$HERE/decompile_funcs.txt" > "$W/log" 2>&1
echo "functions decompiled:            $(grep -c '^// =====' "$W/out.c")"
echo "unresolved inputs (in_*):        $(grep -o '\bin_[A-Za-z0-9_]*' "$W/out.c" | wc -l)"
echo "unaffected registers (unaff_*):  $(grep -o '\bunaff_[A-Za-z0-9_]*' "$W/out.c" | wc -l)"
echo "bad data (halt_baddata):         $(grep -c 'halt_baddata' "$W/out.c" || true)"
echo "output: $W/out.c"
