#!/bin/sh
# Decompile check on real firmware: import the E-M5 III 1.7 main block (block0, unpacked from your own copy of the
# stock firmware with olyfw.py), run Ghidra's auto-analysis and MN103FixCallFrames, then decompile the 40 functions in
# decompile_funcs.txt (spread over the block, 120-500 bytes each, named from confirmed symbols) and count what the
# decompiler couldn't resolve: (1) as plain auto-analysis leaves them, (2) after also disassembling the direct callers
# that auto-analysis never reached (DisassembleCallers.java), so every function gets its call frame, (3) after
# MN103InferParams.
# README.md "Reading the decompile check" explains each count.
# Analysis only: nothing here writes firmware. Takes about as long as import_block0.sh --analyze.
#
# usage: decompile_check.sh GHIDRA_DIR BLOCK0.bin [WORKDIR]
# CSPEC=ptrregs selects the compiler spec with pointer arguments in a0/a1 (mn103_ptr.cspec); default: default.
set -e
G=$1; B=$2; W=${3:-$(mktemp -d)}; CSPEC=${CSPEC:-default}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$W/proj"
"$G/support/analyzeHeadless" "$W/proj" check -import "$B" -processor MN103:LE:32:AM33-2 -cspec "$CSPEC" -loader BinaryLoader \
  -loader-baseAddr 0x60021020 -scriptPath "$HERE/../MN103/ghidra_scripts;$HERE" \
  -postScript MN103FixCallFrames.java \
  -postScript MN103Decompile.java "$W/out.c" -create "@$HERE/decompile_funcs.txt" \
  -postScript DisassembleCallers.java "@$HERE/decompile_funcs.txt" \
  -postScript MN103FixCallFrames.java \
  -postScript MN103Decompile.java "$W/out-callers.c" "@$HERE/decompile_funcs.txt" \
  -postScript MN103InferParams.java "@$HERE/decompile_funcs.txt" \
  -postScript MN103Decompile.java "$W/out-params.c" "@$HERE/decompile_funcs.txt" > "$W/log" 2>&1
count() {
  echo "  functions decompiled:            $(grep -c '^// =====' "$1")"
  echo "  without a call frame (warning):  $(grep -c '^/\* MN103: no disassembled' "$1" || true)"
  echo "  unresolved inputs (in_*):        $(grep -oE '(^|[^:A-Za-z0-9_])in_[A-Za-z0-9_]*' "$1" | wc -l)"
  echo "  unaffected registers (unaff_*):  $(grep -o '\bunaff_[A-Za-z0-9_]*' "$1" | wc -l)"
  echo "  bad data (halt_baddata):         $(grep -c 'halt_baddata' "$1" || true)"
}
echo "1. after auto-analysis and MN103FixCallFrames ($W/out.c):"; count "$W/out.c"
echo "2. after also disassembling the direct callers auto-analysis missed and rerunning MN103FixCallFrames ($W/out-callers.c):"
count "$W/out-callers.c"
echo "3. after MN103InferParams ($W/out-params.c):"; count "$W/out-params.c"
