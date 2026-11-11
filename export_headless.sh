#!/bin/sh
# Headless Ghidra export of a function list, the same steps the maintainer runs in the GUI for a csrc batch:
#   MN103RecoverSwitches (repeated until no new tables), MN103FixCallFrames, MN103InferParams -keep, MN103Decompile.
# Analysis only: reads the Ghidra project, writes one .ghidra.c file. Nothing here writes firmware.
#
# usage: export_headless.sh GHIDRA_DIR PROJECT_DIR LIST OUT.ghidra.c [TIMEOUT_S]
#   PROJECT_DIR holds em5iii.gpr from import_block0.sh. LIST: one 0xaddress or name per line.
#   TIMEOUT_S: seconds per decompile (default 60; use 600 for csrc/ghidra-in/funcs-timeouts.txt).
#   Resumable: InferParams -keep skips functions already done; rerun the whole command after a stop.
#   STOCK_PARAMS=/path/stock-inputs.csv (from csrc/tools/stock_inputs.py): after InferParams, set every
#   function's register params to the registers stock really takes (MN103ApplyStockParams), so calls show
#   all the arguments stock passes. Use it for re-exports of eqcheck "arg differs" functions.
#   CALL_ARGS=/path/variadic.csv (from csrc/tools/find_variadic.py, or - for none): then MN103StockCallArgs
#   gives the variadic functions (level, fmt on the stack, ...) signatures and every indirect call in LIST an
#   override with all four argument registers, so virtual calls keep `this` and logger calls keep fmt + values.
#   STOCK_SIGS=/path/stock-sigs.csv (from csrc/tools/stock_sigs.py): last, set each function's return register
#   (d0 or a0, by what stock callers read) and add the stack params its code reads (MN103ApplyStockSigs).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
G=${1:?usage: export_headless.sh GHIDRA_DIR PROJECT_DIR LIST OUT.ghidra.c [TIMEOUT_S]}
P=${2:?project dir}
L=$(cd "$(dirname "${3:?list}")" && pwd)/$(basename "$3")
O=$(cd "$(dirname "${4:?out}")" && pwd)/$(basename "$4")
T=${5:-60}
run {  # run one script on the existing program, no re-import, no auto-analysis
  "$G/support/analyzeHeadless" "$P" em5iii -process -noanalysis -scriptPath "$HERE/MN103/ghidra_scripts" "$@"
}
for i in 1 2 3; do
  run -postScript MN103RecoverSwitches.java "@$L" 2>&1 | tee "$O.switches$i.log" | grep 'MN103RecoverSwitches:' || true
  grep -q ' 0 new' "$O.switches$i.log" && break
done
run -postScript MN103FixCallFrames.java > "$O.frames.log" 2>&1
run -postScript MN103InferParams.java -keep -timeout "$T" "@$L" > "$O.infer.log" 2>&1
if [ -n "$STOCK_PARAMS" ]; then
  run -postScript MN103ApplyStockParams.java "$STOCK_PARAMS" > "$O.stockparams.log" 2>&1
  grep 'MN103ApplyStockParams:' "$O.stockparams.log" | tail -1
fi
if [ -n "$CALL_ARGS" ]; then
  run -postScript MN103StockCallArgs.java "$CALL_ARGS" "@$L" > "$O.callargs.log" 2>&1
  grep 'MN103StockCallArgs:' "$O.callargs.log" | tail -1
fi
if [ -n "$STOCK_SIGS" ]; then
  run -postScript MN103ApplyStockSigs.java "$STOCK_SIGS" > "$O.stocksigs.log" 2>&1
  grep 'MN103ApplyStockSigs:' "$O.stocksigs.log" | tail -1
fi
run -postScript MN103Decompile.java "$O" -timeout "$T" "@$L" > "$O.decompile.log" 2>&1
echo "functions written: $(grep -c '^// ===== ' "$O")  of $(grep -c . "$L") listed  -> $O"
