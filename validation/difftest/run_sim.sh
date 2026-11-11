#!/bin/sh
# iterate: build, run in sim; on an illegal instruction, exclude that test's shape and retry
D=$1; PER=${2:-20}
B=~/work/mn103
R=~/src/simbuild/sim/mn10300/run
touch $D/exclude.txt
for it in $(seq 1 60); do
  python3 gen_tests.py ~/work/fuzz_od.tsv ~/work/fuzz.bin $D $PER 2>/dev/null
  $B/bin/mn10300-elf-as $D/tests.s -o $D/tests.o || exit 1
  if $R --architecture am33-2 --memory-region 0x100000,0x3f00000 $D/tests.o > $D/sim.out 2>$D/sim.err; then echo "ok after $it"; exit 0; fi
  pc=$($R --architecture am33-2 --memory-region 0x100000,0x3f00000 --trace-insn $D/tests.o 2>&1 >/dev/null | grep '^insn' | tail -1 | awk '{print $3}')
  sh=$(python3 find_fail.py $D $pc)
  echo "exclude: $sh   ($(cat $D/sim.err | head -1))"
  echo "$sh" >> $D/exclude.txt
done
