#!/bin/bash
# matrix.sh OUTROOT "cfg1" "cfg2" ...   cfg = "lang theme WxH tsize mode"
OUT=$1; shift
for cfg in "$@"; do
  set -- $cfg
  name=$(echo "$cfg" | tr ' ' '_')
  (FH=600 /home/claude/mw/scratch/v502/run.sh $OUT/$name $cfg shots > $OUT/$name.log 2>&1) &
  while [ $(jobs -r | wc -l) -ge 3 ]; do sleep 2; done
done
wait
