#!/bin/bash
# usage: run_shot.sh out.png seconds args...
OUT=$1; SECS=$2; shift 2
MINIWIRESHARK_DATA=${DATA:-/tmp/claude-0/mwdata1} MINIWIRESHARK_CONFIG=${DATA:-/tmp/claude-0/mwdata1}/cfg.json python3.12 /home/claude/mw/miniwireshark.py "$@" > /tmp/claude-0/run.log 2>&1 &
PID=$!
sleep $SECS
import -window root $OUT
kill $PID 2>/dev/null; sleep 0.5; kill -9 $PID 2>/dev/null
