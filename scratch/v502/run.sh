#!/bin/bash
# run.sh OUT LANG THEME WxH TSIZE MODE [shots]
S=$4
timeout 1200 xvfb-run -a -s "-screen 0 ${S}x24" python3.12 /home/claude/mw/scratch/v502/crawl.py "$@" 2>&1 | tail -3
