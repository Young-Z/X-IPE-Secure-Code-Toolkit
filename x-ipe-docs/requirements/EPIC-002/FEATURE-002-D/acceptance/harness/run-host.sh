#!/bin/sh
# usage: run-host.sh OUT_PREFIX   (macOS host, never-authorized User; needs $S/handoff from a container run)
W=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
S=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-002d
rm -rf $S/work-host $S/tmp-host; mkdir -p $S/work-host $S/tmp-host
cd $W/x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance
TMPDIR=$S/tmp-host FAT_WORK=$S/work-host HANDOFF=$S/handoff UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit \
  PYTHONDONTWRITEBYTECODE=1 python3 blackbox.py host > "$1.jsonl" 2> "$1.stderr"
echo "exit=$?"
