#!/bin/sh
# B17 run (2026-10-24): as run-host.sh, but against the FROZEN toolkit copy (TOOLKIT_ROOT); macOS host,
# never-authorized User; needs $EV/handoff from run-container-b17.sh.
# usage: run-host-b17.sh OUT_PREFIX
W=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
EV=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-002d-b17
rm -rf $EV/work-host $EV/tmp-host; mkdir -p $EV/work-host $EV/tmp-host
cd $W/x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance
TOOLKIT_ROOT=$EV/frozen/ai-secure-code-toolkit TMPDIR=$EV/tmp-host FAT_WORK=$EV/work-host HANDOFF=$EV/handoff \
  UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit PYTHONDONTWRITEBYTECODE=1 \
  python3 blackbox.py host > "$1.jsonl" 2> "$1.stderr"
echo "exit=$?"
