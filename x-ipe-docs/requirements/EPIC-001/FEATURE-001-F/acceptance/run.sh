#!/bin/sh
# FEATURE-001-F acceptance (TASK-070): black-box runs plus the DAO-009 (3) re-run obligations.
#   sh run.sh fat | rerun001d | regressions | all
# Container runs: fat-uv-git:py312, --network none, UV_OFFLINE=1, read-only source mounts, disposable HOME,
# uv cache volume fat-uv-cache-001f-fat (built offline from the current source; removed afterwards by the worker).
set -u
WS=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
ACC=$WS/x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance
SESSION=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files
ORIG=$SESSION/impl-001f/orig
F=$SESSION/fat-001f
VOL=fat-uv-cache-001f-fat
IMG=fat-uv-git:py312
SAMPLE=$WS/study-case/secure-coding-guidance/playground/shanghai-marathon-registration
cd "$WS" || exit 1

container () { # $1 output stem  $2 runner folder  $3 extra docker args  $4 command
  docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/toolkit -e UV_OFFLINE=1 \
    -e FAT_WORK=/root/fat-work -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 \
    -v $VOL:/root/.cache/uv -v "$WS/ai-secure-code-toolkit":/toolkit:ro -v "$2":/fat:ro $3 \
    $IMG sh -c "$4" > "$ACC/$1.jsonl" 2> "$ACC/$1.stderr"
  echo "$1 exit=$?"
}
host () { # $1 output stem  $2 runner folder  $3 extra env
  mkdir -p "$F/tmp-$1" "$F/work-$1"
  (cd "$2" && env TMPDIR="$F/tmp-$1" FAT_WORK="$F/work-$1" UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit \
     PYTHONDONTWRITEBYTECODE=1 $3 python3 blackbox.py host) > "$ACC/$1.jsonl" 2> "$ACC/$1.stderr"
  echo "$1 exit=$?"
}
fat () {
  container evidence-container-linux "$ACC" "-v $ORIG:/orig:ro -e PRE001F_SCRIPTS=/root/pre001f/x-ipe-secure-code-toolkit-framework/scripts" \
    'sh /fat/prepare_pre001f.sh && mkdir -p /root/fat-work /root/fat-tmp && python3 /fat/blackbox.py container'
  host evidence-host-macos "$ACC" "DESIGN_FILE=$WS/x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/technical-design.md"
}
rerun001d () {
  D=$WS/x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/acceptance
  container rerun-001D-container-linux "$D" "" 'mkdir -p /root/fat-tmp /root/fat-work && python3 /fat/blackbox.py container'
  host rerun-001D-host-macos "$D" ""
}
regressions () {
  for pair in 001B:EPIC-001/FEATURE-001-B 001C:EPIC-001/FEATURE-001-C 002A:EPIC-002/FEATURE-002-A 003A:EPIC-003/FEATURE-003-A; do
    tag=${pair%%:*}; dir=$WS/x-ipe-docs/requirements/${pair#*:}/acceptance
    extra=""; [ "$tag" = 003A ] && extra="-v $SAMPLE:/samples/m:ro"
    container regression-$tag-container-linux "$dir" "$extra" 'mkdir -p /root/fat-tmp /root/fat-work && python3 /fat/blackbox.py container'
    host regression-$tag-host-macos "$dir" ""
  done
}
case "${1:-all}" in
  fat) fat ;; rerun001d) rerun001d ;; regressions) regressions ;;
  all) fat; rerun001d; regressions ;;
esac
