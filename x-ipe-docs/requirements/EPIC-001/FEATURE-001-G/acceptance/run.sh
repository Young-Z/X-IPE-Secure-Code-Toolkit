#!/bin/sh
# FEATURE-001-G acceptance (TASK-103): black-box runs against the FROZEN toolkit copy (git archive of toolkit
# commit 93e3eaa), never the live ai-secure-code-toolkit/ tree.
#   sh run.sh fat | regressions | all
# Container: fat-uv-git:py312, --network none, UV_OFFLINE=1, read-only mounts (frozen copy, step-0 originals, runner),
# disposable HOME (`auth init` only there), fresh copies at /root/toolkit and /root/pre001g (prepare.sh), uv cache
# volume fat-uv-cache-001g-fat (a fresh copy of fat-uv-cache-003b; the seed volume is mounted read-only for the copy
# only and never mutated; the copy is removed afterwards by the worker).
# Host (macOS): never-authorized User paths and structured text checks only; no `auth init`, no trust writes;
# disposable projects/temp under the session evidence folder.
set -u
WS=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
ACC=$WS/x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/acceptance
EV=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-001g
FROZEN=$EV/frozen/ai-secure-code-toolkit
ORIG=$EV/../impl-084
VOL=fat-uv-cache-001g-fat
IMG=fat-uv-git:py312
cd "$WS" || exit 1

fat () {
  docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/root/toolkit -e UV_OFFLINE=1 \
    -e FAT_WORK=/root/fat-work -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 \
    -e PRE001G_SCRIPTS=/root/pre001g/x-ipe-secure-code-toolkit-framework/scripts \
    -e BASELINE_SHA256=/orig/baseline-step0.sha256 \
    -v $VOL:/root/.cache/uv -v "$FROZEN":/frozen:ro -v "$ORIG":/orig:ro -v "$ACC":/fat:ro \
    $IMG sh -c 'sh /fat/prepare.sh && python3 /fat/blackbox.py container' \
    > "$ACC/evidence-container-linux.jsonl" 2> "$ACC/evidence-container-linux.stderr"
  echo "evidence-container-linux exit=$?"
  mkdir -p "$EV/tmp-host" "$EV/work-host"
  (cd "$ACC" && env TMPDIR="$EV/tmp-host" FAT_WORK="$EV/work-host" UV_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1 \
     TOOLKIT_ROOT="$FROZEN" BASELINE_SHA256="$ORIG/baseline-step0.sha256" STEP0_DIR="$ORIG" \
     DESIGN_FILE="$WS/x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/technical-design.md" \
     python3 blackbox.py host) > "$ACC/evidence-host-macos.jsonl" 2> "$ACC/evidence-host-macos.stderr"
  echo "evidence-host-macos exit=$?"
}

regressions () { # delivered features' own acceptance runners, host mode, against the frozen copy
  for pair in 001A:FEATURE-001-A 001B:FEATURE-001-B 001C:FEATURE-001-C 001D:FEATURE-001-D 001F:FEATURE-001-F; do
    tag=${pair%%:*}; dir=$WS/x-ipe-docs/requirements/EPIC-001/${pair#*:}
    extra=""; [ "$tag" = 001F ] && extra="DESIGN_FILE=$dir/technical-design.md"
    mkdir -p "$EV/tmp-reg-$tag" "$EV/work-reg-$tag"
    (cd "$dir/acceptance" && env TMPDIR="$EV/tmp-reg-$tag" FAT_WORK="$EV/work-reg-$tag" UV_OFFLINE=1 \
       PYTHONDONTWRITEBYTECODE=1 TOOLKIT_ROOT="$FROZEN" $extra python3 blackbox.py host) \
      > "$ACC/regression-$tag-host-macos.jsonl" 2> "$ACC/regression-$tag-host-macos.stderr"
    echo "regression-$tag-host-macos exit=$?"
  done
}

case "${1:-all}" in
  fat) fat ;; regressions) regressions ;;
  all) fat; regressions ;;
esac
