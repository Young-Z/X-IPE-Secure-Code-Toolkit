#!/bin/sh
# FEATURE-002-F acceptance (TASK-111): black-box runs against the FROZEN toolkit copy (git archive of toolkit
# commit 73fe2dc), never the live ai-secure-code-toolkit/ tree.
#   sh run.sh volume | container | host | delivered | regressions | seed002g | cleanup
# container: fat-uv-git:py312, --network none, UV_OFFLINE=1, disposable HOME (`auth init` only there), fresh copy
#   of the frozen tree at /root/toolkit, uv cache volume fat-uv-cache-002f (a fresh copy of fat-uv-cache-003b; the
#   seed volume is mounted read-only for the copy only and never mutated; removed afterwards). Writes the seed
#   project (knowledge + scope) to $EV/handoff.
# host (macOS): copies of the seed; never-authorized User/agent CLI; real Docker Desktop runtime with LOCAL images
#   only (python:3.12-slim), every toolkit docker call through the logging wrapper; Maintainer steps that need the
#   real runtime only through maint.py with a disposable trust store under $EV (never `auth init` on the host).
set -u
WS=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
ACC=$WS/x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance
EV=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-002f
FROZEN=$EV/frozen/ai-secure-code-toolkit
FW=$FROZEN/x-ipe-secure-code-toolkit-framework
VOL=fat-uv-cache-002f
IMG=fat-uv-git:py312
PY=/opt/homebrew/bin/python3
cd "$WS" || exit 1

volume () {
  docker volume create $VOL >/dev/null
  docker run --rm --network none -v fat-uv-cache-003b:/src:ro -v $VOL:/dst $IMG sh -c 'cp -a /src/. /dst/' \
    && echo "volume $VOL seeded from fat-uv-cache-003b (read-only)"
}
container () {
  rm -rf "$EV/handoff"; mkdir -p "$EV/handoff"
  docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/root/toolkit -e UV_OFFLINE=1 \
    -e FAT_WORK=/root/fat-work -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 -e HANDOFF=/handoff \
    -v $VOL:/root/.cache/uv -v "$FROZEN":/frozen:ro -v "$ACC":/fat:ro -v "$EV/handoff":/handoff \
    $IMG sh -c 'mkdir -p /root/fat-work /root/fat-tmp && cp -a /frozen /root/toolkit \
      && find /root/toolkit \( -name .venv -o -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache \) -prune -exec rm -rf {} + \
      && uvx --from /root/toolkit/x-ipe-secure-code-toolkit-framework/scripts secure-code --version >&2 \
      && python3 --version >&2 && python3 /fat/blackbox.py container' \
    > "$ACC/evidence-container-linux.jsonl" 2> "$ACC/evidence-container-linux.stderr"
  echo "evidence-container-linux exit=$?"
}
host () {
  chmod -R u+w "$EV/work-host" 2>/dev/null; rm -rf "$EV/work-host" "$EV/tmp-host"; mkdir -p "$EV/work-host" "$EV/tmp-host"
  (cd "$ACC" && env TMPDIR="$EV/tmp-host" FAT_WORK="$EV/work-host" HANDOFF="$EV/handoff" UV_OFFLINE=1 \
     UV_REFRESH_PACKAGE=ai-secure-code-toolkit PYTHONDONTWRITEBYTECODE=1 TOOLKIT_ROOT="$FROZEN" \
     $PY blackbox.py host) > "$ACC/evidence-host-macos.jsonl" 2> "$ACC/evidence-host-macos.stderr"
  echo "evidence-host-macos exit=$?"
  cp "$EV/work-host/docker-calls.jsonl" "$EV/evidence-host-docker-calls.full.jsonl" 2>/dev/null
  # repository copy: argv/rc/fault per call; inspect stdout replaced by its SHA-256 (full log kept under $EV)
  $PY -c 'import hashlib, json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    e = json.loads(line)
    if "stdout" in e:
        e["stdout_sha256"] = hashlib.sha256(e.pop("stdout").encode()).hexdigest()
    print(json.dumps(e, ensure_ascii=False))' "$EV/work-host/docker-calls.jsonl" > "$ACC/evidence-host-docker-calls.jsonl"
}
delivered () { # the delivered helper tests at the frozen revision: default (fake runtime) + opt-in real runtime
  mkdir -p "$EV/tmp-del" "$EV/tmpdir-del"
  (cd "$FW/scripts" && env PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 TMPDIR="$EV/tmpdir-del" uv run --offline python -m pytest \
     -p no:cacheprovider -q -o addopts="" -rs --basetemp="$EV/tmp-del/default" tests/helpers) > "$ACC/evidence-delivered-helpers-default.log" 2>&1
  echo "delivered default exit=$?"
  (cd "$FW/scripts" && env PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 TMPDIR="$EV/tmpdir-del" SECURE_CODE_HELPER_REAL=1 uv run --offline \
     python -m pytest -p no:cacheprovider -q -o addopts="" -rs -s --basetemp="$EV/tmp-del/real" tests/helpers/test_helper_conformance_real.py) \
     > "$ACC/evidence-delivered-helpers-real.log" 2>&1
  echo "delivered real exit=$?"
}
R=$WS/x-ipe-docs/requirements
regh () { # $1 tag  $2 runner folder  $3 extra env
  chmod -R u+w "$EV/tmp-r-$1" "$EV/work-r-$1" 2>/dev/null; rm -rf "$EV/tmp-r-$1" "$EV/work-r-$1"; mkdir -p "$EV/tmp-r-$1" "$EV/work-r-$1"
  (cd "$R/$2" && env TMPDIR="$EV/tmp-r-$1" FAT_WORK="$EV/work-r-$1" UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit \
     PYTHONDONTWRITEBYTECODE=1 TOOLKIT_ROOT="$FROZEN" $3 $PY blackbox.py host) \
     > "$ACC/regression-$1-host-macos.jsonl" 2> "$ACC/regression-$1-host-macos.stderr"
  echo "regression-$1-host-macos exit=$?"
}
regressions () {
  regh 001A EPIC-001/FEATURE-001-A/acceptance ""
  regh 001B EPIC-001/FEATURE-001-B/acceptance ""
  regh 001C EPIC-001/FEATURE-001-C/acceptance ""
  regh 001D EPIC-001/FEATURE-001-D/acceptance ""
  regh 001F EPIC-001/FEATURE-001-F/acceptance "DESIGN_FILE=$R/EPIC-001/FEATURE-001-F/technical-design.md"
  regh 001G EPIC-001/FEATURE-001-G/acceptance "DESIGN_FILE=$R/EPIC-001/FEATURE-001-G/technical-design.md BASELINE_SHA256=$EV/../impl-084/baseline-step0.sha256 STEP0_DIR=$EV/../impl-084"
  regh 002A EPIC-002/FEATURE-002-A/acceptance ""
  regh 002B EPIC-002/FEATURE-002-B/acceptance ""
  regh 002C EPIC-002/FEATURE-002-C/acceptance ""
  regh 002D EPIC-002/FEATURE-002-D/acceptance "HANDOFF=$EV/no-002d-handoff"
  : # 002-G host regression needs its container-made seeds: see seed002g
  regh 003A EPIC-003/FEATURE-003-A/acceptance ""
  regh 003B EPIC-003/FEATURE-003-B/acceptance "FAT_OLD_PKG=$EV/../fat-003b/pre003b-pkg/x_ipe_secure_code"
}
seed002g () { # the unchanged 002-G runner in container mode against the frozen copy: its container cases (as a
  # regression) and the seed projects its host mode needs (written to $EV/002g-handoff); 002-G evidence untouched
  GACC=$R/EPIC-002/FEATURE-002-G/acceptance
  ORIG=$EV/../impl-002g/orig/ai-secure-code-toolkit/x-ipe-secure-code-toolkit-guard/SKILL.md
  chmod -R u+w "$EV/002g-handoff" 2>/dev/null; rm -rf "$EV/002g-handoff"; mkdir -p "$EV/002g-handoff"
  docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/root/tk/ai-secure-code-toolkit -e UV_OFFLINE=1 \
    -e FAT_GA=/ga -e OPENGREP=/og/opengrep -e HANDOFF=/handoff -e ORIG_SKILL=/orig/SKILL.md \
    -e FAT_WORK=/root/fat-work -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 \
    -v $VOL:/root/.cache/uv -v "$FROZEN":/toolkit-src:ro -v "$GACC":/fat:ro -v "$R/EPIC-002/FEATURE-002-A/acceptance":/ga:ro \
    -v og-validate:/og:ro -v "$EV/002g-handoff":/handoff -v "$ORIG":/orig/SKILL.md:ro \
    $IMG sh -c 'mkdir -p /root/tk /root/fat-work /root/fat-tmp && cp -a /toolkit-src /root/tk/ai-secure-code-toolkit \
      && find /root/tk \( -name .venv -o -name __pycache__ -o -name .pytest_cache \) -prune -exec rm -rf {} + \
      && python3 /fat/blackbox.py container' > "$ACC/regression-002G-container-linux.jsonl" \
    2> "$ACC/regression-002G-container-linux.stderr"
  echo "regression-002G-container-linux exit=$?"
  regh 002G EPIC-002/FEATURE-002-G/acceptance "HANDOFF=$EV/002g-handoff ORIG_SKILL=$ORIG"
}
cleanup () {
  docker volume rm $VOL >/dev/null && echo "volume $VOL removed"
}
case "${1:-}" in
  volume) volume ;; container) container ;; host) host ;; delivered) delivered ;; regressions) regressions ;;
  cleanup) cleanup ;; seed002g) seed002g ;;
  *) echo "usage: sh run.sh volume|container|host|delivered|regressions|seed002g|cleanup" ;;
esac
