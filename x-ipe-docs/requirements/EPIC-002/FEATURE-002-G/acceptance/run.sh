#!/bin/sh
# FEATURE-002-G acceptance (TASK-091): black-box runs of `secure-code guard compare`.
#   sh run.sh container | host | fat (both) | regressions
# Container: fat-uv-git:py312, --network none, UV_OFFLINE=1, disposable HOME (auth init happens only here),
# the toolkit copied to a fresh path inside the container so uvx builds the current source, uv cache volume
# fat-uv-cache-002g (seeded offline from fat-uv-cache-003b; removed by the worker afterwards), real Opengrep
# 1.31.0 from the og-validate volume (read-only). The container hands the seed projects to $SESSION/fat-002g/handoff.
# Host: macOS, never-authorized User, copies of the handed-off seeds only.
set -u
WS=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
ACC=$WS/x-ipe-docs/requirements/EPIC-002/FEATURE-002-G/acceptance
GA=$WS/x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/acceptance
SESSION=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files
F=$SESSION/fat-002g
ORIG=$SESSION/impl-002g/orig/ai-secure-code-toolkit/x-ipe-secure-code-toolkit-guard/SKILL.md
VOL=fat-uv-cache-002g
IMG=fat-uv-git:py312
cd "$WS" || exit 1

container () {
  rm -rf "$F/handoff"; mkdir -p "$F/handoff"
  docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/root/tk/ai-secure-code-toolkit -e UV_OFFLINE=1 \
    -e FAT_GA=/ga -e OPENGREP=/og/opengrep -e HANDOFF=/handoff -e ORIG_SKILL=/orig/SKILL.md \
    -e FAT_WORK=/root/fat-work -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 -e FAT_ONLY="${FAT_ONLY:-}" \
    -v $VOL:/root/.cache/uv -v "$WS/ai-secure-code-toolkit":/toolkit-src:ro -v "$ACC":/fat:ro -v "$GA":/ga:ro \
    -v og-validate:/og:ro -v "$F/handoff":/handoff -v "$ORIG":/orig/SKILL.md:ro \
    $IMG sh -c 'mkdir -p /root/tk /root/fat-work /root/fat-tmp && cp -a /toolkit-src /root/tk/ai-secure-code-toolkit \
      && python3 /fat/blackbox.py container' > "$ACC/evidence-container-linux.jsonl" 2> "$ACC/evidence-container-linux.stderr"
  echo "container exit=$?"
}
host () {
  rm -rf "$F/work-host" "$F/tmp-host"; mkdir -p "$F/work-host" "$F/tmp-host"
  (cd "$ACC" && env TMPDIR="$F/tmp-host" FAT_WORK="$F/work-host" HANDOFF="$F/handoff" ORIG_SKILL="$ORIG" UV_OFFLINE=1 \
     UV_REFRESH_PACKAGE=ai-secure-code-toolkit PYTHONDONTWRITEBYTECODE=1 python3 blackbox.py host) \
     > "$ACC/evidence-host-macos.jsonl" 2> "$ACC/evidence-host-macos.stderr"
  echo "host exit=$?"
}
# Regressions: the unchanged runners of 002-A, 002-B, 002-C, 002-D (host part only: its container part needs the
# real Trivy binary and the loopback OCI registry volumes, which no longer exist), 003-A and 003-B, run in place.
# The toolkit is copied inside each container to a fresh path (/root/fresh-002g/...) from a read-only mount, so
# uvx builds the current source (the seeded cache holds stale pre-002-G builds for the path /toolkit - a first
# attempt with /toolkit ran stale code and was discarded); a build check line (`guard compare --help` exit code,
# which only the current source accepts, and the cached cli.py digests) is written to each container stderr file.
R=$WS/x-ipe-docs/requirements
P=$WS/study-case/secure-coding-guidance/playground
regc () { # $1 tag  $2 runner folder  $3 image  $4 extra docker args  $5 extra env args
  docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/root/fresh-002g/ai-secure-code-toolkit -e UV_OFFLINE=1 \
    -e FAT_WORK=/root/fat-work -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 $5 \
    -v $VOL:/root/.cache/uv -v "$WS/ai-secure-code-toolkit":/toolkit-src:ro -v "$R/$2":/fat:ro $4 \
    $3 sh -c 'mkdir -p /root/fat-tmp /root/fat-work /root/fresh-002g && cp -a /toolkit-src /root/fresh-002g/ai-secure-code-toolkit \
      && uvx --from /root/fresh-002g/ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts secure-code guard compare --help >/dev/null 2>&1; \
      echo "build-check: guard compare --help exit=$?" >&2; \
      find /root/.cache/uv -path "*site-packages/x_ipe_secure_code/cli.py" -exec sha256sum {} + | sort -u -k1,1 >&2; \
      python3 /fat/blackbox.py container' > "$ACC/regression-$1-container-linux.jsonl" 2> "$F/regression-$1-container-linux.stderr"
  echo "$1 container exit=$?"
}
regh () { # $1 tag  $2 runner folder  $3 extra env
  rm -rf "$F/tmp-r-$1" "$F/work-r-$1"; mkdir -p "$F/tmp-r-$1" "$F/work-r-$1"
  (cd "$R/$2" && env TMPDIR="$F/tmp-r-$1" FAT_WORK="$F/work-r-$1" UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit \
     PYTHONDONTWRITEBYTECODE=1 $3 python3 blackbox.py host) > "$ACC/regression-$1-host-macos.jsonl" 2> "$F/regression-$1-host-macos.stderr"
  echo "$1 host exit=$?"
}
OGS="-v og-validate:/og:ro -v $P/shanghai-marathon-registration:/samples/m:ro -v $P/test-projects/WebGoat:/samples/w:ro"
OLD=$SESSION/fat-003b/pre003b-pkg
regcontainers () {
  regc 002A EPIC-002/FEATURE-002-A/acceptance ghcr.io/astral-sh/uv:python3.12-bookworm-slim "" ""
  regc 002B EPIC-002/FEATURE-002-B/acceptance $IMG "$OGS" "-e OPENGREP=/og/opengrep"
  regc 002C EPIC-002/FEATURE-002-C/acceptance $IMG "$OGS" "-e OPENGREP=/og/opengrep"
  regc 003A EPIC-003/FEATURE-003-A/acceptance $IMG "-v $P/shanghai-marathon-registration:/samples/m:ro" ""
  regc 003B EPIC-003/FEATURE-003-B/acceptance $IMG "--tmpfs /root/tiny:rw,size=16m -v $OLD:/oldpkg:ro" \
    "-e FAT_OLD_PKG=/oldpkg/x_ipe_secure_code -e FAT_TINY=/root/tiny"
}
regressions () {
  regc 002A EPIC-002/FEATURE-002-A/acceptance ghcr.io/astral-sh/uv:python3.12-bookworm-slim "" ""
  regh 002A EPIC-002/FEATURE-002-A/acceptance ""
  regc 002B EPIC-002/FEATURE-002-B/acceptance $IMG "$OGS" "-e OPENGREP=/og/opengrep"
  regh 002B EPIC-002/FEATURE-002-B/acceptance ""
  regc 002C EPIC-002/FEATURE-002-C/acceptance $IMG "$OGS" "-e OPENGREP=/og/opengrep"
  regh 002C EPIC-002/FEATURE-002-C/acceptance ""
  regh 002D EPIC-002/FEATURE-002-D/acceptance "HANDOFF=$F/no-002d-handoff"
  regc 003A EPIC-003/FEATURE-003-A/acceptance $IMG "-v $P/shanghai-marathon-registration:/samples/m:ro" ""
  regh 003A EPIC-003/FEATURE-003-A/acceptance ""
  regc 003B EPIC-003/FEATURE-003-B/acceptance $IMG "--tmpfs /root/tiny:rw,size=16m -v $OLD:/oldpkg:ro" \
    "-e FAT_OLD_PKG=/oldpkg/x_ipe_secure_code -e FAT_TINY=/root/tiny"
  regh 003B EPIC-003/FEATURE-003-B/acceptance "FAT_OLD_PKG=$OLD/x_ipe_secure_code"
}
case "${1:-fat}" in
  container) container ;; host) host ;; regressions) regressions ;; regcontainers) regcontainers ;;
  fat) container; host ;;
esac
