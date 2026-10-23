#!/bin/sh
# usage: run-regressions.sh OUTDIR  -> unchanged 002-B, 002-C, 002-A, 003-A runners, container (offline) + host
W=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
S=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-002d
O=$1; mkdir -p $O
R=$W/x-ipe-docs/requirements
P=$W/study-case/secure-coding-guidance/playground
cd $W
for f in 002B:EPIC-002/FEATURE-002-B:fat-uv-git:py312 002C:EPIC-002/FEATURE-002-C:fat-uv-git:py312 002A:EPIC-002/FEATURE-002-A:ghcr.io/astral-sh/uv:python3.12-bookworm-slim 003A:EPIC-003/FEATURE-003-A:fat-uv-git:py312; do
  id=${f%%:*}; rest=${f#*:}; dir=${rest%%:*}; img=${rest#*:}
  docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/toolkit -e UV_OFFLINE=1 -e FAT_WORK=/root/fat-work \
    -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 -e OPENGREP=/og/opengrep \
    -v fat2d-uv-cache:/root/.cache/uv -v $W/ai-secure-code-toolkit:/toolkit:ro -v $R/$dir/acceptance:/fat:ro \
    -v og-validate:/og:ro -v $P/shanghai-marathon-registration:/samples/m:ro -v $P/test-projects/WebGoat:/samples/w:ro \
    $img sh -c 'mkdir -p /root/fat-tmp /root/fat-work && python3 /fat/blackbox.py container' \
    > $O/regression-$id-container-linux.jsonl 2> $O/regression-$id-container-linux.stderr
  echo "$id container exit=$?"
  rm -rf $S/tmp-r-$id $S/work-r-$id; mkdir -p $S/tmp-r-$id $S/work-r-$id
  (cd $R/$dir/acceptance && TMPDIR=$S/tmp-r-$id FAT_WORK=$S/work-r-$id UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit \
    PYTHONDONTWRITEBYTECODE=1 python3 blackbox.py host > $O/regression-$id-host-macos.jsonl 2> $O/regression-$id-host-macos.stderr)
  echo "$id host exit=$?"
done
