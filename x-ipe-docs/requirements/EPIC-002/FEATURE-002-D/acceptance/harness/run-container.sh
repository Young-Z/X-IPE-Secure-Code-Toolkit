#!/bin/sh
# usage: run-container.sh OUT_PREFIX [FAT_ONLY]
set -u
W=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
S=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-002d
A=x-ipe-docs/requirements/EPIC-002/FEATURE-002-D
REGIP=$(docker inspect -f '{{(index .NetworkSettings.Networks "fat2d-int").IPAddress}}' fat2d-reg)
docker volume rm -f fat2d-work >/dev/null 2>&1; docker volume create fat2d-work >/dev/null
rm -rf $S/handoff; mkdir -p $S/handoff
cd $W
docker run --rm --name fat2d-run --network fat2d-int \
  --add-host mirror.gcr.io:$REGIP --add-host ghcr.io:$REGIP --add-host pkg-containers.githubusercontent.com:$REGIP \
  -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/toolkit -e FAT_DOCS=/fatdocs -e UV_OFFLINE=1 -e FAT_WORK=/work/w -e TMPDIR=/root/fat-tmp \
  -e PYTHONDONTWRITEBYTECODE=1 -e TRIVY=/tv/ARM64/trivy -e SAMPLES=/samples -e IMAGES=/img -e REGLOG=/reglog \
  -e CA=/certs/ca.pem -e HANDOFF=/handoff -e FIXTURES=/fixtures -e REGIP=$REGIP -e FAT_ONLY="${2:-}" \
  -v fat2d-uv-cache:/root/.cache/uv -v $W/ai-secure-code-toolkit:/toolkit:ro -v $W/$A/acceptance:/fat:ro \
  -v $W/$A:/fatdocs:ro -v fat2d-bin:/tv:ro -v fat2d-img:/img:ro -v fat2d-work:/work \
  -v $W/study-case/secure-coding-guidance/playground:/samples:ro -v fat2d-reglog:/reglog \
  -v $S/certs/ca.pem:/certs/ca.pem:ro -v $S/handoff:/handoff -v $W/$A/tool-validation/fixtures:/fixtures:ro \
  fat-uv-git:py312 sh -c 'mkdir -p /root/fat-tmp && python3 /fat/blackbox.py container' > "$1.jsonl" 2> "$1.stderr"
echo "exit=$?"
