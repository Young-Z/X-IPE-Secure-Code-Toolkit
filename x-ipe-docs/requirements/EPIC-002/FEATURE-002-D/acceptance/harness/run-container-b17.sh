#!/bin/sh
# B17 run (2026-10-24): same container command as run-container.sh, but against the FROZEN toolkit copy
# (git archive of f18423e) and the rebuilt b17-* volumes/network; offline (--internal network b17-int whose
# only peer is the loopback registry b17-reg).
# usage: run-container-b17.sh OUT_PREFIX [FAT_ONLY]
set -u
W=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2
EV=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-002d-b17
TK=$EV/frozen/ai-secure-code-toolkit
A=x-ipe-docs/requirements/EPIC-002/FEATURE-002-D
REGIP=$(docker inspect -f '{{(index .NetworkSettings.Networks "b17-int").IPAddress}}' b17-reg)
docker volume rm -f b17-work >/dev/null 2>&1; docker volume create b17-work >/dev/null
rm -rf $EV/handoff; mkdir -p $EV/handoff
cd $W
docker run --rm --name b17-run --network b17-int \
  --add-host mirror.gcr.io:$REGIP --add-host ghcr.io:$REGIP --add-host pkg-containers.githubusercontent.com:$REGIP \
  -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/toolkit -e FAT_DOCS=/fatdocs -e UV_OFFLINE=1 -e FAT_WORK=/work/w -e TMPDIR=/root/fat-tmp \
  -e PYTHONDONTWRITEBYTECODE=1 -e TRIVY=/tv/ARM64/trivy -e SAMPLES=/samples -e IMAGES=/img -e REGLOG=/reglog \
  -e CA=/certs/ca.pem -e HANDOFF=/handoff -e FIXTURES=/fixtures -e REGIP=$REGIP -e FAT_ONLY="${2:-}" \
  -v b17-uv-cache:/root/.cache/uv -v $TK:/toolkit:ro -v $W/$A/acceptance:/fat:ro \
  -v $W/$A:/fatdocs:ro -v b17-bin:/tv:ro -v b17-img:/img:ro -v b17-work:/work \
  -v $W/study-case/secure-coding-guidance/playground:/samples:ro -v b17-reglog:/reglog \
  -v $EV/certs/ca.pem:/certs/ca.pem:ro -v $EV/handoff:/handoff -v $W/$A/tool-validation/fixtures:/fixtures:ro \
  fat-uv-git:py312 sh -c 'mkdir -p /root/fat-tmp && python3 /fat/blackbox.py container' > "$1.jsonl" 2> "$1.stderr"
echo "exit=$?"
