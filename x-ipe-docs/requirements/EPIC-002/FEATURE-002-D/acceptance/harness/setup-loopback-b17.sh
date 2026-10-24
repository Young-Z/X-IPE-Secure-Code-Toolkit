#!/bin/sh
# B17 run (2026-10-24): loopback registry for the offline black-box run. The OCI artifacts in b17-oci were rebuilt
# (registry.py build) from the components the adapter itself provisioned live in TC-L-01 (copied to b17-comp;
# no new download). Disposable test CA in $EV/certs (3-day validity; deleted after the run).
# usage: setup-loopback-b17.sh
set -u
EV=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files/fat-002d-b17
H=/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2/x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance/harness
docker network create --internal b17-int >/dev/null
docker volume create b17-reglog >/dev/null
docker run -d --name b17-reg --network b17-int -v b17-oci:/oci:ro -v b17-reglog:/reglog \
  -v $EV/certs/leaf.pem:/certs/leaf.pem:ro -v $EV/certs/leaf.key:/certs/leaf.key:ro -v $H/registry.py:/r.py:ro \
  python:3.12-slim python3 /r.py serve >/dev/null
sleep 2
docker logs b17-reg
