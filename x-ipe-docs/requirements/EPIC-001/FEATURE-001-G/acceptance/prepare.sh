#!/bin/sh
# Container preparation for the FEATURE-001-G acceptance runs (TASK-103); stdout is reserved for JSONL, logs go to stderr.
# /frozen: frozen toolkit copy (git archive of toolkit commit 93e3eaa), read-only. /orig: TASK-084 step-0 originals and
# the step-0 per-file SHA-256 list (pre-001-G baseline), read-only. Copies are made at fresh container paths.
set -eu
FW=x-ipe-secure-code-toolkit-framework
cp -a /frozen /root/toolkit
cp -a /frozen /root/pre001g
# host-side caches of the frozen copy (.venv from the diagnostic suite run, caches) are not part of the tree
find /root/toolkit /root/pre001g \( -name .venv -o -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache \) -prune -exec rm -rf {} +
cd /root/pre001g
rm -f $FW/scripts/src/x_ipe_secure_code/knowledge/drafting_*.py $FW/references/knowledge-drafting.md
rm -rf $FW/scripts/tests/drafting
cp /orig/cli.py.step0 $FW/scripts/src/x_ipe_secure_code/cli.py
cp /orig/SKILL.md.step0 $FW/SKILL.md
cp /orig/cli-contract.md.step0 $FW/references/cli-contract.md
cp /orig/carhelp.py.step0 $FW/scripts/tests/carriers/carhelp.py
sha256sum -c --quiet /orig/baseline-step0.sha256 >&2
echo "pre-001-G reconstruction: $(find . -type f | wc -l) files, all baseline-step0.sha256 entries verified" >&2
mkdir -p /root/fat-work /root/fat-tmp
cd /root
for tree in toolkit pre001g; do
  S=/root/$tree/$FW/scripts
  uvx --from $S secure-code --version >&2
  pkg=$(uvx --from $S python -c "import os, x_ipe_secure_code as m; print(os.path.dirname(m.__file__))")
  if diff -r -x __pycache__ "$S/src/x_ipe_secure_code" "$pkg" >/dev/null; then
    echo "installed package for $tree equals its source ($pkg)" >&2
  else
    echo "INSTALLED PACKAGE DIFFERS for $tree" >&2; exit 3
  fi
done
python3 --version >&2; uv --version >&2
