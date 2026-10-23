#!/bin/sh
# Container only: reconstruct the pre-001-F revision from the read-only toolkit (/toolkit) and the
# hash-verified originals of the files FEATURE-001-F changed (/orig, captured before TASK-069 Stage B).
set -eu
mkdir -p /root/fat-tmp /root/fat-work /root/pre001f
tar -C /toolkit --exclude=.venv --exclude=__pycache__ -cf - . | tar -C /root/pre001f -xf -
FW=/root/pre001f/x-ipe-secure-code-toolkit-framework
S=$FW/scripts/src/x_ipe_secure_code
rm "$S/knowledge/catalog.py" "$S/knowledge/presets.py" "$S/knowledge/tags.py" "$S/policy/preset_scope.py" \
   "$FW/references/presets-and-tags.md"
cp /orig/impact.py /orig/exit.py "$S/knowledge/"
cp /orig/cli.py "$S/"
cp /orig/SKILL.md "$FW/"
cp /orig/cli-contract.md /orig/policy-selection.md "$FW/references/"
cd "$FW"
cat > /root/pre001f-expected.txt <<'HASHES'
9d1dd81fee1e7bf1c9e04cafff53bdb3fb09f19e02d35a0e269c7f9753ae51ef  scripts/src/x_ipe_secure_code/knowledge/impact.py
384a98531dd9fa72004e7e3987e288a924c02f66df7a3eaf3f214887a1198d64  scripts/src/x_ipe_secure_code/knowledge/exit.py
f0f6ca23994d1183df8bd73413f2c25830d55958ffe026240ad7adad14cf09df  scripts/src/x_ipe_secure_code/cli.py
5a444baacf695529788bafc92e4bf1220829035e8923b63d679d44c59e5f81ec  SKILL.md
54ad66dcfb3be3b277b28598403b3aeb92f846360f555a8a7ac069e887fd7e68  references/cli-contract.md
5a015418cb4c424dd17747ed7459c0bb4557fae67bb11509e560ef3211262c81  references/policy-selection.md
HASHES
sha256sum -c /root/pre001f-expected.txt >&2
for f in knowledge/catalog.py knowledge/presets.py knowledge/tags.py policy/preset_scope.py; do
  test ! -e "scripts/src/x_ipe_secure_code/$f" || { echo "unexpected $f" >&2; exit 1; }
done
echo "pre-001-F reconstruction ready: $(find . -type f | wc -l) files" >&2
uvx --from "$FW/scripts" secure-code --version >&2
