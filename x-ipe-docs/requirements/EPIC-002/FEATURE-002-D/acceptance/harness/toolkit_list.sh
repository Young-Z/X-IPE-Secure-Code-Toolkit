#!/bin/sh
# usage: toolkit_list.sh OUTFILE  -> writes sorted "sha  path" list; prints count and sha256 of the list
cd /Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2/ai-secure-code-toolkit || exit 1
find . -type f \( -path '*/.venv/*' -o -path '*/__pycache__/*' -o -path '*/.pytest_cache/*' -o -path '*/.ruff_cache/*' -o -name '.coverage' -o -name '.coverage.*' \) -prune -o -type f -print \
 | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done > "$1"
echo "files=$(wc -l < "$1" | tr -d ' ') list_sha256=$(shasum -a 256 "$1" | cut -d' ' -f1)"
