#!/bin/sh
# Full raw-output capture for Adapter fixtures (TASK-029). Runs offline in the validation container.
set -u
OG=/og/opengrep; R=/v/rules; OUT=/out; S=/samples
export HOME=/tmp/h; mkdir -p $HOME
cap() { name=$1; shift; start=$(date +%s.%N); "$OG" "$@" > "$OUT/$name.json" 2> "$OUT/$name.stderr"; ec=$?; end=$(date +%s.%N); echo "{\"case\":\"$name\",\"exit\":$ec,\"seconds\":$(echo "$end - $start" | bc 2>/dev/null || echo 0),\"argv\":\"$*\"}" >> "$OUT/cases.jsonl"; }
cap m-default scan --json --disable-version-check --config $R/python-sql-string-build.yaml $S/m
cap m-verbose scan --json --verbose --disable-version-check --config $R/python-sql-string-build.yaml $S/m
cap m-verbose-include-ignored scan --json --verbose --disable-version-check --x-ignore-semgrepignore-files --config $R/python-sql-string-build.yaml $S/m
cap w-verbose-two-files scan --json --verbose --disable-version-check --config $R/java-sql-string-concat.yaml --config $R/python-sql-string-build.yaml $S/w/src/main/java/org/owasp/webgoat/lessons/jwt
cap mixed-generic scan --json --verbose --disable-version-check --config /v/fixture-rules/generic-secret.yaml $S/m
cap skipped-rule scan --json --verbose --disable-version-check --config /v/fixture-rules/bad-language.yaml $S/m
cap error-plus-results scan --json --verbose --disable-version-check --config $R/python-sql-string-build.yaml /v/fixture-src
cap file-target scan --json --verbose --disable-version-check --config $R/python-sql-string-build.yaml $S/m/registration.py $S/m/public
