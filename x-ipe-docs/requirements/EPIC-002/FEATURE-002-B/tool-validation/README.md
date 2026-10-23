# Opengrep Tool-Level Validation (S-07) — FEATURE-002-B

> Task: TASK-027 (Feature Refinement) · Date: 2026-10-19 · Authorized by the user (download into a disposable container only)
> Scope: small tool-level feasibility check before the full Adapter (AC-002B-03). It is **not** the formal evaluation (AC-28, FEATURE-003-C) and makes no detection-quality claim.

## Setup

| Item | Value |
| --- | --- |
| Tool | Opengrep **v1.31.0** (GitHub release published 2026-10-15), asset `opengrep_manylinux_aarch64` |
| Binary SHA-256 | `2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d` (47,910,328 bytes) |
| Signature / authenticity | `.sig`/`.cert` (cosign) downloaded but **not verified** (no cosign available). Authenticity: the binary's SHA-256 equals the `digest` published for `opengrep_manylinux_aarch64` in the official v1.31.0 release metadata (GitHub API, checked 10-19-2026) |
| Environment | Docker `python:3.12-slim` on macOS arm64 host (Linux aarch64); binary in a disposable volume; scans run with `--network none`; samples mounted read-only |
| Rules | Self-authored local rules only (user decision: local rules, no download): [python-sql-string-build](rules/python-sql-string-build.yaml) (CWE-89), [java-sql-string-concat + java-runtime-exec](rules/java-sql-string-concat.yaml) (CWE-89, CWE-78); [invalid rule](rules-invalid.yaml) for the error case |
| Driver | [validate.py](validate.py); raw results [results-linux-aarch64.jsonl](results-linux-aarch64.jsonl) |
| Samples | `study-case/secure-coding-guidance/playground/shanghai-marathon-registration` (5 `.py`), `…/test-projects/WebGoat/src` (411 `.java` in the repo) |

## Observed Results

| Case | Exit | Time / CPU / max RSS | Observation |
| --- | --- | --- | --- |
| `--version` | 0 | — | prints `1.31.0`; JSON output also carries `version` |
| marathon + Python rule | 0 | 1.05 s / 0.99 s / 268 MB | 2 files scanned, 0 findings; `tests/` skipped by default ignore patterns |
| WebGoat `src` + Java rules | 0 | 1.35 s / 1.29 s / 268 MB | 319 files scanned, 2 findings (CWE-78 `VulnerableTaskHolder.java:67`, CWE-89 `JWTHeaderKIDEndpoint.java:73`) |
| missing rules path | **7** | 0.75 s | JSON `errors`: "unable to find a config"; no results |
| invalid rule file | **7** | 0.87 s | JSON `errors`: `InvalidRuleSchemaError` |
| missing target | **2** | 0.81 s | JSON `errors`: "File not found" |
| no `--config` | 2 | **24.7 s** | tries `https://semgrep.dev/c/auto` → network failure (offline) |
| registry config `p/default` | 2 | 24.7 s | tries `https://semgrep.dev/p/default` → network failure |
| `--timeout 1` (per-rule/file) | 0 | 1.32 s | same results; flag accepted |
| `--metrics=off` (first attempt) | 2 | 0.5 s | **unknown option** in Opengrep (removed vs. Semgrep) — usage error, no JSON |
| `--x-ignore-semgrepignore-files` | 0 | — | marathon: all 5 files scanned incl. `tests/` |
| `--verbose` | 0 | — | JSON `paths.skipped` lists skipped paths with reasons (`semgrepignore_patterns_match`); without it only `paths.scanned` |
| side effects | — | — | samples byte-identical; tool creates `$HOME/.opengrep/semgrep.log` and `$HOME/.cache/opengrep/v1.31.0` (relocatable via `HOME`) |

JSON result shape (v1.31.0): top-level `results`, `errors`, `paths` (`scanned`, `skipped` with `--verbose`), `skipped_rules`, `version`, `interfile_languages_used`. Each result: `check_id` (prefixed with the rule folder path, e.g. `v.rules.java-runtime-exec`), `path`, `start`/`end` (`line`, `col`), `extra` (`severity` ERROR/WARNING/INFO, `message`, `metadata` incl. rule-defined `cwe`, `fingerprint`, **`lines` = the matched source text**, `engine_kind` `OSS`, `validation_state`).

## Known Issues and Consequences for the Adapter

1. A missing `--config` or a non-path config makes Opengrep contact `semgrep.dev` (rule registry/auto) — the Adapter must accept only local rule files/folders and refuse anything else (no network, A-09, E-01).
2. Default ignore patterns silently skip folders such as `tests/`; only `--verbose` reports them. The Adapter must report skipped paths so a check is never `met` on files that were not scanned.
3. Exit 0 covers both "findings" and "no findings"; configuration errors exit 7 and target errors exit 2 with JSON `errors`. A clean exit with zero findings is not a pass (FR-002A-6), and any `errors` entry means the run is not complete.
4. `extra.lines` copies source text into the output → mask before storing (AC-002A-01d).
5. The tool writes logs and caches to `$HOME`; the Adapter should point `HOME` at a private run folder so nothing lands in the user's home or the project.
6. `check_id` depends on the rule folder location; the Adapter must normalize it to the rule id plus the rule file.
7. Semgrep-only options (`--metrics`) are rejected; parameters must be validated against the verified version, not copied from Semgrep documentation.
8. macOS host binary and Windows binary not exercised (container only); signature verification not performed.

## Full Raw-Output Capture (TASK-029, before implementation)

Driver [capture.sh](capture.sh); complete stdout JSON and stderr per case in [fixtures/](fixtures/) (offline, same container and binary). Fixture inputs: [fixture-rules/](fixture-rules/) and [fixture-src/](fixture-src/) (a vulnerable file and a file with a syntax error).

| Case | Observation |
| --- | --- |
| `m-default` vs `m-verbose` | Same 2 scanned files; only `--verbose` adds `paths.skipped` = `[{"path": ".../tests", "reason": "semgrepignore_patterns_match"}]` (a **directory** entry) |
| `m-verbose-include-ignored` | `--x-ignore-semgrepignore-files` scans all 5 `.py` files; `skipped` empty |
| files of other languages (`.json`, `.html`, `.js`, `.db` in marathon with Python rules) | **Neither scanned nor skipped**, even with `--verbose` — the tool gives no per-file statement for them |
| `mixed-generic` (`languages: [generic]`) | Every file is scanned, including binaries (`.pyc`, `.db`, `.jpg`) |
| `w-verbose-two-files` (Java + Python rule files, one Java folder) | Rules and targets are applied as a cross-product; `check_id` = rule-folder path (dotted) + rule id |
| `error-plus-results` (`broken.py` has a syntax error) | `broken.py` listed as **scanned**; `errors` empty; stderr "Partially analyzed … <none>" — parse failures are not reported |
| `skipped-rule` (taint rule with `interfile: true`) | `skipped_rules` empty; the rule is listed as loaded; no indication whether it could run fully |
| `file-target` (explicit file + folder of non-Python files) | Only the Python file appears in `scanned` |

Additional known issues: (9) per-file coverage can only be proven for files the tool lists as scanned or skipped; (10) syntax errors are invisible in the output; (11) rule capability limits of the open-source engine are not reported.

## Official Release Digests (v1.31.0, from release metadata)

| Asset | SHA-256 | Executed here |
| --- | --- | --- |
| opengrep_manylinux_aarch64 | `2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d` | yes (digest matched) |
| opengrep_manylinux_x86 | `dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147` | no |
| opengrep_musllinux_aarch64 | `b7cbedab0b6c9953ea27ce3baa006ad8b6fa1c50ee7433638b63f7fc731519d9` | no |
| opengrep_musllinux_x86 | `02c9fba481611aa0664bc79ccf7ce59e9e334b76af8921c80b2f738d17fabf9b` | no |
| opengrep_osx_arm64 | `035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb` | no |
| opengrep_osx_x86 | `2f0d0c7a41a3e48dc02c30dabc4851bc37c18f021b46c9ae54b15177ece088ee` | no |
| opengrep_windows_x86.exe | `fdd2e22549e7000ceb66976a01366db6910760b2aa4e457b6bda62545070d26a` | no |
