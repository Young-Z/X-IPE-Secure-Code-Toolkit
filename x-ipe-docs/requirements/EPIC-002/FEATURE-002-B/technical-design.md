# Technical Design: Adapter Contract & Opengrep Adapter

> Feature ID: FEATURE-002-B | Version: v1.0 | Last Updated: 2026-10-19
> Specification: [specification.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/specification.md) · Tool validation: [tool-validation/README.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/tool-validation/README.md) · Task: TASK-029 · Depends on: [FEATURE-002-A design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/technical-design.md), [FEATURE-001-A design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md)

## Version History

| Version | Date | Description |
|---------|------|-------------|
| v1.0 | 10-19-2026 | Initial design |

---

## Part 1: Agent-Facing Summary

### Scope & Boundaries

- **Feature:** FEATURE-002-B — `secure-code tools register` (Maintainer), `secure-code guard tool` (run an Adapter inside a Guard verification), `status` tools section; additive extensions of the FEATURE-002-A plan/record/finding/evidence/report; Guard SKILL.md method-choice and tool-run instructions.
- **program_type:** `cli` + `library` (new `adapters/` package, `guard/toolrun.py`) + `skills`.
- **tech_stack:** Python ≥ 3.11 stdlib (`subprocess`, `hashlib`, `os` descriptor APIs, `platform`, `signal`, `shutil`) + **PyYAML ≥ 6** (restricted safe loader, new dependency); pytest, ruff. Opengrep v1.31.0 binary is external.
- **Non-goals:** Trivy/Strix, shared budget/cancel/egress (002-C), OS isolation, Adapter execution on Windows (refused this version — user decision), runtime rule generation, bundled/registry rules, custom binaries, cosign, SARIF, formal evaluation (AC-28).
- **Threat model:** protects against unknown/swapped binaries, rule-registry access, accidental writes to the original project, fabricated tool evidence by the agent and secret leakage into stored output. A local attacker able to write the user's private toolkit folders at the same time is out of scope (as in FEATURE-001-A).

### Outcome / Goal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 | Spec G-02; FR-16, FR-18, AC-24 | Developer, upstream agent | Trustworthy executable evidence; no false pass | One Opengrep process per rule of each check, strict per-file accounting from tool-reported paths only, provenance-backed per-check evidence and findings, reserved Adapter namespace | Scenario: WebGoat CWE-89 rule → findings needing review; a skipped `tests/` or unreported file → failed method | Tool never decides the verdict | AC-002B-02*, 03*, 04a…04c | not measured |
| G-04 | Spec G-04 | Developer, Maintainer | Low cost, requirement kept | Plan `method_choice`, tool runs only for selected/activated methods, `method_changes` with context snapshot, report section | Scenario: unselected tool run refused; supplement recorded with reason and prior results | No all-tools default | AC-002B-04d…04f | not measured |
| G-05 (enabling) | Spec G-05 | Owner, Maintainer | Only the authentic tool runs; originals never handed to it | Official-digest table (trust root in code), descriptor-based snapshots, single commit after cleanup and integrity re-check | Scenario: modified binary refused unexecuted; originals byte-identical; no leftovers | No OS isolation | AC-002B-01*, 03a, 03b, 03i, 03k | not measured |

### Design Options and Tradeoffs

| Means | Selection | Rationale |
| --- | --- | --- |
| Official-digest table in code is the trust root; registration only records which file was chosen | selected (user decision) | Record tampering cannot add a binary; nothing executed before a match |
| Snapshot the binary into private staging via descriptor I/O, hash while copying, execute the snapshot | selected | Checked bytes = executed bytes within the threat model |
| **One Opengrep process per rule** (a single-rule staged file, the check's targets), sharing the request's total time limit | selected (review fixes) | Opengrep applies rules × targets as a cross-product and reports no per-rule execution (observed); a process per rule makes each rule's `paths.scanned` and results provable (cost ≈ 1 s per rule, ≤ 20 rules per check) |
| Strict accounting: an object file is covered only if the tool lists it as scanned or under a skipped entry; everything else is `unaccounted` → failed method | selected (review fix) | Observed: other-language files are neither scanned nor skipped; a guessed extension table could mark unanalysed files as covered |
| Extension table for "not targeted" files | rejected | Guesswork; false success possible |
| Bidirectional target binding: scan targets ⊆ object paths and object ⊆ targets | selected (review fix) | No scope widening; evidence paths always lie on the object (002-A `_met`) |
| Stage the owning target(s) fully (hash-while-copy) and require staged digest = open-time digest | selected | Only per-target digests exist at open; one read per file binds hash and copy |
| Hold the guard lock for the whole tool run (≤ 1800 s); single final state commit after cleanup and integrity re-check | selected (review fix) | No crash window with `ok` evidence before postconditions; no running-state recovery |
| Parse JSON, mask every string recursively, drop `extra.lines`, store the sanitized JSON | selected (review fix) | Text masking of serialized JSON misses escaped strings |
| Reserved Adapter namespace: names case-insensitive; ids prefixed `<adapter>-` for evidence/findings reserved for the Adapter; `next_adapter_run` counter | selected (review fix) | No collisions or fabricated provenance |
| `guard tool` only for methods in `method_choice.selected` or activated by `method_changes` | selected (review fix) | Execution bound to the recorded choice |
| Windows: refuse Adapter execution | selected (user decision) | Process-tree kill needs an untestable Job Object path |
| PyYAML restricted safe loader (no aliases, no duplicate keys, depth/node/rule limits) | selected | Rule ids/languages needed; no code execution; bounded parsing |

### Key Components Implemented

All under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/`.

| Component | Responsibility | Scope/Impact | Tags |
|-----------|----------------|--------------|------|
| `adapters/__init__.py` | Contract (`AdapterSpec`: name, id prefix, max time limit), `ADAPTERS` registry, `reserved_name()`; `adapters_registry.py` re-exports | status, guard, tools | #contract |
| `adapters/digests.py` | Official-digest table (`ToolBuild`: tool, version, os, arch, libc, asset, validated) + `host_platform()` | registration, pre-check, status | #trust |
| `adapters/safe_io.py` | Descriptor-based no-follow open, regular-file check, hash-while-copy, tree walk with `dir_fd` (POSIX) | staging, registration | #security |
| `adapters/registry_store.py` | Registration records, table/platform/libc checks, binary snapshot | tools register, pre-check, status | #trust |
| `adapters/process.py` | Run without shell: minimal env, disposable dirs, stdout spooled with cap, time limit, process-group kill (POSIX) | runs | #execution |
| `adapters/rules.py` | Restricted YAML loader; rule ids/languages; duplicate and suffix-collision checks | runs | #validation |
| `adapters/opengrep.py` | argv for v1.31.0, JSON parse, sanitize (mask + drop `extra.lines`), normalize results, per-check accounting | runs | #core |
| `guard/toolrun.py` | `guard tool`: validation, pre-check, staging, per-check processes, accounting, sanitized output + manifest, single commit | Guard | #core |
| `guard/targets.py` (extended) | `stage()` using `safe_io` with the same digest lines as `snapshot()` | toolrun | #integrity |
| `guard/records.py`, `engine.py`, `report.py` (extended) | `method_choice`, `method_changes`, reserved namespace, provenance pass-through, report sections | 002-A | #validation #output |
| `tools_service.py`, `status.py`, `cli.py` (extended) | `tools register`, tools status, CLI wiring | CLI | #cli |
| Guard `SKILL.md`, `references/guard-records.md`, `cli-contract.md`, `README.md` | Agent procedure and formats | Agent | #skills |

### Dependencies

| Dependency | Source | Design Link | Usage |
|---|---|---|---|
| Run state, plan/record validation, engine `_met`, masking, `Checker`, evidence quota, `runs`, guard lock, report | FEATURE-002-A | [design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/technical-design.md) | Adapter runs live inside verifications |
| `require_maintainer`, `Result`, `atomic_write_bytes`, `ProcessLock`, `status.collect` | FEATURE-001-A | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md) | Gate, envelope, writes, status |
| PyYAML ≥ 6 | PyPI | — | Restricted `SafeLoader` |
| Opengrep v1.31.0 | external | [tool validation](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/tool-validation/README.md) | Executed only as a digest-matched snapshot |

### Major Flow

1. **Register (Maintainer):** `tools register --tool opengrep --path P` → authorization → no-follow open, regular file → SHA-256 → table entry for this host's os/arch/libc → record. Never executed.
2. **Plan (agent):** check with method `opengrep` (runtime) and `method_choice` naming it in `selected` (or later `method_changes`).
3. **Run (`guard tool`, under the guard lock):** sweep stale staging → validate request → pre-check (platform, record, binary snapshot digest) → stage owning targets and rule files (descriptor I/O, digests bound to open-time digests) → parse rules (capability allowlist) → quota check for the manifest bound → for each rule of each check: one Opengrep process on the check's staged targets, sharing the time budget → per-check accounting and normalization → sanitize output → write manifest + sanitized output files → remove staging, verify removal, re-hash originals → **one** atomic state commit (evidence, findings, run entry) → Result.
4. **Judge:** agent records ledger states; Reviewer for verdict-affecting findings; conclude (FEATURE-002-A).

### Usage Example

```bash
FW=.github/skills/x-ipe-secure-code-toolkit-framework
uvx --from $FW/scripts secure-code tools register --project . --tool opengrep --path /usr/local/bin/opengrep   # Maintainer
uvx --from $FW/scripts secure-code status --project . --json
uvx --from $FW/scripts secure-code guard tool --project . --run gv-… --request .x-ipe/private/secure-code/tmp/tool-1.json --json
```

### Tool Capability Summary

`stages.implement.technical_design`: consultation only. Matched: `x-ipe-tool-implementation-python`. Not matched: html5, typescript, java, mcp, general.

---

## Part 2: Implementation Guide

### Files and Layout

```text
.x-ipe/private/secure-code/tools/opengrep.json                       # machine-local registration (0600)
.x-ipe/private/secure-code/guard/<vid>/adapter/stage-<16 hex>/       # staging per attempt (removed after the run; stale ones swept)
    bin/opengrep  src/<owning target trees>  rules/<k>-<basename>  home/ work/ tmp/ out/
.x-ipe/private/secure-code/guard/<vid>/evidence/opengrep-<n>-output.json     # sanitized tool JSON per run (all checks)
.x-ipe/private/secure-code/guard/<vid>/evidence/opengrep-<n>-manifest.json   # full per-check accounting manifest
scripts/src/x_ipe_secure_code/adapters/{__init__,digests,safe_io,registry_store,process,rules,opengrep}.py
scripts/src/x_ipe_secure_code/guard/toolrun.py
scripts/src/x_ipe_secure_code/tools_service.py
scripts/tests/adapters/test_adapters_units.py
scripts/tests/adapters/fake_opengrep.py          # test double driven by env/argv: replays captured fixtures, errors, sleeps+child, floods stdout, writes files
scripts/tests/guard/test_guard_tool.py
```

Sizes: opengrep ~280, toolrun ~380, others < 200 lines; `guard/service.py` unchanged in size.

### Official-Digest Table and Host Platform (`adapters/digests.py`)

Seven entries for v1.31.0 from the release metadata (tool-validation README): manylinux (glibc) / musllinux (musl) × aarch64/x86, macOS arm64/x86, windows x86 — `validated=True` only for manylinux aarch64. `host_platform()`: `os` from `sys.platform` (`linux`/`macos`/`windows`), `arch` from `platform.machine()` normalized (`aarch64`/`arm64` → `aarch64`; `x86_64`/`AMD64` → `x86`), `libc` on Linux from `platform.libc_ver()` (`glibc` → `glibc`, else `musl`), `None` elsewhere. A table entry matches the host only if os, arch and libc (Linux) are equal.

### Safe I/O (`adapters/safe_io.py`)

- `open_nofollow(root_fd | path, rel)`: POSIX walks components with `os.open(part, O_RDONLY | O_NOFOLLOW | O_DIRECTORY, dir_fd=fd)` and the last with `O_NOFOLLOW`; `os.fstat` must show a regular file (or directory where expected). Symlink or other type → `UnsafePath`.
- `copy_hash(src_fd, dest_path, limit)`: reads 1 MiB chunks from the **same descriptor**, writes to `dest` opened `O_CREAT | O_EXCL | O_WRONLY` (0600/0700), returns digest and size; aborts above `limit`. Every chunk is written completely (loop until all bytes are written; a zero-byte write is an error), so the copied bytes are exactly the hashed bytes.
- `walk(root_fd)`: `os.scandir(fd)` + `dir_fd` recursion; yields `(rel, kind)` with `kind ∈ file|dir|link|special`; same exclusions as `targets._tree` (`.git`, `.x-ipe/private/`, `x-ipe-docs/secure-code/`).
- Windows (registration/status only): `lstat` + `st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT` refusal, then open and compare `fstat` identity with `lstat` (narrowed race; execution is refused on Windows anyway).

### Registration (`tools register`)

| Step | Refusal |
|---|---|
| `knowledge_root` | root/init errors |
| `--tool` ∈ `ADAPTERS` | `TOOL_UNKNOWN` |
| `require_maintainer("tools.register")` | `NOT_AUTHORIZED` + next step |
| absolute path; `open_nofollow`; regular file | `TOOL_PATH_INVALID` |
| streamed SHA-256 ∈ table for the tool | `TOOL_DIGEST_UNKNOWN` ("not an official release of a verified version; nothing was executed") |
| entry matches `host_platform()` (os, arch, libc) | `TOOL_PLATFORM_MISMATCH` |
| atomic write (0600) `{tool, path, digest, version, asset, platform: {os, arch, libc}, host: {…}, platform_validated, registered_at}` | `IO_ERROR` |

### Pre-check (`registry_store.precheck`)

Returns a `Gap(code, reason, next_step)` or the `ToolBuild` plus the staged binary path:
1. Host is not Windows (`ADAPTER_PLATFORM_UNSUPPORTED`, "Adapter execution not supported on Windows in this version").
2. Adapter provided; record exists/parses (`TOOL_NOT_REGISTERED`, `TOOL_RECORD_INVALID`).
3. Record digest in table and table entry matches the host (`TOOL_PLATFORM_MISMATCH`).
4. `open_nofollow(record.path)` → `copy_hash` into `stage/bin/opengrep` (0700) → digest equal to record (`TOOL_DIGEST_MISMATCH`).

### Run Request (`guard tool --request FILE`, schema `ai-secure-code-toolkit/guard-tool/v1`)

```json
{"schema": "ai-secure-code-toolkit/guard-tool/v1", "adapter": "opengrep",
 "include_ignored": false, "time_limit_seconds": 300,
 "checks": [{"check": "C1", "rules": ["x-ipe-docs/secure-code/tool-rules/opengrep/python-sql.yaml"],
             "targets": ["src/login.py", "src/db.py"]}]}
```

Validation (refusal `TOOL_REQUEST_INVALID` unless noted; nothing staged or executed on refusal):
- 002-A `load_request` bounds and unknown-key refusal; `adapter` ∈ `ADAPTERS`; `include_ignored` bool; `time_limit_seconds` int 1…1800.
- Verification open, no result, plan present (`RUN_FINISHED`, `PLAN_REQUIRED`).
- `checks` 1…50, unique; each planned with a method whose name equals the adapter (case-insensitive) and kind `runtime` (`METHOD_NOT_PLANNED`); the method is in `method_choice.selected` or was activated by a recorded `method_changes` entry (`METHOD_NOT_SELECTED`).
- `rules` 1…20 per check; each `normalize`d (incl. credential-shaped refusal), extension `.yaml|.yml|.json`, ≤ 1 MiB; a rule file used by two checks → `RULE_FILE_SHARED`.
- `targets` 1…1000 per check; **every target equals or lies inside one of the check's object paths, and every object path equals or lies inside one of the targets** (`TARGETS_MISMATCH`); each target's owning verification target exists and is not deleted.

### Staging and Binding

- Stale sweep: at the start of every `guard tool` (under the lock) remove any `adapter/stage-*` folders of this verification and any `evidence/<adapter>-*` file not referenced by the run state (left by an uncommitted attempt); if anything cannot be removed the request is refused `STAGING_LEFTOVER` (nothing executed).
- New attempt folder `adapter/stage-<secrets.token_hex(8)>` (exclusive `mkdir`, 0700).
- For each owning target of the request: `targets.stage()` walks via `safe_io` and copies regular files with `copy_hash`, building the same digest lines as `snapshot()` (links/special entries hashed by their link text/marker, not copied); staged digest ≠ open-time digest → every requested check under that target gets `TARGET_CHANGED` failed evidence and no process; limits `MAX_STAGE_BYTES = 512 MiB`, `MAX_STAGE_FILES = 50 000` → `STAGE_TOO_LARGE` gap for the run.
- Rule files: `open_nofollow` + `copy_hash` into `rules/<k>-<basename>`; digests recorded; parsed from the staged bytes.

### Rule Parsing (`adapters/rules.py`)

`RestrictedLoader(yaml.SafeLoader)`: aliases/anchors refused, duplicate mapping keys refused, depth ≤ 32, nodes ≤ 100 000, ≤ 500 rules per file. Document must be a mapping with `rules: [ {id, languages, …} ]`; `id` matches `NAME`; `languages` non-empty list of strings. Capability allowlist (validated search mode only): rule keys ⊆ {`id`, `languages`, `severity`, `message`, `metadata`, `pattern`, `patterns`, `pattern-either`, `pattern-regex`, `pattern-not`, `pattern-not-regex`, `pattern-inside`, `pattern-not-inside`, `metavariable-regex`, `metavariable-pattern`, `metavariable-comparison`, `focus-metavariable`}, `mode` absent or `search`, no `options`, no `paths`/`min-version`/`max-version` (a rule must apply to every staged file of its languages); anything else (e.g. `mode: taint`, `options.interfile`, `join`, `extract`) → `RULE_FEATURE_UNSUPPORTED` (observed: the tool gives no signal whether such rules ran fully). Failures → `RULE_FILE_INVALID` (whole request refused). Within one check: duplicate ids → `RULE_ID_DUPLICATE`; any id equal to a dotted suffix of another (`a.foo` vs `foo`) → `RULE_ID_AMBIGUOUS`. Across checks duplicates are allowed (separate processes).

### Execution (`adapters/process.run`, POSIX only)

```python
run(argv, cwd, env, deadline, stdout_path, stdout_cap) -> ProcessOutcome(exit, timed_out, oversized, stderr_tail, seconds)
```
- `Popen(argv, shell=False, cwd=stage/work, env=minimal, stdin=DEVNULL, stdout=<file stage/out/<check>.json>, stderr=PIPE, start_new_session=True)`; a reader thread keeps the last 4 KiB of stderr; the parent polls every 0.1 s: stdout file size > `stdout_cap` (64 MiB) → oversized; `time.monotonic() > deadline` → timed out; either → `os.killpg(pgid, SIGKILL)`, wait; finally `killpg` again to reap stragglers of the group.
- Minimal env: `TMPDIR` → stage subfolder; `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` → a private disposable home (`tempfile.mkdtemp`, 0700, unpredictable name) in the system temporary folder, outside the project, removed with the stage after the run (a leftover counts as "staging not removed"); `PATH=os.defpath`; `LANG=C.UTF-8`. Nothing else inherited. Reason (observed, TASK-032): Opengrep v1.31.0 unpacks its runtime into `$XDG_CACHE_HOME/opengrep/` and exits 0 with no output when that path has non-ASCII characters, so a home inside a project such as `proj ü` never runs. If the system temporary folder path is not ASCII the run is refused before execution (`TOOL_HOME_UNSUPPORTED` pre-check gap). A tool that exits 0 with no output gets an explicit gap. Limit: a toolkit process killed mid-run can leave this home (Opengrep's own runtime files only, no project content) in the system temporary folder; the stale-staging sweep covers only the private run folder.
- Opengrep argv (v1.31.0): `[stage/bin/opengrep, "scan", "--json", "--verbose", "--disable-version-check", "--config", <staged rule>…, ("--x-ignore-semgrepignore-files" if include_ignored), <staged target>…]`.
- Each rule of each check is written to its own staged single-rule file (`rules/<check-index>-<rule-index>.yaml`, re-serialized from the rule parsed from the staged rule-file bytes) and run as its own process; before execution the written config is parsed back with the same restricted loader and must equal exactly that one rule (else the rule is not run: `failed`, gap "rule could not be staged faithfully"); the SHA-256 of the exact config bytes is recorded as `config_digest` in the rule's manifest entry and in the run entry, so the recorded rule-file digest and the executed config are bound by rule id; processes run sequentially; the deadline is shared: `start + time_limit_seconds`. Rules not started before the deadline → `timed_out` (not run).

### Normalization, Sanitizing and Accounting (`adapters/opengrep.py`)

Per rule process, aggregated per check:
- **Status:** timed out → `timed_out`; oversized → `failed` ("output too large"); exit 0 + parseable JSON + `errors == []` → `completed`; exit 0 + errors → `completed_with_errors`; else `failed` (exit code, masked stderr tail).
- **Sanitize:** each rule process's parsed JSON → recursive copy where every string passes `mask_text`, `results[].extra.lines` replaced by `"[removed: matched source]"`, staged absolute paths rewritten to project-relative paths; unparseable → masked first 64 KiB marked `incomplete`. Sanitized documents of all rule processes are stored together in `opengrep-<n>-output.json` (`{check: {rule_id: sanitized}}`).
- **Attribution:** a result belongs to the rule of its process; `check_id` must equal the rule id or end with `.` + rule id, else it is kept in the run record as `unattributed` and the check's evidence fails.
- **Findings:** `{"id": "opengrep-<n>-<m>", "rule": <check's Policy>, "check", "location": {"path", "line": start.line}, "cwe": first `CWE-\d+` in metadata.cwe (str|list) or null, "title": rule id, "description": masked message, "source": "opengrep", "severity": ERROR→high | WARNING→medium | INFO→low | else unknown, "evidence": [<check evidence id>], "disputed": false, "related": [], "merged_from": [], "merge_evidence": [], "merged_into": null, "tool": {"adapter", "run": n, "rule_id", "rule_file", "tool_severity", "end_line", "fingerprint" (hex pattern or null)}}`; sorted by path, line, rule id; findings from partial output are kept even when the status is not `completed`.
- **Accounting:** object files = regular files staged under the check's targets (plus link/special entries, always `unaccounted` "not followed"). Per rule: `scanned_R` from its own `paths.scanned`, `skipped_R` from `paths.skipped`. A file is `scanned` if in some `scanned_R`; `skipped` if under a `skipped_R` entry and in no `scanned_R` (reason kept); `unaccounted` = the rest. A rule with empty `scanned_R` → gap "rule applied to no file"; any non-empty `skipped_rules` → gap for that rule. The check's status is the worst rule status.
- **Python parse check (user decision):** every scanned `.py`/`.pyi` file of the check is parsed from its staged bytes with `ast.parse` (no execution; `SyntaxError`/`ValueError`/decode errors → moved from `scanned` to `unaccounted` with reason "syntax error: not analysable"). Other languages: no independent check — the stated limit applies.
- **method_status:** `ok` iff status `completed` ∧ `skipped == ∅` ∧ `unaccounted == ∅` ∧ no skipped rules ∧ no unattributed results; else `failed`, gaps listed (first 20 in the summary, all in the manifest). Gap hint for unaccounted files: "the tool did not analyse these files (other languages or not reported); make the check object list only files the rules apply to, or add another method".
- **Known limit text** in every tool evidence summary whose check has scanned non-Python files: "files with syntax errors in <languages> may be silently unanalysed (tool limit)"; also listed in result `limits` and the report.

### Recording (`guard/toolrun.py`, single commit)

1. Under the guard lock: stale sweep, validate, `n = state.get("next_adapter_run", 1)`, generated ids `opengrep-<n>-…` checked for collisions (`ID_COLLISION`, cannot happen with the reserved prefix but checked).
2. Pre-check / staging gaps → only failed evidence (no process).
3. Run per check; collect outcomes in memory.
4. Before execution: manifest upper bound = Σ over staged object files of (UTF-8 path length + 96 bytes) + 4 KiB per rule (computed from the staged file list; the manifest stores one file table with per-check status indexes, so a file shared by checks is listed once) — the remaining 002-A evidence quota must cover it plus 1 MiB, else the request is refused `EVIDENCE_QUOTA` (nothing executed). Per-process stdout cap 16 MiB. After execution write `opengrep-<n>-manifest.json` (masked full accounting) and `opengrep-<n>-output.json` (sanitized output); **both are required for successful evidence** — if either cannot be written (quota, I/O), every check's evidence is a failed method naming what was not retained and its `stored`/`manifest` is null.
5. Remove the staging folder; verify it is gone (else every check's evidence fails "staging not removed").
6. Re-hash original targets (`targets.observe`), context files and original rule files; any difference → every check's evidence fails "originals changed during the run" and problem `ORIGINALS_CHANGED`.
7. One atomic `state.json` write: evidence items (`opengrep-<n>-<check-index>`: kind `runtime`, method `opengrep`, `method_status`, `checks: [check]`, `paths: requested targets`, `summary`, `stored: evidence/opengrep-<n>-output.json` (null only for failed evidence), `masked`, `masked_types`, `adapter_run: n`), findings, run entry (`n, adapter, version, asset, platform, platform_validated, binary_digest, include_ignored, time_limit, rules [{check, path, digest, ids, config_digests {rule id: sha256 of the executed single-rule config}}], staged_digests, per-check {status, exit, seconds, counts, gaps (≤ 20), method_status}, manifest {path, digest}, unattributed (masked, ≤ 100)}`), `next_adapter_run = n + 1`.
A crash before step 7 leaves no recorded evidence (the next run sweeps the staging); the sanitized files of an uncommitted attempt are overwritten by the next attempt with the same `n`.

### FEATURE-002-A Extensions (additive; 002-A ACs unchanged)

- `validate_plan`: per check optional `method_choice {considered: [method names, ≥1], cost: text, selected: [method names ⊆ methods, ≥1], reason: text}`; **required** when the check has > 1 method or any Adapter-named method (`PLAN_INVALID`). Adapter-named methods (case-insensitive) must be kind `runtime`.
- `apply_record`: refuse evidence whose `method` or finding whose `source` is an Adapter name (case-insensitive), and any evidence/finding id starting with `<adapter>-` (case-insensitive) (`RECORD_INVALID`, "recorded only by secure-code guard tool"). Optional `method_changes: [{check, change: switch|supplement, method: {name, kind}, from?, reason}]` → method added to the check as `required: false` if new, activated for `guard tool`; event stored in `plan["method_changes"]` with a snapshot `{selected_before, evidence_ids, finding_ids, adapter_runs}`; Adapter-named method must be `runtime`.
- `merged_from`/merges of tool findings stay labels (002-A rule); tool findings cannot be redefined (duplicate id refusal).
- Engine: copies `plan.method_changes` and `adapter_runs` into the result; `LIMITS` mentions Adapters and the no-isolation limit. Report: "Method Choices and Changes" after "Check Plan"; "Adapter Runs" after "Evidence"; findings show tool severity/rule id when present. Old states without new keys read as empty.
- FEATURE-002-A design gets a Design Change Log entry referencing this design.

### Status (`status.py`)

`tools.opengrep`: `{"state": "provided", "registered", "version", "asset", "platform_validated", "check": "ok" | gap reason, "execution": "supported" | "not supported on Windows in this version", "next_step"}`; digest check hashes the registered file (no execution). `trivy`/`strix` unchanged.

### CLI Contract (additions)

| Command | Options | Exit |
|---|---|---|
| `tools register` | `--project`, `--tool opengrep`, `--path PATH`, `--json` | 0 / 1 |
| `guard tool` | `--project`, `--run ID`, `--request FILE`, `--json` | 0 run recorded (any per-check outcome, incl. pre-check gaps recorded as failed evidence); 1 refusal (nothing recorded) |

New codes: `RULE_FEATURE_UNSUPPORTED`, `STAGING_LEFTOVER`, `TOOL_UNKNOWN`, `TOOL_PATH_INVALID`, `TOOL_DIGEST_UNKNOWN`, `TOOL_PLATFORM_MISMATCH`, `TOOL_NOT_REGISTERED`, `TOOL_RECORD_INVALID`, `TOOL_DIGEST_MISMATCH`, `ADAPTER_PLATFORM_UNSUPPORTED`, `TOOL_REQUEST_INVALID`, `METHOD_NOT_PLANNED`, `METHOD_NOT_SELECTED`, `RULE_FILE_SHARED`, `RULE_FILE_INVALID`, `RULE_ID_DUPLICATE`, `RULE_ID_AMBIGUOUS`, `TARGETS_MISMATCH`, `STAGE_TOO_LARGE`, `TARGET_CHANGED`, `ORIGINALS_CHANGED`, `ID_COLLISION`.

### Guard SKILL.md (AC-002B-04f)

"Choosing methods": cheapest sufficient method first; never all tools by default; ask the user before a new tool, wider targets, extra permissions or budget; record `method_choice`; record switches/supplements with reasons (`method_changes`). "Running a tool": local rule files only; one rule set per check; scan targets equal the check object; plan tool checks with objects listing files of the rules' languages (other files cannot be proven analysed); read gaps; never record `opengrep` evidence or findings yourself; Windows: tool runs are not supported yet.

### Implementation Steps

1. `pyproject.toml` `pyyaml>=6`; `uv lock`.
2. `digests.py`, `safe_io.py`, `registry_store.py` + unit tests.
3. `tools_service.py`, `cli tools register` + integration tests (patched table, fake binary file never executed).
4. `process.py` + unit tests (timeout kills group incl. child, stdout cap, minimal env).
5. `targets.stage` + unit tests (digest equals `snapshot`, links not copied, change detected, symlink swap refused).
6. `rules.py`, `opengrep.py` + unit tests on captured fixtures (`tool-validation/fixtures/*.json`).
7. 002-A extensions + unit tests.
8. `toolrun.py`, `cli guard tool` + integration tests with `fake_opengrep.py` (in-process table patch).
9. `status.py`; SKILL.md, references, cli-contract, README + skill tests.
10. ruff; full suite macOS 3.14/3.11, Linux 3.12; acceptance with the real binary in the offline container.

### Edge Cases & Error Handling

| Case | Handling |
|---|---|
| Not registered / swapped / missing binary / Windows host | Pre-check gap → failed evidence per check; nothing executed |
| Record edited to another official digest | Platform/libc mismatch or digest mismatch → gap |
| Target changed since open | `TARGET_CHANGED` failed evidence; no process for affected checks |
| Symlink swapped in during staging | `safe_io` refuses → `STAGE_UNSAFE` gap |
| Invalid/aliased/duplicate-key YAML, ambiguous ids | Request refused before staging targets |
| Opengrep config error | `failed`; masked messages |
| Mixed-language folder object | Unreported files → `unaccounted` → failed method with hint |
| Python file with a syntax error | `ast.parse` fails → `unaccounted` → failed method |
| Java (or other) file with a syntax error | Reported scanned by the tool; stated limit in evidence/report (user decision) |
| Taint/interfile/join rule | `RULE_FEATURE_UNSUPPORTED` |
| Oversized output / timeout | Group killed; `failed`/`timed_out` |
| Crash mid-run | Nothing committed; next `guard tool` sweeps staging |
| Lock held during a run | Other Guard commands `LOCKED`; retry |
| Old state without new keys | Treated as empty |

### Security, Tracing and Observability

- Trust root in code; descriptor I/O; executed snapshot = hashed bytes; no shell; fixed argv; staged paths only; minimal env; disposable dirs; group kill; Windows execution refused.
- Not enforced: tool filesystem/network access (no OS isolation) — in `LIMITS`, SKILL.md, report.
- Sanitizing: recursive masking, `extra.lines` removed, paths relativized; identifiers via 002-A pattern refusal.
- Tracing: N/A.

### Goal / Acceptance / Design / Validation Coverage

| AC | Design means | Planned validation |
|---|---|---|
| 01a | Table lookup before execution; record incl. platform/libc and validation state | Integration (patched table; marker proves fake never executed) |
| 01b | `require_maintainer` | Integration |
| 01c | Digest unknown, path invalid, symlink | Integration |
| 01d | Pre-check on snapshot; failed evidence per check | Integration (swap after registration; delete; Windows via patched `host_platform`) |
| 01e | No download path; next steps | Integration + unit (no `urllib`/`http`/`socket` imports in `adapters/`) |
| 01f | Evidence only | Integration |
| 02a | Schema validation | Integration |
| 02b | Rule file rules | Integration (`p/default`, URL, folder, symlink, outside) |
| 02c | Bidirectional binding | Integration (wider target refused; partial coverage refused; context path) |
| 02d | Restricted loader, duplicates/ambiguity, digests | Unit + Integration |
| 02e | Time limit bounds | Integration |
| 03a | Staging, env, cleanup, re-hash | Integration (fake writes into cwd/home/staged copy; originals identical; staging gone) |
| 03b | argv uses staged rules only | Unit |
| 03c | Normalization/attribution/severity | Unit (fixtures) + Integration |
| 03d | Per-check evidence + run entry + manifest | Integration |
| 03e | Strict accounting; per-rule processes (rule with no file → gap); Python parse check; rule capability allowlist | Unit (fixtures: `m-verbose` skipped dir, `file-target` unaccounted, `error-plus-results` broken.py → unaccounted, skipped_rules synthetic, taint rule refused) + Integration |
| 03f | Status mapping, partial findings kept | Unit + Integration (fake exit 7, garbage, errors+results) |
| 03g | Shared deadline, group kill | Unit (fake spawns sleeping child; both gone) + Integration |
| 03h | Clean zero results ok | Integration |
| 03i | Recursive masking, lines removed, no logs retained | Integration (token in matched line, message, error; staging gone) |
| 03j | Engine `_met` with failed tool evidence; auxiliary substitution | Unit (engine) |
| 03k | Stage digest binding | Integration (modify target after open) |
| 04a | Rules per request; no mapping store | Integration |
| 04b | Method planned + selected; one check per rule file | Integration |
| 04c | Reserved namespace; review rules | Integration (agent evidence `opengrep`, id `opengrep-1-1`, source `OpenGrep` refused; unreviewed high → cannot confirm) |
| 04d | `method_choice` | Unit + Integration (missing → refused; unselected tool run refused) |
| 04e | `method_changes` with snapshot; report | Unit + Integration |
| 04f | SKILL.md | Skill-package test |
| 05a, 05b | Validation README + fixtures; table flags | Structured review + unit test (table digests ⊆ README; validated only manylinux aarch64) |
| 06a, 06b | Status tools section | Integration |

### Outcome Scenario and Evidence Gaps

Scenario (G-02): a Developer verifies a WebGoat lesson; Guard plans a CWE-89 check whose object lists the lesson's Java files, chooses semantic review plus Opengrep with a recorded reason, runs the registered official binary on a staged copy; one finding needs Reviewer confirmation. Observed by real users: **not measured**. Limits: macOS binary digests known but not executed; Windows execution refused; tool network/filesystem not OS-enforced; syntax errors invisible to accounting.

### Test Plan

Unit: `tests/adapters/test_adapters_units.py` (digests/host platform, safe_io, registry, process, rules loader, opengrep normalize/sanitize/accounting with captured fixtures), additions to `tests/guard/test_guard_units.py`, `test_guard_engine.py`, `test_guard_report.py`. Integration: `tests/guard/test_guard_tool.py` with `fake_opengrep.py` and in-process table patch. Existing 417 tests must pass. Acceptance: real Opengrep v1.31.0 in the offline container on both MVP samples plus the FEATURE-002-A black-box runner rerun.

### Mockup-to-Component Mapping

N/A — no UI.

### Delta and Evidence Invalidation

New feature. FEATURE-002-A modules change additively; its test suite is the regression gate and its black-box runner is rerun at 002-B acceptance. `adapters_registry.py` becomes a re-export. PyYAML changes `uv.lock` (offline cache re-warmed).

## Implementation Evidence (TASK-030, 2026-10-19)

- Files (all < 800 lines): `adapters/{__init__, digests, safe_io, registry_store, process, rules, opengrep}.py`, `guard/toolrun.py` (≈700), `tools_service.py`; extended `guard/{records (≈650), targets, engine, report}.py`, `status.py`, `cli.py`, `adapters_registry.py` (re-export); `pyproject.toml`/`uv.lock` (PyYAML 6.0.3; ruff per-file F811 ignore for the shared fixture); Guard `SKILL.md` (Choosing methods, step 5a Running a tool), `references/guard-records.md`, Framework `references/cli-contract.md`, toolkit `README.md`; FEATURE-002-A design change log entry.
- Tests: `tests/adapters/test_adapters_units.py` (contract, digests, safe I/O, restricted YAML, process kill/cap/env, normalization/sanitizing/accounting on the captured real Opengrep fixtures, staging parity), `tests/adapters/fake_opengrep.py` (test double of the observed behaviour), `tests/guard/test_guard_tool.py` (integration per AC), skill tests. TDD: RED = missing modules / failing assertions before each implementation step and before each review fix. Intended contract updates in older tests: 001-A status test (Opengrep now provided, AC-002B-06), 002-A unit fixture (`method_choice` required and reserved `opengrep` name → auxiliary method renamed `custom-scan`; assertions unchanged).
- Results (toolkit tree `0e550343…`): **517 passed, 2 skipped** (non-UTF-8 names unsupported by APFS) on macOS Python 3.14 and 3.11; **519 passed** on Linux Docker 3.12; `ruff check` clean. Coverage of new code: adapters 86–100%, toolrun 89%, tools_service 84%; total 91%.
- Independent code review: 5 findings (git-ignore drops staged copy; method name case mismatch; non-UTF-8 names abort late; nested targets collide; malformed tool JSON shapes) fixed test-first; focused re-review: fixes held, 1 new finding (nested target under a walk-excluded folder dropped → empty object `ok`) fixed test-first with an empty-object backstop gap.
- Real-binary behaviour (registration with the official digest, staged runs on the MVP samples, git work tree) is verified at acceptance in the offline Linux container; macOS binary not executed; Windows execution refused by design.

## Design Change Log

| Date | Version | Change | Reason |
|------|---------|--------|--------|
| 10-19-2026 | v1.0 | Initial design; independent review (12 blocking + 2 non-blocking) applied before approval: one process per check; strict tool-reported accounting (no extension guessing); bidirectional target/object binding; single commit after cleanup and integrity re-check with unique staging folders and stale sweep; reserved Adapter namespace and `next_adapter_run`; runs bound to `method_choice.selected`/`method_changes` with context snapshot; recursive masking and removal of matched source; streamed bounded output, evidence-quota check and full manifest; descriptor-based no-follow I/O; Windows execution refused (user decision); platform/libc provenance; full fixtures captured; restricted YAML loader; unambiguous rule attribution | TASK-029 rubber-duck design review |
| 10-19-2026 | v1.0 | Re-review fixes: stale staging/orphan evidence sweep refuses execution when not removable; manifest reserved and written first, raw output optional; rule capability allowlist (search mode only, no taint/interfile/join/extract/options); Python files parsed with `ast.parse` and unparseable ones unaccounted, other languages carry the stated syntax-error limit (user decision) | TASK-029 focused re-review |
| 10-19-2026 | v1.0 | Final check fixes: one process per rule (proves each rule ran; rule `paths`/version keys refused); manifest size bound computed before execution and covered by quota; retained sanitized output and manifest mandatory for successful evidence; per-process stdout cap 16 MiB | TASK-029 final design check |
| 10-19-2026 | v1.0 | Implementation review fixes (TASK-030): argv adds `--no-git-ignore` (staging lies inside the project's git work tree, which usually ignores `.x-ipe/private/`); Adapter method names must be exactly the Adapter name (`opengrep`) in plans and method changes; non-UTF-8 file names are hashed for the digest but listed as irregular (never scanned); a target nested in another requested target is staged apart only to bind its digest; tool output is accepted only in the observed JSON shape (else `failed`), odd positions tolerated | Independent code review |
| 10-19-2026 | v1.0 | Re-review fix: a target nested in another requested target is staged apart only when the outer walk covers it (not under `.git`/toolkit folders); a check with no object file to scan gets a gap (never `ok`) | Focused code re-review |
| 10-20-2026 | v1.0 | Bug fix TASK-032 (found by acceptance TASK-031 with the real binary): the tool's home/caches move from the stage to a private ASCII-only `mkdtemp` folder in the system temporary folder (Opengrep v1.31.0 silently produces no output with a non-ASCII cache path); non-ASCII system temporary folder → `TOOL_HOME_UNSUPPORTED` pre-check gap; explicit gap for exit 0 without output. AC-002B-03a unchanged (disposable home removed after the run) | User-approved bug fix (TASK-031 decision) |
| 10-20-2026 | v1.0 | Bug fix TASK-034 (closing review TASK-033): `copy_hash` writes every chunk completely (a short `os.write` could leave staged bytes different from the recorded digest); each executed single-rule config is verified to parse back to exactly its source rule and its digest is recorded (`config_digest` in the manifest, `config_digests` in the run entry), binding the recorded rule-file digest to the bytes Opengrep ran. Additive evidence; no AC changed | User-approved bug fix (closing review decision) |
