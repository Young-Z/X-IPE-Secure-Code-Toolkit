# Bug Report — TASK-097: a FIFO at the install record blocks `init`, `status` and `carriers` (+ sweep of the same read class)

## Reported Behavior

- **Source / authority:** TASK-095 closing addendum (`bug-report-TASK-095.md`): the independent reviewer reproduced that a FIFO at `.x-ipe/private/secure-code/install-record.json` hangs `init`, `status` and `carriers` (`install_record.load` checks `exists()` then `read_text()`). Representative DAO-002 (`x-ipe-docs/dao/26-10-23/decisions_made_bug_fix.md`, DEC-4): separate low-priority bug; reproduce first; sweep every path `init`/`status` read (toolkit-owned files under `.x-ipe/private/secure-code/` and the payload) for exists-then-read patterns so the regular-file check is applied consistently; existing problem codes only; within DAO defect-fix authority (spec L192 / NFR-001A-5). Owner brief: also cover `carriers`; fix only paths that can block or crash, otherwise record; delivered tests and 001-A baselines byte-identical; plain init stays 001-A behaviour (FEATURE-003-B rule).
- **Task:** TASK-097, lifecycle owner Sage; this worker: Bug Fix child, free-mode (no workflow action), interaction mode `dao-represent-human-to-interact` (no waiting; decisions listed below). No board, Git, memory or `.github/skills` writes; no subagents; no network.
- **Bug — Low (reported).** Actual (unfixed): with a FIFO at the install record, `init` (fresh or installed project) blocks inside `_locked_body` while holding the project lock; `status` blocks in `collect`; `carriers` blocks in `_load_record`; each until killed. Expected: the existing record refusal — `RECORD_INVALID` "install record unreadable: …", next step "Inspect `.x-ipe/private/secure-code/install-record.json`; it is not repaired automatically" (`init`, `carriers`), and status install section "invalid record" with the same problem; nothing written.
- **Sweep findings fixed (same defect class: a read that blocks or crashes instead of the designed refusal/report):**
  - S1 (Low) `status` crashes (PermissionError traceback, exit 1, no result) when an installed toolkit file cannot be opened.
  - S2 (Low) `status` crashes when a knowledge folder (`knowledge/local`, `knowledge/reference` or a namespace/version folder below) cannot be listed.
  - S3 (Low) `status` blocks when a trust file (`trusted-public-key.pem`, `trust-state.json`, current grant) is a FIFO.
  - S4 (Low) `init` blocks (under the project lock) on a FIFO in the toolkit source (payload) and crashes on an unreadable payload file.
  - S5 (Medium; independent-review finding, folded in under DAO-003) `init` silently installs an incomplete toolkit, exit 0, when a folder in the toolkit source cannot be listed: `os.walk` without `onerror` skips it (reviewer: 13 of 110 files; follow-up probe with `framework/references` mode 000: 104 of 110 files, no routing definition, `ok: true`).

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Safe install / reinstall refuses an unusable install record | 001-A spec L192 "permission denied during install → fail with reason; no partial install" / NFR-001A-5; design §Install Record (toolkit-owned path) and "Blocking problems … return before any write"; existing `_locked_body` / `carriers._load_record` refusal (`RECORD_INVALID`, "Inspect … not repaired automatically") | Maintainer, Developer, calling agent | A non-regular install record is refused like an unreadable one, before the lock is held on a read | `install_record.load` refuses a non-regular record (one check for all three commands) | Existing code / message prefix / next step; no record repair; regular records byte-identical behaviour | AC-001A-05a…05c (re-init, Integration) refusal branch; FEATURE-003-B carriers refusal | FIFO record: fresh init, installed init, carriers | Red: 3 timeouts → green | Not measured |
| Separated, read-only status always renders (G-03/G-06) | 001-A spec AC-001A-09a (separate sections), 09b (no writes), 09c (obvious configuration problems, e.g. unreadable trust file), 09e (invalid authorization shown with reason); design §G Status ("Problems: … unreadable trust files … drifted toolkit files") | User, upstream agent | Status reports an unreadable/non-regular record, toolkit file, knowledge folder or trust file as a problem with existing codes and still returns every section | Record → existing "invalid record"; toolkit file → counted changed (as a FIFO already is); knowledge folder → `IO_ERROR`; trust file → `invalid` / `TRUST_INVALID` | No writes; existing outputs for readable inputs unchanged; status is not a health certificate | AC-001A-09a/09b/09c/09e (Integration) | FIFO record, mode-000 skill file, mode-000 knowledge folders, FIFO trust key | Red: 2 timeouts + 2 tracebacks → green | Not measured |
| Payload is complete before init touches the project | design §Payload Location / L210 `PAYLOAD_INCOMPLETE`; "Blocking problems (root/env/payload/…) → return before any write" | Maintainer | A toolkit source with a file that is not a readable regular file, or a folder that cannot be listed, is refused before the lock and any write | `payload.files` checks each enumerated file and refuses an unlistable folder (`os.walk` `onerror`) | Existing code and next step "Use a complete toolkit folder (--toolkit-source DIR)" | AC-001A-04a (Integration) refusal branch | FIFO / mode-000 file, mode-000 folder in `--toolkit-source` | Red: timeout + traceback + exit 0 partial install → green | Not measured |

## Reproduction

Environment: macOS (darwin, aarch64), non-root user, CPython 3.14.6 from the toolkit's `scripts/.venv`; the real CLI (`x_ipe_secure_code.cli.main`) via the toolkit's test-only launcher (`tests/support/launcher.py`, trust store redirected into the scratch folder), each command in a subprocess with a 15 s timeout. Driver: `<SESSION>/bugfix-097/repro.py` (scratch projects under the session folder; removed afterwards). Unfixed sources: `install_record.py` `92cbaaf1…`, `status.py` `c4d46015…`, `payload.py` `d22c6047…`, `auth/verify.py` `344614a6…`, `project_init.py` `ac770f8f…` (= TASK-095 fixed revision, unchanged here), `carriers.py` `f1204a77…` (unchanged).

```
# R1  mkfifo P/.x-ipe/private/secure-code/install-record.json ; init P                 (fresh)
# R2  init P (ok) ; replace the record by a FIFO ; init P ; status P ; carriers P      (installed)
# R3  control: install record mode 000 ; init / status / carriers                     (existing OSError branch)
secure-code <command> --project P [--env github-copilot] --json
```

Observed (`<SESSION>/bugfix-097/repro.log`): R1 init `TIMEOUT: no exit within 15s (process killed)`, tree afterwards only the FIFO; R2 init, status and carriers each `TIMEOUT`; R3 (control) init/carriers exit 1 `RECORD_INVALID` "install record unreadable: [Errno 13] Permission denied: …" with the "Inspect … not repaired automatically" next step, status exit 0 with install state "invalid record". Sweep probes before the fix (`audit.log`): A1 status traceback `install_record.py line 135 sha256_file … PermissionError` (mode-000 installed SKILL.md); A4/A5 status traceback `status.py line 29/32 _count_rules os.scandir … PermissionError`; A9 init `TIMEOUT` (FIFO in `--toolkit-source`); A10 init traceback `sha256_file … PermissionError` (mode-000 payload file); A11 status `TIMEOUT` (FIFO `trusted-public-key.pem`).

## Root Cause

Implementation errors, not design flaws (the design already names the refusals/reports and codes):

1. `install_record.load` (L146–151 unfixed) returns `None` only when the path does not exist and then calls `read_text`. `unsafe_component` rejects symlinks and folders but accepts any other non-folder, so a FIFO passes; `open()` of a FIFO without a writer blocks. `init` reaches it in `_locked_body` inside `ProjectLock`, `carriers` in `_load_record` inside `ProjectLock`, `status` in `collect`. The `except OSError` around the read only helps once `open()` returns.
2. `status._install` guarded the drift hash with `is_file()` only; an unopenable regular file raised `PermissionError` out of `sha256_file`.
3. `status._count_rules` called `os.scandir` without handling `OSError` on the folder or its namespace/version sub-folders.
4. `auth.verify` read the trusted public key, trust state and grant with `read_bytes()` and no regular-file check (a FIFO blocks; `OSError` was already mapped to `invalid`).
5. `payload.files` enumerated every non-symlink name returned by `os.walk` (FIFOs included) without checking it is a readable regular file; `project_init._plan_file` then hashes the source with `sha256_file(source)` under the project lock. In addition (S5), `os.walk` was called without `onerror`, and its default ignores a folder whose listing fails, so an unlistable folder silently shrank the payload and `init` installed the remainder as complete.

Inspected callers/dependents: `cli.run` → `project_init.initialize_project` → `_locked_body` → `load` / `_plan_and_apply`; `cli.run` → `status.collect` → `load`, `verify`, `_count_rules`, `_install`, `_tool` → `registry_store`, `_host`, `_carriers`; `cli.run` → `carriers.run` → `_locked` → `_load_record` → `load`, `_check_installed`, `_plan_kind`. `install_record.load` importers: `project_init`, `status`, `carriers` only. `verify` callers: `status` and maintainer-gated commands (all now get `invalid` instead of blocking on a non-regular trust file; regular-file behaviour unchanged). `payload.files` importer: `project_init` only.

## Audit of Read Paths Reachable from `init`, `status` and `carriers`

Line numbers at the fixed revision (paths under `scripts/src/x_ipe_secure_code/`). "Guarded" = regular-file check (or non-blocking open + `fstat`) before the read and `OSError` handled.

| # | Path read | Site | Command(s) | Before fix | Verdict |
| --- | --- | --- | --- | --- | --- |
| 1 | `.x-ipe/private/secure-code/install-record.json` | `install_record.py:148–151` `load` | init, status, carriers | exists-then-read: FIFO blocks (R1/R2 reproduced) | **Fixed** — not a regular file → `RecordError` → existing `RECORD_INVALID` refusal / "invalid record" |
| 2 | Installed toolkit files (record `files`) | `status.py:51` `_matches` (was `_install` drift loop) | status | `is_file()`-guarded (FIFO counted changed, A2) but mode 000 → traceback (A1) | **Fixed** — `OSError` → counted changed (`TOOLKIT_FILES_CHANGED`, as a FIFO already was) |
| 3 | `x-ipe-docs/secure-code/knowledge/{local,reference}/<ns>/<ver>` | `status.py:28` `_count_rules.entries` | status | `is_dir()` then `scandir`: unlistable folder → traceback (A4/A5) | **Fixed** — `IO_ERROR` "Folder `<rel>` cannot be read (`<reason>`)", folder contributes nothing to the count |
| 4 | Trust files (`trusted-public-key.pem`, `trust-state.json`, current grant) | `auth/verify.py:66–89` `_read` | status (and maintainer gates) | `read_bytes()` unguarded: FIFO blocks (A11) | **Fixed** — exists and not a regular file → `OSError` → existing `invalid` / `TRUST_INVALID` with reason |
| 5 | Payload (toolkit source) files | `payload.py:113` `files` → `project_init.py:42,222` | init | FIFO blocks under the lock (A9); mode 000 → traceback (A10) | **Fixed** — not a readable regular file → `PAYLOAD_INCOMPLETE`, refused before the lock and any write |
| 5a | Payload (toolkit source) folders | `payload.py:85–92` `files` (`os.walk(…, onerror=unreadable, …)`) | init | **missed in the first audit (review finding):** `os.walk` without `onerror` skipped an unlistable folder → partial toolkit installed, exit 0 (reviewer: 13 of 110 files; probe: 104 of 110) | **Fixed** — `PAYLOAD_INCOMPLETE` "Toolkit source folder `<skill>/<rel>` cannot be read (`<reason>`)", refused before the lock and any write; excluded folders (`.venv`, `__pycache__`, `scripts/tests`, …) are pruned before listing and stay ignored |
| 6 | Skill targets in the project | `project_init.py:46–50` `_plan_file` | init | guarded (TASK-095) | No change |
| 7 | Host entry | `project_init.py:175–177`; `status.py:90` | init, status | guarded (TASK-079/095) | No change |
| 8 | Routing definition (payload and installed) | `routing.py:140–143` `load_file` via `project_init.py:114,136`, `status.py:129`, `carriers.py:188` | all three | guarded (`is_symlink`/`is_file`); FIFO → `ROUTING_DEFINITION_INVALID` / `IO_ERROR` (A7) | No change |
| 9 | Installed SKILL.md files | `carriers.py:174–176` `_check_installed` | carriers | guarded → `SKILLS_INVALID` (A3) | No change |
| 10 | Carrier files (host entry, instructions, system prompt) | `carriers.py:299` `_plan_kind`; `status.py:150` | carriers, status | guarded (`is_file`); FIFO treated as missing (A8/A13) | No change for blocking/crash; see observation O-2 |
| 11 | Tool registration record `.x-ipe/private/secure-code/tools/<tool>.json` | `adapters/registry_store.py:115–119` | status | guarded (A6) | No change |
| 12 | Registered tool binary (absolute path in the record) | `adapters/registry_store.py:151` → `safe_io.open_absolute_nofollow` (blocking `os.open`, then `fstat`) | status | FIFO blocks (A14 reproduced with a hand-written record carrying an official digest) | **Recorded, not fixed** — observation O-1 (FEATURE-002-B module, shared no-follow open used by Guard execution) |
| 13 | Trivy journal / pointer / cache metadata | `adapters/trivy_journal.py:52,190`, `trivy_cache.py:49` (`durable.read`: `S_ISREG` + `O_NONBLOCK` + `fstat`); `trivy_cache.py:237` after `_structure` (lstat walk rejects special files); all inside `except Exception` in `status._trivy` | status | guarded | No change |
| 14 | `presets/default.json`, layout folders | `status.py:286`, `status.py` layout loop | status | stat only (A12) | No change |
| 15 | `direct_url.json` of the installed distribution | `payload.py:35` | init | package metadata (installer-owned, not project/toolkit-owned) | No change (out of sweep scope) |
| 16 | Project root lock | `atomic.py` `ProjectLock._open` (`O_RDONLY|O_DIRECTORY` on the root) | init, carriers | directory open only | No change |

## Scope and Conflicts

- **Affected:** only inputs that previously blocked or crashed: a non-regular install record (all three commands), an unopenable installed toolkit file or unlistable knowledge folder (status), a non-regular trust file (status / `verify`), a non-regular or unreadable payload file (init).
- **Unaffected (verified):** every regular, readable input — plain `init` planning/outcomes/messages (TASK-095 tests, `test_project_init.py`, 001A baseline fixture comparison `tests/carriers/test_project_lock.py` + `fixtures/init_001a_baseline.json` green and byte-identical), the mode-000 record message (characterization, passed before and after), status output for readable projects (`test_status*.py`, `tests/carriers/test_carriers_status.py`), auth (`test_auth_service.py`, `test_auth_cli.py`), payload (`test_payload.py`); `project_init.py`, `carriers.py`, `routing.py`, `paths.py`, `cli.py`, adapters unchanged.
- **Conflicts:** none unexpected. Expected consequences: inputs that hung or crashed now get the existing refusal/report. Classified against the original report, DAO-002 DEC-4 and the 001-A spec/design clauses above.

## Fix and Design Impact

Paths under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/` (4 files, +46/−13 including the review follow-up):

- `src/x_ipe_secure_code/install_record.py` (+2): after the existence check, `if not path.is_file(): raise RecordError("install record unreadable: not a regular file")` (default code `RECORD_INVALID`). `init`/`carriers` return the existing "Inspect … not repaired automatically" refusal; `status` shows "invalid record".
- `src/x_ipe_secure_code/status.py` (+24/−9): `_matches` treats an unopenable toolkit file as not matching the record; `_count_rules(root, folder, problems)` lists folders through a helper that reports `IO_ERROR` "Folder `<rel>` cannot be read (`<reason>`)" and skips that folder.
- `src/x_ipe_secure_code/auth/verify.py` (+10/−3): `_read(path)` raises `OSError("<name> is not a regular file")` for an existing non-regular path before `read_bytes()`; used for the public key, trust state and grant (existing `OSError` handling → `invalid`).
- `src/x_ipe_secure_code/payload.py` (+10/−1): `files` raises `PayloadError("PAYLOAD_INCOMPLETE", "Toolkit source file <skill>/<rel> is not a readable regular file")` for an enumerated file that is not a regular file or not readable (`os.access(R_OK)`); review follow-up: `os.walk` gets `onerror=unreadable`, which raises `PayloadError("PAYLOAD_INCOMPLETE", "Toolkit source folder <skill>/<rel> cannot be read (<reason>)")` instead of skipping the folder.

Design impact: none on interfaces, data model or workflow — existing codes (`RECORD_INVALID`, `TOOLKIT_FILES_CHANGED`, `IO_ERROR`, `TRUST_INVALID`, `PAYLOAD_INCOMPLETE`), existing next steps, no new output key; no Design Change Log entry required. Alternatives rejected: changing shared `paths.unsafe_component` to require regular files (would turn a FIFO record into `PATH_UNSAFE` and change every caller); a new problem code (new output kind); `O_NONBLOCK` + `fstat` reads (more code; the residual check-to-open race for a regular file swapped for a FIFO by a concurrent writer remains a Low honest limit, as for TASK-095).

## Mini AAA and Actual Routing

New test file only: `scripts/tests/test_nonregular_toolkit_reads.py` (11 tests after the review follow-up; CLI via the test launcher with a 30 s timeout so a blocking read fails instead of hanging; `Traceback` in stderr fails; write audit + tree snapshot; permission tests skip as root/non-POSIX, FIFO tests skip on non-POSIX).

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| FIFO record, fresh project (AC-001A-05 refusal / L192) | `mkfifo` install record | `init` | finishes < 30 s; no traceback; exit 1; problems == [`RECORD_INVALID` "install record unreadable: not a regular file"]; next steps == Inspect step; no write; tree unchanged; FIFO intact; no host entry / skills | Python CLI integration, pytest | red: timeout; green: passed |
| FIFO record, installed project: `init`, `carriers` | `init` ok; record → FIFO | `init` / `carriers` | same refusal per command; no write; tree unchanged | same | red: 2 timeouts; green: passed |
| FIFO record, installed project: `status` (AC-001A-09a/09b) | as above | `status` | exit 0; all six sections; install == state "invalid record" + Inspect next step; `RECORD_INVALID` problem; no write | same | red: timeout; green: passed |
| Mode-000 record (characterization) | record mode 000 | `init` | unchanged `RECORD_INVALID` "install record unreadable: [Errno 13] Permission denied…", Inspect step | same | passed before and after |
| Mode-000 installed toolkit file (AC-001A-09c) | `init` ok; SKILL.md mode 000 | `status` | exit 0; installed; `changed_toolkit_files` 1; review next step; `TOOLKIT_FILES_CHANGED`; no write | same | red: traceback; green: passed |
| Unlistable knowledge folders (AC-001A-09a/09c) | `knowledge/local` and `reference/acme` mode 000; readable `reference/beta/1.0/R-2` | `status` | exit 0; all sections; local 0, reference 1; exactly two `IO_ERROR` problems naming the folders; no write | same | red: traceback; green: passed |
| FIFO trust public key (AC-001A-09c/09e) | `trust/trusted-public-key.pem` FIFO | `status` | finishes; authorization role user, state invalid, reason "trusted public key missing or unreadable"; `TRUST_INVALID` with that reason; FIFO intact | same | red: timeout; green: passed |
| FIFO / mode-000 file in `--toolkit-source` (AC-001A-04a refusal) | copy of the three skills + FIFO `guard/extra` / guard `SKILL.md` mode 000 | `init --toolkit-source` | exit 1; problems == [`PAYLOAD_INCOMPLETE` "Toolkit source file … is not a readable regular file"]; next step "Use a complete toolkit folder (--toolkit-source DIR)"; no write; project empty | same | red: timeout / traceback; green: passed |
| Unlistable folder in `--toolkit-source` (review finding; AC-001A-04a refusal) | copy of the three skills; `framework/references` mode 000 | `init --toolkit-source` | exit 1; problems == [`PAYLOAD_INCOMPLETE` "Toolkit source folder x-ipe-secure-code-toolkit-framework/references cannot be read (Permission denied)"]; DEC-5 next step; no write; project empty | same | red: exit 0 (partial install); green: passed |

Routing: the enabled Python fix route was executed directly by this worker (no subagent, per task constraint): red → minimal fix → green → full suite → ruff.

## Verification

| Step | Command (from `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts`) | Result | Log (`<SESSION>/bugfix-097/`) |
| --- | --- | --- | --- |
| Reproduction + sweep probes, unfixed | `repro.py repro`, `repro.py audit` | R1/R2 init, status, carriers TIMEOUT; R3 control refusal; A1/A4/A5/A10 traceback; A9/A11 TIMEOUT; A2/A3/A6/A7/A8/A12/A13 no block/crash | `repro.log`, `audit.log` |
| RED (unfixed sources above, test `01d7ef81…`) | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<SESSION>/bugfix-097/tmp tests/test_nonregular_toolkit_reads.py` | **9 failed** (6 `did not finish within 30s`, 3 `assert 'Traceback' not in …`), 1 passed (characterization), exit 1 | `red.log` |
| GREEN (fixed, test `01d7ef81…`) | same file + `test_project_init_unreadable_targets.py test_project_init_unreadable_host_entry.py test_project_init.py test_payload.py test_status.py test_status_unreadable_host_entry.py test_auth_service.py test_auth_cli.py test_module_size.py tests/carriers` | **348 passed**, exit 0 | `green.log` |
| Lint | `uv run --offline ruff check --no-cache src tests` | first run: 4 × E501 in the new test → long lines wrapped into local variables (identical expected values; test `01d7ef81…` → `aad1fd96…`); rerun **All checks passed**, exit 0 | `ruff.log` |
| RED re-confirmed with the final test | final test `aad1fd96…` run against a session copy of the toolkit whose four sources were reverted to byte-identical unfixed hashes (`hashes-red.txt`) | **9 failed, 1 passed**, exit 1; tracebacks point into the copy's unfixed `install_record.py` / `status.py` | `red-final.log` |
| Reproduction + probes, fixed | `repro.py all` | R1/R2: `RECORD_INVALID` "install record unreadable: not a regular file" with Inspect step (init/carriers exit 1), status exit 0 "invalid record"; R3 unchanged; A1 `TOOLKIT_FILES_CHANGED` (1); A4/A5 `IO_ERROR` folder message; A9/A10 `PAYLOAD_INCOMPLETE`; A11 authorization invalid + `TRUST_INVALID`; others unchanged | `repro-fixed.log` |
| Full suite (fixed, final test `aad1fd96…`) | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<SESSION>/bugfix-097/tmp -rs` | **2603 passed, 4 skipped, 23 deselected in 634 s, exit 0**; the 4 skips are the same pre-existing conditional skips as TASK-095 (`adapters/test_adapters_units.py:510`, `guard/test_guard_units.py:685`, `knowledge/test_exit_review_fixes.py:272`, `presets/test_tags.py:59`) | `full-suite.log` |
| Observation probe O-1 | `probe_a14.py` | status TIMEOUT (not fixed; recorded) | `probe_a14.log` |
| Review follow-up: probe, unfixed (`payload.py` `817cc489…`) | `followup/probe_walk.py` (copy of the three skills; `framework/references` mode 000) | `files()` returns 104 of 110 files; `init --toolkit-source` exit 0, `ok: true`, 104 files created, no problems, no `references/` installed | `followup/probe-before.log` |
| Review follow-up: RED (`payload.py` `817cc489…`, test `afca6518…`) | `… pytest … tests/test_nonregular_toolkit_reads.py -k toolkit_source` | **1 failed** (`assert (0 == 1)`: init exit 0), 2 passed (DEC-5 file cases), exit 1 | `followup/red.log` |
| Review follow-up: GREEN (`payload.py` `dbd25e09…`, same test) | same file + `test_payload.py test_project_init.py test_project_init_unreadable_targets.py tests/carriers/test_project_lock.py tests/carriers/test_carriers_generation.py` | **92 passed**, exit 0; probe after: `PAYLOAD_INCOMPLETE` "Toolkit source folder x-ipe-secure-code-toolkit-framework/references cannot be read (Permission denied)", exit 1, 0 files created | `followup/green.log`, `followup/probe-after.log` |
| Review follow-up: lint | `uv run --offline ruff check --no-cache src tests` | **All checks passed**, exit 0 | `followup/ruff.log` |
| Review follow-up: full suite (final: `payload.py` `dbd25e09…`, test `afca6518…`) | as above, `--basetemp=<SESSION>/bugfix-097/followup/tmp -rs` | **2604 passed, 4 skipped, 23 deselected in 643 s, exit 0**; same 4 pre-existing skips | `followup/full-suite.log` |

Changed / added files (paths under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/`):

| File | Lines | SHA-256 before | SHA-256 after |
| --- | --- | --- | --- |
| `src/x_ipe_secure_code/install_record.py` | 162 → 164 | `92cbaaf1195f7e001996ee881544d6d03f808b735dc1ebf789e36129e9040e77` | `44ee1246755ea5462e81598a4633fb09fea0bcc20d5f6c2464f904eec38cdb75` |
| `src/x_ipe_secure_code/status.py` | 276 → 291 | `c4d460150613ff869830d6505f6ea2aac66fb1ec470dcf112c0b8d6440510c8d` | `10df3fedb25f94448f593c18d8fba691dea85545476792c9f2d773fd29bf146e` |
| `src/x_ipe_secure_code/auth/verify.py` | 132 → 139 | `344614a6c6d47c379a4a62c0c1d95c979a1e1a9c96d288e8d923882a45a78e55` | `59b45c8e3d0791f2e64d682e8120068c2ca7bc99ba191e73ada4ebf46c1cc8bb` |
| `src/x_ipe_secure_code/payload.py` | 108 → 117 | `d22c604ec750d40070726f6700f767bcb45182ffe1a16f61d62f28a4b34824d6` | `dbd25e094494505fe27b2d5c0eb87dd1501593e7cd57206818a2df4152d58263` (first fix `817cc489…`) |
| `tests/test_nonregular_toolkit_reads.py` (new) | 278 | — | `afca6518e40a04f17cb795112b740f6925d1b8b4c1edd4f9c4bfd724bd62fd68` (first fix `aad1fd96…`; the follow-up only appended one test) |

Unchanged (byte-identical before/after, from the file lists): `project_init.py` `ac770f8f…`, `carriers.py` `f1204a77…`, `tests/test_project_init.py` `2f56555b…`, `tests/test_payload.py` `9a114c02…`, `tests/test_status.py` `32771fbd…`, `tests/carriers/test_carriers_status.py` `cbecf4ab…`, `tests/carriers/test_project_lock.py` `2ad04afa…`, `tests/carriers/fixtures/init_001a_baseline.json` `bcd46231…`. No delivered test or baseline was modified.

Toolkit file-list hash (`cd ai-secure-code-toolkit; find . -type f` excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage*` `-exec shasum -a 256 {} +`, `./` stripped, `LC_ALL=C sort -k2`, `shasum -a 256`): before this fix 243 files `272741bc8c8d9213673f47237f777e47ef194e85ae5b13e07fc975c8f3ddac2c`; after the first fix 244 files `a9618fbb21f1bb266c6ed4f2022f3870d4e2e2aaca0b374612680509005e6291`; after the review follow-up (final) 244 files **`cb09bb7c00ad7d34f8c6d31f3e8c5a99766c4436334fe9c3e261e9ae34ed7095`** (diff to `a9618fbb…`: only `payload.py` and the new test; diff to `272741bc…`: exactly the five files above). Note: the "before" list (243 files) already differed from TASK-095's after-list (240 files, `3d0f41cc…`) — changes from other work, not from this task. Hygiene: no build, cache or test artifacts under `ai-secure-code-toolkit/`; nothing created in the workspace `.x-ipe/` or `x-ipe-docs/secure-code/` (neither exists); session scratch projects, the reverted-source copy and pytest temp folders removed (`chmod -R u+rwx` before `rm`).

Independent review: PASS-WITH-FIXES (owner-run, after the first fix); the one finding (unlistable payload folder, S5) is fixed above. Re-review of the follow-up is the owner's step. Representative DAO-003 approved DEC-1…5 and routed O-1/O-2 to separate tasks (not fixed here).

Test gaps (non-blocking, noted by the reviewer):
- The trust-file test covers only a FIFO `trusted-public-key.pem`; FIFO `trust-state.json` and grant files are not tested separately — they share the same `_read` helper (`auth/verify.py:66–69`) and the same existing `OSError` → `invalid` handling.
- The permission-based tests (mode 000 record, toolkit file, knowledge folders, payload file and payload folder) skip when run as root or on non-POSIX systems, so on such hosts only the FIFO cases are exercised.

Engineering delivery: verified by the checks above. Stakeholder outcome: not measured.

## Decisions (for the representative / owner)

- **DEC-1 (reported bug):** a non-regular install record → `RecordError("install record unreadable: not a regular file")`, i.e. the existing `RECORD_INVALID` refusal with "Inspect … not repaired automatically" (`init`, `carriers`) and "invalid record" (`status`) — the owner's suggested fix verbatim, one check in the shared loader.
- **DEC-2 (S1, status, unopenable installed toolkit file):** counted as changed (`TOOLKIT_FILES_CHANGED`, review next step), the same branch a FIFO toolkit file already took; `init` (the next step) then names the file with `IO_ERROR` (TASK-095 DEC-2). Alternative not taken: a separate `IO_ERROR` problem in status (adds a second report for one file).
- **DEC-3 (S2, status, unlistable knowledge folder):** existing general code `IO_ERROR` "Folder `<rel>` cannot be read (`<reason>`)"; the folder contributes nothing to the Local/Reference count (the Policies next step is computed from that count, as before). Alternatives not taken: silent skip (hides an obvious configuration problem, AC-001A-09c); `LAYOUT_MISSING` (the folder exists).
- **DEC-4 (S3, trust file not a regular file):** existing `invalid` authorization / `TRUST_INVALID` with reason (AC-001A-09c/09e, design §G "unreadable trust files"). Fixed in `auth/verify.py`, a FEATURE-001-A module; maintainer-gated commands now get `invalid` instead of blocking. Regular and missing files behave exactly as before.
- **DEC-5 (S4, payload):** a payload file that is not a readable regular file → existing `PAYLOAD_INCOMPLETE` with the existing "Use a complete toolkit folder (--toolkit-source DIR)" step, before the lock and any write.
- **DEC-5a (S5, review finding, same class as DEC-5):** a toolkit-source folder that cannot be listed → `PAYLOAD_INCOMPLETE` "Toolkit source folder `<skill>/<rel>` cannot be read (`<reason>`)" with the same next step, via `os.walk(onerror=…)`, before the lock and any write. Excluded folders are pruned before listing, so an unreadable `.venv`/`__pycache__`/`scripts/tests` is still ignored.
- **Observation O-1 (not fixed, Low, separate candidate):** `status` blocks when a registered tool binary path (absolute, outside the project) is a FIFO: `registry_store.check` → `safe_io.open_absolute_nofollow` opens without `O_NONBLOCK` before its `fstat` regular-file check (reproduced, `probe_a14.log`, with a hand-written registration record carrying the official macOS arm64 Opengrep digest; in practice a registered binary swapped for a FIFO). Suggested fix: add `O_NONBLOCK` to the final open in `safe_io.open_nofollow` (as `durable.read` does; reads of regular files are unaffected). Not folded in: FEATURE-002-B module outside the DAO-002 sweep scope, shared by Guard execution/snapshot paths, so it needs its own regression run and review.
- **Observation O-2 (not fixed, no block/crash):** `carriers` treats a FIFO at a carrier path (incl. the host entry) as a missing file and replaces it with the rendered carrier (A13: `AGENTS.md` FIFO became a regular file, exit 0), and `status` shows it as "missing file", whereas plain `init` refuses a FIFO host entry with `HOST_ENTRY_UNREADABLE` (TASK-095 DEC-3). Consistency decision for the owner (FEATURE-003-B).
- **Honest limit:** the check-then-read window remains (a regular file swapped for a FIFO between `is_file()` and `open()` by a concurrent writer), Low, as recorded for TASK-095.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed
  next_task_based_skill: null
  process_preference:
    interaction_mode: "dao-represent-human-to-interact"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/install_record.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/status.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/auth/verify.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/payload.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/test_nonregular_toolkit_reads.py"
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/bug-report-TASK-097.md"
  bug_severity: "Medium"  # reported FIFO-record bug Low; highest folded-in case (S5 partial install, exit 0) Medium
  root_cause: "install_record.load read the record after an existence check only, so a FIFO install record blocked init and carriers under the project lock and status; the sweep found the same unguarded-read class in status (unopenable toolkit file, unlistable knowledge folder: crash), auth verify (FIFO trust file: block) and payload enumeration (FIFO/unreadable toolkit source file: block/crash; unlistable toolkit source folder silently skipped by os.walk: partial install, review finding)"
  conflicts_found: []
```

One lifecycle owner (Sage) handles independent review, completion and routing; this child made no board, Git, memory or app writes and ran no successor.

## Closing Addendum (2026-10-24, appended by Sage)

- Independent code review: PASS-WITH-FIXES → the reviewer's finding (unreadable toolkit-source folder → silent partial install) folded in as DEC-5a; delta re-review **PASS** (pruned folders never listed, unreadable listed folders refused with PAYLOAD_INCOMPLETE before the lock and any write).
- Representative DAO-003 (`x-ipe-docs/dao/26-10-23/decisions_made_bug_fix.md`): DEC-1…5 approved. O-1 → TASK-100 (FEATURE-002-B safe_io, next in the code queue). O-2 → TASK-101 (FEATURE-003-B carriers, held until the human's B7 smoke is recorded).
- 001-A black-box regression (host, macOS) at the final revision: statuses identical to the original evidence for all 13 entries (`acceptance/regression-TASK-097-host-macos.jsonl`).
