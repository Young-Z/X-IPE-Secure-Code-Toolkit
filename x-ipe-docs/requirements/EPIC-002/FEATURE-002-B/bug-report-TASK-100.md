# Bug Report — TASK-100: a FIFO at a registered tool binary path blocks `status` (shared no-follow open in `adapters/safe_io`; + Guard staging walk)

## Reported Behavior

- **Source / authority:** TASK-097 observation O-1 (`x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/bug-report-TASK-097.md`, audit row 12 and "Observation O-1"; probe A14 `<SESSION>/bugfix-097/probe_a14.py` / `probe_a14.log`): `status` hangs when the binary path of a registration record (absolute, outside the project) is a FIFO, because `registry_store.check` → `safe_io.open_absolute_nofollow` → `open_nofollow` opens with a blocking `os.open` before its `fstat` regular-file check. Representative DAO-003 (`x-ipe-docs/dao/26-10-23/decisions_made_bug_fix.md`): separate bug task on FEATURE-002-B; reproduced hang = defect against the delivered "fail with reason" behaviour, within DAO defect-fix authority; fix = open with `O_NONBLOCK` (where supported), `fstat` regular-file check on the descriptor, clear `O_NONBLOCK` before reading if needed; existing refusal code only; delivered 002-A/002-B/002-D tests byte-identical; 002-B host regression (the 002-D container regression runs at its B9 acceptance).
- **Task:** TASK-100, lifecycle owner Sage; this worker: Bug Fix child, free-mode (no workflow action), interaction mode `dao-represent-human-to-interact` (no waiting; decisions listed below). No board, Git, memory or `.github/skills` writes; no subagents; no network.
- **Bug — Low (reported).** Actual (unfixed): with a FIFO (no writer) at the registered Opengrep binary path, `status` blocks until killed. The same shared helper also blocked — until killed — registration inspection (`tools register` with a FIFO `--path`), the Guard pre-check binary snapshot, Guard tool-request validation of a FIFO rule file and of a FIFO image archive target (reproduced at library level, L1–L5 below). Expected: the existing refusal a non-regular path (e.g. a folder) already gets — `UnsafePath("<name> is not a regular file")`, reported by each caller under its existing code and next step (status: check "The registered binary is missing or unreadable: … is not a regular file" with the register next step); nothing written, nothing executed.
- **Fold-in (DAO-004, same task):** the Guard staging walk (`guard/targets.py` `stage` → `walk`, unfixed L270) opened each entry that `scandir` reported as a regular file with its own blocking `os.open`, then checked `fstat`. A regular file swapped for a FIFO between the listing and the open blocked staging until killed (deterministic reproduction by simulating the swap, below). Expected: the existing outcome when the opened entry is not a regular file — `UnsafePath("<rel> changed while staging")`, i.e. the callers' existing `STAGE_UNSAFE` gap. DAO-004 conditions: deterministic RED first, existing outcome unchanged, no new code, delivered tests byte-identical, full suite + 002-B host regression again; else a separate Low candidate.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Status reports the tool pre-check without executing (FR-002B-8) | 002-B spec AC-002B-06a; design §Safe I/O "`os.fstat` must show a regular file … other type → `UnsafePath`" | User, upstream agent | A registered binary path that is not a regular file is reported with the failing reason and next step; status always renders | Shared helper opens non-blocking, so the designed `fstat` check is reached | Existing `TOOL_NOT_REGISTERED` reason/next step (same as a folder); no execution, no write | AC-002B-06a (Integration) | FIFO at registered binary path → `status` | Red: timeout → green | Not measured |
| Registration refuses a non-regular path (FR-002B-2) | AC-002B-01c; design §Registration "absolute path; `open_nofollow`; regular file → `TOOL_PATH_INVALID`" | Maintainer | Refused with the reason; never executed | same helper | Existing `TOOL_PATH_INVALID` and next step | AC-002B-01c (Integration; here library-level) | `inspect_binary(FIFO)` | Red: timeout → green | Not measured |
| Pre-check snapshot fails closed (FR-002B-5) | AC-002B-01d | Developer, calling agent | Pre-check failure → nothing staged or executed | same helper | Existing `TOOL_NOT_REGISTERED` gap | AC-002B-01d (library-level) | `check(…, stage_bin)` with FIFO binary | Red: timeout → green; nothing staged | Not measured |
| Rule sources / archive targets must be regular local files | AC-002B-02b; FEATURE-002-D archive target validation (`trivy_request._archive`) | Calling agent | Refused with the existing request refusal | same helper | Existing Checker code/message ("… is not an existing regular local rule file without links (…)", "… is not a readable regular file without links (…)") | AC-002B-02b (library-level) | FIFO rule file / FIFO `.tar` target | Red: 2 timeouts → green | Not measured |
| Staging never follows or waits on special entries (FR-002B-5, fold-in DAO-004) | AC-002B-01d "requested target and rule files snapshotted without following symbolic links … any failure means the tool is not executed"; design §Execution "`targets.stage()` walks via `safe_io` … links/special entries … not copied" and §Risks "swapped in during staging → `STAGE_UNSAFE`" | Developer, calling agent | An entry swapped for a FIFO mid-walk fails staging with the existing refusal, without blocking | Same non-blocking open + `fstat` pattern in the walk | Existing `UnsafePath("<rel> changed while staging")` → `STAGE_UNSAFE`; regular files staged/hashed as before | AC-002B-01d (library-level) | swap simulated: `scandir` says regular file, open finds a FIFO | Red: timeout → green | Not measured |

## Reproduction

Environment: macOS (darwin, arm64), non-root user, CPython 3.14.6 from the toolkit's `scripts/.venv`; real CLI (`x_ipe_secure_code.cli.main`) via the toolkit's test-only launcher (`tests/support/launcher.py`, trust store redirected into the scratch folder); every call in a child process with a 15 s timeout. Driver: `<SESSION>/bugfix-100/probe.py` (= TASK-097 probe A14 plus controls and library probes; scratch projects under the session folder, removed afterwards). Unfixed source: `adapters/safe_io.py` `d4fee549…` (= TASK-097 final toolkit, file-list hash `cb09bb7c…`).

```
# P1 (A14) init P ; write .x-ipe/private/secure-code/tools/opengrep.json {path: <abs FIFO>, digest: official macOS arm64}
#          secure-code status --project P --json
# P2/P3 controls: path = a folder / a regular file with other bytes
# L1 safe_io.open_nofollow(project, "rules/fifo.yaml")   L2 safe_io.hash_path(FIFO)
# L3 registry_store.inspect_binary(FIFO)                 L4 registry_store.check(P1, "opengrep", stage_bin=…)
# L5 guard.toolreq._rule_file(FIFO rule file) + control regular rule file
```

Observed before the fix (`probe-before.log`): P1 `TIMEOUT: no exit within 15s (process killed)`; P2 exit 0, check "The registered binary is missing or unreadable: opengrep-dir is not a regular file" + register next step (existing non-regular branch); P3 exit 0, "The registered binary's digest changed since registration; nothing was executed"; L1–L5 (FIFO cases) each `TIMEOUT`; L5 control returns the rule bytes; FIFOs intact.

## Root Cause

Implementation error, not a design flaw (the design already specifies "`os.fstat` must show a regular file … other type → `UnsafePath`"): `safe_io.open_nofollow` (unfixed L55–77) opened the final component with `os.O_RDONLY | NOFOLLOW` (POSIX `dir_fd` branch, L72) or `os.O_RDONLY | BINARY` (lstat/fstat branch, L62). `open(2)` of a FIFO for reading without `O_NONBLOCK` waits for a writer, so `_check_regular` (the `fstat` `S_ISREG` check) was never reached. `open_absolute_nofollow` and `hash_path` delegate to it.

Callers (all inspected; every one already handles `UnsafePath`/`OSError` with an existing refusal):

| Caller | Site | Reached from | Mapping of `UnsafePath` (unchanged) |
| --- | --- | --- | --- |
| `registry_store.check` | `registry_store.py:151` | `status._registration`, Guard tool-run pre-check (`stage_bin` snapshot) | `TOOL_NOT_REGISTERED` "The registered binary is missing or unreadable: …" + register step |
| `registry_store.inspect_binary` | `registry_store.py:64` | `tools register` | `TOOL_PATH_INVALID` "… is not a readable regular file (no symbolic links): …" |
| `guard.toolreq._rule_file` | `toolreq.py:30` | Guard tool request validation | Checker refusal "… is not an existing regular local rule file without links (…)" |
| `trivy_request._archive` | `trivy_request.py:46` | Trivy request validation (002-D) | Checker refusal "… is not a readable regular file without links (…)" |
| `guard.targets.stage` (file kind) | `targets.py:234` | Guard/Trivy staging | `STAGE_UNSAFE` gap (`toolrun.py:228`, `trivy_run.py:213`) |
| `trivy_run` staged archive | `trivy_run.py:224` | Trivy run (staged copy, always regular) | per-archive error entry |
| `guard.toolrun` rule re-hash | `toolrun.py:398` | after a tool run | "rule file … changed during the run" |
| `safe_io.hash_path` | `safe_io.py:128` | (helper) | `UnsafePath` |

Descriptor consumers after a successful open (regular files only): `hash_fd` / `copy_hash` / `trivy_fs.copy_into` / `toolreq._rule_file` (`os.read` loops), `trivy_archive.validate_archive` (positional reads), `os.fstat`. None passes the descriptor to a child process.

Fold-in (DAO-004): `guard/targets.py` `stage` → inner `walk` (unfixed L268–276) lists a folder with `os.scandir(dfd)` and, for an entry reported as a regular file, opens it with its own `os.open(entry.name, O_RDONLY | NOFOLLOW, dir_fd=dfd)` and then checks `fstat` `S_ISREG` (existing refusal `UnsafePath("<rel> changed while staging")`). Same defect: without `O_NONBLOCK` the open of an entry swapped for a FIFO after the listing waits for a writer, so the existing check is never reached. Callers: `toolrun.py:207` and `trivy_run.py:185`, both mapping `UnsafePath` to the existing `STAGE_UNSAFE` gap. Entries already listed as special (not `is_file()`) never reach the open and keep their `special`/`irregular` outcome. Design text (§Execution / §Risks, technical-design L171/L256) already names this refusal.

## Scope and Conflicts

- **Affected:** only paths that are not regular files and previously blocked in `open(2)` (FIFOs; also any other special file whose blocking open would wait). They now reach the existing `_check_regular` refusal; in the staging walk (fold-in) an entry swapped for a FIFO after the listing reaches the existing "changed while staging" refusal.
- **Unaffected (verified):** regular files — `O_NONBLOCK` has no effect on regular-file reads on macOS/Linux, and it is cleared on the descriptor right after the `S_ISREG` check, so every caller receives a descriptor in the same (blocking) state as before (asserted by `test_regular_file_descriptor_unchanged`: blocking mode, bytes across 3 × 1 MiB + 17, digest); folders and links (same message as before, P2 control and characterization test passed before and after); Windows (`O_NONBLOCK` absent → flag 0, no `set_blocking` call: byte-identical behaviour). `open_dir_nofollow`, `copy_hash`, `hash_fd`, all callers, `knowledge/durable.py` and every delivered test unchanged. Staging walk (fold-in): regular files staged, copied and hashed exactly as the snapshot digest (characterization `test_stage_walk_regular_files_unchanged`, passed before and after; delivered staging tests `tests/adapters/test_adapters_units.py`, `tests/guard/*` green and byte-identical); a FIFO listed as special keeps `irregular` / `special` (same test).
- **Conflicts:** none unexpected. Expected consequences: inputs that hung now get the existing refusal of their caller. Classified against the original observation O-1, DAO-003, DAO-004 and AC-002B-01c/01d/02b/06a, design §Safe I/O / §Registration / §Execution. Inspected: `safe_io.py`, `registry_store.py`, `status.py` (`_registration`), `toolreq.py`, `toolrun.py`, `targets.py`, `trivy_request.py`, `trivy_run.py`, `trivy_fs.py`, `trivy_archive.py`, `durable.py`.

## Fix and Design Impact

`ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/safe_io.py` (125 → 129 lines, +4 / 2 lines modified):

- `NONBLOCK = getattr(os, "O_NONBLOCK", 0)` (L18, same pattern as `knowledge/durable.py`).
- Final open of `open_nofollow` with `| NONBLOCK` in both branches (L66 lstat/fstat branch, L76 POSIX `dir_fd` branch).
- `_check_regular` (L30–37): unchanged `fstat` `S_ISREG` refusal (`UnsafePath("<rel> is not a regular file")`, descriptor closed); for a regular file, `os.set_blocking(fd, True)` when `O_NONBLOCK` exists, then return.

Fold-in (DAO-004) — `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/targets.py` (479 → 481 lines, +2 / 1 line modified), `stage` → `walk`:

- L270: `os.open(entry.name, os.O_RDONLY | safe_io.NOFOLLOW | safe_io.NONBLOCK, dir_fd=dfd)`.
- L275–279: unchanged `fstat` `S_ISREG` check and refusal `UnsafePath("<rel> changed while staging")`; then `if safe_io.NONBLOCK: os.set_blocking(fd, True)` before hashing/copying — the helper's semantics (DEC-2), reused via `safe_io.NONBLOCK`. `safe_io._check_regular` itself is not called here because its message ("is not a regular file") would change this site's existing output.

Design impact: none on interfaces, data model or workflow — same function signatures, same exception, same message, no new code or output; the design's "`os.fstat` must show a regular file" is now reachable for FIFOs. No Design Change Log entry required; no other document edited. Alternatives rejected: an `lstat` pre-check before open (leaves the check-to-open swap window and duplicates the descriptor check); per-caller fixes (seven call sites, same defect); leaving `O_NONBLOCK` set on regular-file descriptors (harmless for today's reads, but DEC-2).

## Mini AAA and Actual Routing

New test file only: `scripts/tests/test_safe_io_nonregular.py` (12 tests: 10 in the first round + 2 for the DAO-004 fold-in; each FIFO call runs in a child process — library calls via `python -c`, `status` via the test launcher with the write audit — with a 20 s timeout, so a regression fails in ≤ 20 s per test instead of hanging; `Traceback` in stderr fails; FIFO tests skip on non-POSIX; the status/pre-check tests pick the official Opengrep digest for the current host from `digests.TABLE` and skip if none).

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| Shared helper, project-relative FIFO | `rules/fifo.yaml` FIFO | `open_nofollow(root, "rules/fifo.yaml")` | finishes; `UnsafePath` "rules/fifo.yaml is not a regular file"; FIFO intact | Python library, pytest (child process) | red: timeout; green: passed |
| Shared helper, absolute FIFO (×2) | absolute FIFO outside any project | `open_absolute_nofollow` / `hash_path` | `UnsafePath` "opengrep-bin is not a regular file" | same | red: 2 timeouts; green: passed |
| Registration (AC-002B-01c) | FIFO binary | `registry_store.inspect_binary` | Gap == `TOOL_PATH_INVALID`, "<path> is not a readable regular file (no symbolic links): opengrep-bin is not a regular file", "Pass the real binary file, not a link" | same | red: timeout; green: passed |
| Pre-check snapshot (AC-002B-01d) | record → FIFO, host-official digest | `registry_store.check(…, stage_bin)` | Gap == `TOOL_NOT_REGISTERED`, "The registered binary is missing or unreadable: opengrep-bin is not a regular file", register step; nothing staged | same | red: timeout; green: passed |
| Status (AC-002B-06a) | same record | `secure-code status --json` | exit 0; registered true; check == the reason above; next step == register step; no write (write audit) | Python CLI integration | red: timeout; green: passed |
| Status, folder (characterization) | record → folder | `status` | same reason/next step (existing branch) | same | passed before and after |
| Guard rule file (AC-002B-02b) | FIFO + regular rule file | `toolreq._rule_file` | FIFO → refusal "where: rules/fifo.yaml is not an existing regular local rule file without links (rules/fifo.yaml is not a regular file)"; regular → `("rules/ok.yaml", bytes)` | library (child process) | red: timeout; green: passed |
| Guard image archive target (002-D) | FIFO `image.tar` declared as file target | `trivy_request._archive` | refusal "where: image.tar is not a readable regular file without links (image.tar is not a regular file)" | same | red: timeout; green: passed |
| Regular file descriptor (preservation) | 3 MiB + 17 random bytes; a folder | `open_nofollow`, `hash_path` | descriptor in blocking mode (asserted where `O_NONBLOCK` exists; review fix); bytes and digest identical; folder → "sub is not a regular file" | library (in-process) | passed before and after |
| Staging walk, FIFO swapped in after the listing (AC-002B-01d; DAO-004) | folder `s/` with `a.py` and a FIFO; child process replaces `os.scandir` so the FIFO entry reports `is_file()` (deterministic swap) | `targets.stage(root, "s", "dir", …)` | finishes; `UnsafePath` "s/fifo changed while staging" (existing refusal → `STAGE_UNSAFE`); FIFO intact | library (child process, 20 s timeout) | red: timeout; green: passed |
| Staging walk, regular files (characterization) | `s/a.py`, `s/d/b.py` (70 000 random bytes), a real FIFO; same `scandir` wrapper (wrapped regular entry) | `targets.stage` | files == [`s/a.py`, `s/d/b.py`]; irregular == [`s/fifo`] (existing `special` outcome); digest == `snapshot` digest; staged bytes identical | same | passed before and after |

Routing: the enabled Python fix route was executed directly by this worker (no subagent, per task constraint): red → minimal fix → green → lint → full suite → host black-box regression.

## Verification

| Step | Command (from `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts`) | Result | Log (`<SESSION>/bugfix-100/`) |
| --- | --- | --- | --- |
| Reproduction, unfixed (`safe_io.py` `d4fee549…`) | `.venv/bin/python probe.py` | P1 (A14) status TIMEOUT; L1–L5 FIFO TIMEOUT; P2/P3/L5-control existing outcomes | `probe-before.log` |
| RED (unfixed, first test `7f1cc2c5…`) | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<SESSION>/bugfix-100/tmp/red tests/test_safe_io_nonregular.py` | **8 failed** (all "did not finish within 20s"), 2 passed (characterizations), exit 1 | `red.log`, `hashes-red.txt` |
| Lint | `UV_OFFLINE=1 uv run --offline ruff check --no-cache src tests` | first run: 5 × E501 in the new test → long expected strings moved into constants / wrapped (identical values; test `7f1cc2c5…` → `b53889b3…`); rerun **All checks passed**, exit 0 | `ruff.log` |
| GREEN (fixed `2c9923d8…`, final test `b53889b3…`) | same + `tests/adapters tests/test_status.py tests/test_module_size.py tests/guard/test_guard_units.py tests/guard/test_guard_tool.py tests/guard/test_guard_trivy.py tests/test_nonregular_toolkit_reads.py` | **465 passed, 2 skipped** (pre-existing non-UTF-8 skips), exit 0 | `green.log`, `hashes-green.txt` |
| RED re-confirmed with the final test | final test `b53889b3…` run (scripts `.venv` python) against a session copy of `src`/`tests` whose `safe_io.py` was reverted to the byte-identical unfixed hash `d4fee549…` | **8 failed** (timeouts), 2 passed, exit 1; copy removed afterwards | `red-final.log`, `hashes-red-final.txt` |
| Reproduction, fixed | `probe.py` | P1 status exit 0, check "The registered binary is missing or unreadable: opengrep-bin is not a regular file" + register step (= P2 folder wording); L1/L2 `UnsafePath` "… is not a regular file"; L3 `TOOL_PATH_INVALID`; L4 `TOOL_NOT_REGISTERED`, staged: False; L5 `TOOL_REQUEST_INVALID` refusal; controls unchanged; FIFOs intact | `probe-after.log` |
| Full suite (round 1: `safe_io.py` fixed, test `b53889b3…`) | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<SESSION>/bugfix-100/tmp/full -rs` | **2614 passed, 4 skipped, 23 deselected in 644 s, exit 0** (= 2604 at TASK-097 + 10 new); the 4 skips are the same pre-existing conditional skips (`adapters/test_adapters_units.py:510`, `guard/test_guard_units.py:685`, `knowledge/test_exit_review_fixes.py:272`, `presets/test_tags.py:59`) | `full-suite.log` |
| 002-B host black-box regression (round 1) | `cd x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/acceptance; TMPDIR=<SESSION>/bugfix-100/tmp/bb UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit PYTHONDONTWRITEBYTECODE=1 python3 blackbox.py host > <SESSION>/bugfix-100/blackbox-host.jsonl` | exit 0; TC-B-11 Pass, TC-B-10 Pass, summary 2/2; per entry index identical to `evidence-host-macos.jsonl` (status, checks, failed and summary; the file is byte-identical, `290c2607…`); the uvx-built package's `safe_io.py` hash = fixed `2c9923d8…` (`NONBLOCK` 4); acceptance folder listing unchanged by the run | `blackbox-host.jsonl`, `blackbox-host.stderr`, `acceptance-ls-before/after.txt` |
| Fold-in RED (`targets.py` unfixed `4fbcc3ce…`, test `68533d28…`) | `… pytest … --basetemp=<SESSION>/bugfix-100/followup/tmp/red tests/test_safe_io_nonregular.py` | **1 failed** (`test_stage_walk_fifo_swapped_in_refused_without_blocking`: "stage did not finish within 20s"), 11 passed (incl. the walk characterization), exit 1. (A first draft of the characterization used a 10 000-byte staging limit and failed on `TooLarge` — a test-setup error, not the reproduction; the limit was raised before this recorded RED.) | `followup/red.log`, `followup/hashes-red.txt` |
| Fold-in GREEN (`targets.py` `b186f52f…`, same test `68533d28…`) | same file + `tests/adapters tests/guard tests/test_module_size.py` | **1089 passed, 2 skipped** (pre-existing non-UTF-8 skips), 23 deselected, exit 0 | `followup/green.log`, `followup/hashes-green.txt` |
| Review finding fixed (test only) | `test_regular_file_descriptor_unchanged`: `hasattr(os, "get_blocking")` → `if safe_io.NONBLOCK:` (test `68533d28…` → `102ba212…`); then the new file alone | **12 passed**, exit 0 | `followup/green-final.log`, `followup/hashes-final.txt` |
| Lint (final) | `UV_OFFLINE=1 uv run --offline ruff check --no-cache src tests` | **All checks passed**, exit 0 | `followup/ruff.log` |
| Full suite (final: `safe_io.py` `2c9923d8…`, `targets.py` `b186f52f…`, test `102ba212…`) | as above, `--basetemp=<SESSION>/bugfix-100/followup/tmp/full -rs` | **2616 passed, 4 skipped, 23 deselected in 652 s, exit 0** (= 2604 + 12 new); same 4 pre-existing skips. (A run just before the review-fix edit, test `68533d28…`, gave the same 2616/4.) | `followup/full-suite.log` (`followup/full-suite-pre-review-fix.log`) |
| 002-B host black-box regression (final) | same command, `TMPDIR=<SESSION>/bugfix-100/followup/tmp/bb`, output to `followup/blackbox-host.jsonl` | exit 0; 2/2 Pass; byte-identical to `evidence-host-macos.jsonl` and to the round-1 regression file (`290c2607…`); the uvx-built package's `targets.py` / `safe_io.py` hashes = `b186f52f…` / `2c9923d8…`; acceptance folder listing unchanged by the run | `followup/blackbox-host.jsonl`, `followup/blackbox-host.stderr`, `followup/acceptance-ls-before/after.txt`; saved (overwritten, identical) as `acceptance/regression-TASK-100-host-macos.jsonl` |

Changed / added files:

| File | Lines | SHA-256 before | SHA-256 after |
| --- | --- | --- | --- |
| `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/safe_io.py` | 125 → 129 | `d4fee549319fb3d923ca20e96e0da5a7f71bd8c2c98b8f179b48e7ee9196e7c0` | `2c9923d8db45ec7d78a4b7be85b8307fba7559a7b409b39cc00b5e4ce8c115c2` |
| `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/targets.py` (fold-in) | 479 → 481 | `4fbcc3ce56c97c3388d02335e5ebe509aeac28a9085ff65447aa53dd56ae31a6` | `b186f52fce7334614116c5cd6fc2e46b6f8730644374ce89e301c8a83a09e91d` |
| `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/test_safe_io_nonregular.py` (new) | 289 | — | `102ba21271a0559f63a8a2b6dafe6fab3217f29a158e23973cc7c9d1a4c9ef84` (round 1 `b53889b3…`; fold-in `68533d28…`; review fix → final) |
| `x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/acceptance/regression-TASK-100-host-macos.jsonl` (new) | 3 | — | `290c260700e86553d8d3cf8438e8280190e94aa025711e76ffc1a85fbf3a3805` |

Toolkit file-list hash (`cd ai-secure-code-toolkit; find . -type f` excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage*` `-exec shasum -a 256 {} +`, `./` stripped, `LC_ALL=C sort -k2`, `shasum -a 256`): before 244 files `cb09bb7c00ad7d34f8c6d31f3e8c5a99766c4436334fe9c3e261e9ae34ed7095` (= TASK-097 final); after round 1 245 files `6f95414243b3be819299c24b9a00c58ad0a8bb129a82c2694b6a4152c80108f8`; final 245 files **`22b03da5c734090e510ebdaeac60af5ac8bc89cdb8984bd8d63dd7a8d4e0b7a6`**; the diff to `cb09bb7c…` is exactly `safe_io.py`, `targets.py` and the new test, so every delivered 002-A/002-B/002-D test, fixture and other source is byte-identical (e.g. `registry_store.py` `e26a36ac…`, `tests/test_nonregular_toolkit_reads.py` `afca6518…`). Hygiene: no build, cache or test artifacts under `ai-secure-code-toolkit/` (no `__pycache__`, `.pytest_cache`, `.ruff_cache`, `*.egg-info`, `build`, `dist`); the black-box run left nothing in the acceptance folder (listing identical; its temp projects went to the session `TMPDIR`); nothing created in the workspace `.x-ipe/` or `x-ipe-docs/secure-code/` (neither exists); session scratch projects, the reverted copy and pytest/black-box temp folders removed (`chmod -R u+w` before `rm`).

Independent review (owner-run, round 1 / `safe_io` part): **PASS-WITH-FIXES**, one finding — `test_regular_file_descriptor_unchanged` guarded the blocking-mode assertion with `hasattr(os, "get_blocking")`; on Windows with Python ≥ 3.12 `os.get_blocking` exists but raises `OSError` for a regular-file descriptor, so the test would fail there. **Fixed:** the assertion is guarded with `if safe_io.NONBLOCK:` (the same condition under which the helper restores blocking mode); test only, no source change (verification rows "Review finding fixed", final full suite). Review of the fold-in delta (`targets.py` + the two walk tests) and re-review of the fix: owner's step.

Engineering delivery: verified by the checks above. Stakeholder outcome: not measured.

## Decisions (for the representative / owner)

- **DEC-1 (refusal code):** no new code or message. The helper raises its existing `UnsafePath("<rel> is not a regular file")`; each caller keeps its existing mapping. For `status` and the Guard pre-check this is `TOOL_NOT_REGISTERED` "The registered binary is missing or unreadable: …" with the register next step — the branch a folder at the registered path already took (P2 / characterization test). Conservative choice under the spec even though the code name says "not registered"; renaming or adding a code would be a new output (out of DAO defect-fix authority).
- **DEC-2 (clear `O_NONBLOCK`):** cleared with `os.set_blocking(fd, True)` right after the `S_ISREG` check (DAO-003 "clear `O_NONBLOCK` before reading if needed"). Not strictly needed for today's callers (regular-file reads ignore it on macOS/Linux) but it hands every current and future caller the same blocking descriptor as before. `knowledge/durable.read` (FEATURE-001-B module, reads in place and closes) is not changed.
- **DEC-3 (scope):** fixed once in the shared helper (both branches); no caller changed. The uniform "`O_NONBLOCK` + `fstat` on the descriptor" pattern now covers every `safe_io.open_nofollow` / `open_absolute_nofollow` / `hash_path` read, which closes the check-to-open swap window for these paths (DAO-003 swap-race note).
- **DEC-4 (staging-walk fold-in, DAO-004):** `guard/targets.py` `stage` → `walk` opens with `safe_io.NONBLOCK` and restores blocking mode after its existing `S_ISREG` check (same semantics as DEC-2, flag reused from `safe_io`). An entry that is not a regular file when opened keeps the existing outcome `UnsafePath("<rel> changed while staging")` → `STAGE_UNSAFE`; entries listed as special keep `special` / `irregular`. `safe_io._check_regular` is deliberately not called there, because its message would change this site's output. No new code, no output change; delivered tests byte-identical. Deterministic RED by simulating the swap (child-process `os.scandir` wrapper), as DAO-004 required.

## Honest Limits

- The CLI-level reproduction and test cover `status` (AC-002B-06a). Registration (`tools register`, needs Maintainer authorization), the Guard pre-check snapshot, rule-file and archive validation and the staging walk are verified at library level (the exact functions the commands call), not through full Maintainer-authorized CLI runs. `targets.stage` (file kind), `trivy_run` staged archives and the `toolrun` rule re-hash are covered by code reading only (same helper, existing `UnsafePath` handling); no test was added for them.
- The staging-walk swap is simulated (the `scandir` entry is made to report a regular file); a real concurrent swap was not raced. Previously listed here as an open limit (`guard/targets.py` L270 blocking open) — now **fixed** under DEC-4.
- **Observation O-3 (not fixed, Low, outside DAO-004 scope):** `guard/targets.py` `file_digest` (L79–84) reads with a path-based `open()` and no regular-file check on the descriptor. It is reached by `snapshot` for a file-kind target (L199; e.g. via `observe`, used by the after-run comparison in `toolrun.py:390`) and by the folder digest walk `_walk` (L113–115, after `scandir` `is_file()`). A FIFO is refused or classified before the read (`kind_of` raises / `observe` returns "unsafe"; `_walk` yields `special`), so only a swap between that check and the path-based `open()` could block — the same check-to-open window this task closed for `safe_io` and the staging walk. Different read path (path-based, not `safe_io`), so not folded in; candidate for the owner.
- FIFO tests skip on non-POSIX; status/pre-check tests skip on a host without an official Opengrep build. Only the macOS host was exercised here; the 002-D container regression runs at its B9 acceptance (per DAO-003), and the 002-B container black-box was not re-run.
- Other special files (character/block devices) take the same non-blocking path to the same refusal; not separately tested.

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
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/safe_io.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/targets.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/test_safe_io_nonregular.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/acceptance/regression-TASK-100-host-macos.jsonl"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/bug-report-TASK-100.md"
  bug_severity: "Low"
  root_cause: "safe_io.open_nofollow (used by open_absolute_nofollow/hash_path) opened the final component with a blocking os.open before its fstat regular-file check, so a FIFO at a registered binary path, rule file or archive target blocked status, registration inspection, the Guard pre-check snapshot and Guard request validation; the Guard staging walk (guard/targets.py stage) had the same blocking open for an entry swapped for a FIFO after the folder listing (folded in, DAO-004)"
  conflicts_found: []
```

One lifecycle owner (Sage) handles independent review, completion and routing; this child made no board, Git, memory or app writes and ran no successor.

## Representative Decisions Note (2026-10-24)

- Representative DAO-004 (`x-ipe-docs/dao/26-10-23/decisions_made_bug_fix.md`) approved DEC-1…3 and folded the `guard/targets.py` staging-walk open into TASK-100 under conditions (deterministic RED, existing outcome unchanged, no new code, delivered tests byte-identical, full suite + 002-B host regression again, delta review). Conditions 1, 2 and 4 are met above (DEC-4; RED 1 timeout → GREEN; full suite 2616/4 skips; host regression identical); condition 3 (delta review) is the owner's step.
- Owner-run independent review of the `safe_io` part: PASS-WITH-FIXES; its one finding (Windows `get_blocking` guard in the new test) is fixed above.

## Closing Addendum (2026-10-24, appended by Sage)

- Independent review: `safe_io` part PASS-WITH-FIXES (Windows `get_blocking` test guard, fixed); delta re-review of the walk fold-in and test fix **PASS** (with unfixed `targets.py` in an isolated copy the swap test times out; fixed: passes).
- Representative DAO-005: TASK-100 closes; O-3 (`targets.file_digest` path open after type check) registered as a separate Low bug-fix task after TASK-099.
- Final revision: `safe_io.py` `2c9923d8…`, `targets.py` `b186f52f…`, test `102ba212…`; full suite 2616 passed / 4 pre-existing skips; 002-B host regression identical. The 002-D container regression is deferred to its B9 acceptance.
