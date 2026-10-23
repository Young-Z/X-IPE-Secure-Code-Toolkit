# Bug Report — TASK-079: plain `secure-code init` crashes on an unreadable host entry file

## Reported Behavior

- **Source / authority:** human decision `bug yes` (x-ipe-docs/dao/26-10-23/human_decisions.md, 2026-10-23 20:38: "Bug fix: plain `init` crashes on an unreadable `AGENTS.md` (FEATURE-001-A)"). Candidate first recorded in the FEATURE-003-B technical design, "Code review fixes" → DAO-001 conditions → *Scope*: "Plain `init` still raises `PermissionError` on an unopenable `AGENTS.md` … recorded as a bug candidate".
- **Task:** TASK-079, lifecycle owner Sage; this worker: Bug Fix child, free-mode (no workflow action), interaction mode `dao-represent-human-to-interact` (no waiting; decisions listed below). No board, Git, memory or `.github/skills` writes.
- **Severity:** Medium — a refusal case of an otherwise working command ends in a traceback with no result, no stable code and no next step; nothing is written and no data is lost.
- **Actual (unfixed):** `secure-code init --project P --env github-copilot --json` with an existing `P/AGENTS.md` of mode 000 → uncaught `PermissionError: [Errno 13] Permission denied` traceback, exit 1, no JSON result.
- **Expected (source-authorized):** refused with the existing blocking problem `HOST_ENTRY_UNREADABLE`, the reason, the standard blocked-init next step, and nothing written — the same refusal as a non-UTF-8 host entry file.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-06 (host entry fragment; user content never overwritten) | 001-A spec G-06, US-08, FR-001A-9; edge-case table "Host entry file is not valid UTF-8 or not writable → Refuse the fragment step with reason; nothing reported as success"; Non-functional "when something is … refused, the reason and exactly one next step"; 001-A technical design §Algorithms "Blocking problems (… fragment duplicate/unreadable) → return before any write", "Decode as UTF-8 (strict) else `HOST_ENTRY_UNREADABLE`", problem-code list | Maintainer, Developer (and the calling agent) | An unopenable host entry file is refused with `HOST_ENTRY_UNREADABLE`, a reason and one next step; no file, folder or record is written; the user's file is untouched | Restores the refusal branch of the existing fragment step for a second "unreadable" cause (cannot be opened, beside not UTF-8) | No new code, outcome, next step or AC text; FEATURE-001-A output for every other input unchanged; FEATURE-003-B rule "plain `init` keeps exactly FEATURE-001-A behaviour" and the 001A baseline fixture unchanged | AC-001A-04h (Integration) refusal branch; FR-001A-9; spec edge case | chmod-000 `AGENTS.md` / `CLAUDE.md`, fresh and already-initialized project | Red 3 failed (traceback) → green 4 passed; full suite 2502 passed | Not measured (engineering delivery only) |

## Reproduction

Environment: macOS (darwin, aarch64), non-root user, uv-managed CPython 3.14.6, `uvx --offline` build of the toolkit scripts from the workspace. Unfixed `project_init.py` SHA-256 `7a66080ea2fcf0d742da54a039853eeb050b7f688b37f69517fa9b5ccdc5415d`.

```
mkdir P; printf '# My agent notes\n' > P/AGENTS.md; chmod 000 P/AGENTS.md
PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uvx --offline --from <toolkit scripts> secure-code init --project P --env github-copilot --json
```

Observed (`<SESSION>/bugfix-079/repro.log`): exit 1, no stdout, traceback
`cli.py:298 run → project_init.py:96 initialize_project → :118 _locked_body → :168 _plan_and_apply: data = host.read_bytes() if host.exists() else None → PermissionError: [Errno 13] Permission denied: '…/P/AGENTS.md'`. Project tree afterwards: only `P/AGENTS.md` (nothing written — the crash happens during planning).

## Root Cause

`project_init._plan_and_apply` (FEATURE-001-A implementation, kept by FEATURE-003-B) reads the host entry file with `host.read_bytes() if host.exists() else None` without handling `OSError`. `host_fragment.plan_upsert` only knows the non-UTF-8 kind of "unreadable"; a file that exists but cannot be opened raises before planning completes, so the exception propagates through `initialize_project` and `cli.run` to the top-level handler, which prints a traceback. Implementation error, not a design flaw: the design already names the outcome (`unreadable`), the code (`HOST_ENTRY_UNREADABLE`) and its blocking nature. The read happens inside the project lock (`ProjectLock` only flocks the root folder, no file); the OS releases it on process exit, so no stale state remains.

Inspected callers/dependents: `cli.run` (init) → `initialize_project` → `_locked_body` → `_plan_and_apply`; `host_fragment.plan_upsert`/`FragmentPlan` (only caller: `project_init`); `_accepted_exception` (requires `data`); `carriers._plan_kind` and `status._host` (already fixed for this input in FEATURE-003-B TASK-062 with `HOST_ENTRY_UNREADABLE` / `FRAGMENT_UNREADABLE`).

## Scope and Conflicts

- **Affected:** only the plain-`init` path when the host entry file exists and `open` fails (`OSError`, e.g. permission denied; symlinks and non-file paths are still refused earlier as `PATH_UNSAFE`). Previously a traceback; now a refusal.
- **Unaffected (verified):** every other init input — fresh/re-run/edited/duplicate/malformed/non-UTF-8 host entry, `--replace`, accepted customizations (003-B 01h/01i), lock paths, symlink/PATH_UNSAFE refusals; `carriers` and `status` (not touched); FEATURE-001-A 001A-baseline fixture comparison (`tests/carriers/test_project_lock.py`) green and unchanged.
- **Conflicts:** none unexpected. Expected consequence: an input that ended in a traceback now gets a refusal. Classified against the original report and the 001-A spec/design clauses above; consistent with FEATURE-003-B DAO-001 handling of the same input in `carriers` (`HOST_ENTRY_UNREADABLE`, path named, nothing written) and `status`.
- **Observation, not fixed (out of scope):** `_plan_file` hashes an existing *skill* target file with `sha256_file(target)` without handling `OSError`; an unopenable file inside the environment's skills folder would likely also end in a traceback. Not reproduced or changed here; candidate for the owner.

## Fix and Design Impact

`ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/project_init.py` (+8 lines, 288 → 296): the host-entry read is wrapped in `try/except OSError`; on failure the fragment plan becomes the existing blocking outcome `FragmentPlan("unreadable", None, sha256_text(body), Problem("HOST_ENTRY_UNREADABLE", "Host entry file <host_entry> cannot be read (<strerror>)"), blocking=True)` and `_accepted_exception` is skipped (there is no content to compare). The existing blocked branch then returns `ok: false`, `data.fragment: "unreadable"`, next step "Resolve the listed problems; nothing was written", exit 1, before any write. `FragmentPlan` is imported from `host_fragment`; `host_fragment.py` and `cli.py` are unchanged.

Design impact: none on interfaces, data model or workflow (existing outcome, problem code and blocked path; no new code in `cli-contract.md`). No Design Change Log entry required. Alternative considered: extending `host_fragment.plan_upsert` to accept an error — rejected as a wider signature change of the shared carrier writer.

## Mini AAA and Actual Routing

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| AC-001A-04h refusal branch, both environments | fresh project, `AGENTS.md` / `CLAUDE.md` with user text, mode 000 | CLI `init --env … --json` | no traceback; exit 1; `ok` false; `fragment` `unreadable`; problems == [`HOST_ENTRY_UNREADABLE`], message names the file and "cannot be read"; next steps == ["Resolve the listed problems; nothing was written"]; no write (write audit) and tree unchanged; no `.x-ipe`/`x-ipe-docs`; user text intact | Python CLI integration, pytest (project conventions, `run_cli`, `write_audit`) | red: failed (PermissionError traceback); green: passed |
| Re-init of an installed project | `init` succeeded; `AGENTS.md` mode 000 | `init` again | same refusal; no write; tree/record unchanged; readable again → `already_current` true | same | red: failed (traceback); green: passed |
| Preservation: non-UTF-8 host entry | `AGENTS.md` = `\xff\xfe …` | `init` | exit 1; `fragment` `unreadable`; problems == [{`HOST_ENTRY_UNREADABLE`, "Host entry file is not UTF-8"}]; same next step; tree unchanged | same | passed before and after (characterization) |

Routing: the enabled Python fix route was executed directly in this session by the same worker (no subagent, per task constraint): red → minimal fix → green → full suite → ruff. New test file only: `scripts/tests/test_project_init_unreadable_host_entry.py` (4 tests; POSIX non-root tests skip as root/Windows, like the existing 003-B tests).

## Verification

| Step | Command (from `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts`) | Result | Log (`<SESSION>/bugfix-079/`) |
| --- | --- | --- | --- |
| Reproduction, unfixed | `uvx --offline --from <scripts> secure-code init --project P --env github-copilot --json` (AGENTS.md mode 000) | exit 1, `PermissionError` traceback, no result, nothing written | `repro.log` |
| RED (unfixed `project_init.py` `7a66080e…`) | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=… tests/test_project_init_unreadable_host_entry.py` | 3 failed (all `assert 'Traceback' not in …`, PermissionError at `project_init.py:168`), 1 passed (non-UTF-8 characterization) | `red.log` |
| GREEN (fixed `65100976…`, unchanged test `2c0575ed…`) | same file + `tests/test_project_init.py tests/test_host_fragment.py tests/test_status_unreadable_host_entry.py tests/test_status.py tests/carriers` | 296 passed | `green.log` |
| Reproduction, fixed | same uvx command, JSON and text mode | exit 1, `ok: false`, `fragment: unreadable`, `[HOST_ENTRY_UNREADABLE] Host entry file AGENTS.md cannot be read (Permission denied)`, next step "Resolve the listed problems; nothing was written"; tree still only `P/AGENTS.md` | `repro-fixed.log` |
| Full suite | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<SESSION>/bugfix-079/tmp` | **2502 passed, 4 skipped, 23 deselected in 623.46 s, exit 0** (no write-audit / protected-tree report). The 4 skips, identified with `-rs` (`skips.log`, 1758 passed, exit 0), are pre-existing environment/conditional skips, none in the new file: `adapters/test_adapters_units.py:510` and `guard/test_guard_units.py:685` (file system rejects non-UTF-8 names), `knowledge/test_exit_review_fixes.py:272` (delete has no append step), `presets/test_tags.py:59` (conditional on FEATURE-001-E) | `full-suite.log` |
| Lint | `uv run --offline ruff check --no-cache src tests` | All checks passed, exit 0 | `ruff.log` |

Changed / added files (paths under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/`):

| File | Lines | SHA-256 |
| --- | --- | --- |
| `src/x_ipe_secure_code/project_init.py` (changed; before `7a66080ea2fcf0d742da54a039853eeb050b7f688b37f69517fa9b5ccdc5415d`) | 296 | `65100976a407051770e0aec87e172f8a2890f58a4c0ff8988cf4fdebd64cfdbe` |
| `tests/test_project_init_unreadable_host_entry.py` (new) | 105 | `2c0575ed06bf86fd7a3a7bc940dca024adb6be57dbca4f467087b9be4b4aa700` |

Unchanged (verified byte-identical): `host_fragment.py` `9913629a…`, `cli.py` `ce386af4…`, `tests/test_project_init.py` `2f56555b…`, `tests/test_host_fragment.py` `2b0bb8e6…`, `tests/carriers/test_project_lock.py` `2ad04afa…`, `tests/carriers/fixtures/init_001a_baseline.json` `bcd46231…`, `tests/test_status_unreadable_host_entry.py` `705d7a0f…`, `tests/carriers/test_review_fixes.py` `39dde59f…`. No delivered test was modified.

Toolkit file-list hash (`cd ai-secure-code-toolkit; find . -type f` excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage*` `-exec shasum -a 256 {} +`, `./` stripped, `LC_ALL=C sort -k2`, `shasum -a 256`): 239 files, **`7b4166bc73a4e55806b60770044ea7ff51a3cd7490bdb4bfafd19146e6d1ca71`**. Hygiene: no build, cache or test artifacts left under `ai-secure-code-toolkit/`; scratch projects and pytest temp folders lived in the session folder and were removed.

Independent review: not run in this child (owner's next step; the change touches a public CLI refusal path).

Engineering delivery: verified by the checks above. Stakeholder outcome: not measured.

## Decisions (for the representative / owner)

- **DEC-1 (behaviour):** an existing but unopenable host entry file is refused exactly like a non-UTF-8 one — same code `HOST_ENTRY_UNREADABLE`, same `fragment: "unreadable"`, same blocked next step, nothing written. Source: 001-A spec edge case + design blocking list and problem codes; consistent with FEATURE-003-B `carriers` for the same input. No AC text changed.
- **DEC-2 (message wording):** "Host entry file <name> cannot be read (<OS reason>)" — names the file (as `carriers` does) and the OS reason (spec "refuse … with reason"); the non-UTF-8 message stays byte-identical ("Host entry file is not UTF-8").
- **DEC-3 (next step):** reuse the existing blocked-init next step ("Resolve the listed problems; nothing was written") instead of a new file-specific one, keeping plain init's output set unchanged (003-B "plain init keeps exactly FEATURE-001-A behaviour").
- **DEC-4 (scope):** the analogous unhandled read of an unopenable skill target file in `_plan_file` is recorded as an observation only (not reproduced, not fixed).

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
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/project_init.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/test_project_init_unreadable_host_entry.py"
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/bug-report-TASK-079.md"
  bug_severity: "Medium"
  root_cause: "project_init._plan_and_apply read the host entry file without handling OSError, so an existing but unopenable AGENTS.md/CLAUDE.md raised PermissionError instead of the designed blocking HOST_ENTRY_UNREADABLE refusal"
  conflicts_found: []
```

One lifecycle owner (Sage) handles independent review, completion and routing; this child made no board, Git, memory or app writes and ran no successor.

## Closing Addendum (2026-10-23, appended by Sage)

- Independent code review: **PASS** (fix correct and complete; refusal before any write; no delivered test changed; 285 related tests passed).
- Representative DAO-001 (`x-ipe-docs/dao/26-10-23/decisions_made_bug_fix.md`): DEC-1…DEC-3 approved; DEC-4 routed to a separate bug-fix task.
- **DEC-4 correction:** the reviewer **reproduced** it — an existing but unreadable skill file (e.g. `.github/skills/x-ipe-secure-code-toolkit-framework/SKILL.md` with mode 000) still crashes plain `init` with a `PermissionError` traceback in `_plan_file` → `install_record.sha256_file` (nothing written). Tracked as TASK-095 together with a pre-existing Low issue: `init` blocks indefinitely on a FIFO named `AGENTS.md`/`CLAUDE.md` (not a regression of this fix).
- 001-A black-box regression (host, macOS) at the final revision: 13/13 cases Pass, statuses identical to the original evidence; only temp paths and timings differ (`acceptance/regression-TASK-079-host-macos.jsonl`). Container regression not re-run (no Maintainer path involved).
- Full suite at the fix revision: 2502 passed, 4 skipped, 23 deselected, 0 failed; ruff clean. Toolkit file-list hash `7b4166bc73a4e55806b60770044ea7ff51a3cd7490bdb4bfafd19146e6d1ca71` (239 files).
