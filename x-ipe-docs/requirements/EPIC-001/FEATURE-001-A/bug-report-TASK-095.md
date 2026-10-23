# Bug Report — TASK-095: plain `secure-code init` crashes on an unreadable skill target and blocks on a FIFO host entry

## Reported Behavior

- **Source / authority:** TASK-079 closing addendum (`bug-report-TASK-079.md`, "DEC-4 correction": the independent reviewer reproduced the unreadable skill file crash; plus a pre-existing Low FIFO issue). Representative DAO-001 (`x-ipe-docs/dao/26-10-23/decisions_made_bug_fix.md`): defect fix within DAO defect-fix authority — reproduce first with a failing test; refuse with a reason before any write, using an existing problem code where one fits; delivered tests and 001-A baselines byte-identical.
- **Task:** TASK-095, lifecycle owner Sage; this worker: Bug Fix child, free-mode (no workflow action), interaction mode `dao-represent-human-to-interact` (no waiting; decisions listed below). No board, Git, memory or `.github/skills` writes; no subagents; no network.
- **Bug 1 — Medium.** Actual (unfixed): `init` on a project whose skill target file exists but cannot be opened (installed `.github/skills/x-ipe-secure-code-toolkit-framework/SKILL.md` mode 000, or a foreign mode-000 file at that path on a fresh project) → uncaught `PermissionError` traceback, exit 1, no result. Expected: refused with a reason and the blocked-init next step, nothing written; on a fresh project the foreign file is a `SKILL_NAME_CONFLICT`.
- **Bug 2 — Low (pre-existing).** Actual (unfixed): `init` with `AGENTS.md` / `CLAUDE.md` being a FIFO blocks indefinitely in `host.read_bytes()` while holding the project lock. Expected: a non-regular host entry is refused with `HOST_ENTRY_UNREADABLE` (as `status`/`carriers` check `is_file()`), nothing written.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Safe install / upgrade (skill files) | 001-A spec edge cases L191 "non-toolkit skill with the same name → refuse, report the conflict" and L192 "Read-only filesystem or permission denied during install → Fail with reason; no partial install reported as success (NFR-001A-5)"; 001-A design §A plan table ("no record … → `conflict` → `SKILL_NAME_CONFLICT` (blocking); no provenance is guessed") and "Blocking problems … → return before any write"; problem codes (design L210, `cli-contract.md`) | Maintainer, Developer, calling agent | An unreadable skill target is refused with a stable code, the file and OS reason, one next step; nothing written | Restores the refusal branch of the plan step for "target cannot be hashed" (fresh foreign file → existing conflict branch; recorded file → existing `IO_ERROR`) | Existing codes only; no new output key/next step; every other init output unchanged (003-B "plain init keeps exactly FEATURE-001-A behaviour", 001A baseline fixture) | AC-001A-04a / AC-001A-05a…05c (Integration) refusal branch | mode-000 skill file: fresh foreign and re-init | Red: 3 failed (traceback) → green: passed | Not measured |
| G-06 host entry fragment | 001-A spec G-06, AC-001A-04h, edge case "Host entry file is not valid UTF-8 or not writable → Refuse the fragment step with reason"; design L266 "else `HOST_ENTRY_UNREADABLE`"; TASK-079 DEC-1…3 (DAO-001 approved) | same | A host entry path that exists but is not a regular file is refused like an unopenable one, without blocking | Second "cannot be opened" cause on the TASK-079 path | Same as above | AC-001A-04h (Integration) refusal branch | FIFO `AGENTS.md` / `CLAUDE.md`, fresh and re-init | Red: 3 failed (30 s timeout) → green: passed | Not measured |

## Reproduction

Environment: macOS (darwin, aarch64), non-root user, uv-managed CPython 3.14, `uvx --offline` build of the workspace toolkit scripts. Unfixed `project_init.py` SHA-256 `65100976a407051770e0aec87e172f8a2890f58a4c0ff8988cf4fdebd64cfdbe` (= TASK-079 fixed revision). Driver: `<SESSION>/bugfix-095/repro.py` (scratch projects under the session folder; subprocess timeout for the FIFO).

```
# 1a  init P1 (ok) ; chmod 000 P1/.github/skills/x-ipe-secure-code-toolkit-framework/SKILL.md ; init P1
# 1b  mkdir -p P2/.github/skills/x-ipe-secure-code-toolkit-framework ; echo '# my own skill' > …/SKILL.md ; chmod 000 …/SKILL.md ; init P2
# 2   mkfifo P3/AGENTS.md ; init P3   (subprocess timeout 20 s)
PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uvx --offline --from <toolkit scripts> secure-code init --project P --env github-copilot --json
```

Observed (`<SESSION>/bugfix-095/repro.log`): 1a and 1b exit 1, no stdout, traceback `project_init.py line 46, in _plan_file: disk = sha256_file(target)` → `install_record.py line 135 open(path, "rb")` → `PermissionError: [Errno 13] Permission denied: '…/SKILL.md'`; 1b tree afterwards only the user's file (nothing written). 2: `TIMEOUT: no exit within 20s (process killed)`; tree afterwards only the FIFO.

## Root Cause

Implementation errors, not design flaws (the design already names the blocking outcomes and codes):

1. `project_init._plan_file` hashes an existing skill target with `sha256_file(target)` without handling `OSError`. A target that exists but cannot be opened raises during planning; the exception propagates `_plan_and_apply` → `_locked_body` → `initialize_project` → `cli.run` and is printed as a traceback. The same unguarded `open` also blocks indefinitely on a FIFO at a skill path (`unsafe_component` only distinguishes folder vs. non-folder).
2. `project_init._plan_and_apply` reads the host entry with `host.read_bytes() if host.exists()`. `exists()` is true for a FIFO and `open()` of a FIFO without a writer blocks; this happens inside `ProjectLock`, so the lock is held until the process is killed (the OS releases the flock on exit; no stale state). `status` and `carriers` already require `is_file()` for this input.

Inspected callers/dependents: `cli.run` → `initialize_project` → `_locked_body` → `_plan_and_apply` → `_plan_file` / `_summary`; `FilePlan` is private to `project_init` (no other importer); `host_fragment.plan_upsert`/`FragmentPlan`, `_accepted_exception` (needs `data`), `_host_body` (`routing.load_file` already requires a regular file); `paths.unsafe_component` (shared; not changed); `install_record.sha256_file` (shared; not changed); `carriers.py` L174/L299 and `status.py` L52/L75 (already `is_file()`).

## Scope and Conflicts

- **Affected:** only plain `init` when an existing skill target or the host entry path cannot be read (OS error or not a regular file). Previously traceback / hang; now a blocked refusal before any write.
- **Unaffected (verified):** all readable inputs — create/current/update/locally_edited/replace/conflict planning, the readable foreign-skill conflict message (characterization test, passed before and after), fragment outcomes incl. TASK-079 unreadable/non-UTF-8, `--replace`, 003-B accepted customizations, lock paths, `PATH_UNSAFE` refusals; `carriers`, `status`, `paths`, `install_record`, `host_fragment`, `cli` unchanged; 001A baseline fixture comparison (`tests/carriers/test_project_lock.py`, `fixtures/init_001a_baseline.json`) green and byte-identical.
- **Conflicts:** none unexpected. Expected consequences: inputs that crashed or hung now get a refusal. Classified against the original report and the 001-A spec/design clauses above.
- **Observation, not fixed (out of scope, not reproduced):** `install_record.load` reads `.x-ipe/private/secure-code/install-record.json` with `read_text` after `exists()`; a FIFO at that toolkit-owned path would also block `init`. Candidate for the owner.

## Fix and Design Impact

`ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/project_init.py` (+17/−4, 296 → 309 lines):

- `FilePlan` gains a private field `read_error: str | None = None` (internal dataclass, not output).
- `_plan_file`: an existing target that is not a regular file, or whose hashing raises `OSError`, is planned as the existing blocking outcome `conflict` with the reason (`strerror`, or "not a regular file"); no content is guessed and the file is never overwritten (also with `--replace`).
- Problems for conflicts: unchanged message for readable foreign files; unreadable target **not** in the install record → `SKILL_NAME_CONFLICT` "`<t>` exists and was not placed by this toolkit; it cannot be read (`<reason>`)"; unreadable target **in** the record → `IO_ERROR` "Skill file `<t>` cannot be read (`<reason>`)". Both are listed in `data.files.conflicts` and go through the existing blocked branch: `ok: false`, next step "Resolve the listed problems; nothing was written", exit 1.
- Host entry: an existing path that is not a regular file raises `OSError("not a regular file")` into the TASK-079 handler → `fragment: "unreadable"`, `HOST_ENTRY_UNREADABLE` "Host entry file `<name>` cannot be read (not a regular file)", before any open.

Design impact: none on interfaces, data model or workflow — existing outcomes, existing problem codes, existing next step, no new output key; no Design Change Log entry required. Alternatives rejected: changing shared `paths.unsafe_component` to require regular files (would turn the host FIFO into `PATH_UNSAFE` against the requested `HOST_ENTRY_UNREADABLE` and change `carriers`/`status`/record callers); a new summary key or problem code (new output kind).

## Mini AAA and Actual Routing

New test file only: `scripts/tests/test_project_init_unreadable_targets.py` (8 tests; CLI via the test launcher with a 30 s timeout so a blocking read fails instead of hanging; permission tests skip as root/non-POSIX, FIFO tests skip on non-POSIX).

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| Fresh foreign unreadable skill file, both envs (AC-001A-04a refusal / spec L191, L192) | fresh project, `<skills>/x-ipe-secure-code-toolkit-framework/SKILL.md` user text, mode 000 | `init --env … --json` | no traceback; exit 1; `ok` false; next steps == blocked step; problems == [`SKILL_NAME_CONFLICT`] naming the file + "cannot be read"; `files.conflicts` == [file]; write audit empty; tree unchanged; no host entry, `.x-ipe`, `x-ipe-docs`; user text intact | Python CLI integration, pytest | red: 2 failed (traceback); green: passed |
| Re-init, installed skill file mode 000 (AC-001A-05a…05c refusal / L192) | `init` ok; chmod 000 SKILL.md | `init` again | as above with problems == [`IO_ERROR`] naming file + "cannot be read"; `files.conflicts` == [file]; no write; tree/record unchanged; readable again → `already_current` true | same | red: failed (traceback); green: passed |
| FIFO host entry, fresh, both envs (AC-001A-04h refusal) | `mkfifo AGENTS.md` / `CLAUDE.md` | `init` | finishes < 30 s; exit 1; `fragment` `unreadable`; problems == [`HOST_ENTRY_UNREADABLE`] naming file, "cannot be read", "not a regular file"; no write; tree unchanged; still a FIFO; no `.x-ipe`/`x-ipe-docs` | same | red: 2 failed (timeout); green: passed |
| FIFO host entry, re-init | `init` ok; AGENTS.md replaced by FIFO | `init` | same refusal; no write; tree/record unchanged; regular file restored → `already_current` true | same | red: failed (timeout); green: passed |
| FIFO at a skill path, fresh | `mkfifo …/SKILL.md` | `init` | no hang; problems == [`SKILL_NAME_CONFLICT`] with "not a regular file"; no write; still a FIFO | same | red: failed (timeout); green: passed |
| Preservation: readable foreign skill conflict | foreign readable SKILL.md | `init` | problems == exactly the unchanged FEATURE-001-A message | same | passed before and after (characterization) |

Routing: the enabled Python fix route was executed directly by this worker (no subagent, per task constraint): red → minimal fix → green → full suite → ruff.

## Verification

| Step | Command (from `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts`) | Result | Log (`<SESSION>/bugfix-095/`) |
| --- | --- | --- | --- |
| Reproduction, unfixed (`65100976…`) | `repro.py` (uvx CLI, cases 1a/1b/2) | 1a/1b `PermissionError` traceback, exit 1; 2 timeout after 20 s; nothing written | `repro.log` |
| RED (unfixed `65100976…`, test `56948315…`) | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=… tests/test_project_init_unreadable_targets.py` | **7 failed** (3 `assert 'Traceback' not in …` with `PermissionError` in `_plan_file`; 4 `init did not finish within 30s`), 1 passed (characterization), exit 1 | `red.log` |
| GREEN (fixed `ac770f8f…`, same test `56948315…`) | same file + `tests/test_project_init_unreadable_host_entry.py tests/test_project_init.py tests/test_host_fragment.py tests/test_status.py tests/test_status_unreadable_host_entry.py tests/test_module_size.py tests/carriers` | **305 passed**, exit 0 | `green.log` |
| Reproduction, fixed | `repro.py` | 1a exit 1, `IO_ERROR` "Skill file .github/skills/x-ipe-secure-code-toolkit-framework/SKILL.md cannot be read (Permission denied)"; 1b exit 1, `SKILL_NAME_CONFLICT` "… exists and was not placed by this toolkit; it cannot be read (Permission denied)", tree only the user's file; 2 exit 1 immediately, `fragment: unreadable`, `HOST_ENTRY_UNREADABLE` "Host entry file AGENTS.md cannot be read (not a regular file)", tree only the FIFO; all with next step "Resolve the listed problems; nothing was written" | `repro-fixed.log` |
| Lint | `uv run --offline ruff check --no-cache src tests` | first run: 1 × E501 in the new test's characterization assertion → wrapped into a local variable (same expected value; test `56948315…` → `3c2535bc…`; the 7 red assertions are textually unchanged); rerun **All checks passed**, exit 0 | `ruff.log` |
| Full suite (fixed `ac770f8f…`, test `3c2535bc…`) | `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<SESSION>/bugfix-095/tmp -rs` | **2511 passed, 4 skipped, 23 deselected in 618 s, exit 0**; the 4 skips are the same pre-existing environment/conditional skips as TASK-079 (`adapters/test_adapters_units.py:510`, `guard/test_guard_units.py:685`, `knowledge/test_exit_review_fixes.py:272`, `presets/test_tags.py:59`) | `full-suite.log` |

Changed / added files (paths under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/`):

| File | Lines | SHA-256 |
| --- | --- | --- |
| `src/x_ipe_secure_code/project_init.py` (changed; before `65100976a407051770e0aec87e172f8a2890f58a4c0ff8988cf4fdebd64cfdbe`) | 309 | `ac770f8f58a390edb6303d324a2a35bef34e91110ea64ab8f3cab235dc5b8739` |
| `tests/test_project_init_unreadable_targets.py` (new) | 181 | `3c2535bccd8824b7c17a6a2c3c01512c29d10e87150d187bceda471c8b296abe` |

Unchanged (verified byte-identical before/after): `install_record.py` `92cbaaf1…`, `host_fragment.py` `9913629a…`, `cli.py` `ce386af4…`, `tests/test_project_init.py` `2f56555b…`, `tests/test_project_init_unreadable_host_entry.py` `2c0575ed…`, `tests/test_host_fragment.py` `2b0bb8e6…`, `tests/carriers/test_project_lock.py` `2ad04afa…`, `tests/carriers/fixtures/init_001a_baseline.json` `bcd46231…`. No delivered test or baseline was modified.

Toolkit file-list hash (`cd ai-secure-code-toolkit; find . -type f` excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage*` `-exec shasum -a 256 {} +`, `./` stripped, `LC_ALL=C sort -k2`, `shasum -a 256`): before this fix 239 files `a868b97f2f541c4b2131be79e5042e8cc5889295c1cf891a6a60aab7593f5817`; after 240 files **`3d0f41ccbede14f530ae7ed34bbd2634ce3c41f971c4dd3a16fb57d9d9db54a0`** (diff: exactly the two files above). Note: the "before" list already differed from TASK-079's `7b4166bc…` in `policy/preset_scope.py` and `tests/presets/test_preset_scope.py` — changes from other work, not from this task. Hygiene: no build, cache or test artifacts under `ai-secure-code-toolkit/`; nothing created in the workspace `.x-ipe/` or `x-ipe-docs/secure-code/`; session scratch projects and pytest temp folders removed (`chmod -R u+rwx` before `rm`).

Independent review: not run in this child (owner's next step; public CLI refusal path changed).

Engineering delivery: verified by the checks above. Stakeholder outcome: not measured.

## Decisions (for the representative / owner)

- **DEC-1 (fresh foreign unreadable skill file):** existing outcome `conflict` → `SKILL_NAME_CONFLICT`; the existing message plus "; it cannot be read (`<OS reason>`)". Source: design plan table (no record → conflict, no provenance guessed) and spec L191; the owner's stated expectation. Readable-conflict message byte-identical.
- **DEC-2 (installed skill file unreadable on re-init):** existing code `IO_ERROR` "Skill file `<t>` cannot be read (`<OS reason>`)" (design: "OS error"; spec L192 "permission denied during install → fail with reason"), blocking, file listed in `data.files.conflicts` (no new summary key), existing blocked next step; also refused with `--replace` (nothing is overwritten unseen). Alternatives rejected: `SKILL_NAME_CONFLICT` (false — the record shows the toolkit placed it), `LOCALLY_EDITED` (non-blocking; would rewrite the record without verifying the file), a new code.
- **DEC-3 (non-regular host entry):** `HOST_ENTRY_UNREADABLE`, `fragment: "unreadable"`, reason "not a regular file", via the TASK-079 path (consistent with `status`/`carriers` `is_file()` checks); checked before any open, so the project lock is never held on a blocking read.
- **DEC-4 (scope):** a FIFO at a skill path is covered by the same `_plan_file` guard (same line, same defect class, would also hang under the lock) — refused as DEC-1/DEC-2 with "not a regular file". The analogous install-record FIFO (`install_record.load`) is recorded as an observation only.

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
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/test_project_init_unreadable_targets.py"
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/bug-report-TASK-095.md"
  bug_severity: "Medium"
  root_cause: "project_init hashed existing skill targets (_plan_file → sha256_file) without handling OSError or non-regular files, and opened an existing host entry without checking it is a regular file, so an unreadable skill file raised PermissionError and a FIFO AGENTS.md/CLAUDE.md blocked forever under the project lock instead of the designed blocking refusals"
  conflicts_found: []
```

One lifecycle owner (Sage) handles independent review, completion and routing; this child made no board, Git, memory or app writes and ran no successor.

## Closing Addendum (2026-10-23, appended by Sage)

- Independent code review: **PASS** (no defects in the change; non-regular checks before any open; nothing written on refusal; delivered tests and 001-A baselines unchanged; 305 related tests passed).
- Representative DAO-002 (`x-ipe-docs/dao/26-10-23/decisions_made_bug_fix.md`): DEC-1…DEC-3 approved (existing 001-A codes SKILL_NAME_CONFLICT / IO_ERROR / HOST_ENTRY_UNREADABLE). Residual check-to-open race for a regular file swapped for a FIFO by a concurrent writer is recorded as a Low honest limit.
- DEC-4 reproduced by the reviewer: a FIFO at `.x-ipe/private/secure-code/install-record.json` hangs `init`, `status` and `carriers` (`install_record.load` exists-then-read). Tracked as a separate low-priority bug task (TASK-097).
- 001-A black-box regression (host, macOS) at the final revision: statuses identical to the original evidence for all 13 entries (`acceptance/regression-TASK-095-host-macos.jsonl`).
