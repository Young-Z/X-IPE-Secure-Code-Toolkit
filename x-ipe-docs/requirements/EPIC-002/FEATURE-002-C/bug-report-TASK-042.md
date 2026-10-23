# Bug Report — TASK-042: Lost-commit cleanup could follow a replaced evidence-folder link

## Reported Behavior

- **Source:** independent closing re-review TASK-040 (10-21-2026), after TASK-041. Findings 1–8 were confirmed resolved or acceptably documented; one new blocking finding was raised.
- **Severity:** High (destructive path introduced by TASK-041).
- **Expected:** the toolkit writes and removes files only inside the project's private Guard folders. All path handling refuses symbolic links (FEATURE-002-A/B safety contract, `runs.py` "all paths symlink-checked"). After a lost commit, the refusal (for example `RUN_CANCELLED`, AC-002C-04a/04d) is reported.
- **Actual:**
  1. `toolrun.run_tool` removed `<adapter>-<n>-*` by glob below `<run>/evidence` without any link check. Adapters are not filesystem-isolated, so a surviving process could replace the evidence folder with a link before the commit lost. The cleanup then deleted matching files outside the run folder.
  2. The record path (`service`, via `runs.remove_evidence`) checked links before unlinking, but on a linked folder it raised `PATH_UNSAFE`. That replaced the original `RUN_CANCELLED` refusal.
- **Mode:** free-mode, interact-with-human.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-04 honest cancel without side effects | FR-21; AC-25, AC-26; private-folder safety contract | Developer | Nothing remains after a cancel, and nothing outside the private run folder is touched | Exact-name removal through a descriptor of the evidence folder opened without following links | No AC change; the pre-existing interrupted-run sweep (002-B) is unchanged | AC-002C-04a, 04d / Integration | Evidence folder replaced by a link before the lost commit | RED → GREEN; container 9/9 | not measured |

## Reproduction (RED, revision of TASK-041: tree `a9e5990c…`)

| Test | Failure on the unfixed code |
| --- | --- |
| `test_04d_lost_commit_cleanup_never_follows_a_swapped_evidence_link` | `opengrep-1-manifest.json` and `opengrep-1-output.json` deleted outside the run folder |
| `test_04a_record_cleanup_never_follows_a_swapped_evidence_link` | `PATH_UNSAFE` returned instead of `RUN_CANCELLED` (checked by temporarily restoring the old cleanup code) |
| `test_remove_evidence_files_refuses_a_linked_folder`, `test_remove_evidence_files_removes_named_files_only` | Helper did not exist |

## Root Cause

The TASK-041 cleanup was written with path-based operations (`Path.glob`, `Path.unlink`) instead of the descriptor-based, no-follow access used elsewhere for paths that a tool process could change. The record path reused a helper that raises on unsafe paths inside an exception handler.

## Scope and Conflicts

- **Expected consequences:** if the evidence folder or a target entry is not safe, nothing more is removed and the original refusal is returned. Removal is by the exact names written (`<prefix>-manifest.json`, `<prefix>-output.json`, `<evidence id>.txt`), never by pattern.
- **Not changed:** the 002-B interrupted-run sweep (`_sweep`) already refuses links and runs before any tool process of the run is started; it is out of scope.
- **Unexpected conflicts:** none.

## Fix and Design Impact

- Design Change Log row TASK-042.
- `runs.py`: `remove_evidence_files(root, vid, names) -> bool` replaces `remove_evidence`. On POSIX it walks the path from the project root with `O_NOFOLLOW | O_DIRECTORY` (`safe_io.open_dir_nofollow`) and calls `os.unlink(name, dir_fd=fd)`, which removes a link entry itself, never its target. Elsewhere it uses the existing link checks; Adapter runs are refused on Windows.
- `toolrun.py`: removes only the two files `_record` wrote.
- `service.py`: one call with the exact evidence file names; the result does not mask the refusal.

## Verification

- **GREEN:** the 4 new tests pass; no existing assertion changed.
- **Full suites:**

  | Environment | Passed | Skipped |
  | --- | --- | --- |
  | macOS, Python 3.14 | 661 | 2 |
  | macOS, Python 3.11 | 660 | 3 |
  | Linux, Python 3.12 | 663 | 0 |

  `ruff check` is clean. Toolkit tree `e3389072…`.
- **Acceptance rerun** (fresh offline caches, fixed code confirmed in each cache):

  | Runner | Container | Host |
  | --- | --- | --- |
  | FEATURE-002-C | 9/9, stderr empty (`7a21573d…`) | 2/2 |
  | FEATURE-002-B regression | 10/10 | 2/2 |
  | FEATURE-002-A regression | 26/26 | 2/2 |

  The unit/integration log shows 194 passed, 1 skipped (`eced482c…`).
- **Hashes:** `runs.py` `9c9f8426…`, `service.py` `94d29d9d…`, `toolrun.py` `0c6c9e2c…`; design `6d64c8ae…`; spec `fca9f235…` (unchanged); runner `34756ef9…` (unchanged).
- **Independent review:** the closing reviewer verified the fix; no new blocking issues.
- **Stakeholder outcome:** not measured.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed
  next_task_based_skill: null
  feature_id: "FEATURE-002-C"
  task_output_links:
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/bug-report-TASK-042.md"
  owner_resume: "Feature Closing FEATURE-002-C (TASK-040)"
```
