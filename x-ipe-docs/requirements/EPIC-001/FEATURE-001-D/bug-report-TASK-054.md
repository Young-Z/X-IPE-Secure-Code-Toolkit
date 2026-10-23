# Bug report — TASK-054: rename-target collision lookup follows swapped folders (FEATURE-001-D)

Task: TASK-054 (owner Sage; retained implementation worker). Skill: x-ipe-task-based-bug-fix,
free-mode, `interact-with-human` (human chose this route). Workflow: N/A (no app/board/Git writes).
Matched tool route: `stages.feedback.bug_fix` → `x-ipe-tool-implementation-python`, operation
`fix` (synthetic context BUG-TASK-054, technical_design_link N/A for the tool only).

## Reported Behavior

- **Source:** independent closing review of FEATURE-001-D, verified by the owner.
- **Severity:** Medium/High as reported (security design violation; read-only, no write). Classified
  **High** for this report: the no-follow read guarantee of the exit path is broken (read escape and
  a decision influenced by outside data), but nothing is written and no secret is returned.
- **Actual:** `knowledge/exit.py:114` (unfixed SHA-256
  `8064183f849d83c4a3aa7e74423e8b29a1dfff757a0b3b3177921a07129094b2`) validates the rename target
  with the path-based `identity.find_collision(store.local_root(tree.root), target)`
  (`Path.is_dir()` + `os.scandir(path)`, links followed). If `x-ipe-docs/secure-code/knowledge/local`
  or a namespace/version component is replaced by a symbolic link while `exit-preview`/`exit-confirm`
  runs (after the rule was read through the command's Tree), the lookup lists a folder outside the
  project, and an outside case-variant folder decides `IDENTITY_COLLISION`.
- **Expected (source-authorized):** every exit read goes through the command's `durable.Tree` with
  no-follow, directory-handle-relative operations; a swapped component gives `PATH_UNSAFE` or uses
  the original handle, never an outside read.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 (exits never silently break or misuse other data) — safety subgoal NFR-001D-1/NFR-001D-4 | specification.md `fb74bfe2…` NFR-001D-1 ("All paths are symlink-checked"), NFR-001D-4 (bounded scan: only toolkit files); technical-design.md v1.3 Design Options "Locks and reads", "Handle-based reads" (prepare uses only the command's Tree), Security section (no-follow handles), Edge Cases ("…component replaced by a link → PATH_UNSAFE; nothing … outside") | Maintainer; project owner | Rename-target checks read only in-project folders through the command's Tree; a swapped component → `PATH_UNSAFE` | Handle-relative collision lookup (same case-insensitive rule, same message and code) | Same refusal codes/text and order parse → NS/VER → reserved → collision → exists; import path (`service.py:340`) unchanged; no new contract | US-02 / AC-001D-03e (rename target refusals, Integration), AC-001D-03h (no symbolic links followed, Integration) | Swap `knowledge/local` or `local/CWE/4.14` for a link to an outside copy holding `cwe-79-new` after the rule is read; preview/confirm rename to `CWE/4.14/CWE-79-NEW` | see Verification | not measured |

## Reproduction

Reproduced deterministically in-process (no documented pause exists between the handle-based
rule read and `_target_checks`; `exit_locked` precedes the rule read, which already refuses a
swapped component): the swap is performed inside the first `lifecycle.read_memory` call, which
`prepare` makes immediately before `_target_checks`; `os.scandir` path arguments are recorded.
Environment: macOS, Python via `uv run --offline`, `UV_OFFLINE=1`, `PYTHONDONTWRITEBYTECODE=1`,
session-folder basetemp.

Command (Framework `scripts/`, unfixed `exit.py` `8064183f…`):
`python -m pytest -p no:cacheprovider -o addopts="" --basetemp=$S/bt-054-red -v
tests/knowledge/test_exit_bugfix_task054.py` → exit 1, **4 failed, 2 passed**:

- `[preview|confirm]-[local_root|knowledge_parent]` FAILED at the first assertion: the outside
  folder and its `CWE`, `CWE/4.14` subfolders were listed by `os.scandir(<outside path>)`
  (read escape through `Path.is_dir()` + path `os.scandir` of `find_collision`).
- `[preview|confirm]-version` PASSED before the fix: `find_collision` lists entries with
  `is_dir(follow_symlinks=False)`, so a swapped namespace/version entry is not followed (not
  exploitable); these cases stay as preserved-boundary guards. Only the `local` root and its
  ancestors were followed.

## Root Cause

- `exit._target_checks` (exit.py:114) is the only exit-path read that does not use the command's
  `Tree`: it passes `store.local_root(tree.root)` (a path) to `identity.find_collision`, which walks
  `local/NS/VER` with `Path.is_dir()` (follows links) and `os.scandir(current)` (path-based).
- Trigger: a component of `local/NS/VER` is replaced by a symbolic link between the handle-based
  rule read (`store.read_rule_at`) and the target check. The rule read and the later
  `resolve.snapshot(tree)` would refuse the link, but the collision lookup runs in between.
- Classification: implementation error (design says prepare uses only the command's Tree; the
  design's prepare step 4 names `find_collision` as the rule, not as permission for path reads).
- Callers inspected: `exit.prepare` → `_target_checks` (preview and confirm), `identity.find_collision`
  (also used by `knowledge/service.py:340`, import path), `store.iter_refs_at`/`read_rule_at` (handle-based).

## Scope and Conflicts

- **Affected:** rename-target validation in `knowledge exit-preview` and `knowledge exit-confirm`.
- **Unaffected (preserved):** codes `IDENTITY_COLLISION`/`RENAME_TARGET_EXISTS`/`IDENTITY_RESERVED`/
  `RENAME_TARGET_INVALID`/`IDENTITY_INVALID`, their text and order; case-only rename and case-variant
  refusals (`test_rename_target_refusals`); link entries inside a folder are not folders (as before).
- **Conflict analysis** (actual code read): (1) `knowledge/service.py:340` import uses the same
  path-based `find_collision`; it is outside the exit path and outside this bug's scope (FEATURE-001-B
  path-based reads stay per design "path-based read_rule/iter_refs remain for callers outside this
  feature") — **left unchanged** (expected, no conflict). (2) `identity.find_collision` stays
  unchanged (shared helper; changing it would alter import). (3) A link component now yields
  `PATH_UNSAFE` from the collision step where the old code followed it — this is the source-authorized
  behavior (design Edge Cases/Security), so expected. No unexpected conflict.

## Fix and Design Impact

- Minimal means: a handle-relative lookup `store.find_collision_at(tree, ref)` that walks
  `local/NS/VER` with `tree.opt_dir` + `durable.listdir` (real subfolders only, links not followed,
  a link component → `PATH_UNSAFE`), same case-insensitive comparison and same message as
  `identity.find_collision`; `exit._target_checks` calls it instead of the path-based helper.
- Alternatives rejected: changing `identity.find_collision` (affects import path, out of scope);
  re-checking with `os.path.realpath` (still path-based, racy).
- Design impact: none to contracts or interfaces (same codes, messages, order). Only the evidence
  section of technical-design.md records this fix.

## Mini AAA and Actual Routing

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| AC-001D-03e/03h, NFR-001D-1/4: swapped `local` root or version component during rename-target validation | Initialized project with rules; outside copy of the swapped folder containing case-variant `cwe-79-new`; swap performed at the first exit-memory read (immediately before target validation); `os.scandir` path arguments recorded | `exit.preview` / `exit.confirm` rename R1 → `CWE/4.14/CWE-79-NEW` | (1) the outside folder is never listed; (2) the refusal is `PATH_UNSAFE` (not an outside-based `IDENTITY_COLLISION`); (3) outside canary bytes unchanged; (4) the moved original folder unchanged | Integration (service level), pytest via `x-ipe-tool-implementation-python` operation `fix` | RED unfixed (`exit.py` `8064183f…`): 4 failed (local_root, knowledge_parent × preview/confirm: outside listed), 2 version guards passed; GREEN fixed (`exit.py` `384a9853…`, `store.py` `e5012c6b…`): 6 passed, same test bytes `863aaa0e…` |
| Preserved: in-project case-only / case-variant collisions | Existing `test_rename_target_refusals` | unchanged | unchanged assertions | Integration, pytest | 15 passed after the fix (`test_exit_actions.py` unchanged, `6e224d90…`) |

Tool route (actual): `x-ipe-tool-implementation-python`, operation `fix`, synthetic context
BUG-TASK-054 — learned conventions, wrote `test_fix_*` first, ran it RED, implemented the minimal
fix, ran it GREEN, then the full suite and lint (below). `ruff format --check`: `exit.py` already
formatted; `store.py` "would be reformatted" — pre-existing (the module was never ruff-formatted;
not reformatted here to keep the fix minimal); `ruff check` clean.

## Verification

Fix: new `store.find_collision_at(tree, ref)` (handle-relative walk of `local/NS/VER` with
`tree.opt_dir` + `durable.listdir`, real subfolders only, case-insensitive clash, identical message)
and `exit._target_checks` calls it instead of `identity.find_collision(store.local_root(tree.root), …)`.
A link component now raises `PATH_UNSAFE` from the collision step; codes, messages and validation
order are unchanged. `identity.py` (`8f45438a…`) and `service.py` (`16eb2695…`, import path at
line 340) are unchanged.

| Check | Command (Framework `scripts/`, `UV_OFFLINE=1`, `PYTHONDONTWRITEBYTECODE=1`, basetemp in session folder) | Result |
| --- | --- | --- |
| Regression RED (unfixed) | `python -m pytest … -v tests/knowledge/test_exit_bugfix_task054.py` | exit 1; 4 failed, 2 passed |
| Regression GREEN + preserved rename refusals | `python -m pytest … -v tests/knowledge/test_exit_bugfix_task054.py tests/knowledge/test_exit_actions.py::test_rename_target_refusals` | exit 0; 21 passed |
| Full suite run 1 / run 2 | `python -m pytest -p no:cacheprovider -o addopts="" --basetemp=$S/bt-054fullN -q tests` | exit 0; 1447 passed, 3 skipped (each run; previous baseline 1441 + 6 new) |
| Lint | `ruff check --no-cache .` | All checks passed |
| Module size | `tests/test_module_size.py` (in full suite) | passed (`store.py` 610, `exit.py` 656 lines) |
| Hygiene | `find ai-secure-code-toolkit -newermt <task start>` | only `store.py`, `exit.py`, the new test file; no links/FIFOs/caches/coverage data |

SHA-256: `knowledge/exit.py` fixed `384a98531dd9fa72004e7e3987e288a924c02f66df7a3eaf3f214887a1198d64`
(unfixed `8064183f849d83c4a3aa7e74423e8b29a1dfff757a0b3b3177921a07129094b2`);
`knowledge/store.py` fixed `e5012c6b5f9c4c71479bf81bc594070280cad5b65a740158a58c16936c26f10a`
(before `877dd739948603d27b5ed508a9354e9a546c0753cc4f5b1aafc3146547ea99bd`);
`tests/knowledge/test_exit_bugfix_task054.py` `863aaa0ecd7d98dcdc931b45a48ee69f3aa03437ced567925c97138c38096b6f`;
specification `fb74bfe2…` (unchanged); technical-design.md input `a3de6e00…`.

Engineering delivery: verified at the hashes above. Independent review of this fix: pending
(owner). Stakeholder outcome: not measured.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed  # engineering gates passed; independent review of the fix pending with the owner
  next_task_based_skill: null
  process_preference:
    interaction_mode: "interact-with-human"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/exit.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/store.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/knowledge/test_exit_bugfix_task054.py"
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/bug-report-TASK-054.md"
  bug_severity: "High"
  root_cause: "exit._target_checks used the path-based identity.find_collision (links followed for the local root and its ancestors) instead of the command's no-follow Tree"
  conflicts_found: []
```

Returned to the lifecycle owner (Sage); no board, Git or app writes; completion, review and
routing are the owner's.
