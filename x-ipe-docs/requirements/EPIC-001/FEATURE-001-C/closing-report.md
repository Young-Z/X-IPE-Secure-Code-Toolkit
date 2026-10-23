# Feature Closing Report

> Feature: FEATURE-001-C — Policy Resolution & Adoption Scope Selection (EPIC-001) · version v1.0
> Task: TASK-019 (resumed after Bug Fix TASK-020) · Date: 2026-10-19 · Mode: free-mode, interact-with-human
> Closure scope: engineering delivery only (no release, commit, push or PR — the workspace is not a Git repository and no release was requested)

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Delivery Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-09, FR-10 (X-09, X-10, X-14, P-01, P-02, P-12…P-14, K-17, K-18, K-30, V-23); AC-11 (Framework part), AC-12 | Developer, upstream agent | Imported, suggested and adopted scope never confused; missing knowledge never invented; adopted scope traceable | AC-001C-01a…01f, 02a…02e, 02g, 03a…03d, 04a…04c, 05a…05h all Pass | not measured |
| G-05 (enabling) | EPIC-001 G-05; P-02 | Owner | Selecting Policies grants no editing rights | AC-001C-01e, 02f Pass | not measured |

## Complete Acceptance and Actual Evidence

All 28 specification ACs (AC-001C-01a…05h) and NFR-001C-1 map to 17 test cases with original assertions and types in the [acceptance report](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance-test-cases.md): 17 Pass, 0 Fail, 0 Partial, 0 Blocked.

- Integration (real `uvx --from …/scripts secure-code policy|scope|knowledge …`): offline Linux Docker with disposable HOME 14/14 ([log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/evidence-container-linux.jsonl)), macOS host never-authorized User 1/1 ([log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/evidence-host-macos.jsonl)) — both rerun after TASK-020.
- Unit and skill-package checks 29/29 ([log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/evidence-unit-library.log)); structured review of SKILL.md "Selecting Policies" and `references/policy-selection.md`.
- Windows: not run (same deferral as FEATURE-001-A CR-002).

## Evidence Reuse and Dependency Freshness

| Input | At first acceptance | At closing | Disposition |
| --- | --- | --- | --- |
| Toolkit tree (incl. `uv.lock`, excl. `.venv`/caches) | `6ada1747b51892a8…` | `e9fdecb199e2ff43…` | Changed by TASK-020 (`policy/*.py`, `test_policy.py`) → full black-box rerun 14/14 + 1/1, unit/skill 29/29, developer suite **241 passed** (macOS 3.14/3.11, Linux 3.12), ruff clean |
| Specification | `b35d4e90…` | unchanged | — |
| Technical design | `e99b37c8…` | `625b05fe…` | Design Change Log entry for TASK-020 only; contracts unchanged |
| Runner `blackbox.py` | `d07aac2d…` | `e5550429…` | Checks added only (05d non-UTF-8 record, 05f removed rule); no assertion relaxed |
| Environment | Linux Docker Python 3.12 offline; macOS uv 0.11.23 | same; uv cache re-warmed and verified, host package refreshed | Stale `uvx` tool environment found and eliminated before the final runs |

## Review and Documentation Delta

- Reviews during delivery: specification review (4 blocking + 1 non-blocking fixed), design review (3 blocking fixed, re-review clean), implementation review (3 fixed) and re-review (1 fixed), all test-first.
- Closing review (TASK-019) found a crash on non-UTF-8 text and an untested 05f clause → user chose fix now → [Bug Fix TASK-020](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/bug-report-TASK-020.md), test-first (9 red, then green). Independent fix review: crash paths closed, no valid-input change; its note that the two new acceptance checks under-asserted their ACs was fixed by adding assertions and repeating the run.
- Cross-feature note: the shared project-root check moved from `knowledge/service.py` to `projects.py` (no behaviour change). FEATURE-001-B's tests all pass at the current tree; its recorded acceptance evidence remains at `7dd48fee…`.
- Documentation delta: none needed at closing. SKILL.md, `references/policy-selection.md`, `references/cli-contract.md` and README were written with the implementation, and the closing review confirmed they match actual commands, flags, codes, paths, statuses and exit codes.

## Outcome Gaps

- Stakeholder outcomes for every goal: **not measured** — no real developer/agent observation yet; delivery evidence is automated.
- Real agent conduct (interpreting natural-language clues, setting `--confirmed` only after real user confirmation) is verified only as skill instructions; the script cannot prove a human confirmed (stated limit).
- Windows behaviour (`msvcrt` locks for knowledge and scopes) unverified (CR-002).
- Presets/default Preset (P-13, P-11), Reference Policies, precedence (D-09) and the Copilot empty-library message (D-24) are out of scope by design.

## Quality Assessment Compatibility

No separate refactoring analysis was run. Indicators only: largest new module `policy/scope.py` (under 400 lines), policy coverage 82–100%, ruff clean. Compatibility fields: score N/A, no refactoring recommended (not an assessed quality verdict), no suggestions.

## Release Authority and Disposition

Engineering-only closure. No commit, push or PR: the folder is not a Git repository and no release authority was requested. Delivered files remain in place under [ai-secure-code-toolkit/](ai-secure-code-toolkit/README.md).

## Workflow and Owner Handoff

Free-mode: no application workflow write. Owner (Sage) marks FEATURE-001-C Completed and TASK-019 completed after human confirmation. Next unstarted feature in MVP order: **FEATURE-002-A — Guard Semantic Verification & Verdict Reporting** (depends on FEATURE-001-C).
