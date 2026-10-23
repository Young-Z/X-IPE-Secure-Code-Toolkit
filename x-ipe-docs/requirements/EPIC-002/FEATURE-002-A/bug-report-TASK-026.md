# Bug Report — TASK-026 (FEATURE-002-A closing review findings)

> Feature: FEATURE-002-A — Guard Semantic Verification & Verdict Reporting · Task: TASK-026 (Bug Fix, free-mode, interact-with-human) · Origin: closing review of TASK-025 · Date: 2026-10-19
> User decision: fix all four findings now (closing TASK-025 blocked meanwhile)

## Reported Deviations

| # | Severity | Deviation | Expected (source) | Actual (before fix) |
| --- | --- | --- | --- | --- |
| 1 | High | Whole-project/folder targets counted paths under `.x-ipe/private/`, `x-ipe-docs/secure-code/` (and `.git`) as target paths although the tree digest skips them | BR-02, US-01, AC-002A-02b/02d: a Copilot report is never evidence of a pass; evidence must lie on the verified (digested) artifact | Whole project + plan object `.` + evidence only in an **unlisted** `x-ipe-docs/secure-code/reports/copilot/c-1.md` → `met` → **Pass** (`ALL_CHECKS_SATISFIED`) |
| 2 | Medium | README, design usage example and `guard open` next-step hint put request files in the project root | SKILL.md/guard-records.md: requests under `.x-ipe/private/secure-code/tmp/`; whole-project runs must be able to pass | Following the README in a whole-project run changes the `.` digest → reviews stale, `TARGET_CHANGED`, never Pass |
| 3 | Medium | Masking missed PGP private key blocks, hyphenated `sk-proj-…`/`sk-ant-…` keys and unquoted `KEY=value` lines; NFR-002A-2 claimed keys/credentials are never stored | NFR-002A-2 safety intent; AC-002A-01d (FEATURE-001-B patterns, satisfied) | Those values stored verbatim in evidence/state/result/report |
| 4 | Low | Deeply nested request JSON | Every refusal is an envelope with one next step (UI/UX requirements) | `RecursionError` traceback, no envelope |

## Goal / Restoration Frame

| Goal | Stakeholder | Intended observable outcome | Restoration contribution | AC / rule links | Outcome |
| --- | --- | --- | --- | --- | --- |
| G-02 | Developer, upstream agent | No misleading "pass"; every conclusion traceable to verified evidence | Toolkit data and Git internals can never satisfy a target check; documented request paths keep whole-project runs passable; more credential formats masked; malformed requests refused cleanly | AC-002A-02b, 02d, 01d; BR-02; NFR-002A-2 | not measured |

## Reproduction (before fix)

- #1: closing reviewer's scratch script (service functions) → verdict `pass`. Regression `test_whole_project_never_counts_toolkit_data_as_target` RED: `record` accepted `x-ipe-docs/secure-code/reports/copilot/c-1.md` as evidence (`AssertionError: … c-1.md`, `problems == []`).
- #2: `test_request_paths_in_docs_and_hints_stay_private` RED: README `--request` paths `['open.json', 'plan.json', 'record.json', 'review.json']`.
- #3: `test_guard_masks_more_credential_formats` RED for all 5 formats (secret present in masked text).
- #4: `test_deeply_nested_request_refused` RED: `RecursionError: Stack overflow … while decoding a JSON array` traceback.
- Two first-run failures were setup errors (missing `import re`, `mkdir` on an existing folder) — fixed in the tests and re-run before any source change; only the behavioural failures above count as RED.

## Root Cause

1. `targets.owning_target` matched any path under a folder target (or every path for `.`) while `_tree` excluded `.git`, `.x-ipe/private/` and `x-ipe-docs/secure-code/` from the digest — two definitions of "inside the target" disagreed (implementation error against the design's tree-exclusion rule).
2. Documentation/hint drift from the SKILL.md rule.
3. Guard reused only the FEATURE-001-B pre-check patterns (designed for knowledge items) for arbitrary evidence.
4. `model.load_request` did not catch `RecursionError` from `json.loads`.

## Fix (minimal)

| File | Change |
| --- | --- |
| `guard/targets.py` | `not_in_tree(path)` (any `.git` component or excluded prefix); `owning_target` returns such paths only when they equal an explicit target. Affects plan objects, evidence/finding paths, reviewer binding and `_met` consistently (all use `owning_target`/`path_role`). Listed context/Copilot reports keep their roles. |
| `guard/mask.py` | Guard-only additions: private key blocks incl. `… PRIVATE KEY BLOCK`, `sk-(proj|None|svcacct|admin|ant)-…` keys, unquoted `[export] …KEY/TOKEN/SECRET/PASSWORD… = value` lines with bounded (`{0,64}`) name parts (placeholders kept). `knowledge/precheck.py` unchanged (FEATURE-001-B behaviour preserved). |
| `guard/model.py` | `RecursionError` → `REQUEST_INVALID` "nested too deeply". |
| `guard/service.py`, toolkit `README.md`, design usage example | Request paths under `.x-ipe/private/secure-code/tmp/`; README states why. |
| `specification.md` NFR-002A-2 (+ version row), design Security section + Design Change Log | Honest masking limit (pattern-based; unknown formats can be stored); no AC changed (user decision). |

## Conflict Analysis

- Expected: verifications that previously used evidence in toolkit folders under a folder target are now refused at `record` (`RECORD_INVALID`, "not a recorded path") — the intended restoration. Explicit Copilot reports/context keep working (`test_listed_copilot_report_under_toolkit_folder_stays_context`, TC-A-05).
- Expected: more text masked in Guard evidence (e.g. `SERVICE_TOKEN: …` lines); placeholders untouched.
- Inspected for unexpected conflicts: engine `_relevant_paths`/`_met`, records plan/evidence/finding/merge/review binding, FEATURE-001-B pre-check and its tests (unchanged, passing), FEATURE-001-C tests (passing). None found.

## Independent Fix Reviews (iterations)

1. Fix review: the first masking additions introduced (a) quadratic backtracking in the unquoted-assignment pattern (degenerate 200 KB line ≈ 78 s; 1 MiB extrapolated ≈ 35 min, under the Guard lock) and (b) an over-broad `sk-` pattern that refused ordinary file names such as `src/sk-learn-model-preprocessing-pipeline.py`. Regressions RED (78 s timing failure; both slug paths refused) → bounded name parts and known key prefixes → GREEN; worst case now ≈ 0.03 s per adversarial MiB, 0.84 s for 16 MiB of source.
2. Focused re-review: both fixes hold, no super-linear pattern on 1–16 MiB adversarial input; found OpenAI `sk-None-…` keys unmasked → regression RED → prefix added → GREEN.
3. Other fixes (target ownership, docs paths, recursion) confirmed correct; no unexpected conflicts.

## Verification (final revision, toolkit tree `a5cc8598ed9e98b7…`)

- Regressions: 4 integration + unit cases (masking formats ×6, placeholders, linear timing ×3, slug paths ×2) — each RED before its fix, GREEN after, assertions unchanged.
- Developer suite: **416 passed, 1 skipped** (macOS Python 3.14 and 3.11), **417 passed** (Linux Docker 3.12); `ruff check` clean.
- Acceptance rerun with fresh offline cache volume (final code verified in cache): container **26/26** (new TC-A-27 unlisted Copilot report in whole-project run; strengthened 01a md/json row comparison), host **2/2**, unit/library **253 passed, 1 skipped**.
