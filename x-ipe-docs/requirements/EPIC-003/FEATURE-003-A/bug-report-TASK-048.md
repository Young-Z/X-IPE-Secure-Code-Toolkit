# Bug Report — TASK-048: Markdown report omitted most Reviewer-record fields; acceptance coverage gaps

## Reported Behavior

- **Source:** independent closing review TASK-047 (FEATURE-003-A, rubber-duck, 10-21-2026), 4 blocking findings:
  1. **AC-003A-06a contradicted / acceptance relaxed:** every Copilot command writes the project-wide lock `.x-ipe/private/secure-code/locks/copilot.lock`, outside the collaboration folder, and the runner asserted a relaxed wording ("…, the Copilot lock and own report files").
  2. **AC clauses without a real assertion** (ID present in passing evidence, branch not exercised):
     - 01d: a record covering only stale suggestions;
     - 02b: partial scope through a *missing* Policy;
     - 02d: a *removed* Policy;
     - 03a: stages `bug_fix`/`refactor` and an `unspecified` folder;
     - 04b: missing basis for `partial`/`not_applicable`/`cannot_verify`;
     - 04f: missing agent alone (report naming it);
     - 06f: close with no prior report.
  3. **AC-003A-05a:** the Markdown Reviewer Records omitted reviewed targets, subjects, `reviewed_at` and `recorded_at`, and the runner checked only seq, validity and row count. "Field-by-field" in the acceptance report overstated the evidence.
  4. **Closing report placeholder:** the closing report still held a placeholder while claiming all 42 ACs pass.
- **User decisions:**
  - Clarify AC-003A-06a: the project-wide Copilot lock file is part of Copilot's private data. This is a specification clarification, already made by the owner; behaviour is unchanged.
  - Render the full Reviewer records in the Markdown.
- **Severity:** Medium. The report is partially incomplete: the structured result was complete and correct, and no state, adoption or attention value was wrong.
- **Expected (AC-003A-05a):** "suggestions, states, attention list, gaps, Reviewer records with validity, artifacts and adopted Policies are identical in both".
- **Actual:** the JSON `reviews[]` held invocation (host, agent, read_only, invoked_at, declared), requirement, reviewed_targets, reviewed_at, subjects, masked, recorded_at, reasons, counted and not_counted. The Markdown showed only seq, validity, host, agent, read-only, invoked, requirement, reasons, counted, not counted and masked.
- **Mode:** free-mode. No task board, workflow or Git operations (owner instruction).

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-01 adoption verified, not claimed | Spec G-01; EPIC-001 FR-22 (R-01, R-07), AC-15 | Developer, upstream agent | People reading the Markdown see the same Reviewer records as tools reading the JSON | Render every record field. Free text goes through `cell`; ids, paths, digests and times through `code`. No new schema field | No change of JSON, states, rounds or footer; the spec is not edited by this task; no assertion weakened | US-06 / AC-003A-05a / Integration | Four-record collaboration: incomplete with masked text and no result, valid, `absent` target, wrong version | RED → GREEN; runner 05a field-by-field on 15 rounds | not measured |
| G-01 (enabling) honest boundaries | Spec; EPIC-001 FR-01 (O-04) | Upstream agent | Copilot writes only its private data (collaboration folder, project-wide lock file) and report files | Runner assertion aligned with the clarified wording | Behaviour unchanged | US-07 / AC-003A-06a / Integration | — (wording) | Container 107 commands, host 6 | not measured |

## Reproduction (RED)

Revision: `copilot/report.py` `76ea28caa162ca43ce9ae1b5ccb26194fbfb59d6558507c7163afbb0b46cd521` (TASK-045/046 state, tree `55aeba44…`).

Command: `uv run pytest -p no:cacheprovider -q -o addopts="" tests/copilot/test_copilot_report.py` with the final test file (`368eab5a…`). Result: **2 failed, 28 passed**.

| Test | Failure on the unfixed code |
| --- | --- |
| `test_05a_reviewer_records_identical_in_markdown` | `AssertionError` on record 1: the expected summary row is not in the section. The row has no reviewed or recorded time; the Markdown had 11 columns, the record has 13 rendered fields |
| `test_05a_reviewer_record_values_shown_raw` | `IndexError`: no `### Reviewer record 1` block exists, so there are no reviewed targets or subjects in the Markdown |

The RED was recorded first with the test as written, and repeated after `ruff format` re-wrapped three long lines of the test file (no assertion changed). For the repeat, the exact pre-fix `report.py` bytes (`76ea28ca…`) were restored temporarily.

## Root Cause

`copilot/report.render` built the Reviewer Records table from a hand-picked subset of the record fields (design Part 2, item 9: "Reviewer records with validity"). The implementation stopped at validity plus a summary. Both outputs are rendered from the same result dictionary, but the Markdown only projected part of each `reviews[]` entry. The unit test (`test_05a_05c_…`) and the runner checked only `seq` and validity, so the omission was not detected. This is an implementation gap against AC-003A-05a, not a design or data flaw: the JSON is complete.

## Scope and Conflicts

- **Callers of `render`:** `_publish` (new round), `_reconcile` (uncommitted round after a crash) and `_repair_markdown` (re-create a removed Markdown of the latest committed round). All of them render from the stored JSON.
- **Expected consequences:**
  - New rounds have the full record.
  - The footer still binds the JSON bytes.
  - Earlier rounds are never re-rendered, so they stay byte-identical (05b).
  - A Markdown repaired after the user removed it is rendered in the new layout.
  - The invocation time now goes through `cell` instead of `md_text`. The output is identical, except that a toolkit mask marker becomes a code span, as in all other free text.
- **Side effect (accepted, documented):** suppose a crash left an uncommitted round whose Markdown was written by the previous version. After the upgrade, `_reconcile` finds that the Markdown differs from the new render and refuses with `REPORT_CONFLICT`, as for any mismatch (move the named files away manually). Nothing is overwritten.
- **Not changed:**
  - the JSON schema and contents, the state signature and the round numbering;
  - the Guard report and Guard code;
  - the shared envelope (`reviewer.py`);
  - the CLI.
- **Unexpected conflicts:** none. Inspected `copilot/report.py`, `copilot/service.py` (`_publish`, `_reconcile`, `_repair_markdown`), `copilot/engine.py` (`reviews` rows), `reviewer.py`, the copilot tests and the 003-A, 002-A and 002-B runners.

## Fix and Design Impact

- **`copilot/report.py`** (243 → 264 lines, under 800):
  - The summary table adds **Reviewed** (`cell(reviewed_at)`) and **Recorded** (`code(recorded_at)`).
  - A new `_review_detail` renders, per record, a `### Reviewer record <seq>` block with:
    - the statement "Invocation declared by the agent, not proven." (or "not declared");
    - a **Reviewed targets** table: `code(path)` and `code(digest)`, so `absent` is shown as is;
    - a **Subjects** table: `code(id)`, `code(type)`, `code(result)` (`—` when missing), `cell(basis)`, and the masked labels of that subject (`subjects[i].…` with the prefix removed).
  - No-link and no-HTML guarantees are kept: free text goes through `cell` (`md_text` plus mask markers as code spans), everything else through `code`.
- **Design:** Part 2 "Result and Report" item 9 and the test sentence were updated; a Design Change Log row for TASK-048 was added, noting the AC-003A-06a clarification; Implementation Evidence was appended. There is no interface, schema or data change.
- **Reference:** `x-ipe-secure-code-toolkit-copilot/references/copilot-records.md` ("Report Rounds") now states that both outputs show every Reviewer record in full.
- **Tests:**
  - `tests/copilot/test_copilot_report.py` gains `test_05a_reviewer_records_identical_in_markdown` (every JSON record key is a rendered field; summary row, invocation statement, targets and subjects compared field by field) and `test_05a_reviewer_record_values_shown_raw` (`absent`, digests, missing result `—`, masked basis label, escaping, no link/HTML).
  - No existing test or assertion was changed.
- **Runner** `acceptance/blackbox.py`. All additions are black-box assertions through the real CLI:
  - new stages `extras` (main copy) and `policy_extras` (separate copy);
  - `review_fields` compares every Reviewer-record field on 15 rounds (05a);
  - 04b loop extended;
  - 06a area check names the lock file, and a lock-written check was added;
  - TC→AC map comment and stage dependencies updated.
  - The removed-Policy fixture deletes the rule folder: no removal command exists. It is the FEATURE-001-C runner's fixture, disclosed in the runner and the acceptance report.
  - Two existing free-text comparisons in `consistent()` now use the documented cell form (`mcell`) instead of plain escaping, so masked text compares correctly. This is equivalent for unmasked text.
  - Mutation check: the new 05a runner checks fail on the pre-fix renderer output (4 checks) and pass on the fixed output.

## Verification

- **GREEN:** the same test bytes against fixed `report.py` (`660fcd06…`) → `test_copilot_report.py` 30 passed.
- **Full suites** (`uv run pytest -p no:cacheprovider -q -o addopts=""`):

  | Environment | Passed | Skipped |
  | --- | --- | --- |
  | macOS, Python 3.14.6 | 882 | 2 |
  | macOS, Python 3.11.15 (`UV_PROJECT_ENVIRONMENT` in the session folder) | 881 | 3 |
  | Linux, Python 3.12.12 (docker `ghcr.io/astral-sh/uv:python3.12-bookworm-slim`, tree copy) | 883 | 1 |

  The previous counts were 880/2, 879/3 and 881/1; the 2 new tests account for the difference. `uv run ruff check .` reports "All checks passed!".
- **Coverage** (copilot + reviewer, 221 tests): 95% total (engine 99%, manifest 90%, model 96%, records 94%, report 98%, service 95%, reviewer 100%).
- **Acceptance rerun.** Fresh caches `fat-uv-cache-ca`, `-ga` and `-gb` were removed, recreated and warmed online; the fixed `report.py` (`def _review_detail`) was found in each cache. All runs were offline.

  | Runner | Container | Host |
  | --- | --- | --- |
  | FEATURE-003-A | 11/11, 391 checks, 107 Copilot commands, stderr empty | 2/2 (TC-CA-12, TC-CA-11), stderr empty |
  | FEATURE-002-A regression | 26/26 | 2/2 |
  | FEATURE-002-B regression (real Opengrep) | 10/10 | 2/2 |

  Unit/integration log: 221 passed. Per-TC (container): TC-CA-01 17, 02 11, 03 6, 04 32, 05 216, 06 21, 07 8, 08 16, 09 26, 10 19, 11 19 checks. Host: TC-CA-12 7, TC-CA-11 19. No product check failed, so there is no `run1-FAIL` evidence.
- **Hashes (SHA-256):**

  | Item | Hash |
  | --- | --- |
  | Toolkit tree | `5c3d186ca9138787481a9e143ba352111510527783852a9e4d2f9b9ccf4cdaa3` |
  | `copilot/report.py` | `660fcd06f0b8f2b59f9d8e920cb7b83c16714b6a7ad5f0a2074ab7782f244ee3` |
  | `test_copilot_report.py` | `368eab5a54e59c5b0cf56f151d8b36482f618a3caccb0fa0c4df28ab3a31ffd1` |
  | `copilot-records.md` | `3fac165e4099d043681ff5db205a49f6659a74b59c276e8c8ba4891530fff5f6` |
  | Specification (unchanged by this task) | `4c647c8c4faac1c13b65345df76bf22728120cf35b4e4a4f41afc06a65ed9f88` |
  | Design | `aeff97182bc094e15674f7ff59c7db996bbe5a442e05120ad741f7c914c7acf1` |
  | Runner | `7a4cd98cf3335b94dca85f4c615f14f2708efd034c2be79a7a0b650595cb351e` |
  | Acceptance report | `fd1c0ccf3af10846e571f24b81d96940d14fc1867f19885ef48dee1b788f9af1` |
  | Container evidence | `4b978585269bdb2e5cf866d4029cc48db002a81440e1fddd8732ec310a4c7a51` |
  | Host evidence | `e2e89141e8ecdcee286d14b0e2af2b3fef6cd02d2f214d9fdfb753992cfb566e` |
  | Unit/integration log | `2fd939023584af64600028ac3bd63ac0687d8ed2e9fe1f992318260d154e3615` |
  | Regression 002-A container / host | `404ada17…` / `b87e492e…` |
  | Regression 002-B container / host | `3a256de8…` / `290c2607…` |

  The host and regression outputs are byte-identical to the TASK-046 runs, because those runners print no timestamps or generated ids.
- **Independent review of this fix:** not performed by this executor; left to the owner (closing re-review).
- **Limits:**
  - Windows not run.
  - The removed Policy is simulated by deleting the rule folder.
  - Reviewer invocation is declared, not proven.
- **Stakeholder outcome:** not measured.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed
  next_task_based_skill: null
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  feature_id: "FEATURE-003-A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/copilot/report.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/copilot/test_copilot_report.py"
    - "x-ipe-docs/requirements/EPIC-003/FEATURE-003-A/bug-report-TASK-048.md"
  bug_severity: "Medium"
  root_cause: "Markdown Reviewer Records projected only a subset of each structured Reviewer record; tests compared only seq/validity"
  conflicts_found: []
  owner_resume: "Feature Closing FEATURE-003-A (TASK-047): closing re-review"
```
