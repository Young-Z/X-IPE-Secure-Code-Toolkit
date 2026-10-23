# Bug Report — TASK-041: Closing-review findings for FEATURE-002-C

## Reported Behavior

- **Source:** independent closing review TASK-040 (10-21-2026), 8 findings. User decision: fix #2, #3, #4, #7 and #8; document #1, #5 and #6 (no behaviour change); then rerun the acceptance and resume closing.
- **Severity:** Medium overall. #4 is a credential-handling gap; the others are contract or assertion gaps.
- **Expected (spec):**
  - AC-002C-01c: an attempt of another verification is refused.
  - AC-002C-01b: every Guard command result states the budget.
  - AC-002C-04a/04d: nothing is added after a cancellation.
  - AC-002C-05b/05e: no credential is stored; credential-bearing URLs are refused.
  - AC-002C-04b: termination is claimed only as observed.
- **Actual:**
  1. Attempt ids were local (`a-1`), so a foreign id could not be told apart from a local one.
  2. Evidence, manifest and output files stayed in the run folder when their state commit lost to a cancellation.
  3. A credential that was percent-encoded passed the URL check and was decoded into the stored path.
  4. Egress results and run refusals carried no budget.
  5. The report said "its processes were seen exiting", although processes that leave the group are not tracked.
  6. The cooperative nature of the interactive gate was not stated to users.
  7. Several acceptance clauses were not asserted.
- **Mode:** free-mode, interact-with-human.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-04 budget integrity; honest cancel | FR-21; AC-25, AC-26 | Developer | Attempts belong to one verification; nothing remains after a cancel; every result shows the budget; termination claims stay honest | Run-bound ids; cleanup on a lost commit; central budget attachment; precise wording | No AC change; the interactive gate stays (user decision); limits stated | AC-002C-01b, 01c, 04a, 04b, 04d / Integration | See Actual 1, 2, 4, 5 | RED → GREEN; container 9/9 | not measured |
| G-05 egress | FR-20; E-02; AC-29 | Owner | No credential in a URL or a scope is accepted or stored, even percent-encoded | Check after percent-decoding; path-scope masking check | No DLP | AC-002C-05b, 05e / Integration | Encoded token in a scope URL accepted | RED → GREEN | not measured |

## Reproduction (RED, unfixed revision of TASK-040: tree `9cc46689…`)

| Test | Failure on the unfixed code |
| --- | --- |
| `test_01c_attempt_id_of_another_verification_is_refused` | The foreign id was accepted (no problem raised) |
| `test_01b_every_run_bound_result_and_refusal_carries_the_budget` | `KeyError: 'budget'` |
| `test_01b_egress_results_carry_the_budget` | `KeyError: 'budget'` |
| `test_04a_record_losing_to_cancel_leaves_no_evidence_file` | `E1.txt` remained |
| `test_04d_tool_finishing_after_cancel_records_nothing` (added assertion) | `opengrep-1-manifest.json` and `-output.json` remained |
| `test_05e_percent_encoded_credentials_are_refused` | Grant accepted |
| `test_04b_report_wording_names_the_process_group_and_its_limit` | Wording missing |
| `test_04f_conclude_already_publishing_wins_over_cancel` | Behaviour correct (`RUN_FINISHED`), but the message did not name the ordering |

## Root Cause

- **Attempt ids:** ids were generated per state without a verification binding (implementation gap against AC-002C-01c).
- **Leftover files:** evidence and Adapter output were written before the cancellation-aware commit, with no cleanup when the commit lost.
- **Encoded credentials:** the URL credential check ran on the raw string, but the stored path is percent-decoded.
- **Missing budget:** budget status was added per command for successes only.
- **Overclaiming wording:** the report text promised more than the process-group observation supports.

## Scope and Conflicts

- **Expected consequences:**
  - Attempt ids change format to `a-<n>-<8 characters>`. Ids are opaque; the docs and tests were updated, and old ids still match exactly.
  - Refusals carry an additional `budget` data key.
  - `refuse_closed` decides from the stored result first: a cancelled result gives `RUN_CANCELLED`, a normal one `RUN_FINISHED`.
  - The limits list in every report gains two statements.
- **Not changed (user decision):**
  - The conclude/cancel linearization (#1) is by design; a deterministic test now proves it.
  - The interactive confirmation (#5) is now documented as a cooperative control in the references, README, design threat model and report limits.
- **Unexpected conflicts:** none. Reviewed by an independent code review (below).

## Fix and Design Impact

- Design Change Log row TASK-041 and the threat-model sentence were written before the code.
- **Files changed:**
  - `budget.py` (id format, foreign-id refusal)
  - `service.py` (`_mutate` attaches the budget to refusals; record removes its evidence on a lost commit)
  - `runs.py` (`remove_evidence`, result-first `refuse_closed`)
  - `toolrun.py` (removes `<adapter>-<n>-*` outputs on a lost commit; budget on refusals)
  - `egress.py` (decoded-URL and path-scope credential checks; budget in grant and declaration results)
  - `cancel.py` (`RUN_FINISHED` message names the ordering)
  - `report.py` and `engine.py` (wording and limits)
- **Docs changed:** Guard `references/guard-records.md`, README.
- **Acceptance runner:**
  - foreign id;
  - budget in refusals;
  - the paused matrix (plan, Reviewer, tool refused; conclude and cancel allowed);
  - extension leaves consumption unchanged;
  - a new declaration id per call;
  - returned (run-bound) ids.

## Verification

- **GREEN:** all new tests pass. Existing tests changed only to use returned or run-bound ids (`aid` helper; the CLI round trip). No assertion was relaxed.
- **Full suites:** macOS Python 3.14: 657 passed, 2 skipped. Python 3.11: 656 passed, 3 skipped. Linux Python 3.12: 659 passed. `ruff check` clean. Toolkit tree `a9e5990c…`.
- **Acceptance rerun** (fresh offline caches, fixed code confirmed in the cache):
  - FEATURE-002-C container 9/9, stderr empty ([evidence](acceptance/evidence-container-linux.jsonl), `7a21573d…`); host 2/2.
  - FEATURE-002-A regression 26/26 + 2/2; FEATURE-002-B regression 10/10 + 2/2.
  - Unit/integration log: 190 passed, 1 skipped (`d5dedfb9…`).
  - A runner bug (a variable name collision in TC-C-05) was found and fixed during the rerun; no product change.
- **Independent review** (code-review subagent): no significant issues.
- **Hashes:** `budget.py` `cde5a60c…`, `service.py` `246cafd2…`, `runs.py` `d84419bb…`, `egress.py` `836f8b36…`, `toolrun.py` `0968b3cd…`, `cancel.py` `6a94d7c2…`, `report.py` `3a10aa74…`, `engine.py` `6cc3ab0c…`; design `7c87759d…`; runner `34756ef9…`.
- **Stakeholder outcome:** not measured.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed
  next_task_based_skill: null
  process_preference:
    interaction_mode: "interact-with-human"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/guard/"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/acceptance/blackbox.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/bug-report-TASK-041.md"
  bug_severity: "Medium"
  root_cause: "Attempt ids not bound to a verification; files written before a commit not removed when it lost; URL credential check before percent-decoding; budget status added only to successes; overclaiming termination wording"
  conflicts_found: []
```
