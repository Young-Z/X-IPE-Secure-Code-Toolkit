# Feature Closing Report

> Feature: FEATURE-002-C — Verification Budget, Cancel & Data-Egress Control (EPIC-002) · version v1.0
> Task: TASK-040 (resumed after Bug Fixes TASK-041 and TASK-042) · Date: 2026-10-21 · Mode: free-mode, interact-with-human
> Closure scope: engineering delivery only. No release, commit, push or PR: the workspace is not a Git repository and no release was requested.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Delivery Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-04 | EPIC-001 FR-21; AC-25, AC-26 | Developer | Runs stay within the agreed cost; exhaustion and cancel give honest partial reports | AC-002C-01*, 02*, 03*, 04*, 06b, 06c Pass (real binary for the cancel-during-run case) | not measured |
| G-05 | EPIC-001 FR-20; AC-29; inventory E-01, E-02 | Owner, Developer | Toolkit-owned calls only under purpose-specific grants with minimized, masked payloads; agent calls declared and audited | AC-002C-05*, 06a Pass | not measured |

The source scenarios were exercised with the real CLI in an offline Linux container:
- **Exhaustion:** retries and the time limit exhaust the budget, and the conclusion lists only the checks that were not reached.
- **Cancel during a run:** a running Opengrep v1.31.0 is stopped, and termination is confirmed as observed.
- **Cancel keeps a Fail:** a confirmed High finding stays Fail.
- **Egress:** findings are refused under a target-request-only grant, and the refusal is recorded.

Use by real Developers and Owners: **not measured**.

## Complete Acceptance and Actual Evidence

All 31 specification ACs (AC-002C-01a…06c) map to 13 test cases with their original assertions and types in the [acceptance report](acceptance-test-cases.md): 13 Pass, 0 Fail, 0 Blocked.

- **Black-box, real binary** (`uvx --from …/scripts secure-code …`; offline Linux aarch64 container; project `proj ü`): 9/9, stderr empty ([evidence](acceptance/evidence-container-linux.jsonl)).
- **macOS host**, never-authorized User path: 2/2 ([evidence](acceptance/evidence-host-macos.jsonl)).
- **Unit/integration (fake tool, races, egress through a local HTTP server):** 194 passed, 1 skipped ([log](acceptance/evidence-unit-integration.log)).
- **Structured review:** Guard SKILL.md "Budget, Cancel and Outbound Calls" and steps 5–6, `references/guard-records.md`, CLI contract.
- **Regression runners** (fresh caches):

  | Runner | Container | Host |
  | --- | --- | --- |
  | FEATURE-002-A | 26/26 | 2/2 |
  | FEATURE-002-B (real binary) | 10/10 | 2/2 |

- **Full suites:**

  | Environment | Passed | Skipped |
  | --- | --- | --- |
  | macOS, Python 3.14 | 661 | 2 |
  | macOS, Python 3.11 | 660 | 3 |
  | Linux, Python 3.12 | 663 | 0 |

  `ruff check` is clean.

## Evidence Reuse and Dependency Freshness

| Input | At acceptance (TASK-038) | At closing | Disposition |
| --- | --- | --- | --- |
| Toolkit tree | `9cc46689…` | `e3389072…` | Changed by TASK-041 and TASK-042. After each, the black-box runners were fully rerun with fresh offline caches (fixed code confirmed in each cache) and the full suites ran in 3 environments |
| Specification | `fca9f235…` | `fca9f235…` | Unchanged; no AC changed |
| Technical design | before the TASK-041 row | `6d64c8ae…` | Change Log rows TASK-041 and TASK-042, written before the code |
| Runner `blackbox.py` | before TASK-041 | `34756ef9…` | TASK-041 added assertions; none relaxed. Unchanged by TASK-042 |
| Environment | Linux container Python 3.12 offline + real binary; macOS host | same | Cache volumes recreated for each rerun |

## Review and Documentation Delta

**Reviews during delivery**
- Specification: three rounds.
- Design: three rounds.
- Implementation code review: 4 findings plus 1 follow-up, all fixed. Seven mutation checks compensated for the missing integration RED.

**Acceptance**
- The first real-binary run failed 8/9: Opengrep's worker processes stay as zombies, so termination was not confirmed.
- [Bug Fix TASK-039](bug-report-TASK-039.md) fixed this test-first. Its fix review found a decoding crash, also fixed.

**Closing review (TASK-040)**
- Raised 8 blocking findings. User decision: fix 5, document 3 → [Bug Fix TASK-041](bug-report-TASK-041.md). Its fix review found no issues.
- The focused re-review confirmed all 8 resolved or acceptably documented. It found one new blocking issue: TASK-041's cleanup after a lost commit could follow an evidence folder that had been replaced by a link, and delete files outside the run folder.
- [Bug Fix TASK-042](bug-report-TASK-042.md) fixed it test-first. Files are now removed by exact name through a folder descriptor opened without following links. The record path also returns `RUN_CANCELLED` again instead of `PATH_UNSAFE`.
- The reviewer's final check of TASK-042: finding resolved, no new blocking issues.

**Documentation delta**
- Guard SKILL.md: section "Budget, Cancel and Outbound Calls"; steps 5–6.
- `references/guard-records.md`: attempt, budget, pause, extension, cancel, record/Reviewer attempt and usage, egress.
- `references/cli-contract.md`: rows for attempt, pause, resume, extend, cancel, allow-egress and egress.
- README: cooperative interactive gate and termination wording.

**Cross-feature**
- Additive changes to 002-A and 002-B: budget in results, attempts cited by records, an Egress report section, and a networked-Adapter check.
- The 002-A and 002-B runners were adjusted for run-bound attempts. Their ACs are unchanged and their regressions pass.

## Outcome Gaps and Honest Limits

- **Stakeholder outcome:** not measured.
- **Windows:** not run. Tool runs are refused there (NFR-002B-4).
- **macOS before Python 3.13:** has no `os.waitid`, so the tool's group is killed after the leader is reaped. This leaves a narrow process-group-id reuse window.
- **Interactive confirmation is cooperative:** this covers extend, allow-egress and risk acceptance. A program that drives a pseudo-terminal could pass it; it is not an authorization boundary.
- **Termination confirmation:** means the tool's process group was seen exiting. Processes that left the group are not tracked.
- **Agent work the toolkit cannot observe:**
  - unregistered attempts;
  - work while paused;
  - undeclared outbound calls;
  - host or Reviewer calls after a cancel.

  The agent instructions were verified structurally only.
- **Egress gate:** library-only and verified against a local HTTP server; no toolkit network client exists yet (FEATURE-002-D/E, 001-E). Network access is not OS-enforced.
- **Race fixtures:** the late-commit, concurrent-cancel and unacknowledged-owner races were verified with the fake tool.

## Release Disposition

Engineering-only closure. No commit, push, PR or release was performed or requested; the workspace is not a Git repository.

## Refactoring Assessment

There was no separate analysis, and no refactor is compulsory.
- **Module sizes:** all touched modules are under 800 lines. The largest are `guard/toolrun.py` (749), `guard/service.py` (608) and `guard/egress.py` (461); a module-size test enforces the limit.
- **Coverage of the new modules:** 89–100%.
- **Assessment values:** `overall_quality_score: N/A`; `refactoring_recommended: false` (no evidenced need; this is not a quality verdict); `top_suggestions: []`.

## Next Feature Suggestion

Continue the MVP order with the next unstarted feature on the board. Knowledge seeding (TASK-028) is pending separately until the user provides the policy websites.
