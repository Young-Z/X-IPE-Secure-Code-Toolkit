# Feature Closing Report

> Feature: FEATURE-001-D — Knowledge Exit Impact & Broken-Link Handling (EPIC-001) · version v1.0
> Task: TASK-053 (resumed after Bug Fix TASK-054) · Date: 2026-10-22 · Mode: free-mode, interact-with-human
> Closure scope: engineering delivery only. No release, commit, push or PR: the workspace is not a Git repository and no release was requested.
> Delivery: verified engineering delivery at toolkit file list `a63578d7…`, specification `fb74bfe2…`, design `c052ed3c…`. Outcome: not measured.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Delivery Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-07 (K-34, K-35, K-36, X-15 exit part, D-04); AC-09, AC-10 | Maintainer, Developer, upstream agent | Removing or renaming knowledge never silently breaks or rewrites dependent work; history stays traceable | AC-001D-01a…06c pass (real CLI, offline container + macOS host) | not measured |

The qualitative scenario from the specification was exercised end to end with the real CLI (TC-D-01, rename):
- the impact was shown first and bound to a digest;
- the confirm moved the rule to the new ID with its content and examples byte-identical;
- the incoming relation was reported as "renamed to CWE-89-SQL" and not substituted;
- the adopted scope loads as partial;
- earlier Guard and Copilot reports stayed byte-identical.

Use by real Maintainers, Developers or agents: **not measured**.

## Complete Acceptance and Actual Evidence

All 30 specification ACs (AC-001D-01a…06c, all Integration) map to 22 logical test cases in the [acceptance report](acceptance-test-cases.md). Result: 22/22 pass (100%), 0 Fail, 0 Blocked. All 27 case × environment executions pass.

- **Real CLI black-box** (`uvx --from …/scripts secure-code …`): 29 ACs.
  - Offline Linux container, Maintainer path, `fat-uv-git:py312`, fresh cache verified to hold the fixed `exit.py` `384a9853…` and `store.py` `e5012c6b…`: 16/16 cases, 273 checks, stderr empty ([evidence](acceptance/evidence-container-linux.jsonl)).
  - macOS host, never-authorized User path: 2/2 cases, 14 checks ([evidence](acceptance/evidence-host-macos.jsonl)).
  - Crash recovery (AC-001D-06a) is exercised at all 29 crash points plus the `LOCKED` case. After recovery, each case is compared byte for byte with a full pre-exit snapshot:
    - the whole rule, tombstone or renamed folder;
    - the exit memory and transition log;
    - pending decisions and the document index.
- **Structured package inspection:** AC-001D-06c (the SKILL.md "Exiting Knowledge" section), in both environments.
- **Framework suite** (supporting evidence only): 1447 passed, 3 skipped ([log](acceptance/evidence-unit-integration.log)). `ruff check` is clean. Coverage of the new and changed modules is 84–98% (91% across knowledge + policy, measured at TASK-051 Stage B).
- **Regressions** (unchanged runners; every log byte-identical to the original evidence):

  | Runner | Container | Host |
  | --- | --- | --- |
  | FEATURE-001-B | 14/14 | 1/1 |
  | FEATURE-001-C | 14/14 | 1/1 |
  | FEATURE-002-A | 26/26 | 2/2 |
  | FEATURE-003-A | 11/11 | 2/2 |

## Evidence Reuse and Dependency Freshness

| Input | At first acceptance (TASK-052) | At closing | Disposition |
| --- | --- | --- | --- |
| Toolkit file list (139 files; relative paths, sorted by path) | `6fdb5b15…` (138 files) | `a63578d7…` | Changed by TASK-054: `exit.py`, `store.py`, new test file. Complete acceptance rerun with a fresh offline cache verified against the fixed hashes, regressions and full suite. The owner reproduced the hash at closing |
| Specification | `fb74bfe2…` | `fb74bfe2…` | Unchanged |
| Technical design | `a3de6e00…` | `c052ed3c…` | Implementation Evidence note for Bug Fix TASK-054 appended; no design contract change |
| Runner `blackbox.py` | `eea5a1d8…` | `93a13a31…` | Assertions strengthened for AC-001D-06a (full snapshots) and AC-001D-02a (reactivate); none relaxed |
| Environment | Linux container, Python 3.12, offline; macOS host | same | PyPI unreachable: the cache was seeded offline from third-party packages and the toolkit built from current source (disclosed) |

## Review and Documentation Delta

**Reviews during delivery**
- **Resume check:** the earlier part of TASK-050/051 had run on an unintended model. Everything it did was verified and corrected:
  - a cross-model review of its design corrections and its test suite: 2 design defects, fixed in v1.1 with human authorization; 6 blocking and 3 minor test defects, fixed by strengthening only;
  - its pytest temp folder, left inside the product package, was removed.
- **Human decisions:**
  - version-less references keep their resolution and add an informational `exited` list (design v1.2);
  - owner-recorded means-level adjustments, design v1.3, with no contract or AC change.
- **Implementation code review:** 2 blocking findings (a lost-journal race, and commit-journal names escaping the rule folder) and 1 non-blocking (journals missing keys). The escape fix introduced a `#` example-name regression, also fixed. Every fix was RED → GREEN; the re-review found all resolved.
- **Closing review (TASK-053):** 2 blocking findings.
  1. The exit rename collision check read through a path, so it could list a swapped outside folder.
  2. The black-box crash checks did not prove AC-001D-06a's preservation clause.

  It also found 2 non-blocking: the reactivate impact assertions and the pass-rate denominator. [Bug Fix TASK-054](bug-report-TASK-054.md) fixed the product finding test-first (4 RED → 6 GREEN, handle-relative `store.find_collision_at`) and strengthened the runner. The full acceptance was then rerun. The focused re-review found every finding resolved, no new blocking issue, and the feature closable.

**Documentation delta at closing:** none needed. The Framework SKILL.md "Exiting Knowledge" section, `references/cli-contract.md`, `policy-selection.md`, `knowledge-batch.md` and the README rows were delivered with the implementation. The closing review found their commands, flags, result fields, refusal codes and next steps consistent with the code.

**Cross-feature changes** (additive; regressions pass):
- **001-B:** the update base is now the state digest, and import refuses deactivated and reserved identities.
- **001-C:** new missing reasons; "all" lists active rules only and reports `inactive` counts; scope save holds the knowledge lock and the scope lock, with the not-adopted exception.
- **003-A:** Copilot passes through the next step of four Policy refusals.
- **001-A:** knowledge and scope locks use `durable.DirLock`.
- Rules that never exited keep byte-identical records and digests (fixed characterization vectors).

## Outcome Gaps and Honest Limits

- **Stakeholder outcome:** not measured.
- **Platforms:** Windows was not run. On Windows the design falls back to `lstat` and identity checks, which narrows but does not close link-swap races (stated in the design). POSIX-only tests are skipped there.
- **Durability:** crashes were simulated as process kills at every journal step, not power loss. Directory fsync ordering is implemented per the design but not observed on real power loss.
- **Swaps and failures:** symlink swaps, injected I/O failures and tampered journals are proven by the Framework suite, not by black-box runs.
- **Out of scope:** restore of deleted or renamed rules (K-15), automatic reference repair, Preset/tag/Reference-cache providers (FEATURE-001-E/F only plug in), batch exits and namespace/version exits.
- **Accepted limit U-13:** a local writer can forge a structurally valid journal, as they could edit rule files directly.
- **Agent behaviour:** the agent's behaviour for AC-001D-06c was verified structurally in the skill text only.

## Release Disposition

Engineering-only closure. No commit, push, PR or release was performed or requested; the workspace is not a Git repository.

## Refactoring Assessment

Not assessed in a separate analysis (no compulsory refactor).
- **Module sizes:** all modules are under 800 lines; the largest new ones are `exit.py` (656) and `exit_journal.py` (656). The module-size test enforces this.
- **Assessment values:** `overall_quality_score: N/A`; `refactoring_recommended: false` (no evidenced need; this is not a quality verdict); `top_suggestions: []`.

## Next Feature Suggestion

All FEATURE-001-A…D, 002-A…C and 003-A are completed once this closes. Remaining Planned features: 001-E, 001-F, 001-G, 002-D, 002-E, 002-F, 002-G, 003-B, 003-C, 004-A, 004-B. The earlier closing report listed the MVP order after 001-D as 002-D, 002-E, 003-B and 003-C, so the next is **FEATURE-002-D (Trivy Adapter)**. Pending separately: knowledge seeding TASK-028, once the user provides the policy websites.
