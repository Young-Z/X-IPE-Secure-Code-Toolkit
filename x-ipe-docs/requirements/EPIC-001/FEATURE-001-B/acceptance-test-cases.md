# Acceptance Test Cases

> Feature: FEATURE-001-B — Local Knowledge Maintenance & Changelog (EPIC-001)
> Status: Verified delivery for approved scope (all ACs pass on Linux; refusal path also on macOS; Windows not run — same deferral as FEATURE-001-A CR-002)
> Revision: toolkit tree `7dd48feeef45bd09…` (rerun after Bug Fix TASK-014; first run at `6b7848fdc1950d65…`) · specification `f10d8844613c54b5…` · design `87caedc79f6e4b68…` · runner `f0e5d389e8f44e03…` (SHA-256 prefixes)

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-001-B, board status Implemented (TASK-012) |
| Specification / Source | [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/specification.md); parent EPIC-001 FR-04…FR-07, AC-04…AC-08, AC-10 |
| Design / Implementation | [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/technical-design.md); `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/` |
| Target URL | N/A — CLI/library scope |
| Config / Capability | `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true`. Runner [blackbox.py](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/acceptance/blackbox.py) invokes the real `uvx --from …/scripts secure-code knowledge …`; library cases via the existing pytest suite |
| Planned Cases | 21 (black-box 15, unit 6) |

Maintainer-dependent scenarios run only in an **offline Linux container with a disposable HOME** (the trust store is resolved from the OS account and cannot be redirected, by design); the macOS host run covers the unauthorized-User path without touching the developer's trust store.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-03 | Spec G-03; FR-04, FR-05, FR-07 | Maintainer | Traceable, maintainable Local knowledge | TC-B-01…04, 08, 11, 13 Pass | 02*, 03*, 06*, 07*, 09* | not measured |
| G-04 | Spec G-04; FR-06 | Maintainer | Unchanged work never repeated; partial failures isolated | TC-B-03, 05, 06, 07, 08 Pass | 04* | not measured |
| G-05 | Spec G-05; FR-24, K-32, K-33 | Owner / Maintainer | Only Maintainer writes; suspicious content needs a decision | TC-B-09, 10, 11, 14, 15, TC-U-03/04 Pass | 01, 05*, 08* | not measured |

## Full Acceptance / Evidence Map

| AC ID | TC / Type | Original Assertions (summary) | Evidence | Delivery State |
| --- | --- | --- | --- | --- |
| AC-001B-01 | TC-B-14 (Linux, revoked), TC-B-15 (macOS, never authorized) integration | User cannot import/edit; read available | Pass | verified |
| AC-001B-02a | TC-B-01 integration | folder `CWE/4.14/CWE-79` with record, content, changelog "created" | Pass | verified |
| AC-001B-02b | TC-B-02 integration | `@CUSTOM`, `@ACME`, `@CWE` beside `CWE`; custom marked custom | Pass | verified |
| AC-001B-02c | TC-B-03 integration, TC-U-05 unit | invalid charset/dots/reserved names/length refused, others processed | Pass | verified |
| AC-001B-02d | TC-B-03 integration | case-only collision refused, stored rule unchanged | Pass | verified |
| AC-001B-02e | TC-B-03 integration | custom without name / missing ID refused, nothing invented | Pass | verified |
| AC-001B-02f | TC-B-01 integration | source location stored; missing marked explicitly | Pass | verified |
| AC-001B-03a | TC-B-04 integration | two source versions coexist | Pass | verified |
| AC-001B-03b | TC-B-01 integration | one current content, no revision folders | Pass | verified |
| AC-001B-03c | TC-B-04 integration | examples separate files, missing language not required | Pass | verified |
| AC-001B-03d | TC-B-04 integration | advisory applicability; missing → unknown | Pass | verified |
| AC-001B-03e | TC-U-01 unit | relations are references only | Pass | verified |
| AC-001B-03f | TC-B-03 integration | one primary identity; mentioned IDs not extra identities | Pass | verified |
| AC-001B-04a | TC-B-03 integration | one outcome per item with reasons; no batch-wide claim | Pass | verified |
| AC-001B-04b | TC-B-05 integration | item and source-document states; nothing written | Pass | verified |
| AC-001B-04c | TC-B-05 integration | identical resubmission all current, no change | Pass | verified |
| AC-001B-04d | TC-B-06 integration | update candidate; stale accept refused; explicit accept applies + changelog | Pass | verified |
| AC-001B-04e | TC-U-02 unit | similar content not merged | Pass | verified |
| AC-001B-04f | TC-B-07 integration | expected-count mismatch reported; oversize refused, others stored | Pass | verified |
| AC-001B-04g | TC-B-08 integration | killed mid-batch; resume: written current, rest stored | Pass | verified |
| AC-001B-05a | TC-B-09 integration | credential held, not stored, others stored | Pass | verified |
| AC-001B-05b | TC-B-09 integration | embedded instruction held | Pass | verified |
| AC-001B-05c | TC-B-10 integration | placeholder stored with note | Pass | verified |
| AC-001B-05d | TC-B-09 integration, TC-U-06 unit | held until declared; stored with declared findings logged; new occurrence stays held | Pass | verified |
| AC-001B-05e | TC-U-03 unit | role claims in content grant nothing | Pass | verified |
| AC-001B-05f | TC-B-11 integration | flagged update refused, rule and changelog unchanged | Pass | verified |
| AC-001B-06a | TC-B-11 integration | entry with time/role/digest + content diff | Pass | verified |
| AC-001B-06b | TC-B-11 integration | metadata diff + added + deleted example in one entry | Pass | verified |
| AC-001B-06c | TC-B-11 integration | no-op adds nothing | Pass | verified |
| AC-001B-06d | TC-B-11 integration | earlier entries byte-identical | Pass | verified |
| AC-001B-07a | TC-B-11, TC-B-12 integration | stale base refused; 4 parallel real-CLI updates → exactly one commits, others conflict, readers never inconsistent | Pass | verified |
| AC-001B-07b | TC-B-08 integration | process killed at each of 4 commit boundaries → previous (before journal) or new state, always consistent | Pass | verified |
| AC-001B-08a | TC-B-14, TC-B-15 integration | NOT_AUTHORIZED + next step, nothing written, list works | Pass | verified |
| AC-001B-08b | TC-U-04 unit | revoked mid-batch stops further writes | Pass | verified |
| AC-001B-09a | TC-B-09, TC-B-13 integration | list with filters and pending; read-only | Pass | verified |
| AC-001B-09b | TC-B-13 integration | show record/content/changelog/digest; read-only | Pass | verified |
| AC-001B-09c | TC-B-13 integration | status Local count; next step "None" | Pass | verified |

Outcome state for every row: **not measured**.

## Prerequisites and Relevant Inputs

| Role | Path / Boundary | SHA-256 / Environment | Rationale |
| --- | --- | --- | --- |
| specification | FEATURE-001-B specification | `f10d8844…` | all ACs |
| design | FEATURE-001-B technical design | `87caedc7…` | contracts |
| code + tests | `ai-secure-code-toolkit/` tree | `7dd48fee…` (after [Bug Fix TASK-014](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/bug-report-TASK-014.md); black-box rerun 14/14 + 1/1) | behaviour |
| runner | `acceptance/blackbox.py` | `f0e5d389…` | TC-B-* |
| environment | Linux Docker `ghcr.io/astral-sh/uv:python3.12-bookworm-slim`, `--network none`, read-only toolkit mount, disposable HOME; macOS Darwin uv 0.11.23 | — | isolation of trust store; offline proof |
| evidence | [container log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/acceptance/evidence-container-linux.jsonl) `5bca7a83…`, [host log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/acceptance/evidence-host-macos.jsonl) `259f5fb9…`, [unit log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/acceptance/evidence-unit-library.log) `fa9c2812…` (rerun at `7dd48fee…`) | per-TC results |

## Typed Test Cases

### Integration (real CLI via uvx)

TC-B-01 layout · TC-B-02 custom namespaces · TC-B-03 mixed batch · TC-B-04 versions/examples/applicability · TC-B-05 check + resubmission · TC-B-06 update candidate/accept · TC-B-07 limits · TC-B-08 crash (mid-batch kill + 4 commit boundaries) · TC-B-09 flagged items/declaration/pending · TC-B-10 placeholder · TC-B-11 update changelog/no-op/stale/flagged update · TC-B-12 concurrency + concurrent readers · TC-B-13 list/show/status · TC-B-14 revoked Maintainer refused (Linux) · TC-B-15 never-authorized User refused (macOS). Each case's individual checks and results are in the logs; all Pass.

### Unit (library API, fresh run — 19 tests passed)

TC-U-01 `test_relations_are_references_only` · TC-U-02 `test_similar_content_not_merged` · TC-U-03 `test_role_claims_in_content_grant_nothing` · TC-U-04 `test_revoked_mid_batch_stops_writes` · TC-U-05 `test_invalid_components_rejected` (14 parametrized) · TC-U-06 `test_fingerprints_stable_across_line_shift_and_distinct_per_occurrence`.

## Execution Results

| Type | Total Planned | Passed | Failed | Blocked | Partial / Not Run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 | 0 | 0 | 0 | 0 |
| backend-api | 0 | 0 | 0 | 0 | 0 |
| unit | 6 | 6 | 0 | 0 | 0 |
| integration | 15 | 15 | 0 | 0 | 0 |
| structured-review | 0 | 0 | 0 | 0 | 0 |
| TOTAL | 21 | 21 | 0 | 0 | 0 |

Pass rate 21/21 = 100% (diagnostic only).

### Failures / Blockers / Review Limits

| Item | Detail | Disposition |
| --- | --- | --- |
| Harness defect (resolved) | First container run: TC-B-09 evaluated "rule folder absent" after its own later step had legitimately stored the rule; product behaviour reproduced correct in isolation | Check captured immediately after the first import; assertion unchanged; full rerun 14/14 |
| Windows | `msvcrt` lock and Windows replace behaviour unverified | Same deferral as FEATURE-001-A CR-002 |
| Scope | Maintainer scenarios not run on the macOS host (would modify the developer's real trust store) | Covered on Linux; macOS covered by the full developer suite (160 passed) |

### Engineering Delivery versus Stakeholder Outcome

All scoped ACs have current passing evidence → engineering delivery verified for Linux (and macOS via developer suite + refusal path). Stakeholder outcomes (maintainers keeping knowledge traceable and cheap to maintain) **not measured**.

### Refactor / Closing Recommendation

No evidenced refactoring need (largest module 584 lines < 800, ruff clean, 91% coverage). Recommend **Feature Closing**. Free-mode: no application workflow write.
