# Acceptance Test Cases

> Feature: FEATURE-001-C — Policy Resolution & Adoption Scope Selection (EPIC-001)
> Status: Verified delivery for approved scope (all ACs pass on Linux; never-authorized User path also on macOS; Windows not run — same deferral as FEATURE-001-A CR-002)
> Revision: toolkit tree `e9fdecb199e2ff43…` (rerun after Bug Fix TASK-020; first run at `6ada1747b51892a8…`) · specification `b35d4e9057001556…` · design `625b05fe2b7949f8…` · runner `e5550429fe3a230c…` (SHA-256 prefixes)

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-001-C, board status Implemented (TASK-017) |
| Specification / Source | [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md); parent EPIC-001 FR-09, FR-10, AC-11 (Framework part), AC-12 |
| Design / Implementation | [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/technical-design.md); `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/policy/` |
| Target URL | N/A — CLI/library/skill scope |
| Config / Capability | `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true`. Runner [blackbox.py](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/blackbox.py) invokes the real `uvx --from …/scripts secure-code policy|scope|knowledge …` and never imports toolkit code; library and skill-package cases via the existing pytest suite |
| Planned Cases | 17 (integration 15, unit 1, structured-review 1) |

Scenarios needing prepared knowledge run only in an **offline Linux container with a disposable HOME** (an owner authorization is needed to import test rules; the trust store cannot be redirected by design). The macOS host run covers the never-authorized User path; `auth status` on the host reports role `user`.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-03 | Spec G-03; FR-09, FR-10 | Developer, upstream agent | Library ≠ suggested ≠ adopted; nothing invented; adopted scope traceable | TC-C-01…12, 15, TC-U-01, TC-S-01 Pass | 01*, 02a…02e, 02g, 03*, 04*, 05* | not measured |
| G-05 (enabling) | Spec G-05; P-02 | Owner | Choosing Policies grants no editing rights | TC-C-14, 15 Pass | 01e, 02f | not measured |

## Full Acceptance / Evidence Map

| AC ID | TC / Type | Original Assertions (summary) | Evidence | Delivery State |
| --- | --- | --- | --- | --- |
| AC-001C-01a | TC-C-01 integration | identity, name, marking, full content as requirement, advisory applicability, examples, relations as references, source evidence (location, state digest, last change); `retrieved`; no unresolved | Pass | verified |
| AC-001C-01b | TC-C-01 integration | applicability `unknown`; location `not recorded` listed in unresolved; still available | Pass | verified |
| AC-001C-01c | TC-C-02 integration | partial never complete; counts consistent | Pass | verified |
| AC-001C-01d | TC-C-03 integration | hand-edited → `inconsistent`, undecodable → `unreadable`; no content returned; envelope, no traceback | Pass | verified |
| AC-001C-01e | TC-C-14 (Linux, revoked), TC-C-15 (macOS, never authorized) integration | resolution works without authorization; knowledge and pending stores unchanged | Pass | verified |
| AC-001C-01f | TC-C-01 integration | all available → `complete`; policy-level gaps don't change it | Pass | verified |
| AC-001C-02a | TC-C-02 integration | library size, suggested refs, proposal digest, nothing adopted; no scope record or Preset | Pass | verified |
| AC-001C-02b | TC-C-02 integration | version-less ref over two versions → `unclear`/`multiple_versions` with both candidates; none selected | Pass | verified |
| AC-001C-02c | TC-C-02 integration | `not_found`; `pending_decision` with pending content not returned | Pass | verified |
| AC-001C-02d | TC-C-04 integration | `does_not_match` / `matches` / `unknown`; none excluded | Pass | verified |
| AC-001C-02e | TC-S-01 structured review + executable package check | SKILL.md "Selecting Policies" (lines 87–115) and `references/policy-selection.md`: concrete references via read operations, reasons and language notes, reversible exclusions, unclear/conflict questions with no precedence, confirmation before save, never a Preset | Pass | verified |
| AC-001C-02f | TC-C-14 integration | revoked User saves a scope; import still `NOT_AUTHORIZED` | Pass | verified |
| AC-001C-02g | TC-C-07 integration | clarification note and conflict reason recorded verbatim; no other substitution | Pass | verified |
| AC-001C-03a | TC-C-05 (Linux), TC-C-15 (macOS) integration | empty library (pending only) → `maintenance_needed`, exit 1, no invented Policy, next step Maintainer import | Pass | verified |
| AC-001C-03b | TC-C-06 integration | none of the refs available → `maintenance_needed`; next step names them | Pass | verified |
| AC-001C-03c | TC-C-07 integration | undecided missing/unclear → `DECISION_MISSING` naming them; nothing written; unclear cannot be adopted | Pass | verified |
| AC-001C-03d | TC-C-07 integration | not-adopted with reasons; never counted as adopted; zero adopted refused | Pass | verified |
| AC-001C-04a | TC-C-08 integration | highlighted Apply All notice (first, `!! Notices` in text), every rule of every ns/version, multi-version highlight, pending excluded and counted | Pass | verified |
| AC-001C-04b | TC-C-08 integration | mode `apply_all`, concrete list, artifact scope stated as separate | Pass | verified |
| AC-001C-04c | TC-C-08 integration | rule imported later is not adopted | Pass | verified |
| AC-001C-05a | TC-C-09 integration | record in `scopes/`, named by id, all fields | Pass | verified |
| AC-001C-05b | TC-C-10 integration | unchanged adopted; changed `needs_reconfirmation` with both digests, content for review only; removed `missing`; `partial` with next step | Pass | verified |
| AC-001C-05c | TC-U-01 unit; TC-C-09 integration | id excludes creation time; 4 parallel CLI saves → one record, one `created`; repeat keeps first time | Pass | verified |
| AC-001C-05d | TC-C-11 integration | tampered, malformed and non-UTF-8 records → `SCOPE_INVALID`, next step, no Policies, no traceback | Pass | verified |
| AC-001C-05e | TC-C-12 integration | no `--confirmed` → refused, nothing written | Pass | verified |
| AC-001C-05f | TC-C-12 integration | rule updated or removed before save → `STALE_CONFIRMATION` naming only it; Apply All + new import → stale naming it; nothing written | Pass | verified |
| AC-001C-05g | TC-C-10 integration | unchanged scope → `complete` | Pass | verified |
| AC-001C-05h | TC-C-10 integration | all adopted changed/removed → `maintenance_needed`, nothing adopted | Pass | verified |
| NFR-001C-1 | TC-C-13 integration | knowledge lock held by another process → `LOCKED` envelope with next step | Pass | verified |

Outcome state for every row: **not measured**.

## Prerequisites and Relevant Inputs

| Role | Path / Boundary | SHA-256 / Environment | Rationale |
| --- | --- | --- | --- |
| specification | FEATURE-001-C specification | `b35d4e90…` | all ACs |
| design | FEATURE-001-C technical design | `625b05fe…` (change log only since first run) | contracts |
| code + tests + skill docs | `ai-secure-code-toolkit/` tree | `e9fdecb1…` (after [Bug Fix TASK-020](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/bug-report-TASK-020.md)) | behaviour |
| runner | `acceptance/blackbox.py` | `e5550429…` (TC-C-11 non-UTF-8 record and TC-C-12 removed-rule checks added) | TC-C-* |
| environment | Linux Docker `ghcr.io/astral-sh/uv:python3.12-bookworm-slim`, `--network none`, `UV_OFFLINE=1`, read-only toolkit mount, disposable HOME, uv cache volume freshly warmed and verified to contain the fixed code; macOS Darwin uv 0.11.23 with `UV_REFRESH_PACKAGE=ai-secure-code-toolkit`, Python 3.13 runner | — | trust-store isolation; offline proof |
| evidence | [container log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/evidence-container-linux.jsonl) `03b11dd3…`, [host log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/evidence-host-macos.jsonl) `3ef8a509…`, [unit log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/evidence-unit-library.log) `fd0e1d53…`; host stderr empty, container stderr holds only the cache check (`3` = fixed `scope.py` present in the uv cache) | per-TC results |

## Typed Test Cases

### Integration (real CLI via uvx)

TC-C-01 Policy structure · TC-C-02 mixed request (partial, unclear, not found, pending) · TC-C-03 damaged rules · TC-C-04 language notes · TC-C-05 empty library · TC-C-06 none available · TC-C-07 decisions coverage and verbatim reasons · TC-C-08 Apply All · TC-C-09 record contents + parallel saves · TC-C-10 drift on load · TC-C-11 invalid records · TC-C-12 confirmation flag + stale confirmation · TC-C-13 held lock · TC-C-14 revoked User rights (Linux) · TC-C-15 never-authorized User (macOS). Individual checks and results per case are in the logs; all Pass.

### Unit (library API, fresh run — 29 tests passed incl. TC-S-01)

TC-U-01 `test_scope_id_excludes_creation_time_and_detects_changes` (plus the other unit tests in `test_policy_units.py`: references, status table, proposal digest, tamper, language notes, record validation).

### Structured Review

TC-S-01 Framework `SKILL.md` lines 87–115 and `references/policy-selection.md` read against AC-001C-02e clause by clause (concrete references via `knowledge list`/`show` — SKILL step 1; reasons and language notes — step 3; reversible exclusions and unclear/conflict questions without precedence — step 4; confirm, then `scope save --confirmed`, never a Preset — step 5); executable package check `test_skill_package_describes_scope_selection` passed. Keyword presence alone is not behavioural proof of agent conduct (see gaps).

## Execution Results

| Type | Total Planned | Passed | Failed | Blocked | Partial / Not Run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 | 0 | 0 | 0 | 0 |
| backend-api | 0 | 0 | 0 | 0 | 0 |
| unit | 1 | 1 | 0 | 0 | 0 |
| integration | 15 | 15 | 0 | 0 | 0 |
| structured-review | 1 | 1 | 0 | 0 | 0 |
| TOTAL | 17 | 17 | 0 | 0 | 0 |

Pass rate 17/17 = 100% (diagnostic only). Developer suite at the same revision: 241 passed on macOS Python 3.14, macOS Python 3.11 and Linux Python 3.12 (TASK-020).

### Failures / Blockers / Review Limits

| Item | Detail | Disposition |
| --- | --- | --- |
| Closing-review defect (resolved) | Non-UTF-8 text crashed resolve/save/show (traceback) and 05f removed-rule case was not exercised | [Bug Fix TASK-020](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/bug-report-TASK-020.md); full rerun 14/14 + 1/1 + 29/29 |
| Stale tool environment (resolved) | First post-fix container run used a uv tool environment built before the fix (13/14, reproducing the bug); assertions unchanged | Cache volume re-warmed and verified; host package refreshed; full rerun |
| Windows | `msvcrt` lock path (knowledge and scope locks) unverified | Same deferral as FEATURE-001-A CR-002 |
| Agent conduct | Whether a real agent interprets clues well and sets `--confirmed` only after real user confirmation is not observable by the script | Instructions verified (TC-S-01); honest limit stated in spec Technical Considerations |
| Scope | Maintainer-prepared scenarios not run on the macOS host (would modify the developer's real trust store) | Covered on Linux; macOS covered by the developer suite and the User path |

### Engineering Delivery versus Stakeholder Outcome

All scoped ACs have current passing evidence → engineering delivery verified for Linux (and macOS via the developer suite + User path). Stakeholder outcomes (developers and agents never confusing imported, suggested and adopted Policies in real work) **not measured**.

### Refactor / Closing Recommendation

No evidenced refactoring need: largest new module `policy/scope.py` 373 lines (< 800), ruff clean, new-module coverage 81–100%. Recommend **Feature Closing**. Free-mode: no application workflow write.
