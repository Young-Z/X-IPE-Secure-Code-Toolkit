# Change Request: CR-TASK-077 — Reviewer coverage item `helpers`

> Created: 2026-10-23
> Status: Applied (documents only; product code not changed in this step)
> Classification: modification (of delivered FEATURE-002-C)
> Related Feature: FEATURE-002-C (requested by FEATURE-002-F)

## Request Details

- **Requestor:** FEATURE-002-F refinement (OQ-08 split, DAO-007 in `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md`), raised to the human as blocker B12.
- **Approver (human authority):** the human, B12 = A, 2026-10-23 20:38, `x-ipe-docs/dao/26-10-23/human_decisions.md` (sha256 `32f8602546c3884b…`): "Approve an additive Change Request on delivered FEATURE-002-C: new Reviewer coverage item `helpers` (first coverage planned, re-coverage extra; existing kinds, records and tests unchanged)".
- **Task:** TASK-077, owner Sage, `x-ipe-task-based-change-request`, interaction mode `dao-represent-human-to-interact`, free of board/Git/memory writes (owner exclusions).
- **Priority:** high for FEATURE-002-F (002-F implementation cannot complete before this CR is implemented).
- **Owning folder:** `x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/`.

## Description

**Present behaviour (delivered 002-C).** A `reviewer` attempt covers only `findings` (existing finding ids) and `na` (N/A decisions: check ids or `policy:<rule>`) — AC-002C-01c/01d, technical design "Coverage of `register`", code `guard/budget.py` `_covers` (`ck.obj(raw, "covers", {"findings", "na"})`, L177–197 at sha `1cbc6833…`). Any other key is refused with `ATTEMPT_INVALID` ("covers has unknown fields").

**Requested change.** Add a third Reviewer coverage item, `helpers`: the ids of temporary check scripts (FEATURE-002-F helpers) known in the same verification. Accounting follows the existing Reviewer-item rule: the first coverage of a helper is planned work, every re-coverage is one extra attempt.

**Explicitly not in this CR.**
- The `helper` **Reviewer subject type** in the shared Reviewer record (FR-002A-4 extension point) — owned by FEATURE-002-F.
- The helper records themselves (submission, ids, digests, lifecycle) — owned by FEATURE-002-F.
- The `helper` and `generation` **attempt kinds** — already delivered by 002-C (pairs coverage), unchanged.
- Guard skill text about helpers — owned by FEATURE-002-F (AC-002F-10a).

## Business Justification

FEATURE-002-F requires an independent read-only Reviewer to review new helpers before execution (AC-002F-03c) and to accept clean post-run conclusions (AC-002F-03h), each under a registered `reviewer` attempt (single-use lease, shared budget). With the delivered coverage set a Reviewer attempt cannot name a helper, so either the review runs outside budget accounting (violates 002-C BR-01/BR-02) or 002-F review is unavailable (the declined path AC-002F-05f). Alternatives considered at B12: decline (helpers become failed methods) or a separate attempt kind. The human chose A (additive coverage item, existing kinds unchanged). Not changing: 002-F review/execution stays blocked.

## Goal / Subgoal Delta

| Goal / Subgoal | Parent / Source | Stakeholder | Before Outcome | Proposed Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | Story / AC Links | Delta Kind | Authority | Affected Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-04 (002-C) | EPIC-001 G-04; FR-21 (B-01…B-03); AC-25 | Developer | Reviewer work on findings and N/A decisions is registered and counted (planned first, extra on repeat); Reviewer work on helpers cannot be registered | Reviewer work on helpers is registered and counted under the same rule, so no Reviewer work on helpers escapes the one shared budget | Means extension of the existing "Reviewer item" accounting; selected option A of B12 (separate kind / decline rejected by the human) | Planned checks: unit + CLI integration (see Planned Validation); not yet executed | Additive only; existing kinds, records, request files, run states and delivered tests unchanged; no new problem code | US-01; AC-002C-01h, 01i (new); 01c, 01d extended by note | means only (acceptance additive) | Human B12 = A (`human_decisions.md` `32f8602546c3884b`) | 002-C delivered evidence stays valid for its revision; new ACs planned | not measured |
| G-04 (002-F enabling) | 002-F spec v1.2 OQ-08 (iii), AC-002F-03c, 03h, 06a | Developer | 002-F review/execution blocked on B12 | 002-F can register Reviewer attempts covering helpers | Enabling contract only; 002-F owns helper subject and records | 002-F acceptance (later) | — | AC-002F-03c, 03h (consumers) | unchanged (consumer) | same | none in 002-F yet | not measured |

## Impact Analysis

### Classification

**modification of FEATURE-002-C.** The change stays inside 002-C's approved outcome (G-04: one shared budget; every unit of agent work registered; planned-first/extra-on-repeat; BR-02 already speaks of "Reviewer item"). No new stakeholder, workflow or boundary: the Reviewer, the `reviewer` kind, the lease and the counting rule exist; only the set of Reviewer items grows by one type. The stakeholder outcome that motivates it (temporary check scripts) is already a separate feature (FEATURE-002-F), so no new feature is needed. `new_feature_ids`: none.

### Comparison Matrix

| Aspect | CR Requirement | Existing Feature(s) | Evidence / Boundary Decision |
| --- | --- | --- | --- |
| Users | Host agent registers; Developer reads report | Same | No change |
| Workflow | `guard attempt` (kind `reviewer`, covers helpers) → Reviewer → `guard review` citing the attempt | Same flow with findings/N/A | Unchanged flow; 002-F adds the helper subject |
| Data Model | `guard-attempt/v1` reviewer `covers` gains optional `helpers`; attempt record `covers.helpers` only when requested; `budget.seen_before.helpers` read as empty when absent | `covers` {pairs, findings, na} (+`components` for internal `tool_update`, 002-D) | Additive; `guard-run/v1` and `guard-attempt/v1` unchanged versions; old states load |
| UI Elements | Report "Attempts" table Covers column lists helper ids | Lists pairs, finding and N/A ids | Report-only text; reasoned: no graphical UI (spec "Linked Mockups" N/A) |
| API Endpoints | `budget.register` / `budget.cite` accept/check `helpers`; known helper ids read from run state `helpers[].id` | `register`, `cite` | Library/CLI; no new command, no new problem code |

### Conflict Analysis

Inspected (sha256 prefix at read time): 002-C `specification.md` `fca9f235384ee2b6` (= delivered revision), 002-C `technical-design.md` `6d64c8aef36a94c3`, 002-F `specification.md` `3cbf9d1627ae5c8b`, 002-A `specification.md` `ab170f062928d030` (FR-002A-4), `guard/budget.py` `1cbc6833a8a7643e`, `guard/service.py` `8f3d7303d58182fe`, `guard/report.py` `ce3cc4e54b92b73d`, `guard/control.py` `a230b72e11137ffc`, tests `tests/guard/test_budget_units.py` `7af68ac54af90c63`, `tests/adapters/test_trivy_units.py` `2290b72b91a61624`, `tests/guard/test_guard_budget.py` `903cbb1b9a0e9cc5`, `tests/guard/test_trivy_provision.py` `64065bf9a14b83e1`, Guard skill `references/guard-records.md` `868f2da821fd93e5`; 002-C acceptance `acceptance/blackbox.py` (L190, L371). Callers of `budget.register`/`cite`: `guard/control.py:39`, `guard/toolctl.py:82`, `adapters/trivy_provision.py:250`, `guard/service.py:354,414`. Copilot (003-A) does not call `budget` (own collaboration records). No other pending CR on 002-C found (no `CR-*.md` in `x-ipe-docs/`). Product code may be concurrently edited for FEATURE-002-G by another worker; hashes are at read time.

| # | Type | Affected Feature | Severity | Classification | Description | Source / Revision | Resolution / Authority |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | specification | 002-C | medium | expected | AC-002C-01c/01d, FR-002C-2 limit Reviewer coverage to findings and N/A decisions | spec L75–76, L134 `fca9f235…` | Original text kept; supersession notes + new AC-002C-01h/01i appended (B12) |
| 2 | design | 002-C | medium | expected | "Coverage of `register`" and "Extra counting" name only findings/na; state example `seen_before`/`covers` | design L144–200 `6d64c8ae…` | Appended section "CR-TASK-077 Delta"; original kept (B12) |
| 3 | code | 002-C | medium | expected | `_covers` reviewer keys `{"findings","na"}`; `_seen`, `cite` and the empty-coverage message ignore helpers | `budget.py` L177–197, L220–231, L314–319 `1cbc6833…` | Implementation step after this CR (not here) |
| 4 | code (report) | 002-C | low | expected | Attempts table Covers column concatenates pairs+findings+na; helper ids would be hidden | `report.py` L550 `ce3cc4e5…` | Add `covers.get("helpers", [])` at implementation |
| 5 | dependency (002-A/002-F) | 002-A, 002-F | medium | expected | `guard review` builds `used_items` from `finding`/`na_decision` subjects only; once 002-F adds `helper` subjects, a missing `helpers` entry would let helper subjects bypass the coverage check | `service.py` L410–414 `8f3d7303…`; 002-A FR-002A-4 | DEC-3: CR adds fail-closed `used_items["helpers"]` wiring (inert until 002-F's subject type exists) |
| 6 | dependency (002-F design) | 002-F | medium | expected | Known-helper id source undefined (002-F has no design yet) | 002-F spec AC-002F-03c, 08c | DEC-2: read-only contract `state["helpers"][*]["id"]`; 002-F design must adopt it or raise a follow-up CR |
| 7 | data compatibility | 002-C, 002-D | low | expected | Exact `covers` dict asserted for `tool_update` (`test_trivy_units.py:816–821`); old run states lack the key | tests at hashes above | `helpers` key written only on reviewer attempts that request it; readers default absent → empty; no migration |
| 8 | budget sizing | 002-F | medium | expected | AC-002F-03h post-run acceptance is re-coverage → one extra attempt per helper; default extra attempts = 3 (B-07), so a run with ≥ 4 accepted helpers needs a user extension | design B-07; 002-F AC-002F-03h | Bound by B12 wording ("re-coverage extra"); handed to 002-F design/report wording; no 002-C change |
| 9 | budget bypass | 002-F | low | expected | Agent could resubmit a helper under a new id to get a "first" (planned) review | 002-F AC-002F-08c | Bounded: each resubmission needs a `generation` attempt on the same (check, helper method) pair, which is extra under unchanged 002-C rules; 002-F design must keep that lineage |
| 10 | skill text | 002-C / 002-F | low | expected | `references/guard-records.md:74` describes reviewer coverage as findings and N/A only | `868f2da8…` | DEC-4: leave unchanged in the CR implementation; 002-F updates skill text (AC-002F-10a) |

No unexpected conflicts. No conflict with 002-B (tool attempts cover pairs), 002-D (`tool_update` covers components), 003-A (no `budget` calls), 002-A record/ledger semantics (helper subject is 002-F's extension, not this CR).

Unexpected Conflict Resolution and Mitigation Strategy: none required.

### Affected Components

| Component | Impact Level | Details |
| --- | --- | --- |
| `guard/budget.py` (`_covers`, `_seen`, `register` extra/exhausted naming, `cite`) | medium | Accept, validate, dedupe and count `helpers`; cite checks `used["helpers"]` |
| `guard/service.py` (`review`) | low | `used_items["helpers"]` from subjects of type `helper` (DEC-3) |
| `guard/report.py` (Attempts table) | low | Covers column includes helper ids |
| `guard/control.py` | none | Passes `covers` through unchanged |
| Guard skill references | none (DEC-4) | Updated by 002-F |
| 002-C spec/design | documents | This CR |

### Dependencies

Upstream: FEATURE-002-A (Reviewer record envelope, review command), FEATURE-002-C (budget). Downstream consumer: FEATURE-002-F (AC-002F-03b…03d, 03f, 03h, 04a, 04e, 04f, 04i, 04o, 05g, 06a, 07a, 07c, 07d). Shared contract: run state `guard-run/v1`, request `guard-attempt/v1`.

## Proposed Approach

### Exact delta

1. **Request (`guard-attempt/v1`, version unchanged).** For `kind: "reviewer"`, `covers` allowed keys become `{"findings", "na", "helpers"}`; each optional; `helpers` is a list of helper id strings. At least one item across the three is required. Other kinds unchanged (a `helpers` key there stays "covers has unknown fields" → `ATTEMPT_INVALID`).
2. **Validation.** Each helper id must be a key string present in the verification's known helpers = `{h["id"] for h in state.get("helpers", [])}` (DEC-2); absent key → empty set → any helper id refused `ATTEMPT_INVALID` "covers.helpers[i]: unknown helper '<id>'". Duplicates are deduplicated (as findings/na). Empty-coverage message becomes "a reviewer attempt must cover at least one finding, N/A decision or helper" (no delivered test asserts the old text).
3. **Attempt record.** `covers` gains `"helpers": [...]` **only** when the request named at least one helper; otherwise the record is byte-for-byte the delivered shape `{"pairs": [], "findings": [...], "na": [...]}`.
4. **Counting.** `seen.helpers` = `budget.seen_before.get("helpers", [])` ∪ every earlier attempt's `covers.get("helpers", [])`, whatever its status (finished, unfinished, cancelled — same as findings/na). A covered helper is extra iff in `seen.helpers`; first coverage is planned (there is no plan list for Reviewer items, as for findings/na). `extra` = extra pairs + extra findings + extra na + extra helpers. `ATTEMPTS_EXHAUSTED` names extra helper ids after the finding and N/A ids; first coverage stays possible after the extra attempts run out (AC-002C-03b).
5. **Cite.** `cite` refuses (`ATTEMPT_INVALID` "attempt … does not cover …") any `used["helpers"]` id not in the attempt's `covers.get("helpers", [])`. `guard review` passes `used_items["helpers"] = {s["id"] for s in subjects if s["type"] == "helper"}` (DEC-3).
6. **Budget, pause, time exhaustion, cancel, overrun, model usage.** Unchanged: helper-covering Reviewer attempts are ordinary `reviewer` attempts (`RUN_PAUSED`, `BUDGET_TIME_EXHAUSTED`, cancel marks unfinished ones `cancelled`, overrun in consumed time, model usage counted as Reviewer/unknown).
7. **Legacy/compatibility.** No migration; `ensure` unchanged (pre-002-C states cannot contain helpers, so no baseline needed); `initial()` output unchanged (no `seen_before.helpers` key written). Run states written before this CR load and behave identically. A state containing helper coverage is not supported by an older toolkit (downgrade out of scope).
8. **Report.** Attempts table Covers column = pairs + findings + na + helpers. Budget summary keys unchanged.
9. **Error codes.** None new. `ATTEMPT_INVALID`, `ATTEMPTS_EXHAUSTED`, `BUDGET_TIME_EXHAUSTED`, `RUN_PAUSED`, `RUN_CANCELLED` reused.

### Documents changed in this step

- 002-C `specification.md`: Version History row v1.1; supersession notes under AC-002C-01 (01c/01d text kept); new AC-002C-01h, AC-002C-01i; FR-002C-2 addendum; G-04 AC links; edge cases; Acceptance Traceability row; dependency note. No delivered text deleted.
- 002-C `technical-design.md`: Version History row v1.1; appended section "CR-TASK-077 Delta: Reviewer coverage item `helpers`"; Design Change Log row. No delivered text deleted.

### Affected Acceptance and Planned Validation

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002C-01h | GIVEN an open, unpaused verification with remaining time and helpers known in it WHEN the agent registers a `reviewer` attempt whose coverage names helpers (alone or with findings and N/A decisions) THEN the attempt is recorded with those helpers AND a helper id unknown in that verification, a `helpers` item on any other kind, or a Reviewer attempt covering nothing is refused with `ATTEMPT_INVALID` and nothing recorded AND a Reviewer record citing the attempt whose `helper` subjects name a helper outside its coverage is refused AND attempts and request files that do not name helpers are recorded and validated exactly as before | Integration |
| AC-002C-01i | GIVEN registered attempts WHEN extra attempts are counted THEN covering a helper for the first time is planned work AND every helper an attempt covers again, whatever the earlier result or attempt status, counts as one extra attempt AND when the extra attempts are used up an attempt re-covering a helper is refused with `ATTEMPTS_EXHAUSTED` naming it while first coverage is still accepted AND pause, time exhaustion, cancellation, overrun and model-usage rules apply to these attempts unchanged AND verifications opened before this change load and count as before | Integration |

Planned checks (not executed in this step):
- **Unit (`tests/guard/test_budget_units.py`, new test functions only):** register helpers planned/extra; mixed findings+na+helpers counting; unknown helper / helpers on `semantic_review`/`helper`/`generation` kinds / empty reviewer coverage → `ATTEMPT_INVALID`; dedupe; `ATTEMPTS_EXHAUSTED` names helper id while first coverage passes; cite refuses helper outside coverage and accepts inside; legacy state without `helpers`/`seen_before.helpers` loads and counts; record shape unchanged when no helper named; cancelled attempt's helpers still count as seen.
- **Integration (`tests/guard/test_guard_budget.py`, new test functions only):** `guard attempt` CLI round trip with a run state seeded with a `helpers` list (fixture writes the 002-F-owned key directly, since 002-F commands do not exist yet); pause/time-exhausted/cancelled refusals; report Covers column lists helper ids.
- **Unit (service wiring, DEC-3):** `guard review` passes helper subject ids to `cite` — testable only by unit-level injection until 002-F adds the subject type; black-box coverage moves to 002-F acceptance (AC-002F-03c/03h).
- **Regression:** full delivered suite unchanged and passing; delivered 002-C acceptance runner (`acceptance/blackbox.py`) unchanged and passing.

### Delivered tests: change required vs byte-identical

- **Change required: none.** No delivered test asserts the reviewer coverage set in a way that the additive change breaks.
- **Byte-identical (inspected, must stay unchanged and pass):**
  - `tests/guard/test_budget_units.py:172–190` `test_register_invalid_coverage` — every parameter (including `("reviewer", {"findings": [], "na": []})` and `("reviewer", pairs(...))`) still refused with `ATTEMPT_INVALID`.
  - `tests/guard/test_budget_units.py:193–197` `test_reviewer_items_retry_counts` — counting of findings/na unchanged.
  - `tests/guard/test_budget_units.py:289–316` `test_ensure_legacy_defaults_and_seen_baseline` (`seen_before` asserted per key, not as a whole dict, L309–312) and `:318` `test_ensure_is_idempotent_for_new_states`.
  - `tests/adapters/test_trivy_units.py:793` `test_budget_internal_tool_update_attempt` (exact `covers` dict for `tool_update`, L816–821) — unaffected because `helpers` is never added to non-reviewer attempts.
  - `tests/guard/test_trivy_provision.py:178` `test_02b_operation_argv_declaration_budget_report` (L281 `covers.components`/`pairs`) — unaffected.
  - `tests/guard/test_guard_budget.py:116, 295, 348` reviewer attempts with findings/na — unaffected.
  - 002-C acceptance `acceptance/blackbox.py:190, 371` — unaffected.
- **Invalidated evidence:** none of 002-C's delivered acceptance/closing evidence is invalidated (behaviour for requests without `helpers` is unchanged); the two new ACs are `planned`.

## Decisions (DAO mode — within-skill, inside the B12 scope)

| ID | Question | Options | Recommendation (applied in documents) |
| --- | --- | --- | --- |
| DEC-1 | Classification | A modification of 002-C · B new feature | **A** — same G-04 outcome and accounting rule; 002-F already owns the new stakeholder outcome |
| DEC-2 | Source of "known helper ids" for validation | A read-only `state["helpers"][*]["id"]` (key owned and written by 002-F) · B no validation (any string) · C callback registry injected by 002-F | **A** — fail-closed now (absent → nothing known), simple, keeps budget pure; 002-F design must adopt it or raise a follow-up CR. B rejected (unknown items would let an agent pre-burn or fake coverage); C over-engineered |
| DEC-3 | Wire `used_items["helpers"]` in `guard review` | A in this CR (inert until 002-F's subject type exists) · B leave to 002-F | **A** — keeps the coverage check complete and fail-closed at the point the contract is defined; one line in `service.py` (599 lines, below the 800 limit) |
| DEC-4 | Guard skill reference text (`guard-records.md:74`) | A update now · B leave to 002-F (AC-002F-10a) | **B** — helpers do not exist until 002-F; AC-002C-06a unchanged |
| DEC-5 | Record shape for attempts not naming helpers | A always write `helpers: []` · B write `helpers` only when named | **B** — required by "existing records and tests unchanged" (exact dict at `test_trivy_units.py:816`) |
| DEC-6 | Spec/design version | A v1.1 minor additive · B v2.0 | **A** — additive, no retirement |

None of these changes goal, acceptance boundary or authority beyond B12; all are DAO-resolvable. Large-scope gate: not triggered (single feature, additive ACs, human-approved).

## Mockup Impact

UI/UX change: No. No mockups exist for FEATURE-002-C (spec "Linked Mockups": N/A).

## Approval

Human decision B12 = A (2026-10-23 20:38, `x-ipe-docs/dao/26-10-23/human_decisions.md` sha256 `32f8602546c3884b…`) authorizes exactly this additive CR on FEATURE-002-C; document writes limited to this CR file and the 002-C specification and technical design (owner instruction, TASK-077). DEC-1…DEC-6 are within-skill recommendations inside that scope, not human approvals. Product-code changes need a separate implementation task.

## Execution

- Classification Result: modification.
- Conflicts Resolution: all_expected.
- Actual Actions Taken: this CR file created; 002-C specification and technical design received append/supersession-only deltas (Version History v1.1 rows, notes, new ACs AC-002C-01h/01i, appended design section, change-log row). No delivered text deleted, no IDs reused, no product code, board, Git or memory change, no mockup.
- Remaining work (suggested to the owner, not executed): implementation of this CR in `guard/budget.py`, `guard/service.py`, `guard/report.py` with the planned tests (test-first), then 002-C regression and the two new ACs' acceptance; FEATURE-002-F technical design adopts DEC-2 and risks #8/#9.

### Context and Verification Evidence

See Conflict Analysis for input hashes. Output hashes are reported by the task owner hand-off (computed after writing). Delivery: documents only. Stakeholder outcome: not measured.

## Links

- Specification: `x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/specification.md`
- Technical design: `x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/technical-design.md`
- Requesting feature: `x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/specification.md`
- Authority: `x-ipe-docs/dao/26-10-23/human_decisions.md` (B12); `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md` (DAO-007)

## Change History

| Date | Change | By |
| --- | --- | --- |
| 2026-10-23 | CR created and applied to 002-C specification and technical design (documents only) | Sage (TASK-077) |

## Erratum (2026-10-23, TASK-081 — FEATURE-002-F technical design, DAO-014 TD DEC-9)

Non-destructive note; the text above is unchanged and this CR's exact delta is unaffected (no 002-C change).

The budget-sizing estimate in Conflict #8 and in the 002-C design handoff (2) ("a run with ≥ 4 accepted helpers needs a user extension") counted only the post-run acceptance re-coverage. Under the unchanged 002-C rules:
- one helper costs **one extra attempt for its `helper` attempt**, because the same (check, helper method) pair is already seen through the authoring `generation` attempt;
- it costs **one more for the post-run acceptance** of a clean result (helper re-coverage);
- it costs **one more** when the helper method was added by a method change, because the `generation` pair was not planned.

With the default 3 extra attempts, about **one clean helper** fits; a second helper normally needs `secure-code guard extend` by the user. FEATURE-002-F reports the expected extra attempts (design §11.3). Optional human CR candidate (not approved): a helper-aware default budget. Recorded by the TASK-081 design worker for Sage per DAO-014 (technical design, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`).
