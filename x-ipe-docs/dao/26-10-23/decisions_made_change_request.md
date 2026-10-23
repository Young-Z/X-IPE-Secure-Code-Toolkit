# DAO Decisions: Change Request

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-23T20:46:18+08:00 | TASK-078 | x-ipe-task-based-change-request | approval | 0.85 | CR4 (human-approved) on FEATURE-001-F: DEC-1…5 all A confirmed (full Preset adoption text, `_proposal` only, no skill change, all statuses, additive AC-001F-04l + BR-18); a short independent delta review of CR doc + spec v1.6 + design v1.4 required before implementation (not blocking other work) |
| DAO-002 | 2026-10-23T20:48:26+08:00 | TASK-077 | x-ipe-task-based-change-request | approval | 0.84 | CR B12 on FEATURE-002-C: DEC-1 A, DEC-2 A (fail-closed state['helpers'] contract that 002-F must adopt or raise a follow-up CR), DEC-3 A (inert fail-closed wiring), DEC-4 B, DEC-5 B, DEC-6 A confirmed; confirmation of CR docs after the running independent review passes; acceptance scope of 077 clarified for DAO-014 (1) |
| DAO-003 | 2026-10-23T22:10:19+08:00 | TASK-086 | x-ipe-task-based-change-request | approval | 0.84 | CR C1 (human-approved) on FEATURE-002-A renderer identity: DEC-1…9 and DEC-G1 all A, with condition that renderer_digest covers report.py plus its toolkit-internal rendering imports (fail-safe direction) guarded by a test; 002-G follow-up never claims tampering; docs confirmed after the running independent review |

---

<!-- Detail sections are appended below this line -->

## DAO-001
- **Timestamp:** 2026-10-23T20:46:18+08:00
- **Task ID:** TASK-078
- **Feature ID:** FEATURE-001-F
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-change-request
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human CR4 = yes (human_decisions.md, 20:38)
- **Disposition:** approval
- **Confidence:** 0.85

### Message
> CR4: CR doc CR-TASK-078-adoption-text.md (ac400b62…), spec v1.6 (ccb4d48b…; new AC-001F-04l, BR-18, no existing text changed), design v1.4 (14e1bfe6…). Fix in preset_scope._proposal only: adoption = "nothing adopted yet — the user must confirm, then: secure-code preset scope-save NAME --decisions FILE --confirmed"; plain policy resolve byte-identical; key set/order and proposal_digest unchanged; no BR-11/09a supersession. Confirm DEC-1 A (full form), DEC-2 A (_proposal only), DEC-3 A (no skill change), DEC-4 A (all statuses incl. maintenance_needed), DEC-5 A (new AC + BR-18). No independent review of the CR docs yet — required before implementation?

### Guidance Returned
> DAO verified:
> - hashes: CR doc ac400b62…, spec ccb4d48b… (v1.6 row L20, AC-001F-04l L117, BR-18 L226) and design 14e1bfe6…;
> - the human approval (CR4 = yes, human_decisions.md);
> - delivered `policy/resolve.py` L354 holds the 001-C adoption text ("…then: secure-code scope save --confirmed");
> - the earlier DAO-005 (refinement) finding that `proposal_digest` covers only mode and entries, so the adoption text is outside the digest;
> - existing tests: `tests/presets/test_preset_scope.py` L32 (key set) and L66 ("nothing adopted yet" substring) stay true; the pre-001-F fixtures (`fixtures/pre_001f/*-proposal.json`) are plain `policy resolve` outputs and stay unchanged; the 001-C `test_policy.py` assertions are unaffected.
> Decisions:
> - **DEC-1 → A.** Full form, matching `next_steps` and the skill.
> - **DEC-2 → A.** `_proposal` only. `resolve.py`, plain `policy resolve`, 001-C tests and the pre-001-F fixtures stay byte-identical; the key set/order and `proposal_digest` are unchanged.
> - **DEC-3 → A.** No skill change; the skill already directs `preset scope-save`.
> - **DEC-4 → A.** Consistent with status-independent 001-C text; `next_steps` carry the repair guidance and the save path still refuses unusable proposals.
> - **DEC-5 → A.** Additive AC + BR-18. BR-11/AC-001F-09a/09d are not violated because 001-C output is unchanged.
> **Independent review: required before implementation.** It modifies a Completed feature, so make it a short delta review of the CR doc, spec v1.6 and design v1.4. It does not block other work, and implementation is serialized behind TASK-076 anyway.
> Implementation conditions:
> - TDD with the new AC-001F-04l test written first (RED);
> - full suite, including byte-identity of plain `policy resolve` against the pre-001-F fixtures;
> - after implementation, re-run 001-F acceptance for 04a/04l plus the 001-C regression;
> - append a note to the earlier 001-F acceptance/closing evidence citing CR-TASK-078 (never edit old results);
> - the Framework package payload is unchanged, so no ERA_001A_REMOVED update is needed unless files are added.
> No commit, push or release (B8).

### Rationale
> The CR is human-approved, small, and confined to 001-F output, with delivered 001-C behavior and digests unchanged. Because it modifies a delivered feature, a proportionate independent delta review keeps the established gate.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-change-request"
>     match_strength: "strong"
>     reason: "Independent delta review of the CR documents, then hand off to implementation"
>     execution_steps:
>       - phase: "Review"
>         step: "Independent review at CR/spec/design hashes"
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "partial"
>     reason: "After review, TDD implementation queued behind TASK-076"

### Follow-up
> None.

## DAO-002
- **Timestamp:** 2026-10-23T20:48:26+08:00
- **Task ID:** TASK-077
- **Feature ID:** FEATURE-002-C
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-change-request
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B12 = A (human_decisions.md, 20:38)
- **Disposition:** approval
- **Confidence:** 0.84

### Message
> CR doc CR-TASK-077-helpers-coverage.md (16a593d2…); 002-C spec v1.1 (14c59830…; new AC-002C-01h/01i, FR-002C-2a, append-only, 01c/01d text kept with extension note); design v1.1 (8b10febb…; covers may carry `helpers`, request schema stays guard-attempt/v1, `helpers` written only when named, missing keys read as empty, no new error codes, pause/time/cancel unchanged). Worker claims no delivered test changes. Independent CR review running. Decide DEC-1 A modification; DEC-2 A helper ids from state["helpers"][*]["id"] (owned by 002-F; fail-closed until 002-F) vs B no check vs C 002-F lookup; DEC-3 A wire helper ids in guard review in this CR (inert until 002-F) vs B leave to 002-F; DEC-4 B Guard skill text left to 002-F; DEC-5 B write `helpers` only when named; DEC-6 A v1.1.

### Guidance Returned
> DAO verified:
> - hashes: CR doc 16a593d2…, spec 14c59830… (v1.1 row L16; AC-002C-01h/01i L84–85; supersession note L87; FR-002C-2a L142) and design 8b10febb…;
> - the human authority (B12 = A, human_decisions.md);
> - delivered `guard/service.py` L409–414: `review` builds `used_items` only from `finding`/`na_decision` subjects;
> - no `helpers` key exists yet in guard code;
> - `tests/adapters/test_trivy_units.py` L816 asserts the exact `covers` dict, which justifies DEC-5 B.
> Decisions:
> - **DEC-1 → A**, modification of 002-C: same G-04 accounting rule; 002-F owns the new outcome.
> - **DEC-2 → A.**
>   - Fail-closed is safe: an absent `state["helpers"]` means every helper id is refused.
>   - B would let an agent pre-burn or fake coverage. C is unnecessary.
>   - Binding: the key name and the `[*]["id"]` shape become a contract that 002-F's design must adopt exactly, or raise a follow-up CR. 002-F must not invent a parallel helper registry.
> - **DEC-3 → A.**
>   - The coverage check becomes complete and fail-closed at the point the contract is defined.
>   - The line stays inert while 002-A validation rejects unknown subject types.
>   - Condition: a unit test with an injected `helper` subject proves the refusal when it is uncovered.
> - **DEC-4 → B.** Helpers don't exist until 002-F, and AC-002C-06a stays true; 002-F updates `guard-records.md` under AC-002F-10a.
> - **DEC-5 → B.** Records and the exact-dict test stay unchanged; missing keys read as empty.
> - **DEC-6 → A**, v1.1 additive.
> Conditions:
> 1. **Delivered tests:** all delivered 002-A/B/C/D, 003-A and 001-x tests stay byte-identical and pass. If the worker's list of "no delivered test changes" proves wrong, stop and return.
> 2. **New tests only:** new test functions; the only allowed message change is the empty-coverage message, which no delivered test asserts.
> 3. **Acceptance scope of TASK-077 (clarifies DAO-014 (1)):** unit/integration evidence with a synthetic `state["helpers"]`, plus the full regression. The black-box helper path is verified in 002-F acceptance. "Accepted" for 002-F's gate means this evidence is in place. Never report the black-box helper path as passed before 002-F.
> 4. **Before implementation:** the CR docs are confirmed only after the running independent review passes, or after its blocking findings are fixed and re-reviewed.
> No commit, push or release (B8).

### Rationale
> The choices implement exactly the human-approved additive coverage item, stay fail-closed until the consuming feature exists, and keep every delivered record, request and test unchanged.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-change-request"
>     match_strength: "strong"
>     reason: "Await independent review, then confirm CR docs"
>     execution_steps:
>       - phase: "Review"
>         step: "Independent review at CR/spec/design hashes"
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "partial"
>     reason: "After review: TDD implementation (queued per owner serialization)"

### Follow-up
> 002-F design must adopt the `state["helpers"][*]["id"]` contract or raise a follow-up CR.

## DAO-003
- **Timestamp:** 2026-10-23T22:10:19+08:00
- **Task ID:** TASK-086
- **Feature ID:** FEATURE-002-A
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-change-request
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human C1 = yes (human_decisions.md 21:58); human B8 = A (local commits, no push) and commit author input 22:09
- **Disposition:** approval
- **Confidence:** 0.84

### Message
> CR doc CR-TASK-086-renderer-version.md (121b92c3…), 002-A spec edc41ca9… (AC-002A-01i/j/k, FR-002A-10, insert-only), design f8b44084…. Independent CR review running. Decide DEC-1…9 + DEC-G1 (all A): 1 result file + report; 2 toolkit version + SHA-256 of guard/report.py; 3 keep schema guard-result/v1; 4 footer unchanged; 5 recorded at result-writing code, engine.conclude untouched; 6 risk acceptance re-records current build; 7 cross-build report repair leaves result as is + stated limit; 8 final "Report Origin" section only when present; 9 implement after TASK-076 then a small 002-G follow-up CR; G1 002-G follow-up adds integrity state renderer_differs.

### Guidance Returned
> DAO verified:
> - human decision C1 = yes (human_decisions.md 21:58);
> - hashes: CR doc 121b92c3…, spec edc41ca9… (v1.1 row L16; AC-002A-01i/j/k L72–74; FR-002A-10 L168) and design f8b44084…;
> - the CR's delivered-test analysis (no delivered test changes with DEC-3/5/7/8);
> - delivered `guard/report.py`, whose only toolkit-internal import today is `atomic.dumps_json`.
> All ten recommendations are approved (A), as the means for the human-approved C1:
> - **DEC-1, DEC-3, DEC-4, DEC-5, DEC-8:** keep `guard-result/v1` and the footer, keep the engine pure, and keep old results rendering byte-identically. This follows the 002-B/C/D additive precedent and the 002-G v1 contract.
> - **DEC-2 → A, with a condition.** `renderer_digest` must cover the whole rendering closure: `report.py` plus every toolkit-internal module it imports for rendering. Today that is `atomic.py`; later it includes 002-F's `helper_report` once added.
>   - Implement it as SHA-256 over the sorted sources of an explicit module list, with a test that fails if `report.py` gains a toolkit import missing from the list.
>   - Rationale: under-inclusion would make 002-G call a report from a changed renderer "edited", a false tamper hint. Over-inclusion only causes a harmless "renderer differs".
>   - The `null`-if-unreadable fallback is reported as "renderer unknown", never as a match.
> - **DEC-6 → A.** The rewritten result names the current build; verdict, findings and severities are unchanged (AC-002A-01k).
> - **DEC-7 → A.** Keep the stated limit. The field means "build that wrote the result", and 002-G wording never infers tampering from it.
> - **DEC-9 → A.** Implement after TASK-076 completes, in the serialized code queue. The 002-G follow-up CR comes after 002-G's own acceptance; 002-G v1 stays unchanged (05l stays true for unstamped results).
> - **DEC-G1 → A**, as a planned follow-up. `renderer_differs` is a non-accusatory integrity state. When the identity is equal but the Markdown differs, wording stays "edited, or changed by an unrecorded renderer change", never "tampered".
> Conditions:
> 1. Every delivered test stays byte-identical (per the CR's list); if one must change, stop.
> 2. Add new tests for 01i/01j/01k plus the closure test.
> 3. The CR docs count as confirmed only after the running independent review passes (or its blocking findings are fixed and re-reviewed).
> 4. B8 = A authorizes local commits only (no push, PR or release), using the repo-local author identity the human gave. This CR does not itself require a commit decision from DAO.

### Rationale
> The choices realize the human-approved C1 additively, with no schema bump or delivered test change. The closure condition makes the provenance signal fail-safe, so it can never produce a false "edited" claim.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-change-request"
>     match_strength: "strong"
>     reason: "Await independent review, then confirm CR docs"
>     execution_steps:
>       - phase: "Review"
>         step: "Independent review at CR/spec/design hashes"
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "partial"
>     reason: "After review and TASK-076: TDD implementation in the serialized code queue"

### Follow-up
> 002-G follow-up CR (renderer_differs) after 002-G acceptance.
