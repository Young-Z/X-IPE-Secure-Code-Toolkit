# DAO Decisions: Code Implementation

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-23T11:11:10+08:00 | TASK-062 | x-ipe-task-based-code-implementation | approval | 0.82 | FEATURE-003-B: status._host unreadable-AGENTS.md change accepted as a defect fix (A) with conditions: correct next step for the OSError case only, regression test, document FRAGMENT_UNREADABLE in cli-contract, init traceback recorded as separate defect candidate |
| DAO-002 | 2026-10-23T15:28:27+08:00 | TASK-069 | x-ipe-task-based-code-implementation | approval | 0.84 | FEATURE-001-F: Q1 A — append the 5 new 001-F payload paths to delivered 003-B test helper ERA_001A_REMOVED as a test-defect fix (no assertion/fixture/AC change); DAO-009 (2) amended; maintenance point noted in 003-B/001-F designs; Q2 Framework Status line updated honestly |

---

<!-- Detail sections are appended below this line -->

## DAO-001
- **Timestamp:** 2026-10-23T11:11:10+08:00
- **Task ID:** TASK-062
- **Feature ID:** FEATURE-003-B
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-code-implementation
- **Source:** ai (lifecycle owner "Sage"); mode dao-represent-human-to-interact (human returned 11:03 and is answering pending decisions; delegation stands until they choose otherwise)
- **Disposition:** approval
- **Confidence:** 0.82

### Message
> Code-review fix for an unreadable carrier file (chmod 000): besides the new 003-B code paths, the worker changed one read in FEATURE-001-A's `status._host` (status.py:73): with AGENTS.md unreadable, status previously crashed with a PermissionError traceback (no result at all); now it reports the host entry as `unreadable` with the EXISTING 001-A problem code FRAGMENT_UNREADABLE and still produces full status output. Only this input changes; no 001-A test changed; plain init on an unreadable AGENTS.md is untouched (still raises as delivered). Full suite 2048 passed. (A) acceptable defect fix within confirmed scope, or (B) 001-A behaviour change to revert and park as CR? Owner recommendation: A.

### Guidance Returned
> Choose A. A traceback with no output violates the delivered status contract: AC-001A-09a/09c say status reports each condition separately with a next step, including obvious configuration problems such as unreadable files, and US-06 calls status read-only. Turning the crash into a reported problem is a defect fix. No delivered assertion changes. Conditions:
> 1. Evidence precision: DAO checked the code. `FRAGMENT_UNREADABLE` is the status code built as "FRAGMENT_" + state for the state `inspect()` already returns for non-UTF-8 host entries, so it is existing status output. It is not listed in `references/cli-contract.md` (which lists `HOST_ENTRY_UNREADABLE` for init/carriers). Say exactly this in the evidence, and add `FRAGMENT_UNREADABLE` to the cli-contract status problem list as documentation of existing output.
> 2. Next step: for the new OSError case only, do not point to "Run project initialization". Plain init on that file still raises, so that guidance would be wrong. Use "Make <host_entry> readable, then re-run status". The existing non-UTF-8 case stays byte-identical.
> 3. Tests: a 001-A-level status regression with chmod-000 AGENTS.md (RED-before = the traceback, recorded), asserting full output, the problem code, the corrected next step, and no writes (AC-001A-09b). All existing 001-A tests stay unchanged and pass.
> 4. Scope: plain `init` raising on an unreadable AGENTS.md is a separate pre-existing 001-A defect. Do not fix it inside 003-B. Record it as a bug candidate for the human or a later Bug Fix task.

### Rationale
> The change restores documented status behavior for an input that produced no result, uses status output that already existed, and changes no delivered assertion, so it is a defect fix, not a CR. The conditions keep the evidence accurate and the next step truthful.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "Continue TASK-062 with the bounded status fix, test and contract doc line"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Write failing test then fix (TDD)"

### Follow-up
> Owner records "plain init raises PermissionError on unreadable AGENTS.md (001-A)" as a bug candidate for the human.

## DAO-002
- **Timestamp:** 2026-10-23T15:28:27+08:00
- **Task ID:** TASK-069
- **Feature ID:** FEATURE-001-F
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-code-implementation
- **Source:** ai (lifecycle owner "Sage"); delegation continues (human confirmed 13:16 and 14:00)
- **Disposition:** approval
- **Confidence:** 0.84

### Message
> Implementation complete; full suite 2254 passed / 4 skipped / 10 failed; DAO-009 (2) stop triggered. Q1: the 10 failures are delivered FEATURE-003-B tests (test_project_lock::test_plain_init_with_unavailable_lock_identical_to_001a_baseline ×8, test_carriers_preservation::test_04i…, test_record_compat::test_08c_member_less…). They synthesise a "001-A-era" toolkit by copying the current tree and deleting carhelp.py ERA_001A_REMOVED (only the 4 003-B files), then compare to a fixture recording "<94 files>"; the 5 new 001-F payload files make it 99; nothing else differs. Candidate: append those 5 paths to ERA_001A_REMOVED (scratch: 76/76 pass); no assertion/fixture/AC/schema change. Options: A) test-support helper maintenance within DAO authority (amend DAO-009 (2); record in 003-B design as a maintenance point); B) re-record the fixture count (rejected: weakens baseline); C) escalate as CR and park. Q2: Framework SKILL.md "Status of This Skill" still says Presets/tags come in later features; allow updating it (Framework only)?

### Guidance Returned
> DAO verified the following:
> - `carhelp.py` L54-60: ERA_001A_REMOVED lists only the 4 FEATURE-003-B paths. `toolkit_copy(era="001A")` (L321-323) unlinks them from a full copy of the current tree.
> - `fixtures/init_001a_baseline.json` records only the count placeholder `<94 files>`, not file contents. The test asserts `steps == baseline_001a()`, so any newly added payload file breaks it.
> - The candidate diff adds exactly the 5 FEATURE-001-F paths, and those files exist (new today).
> - 003-B design L1041 defines era="001A" as "the payload without the FEATURE-003-B additions".
> - The Framework SKILL.md L166-173 Status line still says Presets/tags come in later features. Only the Copilot and Guard skill tests mention a Status section, and they assert it is absent there.
> Q1: Choose A, classified as a test-defect fix in delivered test support. The helper ties a behavioral baseline (plain init without a lock = 001-A behavior) to the current payload size. Any later payload-adding feature therefore produces false failures, while the behavior under test is unchanged. The fix restores the exact baseline the fixture recorded, and leaves every assertion, the fixture, every AC and the schema unchanged. This is within delegated authority (defect fixes). DAO-009 (2) is amended to allow exactly this.
> Conditions:
> 1. Apply exactly the 5-path append from the reviewed diff. A comment may clarify that the list removes every payload file added after the recorded baseline. No other 003-B test or helper change.
> 2. Append a non-destructive maintenance note to the 003-B technical design. Attribute it to the DAO representative under delegation (DAO-002 code implementation). Text: "every later payload-adding feature appends its payload paths to ERA_001A_REMOVED; fixture and assertions are never re-recorded for this reason". Mention it in the 001-F design/implementation notes too.
> 3. Re-run the full suite at the implementation revision. It must have 0 failures. The full 003-B suite is now part of the 001-F regression set, alongside 001-B/C/D, 002-A and 003-A (DAO-009 (3)). Do not edit earlier 003-B acceptance evidence; append a note citing the helper change and the re-run. 003-B stays parked on B7/B11, unchanged.
> 4. If any of the 10 tests still fails after the append, or any other difference appears, stop: that would be a real behavior difference, and goes to the human as a CR.
> B is rejected because it weakens the baseline. C is unnecessary because no delivered behavior or AC changes.
> Q2: Approved, Framework SKILL.md only. State that FEATURE-001-F delivers Presets and tags, using the actual delivered command names. Keep Reference knowledge (001-E) and Adapters as later features. Keep "status reports them honestly as empty or not provided" only if it is still true for what remains; do not claim status-command changes that were not implemented. Do not change Copilot or Guard skill text. Re-run the Framework skill tests (test_preset_skill consistency, 001-C 02e, 001-D test_exit_skill) and the Copilot/Guard skill tests.
> No commit, push or release is implied.

### Rationale
> The failing check is coupled to payload size, not to the behavior it guards. Restoring the recorded baseline preserves the assertion's strength, whereas re-recording would weaken it. This is a defect fix with a stop condition if anything else differs. The Status line is a factual consistency update for the feature being delivered, with precedent in 001-D.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "Apply helper fix and Status line, re-run full suite, continue to completion"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Apply fix, full regression, independent code review"
>   - skill_name: "x-ipe-task-based-feature-acceptance-test"
>     match_strength: "partial"
>     reason: "Engineering-next after implementation, with DAO-007/009 re-run obligations"

### Follow-up
> 003-B design maintenance note (ERA_001A_REMOVED) to be appended by the owner.
