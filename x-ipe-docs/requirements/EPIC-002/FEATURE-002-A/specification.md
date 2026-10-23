# Feature Specification: Guard Semantic Verification & Verdict Reporting

> Feature ID: FEATURE-002-A  
> Epic: EPIC-002 (Guard: Verification, Adapters & Evidence)  
> Version: v1.0  
> Status: Refined — confirmed by human (TASK-021, 2026-10-19)  
> Last Updated: 10-19-2026
> Amended: v1.1 on 10-23-2026 by [CR-TASK-086](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/CR-TASK-086-renderer-version.md) (additive renderer identity in the structured result and report; delivered v1.0 text kept)

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-19-2026 | Initial specification | N/A |
| v1.0 | 10-19-2026 | NFR-002A-2 wording corrected to an honest masking limit (closing review, Bug Fix TASK-026, user decision); no AC changed | N/A |
| v1.1 | 10-23-2026 | Additive renderer identity (human decision C1 = Yes, `x-ipe-docs/dao/26-10-23/human_decisions.md` 21:58): new AC-002A-01i, 01j, 01k, 01l (01l and cancellation/manifest/section wording from independent-review round 2; DAO-003); FR-002A-10; NFR-002A-1 note; edge cases; consumer FEATURE-002-G; traceability and evidence rows. No delivered AC changed; schema id stays `guard-result/v1` | [CR-TASK-086](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/CR-TASK-086-renderer-version.md) |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: agent skill, command-line operations, files and Markdown/structured reports. Bounded discovery: EPIC-002 has no mockups folder content; the idea folder has no mockups. | — | — |

## Overview

FEATURE-002-A makes the Guard skill work: it verifies an already formed design or implementation against the Policies the user adopted (FEATURE-001-C) and reports an honest verdict with evidence. Guard never fixes anything.

- **Agent judges, script decides the verdict.** The Guard skill (an AI agent) chooses the artifact scope with the user, turns adopted Policies into a lightweight check plan, performs the semantic review and asks an independent read-only Reviewer to re-check verdict-affecting or disputed findings. The deterministic `secure-code` script opens the verification, records targets and adopted Policies, validates everything the agent records, computes the verdict by fixed rules and renders the Markdown report and the structured result from the same data.
- **Three-state verdict, four-state ledger.** The verdict is **Pass**, **Fail** or **Cannot confirm pass**. Each necessary check is **met**, **not met**, **unconfirmed** or **N/A**, always with evidence or a reason. A verified Medium/High/Critical finding fails; zero findings with missing evidence, unknown severity or an unresolved conflict never pass.
- **Two separate scopes.** The artifact scope (what is checked) is chosen explicitly and never expands because Apply All selected every Policy. Read-only context is recorded apart from targets; added, deleted and renamed files keep their change meaning.
- **Reviewer records bound to the version reviewed.** A review counts only if its record is complete and refers to the current digest of the reviewed targets; otherwise the report says it is not a valid review.
- **Evidence and reports.** Raw evidence stays in a private run folder for 30 days after the verification ends (removed only by an explicit cleanup command); reports stay until the user removes them; sensitive values are masked. A User or authorized upstream may record a risk acceptance, which never changes findings, severities or the verdict.

Tool Adapters (FEATURE-002-B/D/E), shared budget and cancellation (FEATURE-002-C), comparison of two reports (R-11/R-12, later) and reuse of evidence from an earlier run (V-18, undecided) are outside this feature. Until Adapters exist, a check whose plan requires tool evidence ends **unconfirmed**, and the verdict reflects it.

## User Stories

- **US-01:** As a Developer or upstream agent, I want to verify a design or implementation without a prior Copilot run, so that Guard gives an independent result and a Copilot report is never mistaken for a pass.
- **US-02:** As a Developer, I want the artifact scope chosen explicitly — targets, read-only context and change meaning — and never widened to the whole project by Apply All, so that I know exactly what was verified.
- **US-03:** As a Developer, I want Guard to use only the Policies I adopted and to stop with "maintenance needed" when none are usable, so that no rule is invented and no empty check list counts as a pass.
- **US-04:** As a Developer, I want each necessary check to state its object, method and minimum evidence, and the ledger to record met / not met / unconfirmed / N/A with evidence, so that gaps are visible instead of hidden behind a percentage.
- **US-05:** As a Developer, I want verdict-affecting findings re-checked by an independent read-only Reviewer whose record is bound to the reviewed version, so that unreviewed, mis-versioned or stale reviews never confirm or dismiss a finding.
- **US-06:** As a Developer or upstream agent, I want the verdict computed by fixed rules (Fail / Cannot confirm pass / Pass), so that a clean tool exit, zero findings or a low threshold never produce a false pass.
- **US-07:** As a User or authorized upstream, I want to record a risk acceptance separately, so that my decision is traceable while findings, severities and the verdict stay unchanged.
- **US-08:** As a Developer, I want a Markdown report and a structured result from the same data, with raw evidence kept 30 days and sensitive values masked, so that people and tools read the same conclusion safely.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 | EPIC-001 G-02; FR-14, FR-15, FR-02, FR-22, FR-01 (V-01…V-17, V-19…V-25, R-01…R-09, R-13, O-03, O-05, O-07, O-08) | Developer, upstream agent | No misleading "pass"; every conclusion traceable to evidence | Guard verdict engine and report. Selected means: agent plans/reviews, script records and computes the verdict deterministically (user decision); conservative severity/conflict rule; fixed Medium threshold; explicit cleanup; declared-and-bound Reviewer records | Scenario: the known-vulnerable marathon sample is not reported Pass; the ledger lists unconfirmed items; a stale review is rejected | Guard never fixes; no coverage percentage; no Adapters/budget here; threshold not configurable (V-16 authority open) | AC-002A-01a…01h, 02a…02g, 03a…03d, 04a…04j, 05a…05h, 06a…06k, 07a…07d, 08a…08b | not measured |
| G-01 (enabling) | EPIC-001 FR-01 (O-01…O-05) | Upstream agent | Guard and Reviewers write no business artifacts | Guard writes only its run folder and report files | Scenario: target bytes unchanged after a verification | — | AC-002A-08a, 08b | not measured |

> **CR-TASK-086 (v1.1):** G-02 is additionally covered by AC-002A-01i, 01j, 01k, 01l (enabling subgoal "result provenance": a result and its report name the build that wrote them, so a later comparison can tell a report rendered by another build from one changed after writing).

## Acceptance Criteria

Breakdown AC-002A-01 (report, structured result, 30-day evidence, masking) is refined by AC-002A-01a…01h. EPIC-001 mapping: AC-01 (Guard part) → 08a, 08b; AC-02 → 05e…05g; AC-11 (Guard part) → 03a…03d; AC-16 → 02a, 02b; AC-17 → 02c; AC-18 → 04a…04j; AC-19 → 06a…06c, 06k; AC-20 → 06d; AC-21 → 07a…07d; AC-22 → 05b…05d.

### AC-002A-01: Report, Structured Result and Evidence

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-01a | GIVEN a concluded verification WHEN its outputs are inspected THEN a Markdown report exists in `x-ipe-docs/secure-code/reports/guard/` and a structured result exists beside it, both named by the verification ID AND verdict, ledger, findings, targets and adopted Policies are identical in both | Integration |
| AC-002A-01b | GIVEN a concluded verification WHEN the report is read THEN it states the verification ID, targets with digests, read-only context, adopted scope identifier and rules, check plan, ledger, findings with classification and severities, Reviewer records with validity, verdict with its reasons, risk acceptances and the evidence retention period and location | Integration |
| AC-002A-01c | GIVEN a verification WHEN evidence is recorded THEN raw evidence, logs and the run state are stored under `.x-ipe/private/secure-code/guard/<verification-id>/` AND the report refers to evidence by location, not by copying all raw output | Integration |
| AC-002A-01d | GIVEN evidence containing a suspected credential (pre-check patterns of FEATURE-001-B) WHEN it is stored or reported THEN the value is masked in the stored evidence, the report and the structured result AND the evidence is labelled as masked, never as unchanged raw output | Integration |
| AC-002A-01e | GIVEN finished verifications ended 31 and 29 days ago and one still running WHEN the explicit evidence cleanup runs THEN only the 31-day-old evidence folder is removed AND the reports of all three remain AND reading evidence never extends its retention | Integration |
| AC-002A-01f | GIVEN an expired evidence folder on which a User or upstream set a keep marker with a reason (explicit command) WHEN cleanup runs THEN it is not removed AND the cleanup result names it with the reason; GIVEN the marker is then released by explicit command THEN the next cleanup removes it | Integration |
| AC-002A-01g | GIVEN a report whose evidence folder was removed WHEN the report is shown THEN it still shows the original findings and verdict AND states that the raw evidence is no longer available | Integration |
| AC-002A-01h | GIVEN two verifications of the same targets WHEN both are concluded THEN each has its own report AND an older report is never presented as the result for a changed target version | Integration |
| AC-002A-01i | (CR-TASK-086, v1.1) GIVEN a verification WHEN it is concluded normally, cancelled directly with `guard cancel`, or has a pending cancellation finalized by `guard conclude` THEN the structured result has `renderer` with the toolkit version reported by `secure-code --version` and the renderer digest over the renderer manifest (FR-002A-10) AND the Markdown report ends, before the footer, with a "Structured Result Origin" section naming both and stating that it identifies the build that wrote the structured result, which may differ from a later report-repair build AND the footer still equals the SHA-256 of the JSON bytes | Integration |
| AC-002A-01j | (CR-TASK-086, v1.1) GIVEN a structured result without `renderer` (written before this change) WHEN it is shown, concluded again, cleaned up or rendered THEN it is accepted with schema `guard-result/v1` unchanged AND its rendering is byte-identical to the rendering before this change AND no result is rewritten except by risk acceptance | Integration / Unit |
| AC-002A-01k | (CR-TASK-086, v1.1) GIVEN a concluded Fail result whose `renderer` is absent or names another build WHEN a risk acceptance is recorded THEN the rewritten result's `renderer` names the current build AND verdict, findings and severities are unchanged | Integration |
| AC-002A-01l | (CR-TASK-086, v1.1) GIVEN the renderer manifest WHEN the bytes of any listed component (e.g. `guard/report.py` or `atomic.py`) change THEN the renderer identity changes; GIVEN `guard/report.py` imports a toolkit-internal module missing from the manifest WHEN the closure test runs THEN it fails; GIVEN an unreadable component WHEN a result is written THEN `renderer_digest` is `null`, the report says "renderer unknown" AND that identity never matches any identity | Unit |

### AC-002A-02: Independent Invocation and Artifact Scope

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-02a | GIVEN explicit targets and an adopted scope but no Copilot report WHEN a verification is opened THEN it proceeds independently | Integration |
| AC-002A-02b | GIVEN a Copilot report supplied as context WHEN a check's evidence refers only to that report THEN the check is not met by it AND the report is listed as context, never as evidence of a pass | Integration |
| AC-002A-02c | GIVEN an adopted Apply All scope and two target files WHEN the verification is opened THEN exactly those two files are targets AND the project is not expanded to all files; a whole-project target is accepted only when explicitly requested | Integration |
| AC-002A-02d | GIVEN targets plus read-only context files and suggested extension targets WHEN recorded THEN the three roles are kept separate AND the report lists context and suggested files as not verified AND a check whose object is a target cannot be `met` by evidence located only in context files | Integration |
| AC-002A-02e | GIVEN a change with an added, a deleted and a renamed file WHEN targets are recorded THEN the added file is a target, the deleted file is recorded as deleted (no digest) and still available for impact checks, AND the rename keeps both the old and new path | Integration |
| AC-002A-02f | GIVEN a target path that does not exist (and is not declared deleted), lies outside the project or is a symbolic link WHEN the verification is opened THEN it is refused with the path and a next step | Integration |
| AC-002A-02g | GIVEN the Guard skill package WHEN its instructions are inspected THEN they direct the agent to ask the user only for unclear project, baseline or targets, not to re-confirm an explicit scope, and to require an explicit choice for a whole-project target | Integration |

### AC-002A-03: Adopted Policies Precondition

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-03a | GIVEN no adopted scope, or one whose load status is `maintenance_needed` WHEN a verification is requested THEN no verification is opened AND the result is "maintenance needed" with the Framework next step AND no report claims Pass or 100% | Integration |
| AC-002A-03b | GIVEN an adopted scope with load status `partial` (changed or missing Policies) WHEN a verification is requested THEN it is refused with the available, changed and missing Policies listed AND the next step is to confirm a new scope (FEATURE-001-C) before verifying | Integration |
| AC-002A-03c | GIVEN a complete adopted scope WHEN a verification is opened THEN the adopted scope identifier, every adopted rule and its confirmed state digest are recorded in the run and later in the report | Integration |
| AC-002A-03d | GIVEN a check plan entry referring to a rule that is not in the adopted scope WHEN the plan is recorded THEN that entry is refused AND no Policy outside the adopted scope is used | Integration |

### AC-002A-04: Check Plan and Ledger

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-04a | GIVEN adopted Policies and targets WHEN a check plan is recorded THEN every necessary check names its Policy, object (target or part), method and minimum evidence (accepted evidence kinds) AND an entry missing any of these is refused | Integration |
| AC-002A-04b | GIVEN a plan WHEN recorded THEN Policies judged not applicable carry a factual reason AND the plan is not required to pair every file with every rule | Integration |
| AC-002A-04c | GIVEN a concluded verification WHEN the ledger is produced THEN every planned check has exactly one state — `met`, `not_met`, `unconfirmed` or `n/a` — with evidence references or a reason AND no percentage score is produced | Integration |
| AC-002A-04d | GIVEN a check whose minimum evidence requires runtime evidence (tool or test output) WHEN only reading or reasoning evidence is recorded THEN it cannot be `met` AND becomes `unconfirmed` with the missing evidence named | Integration |
| AC-002A-04e | GIVEN a check recorded as `n/a` because the method was unavailable, not executed or evidence is missing WHEN validated THEN it is refused as N/A AND must be `unconfirmed` | Integration |
| AC-002A-04f | GIVEN the user excludes a check from this verification WHEN recorded THEN it appears as a scope exclusion with the user's reason, separate from objective N/A and from met, AND the verdict cannot be Pass for the original scope while the exclusion is reported | Integration |
| AC-002A-04g | GIVEN a planned check with no ledger state at conclusion WHEN the verification is concluded THEN it is recorded as `unconfirmed` (not executed) AND never silently dropped | Integration |
| AC-002A-04h | GIVEN N/A decisions (Policy-level in the plan or check-level in the ledger) WHEN concluded THEN each counts as N/A only if a valid Reviewer record confirms it in the batch AND an unreviewed or rejected N/A becomes `unconfirmed` with that reason | Integration |
| AC-002A-04i | GIVEN evidence of kinds `document` (declaration), `reading` (reasoning), `runtime` and `reviewer` WHEN recorded and reported THEN each item keeps its kind AND the report shows them separately, never merging a declaration or reasoning into runtime evidence | Integration |
| AC-002A-04j | GIVEN a check whose auxiliary method failed but another accepted kind of its minimum evidence is recorded WHEN concluded THEN the check can be `met` with the substitution and the failed method shown; GIVEN the failed method was the required one THEN it stays `unconfirmed` | Integration |

### AC-002A-05: Findings and Independent Review

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-05a | GIVEN two reported findings at the same location with the same CWE but different evidence WHEN normalized THEN they stay separate unless evidence shows the same root cause AND a merge records its evidence | Integration |
| AC-002A-05b | GIVEN verdict-affecting (severity unknown or ≥ Medium) or disputed findings WHEN concluded without a valid Reviewer record covering them THEN they stay `unconfirmed` AND the verdict cannot be Pass | Integration |
| AC-002A-05c | GIVEN a valid Reviewer record for a batch of findings WHEN applied THEN each finding is `confirmed`, `false_positive` (with its evidence) or `unconfirmed` AND the original tool/semantic conclusion and the Reviewer's basis are both kept | Integration |
| AC-002A-05d | GIVEN a finding the Reviewer could not confirm WHEN reported THEN it is `unconfirmed`, never removed or labelled false positive | Integration |
| AC-002A-05e | GIVEN a Reviewer record without its invocation source, review requirement, reviewed target digests or result WHEN recorded THEN it is not a valid review AND the report says why | Integration |
| AC-002A-05f | GIVEN a Reviewer record bound to target digests that differ from the targets' current digests WHEN the verification is concluded THEN the review is invalid as stale AND the findings it covered return to `unconfirmed` | Integration |
| AC-002A-05g | GIVEN a valid Reviewer record WHEN it tries to change targets, adopted scope, ledger states of other checks or record a risk acceptance THEN those parts are refused because a Reviewer has no extra authority | Integration |
| AC-002A-05h | GIVEN the Guard skill package WHEN its instructions are inspected THEN they direct the agent to call one independent read-only Reviewer per batch through the host, to pass only relevant summaries and evidence locations, and to record the review result with the reviewed digests | Integration |

### AC-002A-06: Verdict Rules

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-06a | GIVEN a confirmed finding with final severity Medium, High or Critical WHEN concluded THEN the verdict is **Fail** whatever the other ledger states | Unit |
| AC-002A-06b | GIVEN only Low or Info findings that are undisputed (no review required) or confirmed, every necessary check `met` or reviewed objective `n/a`, no scope exclusion, no unconfirmed verdict-affecting finding, no unresolved conflict and unchanged targets and Policies WHEN concluded THEN the verdict is **Pass** AND the Low findings are reported | Unit |
| AC-002A-06c | GIVEN a confirmed finding with unknown severity WHEN concluded THEN it is not treated as Low AND the verdict is **Cannot confirm pass** unless another rule makes it **Fail** | Unit |
| AC-002A-06d | GIVEN zero findings (including a tool that exited normally) but at least one necessary check `unconfirmed` WHEN concluded THEN the verdict is **Cannot confirm pass**, not Pass | Unit |
| AC-002A-06e | GIVEN conflicting severities for one finding (tool High, Reviewer Low without evidence) WHEN concluded THEN the higher severity stands AND the conflict is shown; GIVEN the Reviewer gives evidence for the lower severity THEN the lower final severity is used with both originals kept | Unit |
| AC-002A-06f | GIVEN an unresolved verdict-affecting conflict between requirements, severities or evidence WHEN concluded THEN the verdict is not Pass AND the conflict is listed as a reason | Unit |
| AC-002A-06g | GIVEN any verdict WHEN produced THEN the report lists every reason that determined it (rule, finding or check) AND the precedence is Fail over Cannot confirm pass over Pass | Unit |
| AC-002A-06h | GIVEN the same recorded run WHEN concluded twice THEN the verdict, ledger and structured result are identical (deterministic, no AI in the script) | Integration |
| AC-002A-06i | GIVEN a user scope exclusion and otherwise Pass conditions WHEN concluded THEN the verdict is **Cannot confirm pass** with the exclusion as reason; GIVEN additionally a confirmed High finding THEN the verdict is **Fail** | Unit |
| AC-002A-06j | GIVEN a verification whose target files changed, or whose adopted Policies changed state, after it was opened WHEN concluded THEN the verdict is not Pass AND the changed targets or Policies are listed as reasons | Integration |
| AC-002A-06k | GIVEN a finding classified `false_positive` by a valid review (any severity) or with severity Info WHEN concluded THEN it does not cause Fail AND it stays in the report with its evidence | Unit |

### AC-002A-07: Risk Acceptance

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-07a | GIVEN a concluded Fail verification WHEN a User at an interactive terminal records a risk acceptance for a finding with a reason and types the finding ID to confirm THEN the acceptance is recorded separately with who (role), when and why AND the finding, its severity and the verdict are unchanged in the report and structured result | Integration |
| AC-002A-07b | GIVEN a risk acceptance WHEN another verification of the same targets runs THEN the acceptance is not applied to it automatically | Integration |
| AC-002A-07c | GIVEN the Guard skill package WHEN inspected THEN it forbids the agent or Reviewer from recording a risk acceptance on the user's behalf AND states that an existing Maintainer authorization is not consent | Integration |
| AC-002A-07d | GIVEN the risk-acceptance command run without an interactive terminal (as an agent would), or with a typed confirmation that does not match the finding ID WHEN executed THEN it is refused AND nothing is recorded, even when a valid Maintainer authorization exists | Integration |

### AC-002A-08: No Business Writes

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002A-08a | GIVEN a full verification run WHEN it completes THEN every target and context file is byte-identical to before AND only the run folder and report files were written | Integration |
| AC-002A-08b | GIVEN the Guard skill package WHEN inspected THEN it states that Guard and its Reviewer never edit business artifacts, never start remediation or automatic re-scan loops, and leave fixes to the current task executor | Integration |

## Functional Requirements

- **FR-002A-1 Open verification.** Input: project, adopted scope identifier (FEATURE-001-C), targets with roles (`target`, `context`, `suggested`), change entries (`added`, `modified`, `deleted`, `renamed` with old path), optional Copilot report as context, whole-project flag. Process: load the adopted scope (must be `complete`), validate paths, compute target digests, allocate the verification ID and run folder. Output: verification ID, recorded targets and Policies.
- **FR-002A-2 Record plan.** Checks with Policy (adopted rule), object, method, minimum evidence (accepted kinds: `document`, `reading`, `runtime`, `reviewer`), required/auxiliary; N/A Policies with factual reasons; user scope exclusions with reasons.
- **FR-002A-3 Record evidence and findings.** Evidence items (kind, source, location, masked flag, stored file); findings (rule, location, description, source `semantic` or tool, original severity, proposed severity, evidence, related findings, merge evidence); ledger states per check with evidence or reason.
- **FR-002A-4 Record review.** Shared Reviewer record envelope: invocation source (host and agent identity as declared), review requirement, reviewed target digests, time, and a list of typed subjects with results. Guard subject types: `finding` (`confirmed`, `false_positive`, `unconfirmed`, optional severity opinion with evidence) and `na_decision` (`confirmed`, `rejected`). The envelope is reused by FEATURE-003-A, which adds its own subject type (`adoption`). Validity: complete and bound to current target digests; Reviewer records cannot change targets, scope, other ledger states or risk acceptances.
- **FR-002A-5 Conclude.** Recompute target digests and reload the adopted scope (FEATURE-001-C) to detect changed targets or Policies; apply missing ledger states as `unconfirmed`; turn unreviewed or rejected N/A decisions into `unconfirmed`; validate Reviewer records; resolve severities (conservative rule); compute the verdict and its reasons (FR-002A-6); write the structured result and render the Markdown report from it; mark the run finished with its end time.
- **FR-002A-6 Verdict rules.** Fail if any confirmed finding has final severity ≥ Medium. Otherwise Cannot confirm pass if any necessary check is `unconfirmed`, any scope exclusion applies, any verdict-affecting finding (severity unknown or ≥ Medium, or disputed) is `unconfirmed` or has unknown severity, any verdict-affecting conflict is unresolved, or any target or adopted Policy changed since the verification was opened. Otherwise Pass. `false_positive` findings (valid review) and Info findings never cause Fail. Threshold fixed at Medium (not configurable in this version).
- **FR-002A-7 Risk acceptance.** Interactive terminal only (like `auth init`): input verification ID, finding, reason; the person types the finding ID to confirm. Appends an acceptance record (role `user`, time, reason); regenerates the report with an acceptance section; findings and verdict unchanged. Non-interactive acceptance by an authorized upstream workflow is deferred (open gap, user decision 10-19-2026).
- **FR-002A-8 Evidence cleanup and keep markers.** Explicit keep/release commands set or remove a keep marker with a reason on one verification's evidence (for a pending candidate or release process). Explicit cleanup removes evidence folders of finished verifications whose end time is more than 30 days ago and that have no keep marker; never touches running verifications or reports; reports what was removed and what was kept and why. Long-term retention beyond a pending process needs separate authorization (not provided here).
- **FR-002A-9 Show.** Read a report's structured result; states whether its raw evidence still exists.
- **FR-002A-10 Renderer identity (CR-TASK-086).** Every write of a structured result that also renders its report — conclusion, conclusion by cancellation (direct `guard cancel` or a pending cancellation finalized by `guard conclude`), risk acceptance — records `renderer`: the toolkit version (same source as `secure-code --version`) and the renderer digest: SHA-256 over an explicit, sorted manifest of every module that affects the report output (today `guard/report.py` and `atomic.py`; later modules such as FEATURE-002-F's helper report are added), each framed as path, NUL, byte length, NUL, bytes; any unreadable component gives `null` ("renderer unknown", never equal to any identity). It identifies the build that wrote the result. Risk acceptance re-records the current build without changing verdict, findings or severities. The report shows it in a final "Structured Result Origin" section only when present, stating that it identifies the build that wrote the structured result, which may differ from a later report-repair build; results without it stay valid `guard-result/v1` and render exactly as before. Re-creating a missing or mismatched report on a repeated conclusion does not rewrite the result. The identity is declared by the writing build, not a proof of origin.

## Non-Functional Requirements

- **NFR-002A-1 Determinism.** The script uses no AI; the same recorded run gives the same verdict and outputs.
- **NFR-002A-2 Safety.** No network; no execution of target content; suspected credentials masked before storage with the FEATURE-001-B pre-check patterns plus Guard additions (private key blocks incl. PGP, OpenAI/Anthropic `sk-proj-|sk-None-|sk-svcacct-|sk-admin-|sk-ant-…` keys, unquoted `…KEY/TOKEN/SECRET/PASSWORD=` lines); masking is pattern-based, not a complete data-loss-prevention guarantee, and unknown credential formats can still be stored; `private` folders are not claimed as strong isolation.
- **NFR-002A-3 Consistency.** Run-state writes are atomic; concurrent commands on one verification are serialized; a crash never leaves a report that disagrees with its structured result.
- **NFR-002A-4 Bounded context.** The skill passes only relevant summaries and evidence locations to the model and Reviewer, never all historical reports or raw output (R-09).
- **NFR-002A-5 Portability and independence.** macOS, Linux and Windows path rules; no dependency on X-IPE task or workflow files (NFR-01).
- **NFR-002A-1 note (CR-TASK-086, v1.1).** "Same outputs" holds for the same toolkit build; since FR-002A-10 the result bytes of a newly written result also carry the writing build's identity.

## UI/UX Requirements

No graphical UI. Command-line operations under `secure-code guard` (names finalized in technical design) for open, plan, record, review, conclude, accept-risk, show and evidence cleanup. Every command returns the toolkit result envelope (text and `--json`) with one next step per refusal. The Markdown report leads with the verdict and its reasons, then scope, ledger, findings, reviews, risk acceptances and retention. The Guard SKILL.md describes the agent's verification procedure.

## Dependencies

- **Internal:** FEATURE-001-C — adopted scope load (`scope show`), statuses and rule state digests; FEATURE-001-B — pre-check patterns for masking, consistent knowledge reads; FEATURE-001-A — root validation, layout (`reports/guard`), result envelope, atomic writes, locks.
- **External:** None beyond the toolkit runtime.
- **Consumers:** FEATURE-002-B/D/E (Adapters add runtime evidence), FEATURE-002-C (budget/cancel enter the run state), FEATURE-003-A (reuses the Reviewer record and report store), FEATURE-003-C (acceptance harness cases).
- **Consumer (CR-TASK-086):** FEATURE-002-G may read `renderer` to tell a report rendered by another build from one changed after writing (its own follow-up change; 002-G v1 ignores the key).

## Business Rules

- **BR-01:** Guard verifies and reports; it never fixes, starts remediation or loops re-scans (V-01, O-03).
- **BR-02:** A Copilot report is context only, never evidence of a pass (V-02).
- **BR-03:** Artifact scope and Policy scope are independent; Apply All never widens targets (V-03, AC-17).
- **BR-04:** Only adopted, complete Policies are used; none usable → maintenance needed, never a pass (V-10, V-23, AC-11).
- **BR-05:** N/A needs a fact; missing capability, non-execution or missing evidence are `unconfirmed` (V-20).
- **BR-06:** User exclusions are scope changes, not N/A or met (V-21).
- **BR-07:** Unconfirmed findings are never deleted as false positives (V-14).
- **BR-08:** Verdict precedence Fail > Cannot confirm pass > Pass; threshold Medium fixed (V-15, V-16, V-17).
- **BR-09:** Severity conflicts: the higher stands unless the Reviewer gives evidence for a lower one; unresolved verdict-affecting conflicts prevent Pass (V-24, decision 10-19-2026).
- **BR-10:** A Reviewer record is valid only if complete and bound to the current target digests; Reviewers have no extra authority (O-05, O-07, O-08).
- **BR-11:** Risk acceptance is recorded by a User at an interactive terminal only, never by Guard, a Reviewer or an agent; it changes no fact or verdict and does not carry over (V-22, R-13, D-11). Authorized-upstream recording is deferred.
- **BR-14:** N/A is accepted only when a valid Reviewer record confirms it (V-20).
- **BR-15:** Evidence kinds stay distinct; required runtime evidence is never replaced by reading or zero findings; an auxiliary method may be replaced by other accepted sufficient evidence (V-09, V-25).
- **BR-12:** Raw evidence is kept 30 days after the end of the verification, never renewed by reading, removed only by explicit cleanup; reports stay until the user removes them (R-04…R-07).
- **BR-13:** Every run is fresh; evidence from an earlier verification is not reused (V-18 undecided).

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Project not initialized | Refused with next step `secure-code init` |
| Targets change during the verification | Conclusion detects digest change; reviews bound to old digests are stale; verdict cannot be Pass |
| Verification concluded twice | Same outputs (deterministic); later recordings after conclusion refused except risk acceptance |
| Unknown verification ID | Refused with next step |
| Plan refers to a Policy outside the adopted scope | Entry refused |
| Evidence file very large | Stored in the run folder; report references location and summary only |
| Evidence contains a private key or token | Masked before storing; labelled masked |
| Cleanup while a verification is running | Running verification untouched |
| Deleted target | Recorded without digest; impact checks allowed; not silently dropped |
| Whole-project target | Only with explicit flag; otherwise refused |
| Result written before CR-TASK-086 (no `renderer`) | Shown, concluded again and cleaned up as before; rendered byte-identically; risk acceptance adds the current identity (CR-TASK-086) |
| A renderer manifest component unreadable when a result is written | `renderer_digest` recorded as `null` ("renderer unknown"; never a match), version still recorded; report says "renderer unknown" (CR-TASK-086) |
| Report re-created by a repeated conclusion under another build | Result not rewritten; `renderer` keeps naming the build that wrote the result (CR-TASK-086) |

## Out of Scope

- Tool Adapters and executable tool runs (FEATURE-002-B/D/E); temporary check scripts (FEATURE-002-F).
- Shared budget, time limits and cancellation (FEATURE-002-C).
- Comparison of two scan reports (R-11, R-12), management briefings (R-15), dedicated JSON exporter (R-14).
- Threshold configuration interface (V-16 authority open); reuse of earlier evidence (V-18); waiver engine (D-11).
- Copilot behaviour (FEATURE-003-A) beyond sharing the Reviewer record format.

## Technical Considerations

- Run-state, plan, finding, Reviewer record and report schemas (D-12, D-13, D-14, R-10), command names, ID format, and masking integration are decided in technical design.
- The script cannot prove a Reviewer sub-agent was really invoked; it records the agent's declaration and binds it to target digests (user decision; same honest-limit class as FEATURE-001-A U-13 and FEATURE-001-C confirmation).
- Reuse FEATURE-001-C `scope show` semantics in-process (no second scope reader) and FEATURE-001-B pre-check patterns.

## Open Questions

None material. Decisions (10-19-2026, interact-with-human):

| Question | Decision |
|---|---|
| Responsibility split | Agent plans and reviews; script records, validates, computes the verdict and renders both outputs from one source |
| Severity and conflicts (D-13, V-24) | Keep tool and final severity; higher stands unless the Reviewer gives evidence for lower; unresolved verdict-affecting conflict → Cannot confirm pass |
| Threshold (V-16) | Fixed Medium in MVP; no configuration interface |
| Evidence cleanup (R-04, R-05) | Explicit cleanup command; finished and expired only; keep marker respected; reports never deleted |
| Reviewer record (FR-02) | Completeness + binding to current target digests; invocation source declared by the agent |
| Evidence reuse (V-18) | Not in MVP; every run fresh |
| Risk acceptance recording (R-13) | Interactive terminal only with typed finding ID; authorized-upstream non-interactive recording deferred (open gap) |
| Renderer identity (CR-TASK-086, human C1 = Yes 10-23-2026; options DEC-1…DEC-9 = A by DAO-003 with conditions) | Optional `renderer` in the v1 result (no schema bump), covered by the existing footer digest, shown in a final "Structured Result Origin" section; digest over the renderer manifest with a closure test; stamped by conclusion, both cancellation paths and risk acceptance, not by report repair; delivered tests stay byte-identical |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| R-01…R-03, R-06…R-09; FR-002A-5, FR-002A-9 | US-08 | AC-002A-01a…01d, 01g, 01h | N/A | Integration | covered |
| R-04, R-05; FR-002A-8 | US-08 | AC-002A-01e, 01f | N/A | Integration | covered |
| Human C1 (10-23-2026); FR-002A-10 | US-08 | AC-002A-01i, 01j, 01k, 01l | N/A | Integration / Unit | implemented, unit/integration tests pass (TASK-090); acceptance pending — CR-TASK-086 |
| V-02, AC-16 | US-01 | AC-002A-02a, 02b | N/A | Integration | covered |
| V-03…V-07, AC-17; FR-002A-1 | US-02 | AC-002A-02c…02g | N/A | Integration | covered |
| V-10, V-23, AC-11 | US-03 | AC-002A-03a…03d | N/A | Integration | covered |
| V-08, V-09, V-19…V-21, V-25, AC-18; FR-002A-2/3 | US-04 | AC-002A-04a…04j | N/A | Integration | covered |
| V-11…V-14, AC-22; O-05, O-07, O-08, AC-02; FR-002A-4 | US-05 | AC-002A-05a…05h | N/A | Integration | covered |
| V-15…V-17, V-24, AC-19, AC-20; FR-002A-6 | US-06 | AC-002A-06a…06k | N/A | Unit / Integration | covered |
| V-22, R-13, AC-21; FR-002A-7 | US-07 | AC-002A-07a…07d | N/A | Integration | covered |
| V-01, O-03, AC-01 | US-01 | AC-002A-08a, 08b | N/A | Integration | covered |
| V-18, R-10…R-12, R-14, R-15, D-11 | — | — | N/A | — | out of scope / design-level |
| NFR-002A-1…5 | — | (06h; design-level otherwise) | N/A | — | design/implementation evidence |

## Context and Verification Evidence

- Sources: [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) (EPIC-001 FR-01, FR-02, FR-14, FR-15, FR-22; AC-01, AC-02, AC-11, AC-16…AC-22; FEATURE-002-A details); inventory v2 rows O-01…O-08, V-01…V-25, R-01…R-15, D-11…D-14; [FEATURE-001-C specification](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md) and implementation (scope load); FEATURE-001-B pre-check; FEATURE-001-A layout.
- Board: FEATURE-002-A, EPIC-002, v1.0, Planned, depends on FEATURE-001-C (Completed).
- Independent review (rubber-duck, 10-19-2026): 5 blocking + 2 non-blocking findings fixed — exclusion vs Pass (06b, 06i); stale targets/Policies (FR-002A-5/6, 06j); reviewed N/A (V-20, 04h, BR-14); keep-marker lifecycle (R-05, 01f, FR-002A-8); risk acceptance interactive-only (07a, 07d, user decision); evidence kinds and fallback (V-05, V-09, V-25: 02d, 04i, 04j, BR-15); shared Reviewer envelope with typed subjects (FR-002A-4); false-positive/Info (06k).
- Mockups: none. Execution mode: free-mode.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-002A-01a…08b | Planned per Test Type; no tests yet | planned | not measured |
| AC-002A-01i, 01j, 01k, 01l (CR-TASK-086) | Planned per Test Type; not implemented (documents-only CR; delivered v1.0 evidence for other ACs unaffected) | planned | not measured |
| AC-002A-01i, 01j, 01k, 01l (CR-TASK-086, TASK-090) | Implemented; `tests/guard/test_guard_renderer.py` (30 tests) RED before / GREEN after; full suite 2593 passed, 4 skipped; delivered tests byte-identical — see [CR Implementation Evidence](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/CR-TASK-086-renderer-version.md) | implemented (acceptance pending) | not measured |
