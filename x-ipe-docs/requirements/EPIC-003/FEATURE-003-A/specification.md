# Feature Specification: Copilot In-flow Suggestions & Adoption Review

> Feature ID: FEATURE-003-A  
> Epic: EPIC-003 (Copilot Collaboration & Host Integration)  
> Version: v1.0  
> Status: Refined — confirmed by human (TASK-043, 2026-10-21)  
> Last Updated: 10-21-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-21-2026 | Initial specification | N/A |
| v1.0 | 10-21-2026 | AC-003A-06a clarified: the project-wide Copilot lock file is part of Copilot's private data (user decision, closing review TASK-047); behavior unchanged | N/A |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: agent skill, command-line operations, files and Markdown/structured reports. Bounded discovery: the EPIC-003 folders contain no mockups and the idea folder has none. | — | — |

## Overview

FEATURE-003-A makes the Copilot skill work. It collaborates *during* design, implementation, bug fix and refactor work, including changes to an existing design. It gives concrete suggestions based on the Policies the user adopted (FEATURE-001-C). After the current task executor applies them, one independent read-only Reviewer checks adoption. Copilot never writes business artifacts and never passes or approves work.

- **Agent suggests and reviews; the script records and decides staleness** (user decision 10-21-2026, same split as Guard):
  - The Copilot skill (an AI agent) reads the adopted Policies, writes suggestions tied to specific artifacts and calls one read-only Reviewer per batch through the host.
  - The deterministic `secure-code` script:
    - opens a collaboration and records the artifacts with their digests;
    - validates the suggestions against the adopted scope;
    - records the Reviewer's adoption results in the shared Reviewer record (FEATURE-002-A), bound to the file digests the Reviewer saw;
    - renders each report and its structured result from the same data.
- **Five adoption results.** Each reviewed suggestion is **adopted**, **partial**, **not adopted**, **not applicable** or **cannot verify**, with the Reviewer's basis. A suggestion without a current valid review is reported as **not reviewed**, **stale** (a bound file changed) or **Policy changed**, never as adopted.
- **High-risk attention.** Every suggestion that is not adopted, partly adopted, cannot be verified, not reviewed, stale or Policy-changed is listed. Those with severity High, Critical or unknown are flagged for the upstream caller's attention (user decision). Copilot does not stop the work; the upstream caller decides.
- **Targeted re-review.** Each suggestion is bound to the artifact files it concerns. A later change to one of those files makes only that suggestion's review stale. Edits to other files leave it current. A re-review covers only stale (and new) suggestions (user decision).
- **One report per round.** Each report request after a state change publishes a new numbered pair, `<collaboration-id>-r<n>.md` and `.json`, in `x-ipe-docs/secure-code/reports/copilot/`, and is never overwritten. The latest is current; older reports are history and never prove the current version (user decision).

A Copilot report is context for Guard, never evidence of a pass (FEATURE-002-A BR-02). Copilot does not replace Guard verification. Host routing that triggers Copilot automatically is FEATURE-003-B. The requirement-analysis stage (C-03) stays open and is not in scope.

## User Stories

- **US-01:** As a Developer or upstream agent doing design, implementation, bug fix or refactor work, I want Copilot to give concrete suggestions tied to my artifact and to an adopted Policy, so that security measures are applied while I work, not only at a final gate.
- **US-02:** As a Developer, I want Copilot to stop with "maintenance needed" when no usable Policies are adopted, and to refuse a partially changed scope until I confirm a new one, so that no rule is invented.
- **US-03:** As a Developer or upstream agent, I want one independent read-only Reviewer to check the formed artifact against the batch of suggestions, so that adoption is verified rather than claimed by the executor.
- **US-04:** As an upstream agent, I want high-risk suggestions that were not adopted, partly adopted, not verifiable, not reviewed or stale flagged in the result, so that I can decide whether to continue without Copilot deciding for me.
- **US-05:** As a Developer, I want only the suggestions whose files changed to be re-reviewed after a relevant change, so that review cost is not repeated for unrelated edits.
- **US-06:** As a Developer or upstream agent, I want a Markdown report and a same-source structured result per review round, so that people and tools read the same adoption state and old reports are never mistaken for the current state.
- **US-07:** As an upstream agent, I want Copilot and its Reviewer never to write business artifacts or claim a pass, so that the current executor stays the single writer and continuing is never mistaken for adoption.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-01 | EPIC-001 G-01; FR-13 (C-01, C-02, C-04…C-12), FR-02 (O-07, O-08), FR-22 (R-01, R-02, R-06…R-09), FR-09/FR-10 (AC-11) | Developer, upstream agent | Security measures are applied during the work and adoption is verified, not claimed | Copilot suggestions + adoption review + report. Selected means: agent suggests/reviews, script records, binds digests and renders (user decision); per-suggestion file binding for staleness; per-round immutable reports; High/Critical/unknown attention flag | Scenario: a change to the marathon sample gets specific suggestions; after the executor applies some, the Reviewer record distinguishes adopted / not adopted / cannot verify bound to the current file digests; an unrelated edit leaves results current, a relevant edit makes only the affected suggestion stale | Copilot never writes business artifacts; not a pass or approval; no requirement-analysis stage (C-03); no budget (FR-21 is per verification) | AC-003A-01a…01e, 02a…02e, 03a…03i, 04a…04j, 05a…05g, 06a…06f | not measured |
| G-01 (enabling) | EPIC-001 FR-01 (O-04, O-05), FR-27 (I-08…I-10) | Upstream agent | The executor stays the single business writer; Reviewers gain no authority and trigger no recursion | Copilot writes only its private data (collaboration folders, its lock file) and report files; skill instructions | Scenario: artifact bytes unchanged by any Copilot command | — | AC-003A-06a…06f | not measured |

## Acceptance Criteria

EPIC-001 mapping: AC-01 (Copilot part) → 06a, 06b; AC-02 → 04f…04h; AC-11 (Copilot part) → 02a…02e; AC-13 → 03a…03i; AC-14 → 04a…04e, 04i, 04j; AC-15 → 05a…05g, 06f. Breakdown AC-003A-01 (targeted re-review) is refined by AC-003A-01a…01e.

### AC-003A-01: Targeted Re-review

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003A-01a | GIVEN a suggestion with a valid review WHEN a file outside the suggestion's bound files changes and a report is produced THEN the suggestion keeps its reviewed result as current AND no re-review is requested for it | Integration |
| AC-003A-01b | GIVEN a suggestion with a valid review WHEN one of its bound files changes, is deleted or is renamed away and a report is produced THEN that suggestion is `stale` with the file and change named AND its earlier result is shown as history, not as current adoption | Integration |
| AC-003A-01c | GIVEN stale and current suggestions WHEN the collaboration state is shown THEN the stale suggestions are listed as needing re-review AND the current ones are not | Integration |
| AC-003A-01d | GIVEN a new Reviewer record covering only the stale suggestions (deleted or renamed-away bound files recorded as `absent`) WHEN recorded and a report is produced THEN those suggestions show the new results AND the unaffected suggestions keep their earlier current results without being re-reviewed | Integration |
| AC-003A-01e | GIVEN the Copilot skill package WHEN its instructions are inspected THEN they direct the agent not to re-review after every edit, to check which suggestions are stale after a relevant change and to send only those (and new suggestions) to the Reviewer | Integration |

### AC-003A-02: Adopted Policies Precondition

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003A-02a | GIVEN an adopted scope whose load status is `maintenance_needed` (no usable Policies) WHEN a collaboration is requested THEN no collaboration is opened AND the result is "maintenance needed" with the Framework maintenance next step AND no suggestion is recorded | Integration |
| AC-003A-02b | GIVEN an adopted scope with load status `partial` (changed or missing Policies) WHEN a collaboration is requested THEN it is refused with the available, changed and missing Policies listed AND the next step is to re-propose and confirm a new scope (FEATURE-001-C) | Integration |
| AC-003A-02c | GIVEN a complete adopted scope WHEN a collaboration is opened THEN the adopted scope identifier and every adopted rule with its confirmed state digest are recorded AND later appear in every report | Integration |
| AC-003A-02d | GIVEN an adopted Policy that changed or was removed after the collaboration was opened WHEN a report is produced THEN every suggestion based on it has state `policy_changed` for the rest of this collaboration (its earlier review result shown as history) AND is not counted as current adoption AND the next step is to re-confirm the scope and open a new collaboration | Integration |
| AC-003A-02e | GIVEN no adopted scope identifier, or one that does not exist WHEN a collaboration is requested THEN no collaboration is opened AND the next step is to resolve, select and confirm a scope (FEATURE-001-C), not to maintain knowledge | Integration |

### AC-003A-03: Collaboration Scope and Suggestions

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003A-03a | GIVEN a task of stage `design`, `implementation`, `bug_fix` or `refactor`, a short task description and explicit artifact files with change meaning (`added`, `modified`, `deleted`, `renamed` with old path, `unspecified`) or existing folders (`added`, `modified`, `unspecified`) WHEN a collaboration is opened THEN the collaboration ID, stage, task, artifacts and the adopted scope are recorded AND every artifact file and every regular file inside a folder artifact is recorded in a per-file manifest with its digest (deleted artifacts without digest) | Integration |
| AC-003A-03b | GIVEN a request without explicit artifacts or asking for the whole project WHEN a collaboration is opened THEN it is refused with a next step to name the changed artifacts (Copilot focuses on the change and its related impact, no automatic whole-project review) | Integration |
| AC-003A-03c | GIVEN an artifact path that does not exist (and is not declared deleted), lies outside the project or is a symbolic link, or a folder declared `deleted` or `renamed` WHEN a collaboration is opened or artifacts are updated THEN it is refused naming the path with a next step (deleted or renamed folders are recorded as their individual files) | Integration |
| AC-003A-03d | GIVEN a batch of suggestions WHEN recorded THEN each suggestion has an ID, one adopted rule, one or more bound files that are members of the collaboration's per-file manifest, the location or part of the artifact, the concrete action to take, the reason, severity (`critical`, `high`, `medium`, `low`, `info` or `unknown`) and the stage AND all are stored | Integration |
| AC-003A-03e | GIVEN a suggestion naming a rule outside the adopted scope, no bound file, a file that is not a manifest member, an empty location, an empty action or an ID already used in the collaboration WHEN recorded THEN that suggestion is refused with the reason AND nothing of the batch is stored | Integration |
| AC-003A-03f | GIVEN a suggestion without a known severity WHEN recorded THEN its severity is `unknown`, never defaulted to `low` | Integration |
| AC-003A-03g | GIVEN a suspected credential in any free text (task description, location, action, reason, Reviewer requirement or basis) WHEN stored or reported THEN the value is masked in the collaboration state, the structured result and the Markdown report AND the masked item is labelled as masked, never as unchanged input | Integration |
| AC-003A-03i | GIVEN an open collaboration WHEN an artifact update adds, modifies, deletes or renames files (renamed with old and new path) THEN the manifest records each change with its change meaning and the digest at the update (none for deleted) AND added or renamed files become bindable AND suggestions bound to a deleted or renamed-away path become `stale` naming that path at the next report AND no other suggestion changes state because of the update | Integration |
| AC-003A-03h | GIVEN the Copilot skill package WHEN its instructions are inspected THEN they direct the agent to work during design, implementation, bug fix and refactor (including changes to an existing design), to load the adopted Policies through the Framework, to give concrete suggestions tied to an artifact location and a Policy source (no generic checklist), to focus on the change and its related impact, and to leave all edits to the current executor | Integration |

### AC-003A-04: Adoption Review

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003A-04a | GIVEN a formed artifact and a batch of suggestions WHEN a Reviewer record is recorded THEN it uses the shared Reviewer record (FEATURE-002-A `reviewer-record/v1`: invocation with host, agent, read-only flag and invocation time; review requirement; reviewed file digests; subjects) with subject type `adoption` AND each subject is a suggestion of the collaboration with a result `adopted`, `partial`, `not_adopted`, `not_applicable` or `cannot_verify` and a basis | Integration |
| AC-003A-04b | GIVEN an adoption subject without a basis (for any result, including `adopted`, whose basis names where the measure is found) or naming a suggestion that does not exist in the collaboration WHEN recorded THEN the subject is refused AND nothing of the record is stored | Integration |
| AC-003A-04c | GIVEN a Reviewer record WHEN recorded THEN it carries, for every bound file of each covered suggestion, the digest the Reviewer saw or the marker `absent` for a file that no longer exists AND, when the reviewed-digest list is present, a covered suggestion with a bound file missing from it refuses the whole record (nothing stored) | Integration |
| AC-003A-04d | GIVEN a Reviewer record WHEN it tries to add, change or delete suggestions, artifacts, the adopted scope or the collaboration stage THEN those parts are refused because a Reviewer has no extra authority | Integration |
| AC-003A-04e | GIVEN suggestions never covered by a valid Reviewer record WHEN a report is produced THEN they are `not_reviewed` AND never counted as adopted | Integration |
| AC-003A-04f | GIVEN a Reviewer record without its invocation source (host, agent), invocation time, read-only declaration, review requirement, the reviewed-digest list as a whole or results WHEN recorded THEN it is kept but is not a valid review AND the report says why | Integration |
| AC-003A-04g | GIVEN a Reviewer record bound to digests that differ from the current digests of the covered suggestion's bound files WHEN a report is produced THEN the review does not count for that suggestion (stale) AND the report says so | Integration |
| AC-003A-04h | GIVEN a Reviewer record bound to digests that already differed from the files when it was recorded (wrong version) WHEN a report is produced THEN it is not a valid review for the suggestions concerned AND the report says so | Integration |
| AC-003A-04i | GIVEN a report WHEN a suggestion with severity `high`, `critical` or `unknown` has state `partial`, `not_adopted`, `cannot_verify`, `not_reviewed`, `stale` or `policy_changed` THEN it appears in the attention list of the report and the structured result with its reason AND every other suggestion in one of those states is listed as a gap AND only `adopted` and `not_applicable` suggestions appear in neither | Integration |
| AC-003A-04j | GIVEN the Copilot skill package WHEN its instructions are inspected THEN they direct the agent to call one independent read-only Reviewer per batch through the host (not one per rule), to pass only the task, the relevant suggestions, artifact locations and digests, to have it check the actual artifact rather than the executor's claim, and never to let the Reviewer edit artifacts, widen the review or start further agents | Integration |

### AC-003A-05: Report and Structured Result

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003A-05a | GIVEN a collaboration whose state changed since its latest report (or that has none) WHEN a report is requested THEN a new round is published: a Markdown report and a structured result named `<collaboration-id>-r<n>` in `x-ipe-docs/secure-code/reports/copilot/` AND suggestions, states, attention list, gaps, Reviewer records with validity, artifacts and adopted Policies are identical in both | Integration |
| AC-003A-05b | GIVEN an earlier report WHEN a later round is published THEN the earlier report files are byte-identical AND the new report has the next number AND states which round it supersedes | Integration |
| AC-003A-05c | GIVEN a report WHEN read THEN it states the collaboration ID and round, stage, task, artifacts with digests, adopted scope identifier and rules, every suggestion with its current state and Reviewer basis, history of earlier results for stale and Policy-changed items, the attention list and gaps AND, when no valid review exists yet, that the round is a snapshot before review | Integration |
| AC-003A-05d | GIVEN any report WHEN read THEN it states that it is not a pass, approval or security verification, that the independent review is not a correctness guarantee and does not replace Guard verification AND, for a `design` stage, that adoption in the design does not show the measure is implemented | Integration |
| AC-003A-05e | GIVEN the structured result WHEN read by an upstream caller THEN it contains the suggestions, adoption states, attention list and gaps (§14.2 consumption duty) AND contains no pass, approved or completed-safely field | Integration |
| AC-003A-05f | GIVEN a collaboration whose state (suggestions, reviews, manifest, current file digests and Policy states) is unchanged since its latest report WHEN a report is requested again THEN no new round is published AND the existing latest pair is returned; GIVEN the same structured result WHEN the Markdown is rendered twice THEN the output is identical (deterministic, no AI in the script) | Integration |
| AC-003A-05g | GIVEN a report WHEN read THEN both outputs state that reports stay until the user removes them and that the private collaboration data stays until the user removes it (no automatic expiry) AND any statement about that data's existence is labelled as of the publication time; GIVEN the collaboration state is shown later THEN `show` states whether the private data and each report still exist | Integration |

### AC-003A-06: No Business Writes and Honest Boundaries

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003A-06a | GIVEN a full collaboration (open, suggest, review, report, close) WHEN it completes THEN every artifact file is byte-identical to before each Copilot command AND only Copilot's private data (the collaboration folder and the project-wide Copilot lock file `.x-ipe/private/secure-code/locks/copilot.lock`) and report files were written | Integration |
| AC-003A-06b | GIVEN the Copilot skill package WHEN its instructions are inspected THEN it states that Copilot and its Reviewer never edit business artifacts, that the current executor makes all changes, and that Copilot does not pause or block the work (the upstream caller decides from the attention list) | Integration |
| AC-003A-06c | GIVEN the Copilot skill package WHEN inspected THEN it states that an upstream decision to continue is not adoption or a pass, that the read-only Reviewer must not trigger the Copilot or Guard flow again, that failed or old reports never count as done for the current version, and that Policies are never invented from memory | Integration |
| AC-003A-06d | GIVEN a closed collaboration WHEN suggestions or reviews are recorded THEN they are refused with a next step to open a new collaboration AND its reports stay unchanged | Integration |
| AC-003A-06f | GIVEN an open collaboration whose state changed since its latest report (or that has none) WHEN it is closed THEN a final round is published before closing AND the close result returns the latest report pair; GIVEN no change since the latest report THEN no new round is published | Integration |
| AC-003A-06e | GIVEN a collaboration WHEN Guard is later opened with its report as context THEN Guard records it as context only (FEATURE-002-A AC-002A-02b), never as evidence of a pass | Integration |

## Functional Requirements

- **FR-003A-1 Open collaboration.**
  - **Input:** project; adopted scope identifier (FEATURE-001-C); stage (`design`, `implementation`, `bug_fix`, `refactor`); task description; explicit artifact files with change meaning (`added`, `modified`, `deleted`, `renamed` with old path, `unspecified`) or existing folders (`added`, `modified`, `unspecified`); optional read-only context paths.
  - **Process:** a missing or unknown scope identifier is refused with a select-and-confirm next step; the loaded scope must be `complete` (`maintenance_needed` → maintenance needed; `partial` → reconfirm). Validate the paths (no whole-project option), record a per-file manifest with digests (every artifact file and every regular file inside a folder artifact), and allocate the collaboration ID and its private folder.
  - **Output:** collaboration ID, recorded artifacts and manifest with digests, adopted Policies.
- **FR-003A-2 Record suggestions.**
  - **Input:** a batch of suggestions, each with ID, rule, bound artifact files, location or part, action, reason, severity and stage.
  - **Validation:** rule in the adopted scope; bound files are manifest members (current or recorded deleted); required texts non-empty; IDs unique within the collaboration; severity enum with `unknown` as default. Text is masked before storage.
  - **Atomicity:** the whole batch is refused on any invalid suggestion.
  - **Change between rounds:** suggestions may be added in later rounds.
- **FR-003A-2a Update artifacts.** Records added, modified, deleted and renamed (old and new path) files in the manifest with change meaning and the digest at the update (none for deleted). Added and renamed files become bindable. Folders are added or modified as trees of files; deleted or renamed folders must be given as individual files. The update does not itself change any suggestion's state; staleness is always computed against the reviewed digests (FR-003A-4).
- **FR-003A-3 Record review.**
  - **Format:** shared `reviewer-record/v1` envelope (FEATURE-002-A FR-002A-4): invocation (host, agent, read-only declaration, invocation time), review requirement, reviewed file digests (or `absent` for a bound file that no longer exists) and typed subjects. Copilot subject type `adoption`, results `adopted`, `partial`, `not_adopted`, `not_applicable`, `cannot_verify`, each with a non-empty basis (for `adopted`, where the measure is found).
  - **No attempt field:** Copilot collaborations have no budget, so the Guard `attempt` and `usage` fields are not used and are refused. A record's coverage is exactly its subjects.
  - **Recording:** a subject without a basis or naming an unknown suggestion refuses the whole record. A record missing invocation fields, requirement, the whole reviewed-digest list or results is kept and marked invalid with its reason; a present digest list that omits a bound file of a covered suggestion refuses the whole record. Reviewed digests that already differ from the files when recorded make the record invalid (wrong version) for the suggestions concerned. A record trying to change suggestions, artifacts, scope or stage is refused.
- **FR-003A-4 Produce report (one round).**
  - Recompute the manifest file digests and reload the adopted scope.
  - State per suggestion, in this precedence: `policy_changed` if its rule changed or was removed since the collaboration was opened; otherwise, from the most recent valid Reviewer record covering it, that record's result when the current digests of all its bound files equal the reviewed ones, else `stale` naming the changed, deleted or renamed files (a file still absent matches a reviewed `absent`); `not_reviewed` if no valid record covers it. Earlier results of stale and Policy-changed suggestions are kept as history.
  - Attention list: severity `high`, `critical` or `unknown` with state `partial`, `not_adopted`, `cannot_verify`, `not_reviewed`, `stale` or `policy_changed`. Gaps: every other suggestion in one of those states.
  - A new round is published only when the state (suggestions, reviews, manifest, current digests, Policy states) differs from the latest report; otherwise the latest pair is returned. Write the structured result `<collaboration-id>-r<n>.json`, then render `<collaboration-id>-r<n>.md` from it; never modify earlier rounds. Both state report and private-data retention (until the user removes them; no automatic expiry); existence statements are as of publication.
- **FR-003A-5 Show.** Current collaboration state without writing a report: artifacts with current and recorded digests, suggestions with their current state, the suggestions needing re-review (`stale`, `not_reviewed`), the latest report path and whether the private data and each report still exist.
- **FR-003A-6 Close.** Publishes a final round if the state changed since the latest report (or none exists), then marks the collaboration closed with its end time and returns the latest report pair. Later suggestion, artifact or review recordings are refused. Reports and the private folder stay until the user removes them.

## Non-Functional Requirements

- **NFR-003A-1 Determinism.** The script uses no AI. The same recorded state renders the same report content and structured result (apart from the round number and supersedes reference).
- **NFR-003A-2 Safety.**
  - No network; no execution of artifact content.
  - Suspected credentials are masked before storage with the FEATURE-002-A patterns. Masking is pattern-based, not a complete data-loss-prevention guarantee.
  - `private` folders are not claimed as strong isolation.
- **NFR-003A-3 Consistency.** Collaboration-state writes are atomic, and concurrent commands on one collaboration are serialized. A crash never leaves a report that disagrees with its structured result, and never leaves a half-numbered round.
- **NFR-003A-4 Bounded context.** The skill passes only the task, relevant suggestions, artifact locations and digests to the model and Reviewer, never all historical reports or whole files beyond the artifacts (R-09).
- **NFR-003A-5 Portability and independence.** macOS, Linux and Windows path rules; no dependency on X-IPE task or workflow files (NFR-01). The collaboration does not need a task ID (R-02).

## UI/UX Requirements

No graphical UI.
- **Commands:** command-line operations under `secure-code copilot` (names finalized in technical design) for open, artifact update, suggest, review, report, show and close. Every command returns the toolkit result envelope (text and `--json`) with one next step per refusal.
- **Report layout:** the Markdown report leads with the attention list and its reasons, then gaps, suggestions with states and Reviewer basis, artifacts, adopted Policies, Reviewer records with validity and the boundary statements of AC-003A-05d.
- **Skill:** the Copilot SKILL.md describes the agent's collaboration procedure and replaces the "not yet available" note of the FEATURE-001-A skeleton.

## Dependencies

- **Internal:**
  - FEATURE-001-C: adopted scope load (`scope show` semantics), statuses and rule state digests.
  - FEATURE-002-A: shared Reviewer record envelope and validity rules, masking patterns, path and digest handling, report store conventions, result envelope.
  - FEATURE-001-A: root validation, layout (`reports/copilot`), atomic writes, locks.
- **External:** None beyond the toolkit runtime.
- **Consumers:**
  - FEATURE-002-A (Copilot report as context only);
  - FEATURE-003-B (carriers route design/implementation/fix/refactor tasks to Copilot);
  - FEATURE-004-A (run feedback, Phase 3);
  - FEATURE-003-C (acceptance cases).

## Business Rules

- **BR-01:** The current task executor is the single business writer. Copilot and its Reviewer never edit business artifacts (O-04, C-04, AC-01).
- **BR-02:** Copilot gives no pass, approval or verdict. An upstream decision to continue is not adoption, and a measure written in a design is not an implemented measure (C-09).
- **BR-03:** Only adopted, complete Policies are used. With none usable, the result is maintenance needed and nothing is invented (AC-11, X-14).
- **BR-04:** Suggestions are concrete: one adopted rule, at least one bound artifact file, a location and an action (C-04, AC-13).
- **BR-05:** Adoption is decided only by a valid Reviewer record bound to the current digests of the suggestion's bound files. Otherwise the suggestion is `not_reviewed`, `stale` or `policy_changed`, never adopted (C-05, C-06, O-07, O-08, AC-02, I-09).
- **BR-06:** One independent read-only Reviewer per batch. It has no extra authority, does not widen the review and does not start further agents (C-05, C-06, O-05, I-08).
- **BR-07:** High-risk attention covers severities `high`, `critical` and `unknown`. Unknown is never treated as low. Copilot does not pause the work; the upstream caller decides (C-08, user decision 10-21-2026).
- **BR-08:** Re-review is targeted. A suggestion goes stale only when one of its bound files changes, and unrelated edits trigger nothing (C-11, AC-003A-01, user decision).
- **BR-09:** One immutable report pair per round, published only after a state change; the latest is current. Old reports never prove the current version (R-07, I-09, user decision).
- **BR-10:** Independent review reduces self-confirmation bias but is not a correctness guarantee, and does not replace Guard verification (C-12).
- **BR-11:** Reports stay until the user removes them (R-06). Sensitive values are masked and no private keys or model credentials are recorded (R-08).

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Project not initialized | Refused with next step `secure-code init` |
| No adopted scope / unknown scope ID | Refused; next step resolve, select and confirm a scope (FEATURE-001-C) |
| Adopted scope with no usable Policies | "Maintenance needed" with the Framework maintenance next step; no collaboration opened |
| Bound file deleted after review | Suggestion `stale`, file named as deleted |
| Artifact renamed after review | The artifact update records the rename; suggestions bound to the old path are `stale`; a re-review records the old path as `absent`, and a new suggestion may be bound to the new path |
| Folder deleted or renamed | Refused as a folder entry; the agent records the individual files |
| File added inside a folder artifact after opening | Not bindable until recorded by an artifact update; no existing suggestion changes state |
| Policy removed or changed during the collaboration | Affected suggestions `policy_changed` for the rest of the collaboration (attention if high/critical/unknown, else gap); next step re-confirm scope and open a new collaboration |
| Two Reviewer records disagree on one suggestion | The most recent valid record covering it decides; both are shown |
| Report requested before any review | Published as a snapshot before review; all suggestions `not_reviewed`; high-risk ones in the attention list |
| Report requested with no state change | No new round; the latest pair is returned |
| Suggestion ID reused within a collaboration | Batch refused |
| Very long suggestion text | Bounded size (same limits as Guard records); refused with the limit |
| Recording after close | Refused with next step to open a new collaboration |
| Close with unreported changes | Final round published, then closed |
| Concurrent commands on one collaboration | Serialized; no lost or duplicated round number |

## Out of Scope

- Requirement-analysis / gathering stage (C-03, open).
- Budget, attempt counting and cancellation for Copilot (FR-21 applies to Guard verifications; the Reviewer is a host sub-agent, not an outbound call under FEATURE-002-C).
- Host carriers and automatic routing (FEATURE-003-B); automatic host-loading acceptance (I-19).
- Automatic cleanup of the private collaboration folder or reports; reports are removed only by the user.
- Improvement suggestions / Lessons from Copilot runs (FEATURE-004-A, Phase 3).
- Reference knowledge, Presets and tags (FEATURE-001-E/F).

## Technical Considerations

- **Decided in technical design:** collaboration ID format, command names, state and report schemas (R-10), the exact "maintenance needed" output format for Copilot (D-24) and the bounded text sizes.
- **Unprovable invocation:** the script cannot prove a Reviewer sub-agent was really invoked. It records the agent's declaration and binds it to file digests (same honest limit as FEATURE-002-A).
- **Reuse:** the FEATURE-002-A Reviewer-record validation, masking, path/digest and report-writing code; no second implementation. Reuse the FEATURE-001-C scope load in-process.
- **No verifier:** concreteness of suggestions beyond the structural checks of BR-04 is an agent responsibility, verified by the skill instructions and reviews, not by the script.

## Open Questions

None material. Decisions (10-21-2026, interact-with-human):

| Question | Decision |
|---|---|
| Responsibility split | Agent suggests and reviews; script records, binds digests and renders both outputs from one source |
| High-risk threshold (C-08) | Severity High, Critical or unknown; unknown never defaults to Low |
| Re-review trigger (C-11) | Per-suggestion bound files; only suggestions whose files changed become stale |
| Report files (R-10 update vs new) | New immutable numbered report pair per review round; latest is current |
| Adoption result enumeration (C-07) | `adopted`, `partial`, `not_adopted`, `not_applicable`, `cannot_verify` (EPIC-001 AC-14) |
| Requirement-analysis stage (C-03) | Stays open; not in scope |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| C-11, AC-003A-01 (breakdown); FR-003A-4, FR-003A-5 | US-05 | AC-003A-01a…01e | N/A | Integration | covered |
| AC-11 (Copilot part), X-14; FR-003A-1 | US-02 | AC-003A-02a…02e | N/A | Integration | covered |
| C-01, C-02, C-04, AC-13, R-08; FR-003A-1, FR-003A-2 | US-01 | AC-003A-03a…03i | N/A | Integration | covered |
| C-05…C-08, AC-14, AC-02, O-05, O-07, O-08; FR-003A-3, FR-003A-4 | US-03, US-04 | AC-003A-04a…04j | N/A | Integration | covered |
| C-10, C-12, AC-15, R-01, R-02, R-06, R-07, R-09, §14.2; FR-003A-4 | US-06 | AC-003A-05a…05g | N/A | Integration | covered |
| AC-01, O-04, C-09, I-08…I-10; FR-003A-6 | US-07 | AC-003A-06a…06f | N/A | Integration | covered |
| C-03, D-24 (format), R-10 | — | — | N/A | — | open / design-level |
| NFR-003A-1…5 | — | (05f; design-level otherwise) | N/A | — | design/implementation evidence |

## Context and Verification Evidence

- **Sources:**
  - [requirement-details.md](x-ipe-docs/requirements/requirement-details.md): EPIC-001 FR-01, FR-02, FR-13, FR-22; AC-01, AC-02, AC-11, AC-13…AC-15; FEATURE-003-A details; G-01.
  - Inventory v2 rows O-01…O-08, C-01…C-12, R-01…R-10, I-05…I-10, §14.2, §19.1, D-24.
  - [FEATURE-002-A specification](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/specification.md) (FR-002A-4 shared envelope with `adoption` subject reserved; BR-02).
  - [FEATURE-001-C specification](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md) (load statuses, BR-11).
  - Copilot skill skeleton from FEATURE-001-A.
- **Board:** FEATURE-003-A, EPIC-003, v1.0, Planned; depends on FEATURE-001-C and FEATURE-002-A, both Completed.
- **Engineering delivery:** not started (refinement only). **Stakeholder outcome:** not measured.
- **Independent review (rubber-duck, 10-21-2026):** three rounds.
  - Round 1: 6 blocking and 2 non-blocking findings, all fixed: no-scope versus maintenance-needed next steps (02e); per-file manifest and artifact update (03a, 03i); `policy_changed` state in attention and gaps; exact Reviewer-record fields with no attempt field; a round only on a state change; retention statements (05g); a basis for every result; masking of all free text.
  - Round 2: 3 blocking and 2 non-blocking findings, all fixed: `absent` marker for deleted or renamed-away files; folder delete/rename refused; close publishes a final round (06f); `policy_changed` is permanent for the collaboration; existence statements as of publication.
  - Round 3: 2 blocking findings, fixed: allowed folder change meanings; missing versus incomplete reviewed-digest list.
- **Execution:** free-mode, no application workflow write (`workflow_action_updated: false`).
