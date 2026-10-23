# Feature Specification: Policy Resolution & Adoption Scope Selection

> Feature ID: FEATURE-001-C  
> Epic: EPIC-001 (Framework: Knowledge, Authorization & Policy)  
> Version: v1.1  
> Status: Refined — confirmed by human 10-19-2026 (TASK-015)  
> Last Updated: 10-23-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-19-2026 | Initial specification | N/A |
| v1.1 | 10-23-2026 | Non-destructive supersession notes only, by the delegated DAO representative under the human's delegation (DAO-007, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`), not by the human: AC-001C-02e and BR-08 superseded in part by AC-001F-02a (Preset only on the user's explicit request); text kept, earlier acceptance evidence not edited | N/A (anticipated hand-over to FEATURE-001-F, not a CR) |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: command-line operations, files and structured results. Bounded discovery: EPIC-001 mockups folder is empty; the idea folder has no mockups. | — | — |

## Overview

FEATURE-001-C turns formal Local knowledge (FEATURE-001-B) into **Policies** that Guard (FEATURE-002-A) and Copilot (FEATURE-003-A) can use, and records which Policies the user actually **adopted** for a piece of work.

- **Three scopes, never confused.** The *library* is every formal rule stored; the *suggested scope* is what the agent proposes for this work; the *adopted scope* is what the user confirmed. Importing, listing or suggesting a rule never adopts it (P-01).
- **Agent interprets, script resolves.** The Framework skill (an AI agent) turns the user's clues — rule references or natural language — into concrete rule references, explaining why each was suggested. The deterministic `secure-code` script resolves those references (or "all") into structured Policies with an availability check and never guesses.
- **Structured, honest output.** Each Policy carries its identity, the actual requirement text, applicability notes, source evidence, retrieval status and unresolved items. A partial result is never reported as complete; an empty library yields "maintenance needed", never invented rules (X-09, X-10, X-14, K-30).
- **Confirmation, then a scope record.** Nothing is adopted until the user confirms — including the highlighted **Apply All** proposal used when no clues are given (there are no Presets in the MVP). The confirmed scope is saved as a temporary **scope record** identified by its digest, so Guard and Copilot load exactly what was adopted and see if a Policy changed since confirmation. A scope record is not a Preset and not knowledge.
- **Policy scope ≠ artifact scope.** Apply All selects all Policies, never all project files; which artifacts are checked is decided separately by the consumer (AC-12, AC-17).

Presets, tags and the default-Preset branch (FEATURE-001-F), Reference knowledge (FEATURE-001-E) and precedence between conflicting sources (D-09, undecided) are outside this feature.

## User Stories

- **US-01:** As a Developer or upstream agent, I want rule references resolved into Policies with the actual requirement text and source evidence, so that suggestions and checks rest on real content, not on rule IDs or titles.
- **US-02:** As a Developer, I want to give clues (rule references or a description of my work) and have the agent suggest a scope with reasons that I then confirm, so that imported, suggested and adopted rules are never confused.
- **US-03:** As a Developer who gives no clues, I want a highlighted Apply All proposal for all formal Policies, so that I knowingly adopt everything without it widening which files are checked.
- **US-04:** As a Developer, I want an empty or partially usable library to be reported as maintenance needed or as available / missing / unclear items, so that missing knowledge is never invented and I decide how to proceed.
- **US-05:** As Guard, Copilot or their upstream agent, I want to load a confirmed scope by its identifier and learn if any adopted Policy changed or disappeared since confirmation, so that reports cite exactly what was adopted.
- **US-06:** As an Owner, I want scope confirmation to need and grant no maintenance rights, so that choosing Policies never becomes a way to change knowledge.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-09, FR-10 (X-09, X-10, X-14, P-01, P-02, P-12…P-14, K-17, K-18, K-30, V-23) | Developer, upstream agent | Imported, suggested and adopted scope are never confused; missing knowledge is never invented; adopted scope is traceable in reports | Single Policy entry point (resolve + scope record) consumed by Guard and Copilot. Selected means: agent interprets clues, script resolves deterministically; persisted digest-identified scope record (selected over result-only hand-over); confirmation always required | Scenario: empty, partial and full libraries each produce the correct response; a confirmed scope is loaded later and a changed Policy is reported | No Presets/tags (001-F), no Reference (001-E), no precedence arbitration (D-09); language field advisory only; Apply All ≠ artifact scope | AC-001C-01a…01f, 02a…02g, 03a…03d, 04a…04c, 05a…05h | not measured |
| G-05 (enabling) | EPIC-001 G-05; P-02, BR-07 of 001-B | Owner | Selecting Policies never grants knowledge-editing rights | Scope operations need no Maintainer authorization and never write knowledge | Scenario: a User saves a scope record; a knowledge import by the same User is still refused | — | AC-001C-02f, 01e | not measured |

## Acceptance Criteria

Breakdown ACs map to groups with the same number: AC-001C-01 → AC-001C-01a…01f, AC-001C-02 → AC-001C-02a…02g, AC-001C-03 → AC-001C-03a…03d. EPIC-001 AC-12 → AC-001C-04a…04c; EPIC-001 AC-11 (Framework part) → AC-001C-03a…03d.

### AC-001C-01: Structured Policy Output

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001C-01a | GIVEN a formal rule `CWE/4.14/CWE-79` with content, a general and a Python example, applicability `python`, one related rule and a source location WHEN it is resolved by reference THEN the Policy contains its identity, name, custom/institutional marking, the full current content as the actual requirement, applicability notes (advisory language list), the example list, relations as references only, and source evidence (source location, rule state digest, time of the latest changelog entry) AND its retrieval status is `retrieved` AND its unresolved items are empty | Integration |
| AC-001C-01b | GIVEN a formal rule stored without language applicability and without a source location WHEN resolved THEN its applicability is `unknown` (never "all languages") AND its source location is `not recorded` AND that evidence gap is listed in its unresolved items AND the Policy is still available | Integration |
| AC-001C-01c | GIVEN a request where at least one reference is available and at least one is missing or unclear WHEN resolved THEN the overall status is `partial`, never `complete` AND the result counts requested, available, missing and unclear references consistently with the per-reference entries | Integration |
| AC-001C-01d | GIVEN a rule whose files were changed by hand so its state no longer matches its changelog, or whose content cannot be read WHEN resolved THEN that reference is `missing` with reason `inconsistent` or `unreadable` AND no content of it is returned as a requirement | Integration |
| AC-001C-01e | GIVEN a User without Maintainer authorization WHEN they resolve references or all Policies THEN resolution succeeds AND nothing under the knowledge store or pending store is written | Integration |
| AC-001C-01f | GIVEN every requested reference names exactly one available formal rule WHEN resolved THEN the overall status is `complete` AND Policy-level evidence gaps (such as `not recorded` source location) stay listed in that Policy's unresolved items without changing the overall status | Integration |

### AC-001C-02: Clue-based Scope Proposal and Confirmation

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001C-02a | GIVEN rule references supplied as clues without a request to save a Preset WHEN they are resolved THEN the result states the library size (formal rules), the suggested references, a proposal digest and that nothing is adopted yet AND no scope record or Preset is created | Integration |
| AC-001C-02b | GIVEN formal rules `CWE/4.13/CWE-79` and `CWE/4.14/CWE-79` WHEN the reference `CWE/CWE-79` (no version) is resolved THEN it is `unclear` with reason `multiple_versions` listing both candidates AND neither is selected automatically | Integration |
| AC-001C-02c | GIVEN a reference to a rule that does not exist and another to an item waiting for a Maintainer decision WHEN resolved THEN both are `missing`, with reasons `not_found` and `pending_decision` respectively AND the pending item's content is not returned as a Policy | Integration |
| AC-001C-02d | GIVEN formal rules with applicability `python`, `java` and none WHEN they are resolved with the artifact language context `java` THEN all three are returned as Policies AND each shows a language note `matches`, `does_not_match` or `unknown` AND no rule is excluded or marked not applicable because of language | Integration |
| AC-001C-02e | GIVEN the Framework skill package WHEN its scope-selection instructions are inspected THEN they direct the agent to turn natural-language clues into concrete rule references using the read operations, to show each suggestion with its reason and applicability note, to present any agent-proposed exclusion as a suggestion the user can reverse, to list Policies it judges ambiguous, contradictory, lacking context or conflicting with another Policy as unclear with a question (applying no precedence), to ask the user to confirm the adopted scope before saving it, and never to create a Preset. *Supersession note (10-23-2026, DAO-007): superseded in part by AC-001F-02a — only on the user's explicit request to make clues reusable.* | Integration |
| AC-001C-02f | GIVEN a User without Maintainer authorization WHEN they confirm and save a scope THEN the scope record is saved AND a subsequent knowledge import by the same User is still refused with `NOT_AUTHORIZED` | Integration |
| AC-001C-02g | GIVEN a proposal with two available Policies that the user found conflicting or unclear WHEN the scope is saved with one marked not adopted (reason given) and the other adopted with a clarification note THEN the record holds exactly those two decisions with reason and note AND no other precedence or substitution is applied | Integration |

### AC-001C-03: Empty and Partial Availability

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001C-03a | GIVEN an empty Local library (only pending items or nothing) WHEN references or all Policies are resolved THEN the status is `maintenance_needed` with no Policies AND the next step asks a Maintainer to import knowledge AND no rule is invented | Integration |
| AC-001C-03b | GIVEN a non-empty library where none of the requested references is available WHEN resolved THEN the status is `maintenance_needed` AND the next step names the missing and unclear references (revise the scope or ask a Maintainer to import them) | Integration |
| AC-001C-03c | GIVEN a partial result with missing or unclear references WHEN a scope save is requested without a not-adopted decision for each of them THEN the save is refused naming the undecided references AND no scope record is written | Integration |
| AC-001C-03d | GIVEN the same partial result WHEN each missing or unclear reference is given a not-adopted decision and the scope is saved THEN those references are recorded as not adopted with their reasons AND are never counted as adopted Policies AND a save with zero adopted Policies is refused | Integration |

### AC-001C-04: No Clues — Apply All (EPIC-001 AC-12)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001C-04a | GIVEN no clues and no default Preset WHEN all Policies are resolved THEN the result carries a highlighted notice that Apply All is proposed because there are no clues and no default Preset AND the proposal contains every formal Local rule of every namespace and source version AND rules present in several source versions are highlighted AND pending items are excluded and counted | Integration |
| AC-001C-04b | GIVEN an Apply All proposal WHEN the user confirms it and it is saved THEN the scope record has mode `apply_all`, lists each adopted rule reference concretely AND states that the artifact scope is not determined by the Policy scope | Integration |
| AC-001C-04c | GIVEN a confirmed Apply All scope WHEN a new rule is imported afterwards and the scope is loaded THEN the new rule is not part of the adopted scope | Integration |

### AC-001C-05: Scope Record

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001C-05a | GIVEN a confirmed scope WHEN it is saved THEN a scope record is stored outside the Preset and knowledge folders containing its identifier, mode (`clues` or `apply_all`), the clues as given, each adopted reference with its confirmed rule state digest and optional clarification note, each not-adopted reference with its reason, the confirmation note and the creation time AND the identifier is the digest of all of these except the creation time | Integration |
| AC-001C-05b | GIVEN a saved scope with three adopted Policies WHEN one is then updated, one removed and the scope is loaded THEN the unchanged one is adopted in the structured form of AC-001C-01a AND the updated one shows its confirmed and current state digests, `changed_since_confirmation` and adoption state `needs_reconfirmation` (current content returned for review only, not counted as adopted) AND the removed one is `missing` AND the load status is `partial` with a next step to re-propose and confirm a new scope | Integration |
| AC-001C-05c | GIVEN the same confirmed scope (same decisions, digests, mode, clues and note) WHEN it is saved twice at different times THEN the same identifier is returned AND only one record exists, keeping the first creation time | Unit |
| AC-001C-05d | GIVEN a scope record whose content was changed so that it no longer matches its identifier, or that is malformed WHEN it is loaded THEN it is refused as invalid with a next step AND no Policies are returned from it | Integration |
| AC-001C-05e | GIVEN a scope save without the explicit confirmation flag WHEN requested THEN it is refused AND no scope record is written | Integration |
| AC-001C-05f | GIVEN a proposal digest shown to the user WHEN, before the save, a proposed rule is updated, removed or (for Apply All) a formal rule is added AND the save presents that proposal digest THEN the save is refused as `stale_confirmation` naming the changed references AND no scope record is written AND the next step is to resolve again and re-confirm | Integration |
| AC-001C-05g | GIVEN a saved scope whose adopted rules are all unchanged WHEN loaded THEN every adopted Policy is returned as adopted AND the load status is `complete` | Integration |
| AC-001C-05h | GIVEN a saved scope where every adopted rule has changed or been removed WHEN loaded THEN the load status is `maintenance_needed` AND no Policy is reported as adopted | Integration |

## Functional Requirements

- **FR-001C-1 Resolve.** Input: one or more rule references (`NAMESPACE/VERSION/RULE_ID`, or `NAMESPACE/RULE_ID` without version) or "all"; optional artifact language context; optional clue text and mode label for the proposal. Process: read-only availability check per reference (FR-001C-2). Output: overall status (BR-11), library size, pending count, counts, one entry per reference (available Policy, `missing` or `unclear` with reason and candidates), a proposal digest covering every considered reference with its availability and rule state digest (and, for "all", the library state), highlighted notices and one next step.
- **FR-001C-2 Availability check (X-14).** A reference is available only when it names exactly one formal rule (not pending), whose stored state is consistent and whose content is readable. Reasons: `not_found`, `pending_decision`, `inconsistent`, `unreadable`, `invalid_reference` (missing); `multiple_versions` (unclear). Whether a requirement is understandable, contradictory, lacking context or in conflict with another Policy is judged by the agent, who reports such Policies to the user as unclear with a question before confirmation; the user's answer is recorded as a save decision (FR-001C-5). The script's availability result and the agent's judgment stay separate; the script never edits or reinterprets requirements.
- **FR-001C-3 Policy structure (X-09, X-10).** Identity; name; custom/institutional marking; actual requirement (full current content); applicability notes (advisory languages or `unknown`, plus language note against the given context); example list; relations as references; source evidence (source location or `not recorded`, source-document digest when recorded, rule state digest, latest changelog time); retrieval status (`retrieved`); unresolved items. Never identity or title only.
- **FR-001C-4 Scope proposal (agent).** The Framework skill interprets natural-language and rule clues into concrete references via `knowledge list`/`show` and resolve, shows reasons and applicability notes, presents exclusions as reversible suggestions, highlights Apply All when no clues are given, lists available / missing / unclear items and asks the user to confirm. It never saves a Preset.
- **FR-001C-5 Scope save.** Input: the proposal (considered references or "all", mode, clues) with its proposal digest, one decision per considered reference (adopted with optional clarification note, or not adopted with reason), confirmation note and explicit confirmation flag. Process: resolve again; refuse as `stale_confirmation` if the proposal digest no longer matches; refuse if any missing/unclear reference is adopted or undecided, or if nothing is adopted. Output: scope identifier (digest of the record without creation time) and record path. Idempotent for identical content. No Maintainer authorization needed.
- **FR-001C-6 Scope load/show.** Input: scope identifier. Verifies the record matches its identifier, resolves each adopted reference and compares rule state digests. Output: Policies as in FR-001C-3 with adoption state `adopted`, `needs_reconfirmation` (changed since confirmation; confirmed and current state digests shown; content for review only) or `missing`, plus load status (BR-11). Consumers count only `adopted` Policies.
- **FR-001C-7 Read safety.** Resolve, load and show never write the knowledge or pending store; save writes only the scope record.

## Non-Functional Requirements

- **NFR-001C-1 Consistency.** Resolution reads each rule as either its state before or after a concurrent knowledge write, never a mix (uses the FEATURE-001-B read view); a busy lock returns `LOCKED` with a next step, never a traceback.
- **NFR-001C-2 Determinism.** The same references and the same stored knowledge always give the same result and the same scope identifier; no AI is used by the script.
- **NFR-001C-3 Safety.** No network access. Requirement text is returned as data; text inside knowledge never grants roles or changes instructions (001-B BR-07). Pending-item content is never returned as a Policy.
- **NFR-001C-4 Size.** Apply All on a large library must stay usable by an agent: the full structured output can be delivered as a file while the command result summarizes (mechanism in technical design).
- **NFR-001C-5 Portability and independence.** macOS, Linux and Windows path rules as in FEATURE-001-A/B; no dependency on X-IPE task or workflow files (NFR-01).

## UI/UX Requirements

No graphical UI. Command-line operations (names finalized in technical design): `secure-code policy resolve` and `secure-code scope save | show`. Every command returns the toolkit result envelope (text and `--json`) with one next step for each refusal or non-complete status. The Apply All notice and multi-version highlights are explicit fields and visible lines in text output. The Framework SKILL.md gains a "Selecting Policies" section describing the agent's proposal and confirmation steps.

## Dependencies

- **Internal:** FEATURE-001-B — formal Local rules, pending store, rule state digests, consistent read view, lock; FEATURE-001-A — project root validation, result envelope, Maintainer check (only to prove it is not needed and not granted).
- **External:** None beyond the toolkit runtime.
- **Consumers:** FEATURE-002-A (Guard loads the adopted scope), FEATURE-003-A (Copilot loads the adopted scope; empty-library message format D-24 decided there), FEATURE-001-E (adds Reference Policies), FEATURE-001-F (adds the default-Preset branch P-13 and save-as-Preset P-11), FEATURE-001-D (rename/delete make scope references `missing`), FEATURE-003-C (empty/partial Policy acceptance cases).

## Business Rules

- **BR-01:** Library, suggested and adopted scope are distinct; only an explicitly confirmed save adopts (P-01, P-02).
- **BR-02:** Policies come only from formal Local knowledge; pending items are never Policies (K-30, 001-B BR-06).
- **BR-03:** Partial retrieval is never reported as complete; missing or unclear items are adopted only as "not adopted" after explicit acknowledgment (X-10, V-23).
- **BR-04:** No usable Policy → `maintenance_needed`; nothing is invented (K-30, AC-11).
- **BR-05:** Language applicability is advisory; mismatch or `unknown` never excludes a rule automatically and `unknown` never becomes "all" (K-17, K-18).
- **BR-06:** No clues and no default Preset → highlighted Apply All proposal; Apply All is a Policy scope, never an artifact scope (P-14, AC-12).
- **BR-07:** A reference without a version that matches several source versions is unclear; the user chooses (decision 10-19-2026).
- **BR-08:** Clues are never saved as a Preset (P-12); a scope record is temporary work data, not knowledge. *Supersession note (10-23-2026, DAO-007): superseded in part by AC-001F-02a — only on the user's explicit request to make clues reusable.*
- **BR-09:** Confirming a scope needs and grants no maintenance rights (P-02).
- **BR-10:** Conflicts between Policies are listed for the user as unclear; no precedence is applied silently (D-09 undecided).
- **BR-11:** Status truth table for resolve and load: `complete` = every considered reference is usable (available; for load also unchanged); `partial` = at least one usable and at least one missing, unclear or changed; `maintenance_needed` = none usable. Policy-level evidence gaps do not change the overall status.
- **BR-12:** Only what the user confirmed is adopted: a save whose proposal changed before saving is refused, and a Policy changed after confirmation needs reconfirmation through a new scope record.

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Project not initialized (no layout) | Refused with next step `secure-code init` |
| Reference with invalid syntax or unsafe characters | That reference `missing` with `invalid_reference`; others processed |
| Same reference given twice | Resolved once; duplicate noted |
| Knowledge update running during resolve | Each rule read as a consistent before or after state; busy lock → `LOCKED` |
| Rule changed between proposal and save | Save refused `stale_confirmation`; re-resolve and re-confirm |
| Rule changed after the scope was confirmed | Load marks it `changed_since_confirmation`, adoption state `needs_reconfirmation`; current content for review only; status `partial` (or `maintenance_needed` if none usable) |
| Rule removed or renamed after confirmation (FEATURE-001-D) | Load marks it `missing`; never substituted |
| Scope record folder missing in a project initialized before this feature | Created on first save; `status` does not report it as a layout problem |
| Scope record hand-edited or truncated | Refused as invalid (identifier mismatch / malformed) |
| Apply All on an empty library | `maintenance_needed`; no scope can be saved with zero adopted Policies |
| Very large library | Full output delivered as a file; command result summarizes (NFR-001C-4) |

## Out of Scope

- Presets, default Preset (P-13), save-as-Preset (P-11), `query` intent, tags (FEATURE-001-F).
- Reference knowledge and exploration cache (FEATURE-001-E).
- Precedence/arbitration between project, task, tool defaults and knowledge (D-09 undecided) and `application/system` policy domains (D-10 undecided).
- Scenario recommender tool (X-13 undecided); the agent's judgment is the only recommender.
- Artifact scope selection, check plans and verdicts (FEATURE-002-A); Copilot empty-library message format (D-24, FEATURE-003-A).
- Scope record retention/cleanup policy (records are kept until the user removes them).

## Technical Considerations

- Reference syntax, resolve output file format and size threshold, scope record format, identifier digest and storage folder, and how the agent passes clue text are decided in technical design.
- Reuse FEATURE-001-B store reads (`iter_refs`, `read_rule`, read view, rule state digest, pending store) and FEATURE-001-A envelope, path checks and atomic writes; no second knowledge reader.
- The script cannot prove that a human confirmed a scope; it records the agent's explicit confirmation flag and note. The SKILL.md must instruct the agent to set it only after the user confirms (honest limit, same class as FEATURE-001-A U-13).

## Open Questions

None material. Decisions (10-19-2026, interact-with-human):

| Question | Decision |
|---|---|
| Responsibility split | Agent interprets clues into concrete references; script resolves references or "all" deterministically with availability status |
| Adopted-scope persistence | Saved as a temporary, digest-identified scope record that Guard/Copilot load and reports cite; never a Preset or knowledge |
| Multiple source versions | Version-less reference matching several versions is unclear (user picks); Apply All includes every formal rule-version and highlights multi-version rules |
| Confirmation | Always required, including Apply All; partial availability lists available / missing / unclear first |
| Undecided items (D-09, D-24, X-13) | Ignored for now per user direction; conflicts reported, never resolved silently |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| X-09, X-10; FR-001C-1, FR-001C-3; BR-11 | US-01 | AC-001C-01a, 01b, 01c, 01f | N/A | Integration | covered |
| X-14; FR-001C-2 | US-01, US-04 | AC-001C-01d, 02b, 02c | N/A | Integration | covered |
| P-02, BR-07 (001-B); FR-001C-7 | US-06 | AC-001C-01e, 02f | N/A | Integration | covered |
| P-01, P-12; FR-001C-4; X-14 (agent judgment), BR-10 | US-02 | AC-001C-02a, 02e, 02g | N/A | Integration | covered |
| K-17, K-18 | US-02 | AC-001C-02d | N/A | Integration | covered |
| K-30, AC-11 (Framework), V-23 | US-04 | AC-001C-03a…03d | N/A | Integration | covered |
| P-13, P-14, AC-12 | US-03 | AC-001C-04a…04c | N/A | Integration | covered (P-13 default-Preset branch deferred to 001-F) |
| FR-001C-5, FR-001C-6; P-01; BR-11, BR-12 | US-05 | AC-001C-05a…05h | N/A | Integration / Unit | covered |
| D-09, D-10, D-24, X-13 | — | — | N/A | — | out of scope (undecided; user direction 10-19-2026) |
| NFR-001C-1…5 | — | (design-level; NFR-001C-1 via 001-B lock tests) | N/A | — | design/implementation evidence |

## Context and Verification Evidence

- Sources: [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) (EPIC-001 FR-09, FR-10, AC-11, AC-12; FEATURE-001-C details); inventory v2 rows X-09, X-10, X-13, X-14, P-01, P-02, P-11…P-14, K-17, K-18, K-30, V-23, D-09, D-10, D-24; [FEATURE-001-B specification](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/specification.md) and implementation (store, read view, pending store); FEATURE-001-A layout and status.
- Board: FEATURE-001-C, EPIC-001, v1.0, Planned, depends on FEATURE-001-B (Completed).
- Independent review (rubber-duck, 10-19-2026): 4 blocking + 1 non-blocking findings fixed — stale confirmation (proposal digest, AC-001C-05f, BR-12); changed Policies never counted as adopted (05b, `needs_reconfirmation`); status truth table (BR-11, 01c, 01f, 05g, 05h); agent-judged unclear/conflict recorded as user decisions (FR-001C-2, 02e, 02g); identifier excludes creation time (05a, 05c).
- Mockups: none. Execution mode: free-mode.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-001C-01a…05h | Planned per Test Type; no tests yet | planned | not measured |
