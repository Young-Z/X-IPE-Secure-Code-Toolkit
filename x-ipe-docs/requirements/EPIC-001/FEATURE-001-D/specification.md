# Feature Specification: Knowledge Exit Impact & Broken-Link Handling

> Feature ID: FEATURE-001-D  
> Epic: EPIC-001 (Framework: Knowledge, Authorization & Policy)  
> Version: v1.1  
> Status: Refined — confirmed by human (TASK-049, 2026-10-22)  
> Last Updated: 10-23-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-22-2026 | Initial specification | N/A |
| v1.1 | 10-23-2026 | Non-destructive notes only, by the delegated DAO representative under the human's delegation (DAO-007, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`), not by the human: supersession note on AC-001D-02b (Presets/tags become supported kinds with FEATURE-001-F; text kept) and extension note on FR-001D-7 (link check reports broken Preset/tag references, AC-001F-06e). No AC/BR text changed; earlier acceptance evidence is not edited | N/A (anticipated plug-in notes, not a CR) |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: command-line operations and files. Bounded discovery: the EPIC-001 feature folders and the idea folder contain no mockups. | — | — |

## Overview

FEATURE-001-D lets an authorized Maintainer take one Local rule out of use. There are three exit actions:
- **Deactivate:** keep the rule but stop it being used.
- **Delete:** remove it from formal knowledge.
- **Rename:** change its rule ID.

**Reactivate** undoes a deactivation (user decision). The feature makes the consequences visible before the action, and honest afterwards.

- **Impact first, two steps** (user decisions; preview and confirm both need the Maintainer authorization):
  - The first call only shows what depends on the rule, with an impact digest:
    - rules whose relations point to it;
    - adopted scope records that adopt it;
    - open Guard verifications and open Copilot collaborations that use it;
    - pending import decisions for it;
    - the toolkit's known caches (the knowledge-documents index).
  - The second call, with the digest, performs the action. It is refused if the impact changed in between.
  - References never block the Maintainer's decision.
- **Nothing else is edited.** Other rules, scope records, Guard and Copilot runs, and reports are never modified. Broken references are reported as broken with the reason ("deactivated", "deleted", "renamed to X") and are never silently replaced by another rule, ID or source version. Repairing references is a separate, explicit choice by an authorized person.
- **Known caches are invalidated.** The knowledge-documents index entries for the rule are invalidated at once (not after a waiting period), so a later import re-evaluates the document. The impact contract is extensible: Presets, tags and the Reference cache are added by FEATURE-001-F and FEATURE-001-E.
- **History is kept.**
  - Deactivate, reactivate and rename are recorded in the rule's changelog.
  - Delete keeps a private tombstone with the rule's last content, its full changelog and the exit record (user decision).
  - Rename keeps the content and changelog with the new ID. It changes only the rule ID within the same namespace and source version (user decision).
  - Historical Guard and Copilot reports and scope records stay byte-identical.

Restoring a deleted or renamed rule (K-15) stays out of scope, and exited identities are reserved (never reused). Every exit action changes the rule's state revision, so scopes and open Guard and Copilot runs notice even a deactivate-then-reactivate cycle (user decision). Preset and tag impact is verified with non-empty fixtures when FEATURE-001-F lands.

## User Stories

- **US-01:** As a Maintainer, I want to see everything that depends on a rule before I deactivate, delete or rename it, so that I decide knowing the consequences.
- **US-02:** As a Maintainer, I want my decision not to be blocked by existing references and no other record to be changed for me, so that I keep control and nothing is rewritten silently.
- **US-03:** As a Developer or upstream agent, I want references to an exited rule to be reported as broken with the reason, never replaced by another rule, so that Policies, Guard verifications and Copilot collaborations stay honest.
- **US-04:** As a Maintainer or auditor, I want the exit recorded and old reports unchanged, so that history stays traceable after knowledge leaves.
- **US-05:** As a Maintainer, I want a deactivated rule to be reactivated the same way, so that a temporary withdrawal is reversible.
- **US-06:** As a Maintainer, I want an interrupted or concurrent exit never to be reported as done when it was not, so that the library stays consistent.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-07 (K-34, K-35, K-36, X-15 exit part, D-04); AC-09, AC-10 | Maintainer, Developer, upstream agent | Removing or renaming knowledge never silently breaks or rewrites dependent work; history stays traceable | Exit operations with impact preview. Selected means (user decisions 10-22-2026): Maintainer-only two-step preview/confirm with impact digest, tombstone on delete, reactivate as the only restore, rename of the rule ID only, reserved exited identities, lifecycle state revision | Scenario: rename a rule that another rule relates to and a scope adopts. The impact is shown first, then the relation is reported "renamed to X" (not substituted), the scope loads as partial, and old reports are unchanged | No automatic cascade edits; the Maintainer keeps the decision; no restore of delete/rename (K-15); no Preset/tag/Reference cache impact before FEATURE-001-E/F | AC-001D-01a…01c, 02a…02f, 03a…03h, 04a…04f, 05a…05d, 06a…06c | not measured |

## Acceptance Criteria

EPIC-001 mapping: AC-09 → 02a…02f, 03a…03h, 04a…04f; AC-10 (exit part) → 06a, 06b. Breakdown AC-001D-01 (deciding not blocked; no automatic modification) is refined by AC-001D-01a…01c.

In every AC, "nothing is written" or "nothing is changed" means no write attributable to the current request. The only exception is the bounded recovery of an earlier interrupted exit (FR-001D-6), which any knowledge or Policy command may perform first. The same reading applies to the read-only guarantees of FEATURE-001-B and FEATURE-001-C.

### AC-001D-01: Maintainer Decision and Authorization

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001D-01a | GIVEN a rule that another rule relates to and that an adopted scope adopts WHEN the Maintainer confirms its deactivation, its deletion or its rename (each tested) with the current impact digest THEN the action is performed (references do not block it) AND no other rule, scope record, Guard or Copilot run, or report is modified | Integration |
| AC-001D-01b | GIVEN no valid Maintainer authorization (missing, invalid or revoked) WHEN an exit preview is requested THEN it is refused with `NOT_AUTHORIZED` and its next step AND no impact data is returned AND nothing is written (apart from the bounded recovery of FR-001D-6) | Integration |
| AC-001D-01c | GIVEN no valid Maintainer authorization WHEN an exit confirmation is attempted THEN it is refused with `NOT_AUTHORIZED` AND nothing is written; GIVEN a valid authorization at preview time that is revoked before the confirmation THEN the confirmation is refused, because it re-verifies the authorization | Integration |

### AC-001D-02: Impact List First

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001D-02a | GIVEN a rule WHEN any exit action (deactivate, reactivate, delete, rename) is previewed THEN the result lists, each with identifiers: rules whose relations point to it, adopted scope records that adopt it, open Guard verifications and open Copilot collaborations whose adopted rules include it, pending import decisions for it, and knowledge-documents index entries for it AND an impact digest AND nothing is written (apart from the bounded recovery of FR-001D-6) | Integration |
| AC-001D-02b | GIVEN a preview WHEN it is read THEN it also states, for each impact kind not yet supported (Presets, tags, Reference cache), that it is not checked in this version, never that it is empty. *Supersession note (10-23-2026, DAO-007): from FEATURE-001-F, Presets and tags are supported kinds (AC-001F-06a/06b); this AC continues to apply to the Reference cache until FEATURE-001-E.* | Integration |
| AC-001D-02c | GIVEN a preview digest WHEN, before the confirmation, the rule changes, a rule relation to it is added or removed, a scope adopting it is saved, or a pending decision or index entry for it changes THEN the confirmation is refused as stale with the new impact AND nothing is changed | Integration |
| AC-001D-02d | GIVEN a confirmation without a digest, with a digest of another rule, action, reason or rename target, or for a rule that does not exist WHEN executed THEN it is refused with the reason and the next step to preview AND nothing is changed | Integration |
| AC-001D-02e | GIVEN a rule with no dependencies WHEN previewed THEN every supported impact list is explicitly empty AND the action still needs the confirmation step | Integration |
| AC-001D-02f | GIVEN a confirmation in progress WHEN a scope save for a scope adopting the rule runs at the same time THEN the two are serialized: either the scope save publishes first and the confirmation is refused as stale, or the exit commits first and the scope save re-checks the rule under the locks and is refused with `STALE_CONFIRMATION` with no scope published (publication stays allowed only if the user's confirmed decision already marked that reference not adopted); a Guard verification or Copilot collaboration opened during the confirmation reports the change through its existing Policy-change handling | Integration |

### AC-001D-03: Exit Actions

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001D-03a | GIVEN a confirmed deactivation with a non-empty reason WHEN done THEN the rule stays stored with its content and changelog AND is marked deactivated AND its changelog records the action with time and reason AND its rule state revision changes | Integration |
| AC-001D-03b | GIVEN a deactivated rule WHEN reactivation is previewed and confirmed with a reason THEN it is usable again AND its changelog records the reactivation AND its rule state revision changes again (it never returns to the pre-deactivation value); reactivating an active rule is refused | Integration |
| AC-001D-03c | GIVEN a confirmed deletion with a reason WHEN done THEN the rule is no longer in formal Local knowledge AND a private tombstone holds its last content, examples, metadata, full changelog and the exit record (action, time, reason) | Integration |
| AC-001D-03d | GIVEN a confirmed rename with a reason to a new rule ID in the same namespace and source version WHEN done THEN the rule exists only under the new ID with byte-identical content and examples and unchanged non-identity metadata (name, applicability, source location, source documents and relations, including any relation that points to its old ID, which is then reported broken `renamed`); only the rule ID, the state digests, the lifecycle revision, the update time and the changelog change AND its changelog is kept and records old and new ID AND the old ID is remembered as "renamed to <new>" | Integration |
| AC-001D-03e | GIVEN a rename to an ID that exists (active or deactivated), that is an exited identity (deleted or renamed away), that differs only in letter case from one of those, to another namespace or source version, or to an invalid ID WHEN previewed or confirmed THEN it is refused with the reason AND nothing is changed | Integration |
| AC-001D-03f | GIVEN pending import decisions and knowledge-documents index entries for the rule WHEN deletion or rename is confirmed THEN its pending decisions are removed and reported AND its index entries are invalidated; WHEN deactivation is confirmed THEN its pending decisions are kept AND its index entries are invalidated; in every case a later document check of the same document does not report it as fully stored | Integration |
| AC-001D-03g | GIVEN a confirmation without a reason or with a blank reason WHEN executed THEN it is refused AND nothing is changed | Integration |
| AC-001D-03h | GIVEN a rule whose files are inconsistent or unreadable WHEN deactivate, reactivate or rename is previewed THEN it is refused with the next step to restore its files (for example from version control) or to delete it; WHEN its deletion is previewed THEN the digest binds a fingerprint of the rule folder as found (no symbolic links followed) AND after confirmation the files are moved to the tombstone as found AND the exit record states that the rule was inconsistent | Integration |

### AC-001D-04: Broken References Reported, Never Substituted

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001D-04a | GIVEN a deactivated, deleted or renamed rule WHEN it is resolved by explicit reference THEN the reference is `missing` with reason `deactivated`, `deleted` or `renamed` (with the new ID as information) AND no content is returned AND the new ID's rule is never returned in its place | Integration |
| AC-001D-04b | GIVEN a resolve of "all" WHEN rules have exited THEN only active formal rules are resolved AND deactivated and exited identities are reported as separate informational counts that do not affect the overall status | Integration |
| AC-001D-04c | GIVEN an adopted scope that adopts the exited rule WHEN the scope is loaded THEN that rule is `missing` with the same reason AND the scope record file is byte-identical AND the load status follows the existing rules (`partial` or `maintenance_needed`) | Integration |
| AC-001D-04d | GIVEN an adopted scope that adopts a rule that was deactivated and then reactivated with unchanged content WHEN the scope is loaded THEN that rule is `needs_reconfirmation` (its rule state revision differs from the confirmed one) AND the load status is `partial` with the next step to re-confirm | Integration |
| AC-001D-04e | GIVEN other rules whose relations point to the exited rule WHEN a read-only link check runs, and when such a rule is shown THEN each broken relation is reported with its source rule, target and reason AND the relations themselves are unchanged | Integration |
| AC-001D-04f | GIVEN existing Guard and Copilot reports (Markdown and structured) and scope records that mention the rule WHEN it is deactivated, reactivated, deleted or renamed THEN all of them are byte-identical afterwards AND an open Guard verification or Copilot collaboration using it reports the Policy change at its next conclusion or report, including after a deactivate-then-reactivate cycle | Integration |

### AC-001D-05: Use After Exit

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001D-05a | GIVEN a deactivated rule WHEN it is updated by the Maintainer with the base state of the current deactivated revision THEN the update is recorded and the rule stays deactivated | Integration |
| AC-001D-05b | GIVEN a deactivated rule WHEN an import batch contains an item with the same identity THEN that item is refused with the next step to reactivate first AND other items of the batch follow the existing partial-import rules | Integration |
| AC-001D-05c | GIVEN a deleted or renamed-away identity WHEN an import contains an item with that identity, or with an identity differing from it only in letter case THEN that item is refused as a reserved exited identity AND the tombstone and exit memory stay unchanged AND other items follow the existing partial-import rules | Integration |
| AC-001D-05d | GIVEN the list and show commands WHEN rules are listed or shown THEN deactivated rules are marked deactivated AND deleted and renamed identities are listed separately as exited with their reason and time | Integration |

### AC-001D-06: Consistency Under Interruption and Concurrency

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001D-06a | GIVEN a deactivate, reactivate, delete or rename interrupted after each durable write step of the exit transaction (simulated crash at every documented step of each action) WHEN any knowledge or Policy command runs next (import, update, exit, check, list, show, resolve, scope save or load) THEN it first completes or rolls back the exit so the rule is either fully exited or fully as before (rule folder or marker, tombstone or new ID, changelog, lifecycle revision, exit memory, pending decisions and index entries consistent; a deactivated rule's document is never reported fully stored) AND no command ever shows a half state (it returns `LOCKED` if the recovery cannot run) AND the interrupted command was never reported as success | Integration |
| AC-001D-06b | GIVEN two concurrent knowledge writes on the same rule (an exit and an update, or two exits) WHEN they run THEN they are serialized AND the second one is evaluated against the result of the first: an update whose base state predates a deactivation or reactivation is refused as stale, because the base state includes the lifecycle revision AND nothing is half-written | Integration |
| AC-001D-06c | GIVEN the Framework skill package WHEN its instructions are inspected THEN they direct the agent to preview the impact and show it to the Maintainer before confirming, never to confirm on the Maintainer's behalf without a real request, never to repair references automatically, and to state that references do not block the decision | Integration |

## Functional Requirements

- **FR-001D-1 Preview.**
  - **Input:** project, rule reference `NAMESPACE/VERSION/RULE_ID`, action (`deactivate`, `reactivate`, `delete`, `rename` with new rule ID), reason (required, non-empty).
  - **Process:** verify the Maintainer authorization (the preview exposes private run and decision identifiers); read-only collection of the impact (FR-001D-2); validation of the action against the rule state:
    - the rule exists;
    - it is active or deactivated as the action requires;
    - it is readable, except for delete;
    - a rename target is free, not reserved, in the same namespace and version, and a valid ID.
  - **Output:** the impact lists, the unsupported impact kinds, what the action will do and the impact digest.
  - **Digest:** covers the action, reason, rename target, rule state revision (for an inconsistent or unreadable rule: a fingerprint of its folder as found, no links followed), and each provider's state fingerprint (FR-001D-2).
  - **Writes:** none, apart from the bounded recovery of FR-001D-6.
- **FR-001D-2 Impact providers (MVP).** Each provider returns its identifiers plus a state fingerprint of what it read:
  - relations of all other Local rules;
  - adopted scope records under `x-ipe-docs/secure-code/scopes/`;
  - open Guard verifications (run-state adopted rules);
  - open Copilot collaborations (state adopted rules);
  - pending decisions;
  - knowledge-documents index entries.

  The provider list is extensible, so FEATURE-001-E/F add the Reference cache, Presets and tags without changing this contract.
- **FR-001D-3 Confirm.**
  - **Input:** the same request plus the impact digest.
  - **Order:** re-verify the authorization; take the knowledge write lock and the scope lock (fixed order); recover any pending exit transaction; recompute the impact; refuse if the digest differs; perform the action through the exit transaction (FR-001D-6); return the result and the invalidated cache entries.
  - **Open runs:** Guard verifications and Copilot collaborations are not locked. A run opened concurrently detects the change through its existing Policy-change handling (AC-001D-02f).
  - **Scope save:** scope save (FEATURE-001-C) takes the knowledge lock and then the scope lock across its final re-check and publication, so it cannot publish an adoption of a rule that exited after its earlier validation (additive change).
- **FR-001D-4 Actions.**
  - **Deactivate:** deactivated marker; changelog entry; index entries invalidated.
  - **Reactivate:** marker removed; changelog entry.
  - **Delete:** the rule (record, content, examples, changelog) moves to a private tombstone with the exit record; its pending decisions are removed, its index entries invalidated, and the identity reserved in the exit memory.
  - **Rename:** the rule folder moves to the new ID with a changelog entry (old → new); its pending decisions are removed, its index entries invalidated, and the old identity is reserved as "renamed to".
  - **State revision:** every action changes the rule state revision, and a revision never repeats.
- **FR-001D-5 Rule state revision.**
  - **Contents:** the rule state digest used by FEATURE-001-C (and therefore by scope records, Guard and Copilot) includes the rule's lifecycle revision, not only its content. Additive for existing rules: an unexited rule's revision is the content state.
  - **Scope load:** a reactivated rule loads as `needs_reconfirmation` against a scope confirmed before the deactivation.
  - **Update base state:** the base state that `knowledge update` must match (FEATURE-001-B) includes the lifecycle revision, so an update prepared before an exit action is refused as stale (additive change).
  - **Open runs:** Guard and Copilot compare the same digest and so report the change.
- **FR-001D-6 Exit transaction.**
  - **Journal:** every exit action (deactivate, reactivate, delete, rename) changes several files, so each one uses a project-level exit journal under `.x-ipe/private/secure-code/`, written before the first change.
  - **Recovery:** every knowledge and Policy command (import, update, exit, check, list, show, link check, resolve, scope save and load) first completes or rolls back a pending journal, briefly taking the knowledge write lock when a journal exists. If the lock cannot be taken in time, the command returns `LOCKED`; it never shows a half state.
  - **Journal validation:** before acting, recovery validates the journal: schema, a known action, an existing rule or tombstone path inside the toolkit folders (no symbolic links), and before/after digests that match the files found. An invalid or inconsistent journal returns `EXIT_JOURNAL_INVALID` with a next step for the Maintainer, and changes no knowledge. Honest limit (U-13): the journal is not cryptographically bound to the authorization. Someone with local write access could forge one, just as they could edit or delete rule files directly; this is the same workflow-level trust boundary as the rest of the toolkit.
  - **Recovery is not a new write decision:** it only finishes or undoes an exit that an authorized Maintainer already confirmed. It runs before any authorization check of the current command, needs no authorization, and is the only write a read-only command (preview, check, list, show, link check, resolve, scope load) may perform. Its result names the recovered rule and action.
  - **Success:** reported only after the commit.
- **FR-001D-7 Broken references.**
  - **Explicit references and scope load:** an exited rule is `missing` with reason `deactivated`, `deleted` or `renamed` (plus `renamed_to` information).
  - **"All":** resolves only active rules; deactivated and exited counts are informational.
  - **Link check:** a read-only check lists every broken relation (source rule, target, reason) and every adopted scope record adopting an exited or absent rule.
  - **Show:** a rule's broken relations are marked.
  - Nothing is substituted or repaired automatically.
  - *Extension note (10-23-2026, DAO-007): from FEATURE-001-F the link check also reports broken Preset and tag references (AC-001F-06e) in an additive section that appears only when Preset/tag files exist; for projects without Preset/tag files the output is unchanged. This is the second and last named 001-D extension point, not a general licence.*
- **FR-001D-8 Reserved identities.** Deleted and renamed-away identities, and identities differing from them only in letter case, are refused for import and as rename targets (no reuse until an approved restore/reuse contract).

## Non-Functional Requirements

- **NFR-001D-1 Safety.** All paths are symlink-checked. The tombstone and exit memory are private (`.x-ipe/private/secure-code/`). No network.
- **NFR-001D-2 Determinism.** The same library and provider state gives the same impact lists and digest.
- **NFR-001D-3 Portability and independence.** macOS, Linux and Windows path rules; no dependency on X-IPE task or workflow files (NFR-01).
- **NFR-001D-4 Bounded scan.** The impact scan reads only toolkit files (knowledge, scopes, private run states, pending decisions, index), never business code.

## UI/UX Requirements

No graphical UI.
- **Commands:** command-line operations under `secure-code knowledge` (names finalized in technical design) for exit preview/confirm per action and a read-only link check. Every command returns the toolkit result envelope (text and `--json`) with one next step per refusal.
- **Text output:** the impact list leads the preview output, grouped by kind with counts; an empty list is printed as "none", and an unsupported kind as "not checked in this version".
- **Skill:** the Framework SKILL.md gains an "Exiting Knowledge" section.

## Dependencies

- **Internal:**
  - FEATURE-001-B: Local store, changelog, journal/recovery, knowledge lock, Maintainer authorization check, pending decisions, index.
  - FEATURE-001-C: resolve and scope-load reasons, scope records. Additive changes: new `missing` reasons, "all" limited to active rules with informational counts, a rule state digest that includes the lifecycle revision, and scope save holding the knowledge and scope locks across its final re-check and publication. FEATURE-001-B: the update base state includes the lifecycle revision; import refuses reserved and deactivated identities.
  - FEATURE-002-A / FEATURE-003-A: run and collaboration states read for impact; their existing Policy-change handling (no change).
  - FEATURE-001-A: authorization verification, result envelope.
- **External:** None.
- **Consumers:**
  - FEATURE-001-E (Reference cache invalidation provider);
  - FEATURE-001-F (Preset and tag impact providers);
  - FEATURE-003-C (acceptance cases).

## Business Rules

- **BR-01:** Exits, including their preview, are started only by an authorized Maintainer on a real request. The agent never confirms on its own initiative (K-34, U-03; user decision).
- **BR-02:** References never block the Maintainer's decision; the impact is shown first (K-34, AC-001D-01).
- **BR-03:** No automatic cascade: other rules, scope records, runs and reports are never modified. Reference repair is a separate explicit action (K-35).
- **BR-04:** Broken references are reported with the reason and never replaced by another ID or source version. A rename target is shown as information only (K-35).
- **BR-05:** Known dependent caches are invalidated at once by every exit action, including deactivation (X-15, exit part); unknown remote changes are not claimed to be detected. The source-record/entry part of X-15 belongs to the Reference cache (FEATURE-001-E).
- **BR-06:** History stays: changelog entries, the tombstone for delete, unchanged reports and scope records (K-13, K-35, R-06).
- **BR-07:** Rename changes only the rule ID within the same namespace and source version (user decision).
- **BR-08:** Reactivate is the only restore; restoring deleted or renamed rules is out of scope (K-15 open). Exited identities are reserved and never reused (user decision).
- **BR-10:** Every exit action changes the rule state revision; a reactivated rule needs scope re-confirmation even with unchanged content (user decision).
- **BR-09:** An exit is reported successful only after its commit; interrupted exits (any action) are recovered by the next knowledge or Policy command, which is the only write a read-only command may make (K-36, D-04).

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Project not initialized | Refused with next step `secure-code init` |
| Rule unknown | Preview and confirm refused with `RULE_NOT_FOUND` |
| Rule inconsistent or unreadable (hand-edited) | Deactivate, reactivate and rename refused with next step to restore its files or delete it; delete allowed (digest binds the folder fingerprint), files moved to the tombstone as found and labelled inconsistent |
| Deactivate an already deactivated rule | Refused (no change) |
| Rename to the same ID | Refused |
| The rule relates to itself | Listed once as a self-relation; on rename the relation stays byte-identical (pointing to the old ID) and is reported broken `renamed` |
| A relation on the renamed rule points to other rules | Unchanged (moves with the rule) |
| Exit while a Guard verification is open | Allowed; listed in the impact; the verification reports the Policy change at conclusion |
| Delete, then import the same identity | Refused as a reserved exited identity |
| Exit journal left by a crash | Completed or rolled back by the next knowledge or Policy command; `LOCKED` if recovery cannot run; never a half state |
| Exit journal invalid or hand-edited | `EXIT_JOURNAL_INVALID`, no knowledge changed; next step for the Maintainer |
| Tombstone folder replaced by a symbolic link | Refused (`PATH_UNSAFE`); nothing written outside |

## Out of Scope

- Restoring deleted or renamed rules; diff format and restore commands (K-15, open).
- Automatic or assisted reference repair.
- Preset, tag and Reference cache impact (FEATURE-001-F, FEATURE-001-E); the contract only reserves them.
- Batch exits of many rules in one command.
- Exits of whole namespaces or source versions.

## Technical Considerations

- Command names and flags, the impact digest canonical form, the deactivated marker, the tombstone layout, the exit-memory format and the journal steps are decided in technical design (K-15 expression).
- Reuse the FEATURE-001-B journal/recovery and lock, the FEATURE-001-C reason codes and scope reader, and the read-only parsing of Guard and Copilot states; no second store implementation.
- The open runs' own Policy-change handling (FEATURE-002-A 06j, FEATURE-003-A `policy_changed`) already covers deactivated/deleted/renamed rules as changed or missing. The only shared change is additive, in FEATURE-001-C: the rule state digest includes the lifecycle revision, and new `missing` reasons are added. Guard and Copilot code is unchanged, and their regression runners confirm it.

## Open Questions

None material. Decisions (10-22-2026, interact-with-human):

| Question | Decision |
|---|---|
| Impact first | Two-step: preview with impact digest, then confirm with the digest; stale digest refused |
| Delete | Private tombstone with last content, changelog and exit record |
| Restore | Reactivate (inverse of deactivate) only; restore of delete/rename stays open (K-15) |
| Rename | Rule ID only, same namespace and source version |
| Preview access (review) | Requires valid Maintainer authorization |
| Exited identities (review) | Reserved; no import or rename into them (case-insensitive) |
| Reactivation visibility (review) | Every exit action changes the rule state revision; reactivated rules need scope re-confirmation |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| K-34, AC-001D-01 (breakdown), U-03; FR-001D-3 | US-02 | AC-001D-01a…01c | N/A | Integration | covered |
| K-34, AC-09; FR-001D-1, FR-001D-2, FR-001D-3 | US-01 | AC-001D-02a…02f | N/A | Integration | covered |
| K-34, K-13, X-15 (exit part), AC-09; FR-001D-4, FR-001D-5 | US-04, US-05 | AC-001D-03a…03h | N/A | Integration | covered |
| K-35, AC-09; FR-001D-5, FR-001D-7 | US-03, US-04 | AC-001D-04a…04f | N/A | Integration | covered |
| K-34, K-35; FR-001D-4, FR-001D-8 | US-03, US-05 | AC-001D-05a…05d | N/A | Integration | covered |
| K-36, D-04, AC-10; FR-001D-6 | US-06 | AC-001D-06a, 06b | N/A | Integration | covered |
| U-03, I-10 (skill) | US-02 | AC-001D-06c | N/A | Integration | covered |
| K-15, P-xx, T-xx, X-05…X-08, X-15 (source-record/entry part) | — | — | N/A | — | out of scope / later features (FEATURE-001-E/F) |
| NFR-001D-1…4 | — | (design-level) | N/A | — | design/implementation evidence |

## Context and Verification Evidence

- **Sources:**
  - [requirement-details.md](x-ipe-docs/requirements/requirement-details.md): EPIC-001 FR-07, AC-09, AC-10, G-03; FEATURE-001-D details.
  - Inventory v2 rows K-13, K-15, K-19, K-34, K-35, K-36, X-15, D-04.
  - [FEATURE-001-B specification](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/specification.md) (authorization AC-001B-08, store, changelog, recovery).
  - [FEATURE-001-C specification](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md) (`missing` reasons, scope load statuses).
- **Board:** FEATURE-001-D, EPIC-001, v1.0, Planned, depends on FEATURE-001-B (Completed).
- **Engineering delivery:** not started (refinement only). **Stakeholder outcome:** not measured.
- **Independent review (rubber-duck, 10-22-2026):** four rounds; all findings fixed.
  - Round 1: 9 blocking, 3 non-blocking. User decisions: Maintainer-only preview, reserved exited identities, lifecycle state revision. Other fixes: reactivate covered; no-blocking rule tested per action; "all" limited to active rules; provider fingerprints with fixed lock order; project exit journal; deactivation invalidates the index; mandatory reason; corrupted rules; self-relation.
  - Round 2: 5 blocking. Scope save holds the locks; rename metadata; deleting a corrupted rule; every command recovers; update base state includes the revision.
  - Round 3: 3 blocking. Scope-save race refused as stale; recovery as a bounded write; journal for all four actions.
  - Round 4: 2 blocking. Journal validation with an honest limit; global meaning of "nothing written".
- **Execution:** free-mode, no application workflow write (`workflow_action_updated: false`).
