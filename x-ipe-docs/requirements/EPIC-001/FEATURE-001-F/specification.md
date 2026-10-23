# Feature Specification: Presets & Tags

> Feature ID: FEATURE-001-F  
> Epic: EPIC-001 (Framework: Knowledge, Authorization & Policy)  
> Phase: Phase 2 (P2)  
> Version: v1.6  
> Status: Refined — OQ-01…OQ-09 decided by the DAO representative under the human's delegation (DAO-003), revised after independent reviews (DAO-004, DAO-005); TASK-066, free mode; re-review at the final hash pending  
> Last Updated: 10-23-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-23-2026 | Initial specification | N/A |
| v1.1 | 10-23-2026 | Applied DAO-003 decisions on OQ-01…OQ-09: Maintainer-only tag writes, slug identity, agent-produced recompute candidates validated by the CLI, digest-checked writes, strictly additive `preset` scope mode, reserved `default` Preset, no toolkit history, mandatory summary on membership change, fixed-order Preset listing; appended AC-001F-01g, 02g…02i, 03f, 03g, 04f, 04g, 07d, 09a…09d; rewrote 07c to the decided rule | N/A (refinement decision, not a CR) |
| v1.2 | 10-23-2026 | Applied DAO-004 after independent review: no new lock files but the existing knowledge lock (knowledge → scope order, `LOCK_TIMEOUT` → `LOCKED`); OQ-05 revised to option C (no `preset` scope mode — unchanged 001-C `clues` path with a toolkit-generated canonical Preset clue); unusable `default` Preset refused instead of automatic Apply All fallback; write-path `PATH_UNSAFE` integrity; Maintainer-only tag writes limited to toolkit-mediated operations; no Preset rename; proposal digest binds Preset identity + file digest. Reworked AC-001F-02c, 04a, 04c, 04e, 04g, 07c, 09a, 09d; superseded 09b, 09c; appended 02j, 02k, 04h, 04i, 06i, 09e…09g | N/A (refinement decision, not a CR) |
| v1.3 | 10-23-2026 | Applied DAO-005 after re-review: the delivered 001-C proposal digest covers only the mode and the resolved entries, so the provenance clue is not bound — DAO-004's binding condition (R-4) is withdrawn. The clue is information-only toolkit-generated text; drift is guaranteed only for concrete references and their rule-state digests; a metadata-only Preset change between proposal and save is a documented known limit. Reworded AC-001F-04a, 04i, 09e, 09g; superseded 04h; appended 04j, 04k; future CR candidate extended to save-validated Preset provenance; no change to delivered 001-C/002-A/003-A code or tests | N/A (refinement decision, not a CR) |
| v1.4 | 10-23-2026 | Applied DAO-006 (delegated DAO representative, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`): AC-001F-06i, FR-001F-9, Technical Considerations and OQ-04 now state that 001-D is unchanged except the anticipated plug-in (the one "not checked in this version" test loop narrowed to the Reference cache; `impact.py` unsupported set drops `presets`/`tags`); appended AC-001F-06j (pre-upgrade previews stale once, fail-safe re-preview) | N/A (refinement correction, not a CR) |
| v1.5 | 10-23-2026 | Applied DAO-008 (delegated DAO representative under the human's delegation, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`; not the human): clarifications only — AC-001F-05a adds "until FEATURE-001-E, 'several sources' means several Local sources (namespaces); a Reference member is refused `invalid_reference` with the next step" (restates the existing rule at Dependencies/Edge Cases); AC-001F-06e adds "knowledge links output is byte-identical for projects without Preset/tag files (DAO-007 (2a))". Original Given/When/Then text kept; no other change | N/A (clarification, not a CR) |
| v1.6 | 10-23-2026 | Applied CR-TASK-078 (human CR4 = yes, `x-ipe-docs/dao/26-10-23/human_decisions.md`; acceptance observation O-2): `preset resolve` output `adoption` text names `preset scope-save NAME`. Appended AC-001F-04l, BR-18 and one traceability row; AC-001F-04a, 09a, 09d and BR-11 text unchanged (001-C output unchanged, no supersession) | CR-TASK-078 |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
| --- | --- | --- | --- | --- | --- |
| N/A | CLI | N/A | Command-line and agent-skill feature; no visual mockup | N/A | N/A |

## Overview

A **Preset** is a reusable, named Policy scope: a saved list of **concrete rule references** that a user can pick again instead of re-describing the same scope every time. A **tag** is a classification of rules (inside one source or across sources) used for lookup, grouping and as a conversational clue. Both live as visible JSON files in the project (`x-ipe-docs/secure-code/presets/`, `x-ipe-docs/secure-code/tags/`), one file per Preset or tag, JSON being the only authoritative format (P-03, T-01, T-02).

The feature closes the gap left open on purpose by FEATURE-001-C and FEATURE-001-D:

- **Scope selection (001-C).** A Preset becomes an input to the existing resolve → propose → confirm → scope-record flow. A user can explicitly ask to turn clues into a reusable Preset (P-11), and when no clues are given the reserved `default` Preset, if present, is highlighted and proposed before Apply All (P-13, handed to 001-F by 001-C). Selecting a Preset never adopts anything by itself; only the confirmed scope save adopts (001-C BR-01).
- **No hidden drift.** A Preset's effective content is only its concrete references — never a tag expression evaluated at use time (P-04). It may also carry the **query intent** that produced the list (pseudo-code, never executed as a program; P-05), the **snapshot_at** time of the last confirmed list change (P-07) and an **AI applicability summary** (P-09). The query is re-run only on explicit request, as an add/remove diff the user confirms (P-06). Tags never change severity, mandatory marking or saved Presets (T-04).
- **Exit impact (001-D).** Presets and tags become real impact providers: a rule deactivation, reactivation, deletion or rename shows the Presets and tags that reference it, and afterwards broken references are reported, never substituted (EPIC-001 AC-09 completion).

Users (Developer, upstream agent) maintain Presets without Maintainer authorization (P-03, U-04); this never grants knowledge-editing rights (001-B, 001-C BR-09). Tags are created, updated and deleted only by a Maintainer (U-04 does not list tags; K-03); everyone may read tags and use them as clues. The toolkit keeps no change history for Presets or tags — version control is the history, and `snapshot_at` is not a history.

## User Stories

- **US-01 (Developer):** As a developer, I want to save a scope I describe often as a Preset, so that I can reuse exactly the same rules next time without re-explaining them (P-03, P-11).
- **US-02 (Developer / upstream agent):** As a developer, I want to pick a Preset as the input of a scope proposal, so that I confirm a known list instead of building one from scratch, while still seeing missing or changed rules (P-11, 001-C).
- **US-03 (Developer):** As a developer, I want a Preset to keep the query intent that produced it and to recompute it only when I ask, with a diff to confirm, so that the list never drifts silently (P-05, P-06, P-07).
- **US-04 (Developer / upstream agent):** As a developer, I want the agent to tell me when a Preset's applicability clearly does not fit my current task, so that I can continue or adjust deliberately (P-09).
- **US-05 (Maintainer / Developer):** As a Maintainer, I want to tag rules (within or across sources), and as any user I want to use tags to find rules and as clues, so that the library is navigable without tags changing what is enforced (T-01…T-04, K-03).
- **US-06 (Maintainer):** As a Maintainer, I want rule exits to show the Presets and tags that reference the rule and to report them as broken afterwards, so that removing or renaming knowledge never silently rewrites or breaks reusable scopes (AC-09).
- **US-07 (Owner):** As the owner, I want Preset maintenance to stay separate from knowledge maintenance, so that editing a scope never grants the right to edit rules (P-02, U-04, U-05).

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-12 (P-03…P-07, P-09, P-11, T-01…T-04); FR-07/AC-09 (Preset/tag impact part) | Developer, Maintainer, upstream agent | Reusable, explicit rule scopes without hidden drift; removing or renaming knowledge never silently breaks or rewrites Presets and tags | Preset and tag stores (all required); Preset as 001-C scope input; Preset/tag exit-impact providers in 001-D | Scenario (planned): save a Preset from clues, change tag membership, reuse the Preset, recompute on request with diff, rename a referenced rule; Preset unchanged until confirmed update, impact listed first, reference reported broken | No body fingerprints or body copies (P-08); query never executed by the CLI; tags never change severity; no cascade edits; no toolkit change history | AC-001F-01a…08c, 09a, 09d…09g | not measured |
| G-03 (default-Preset branch) | EPIC-001 FR-10 / P-13, handed to 001-F by FEATURE-001-C (Overview, Out of Scope, traceability "P-13 default-Preset branch deferred to 001-F"); the EPIC-001 breakdown scope line for 001-F omits P-13 — approved deferred scope per DAO-003, not new scope | Developer, upstream agent | With no clues, a known default scope is proposed before Apply All and is adopted only on confirmation | Reserved `default` Preset feeding the 001-C no-clue branch | Scenario (planned): resolve without clues with and without a `default` Preset | No auto-adoption; AC-001C-04a unchanged when absent | AC-001F-04e, 04g | not measured |
| G-05 (enabling) | EPIC-001 G-05; P-02, U-04, U-05, K-03; 001-C BR-09 | Owner | Scope maintenance never grants knowledge-editing rights; shared classifications stay under least privilege | Preset operations need no Maintainer authorization and never write knowledge; tag writes are Maintainer-only | Scenario (planned): a User saves a Preset, is refused a tag write and a later knowledge import | Reading tags and using them as clues stays open to all | AC-001F-07a…07d | not measured |

## Acceptance Criteria

Preliminary breakdown ACs map as: AC-001F-01 → AC-001F-01a…01f; AC-001F-02 → AC-001F-03a…03e; AC-001F-03 → AC-001F-05c, 05d; AC-001F-04 → AC-001F-06a…06h.

### AC-001F-01: Preset Content and Read Safety

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-01a | GIVEN a confirmed Preset save with three available formal rule references WHEN it is saved THEN exactly one JSON file for that Preset exists under `x-ipe-docs/secure-code/presets/` AND its effective membership lists each rule as a fully qualified concrete reference (source kind, namespace, source version, rule ID) AND it holds no rule content, example or rule state digest | Integration |
| AC-001F-01b | GIVEN a Preset save whose membership contains a tag name, a tag expression, a wildcard or any other dynamically expanded selector instead of concrete references WHEN requested THEN it is refused with the reason AND nothing is written | Integration |
| AC-001F-01c | GIVEN a Preset save that also supplies a query intent and an applicability summary WHEN saved THEN both are stored as given alongside the membership AND `snapshot_at` is set to the confirmation time with its timezone offset | Integration |
| AC-001F-01d | GIVEN a saved Preset WHEN it is listed, shown, resolved as a scope input or scanned by an exit-impact preview THEN the Preset file is byte-identical afterwards AND `snapshot_at` is unchanged | Integration |
| AC-001F-01e | GIVEN a saved Preset whose referenced rule content was updated after `snapshot_at` WHEN the Preset is shown THEN its output states that `snapshot_at` is the time of the last confirmed list change and does not freeze rule content AND the current availability of each reference is shown (P-08) | Integration |
| AC-001F-01f | GIVEN a Preset save that references a rule that does not exist, a pending item, an inconsistent rule or a version-less reference matching several source versions WHEN requested THEN it is refused with each reference's reason (`not_found`, `pending_decision`, `inconsistent`, `multiple_versions`) as defined by 001-C FR-001C-2 AND nothing is written | Integration |
| AC-001F-01g | GIVEN a Preset whose membership was updated twice WHEN it is shown THEN only the current membership and latest `snapshot_at` are returned AND the output states that the toolkit keeps no Preset/tag change history (version control is the history) and that `snapshot_at` is not a history AND no history or backup file is written by the toolkit | Integration |

### AC-001F-02: Save-as-Preset and Preset Maintenance

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-02a | GIVEN the Framework skill package WHEN its scope-selection instructions are inspected THEN they direct the agent to create a Preset only when the user explicitly asks to make the clues reusable, to show the concrete list (with reasons) and the applicability summary first, and to save only after the user's confirmation; clues without that request remain a temporary scope (001-C BR-08, P-12) | Integration |
| AC-001F-02b | GIVEN a Preset save, update or delete without the explicit confirmation flag WHEN requested THEN it is refused AND nothing is written | Integration |
| AC-001F-02c | GIVEN an existing Preset WHEN its membership is explicitly updated and confirmed THEN only the confirmed membership is stored AND `snapshot_at` is set to the new confirmation time; WHEN only its query intent or applicability summary is changed THEN the membership and `snapshot_at` are unchanged; the slug is the identity and cannot be changed (no rename and no separate display label in this version — use delete and create) | Integration |
| AC-001F-02d | GIVEN a save for a Preset identity that already exists (including one differing only in letter case) WHEN requested as a new Preset THEN it is refused with the next step to update the existing Preset or choose another name | Integration |
| AC-001F-02e | GIVEN a confirmed Preset deletion WHEN done THEN its file is removed AND scope records previously saved from it are byte-identical and still load (they hold concrete references, 001-C) | Integration |
| AC-001F-02f | GIVEN an empty membership WHEN a Preset save or update is requested THEN it is refused AND nothing is written | Unit |
| AC-001F-02g | GIVEN a Preset or tag identity that contains characters other than lowercase `a–z`, `0–9` and hyphen, a path separator, a Windows-reserved device name (`con`, `prn`, `aux`, `nul`, `com1`…`com9`, `lpt1`…`lpt9`), or that equals an existing identity ignoring case WHEN a save is requested THEN it is refused with the reason AND nothing is written; GIVEN the identity `default` THEN it is accepted only as the default Preset (the output states it becomes the default Preset) and refused for tags | Unit |
| AC-001F-02h | GIVEN an update or delete of a Preset or tag WHEN it is requested without the current file digest, or with a digest that no longer matches the file THEN it is refused as stale with the current digest AND nothing is written AND no new lock file is created; WHEN the digest matches THEN the write takes the existing knowledge lock (AC-001F-02j) and is atomic | Integration |
| AC-001F-02i | GIVEN a confirmed membership change (direct update or recompute confirmation) WHEN it is requested without either a new applicability summary or an explicit "keep current summary" decision THEN it is refused AND nothing is written; WHEN the summary is explicitly kept THEN the stored summary is unchanged and the output says it was kept | Integration |
| AC-001F-02j | GIVEN the existing knowledge lock held by another toolkit operation WHEN a Preset or tag create, update or delete waits longer than the existing toolkit `LOCK_TIMEOUT` THEN it is refused with `LOCKED` AND nothing is written AND it never proceeds without the lock AND no new lock file is created | Integration |
| AC-001F-02k | GIVEN the target file, `presets/`, `tags/` or any intermediate parent (`x-ipe-docs/`, `x-ipe-docs/secure-code/`) is a symbolic link or other link pointing elsewhere WHEN a Preset or tag create, update or delete is requested THEN it is refused with `PATH_UNSAFE` AND nothing is written inside or outside the project AND any previous file is byte-identical; the check uses the delivered no-follow `durable.Tree` / `ensure_safe` mechanism | Integration |

### AC-001F-03: Query Intent — Never Run Implicitly, Recompute on Request

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-03a | GIVEN a Preset with a query intent WHEN it is listed, shown, used as a scope input or scanned by an exit-impact preview THEN the query is not evaluated AND the effective membership used is exactly the stored list | Integration |
| AC-001F-03b | GIVEN a query intent containing program code, shell syntax or any executable text WHEN it is stored or recomputed THEN it is never executed as a program; it is only treated as intent text (P-05) | Unit |
| AC-001F-03c | GIVEN an explicit recompute request for a Preset WHEN candidates are produced THEN the result shows the rules to add, the rules to remove and the unchanged count against the stored membership, with each candidate's availability and a recompute digest AND the Preset file is unchanged until confirmation | Integration |
| AC-001F-03d | GIVEN a recompute result WHEN the user confirms it with its digest (optionally accepting only some additions/removals) THEN the stored membership becomes exactly the confirmed result AND `snapshot_at` is updated; WHEN the Preset or a candidate rule changed since the recompute THEN the confirmation is refused as stale with the new diff AND nothing is changed | Integration |
| AC-001F-03e | GIVEN a recompute that produces no difference WHEN shown THEN it states that the list is unchanged AND `snapshot_at` is not updated unless the user explicitly re-confirms the list | Integration |
| AC-001F-03f | GIVEN a recompute request carrying agent-produced candidate references WHEN the CLI processes it THEN it never evaluates or executes the query text AND it validates that every candidate is an existing formal rule (001-C availability check), listing any invalid candidate with its reason and excluding it from confirmable additions AND it computes the add/remove diff and digest from the valid candidates only | Integration |
| AC-001F-03g | GIVEN the Framework skill package WHEN its Preset instructions are inspected THEN they direct the agent to turn the query intent into candidate references only through the existing read operations (`knowledge list`/`show`, tags, Policy resolve), to submit them for recompute, to show the diff and to request explicit confirmation before any update (P-06) | Integration |

### AC-001F-04: Preset as Scope-Selection Input (001-C)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-04a | GIVEN a saved Preset WHEN it is chosen as the input of a Policy resolve THEN the considered references are exactly its stored membership AND the result follows the 001-C proposal contract (library size, per-reference availability, proposal digest, "nothing adopted yet") AND names the Preset, its `snapshot_at` and its applicability summary AND carries the toolkit-generated information clue `preset:<slug>@sha256:<file digest>` AND the proposal digest is the unchanged 001-C digest over the mode and the considered references with their availability and rule state digests (it does not cover the clue text) | Integration |
| AC-001F-04b | GIVEN a Preset with one available, one deleted and one changed-but-available reference WHEN resolved THEN availability is reported per 001-C (`missing` with reason for the deleted one) AND the overall status follows 001-C BR-11 AND the Preset file is unchanged | Integration |
| AC-001F-04c | GIVEN a Preset-based proposal WHEN the user confirms and the scope is saved THEN it is saved through the unchanged 001-C proposal → confirmation path as a `clues`-mode scope record whose clues are the toolkit-generated canonical clue `preset:<slug>@sha256:<file digest>` plus the Preset's concrete references as rule clues AND it holds the adopted references with their confirmed rule state digests AND a later Preset change or deletion never changes that scope record | Integration |
| AC-001F-04d | GIVEN the Framework skill package WHEN its instructions are inspected THEN they direct the agent to compare the Preset's applicability summary with the current task and, when they clearly mismatch, to explain the difference and wait for the user's decision to continue or adjust before proposing confirmation (P-09) | Integration |
| AC-001F-04e | GIVEN no clues and a valid `default` Preset WHEN Policies are resolved without clues THEN a highlighted notice says the default Preset is proposed because no clues were given AND the proposal is built through the same Preset path (canonical clue for `default` plus its references) AND nothing is adopted until the user confirms the scope save, which is stored in `clues` mode; GIVEN no clues and no `default` Preset THEN the existing Apply All proposal of AC-001C-04a is unchanged | Integration |
| AC-001F-04f | GIVEN clues that match several Presets WHEN the agent offers Presets THEN all matching Presets are listed by name in a fixed (name-sorted) order with no ranking AND each entry shows its applicability summary and any clear mismatch with the current task (P-09) AND the user picks; the Preset list output is name-sorted on every call | Integration |
| AC-001F-04g | GIVEN no clues and a `default` Preset file that is malformed, schema-invalid, path-unsafe or whose references are all missing WHEN Policies are resolved without clues THEN the result is refused or `maintenance_needed` with the reason AND the next step is to repair the default Preset or choose another scope AND no Apply All proposal is made automatically; Apply All is proposed (per AC-001C-04a content) only when the user then separately and explicitly chooses it | Integration |
| AC-001F-04h | **Superseded by DAO-005** (the delivered proposal digest does not cover clue text; Preset identity/file digest are not checked at save; see AC-001F-04j, 04k). Former text: GIVEN a Preset-based proposal WHEN the scope save echoes a Preset identity or file digest that differs from the proposal's, or the Preset file changed after the proposal THEN the save is refused (as `stale_confirmation` or with the mismatch reason) AND nothing is written | Integration |
| AC-001F-04i | GIVEN a Preset used as scope input WHEN the proposal is produced THEN the information clue `preset:<slug>@sha256:<file digest>` is generated by the toolkit from the Preset file it read (the skill instructs the agent never to compose it) and is shown and stored only as clue text AND GIVEN a user clue that merely looks like it WHEN resolved without a Preset input THEN it is ordinary clue text: not refused, not verified, no Preset is loaded from it, and the toolkit does not claim to tell it apart from a generated one | Integration |
| AC-001F-04j | GIVEN a Preset-based proposal WHEN the Preset's concrete references are changed (a rule added or removed) before the scope save for that Preset is requested THEN the considered references taken from the current Preset no longer match the proposal AND the existing 001-C proposal-digest check refuses the save as `stale_confirmation` AND nothing is written; GIVEN a referenced rule's content changed instead THEN the same existing check refuses it; in every case the adopted scope is exactly what the user confirmed | Integration |
| AC-001F-04k | GIVEN a Preset-based proposal WHEN only the Preset's applicability summary, query intent or `snapshot_at` changes (concrete references unchanged) before the save THEN the save succeeds through the unchanged 001-C path AND the change is not detected — documented known limit (test asserts this behaviour and the skill/known-limits text states it) AND the adopted references and rule state digests are exactly those the user confirmed | Integration |
| AC-001F-04l | GIVEN a saved Preset NAME (or a usable `default` Preset) WHEN `preset resolve NAME` (or `preset resolve --default`) produces a proposal, including a `maintenance_needed` one, THEN its `adoption` field reads exactly `nothing adopted yet — the user must confirm, then: secure-code preset scope-save NAME --decisions FILE --confirmed` (NAME = the resolved Preset's name) in the result and in any `--output` file AND the proposal keys, their order, `proposal_digest`, entries and `next_steps` are otherwise unchanged AND plain `policy resolve` of the same references returns the unchanged 001-C `adoption` text `nothing adopted yet — the user must confirm, then: secure-code scope save --confirmed` AND the no-default-Preset answer keeps `nothing proposed — no default Preset` (CR-TASK-078) | Integration |

### AC-001F-05: Tags

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-05a | GIVEN a confirmed tag save with members from one or several sources WHEN saved THEN exactly one JSON file for the tag exists under `x-ipe-docs/secure-code/tags/` (visible, no leading dot) AND each member is a concrete reference to source, source version and rule ID AND no rule content is copied; until FEATURE-001-E, 'several sources' means several Local sources (namespaces); a Reference member is refused `invalid_reference` with the next step | Integration |
| AC-001F-05b | GIVEN a tag member that does not resolve to exactly one formal rule WHEN the tag save is requested THEN it is refused with the 001-C availability reason AND nothing is written | Integration |
| AC-001F-05c | GIVEN a saved Preset and a tag sharing rules WHEN tag members are added or removed and the Preset is then shown or used THEN the Preset's membership is unchanged AND the Preset file is byte-identical (T-04, P-04) | Integration |
| AC-001F-05d | GIVEN a rule with and without tags WHEN it is resolved as a Policy THEN its requirement, custom/institutional marking and any severity or mandatory attribute are identical in both cases | Integration |
| AC-001F-05e | GIVEN a tag given as a clue WHEN the agent builds a scope proposal THEN the tag is expanded into concrete references at proposal time AND the saved scope record holds only those references AND later tag changes do not change the scope record | Integration |
| AC-001F-05f | GIVEN tags WHEN they are listed or shown THEN each tag shows its members with current availability AND reading writes nothing | Integration |

### AC-001F-06: Exit Impact Providers (completes EPIC-001 AC-09, extends 001-D)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-06a | GIVEN non-empty fixtures with two Presets and two tags referencing a rule and one of each not referencing it WHEN any exit action (deactivate, reactivate, delete, rename) is previewed THEN the impact list contains a `presets` and a `tags` kind listing exactly the referencing Presets and tags by identity AND they are no longer stated as "not checked in this version" | Integration |
| AC-001F-06b | GIVEN no Preset or tag referencing the rule WHEN previewed THEN the `presets` and `tags` lists are explicitly empty AND the Reference cache is still stated as not checked until FEATURE-001-E provides it (AC-001D-02b) | Integration |
| AC-001F-06c | GIVEN a preview digest WHEN, before confirmation, a Preset or tag referencing the rule is added, changed or removed THEN the confirmation is refused as stale with the new impact AND nothing is changed (extends AC-001D-02c) | Integration |
| AC-001F-06d | GIVEN a confirmed delete, rename or deactivation of a rule referenced by Presets and tags WHEN done THEN every Preset and tag file is byte-identical (no cascade edit, no automatic substitution) | Integration |
| AC-001F-06e | GIVEN a Preset or tag referencing an exited rule WHEN it is shown, resolved or the read-only link check runs THEN the reference is reported broken with its owner (Preset or tag), target and reason (`deactivated`, `deleted`, `renamed` with the new ID as information only) AND the new ID is never used in its place AND knowledge links output is byte-identical for projects without Preset/tag files (DAO-007 (2a)) | Integration |
| AC-001F-06f | GIVEN an unreadable or malformed Preset or tag file WHEN an exit preview runs THEN that file is reported as an unreadable finding in its kind (never as an empty list) AND it is bound into the impact digest | Integration |
| AC-001F-06g | GIVEN a Preset save or tag save referencing the rule running at the same time as an exit confirmation WHEN both complete THEN they are serialized: either the save publishes first and the confirmation is refused as stale, or the exit commits first and the save re-checks the rule and is refused with its reason | Integration |
| AC-001F-06h | GIVEN a rule deactivated and then reactivated WHEN a Preset referencing it is shown or resolved THEN the reference is available again under the same identity AND the Preset file was never changed | Integration |
| AC-001F-06i | GIVEN a Preset create, update or delete referencing a rule and a 001-D exit confirmation for that rule at the same time WHEN both run THEN they are serialized by the existing knowledge lock in 001-D's fixed order (knowledge → scope) without deadlock: either the Preset write publishes first and the exit confirmation is refused as stale (impact digest changed), or the exit commits first and the Preset write re-checks the rule and is refused with its reason AND the delivered 001-D behaviour and tests are unchanged, except the anticipated plug-in: the one 001-D test loop asserting "not checked in this version" is narrowed to the Reference cache (superseded per AC-001F-06a/06b, anticipated by 001-D's provider list), and `impact.py`'s unsupported set drops `presets`/`tags` | Integration |
| AC-001F-06j | GIVEN an exit preview opened before FEATURE-001-F is installed WHEN its confirmation is requested afterwards THEN it is refused once as stale because the impact digest changes with the provider list AND the next step is to re-preview AND nothing is confirmed against an outdated impact list AND stored historical reports and scope records are byte-identical (fail-safe) | Integration |

### AC-001F-07: Authorization Separation

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-07a | GIVEN a User without Maintainer authorization WHEN they save, update, recompute or delete a Preset THEN it succeeds AND nothing under the knowledge or pending store is written | Integration |
| AC-001F-07b | GIVEN a User who just saved a Preset WHEN they attempt a knowledge import or update THEN it is still refused with `NOT_AUTHORIZED` (001-B AC-001B-08a) | Integration |
| AC-001F-07c | GIVEN a User without Maintainer authorization WHEN they create, update or delete a tag through the toolkit THEN the existing Maintainer check (`require_maintainer`) refuses it with `NOT_AUTHORIZED` and the next step to ask a Maintainer AND nothing is written; WHEN a Maintainer does the same with the explicit confirmation THEN it succeeds AND nothing under the knowledge or pending store is written; this applies to toolkit-mediated operations only (no filesystem-level isolation claim, 001-A / U-13) | Integration |
| AC-001F-07d | GIVEN a User without Maintainer authorization WHEN they list or show tags or use a tag as a clue in a scope proposal THEN it succeeds AND nothing is written | Integration |

### AC-001F-08: Stored File Integrity

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-08a | GIVEN a malformed, schema-invalid or symbolically linked Preset or tag file WHEN it is listed, shown or used THEN it is refused as invalid with the next step (restore from version control or re-save) AND no Policies are proposed from it AND other Presets/tags still work | Integration |
| AC-001F-08b | GIVEN the same Preset content saved twice WHEN serialized THEN the file bytes are identical (deterministic key order and reference order) | Unit |
| AC-001F-08c | GIVEN a save interrupted after writing starts WHEN the store is read again THEN the Preset or tag is either the previous complete version or the new complete version, never partial | Integration |

### AC-001F-09: Preset Provenance through the Unchanged 001-C Path (no new scope mode)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001F-09a | GIVEN fixtures of `clues` and `apply_all` proposals and scope records produced before FEATURE-001-F WHEN the same inputs are resolved and saved after it THEN the proposal digests, scope identifiers and record bytes are byte-identical to the fixtures AND the scope record schema and mode set are unchanged | Integration |
| AC-001F-09b | **Superseded by DAO-004** (no new scope mode; see AC-001F-09e…09g). Former text: GIVEN a confirmed Preset-based scope WHEN it is saved THEN the record has mode `preset`, the Preset name and the Preset file digest as read at proposal time, and otherwise the 001-C record content AND its identifier is computed by the 001-C rule over that content | Integration |
| AC-001F-09c | **Superseded by DAO-004** (no new scope mode; see AC-001F-09e…09g). Former text: GIVEN a `preset`-mode scope record WHEN it is loaded by 001-C `scope show`, by a Guard verification (FEATURE-002-A) and by a Copilot collaboration (FEATURE-003-A) THEN each accepts it and treats its adopted references exactly like a `clues` record AND the record loads even if the Preset was since changed or deleted (regression test added per consumer) | Integration |
| AC-001F-09d | GIVEN the delivered test suites of FEATURE-001-C, FEATURE-002-A and FEATURE-003-A WHEN run unchanged after FEATURE-001-F THEN all pass; any required change to a delivered AC, test or observable behaviour stops the work and is raised as a human change request (BR-11) | Integration |
| AC-001F-09e | GIVEN a confirmed Preset-based scope WHEN it is saved THEN the record has mode `clues` with no new field AND its clues contain the toolkit-generated information clue `preset:<slug>@sha256:<file digest>` as given (generated from the Preset file read for the proposal; not re-checked at save) AND its identifier is computed by the unchanged 001-C rule | Integration |
| AC-001F-09f | GIVEN a Preset-based `clues` record WHEN it is loaded by 001-C `scope show`, by a Guard verification (FEATURE-002-A) and by a Copilot collaboration (FEATURE-003-A) THEN each loads it through the unchanged path like any `clues` record AND it loads even if the Preset was since changed or deleted (one regression test each for Guard and Copilot) | Integration |
| AC-001F-09g | GIVEN a Preset-based proposal or record WHEN it is shown THEN the Preset provenance appears only as information clue text AND neither the output nor the skill states that it is bound, verified, tamper-evident or a structured field, or that the Preset still exists or still matches the digest | Integration |

## Functional Requirements

- **FR-001F-1 Preset store (P-03, P-04, P-07, P-08).** Input: identity (slug: lowercase `a–z`, `0–9`, hyphen; unique ignoring case; no path separators; no Windows-reserved device names; `default` reserved for the default Preset), concrete references, optional query intent, optional applicability summary, explicit confirmation. Process: validate every reference with the 001-C availability check; refuse non-concrete selectors, empty lists, invalid or duplicate identities. Output: one JSON per Preset under `x-ipe-docs/secure-code/presets/` with membership, query intent, `snapshot_at` (timezone-aware), applicability summary; no rule content or rule digest.
- **FR-001F-2 Preset read (P-07).** List and show return membership with current per-reference availability (001-C reasons, including 001-D exit reasons), `snapshot_at` with its meaning, query intent and summary. Never writes; never evaluates the query.
- **FR-001F-3 Preset update and delete.** Explicit, confirmed operations carrying the current file digest (stale refused). Membership change sets `snapshot_at` and requires a new or explicitly kept applicability summary (never silently stale); query/summary changes leave membership unchanged. No identity rename (delete + create). Delete removes only the Preset file; scope records are untouched.
- **FR-001F-4 Recompute on request (P-05, P-06).** Two steps: recompute (read-only) takes candidate references that the agent derived from the query intent through existing read operations; the CLI never executes the query, validates every candidate as an existing formal rule and computes the add/remove diff against the stored list, availability and a recompute digest; confirm applies only the confirmed changes if the digest still matches, otherwise refuses as stale.
- **FR-001F-5 Preset as scope input (P-11, 001-C).** Policy resolve accepts a Preset as the source of considered references; the toolkit reads the Preset file, takes its concrete references as rule clues and generates one information-only clue `preset:<slug>@sha256:<file digest>`; the proposal reports the Preset identity, `snapshot_at` and summary. The proposal digest is the unchanged 001-C digest (mode + considered references with availability and rule state digests); it does not cover clue text. Scope save goes through the unchanged 001-C confirmation path in `clues` mode with the considered references taken from the Preset at save time, so a change of concrete references or rule state between proposal and save is refused as `stale_confirmation`; a Preset change that leaves the concrete references unchanged is not detected (known limit, BR-17). Save-as-Preset is an agent flow ending in FR-001F-1 only on the user's explicit request.
- **FR-001F-6 Default Preset branch (FR-10/P-13 via 001-C deferral).** With no clues, a valid reserved `default` Preset is highlighted and proposed through the FR-001F-5 path (adopted only after confirmation). Without one, 001-C AC-001C-04a applies unchanged. An unusable `default` Preset is refused / `maintenance_needed` with a repair-or-choose-another-scope next step; Apply All only on a separate explicit user choice.
- **FR-001F-7 Applicability check (P-09).** The skill instructs the agent to summarize a Preset's applicability when it is saved or its membership changes, and to compare it with the current task when the Preset is used, pausing for a continue/adjust decision on clear mismatch.
- **FR-001F-8 Tag store (T-01…T-04).** One JSON per tag under `x-ipe-docs/secure-code/tags/`; members are concrete references within or across sources; list/show for everyone; save/update/delete by a Maintainer only (`NOT_AUTHORIZED` otherwise), with explicit confirmation and the current file digest; tags are read by the agent as lookup aids and clues and are never consulted to compute severity, mandatory marking or Preset membership.
- **FR-001F-9 Exit impact providers (AC-09, 001-D FR-001D-2).** Add `presets` and `tags` providers to the 001-D provider list: each lists referencing files by identity, reports unreadable files as findings, and contributes a state fingerprint to the impact digest; remove them from the "not checked in this version" set (`impact.py` unsupported set drops `presets`/`tags`; the Reference cache stays). 001-D behaviour and tests are unchanged, except the anticipated plug-in: the one 001-D test loop asserting "not checked in this version" is narrowed to the Reference cache (superseded per AC-001F-06a/06b, anticipated by 001-D's provider list), and `impact.py`'s unsupported set drops `presets`/`tags`; previews opened before the upgrade become stale once (AC-001F-06j). The read-only link check also reports broken Preset and tag references.
- **FR-001F-10 Serialization and write safety.** Preset/tag writes take the existing delivered knowledge lock in 001-D's fixed order (knowledge → scope), wait at most the existing toolkit `LOCK_TIMEOUT` and are otherwise refused `LOCKED` with nothing written; no new lock files; the caller supplies the current file digest (stale refused); writes are atomic; every write path is checked with the delivered no-follow `durable.Tree` / `ensure_safe` mechanism (`PATH_UNSAFE`).
- **FR-001F-11 Preset provenance (DAO-004 option C, limited by DAO-005).** No new scope mode or field: Preset-based scopes are `clues`-mode records carrying the toolkit-generated information clue. `clues`/`apply_all` proposals, records and digests stay byte-identical; 001-C, FEATURE-002-A and FEATURE-003-A keep their code and existing tests unchanged, plus a regression test that Guard and Copilot load a Preset-based scope. Honest limit: provenance is unverified clue text — not bound by any digest, not validated at save, not tamper-evident; a look-alike user clue is just a clue. Any needed change to delivered ACs or behaviour stops the work for a human CR.
- **FR-001F-12 Preset listing.** Preset list output and the agent's offer of matching Presets are in fixed name order without ranking; each entry shows its applicability summary and any clear mismatch with the current task (P-09); the user picks.
- **FR-001F-13 No toolkit history.** The toolkit keeps no change history for Presets or tags; version control is the history; `snapshot_at` is the time of the last confirmed list change, not a history.

## Non-Functional Requirements

- **NFR-001F-1 Safety.** All Preset/tag paths are inside the toolkit folders and symlink-checked; query text is never executed; no network.
- **NFR-001F-2 Determinism.** Same inputs → same file bytes, same diff and same digests (sorted keys and references).
- **NFR-001F-3 Read purity.** Read, resolve, recompute-preview and impact preview never write Preset, tag, knowledge or pending files.
- **NFR-001F-4 Portability and independence.** macOS, Linux and Windows path rules; case-insensitive identity collisions refused; no dependency on X-IPE task/workflow files (NFR-01).
- **NFR-001F-5 Bounded scan.** Impact and link checks read only toolkit files; cost grows linearly with the number of Preset/tag files.
- **NFR-001F-6 Privacy.** Preset/tag files hold references, intent text and summaries only — no secrets or rule bodies; skill instructions keep the 001-B pre-check expectation for free text.

## UI/UX Requirements

CLI and agent-skill only. Text output follows the 001-C/001-D style: status and next step first; Preset show prints membership with availability, `snapshot_at` with the note "last confirmed list change; does not freeze rule content", query intent marked "not run"; recompute prints `+` additions and `-` removals with counts; exit preview prints `presets` and `tags` groups with counts ("none" when empty). All commands keep the `--json` option.

## Dependencies

- **Internal:** FEATURE-001-C — availability check, resolve/proposal contract, scope save/load, skill scope-selection instructions (P-11 branch, P-13 default branch reserved for 001-F, AC-001C-04a notice `default_preset_exists`); FEATURE-001-D — exit actions, provider list, impact digest, link check, exit reasons; FEATURE-001-B — formal rules, Maintainer check (`NOT_AUTHORIZED`), locks; FEATURE-001-A — project layout already creating `presets/` and `tags/`, result envelope.
- **Phase 2 peers:** FEATURE-001-E — Reference rule references in Presets/tags become valid once Reference knowledge exists; until then only Local references are accepted.
- **Consumers:** FEATURE-002-A (Guard), FEATURE-003-A (Copilot) and 001-C `scope show` load Preset-based scopes as ordinary `clues` records through the unchanged path; existing tests unchanged plus one regression test each for Guard and Copilot (FR-001F-11).
- **External:** none.

## Business Rules

- **BR-01:** A Preset's effective content is only its concrete references; tags, queries and summaries never expand into membership at use time (P-04).
- **BR-02:** The query is intent text; it runs only on explicit recompute request and never as a program; changes need a confirmed diff (P-05, P-06).
- **BR-03:** `snapshot_at` changes only on a confirmed membership change; reading never refreshes it, and it never claims to freeze rule content (P-07, P-08).
- **BR-04:** No rule bodies, examples or rule fingerprints are stored in Presets or tags (P-08, T-03).
- **BR-05:** Tags never change severity, mandatory marking or saved Presets (T-04).
- **BR-06:** Selecting a Preset adopts nothing; only a confirmed 001-C scope save adopts (P-01, 001-C BR-01).
- **BR-07:** Clues become a Preset only on the user's explicit request (P-11, P-12).
- **BR-08:** Preset maintenance needs and grants no Maintainer authorization; knowledge stays Maintainer-only (P-03, U-04, P-02). Tag create/update/delete is Maintainer-only via the existing `require_maintainer` check for toolkit-mediated operations (no filesystem-level isolation claim; 001-A / U-13); reading tags and using them as clues is open to everyone (U-04, K-03; DAO-003, DAO-004).
- **BR-09:** Rule exits never edit Presets or tags; broken references are reported, never substituted (AC-09, 001-D).
- **BR-10:** JSON is the only authoritative format for Presets and tags; no duplicate Markdown lists (T-02).
- **BR-11:** Preset-based scopes use only the unchanged 001-C `clues` path (no new scope mode or field); if any delivered AC, test or observable behaviour of 001-C, 002-A or 003-A would change, work stops and a human change request is raised.
- **BR-15:** An unusable `default` Preset never triggers an automatic Apply All proposal; Apply All requires a separate explicit user choice.
- **BR-16:** Preset and tag writes reuse the existing knowledge lock and no-follow path checks; no new lock files; a timed-out lock means `LOCKED` with nothing written.
- **BR-17:** Drift and staleness are guaranteed only for the concrete rule references and their rule state digests (delivered 001-C behaviour); a Preset change that leaves the concrete references unchanged (summary, query intent, `snapshot_at`, metadata) between proposal and save is not detected; the adopted scope is always exactly what the user confirmed. The provenance clue is information only and never claimed as bound, verified or tamper-evident.
- **BR-18 (CR-TASK-078):** Every save instruction in `preset resolve` output names `secure-code preset scope-save NAME`: its `adoption` value is the Preset text of AC-001F-04l. This is a value change of a 001-F command only — the 001-C `adoption` key, its position, the "nothing adopted yet" prefix and the complete plain `policy resolve` output stay unchanged, so BR-11 and AC-001F-09a/09d are not triggered.
- **BR-12:** The toolkit keeps no Preset/tag change history; `snapshot_at` is not a history (version control is).
- **BR-13:** A membership change always comes with a new or explicitly kept applicability summary.
- **BR-14:** Matching Presets are listed in fixed name order with no ranking; the user picks.

## Edge Cases & Constraints

| Scenario | Expected Behavior |
| --- | --- |
| Preset references a rule later deleted/renamed/deactivated | Preset unchanged; shown/resolved as `missing` with reason; user may explicitly update |
| Version-less reference matching several source versions at save | Refused as `multiple_versions`; user chooses; stored references are always fully qualified |
| Reference to Reference knowledge before 001-E is delivered | Refused as `invalid_reference` with a note that Reference sources are not available |
| `default` Preset deleted (absent) | No default exists → AC-001C-04a Apply All proposal unchanged |
| `default` Preset malformed, path-unsafe or all references missing | Refused / `maintenance_needed`; next step: repair it or choose another scope; Apply All only on a separate explicit choice |
| User types a clue `preset:x@sha256:…` | Ordinary clue text; not refused, not verified, no Preset loaded; indistinguishable in the record from a generated clue (known limit) |
| Preset summary/query intent edited between proposal and save, references unchanged | Save succeeds; change not detected (known limit, AC-001F-04k); adopted scope equals the confirmed one |
| Knowledge lock busy beyond `LOCK_TIMEOUT` | `LOCKED`; nothing written; retry later |
| Recompute candidate is pending or unclear | Shown in the diff with its reason; cannot be confirmed as an addition |
| Two users edit the same Preset/tag file | The second write carries a stale file digest and is refused with the current digest; never a silent merge or overwrite |
| Identity `CON`, `lpt1`, `a/b`, `My_Preset` or `Default` for a tag | Refused with the reason (charset, path separator, reserved device name, reserved `default`) |
| A User asks the agent to create a tag | Refused `NOT_AUTHORIZED`; the agent may instead save the rules as a Preset or ask a Maintainer |
| Tag file named with a leading dot or outside `tags/` | Not a tag; reported by list as ignored/invalid (T-01) |
| Preset whose every reference is missing | Show/resolve status `maintenance_needed` per 001-C BR-11; file unchanged |
| Query intent empty | Recompute refused with the next step to add an intent or edit the list directly |
| Very large Preset (e.g. derived from Apply All) | Allowed; stored as concrete list; later-imported rules are not added (mirrors AC-001C-04c) |

## Out of Scope

- Preset rule-body fingerprints or body copies (P-08) and any claim that `snapshot_at` freezes rule content.
- Automatic change detection or background re-running of queries (P-06); Preset ranking (P-10 remains undecided; fixed name order instead).
- Toolkit-kept change history for Presets/tags (version control only).
- Tags affecting severity, enforcement or Preset membership (T-04).
- Reference-cache impact provider (FEATURE-001-E).
- Restoring deleted rules (K-15) and cascade rewrites of Presets/tags after exits.
- Preset/tag sharing across projects, permission tables beyond Maintainer-only tag writes (U-06), and a graphical editor.
- Preset identity rename (delete + create instead) and a separate Preset display label.
- Structured, save-validated Preset provenance — a structured Preset scope mode (scope-record schema v2 or new mode enum) or a bound token/field validated at scope save — recorded as an optional future CR candidate for the human (DAO-004, extended by DAO-005); not a blocker and not part of this version.
- Filesystem-level protection of tag files against direct edits outside the toolkit (U-13).

## Technical Considerations

- **P-10:** decided for this feature by DAO-003 — query syntax is free intent text never executed by the CLI; matching shows all Presets in fixed name order (ranking stays undecided and out of scope); shared-file conflicts use the current file digest; no automatic change detection. The applicability-summary key name and exact JSON keys are design choices (inventory §6.1: example keys are not an approved schema; only the semantics "concrete list + query intent + `snapshot_at` + applicability summary" are approved).
- **T-05:** decided by DAO-003 — Maintainer-only tag writes, slug identities without namespaces (members are fully qualified), no toolkit history; exact tag JSON keys are a design choice.
- Command names should follow the existing CLI groups (`knowledge`, `policy`, `scope`): suggested new groups `preset` and `tag`, plus a Preset input on `policy resolve`; `knowledge exit-preview`/`exit-confirm`/`links` keep their names and gain the new kinds.
- The delivered 001-D implementation lists `presets` and `tags` in its unsupported set and has an extensible provider list; the delivered 001-C resolver already reports `default_preset_exists` against `x-ipe-docs/secure-code/presets/default.json` — design should keep these contracts and only add providers/branches; the only anticipated 001-D change is the plug-in described in FR-001F-9 (DAO-006).
- Reuse 001-C availability checks and the proposal/confirmation path, the delivered knowledge lock (`knowledge.lock`, fixed order knowledge → scope, `LOCK_TIMEOUT`, `LOCKED`), the no-follow `durable.Tree` / `ensure_safe` checks (`PATH_UNSAFE`) and `require_maintainer` rather than new mechanisms.

## Open Questions

No material question remains open. OQ-01…OQ-09 were decided by the delegated DAO representative (工程師) under the human's delegation — DAO-003 (2026-10-23T13:24:51+08:00), recorded in [decisions_made_feature_refinement.md](x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md). After the independent review, DAO-004 (2026-10-23T13:32:29+08:00, same record) clarified OQ-04, revised OQ-05 to option C, tightened OQ-06 and added R-1…R-4; after the re-review DAO-005 (2026-10-23T13:36:56+08:00) limited OQ-05 to an information-only clue, withdrew R-4 and added R-5. The refiner did not decide them.

| ID | Question | Decision (DAO-003) | Applied in |
| --- | --- | --- | --- |
| OQ-01 | Who may write tags (T-05)? | Maintainer only for create/update/delete (U-04 lists Preset edits, not tags; K-03); anyone may read tags and use them as clues; Presets stay editable by any user (P-03) | BR-08, FR-001F-8, AC-001F-07c, 07d |
| OQ-02 | Preset/tag identity | File-name slug: lowercase `a–z`, `0–9`, hyphen; unique ignoring case; no path separators; Windows-reserved device names refused; `default` reserved | FR-001F-1, AC-001F-02d, 02g |
| OQ-03 | Query and recompute | CLI never executes the query (P-05); the agent turns intent into candidates via existing read operations; the CLI validates each candidate as an existing formal rule and computes diff + digest; explicit confirmation (P-06) | FR-001F-4, AC-001F-03a…03g |
| OQ-04 | Shared-file conflicts | DAO-003: caller supplies current file digest; stale refused; atomic writes; no lock files. **Clarified by DAO-004:** no *new* lock files — writes take the existing knowledge lock in 001-D's order (knowledge → scope), bounded by `LOCK_TIMEOUT` then `LOCKED`, never unlocked; the file digest stays the stale-edit guard; 001-D unchanged except the anticipated provider plug-in (DAO-006, FR-001F-9) | FR-001F-10, BR-16, AC-001F-02h, 02j, 06i, 08c |
| OQ-05 | Scope provenance | DAO-003 option (new `preset` mode) **revised by DAO-004 to option C:** no new scope mode; unchanged 001-C `clues` path with one toolkit-generated clue `preset:<slug>@sha256:<file digest>` plus the Preset's references as rule clues; regression tests for Guard and Copilot. **Limited by DAO-005 (option B):** the clue is information only (not bound, verified or tamper-evident); staleness only for concrete references and rule state digests; metadata-only Preset change is a known limit; save-validated provenance is an optional future CR candidate | FR-001F-5, FR-001F-11, BR-11, BR-17, AC-001F-04a, 04c, 04i…04k, 09a, 09d…09g (04h, 09b, 09c superseded) |
| OQ-06 | Default Preset | Included as the reserved `default` Preset, traced to FR-10/P-13 via the 001-C deferral; highlighted and proposed through the same Preset path, adopted only after confirmation; without it AC-001C-04a is unchanged. **DAO-004:** an unusable `default` is refused / `maintenance_needed`, no automatic Apply All | FR-001F-6, BR-15, Goal coverage, AC-001F-04e, 04g |
| R-1 (DAO-004) | Write-path integrity | Symlinked target or parent → `PATH_UNSAFE`, nothing written, previous file intact, via the delivered no-follow mechanism | FR-001F-10, AC-001F-02k |
| R-2 (DAO-004) | Tag authorization scope | Maintainer-only tag writes apply to toolkit-mediated operations via `require_maintainer`; no filesystem-level isolation claim (001-A / U-13) | BR-08, AC-001F-07c |
| R-3 (DAO-004) | Preset identity changes | Slug is the identity; no rename or display label in this version (delete + create) | FR-001F-3, AC-001F-02c |
| R-4 (DAO-004) | Proposal binding | **Withdrawn by DAO-005:** the delivered proposal digest covers only the mode and resolved entries, not clue text; the Preset identity/file digest are not checked at save | — (AC-001F-04h superseded) |
| R-5 (DAO-005) | Exact guarantees | Information-only clue; staleness only for concrete references and rule state digests; metadata-only change undetected (known limit); adopted scope exactly as confirmed; zero change to delivered 001-C/002-A/003-A code and tests | FR-001F-5, FR-001F-11, BR-17, AC-001F-04j, 04k, 09g |
| OQ-07 | Change history | Version control only; the toolkit keeps no Preset/tag history and `snapshot_at` is not a history | FR-001F-13, BR-12, AC-001F-01g |
| OQ-08 | Summary on membership change | New or explicitly kept summary required; never silently stale | FR-001F-3, BR-13, AC-001F-02i |
| OQ-09 | Several matching Presets | All listed by name in fixed order, no ranking (P-10 ranking undecided), each shows any P-09 mismatch; user picks | FR-001F-12, BR-14, AC-001F-04f |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| P-03, P-04, P-08, FR-001F-1 | US-01 | AC-001F-01a, 01b, 01f, 02d, 02f, 02g | N/A | Integration/Unit | covered |
| P-05, P-07, P-09, FR-001F-1/2 | US-01, US-03 | AC-001F-01c…01e, 01g | N/A | Integration | covered (prelim AC-001F-01; OQ-07) |
| P-11, P-12, FR-001F-3/5 | US-01, US-02 | AC-001F-02a…02e, 02h, 02i, 04a…04c | N/A | Integration | covered (OQ-04, OQ-08) |
| P-05, P-06, FR-001F-4 | US-03 | AC-001F-03a…03g | N/A | Integration/Unit | covered (prelim AC-001F-02; OQ-03) |
| P-09, FR-001F-7, FR-001F-12 | US-04 | AC-001F-04d, 04f | N/A | Integration | covered (OQ-09) |
| FR-10/P-13 (via 001-C deferral), FR-001F-6, BR-15 | US-02 | AC-001F-04e, 04g | N/A | Integration | covered (OQ-06, DAO-004) |
| T-01…T-04, FR-001F-8 | US-05 | AC-001F-05a…05f | N/A | Integration | covered (prelim AC-001F-03) |
| FR-07/AC-09, 001-D FR-001D-2, FR-001F-9 | US-06 | AC-001F-06a…06h, 06j | N/A | Integration | covered (prelim AC-001F-04; 06j per DAO-006) |
| P-02, P-03, U-04, U-05, K-03, BR-08 | US-07 | AC-001F-07a…07d | N/A | Integration | covered (OQ-01) |
| FR-001F-10, BR-16, NFR-001F-1…3 | US-01, US-05 | AC-001F-02j, 02k, 06i, 08a…08c | N/A | Integration/Unit | covered (OQ-04, R-1) |
| FR-001F-5, FR-001F-11, BR-11; 001-C FR-001C-5/6; 002-A, 003-A scope loading | US-02 | AC-001F-04i…04k, 09a, 09d…09g (04h, 09b, 09c superseded) | N/A | Integration | covered (OQ-05 option C limited by DAO-005; metadata-only change is a known limit; human CR if not additive) |
| FR-001F-5, BR-18; CR-TASK-078 (human CR4) | US-02 | AC-001F-04l | N/A | Integration | covered (CR-TASK-078; planned, not yet implemented; 001-C `policy resolve` output unchanged) |

## Context and Verification Evidence

- Sources (SHA-256 prefixes): requirement-details.md `1747efe61b9c5cf1` (FR-12, G-03, AC-09, FEATURE-001-F section); inventory v2 `f36a27538196f351` (P-01…P-14, T-01…T-05, U-04…U-06, §6.1 note); FEATURE-001-C specification `b35d4e9057001556`; FEATURE-001-D specification `fb74bfe254d3a6cb`; delivered `knowledge/impact.py` `9d1dd81fee1e7bf1` (`UNSUPPORTED = presets, tags, reference_cache`); `policy/resolve.py` default-Preset path; `cli.py` command groups.
- Decisions: DAO-003 and DAO-004 in `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md` (SHA-256 prefix `1f1c96d34e02cea1` when DAO-003 was applied in v1.1; `aa965e785ab1c022` when DAO-004 was applied in v1.2; `85f166f0fefb2af8` when DAO-005 was applied in v1.3); DAO-006 in `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` (`980ec55554ea285f` when applied in v1.4). Decisions are the delegated DAO representative's (工程師) under the human's delegation.
- Workflow: free mode (TASK-066, owner Sage); no board, Git or memory writes; no open material question; independent re-review of v1.3 at its final hash still required; no delivered 001-C/002-A/003-A code or test change is specified.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-001F-01a…09g (09b, 09c superseded) | Planned Integration/Unit scenarios as listed; no tests run | planned | not measured |
