# Feature Specification: Local Knowledge Maintenance & Changelog

> Feature ID: FEATURE-001-B  
> Epic: EPIC-001 (Framework: Knowledge, Authorization & Policy)  
> Version: v1.0  
> Status: Refined — awaiting human confirmation (TASK-009)  
> Last Updated: 10-19-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-19-2026 | Initial specification | N/A |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: command-line operations, files and structured results. Bounded discovery: EPIC-001 mockups folder is empty; the idea folder has no mockups. | — | — |

## Overview

FEATURE-001-B lets an authorized **Maintainer** build the formal **Local** security knowledge that every later feature (Policies, Copilot, Guard) draws on. Knowledge starts empty after project initialization (FEATURE-001-A); this feature fills it.

- **Agent structures, script stores.** The Framework skill (an AI agent) turns local documents — standards excerpts, company rules — into a batch file of separate rules. The deterministic `secure-code` script then validates identities, pre-checks content, skips work already done, stores each rule in its own folder and writes a full changelog. Before doing expensive AI structuring, the agent can ask the script which items are already stored unchanged.
- **Identity follows the source.** Rules keep the issuing institution's real IDs and versions (`CWE/4.14/CWE-79`); company rules live in custom `@` namespaces (`@CUSTOM`, `@ACME`) with a Maintainer-chosen version.
- **One current content, full history.** Each source version of a rule has exactly one current formal content. Every change appends a changelog entry with full before/after differences for body, metadata and examples — enough to trace back, without a snapshot chain or automatic restore.
- **Safe and honest batches.** Batches succeed or fail per item, can be resubmitted after interruption, never silently overwrite changed inputs, and hold suspicious items (suspected secrets, embedded operating instructions) for an explicit Maintainer decision.
- **Authority.** All writes require the verified Maintainer qualification from FEATURE-001-A, re-checked on every write. Anyone may read.

Deactivate, delete and rename (FEATURE-001-D), Reference sources (FEATURE-001-E), Presets/tags (FEATURE-001-F) and AI-drafted examples/explanations (FEATURE-001-G) are separate features.

## User Stories

- **US-01:** As a Maintainer, I want the agent to split my local documents into separate rules and the script to store each one under its source identity, so that knowledge stays traceable and individually maintainable.
- **US-02:** As a Maintainer, I want a batch to report each item as stored, current, update candidate, needs decision, refused or not processed, with reasons, so that one bad item never hides or blocks the others.
- **US-03:** As a Maintainer (through the agent), I want to know before AI processing which items are already stored unchanged, so that resubmitting after an interruption costs no repeated AI work.
- **US-04:** As a Maintainer, I want suspected secrets and embedded operating instructions held for my decision, so that unsafe content never becomes formal knowledge silently.
- **US-05:** As a Maintainer, I want to update one rule's content, metadata or examples and get a full before/after changelog entry, so that every change can be traced back.
- **US-06:** As a Maintainer, I want company requirements stored as custom-namespace rules beside institutional ones, so that local requirements never masquerade as official rules.
- **US-07:** As a User or upstream agent, I want to list and show stored rules read-only, so that I can see what knowledge exists without maintenance rights.
- **US-08:** As a Maintainer, I want concurrent or interrupted writes never to lose another change or leave a half-written rule reported as success, so that the knowledge base stays consistent.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-04, FR-05, FR-07 (K-36, D-04) | Maintainer | Security knowledge is maintainable and traceable: identity from the source, one current content, full change history | Per-rule folders, strict identity rules, append-only unified-diff changelog (selected over a snapshot chain, K-12) | Scenario: import CWE and @ACME rules, update one, read the changelog; identities, content and diffs match | No restore command (K-15 open); no licence fields (K-10) | AC-001B-02a…f, 03a…f, 06a…d, 07a…b, 09a…c | not measured |
| G-04 | EPIC-001 G-04; FR-06 (K-23…K-28, D-05) | Maintainer | Re-importing costs nothing for unchanged items; partial failures stay isolated | Pre-AI check operation, per-item digests, per-item outcomes (selected: agent structures, script stores) | Scenario: resubmit an interrupted batch; done items reported current before AI work; one invalid item does not block others | No fixed item-count limit (D-05 decision) | AC-001B-04a…g | not measured |
| G-05 | EPIC-001 G-05; FR-24 via FEATURE-001-A (U-04, U-05), K-32, K-33 | Owner / Maintainer | Only the verified Maintainer changes formal knowledge; suspicious content needs an explicit decision | `require_maintainer` on every write; pre-check on import and update holds flagged items (selected over all-draft activation) | Scenario: a User's import is refused; a batch with a planted key is stored except the flagged item, which waits for decision | Pre-check is lightweight, not a DLP system | AC-001B-01, 05a…f, 08a…b | not measured |

## Acceptance Criteria

AC-001B-01 is reserved by the breakdown (User without Maintainer authorization cannot import or edit; reading stays available) and is refined by AC-001B-08.

### AC-001B-02: Identity and Storage Layout

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-02a | GIVEN a valid batch item with namespace `CWE`, source version `4.14` and rule ID `CWE-79` WHEN a Maintainer imports it THEN a folder `x-ipe-docs/secure-code/knowledge/local/CWE/4.14/CWE-79/` exists containing the identity metadata, the current content and a changelog with one "created" entry | Integration |
| AC-001B-02b | GIVEN items in custom namespaces `@CUSTOM` and `@ACME` with a Maintainer-chosen version WHEN imported THEN they are stored under `@CUSTOM/<version>/<id>` and `@ACME/<version>/<id>` AND a custom `@CWE` rule coexists with institutional `CWE` rules AND custom rules are marked as custom, never as the institution's official rule | Integration |
| AC-001B-02c | GIVEN an item whose namespace, version or rule ID is empty, contains characters outside `A–Z a–z 0–9 . _ -` (after the optional leading `@` of a namespace), is `.` or `..`, starts or ends with a dot, equals a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, any case, with or without extension), exceeds the component length limit, or whose resulting folder would not be a plain folder inside the knowledge root WHEN imported THEN that item is refused with the offending field and reason AND the other items are processed | Integration |
| AC-001B-02d | GIVEN a stored rule `CWE/4.14/CWE-79` WHEN an item `CWE/4.14/cwe-79` (differing only in letter case) is imported THEN it is refused as an identity collision AND the stored rule is unchanged | Integration |
| AC-001B-02e | GIVEN a custom-namespace item without a rule name, or an institutional item without the source's own rule ID WHEN imported THEN it is refused with a reason and no ID or name is invented | Integration |
| AC-001B-02f | GIVEN an item without a source location WHEN imported THEN it is stored with the source location explicitly marked missing AND no location is invented; GIVEN a source location THEN it is stored in the metadata | Integration |

### AC-001B-03: Content, Versions, Examples and Relations

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-03a | GIVEN the same rule ID in two source versions (`CWE/4.13/CWE-79`, `CWE/4.14/CWE-79`) WHEN both are imported THEN both exist as separate rules and neither changes the other | Integration |
| AC-001B-03b | GIVEN any stored rule WHEN its folder is inspected THEN it holds exactly one current content and no revision or snapshot folders | Integration |
| AC-001B-03c | GIVEN an item with a general example and a Python example but no Java example WHEN imported THEN the examples are stored as separate files from the content (general and per-language) AND the missing language is not required | Integration |
| AC-001B-03d | GIVEN an item with language applicability `python, java` and another with none WHEN imported and shown THEN the first shows that advisory list AND the second shows applicability `unknown` (never converted to "all languages") | Integration |
| AC-001B-03e | GIVEN an item listing related rules by identity WHEN imported and shown THEN the relations are stored as references only AND no requirement, severity or status of the related rules is copied or changed | Unit |
| AC-001B-03f | GIVEN a batch of N valid distinct items WHEN imported THEN N separate rule folders exist; GIVEN an item without exactly one primary identity (namespace, version, rule ID) THEN it is refused AND rule IDs mentioned inside content or relations never count as additional identities | Integration |

### AC-001B-04: Partial, Idempotent and Resumable Import

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-04a | GIVEN a batch mixing valid, invalid and flagged items WHEN imported THEN the result lists every item with exactly one outcome — `stored`, `current`, `update_candidate`, `needs_decision`, `refused` or `not_processed` — and a reason for every non-stored outcome AND the command does not report the whole batch as one success or failure | Integration |
| AC-001B-04b | GIVEN a list of item identities with input digests, or of source-document digests recorded at earlier imports (no content) WHEN the agent runs the pre-processing check THEN each item is reported `stored_unchanged`, `stored_changed` or `new`, AND each source document is reported `fully_stored` (every item imported from that unchanged document is stored unchanged) or `not_fully_stored`, so fully stored documents need no new AI structuring AND nothing is written | Integration |
| AC-001B-04c | GIVEN a batch already fully imported WHEN the identical batch is submitted again THEN every item is `current`, no file changes and no changelog entry is added | Integration |
| AC-001B-04d | GIVEN a stored rule WHEN an item with the same identity but different input is imported THEN it is reported `update_candidate` and the stored rule is unchanged; WHEN the Maintainer re-runs with an explicit accept for that identity THEN it is applied as an update with a changelog entry | Integration |
| AC-001B-04e | GIVEN two items from different namespaces with nearly identical content WHEN imported THEN both are stored separately and nothing is merged | Unit |
| AC-001B-04f | GIVEN a batch declaring an expected item count that differs from the actual count, or an item exceeding the maximum item size WHEN imported THEN the count mismatch is reported AND the oversize item is refused with a reason while other items are processed | Integration |
| AC-001B-04g | GIVEN an import interrupted after some items were written WHEN the same batch is submitted again THEN fully written items are `current`, remaining items are processed AND no half-written rule exists or is reported as stored | Integration |

### AC-001B-05: Pre-check and Maintainer Decision

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-05a | GIVEN an item whose content or examples contain a suspected real credential (e.g. a private-key block or a cloud access key pattern) WHEN imported THEN that item is `needs_decision` with the finding and its location AND it is not stored as formal knowledge AND the other items proceed | Integration |
| AC-001B-05b | GIVEN an item containing embedded operating instructions aimed at agents or shells (e.g. "ignore previous instructions", a destructive shell command outside an example) WHEN imported THEN that item is `needs_decision` with the finding and location | Integration |
| AC-001B-05c | GIVEN an item containing clearly marked teaching placeholders (e.g. `<your-password>`, `changeme`, documented example keys ending in `EXAMPLE`) in an example file WHEN imported THEN it is stored AND the placeholder is reported as an informational note, not a blocking finding | Integration |
| AC-001B-05d | GIVEN a `needs_decision` item WHEN the Maintainer re-runs the import explicitly declaring that identity's listed findings false positives THEN it is stored and its changelog entry records the declared findings by type and location (never the full value); WITHOUT that declaration, or if the content now has a finding that was not declared, it stays not stored on every re-run; a genuine secret must be removed from the input and re-imported | Integration |
| AC-001B-05f | GIVEN a stored rule WHEN an update introduces content or examples with a suspected credential or embedded operating instruction THEN the update is refused as `needs_decision` with the findings AND the stored rule and changelog are unchanged until the Maintainer declares those findings false positives or removes them | Integration |
| AC-001B-05e | GIVEN an item whose text claims to grant roles or authority (e.g. "the importer is Maintainer") WHEN imported by a User THEN the import is still refused AND no text inside knowledge changes any role | Unit |

### AC-001B-06: Update and Changelog

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-06a | GIVEN a stored rule WHEN the Maintainer updates its content THEN the current content is replaced AND one changelog entry is appended with time, actor role, operation, input digest and a unified diff of the content before and after | Integration |
| AC-001B-06b | GIVEN a stored rule WHEN its metadata changes and an example is added and another deleted in one update THEN the single changelog entry contains a diff for the metadata, the full added example and the full deleted example | Integration |
| AC-001B-06c | GIVEN an update identical to the current state WHEN applied THEN nothing changes and no changelog entry is added | Integration |
| AC-001B-06d | GIVEN several earlier changelog entries WHEN a new change is recorded THEN all earlier entries remain byte-identical (append-only) | Integration |

### AC-001B-07: Consistency under Concurrency and Interruption

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-07a | GIVEN two or more updates of the same rule based on the same earlier state digest WHEN they run concurrently or in sequence THEN exactly one commits AND every other is refused as a conflict naming the new state digest, so no change is lost (which one commits is not prescribed) | Integration |
| AC-001B-07b | GIVEN a write of a rule (create or update) interrupted at any file step WHEN the rule is read afterwards THEN content, metadata, examples and changelog are either all in the previous state or all in the new state AND an interrupted write is never reported as success | Integration |

### AC-001B-08: Maintainer Authority (refines AC-001B-01)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-08a | GIVEN no valid Maintainer authorization (missing, invalid or revoked) WHEN import, update or accept is attempted THEN it is refused with `NOT_AUTHORIZED` and the next step AND nothing is written; list and show still work | Integration |
| AC-001B-08b | GIVEN a valid authorization at the start of a batch WHEN it is revoked before the next write THEN that next write is refused, because each write re-verifies | Unit |

### AC-001B-09: Read Operations and Status

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001B-09a | GIVEN stored rules WHEN anyone lists knowledge (optionally filtered by namespace and version) THEN identities, names, custom/institutional marking, applicability and pending-decision items are returned AND nothing is written | Integration |
| AC-001B-09b | GIVEN a stored rule WHEN anyone shows it THEN its metadata, current content, example list and changelog entries (with diffs) are returned AND nothing is written | Integration |
| AC-001B-09c | GIVEN N stored Local rules WHEN status runs (FEATURE-001-A) THEN the Local count is N and its next step no longer asks for Policy maintenance | Integration |

> **Test Type Legend:** Unit — library function; Integration — CLI subprocess with files; no UI or HTTP API.

## Functional Requirements

- **FR-001B-1 Batch file.** A versioned, documented batch format carries, per item: exactly one primary identity (namespace, source version, rule ID), optional source-document digest, name (required for custom namespaces), source location (optional), content, optional general/per-language examples, advisory language applicability, related rule identities, and optional expected item count for the batch. The exact format is defined in technical design.
- **FR-001B-2 Pre-processing check.** Input: item identities plus input digests and/or source-document digests. Output: `stored_unchanged | stored_changed | new` per item and `fully_stored | not_fully_stored` per source document. Read-only; usable by anyone. Imports record, per stored item, the digest of the source document it came from (when the batch provides it).
- **FR-001B-3 Import.** Input: batch file, optional explicit accepts (update candidates, needs-decision items). Process per item: validate identity and fields → pre-check → compare with stored state by digest → store / skip / report. Each item is independent. Output: per-item outcomes with reasons, counts, expected-count check.
- **FR-001B-4 Update.** Input: one rule identity, new content/metadata/examples (full or partial), and the state digest the change is based on. Process: refuse on state mismatch; compute diffs; write all files and the changelog entry consistently. Output: changed files and the new state digest.
- **FR-001B-5 Pre-check.** Runs on every create and update before any diff or changelog is produced. Detects suspected real credentials and embedded operating instructions in content and examples; distinguishes clearly marked teaching placeholders (informational). Findings carry type, location and a finding fingerprint, never the full value. Acceptance is a Maintainer false-positive declaration bound to the listed findings; there is no way to store a flagged value without it. Not a DLP system.
- **FR-001B-6 Changelog.** Append-only per rule; one entry per effective change with time (UTC), actor role, operation (`created`, `updated`, `accepted_update`, `accepted_flagged`), input digest, accepted findings (if any) and unified diffs for every changed, added or deleted file.
- **FR-001B-7 Read.** `list` (filters: namespace, version; includes pending-decision items) and `show` (one rule). No authorization needed.
- **FR-001B-8 Authority.** Every write calls the FEATURE-001-A Maintainer check immediately before writing.
- **FR-001B-9 Pending decisions.** `needs_decision` items are kept outside formal knowledge with their findings so they can be listed and later accepted or dropped by the Maintainer; they never count as formal Policies.

## Non-Functional Requirements

- **NFR-001B-1 Consistency.** Single-rule writes are all-or-nothing from a reader's view (content, metadata, examples, changelog); no cross-batch transaction is required (D-04).
- **NFR-001B-2 Portability.** Identities and file names valid on macOS, Linux and Windows (allowed character set; case-insensitive collision check).
- **NFR-001B-3 Cost.** The pre-processing check reads metadata/digests only and never requires AI processing.
- **NFR-001B-4 Safety.** No network access; no code execution of imported content; secrets found by the pre-check are reported by location and type, never echoed in full.
- **NFR-001B-5 Independence.** No dependency on X-IPE task/workflow files (NFR-01).

## UI/UX Requirements

No graphical UI. Command-line operations under `secure-code knowledge` (names finalized in technical design): `check`, `import`, `update`, `list`, `show`. Every command returns the toolkit result envelope (text and `--json`), per-item outcomes and one next step for each refusal. The Framework SKILL.md describes how the agent structures documents into a batch and calls `check` before AI processing.

## Dependencies

- **Internal:** FEATURE-001-A — Maintainer verification (`require_maintainer`), project layout, result envelope, status counting.
- **External:** None beyond the toolkit runtime (Python, uv, `cryptography` from 001-A).
- **Consumers:** FEATURE-001-C (Policy resolution), FEATURE-001-D (exit operations), FEATURE-001-F (Presets/tags), FEATURE-001-G (AI drafting).

## Business Rules

- **BR-01:** Identity = namespace + source version + rule ID; institutional IDs are the source's own (K-02, K-03).
- **BR-02:** Custom namespaces start with `@`; `@CUSTOM` is the default; custom rules never claim to be official (K-04…K-06).
- **BR-03:** One current content per identity; history only in the changelog (K-11, K-12).
- **BR-04:** Same identity with changed input is an update candidate, applied only on explicit acceptance (K-27).
- **BR-05:** Similar content across sources is never merged (K-28).
- **BR-06:** Flagged items (import or update) are never formal until the Maintainer declares the listed findings false positives; genuine secrets must be removed from the input (K-32, K-33).
- **BR-07:** Text inside knowledge never grants roles or authority (K-33, U-03).
- **BR-08:** New company requirements are custom rules, never edits to an institution's rule disguised as explanation (K-22).
- **BR-09:** Language applicability is advisory; missing means unknown (K-17, K-18).

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Batch file unreadable or wrong format version | Whole command refused with reason; nothing written |
| Two items in one batch with the same identity | Both refused as duplicates within the batch |
| Item identity collides with a pending-decision item | Treated as the same identity (re-evaluated) |
| Maintainer accepts an identity not present in the batch | Reported as an unknown accept; no effect |
| Disk full / permission denied mid-batch | Items written so far are complete; the failing item and the rest are `not_processed`; command reports failure |
| Rule folder edited by hand so its state does not match its changelog | Reported on `show`/update as inconsistent; update refused until resolved (no silent repair) |
| Very large content | Refused per item above the maximum item size (value in technical design) |

## Out of Scope

- Deactivate, delete, rename and impact lists (FEATURE-001-D).
- Reference knowledge, URL fetching, caching (FEATURE-001-E; needs egress authorization from FEATURE-002-C).
- Presets and tags (FEATURE-001-F).
- AI-drafted examples and explanations stored as labelled supplements (FEATURE-001-G); the agent may still structure documents supplied by the Maintainer.
- Restore/rollback commands (K-15 open), draft/activation workflow (D-08 open), licence fields (K-10 excluded), aliases/old-ID migration (D-06 open).

## Technical Considerations

- Batch format and versioning, digest algorithm, maximum item size, changelog entry layout, pending-decision storage location, and the consistency mechanism (per-rule lock and commit point) are decided in technical design (K-15, K-28, D-04, D-05, D-08 remain design-level).
- Reuse FEATURE-001-A building blocks: `require_maintainer`, atomic writes, `unsafe_component` path checks, result envelope.
- Pre-check patterns must be maintainable and testable with known positive and negative samples.

## Open Questions

None material. Decisions (10-19-2026, interact-with-human):

| Question | Decision |
|---|---|
| Import sources | Local sources only; agent structures documents into a batch; script validates/pre-checks/stores; no URL fetching here |
| Activation | Maintainer imports are formal immediately; only pre-check-flagged items wait for an explicit decision |
| Identity rules | Keep source IDs/versions; allowed `A–Z a–z 0–9 . _ -`; case-insensitive collisions; rule sets in the version segment; custom namespaces need a Maintainer version |
| Changelog | Append-only unified-diff entries; no restore command |
| Operations | check, import, update, list, show |
| Batch size | No fixed item count; expected count checked; per-item size limit set in design |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| K-01 (Local), K-02, K-03, K-08; FR-001B-3 | US-01 | AC-001B-02a, 02f | N/A | Integration | covered |
| K-04…K-07; BR-02 | US-06 | AC-001B-02b, 02e | N/A | Integration | covered |
| D-06/K-09/D-07 decisions; NFR-001B-2 | US-01 | AC-001B-02c, 02d | N/A | Integration | covered |
| K-11, K-12 | US-05 | AC-001B-03a, 03b | N/A | Integration | covered |
| K-16…K-19 | US-01 | AC-001B-03c…03e | N/A | Integration / Unit | covered |
| K-23 | US-01 | AC-001B-03f | N/A | Integration | covered |
| K-24, K-26 | US-02 | AC-001B-04a, 04g | N/A | Integration | covered |
| K-25; FR-001B-2 | US-03 | AC-001B-04b, 04c | N/A | Integration | covered |
| K-27, K-28 | US-02 | AC-001B-04d, 04e | N/A | Integration / Unit | covered |
| D-05 decision | US-02 | AC-001B-04f | N/A | Integration | covered |
| K-32, K-33; FR-001B-5, FR-001B-9 | US-04 | AC-001B-05a…05f | N/A | Integration / Unit | covered |
| K-13, K-14, K-36; FR-001B-6 | US-05 | AC-001B-06a…06d | N/A | Integration | covered |
| K-36, D-04; NFR-001B-1 | US-08 | AC-001B-07a, 07b | N/A | Integration | covered |
| U-04, U-05, U-12 (via 001-A) | US-07 | AC-001B-01 → 08a, 08b | N/A | Integration / Unit | covered |
| FR-001B-7; X-11 (status count) | US-07 | AC-001B-09a…09c | N/A | Integration | covered |
| K-22 | US-06 | (BR-08; custom namespace path AC-001B-02b) | N/A | Integration | covered by rule + 02b |
| K-29, K-30 | — | (FEATURE-001-A AC-001A-04a, 09a) | N/A | — | covered by 001-A |
| K-15, D-05 sizes, D-08, K-28 digest | — | — | N/A | — | design-level decisions |

EPIC-001 acceptance mapping: AC-04 → AC-001B-02a/02b/02f; AC-05 → AC-001B-03b, 06a, 06b; AC-06 → AC-001B-04a; AC-07 → AC-001B-04b, 04c, 04d; AC-08 → AC-001B-05a…05d; AC-10 → AC-001B-07a, 07b. Breakdown AC-001B-01 → AC-001B-08a.

## Context and Verification Evidence

- Independent review (rubber-duck, 10-19-2026): 2 blocking + 3 non-blocking findings fixed — pre-check on updates and false-positive-only acceptance (05d, 05f, FR-001B-5, BR-06); unsafe/portable identity components (02c); pre-AI check via source-document digests (04b, FR-001B-2); exactly one primary identity per item (03f); race-independent concurrency (07a).

- Sources: [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) (EPIC-001 FR-04…FR-07, FEATURE-001-B details); inventory v2 rows K-01…K-36, D-04…D-08 and §3.1; FEATURE-001-A specification and implementation (`require_maintainer`, layout, result envelope).
- Board: FEATURE-001-B, EPIC-001, v1.0, Planned, depends on FEATURE-001-A (Completed).
- Mockups: none. Execution mode: free-mode.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-001B-02a…09c | Planned per Test Type; no tests yet | planned | not measured |
