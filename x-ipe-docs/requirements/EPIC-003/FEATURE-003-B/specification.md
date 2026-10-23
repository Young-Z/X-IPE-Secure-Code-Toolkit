# Feature Specification: Single-source Host Integration Carriers

> Feature ID: FEATURE-003-B  
> Epic: EPIC-003 (Copilot Collaboration & Host Integration)  
> Version: v1.0  
> Status: Refined draft — open questions Q1…Q9 decided by the delegated 工程師 representative (DAO-001, 10-23-2026) under the human's delegation; 5 blocking independent-review findings fixed (10-23-2026); DAO-003/DAO-004 corrections applied; **open human blocker B11 (Windows `carriers` support)**; no human confirmation of this specification yet  
> Last Updated: 10-23-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-23-2026 | Initial specification (draft; open questions Q1…Q8 pending decision) | N/A (scope carries CR-001 note: reuse/extend the FEATURE-001-A fragment writer) |
| v1.0 | 10-23-2026 | Applied DAO-001 decisions Q1…Q9 (delegated representative, not the human). Carrier locations fixed; the instructions file uses toolkit markers. Deselected carriers are reported as "no longer managed" and never deleted. Difference handling mirrors FEATURE-001-A and shows the replaced content. The install record extension is strictly additive, with a FEATURE-001-A regression requirement. Persona files (D-25) are out of scope. Routing wording is directive with exclusions. AC-33 is in scope and closing waits for the human smoke record (HO-003B-01, B7). Symbolic links stay refused. Wording of 01a, 03b, 03c, 03d, 03e, 05a, 05c and 06a was made concrete; new ACs 01f, 03g, 03h, 08a, 08b and 08c were appended; no AC ID changed or was removed. | N/A (decision log: `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md` DAO-001) |
| v1.0 | 10-23-2026 | Fixed 5 blocking independent-review findings. (1) Carrier generation is a dedicated carriers operation; plain `init` keeps exactly FEATURE-001-A behaviour and ignores stored optional selections. The record gets one optional, defaulted per-carrier member under the same `install-record/v1` schema, omitted when unused; the top-level fields stay authoritative for the host entry. One environment per record, with no cross-environment carrier reporting. Older toolkit versions are not forward-compatible with extended records. (2) The instructions file has two managed boundaries: the exact front matter at file start and the marker-delimited body. (3) HO-003B-01 gains case 4: host de-duplication with both carriers active. (4) Fragment content and differences are secret-masked, with redaction markers and canary ACs. (5) Write auditing and protected-tree snapshots for the whole automated suite. Reworded 01e, 01f, 03a, 03b, 03g, 04a, 05c, 06d, 08b and 08c; appended 05f, 05g, 07c, 07d, 07e, 08d and 08e; no AC ID changed or was removed. | N/A (independent spec review, 10-23-2026) |
| v1.0 | 10-23-2026 | Re-review blocker fixed. The carriers operation may modify only the selected carrier files and the install record, never the skills folder. Missing or invalid installed skills or routing definition lead to a refusal with an `init` next step (no implicit reinstall). Changed AC-003B-03d, FR-003B-4 and BR-17; no AC ID added, changed or removed. | N/A (independent spec re-review, 10-23-2026) |
| v1.0 | 10-23-2026 | Defect corrections decided by the delegated 工程師 representative under the human's delegation (DAO-003, TASK-061 Technical Design; not a human decision). (1) AC-003B-01d now describes the real two-step upgrade of a pre-003B install: `carriers` is refused per 03d with an `init` next step; `init` installs the routing definition and upgrades the host entry in place under FEATURE-001-A rules; `carriers` then succeeds. (2) Plain `init` gets a single bounded exception: it honours an exactly matching accepted host-entry customization, only when the per-carrier member exists and is valid. It fails closed, never overwrites the customization and never claims it current; a routing change since acceptance is reported with a `carriers` next step. Reworded 01d and 08c and the related Overview, FR-003B-4, BR-17 and edge-case text; appended 01g, 01h, 01i and 01j; no AC removed. | N/A (decision log: `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` DAO-003) |
| v1.0 | 10-23-2026 | DAO-004, decided by the delegated 工程師 representative under the human's delegation (TASK-061 Technical Design; not a human decision). Q2: plain `init` never overwrites an accepted customization unless the Maintainer explicitly supplies `--replace AGENTS.md`, which is delivered FEATURE-001-A behaviour. The result then reports `replaced`, says an accepted customization was replaced, shows the masked previous content or difference, and the acceptance lapses. Q3: a run that cannot take the toolkit lock waits a bounded time using an existing toolkit lock timeout, then refuses with `LOCKED`, writes nothing and gives a retry next step; it never proceeds unlocked where the lock is available. Q4: on Windows `carriers` refuses with `LOCK_UNAVAILABLE` as **interim** behaviour (never unlocked, no lock file). This is recorded as an open gap and pending-human blocker B11 against the human-confirmed Windows requirement; it is **not** a scope reduction. Hard condition: plain `init` on Windows keeps exactly the delivered FEATURE-001-A behaviour. Reworded 01g, 01i and 04g plus the related Overview, FR, NFR, BR, edge-case and Out-of-Scope text; appended 01k, 04h and 04i. Automated AC count is now 56 (45 Integration, 11 Unit); it was 53 (43 Integration, 10 Unit) before this row. No AC removed. | N/A (decision log: `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` DAO-004) |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: carriers are text files generated by the toolkit command line, plus a structured result and status sections. Bounded discovery (10-23-2026): `x-ipe-docs/requirements/EPIC-003/` has no `mockups/` folder, FEATURE-003-B's folder was empty, and the idea folder `x-ipe-docs/ideas/Draft Idea - 10142026 153612/` contains no mockups. | — | — |

## Overview

FEATURE-003-B makes the toolkit's host integration **single-source**. The Framework keeps **one routing definition**: which skill handles which kind of request, what context to pass and what result to consume. From it the toolkit generates up to three **carriers**:

1. the **host entry carrier** — the toolkit fragment in the environment's host entry file (`AGENTS.md` for `github-copilot`, `CLAUDE.md` for `claude-code`). It is the only default carrier;
2. optional **GitHub instructions**, generated only on explicit selection for `github-copilot`. They live in the toolkit-owned file `.github/instructions/x-ipe-secure-code-toolkit.instructions.md`, which has `applyTo` front matter and a toolkit-marked body;
3. an optional **system-prompt fragment**, generated only on explicit selection for an explicitly named host. It is written as a toolkit-owned file under `.x-ipe/private/secure-code/carriers/` and shown in the result. The user adds it to the host manually.

All three are one integration declaration. Each states the same routing:

- **Copilot** is used proactively for design, implementation, bug fix and refactor tasks;
- **Guard** is used only on an explicit or authorized verification request;
- read-only Reviewers never start the security flow again;
- the same stage and context is not triggered twice;
- failed or old reports never count as done;
- the minimal handoff of inventory §14.2 applies.

The skills stay self-contained. The carriers only route to them and copy no internal procedure or knowledge (I-02).

**Builds on FEATURE-001-A (CR-001).** FEATURE-001-A already writes one minimal toolkit fragment into the host entry file during `secure-code init --env`. It uses delimited markers, keeps content outside the fragment byte-identical, never writes twice, keeps a user-edited fragment and reports it (`FRAGMENT_EDITED`). It replaces that fragment only with `--replace`. Its install record (`.x-ipe/private/secure-code/install-record.json`, schema `install-record/v1`) holds one `host_entry` and one `fragment_sha256`. This feature **reuses and extends that writer and record**: it does not add a second writer. It adds:

- generation from one routing definition through a **dedicated carriers operation** (e.g. `secure-code carriers …`; final name in technical design);
- carrier selection;
- per-carrier difference handling with the Maintainer's choices (I-15, I-16);
- per-carrier status.

The record extension (I-17) is strictly additive (Q5): FEATURE-001-A's observable behaviour and tests stay unchanged.

- **Plain `init` is unchanged.** `secure-code init` without carrier options keeps exactly FEATURE-001-A behaviour and ignores stored optional selections. **Single exception:** plain `init` reads only the accepted-customization digest of the host entry, and only when the per-carrier member exists and is valid. It then reports `customized` only while the current fragment bytes exactly equal that digest. It never overwrites an accepted customization unless the Maintainer explicitly supplies `--replace AGENTS.md` (delivered FEATURE-001-A behaviour; AC-003B-01k), and never reports it as current or synchronized. If the routing definition changed since acceptance, it says so and names `carriers` as the next step (AC-003B-01g…01k). On FEATURE-001-A-only projects nothing changes. Both `init` and the carriers operation render the host entry fragment from the routing definition through the same writer.
- **Record shape.** The install record gains one optional, defaulted per-carrier member under the same `install-record/v1` schema. It is omitted on records that never had an optional carrier or an accepted customization. The top-level `host_entry`/`fragment_sha256` stay authoritative for the host entry carrier. A record covers one environment.
- **No forward compatibility.** Toolkit versions before this feature cannot read an extended record and refuse it. Requiring forward compatibility would be a CR.

**Honest limits.** In MVP the toolkit checks only files, managed boundaries and required host metadata (I-18). Whether a host actually loads a carrier and routes correctly is not verified automatically; that acceptance is deferred (I-19, S-05). Status therefore always reports host effect as "not verified". The MVP still needs evidence that the toolkit is actually invocable on GitHub Copilot (CLI and VS Code). That evidence is a **recorded human observation** (HO-003B-01 for EPIC AC-33, which is in scope). Automation, DAO guidance or fixtures cannot satisfy it, and agents must not perform it. The feature is parked at acceptance until the human records it, and closes only afterwards (Q8). GitHub Copilot is the only verified host in MVP; `claude-code` stays an unverified profile.

**Who:** Maintainers (choose carriers, decide differences), Developers and upstream agents (get routed to the right skill), and the human observer who records the GitHub Copilot smoke check.

## User Stories

- **US-01:** As a Maintainer, I want every carrier generated from one routing definition, so that Copilot and Guard are routed the same way whichever carrier a host loads, and integrations do not contradict each other.
- **US-02:** As a Developer or upstream agent, I want the carriers to send design, implementation, bug-fix and refactor work to Copilot and only explicit or authorized verification requests to Guard, so that security help arrives during the work without unrequested scans.
- **US-03:** As a Developer or upstream agent, I want the carriers to prevent duplicate and recursive security flows, so that a host loading several carriers, or a read-only Reviewer, does not start the flow again.
- **US-04:** As a Maintainer, I want to choose which carriers are generated (`AGENTS.md` by default; GitHub instructions and the system-prompt fragment only on request), so that no global prompt, other host's file or `.gitignore` is changed without my choice.
- **US-05:** As a Maintainer, I want regeneration to touch only toolkit fragments, never duplicate them and preserve all my other edits, so that the toolkit and my own instructions coexist.
- **US-06:** As a Maintainer, I want each difference between a toolkit fragment and the toolkit rendering reported to me with my choices, so that I decide whether to keep, modify, change the routing definition, regenerate or accept my customization, and nothing is silently overwritten or hidden.
- **US-07:** As a User or upstream agent, I want status to report each carrier's file, boundary and metadata state and say plainly that host effect is not verified, so that a written file is never mistaken for working routing.
- **US-08:** As the human owner, I want a recorded manual smoke check on GitHub Copilot CLI and VS Code showing Copilot and Guard really being invoked, so that the MVP's invocability claim rests on an actual observation.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-06 | EPIC-001 G-06 (idea summary v2 Problem 7); FR-27, FR-28 | Maintainer, Developer | Host integrations route to the right skill without conflicting with each other or overwriting user content | All-required children G-06a…G-06d below | Scenario (from requirement-details): regenerate carriers after user edits; only toolkit-fragment differences are reported; manual smoke on GitHub Copilot shows Copilot/Guard invoked | Automatic host-loading acceptance deferred (I-19); GitHub Copilot only verified host | AC-31, AC-32, AC-33, AC-003B-01 (via children) | not measured |
| G-06a | G-06; FR-27 (I-01, I-02, I-03, I-07); EPIC AC-31; CR-001 note | Maintainer | One routing definition yields consistent carriers; one writer, no competing fragments | Single routing definition rendered into selected carriers through the FEATURE-001-A writer (all-required) | Scenario: in a sandbox target project, all selected carriers carry the same routing-definition identity; a definition change updates every unedited carrier in one run; `init` and generation never create a second fragment or disagree on the host entry state | Carriers do not copy skill procedures or knowledge (I-02) | AC-003B-01a…01k | not measured |
| G-06b | G-06; FR-27 (I-05…I-11, §14.2); breakdown AC-003B-01 | Developer, upstream agent | Copilot is used for design/implementation/fix/refactor, Guard only on explicit/authorized verification; no duplicate or recursive flows; failed/old reports never count | Routing statements in every carrier, consistent with the skill packages' "When to Use" (all-required) | Content scenario: each carrier's statements match the definition and the three SKILL.md files. Real triggering is observed only by HO-003B-01 | Automated checks prove carrier content, not host behaviour (I-18, I-19) | AC-003B-02a…02g; HO-003B-01 | not measured |
| G-06c | G-06; FR-27 (I-03, I-04), FR-28 (I-12…I-16); EPIC AC-32 | Maintainer | Only chosen carriers are written; user content survives; the Maintainer decides every fragment difference | Carrier selection + fragment-level idempotency + Maintainer difference handling, all required; additive install-record extension with FEATURE-001-A regression (Q2, Q3, Q5 decided) | Scenario: user edits outside fragments survive byte-identical; an edited fragment is kept and reported each run until the Maintainer chooses; unchanged inputs write nothing; FEATURE-001-A tests pass unchanged | Never lock whole files; never take over user text because it mentions the toolkit (I-12, I-13); never delete deselected carriers (I-21) | AC-003B-03a…03h, AC-003B-04a…04i, AC-003B-05a…05g, AC-003B-08a…08e | not measured |
| G-06d | G-06; FR-28 (I-18), FR-03 (O-10, X-11, X-12), I-19; EPIC AC-33; DAO blocker B7 | User, owner | Status is honest about host effect; MVP invocability on GitHub Copilot rests on an actual human observation | Per-carrier status with "host effect: not verified" + recorded manual smoke observation (all-required) | Status scenario (automated) + HO-003B-01 record by a human on Copilot CLI and VS Code | No automatic loading/routing acceptance (I-19, S-05) | AC-003B-06a…06d; HO-003B-01 | not measured (HO-003B-01 pending human; closing waits for it, Q8) |
| G-06e (enabling) | DAO plan for TASK-060; S-01…S-04, AC-35 | Maintainer | Developing and testing carriers never activates or alters routing in the toolkit's own development repository | All generation in tests and smoke happens in sandbox target projects | Scenario: with write auditing, every product write of the whole automated suite resolves beneath a test-created sandbox root; protected toolkit-source and ancestor trees are byte-identical and gain no carrier, instructions or `.x-ipe/private/secure-code/` paths | Workspace sandbox ≠ OS isolation (S-06) | AC-003B-07a…07e | not measured |

## Acceptance Criteria

**Mapping of source acceptance.**

| Source acceptance | Refined into |
| --- | --- |
| EPIC AC-31 | AC-003B-01a…01f, 02c (component/content); host de-duplication: HO-003B-01 case 4 |
| EPIC AC-32 | AC-003B-04a…04c, 05a…05e |
| EPIC AC-33 | HO-003B-01 (recorded human observation; in scope; pending human), backed by the automated AC-003B-06c |
| Breakdown AC-003B-01 (I-05, I-06) | Carrier content: AC-003B-02a, 02b, 02f. Actual triggering on a host: HO-003B-01 |

The open questions were decided by the delegated representative (DAO-001; see Open Questions). The new ACs added for those decisions are listed in the version history.

**Common precondition.** Every automated AC runs in a **sandbox target project**: a project root created by the test, outside the protected trees of AC-003B-07c…07e. A FEATURE-003-C sandbox (`.x-ipe/private/secure-code/sandboxes/<id>/`) is for manual use such as HO-003B-01. The project is initialized by FEATURE-001-A with an explicit `--env`. "Carriers are generated" means the dedicated carriers operation runs. No AC writes a carrier into the toolkit development repository (AC-003B-07a, 07c).

### AC-003B-01: Single-source Generation through the FEATURE-001-A Writer

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-01a | GIVEN a sandbox target project for `github-copilot` AND the host entry carrier, GitHub instructions and system-prompt fragment all selected WHEN carriers are generated THEN each selected carrier exists at its decided location: the `AGENTS.md` fragment, `.github/instructions/x-ipe-secure-code-toolkit.instructions.md` and the system-prompt fragment file under `.x-ipe/private/secure-code/carriers/` AND each carrier's toolkit-owned content equals the rendering of the single routing definition for that carrier kind AND every carrier states the same routing-definition identity (toolkit version and definition digest) | Integration |
| AC-003B-01b | GIVEN unedited carriers generated from routing definition A WHEN the definition changes to B (new toolkit version, or a Maintainer edit of the installed definition file) and carriers are regenerated THEN every selected, unedited carrier is updated in the same run to identity B AND the result lists each updated carrier AND no selected carrier still states identity A without being reported as a difference | Integration |
| AC-003B-01c | GIVEN the routing definition WHEN it is rendered into any carrier kind THEN the content holds only the routing statements of AC-003B-02, pointers to the three installed skills and the status command AND holds no Policy or knowledge text, no copied skill procedure, no absolute machine path, no credential and no authorization material | Unit |
| AC-003B-01d | GIVEN a project initialized by a FEATURE-001-A toolkit version before this feature (record without a per-carrier member, no installed routing definition, unedited fragment in `AGENTS.md`) WHEN the carriers operation runs first THEN it is refused per AC-003B-03d, naming the missing routing definition, with the next step `secure-code init`, AND nothing is written; WHEN plain `secure-code init` of this toolkit version then runs THEN it installs the skills including the routing definition under FEATURE-001-A safe-reinstall rules AND updates the unedited fragment in place between the same markers, reported as updated (not as edited) AND exactly one toolkit fragment exists in `AGENTS.md` AND the record keeps the earlier `initialized_at`; WHEN the carriers operation then runs again THEN it succeeds and reports the host entry carrier as current. The test reproduces the whole sequence, including the first refusal | Integration |
| AC-003B-01e | GIVEN a sandbox target project WHEN plain `secure-code init` and the carriers operation run in any order and any number of times THEN each carrier file contains at most one toolkit fragment AND both commands report the same fragment state for the host entry file AND neither reports the other's fragment as foreign or edited | Integration |
| AC-003B-01f | GIVEN a sandbox target project with both the `AGENTS.md` carrier and the GitHub instructions carrier generated WHEN the texts a host would load from both are combined and checked by the automated routing-consistency check THEN both carry the same routing-definition identity AND their routing statements are identical (no conflicting or additional trigger between them) AND each carrier states that toolkit carriers with the same routing identity are one integration declaration and start at most one Copilot or Guard flow for the same stage and effective context AND generation and status report the two carriers as one integration declaration with one identity (EPIC AC-31 de-duplication as a component/content check only; de-duplication by a real host is observed in HO-003B-01 case 4, and automatic host-loading acceptance stays deferred, I-19) | Integration |
| AC-003B-01g | GIVEN the Maintainer accepted an edited host-entry fragment through the carriers operation (valid per-carrier member, accepted digest equal to the current fragment bytes, routing definition unchanged) WHEN plain `init` and then the carriers operation run, and also in the reverse order (no `--replace AGENTS.md` given) THEN both report the host entry as `customized` (accepted, not synced with the routing definition) AND neither writes `AGENTS.md`, because `init` never overwrites an accepted customization unless the Maintainer explicitly supplies `--replace AGENTS.md` (AC-003B-01k) AND `init` reports neither `FRAGMENT_EDITED` nor current/updated AND the recorded acceptance data is unchanged | Integration |
| AC-003B-01h | GIVEN an accepted host-entry customization AND the user edits the fragment again afterwards (current bytes differ from the accepted digest) WHEN plain `init` runs THEN it reports `FRAGMENT_EDITED` as in FEATURE-001-A AND the fragment is kept byte-identical AND `customized` is not reported; WHEN the carriers operation runs THEN it reports the fragment as a difference for the Maintainer's decision (AC-003B-05d) | Integration |
| AC-003B-01i | GIVEN an accepted host-entry customization AND a per-carrier member that is unreadable or invalid (e.g. wrong type, missing or malformed accepted digest) WHEN plain `init` runs THEN the acceptance is not honoured: `init` reports the host entry fragment as edited (`FRAGMENT_EDITED`, kept, not replaced unless `--replace AGENTS.md` is given explicitly), or refuses where the existing invalid-record handling already refuses the record AND in no case reports `customized`, current or synchronized AND `AGENTS.md` is not overwritten AND no other fallback is introduced | Integration |
| AC-003B-01j | GIVEN a host-entry customization accepted against routing-definition identity A AND an installed routing definition now at identity B WHEN plain `init` runs THEN the fragment is kept byte-identical AND reported as `customized` (accepted, not synced) together with the statement that the routing definition changed since acceptance (A → B) AND the next step names the carriers operation for the Maintainer's decision AND it is never reported as current or synchronized (BR-09); WHEN the carriers operation then runs THEN it reports the carrier again as a difference for a decision (AC-003B-05d) | Integration |
| AC-003B-01k | GIVEN an accepted host-entry customization whose fragment contains canary secret values WHEN plain `init --replace AGENTS.md` runs THEN the fragment is replaced with the current rendering and all bytes outside it stay identical AND the result reports `replaced` and states that an accepted customization was replaced AND it shows the previous content or difference masked with the redaction markers of AC-003B-05f/05g (no canary value in text, JSON or logs) AND the acceptance no longer applies (the recorded acceptance is cleared or marked lapsed) AND a following carriers operation and a following plain `init` both report the host entry as current, the same state (AC-003B-01e), never `customized` | Integration |

### AC-003B-02: Routing Content (Copilot vs Guard, De-duplication, Handoff)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-02a | GIVEN any generated carrier WHEN its routing statements are read THEN they direct the agent to use the Copilot skill proactively for design, implementation, bug fix and refactor tasks (including changes to an existing design) AND not for plain questions or read-only knowledge lookups (I-05) | Unit |
| AC-003B-02b | GIVEN any generated carrier WHEN read THEN it directs the agent to use the Guard skill only on an explicit verification request or an authorized upstream verification step AND never automatically because an artifact was completed AND never to substitute Guard for Copilot (I-06, I-10) | Unit |
| AC-003B-02c | GIVEN any generated carrier WHEN read THEN it states the following (I-07, I-08). (1) All toolkit carriers are one integration declaration, so loading several of them does not start a flow more than once. (2) For the same stage and the same effective context the flow is not started again. (3) A relevant change of input or stage is evaluated again, not skipped permanently. (4) A read-only Reviewer never starts the Copilot or Guard flow. (5) Different Framework needs within one task are not merged. | Unit |
| AC-003B-02d | GIVEN any generated carrier WHEN read THEN it states the following (I-09, I-10). (1) A failed or old report never counts as done for the current work. (2) An unavailable skill or invalid output is reported as not completed and the upstream caller decides under its existing gates. (3) Policies are never made up from memory. (4) Continuing the work is not passing. (5) Mandatory gates are never bypassed silently. | Unit |
| AC-003B-02e | GIVEN any generated carrier WHEN read THEN it states the minimal handoff of inventory §14.2 for each skill: Framework gets scenario, rule clues and information need, and returns concrete Policies, sources and unresolved items. Copilot gets task, current artifact or change and constraints, and returns concrete suggestions, adoption review and items not adopted or not verifiable. Guard gets formed artifact, explicit targets, rule clues and execution authorization/budget, and returns the three-state verdict, findings, coverage gaps and execution state. It also states that only naming a skill is not a completed handoff and that results must be acted on by the upstream caller | Unit |
| AC-003B-02f | GIVEN the installed Copilot, Guard and Framework skill packages AND a generated carrier WHEN the carrier's trigger statements are compared with each skill's "When to Use" and description THEN every trigger in the carrier points to the skill whose own "When to Use" covers it AND no carrier statement contradicts a skill's stated non-use (e.g. Copilot "not for verifying finished artifacts", Guard "not for in-flow suggestions") | Unit |
| AC-003B-02g | GIVEN any generated carrier WHEN read THEN it states that roles come only from actual verification (Maintainer by the owner-signed authorization; agents by real requests or signed pre-authorization) AND that carrier text itself grants no role, permission or consent (I-11) | Unit |

### AC-003B-03: Carrier Selection and Write Boundaries

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-03a | GIVEN a sandbox target project for `github-copilot` AND no stored carrier selection in the install record AND no carrier selection given WHEN the carriers operation runs THEN only the host entry carrier (`AGENTS.md` fragment) is generated or checked AND no GitHub instructions file and no system-prompt fragment file is created (I-04; `AGENTS.md` is the only default) | Integration |
| AC-003B-03b | GIVEN the GitHub instructions carrier is selected explicitly for `github-copilot` WHEN carriers are generated THEN `.github/instructions/x-ipe-secure-code-toolkit.instructions.md` exists with two managed boundaries: (1) the exact toolkit-owned front matter (with `applyTo`) at file start and (2) the routing content between the toolkit markers AND the result names its path and state | Integration |
| AC-003B-03c | GIVEN the system-prompt fragment is selected explicitly for an explicitly named host WHEN carriers are generated THEN the fragment is written as a toolkit-owned file under `.x-ipe/private/secure-code/carriers/` AND it is also shown in the result AND the result says that adding it to the host is a manual step AND no host system prompt, global or user-level configuration, or file outside the project root is created or modified (I-03) | Integration |
| AC-003B-03d | GIVEN any run of the carriers operation WHEN files are compared before and after THEN only the selected carriers' files and the install record may differ. The skills folder (including the installed routing definition) is never created, modified or deleted by this operation. Everything else is byte-identical, in particular `.gitignore`, the host entry files of other environments (e.g. `CLAUDE.md` for `github-copilot`), a pre-existing `.github/copilot-instructions.md` and files outside the project root (I-04); GIVEN an installed toolkit skill or the installed routing definition is missing, unreadable or invalid (a Maintainer edit that is still valid is not invalid, Q4) WHEN the carriers operation runs THEN it is refused naming the problem, with the next step to run `secure-code init` AND nothing is written (no implicit reinstall) | Integration |
| AC-003B-03e | GIVEN a carrier selected in an earlier run AND not selected now WHEN carriers are generated THEN that carrier's file and fragment are not deleted or modified AND the result and status report it as "no longer managed" with the manual next step (automatic uninstall I-21 is out of scope); GIVEN a later run without any selection THEN the carriers recorded as selected are generated or checked again | Integration |
| AC-003B-03f | GIVEN an unknown carrier name, or a carrier not supported for the given environment (e.g. GitHub instructions for `claude-code`) WHEN carriers are generated THEN the run is refused, lists the carriers supported for that environment AND writes nothing | Integration |
| AC-003B-03g | GIVEN a generated toolkit-owned instructions file to which the user added content outside both managed boundaries (between the front matter and the markers, or after the markers) WHEN the carriers operation or status runs THEN those user bytes are byte-identical AND reported as user content detected outside the managed boundaries (informational, not a toolkit difference) AND reported separately from front-matter drift (AC-003B-06d) AND only the front matter and the marker-delimited body are managed by the toolkit | Integration |
| AC-003B-03h | GIVEN a generated system-prompt fragment file WHEN its content and its directory are inspected THEN it contains no credential, key, passphrase, authorization or signing material AND its directory contains no key, trusted-public-key, authorization or revocation file AND it is not the owner's trust location (the FEATURE-001-A trust files stay outside the project and unchanged) | Integration |

### AC-003B-04: Fragment-level Idempotency and Preservation of User Content

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-04a | GIVEN selected carrier files containing user content outside the toolkit fragment (including edits made after the last generation, LF or CRLF newlines and non-ASCII text) WHEN carriers are regenerated THEN all bytes outside each carrier's managed boundaries (the toolkit fragment; for the instructions file also its toolkit-owned front matter at file start, the only exemption) are byte-identical AND managed content uses the file's newline style (I-12, I-13; EPIC AC-32) | Integration |
| AC-003B-04b | GIVEN carriers generated from unchanged inputs (same routing definition, selection and environment) WHEN generation runs again THEN no file is written, the install record is byte-identical AND the result reports every carrier as current with no duplicate fragment (I-14) | Integration |
| AC-003B-04c | GIVEN user text outside the markers that mentions the toolkit, `secure-code` or the skill names, or that copies the fragment text without markers WHEN carriers are regenerated THEN that text is neither treated as the toolkit fragment, replaced nor reported as a toolkit difference (I-13) | Integration |
| AC-003B-04d | GIVEN any selected carrier with unmatched, reversed or duplicate toolkit markers, or not valid UTF-8 WHEN carriers are generated THEN the whole run is refused naming each affected carrier and problem AND no carrier, skill file or install record is written | Integration |
| AC-003B-04e | GIVEN any selected carrier path, or a folder on it, that is a symbolic link (even one pointing inside the project) WHEN carriers are generated THEN the run is refused with `PATH_UNSAFE` naming the path AND nothing is written (as FEATURE-001-A) | Integration |
| AC-003B-04f | GIVEN a write failure after some carriers were written WHEN the run ends THEN it reports failure, lists the carriers written before the failure, AND the install record is not updated; WHEN generation runs again after the cause is fixed THEN already written carriers are recognized as current AND no fragment is duplicated | Integration |
| AC-003B-04g | GIVEN two carriers or plain `init` runs started concurrently on the same project where the toolkit lock is available WHEN both end THEN no carrier contains more than one toolkit fragment AND the install record matches the carriers on disk AND each run either completed under the lock or, after waiting no longer than the bounded wait (an existing toolkit lock timeout), refused with `LOCKED`, writing nothing, with a retry next step AND no run proceeded without the lock (no silent loss) | Integration |
| AC-003B-04h | GIVEN another process holds the toolkit lock of the project for longer than the bounded wait WHEN plain `init` runs, and separately when the carriers operation runs THEN each waits at most the bounded wait (the existing toolkit lock timeout, not a new value) AND then refuses with `LOCKED` and a retry next step AND no carrier, skill file or install record is written AND neither proceeds without the lock | Integration |
| AC-003B-04i | GIVEN a platform on which the toolkit lock is unavailable (Windows, simulated in the test) WHEN the carriers operation runs THEN it refuses with `LOCK_UNAVAILABLE`, creates no lock file and writes nothing. This is interim behaviour and an open gap under B11, not a decided scope. WHEN plain `init` runs on that platform THEN it behaves exactly as delivered FEATURE-001-A: no `LOCKED` or `LOCK_UNAVAILABLE` refusal, no lock file, same outcomes | Unit |

### AC-003B-05: Maintainer Difference Handling

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-05a | GIVEN a toolkit fragment in any selected carrier that differs from both the recorded and the current toolkit rendering (user-edited) WHEN carriers are regenerated without a decision THEN the fragment is kept byte-identical AND the result reports the carrier path, that it differs, the difference between the current fragment and the toolkit rendering (secret-masked, AC-003B-05f), and the Maintainer's choices: keep (default), modify (the user edits the fragment, then keeps or accepts it), change the routing definition, regenerate, accept customization (I-15; mirrors FEATURE-001-A) | Integration |
| AC-003B-05b | GIVEN a kept (ignored) difference WHEN carriers are regenerated again or status runs THEN the difference is reported again each time AND never silently overwritten, merged or dropped from the report (I-16) | Integration |
| AC-003B-05c | GIVEN a reported difference AND the Maintainer explicitly chooses regenerate for that carrier WHEN carriers are generated THEN only that carrier's managed boundaries are replaced with the current rendering. For the instructions file both boundaries are restored: the front matter at file start (inserted at file start if missing) and the marker-delimited body. AND the result shows the replaced content or its difference to the new rendering, secret-masked (AC-003B-05g) AND all other user bytes stay identical AND other differing carriers stay kept and reported | Integration |
| AC-003B-05d | GIVEN a reported difference AND the Maintainer explicitly accepts it as a customization for that carrier WHEN the acceptance is recorded THEN the record holds the accepted fragment digest, the routing-definition identity at acceptance and the time AND later results and status show the carrier as "customized (accepted) — not synced with the routing definition", never as synced or current; WHEN the accepted fragment or the routing definition later changes THEN it is reported again as a difference for a decision | Integration |
| AC-003B-05e | GIVEN a fragment whose recorded digest is missing, unreadable or does not match (e.g. a record from another environment, or a lost record) WHEN carriers are regenerated THEN a fragment differing from the toolkit rendering is kept and reported for a decision AND is never overwritten because the digest is unknown or inconsistent (I-15: a digest mismatch does not remove the Maintainer's decision) | Integration |
| AC-003B-05f | GIVEN a kept (user-edited) fragment and a drifted instructions front matter containing canary secret values of each masked kind (e.g. a GitHub token, a cloud access key, a private-key block, a `password=` assignment) WHEN the carriers operation and status report the differences as text and as JSON THEN no canary value appears anywhere in the output AND each is replaced by an explicit redaction marker naming its kind (e.g. `[REDACTED:github-token]`) AND the shown content is labelled as masked | Integration |
| AC-003B-05g | GIVEN the same canaries in a fragment and front matter that the Maintainer explicitly regenerates WHEN the result shows the replaced content or difference THEN it is masked with the same redaction markers AND no unmasked replaced content is returned in text, JSON or logs | Integration |

### AC-003B-06: Status and Honest Host Effect

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-06a | GIVEN a project with carriers WHEN status runs THEN the host-integration section lists each selected or no-longer-managed carrier of the record's environment (no other environment's carriers) with path, selection, fragment state (present / absent / missing file / modified / customized / no longer managed / malformed / unreadable), required-metadata state and one next step AND host effect "not verified" for every carrier | Integration |
| AC-003B-06b | GIVEN any project state WHEN status runs THEN no carrier, install record or other file is created, modified or deleted | Integration |
| AC-003B-06c | GIVEN any generation result, status output, carrier text or Framework skill/reference text WHEN read THEN none claims that a carrier is loaded by a host or that routing was verified AND the generation result states "written / component-checked; host effect not verified" (I-18, I-19) | Integration |
| AC-003B-06d | GIVEN the instructions file whose toolkit-owned front matter was removed, altered (e.g. `applyTo` changed or keys added) or is no longer at file start WHEN status or the carriers operation runs THEN it is reported as **front-matter drift** with the masked difference and the next step AND this is distinct from user content outside the managed boundaries (AC-003B-03g) AND the file is kept, not rewritten, unless the Maintainer chooses regenerate, which restores the front matter while preserving all other user bytes (AC-003B-05c) | Integration |

### AC-003B-07: Sandbox-only Generation during Development

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-07a | GIVEN the toolkit development repository (which has its own `.github/copilot-instructions.md`) WHEN this feature's automated test suite runs THEN every carrier write targets a sandbox target project root AND the repository's `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` and `.github/instructions/` are byte-identical (or still absent) afterwards | Integration |
| AC-003B-07b | GIVEN a sandbox target project nested inside a directory tree whose ancestors contain `AGENTS.md` or `.github/copilot-instructions.md` WHEN carriers are generated with the explicit sandbox root THEN only carriers under that root are written AND ancestor files are byte-identical AND no parent directory is searched or used as the project (S-04) | Integration |
| AC-003B-07c | GIVEN write auditing enabled for the full automated suite, covering product code in the test process and in every CLI subprocess it starts, and recording every file create, modify, delete, rename and folder creation WHEN the suite runs THEN every product write resolves (after normalization and symlink resolution) beneath a test-created sandbox root, except explicitly listed test-cache exceptions declared in the test configuration (e.g. the pytest cache, the uv cache, bytecode caches) AND any other write fails the suite | Integration |
| AC-003B-07d | GIVEN snapshots (path list and SHA-256) of the protected trees taken before the full automated suite — the toolkit source tree `ai-secure-code-toolkit/`, the development repository root carriers, and the ancestor trees of every sandbox root WHEN the suite ends THEN every protected file is byte-identical AND no new `AGENTS.md`, `CLAUDE.md`, `.github/instructions/**` or `.x-ipe/private/secure-code/**` path exists anywhere in the protected trees outside a test-created sandbox root | Integration |
| AC-003B-07e | GIVEN a test-created root seeded with ancestor variants above the sandbox project: `AGENTS.md` and `CLAUDE.md` with and without toolkit markers, `.github/copilot-instructions.md`, `.github/instructions/x-ipe-secure-code-toolkit.instructions.md`, an ancestor `.x-ipe/private/secure-code/install-record.json` and an ancestor skills folder WHEN `init`, the carriers operation and status run with the explicit nested sandbox root THEN results equal those of the same runs without the seeds AND read auditing shows no ancestor install record, carrier or skills file is opened for project discovery AND write auditing shows no ancestor write | Integration |

### AC-003B-08: FEATURE-001-A Compatibility (Additive Extension)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-003B-08a | GIVEN the FEATURE-001-A automated tests (including `test_project_init.py` and `test_host_fragment.py`) without modification WHEN they run against the code delivered by this feature THEN all of them pass | Integration |
| AC-003B-08b | GIVEN an install record written by this feature WHEN it is read THEN its schema id is the unchanged `ai-secure-code-toolkit/install-record/v1` AND every FEATURE-001-A field is present with unchanged meaning (`toolkit_version`, `environment`, `skills_dir`, `host_entry`, `fragment_sha256`, `initialized_at`, `updated_at`, `files`) AND the top-level `host_entry`/`fragment_sha256` are authoritative for the host entry carrier AND the only addition is one optional per-carrier member with a default; GIVEN no optional carrier was ever selected and no customization accepted WHEN any command writes the record THEN the member is omitted and the record equals what FEATURE-001-A writes; GIVEN a FEATURE-001-A record WHEN read by this feature THEN it is accepted without loss | Unit |
| AC-003B-08c | GIVEN a sandbox target project with or without stored optional carrier selections WHEN plain `secure-code init --env github-copilot` runs without carrier options THEN its observable behaviour is exactly FEATURE-001-A's, apart from the single accepted-customization exception (AC-003B-01g…01j), which applies only when a valid per-carrier member exists. On projects without a per-carrier member, behaviour and records are byte-identical to FEATURE-001-A and the FEATURE-001-A tests are unchanged: the same command options, refusals, problem codes, per-file outcomes, single `AGENTS.md` fragment with the same markers AND it neither generates, checks, reports nor modifies optional carriers (stored selections are ignored) AND, for the same environment, it carries any stored per-carrier member forward unchanged AND the existing status host-section fields keep their names and meaning, with per-carrier entries only additional. If delivering this feature would require any change to FEATURE-001-A observable behaviour, implementation stops and the change is parked as a human CR (BR-14) | Integration |
| AC-003B-08d | GIVEN a record for environment X WHEN the carriers operation runs with environment Y THEN it is refused with the next step to initialize for Y, and nothing is written; GIVEN plain `init` switches the project to environment Y (FEATURE-001-A behaviour) THEN the new record has no per-carrier entries for X AND no result or status reports X's carriers AND X's carrier files are left untouched (one environment per record) | Integration |
| AC-003B-08e | GIVEN the Framework `environments.md` and `cli-contract.md` references WHEN read THEN they state that toolkit versions before this feature cannot read an extended install record and refuse it with their record error (no forward compatibility), and that the per-carrier member is omitted while no optional carrier or customization is recorded | Unit |

> **Test Type Legend:** UI — browser/DOM; API — HTTP request/response; Unit — isolated function/module or content check of rendered text; Integration — CLI process + filesystem in a sandbox target project. This feature has no UI or HTTP API.

### HO-003B-01: Recorded Human Observation — GitHub Copilot Smoke Check (EPIC AC-33; in scope; pending human)

This item is **not an automated acceptance criterion** and has no automated Test Type. No automated test, fixture, model self-report, DAO guidance or approval can satisfy it (DAO blocker B7).

**Closing rule (Q8 = B, DAO-001).** AC-33 is in scope.
- Refinement, technical design, implementation and automated acceptance proceed.
- The feature is then parked at acceptance with AC-33 recorded as "not executed — human smoke HO-003B-01/B7".
- The feature closes only after the human records this observation.
- **Agents must not perform the smoke check.** It is manual by definition, and running it would send sample data to the host's model service for a new purpose.

- **Precondition:** the human prepares a sandbox target project that is a copy of an MVP sample (marathon registration; WebGoat optional), initialized with `--env github-copilot`, Policies adopted and the carriers generated. Cases 1–3 use `AGENTS.md` only. Case 4 also has the GitHub instructions carrier selected, so both are active. The record states which carriers were generated, with their digests.
- **Observation, on GitHub Copilot CLI and on VS Code with GitHub Copilot, each separately:**
  1. An implementation task actually invokes the Copilot skill and produces a Copilot report.
  2. An explicit verification request actually invokes the Guard skill and produces a Guard report.
  3. Negative checks: Guard is not invoked merely because the implementation task finished, and a plain question does not invoke Copilot.
  4. De-duplication with both `AGENTS.md` and the GitHub instructions active (EPIC AC-31 on a real host). For one stage and context, exactly one Copilot collaboration and its reports are created for the implementation task. Exactly one Guard verification is created for one explicit verification request. The read-only Reviewer sub-agents start no further Copilot collaboration or Guard verification (no recursion). The observer counts these in `x-ipe-docs/secure-code/reports/` and the toolkit's private collaboration/verification data.
- **Record (written by the human observer in the feature's acceptance evidence):** date, observer, host and version (Copilot CLI version; VS Code and Copilot extension versions), toolkit version and routing-definition identity, sandbox path, prompts used, observed invocations, report paths, and the result per check: observed / not observed / partly observed, with notes.
- **Limits:** one observation shows invocability on that host and version at that time. It is not automatic host-loading acceptance (I-19 stays deferred), and it does not prove routing or de-duplication in every case. It remains DAO blocker B7.

## Functional Requirements

- **FR-003B-1 Single routing definition.**
  - **Input:** the toolkit's routing definition, held in a toolkit-owned data file inside the installed Framework skill (Q4). A Maintainer changes it by editing that installed file. FEATURE-001-A's safe reinstall keeps such an edit and reports it as locally edited, and carriers render from the installed copy.
  - **Process:** the definition holds, once, the routing statements of AC-003B-02 (Copilot and Guard triggers, de-duplication and no recursion, failed/old reports, no invented Policies, roles, minimal handoff §14.2) and the pointers to the three skills and the status command. Its identity is the toolkit version plus a digest of the definition content. Wording is directive (Q7). It includes explicit exclusions: read-only Reviewer sub-agents never trigger the flow again; Guard runs only on an explicit or authorized verification; failed or old reports never count as done; Policies are never invented.
  - **Output:** the source for every carrier rendering. No carrier text is maintained elsewhere (I-01).
- **FR-003B-2 Carrier rendering.**
  - **Input:** routing definition, environment profile, carrier kind.
  - **Process:** a deterministic rendering per carrier kind. Kinds:
    - host entry fragment (`AGENTS.md` / `CLAUDE.md`);
    - GitHub instructions (`github-copilot` only): a toolkit-owned file `.github/instructions/x-ipe-secure-code-toolkit.instructions.md` with two managed boundaries, so user additions and drift are detected:
      1. the exact toolkit-owned front matter (with `applyTo`) at file start;
      2. the routing body between the toolkit markers;
    - system-prompt fragment: concise, a toolkit-owned file under `.x-ipe/private/secure-code/carriers/`, holding no secrets and never placed with key, trust or authorization material.

    Each rendering states that it is one of the toolkit's integration carriers and gives the definition identity.
  - **Output:** carrier content. Rendering never copies skill procedures or knowledge (I-02, I-03).
- **FR-003B-3 Carrier selection.**
  - **Input:** the dedicated carriers operation with explicit project root and environment (as FEATURE-001-A; must match the record's environment), and an optional explicit carrier selection.
  - **Process:** the default is the host entry carrier only. GitHub instructions and the system-prompt fragment are generated only when selected, and the system-prompt fragment only for an explicitly named host. Selection is validated against the environment's supported carriers. The selection is stored in the install record, and later runs without a selection regenerate or check the stored set (Q2). A deselected carrier is never deleted; it is reported as "no longer managed" (automatic uninstall I-21 is out of scope).
  - **Output:** the resolved carrier set, or a refusal.
- **FR-003B-4 Generation through the FEATURE-001-A writer.**
  - **Process:** plan every selected carrier first, using the existing fragment writer's outcomes (create file / append / current / update / edited kept / replaced / malformed / unreadable) and path-safety checks. If any carrier is blocked (malformed, unreadable, unsafe path, unsupported selection), refuse the whole run and write nothing. Otherwise write the planned carriers atomically and then update the install record. The host entry carrier *is* the FEATURE-001-A fragment: `init` and the carriers operation share one writer, one marker convention and one record (CR-001). Carrier generation, selection and difference decisions for optional carriers happen only in the dedicated carriers operation. Plain `init` without carrier options keeps exactly FEATURE-001-A behaviour and ignores stored optional selections. **Single exception:** plain `init` reads only the accepted-customization digest of the host entry, and only when the per-carrier member exists and is valid. It then reports `customized` only while the current fragment bytes exactly equal that digest. It never overwrites an accepted customization unless the Maintainer explicitly supplies `--replace AGENTS.md` (delivered FEATURE-001-A behaviour; AC-003B-01k), and never reports it as current or synchronized. If the routing definition changed since acceptance, it says so and names `carriers` as the next step (AC-003B-01g…01k). On FEATURE-001-A-only projects nothing changes. The carriers operation writes only the selected carrier files and the install record. It never creates, modifies or deletes anything in the skills folder. If an installed toolkit skill or the installed routing definition is missing, unreadable or invalid, it refuses with an `init` next step and writes nothing; there is no implicit reinstall.
  - **Output:** per-carrier result, the "host effect not verified" statement and next steps.
- **FR-003B-5 Maintainer difference handling.**
  - **Process:** a toolkit fragment that differs from both the recorded and the current rendering is kept and reported, with the difference and the choices: keep (default), modify (the user edits the fragment, then keeps or accepts it), change the routing definition, regenerate (explicit per carrier; the result shows the replaced content or difference) and accept customization (explicit per carrier, recorded truthfully). This mirrors FEATURE-001-A (Q3). Kept differences are reported on every run and in status. An accepted customization is never presented as synced with the routing definition. Any fragment, front-matter content or difference is secret-masked before it enters a text or JSON result or a log. Masking uses the FEATURE-002-A patterns with explicit redaction markers; raw replaced content is never returned.
  - **Authority:** as in FEATURE-001-A `init`/`--replace`, no signed Maintainer authorization is required. Explicit per-carrier choice is required (Q3; a signed-authorization gate would be a CR on FEATURE-001-A).
- **FR-003B-6 Install record extension (I-17).**
  - The FEATURE-001-A install record is extended **strictly additively** rather than duplicated (Q5).
    - The existing `InstallRecord` gains one optional, defaulted per-carrier member under the same `install-record/v1` schema id. The member is omitted when no optional carrier was ever selected and no customization accepted, so such records equal what FEATURE-001-A writes.
    - The top-level `host_entry`/`fragment_sha256` stay authoritative for the host entry carrier. The member holds the stored selection, the optional carriers (kind, path, managed-boundary digests, routing-definition identity) and any accepted-customization data (accepted digest, identity at acceptance, time), including for the host entry.
    - A FEATURE-001-A regression run is required (AC-003B-08a…08e).
  - **One environment per record.** The carriers operation refuses an environment other than the record's. When plain `init` switches environment, the member for the old environment is not kept and the old carriers are neither reported nor touched.
  - Concurrent `init`/carriers runs are serialized. On partial failure the record is not updated and re-runs converge.
  - A FEATURE-001-A record is read and carried forward without losing `initialized_at` and without reporting an unedited fragment as edited.
  - **No forward compatibility:** toolkit versions before this feature refuse an extended record with their existing record error. Requiring them to read it would be a CR.
  - The record and its digests detect changes only; they grant no permission (I-14).
- **FR-003B-7 Per-carrier status.** The status host-integration section keeps its FEATURE-001-A fields and adds entries for every selected or no-longer-managed carrier of the record's environment. It reports file, managed boundary and required metadata states (front-matter drift distinct from user content), with one next step each and host effect "not verified". Status stays read-only, and any content it shows is masked.
- **FR-003B-8 Documentation.** The Framework skill and its `environments.md` and `cli-contract.md` references describe the carriers, selection, difference choices, problem codes and the honest host-effect limit. The Copilot and Guard skills keep their own "When to Use", and the carriers point to them.

## Non-Functional Requirements

- **NFR-003B-1 Determinism.** The same routing definition, environment and selection always render byte-identical carrier content apart from the file's newline style. The renderer uses no AI and no time-dependent text inside fragments.
- **NFR-003B-2 Safety.**
  - No network.
  - No writes outside the explicit project root, and no host, global or user-level configuration.
  - No credential, key or absolute machine path in any carrier.
  - Carriers are data for the host and grant no role or permission.
  - Fragment content and differences are secret-masked before entering any text or JSON result or log, using explicit redaction markers. Masking is pattern-based, not a complete data-loss-prevention guarantee.
- **NFR-003B-3 Reliability.**
  - Plan everything first; a refused run writes nothing.
  - Where the toolkit lock is available, `init` and the carriers operation run only under the lock. A run that cannot take it waits a bounded time (an existing toolkit lock timeout), then refuses with `LOCKED` and a retry next step; it never proceeds unlocked (DAO-004 Q3). Plain `init` on a platform without the lock keeps exactly FEATURE-001-A behaviour (DAO-004 Q4 hard condition).
  - Writes are atomic per file. The install record is updated only after all carrier writes succeed.
  - A re-run converges without duplicates (AC-003B-04f, 04g).
- **NFR-003B-4 Concision.** Carriers contain only routing statements and pointers (AC-003B-01c). No numeric size threshold is set in this specification; a threshold would need a sourced value.
- **NFR-003B-5 Portability and independence.**
  - Same platforms and path rules as FEATURE-001-A; Windows verification follows FEATURE-001-A's tracked CR-002 item.
  - **Open gap B11 (pending human):** on Windows the carriers operation currently refuses with `LOCK_UNAVAILABLE` (interim). Windows remains a human-confirmed supported platform (NFR-001A-4, G-08); see Open Questions.
  - LF/CRLF preserved.
  - No dependency on X-IPE task, board or workflow files (NFR-01).
- **NFR-003B-6 Honest limits.** Results, status and documentation separate "written / component-checked" from "host effect not verified" (I-18, I-19). A workspace sandbox is not OS isolation (S-06).
- **NFR-003B-7 Test isolation.** The full automated suite runs with write auditing and protected-tree snapshots (AC-003B-07c…07e). Explicit test-cache exceptions are the only writes allowed outside test-created sandbox roots.

## UI/UX Requirements

No graphical UI. Command-line experience, consistent with FEATURE-001-A:

- Carrier generation, selection and difference decisions use a **dedicated carriers operation** of the toolkit CLI (e.g. `secure-code carriers …`; final name and options in technical design). Plain `secure-code init` keeps its FEATURE-001-A options and behaviour. Every run returns the toolkit result envelope as text and `--json`.
- The result lists each carrier with path, state (created / appended / current / updated / kept-differs / replaced / customized / no longer managed / blocked) and one next step. A kept difference shows the masked difference to the toolkit rendering and the Maintainer's choices. For the instructions file, front-matter drift and user content outside the managed boundaries are shown separately.
- The system-prompt fragment result says where the fragment is and that adding it to a host is the user's manual step.
- Status shows a host-integration section with one line per carrier and "host effect: not verified".
- No prompt defaults to replacing, regenerating or accepting. Every overwrite of a differing fragment needs an explicit per-carrier choice.

## Dependencies

- **Internal:**
  - FEATURE-001-A (Completed). Provides `secure-code init --env`, environment profiles (`github-copilot` → `.github/skills/`, `AGENTS.md`; `claude-code` → `.claude/skills/`, `CLAUDE.md`), the fragment writer (`host_fragment.plan_upsert` / `inspect`, markers `<!-- BEGIN ai-secure-code-toolkit: managed fragment, edits are reported not overwritten -->` / `<!-- END ai-secure-code-toolkit -->`), the install record (`install-record/v1`), path safety, atomic writes and the status host section. This feature extends them; there is no second writer (CR-001).
  - FEATURE-003-A (Copilot skill) and FEATURE-002-A (Guard skill): the working skills the carriers route to. Their "When to Use" sections are the reference for AC-003B-02f.
  - FEATURE-001-C: adopted Policies needed for the HO-003B-01 smoke.
- **Consumers:** FEATURE-003-C (the sandbox includes `AGENTS.md` and optional instructions, S-02; it may host the HO-003B-01 sandbox); later hosts beyond GitHub Copilot.
- **External:** GitHub Copilot CLI and VS Code with GitHub Copilot, needed **only** for the human observation HO-003B-01, with versions recorded by the observer. The instructions front matter (`applyTo`) follows GitHub Copilot's documented path-specific instruction format as of technical design.

## Business Rules

- **BR-01:** One routing definition; every carrier is rendered from it. Carriers are one integration declaration, not three independent ones (I-01, I-07).
- **BR-02:** Skills stay self-contained. Carriers route; they never copy skill procedures or knowledge (I-02).
- **BR-03:** Copilot is used for design, implementation, bug fix and refactor; not for plain questions or read-only lookups (I-05).
- **BR-04:** Guard is used only on an explicit verification request or an authorized upstream verification step, never automatically on artifact completion (I-06).
- **BR-05:** Read-only Reviewers never start the security flow again. The same stage and effective context is not started twice, and relevant changes are evaluated again (I-07, I-08).
- **BR-06:** Failed or old reports never count as done. Policies are never invented. Continuing is not passing (I-09, I-10).
- **BR-07:** Only the delimited toolkit fragment, or a toolkit-owned carrier file, belongs to the toolkit. Everything else belongs to the user, even when it mentions the toolkit (I-12, I-13).
- **BR-08:** The host entry carrier is generated by default. Other carriers only on explicit selection. No change to global prompts or configuration, other hosts' files or `.gitignore` (I-03, I-04).
- **BR-09:** Every fragment difference belongs to the Maintainer. Keep is the default and is reported every time. Regenerate and accept are explicit per carrier. A digest mismatch never removes the decision. An accepted customization is never claimed as synced (I-15, I-16).
- **BR-10:** The install record and digests detect change; they grant no permission (I-14).
- **BR-11:** A written or component-checked carrier is not evidence of host loading or routing. Host effect is "not verified" until I-19 is delivered. MVP invocability rests on HO-003B-01 (I-18, I-19).
- **BR-12:** During development and testing, carriers are generated only in sandbox target projects, never in the toolkit development repository (DAO plan, S-01…S-04).
- **BR-13:** AC-33 is in scope. The feature is parked at acceptance with AC-33 "not executed — human smoke HO-003B-01/B7" and closes only after the human records the smoke and the human resolves B11 (Windows `carriers` support). Agents never perform the smoke: it is manual by definition, and running it would send sample data to the host's model service for a new purpose (Q8).
- **BR-14:** The extension of FEATURE-001-A is strictly additive. If FEATURE-001-A observable behaviour would have to change, work stops and the change goes to the human as a CR (Q5).
- **BR-15:** A deselected carrier is never deleted. It is reported as "no longer managed" (Q2, I-21).
- **BR-16:** No fragment, front-matter content or difference enters a result or log unmasked. Redactions are explicit.
- **BR-17:** Plain `init` keeps exactly FEATURE-001-A behaviour; optional carriers are handled only by the dedicated carriers operation. The single exception is the exactly matching accepted host-entry customization read from a valid per-carrier member. It fails closed, never overwrites the customization unless the Maintainer explicitly supplies `--replace AGENTS.md`, and never reports it as current (AC-003B-01g…01k). That operation modifies only the selected carrier files and the install record. It never touches the skills folder and never reinstalls implicitly; missing or invalid skills or routing definition lead to a refusal with an `init` next step. One install record covers one environment. Older toolkit versions are not forward-compatible with extended records.
- **BR-18:** For the instructions file, the toolkit owns exactly two managed boundaries: the front matter at file start and the marker-delimited body. Everything else in that file belongs to the user.

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Project not initialized by FEATURE-001-A | Refused with next step `secure-code init --project … --env …`; nothing written |
| Project initialized by a pre-003B toolkit version | Two-step upgrade: `carriers` refused with an `init` next step; `init` installs the routing definition and updates the unedited fragment in place; `carriers` then succeeds (AC-003B-01d) |
| Install record unreadable or symlinked | Refused, as FEATURE-001-A; not repaired automatically |
| Carriers operation with an environment other than the record's | Refused; next step: initialize for that environment first (AC-003B-08d) |
| Plain `init` switches environment (FEATURE-001-A behaviour) | The record now covers only the new environment. The old environment's carriers are left untouched and not reported (one environment per record; no automatic removal, I-21) |
| Extended record read by a toolkit version from before this feature | That version refuses with its record error and writes nothing; no forward compatibility (AC-003B-08e) |
| Plain `init` on a project with stored optional selections | FEATURE-001-A behaviour; optional carriers ignored; stored member carried forward (AC-003B-08c). The only exception is the exactly matching accepted host-entry customization (AC-003B-01g…01j) |
| Host entry edited again after acceptance, or per-carrier member invalid | Plain `init` reports `FRAGMENT_EDITED` and keeps the fragment (fail closed); never `customized` or current (AC-003B-01h, 01i) |
| Carrier deselected | Left in place, reported as "no longer managed"; never deleted (I-21) |
| Host entry file deleted by the user after generation | Status: "missing file". Generation re-creates it only when the carrier is still selected and reports it as created |
| Fragment edited, and the routing definition also changed | Kept and reported with the difference to the new rendering; regenerate or accept only on explicit choice |
| Accepted customization, then a new toolkit version changes the definition | Plain `init` keeps it, reports `customized` plus the routing change and names `carriers` as next step (AC-003B-01j); the carriers operation reports it again as a difference for a decision (AC-003B-05d) |
| Two toolkit fragments in one carrier (e.g. manual copy) | Whole run refused (`FRAGMENT_DUPLICATE`); not repaired silently |
| Fragment text pasted without markers | User text; not taken over (AC-003B-04c); a new fragment may be appended, and the result notes the similar text |
| Carrier path is a symlink (e.g. `CLAUDE.md -> AGENTS.md`) | Refused with `PATH_UNSAFE`, as FEATURE-001-A; in-project links stay refused (Q9) |
| Instructions front matter removed, altered or moved from file start | Reported as front-matter drift, kept; regenerate restores it at file start and keeps all other user bytes (AC-003B-06d, 05c) |
| Secret pasted into a toolkit fragment or front matter | Kept on disk as the user's content; every reported difference or replaced content shows redaction markers (AC-003B-05f, 05g) |
| Selected carrier unsupported for the environment | Refused, supported carriers listed (AC-003B-03f) |
| Pre-existing user `.github/copilot-instructions.md` | Always untouched; the instructions carrier is the separate toolkit-owned `.instructions.md` file (Q1) |
| User adds text outside the markers of the toolkit-owned instructions file | Preserved and reported as user content detected (AC-003B-03g) |
| Implementation would need a change to FEATURE-001-A observable behaviour | Stop and park it as a human CR (BR-14); never changed silently |
| Sandbox nested in a repository with ancestor instructions | Only the explicit root is read for discovery and written (AC-003B-07e); ancestor-instruction influence on a host is a known risk to observe in HO-003B-01, not something the toolkit claims to prevent (S-04) |
| Write failure midway | Failure reported with carriers written; record not updated; re-run converges (AC-003B-04f) |
| Concurrent runs | No duplicate fragments; record matches disk; a run that cannot take the lock waits a bounded time, then refuses with `LOCKED` (AC-003B-04g, 04h) |
| Accepted customization, then `init --replace AGENTS.md` | Replaced; result reports `replaced`, says an accepted customization was replaced and shows the masked previous content; the acceptance lapses; `init` and `carriers` then agree (AC-003B-01k) |
| Windows: carriers operation | Interim refusal `LOCK_UNAVAILABLE`, no lock file, nothing written; open gap B11 pending human, not a decided scope (AC-003B-04i) |
| Windows: plain `init` | Exactly delivered FEATURE-001-A behaviour; the new lock never makes it refuse (AC-003B-04i). If this cannot be guaranteed, implementation stops and B11 is extended with the FEATURE-001-A regression risk |

## Out of Scope

- Automatic acceptance of actual host loading and routing behaviour (I-19, S-05); deferred.
- Agent persona/profile files and their host-specific distribution (D-25): out of scope until D-25 is decided (Q6). Inventory §19 also notes that `install-agent-profile` is not required by default in the first version.
- Automatic removal of carriers, uninstall and failure-maintenance recovery (I-21).
- Writing into host system prompts, global or user-level configuration, or other hosts' mirrors and `.gitignore` (I-03, I-04).
- Verified support for hosts other than GitHub Copilot. `claude-code` remains an unverified profile.
- The legacy `assist / verify / both / off` mode switch (I-22).
- Support for symbolic links on carrier paths (tracked item from FEATURE-001-A closing; stays refused per Q9).
- Deleting deselected carriers or any automatic uninstall (I-21; Q2).
- Windows verification (follows FEATURE-001-A CR-002 tracked item). Windows `carriers` **support** is not out of scope; it is open gap B11 (see Open Questions).
- Requirement-analysis-stage routing to Copilot (C-03, open).

## Technical Considerations

- **Reuse, not a second writer (CR-001).** Extend `host_fragment` (rendering per carrier kind, plan/inspect) and `project_init`'s plan-then-apply pipeline and path-safety checks. `render_body(profile)` is today's single hard-coded rendering and becomes a rendering of the routing definition. Keep the existing marker convention for Markdown carriers. The toolkit-owned instructions file has two managed boundaries: the exact front matter at file start (required host metadata) and the toolkit-marker-delimited routing body. The system-prompt fragment file's delimiting is a design detail; it must allow fragment-level change detection.
- **Install record (I-17, Q5).** One optional, defaulted per-carrier member on the existing `InstallRecord`, under the same `install-record/v1` schema id.
  - Omit the member when it is empty, so records without optional carriers stay byte-equal to FEATURE-001-A output. Keep it out of the comparison that decides whether `init` rewrites the record, so plain `init` stays a no-op on unchanged projects.
  - Today's `install_record.load` rejects unknown keys. Releases before this feature therefore refuse extended records; this is accepted and documented (AC-003B-08e).
  - Also needed: concurrent-write protection and partial-failure convergence.
  - If any of this changes FEATURE-001-A observable behaviour, stop and raise a human CR.
- **Status.** Extend `status._host` from one `host_entry` to a per-carrier list, keeping `host_effect: "not verified"`.
- **Command surface.** A dedicated carriers subcommand calls the same writer (name and options in technical design). Document it in `cli-contract.md` with any new problem codes (e.g. unsupported carrier, environment mismatch, front-matter drift). `init` keeps its FEATURE-001-A options.
- **GitHub instructions metadata.** The exact toolkit-owned front matter (with an `applyTo` pattern) is fixed in technical design against GitHub Copilot's documented path-specific instruction format at that time (I-18). Drift is detected by comparison with that exact block.
- **Masking.** Reuse the FEATURE-002-A masking patterns and add explicit redaction markers. Mask before formatting any text or JSON result.
- **Consistency with skills.** AC-003B-02f compares carrier statements with the installed SKILL.md "When to Use" text. A wording change in either place must keep them consistent.
- **Development safety.** Tests use sandbox target roots only. The development repository contains X-IPE's own `.github/copilot-instructions.md`, which must never be written (AC-003B-07a).
  - Write and read auditing must also cover CLI subprocesses, e.g. through an audit hook or wrapper loaded by every product process under test; the mechanism is decided in design.
  - Test-cache exceptions are an explicit list in the test configuration.

## Open Questions

**Open — pending human: B11 (Windows `carriers` support).**
- **Source:** DAO-004 unit 1, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` (SHA-256 `d1cb45d926deca02…`). Deferring Windows functionality is outside DAO authority.
- **Requirement:** Windows is a human-confirmed supported platform (NFR-001A-4, G-08; FEATURE-001-A v1.2 "Windows remains a supported-platform requirement"). CR-002 deferred Windows *verification* only.
- **Interim behaviour (parked, honest):** on Windows the carriers operation refuses with `LOCK_UNAVAILABLE`, never runs unlocked and creates no lock file (AC-003B-04i).
- **Hard condition:** plain `init` on Windows keeps exactly the delivered FEATURE-001-A behaviour. If that cannot be guaranteed, implementation stops and the FEATURE-001-A regression risk is added to B11.
- **Question for the human:** approve deferring Windows `carriers` support, or require a Windows-specific locking design that creates no extra file. The technical designer may attach candidate Windows approaches here for the human.
- **Closing:** FEATURE-003-B closing waits on B7 (HO-003B-01) and B11.

| ID | Question | Status |
|---|---|---|
| B11 | Windows `carriers` support: approve deferral, or require a Windows-specific locking design without an extra file | **pending human** (candidate approaches: none attached yet) |

**Decided (not open):** Q1…Q9 were decided on 10-23-2026 by the **delegated 工程師 representative (DAO)** under the human's delegation (interaction mode dao-represent-human-to-interact). They are **not human decisions**.
- Decision log: `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md`, entry DAO-001 (SHA-256 `6a63a8c1c617910f…`).
- No human confirmation of this specification has been given.
- D-25 remains open at inventory level (not in this feature).

| ID | Question | Decision (DAO-001) | Conditions / notes from the decision |
|---|---|---|---|
| Q1 | Carrier set and file locations per host | **A** | `github-copilot`: the `AGENTS.md` fragment is the **only default**. The GitHub instructions file `.github/instructions/x-ipe-secure-code-toolkit.instructions.md` (`applyTo` front matter) and the system-prompt fragment file under `.x-ipe/private/secure-code/carriers/` (also shown in the result) are generated only on explicit selection (FR-27 optional; BR-08). `claude-code`: `CLAUDE.md` fragment + system-prompt fragment only. The toolkit-owned instructions file still uses the toolkit markers, so user additions are detected (AC-003B-03g). The system-prompt fragment file holds no secrets and does not share a directory with key or signing material (AC-003B-03h). Added automated AC-003B-01f for AC-31 de-duplication when a host loads both `AGENTS.md` and the instructions file. |
| Q2 | Selection persistence and deselection | **A** | Selection is stored in the install record. Deselection never deletes (automatic uninstall I-21 is out of scope); the result reports the carrier as "no longer managed" (AC-003B-03e). |
| Q3 | Maintainer difference choices and authority | **A**, mirroring FEATURE-001-A | Keep is the default. "Modify" (FR-28) is the user's own edit, followed by keep or accept. Regenerate and accept are explicit per carrier. The result shows the replaced fragment content or difference. No signed authorization is needed; option B would be a CR on delivered FEATURE-001-A and is outside DAO authority. |
| Q4 | Routing definition location | **A** | A toolkit-owned data file in the installed Framework skill. Option B was rejected as adding surface without a sourced need. |
| Q5 | Install record (I-17) | **A**, strictly additive | FEATURE-001-A readers and tests stay unchanged and a FEATURE-001-A regression run is required (AC-003B-08a…08c). If FEATURE-001-A observable behaviour would change, stop and park it as a human CR (BR-14). Made concrete after independent review (10-23-2026, within this decision): one optional, defaulted member under the same v1 schema; one environment per record; no forward compatibility for older versions. |
| Q6 | Persona files (D-25) | **A** | Out of scope until D-25 is decided. |
| Q7 | Routing wording | **A**, directive with exclusions | The exclusions must include: read-only Reviewer sub-agents never trigger the flow again (02c); Guard only on explicit or authorized verification (02b); failed or old reports never count as done (02d); no invented Policies (02d). |
| Q8 | HO-003B-01 / AC-33 and closing | **B** | AC-33 is in scope. Complete refinement, design, implementation and automated acceptance, then park at acceptance with AC-33 "not executed — human smoke HO-003B-01/B7". Close only after the human records the smoke. Agents must not perform it: it is manual by definition and would send sample data to the host's model service for a new purpose (BR-13). |
| Q9 | In-project symbolic links | **A** | Keep refusing with `PATH_UNSAFE`. |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| FR-27 (I-01, I-02, I-03, I-07); EPIC AC-31; CR-001; FR-003B-1, -2, -4 | US-01, US-03, US-06 | AC-003B-01a…01k | N/A | Integration (sandbox target project) + Unit (rendering) | covered (01f added per Q1 condition, DAO-001) |
| FR-27 (I-05, I-06, I-10); breakdown AC-003B-01; FR-003B-1 | US-02 | AC-003B-02a, 02b, 02f | N/A | Unit (carrier content vs SKILL.md) | covered for content; actual triggering → HO-003B-01 |
| FR-27 (I-07, I-08); EPIC AC-31 | US-03 | AC-003B-02c | N/A | Unit | covered |
| FR-27 (I-09, I-10, I-11, §14.2) | US-02, US-03 | AC-003B-02d, 02e, 02g | N/A | Unit | covered |
| FR-27 (I-03, I-04); FR-003B-3 | US-04 | AC-003B-03a…03h | N/A | Integration | covered (Q1, Q2 decided; 03g, 03h added per Q1 conditions) |
| FR-28 (I-12, I-13, I-14); EPIC AC-32; FR-003B-4, -6 | US-05 | AC-003B-04a…04i | N/A | Integration; 04i Unit with simulated platform | covered (04g/04h bounded lock per DAO-004 Q3); Windows `carriers` support: open gap B11, pending human |
| FR-28 (I-15, I-16); EPIC AC-32; FR-003B-5 | US-06 | AC-003B-05a…05e | N/A | Integration | covered (Q3 decided) |
| FR-28 (I-18), FR-03 (O-10, X-11, X-12), I-19; FR-003B-7 | US-07 | AC-003B-06a…06d | N/A | Integration | covered |
| FR-27; EPIC AC-33; breakdown AC-003B-01 (actual triggering) | US-08 | HO-003B-01 | N/A | Recorded human observation on Copilot CLI and VS Code, cases 1–4 incl. de-duplication with both carriers active (not automatable; agents must not perform it) | in scope; pending human; closing waits for the record (Q8 = B) |
| DAO plan; S-01…S-04; AC-35; BR-12; NFR-003B-7 | US-05 | AC-003B-07a…07e | N/A | Integration (write/read auditing, protected-tree snapshots) | covered |
| R-08 / FEATURE-002-A masking; NFR-003B-2; BR-16; FR-003B-5 | US-06 | AC-003B-05f, 05g | N/A | Integration (canary secrets) | covered |
| NFR-003B-1…6 | — | 01c, 04a, 04b, 04f, 06c (otherwise design/implementation evidence) | N/A | Unit / Integration | covered by ACs + design |
| I-17 (Q5 strictly additive); BR-14, BR-17; FR-003B-6 | US-05 | AC-003B-08a…08e | N/A | Integration (FEATURE-001-A regression) + Unit (record compatibility) | covered; schema detail decided in technical design |
| D-25 | — | — | N/A | — | out of scope until decided (Q6 = A) |
| I-19, S-05, I-21, I-22 | — | — | N/A | — | deferred / excluded (Out of Scope) |

## Context and Verification Evidence

- **Sources (SHA-256 prefixes, read 10-23-2026):**
  - `x-ipe-docs/requirements/requirement-details.md` `1747efe61b9c5cf1`. Sections used: FR-27, FR-28, G-06, AC-31…AC-33, FEATURE-003-B details with the CR-001 note, FEATURE-001-A CR-001 note.
  - inventory v2 `f36a27538196f351`. Rows used: §14.1 I-01…I-11, §14.2, §14.3 I-12…I-17, §14.4 I-18…I-22, §15 S-01…S-09, §17 D-25, §19 `install-agent-profile`, §19.1.
  - `idea-summary-v2.md` `9a7db37ebf2f31ac`. Sections used: Problem 7 and the host-integration paragraphs.
  - FEATURE-001-A specification `729ff1f519753500`; FEATURE-003-A specification `4c647c8c4faac1c1`.
- **Actual implementation inspected (contracts this specification extends):**
  - Code: `host_fragment.py` `a14b9b859a680c65`, `project_init.py` `7bfe353ed969ec5f`, `environments.py` `a3d975d4160bfa8d`, `install_record.py` `613ee0704be8a576`, `status.py` `1966adebadb53c1d`.
  - Tests: `tests/test_host_fragment.py` `2b0bb8e672508791`; `tests/test_project_init.py` (fragment tests).
  - Framework references: `environments.md` `e713fae2d5944ea7`, `cli-contract.md` `c23568c31c481ec4`.
  - Skill packages: Copilot `8b954e90ec4426b7`, Framework `c8f8af097c1519ef`, Guard `cdbfc5bc9c312604`.
- **Board:** not queried in this worker (no board access by instruction). Feature identity, version v1.0 and dependencies FEATURE-002-A and FEATURE-003-A come from the requirement-details breakdown table and the owner's task context.
- **Mockups:** none (bounded discovery above).
- **Decisions:** Q1…Q9 decided by the delegated 工程師 representative.
  - Source: DAO-001 in `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md` (SHA-256 `6a63a8c1c617910f707d6070131ffd81420425ae151cd421545b678e94f25edf`), made against draft revision `880578dd96b21211…`.
  - Applied in this revision. They are DAO decisions under the human's delegation, not human decisions.
- **DAO-003 defect corrections (10-23-2026, during TASK-061 Technical Design):**
  - Decided by the delegated representative under the human's delegation; source `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` (SHA-256 `bff42f5b96f492ef…`).
  - Corrected: AC-003B-01d (two-step upgrade) and the bounded plain-`init` exception; added 01g…01j.
  - Design evidence bound to earlier specification hashes is affected for these items and needs re-review at this revision.
- **DAO-004 (10-23-2026, TASK-061 Technical Design):** applied Q2 (`--replace AGENTS.md` after an acceptance), Q3 (bounded lock wait, `LOCKED`) and Q4 (Windows interim refusal as open gap B11, pending human). Source log SHA-256 `d1cb45d926deca02…`. Design evidence bound to earlier specification hashes needs re-review for 01g, 01i, 01k and 04g…04i.
- **Independent review (10-23-2026):** 5 blocking findings, all fixed in this revision:
  1. Command and install-record semantics.
  2. The two managed boundaries of the instructions file.
  3. Host de-duplication added to HO-003B-01 as case 4.
  4. Secret masking of differences.
  5. Suite-wide write auditing.
- **Confirmation:** no human confirmation of this specification. Per DAO-001 the next step is independent review, then the owner's specification confirmation.
- **Execution:** free-mode; no application workflow write (`workflow_action_updated: false`); no board, Git or memory writes.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-003B-01a…08e | Planned per Test Type above; no tests exist yet | planned | not measured |
| HO-003B-01 (AC-33) | Recorded human observation on GitHub Copilot CLI and VS Code; not yet performed; at acceptance recorded as "not executed — human smoke HO-003B-01/B7" | pending human (feature parks at acceptance; closes only after the record) | not measured |
