# Feature Specification: Strix Adapter with Original-Project Protection

> Feature ID: FEATURE-002-E  
> Epic: EPIC-002 (Guard: Verification, Adapters & Evidence)  
> Version: v1.0  
> Status: Draft (TASK-064, refinement by Sage) — **tool-level validation NOT done; Technical Design blocked by human blocker B1**  
> Last Updated: 10-23-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-23-2026 | Initial specification. Written under boundary B1: no Strix download or run, no model keys, no data sent to model services. Pending decisions OQ-1…OQ-8 recorded with recommendations, not decided. | N/A |

## Linked Mockups

N/A — command-line and skill-driven feature; no UI mockup.

## Overview

Strix is an autonomous, model-driven security testing tool. It is the third prebuilt Adapter (FR-16) after Opengrep (FEATURE-002-A scope) and Trivy (FEATURE-002-D), and the only one that (a) calls model services and (b) sends requests to a running target. It therefore carries two risks the other Adapters do not: it can **modify the original project** (agents may edit files or apply fixes) and it can cause **uncontrolled egress and cost**.

This feature delivers a Strix Adapter on the shared Adapter contract (FEATURE-002-B) that:

- registers a **pinned** Strix version and container image, verified by official digest **before anything executes**; never auto-downloads or upgrades (A-08, A-09, AC-24);
- **proves** before a run that the original project cannot be written (a tested write attempt is *rejected*); otherwise runs only on an **explicit working copy** and reports copy scope and environment differences; never silently relaxes permissions; never writes fixes back (FR-17, AC-23);
- allows every model call and every target request only under a matching purpose-specific grant from FEATURE-002-C, declaring purpose, data and recipient; charges the shared verification budget; stops on cancel (FR-20, E-02, B-01, B-08, AC-002E-01);
- reports tool failures honestly and normalizes real output into per-check evidence; the Guard decides, the Adapter executes (AC-24, FR-16);
- is preceded by a small **tool-level validation** on the MVP samples whose observed results and known issues are recorded (S-07, AC-002E-02); formal-delivery evaluation (AC-28) belongs to FEATURE-003-C.

**Blocker B1 (human):** the tool-level validation requires downloading and running Strix with real model credentials and sending sample code to a model provider. None of this is authorized in this task. AC-002E-07a/07b are **not done** and **block Technical Design** until the human resolves B1 (see OQ-8). ACs marked **[B1]** below cannot be verified with the real tool until then.

## User Stories

- **US-01:** As a Developer, I want the Guard to use Strix for deep autonomous verification so that risks that rule-based tools miss can be checked against a running sample.
- **US-02:** As a Developer, I want proof that Strix cannot change my original project, or an explicit, reported working copy, so that verification never damages my code.
- **US-03:** As a Maintainer, I want to register exactly one pinned, digest-verified Strix build so that only a known tool runs and nothing is downloaded silently.
- **US-04:** As an Owner, I want every model call and target request by Strix to be authorized for its purpose, recipient and data and charged to the budget, so that source code is never uploaded and cost is bounded.
- **US-05:** As an upstream agent, I want Strix failures and partial runs reported as such, so that a crash, timeout or zero findings is never read as Pass.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 | EPIC-001 G-02; FR-16, FR-18 | Developer, upstream agent | Deep verification results are trustworthy: no Pass from tool exit, zero findings, failure or cancel | Strix Adapter on shared contract; honest normalization | Scenario: Strix on MVP samples yields per-check evidence; a failed/cancelled run leaves checks unconfirmed | Guard never fixes; no coverage percentage; no vendor claims as results | AC-002E-03, 05, 06, 07, 08 | not measured |
| G-05 | EPIC-001 G-05; FR-17, FR-20 | Owner, Developer | Strix cannot write the original project or falls back to a reported copy; no data leaves without a purpose grant | Read-only feasibility gate; working-copy fallback; egress gate; budget/cancel | Scenario: write attempt to original rejected, or explicit copy used and reported; run without model grant submits nothing | No write-back; no isolation claim without proof; no heavy DLP | AC-002E-01, 02, 04 | not measured |

## Acceptance Criteria

Breakdown ACs: AC-23 (FR-16, FR-17) → AC-002E-02a…02g; AC-24 (Strix) → AC-002E-01a…01d, 03a…03c, 05a…05e; requirement AC-002E-01 (egress, budget, cancel) → AC-002E-04a…04g; requirement AC-002E-02 (tool-level validation) → AC-002E-07a…07b; Guard/Adapter split → AC-002E-06a…06b; status → AC-002E-08a…08b.

Failure semantics follow FEATURE-002-B: a malformed or rule-violating request is **refused** (no attempt, no evidence); an **accepted** request registers its attempt, and a failing pre-check or protection gate then records a failed attempt with the gap and executes nothing.

### AC-002E-01: Registration and Pre-check

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-01a | GIVEN a valid Maintainer authorization and a locally present Strix build (version and container image) whose identity equals an entry of the toolkit's official-digest table for the pinned Strix version (OQ-1, OQ-2) WHEN it is registered THEN the digests are compared before any Strix code or image executes AND the registration records version, image reference, image digest and the table entry used | Integration |
| AC-002E-01b | GIVEN no valid Maintainer authorization, or a version/image not in the table (other tag, mutable tag only, custom build, modified image) WHEN registration is requested THEN it is refused with the reason AND nothing executes AND nothing is recorded | Integration |
| AC-002E-01c | GIVEN an accepted Strix run request WHEN pre-check finds no registration, a digest mismatch, the required container runtime missing (OQ-2), an unsupported platform (OQ-7) or no model-credential reference configured (OQ-3) THEN the attempt fails with the named gap and a next step AND nothing is executed AND nothing is pulled, downloaded, upgraded or relaxed | Integration |
| AC-002E-01d | GIVEN any Strix registration, pre-check or run WHEN its records and reports are produced THEN model keys and other credential values never appear in them; only the credential reference name is shown | Unit |

### AC-002E-02: Original-Project Protection (read-only gate, working-copy fallback) [B1]

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-02a | GIVEN an accepted Strix run on an original project WHEN the protection gate runs before Strix starts THEN, from inside the same execution environment Strix will use, a write attempt (create, modify and delete of a sentinel) on the original project is made AND it is recorded as proven read-only only if every attempt is *rejected* and the original's content fingerprint is unchanged | Integration |
| AC-002E-02b | GIVEN the read-only proof succeeded WHEN Strix runs THEN it runs against the original in the proven configuration only AND the evidence records the proof (method, time, result) AND after the run the original's fingerprint is compared again; any change is reported as a protection failure and the run's results are marked failed | Integration |
| AC-002E-02c | GIVEN the write attempt was not rejected, or the gate could not run WHEN the working-copy fallback is permitted by policy (OQ-4) THEN Strix runs only on an explicit working copy AND the report states that a copy was used, its scope (included/excluded paths, size), how it was made and the environment differences from the original | Integration |
| AC-002E-02d | GIVEN the write attempt was not rejected WHEN the fallback is not permitted or the copy cannot be made THEN the attempt fails with the gap "original project cannot be proven read-only" and a next step AND Strix is not started | Integration |
| AC-002E-02e | GIVEN any outcome of the gate WHEN the report is produced THEN it never claims isolation or read-only protection without the recorded proof from AC-002E-02a AND permissions are never relaxed to make a run possible | Unit |
| AC-002E-02f | GIVEN Strix produced fixes, patches or file changes in the working copy or proposes them in output WHEN the run ends THEN nothing is written back to the original project AND proposed fixes appear only as finding text/evidence | Integration |
| AC-002E-02g | GIVEN a run used a working copy WHEN the run ends, fails or is cancelled THEN the copy is handled per policy (OQ-4) and its location and retention are reported; the original is never touched by cleanup | Integration |

### AC-002E-03: Adapter Request — Named Parameters

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-03a | GIVEN a Strix run request WHEN it is validated THEN only the Adapter's named, typed parameters are accepted (target project, target URL(s) of the running sample, mode/scope, instruction focus, time limit, grant references) AND unknown or ill-typed parameters cause refusal with the parameter named | Unit |
| AC-002E-03b | GIVEN a request whose target URL is outside the target-request grant scope (OQ-5) or whose project path is outside the project WHEN validated THEN it is refused before any attempt is registered | Integration |
| AC-002E-03c | GIVEN a request carrying free-form tool arguments, an image or version override, or a request to disable protection WHEN validated THEN it is refused | Unit |

### AC-002E-04: Egress, Budget and Cancel (requirement AC-002E-01) [B1]

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-04a | GIVEN a Strix run request WHEN it lacks a grant for "submission to models or third parties" naming the model recipient and data categories, or a grant for "requests to the target under test" covering the target scope THEN the attempt is refused before execution naming the missing purpose (AC-002C-05h) | Integration |
| AC-002E-04b | GIVEN matching grants WHEN Strix makes a model call or a target request THEN the call is allowed only if its purpose, recipient (origin) and scope are within the grant AND each call is recorded with purpose, recipient, data categories and decision | Integration |
| AC-002E-04c | GIVEN a running Strix WHEN it attempts a call to a recipient or scope not granted (other model provider, telemetry, update check, other host) THEN the call is blocked and recorded AND no silent service switch or fallback occurs | Integration |
| AC-002E-04d | GIVEN data prepared for a model call WHEN it is sent THEN only the granted data categories are included, sensitive values are minimized/masked per FEATURE-002-C AND credentials, signing keys and model keys are never included | Integration |
| AC-002E-04e | GIVEN an open verification with remaining budget WHEN Strix runs THEN its time limit is capped at the remaining time, its model usage (requests, input/output tokens) is added to the verification's usage AND reaching the time limit or any model-usage cap (OQ-6) stops the run and records it as incomplete, never as success | Integration |
| AC-002E-04f | GIVEN a Strix run in progress WHEN the verification is cancelled THEN no new model call or target request is allowed, the Strix processes/containers are terminated per AC-002C-04b/04c, and nothing is recorded after the cancel | Integration |
| AC-002E-04g | GIVEN a concluded or cancelled verification WHEN the report is produced THEN it lists Strix's grants and per-call records (or counts plus a list of distinct recipients if per-call volume exceeds a stated limit) with any blocked calls | Integration |

### AC-002E-05: Honest Failure and Normalization (AC-24)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-05a | GIVEN real Strix output from a completed run WHEN normalized THEN each finding becomes a result with location/endpoint, category, severity, Strix's evidence and run identity, attached as evidence to the checks the Guard assigned to this run | Unit |
| AC-002E-05b | GIVEN a Strix run that exits non-zero, crashes, times out, hits a model error, is blocked by egress or budget, or produces missing/unparseable output WHEN status is set THEN it is failed or incomplete with the reason, never success | Unit |
| AC-002E-05c | GIVEN a completed run with zero findings WHEN evidence is recorded THEN it states what was attempted and covered; it does not by itself make any check Pass | Unit |
| AC-002E-05d | GIVEN a failed, incomplete or cancelled run WHEN the ledger is updated THEN checks it was meant to cover remain unconfirmed unless other evidence covers them | Integration |
| AC-002E-05e | GIVEN a finding whose verification evidence comes from Strix's model reasoning only WHEN normalized THEN it is labeled as model-derived (not a confirmed exploit) unless Strix output contains a reproducible request/response proof | Unit |

### AC-002E-06: Guard Decides, Adapter Executes (AC-23 context, FR-16)

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-06a | GIVEN a verification plan WHEN Strix is used THEN the Guard (agent following the Guard skill) chooses targets, mode, scope and time limit and registers the attempt; the Adapter only validates, executes and normalizes AND there is no fixed Policy→Strix mapping | Integration |
| AC-002E-06b | GIVEN the Guard skill instructions WHEN inspected THEN they direct the cheapest sufficient method first and Strix only where rule-based/dependency tools cannot cover the check, naming the grants and budget it needs | Unit |

### AC-002E-07: Tool-Level Validation Record (requirement AC-002E-02, S-07) [B1 — NOT DONE, blocks Technical Design]

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-07a | GIVEN B1 resolved by the human (OQ-8) WHEN the Strix Adapter is designed THEN a small tool-level validation on the MVP samples (marathon registration, WebGoat) in a sandbox precedes Technical Design AND its record (`FEATURE-002-E/tool-validation/`) states Strix version and image digest, platform, model provider and data sent, read-only proof result, observed findings, time, model usage and known issues | Integration |
| AC-002E-07b | GIVEN the validation record WHEN it is read THEN it contains only observed results (no vendor claims as results) AND it states that formal-delivery evaluation (AC-28) is deferred to FEATURE-003-C | Unit |

### AC-002E-08: Status Reporting

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002E-08a | GIVEN a toolkit version that does not yet deliver the Strix Adapter WHEN `status` runs THEN Strix is reported as not provided (as today, AC-002D-08b) | Integration |
| AC-002E-08b | GIVEN a toolkit version that delivers the Adapter WHEN `status` runs THEN Strix is reported as provided with registration state, digest pre-check state, container-runtime availability, platform support, credential-reference presence (not value) and the last protection-gate result, without executing Strix or contacting any network | Integration |

## Functional Requirements

- **FR-002E-1 Registration:** Maintainer-authorized registration of one pinned Strix version and container image, verified against a toolkit official-digest table before execution; no auto pull/download/upgrade (FR-16, A-08, A-09).
- **FR-002E-2 Pre-check:** registration, digest, container runtime, platform and credential reference checked per accepted run; failure → gap + next step, nothing executed.
- **FR-002E-3 Protection gate:** tested write attempt on the original from Strix's execution environment; proven read-only or explicit working copy per policy; post-run fingerprint compare; never relax permissions; never write back (FR-17).
- **FR-002E-4 Request:** named, typed parameters only; target scope bound to grants.
- **FR-002E-5 Egress:** model calls under "submission to models or third parties", target requests under "requests to the target under test"; recipient/scope enforced per call; minimization/masking; per-call records (FR-20, E-02).
- **FR-002E-6 Budget and cancel:** time cap from remaining budget; model usage summed into the verification; cap stops run; cancel terminates run (B-01, B-08).
- **FR-002E-7 Normalization:** real output → per-check evidence; honest failed/incomplete states; zero findings ≠ Pass (AC-24).
- **FR-002E-8 Validation record and status:** tool-level validation precedes design (S-07); status reports provided only after delivery.

## Non-Functional Requirements

- **NFR-002E-1 Safety:** the original project's content is unchanged after any Strix run (fingerprint-verified); violation is a reported protection failure.
- **NFR-002E-2 Confidentiality:** no credential, signing key or model key in model payloads, records or reports.
- **NFR-002E-3 Determinism of gate:** the protection gate and pre-check do not depend on model calls or network.
- **NFR-002E-4 Bounded resources:** run time ≤ remaining budget; container resource limits stated in evidence (values decided in design).
- **NFR-002E-5 Auditability:** every grant, call decision, gate result and copy used is reproducible from the verification record.

## UI/UX Requirements

Command-line only. Refusals and gaps name the reason and one next step (consistent with FEATURE-002-B/C/D).

## Dependencies

- **FEATURE-002-B** (Adapter contract, attempt registration, two-phase failure semantics)
- **FEATURE-002-C** (budget, pause, cancel, egress grants and gate; reserves "model and target purposes, through the gate; budget" for 002-E)
- Per FEATURE-002-D's evidence, 002-B and 002-C have closing reports (not re-queried; no board access).
- **FEATURE-002-A** (verdict and ledger rules: unconfirmed checks, never Pass on unconfirmed).
- **FR-24** (signed Maintainer authorization) — as used for Trivy registration.
- **FEATURE-003-C** consumes this Adapter for formal-delivery evaluation (AC-28).
- **External:** Strix (pinned version, OQ-1), container runtime (OQ-2), model provider (OQ-3) — all blocked by B1.

## Business Rules

- **BR-01:** No isolation or read-only claim without a recorded, passing write-rejection proof.
- **BR-02:** Permissions are never relaxed to let Strix run; fallback is only an explicit, reported working copy.
- **BR-03:** No fix is ever written back to the original project.
- **BR-04:** A grant for one purpose never authorizes another; model submission always needs its own grant naming recipient and data (BR-06 of 002-C).
- **BR-05:** Failed, incomplete, blocked or cancelled runs are never success; zero findings alone never make Pass.
- **BR-06:** Nothing is auto-downloaded, pulled, upgraded or relaxed on a failed pre-check.
- **BR-07:** The Guard decides; the Adapter executes. Strix never chooses its own target outside the granted scope.

## Edge Cases & Constraints

- Original on a filesystem where read-only enforcement is unavailable (e.g. some mounts) → gate fails → fallback or refusal (AC-002E-02c/02d).
- Gate passes but Strix still changes the original (enforcement gap) → post-run fingerprint mismatch → protection failure reported, results failed (AC-002E-02b).
- Project contains secrets → copy and model payload exclude/mask them; masking failure blocks the call.
- Very large project → copy size/time counted in budget; copy scope reported.
- Strix retries model calls aggressively → each retry is a call, recorded and charged.
- Target sample not running or unreachable → run incomplete with reason, not "no findings".
- Model provider rate limit/outage → incomplete; no switch to another provider.
- Cancel during copy creation or gate → nothing started; partial copy handled per OQ-4.
- Image present but registered digest differs (re-tagged) → pre-check fails.
- Concurrent verifications on the same project → each run has its own copy/gate record.

## Out of Scope

- Downloading or running Strix, obtaining model keys or sending data to model services in this task (B1).
- Formal-delivery evaluation and measurement bar (AC-28, FEATURE-003-C).
- Testing real systems not authorized (S-07: only MVP samples and safety comparison samples).
- Applying or proposing code fixes to the original; heavy DLP; network sandbox beyond what the protection and egress gates need.
- Opengrep and Trivy Adapters; temporary check scripts (FEATURE-002-F).

## Technical Considerations

- WHAT, not HOW: the design must show how write rejection is proven from Strix's own execution environment, how per-call egress enforcement is achieved for an autonomous tool whose calls the toolkit does not make itself, and how model usage is obtained from the run.
- Docker and model credentials (D-17: credential references, allowed environment variables, isolated HOME, binary identity) and copy/isolation failure handling (inventory §9.3 item 5) are open for design.
- Test dependencies, images, samples, resources, cleanup and platforms (S-08, pending) must be stated without automatic installs or deletion of the whole sandbox.
- Integration tests with the real tool are possible only after B1; contract tests may use a stand-in that emulates Strix output and calls.

## Open Questions (pending decisions)

| ID | Question | Options | Recommendation |
| --- | --- | --- | --- |
| OQ-1 | Strix version and provenance | A: latest stable release from the official repository, pinned by tag + digest; B: a specific older release already used by others; C: build from source at a pinned commit | **A**, chosen during tool-level validation from the official source only; the table records exactly one version |
| OQ-2 | Container requirement and image digest | A: require Docker-compatible runtime and the official image pinned by digest; B: allow Docker or Podman; C: no container (host install) | **A** — the container is also the natural boundary for the read-only proof; digest from the official registry recorded at registration |
| OQ-3 | Model provider, credentials and allowed data | A: one provider named in the grant, key via credential reference only, data = sample code + target responses; B: user's host agent model only (not egress); C: local model only | **A** for MVP with data limited to the MVP samples; keep C as later option; B is not possible if Strix calls models itself |
| OQ-4 | Read-only proof method and copy fallback policy | A: read-only mount of the original + tested write; fallback copy only after explicit user confirmation per run; B: same proof, fallback copy automatic but reported; C: always use a copy (never the original) | **A** — strongest guarantee, user sees the trade-off; copy kept until verification concludes, then removed with location reported |
| OQ-5 | Target network scope | A: only localhost/loopback URLs of the running sample; B: any host named in the target grant; C: local network ranges | **A** for MVP (only authorized MVP samples, S-07) |
| OQ-6 | Model-token budget accounting | A: sum reported usage and add an optional per-verification token cap that stops the run; B: count only (no cap), time budget bounds cost; C: count model calls as extra attempts | **A** — cost control is an explicit goal; cap default chosen after validation shows typical usage |
| OQ-7 | Supported platforms | A: Linux x86-64/arm64 only (as Trivy); B: Linux + macOS with Docker Desktop; C: all three incl. Windows | **A** for MVP; macOS read-only semantics via Docker Desktop need separate proof |
| OQ-8 | How the tool-level validation gets authorized (B1) | A: human authorizes a one-off sandbox validation with a named provider, a key they supply and MVP sample data only; B: validation with a local model only; C: defer Strix and deliver the Adapter later | **A** — smallest step that produces real evidence; until decided, Technical Design stays blocked |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| FR-16, A-08, A-09, AC-24 (pre-check, no download); D-17; FR-002E-1/2; NFR-002E-2 | US-03 | AC-002E-01a…01d | N/A | Integration | covered |
| FR-17, AC-23; FR-002E-3; NFR-002E-1; BR-01…03 | US-02 | AC-002E-02a…02g [B1] | N/A | Integration | covered; real-tool proof after B1 |
| FR-16 (typed parameters); FR-002E-4; BR-07 | US-01 | AC-002E-03a…03c | N/A | Unit/Integration | covered |
| AC-002E-01 (req.), FR-20, E-02, B-01, B-08; FR-002E-5/6; BR-04 | US-04 | AC-002E-04a…04g [B1] | N/A | Integration | covered; real-tool proof after B1 |
| AC-24 (honest failure, normalization); FR-002E-7; BR-05 | US-05 | AC-002E-05a…05e | N/A | Unit/Integration | covered |
| FR-16 (Guard decides); AC-23 context | US-01 | AC-002E-06a…06b | N/A | Integration/Unit | covered |
| AC-002E-02 (req.), FR-18, S-07; AC-28 → 003-C | US-01 | AC-002E-07a…07b [B1] | N/A | Integration | **not done — blocked by B1** |
| FR-002E-8 (status) | US-03 | AC-002E-08a…08b | N/A | Integration | covered |

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-002E-07a/07b | None — blocked by B1 | not started | not measured |
| other AC-002E-* | Planned per Test Type; no tests yet | planned | not measured |

## Context and Verification Evidence

- **Sources (read selectively, read-only):** `x-ipe-docs/requirements/requirement-details.md` (SHA-256 `1747efe61b9c5cf1…`; FEATURE-002-E entry, FR-16/17/18/20, AC-23/24/28, G-02/G-05); feature inventory v2 (`f36a27538196f351…`; E-02, B-01, B-08, S-07, S-08, D-17); FEATURE-002-D specification (`229cc76e4ff651a7…`; structure, AC-002D-08b); FEATURE-002-C specification (`fca9f235384ee2b6…`; four egress purposes, AC-002C-01/04/05, BR-06).
- **Not done:** no web fetch, no code read, no Strix download/run, no model keys, no data to model services (B1). No board or Git operations.
