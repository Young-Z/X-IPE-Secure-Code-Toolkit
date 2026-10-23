# Feature Specification: Temporary Check Scripts

> Feature ID: FEATURE-002-F  
> Epic: EPIC-002 (Guard: Verification, Adapters & Evidence)  
> Phase: Phase 2 (P2)  
> Version: v1.3.1  
> Status: Confirmed (v1.3.2) — confirmed by the DAO representative (DAO-014 refinement; DAO-018/DAO-019 technical design) under the human's delegation; human decision B12 = A. v1.3.2 is editorial only. Implementation gate: TASK-083 (CR-077 implementation) implemented and accepted  
> Last Updated: 10-23-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-23-2026 | Initial draft specification from FR-19 (A-13…A-17, A-18 open), preliminary AC-002F-01…03 and the binding workflow DAO-001 / closing DAO-001 gates | N/A |
| v1.1 | 10-23-2026 | Applied DAO-007 (DAO representative under the human's delegation, `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md`; not the human): OQ-01 A, OQ-02 A, OQ-03 A, OQ-04 A only (Maintainer fallback rejected), OQ-05 C, OQ-06 B as amended, OQ-07 A, OQ-09 A as amended, OQ-08 split into (i) attempt mapping, (ii) additive `helper` Reviewer subject (FR-002A-4 extension point) and (iii) human blocker **B12**. Applied every finding of the independent specification review of v1.0 (verdict FAIL): `generation` attempt for authoring; unchanged 002-A ledger semantics (helper = auxiliary method); link-free race-resistant input copy and safe result handling; canonical runtime configuration verified field-by-field; numeric limits; offline conformance suite; untrusted-content rules; clean-result rule; snapshot binding to the verification's target version; Python version, static rules and result schema; consent wording. Reworded 01b, 02a…02d, 03a…03f, 04a…04h, 05a…05d, 06a, 06b, 07a…07f, 08a, 08c, 09a, 09b, 10a, 10c (01a, 01c, 01d, 02e, 05e, 08b, 08d, 08e, 09c unchanged); appended 02f, 02g, 03g, 03h, 04i…04p, 05f, 05g, 06c, 07g, 08f, 10d, 11a…11f, 12a…12d. No ID renumbered or reused. ACs that need B12 are marked "conditional on B12" | N/A (refinement decision, not a CR) |
| v1.2.1 | 10-23-2026 | Sage (lifecycle owner) applied the v1.2 re-review nit (PASS-WITH-NITS): stale B12 wording in AC-002F-03c, 03h and 10a now names the human-approved 002-C Change Request TASK-077 instead of the resolved decision B12. Editorial only | N/A |
| v1.2 | 10-23-2026 | Applied the human decision B12 = A (2026-10-23 20:38, `x-ipe-docs/dao/26-10-23/human_decisions.md`), applied by Sage: an additive Change Request on delivered FEATURE-002-C adds the Reviewer coverage item `helpers` (TASK-077). Removed the "conditional on B12" marker from AC-002F-03b…03d, 03f, 03h, 04a, 04e, 04f, 04i, 04o, 05g, 06a, 07a, 07c, 07d (criterion text unchanged), which now depend on the 002-C CR (TASK-077); AC-002F-05f marked "Not applicable — human chose B12=A" (ID kept). Added the 002-C CR dependency; numeric limits L-01…L-12 remain proposed values pending the independent re-review. No other AC change | N/A (human decision applied; the CR is on FEATURE-002-C, TASK-077) |
| v1.3 | 10-23-2026 | Clarifications decided by the DAO representative under the human's delegation (DAO-014, technical design, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`; not the human), applied by the TASK-081 design worker for Sage: (1) AC-002F-07c — a clean helper result counts only when its scanned files cover the whole check object within the targets; partial coverage counts as a failed auxiliary method naming the uncovered parts (stricter than before; 002-A ledger rules stay unchanged, BR-08); (2) FR-002F-5 — the container environment is exactly the Maintainer-registered image's own environment (recorded and shown at registration; credential-like values refused) overlaid by the four toolkit variables, with no other variable. No other AC, FR or limit changed; no ID renumbered. Optional human CR candidates recorded by DAO-014: 002-A engine support for partial-coverage evidence; helper-aware default budget | N/A (DAO clarification within delegation, not a CR) |
| v1.3.2 | 10-23-2026 | Sage (lifecycle owner) applied the design re-review nits (PASS-WITH-NITS): edge-case line on narrower read scope aligned with AC-002F-07c (no per-file claim); FR-002F-5 command wording aligned with the DAO-018-approved PID-1 launcher (the script still runs as `<interpreter> -I -B /helper/script.py`). Editorial only | N/A |
| v1.3.1 | 10-23-2026 | Correction decided by the DAO representative under the human's delegation (DAO-018, technical design, `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`; not the human), applied by the TASK-081 design worker for Sage: AC-002F-07c v1.3 over-claimed ("the check stays `unconfirmed` unless other accepted evidence covers it" — wording introduced by DAO-014; delivered 002-A counts any usable evidence on any part of the check object). 07c now says partial coverage contributes failed auxiliary-method evidence naming the uncovered files, the check state is exactly what the unchanged 002-A rules compute, other evidence may make the check `met` without covering the named files, and the helper never counts for the uncovered files. Added the honest limit that Guard does not enforce per-file coverage of the check object for any method. No other AC, FR or limit changed. Optional human CR candidate (unchanged): 002-A engine support for partial-coverage evidence | N/A (DAO correction within delegation, not a CR) |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
| --- | --- | --- | --- | --- | --- |
| N/A | CLI | N/A | No product UI: Guard skill text, `secure-code guard` commands, run-folder files and the Markdown/structured Guard report. Bounded discovery: the FEATURE-002-F section of the requirement and EPIC-002 link no mockup. | N/A | N/A |

## Overview

Sometimes no existing method can produce the evidence a check in the Guard check plan needs: semantic review (reading) is not enough and no delivered Adapter (Opengrep, Trivy) covers the object. FEATURE-002-F lets the Guard agent close such a **real gap** with a **temporary check script** ("helper"): a one-off Python script bound to one check-plan check that states its check goal, read scope and judgement basis (A-13), and passes three layers of constraint before any result counts (A-14):

1. **Syntax and logic checks.** Exact syntax check by the registered image's interpreter (compile only, never executed) and static allow/deny rules. The static rules are defence in depth only; they never make a script "safe".
2. **Independent review with known positive and negative samples** by the existing read-only Guard Reviewer (FEATURE-002-A), using an additive `helper` subject in the shared Reviewer record (FR-002A-4 extension point); new helpers are reviewed in a batch (A-15).
3. **Real execution limits enforced by the toolkit**: the script runs only inside a **local disposable container with the network disabled**, started by the toolkit on a runtime that passed an offline conformance suite, with a canonical configuration verified field-by-field from the runtime's own inspect output before start. It reads only a read-only, link-free copy of its declared scope bound to the verification's target version, writes only a bounded results area, and is bounded in processes, memory, CPU, files, output and time, inside the 002-C budget and cancel (A-15; DAO-001).

**Review is not authorization** (A-16). Execution additionally needs a **user grant typed at an interactive terminal** that names the verification and the reviewed helpers' script and sample SHA-256s. The grant is recorded cooperative consent, not a security boundary: the toolkit cannot prove a person rather than an agent typed it. The security boundary is the enforced container limits. Agent-only flows do not run helpers.

When any limit cannot be enforced or proven — no runtime, no passing conformance, no registered local image, no grant, failed review, budget, pause or cancel — the script is **not executed** and the gap is reported. This is the intended behaviour, not a workaround (A-16; DAO-001). A helper that does not run or fails is a **failed auxiliary method**; the check's state is computed by the unchanged 002-A minimum-evidence and substitution rules (AC-002A-04j). A successful exit is never evidence, and "no findings" is not by itself sufficiency (A-16).

Helpers are artifacts of one verification run: kept in its private run folder under the existing retention, never written into formal knowledge, rule folders, skills or a `checks/` folder, never reused across runs and never published (A-17, A-18).

All helper work fits the existing model: plan method (002-A), `generation` and `helper` attempts under the shared budget (002-C), `runtime` evidence and findings with a helper source in the one Guard report, deterministic verdict. No new model API, key, network purpose or third-party service. Scripts are written by the host agent session already in use.

**B12 — decided by the human (2026-10-23 20:38): A.** Letting a `reviewer` attempt cover helpers changes the delivered 002-C Reviewer coverage (AC-002C-01c/01d: findings and N/A decisions only). The human approved an additive Change Request on FEATURE-002-C (TASK-077) adding the coverage item `helpers` (first coverage planned, re-coverage extra; existing kinds, records and tests unchanged). The review and execution ACs therefore apply unconditionally, but **002-F implementation cannot complete before the 002-C CR (TASK-077) is implemented**. The B12-declined path (AC-002F-05f) is not applicable.

## User Stories

- **US-01 (Developer):** As a developer, I want Guard to check a requirement that no existing method covers with a small purpose-built script, so that a real gap becomes evidence instead of silently staying unchecked (A-13, G-02).
- **US-02 (Developer / Maintainer):** As a developer, I want every helper script to state what it checks, what it reads and how it judges, and to prove itself on known positive and negative samples under independent review, so that I can trust its result (A-13, A-14).
- **US-03 (Developer / Owner):** As the owner, I want helper scripts to run only under limits the toolkit actually enforces and has proven on my runtime — no network, read-only link-free input, bounded results-only writes, bounded processes, resources, output, time and budget — and only after I grant it, so that ad-hoc code never risks my project or data (A-15, A-16, DAO-001).
- **US-04 (Developer):** As a developer, I want a helper that cannot be run safely to be reported as a gap rather than run anyway or treated as passed, so that the verdict never claims more than was checked (A-16, G-02).
- **US-05 (Developer / upstream agent):** As a report reader, I want helper findings and evidence to be clearly labelled as temporary helper results, distinct from Adapter and semantic findings, bound to the exact inputs they saw and auditable, so that I can weigh them correctly (A-16, FR-22).
- **US-06 (Maintainer):** As a Maintainer, I want helper scripts to stay run-only artifacts and the helper image to be one I registered, so that unreviewed ad-hoc code never becomes formal knowledge or a published tool (A-17, OQ-03).

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 | Requirement G-02; FR-19 (A-13…A-17; A-18 decided by DAO-007); preliminary AC-002F-01…03 | Developer, Maintainer, upstream agent | Real coverage gaps can be checked without unsafe ad-hoc code; no misleading "pass" from a helper that was not run, not reviewed, merely exited cleanly or reported no findings | All required: (G-02.1) gap-bound auxiliary helper method; (G-02.2) declaration + exact syntax + static rules; (G-02.3) independent review with known samples (needs the 002-C CR, TASK-077); (G-02.4) consent grant + conformance-proven, inspect-verified container limits inside 002-C budget/cancel; (G-02.5) non-execution with reported gap; (G-02.6) labelled, snapshot-bound results under unchanged 002-A ledger rules; (G-02.7) run-only retention; (G-02.8) untrusted-content handling | Planned scenario: on a conformance-passing local runtime with a registered local image, a gap check gets a helper whose positive samples are detected and negative samples are clean; after the user's grant it runs on a link-free read-only snapshot bound to the target version, and its labelled finding appears in the report. The same request with no runtime, no conformance or no grant leaves the helper a failed auxiliary method with a reported gap and no execution. Nothing is written outside the run folder/report files | Not auto-promoted to formal knowledge; not the FR-29 sandbox; no new network/model/keys/services; Guard never fixes; grant is not a security boundary | AC-002F-01a…12d | not measured |

## Acceptance Criteria

Preliminary breakdown ACs map as: AC-002F-01 → AC-002F-01a…01d, 02a…02g, 03a…03h; AC-002F-02 → AC-002F-04a…04p, 05a…05g, 11a…11f; AC-002F-03 → AC-002F-08a…08f.

Test Type gives the primary type (Unit, Integration) followed by the check style: `black-box` (through the `secure-code` command line and files only), `conformance` (offline suite against a real local runtime and registered local image) or `skill-text` (inspection of the Guard skill package text). Automated orchestration tests use a fake container runtime; **enforcement claims are accepted only from the conformance suite on a real runtime**. ACs that need Reviewer coverage of helpers (03b…03d, 03f, 03h, 04a, 04e, 04f, 04i, 04o, 05g, 06a, 07a, 07c, 07d) depend on the FEATURE-002-C CR (TASK-077); AC-002F-05f is not applicable (human chose B12=A). Numeric limits L-01…L-12 are defined under Functional Requirements.

### AC-002F-01: When a Helper May Be Proposed (real gap, tied to the check plan)

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-01a | GIVEN an open verification with a recorded check plan WHEN a helper script is requested for a check THEN it is accepted only if it names exactly one existing check of the plan AND the check's methods include it as a helper method (planned, or added by a recorded method change) AND a request naming no check, an unknown check or a check of another verification is refused with the reason | Integration · black-box | Refusal reason names the missing/unknown check; no helper file is stored |
| AC-002F-01b | GIVEN a helper method added to a check WHEN it is recorded THEN it is recorded as an auxiliary method (`required: false`, kind `runtime`, a helper method name) AND a method choice or method change records the methods considered, why existing methods (semantic review, delivered Adapters) cannot provide the check's minimum evidence, and the gap the helper covers AND a helper method recorded as required or without this gap reason is refused | Integration · black-box | Stored plan shows the auxiliary helper method and gap reason; required helper or missing reason → refused |
| AC-002F-01c | GIVEN the Guard skill package WHEN inspected THEN it tells the agent to propose a helper only for a real gap of a planned check, never for convenience, never instead of an available Adapter that covers the object, and never to fix, rewrite or remediate targets | Unit · skill-text | Skill text contains each of these rules |
| AC-002F-01d | GIVEN a helper method added after planned work started WHEN attempts are counted THEN it follows the 002-C rules unchanged (a method added later costs extra attempts; nothing is reset) | Integration · black-box | Extra-attempt count increases exactly as for any later-added method |

### AC-002F-02: Declaration, Syntax and Static Checks

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-02a | GIVEN a helper submission WHEN it is stored THEN it carries the bound check, the check goal, the read scope (target paths it may read, each inside a verification target), the judgement basis (what output means a finding and what means no finding), the language `python` and the script text AND a submission missing any of these is refused | Integration · black-box | Stored declaration has all fields; each missing field → refusal naming it |
| AC-002F-02b | GIVEN a declared read scope WHEN validated THEN every entry is a project-relative path inside a verification target AND every path component of every entry is an existing directory or regular file that is not a symbolic link, junction or other link AND no entry escapes with `..`, an absolute path or a device/special file AND a scope exceeding L-05 is refused AND anything else is refused with the offending entry | Integration · black-box | Link in any component, escape, special file or oversize → refused; nothing stored |
| AC-002F-02c | GIVEN a helper script and the registered image's recorded CPython version (L-12) WHEN syntax is checked THEN the toolkit compiles it (never executes it) with that image's interpreter inside a container under the canonical configuration (AC-002F-04b) AND a syntax error refuses the helper with the parser message AND an image version outside L-12, an unknown version or an unavailable compile probe refuses the helper with that reason, never assuming a version | Integration · black-box | Syntax error/version mismatch → refused with reason; no script execution; probe run recorded |
| AC-002F-02d | GIVEN a syntactically valid script WHEN the static rules are checked with the toolkit's parser THEN imports are limited to the allowlist of FR-002F-3 AND denied modules, denied calls and names, dunder attribute access, star or relative imports and writes other than the results file are refused with the rule name AND a script the toolkit's parser cannot parse is refused (fail closed) AND the record states that static rules are defence in depth, not proof of safety | Unit · black-box | Each listed violation → refusal naming the rule; accepted script stored with its SHA-256 |
| AC-002F-02e | GIVEN syntax and static checks WHEN they pass THEN the helper is only "checked", not "reviewed" and not "executable" AND its state is shown as such | Integration · black-box | Helper state after checks = checked |
| AC-002F-02f | GIVEN a script WHEN checked THEN a script over L-03 or an AST over L-04 (nesting depth or node count) is refused before compiling or rule checking | Unit · black-box | Oversize/over-deep script → refused; no probe run |
| AC-002F-02g | GIVEN a verification WHEN a helper is submitted beyond L-01 THEN it is refused | Integration · black-box | Sixth helper → refused |

### AC-002F-03: Samples and Independent Review

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-03a | GIVEN a checked helper WHEN samples are attached THEN it has positive samples (must produce a finding) and negative samples (must produce none) within L-02, each with a recorded origin: a formal rule example only when its safe/unsafe label is explicit, otherwise a synthetic fixture written for this check AND each sample is copied into the staging input (knowledge folders are never mounted) AND a verification target file used as a sample, a missing positive or negative sample or an unlabeled formal example used as one is refused | Integration · black-box | Refusals as listed; origin and SHA-256 recorded per sample |
| AC-002F-03b | GIVEN a granted helper (AC-002F-04o) WHEN its samples are run THEN each sample runs in its own container under the same canonical configuration and limits as the target run AND sample outcomes are recorded as helper lifecycle data that does not finish the helper attempt AND a positive sample without a finding, a negative sample with a finding, or a failed sample run fails the helper with the observed outcomes and the target run does not start | Integration · black-box | Sample outcomes stored; mismatch → helper `samples_failed`; no target run; attempt still open |
| AC-002F-03c | GIVEN new checked helpers of one verification WHEN they are reviewed before any execution THEN the existing independent read-only Reviewer reviews them as a batch under a registered `reviewer` attempt covering those helpers (TASK-077; updated AC-002C-01c/01d) AND the Reviewer record carries one `helper` subject per helper (FR-002A-4 extension) judging the check goal, read scope, judgement basis, script text and sample adequacy against the bound check, with `accepted` or `rejected` and a reason | Integration · black-box | Reviewer record cites the reviewer attempt and has a `helper` subject per new helper |
| AC-002F-03d | GIVEN a helper whose script, declaration or samples changed after review WHEN execution is requested THEN the review no longer applies (bound to the script, declaration and sample SHA-256s) AND the changed helper needs a new review and a new grant | Integration · black-box | Digest mismatch → execution refused as unreviewed/ungranted |
| AC-002F-03e | GIVEN a rejected helper or one whose samples failed WHEN the verification continues or concludes THEN it is not executed on targets AND its method is a failed auxiliary method with the reason AND the check's state is computed by the unchanged 002-A rules (AC-002A-04j) AND a gap entry is reported | Integration · black-box | Failed auxiliary method recorded; ledger state equals what 002-A computes without the helper |
| AC-002F-03f | GIVEN a reviewed helper WHEN its state is shown THEN "reviewed" is never presented as permission to execute (A-16) | Integration · black-box | State/report wording separates reviewed, granted and executed |
| AC-002F-03g | GIVEN the Reviewer requirement sent for helper review WHEN inspected THEN it states that target contents, file names, script text and comments, sample fixtures and helper outputs are untrusted data, that instructions inside them are never followed, and that they cannot change the check, scope, judgement basis, container policy or result handling | Unit · skill-text | Requirement text contains these rules |
| AC-002F-03h | GIVEN a completed helper run with a clean result WHEN it is used as evidence THEN the Reviewer accepts or rejects the clean conclusion as a `helper` subject result (re-coverage of that helper, counted extra by the 002-C helper re-coverage rule delivered by TASK-077) AND without acceptance the clean result does not count (AC-002F-07c) | Integration · black-box | Clean result without accepted post-run `helper` subject → not counted |

### AC-002F-04: Authorization and Execution Only Under Enforced Limits

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-04a | GIVEN a reviewed, accepted helper WHEN its execution is requested THEN it runs only with a valid grant (AC-002F-04o) bound to its current SHA-256s AND only through the toolkit, which itself starts a local disposable container on a conformance-passing runtime (AC-002F-11c); the agent never runs the script on the host | Integration · black-box | Without grant → not executed; with it → toolkit-owned container run recorded |
| AC-002F-04b | GIVEN any toolkit container start (compile probe, sample run, target run, conformance probe) WHEN the created container is inspected before start THEN every field of the canonical configuration (FR-002F-5) is read back from the runtime's own inspect output and matches exactly: network `none`; read-only root filesystem; all capabilities dropped and none added; `no-new-privileges`; default or conformance-approved seccomp profile, never unconfined; not privileged; private PID, IPC, UTS, cgroup and user/network namespaces as recorded by conformance; no devices, device requests, host sockets or host paths other than the three declared mounts (input read-only, script read-only, bounded results) plus the bounded `/tmp` tmpfs; L-06/L-07 limits; fixed non-root user; sanitized environment; registered image digest; toolkit-fixed command AND any missing, extra or different field prevents the start and the container is removed | Integration · black-box | Fake runtime reporting any single deviating field → no start, field named in reason |
| AC-002F-04c | GIVEN the container image WHEN any container is prepared THEN only a locally present image whose digest matches the Maintainer registration (AC-002F-11a) is used AND it is never pulled, built or loaded from the network | Integration · black-box | Missing/mismatched image → not executed; no pull/build command issued |
| AC-002F-04d | GIVEN any helper container run WHEN it ends THEN every target and context file is byte-identical to before AND the original project was never mounted (only the snapshot copy) AND 002-A AC-002A-08a holds | Integration · black-box | Target digests equal before/after; recorded mounts contain no project path |
| AC-002F-04e | GIVEN a helper container run WHEN its time limit is set THEN it is L-10, capped by the remaining verification time (as 002-C AC-002C-01g) AND a run exceeding it is terminated and recorded as a failed method, never as a clean result | Integration · black-box | Cap recorded; timed-out run → failed method |
| AC-002F-04f | GIVEN a helper container in progress WHEN the user cancels the verification THEN the toolkit stops and removes the container it owns, claims termination only after the runtime reports it stopped, and otherwise reports termination as not confirmed AND nothing recorded afterwards changes the result (002-C cancel) | Integration · black-box | Cancel → container stopped/removed or "termination not confirmed" |
| AC-002F-04g | GIVEN an exhausted budget or a paused verification WHEN a compile probe, sample run or target run is requested THEN it is refused like any other new work AND the helper becomes a failed auxiliary method with that reason | Integration · black-box | Refusal reason budget/paused; no container start |
| AC-002F-04h | GIVEN any helper container WHEN it finishes, fails or is cancelled THEN the container, the snapshot copy and the results staging are removed and only normalized records remain in the run folder | Integration · black-box | No container, staging or raw result file remains |
| AC-002F-04i | GIVEN a granted helper immediately before its target run starts WHEN the snapshot is built THEN a manifest lists every copied file's project-relative path, size and SHA-256 computed from the copied bytes AND each file matches the target version recorded when the verification was opened (002-A target digests) AND any mismatch, missing or added file refuses the run with "target changed since open" AND the manifest digest is bound to the helper attempt, evidence and audit | Integration · black-box | Modified target after open → run refused; evidence carries manifest digest |
| AC-002F-04j | GIVEN the snapshot copy WHEN files are read THEN each is opened without following links (every component checked), confirmed a regular file on the opened handle, read once and hashed from those bytes AND a link, special file, path change during copy or L-05 excess aborts the copy and the run | Integration · black-box | Swapping a file for a symlink during copy → run refused; no link in snapshot |
| AC-002F-04k | GIVEN a finished run WHEN results are collected THEN the toolkit opens only the expected `result.json` in the ephemeral results staging, without following links and beneath that staging, confirms a regular file owned by the container user within L-08 AND any other file, link, special file, directory, wrong owner or excess size/count makes the method failed AND only the normalized, masked record is persisted, never raw helper files | Integration · black-box | Extra file/link/oversize result → failed method; run folder contains no raw result file |
| AC-002F-04l | GIVEN a running helper WHEN it exceeds memory, PIDs, open files, CPU-time-bounded wall time, `/tmp` size or results size (L-06…L-08, L-10) THEN it is terminated or its writes fail, AND the method is failed naming the limit AND no oversized output is retained | Integration · conformance | Each limit probe → failed method naming the limit; nothing beyond limit stored |
| AC-002F-04m | GIVEN stdout and stderr of any helper container WHEN captured THEN each is read up to L-09 only, used only as masked diagnostics and never as evidence AND exceeding L-09 terminates the run, records "output limit exceeded" and retains none of the excess | Integration · black-box | Flooding stdout → terminated, failed method, stored diagnostics ≤ L-09 |
| AC-002F-04n | GIVEN a scope or sample set over L-02/L-05 WHEN execution is prepared THEN it is refused before any container starts AND the helper is a failed auxiliary method with the limit named | Integration · black-box | No container start; reason names limit |
| AC-002F-04o | GIVEN reviewed, accepted helpers WHEN the user runs the additive grant command at an interactive terminal THEN it shows the verification and, per helper, the check, check goal, read scope and script/declaration/sample SHA-256s, and records a grant naming that verification bound to exactly those SHA-256s AND a non-interactive invocation is refused AND a changed or newly added helper needs a new grant AND no egress purpose is created | Integration · black-box | Non-tty → refused; grant record lists digests; changed helper → grant invalid |
| AC-002F-04p | GIVEN the grant WHEN described in the skill text, the grant command output and the report THEN it is called recorded cooperative consent that the toolkit cannot prove was given by a person, never a security boundary, AND the report names the enforced container limits as the security boundary | Unit · skill-text | Wording present in skill, command output and report |

### AC-002F-05: Non-Execution and Gap Reporting

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-05a | GIVEN no usable local container runtime (absent, not running, not accessible, no passing conformance record, or unable to enforce a required setting) WHEN a compile probe, sample run or target run would start THEN the script is not executed in any other way (no host fallback) AND the reason is recorded | Integration · black-box | No process of the script is started; reason recorded |
| AC-002F-05b | GIVEN a helper that was not executed or failed for any reason (limits, conformance, image, grant, review, samples, budget, pause, cancel, results) WHEN the verification is concluded THEN the helper method is a failed auxiliary method with the reason AND the check's state is computed by the unchanged 002-A minimum-evidence and substitution rules (AC-002A-04d/04e/04j) AND no helper-specific state override exists | Integration · black-box | Ledger equals the 002-A computation with the helper recorded as failed auxiliary method |
| AC-002F-05c | GIVEN a non-executed or failed helper WHEN the report is produced THEN a gap entry shows the check, the helper's check goal and the reason AND the verdict follows the unchanged 002-A verdict rules | Integration · black-box | Report gap entry present; verdict equals 002-A computation |
| AC-002F-05d | GIVEN the Guard skill package WHEN inspected THEN it states that not running a helper when limits cannot be enforced is the intended behaviour, that the agent must not run the script elsewhere or by other means, that review is not execution authorization, and that agent-only flows take the non-execution path | Unit · skill-text | Skill text contains these rules |
| AC-002F-05e | GIVEN a host without a container runtime WHEN the full helper flow is exercised black-box THEN it completes on the non-execution path with a reported gap and no error other than the stated reason | Integration · black-box | Conclude succeeds; report shows gap |
| AC-002F-05f | GIVEN B12 declined WHEN a checked helper would be reviewed or executed THEN review and execution are unavailable, the helper is a failed auxiliary method with "helper review unavailable" AND the gap is reported (non-execution path only) | Not applicable — human chose B12=A | Not applicable — human chose B12=A |
| AC-002F-05g | GIVEN a verification where no grant is given (agent-only or non-interactive flow) WHEN it concludes THEN every reviewed helper is a failed auxiliary method with "not granted" AND the gap is reported | Integration · black-box | Reason "not granted"; no target run |

### AC-002F-06: Budget, Attempts and Model Usage (002-C rules unchanged)

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-06a | GIVEN a granted helper WHEN it is executed THEN each result-producing execution (its sample runs and target run) is covered by its own registered `helper` attempt for the (check, helper method) pair AND sample outcomes do not finish the attempt AND the first result record citing it finishes it under the delivered single-use lease rule AND a re-execution needs a new attempt counted by the unchanged 002-C repeat rules AND an attempt whose helper was rejected or not executed is reported as unfinished, never finished AND a record citing no, a foreign, a finished or a wrong-kind attempt is refused | Integration · black-box | Refusals as listed; second execution consumes an extra attempt; open attempts listed unfinished |
| AC-002F-06b | GIVEN helper container runs and compile probes WHEN time is consumed THEN their running time counts in the verification's consumed time AND `helper` attempts report model usage "not applicable" (no model runs in the container) | Integration · black-box | Consumed time includes run time; helper attempt usage n/a |
| AC-002F-06c | GIVEN the host agent writes a helper WHEN authoring starts THEN it registers an existing `generation` attempt covering the (check, helper method) pair, carrying host-reported model usage or `unknown`, finished by the helper submission record AND, under the unchanged 002-C rules, the later `helper` attempt covering the same pair counts as one extra attempt, and every re-authoring is a new `generation` attempt counted the same way | Integration · black-box | Submission without a `generation` attempt → refused; extra-attempt counts as stated; usage summed or unknown |

### AC-002F-07: Result Handling and Labelling in the Guard Report

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-07a | GIVEN a completed helper run WHEN its results are recorded THEN evidence is kind `runtime` with the helper's own method name (never `opengrep`, `trivy` or another reserved Adapter name) AND findings carry a helper source distinct from `semantic` and Adapter sources AND both reference the helper id, script SHA-256 and snapshot manifest digest | Integration · black-box | Reserved name/source → refused; stored items carry id + digests |
| AC-002F-07b | GIVEN helper output WHEN `result.json` is missing, empty, unparseable, not schema-valid or reports `status: error` THEN the helper method is a failed method, never a clean result AND an exit status alone (zero or not) is never evidence | Integration · black-box | Exit 0 without valid result → failed method; no "no findings" claim |
| AC-002F-07c | GIVEN a schema-valid helper result with no findings WHEN the check is concluded THEN it counts as `runtime` evidence only if the samples passed, the Reviewer accepted the helper and its clean conclusion (`helper` subject), and only when the files the result lists as scanned cover every file of the check object within the targets (as at open); partial coverage contributes failed auxiliary-method evidence naming the uncovered files, and the helper never counts for the uncovered files AND it never substitutes a required Adapter method AND "no findings" alone is never treated as sufficiency; the check state is then exactly what the unchanged 002-A rules compute from all recorded evidence (002-A counts any usable evidence on any part of the check object, so other evidence may make the check `met` without covering the named files) (v1.3.1, DAO-018 TD) | Integration · black-box | Partial coverage alone → failed auxiliary method naming the uncovered files and the check `unconfirmed`; partial coverage + other evidence on a scanned file only → the state the unchanged rules compute (`met`) and the report still names the uncovered files; full coverage + acceptance → usable `runtime` evidence; required failed Adapter → still `unconfirmed` |
| AC-002F-07d | GIVEN a helper finding that affects the verdict WHEN concluded THEN it is re-checked by the independent Reviewer as an existing `finding` subject (002-A) AND an unconfirmed or rejected helper finding does not drive Fail on its own | Integration · black-box | Verdict-affecting helper finding has a Reviewer `finding` decision |
| AC-002F-07e | GIVEN the Markdown and structured report WHEN produced THEN a "Temporary helper checks" part lists every helper with id, bound check, check goal, read scope, judgement basis, script SHA-256, sample origins and outcomes, Reviewer decisions, grant (as recorded cooperative consent), conformance record, snapshot manifest digest, execution state (executed / not executed + reason), enforced limits, time used and findings, each marked "temporary, run-only — not a formal rule or Adapter" AND both outputs come from the same recorded data | Integration · black-box | Both reports contain the same helper entries and the marking |
| AC-002F-07f | GIVEN helper excerpts, diagnostics or script text WHEN stored or reported THEN they are masked like all Guard evidence (002-C masking) | Integration · black-box | Seeded secret appears masked |
| AC-002F-07g | GIVEN `result.json` WHEN validated THEN it must match the FR-002F-8 schema exactly (no unknown keys, JSON depth ≤ L-08, counts and string lengths within L-08, every path in the snapshot manifest, `rule` equal to the bound check's rule) AND any violation makes the method failed | Unit · black-box | Each violation → failed method naming it |

### AC-002F-08: Retention, No Promotion, No Publication

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-08a | GIVEN a run with helpers WHEN it finishes THEN scripts, declarations, sample copies and normalized helper records exist only in that verification's private run folder and its reports AND nothing is written to formal knowledge, rule or example folders, Presets/tags, skills, a `checks/` folder or any other project location | Integration · black-box | Project tree diff outside run folder/report files is empty |
| AC-002F-08b | GIVEN finished runs WHEN the existing Guard retention commands (`cleanup`, `keep`, `release`) are used THEN helper artifacts follow the run's evidence retention with no separate store or lifetime | Integration · black-box | Cleanup removes helper artifacts with the run; keep protects them |
| AC-002F-08c | GIVEN a later verification WHEN a helper is needed again THEN a script from an earlier run is not reused as reviewed, granted or executable; any reuse is a new submission that passes AC-002F-02…04 again | Integration · black-box | Earlier helper id/digest not accepted in a new run |
| AC-002F-08d | GIVEN the toolkit WHEN helper features are used THEN no command promotes, exports, uploads or publishes a helper script, and no network call, key or third-party service is used | Integration · black-box | No such command; no egress record for helpers |
| AC-002F-08e | GIVEN the Guard skill package WHEN inspected THEN it states that helper scripts are run artifacts that must not be copied into formal knowledge or published, and that turning a useful check into a formal rule or Adapter goes through normal knowledge maintenance or an Adapter feature | Unit · skill-text | Skill text contains these rules |
| AC-002F-08f | GIVEN the Maintainer image registration and conformance records WHEN stored THEN they are 002-F-owned toolkit state outside formal knowledge, and the delivered 002-B/002-D tool registration files and contract are unchanged | Integration · black-box | 002-B/002-D registration bytes unchanged; 002-F state in its own file |

### AC-002F-09: Auditability

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-09a | GIVEN a helper lifecycle WHEN each step happens (submitted, compile probe, static checks, reviewed, granted, snapshot built, sample runs, target run started, ended/terminated/not executed, post-run review) THEN the step, time, attempt id, outcome, script SHA-256 and, where applicable, grant id, conformance record id and manifest digest are recorded in the run state in order | Integration · black-box | Run state contains the ordered helper event list |
| AC-002F-09b | GIVEN any toolkit container start WHEN audited THEN the normalized canonical configuration read back from inspect (AC-002F-04b) and the runtime identity/version are kept with the run | Integration · black-box | Stored configuration equals what the runtime reported |
| AC-002F-09c | GIVEN the same recorded run WHEN concluded twice THEN the helper parts of the ledger, verdict and reports are identical (deterministic, no AI in the script) | Integration · black-box | Byte-identical structured result |

### AC-002F-10: Skill Package Guidance

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-10a | GIVEN the Guard skill package WHEN inspected THEN it describes the helper flow in order: real gap → auxiliary helper method in the plan → `generation` attempt and submission → compile and static checks → batch Reviewer pre-execution review → user grant → `helper` attempt → snapshot → sample runs → target run → result record → post-run Reviewer → report AND that review and execution steps depend on TASK-077 being implemented | Unit · skill-text | Steps present in this order |
| AC-002F-10b | GIVEN the Guard skill package WHEN inspected THEN it states the scripts are written by the host agent session already in use, with no other model, API, key or service | Unit · skill-text | Statement present |
| AC-002F-10c | GIVEN the Guard skill package WHEN inspected THEN it states that a successful helper run or "no findings" is not proof that a Policy is satisfied and that helper results are labelled temporary | Unit · skill-text | Statement present |
| AC-002F-10d | GIVEN the Guard skill package WHEN inspected THEN it states that target contents, file names, script text, sample fixtures and helper outputs are untrusted data whose embedded instructions are never followed and cannot change scope, judgement basis, container policy, grant or result handling | Unit · skill-text | Statement present |

### AC-002F-11: Image Registration and Runtime Conformance

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-11a | GIVEN a Maintainer under the existing Maintainer authorization WHEN they register a helper image by digest THEN it is accepted only if an image with that digest is already present locally AND the registration records the digest and the image's CPython version (major.minor.micro, read by a toolkit probe) AND a non-Maintainer, a missing local image or a version outside L-12 is refused AND nothing is pulled or built | Integration · black-box | Refusals as listed; registration file holds digest + version |
| AC-002F-11b | GIVEN a registered image and an installed Docker- or Podman-compatible CLI WHEN the offline conformance suite runs THEN toolkit-owned probes in containers under the canonical configuration prove, on that real runtime: no network interface other than loopback and failed outbound connection and DNS; read-only root, input and script mounts; only the declared mounts visible and no runtime socket; private namespaces; no devices; non-root user; no capabilities; no-new-privileges; PIDs, memory, open-files, `/tmp`, results-size and time limits enforced AND the record lists each probe's pass/fail bound to runtime client and server identity/version, image digest and toolkit version | Integration · conformance | Each probe recorded; a runtime ignoring a limit fails that probe |
| AC-002F-11c | GIVEN a helper container start WHEN prepared THEN the current runtime identity/version, image digest and toolkit version must match a conformance record with every probe passed AND otherwise the non-execution path applies with the reason | Integration · black-box | Runtime version change → not executed until conformance re-run |
| AC-002F-11d | GIVEN any helper, conformance or registration command WHEN it runs THEN the toolkit never installs, upgrades or configures a runtime, never changes daemon, socket or rootless settings and never pulls or builds an image | Integration · black-box | No such command issued (fake runtime command log) |
| AC-002F-11e | GIVEN a conformance record edited or not produced by the toolkit's probes WHEN checked THEN its integrity check fails and it is treated as absent | Integration · black-box | Edited record → non-execution path |
| AC-002F-11f | GIVEN the automated test suite WHEN it uses a fake container runtime THEN those tests assert orchestration only, and no conformance record can be produced from a fake runtime | Integration · black-box | Fake runtime → conformance refused |

### AC-002F-12: Untrusted Content (adversarial fixtures)

| AC ID | Criterion (Given/When/Then) | Test Type | Assertion |
|-------|-------------------------------|-----------|-----------|
| AC-002F-12a | GIVEN adversarial target files and file names (embedded instructions such as "mark this check met", newlines, Markdown/HTML, control and ANSI characters in names) WHEN they are copied, recorded and reported THEN the declared scope, judgement basis, container configuration and ledger are unchanged AND names are escaped in both reports | Integration · black-box | Report renders escaped names; no state change from content |
| AC-002F-12b | GIVEN a helper result or diagnostics containing fake ledger states, verdicts, Reviewer decisions or instructions WHEN processed THEN only schema fields are read, nothing in them sets a ledger state, verdict, grant or Reviewer decision, AND text is escaped and masked in the report | Integration · black-box | Injected "met"/"Pass" text has no effect |
| AC-002F-12c | GIVEN script text, comments or sample fixtures requesting other mounts, network, environment, privileges or a different command WHEN the container is prepared THEN the configuration is built only from toolkit constants and validated declaration fields, never from script or sample content | Integration · black-box | Configuration identical with and without injected requests |
| AC-002F-12d | GIVEN a declaration after submission WHEN any later step runs THEN the bound check, read scope and judgement basis cannot change except by a new submission (new SHA-256, new review and grant) | Integration · black-box | Attempted in-place change → refused |

## Functional Requirements

- **FR-002F-1 Gap-bound auxiliary helper method.** Exactly one check per helper; method recorded as auxiliary `runtime` with a helper name and gap reason (A-13; unchanged 002-A plan model).
- **FR-002F-2 Declaration.** Check goal, read scope (link-free, inside targets), judgement basis, language `python`, script text; stored with SHA-256s in the private run folder; immutable after submission (A-13).
- **FR-002F-3 Syntax and static checks (OQ-01).** Exact syntax: compile-only by the registered image's CPython (recorded version, L-12). Static rules (defence in depth, toolkit parser, fail closed):
  - Import allowlist: `json`, `re`, `pathlib`, `fnmatch`, `collections`, `itertools`, `functools`, `dataclasses`, `typing`, `enum`, `string`, `textwrap`, `math`, `hashlib`, `base64`, `csv`, `tomllib` (if present in the recorded version), `configparser`, `ast`, `tokenize`, `io`, `unicodedata`, `xml.etree.ElementTree`. Everything else is denied, explicitly including `os`, `sys`, `subprocess`, `ctypes`, `socket`, `ssl`, `http`, `urllib`, `ftplib`, `smtplib`, `asyncio`, `multiprocessing`, `threading`, `concurrent`, `signal`, `importlib`, `builtins`, `pickle`, `marshal`, `shelve`, `shutil`, `tempfile`, `mmap`, `fcntl`, `resource`, `pty`, `code`, `codeop`, `runpy`, `inspect`, `gc`, `site`, `sysconfig`, `platform`, `webbrowser`.
  - Denied calls/names: `exec`, `eval`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `locals`, `vars`, `breakpoint`, `input`, `help`, `memoryview`; any attribute or name starting and ending with `__`; star and relative imports.
  - Writes: `open` only with a literal mode; any write mode only with the literal results path `/results/result.json`; `pathlib` write/unlink/rename/mkdir/chmod/touch/symlink methods denied.
- **FR-002F-4 Samples and review.** L-02 samples with recorded origin (explicitly labelled formal example, else synthetic fixture; never targets), copied into staging. Pre-execution batch review and post-run acceptance of clean conclusions as `helper` subjects in the shared Reviewer record (FR-002A-4 extension; Reviewer coverage of helpers via the 002-C CR, TASK-077) (A-14, A-15).
- **FR-002F-5 Canonical container configuration (OQ-02, OQ-09).** Toolkit-built from constants and validated declaration fields only; verified field-by-field from runtime inspect before start; fail closed. Fields: network `none`; read-only root; `CapDrop` all, no `CapAdd`; `no-new-privileges`; default or conformance-approved seccomp (never unconfined), no unconfined AppArmor/SELinux label; not privileged; private PID/IPC/UTS/cgroup/network namespaces and the conformance-recorded user-namespace mode; no devices, device requests, extra hosts, DNS, port bindings, links, sysctls or group additions; mounts exactly: snapshot input read-only at `/input`, script read-only at `/helper`, results at `/results` (bounded, L-08), tmpfs `/tmp` (L-07, `noexec,nosuid,nodev`); limits L-06; user `65534:65534`; environment exactly the Maintainer-registered image's own environment (keys and values recorded at registration and shown to the Maintainer; credential-like values refused at registration) overlaid by `PATH`, `LANG=C.UTF-8`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONHASHSEED=0`, with no other variable and nothing from the host environment (v1.3, DAO-014 TD); image = registered digest; container command fixed to the digest-bound toolkit launcher `/helper/launcher.py` (PID 1), which starts the registered image interpreter in isolated mode on `/helper/script.py`; no restart policy. Podman equivalents are mapped field-by-field in the conformance record.
- **FR-002F-6 Snapshot (OQ-09).** No-follow, regular-file-only, race-resistant copy of the declared scope into toolkit-owned disposable staging (002-B staging/cleanup conventions); manifest of path, size and SHA-256; must match the target version recorded at open immediately before start; original never mounted.
- **FR-002F-7 Grant (OQ-04).** Additive interactive-terminal command naming the verification, bound to reviewed helpers' script, declaration and sample SHA-256s; recorded cooperative consent, not a security boundary; no new egress purpose; changed/new helper needs a new grant.
- **FR-002F-8 Result schema.** `/results/result.json` only: `{"schema": "x-ipe-helper-result/1", "helper": <id>, "status": "complete"|"error", "scanned": [<manifest path>…], "findings": [{"path": <manifest path>, "line": <int ≥ 1 or null>, "rule": <bound check's rule>, "title": <str>, "excerpt": <str>, "basis": <str>}…], "notes": <str>}`; no other keys; bounds L-08. Clean = `status: complete`, empty `findings`; coverage = `scanned`.
- **FR-002F-9 Non-execution.** Any unproven limit, missing conformance/image/grant, failed review/samples, budget, pause, cancel → not executed; failed auxiliary method; gap reported; 002-A computes the check state (A-16).
- **FR-002F-10 Budget and cancel.** `generation` attempt for authoring; one `helper` attempt per result-producing execution; delivered lease and repeat rules unchanged; time capped; cancel stops the toolkit-owned container (002-C).
- **FR-002F-11 Result recording and reporting.** `runtime` evidence with helper method name and source; failed-method rules; Reviewer on verdict-affecting findings; masking; "Temporary helper checks" report part with gaps (FR-22).
- **FR-002F-12 Registration and conformance (OQ-02, OQ-03).** Maintainer registration of a locally present image digest; offline conformance suite per runtime identity/version, image digest and toolkit version; integrity-protected 002-F-owned state.
- **FR-002F-13 Run-only retention (OQ-07).** Private run folder; existing cleanup/keep/release; no reuse, promotion or publication (A-17).
- **FR-002F-14 Audit trail and skill guidance** including untrusted-content rules.

**Numeric limits (proposed values pending the independent re-review; a change after confirmation is a specification change):**

| ID | Limit | Value |
| --- | --- | --- |
| L-01 | Helpers submitted per verification | ≤ 5 |
| L-02 | Samples per helper | ≥ 1 positive and ≥ 1 negative; ≤ 5 of each; ≤ 64 KiB each; ≤ 256 KiB total |
| L-03 | Script | ≤ 64 KiB UTF-8; ≤ 2,000 lines |
| L-04 | Script AST | nesting depth ≤ 50; ≤ 20,000 nodes |
| L-05 | Read-scope snapshot | ≤ 2,000 files; ≤ 5 MiB per file; ≤ 50 MiB total; ≤ 32 path components and ≤ 1,024 bytes per path |
| L-06 | Container resources | memory 512 MiB with swap equal to memory (no swap); 1.0 CPU; ≤ 64 PIDs; open files ≤ 256 (soft = hard) |
| L-07 | Writable scratch | root filesystem read-only; `/tmp` tmpfs ≤ 16 MiB |
| L-08 | Results | only `result.json`; results area ≤ 2 MiB; `result.json` ≤ 1 MiB; JSON depth ≤ 16; ≤ 500 findings; ≤ 2,000 `scanned` entries; `title` ≤ 200 chars, `excerpt` ≤ 2 KiB, `basis` ≤ 500 chars, `notes` ≤ 2 KiB |
| L-09 | stdout / stderr | ≤ 64 KiB each, diagnostics only |
| L-10 | Wall time per container run | compile probe ≤ 30 s; each sample run and the target run ≤ 120 s; all capped by remaining verification time |
| L-11 | Termination wait | the 002-C cancel wait (decided in 002-C technical design) |
| L-12 | Supported image interpreter | CPython 3.10.0 – 3.13.x, recorded as major.minor.micro |

## Non-Functional Requirements

- **NFR-002F-1 Determinism.** Recording, ledger and verdict for helpers are computed by the script without AI; same recorded run → same outputs.
- **NFR-002F-2 Fail closed.** Any doubt about runtime, conformance, configuration, image, snapshot, grant or results yields non-execution or a failed method, never a clean result.
- **NFR-002F-3 No new egress or authority.** No network access, model API, key, third-party service or download; images are never pulled or built; no new egress purpose.
- **NFR-002F-4 Bounded footprint.** L-01…L-12 hold; exceeding a limit never retains oversized data.
- **NFR-002F-5 Platform honesty.** Where no conformance-passing runtime exists, only the non-execution path is available and the report says so.
- **NFR-002F-6 Untrusted content.** No content from targets, samples, scripts or outputs influences configuration, scope, judgement, grant or ledger.

## UI/UX Requirements

N/A — no visual UI. Command-line results, refusals and report text name the reason and the next step (e.g. "no conformance-passing container runtime: helper not executed; auxiliary method failed; check C3 state per 002-A").

## Dependencies

- **FEATURE-002-A** (Completed): check plan (method choice/changes, auxiliary methods, minimum evidence), ledger and substitution rules (AC-002A-04d/04e/04j, unchanged), target digests at open, Reviewer envelope with typed subjects (FR-002A-4 — this feature adds the `helper` subject type as an additive extension; existing records and tests unchanged; extension note to be added to FR-002A-4), deterministic verdict, report, run folder, retention commands, interactive-terminal gate pattern.
- **FEATURE-002-C** (Completed): shared budget, `generation` and `helper` attempt kinds, single-use leases and repeat accounting (unchanged), remaining-time cap, pause, cancel, masking. **Change Request on FEATURE-002-C (TASK-077, human decision B12 = A):** additive Reviewer coverage item `helpers` (first coverage planned, re-coverage extra; existing kinds, records and tests unchanged) — changes AC-002C-01c/01d text and the attempt request/run-state schema. Required by AC-002F-03b…03d, 03f, 03h, 04a, 04e, 04f, 04i, 04o, 05g, 06a, 07a, 07c, 07d; **002-F implementation cannot complete before this CR is implemented**.
- **FEATURE-002-B** (Completed, reused unchanged): staging/cleanup conventions, termination of owned processes, failed-method evidence; tool registration contract unchanged.
- **FEATURE-002-D** (Completed): its registration is unchanged.
- **Local container runtime and image** on the user's host (not shipped, installed or configured by the toolkit); absence leads to the non-execution path.
- **Related, not dependent:** FEATURE-001-G (explicitly labelled rule examples may serve as samples); FR-29 sandbox (EPIC-004) is a different purpose and is not reused.

## Business Rules

- **BR-01:** A helper exists only for a real gap of a planned check and is always an auxiliary method; it never replaces an available Adapter or sufficient semantic review (A-13).
- **BR-02:** Three layers are all required — syntax/static checks, independent review with known samples, enforced limits — before a helper result counts (A-14). The review layer relies on Reviewer coverage of helpers delivered by the 002-C CR (TASK-077).
- **BR-03:** Review is not execution authorization. Execution needs the user's interactive grant, which is recorded cooperative consent and not a security boundary; the enforced container limits are the boundary (A-16, OQ-04).
- **BR-04:** If any limit cannot be enforced and proven by conformance, the script is not executed anywhere and the gap is reported; this is intended behaviour (A-16, DAO-001).
- **BR-05:** Helpers run only in a toolkit-started local disposable container with network disabled on a conformance-passing runtime; never on the host (DAO-001).
- **BR-06:** The original project is never mounted; the helper reads only a link-free snapshot bound to the target version at open (A-15).
- **BR-07:** An exit status is never evidence and "no findings" is not by itself sufficiency; a clean result counts only under AC-002F-07c (A-16).
- **BR-08:** 002-A ledger semantics are unchanged: a non-executed or failed helper is a failed auxiliary method; 002-A computes the check state.
- **BR-09:** Helper evidence and findings are labelled helper/temporary and never use reserved Adapter names.
- **BR-10:** Helpers are run artifacts: never written to formal knowledge, never published, never reused across runs (A-17).
- **BR-11:** No new network, model API, keys or third-party services; scripts are authored by the host agent session already in use; authoring is a `generation` attempt (DAO-001).
- **BR-12:** All helper work is inside the 002-C budget/cancel model and the 002-A plan/ledger/report model; no parallel mechanism; 002-C lease and repeat rules unchanged.
- **BR-13:** Target contents, names, scripts, samples and outputs are untrusted data.
- **BR-14:** Guard never fixes; a helper never writes to targets or performs remediation.

## Edge Cases & Constraints

- Runtime absent, daemon stopped, socket inaccessible, rootless mode unable to apply a field, or runtime version changed since conformance → not executed, reason recorded.
- Inspect output missing a field, showing an extra mount or an unconfined profile → no start.
- Registered image missing locally or digest mismatch; no registration → not executed; never pulled.
- Image interpreter version outside L-12 or toolkit parser unable to parse newer syntax → refused (fail closed).
- Script attempts network, reads outside `/input`, writes outside `/results` or `/tmp` → fails inside the container; outcome is a failed method unless a schema-valid result was written (the Reviewer then judges it).
- Results with extra files, symlinks, FIFOs, directories, wrong owner, oversize → failed method; nothing raw retained.
- Fork bomb, memory exhaustion, file-descriptor exhaustion, `/tmp` fill, stdout flood → terminated or write fails; failed method naming the limit.
- Target edited, replaced by a symlink or removed between open and the run, or during the copy → run refused.
- Cancel during a compile probe, sample run or target run → container stopped; termination confirmed or reported not confirmed.
- Budget exhausted after review/grant but before the run → not executed; gap.
- Reviewer rejects one helper of a batch → only that helper is blocked.
- Grant given, then helper resubmitted → old grant invalid for it.
- Non-interactive session (agent-only) → no grant → non-execution path.
- Declared read scope narrower than the check object → partial coverage is reported with the uncovered files; the helper does not count for them; the final check state follows the unchanged 002-A rules (AC-002F-07c).
- Same check gets a second helper → new submission, `generation` and `helper` attempts counted extra per 002-C.
- Hosts where 002-B tool runs are unsupported in this version → helper execution likewise unsupported; non-execution path.
- 002-C CR (TASK-077) not yet delivered → 002-F implementation cannot complete; no partial delivery is claimed.

## Out of Scope

- A permanent check library, `checks/` folder or promotion of helpers into rules, Adapters or skills (A-17, A-18).
- Languages other than Python 3 standard library; third-party packages.
- Network-enabled helpers, downloading/pulling/building images, any new egress purpose.
- Installing or configuring container runtimes; OS-level sandboxes other than the local container; host fallback.
- A Maintainer per-project execution enablement (rejected by DAO-007).
- Helpers for remediation, fixing or automatic re-scan loops.
- New model APIs, keys or third-party services; Copilot generation budgets (FEATURE-003-A).
- The FR-29 sandbox (EPIC-004); cross-run comparison (FEATURE-002-G).

## Technical Considerations

- Reuse the delivered Guard paths (`guard/toolrun.py`, `toolctl.py`, `budget.py`, `cancel.py`, `runs.py`, `records.py`, `report.py`, `retention.py`); `budget.py` already defines `helper` and `generation` kinds; Reviewer coverage of helpers comes from the 002-C CR (TASK-077).
- Under unchanged 002-C repeat accounting, a `generation` attempt and the later `helper` attempt cover the same (check, helper method) pair, so every helper execution costs at least one extra attempt; technical design should account for this in default budgets (no rule change).
- The results area must be size-bounded by a means the conformance suite proves on that runtime (e.g. a bounded tmpfs-backed area collected before removal); if no proven means exists, non-execution.
- If the design cannot satisfy the delivered single-use lease rule (sample outcomes not finishing the lease), stop and escalate (DAO-007 OQ-08 (i)).
- Delivered skill text says runtime evidence comes only from Adapters run by the script; this feature extends that to toolkit-run helpers (skill text update in scope).
- 002-A target digests: technical design confirms the delivered digest form for folder targets; the snapshot must reproduce it from copied bytes or compare per file.
- Test strategy: fake runtime for orchestration ACs; real-runtime conformance and acceptance offline, only with an image already present locally (pulling one needs the human, DAO-007 OQ-03); with no runtime/image, only the non-execution path is accepted and that limit is reported.
- Honest limits: the toolkit cannot prove the script was written by the host agent; the grant cannot prove a person typed it; container isolation is the runtime's isolation and not a guarantee against runtime or kernel vulnerabilities; samples prove only that the script separates those samples; the Reviewer is the host model and its acceptance of a clean conclusion is a judgement, not proof of completeness; static rules are defence in depth only; Guard does not enforce per-file coverage of the check object for any method (002-A counts any usable evidence on any part of the object), so a partially covering helper is reported with its uncovered files and other evidence may still make the check `met` (v1.3.1, DAO-018 TD; optional human CR candidate: 002-A engine support for partial-coverage evidence).

## Open Questions

OQ-01…OQ-09 are decided by DAO-007 (DAO representative under the human's delegation, not the human):

| ID | Decision | Applied in |
| --- | --- | --- |
| OQ-01 | A — Python 3 standard library only; syntax at the image interpreter's recorded version; static checks are defence in depth | FR-002F-3, L-12, AC-002F-02c, 02d, 11a |
| OQ-02 | A — installed Docker/Podman-compatible CLI; verify via inspect before start; never install/configure; no host fallback | FR-002F-5, AC-002F-04b, 05a, 11b…11d |
| OQ-03 | A — locally present image matching a Maintainer-registered digest; never pull/build; new 002-F-owned registration; 002-B/002-D unchanged | AC-002F-04c, 08f, 11a |
| OQ-04 | A only — interactive grant naming the verification, bound to reviewed SHA-256s; Maintainer fallback rejected; agent-only → gap; cooperative consent, not a security boundary | FR-002F-7, AC-002F-04o, 04p, 05g |
| OQ-05 | C — explicitly labelled formal example, else synthetic fixture; origin recorded; copied to staging; never targets | AC-002F-03a |
| OQ-06 | B as amended — clean counts only with valid results, passed samples, Reviewer acceptance, within declared scope; uncovered part `unconfirmed`; never replaces a required Adapter method; exit status never evidence | AC-002F-07b, 07c, 03h |
| OQ-07 | A — run folder only, existing retention, no reuse, no `checks/` | AC-002F-08a…08c |
| OQ-08 | Split — (i) one `helper` attempt per result-producing execution, lease rule unchanged; (ii) additive `helper` Reviewer subject (FR-002A-4); (iii) Reviewer coverage of helpers → **B12**, decided by the human: A (002-C CR, TASK-077) | AC-002F-06a, 03c, 03h; B12 marks |
| OQ-09 | A as amended — no-follow regular-file snapshot in toolkit staging, read-only; bounded separate results area parsed and masked by the toolkit; original never mounted | FR-002F-6, AC-002F-04i…04k |

Open: none. B12 was decided by the human on 2026-10-23 20:38 (A: additive 002-C Reviewer coverage item `helpers`, CR tracked as TASK-077). The numeric limits L-01…L-12 are proposed values pending the independent re-review.

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| A-13, FR-002F-1, BR-01, BR-08 | US-01 | AC-002F-01a…01d | N/A | Integration/Unit | covered |
| A-13, A-14, OQ-01, FR-002F-2/3, L-01, L-03, L-04 | US-02 | AC-002F-02a…02g | N/A | Integration/Unit | covered |
| A-14, A-15, A-16, OQ-05, OQ-08 (ii), FR-002F-4 | US-02 | AC-002F-03a…03h | N/A | Integration/Unit | covered; 03b…03d, 03f, 03h depend on 002-C CR (TASK-077) |
| A-15, A-16, DAO-001, OQ-02, OQ-04, OQ-09, FR-002F-5…7, L-05…L-10 | US-03 | AC-002F-04a…04p | N/A | Integration/Unit/conformance | covered; 04a, 04e, 04f, 04i, 04o depend on 002-C CR (TASK-077) |
| A-16, DAO-001, FR-002F-9, BR-04, BR-08 | US-04 | AC-002F-05a…05g | N/A | Integration/Unit | covered; 05f not applicable (B12=A); 05g depends on 002-C CR (TASK-077) |
| 002-C B-02…B-04, OQ-08 (i), FR-002F-10, BR-11/12 | US-03 | AC-002F-06a…06c | N/A | Integration | covered; 06a depends on 002-C CR (TASK-077) |
| A-16, FR-22, OQ-06, FR-002F-8/11, BR-07/09 | US-05 | AC-002F-07a…07g | N/A | Integration/Unit | covered; 07a, 07c, 07d depend on 002-C CR (TASK-077) |
| A-17, A-18, OQ-03, OQ-07, FR-002F-13, BR-10 | US-06 | AC-002F-08a…08f | N/A | Integration/Unit | covered |
| FR-002F-14, NFR-002F-1 | US-05 | AC-002F-09a…09c | N/A | Integration | covered |
| FR-002F-14, BR-11, BR-13 | US-01…US-06 | AC-002F-10a…10d | N/A | Unit (skill-text) | covered |
| OQ-02, OQ-03, FR-002F-12 | US-03, US-06 | AC-002F-11a…11f | N/A | Integration/conformance | covered |
| BR-13, NFR-002F-6 | US-03, US-05 | AC-002F-12a…12d, 03g, 10d | N/A | Integration/Unit | covered |

Independent review (v1.0, FAIL) finding → AC map: (1) authoring attempt → 06a, 06c; (2) 002-A ledger semantics → 01b, 03e, 05b, 05c, 07c; (3) input/results handling → 02b, 04j, 04k, 04h; (4) canonical configuration → 04b, 09b, FR-002F-5; (5) numeric limits → L-01…L-12, 02f, 02g, 04l…04n; (6) conformance → 11b, 11c, 11e, 11f, 04l; (7) untrusted content → 03g, 10d, 12a…12d; (8) clean result → 07c, 03h, 10c; (9) snapshot binding → 04i, 07a, 09a; (10) Python version, static rules, schema, inspection, bounds → 02c, 02d, 07g, FR-002F-3/5/8, L-12; (11) grant wording → 04o, 04p, BR-03.

## Context and Verification Evidence

- Sources (SHA-256 prefixes): requirement-details.md `1747efe61b9c5cf1` (FR-19, G-02, FEATURE-002-F section); feature inventory v2 `f36a27538196f351` (§9.2 A-13…A-18); FEATURE-002-A specification `ab170f062928d030` (AC-002A-04, FR-002A-1/4/5/6); FEATURE-002-C specification `fca9f235384ee2b6`; workflow DAO-001 `ae4ff0091f923c9e`; closing DAO-001 `af7f87fc4fad5b47`; DAO-007 in `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md` `2c85ef3b85554904` when applied; previous specification v1.0 `20945a54cbdb4151`; delivered Guard skill and `guard/budget.py` read for terms only.
- Workflow: TASK-072, owner Sage, interaction mode `dao-represent-human-to-interact`; refinement worker made no board, Git, memory or skill writes and no product-code change.
- Readiness: draft, ready for re-review; B12 decided by the human (A; `x-ipe-docs/dao/26-10-23/human_decisions.md` `32f8602546c3884b`); 002-F implementation depends on the 002-C CR (TASK-077); numeric limits L-01…L-12 are proposed values pending the independent re-review; previous specification v1.1 `7a97d689f1219efb`.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-002F-01a…12d | Planned Integration/Unit/conformance scenarios as listed; no tests run | planned | not measured |
