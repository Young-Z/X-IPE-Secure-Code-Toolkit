# Feature Specification: Adapter Contract & Opengrep Adapter

> Feature ID: FEATURE-002-B  
> Epic: EPIC-002 (Guard: Verification, Adapters & Evidence)  
> Version: v1.0  
> Status: Refined — confirmed by human (TASK-027, 2026-10-19)  
> Last Updated: 10-19-2026

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-19-2026 | Initial specification | N/A |
| v1.0 | 10-19-2026 | Edge cases added for syntax errors (Python checked by the toolkit; stated limit for other languages) and unsupported rule features (user decision during TASK-029); no AC changed | N/A |
| v1.0 | 10-19-2026 | NFR-002B-4 narrowed: Adapter execution refused on Windows in this version (process-tree termination needs an untestable Job Object path; user decision during TASK-029 design review); registration/status unchanged; no AC changed | N/A |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: script commands, files and Markdown/structured reports. Bounded discovery: EPIC-002 and the idea folder contain no mockups. | — | — |

## Overview

FEATURE-002-B gives Guard its first executable evidence source. It defines the shared **Adapter contract** in the Framework scripts and delivers the **Opengrep Adapter**.

- **Guard decides, the Adapter executes.** The Guard agent decides whether a tool is the cheapest sufficient method for a planned check and which local rule files, targets and limits to use, and records why. The script validates these named parameters, runs the tool inside the open Guard verification, accounts for every file and rule, normalizes the output and records provenance-backed `runtime` evidence per check plus the tool's results as findings (user decision 10-19-2026). The agent still decides ledger states and asks the Reviewer; the Adapter never decides a verdict.
- **The original project is never handed to the tool.** The Adapter snapshots the requested files, the rule files and the binary into a private disposable staging area, hashes the snapshots and passes only staged paths to the tool; its working folder, home, logs and caches are disposable too (user decision). Filesystem and network access are not OS-enforced (no isolation): rule sources must be local files (the tool contacts its rule registry otherwise — observed), and real egress control is FEATURE-002-C.
- **Only the authentic, known binary runs.** A Maintainer registers the Opengrep binary; registration and every run compare its SHA-256 with the toolkit's table of official release digests for verified versions **before anything is executed** (user decision). Any other binary is refused; nothing is downloaded, upgraded or relaxed.
- **Honest results.** Tool errors, skipped files, skipped rules, timeouts and unparseable output make the affected check's evidence a failed method; a clean exit with zero findings is evidence, never a pass.
- **Validated before built.** A tool-level validation of Opengrep v1.31.0 on both MVP samples was performed during refinement ([tool validation](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/tool-validation/README.md)); formal evaluation (AC-28) belongs to FEATURE-003-C.

Trivy (002-D) and Strix (002-E) will use the same contract. Shared budget, cancellation and egress control (002-C), runtime rule generation (A-11), bundled rule packs and formal evaluation are outside this feature.

## User Stories

- **US-01:** As a Developer, I want Guard to run Opengrep on exactly the objects of a check and record the real output as runtime evidence, so that checks needing tool evidence can be met instead of staying unconfirmed.
- **US-02:** As a Guard agent, I want to pass only named, validated parameters through one Adapter contract, so that I decide the scan strategy without writing command lines and without a pre-maintained Policy-to-rule mapping.
- **US-03:** As a Maintainer, I want only the authentic released Opengrep binary to be registered and run, so that a swapped or unknown tool is never executed and nothing is downloaded behind my back.
- **US-04:** As a Developer, I want tool failures, timeouts, skipped files and skipped rules reported honestly per check, so that a clean exit or zero findings is never mistaken for a pass.
- **US-05:** As a Developer, I want the original project protected from the tool, so that verification never changes my files.
- **US-06:** As a Developer, I want Guard to record why it chose a method and any switch or supplement, so that cost stays low without lowering the requirement and the choice is reviewable.
- **US-07:** As a Maintainer, I want a recorded tool-level validation before the full Adapter, so that known tool behaviour and issues are evidence, not assumptions.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 | EPIC-001 FR-16, FR-18 (Opengrep); A-01…A-09, S-07; AC-24 | Developer, upstream agent | Executable rule-driven evidence that is trustworthy: real output, complete accounting, honest failure, no false pass | Adapter contract + Opengrep Adapter run by the script inside the Guard verification; per-check coverage accounting; provenance-backed per-check evidence and tool findings bound to the recorded target version | Scenario: on WebGoat a CWE-89 rule file for check C1 yields findings that need review; a skipped test folder makes C1's tool evidence a failed method; a registry rule source is refused | No Policy→rule mapping; no runtime rule generation; tool never decides a verdict | AC-002B-01a…06b | not measured |
| G-04 | EPIC-001 FR-16 (cheapest sufficient), FR-18 | Developer, Maintainer | Low cost without lowering the requirement | Recorded method choice (considered methods, cost notes, sufficiency reason); switches/supplements with reasons | Scenario: semantic review planned for one check, Opengrep for another with a recorded reason; a later supplement keeps earlier results | No all-tools default; budget enforcement is 002-C | AC-002B-04d…04f | not measured |
| G-05 (enabling) | EPIC-001 FR-24, FR-17 principle, E-01, A-08, A-09 | Owner, Maintainer, Developer | Only the approved authentic tool runs; the original project is never written by it; no silent download or network fetch by the toolkit | Maintainer registration against official digests checked before execution; staged disposable copy; local rule files only | Scenario: a modified binary is refused without being executed; a tool run leaves the original project byte-identical and leaves no files behind | No OS-level isolation or network enforcement claimed | AC-002B-01a…01f, 02b, 03a, 03b, 03i | not measured |

## Acceptance Criteria

Breakdown ACs: AC-002B-01 (Guard supplies parameters, targets and mode; no Policy→rule mapping) → AC-002B-02a, 02c, 04a, 04b; AC-002B-02 (cheapest sufficient method, switch/supplement reasons) → 04d…04f; AC-002B-03 (tool-level validation before the full Adapter) → 05a, 05b. EPIC-001 AC-24 (Opengrep part) → 01*, 02*, 03*. "Mode" for Opengrep is the scan mode `include_ignored` (scan files the tool ignores by default, or not); "budget" is the per-run time limit — shared budgets are FEATURE-002-C.

### AC-002B-01: Tool Registration and Pre-check

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002B-01a | GIVEN a valid Maintainer authorization and a binary whose SHA-256 equals an entry of the toolkit's official-digest table (tool, version, platform) WHEN it is registered THEN the digest is compared before the binary is executed AND the path, digest, version, platform and whether that platform was tool-level validated are recorded | Integration |
| AC-002B-01b | GIVEN no valid Maintainer authorization (none, revoked or tampered) WHEN a tool registration is requested THEN it is refused with a next step AND nothing is recorded | Integration |
| AC-002B-01c | GIVEN a binary whose digest is not in the official-digest table (custom build, other version, modified file) or a path that is missing, not a regular file or a symbolic link WHEN registration is requested THEN it is refused with the reason AND the binary is never executed | Integration |
| AC-002B-01d | GIVEN an Adapter run request WHEN the pre-check runs THEN before executing anything it verifies: Adapter provided, tool registered, a private snapshot of the binary whose digest equals the registration and the table (the snapshot is what gets executed), time limit valid, and the requested target and rule files snapshotted without following symbolic links AND any failure means the tool is not executed AND a failed `opengrep` method with the reason is recorded for each requested check | Integration |
| AC-002B-01e | GIVEN any pre-check failure or an unregistered tool WHEN the toolkit responds THEN nothing is downloaded, installed, upgraded or re-registered automatically AND the next step names the Maintainer action | Integration |
| AC-002B-01f | GIVEN a successful pre-check and tool run WHEN the result is reported THEN it is evidence for the listed checks only AND is never presented as a security pass | Integration |

### AC-002B-02: Adapter Contract — Typed Parameters

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002B-02a | GIVEN an Adapter run request WHEN it is validated THEN only the contract's named parameters are accepted (verification, Adapter name, per check: rule files and scan targets; scan mode `include_ignored`; total time limit) AND unknown fields, missing required fields, wrong types or any free-form argument or shell text are refused before any tool runs | Integration |
| AC-002B-02b | GIVEN a rule source that is not an existing regular local rule file inside the project (a folder, registry name, URL, `auto`, absent, outside the project, or with a symbolic link in its path) WHEN validated THEN the request is refused AND the tool is not executed | Integration |
| AC-002B-02c | GIVEN the scan targets requested for a check WHEN validated THEN together they must cover that check's complete declared object AND each must be a target of the open verification or lie inside a folder target AND context, suggested, deleted or unrelated paths are refused | Integration |
| AC-002B-02d | GIVEN the rule files of a request WHEN validated THEN every rule has an id AND a rule id appearing in more than one file of the request is refused AND the digest of every rule file used is recorded with the evidence | Integration |
| AC-002B-02e | GIVEN a time limit that is missing, not positive or above the toolkit's documented maximum WHEN validated THEN the request is refused | Integration |

### AC-002B-03: Protected Execution and Normalized Results

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002B-03a | GIVEN a valid request WHEN the tool runs THEN the Adapter passes it only staged paths (snapshots of the requested target files and rule files) with a disposable working folder, home, logs and caches and a minimal environment AND the staging and disposable locations are removed after the run AND every original target, context and rule file is byte-identical | Integration |
| AC-002B-03k | GIVEN a target file whose current bytes differ from the digest recorded when the verification was opened WHEN it is snapshotted for a run THEN the tool is not run on it AND the evidence of every check whose object contains it is a failed method naming the change (evidence always describes the recorded version) | Integration |
| AC-002B-03b | GIVEN any run WHEN the tool is invoked THEN only the staged copies of the request's local rule files are passed as rule sources AND no rule source that would make the tool contact a registry is used | Integration |
| AC-002B-03c | GIVEN a run with results WHEN normalized THEN each result is recorded as a finding with source `opengrep`, tool rule id and rule file, original project-relative location and line range, the tool's own severity, a Guard severity from a fixed documented mapping (`unknown` when not mappable), the CWE if the rule declares one and the message AND it is attributed to the check (and adopted Policy) whose rule file produced it | Integration |
| AC-002B-03d | GIVEN a run WHEN recorded THEN one `runtime` evidence item per requested check (method `opengrep`) refers to the shared masked tool output in the private run folder AND carries provenance: tool version, binary digest, platform validation state, rule digests, staged file digests, exit status, duration, normalized status and the check's scanned and skipped files | Integration |
| AC-002B-03e | GIVEN a check whose object files were all scanned, whose rules all ran, with no tool errors WHEN recorded THEN that check's evidence is a successful method; GIVEN any of its object files skipped (with the tool's reason), not accounted for, or any of its rules skipped or not executed THEN that check's evidence is a failed method naming each gap AND other checks of the same run are unaffected | Integration |
| AC-002B-03f | GIVEN a tool configuration error, target error, error entries in the output, unparseable output or an unexpected exit status WHEN recorded THEN the normalized status says so with the tool's message AND the evidence of every requested check is a failed method AND results present in partial output are still recorded as findings | Integration |
| AC-002B-03g | GIVEN a run exceeding its time limit WHEN the limit is reached THEN the tool and its child processes are stopped AND the status is `timed_out` AND every requested check's evidence is a failed method | Integration |
| AC-002B-03h | GIVEN a complete clean run with zero results WHEN recorded THEN the evidence is successful with no findings AND the verdict is decided only by the FEATURE-002-A rules (zero findings alone never makes Pass) | Integration |
| AC-002B-03i | GIVEN tool output, error messages, matched source lines, rule messages or paths containing a suspected credential WHEN anything is stored or reported THEN it is masked (or, for identifiers and paths, refused) under the FEATURE-002-A masking rules AND tool logs and caches are not retained | Integration |
| AC-002B-03j | GIVEN a failed `opengrep` method for a check WHEN the verification is concluded THEN the failed evidence never satisfies the check AND the check is `met` only if FEATURE-002-A's rules are satisfied by other evidence (an auxiliary tool method may be substituted; a required one may not) | Integration |

### AC-002B-04: Guard Integration and Method Choice

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002B-04a | GIVEN a Guard check plan WHEN Opengrep is used THEN Guard supplies rule files, targets, scan mode and time limit through the Adapter request AND no pre-maintained Policy-to-rule mapping is required or consulted | Integration |
| AC-002B-04b | GIVEN an Adapter run request WHEN validated THEN it is accepted only for an open verification with a plan, for planned checks that declare an `opengrep` method of kind `runtime` AND each rule file is assigned to exactly one requested check | Integration |
| AC-002B-04c | GIVEN tool findings recorded by the Adapter WHEN the verification is concluded THEN they follow the FEATURE-002-A rules (verdict-affecting or `unknown` severity need a valid Reviewer record; a confirmed Medium or higher fails) AND the agent cannot remove or rewrite them | Integration |
| AC-002B-04d | GIVEN a planned check with more than one method or with a tool method WHEN the plan is recorded THEN it carries a method choice: the capable methods considered, known cost factors, the selected method and why it is sufficient AND a plan lacking it is refused | Integration |
| AC-002B-04e | GIVEN Guard switches a check to another method or adds a supplementary one during the run WHEN recorded THEN the change, its reason and the results so far are kept AND the report shows the original choice, the change and the reason | Integration |
| AC-002B-04f | GIVEN the Guard skill package WHEN its instructions are inspected THEN they direct the agent to prefer the cheapest sufficient method, never to run every tool by default, to ask before adding a new tool, a wider target, extra permissions or budget, and to record the method choice and any switch or supplement with reasons | Integration |

### AC-002B-05: Tool-Level Validation Record

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002B-05a | GIVEN the Opengrep Adapter WHEN its delivery is reviewed THEN a tool-level validation on both MVP samples dated before the Adapter implementation exists with the tool version, binary digest matching the official release digest, environment, rules, commands, observed results, timings and known issues | Integration |
| AC-002B-05b | GIVEN the toolkit's official-digest table WHEN inspected THEN every entry comes from the official release metadata of a version covered by a recorded tool-level validation AND each entry states whether its platform was tool-level validated AND the formal evaluation (AC-28) is stated as pending in FEATURE-003-C | Integration |

### AC-002B-06: Status Reporting

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-002B-06a | GIVEN a project WHEN `status` runs THEN the tools section reports for Opengrep that the Adapter is provided and whether a tool is registered and passes the digest pre-check (with platform validation state), with the failing reason and next step otherwise, without executing the tool | Integration |
| AC-002B-06b | GIVEN Trivy and Strix WHEN `status` runs THEN they are still reported as not provided by this toolkit version | Integration |

## Functional Requirements

- **FR-002B-1 Adapter contract.** One contract for all Adapters: name, official-digest table of verified versions per platform, named parameter schema, pre-check, protected execution with a total time limit, coverage accounting and normalization into per-check status, findings and evidence provenance. Trivy/Strix add contract implementations, not new Guard rules.
- **FR-002B-2 Tool registration (Maintainer).** Input: tool name, binary path. Process: Maintainer authorization (FEATURE-001-A); regular file, no symbolic link; digest; lookup in the official-digest table **without executing the binary**. Output: machine-local registration record (path, digest, version, platform, validation state, time). Re-registration replaces it explicitly.
- **FR-002B-3 Pre-check.** Before executing: Adapter provided; tool registered; binary regular and digest equal to registration and table; parameters valid (FR-002B-4); requested files stageable. Failure → no execution; failed method per requested check with reason; next step.
- **FR-002B-4 Run request.** Verification id; per check: rule files (individual local files inside the project), scan targets covering the check's full object; scan mode `include_ignored` (default false); total time limit (required, ≤ documented maximum). Only for an open verification with a plan and checks declaring an `opengrep` runtime method.
- **FR-002B-5 Protected execution.** Snapshot (no symbolic links followed) the binary, the requested target files and the rule files into private staging; hash the snapshots; require binary digest = registration = table and staged target digests = digests recorded at open; run the binary snapshot without a shell on staged paths only, with disposable working folder/home/caches and a minimal environment; stop the tool and its children at the time limit; remove staging and disposable locations; confirm original targets, context and rule files unchanged.
- **FR-002B-6 Accounting and normalization.** Statuses: `completed`, `completed_with_errors`, `failed`, `timed_out`, `precheck_failed`. Per check: object files scanned/skipped (with reason)/unaccounted, rules executed/skipped; evidence `ok` only when everything is accounted for and nothing failed. Results → findings with tool provenance and documented severity mapping (`unknown` fallback), attributed by rule file. All persisted text masked; identifiers/paths that look like credentials refused.
- **FR-002B-7 Method choice and changes.** The plan records per check the method choice (considered methods, cost factors, selection, sufficiency reason) when a check has a tool method or several methods; the record step accepts switches/supplements with reasons; the report shows them.
- **FR-002B-8 Status.** Tools section per Adapter: provided / not provided; registration, digest pre-check and platform validation state; next step.

## Non-Functional Requirements

- **NFR-002B-1 Safety.** No shell; no download, install or upgrade by the toolkit; binary authenticity checked by digest on the private snapshot that is executed; the Adapter passes only staged paths (snapshots of targets and local rule files); all stored output masked. Filesystem and network access by the tool are not OS-enforced (no OS isolation): refusing non-local rule sources removes the registry access observed in validation; egress control is FEATURE-002-C.
- **NFR-002B-2 Determinism of normalization.** The same tool output and inputs always normalize to the same findings, accounting and statuses.
- **NFR-002B-3 Bounded resources.** Every run has a total time limit; staged copies and stored output follow the FEATURE-002-A evidence bounds.
- **NFR-002B-4 Portability.** Adapter execution on macOS and Linux; on Windows it is refused with a clear gap in this version (user decision 10-19-2026: reliable process-tree termination is not testable here; later item), while registration and status work. Tool-level validated: Linux aarch64 (container) only; macOS official digests known but not executed.

## UI/UX Requirements

No graphical UI. New or extended `secure-code` commands (names finalized in technical design) to register a tool (Maintainer) and to run an Adapter inside a Guard verification; `status` extended. Every command returns the toolkit result envelope (text and `--json`) with one next step per refusal. The Guard report shows each Adapter run (tool, version, platform validation state, status, per-check scanned/skipped accounting, errors), the method choice per check and any switch or supplement with reasons.

## Dependencies

- **Internal:** FEATURE-002-A — verification run, plan methods, evidence, findings, review, verdict, masking and report. This feature extends its records **additively**: tool provenance on findings (tool rule id, rule file, tool severity, source run) and evidence (Adapter run provenance), method choice and method changes in the plan/record; FEATURE-002-A acceptance criteria are unchanged. FEATURE-001-A — Maintainer authorization, result envelope, status, atomic writes, locks. FEATURE-001-C — adopted Policies behind planned checks.
- **External:** Opengrep binary installed by the user/Maintainer (v1.31.0 official release); MVP samples under `study-case/secure-coding-guidance/playground/`.
- **Consumers:** FEATURE-002-C (budget/cancel/egress around Adapter runs), FEATURE-002-D/E (Trivy, Strix on the same contract), FEATURE-003-C (formal evaluation AC-28).

## Business Rules

- **BR-01:** Framework scripts hold the Adapter; Guard decides whether and how to call it; no Policy→rule mapping is pre-maintained (A-01…A-04, O-06).
- **BR-02:** Only named parameters; never a shell string or arbitrary argument (A-03).
- **BR-03:** Only a binary matching an official release digest of a verified version is registered or run, checked before execution; failures are reported gaps, never a download, upgrade or relaxation; a passed pre-check is not a security pass (A-08, A-09; user decision).
- **BR-04:** Rules come only from local rule files named in the request; no runtime rule generation in this version (user decision; A-11 deferred).
- **BR-05:** The tool works on a disposable copy; the original project is never handed to it (user decision; FR-17 principle).
- **BR-06:** Incomplete coverage (skipped or unaccounted files, skipped rules), errors, timeouts or unparseable output make the affected check's tool evidence a failed method; FEATURE-002-A decides what that means for the check (required vs auxiliary).
- **BR-07:** Tool findings are findings like any other: reviewed when verdict-affecting or of unknown severity, never deleted (FEATURE-002-A BR-07).
- **BR-08:** Only a Maintainer registers tools; registration is not consent to run against new targets or with more permissions (A-06).
- **BR-09:** Cheapest sufficient method first; the choice and any switch/supplement are recorded with reasons; no all-tools default (A-05…A-07).

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Opengrep not registered | Pre-check fails; failed method per check; next step: Maintainer registration |
| Binary replaced after registration | Digest mismatch → pre-check fails before execution |
| Binary of another version, platform build not in the table, or custom build | Registration refused without executing it |
| Rule source `p/default`, URL, `auto`, folder or absent | Refused before running |
| Duplicate rule id across two rule files | Refused |
| Rule file invalid | Tool config error → `failed`; tool message kept |
| Check object contains files the tool ignores by default | Skipped files listed; that check's tool evidence failed; agent may rerun with `include_ignored` |
| Scan targets for C1 do not cover C1's object | Refused |
| Very large target | Staging bounded by evidence limits; time limit stops the run → `timed_out` |
| Matched source line contains a secret | Masked before storage |
| Verification already concluded | Refused (`RUN_FINISHED`) |
| Guard runs on Windows | Pre-check gap "Adapter execution not supported on Windows in this version"; failed method per check; nothing executed |
| File with a syntax error | Reported by the tool as scanned without any error (observed). Python files are checked by the toolkit and unparseable ones make the check's tool evidence a failed method; for other languages the evidence and report state the limit (user decision 10-19-2026) |
| Rule using features the tool cannot confirm it ran (taint, interfile, join, extract, options) | Refused before running (only validated search-mode rules) |
| Same rule matches twice at one location | Separate findings unless merged with evidence (AC-002A-05a) |

## Out of Scope

- Trivy (002-D) and Strix (002-E) Adapters; shared budget, cancellation and data-egress control (002-C) beyond the per-run time limit; OS-level network or process isolation.
- Runtime generation of Opengrep rules (A-11), bundled or downloaded rule packs, registry configs, rule folders.
- Custom or self-built binaries; signature (cosign) verification (official release digests are used instead).
- Formal performance/effectiveness evaluation and delivery bar (AC-28, FEATURE-003-C); SARIF output.
- Automatic tool installation or update.

## Technical Considerations

- Observed tool facts to respect ([tool validation](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/tool-validation/README.md)): exit 0 with or without findings, 7 for config errors, 2 for target errors; JSON `errors`, `skipped_rules`; skipped paths only in verbose output; `check_id` prefixed by the rule location; matched source in `extra.lines`; Semgrep-only options rejected; logs/caches under the tool home; registry contacted without a local config.
- Exact command options, environment, staging layout, request schema, severity mapping table, registration record location (machine-local private data), maximum time limit and locking during long runs are decided in technical design, with version-specific tests.
- Official digests v1.31.0 (release metadata): macOS arm64/x86, Linux manylinux/musllinux aarch64/x86, Windows x86 — only Linux manylinux aarch64 executed so far (digest matched).

## Open Questions

None material. Decisions (10-19-2026, interact-with-human):

| Question | Decision |
|---|---|
| Tool-level validation environment (S-07) | Download official Opengrep v1.31.0 into a disposable container only; run on both samples; record results (done) |
| Rule source (A-10/A-11) | Local rule files only, named per run; no bundled pack; no runtime generation; no network fetch |
| How results reach the ledger | Script runs the Adapter inside the Guard verification and records provenance-backed per-check runtime evidence and tool findings; the agent judges ledger states and reviews |
| Tool trust (A-08) | Maintainer registers; registration and every run compare the digest with the toolkit's official release digests of verified versions before execution; other binaries refused |
| Original-project protection | Tool scans a private disposable staged copy; network not OS-enforced (honest limit; 002-C) |

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| A-08, A-09, AC-24 (pre-check, no download); FR-002B-2/3 | US-03 | AC-002B-01a…01f | N/A | Integration | covered (A-08 "authorized budget/environment": time limit here, shared budget/egress deferred to 002-C) |
| A-03, AC-24 (named parameters), breakdown AC-002B-01 (parameters, targets, mode); FR-002B-1/4 | US-02 | AC-002B-02a…02e | N/A | Integration | covered |
| AC-24 (normalization, honest failure), FR-17 principle (original protection); FR-002B-5/6 | US-01, US-04, US-05 | AC-002B-03a…03k | N/A | Integration | covered (network enforcement deferred to 002-C) |
| Breakdown AC-002B-01, AC-002B-02; A-02…A-07, O-06; FR-002B-7 | US-02, US-06 | AC-002B-04a…04f | N/A | Integration | covered |
| Breakdown AC-002B-03; S-07, FR-18 | US-07 | AC-002B-05a, 05b | N/A | Integration | covered (validation performed in TASK-027) |
| FR-002B-8; FEATURE-001-A status contract | US-03 | AC-002B-06a, 06b | N/A | Integration | covered |
| AC-28, A-11, A-10 (rule sets), Trivy/Strix, budget/cancel/egress | — | — | N/A | — | out of scope / deferred |

## Context and Verification Evidence

- Sources: [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) (FR-16, FR-17, FR-18, AC-24, AC-28; FEATURE-002-B details), inventory v2 A-01…A-12, §9.3, §9.4, S-07, E-01; [FEATURE-002-A specification](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/specification.md) and design; FEATURE-001-A status contract.
- Tool-level validation (TASK-027): [tool-validation/README.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/tool-validation/README.md) — Opengrep v1.31.0, binary `2b713a29…` equal to the official release digest, Linux aarch64 container, offline scans on marathon (2 of 5 files scanned by default, 0 findings) and WebGoat `src` (319 files, 2 findings, ≈1.3 s, ≈268 MB RSS); error/exit cases and known issues recorded.
- Independent review (rubber-duck, 10-19-2026): 10 blocking + 2 non-blocking findings fixed — binary authenticity before execution (official digests, user decision); enforced original protection (staged copy, user decision) and honest network limit; per-check object coverage (02c); skipped rules and unaccounted files (03e); per-check evidence and auxiliary substitution consistent with AC-002A-04j (03d, 03j); additive FEATURE-002-A record extension for tool provenance and severity (03c, Dependencies); disposable tool home and masking of every persisted field (03a, 03i); rule files only and duplicate ids (02b, 02d); recorded method choice (04d); "mode"/budget mapping and A-08 coverage (traceability); platform validation claims (NFR-002B-4, 05b); command details moved to design. Focused re-review: all 12 resolved; 2 new blocking findings fixed — digests bound to the executed/scanned bytes via private snapshots and the recorded target digests (01d, 03k, FR-002B-5); rule files staged too and the "only sees" claim replaced by the testable "passes only staged paths" with an explicit no-isolation limit (03a, 03b, NFR-002B-1).
- Board: FEATURE-002-B, EPIC-002, v1.0, Planned, depends on FEATURE-002-A (Completed). Mockups: none. Execution mode: free-mode.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-002B-05a | Tool-level validation record exists (pre-implementation) | evidence recorded; verification at acceptance | not measured |
| other AC-002B-* | Planned per Test Type; no tests yet | planned | not measured |
