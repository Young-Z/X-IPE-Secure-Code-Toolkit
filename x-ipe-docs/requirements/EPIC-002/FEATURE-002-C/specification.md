# Feature Specification: Verification Budget, Cancel & Data-Egress Control

> Feature ID: FEATURE-002-C  
> Epic: EPIC-002 (Guard: Verification, Adapters & Evidence)  
> Version: v1.1 (base v1.0 delivered; v1.1 = CR-TASK-077 amendment)  
> Status: Refined — confirmed by human (TASK-035, 2026-10-20)  
> Last Updated: 10-20-2026
> Amended: v1.1 on 10-23-2026 by [CR-TASK-077](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/CR-TASK-077-helpers-coverage.md) (additive Reviewer coverage item `helpers`; delivered v1.0 text kept)

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-20-2026 | Initial specification | N/A |
| v1.0 | 10-20-2026 | Edge case added: cancel while another process is suspended mid-commit → "finalization pending" until that commit finishes (design review, TASK-036); no AC wording changed | N/A |
| v1.1 | 10-23-2026 | Additive Reviewer coverage item `helpers` (human decision B12 = A, `x-ipe-docs/dao/26-10-23/human_decisions.md`): new AC-002C-01h, AC-002C-01i; supersession notes on AC-002C-01c/01d and FR-002C-2 (original text kept); FR-002C-2a; edge cases; traceability row. Existing kinds, records, request files and delivered tests unchanged | [CR-TASK-077](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/CR-TASK-077-helpers-coverage.md) |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: script commands, files and Markdown/structured reports. Bounded discovery: EPIC-002 and the idea folder contain no mockups for this feature. | — | — |

## Overview

FEATURE-002-C puts three controls around every Guard verification (FEATURE-002-A) and every Adapter run (FEATURE-002-B and later Trivy/Strix):

- **One shared budget per verification.** A total execution time plus a limited number of extra attempts.
  - **Agreed:** an agent can open with the toolkit defaults or less. Only the user at an interactive terminal can add more (user decision, B-03).
  - **Time:** wall-clock since opening, frozen while the verification is paused. The agent may pause while it waits for the user. Nothing can start or be recorded while paused, and every pause is listed in the report with its reason (user decision, B-05).
  - **Attempts:** every unit of work is **registered before it starts** (semantic review, Reviewer call, helper script, generation; tool runs register themselves). Each attempt is a single-use lease that its first record finishes, and results must cite it (user decision). The first attempt of each planned method for each check is planned work. Any further attempt for the same check and method, or for a method added later, is an extra attempt (B-02, B-03).
  - **Exhaustion:** new attempts are refused. Attempts already started may still record their results, and the verification can be concluded with an honest partial report (B-06).
  - **Model usage:** summed where the host reports it and stated as unknown otherwise; no price table and no prediction (B-04).
- **User cancellation.** Cancel ends one verification for good:
  - Nothing that happens afterwards changes its result.
  - A tool it is running is terminated by the toolkit process that owns it. Termination is claimed only when that process has observed its tool processes exit.
  - Completed results are kept, and the partial report gives Fail when a confirmed problem requires it, otherwise "cannot confirm pass". It is never Pass (user decision).
  - Work the toolkit does not own (the host agent, its Reviewer sub-agent, remote services) is asked to stop through the skill. The report says that this termination is not confirmed by the toolkit (B-08–B-10).
- **Purpose-specific data egress.**
  - **Four purposes, granted separately:** Reference fetching, tool/vulnerability-database updates, requests to the target under test, and submissions to models or third-party services (E-01). Nothing is granted by default.
  - **Who grants:** the user, for one verification, at an interactive terminal, naming the recipient, data and scope (user decision).
  - **Toolkit-owned calls** made by the toolkit's own network clients (Adapters, Reference fetching) go through a gate that makes the actual call only under a matching single-use authorization. The payload is minimized and masked before sending. Network access by external tools that Adapters launch is not gated; an Adapter whose tool needs network for a purpose runs offline or is refused without a grant.
  - **Agent calls** are declared before they are made, checked against the grants and recorded. This is an audit control, not enforced blocking. The toolkit cannot see undeclared calls, and network access is not OS-enforced (user decision).
  - **Not egress:** the host agent session, including its Reviewer sub-agent, is the user's chosen model. Anything sent elsewhere needs a submission grant (user decision).
  - **Masking:** every stored field is masked; signing private keys and model credentials are never grantable (E-02).

Default numbers (time, attempts, maximums, cancel wait) are decided in technical design (B-07, D-16), not here. Out of scope: budgets for Copilot generation (FEATURE-003-A), OS-level network or process isolation, a heavy DLP platform, cost guarantees and an asynchronous progress API.

## User Stories

- **US-01:** As a Developer, I want each verification to run within one budget I agreed to, which retries, method changes and new sessions cannot reset or bypass, so that cost stays predictable and I get an honest partial result instead of an endless run.
- **US-02:** As a Developer, I want time spent waiting for my answers excluded only while the verification is visibly paused and no work can proceed, so that the budget measures execution, not my think time.
- **US-03:** As a Developer, I want only myself to raise the budget, so that an agent cannot silently extend cost.
- **US-04:** As a Developer, I want to cancel one verification and keep what was already found, so that I can stop wasted work without losing confirmed problems or affecting other runs.
- **US-05:** As an Owner, I want every outbound call to be authorized for its specific purpose, recipient and data, so that "network allowed" never means "source code may be uploaded".
- **US-06:** As a Developer reading a report, I want budget use, attempts, pauses, extensions, cancellation and every outbound declaration shown with honest limits, so that I can trust what the run did and did not do.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-04 | EPIC-001 G-04; FR-21 (B-01…B-06, B-08…B-10); AC-25, AC-26 | Developer | Runs stay within the agreed cost; exhaustion and cancel give honest partial reports | Shared budget with registered attempts, visible pauses, user-only increases, final cancellation with owned-tool termination. Selected means: wall-clock frozen while paused; attempt registration (user decisions) | Scenario: a verification whose retries exhaust the budget concludes with listed unverified checks; a cancelled run keeps its confirmed Fail | Estimates, not hard money caps; no price table; unregistered host-agent work and host calls cannot be observed or stopped (stated) | AC-002C-01a…04f, 06b | not measured |
| G-05 | EPIC-001 G-05; FR-20 (E-01, E-02); AC-29 | Owner, Developer | Calls by the toolkit's own network clients never send data without a matching purpose-specific grant and send only minimized, masked data; agent calls are declared and audited; network-needing tool runs need a grant or run offline | Per-verification grants at an interactive terminal; gated single-use authorization for toolkit-owned calls; declare-before-call audit for agent calls; masked egress records. Selected means: host session is not egress; no OS enforcement (user decision) | Scenario: with only a target-request grant, sending source to a model is refused and recorded; a toolkit-owned call to an ungranted host is not made | No heavy DLP; undeclared agent calls and network access by launched tools cannot be observed or blocked (stated) | AC-002C-05a…05h, 06a | not measured |

Breakdown ACs: AC-25 → AC-002C-01c…01e, 03a…03c; AC-26 → AC-002C-04a…04f; AC-29 → AC-002C-05a…05h.

> **CR-TASK-077 (v1.1):** G-04 is additionally covered by AC-002C-01h and AC-002C-01i (Reviewer work on FEATURE-002-F helpers is registered and counted in the same shared budget). AC-25 → also AC-002C-01h, 01i.

## Acceptance Criteria

Commands are named here for readability; final names and request schemas are fixed in technical design.

### AC-002C-01: Budget, Attempts and Consumption

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002C-01a | GIVEN a request to open a verification WHEN it carries no budget THEN the toolkit defaults are recorded and marked as defaults AND WHEN it carries a budget within the defaults THEN that budget is recorded AND a budget above the defaults or not positive is refused with nothing created and the next step "open with the defaults, then let the user extend it" | Integration |
| AC-002C-01b | GIVEN an open verification WHEN any Guard command for it runs THEN its result and `guard show` state the budget, the consumed time, the remaining time and the extra attempts used and remaining AND consumed time = wall-clock since opening minus all pause time (completed pauses and the elapsed part of a current pause), so it is frozen while paused AND it never decreases between commands, including after resume or a backwards clock change | Integration |
| AC-002C-01c | GIVEN an open, unpaused verification with remaining time WHEN the agent registers an attempt naming its kind (semantic review, Reviewer, helper script, generation) and what it covers (checks and methods, or findings and N/A decisions for a Reviewer) THEN an attempt id, its start time and the remaining-time deadline are returned and recorded AND every tool run registers its own attempt AND a record, finding or Reviewer record that cites no registered attempt, an attempt of another verification, an attempt of another kind, or an item outside the attempt's coverage is refused | Integration |
| AC-002C-01d | GIVEN registered attempts WHEN extra attempts are counted THEN covering a check and a method that is in the plan, or a finding or N/A decision for a Reviewer, for the first time is planned work AND every check-and-method pair or Reviewer item an attempt covers again, whatever the earlier result, counts as one extra attempt (an attempt re-covering three pairs uses three) AND every pair of a method added by a later switch or supplement counts as an extra attempt AND planned pairs grouped in one attempt use no extra attempts | Integration |
| AC-002C-01e | GIVEN consumed time and attempts WHEN a method is switched or supplemented, the plan is re-recorded, or a new agent session continues the same verification THEN nothing is reset AND an attempt is a single-use lease: the first record (or Reviewer record) citing it finishes it atomically and later citations are refused AND a record that arrives after the attempt's deadline is accepted only for an attempt started before exhaustion, with its overrun counted in consumed time and shown in the report | Integration |
| AC-002C-01f | GIVEN record or Reviewer requests WHEN they carry model usage reported by the host (requests, input and output tokens) for their attempt THEN the usage is summed per verification AND model-capable attempts (semantic review, Reviewer, generation) without reported usage are counted as unknown while attempts that use no model (tool runs, local helper scripts) are "not applicable" AND the report shows the totals and the number of unknown attempts without any price or prediction | Integration |
| AC-002C-01g | GIVEN a tool run request WHEN its time limit exceeds the remaining time THEN the effective limit is the remaining time and the cap is recorded with the run AND the tool's running time is part of the consumed time | Integration |
| AC-002C-01h | GIVEN an open, unpaused verification with remaining time and helpers (FEATURE-002-F temporary check scripts) known in it WHEN the agent registers a Reviewer attempt whose coverage names helpers (alone or together with findings and N/A decisions) THEN the attempt is recorded with those helpers AND a helper unknown in that verification, helpers named for any other attempt kind, or a Reviewer attempt covering nothing is refused and nothing is recorded AND a Reviewer record citing the attempt that judges a helper outside its coverage is refused AND attempts and requests that name no helpers are recorded and validated exactly as before (CR-TASK-077) | Integration |
| AC-002C-01i | GIVEN registered attempts WHEN extra attempts are counted THEN covering a helper for the first time is planned work AND every helper an attempt covers again, whatever the earlier result or attempt status, counts as one extra attempt AND when the extra attempts are used up an attempt re-covering a helper is refused naming the attempt limit and that helper while first coverage is still accepted AND pause, time exhaustion, cancellation, overrun and model-usage rules apply to these attempts unchanged AND verifications opened before this change load and count as before (CR-TASK-077) | Integration |

> **Supersession note (CR-TASK-077, v1.1, human decision B12 = A):** AC-002C-01c and AC-002C-01d keep their delivered wording and remain valid for findings and N/A decisions. Where they say a Reviewer attempt covers "findings and N/A decisions" and count "a finding or N/A decision for a Reviewer", the Reviewer coverage is extended by AC-002C-01h and AC-002C-01i to also include helpers. The `helper` subject type of the shared Reviewer record (FR-002A-4 extension point) and the helper records themselves belong to FEATURE-002-F, not to this feature.

### AC-002C-02: Pause and Resume

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002C-02a | GIVEN an open verification WHEN the agent pauses it with a reason THEN the pause start and reason are recorded AND while paused attempt registration, plan, record, Reviewer, tool and egress-declaration commands are refused with a "paused" reason and the resume step AND show, resume, cancel and conclude still work | Integration |
| AC-002C-02b | GIVEN a paused verification WHEN it is resumed, concluded or cancelled THEN the pause period (start, end, reason) is recorded AND excluded from consumed time AND listed in the report together with the statement that work done outside the toolkit while paused cannot be observed | Integration |

### AC-002C-03: Exhaustion and Extension

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002C-03a | GIVEN a verification whose consumed time has reached its total time WHEN a new attempt is registered or a tool run is requested THEN it is refused naming the exhausted time limit and nothing is recorded AND records citing an unfinished attempt that started before exhaustion are accepted AND a ledger-only request (ledger states that reference already recorded evidence, and nothing else: no evidence, findings, conflicts, merges or method changes) is accepted AND every other change is refused | Integration |
| AC-002C-03b | GIVEN a verification whose extra attempts are used up but time remains WHEN an extra attempt is registered THEN it is refused naming the attempt limit AND planned first attempts are still accepted | Integration |
| AC-002C-03c | GIVEN an exhausted budget WHEN the verification is concluded THEN the verdict follows FEATURE-002-A rules on the recorded evidence only (never Pass with an unconfirmed check) AND the report states that the budget was exhausted, which limit and the consumption AND lists checks that are `unconfirmed` or have no ledger state as unverified, while `not_met` and reviewed `n/a` checks keep their states AND unfinished attempts are listed | Integration |
| AC-002C-03d | GIVEN an open verification WHEN a User at an interactive terminal adds time and/or attempts with a reason and types the verification id to confirm THEN the budget is increased and the extension is recorded with time, amounts and reason AND consumption is unchanged | Integration |
| AC-002C-03e | GIVEN the extension command run without an interactive terminal (as an agent would) or with a mismatching typed id, or any request file that tries to change the budget after opening WHEN executed THEN it is refused AND the budget is unchanged | Integration |

### AC-002C-04: Cancellation

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002C-04a | GIVEN an open or paused verification WHEN it is cancelled THEN the cancellation is recorded durably at once, without waiting for the Guard lock held by a running tool, and from then on every command that would add or change verification data (evidence, findings, Reviewer records, ledger states, conflicts, method changes, attempts, grants, declarations) is refused with a "cancelled" reason AND only the cancellation workflow itself may still record its metadata (termination acknowledgement, attempt cancellation, finalization) AND after termination of its owned tool is requested and the bounded wait has ended, exactly one final structured result and report are created atomically, whose verification data is only what was recorded before the cancellation AND other verifications of the same project, including one with a running tool, are unaffected | Integration |
| AC-002C-04b | GIVEN a tool run of that verification in progress WHEN it is cancelled THEN the toolkit process that owns the tool terminates the tool's processes and removes its staging AND the run's attempt is listed as cancelled without new evidence AND the final result states termination confirmed only when that owner reported, within the bounded wait, that it observed every tool process it started exit | Integration |
| AC-002C-04c | GIVEN a tool run whose owning toolkit process does not acknowledge the cancellation within the bounded wait, or whose termination it cannot confirm WHEN cancel returns THEN the verification is still cancelled AND the result and report state termination not confirmed, naming the process, and never claim it stopped | Integration |
| AC-002C-04d | GIVEN a tool run whose owner finishes or acknowledges after the cancellation was recorded WHEN it tries to record results THEN nothing is added and the final cancelled result and report are not changed AND two concurrent cancels yield one final result | Integration |
| AC-002C-04e | GIVEN a cancelled verification WHEN its report is produced THEN all results recorded before the cancellation are kept (evidence, findings, Reviewer records, ledger states) AND the verdict is Fail if a confirmed problem makes it Fail under FEATURE-002-A rules, otherwise "cannot confirm pass", never Pass AND unverified checks and unfinished attempts are listed AND agent attempts (semantic review, Reviewer, helper, generation) that were unfinished when the cancellation was recorded are listed as "stop requested, not confirmed by the toolkit" AND the report states that remote requests may continue or be billed | Integration |
| AC-002C-04f | GIVEN a finished verification WHEN cancel is requested THEN it is refused and nothing changes AND GIVEN an already cancelled verification THEN cancel returns the same result AND a missing or damaged report of a cancelled verification is regenerated only from its stored final result, without recomputing anything | Integration |

### AC-002C-05: Data Egress

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002C-05a | GIVEN a newly opened verification WHEN its egress grants are read THEN none of the four purposes (Reference fetching, tool/database update, requests to the target, submission to models or third parties) is granted | Integration |
| AC-002C-05b | GIVEN a User at an interactive terminal WHEN they grant one purpose for one open verification naming the recipient (origin), the data categories and the scope with a reason and type the verification id to confirm THEN the grant is recorded with time AND the command without an interactive terminal, with a mismatching id, for a finished or cancelled verification, with a recipient or scope containing credentials (for example user information or tokens in a URL), or including the signing private key or model credentials is refused and nothing is recorded | Integration |
| AC-002C-05c | GIVEN an agent's declaration of an outbound call (purpose, recipient, data categories, items and scope) WHEN it is covered by a grant (same purpose and recipient, data categories and scope within the grant) THEN a single-use declaration id is returned and the declaration is recorded as allowed AND otherwise it is recorded as refused and "not authorized" is returned naming the missing purpose, recipient, data or scope | Integration |
| AC-002C-05d | GIVEN only grants for Reference fetching, tool updates or requests to the target WHEN a declaration or a toolkit-owned call would send source code, findings or credentials to a model or third party THEN it is refused and recorded AND a toolkit-owned call is not made (AC-29) | Integration |
| AC-002C-05e | GIVEN grants and declarations WHEN stored THEN every persisted free-text and URL field (items, recipient, scope, reason, refusal details) is masked with the FEATURE-002-A patterns AND a signing private key or model credential in a recognized format never appears in any record or report AND the report repeats that masking is pattern-based and unknown credential formats may remain (NFR-002A-2) | Integration |
| AC-002C-05f | GIVEN a toolkit component making an outbound call through the egress gate WHEN the call is made THEN it happens only with a matching single-use authorization for that purpose, origin, data and scope AND a redirect to another origin, a fallback service, a retry to another host or telemetry is a new call that needs its own grant and is otherwise not made AND toolkit components send no telemetry by default AND the payload sent is built only from the authorized items, limited to the granted data categories and scope, and masked before transmission AND a payload in which a prohibited credential is still recognized is not sent | Integration |
| AC-002C-05h | GIVEN an Adapter whose tool run, as configured, needs network access for a purpose (for example a database update) WHEN no matching grant exists THEN it runs only in an offline configuration or is refused before execution with the missing purpose named AND an Adapter whose tool needs no network (Opengrep) runs without any grant, with the report stating that the tool's own network access is not enforced | Unit |
| AC-002C-05g | GIVEN a concluded or cancelled verification WHEN its report is produced THEN it lists every grant and every declaration and gated call with purpose, recipient, data, scope and decision AND states that agent declarations are an audit record, that network access is not OS-enforced (including network access by tools the Adapters launch) and that undeclared calls cannot be observed by the toolkit | Integration |

### AC-002C-06: Guard Skill, Report and Compatibility

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002C-06a | GIVEN the Guard skill package WHEN its instructions are inspected THEN they direct the agent to: <br>• open with the defaults or less and ask the user to extend when more is needed; <br>• register an attempt before every unit of work and cite it; <br>• pause only while waiting for the user and do no work while paused; <br>• stop new attempts and conclude when the budget is exhausted; <br>• cancel on the user's request and stop its own Reviewer and helper work; <br>• declare every outbound call before making it and send only the declared, minimized and masked data; <br>• never send source, findings or credentials to another model or service without a submission grant. <br>AND they state that the host session and its Reviewer sub-agent are not egress | Integration |
| AC-002C-06b | GIVEN a concluded or cancelled verification WHEN its report is produced THEN a Budget section shows the limits (and whether defaulted), extensions, consumed time, pauses with reasons, attempts (planned, extra, unfinished), model usage (with unknown attempts) and any exhaustion AND a Cancellation section appears when cancelled | Integration |
| AC-002C-06c | GIVEN a verification opened before this feature (no budget or attempt fields) WHEN any command reads it THEN the toolkit defaults apply measured from its opening AND records already stored stay valid without attempt ids AND new records must cite attempts AND the report states that the budget was defaulted AND no grant is assumed | Integration |

## Functional Requirements

- **FR-002C-1 Budget record.** Each verification stores: total time, extra attempts, whether defaulted, extensions (time, amounts, reason), pauses (start, end, reason), consumed-time high-water mark, attempts, model-usage totals and the unknown count. An open request may carry a budget up to the defaults.
- **FR-002C-2 Attempts.** Register an attempt (kind, coverage) → id, start time, deadline. Each attempt has a status: unfinished, finished, or cancelled. Each attempt is a single-use lease: the first record citing it finishes it atomically, and later citations are refused. Tool runs register and finish their own attempt. Planned versus extra counting is per check-and-method pair (or Reviewer item) covered, as in AC-002C-01d.
- **FR-002C-2a Reviewer coverage of helpers (CR-TASK-077).** A Reviewer attempt may also cover helpers known in the verification (FEATURE-002-F). "Reviewer item" in FR-002C-2 and BR-02 includes helpers: first coverage is planned, every re-coverage is one extra attempt. Requests, attempt records and run states that name no helpers are unchanged; no new problem code.
- **FR-002C-3 Consumption.** Consumed time is wall-clock since opening minus all pause time, kept as a never-decreasing high-water mark. Each attempt and tool run receives the remaining-time deadline.
- **FR-002C-4 Pause and resume.** Pause (with reason) and resume one verification. While paused, only show, resume, cancel and conclude are accepted.
- **FR-002C-5 Exhaustion.** When the time is exhausted, new attempts and tool runs are refused. Records completing earlier-started attempts are accepted, as are ledger-only requests. When the extra attempts are exhausted, only extra attempts are refused. Conclusion yields the partial report.
- **FR-002C-6 Extension.** Interactive-terminal command (verification id, minutes, attempts, reason) confirmed by the typed id. Same gate as risk acceptance.
- **FR-002C-7 Cancel.** Command to cancel one verification. The cancellation is durable and independent of the project's Guard lock. One final result reflects only what was recorded before it. The owning process of a running tool terminates it and reports whether termination is confirmed; a bounded wait applies. Late results cannot change the final result. Report repair renders only from the stored result.
- **FR-002C-8 Egress grants.** Interactive-terminal command granting one purpose for one open verification, with these elements:
  - recipient: a canonical origin, free of credentials;
  - data categories: from a fixed list defined in design;
  - scope: paths or target URLs;
  - reason.

  Signing private keys and model credentials are never grantable.
- **FR-002C-9 Egress declarations and gate.**
  - **Agent declaration:** a command that checks the declaration against the grants and returns a single-use declaration id or a refusal. The result is recorded masked.
  - **Toolkit gate:** a library gate wraps every outbound call made by the toolkit's own network clients (Adapters, Reference fetching). It makes the call only under a matching single-use authorization, with a payload built from the authorized items, minimized and masked. Redirects, fallbacks, retries to another host and telemetry are new calls.
  - **Adapter network needs:** each Adapter states whether its tool, as configured, needs network and for which purpose. Without a matching grant, the tool runs offline or is refused before execution.
- **FR-002C-10 Report and show.** The FEATURE-002-A report and structured result gain Budget, Cancellation and Egress sections. `guard show` shows the budget, attempt, pause and cancel state.
- **FR-002C-11 Skill.** Guard SKILL.md and its references are updated per AC-002C-06a.

## Non-Functional Requirements

- **NFR-002C-1 Safety.** The toolkit's own code makes no network call except through the egress gate under a grant; in this feature no toolkit component needs one. External tools launched by Adapters are not network-isolated (stated limit). All budget, attempt, pause, cancel and egress records are atomic and masked before storage.
- **NFR-002C-2 Honesty.** Termination, egress and model-usage claims are made only from what the toolkit observes. Items it cannot observe are stated: unregistered agent work, host calls, undeclared network calls, work done while paused and remote billing.
- **NFR-002C-3 Isolation of runs.** Cancel, pause, exhaustion and grants affect only the named verification.
- **NFR-002C-4 Portability.** Verified on macOS and Linux. On Windows, the budget, attempt, pause, cancel and egress records work, and tool runs remain refused (NFR-002B-4).

## UI/UX Requirements

There is no graphical UI. New Guard commands return the toolkit result envelope (text and `--json`), with one next step per refusal. Interactive-terminal commands (extension, egress grant) follow the risk-acceptance pattern: a prompt, the typed verification id, and refusal when the terminal is not interactive.

## Dependencies

- **FEATURE-002-A** (Completed): run state, Guard lock, record/review/conclude, verdict rules and ledger states, report and report repair, masking, the interactive-terminal gate.
- **FEATURE-002-B** (Completed): tool runs (time limit, process-group termination, staging cleanup, failed-method evidence, single commit).
- **Consumers:**
  - FEATURE-002-D: tool/database update purpose, through the gate.
  - FEATURE-002-E: model and target purposes, through the gate; budget.
  - FEATURE-002-F: budget, attempts.
  - FEATURE-002-F (CR-TASK-077): Reviewer coverage of helpers (AC-002C-01h, 01i); FEATURE-002-F owns the `helper` Reviewer subject and the helper records.
  - FEATURE-001-E: Reference fetching purpose, through the gate.
  - FEATURE-003-A: Copilot uses Guard under these controls.
  - FEATURE-003-C: cancel and budget-exhaustion acceptance cases (AC-30).

## Business Rules

- **BR-01:** One budget per verification. Nothing resets consumption (B-01, B-03).
- **BR-02:** Planned work is the first attempt per planned check and method, or per Reviewer item. Everything else is an extra attempt, including reruns after a success and methods added later (B-02).
- **BR-03:** Only a User at an interactive terminal raises the budget or grants egress. Agents and request files cannot (B-03, E-01).
- **BR-04:** Exhaustion and cancellation never produce Pass with unconfirmed checks and never skip verification silently. Results of attempts started within the budget are kept (B-06, B-09).
- **BR-05:** Termination is claimed only when confirmed by the owning toolkit process (B-10).
- **BR-06:** "Network allowed" for one purpose never authorizes another purpose. Submissions to models or third parties always need their own grant naming the recipient and data (E-01, AC-29).
- **BR-07:** Signing private keys, model credentials and credential-bearing URLs are never grantable; credentials in recognized formats are never stored, and unknown formats are a stated masking limit (E-02, AC-27, NFR-002A-2).
- **BR-08:** The host agent session, including its Reviewer sub-agent, is not egress (user decision).
- **BR-09:** No price table, token prediction or prediction agent (B-04). Unreported usage of model-capable attempts is unknown; attempts that use no model are not applicable.
- **BR-10:** After cancellation, nothing changes the final result.

## Edge Cases & Constraints

| Scenario | Expected Behavior |
| --- | --- |
| System clock moves backwards | Consumed time keeps its high-water mark |
| Budget runs out during a tool run | The tool is capped at the remaining time and ends as timed out (failed method). Later attempts are refused |
| Reviewer started before exhaustion, recorded after | Accepted: it cites its earlier-started unfinished attempt. The overrun counts and is shown |
| Agent groups several retried checks into one attempt | Each retried check-and-method pair counts as one extra attempt |
| Agent registers one attempt and tries to cite it in a second record | Refused: the first record finished the attempt |
| Agent rewrites the plan to make a retried method look new | An attempt for a check and method already attempted is extra. A method added after the first attempt on a check is extra |
| Pause requested while a tool runs | The pause is recorded once the tool run ends (the run holds the Guard lock). The tool's time counts |
| Cancel while paused | Cancelled. The pause closes at the cancel time |
| Owning process of a running tool was killed | Cancelled. Termination is not confirmed (the process is named) |
| Two cancels at once | One final result. Both return it |
| A process suspended in the middle of committing a change to the same verification when cancel arrives | The cancellation is recorded and every change is refused. The final result is created once that commit has finished (it counts as pre-cancel work), at the latest on the next cancel or conclude after the suspended process ends; until then cancel reports "finalization pending" (clarification during design, TASK-036) |
| Declaration recipient differs only in letter case, default port or trailing slash | Compared as canonical origins (normalization defined in design) |
| Opengrep run | Needs no egress grant and makes no gated call. Its network access is not enforced (stated) |
| Verification opened before this feature | Defaults apply from its opening. Existing records stay valid. No grants |
| Grant or declaration for a finished or cancelled verification | Refused |
| Reviewer attempt names a helper not known in the verification, or helpers on a non-Reviewer attempt (CR-TASK-077) | Refused; nothing recorded |
| Post-run acceptance of a helper already reviewed before execution (CR-TASK-077) | Re-coverage: one extra attempt; refused naming the attempt limit when none are left, until the user extends |
| Reviewer attempt covering a helper was cancelled or never cited (CR-TASK-077) | The helper still counts as covered; covering it again is extra |

## Out of Scope

- Budgets for Copilot generation (FEATURE-003-A); cost guarantees or money caps.
- OS-level network or process isolation; blocking undeclared agent calls; a DLP platform.
- Stopping host-agent or remote calls; an asynchronous progress API (B-11 remote cancel).
- Standing per-project grants (user decision: per verification only).
- Network evidence, screenshots and their storage or integrity (D-19 beyond declarations: FEATURE-002-E).
- Default numbers (B-07), limits (D-16), signalling, polling and storage mechanisms: technical design.

## Technical Considerations

- Observable constraints that the design must satisfy:
  - Cancel must not wait for the Guard lock that a running tool holds.
  - The cancellation must be durable before cancel returns.
  - The final result is written exactly once.
  - Every state change is atomic.
- Decisions left to technical design: B-07 (defaults and maximum), D-16 (rate and size limits), the cancel acknowledgement wait, canonical-origin normalization, the data-category list, request fields for attempts and model usage, and the gate interface for FEATURE-002-D/E and FEATURE-001-E.

## Open Questions

None blocking. Decided by the user on 10-20-2026:

- Time is wall-clock minus explicit pauses. The agent may pause, the pause is visible, and nothing can be done while paused.
- Budget increases only by the User at an interactive terminal, and opening is capped at the defaults.
- A cancelled verification gives Fail or "cannot confirm pass", never Pass.
- Egress grants are per verification, at an interactive terminal.
- The host session is not egress, and there is no OS network enforcement.
- Attempts are registered before work.

## Acceptance Traceability

| Source | Story | Spec ACs | Mockup | Planned Validation | State |
| --- | --- | --- | --- | --- | --- |
| AC-25; FR-21 (B-01…B-06) | US-01, US-02, US-03 | AC-002C-01a…03e | N/A | Integration | planned |
| AC-26; FR-21 (B-08…B-10) | US-04 | AC-002C-04a…04f | N/A | Integration | planned |
| AC-29; FR-20 (E-01, E-02) | US-05 | AC-002C-05a…05h | N/A | Integration (05h Unit) | planned |
| FR-20, FR-21 reporting; skill; compatibility | US-06 | AC-002C-06a…06c | N/A | Integration | planned |
| CR-TASK-077 (B12 = A); AC-25; FR-21 (B-02) | US-01 | AC-002C-01h, 01i | N/A | Integration (plus Unit) | planned (CR, not implemented) |
| B-07, B-11 (remote/async), D-16, D-19 (beyond declarations) | — | — | N/A | — | design / out of scope |

## Context and Verification Evidence

- **Sources:**
  - requirement-details.md: FR-20, FR-21, AC-25, AC-26, AC-29, and the FEATURE-002-C breakdown entry.
  - Feature inventory v2: §9.5 (E-01, E-02), §10.1 (B-01…B-07), §10.2 (B-08…B-11), D-16, D-17, D-19.
  - FEATURE-002-A and FEATURE-002-B specifications and code: the project-wide Guard lock held during tool runs, `method_status` on evidence, the open/finished states, the interactive-terminal gate.
- **User decisions** (TASK-035, 10-20-2026): seven decisions, all recommended options; listed under Open Questions.
- **Independent review** (rubber-duck, 10-20-2026): 8 blocking and 2 non-blocking findings, all addressed:
  - attempt registration and accounting (01c–01e);
  - initial budget capped at the defaults (01a);
  - pause-frozen consumption (01b);
  - started attempts keep their results, and ledger-only is defined (03a);
  - final-result cancel semantics with races (04a–04d);
  - gated single-use toolkit calls, redirects and telemetry (05f), and the narrowed G-05;
  - masking of every field (05e);
  - focused re-review (10-20-2026): attempts made single-use leases with per-pair retry counting (01d, 01e); cancel ordering fixed (durable mark → termination request → bounded wait → one final result, 04a–04d); payload minimization and masking for gated calls (05f); Adapter network needs and the honest child-tool limit (05h, 05g, NFR-002C-1); credential claim scoped to recognized formats (05e); "not applicable" model usage (01f); stop-requested status only for unfinished attempts (04e);
  - 002-A ledger states preserved (03c);
  - report repair (04f);
  - mechanics moved to design.
- **Engineering delivery:** not started. **Stakeholder outcome:** not measured.
- **CR-TASK-077 (10-23-2026, v1.1):** additive Reviewer coverage item `helpers` authorized by the human (B12 = A). Delivered v1.0 evidence stays valid for requests without helpers; AC-002C-01h/01i are planned, not implemented. Classification, conflicts, decisions DEC-1…DEC-6 and the test plan: [CR-TASK-077](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/CR-TASK-077-helpers-coverage.md).
