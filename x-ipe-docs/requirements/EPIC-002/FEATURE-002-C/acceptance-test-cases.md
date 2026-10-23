# Acceptance Test Cases

> Feature: FEATURE-002-C — Verification Budget, Cancel & Data-Egress Control (EPIC-002)
> Status: Verified delivery for the approved scope. All 31 ACs pass. The real Opengrep v1.31.0 binary was used for the cancel-during-run case on Linux aarch64; the never-authorized User path was also run on macOS. Windows was not run.
> Revision: toolkit tree `e3389072…` · specification `fca9f235…` · design `6d64c8ae…` · runner `34756ef9…` (SHA-256 prefixes). Final run after Bug Fix TASK-042 (closing re-review finding); before that, TASK-041 (closing-review findings). Earlier: the first run failed one check and was fixed by TASK-039 (see Results).

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-002-C, board status Implemented (TASK-037); acceptance task TASK-038 |
| Specification / Source | [specification.md](specification.md); parent EPIC-001 FR-20, FR-21; AC-25, AC-26, AC-29; inventory E-01, E-02, B-01…B-10 |
| Design / Implementation | [technical-design.md](technical-design.md); `guard/{budget,control,cancel,egress,runs,service,toolrun,engine,report}.py`, `adapters/process.py`; Guard SKILL.md, `references/guard-records.md`, CLI contract, README |
| Target URL | N/A: CLI, library and skill scope (no UI) |
| Config / Capability | Python implementation tool (pytest). Black-box runner [blackbox.py](acceptance/blackbox.py) calls the real CLI through `uvx` and never imports toolkit code. The real Opengrep comes from the docker volume `og-validate` |
| Planned Cases | 13: black-box integration 10 (TC-C-01…08, TC-C-09 container; TC-C-10, TC-C-09 host), structured review 1 (TC-S-01), unit/integration 1 (TC-U-01), regression 1 (TC-R-01) |

**Environment.** Scenarios that need a Maintainer authorization and knowledge run in an **offline Linux container (`--network none`, `UV_OFFLINE=1`) with a disposable HOME**. The project path contains `ü`, and the MVP samples (marathon, WebGoat) are mounted read-only.

**Fixtures (disclosed).**
- **TC-C-07:** writes a stale `tool-active.json` with a dead pid to simulate a crashed tool owner.
- **TC-C-09:** removes the budget keys from a run state to simulate a verification opened before this feature.
- **Real time:** TC-C-03 lets one real minute pass with a 1-minute budget (no clock patching in black-box runs).

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-04 | Spec G-04; FR-21; AC-25, AC-26 | Developer | Runs stay within the agreed cost; exhaustion and cancel give honest partial reports | TC-C-01…07, TC-U-01 | 01*, 02*, 03*, 04*, 06b, 06c | not measured |
| G-05 | Spec G-05; FR-20; AC-29 | Owner, Developer | Toolkit-owned calls only under purpose-specific grants with minimized, masked payloads; agent calls declared and audited | TC-C-08, TC-C-10, TC-U-01 | 05*, 06a | not measured |

The source scenarios were exercised with the real CLI:
- **Exhaustion:** retries and the time limit exhaust the budget, and the conclusion lists only the checks that were not reached.
- **Cancel during a run:** a running Opengrep is stopped, termination is confirmed, and no process remains.
- **Cancel keeps a Fail:** a cancelled run with a confirmed High finding stays Fail.
- **Egress:** with only a target-request grant, sending findings is refused and recorded.

Real Developers and Owners using budgets and grants: **not measured**.

## Full Acceptance / Evidence Map

| AC ID | TC / Type | Original Assertions (summary) | Evidence | Delivery State |
| --- | --- | --- | --- | --- |
| AC-002C-01a | TC-C-01 integration | Defaults recorded and marked; a lower budget recorded; above defaults or invalid refused with nothing created, and the next step names extension | Pass | verified |
| AC-002C-01b | TC-C-01, TC-C-02, TC-C-04, TC-C-08 integration; TC-U-01 | `show` on an open run: `NOT_CONCLUDED` with budget, consumed and remaining; never decreasing (real clock); backward clock (patched); run refusals (attempt, record, tool) and egress results carry the budget (TASK-041) | Pass | verified |
| AC-002C-01c | TC-C-02 integration; TC-U-01 | Evidence without an attempt refused; run-bound attempt id and deadline returned; unknown attempt, an actual attempt of another verification, other kind or outside coverage refused; Reviewer record needs an attempt | Pass | verified |
| AC-002C-01d | TC-C-02 integration; TC-U-01 | Re-covering two pairs costs two; a method added later costs one; planned pairs grouped are free; legacy work counts as seen | Pass | verified |
| AC-002C-01e | TC-C-02, TC-C-03 integration | Single-use: the second citation is refused; a cited record cannot carry conflicts; overrun shown in consumed time | Pass | verified |
| AC-002C-01f | TC-C-02 integration; TC-U-01 | Usage summed; model attempts without usage counted unknown; tool attempts not applicable; no price | Pass | verified |
| AC-002C-01g | TC-C-03 integration (real binary) | Tool time limit capped at the remaining time and the cap recorded (`requested_time_limit`, `time_limit_capped`) | Pass | verified |
| AC-002C-02a | TC-C-04 integration | Pause with reason; attempt, record, plan, Reviewer record, tool run and egress declaration refused while paused; show, conclude and cancel work; second pause refused | Pass | verified |
| AC-002C-02b | TC-C-04 integration | Clock frozen during a real 4 s pause; resumed without the pause time; pause (start, end, reason) in result and report | Pass | verified |
| AC-002C-03a | TC-C-03 integration | After the real minute: new attempt and tool run refused; the started attempt still records (overrun); ledger-only accepted; conflicts refused | Pass | verified |
| AC-002C-03b | TC-C-03 integration | With 0 extra attempts the retry is refused (`ATTEMPTS_EXHAUSTED`); first executions still accepted | Pass | verified |
| AC-002C-03c | TC-C-03 integration; TC-U-01 | Never Pass; exhaustion and limit stated; only `unconfirmed`/missing checks listed; `not_met` kept | Pass | verified |
| AC-002C-03d | TC-C-05 integration (pseudo-terminal) | User types the verification id → 90 min / 5 extra attempts; extension recorded (user role, reason); consumed time before and after differs only by the elapsed time | Pass | verified |
| AC-002C-03e | TC-C-05, TC-C-10 integration | No terminal → `INTERACTIVE_REQUIRED`; mismatching id refused; a request file with `budget` refused; budget unchanged | Pass | verified |
| AC-002C-04a | TC-C-06, TC-C-10 integration; TC-U-01 | Cancel of one verification is not blocked by another's running real tool, whose run then completes and is recorded; later changes refused; "finalization pending" while a commit is in progress; a record losing to the cancel leaves no evidence file; a conclusion already publishing wins and cancel answers `RUN_FINISHED` naming the order (TC-U) | Pass | verified |
| AC-002C-04b | TC-C-06 integration (real binary); TC-U-01 | Running Opengrep stopped by its owner; termination confirmed (its process group was seen exiting; processes that left the group are not tracked, stated); no opengrep process left; attempt cancelled without evidence; staging removed | Pass | verified (after Bug Fixes TASK-039, TASK-041) |
| AC-002C-04c | TC-C-07 integration; TC-U-01 | Crashed owner (dead pid): cancelled at once, `not_confirmed` naming the pid; unacknowledged live owner → `not_confirmed` after the bounded wait (TC-U, wait patched) | Pass | verified |
| AC-002C-04d | TC-C-07 integration; TC-U-01 | Cancelled result final (risk acceptance refused, result unchanged); a tool finishing after the cancel records nothing and leaves no output files; concurrent cancels give one result (TC-U, fake tool) | Pass | verified (late-commit races with the fake tool) |
| AC-002C-04e | TC-C-07 integration | Confirmed High kept → Fail; earlier results kept; unfinished agent attempt "stop requested, not confirmed"; remote billing stated | Pass | verified |
| AC-002C-04f | TC-C-07 integration | Second cancel returns the same result; report regenerated only from the stored result; a finished verification cannot be cancelled | Pass | verified |
| AC-002C-05a | TC-C-08 integration | No grants by default; declaration refused | Pass | verified |
| AC-002C-05b | TC-C-08, TC-C-10 integration (pseudo-terminal) | User grants at a terminal; agent refused; credential URL, prohibited data and findings for a non-submission purpose refused | Pass | verified |
| AC-002C-05c | TC-C-08 integration | Covered declaration allowed; each declared call gets its own id (agent declarations are audit records, one per call); refusal names the missing element | Pass | verified |
| AC-002C-05d | TC-C-08 integration; TC-U-01 | Target or network grants never authorize findings or source; refused and recorded | Pass | verified |
| AC-002C-05e | TC-C-08 integration; TC-U-01 | Every stored field masked (token in reason and items); private key masked; percent-encoded credentials in URLs and scopes refused (TASK-041) | Pass | verified |
| AC-002C-05f | TC-U-01 integration (library API, local HTTP server) | Gate: single-use; bound URL path and payload digest; same-origin path change, encoded traversal and uncovered refs refused; private key/model key refused; masking; reuse and use after pause or cancel refused; no proxy (environment proxies set), no redirect followed; encoded URLs sent as given; no network client outside `egress.py` | Pass | verified (no toolkit network client exists yet; library API only) |
| AC-002C-05g | TC-C-08 integration | Report lists grants and declarations with decisions and the audit/not-OS-enforced limits | Pass | verified |
| AC-002C-05h | TC-U-01 unit/integration (fake tool) | Adapter network check: none / networked (toolkit declaration recorded) / offline argv applied to the tool / refused naming the purpose; Opengrep needs no grant | Pass | verified |
| AC-002C-06a | TC-C-09, TC-S-01 structured | Skill states all instructions (defaults, extension, attempts, pause, exhaustion, cancel, egress, host not egress); reference documents attempt and egress requests | Pass | verified (agent behaviour not measured) |
| AC-002C-06b | TC-C-05 integration; TC-U-01 | Budget section: limits (default marked), extensions, pauses, attempts, usage; Cancellation section when cancelled | Pass | verified |
| AC-002C-06c | TC-C-09 integration | Legacy run: defaults from its opening; earlier evidence counts as seen; no grants; the report states the budget was defaulted | Pass | verified |

## Test Cases

| TC | Type | Priority | Command / Method | Result |
| --- | --- | --- | --- | --- |
| TC-C-01…TC-C-09 | integration (black-box CLI, real binary for TC-C-03/06) | P0 (03*, 04*, 05b–05e), P1 others | `python3 blackbox.py container` in `fat-uv-git:py312`, `--network none`, `UV_OFFLINE=1`, real Opengrep; fresh cache volume `fat-uv-cache-gc` (fixed code checked in the cache) | 9/9 Pass, stderr empty ([evidence](acceptance/evidence-container-linux.jsonl), `7a21573d…`) |
| TC-C-10, TC-C-09 | integration (host User path) + structured | P1 | `UV_REFRESH_PACKAGE=ai-secure-code-toolkit python3 blackbox.py host` on macOS (Python 3.13 runner) | 2/2 Pass ([evidence](acceptance/evidence-host-macos.jsonl), `b9261d26…`) |
| TC-S-01 | structured review | P1 | Guard SKILL.md "Budget, Cancel and Outbound Calls", steps 5–6; `guard-records.md` attempt, budget, record, Reviewer and egress sections; CLI contract rows (phrase checks also executable in TC-C-09) | Pass |
| TC-U-01 | unit / integration | P1 | `uv run pytest -o addopts="" -v` budget, runs, budget/cancel/egress integration, skill, module size and adapter tests (macOS Python 3.14) | 194 passed, 1 skipped ([log](acceptance/evidence-unit-integration.log), `eced482c…`) |
| TC-R-01 | regression | P1 | FEATURE-002-A runner (container + host) and FEATURE-002-B runner (container with real binary + host), fresh caches | 26/26 + 2/2; 10/10 + 2/2 ([002-A container](acceptance/regression-002A-container-linux.jsonl), [002-B container](acceptance/regression-002B-container-linux.jsonl)) |

Full suites at the final revision: macOS Python 3.14 661 passed, 2 skipped; Python 3.11 660 passed, 3 skipped; Linux Python 3.12 663 passed; `ruff check` clean.

## Results

| Type | Planned | Passed | Failed | Blocked |
| --- | --- | --- | --- | --- |
| integration (black-box) | 10 | 10 | 0 | 0 |
| structured review | 1 | 1 | 0 | 0 |
| unit / integration | 1 | 1 | 0 | 0 |
| regression | 1 | 1 | 0 | 0 |
| **Total** | **13** | **13** | **0** | **0** |

Pass rate: 13/13 at the final revision. All 31 ACs have current passing evidence.

**First container run (failed, kept as evidence):** [evidence-container-linux-run1-FAIL.jsonl](acceptance/evidence-container-linux-run1-FAIL.jsonl) (`bdc87d87…`), 8/9. Cancelling a real Opengrep run stopped it, but the result reported "termination not confirmed". Opengrep's worker processes linger as zombies (the container's PID 1 does not reap them) or finish exiting asynchronously, and the signal-0 probe counted them as survivors. Fixed in [Bug Fix TASK-039](bug-report-TASK-039.md), test-first: the probe waits up to 5 s and counts exited (zombie) members as gone. A fix review found a decoding crash on non-UTF-8 process names, fixed test-first. The complete set was then rerun with fresh caches.

**Closing-review rerun (Bug Fix TASK-041):** the closing review (TASK-040) found:
- attempt ids not bound to their verification;
- files left after a commit lost to a cancellation;
- percent-encoded credentials accepted in URLs;
- budget missing from egress results and refusals;
- overclaiming termination wording;
- acceptance clauses that were not asserted.

All were fixed test-first ([bug report](bug-report-TASK-041.md)). The runner gained assertions for:
- an actual foreign attempt id;
- budget in refusals;
- the full paused matrix;
- consumption unchanged by an extension;
- a new declaration id per call.

The interactive gate is documented as a cooperative control (user decision). Everything was rerun with fresh caches: 9/9, host 2/2, regressions 26/26 + 2/2 and 10/10 + 2/2.

**Closing re-review rerun (Bug Fix TASK-042):** the re-review confirmed all TASK-041 findings resolved or documented, and found that the new lost-commit cleanup could follow an evidence folder replaced by a link and delete outside files (the record path also reported `PATH_UNSAFE` instead of `RUN_CANCELLED`). Fixed test-first ([bug report](bug-report-TASK-042.md)): exact-name, no-follow removal through a folder descriptor. Everything was rerun with fresh caches: 9/9 (stderr empty), host 2/2, regressions 26/26 + 2/2 and 10/10 + 2/2; no runner change.

**Runner correction during this task (not a product change):** TC-C-06 first opened its second verification while the first one's tool held the Guard lock (002-A behaviour: open waits for the lock). The runner now opens both verifications before starting the long run; no assertion changed.

## Gaps and Honest Limits

- **Windows:** not run. Tool runs are refused there (NFR-002B-4); budget, pause, cancel and egress records are designed for Windows but not verified on it.
- **macOS before Python 3.13:** no `os.waitid`, so the tool's group is killed after the leader is reaped (narrow process-group-id reuse window). Termination is still confirmed only when observed.
- **Interactive confirmation (extend, allow-egress, risk acceptance) is a cooperative control:** a program that drives a pseudo-terminal could pass it; it is not an authorization boundary (stated in the references, README and every report).
- **Termination confirmation:** means the tool's process group was seen exiting; processes that left the group are not tracked.
- **Agent behaviour is not observable by the toolkit:**
  - work without a registered attempt;
  - work while paused;
  - undeclared outbound calls;
  - host or Reviewer calls after a cancel.

  Instructions were verified structurally only.
- **Egress gate:** verified through the library API with a local HTTP server; no toolkit component makes network calls yet (FEATURE-002-D/E/001-E will).
- **Network access is not OS-enforced**, including for tools that Adapters launch (stated in every report).
- **Fixtures:** the late-commit and concurrent-cancel races (04d) and the unacknowledged live owner (04c) were verified with the fake tool in integration tests.
- **Stakeholder outcome:** not measured.

## Note — CR-TASK-077 implementation (2026-10-24, TASK-083; append-only)

The results above are for the v1.0 delivery and stay valid for requests that name no helpers. CR-TASK-077 (human B12 = A) added the Reviewer coverage item `helpers` in `guard/budget.py`, `guard/service.py` and `guard/report.py`. New criteria AC-002C-01h and AC-002C-01i are covered by unit/integration tests in two new test files, using a synthetic `state["helpers"]`. Full suite: 2563 passed, 4 skipped. ruff: clean. All 128 delivered test files are byte-identical.

Black-box regression in host mode used the unchanged runner `34756ef9…`: 2/2 Pass (TC-C-10, TC-C-09), with output byte-identical to `acceptance/evidence-host-macos.jsonl`. Container cases were not rerun; they need `auth init`, which is never run on the host. The helper path has no black-box case in 002-C; it moves to FEATURE-002-F acceptance. The toolkit tree after the change is `b89a972f…`. Details and logs: [CR-TASK-077 Implementation Evidence](CR-TASK-077-helpers-coverage.md#implementation-evidence-2026-10-24-task-083--code-implementation-owner-sage).
