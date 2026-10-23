# Technical Design: Verification Budget, Cancel & Data-Egress Control

> Feature ID: FEATURE-002-C | Version: v1.1 (base v1.0 delivered; v1.1 = CR-TASK-077 amendment) | Last Updated: 2026-10-20
> Specification: [specification.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/specification.md) · Task: TASK-036 · Depends on: [FEATURE-002-A design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/technical-design.md), [FEATURE-002-B design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/technical-design.md)
> Amended: v1.1 on 2026-10-23 by [CR-TASK-077](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/CR-TASK-077-helpers-coverage.md) — appended section "CR-TASK-077 Delta: Reviewer coverage item `helpers`" (delivered v1.0 design kept)

## Version History

| Version | Date | Description |
|---------|------|-------------|
| v1.0 | 10-20-2026 | Initial design |
| v1.1 | 10-23-2026 | CR-TASK-077 (human decision B12 = A): additive Reviewer coverage item `helpers`; appended delta section; no delivered design text removed |

---

## Part 1: Agent-Facing Summary

### Scope & Boundaries

- **Feature:** FEATURE-002-C.
  - **Budget:** a budget and registered attempts for every Guard verification.
  - **Pause and resume.**
  - **Extension:** user-only, at an interactive terminal.
  - **Cancel:** durable, with a single final result.
  - **Egress:** per-verification grants (user-only, at an interactive terminal), agent declarations, and a gate for the toolkit's own network clients, plus Adapter network needs.
  - **Reporting:** Budget, Cancellation and Egress report sections, and the Guard skill update.
- **program_type:** `cli` + `library` (new `guard/budget.py`, `guard/control.py`, `guard/cancel.py`, `guard/egress.py`, `guard/toolreq.py`) + `skills`.
- **tech_stack:** Python ≥ 3.11 stdlib only (`os`, `time`, `urllib.parse`, `json`), with no new dependency; pytest and ruff.
- **Defaults (B-07, user decision 10-20-2026):**
  - 60 minutes total time and 3 extra attempts.
  - After extensions, at most 480 minutes and 20 extra attempts.
  - Opening is capped at the defaults.
  - Cancel acknowledgement wait: 3600 s. It applies only when a tool's owning process does not react; a normal cancel returns within about a second.
- **Non-goals:** budgets for Copilot generation; OS network or process isolation; blocking undeclared agent calls; stopping host or remote work; a progress API; standing grants; an HTTP client (no toolkit component makes network calls yet; the gate is ready for FEATURE-002-D, 002-E and 001-E).
- **Threat model:** protects against:
  - an agent silently growing cost: open is capped, retries are counted per pair, and only the user can extend;
  - work recorded after cancellation;
  - false termination claims;
  - toolkit-owned calls to ungranted recipients or carrying unmasked credentials;
  - secrets stored in egress records.

  It does not protect against an agent that works without registering attempts, makes undeclared calls, or does work while the verification is paused. The interactive-terminal gates (extend, allow-egress) are cooperative: a program that can drive a pseudo-terminal could pass them (same limit as risk acceptance). These limits are stated in the report.

### Outcome / Goal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-04 | Spec G-04; FR-21; AC-25, AC-26 | Developer | Runs stay within the agreed cost; exhaustion and cancel give honest partial reports | `budget.py`: time high-water mark, pause-frozen clock, attempts as single-use leases, per-pair extra counting. `control.py`: attempt, pause, resume, extend commands. `cancel.py`: durable marker under the commit barrier, frozen state, owner acknowledgement, exclusive final result | Scenario: retries exhaust the attempts → refused, conclusion lists unverified checks; cancel during a tool run → tool killed, Fail kept | No money caps; host work not controllable | AC-002C-01a…04f, 06b, 06c | not measured |
| G-05 | Spec G-05; FR-20; AC-29 | Owner, Developer | Toolkit-owned calls only under purpose-specific grants with minimized, masked payloads; agent calls declared and audited | `egress.py`: grants (interactive terminal), canonical origins, declaration checks, `EgressGate` (single-use authorization, no redirect following, payload credential refusal and masking), Adapter network needs | Scenario: a submission without a submission grant is refused and recorded; a gated call to another origin is not made | Audit only for agent calls; launched tools not network-isolated | AC-002C-05a…05h, 06a | not measured |

### Design Options and Tradeoffs

| Option | Decision | Reason |
| --- | --- | --- |
| Cancel waits for the project Guard lock | rejected | A tool run of any verification holds it for up to 30 minutes (AC-002C-04a) |
| Per-verification run lock held for whole commands | rejected (design review) | A marker created outside it still races a writer between its check and its write; long holds block cancel |
| **Cancel marker + short per-verification commit barrier + exclusively created final result** | selected | Every state commit re-checks the marker and writes under the barrier (milliseconds); cancel creates the marker under the same barrier, so after the marker no commit can happen and the state is frozen; exactly one final result (`O_EXCL`) |
| **Owner polls the marker inside `process.run` and acknowledges** | selected | Only the process that owns the tool can kill its group and observe the exit (B-10); the existing 0.1 s polling loop is reused |
| Budget as a new command group only (no change to record/review) | rejected | Attempts must be cited by results to count work (spec review finding 1) |
| **Attempts registered by `guard attempt`; `record`/`review` cite them; tool runs self-register** | selected | User decision; single-use leases close the reuse loophole |
| Count extra attempts per attempt | rejected | Batching several retried checks would cost one attempt |
| **Count per check-and-method pair (or Reviewer item) re-covered or added later** | selected | AC-002C-01d |
| Time from summed command durations | rejected | Cannot see agent work between commands |
| **Wall-clock since opening minus pauses, high-water mark** | selected | User decision (B-05); never decreases |
| `guard show` on an open run returns full data | rejected | Changes FEATURE-002-A behaviour (`NOT_CONCLUDED`, tested) |
| **Keep the `NOT_CONCLUDED` refusal, attach the budget state to its data** | selected | Additive; satisfies AC-002C-01b |
| Mask credentials in gated payloads and send | rejected for model credentials and private keys | E-02: these never leave; other recognized secrets are masked |
| Caller-supplied transport for the gate | rejected (design review) | A caller transport could follow redirects or use proxies |
| **Gate-owned `urllib.request` opener: no redirects, `ProxyHandler({})`** | selected | The only production transport. Tests replace the whole opener through a private constructor argument |
| Keep new logic in `service.py` / `toolrun.py` | rejected | 662 / 755 lines; the 800-line limit. New modules; `toolrun.py` request validation moves to `guard/toolreq.py` |

### Key Components Implemented

| Component | Responsibility | Used by | Tags |
| --- | --- | --- | --- |
| `guard/budget.py` | Defaults, legacy defaulting, consumed/remaining time, high-water mark, pause/resume math, extension apply, attempt registration, citation and finishing, extra counting, model usage, exhaustion checks, budget status and result summary (pure functions on the state dict) | service, control, toolrun, cancel, engine | #core #budget |
| `guard/control.py` | Commands: `guard attempt`, `guard pause`, `guard resume`, `guard extend` (interactive terminal) | cli | #cli |
| `guard/cancel.py` | Marker/ack/active-tool files, commit barrier, `guard cancel`, cancelled finalization (also used by `conclude` for an unfinished cancel) | cli, service, toolrun | #core #cancel |
| `guard/egress.py` | Purposes, data categories, canonical origin, scope checks, `guard allow-egress` (interactive terminal), `guard egress` declarations, `EgressGate`, `adapter_network_check` | cli, toolrun, future Adapters | #security #egress |
| `guard/toolreq.py` | FEATURE-002-B tool request validation moved out of `toolrun.py` unchanged | toolrun | #refactor |
| `guard/service.py` (extended) | Open budget; `_mutate` checks cancellation, pause and budget and commits through the barrier; record/review attempt citation; conclude via exclusive result and cancelled finalization; show attaches the budget | cli | #core |
| `guard/toolrun.py` (extended) | Tool attempt, capped time limit, cancellation polling, owner ack, no commit after cancel, Adapter network check | cli | #core |
| `adapters/process.py` (extended) | `run(..., should_stop)` → `ProcessOutcome.cancelled`, `group_gone` | toolrun | #process |
| `guard/runs.py` (extended) | `commit_state` (commit barrier + marker re-check + atomic write), `create_result_exclusive`, `bump_clock` (monotonic `clock.json`), directory fsync, paths for marker/ack/active | service, control, cancel, egress, toolrun | #storage |
| `guard/engine.py`, `guard/report.py` (extended) | Result keys `budget`, `attempts`, `cancellation`, `egress`; cancelled verdict rule; report sections | conclude, cancel | #report |
| Guard `SKILL.md`, `references/guard-records.md`, framework `references/cli-contract.md`, README | AC-002C-06a instructions, request formats, command rows | agent | #skill |

### Dependencies

| Dependency | Use |
| --- | --- |
| FEATURE-002-A run state, `ProcessLock`, `atomic_write_bytes`, `mask.mask_text`, `TerminalInteraction`, engine/report | Storage, locks, masking, interactive gate, verdict and report |
| FEATURE-002-B `process.run`, staging cleanup, `ADAPTERS` registry | Tool cancel and network needs |
| Consumers: FEATURE-002-D/E, FEATURE-001-E (`EgressGate`, `adapter_network_check`), FEATURE-003-C (cancel/exhaustion cases) | — |

### Major Flow

1. **Opening:** `guard open` (optional `budget` up to the defaults) → state `budget` {limits, defaulted, pauses [], extensions [], hw 0, planned null} and `attempts` [], `egress` {grants [], declarations []}.
2. **Planning:** `guard plan` → records `budget.planned` = the plan's (check, method) pairs.
3. **Each unit of work:** `guard attempt` (kind, covers) → id `a-<n>`, deadline. The agent works, then `guard record` / `guard review` with `"attempt": "a-<n>"` (+ optional `usage`) → validated coverage; the attempt is finished.
4. **Tool runs:** `guard tool` registers its own `tool` attempt, caps its time limit at the remaining time, polls the cancel marker and commits only if not cancelled.
5. **Waiting for the user:** `guard pause --reason` → clock frozen; `guard resume`.
6. **Exhaustion:** new attempts, tool runs and egress declarations are refused. Records citing unfinished attempts and ledger-only records still work. The user may `guard extend` at a terminal; otherwise conclude.
7. **Cancel:** `guard cancel` → marker created under the commit barrier (state frozen from now on) → wait for the tool owner's acknowledgement (≤ 3600 s) → cancelled result created exclusively from the frozen state → report → state `cancelled`.
8. **Egress:** the user runs `guard allow-egress` at a terminal → grant. The agent runs `guard egress` before each outbound call → allowed (single-use id) or refused, recorded masked. Toolkit clients use `EgressGate`.
9. **Conclusion:** `guard conclude` → result with budget, attempts, cancellation and egress → report sections.

### Usage Example

```bash
G="uvx --from $FW/scripts secure-code guard"
$G open --project . --request .x-ipe/private/secure-code/tmp/open.json          # budget ≤ 60 min / 3 extra
$G plan --project . --run $VID --request .x-ipe/private/secure-code/tmp/plan.json
$G attempt --project . --run $VID --request .x-ipe/private/secure-code/tmp/attempt.json   # {"kind":"semantic_review","covers":[{"check":"C1","method":"semantic-review"}]}
$G record --project . --run $VID --request .x-ipe/private/secure-code/tmp/record.json     # {"attempt":"a-1","usage":{"requests":3,"input_tokens":12000,"output_tokens":900},...}
$G pause --project . --run $VID --reason "asking the user which config is deployed"
$G resume --project . --run $VID
$G extend --project . --run $VID --minutes 30 --attempts 2 --reason "WebGoat needs a second tool pass"   # user's terminal
$G allow-egress --project . --run $VID --purpose submission --recipient https://api.example.com --data findings --scope src/login.py --reason "..."   # user's terminal
$G egress --project . --run $VID --request .x-ipe/private/secure-code/tmp/egress.json
$G cancel --project . --run $VID --reason "user stopped"
```

### Tool Capability Summary

| Tool | Enabled (technical_design) | Matched | Use |
| --- | --- | --- | --- |
| x-ipe-tool-implementation-python | yes | yes (Python CLI/library) | Informational: pytest, type hints, module size practices |
| x-ipe-tool-implementation-general | yes | fallback, not needed | — |
| html5 / typescript / java / mcp | yes | no (no matching stack) | Excluded |

---

## Part 2: Implementation Guide

### Files and Layout

```
scripts/src/x_ipe_secure_code/guard/{budget,control,cancel,egress,toolreq}.py     # new
scripts/src/x_ipe_secure_code/guard/{service,toolrun,runs,engine,report,model,records}.py   # extended
scripts/src/x_ipe_secure_code/adapters/{process,__init__}.py, cli.py                  # extended
scripts/tests/guard/{test_guard_budget,test_guard_cancel,test_guard_egress}.py, tests/guard/test_budget_units.py   # new
.x-ipe/private/secure-code/guard/<vid>/{cancel.json, cancel-ack.json, tool-active.json, clock.json, commit.lock}     # runtime files
```

### State Additions (`guard-run/v1`, additive; absent keys = legacy)

```json
"budget": {"total_seconds": 3600, "extra_attempts": 3, "defaulted": true, "legacy": false,
           "extensions": [{"at": "…", "seconds": 1800, "attempts": 2, "reason": "…", "role": "user"}],
           "pauses": [{"start": "…", "end": null, "reason": "…"}],
           "extra_used": 1, "planned": [["C1","semantic-review"], ["C1","opengrep"]],
           "seen_before": {"pairs": [], "findings": [], "na": []}},
"attempts": [{"id": "a-1", "kind": "semantic_review", "covers": {"pairs": [["C1","semantic-review"]], "findings": [], "na": []},
              "extra": 0, "started_at": "…", "deadline_consumed": 3600, "deadline_adjustments": [{"at": "…", "to": 5400, "extension": 1}],
              "status": "unfinished|finished|cancelled",
              "finished_at": null, "overrun_seconds": 0, "usage": null, "tool_run": null}],
"egress": {"grants": [{"id": "g-1", "purpose": "submission", "recipient": "https://api.example.com",
                       "data": ["findings"], "scope": ["src/login.py"], "reason": "…", "at": "…", "role": "user"}],
           "declarations": [{"id": "eg-1", "by": "agent|toolkit", "purpose": "…", "recipient": "…", "data": [], "items": [],
                             "scope": [], "decision": "allowed|refused", "missing": null, "at": "…", "used": false}]},
"status": "open | finished | cancelled",
"revision": 17
```

`clock.json` (separate file, `{"consumed_hw": 812.4}`, guarded by its own tiny `clock.lock`) holds the consumed-time high-water mark so that read-only callers (`show`) can persist it without rewriting the state. `revision` increases with every state commit (optimistic concurrency check).

### Budget (`guard/budget.py`)

Constants: `DEFAULT_SECONDS = 3600`, `DEFAULT_ATTEMPTS = 3`, `MAX_SECONDS = 28800`, `MAX_ATTEMPTS = 20`, `MODEL_KINDS = {"semantic_review", "reviewer", "generation"}`, `AGENT_KINDS = MODEL_KINDS | {"helper"}`, `KINDS = AGENT_KINDS | {"tool"}`.

```python
def initial(budget_req: dict | None) -> dict                     # validates ≤ defaults, > 0; GuardError BUDGET_INVALID
def ensure(state: dict) -> dict                                  # legacy: defaults, defaulted+legacy True, planned + seen_before baseline
def pause_seconds(b: dict, now: datetime) -> float              # completed + current (now - start)
def raw_consumed(state: dict, now: datetime) -> float           # (now - opened_at) - pause_seconds
def consumed(root, state, now) -> float                          # runs.bump_clock(max(stored hw, raw)) → monotonic, persisted
def status(state, consumed_s) -> dict                           # limits, consumed, remaining, extra used/left, paused, exhausted
def require_running(state, consumed_s) -> None                  # RUN_PAUSED / BUDGET_TIME_EXHAUSTED (no change)
def register(state, kind, covers, consumed_s, now) -> dict       # coverage, extra, ATTEMPTS_EXHAUSTED
def cite(state, attempt_id, kinds: set, used: dict, consumed_s, now) -> dict   # ATTEMPT_INVALID; finishes; overrun
def add_usage(attempt, usage) -> None                           # ints ≥ 0: requests, input_tokens, output_tokens
def extend(state, seconds, attempts, reason, now) -> dict       # caps MAX_*; EXTENSION_INVALID
def summary(state, consumed_s) -> dict                          # for the result/report
```

**Clock.**
- Consumed time is persisted in `clock.json` by `runs.bump_clock`: under `clock.lock`, `hw = max(stored, raw)`.
- Once `cancel.json` exists, `bump_clock` returns the marker's `consumed_at_request` and never advances beyond it, so the clock is frozen at cancellation. Every command that reads a run for an open verification calls `consumed()`, including `show` and every `_mutate` command.
- The value therefore never decreases, even across a backward clock change between two `show` calls (spec review finding 3).
- `show` writes only `clock.json`, never the state.

**Coverage of `register`:**
- Kinds `semantic_review`, `helper` and `generation`: `pairs` [(check, method)], where the check is in the plan and the method belongs to that check in the current plan, including changes.
- Kind `reviewer`: `findings` (existing finding ids) and `na` (N/A rule ids of the plan).
- Kind `tool`: only internal.

**Extra counting.** `seen` = `seen_before` ∪ every pair and item covered by earlier attempts, whatever their status.
- A pair is extra if it is in `seen` or not in `budget.planned`.
- A Reviewer item is extra if it is in `seen`.
- The attempt's `extra` is their sum. Planned pairs grouped in one attempt are free.
- **Refusals:**
  - Time exhausted → `BUDGET_TIME_EXHAUSTED`, naming the time limit.
  - `extra_used + extra > extra_attempts` → `ATTEMPTS_EXHAUSTED`, naming the limit and the extra pairs. Planned-only attempts stay possible.

**Legacy baseline (`ensure`, first call on a pre-feature state).**
- `planned` = the plan's methods minus those added by `method_changes`.
- `seen_before`:
  - pairs from existing evidence `(check, method)` and Adapter runs `(check, adapter)`;
  - finding and N/A ids from existing reviews.
- A later retry of legacy work is therefore extra (spec AC-002C-01e/06c). Old records keep no attempt ids.

**Deadline and overrun.**
- `register` records `deadline_consumed`: the consumed-time value at which the budget runs out, which is the total seconds at registration. It returns that value together with `remaining_seconds`.
- An extension moves the deadline of every unfinished attempt to the new total and appends to `deadline_adjustments`.
- Overrun is measured in consumed time, so pauses never count: `overrun_seconds = max(0, consumed_at_finish − deadline_consumed)`.

**Clock source.** UTC ISO timestamps (`utc_now()`, patchable in tests).

### Commands (`guard/control.py`)

| Command | Arguments | Behaviour | Exit |
| --- | --- | --- | --- |
| `guard attempt` | `--project`, `--run`, `--request FILE` (`guard-attempt/v1`: `kind`, `covers`), `--json` | `_mutate`: running checks → `register` → data {attempt, deadline, extra, budget} | 0 / 1 |
| `guard pause` | `--run`, `--reason TEXT` | Already paused → `ALREADY_PAUSED`; appends a pause | 0 / 1 |
| `guard resume` | `--run` | Not paused → `NOT_PAUSED`; closes the pause; `consumed()` | 0 / 1 |
| `guard extend` | `--run`, `--minutes N`, `--attempts N`, `--reason TEXT` | Interactive terminal (`TerminalInteraction`), typed verification id, else `INTERACTIVE_REQUIRED` / `CONFIRMATION_MISMATCH`; caps → `EXTENSION_INVALID`; allowed while paused or exhausted | 0 / 1 |

### Changes to FEATURE-002-A Commands (`guard/service.py`)

- **`open`:** request key `budget` {`minutes`, `extra_attempts`} (optional) → `budget.initial`. The state gains `budget`, `attempts` and `egress`. Result data includes `budget`.
- **Commit primitives** (in `runs`, the only writers of an open run's state; never nested):
  - **`commit_state(root, new_state, expected_revision)`:**
    1. Take `commit.lock` (`ProcessLock`, held for milliseconds).
    2. Refuse `RUN_CANCELLED` if `cancel.json` exists and `RUN_FINISHED` if a result exists. Refuse `LOCKED` ("state changed meanwhile, retry") if the stored `revision` ≠ `expected_revision`.
    3. Write atomically with `revision + 1`.
  - **`update_state(root, vid, fn)`:** take `commit.lock`, re-check the marker and result, read the latest state, `fn(state)` validates and mutates, write with `revision + 1`. Used by the egress gate.
  - Callers that also need the project lock take it first (project lock → commit lock).

  `runs.write_state` stays private to `runs` and `cancel` (the final status update).
- **`_mutate(root, run_id, change, *, gate)`:**
  1. Take the project lock.
  2. Early refusal: marker → `RUN_CANCELLED`; result → `RUN_FINISHED`.
  3. `budget.ensure`; `consumed()`.
  4. Apply the `gate`: `"work"` → `require_running` (pause and time); `"cited"` → pause only; `"ledger"` → pause only.
  5. Call `change`, which ends with `commit_state(..., expected_revision=state["revision"])`. The barrier's re-check closes the window between the early check and the write; the revision check catches any writer that does not hold the project lock.
- **Record classification** (normalized: empty lists count as absent; spec review finding 9):
  - **Cites `attempt`:** allowed operations are evidence, findings and ledger only. Method changes or conflicts in the same request → `ATTEMPT_INVALID` ("record them separately"). `budget.cite` takes kinds AGENT_KINDS minus reviewer and checks coverage against each evidence `(check, method)` and finding `check`. The attempt is finished and `usage` is added. Gate `cited`: allowed after time exhaustion, because the attempt started earlier.
  - **No `attempt`, with evidence or findings:** `ATTEMPT_REQUIRED`.
  - **No `attempt`, only ledger states:** gate `ledger`.
  - **No `attempt`, with conflicts or method changes:** gate `work` (refused when paused or exhausted).
- **`plan`:** gate `work`; sets `budget.planned`.
- **`review`:** `attempt` required (`ATTEMPT_REQUIRED`), kind `reviewer`; subjects ⊆ covers; finishes the attempt; adds `usage`. Gate `cited`.
- **`conclude`** (project lock):
  - If a result exists → repair the report from it. A cancelled result reconciles the state to `cancelled` (not `finished`).
  - Else if the marker exists → `cancel.finalize_frozen(...)`, completing an interrupted cancel.
  - Else, outside the barrier, close an open pause in memory and build the result with the engine (`control = budget.summary + egress`; no other writer can commit, because conclude holds the project lock). Then **inside the barrier** only: re-check the marker and the revision, and publish with `runs.create_result_exclusive`. On `FileExistsError`, read and return the winner.
- **`show`:** an open run → `consumed()` (persists `clock.json`) → raises `NOT_CONCLUDED` with data `{"budget": …, "paused": …, "cancel_requested": …}`. Concluded runs gain `budget` in their data.
- **`accept-risk`:** refuses a cancelled result (`NOT_ACCEPTABLE`, "a cancelled verification's result is final"); otherwise unchanged.
- Every `_mutate`-based command adds `data["budget"]`.
- **Module size:** estimated `service.py` ≈ 760 lines after these changes (budget logic lives in `budget.py`). A test asserts every module stays below 800 lines. If `service.py` reaches its limit, risk acceptance, keep, release and cleanup move to `guard/retention.py`.

### Cancel (`guard/cancel.py`)

Files in the run folder (created through `store.ensure_safe` paths, mode 0600; after each exclusive creation the run directory is fsynced):
- `cancel.json` {requested_at, reason, consumed_at_request} — created **at once, without any lock** (`O_CREAT|O_EXCL`, fsync file and directory). An existing file is kept (the first one wins). `consumed_at_request = max(clock hw, raw_consumed(requested_at))`.
- `tool-active.json` {pid, run, attempt, started_at} — written by the tool owner after it has committed its unfinished tool attempt and before spawning; removed in its `finally`.
- `cancel-ack.json` {pid, run, confirmed: bool, detail, at} — written by the tool owner when it stops because of the marker.
- `commit.lock` — the commit barrier (shared with `runs.commit_state`).

`guard cancel --run ID [--reason TEXT]` (no interactive gate: cancelling only reduces work):
1. `check_id`. If a result exists:
   - with `cancellation` set → return it (the same result, AC-002C-04e);
   - otherwise refuse `RUN_FINISHED`.
2. Create the marker immediately. The cancellation is now durable (AC-002C-04a).
   - **Linearization:** a writer that is already inside the barrier when the marker appears may finish; its commit counts as pre-cancel work, because it re-checked the marker earlier. No later writer can commit.
3. Take the commit barrier, then release it at once: this waits for a writer that is inside. Timeout 30 s, because holders keep it for milliseconds.
   - **On a timeout** (a writer suspended inside the barrier): do **not** finalize. Return `ok` with `"finalization": "pending"`, "cancellation recorded; a commit in progress has not finished". The marker stays durable, and every change stays refused.
   - The next `guard cancel` or `guard conclude` finalizes once the barrier can be taken. `ProcessLock` is OS-managed, so it is released when the suspended holder exits or is killed.
   - The final result is therefore always built from a frozen state that includes the in-flight pre-cancel commit.
4. If `tool-active.json` exists, poll every 0.2 s until `cancel-ack.json` appears or `tool-active.json` disappears, for at most `CANCEL_WAIT = 3600` s (user decision).
5. `finalize_frozen(root, vid, termination)` (no lock needed: the state is frozen and only an exclusive create follows; the budget uses `consumed_at_request`):
   - Read the state. Close an open pause at `requested_at`. Mark unfinished attempts `cancelled`; the tool attempt is present because the owner committed it before spawning.
   - **Termination:**
     - no tool active → `{"tool": "none"}`;
     - acknowledged and confirmed → `confirmed`;
     - otherwise → `not_confirmed`, naming the pid;
     - agent attempts unfinished at `requested_at` → "stop requested, not confirmed by the toolkit".
   - Engine call: `engine.conclude(state, observed, policy_now, ended_at=requested_at, control=…, cancellation=…)`. When the knowledge store is locked, `policy_now` falls back to `{}` with a limit note.
   - `runs.create_result_exclusive` (fsync file and directory). On `FileExistsError`, re-read: a cancelled result is returned; otherwise refuse `RUN_FINISHED` (conclude won).
   - Write the report. `runs.write_state` sets `status = "cancelled"` and `ended_at`. This is the only post-marker state write; nothing reads it for verification data.
6. Return the final summary and `termination`.

`conclude` uses the same `finalize_frozen` for an interrupted cancel (marker but no result).

**Engine rule:** with `cancellation` set, `pass` becomes `cannot_confirm_pass` with reason `CANCELLED`; `fail` stays. `other_blockers` gains `CANCELLED`. The verification data is exactly the frozen state, i.e. what was committed before the marker existed.

### Tool Run Changes (`guard/toolrun.py`, `adapters/process.py`)

**`process.run(..., should_stop: Callable[[], bool] | None = None)`** (no PGID reuse; design review finding 7):
- `should_stop()` is checked before spawning and in the polling loop.
- Waiting uses `os.waitid(P_PID, pid, WEXITED | WNOWAIT)` polling (`WNOHANG`), so the group leader stays a zombie and its pid and process-group id cannot be reused while the toolkit signals the group.
- On timeout, size limit or stop: `killpg(pgid, SIGKILL)` while the leader is unreaped.
- After the leader exits, a final `killpg(pgid, SIGKILL)` is sent, again while the leader is unreaped; then the leader is reaped (`waitpid`).
- Only then a harmless probe sets `group_gone`, waiting up to 5 s for the group to disappear (Bug fix TASK-039):
  - `killpg(pgid, 0)` raises `ProcessLookupError` → True.
  - Otherwise the group's members are listed (Linux `/proc/<pid>/stat`, elsewhere `ps -A -o pgid=,stat=`). If all of them have already exited (zombie state `Z`/`X`), the result is True: zombies are exited processes awaiting reaping by their (re-)parent, which a container whose PID 1 does not reap never does.
  - A live member, an unreadable member list, or a timeout → False.
  - A reused id would show a live member, so the probe can only err towards "not confirmed".
- Descendants that left the group (`setsid`) are not tracked (stated limit).
- `ProcessOutcome` gains `cancelled` and `group_gone`.

**`run_tool` (project lock):**
1. Early marker check → `RUN_CANCELLED`.
2. `consumed()`; `require_running`.
3. Validate the request (moved to `toolreq.py`).
4. `mode = egress.adapter_network_check(state, adapter, req)`.
5. `budget.register(state, "tool", pairs)`.
6. `time_limit = min(req, floor(remaining))`, with a cap note. Remaining < 1 s → `BUDGET_TIME_EXHAUSTED`.
7. **`commit_state`** with the unfinished tool attempt (refused if cancelled meanwhile).
8. Write `tool-active.json`.
9. `_execute(..., argv_extra=mode.argv_extra, should_stop=marker.exists)`.

**Cancelled outcome** (or marker seen before a later rule's spawn):
- Stop the remaining rules; clean the staging and the tool home (existing `finally`).
- Write `cancel-ack.json` {confirmed: `group_gone` for every started process (True when none was running)}.
- Do not commit. Return refused `RUN_CANCELLED` with the termination data.

**Commit:**
- `commit_state` with the run entry and the finished attempt.
- If the marker appeared meanwhile, the barrier refuses: the owner writes the ack {confirmed: true, detail: "tool had finished"} and returns `RUN_CANCELLED`. Its results are not recorded.
- The run entry records `effective_time_limit` and the cap note.

`finally`: remove `tool-active.json`.

**Module size:** `toolrun.py` ≈ 640 lines after moving `_validate` and its helpers (≈ 150 lines) to `toolreq.py`.

### Egress (`guard/egress.py`)

**Purposes:** `reference_fetch`, `tool_update`, `target_requests`, `submission`.

**Data categories:**
- `metadata` (tool, version and rule ids, file names);
- `public_query` (queries without project content);
- `target_traffic` (requests to the target under test);
- `dependency_manifest`;
- `findings`;
- `source_excerpts`.

`credentials`, `signing_key` and `model_credentials` are refused by name (`EGRESS_PROHIBITED`). Content categories are `findings`, `source_excerpts` and `dependency_manifest`: sending them needs purpose `submission`, except `dependency_manifest` under `tool_update`, which FEATURE-002-D decides (AC-29).

**URLs:** `canonical_url(url) -> (origin, path)`.
- http or https only.
- Userinfo, a query or a fragment → refused (`EGRESS_URL_CREDENTIALS` / `EGRESS_INVALID`).
- The host is lowercased and IDNA-encoded; the default port is dropped.
- The path is percent-decoded once. Dot segments, encoded `/` or `\`, double encoding or control characters → `EGRESS_INVALID`.
- Recipients are origins (path empty or `/`).
- Scope entries are project-relative paths (no `..`, validated like targets) or URL prefixes `origin/path`.
- **Coverage:** equal, or below a granted entry at a `/` boundary on the same origin.

**`coverage(state, purpose, origin, data, scope) -> missing | None`.** One function used by declarations, the gate and Adapters. It checks, in order:
1. the purpose;
2. the origin;
3. data ⊆ the grant's data;
4. every scope entry covered.

It returns the first element that is missing.

**`guard allow-egress`:**
- **Inputs:** `--run`, `--purpose`, `--recipient`, `--data` (comma-separated), `--scope` (repeatable), `--reason`.
- **Gate:** interactive terminal with the typed verification id; otherwise `INTERACTIVE_REQUIRED` / `CONFIRMATION_MISMATCH`.
- **Run state:** the run must be open; a cancelled or finished run is refused. Allowed while paused, because the user is the one answering. Refused when the time budget is exhausted (spec 03a); the next step is "extend first".
- **Storage:** every field passes `mask_text`. A recipient or scope that masking would change is refused (`EGRESS_URL_CREDENTIALS`); the reason is stored masked.
- **Commit:** `commit_state`.

**`guard egress --request`** (`guard-egress/v1`: `purpose`, `recipient`, `data`, `items` [≤ 50 × ≤ 500 chars], `scope`):
- Gate `work`.
- `coverage` decides: allowed with id `eg-<n>`, or refused with `missing`.
- Recorded masked either way through `commit_state`.
- A refusal returns problem `EGRESS_NOT_AUTHORIZED` with exit 1.

**`EgressGate(root, vid)`**, for toolkit-owned clients:
- **`authorize(purpose, url, items: list[Item], scope) -> Authorization`**, where `Item = {category, content, ref}`. The gate builds the payload itself from structured items (no free-form payload):
  1. Every item's category must be granted.
  2. Each `ref` (project path or URL) must be covered by the scope.
  3. `url`'s path must be covered too.
  4. Content is masked with `mask_text`. Recognized private keys or model credentials → `EGRESS_PROHIBITED`, nothing sent.
  5. The payload is canonical JSON of the masked items.

  The authorization binds the purpose, canonical URL, categories, item refs and payload digest. It is recorded as a declaration `by: toolkit` (with the authorization id and payload digest) via the project lock and `update_state`, with gate `work`.
- **`send(auth)`** consumes the authorization **before I/O** in one `update_state` transaction (project lock → commit lock).
  - It checks the persisted declaration (id, digest, `used: false`) and re-checks the marker or result, pause and time budget. Reuse is refused with `EGRESS_REUSED`.
  - It sets `used: true`, writes, and releases both locks; then it sends exactly the bound payload to exactly the bound URL with the gate's own opener.
  - A failed call stays consumed.
- **Transport:** an `urllib.request` opener built from `ProxyHandler({})`, so environment proxies are never used, and a redirect handler that raises; a 3xx response is returned as "redirect requires a new authorization".
  - Tests replace the whole opener through a private constructor argument.
  - Tests also check the production opener's handlers: proxy environment variables are set and no proxy is used, and a redirect is not followed. Both use a local test HTTP server on 127.0.0.1, which is the only network use in the tests.

Categories on items are set by toolkit code (reviewed), not by agents. Mislabelling by toolkit code is a code-review matter (stated).

**`adapter_network_check(state, adapter, req) -> ExecutionMode`:**
- `ADAPTERS[name]` gains `network: {"purpose", "recipient", "data", "scope_from": "targets|none", "offline_argv": [...] | None} | None`.
- Opengrep: `None` → `ExecutionMode("none", [])`.
- Otherwise `coverage(...)` with the declared data and the derived scope:
  - granted → `("networked", [])`, with a `toolkit` declaration;
  - else, if `offline_argv` is set → `("offline", offline_argv)`, which toolrun appends to argv (tested on the final argv);
  - else refuse before execution with `EGRESS_NOT_AUTHORIZED`, naming the missing element.
- The report always states that launched tools are not network-isolated.

**Static test:** no module outside `egress.py` imports `socket`, `http.client`, `urllib.request`, `requests` or `ssl`. Parsing-only `urllib.parse` (`payload.py`) is allowed.

### Result and Report (`engine.py`, `report.py`)

- **Result keys (additive):**
  - `budget`: limits, defaulted/legacy, extensions, pauses, consumed, `exhausted` (limit or null), `extra_used`, model usage {requests, input_tokens, output_tokens, unknown_attempts, not_applicable_attempts}.
  - `attempts`: id, kind, covers, extra, status, overrun.
  - `cancellation`: requested_at, reason, consumed_at_request, termination, or null.
  - `egress`: grants and declarations.
- `limits` add: unregistered work, undeclared calls, work while paused, launched tools not network-isolated, masking pattern-based (NFR-002A-2), remote work may continue and be billed.
- **Report sections:**
  - **Budget:** a limits table, then extensions, pauses with reasons, an attempts table (planned/extra/unfinished/cancelled, overrun) and usage. If exhausted, a line "Budget exhausted (time|attempts) — unverified checks: …", listing only `unconfirmed` or missing-ledger checks; `not_met` and `n/a` keep their states.
  - **Cancellation:** shown when cancelled. Requested time, reason, tool termination, the agent attempts "stop requested, not confirmed by the toolkit", and "remote requests may continue or be billed".
  - **Egress:** a table of grants and declarations (purpose, recipient, data, scope, decision, by), plus the limit text.
- Report repair renders from the stored result only (existing `_repair_report`).

### CLI Contract (additions)

`guard attempt`, `guard pause`, `guard resume`, `guard extend`, `guard cancel`, `guard allow-egress`, `guard egress`, with options as in the tables above, all `--project` and `--json`.
- **New problem codes:** `BUDGET_INVALID`, `BUDGET_TIME_EXHAUSTED`, `ATTEMPTS_EXHAUSTED`, `ATTEMPT_REQUIRED`, `ATTEMPT_INVALID`, `RUN_PAUSED`, `ALREADY_PAUSED`, `NOT_PAUSED`, `EXTENSION_INVALID`, `RUN_CANCELLED`, `EGRESS_INVALID`, `EGRESS_PROHIBITED`, `EGRESS_URL_CREDENTIALS`, `EGRESS_NOT_AUTHORIZED`, `EGRESS_REUSED`.
- **Reused codes:** `INTERACTIVE_REQUIRED` and `CONFIRMATION_MISMATCH`.

### Guard SKILL.md (AC-002C-06a)

New "Budget, pause and cancel" and "Outbound calls" sections covering:
- defaults or less, and ask the user to extend;
- register an attempt per unit of work and cite it;
- pause only while waiting and do nothing while paused;
- on exhaustion, stop and conclude;
- on cancel, stop your Reviewer and helpers;
- declare before every outbound call, send only declared, minimized and masked data, and never submit source, findings or credentials without a submission grant;
- the host session and its Reviewer are not egress.

`references/guard-records.md` gains the attempt, egress and usage formats; `cli-contract.md` gains the rows.

### Implementation Steps

1. Move the tool request validation into `toolreq.py` (behaviour unchanged; the existing tests stay green).
2. Add `budget.py` and its unit tests (time math with injected `now`, legacy, extra counting, citation, extension, usage).
3. Add `runs.py` `commit_state` (barrier), `bump_clock`, exclusive result; extend `service.py` (open, `_mutate`, plan, record, review, conclude, show) and the record/review schemas.
4. Add `control.py` (attempt, pause, resume, extend) and the CLI.
5. Add `process.run` `should_stop`; integrate `toolrun.py` (attempt, cap, active/ack, no commit after cancel, network check).
6. Add `cancel.py` and the engine cancelled rule; tests including concurrent cancel with a sleeping fake tool, a hung owner (SIGSTOP), conclude-versus-cancel and two cancels.
7. Add `egress.py`, the CLI commands, `EgressGate` with a fake transport, and the Adapter network check with a fake registry entry.
8. Add the report and result sections and update the existing report tests additively.
9. Update the skill, references, CLI contract and README; update the acceptance-runner expectations of FEATURE-002-A/B for attempts (old runners now need `guard attempt`).

### Edge Cases & Error Handling

| Case | Handling |
| --- | --- |
| Backward clock | High-water mark |
| Pause during a tool run | `LOCKED` (project lock held) → the agent retries after the run |
| Cancel while another verification's tool holds the project lock | Cancel needs only its own commit barrier → proceeds |
| Owner hung (SIGSTOP) | No ack within 3600 s → finalize from the frozen state, `not_confirmed` with pid; when resumed, the owner's commit is refused by the barrier |
| Commit barrier held by a suspended process | The marker is already durable and changes are refused. After 30 s, cancel returns "finalization pending". The next cancel or conclude finalizes from the frozen state once the barrier is free (the OS releases it when the holder exits) |
| `show` after cancel, before finalization | Returns `consumed_at_request` (frozen clock) |
| Two egress `send` calls race on one authorization | `update_state` lets exactly one set `used`; the other gets `EGRESS_REUSED` |
| Proxy variables set in the environment | Ignored by the gate's opener (`ProxyHandler({})`) |
| Writer between its early check and its write when cancel arrives | The barrier re-check refuses its commit → `RUN_CANCELLED` |
| `accept-risk` on a cancelled Fail | Refused; the cancelled result is final |
| Two `show` calls around a backward clock change | `clock.json` keeps the high-water mark |
| Cancel process killed after the marker | The run is refused for changes; `conclude` finalizes it as cancelled |
| Conclude and cancel race | First exclusive result wins; the loser returns it or `RUN_FINISHED` |
| Attempt cites another verification's id | `ATTEMPT_INVALID` (ids are per state) |
| Record with evidence for a pair outside the attempt | `ATTEMPT_INVALID`, nothing recorded |
| Legacy open run | `ensure` defaults from `opened_at` (may be exhausted at once → user extends or concludes) |
| Grant recipient with a token in the URL | `EGRESS_URL_CREDENTIALS`, nothing stored |
| Gated payload with a PEM private key | `EGRESS_PROHIBITED`, not sent, refusal recorded |

### Security, Tracing and Observability

- No secrets in the budget records. Reasons and items are masked (`mask_text`). Grant and declaration fields that change under masking are refused (URLs) or stored masked (text).
- The marker, ack and active files contain only pids and timestamps.
- No logging beyond the result envelope (consistent with FEATURE-002-A).
- Interactive gates reuse `TerminalInteraction`. Honest limit: a pseudo-terminal counts as interactive.
- Tracing: N/A. The project has no tracing infrastructure, and the run state and report are the audit trail.

### Goal / Acceptance / Design / Validation Coverage

| AC | Design means | Planned validation |
| --- | --- | --- |
| 01a | `budget.initial`, open | integration: none/≤/>/0 budgets |
| 01b | `consumed` + `clock.json`; show `NOT_CONCLUDED` data | unit (pause-frozen); integration: two `show` calls around a patched backward clock, record data |
| 01c | `control.attempt`, `register`, record/review `cite`, tool self-register | integration: no attempt/other run/other kind/out of coverage refused |
| 01d | extra counting per pair/item, `planned`, `seen_before` | unit + integration (batched retries cost per pair; later method extra; legacy evidence/Adapter/review retries extra) |
| 01e | single-use `cite`, overrun in consumed time | integration: second citation refused; overrun excludes pauses |
| 01f | `add_usage`, MODEL_KINDS | unit + report test |
| 01g | toolrun cap | integration with fake tool sleep, small remaining |
| 02a, 02b | pause/resume, gates | integration per command; report pauses |
| 03a, 03b | `require_running`, `register` refusals, record classification | integration (time via patched clock) |
| 03c | engine/report exhaustion line | integration: `not_met`/`n/a` preserved |
| 03d, 03e | `control.extend` interactive terminal | integration with fake Interaction (typed id, mismatch, non-interactive, request field refused) |
| 04a | marker under commit barrier, frozen state, `finalize_frozen` | integration: cancel while B's tool holds the project lock (thread), B unaffected; record committing concurrently (barrier race injected) refused |
| 04b | `should_stop`, ack confirmed | integration with real subprocess fake tool sleep |
| 04c | wait → not confirmed | integration: SIGSTOPped owner, wait patched short |
| 04d | barrier refuses late commits; exclusive result; two cancels; `accept-risk` refused | integration (threads; tool finishing after marker) |
| 04e | engine cancelled rule; report section | integration: confirmed High → Fail; else cannot_confirm_pass |
| 04f | idempotent cancel; repair from result | integration |
| 05a–05e | egress grants/declarations, masking | integration with fake Interaction |
| 05f | `EgressGate` (structured items, bound URL/digest, consume-before-I/O, own no-redirect transport) | unit: same-origin path change, encoded traversal, uncovered item ref, private key, masking, concurrent reuse, use after cancel/pause/exhaustion, redirect-following injected transport; static import test |
| 05g | report egress section and limits | integration |
| 05h | `adapter_network_check` → `ExecutionMode` | unit with patched registry (granted / offline argv applied / refused); Opengrep none |
| 06a | SKILL.md text | structured phrase checks (existing skill test pattern) |
| 06b | report sections | integration |
| 06c | `ensure` legacy | integration with a pre-feature state fixture |

### Outcome Scenario and Evidence Gaps

- **Scenario (planned black-box acceptance with the real CLI):**
  - A verification on the marathon sample: two failed tool retries exhaust the 3 extra attempts, and a third is refused. Conclude → a partial report with unverified checks.
  - A second verification is cancelled during an Opengrep run (WebGoat), with termination confirmed; a recorded confirmed High still gives Fail.
  - A submission declaration without a grant is refused.
- **Gaps:** host/Reviewer termination and undeclared calls are unobservable. Stakeholder outcome: not measured.

### Test Plan

New: `tests/guard/test_budget_units.py`, `test_guard_budget.py`, `test_guard_cancel.py`, `test_guard_egress.py`, `tests/test_module_size.py` (every module < 800 lines). The cancel tests include races for a record commit, a tool attempt registration, a pre-spawn stop, a hung (SIGSTOP) owner and a mocked PGID-reuse probe. The FEATURE-002-A/B test helpers gain `attempt()`. All existing assertions are kept, and only the call sequences add attempt registration. Run the full suites on macOS 3.14/3.11 and Linux 3.12, plus ruff.

### Mockup-to-Component Mapping

N/A — no UI.

### Delta and Evidence Invalidation

FEATURE-002-A/B behaviour changes additively:
- new records must cite attempts;
- `_mutate` checks pause, cancellation and budget;
- results gain new keys.

Their unit tests and black-box runners must be updated for attempt registration (no assertion relaxed) and rerun. The closed features' evidence stays historical for their revision.

## Implementation Evidence (TASK-037, 2026-10-21)

- Toolkit tree `4fcd9750…`. Source hashes: `budget.py` `3099a8b0…`, `control.py` `a230b72e…`, `cancel.py` `d4eb179e…`,
  `egress.py` `4dc1856b…`, `runs.py` `64cb5f4d…`, `service.py` `839305e2…`, `toolrun.py` `ef189f74…`, `engine.py`
  `4f9a4297…`, `report.py` `7063af62…`, `retention.py` `7aeefc0c…`, `toolreq.py` `11030355…`, `adapters/process.py`
  `4fcf6b75…`; specification `fca9f235…`.
- TDD: unit RED recorded for `budget` (32 failed/1 passed on the no-op skeleton), `runs` primitives (8 failed), `process`
  stop/probe (3 failed), cancel (10 failed), egress (37 failed), skill text (2 failed) and the code-review fixes (5 RED,
  incl. a dead-owner cancel that hung > 180 s). The service-wiring integration tests were written first but not executed
  before the wiring (process gap); compensated by 7 mutation checks (attempt requirement, pause/time gate, single-use
  attempts, cancelled never pass, barrier marker re-check, clock high-water, egress data coverage) — all mutants killed,
  sources restored byte-identical.
- Suites: macOS Python 3.14 647 passed, 2 skipped; Python 3.11 646 passed, 3 skipped (waitid variant); Linux Python 3.12
  649 passed; `ruff check` clean; every module < 800 lines (test); coverage of new/changed modules 89–100% (92% overall).
- Regression runners with the new attempt sequence (early check, container, real Opengrep): FEATURE-002-A 26/26,
  FEATURE-002-B 10/10 (rerun at acceptance).
- Existing-test changes (call sequence only, no assertion relaxed): `test_guard.py` helpers register attempts
  (`with_attempt`, CLI round trip uses `guard attempt`); `test_guard_tool.py` 04e records its method change and evidence
  separately; `test_guard_report.py` heading list gains "Outbound Calls (Egress)" (AC-002C-05g).
- Independent code review (code-review subagent): 4 findings (termination claim across rules, dead owner wait, payload
  digest in `send`, encoded URLs) + 1 follow-up (late-cancel ack) fixed test-first; final check: no remaining issues.

## Design Change Log

| Date | Version | Change | Reason |
|------|---------|--------|--------|
| 10-20-2026 | v1.0 | Initial design. User decisions: defaults 60 min / 3 extra attempts, max 480 min / 20, cancel wait 3600 s (B-07) | TASK-036 |
| 10-20-2026 | v1.0 | Design review fixes (7 blocking, 4 non-blocking): commit barrier replaces the run lock (marker under barrier, frozen state, owner commits its tool attempt before spawning); `accept-risk` refuses cancelled results, conclude reconciles to `cancelled`; `clock.json` high-water mark persisted by `show`; legacy `seen_before` baseline; structured-item egress gate bound to URL path/payload digest, consumed before I/O with re-checks, own no-redirect transport; grants refused after exhaustion, Adapter network check via the shared coverage function returning an execution mode; `waitid(WNOWAIT)` group handling without PGID reuse; overrun in consumed time; normalized record classification; fsync of directories; module-size test | Independent design review |
| 10-20-2026 | v1.0 | Re-review fixes (5 blocking, 1 non-blocking): cancel marker created at once without a lock (linearization at barrier; 30 s barrier wait, then finalize with lock note); clock frozen at `consumed_at_request`; `revision` optimistic check in `commit_state` and `update_state` transaction for the gate (consume before I/O, persisted id/digest); `deadline_consumed` recorded and moved by extensions; `ProxyHandler({})`; transport option row corrected; final check: no finalization while the barrier is held, "finalization pending" until the next cancel or conclude | Focused design re-review |
| 10-21-2026 | v1.0 | Implementation adjustments (TASK-037), within the approved contracts: (1) `os.waitid` is missing on macOS before Python 3.13 — there `process.run` falls back to the FEATURE-002-B order (reap, then kill the group), leaving a narrow process-group-id reuse window (stated limit; the termination probe stays conservative); (2) risk acceptance, keep, release and cleanup moved from `service.py` to `guard/retention.py` (re-exported; behaviour unchanged) to stay below 800 lines; (3) a well-formed record with evidence/findings but no attempt is refused with `ATTEMPT_REQUIRED` after shape validation, so malformed requests still get `RECORD_INVALID`/`REVIEW_INVALID`; (4) the report's Egress section is rendered for results that carry egress data (pre-feature results re-render unchanged); (5) a networked Adapter run records a `toolkit` declaration in the run state | Implementation |
| 10-21-2026 | v1.0 | Bug fix TASK-039 (acceptance TASK-038 with the real Opengrep): the termination probe waits up to 5 s for the tool's process group to disappear and counts already-exited (zombie) members as gone; members are listed from `/proc` (Linux) or `ps`; unknown member state stays "not confirmed". Real Opengrep runs worker children that are killed but linger as zombies (or finish exiting asynchronously), so the previous signal-0 probe never confirmed. No AC changed | User-approved bug fix (TASK-038 decision) |
| 10-21-2026 | v1.0 | Bug fix TASK-041 (closing review TASK-040):
<br>• attempt ids are bound to their verification (`a-<n>-<last 8 hex of the verification id>`), and a foreign id is refused naming the other verification;
<br>• evidence, manifest and output files written for a commit that loses to a cancellation are removed;
<br>• URLs are checked for credentials after percent-decoding as well;
<br>• every run-bound command result and refusal carries the budget status (central in `_mutate`/tool run);
<br>• wording: termination confirmation means the tool's process group was seen exiting (processes that left the group are not tracked);
<br>• the interactive-terminal gates (extend, allow-egress) are cooperative controls, like risk acceptance — a program able to drive a pseudo-terminal could pass them, and they are not an authorization boundary;
<br>• conclude/cancel ordering stays linearized (a conclusion already publishing wins; cancel answers `RUN_FINISHED`), now proven by a deterministic test.
<br>No AC changed | User-approved bug fix (closing review decision) |
| 10-21-2026 | v1.0 | Bug fix TASK-042 (closing re-review TASK-040): files left by a commit that lost are removed only by exact name through a descriptor of the run's evidence folder opened without following links (`runs.remove_evidence_files`, `unlink(dir_fd=)`); a linked or replaced folder is left alone and the original refusal (for example `RUN_CANCELLED`) is still returned. The tool run no longer removes by pattern. No AC changed | Closing re-review finding |
| 10-23-2026 | v1.1 | CR-TASK-077 delta appended (Reviewer coverage item `helpers`; DEC-2 known-helper source `state["helpers"][*]["id"]`, DEC-3 review wiring, DEC-5 record shape only when named). Design only; not implemented | Human decision B12 = A; [CR-TASK-077](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/CR-TASK-077-helpers-coverage.md) |

## CR-TASK-077 Delta: Reviewer coverage item `helpers` (v1.1, 2026-10-23)

> Source: [CR-TASK-077](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/CR-TASK-077-helpers-coverage.md) (classification: modification; human decision B12 = A). This section extends, and does not remove, "Coverage of `register`", "Extra counting", "State Additions" and the `cite` contract above. Spec: AC-002C-01h, AC-002C-01i, FR-002C-2a. Status: designed, **not implemented**.

**Scope.** Reviewer attempts may cover helpers (FEATURE-002-F temporary check scripts). Out of scope here: the `helper` Reviewer subject type (FR-002A-4 extension, FEATURE-002-F), helper records/ids/lifecycle (FEATURE-002-F), the delivered `helper`/`generation` attempt kinds (pairs coverage, unchanged), Guard skill text (FEATURE-002-F, AC-002F-10a; DEC-4).

**Request `guard-attempt/v1` (version unchanged).**

```json
{"schema": "guard-attempt/v1", "kind": "reviewer",
 "covers": {"findings": ["F1"], "na": [], "helpers": ["<helper id>"]}}
```

- `kind == "reviewer"`: `covers` allowed keys `{"findings", "na", "helpers"}`, each optional; at least one item in total, else `ATTEMPT_INVALID` "a reviewer attempt must cover at least one finding, N/A decision or helper".
- Other kinds: unchanged (`{"pairs"}`; `helpers` → "covers has unknown fields" `ATTEMPT_INVALID`). Internal `tool`/`tool_update`: unchanged.

**Known helpers (DEC-2).** `known = {h["id"] for h in state.get("helpers", []) if isinstance(h, dict) and isinstance(h.get("id"), str)}`. The `helpers` run-state key is owned and written only by FEATURE-002-F; 002-C reads ids only. Absent key → empty set → every helper id refused `ATTEMPT_INVALID` "covers.helpers[i]: unknown helper '<id>'". Ids are validated with `ck.key` and deduplicated in request order (as findings/na).

**State additions (`guard-run/v1`, additive; absent keys = empty).**

```json
"attempts": [{"id": "a-7-…", "kind": "reviewer",
              "covers": {"pairs": [], "findings": [], "na": [], "helpers": ["h-1", "h-2"]}, "extra": 0, "…": "…"}],
"budget": {"seen_before": {"pairs": [], "findings": [], "na": []}}
```

- `covers.helpers` is written **only** when the request named at least one helper (DEC-5); every other attempt keeps the delivered shape (exact-dict test `tests/adapters/test_trivy_units.py:816–821` stays valid).
- `budget.seen_before.helpers` is never written; read as `seen_before.get("helpers", [])`. `initial()` and `ensure()` are unchanged (pre-002-C states cannot contain helpers, so no legacy baseline is needed). No migration.

**`budget.py` changes.**

| Function | Change |
| --- | --- |
| `_covers(state, "reviewer", raw)` | Allowed keys + `helpers`; validate against `known`; message per key (`finding`, `N/A`, `helper`); add `out["helpers"]` only when non-empty; empty-coverage message as above |
| `_seen(state)` | `seen["helpers"] = set(base.get("helpers", [])) ∪ ⋃ a["covers"].get("helpers", [])` over all attempts, any status |
| `register` | `extra_items` += `[h for h in cov.get("helpers", []) if h in seen["helpers"]]` (after findings, then na); `ATTEMPTS_EXHAUSTED` names them; first coverage never extra |
| `cite` | `outside` += `[h for h in used.get("helpers", set()) if h not in cov.get("helpers", [])]` |
| `cancel_unfinished`, `extend`, `summary`, `require_running`, overrun, usage | Unchanged (helper-covering attempts are ordinary `reviewer` attempts: `MODEL_KINDS`, `RUN_PAUSED`, `BUDGET_TIME_EXHAUSTED`, cancelled on cancel) |

**`service.py` (`guard review`, DEC-3).** `used_items["helpers"] = {s["id"] for s in subjects if s["type"] == "helper"}` next to `findings`/`na` (L410–413 at `8f3d7303…`). Inert until FEATURE-002-F adds the subject type (002-A validation refuses unknown subject types today); keeps the coverage check fail-closed. `service.py` stays < 800 lines.

**`report.py`.** Attempts table Covers column: `pairs + findings + na + covers.get("helpers", [])` (L550 at `ce3cc4e5…`). Budget summary keys unchanged.

**Error codes.** None new.

| Case | Result |
| --- | --- |
| Unknown helper id / no `helpers` state | `ATTEMPT_INVALID`, nothing recorded |
| `helpers` on `semantic_review`, `helper`, `generation` | `ATTEMPT_INVALID` (unknown fields), unchanged |
| Re-coverage with no extra attempts left | `ATTEMPTS_EXHAUSTED` naming the helper ids; first coverage accepted |
| Paused / time exhausted / cancelled / finished | `RUN_PAUSED` / `BUDGET_TIME_EXHAUSTED` / `RUN_CANCELLED` / `RUN_FINISHED`, unchanged |
| Review cites attempt; `helper` subject outside coverage | `ATTEMPT_INVALID` "attempt … does not cover <id>" |

**Compatibility.** Old request files, attempt records, run states and results load and behave byte-identically; a new request naming helpers sent to an older toolkit is refused (`ATTEMPT_INVALID`, fail closed). Downgrade of a state containing helper coverage is not supported.

**Handoffs to FEATURE-002-F design.** (1) Adopt `state["helpers"][*]["id"]` (or raise a follow-up CR); (2) post-run acceptance is re-coverage → one extra attempt per helper; default 3 extra attempts (B-07) means ≥ 4 accepted helpers need a user extension — state it in skill/report; (3) a resubmitted helper under a new id must still need a `generation` attempt on the same (check, helper method) pair so it is extra under unchanged rules.

**Test plan (test-first; new test functions only, no delivered test edited).**
- `tests/guard/test_budget_units.py`: planned/extra helpers; mixed findings+na+helpers; unknown helper, helpers on other kinds, empty coverage → `ATTEMPT_INVALID`; dedupe; `ATTEMPTS_EXHAUSTED` names helper while first coverage passes; cancelled attempt's helpers count as seen; `cite` inside/outside; legacy state without `helpers`/`seen_before.helpers`; record shape unchanged when no helper named; service wiring of `used_items["helpers"]` by unit injection.
- `tests/guard/test_guard_budget.py`: `guard attempt` CLI round trip on a run state seeded with a `helpers` list (fixture writes the 002-F-owned key); pause/time/cancel refusals; report Covers column.
- Regression: full suite and 002-C `acceptance/blackbox.py` unchanged and passing; ruff; module-size test.
- Delivered tests requiring change: **none** (inspected list in the CR document).

**Evidence invalidation.** None of the delivered 002-C evidence (TASK-037/038/040) is invalidated for requests without helpers; AC-002C-01h/01i evidence is pending implementation.

> **Implementation status (2026-10-24, appended by Sage):** the CR-TASK-077 delta is implemented by TASK-083 (`guard/budget.py`, `guard/service.py`, `guard/report.py`; new tests `tests/guard/test_budget_helpers_units.py`, `tests/guard/test_guard_budget_helpers.py` — new files instead of the planned appends, so delivered test files stay byte-identical). Independent code review PASS; full suite 2563 passed, 0 failed; 002-C host black-box regression byte-identical. Evidence: CR-TASK-077 "Implementation Evidence" section. Toolkit file-list hash `b89a972fa0fe35007e6017519365e73ed0a2309005495178ec44b5a5d63c176a`.
