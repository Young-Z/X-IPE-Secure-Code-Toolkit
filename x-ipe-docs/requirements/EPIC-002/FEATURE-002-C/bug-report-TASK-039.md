# Bug Report — TASK-039: Cancelling a real Opengrep run never confirmed termination

## Reported Behavior

- **Source:** FEATURE-002-C acceptance TASK-038, first container run with the real Opengrep v1.31.0 binary.
  Result: 8/9; TC-C-06 failed its check "04b running Opengrep stopped by its owner; termination confirmed"
  ([evidence-container-linux-run1-FAIL.jsonl](acceptance/evidence-container-linux-run1-FAIL.jsonl), `bdc87d87…`).
- **Severity:** Medium. The tool was stopped and the report erred on the honest side (`not_confirmed`), but
  AC-002C-04b could never be met for a multi-process tool.
- **Expected:** AC-002C-04b — the final result states termination confirmed when the owner has observed every tool
  process it started exit.
- **Actual:** The owner returned `{"tool": "not_confirmed", "detail": "tool process group still present"}`, although no
  `opengrep` process was left running afterwards.
- **Mode:** free-mode, interact-with-human; the user chose Bug Fix.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-04 (honest cancel) | spec G-04; AC-26 (B-10) | Developer | Cancel reports termination confirmed when the tool's processes have exited, and never claims it otherwise | Probe that waits briefly and counts exited (zombie) members as gone | Never a false confirmation; live, unknown or reused members stay "not confirmed" | AC-002C-04b / Integration | Real Opengrep run cancelled in a container → `not_confirmed` | RED/GREEN below; real-binary rerun 9/9 | not measured |

## Reproduction

- Container `fat-uv-git:py312`, real Opengrep, WebGoat `src` with 12 rules (long run). Cancel 2 s after the tool
  started → the cancel and tool results both report `not_confirmed`, and `/proc` then shows no `opengrep` process.

## Root Cause

`process._group_gone` judged the group by `killpg(pgid, 0)` immediately after reaping the leader. Opengrep runs worker
child processes in the same process group. After SIGKILL they exit, but they stay as zombies until reaped. In the
container, PID 1 is the runner, which never reaps adopted orphans; on hosts the reaping happens asynchronously. A
zombie still belongs to the group, so `killpg(pgid, 0)` succeeded. macOS answers `EPERM` for a zombie-only group,
which the old code also counted as "present". This was a design flaw in the probe (implementation `4fcf6b75…`).

## Scope and Conflicts

- **Expected consequence:** termination is confirmed when only exited members remain, or the group disappears within
  5 s. A normal run whose group is already empty still returns immediately (ESRCH).
- **Unchanged:** the kill order (waitid kill-before-reap, or the fallback on macOS before Python 3.13), staging cleanup,
  acknowledgement files and the final result rules.
- **Safe direction kept:** a live member, an unreadable member list (no `/proc` and no `ps`) or a timeout all mean
  "not confirmed". A reused process-group id would show a live member.
- **Unexpected conflicts:** none. Inspected: AC-002C-04b/04c, design "Tool Run Changes", `process.run`, `toolrun`
  ack paths, `cancel._termination`.

## Fix and Design Impact

- Design updated first: Tool Run Changes probe bullet; Design Change Log row TASK-039.
- `process._live_members(pgid, proc=Path("/proc"))`:
  - **Linux:** reads `/proc/<pid>/stat` as bytes, taking the fields after the last `)`.
  - **Elsewhere:** runs `ps -A -o pgid=,stat=`.
  - **Result:** `True` if any member is not `Z`/`X`; `False` if none is; `None` if the list cannot be read.
- `process._group_gone(pgid, wait=5 s)`:
  - Loops until the group is gone or the wait ends.
  - `ProcessLookupError` → gone.
  - `PermissionError` (macOS zombie group) → the member list decides.
  - `_live_members` is `False` → gone.
  - Timeout → not gone.
- **Fix-review follow-up:** the first version read `stat` as text, so a process name with non-UTF-8 bytes would raise
  an uncaught `UnicodeDecodeError` inside `run()`. It now parses bytes (RED test with a fake `/proc` below).

## Mini AAA and Actual Routing

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| Zombie-only group (04b) | Child in its own session exited, left unreaped | `_group_gone(pid)` | `True` | pytest unit (real process) | RED macOS (`e8d2909a…` test file) and Linux: `False`; GREEN |
| Live member (safe side) | `sleep 30` in its own session | `_group_gone(pid, wait=0.3)` | `False` | pytest unit | added with the RED pair (API RED: `wait` kwarg); GREEN |
| Odd process names | Fake `/proc`: truncated UTF-8 name, `) (` in a name, invalid bytes | `_live_members(77, proc=…)` | zombies → `False`; live member → `True` | pytest unit | RED on the text parsing: `UnicodeDecodeError`; GREEN |
| Real binary (04b) | Container, real Opengrep, long run | `guard cancel` | termination confirmed; no opengrep process left | black-box TC-C-06 | 9/9 |

One existing test was adjusted for the new rule: `test_process_group_probe_reports_survivor_as_not_gone` now models
its survivor as a live member (`_live_members → True`, wait 0.3 s). Its intent — a surviving group is never confirmed —
is unchanged.

## Verification

- **RED:** Linux and macOS, `assert False is True` for the zombie-only group on unfixed `process.py` `4fcf6b75…`. The
  odd-name case raises `UnicodeDecodeError` on the text-parsing variant.
- **GREEN:** `process.py` `72a1cfed…`, tests `229566a9…`.
- **Full suites:** macOS Python 3.14: 650 passed, 2 skipped. Python 3.11: 649 passed, 3 skipped. Linux Python 3.12:
  652 passed. `ruff check` clean. Toolkit tree `9cc46689…`.
- **Original reproduction:** fresh offline cache with the fixed code. FEATURE-002-C container 9/9, stderr empty
  ([evidence](acceptance/evidence-container-linux.jsonl), `3622e5e8…`). Regression: FEATURE-002-A 26/26 + 2/2,
  FEATURE-002-B 10/10 + 2/2. Host 2/2.
- **Independent review** (code-review subagent): one finding (text decoding of `/proc`), fixed test-first; final check
  found no issues.
- **Stakeholder outcome:** not measured.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed
  next_task_based_skill: null
  process_preference:
    interaction_mode: "interact-with-human"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/process.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/adapters/test_adapters_units.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/technical-design.md"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/bug-report-TASK-039.md"
  bug_severity: "Medium"
  root_cause: "The termination probe counted killed-but-unreaped (zombie) Opengrep workers as surviving members of the tool's process group"
  conflicts_found: []
```
