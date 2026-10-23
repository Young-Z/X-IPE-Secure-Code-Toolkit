# Bug Report — TASK-032: Opengrep silently produces no output in a non-ASCII project path

## Reported Behavior

- **Source:** FEATURE-002-B acceptance (TASK-031), first real-binary container run
  ([evidence-container-linux-run1-FAIL.jsonl](acceptance/evidence-container-linux-run1-FAIL.jsonl),
  sha256 `cb531fbe…`, stderr file empty). Result 5/10: every case that ran Opengrep failed.
- **Severity:** High. The feature (running the Opengrep Adapter inside Guard verification) did not work
  for any project whose path contains non-ASCII characters (acceptance project `proj ü`).
- **Expected (spec):** AC-002B-03a (disposable home, removed after the run), AC-002B-03c/03d (tool findings
  recorded as evidence), AC-002B-03f (tool errors become failed methods, never a clean result),
  AC-002B-03h (zero findings only when the tool really scanned).
- **Actual:** Opengrep v1.31.0 exited 0 with empty stdout and stderr. The toolkit could not parse the output,
  so the method failed. No false Pass was observed, but no scan was possible.
- **Mode:** free-mode, interact-with-human. The user chose Bug Fix at the TASK-031 boundary.
  Write scope: `guard/toolrun.py`, its tests and test double, and the 002-B technical design.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-05 (approved tool runs on a disposable copy) and the 002-B tool-evidence goal | specification.md G-05, EPIC-001 FR-24 | Developer, Owner | A registered Opengrep run produces tool findings for a project whatever characters its path contains | Moving the disposable home outside the project removes the trigger. An explicit gap covers any remaining silent exit | Home still disposable and private, and removed after the run. No OS isolation claimed. Original project unchanged | AC-002B-03a, 03c, 03d, 03f, 03h / Integration | Project `proj ü` → Opengrep exit 0, no output | RED/GREEN below. Real-binary rerun in TASK-031 | not measured |

## Reproduction

- Container `fat-uv-git:py312` (Linux aarch64, Python 3.12), real Opengrep v1.31.0 (official
  manylinux_aarch64 digest `2b713a29…`), acceptance runner `acceptance/blackbox.py container`, project
  `proj ü`. 5 of 10 cases failed with "output could not be parsed".
- Isolation run: the same binary on the same rules and targets with `XDG_CACHE_HOME` set to a non-ASCII
  path → exit 0, empty stdout and stderr. With an ASCII cache path → normal JSON. A non-ASCII binary path,
  config, target, cwd, `TMPDIR` or a path with spaces did not trigger the failure.
- A diagnostic run with an ASCII project passed 10/10. It confirms the cause but is not acceptance evidence.

## Root Cause

`guard/toolrun.py` (unfixed sha256 `3231e8da…`) created the tool's disposable `HOME` (and so
`XDG_CACHE_HOME`, where Opengrep unpacks its runtime) inside the staging folder, which is under the
project. When the project path contains non-ASCII characters, Opengrep v1.31.0 fails to load its unpacked
runtime and exits 0 with no output. The toolkit design didn't account for this vendor-tool limitation.
The toolkit logic was otherwise correct: the empty output was already reported as a failed method, not a
pass. However, the "no output" case had no explicit gap text explaining it.

Callers inspected: `_execute` (setup and cleanup of stage/home), `_env`, `_stage_and_run`
(parsing/status), the `staging_left` cleanup report, `adapters/process.run` (receives an explicit env
only) and `adapters/opengrep.parse/status_of`.

## Scope and Conflicts

- **Expected consequence:** the home moves from `<stage>/home` to a private `mkdtemp` folder in the system
  temporary directory. AC-002B-03a requires a disposable home that is removed after the run, not one
  located inside the stage. The "staged paths" in 03a refer to targets and rule files, and that wording
  is unchanged. No AC change.
- **Expected consequence:** if the system temporary directory itself is non-ASCII, the run is refused
  before execution with the `TOOL_HOME_UNSUPPORTED` gap and a failed method. This keeps the
  "honest failure" principle (AC-24) instead of a silent failure.
- **Expected consequence:** a home left behind (for example if the process is killed) is reported through
  `staging_left` → "staging not removed" gap. This is the existing limit, now also covering the home.
- **Unaffected:** staging of targets and rules, digest checks before execution, the single commit after
  cleanup, masking, accounting and reporting. Full suites below.
- **Unexpected conflicts:** none found. Inspected: specification AC-002B-03a…03k, technical design
  Execution section, toolrun.py and the callers listed above.

## Fix and Design Impact

- `_tool_home()`: `tempfile.mkdtemp(prefix=…)` in `tempfile.gettempdir()` (mode 0700). A non-ASCII path
  removes the folder and returns the `TOOL_HOME_UNSUPPORTED` gap. It is created only after the registry
  check passes.
- `_env(stage, home)`: `HOME`, `XDG_CACHE_HOME` and `XDG_CONFIG_HOME` under the home. `TMPDIR` stays in
  the stage.
- `_execute`: home removed in `finally`. `staging_left` covers stage or home.
- `_stage_and_run`: exit 0 with empty output adds the gap "tool exited N with no output" (status remains
  failed).
- Design: technical-design.md Execution "Minimal env" bullet and Design Change Log row 10-20-2026 were
  updated before the code (design sha256 `537861ca…`).
- Alternatives rejected: renaming the project path (out of the toolkit's control), or ASCII-escaping the
  path inside the stage (the stage path inherits the project name).

## Mini AAA and Actual Routing

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| Non-ASCII project runs (03a/03c) | Fixture project `my project ü`. The fake emulates the vendor's silent exit for a non-ASCII cache | `guard tool` | Fake invoked; cache under an ASCII home; findings recorded | pytest integration | RED on unfixed, GREEN on fixed |
| Home removed (03a) | `test_03a_03b…` | `guard tool` | Home is not under the stage and was removed after the run | pytest | RED → GREEN |
| Non-ASCII temporary folder (honest refusal) | `tempfile.tempdir` set to a non-ASCII folder | `guard tool` | Not executed; temp folder left empty; method failed; summary mentions ASCII | pytest | RED → GREEN |
| Silent exit (03f) | Fake `silent` mode | `guard tool` | Status failed; "no output" gap | pytest | RED → GREEN |

The Python tool route was used directly with pytest (project convention). No app action or tag was written.

## Verification

- **RED:** unfixed `toolrun.py` `3231e8da…`, tests `test_guard_tool.py` `c462ee70…`,
  `fake_opengrep.py` `836be7b7…` → 17 failures with the real-binary symptom
  (`uv run pytest tests/guard/test_guard_tool.py`).
- **GREEN:** fixed `toolrun.py` `d79d9d1a…`, the same unchanged test (`c462ee70…`) and fake (`836be7b7…`)
  files → all pass.
- **Full suites:** macOS Python 3.14: 520 passed, 2 skipped (non-UTF-8 file names on APFS). macOS Python
  3.11: 520 passed, 2 skipped. Linux Python 3.12 (container): 522 passed. `ruff check`: all checks passed.
  `ruff format --check` lists files that were already unformatted before this fix; that is not a
  regression and is out of scope. `mkdtemp` mode 0700 checked. No leftover tool homes in the temporary
  directories after the suites.
- **Toolkit tree:** sha256 `30346157…`.
- **Independent review** (code-review subagent, 10-20-2026): no significant issues. Home cleanup on all
  paths, 0700 permissions, explicit six-variable env, the no-output gap cannot yield Pass, single commit
  after cleanup preserved. Open assumption: `TMPDIR` stays inside the stage. Isolation runs showed a
  non-ASCII `TMPDIR` is fine; the TASK-031 real-binary rerun is the confirming check.
- **Original reproduction at the fixed revision:** fresh uv cache volume warmed with the fixed toolkit
  (cache contains `TOOL_HOME_UNSUPPORTED`). Same offline container command, real Opengrep v1.31.0,
  project `proj ü` → 10/10 passed, stderr empty
  ([evidence-container-linux.jsonl](acceptance/evidence-container-linux.jsonl), sha256 `882e39c0…`;
  runner sha256 `59796b04…`).
- **Engineering delivery:** verified with the fake tool and the real binary (Linux aarch64).
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
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/toolrun.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/guard/test_guard_tool.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/adapters/fake_opengrep.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/technical-design.md"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/bug-report-TASK-032.md"
  bug_severity: "High"
  root_cause: "Tool HOME/XDG_CACHE_HOME was placed inside the project-derived stage; Opengrep v1.31.0 exits 0 with no output when its cache path is non-ASCII"
  conflicts_found: []
```

The owner (Sage) records completion. TASK-031 acceptance resumes with a fresh real-binary rerun.
