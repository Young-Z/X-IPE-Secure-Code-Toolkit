# Bug report — TASK-059: FEATURE-002-D acceptance findings F-1 and F-2

> Task TASK-059 (Bug Fix), owner Sage, free-mode (`workflow.name` N/A; no app bug_fix action exists), interaction
> mode `dao-represent-human-to-interact`. Authority: DAO-001 of `x-ipe-docs/dao/26-10-23/decisions_made_feature_acceptance_test.md`
> (approval: bug fix without specification change, exact version-pinned fail-closed allow-list, RED first).
> Paths below `scripts/` mean `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/`.

## Reported Behavior

Source: acceptance report `x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance-test-cases.md`
(SHA-256 `374b8429…`), findings **F-1** and **F-2** (real Trivy v0.76.1, offline Linux arm64 container).

| Finding | AC (specification `229cc76e…`) | Severity | Actual | Source-authorized expected |
| --- | --- | --- | --- | --- |
| F-1 | AC-002D-03d: "the type must be one of the misconfiguration types supported by the verified tool version (compose is not one)" | Medium (a supported, valid request is refused; workaround: another method) | `config_types` override with type `ansible` → exit 1 `TOOL_REQUEST_INVALID`; the toolkit accepts 8 types, real `trivy fs --help` lists 9 | Exactly the 9 types of the real v0.76.1 help accepted; compose (and anything else) still refused |
| F-2 | AC-002D-05b (fully analysed, no tool error → successful method), AC-002D-05f (only analysis-degrading messages fail the method) | High (every pip-manifest check, and every `secret` check whose object contains a `requirements.txt`, is a failed method on hosts without Python on the minimal `PATH`) | WARN "[pip] Unable to find python `site-packages` directory. License detection is skipped." (and the informational "Using severities from other vendors for some vulnerabilities. Read https://trivy.dev/docs/v0.76/guide/scanner/vulnerability#severity-selection for details.") → `completed_with_errors`, failed method, although every file was analysed | These two exact messages of v0.76.1 do not degrade coverage (license scanning is out of scope; the severity notice is informational); every other or unknown WARN/ERROR and any other tool version stay analysis-degrading (fail-closed, DAO-001 condition 2) |

Scope: FEATURE-002-D only; no specification change; no change to FEATURE-002-B/002-C behaviour; no network; real
Trivy not run. Write scope: `scripts/src/x_ipe_secure_code/adapters/{trivy.py,trivy_log.py,trivy_run.py}`, Guard
`references/guard-records.md` (type list), new test file, opt-in test-double additions, this report, design
Implementation Evidence note.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 trustworthy dependency/configuration/secret evidence | Spec G-02 (EPIC-001 G-02, FR-16, FR-18) | Developer, upstream agent | A valid override of a type the verified tool supports is accepted and reaches the tool | Restores the 03d type list to the verified version's list (F-1) | Compose stays refused; no new type beyond the real help; pinned to v0.76.1 | US-02 / AC-002D-03d / Integration | `ansible` override refused `TOOL_REQUEST_INVALID` | RED→GREEN `test_config_types_are_exactly_the_v0761_help_list`, `test_ansible_override_accepted_and_reaches_the_tool`; guards `test_compose_and_non_listed_types_still_refused` ×4; existing 03d tests unchanged | not measured (real-binary `ansible` execution is for the acceptance rerun, DAO-001 condition 1) |
| G-02 honest failure, no false pass | Spec G-02; design log classification | Developer, upstream agent | Fully analysed check with no tool error → successful method; analysis-degrading messages still fail it | Exact, version-pinned allow-list of the two observed non-degrading WARNs (F-2) | No message classes or substrings; WARN level only; any other version → no allow-list; findings/messages still recorded | US-06 / AC-002D-05b, 05f / Integration | pip `requirements.txt` with the license WARN → failed method | RED→GREEN `test_observed_warnings_on_fully_analysed_check_succeed`, parser allow-list tests; guards: unlisted WARN, near-miss texts, ERROR level, other version → degrading; existing 05f tests unchanged | not measured |

## Reproduction

- **F-1 (acceptance):** container, `secure-code guard tool` with check F7 `{"scanners": ["misconfig"], "targets":
  ["WebGoat/Dockerfile_desktop"], "config_types": [{"path": "WebGoat/Dockerfile_desktop", "type": "ansible"}]}` → exit 1
  `TOOL_REQUEST_INVALID`; FF-01 `acceptance/tool-level/ff-help-tf.jsonl` (SHA-256 `ca18e1cf…`): `help-fs`/`help-config`
  `misconfig_scanners_default` = `azure-arm, cloudformation, dockerfile, helm, kubernetes, terraform,
  terraformplan-json, terraformplan-snapshot, ansible`.
- **F-1 (local, unfixed `trivy.py` `0eef3797…`):** `test_ansible_override_accepted_and_reaches_the_tool` → `guard tool:
  REFUSED`; `test_config_types_are_exactly_the_v0761_help_list` → set without `ansible`.
- **F-2 (acceptance):** `fixtures/req/requirements.txt` = `six==1.17.0`, check C8 `vuln`+`secret` → exit 0, file analysed
  by both, only the license WARN → `completed_with_errors`, `method_status: failed` (`acceptance/evidence-container-linux.jsonl`
  `6fe87590…`). Raw log line recorded in `tool-validation/results-linux-aarch64.jsonl` (`00f43284…`):
  `WARN\t[pip] Unable to find python \`site-packages\` directory. License detection is skipped.\terr="unable to find path to Python executable"`.
  The vendor-severity WARN text is taken from the acceptance gaps (C20, `go.mod`/`redis:6-alpine`).
- **F-2 (local, unfixed `trivy_log.py` `646eb8c8…`, `trivy_run.py` `daeb462c…`):** fake trivy emitting both observed
  WARNs on a fully analysed `requirements.txt` → `test_observed_warnings_on_fully_analysed_check_succeed` fails with
  status `completed_with_errors`.

Commands (hygiene as for TASK-057): `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p
no:cacheprovider -o addopts="" -q --basetemp=<session>/files/impl-002d/bt-<name> tests/guard/test_trivy_bugfix_task059.py`.

## Root Cause

- **F-1 — implementation of a provisional value:** `adapters/trivy.py` `CONFIG_TYPES` was the provisional 8-type list
  (comment "Provisional until the mandatory real-binary gate compares it with `trivy fs --help`"; Implementation
  Evidence deviation (d)); the tool-level validation had recorded option names only, not the default list.
  `adapters/trivy_request._config_types` refuses any type outside `CONFIG_TYPES`. `guard-records.md` documented the same
  8 types. Callers: only `trivy_request` (validation) and the real gate test; `--file-patterns` argv uses the type as given.
- **F-2 — design rule too broad for observed v0.76.1 behaviour:** `adapters/trivy_log.LogParser._line` classified every
  WARN/ERROR not containing one of three benign substrings as `degrading` (design: "every other WARN/ERROR");
  `trivy_run._process` turns any degrading message into `completed_with_errors` and a gap → failed method. The pip
  analyzer emits the license WARN whenever no Python is on the toolkit's minimal `PATH=/bin:/usr/bin` (by design of
  the minimal environment), and the vendor-severity notice is informational; neither reduces analysis coverage, which
  is accounted separately from the tool's own per-file statements. Design flaw (classification), not a coverage gap.

## Scope and Conflicts

Inspected: `trivy.py` (`CONFIG_TYPES`, `scan_argv`), `trivy_request.py`, `trivy_log.py` (`BENIGN`, `_line`, `_message`),
`trivy_run._process` (status/gaps), `trivy_provision` (`LogParser()` for provisioning — unchanged, no allow-list there),
`trivy_account` (coverage from tool statements — unchanged), tests `test_guard_trivy.py` 03d/05f/05h,
`test_trivy_units.py::test_config_types_pinned_without_compose` (asserts a subset and no compose; still true — **not
edited**), `test_trivy_real.py::test_config_types_equal_the_help_list` (gate; expects exactly the help list — now
consistent; deselected, not run).

| Consequence | Classification | Disposition |
| --- | --- | --- |
| `ansible` overrides accepted and passed as `--file-patterns ansible:<path>` | expected (AC-002D-03d restoration) | applied; compose/other types still refused |
| Two exact WARN texts no longer fail a check for v0.76.1 | expected (AC-002D-05b/05f restoration; DAO-001 condition 2) | applied; messages still recorded in the process messages |
| Any other WARN/ERROR, the same text as ERROR, a near-miss text, or another tool version | must stay degrading | preserved and tested (fail-closed) |
| Design text "every other WARN/ERROR" (technical design, log classification) and "provisional" `CONFIG_TYPES` | documentation lag | reported to the owner; this task may edit only the Implementation Evidence section |
| FEATURE-002-B/002-C | not touched | no change |

No unexpected conflict. Existing tests asserting the provisional 8-type list itself: **none** (no before/after edits needed).

## Fix and Design Impact

- `trivy.py`: `CONFIG_TYPES` = the 9 help types (appended `ansible`), comment cites FF-01 / `ff-help-tf.jsonl` and pins
  to v0.76.1. Validation message ("… (compose is not supported)") unchanged.
- `trivy_log.py`: `BENIGN_EXACT = {"0.76.1": frozenset({<pip license text>, <vendor severity text>})}`;
  `LogParser(version=None)` selects the set for the running version (unknown/None → empty); a message is benign only
  if it is a WARN whose message equals an entry exactly (existing substring list `BENIGN` unchanged).
- `trivy_run.py`: `LogParser(version=<registered build version>)`.
- `guard-records.md`: type list now includes `ansible` (the v0.76.1 `--misconfig-scanners` list).
- Alternatives rejected: substring/class matching (DAO-001: "do not widen to message classes"); adding Python to `PATH`
  (changes the minimal environment and would enable license detection, out of scope).
- Design impact: no interface/schema/workflow change (one constructor keyword with default). The design's
  classification sentence and provisional-list remark lag the code; recorded in the Implementation Evidence note for the
  owner.

## Mini AAA and Actual Routing

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| 03d list | toolkit constants | read `CONFIG_TYPES` | equals the 9 help types | pytest unit | RED (no `ansible`) → GREEN |
| 03d ansible | `deploy/site.yml` target, provisioned components | `guard tool` misconfig with `ansible` override | accepted; argv `--file-patterns ansible:deploy/site\.yml`; run records the override | pytest integration (fake trivy) | RED (REFUSED) → GREEN |
| 03d compose | Dockerfile target | override `compose`/`docker-compose`/`Ansible`/`ansible-playbook` | `TOOL_REQUEST_INVALID` naming compose; nothing recorded; tool not run | pytest integration | guard: pass before and after |
| 05b allowed | `requirements.txt`, fake emits both observed WARNs | `guard tool` vuln+secret | status `completed`; method `ok`; message still recorded | pytest integration | RED (`completed_with_errors`) → GREEN |
| 05b/05f parser | WARN lines | `LogParser(version="0.76.1")` | both observed texts `benign` | pytest unit | RED (constructor keyword absent — interface, not behaviour) → GREEN |
| 05f unlisted | as above + extra WARN (other text / near-miss) | `guard tool` | `completed_with_errors`; failed method; gap names the WARN | pytest integration | guard: pass before and after |
| 05f version | 0.77.0 binary registered | `guard tool` with both observed WARNs | failed method; gap names the license WARN | pytest integration | guard: pass before and after |
| 05f parser fail-closed | near-miss texts, ERROR level, other/none version, npm text | `LogParser(version)` | `degrading` | pytest unit | RED (keyword absent) → GREEN |

Routing: `x-ipe-docs/config/tools.json` `stages.feedback.bug_fix` enables `x-ipe-tool-implementation-python`; it was **not
invoked as a separate tool** (owner constraint: no subagents); its Python/pytest practices were applied directly. No
synthetic feature context, app action or tag was created.

## Verification

- **RED (unfixed sources above):** `tests/guard/test_trivy_bugfix_task059.py` → **12 failed, 7 passed**: behavioural
  failures 3 (F-1 list, F-1 `ansible` refused, F-2 fully analysed check `completed_with_errors`); 9 parser unit tests
  failed on the missing `version` keyword (interface absence, not counted as behavioural reproduction); 7 passing are
  fail-closed/compose guards that must hold before and after.
- **GREEN:** same file **19 passed** (unchanged assertions); `tests/guard/test_guard_skill.py` passes.
- **Full suite:** 1796 passed, 3 skipped, 23 deselected — twice (325 s, 334 s); `ruff check --no-cache src tests` all
  passed (twice); new/changed modules `ruff format`-clean; `tests/test_module_size.py` passes (`trivy.py` 367,
  `trivy_log.py` 223, `trivy_run.py` 502 lines).
- **Existing tests:** byte-identical (`test_guard_trivy.py` `4eefabcb…`, `test_trivy_provision.py` `64065bf9…`,
  `test_trivy_units.py` `2290b72b…`, `test_trivy_review_fixes.py` `4c206b29…`); test double changed additively only.
- **Hygiene:** only new path in `ai-secure-code-toolkit/` is the new test file; no caches, logs, links or FIFOs; no
  board, Git, network, `.github/skills` or memory change; real Trivy not run.
- **Not executed here:** real-binary `ansible` override and real WARN classification (acceptance rerun, DAO-001
  condition 1/4); independent review of this fix (owner, DAO-001 condition 4) — **pending**.

| File | SHA-256 (after fix) |
| --- | --- |
| `scripts/src/x_ipe_secure_code/adapters/trivy.py` | `b06073d86f87d321925d8d672d1337cf80b24ddd379510bc075c7965a78d7e09` |
| `scripts/src/x_ipe_secure_code/adapters/trivy_log.py` | `44ff4d1e3fb1077f37999b4fd47f2e88e01871f7fbc2233e7f4c4f7737910b16` |
| `scripts/src/x_ipe_secure_code/adapters/trivy_run.py` | `7b1072c73a9d3f11797b76172fceecc0e3c6697dd3f21c6bd4dc6c6946636192` |
| `scripts/tests/guard/test_trivy_bugfix_task059.py` (new) | `2374100f863b221f637498e9cb1de9d2ba721e51381ab22b9d6d43e93b46f7b0` |
| `scripts/tests/adapters/fake_trivy.py` (additive) | `1d1f0fcea229fef09f95233c3e57190e91611c24e348b81d1b5062dd620d5cf5` |
| `x-ipe-secure-code-toolkit-guard/references/guard-records.md` | `868f2da821fd93e54060ea0c707fe0cd84203c4a332d103f865456cf36f33f85` |

Engineering delivery: verified with the test double (fake trivy built from recorded real outputs). Stakeholder outcome:
not measured.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed  # engineering fix; acceptance rerun and independent review pending with the owner
  next_task_based_skill: null
  process_preference:
    interaction_mode: "dao-represent-human-to-interact"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/trivy.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/trivy_log.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/trivy_run.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/guard/test_trivy_bugfix_task059.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/bug-report-TASK-059.md"
  bug_severity: "High"
  root_cause: "F-1: provisional 8-type CONFIG_TYPES (no ansible) instead of the verified v0.76.1 help list; F-2: every WARN not matching a benign substring classified analysis-degrading, including two observed v0.76.1 WARNs that do not reduce coverage"
  conflicts_found: []
```

One lifecycle owner (Sage) handles review, acceptance rerun, board and routing; this child wrote no board/Git/app state.

## Owner Addendum (2026-10-24, appended by Sage)

- Independent review of this fix (DAO-001 condition 4): **PASS-WITH-NITS** at toolkit revision f18423e (git-archive copy). F-1 (9 v0.76.1 config types incl. `ansible`) and F-2 (version-keyed exact benign WARN allow-list, WARN only, provisioning unaffected) fixed at the root; no regression; targeted tests 27 passed, four Trivy test files 220 passed; RED claim assessed from test content. Nits were documentation-only (design log-regex `Z` vs accepted offsets; out-of-date "design text lag" note) and are corrected in the design erratum of 2026-10-24.
- The acceptance rerun and the B17 run (46/46 ACs, commit c567207, DAO-006) supersede the "pending" notes above.
