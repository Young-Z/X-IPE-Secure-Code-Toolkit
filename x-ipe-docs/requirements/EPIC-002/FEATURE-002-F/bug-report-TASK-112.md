# Bug Report — TASK-112: a full results area is reported as "tmp limit reached" (D-1, AC-002F-04l; `guard/helpers/execute_io` ENOSPC hint)

## Reported Behavior

- **Source / authority:** FEATURE-002-F acceptance TASK-111, defect **D-1** (`acceptance-test-cases.md` "Failures / Blockers / Disclosures", TC-F-27; doc `e58c0bc4…` before this task's append). Representative **DAO-007** (`x-ipe-docs/dao/26-10-23/decisions_made_feature_acceptance_test.md`): option (a) bug fix — RED first on the TC-F-27 scenario; classify `ENOSPC` by the failing path/mount (results area → results-size limit; `/tmp` → tmp limit); existing limit names only, no new output kind; re-run TC-F-27, TC-F-21 and TC-F-51 on a new frozen copy plus the full suite; append to the acceptance doc without editing the original Fail; independent review by the owner. Option (b) (accept the wrong name) was rejected by DAO-007.
- **Task:** TASK-112 (in_progress), lifecycle owner Sage; this worker: Bug Fix child, free-mode (no workflow action), standalone, `next_task_based_skill: null`. No board, Git, memory, `.github/skills` writes; no subagents; no successors.
- **Bug — Low/minor (as classified by acceptance).** Actual (unfixed): a helper writing 3 MiB into `/results/result.json` (results area 2 MiB) is stopped by `ENOSPC`, the method fails and nothing over the limit is kept (correct), but the run reports `limit: tmp`, reason "tmp limit reached". Expected (AC-002F-04l, spec v1.3.3 `fcf0f92a…` L117: "the method is failed naming the limit"): the results-size limit is named.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A limit hit by a helper is reported by its name (G-02.4) | spec AC-002F-04l; design §9.3 step 5 (L680: "`/tmp` exhaustion … `ENOSPC` on `/tmp`"), §2 L250 limit enum (`time`, `memory`, `output`, `results`, `pids`, `open_files`, `tmp`), §9.4 L-08 "area ≤ 2 MiB (16 inodes)" | Reviewer, calling agent, developer | A full results area → failed method naming the results limit; a full `/tmp` → still `tmp` | `ENOSPC` attributed by measuring the results mount after the stop | Existing limit name `results` only; no new output field/kind; nothing beyond the limit kept; failed method unchanged; no launcher/payload change | AC-002F-04l (Integration · conformance); TC-F-27 | 3 MiB write to `/results/result.json` | Fake-runtime RED → GREEN; real runtime TC-F-27 Fail → Pass | Not measured |
| Nothing beyond a limit is stored (G-02.4) | AC-002F-04l "no oversized output is retained", AC-002F-04k | Reviewer | The measured area is never kept, extracted or parsed as a result | Same holder `cp` tar stream, parsed in memory for sizes only | `result_sha256` stays `null`; no `run-*-result.json` | AC-002F-04l/04k | idem | asserted in the new test; TC-F-27 "no raw result file" | Not measured |
| `/tmp` exhaustion keeps its name (preservation) | design §9.3 step 5 | idem | `ENOSPC` with room left in the results area → `tmp`, "tmp limit reached" | unchanged branch | — | AC-002F-04l | `ENOSPC` stderr, empty results area | passed before and after | Not measured |

## Reproduction

Environment: macOS 26 arm64 host, CPython from the toolkit `scripts/.venv` (uv offline), fake runtime CLI `tests/helpers/fake_runtime.py` for orchestration; real Docker Desktop 29.7.2 (LinuxKit, aarch64) with the local `python:3.12-slim` (`a6e34c59…`) for the real checks. Unfixed sources at HEAD `41bdbde`: `execute_io.py` `b8e3948b…`, `results.py` `786822ee…`.

1. **Acceptance (original):** TC-F-27 case "04l/04k results over L-08" (`acceptance/blackbox.py` `RESULT_CASES_B`: `doc['notes'] = 'n' * (3 * 1024 * 1024)` then `json.dump` into `/results/result.json`) → `failed`, `limit: tmp`, "tmp limit reached"; stderr `OSError: [Errno 28] No space left on device` (243 bytes kept as diagnostics).
2. **Real-runtime probe (this task, session `bugfix-112/`):** a tmpfs volume with the toolkit's exact `VOLUME_OPTS` (`size=2097152,nr_inodes=16,uid=65534,…`), `--network none`, user 65534: `json.dump` of 3 MiB → `ENOSPC`, file stops at exactly **2,097,152 bytes**, `statvfs` free 0; inode fill → `ENOSPC` after 16 entries (root + 15 files), and an `open` error names its path. The volume was removed. The traceback of a *write* failure names no path, so stderr alone cannot tell the mounts apart.
3. **Fake-runtime RED** (below): the same failure observed through the orchestration (`'tmp' == 'results'`).

## Root Cause

- `execute_io._classify` (HEAD L226–239): for a non-zero exit without OOM/timeout it calls `_hint(out.stderr)`; `ERRNO_HINTS` (L25–29) maps the text `No space left on device`/`ENOSPC` unconditionally to `tmp`. The failing mount is never consulted, although design §9.3 limits the `tmp` name to "`ENOSPC` on `/tmp`". **Implementation error** (design intent correct, code over-generalised).
- Trigger: any helper that fills the results area (the only write a statically accepted helper may perform, `static.py` `open_form`/`results_handle`) — so in practice every helper `ENOSPC` was misnamed.
- Only observable of the failing mount after the stop: the results volume, still mounted read-only by the holder (the run container's `/tmp` tmpfs disappears when it stops). Runs without a results volume (version/compile probes) can only fill `/tmp`.
- Callers: `execute.py` target/sample/compile paths read `out.limit`/`out.reason` (L170, L436, L458, L556); conformance P-12/P-13 judge their own probe answers (`error == "ENOSPC"`), not `out.limit`; P-14/P-15/P-17 use `time`/`output` only.

## Scope and Conflicts

- **Affected:** only runs whose stderr carries the `ENOSPC` hint **and** that have a results volume (sample and target runs, conformance probe containers). Collection itself is unchanged: a run with any limit is still never collected as a result.
- **Unaffected (verified):** `memory`/`time`/`output`/`pids`/`open_files` naming; version/compile probes (no results volume → `tmp` as before); `ENOSPC` with room left in the area → `tmp` unchanged (test); clean runs (no extra runtime call); cleanup/sweep; launcher payload and its pinned digest; P-12/P-13 conformance (real TC-F-21 20/20, TC-F-51 4/4).
- **One extra runtime call** (`cp <holder>:/results -`) only in the `ENOSPC` case, before the existing removal; same argv form as normal collection (never follows links; cap `TAR_CAP`); `--network none`/no-pull invariants unaffected (real log: 0 forbidden calls).
- **Conflict analysis (detector over `execute_io`, `results`, `execute`, `conformance`, `canonical`, `static`, design §2/§9/§10, spec 04k/04l; validator against the D-1 report and DAO-007):**
  - Expected: `limit: results` + reason "results area limit (L-08)" for a full area — the restoration requested.
  - Expected, disclosed (DEC-2): an `ENOSPC` hint whose results area cannot be read now names **no** limit ("script error under enforced limits (exit N)") instead of guessing `tmp`; this is design §9.3 step 5's "otherwise" branch. Not reachable in the fake/real runs here except by injected `cp` failure (unit test).
  - No unexpected conflict; no AC/scope/design change. `conflicts_found: []`.
- Byte-pin tests: `tests/helpers/test_helper_boundary.py` pins delivered pre-002-F files only; `execute_io.py`/`results.py` are 002-F-owned (listed by name, not bytes, in `tests/drafting/drafthelp.py` `NEW_PAYLOAD`). Boundary test passed in the helpers run and the full suite; no pin edited.

## Fix and Design Impact

- `guard/helpers/execute_io.py` (+13 lines): after `_classify(out)`, `if volume and out.limit == "tmp": _enospc_mount(rt, holder, out)`. `_enospc_mount` reads `cp <holder>:/results -` (cap `results.TAR_CAP`), asks `results.area_full`; `True` → `limit "results"`, reason **"results area limit (L-08)"**; `None` (cp failed/oversized/unreadable) → no limit, "script error under enforced limits (exit N)"; `False` → `tmp` unchanged.
- `guard/helpers/results.py` (+16 lines): `AREA_SLACK = 64 KiB`; `area_full(data)` opens the tar stream in memory (never extracts), returns `len(members) >= L08_INODES or regular bytes > L08_AREA - AREA_SLACK`, `None` when missing/unreadable. Slack covers tmpfs page rounding of up to 15 files (4 KiB pages); the real probe filled exactly 2 MiB.
- No change to: output schema/kinds, existing limit names (`results` already in design §2), the launcher, conformance probes, collection rules (04k), CLI/skill text.
- Design impact: none required — the fix implements §9.3 step 5 as written. **Optional clarification for the owner (DEC-3):** §9.3 step 5 could add "`ENOSPC` with a full results area → `results area limit (L-08)`; unreadable area → script error". Not edited by this child.

## Mini AAA and Actual Routing

New tests only (no existing assertion changed): `tests/helpers/test_helper_execute.py` +4, `tests/helpers/test_helper_results.py` +1 parametrized (8 ids).

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| TC-F-27 twin: full results area by bytes (04l) | fake runtime: target exits 1, stderr `OSError: [Errno 28] No space left on device`, results area = `result.json` of 2 MiB | `helper run` | outcome `failed`; `limit == "results"`; "L-08" in reason; `result_sha256` null; no `*-result.json` stored | Python CLI orchestration, pytest | red: `'tmp' == 'results'`; green: passed |
| Full results area by inodes (04l) | 16 entries (dir + 15 files), same stderr | idem | failed; `limit == "results"` | idem | red: `'tmp' == 'results'`; green: passed |
| `/tmp` full, results area has room (preservation) | empty area, same stderr | idem | failed; `limit == "tmp"`; reason "tmp limit reached" | idem | passed before and after |
| Unreadable results area (DEC-2) | stub runtime whose `cp` exits 1; outcome pre-classified `tmp` | `execute_io._enospc_mount` | `limit is None`; "script error under enforced limits (exit 1)" | Python unit | red: AttributeError (new seam; not counted as behavioural red); green: passed |
| `area_full` (04l/04k) | none / empty / not-tar / dir-only / small result / 2 MiB file / 16 entries / 15 entries | `results.area_full` | `None`,`None`,`None`,`False`,`False`,`True`,`True`,`False` | Python unit | red: AttributeError (new function); green: 8 passed |

Routing: the enabled Python fix route executed directly by this worker: red → minimal fix → green → lint → helpers suite → full suite → real-runtime re-run on a frozen copy.

## Verification

Logs in the session folder `<SESSION>/bugfix-112/` unless noted; commands from `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts` with `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<SESSION>/bugfix-112/tmp-<name>`.

| Step | Command / scope | Result | Log |
| --- | --- | --- | --- |
| Real-runtime probe (unfixed semantics) | tmpfs volume with `VOLUME_OPTS`, 3 MiB `json.dump`, inode fill | ENOSPC at 2,097,152 bytes; 16 entries | progress.md Step 2 |
| RED round 1 (unfixed, first test `4599d0e6…`) | `-k enospc` | **2 failed** (`'tmp' == 'results'`), 1 passed | `red.log`, `red-hashes.txt` |
| RED final (sources reverted to HEAD bytes `b8e3948b…`/`786822ee…`; final tests `9aead73f…`/`580c05fb…`; 17:04:42Z) | `test_helper_execute.py test_helper_results.py -k "enospc or area_full"` | **11 failed, 1 passed**, exit 1 — behavioural: byte-full and inode-full `limit` `tmp` ≠ `results`; 9 AttributeError (new seams); tmp branch passed | `red-final.log`, `red-final.hashes` |
| GREEN (fixed `9b427c83…`/`17d84545…`, same tests, 17:05:08Z) | same | **12 passed**, exit 0 | `green-final.log`, `green-final.hashes` |
| Lint | `ruff check src/ tests/`; `ruff format --check` on the 4 touched files | All checks passed; 4 files formatted (3 pre-existing unformatted files elsewhere untouched) | — |
| Helpers suite | `tests/helpers` (17:05:53Z–17:23:47Z) | **361 passed, 4 skipped** (opt-in real tests), exit 0 — incl. `test_helper_boundary.py` | `helpers-suite.log` |
| Full suite (one run, 17:24Z–01:58:09Z; host heavily loaded by fseventsd/Docker, see Honest Limits) | whole suite, `-rfEs` | **3513 passed, 1 failed, 7 skipped, 23 deselected**, exit 1; the only failure = known flaky delivered `tests/drafting/test_draft_cli_approve.py::test_02e_equivalent_to_plain_update_time_normalised` (changelog time-normalised compare). 3513 + 1 = 3514 = baseline 3502 + 12 new; the 7 skips = baseline | `full-suite.log` |
| Flaky file re-run ×3 (isolation) | `tests/drafting/test_draft_cli_approve.py` | 25 passed / 25 passed / **1 failed** (same `test_02e`) 24 passed → pre-existing nondeterminism (DAO code-implementation L241: separate Low task); unrelated to `guard/helpers` | `flaky-rerun.log` |
| Real-runtime re-run, frozen copy `e8a8bc44…` (start = end, 415 files) | `acceptance/run-d1.py` (imports unchanged `blackbox.py`): TC-F-20 prerequisite, TC-F-21, TC-F-27; throwaway trust store via `maint.py`; 02:00:55Z–02:03:31Z | **3/3 Pass**: TC-F-21 11/11 (20/20 probes); TC-F-27 7/7 — results write → `failed`, `limit: results`, "results area limit (L-08)"; 102 creates all `--network none`, 0 forbidden calls, no leftovers | `acceptance/evidence-host-macos-d1.jsonl` (repo) |
| TC-F-51 on the frozen copy (02:03:47Z–02:07:21Z) | `SECURE_CODE_HELPER_REAL=1 … tests/helpers/test_helper_conformance_real.py` | **4 passed**, exit 0 | `acceptance/evidence-delivered-helpers-real-d1.log` (repo) |
| Docker hygiene | `ps -a`/`volume ls`/`images`/`network ls` before (pre2) and after | identical; only pre-existing difference since 01:0x +08 is `fat-uv-cache-001e` (concurrent worker, untouched); no seed volume mounted | `docker-pre*/post-*.txt` |

Changed / added files:

| File | Lines | SHA-256 before | SHA-256 after |
| --- | --- | --- | --- |
| `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/helpers/execute_io.py` | 276 → 289 | `b8e3948bdbf9bb6bc0395b8b26de283ead99afff13469fca71194313e1a9fe49` | `9b427c83a09ab20bc2773381b586deef9522c8baca9b4c00c279bb5a0df5193f` |
| `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/helpers/results.py` | 197 → 213 | `786822ee7a2e0144818523bc9777da2d552e3074009dec5a312b2ad35df7e42a` | `17d845459e3fe9448f3de8b48117e0d830fc00868862aca4f321176bb572c06e` |
| `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/helpers/test_helper_execute.py` | 305 → 357 | `418ead13216eac1018804a2e7de309443072836b0f513c901a14b164a15d5758` | `9aead73fdc5c72168d33d6b4ff458d6f12754a4a28c821d82bbccaa4f3240deb` |
| `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/helpers/test_helper_results.py` | 256 → 275 | `979b10dd0ed3f50821d222bf07aaba6f459e1f6edc2af0aad82fe7f6609165ce` | `580c05fb7ad9ab89df6f002ea51fd54053ba2f7ebb09fbec5bf1189de452fb70` |
| `x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance-test-cases.md` (append-only, 19 lines) | 300 → 319 | `e58c0bc44a75e5d1bcaaf5da6bb45c46414c1f83d68295a63f78ac9854824486` | `a435ae1030a544f08a998161b585864ba4a3f32285f1f085fb821d57dd8e388d` |
| `…/FEATURE-002-F/acceptance/run-d1.py` (new driver) | 44 | — | `43456da26f33b626b03a1b648044af42001d77ff6ddc0577e206423548a50391` |
| `…/FEATURE-002-F/acceptance/evidence-host-macos-d1.jsonl` (new) | 4 | — | `cb3f8ef840c5784d332aa9239ad628aebf1c016944817b9a97317f51fa91d927` |
| `…/FEATURE-002-F/acceptance/evidence-host-macos-d1.stderr` (new, empty) | 0 | — | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `…/FEATURE-002-F/acceptance/evidence-host-docker-calls-d1.jsonl` (new) | 1050 | — | `fb1b91cd60bafdfcb609d7b6c82278262796cebcad146569b756c48c635ac5a9` |
| `…/FEATURE-002-F/acceptance/evidence-delivered-helpers-real-d1.log` (new) | 255 | — | `2c42fbf5cbdd8aa0f51d560c91ba6e17bc68433540acc99f6dcee1384f05a754` |

Toolkit file-list hashes after the fix: frozen-copy method (`find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256`, caches/`.venv` excluded) `e8a8bc44e52d49a696f8a5e7363c58a225bd662ca880826dd413cf744ecd15f8` (415 files); TASK-100 method (`./` stripped, `sort -k2`) `80b7bd54b665091d821045fea5346158dfab9e1e8336654b1e3519ad339c3050`. `git diff --stat` of the toolkit: 4 files, 100 insertions, 0 deletions. Spec `fcf0f92a…` and design `9139ed25…` unchanged.

Independent review: **not performed by this child** (owner-run per DAO-007). Engineering delivery: verified by the checks above. Stakeholder outcome: not measured.

## Decisions (for the representative / owner)

- **DEC-1 (name and reason):** existing limit name `results` (design §2 enum); reason text "results area limit (L-08)", in the style of "memory limit (L-06)"/"time limit (L-10)". The `tmp`/`pids`/`open_files` reasons keep "… limit reached". No new field or output kind.
- **DEC-2 (unreadable area):** `ENOSPC` + results area that cannot be read → no limit named, "script error under enforced limits (exit N)" (design §9.3 step 5 "otherwise"), instead of guessing `tmp`. Owner may prefer keeping `tmp` there; only reachable when the holder `cp` fails.
- **DEC-3 (design wording, optional):** add the results-area `ENOSPC` sentence to design §9.3 step 5 / Change Log; not edited here (no behaviour or interface change requires it).
- **DEC-4 (fullness threshold):** 16 entries or regular bytes > 2 MiB − 64 KiB. A `/tmp` `ENOSPC` while the results area happens to be within 64 KiB of full would be named `results` — accepted as the more specific observable (static rules allow only the one results file).

## Honest Limits

- Attribution is by observation of the results mount after the stop, not by the kernel's failing path (a write traceback names none); stderr is helper-controlled, so a helper that fills the area and prints an `ENOSPC` text gets `results` — which is then true of the area. Design §15 honesty on best-effort naming still applies.
- One runtime (Docker Desktop on macOS arm64, 4 KiB pages); other runtimes/page sizes not run. Only TC-F-20/21/27/51 were re-run on the real runtime; the other TCs and the regression runners were not re-run (covered by the unchanged-elsewhere diff and the full suite).
- Seeds for the host run are a byte copy of the original TASK-111 container-made handoff (made by the 73fe2dc toolkit); the container mode was not re-run.
- Full suite: one run, executed under severe host load (fseventsd ~100–250 % CPU from millions of stale temp files plus a busy Docker VM; pytest reported 2680 s, wall ≈ 8.5 h; it sped up after the owner's cleanup ~09:45 +08) — not abandoned, completed with the single known flaky failure, so no second full run was made. The flaky `test_02e` also failed 1 of 3 isolated re-runs; it remains outside this task (separate Low item per DAO).
- The new unit tests for `area_full`/`_enospc_mount` could only fail by `AttributeError` before the fix; the behavioural RED is the two flow tests.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed
  next_task_based_skill: null
  process_preference:
    interaction_mode: "dao-represent-human-to-interact"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/helpers/execute_io.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/helpers/results.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/helpers/test_helper_execute.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/helpers/test_helper_results.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance-test-cases.md"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance/run-d1.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance/evidence-host-macos-d1.jsonl"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance/evidence-host-docker-calls-d1.jsonl"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance/evidence-delivered-helpers-real-d1.log"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/bug-report-TASK-112.md"
  bug_severity: "Low"
  root_cause: "execute_io.ERRNO_HINTS mapped every ENOSPC in helper stderr to the tmp limit without consulting the failing mount, although design §9.3 names tmp only for ENOSPC on /tmp; a full results area (L-08) was therefore reported as 'tmp limit reached'."
  conflicts_found: []
```

`interaction_mode` is as supplied by the owner's delegation (DAO-represented, per DAO-007 "delegation continues"); the owner corrects it if different. One lifecycle owner (Sage) handles independent review, completion and routing; this child made no board, Git, memory or app writes and ran no successor.

## Owner Addendum (2026-10-25, appended by Sage)

- Independent review: **PASS** (no findings).
- Representative DAO-006 (bug fix): DEC-1, DEC-2, DEC-4 approved (DEC-2 and DEC-4 recorded as honest limits for the 002-F closing report); DEC-3 applied as design §9.3 step 5 erratum + Design Change Log row.
- AC-002F-04l: Pass on the "D-1 Re-run" evidence; FEATURE-002-F acceptance 74/74 active ACs (05f N/A per B12 = A).
