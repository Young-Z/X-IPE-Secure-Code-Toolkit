# Feature Closing Report

> Feature: FEATURE-001-F — Presets & Tags (EPIC-001) · specification v1.5 · board status at closing start: Tested (read-only)
> Task: TASK-071 (Feature Closing), lifecycle owner Sage, worker · Date: 2026-10-23 · free mode, workflow N/A · interaction mode `dao-represent-human-to-interact` (no human waited for; decisions listed at the end)
> Closure scope: engineering delivery only. No commit, push, PR or release was performed: there is no explicit human authority for them, and the workspace is not a Git repository.
> Delivery: **verified engineering delivery** at toolkit file list `ebe3ce44…`, specification `e00d6721…`, design v1.3 `353b0f30…` (first 585 lines). Outcome: **not measured**.

## Inputs Re-verified at Closing (SHA-256)

| Input | Expected | At closing | Match |
| --- | --- | --- | --- |
| [specification.md](specification.md) v1.5 | `e00d67215106d60aadeb07fc1f669ba354be593c3e7feb0171b0ee386805d2a9` | same | yes |
| [technical-design.md](technical-design.md) v1.3, first 585 lines (Parts 1 and 2) | `353b0f3053328b4380ffaef341bde63015b9d1deed22170699f6fd8fb1c4ad2b` | same | yes |
| technical-design.md, whole file (incl. appended Implementation Evidence, DAO-002 update and code-review fixes) | `d2337bf0…` (as cited by the acceptance report) | `d2337bf0013969be058c01160bb2eb40c7ed294de2d8a25b3119d7273e9e9d9a` | yes |
| [acceptance-test-report.md](acceptance/acceptance-test-report.md) | `87c08f43…` | `87c08f43864f50cbca5952adafd8349789cceee4cc119c56b98cd84b3a13d2a1` | yes |
| Toolkit file list (222 files; method below) | `ebe3ce4491f1248bb07f7fcf6ac00fadfd979407c7bfd7fb10baec37ee7bb521` | same, before and after the closing spot re-run | yes |
| requirement-details.md (source of G-03, FR-12, AC-09 and the FEATURE-001-F section) | `1747efe6…` (spec source evidence) | `1747efe61b9c5cf1…` | yes |
| DAO records `decisions_made_technical_design.md` (DAO-006…009) / `decisions_made_code_implementation.md` (DAO-002) | `03828e43…` / `d7708266…` | same | yes |
| `decisions_made_feature_acceptance_test.md` (DAO-002, read in full) | — | `8d5d648e…` | read |

Toolkit method: `cd ai-secure-code-toolkit; find . -type f` excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache` and `.coverage`; `-exec shasum -a 256 {} +`; strip `./`; `LC_ALL=C sort -k2`; `shasum -a 256`.

Delivered product files also match the design's evidence table and the acceptance report: `catalog.py 79e0c69e`, `presets.py 50cf6cda`, `tags.py 34b5b8d9`, `preset_scope.py aa9b0bbb`, `impact.py 906c4562`, `exit.py 165b7865`, `cli.py a1e8d924`, `SKILL.md 980c9ff6`, `policy-selection.md 6f9c29d2`, `cli-contract.md 75f3c146`, `presets-and-tags.md 6d4df848`, `tests/carriers/carhelp.py ed1fc988`, `tests/knowledge/test_exit_preview.py 49c61bce`. Acceptance evidence files match the hashes the report cites (`blackbox.py 3fe65523`, `run.sh 59e185bc`, `evidence-container-linux.jsonl a87e978b`, `evidence-host-macos.jsonl 5c5c1350`, `evidence-unit-integration.log e7359dd7`, `rerun-001D-* f70eabc4 / 1c1171cd`, eight regression logs).

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Delivery Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-12 (P-03…P-07, P-09, P-11, T-01…T-04); FR-07 / EPIC AC-09 (Preset/tag impact part); requirement-details FEATURE-001-F preliminary AC-001F-01…04 | Developer, Maintainer, upstream agent | Reusable, explicit rule scopes without hidden drift; removing or renaming knowledge never silently breaks or rewrites Presets and tags | AC-001F-01a…08c, 09a, 09d…09g pass (real CLI, offline Linux container + macOS host) | not measured |
| G-03 (default-Preset branch) | EPIC-001 FR-10 / P-13, deferred to 001-F by FEATURE-001-C (DAO-003) | Developer, upstream agent | With no clues a known default scope is proposed before Apply All and adopted only on confirmation | AC-001F-04e, 04g pass | not measured |
| G-05 (enabling) | EPIC-001 G-05; P-02, U-04, U-05, K-03; 001-C BR-09 | Owner | Scope maintenance never grants knowledge-editing rights; tag writes least-privilege | AC-001F-07a…07d pass | not measured |

**Source traceability.**
- The four preliminary ACs map to spec rows as the spec states: AC-001F-01 → 01a…01f; AC-001F-02 → 03a…03e; AC-001F-03 → 05c, 05d; AC-001F-04 → 06a…06h.
- EPIC-001 AC-09's Phase-2 clause ("Preset and tag impact detection is verified with non-empty fixtures when FR-12 lands") is met by TC-F-10: two referencing and one non-referencing Preset, and the same for tags, across all four exit actions.

**Qualitative scenario.** The spec's planned scenario was exercised end to end as delivery checks (TC-F-01, 05, 06, 09, 10, plus `test_outcome_scenario_end_to_end`):
1. Save a Preset from clues.
2. Change tag membership.
3. Reuse the Preset.
4. Recompute on request, with a diff.
5. Rename a referenced rule.

The Preset stayed unchanged until a confirmed update, the impact was listed first, and the reference was reported broken. Use by real Developers, Maintainers or agents: **not measured**.

## Goal → AC → Evidence

Every row: toolkit `ebe3ce44…`, spec `e00d6721…`. Per-clause evidence (check counts per row) is in the [acceptance report § AC → Evidence](acceptance/acceptance-test-report.md); this table reuses it, and the closing re-check confirmed its inputs are unchanged.

| Goal | Spec AC group (all IDs) | Type (spec) | Acceptance TCs (C = Linux container, H = macOS host) | Delivery |
| --- | --- | --- | --- | --- |
| G-03 | 01 Preset content and read safety: 01a, 01b, 01c, 01d, 01e, 01f, 01g | Integration | TC-F-01, 02, 03, 04, 10, 17, 18 | Pass (7/7) |
| G-03 | 02 Save-as-Preset and maintenance: 02a, 02b, 02c, 02d, 02e, 02f, 02g, 02h, 02i, 02j, 02k | Integration; 02f, 02g Unit | TC-F-01, 02, 03, 05, 07, 09, 12, 13, 17, 18 (02a structured review); unit tests in the passing suite | Pass (11/11) |
| G-03 | 03 Query intent, recompute on request: 03a, 03b, 03c, 03d, 03e, 03f, 03g | Integration; 03b Unit | TC-F-01, 04, 05, 18 (03g structured review); unit AST test in the suite | Pass (7/7) |
| G-03 / default branch | 04 Preset as 001-C scope input: 04a, 04b, 04c, 04d, 04e, 04f, 04g, 04i, 04j, 04k | Integration | TC-F-06, 07, 08, 14, 17, 18 (04d structured review) | Pass (10/10) |
| G-03 | 04h | — | none, by spec | **Superseded by DAO-005**, no test |
| G-03 | 05 Tags: 05a, 05b, 05c, 05d, 05e, 05f | Integration | TC-F-09, 18 | Pass (6/6). 05a's Reference-source membership is deferred to 001-E (skipped unit test); the black-box run shows the `invalid_reference` refusal |
| G-03 (AC-09) | 06 Exit impact providers: 06a, 06b, 06c, 06d, 06e, 06f, 06g, 06h, 06i, 06j | Integration | TC-F-10, 11, 12, 14, 17, 18; 001-D re-runs (§ Superseded) | Pass (10/10) |
| G-05 | 07 Authorization separation: 07a, 07b, 07c, 07d | Integration | TC-F-09, 16 (C, User via moved trust folder), 17 (H, never-authorized User), 18 | Pass (4/4) |
| G-03 | 08 Stored file integrity: 08a, 08b, 08c | Integration; 08b Unit | TC-F-01, 08, 11, 13; unit tests in the suite | Pass (3/3) |
| G-03 | 09 Provenance via unchanged 001-C path: 09a, 09d, 09e, 09f, 09g | Integration | TC-F-06, 14, 15, 18; full suite with byte-identical `tests/policy`, `tests/guard`, `tests/copilot`; 001-C/002-A/003-A black-box regressions | Pass (5/5) |
| G-03 | 09b, 09c | — | none, by spec | **Superseded by DAO-004**, no test |

Totals: **66 AC rows. 63 Pass, 3 Superseded, 0 Fail, 0 Blocked.**

**Runs.**
- Container: 17/17 cases, 276/276 checks; stderr holds only the hash-verified pre-001-F reconstruction log.
- Host: 2/2 cases, 28/28 checks; stderr empty.
- TC-F-18 (structured review) ran in both environments.
- Full Framework suite: 2265 passed, 0 failed, 4 skipped, 23 deselected. `ruff` is clean.

**Agent-behaviour rows** (02a, 03g, 04d, and the agent part of 04f and 05e) are verified by structured review of the skill text, as those ACs specify ("instructions are inspected"), plus the CLI support they rely on. No real agent session was run.

**Closing semantic check.** I parsed every evidence JSONL: no failed check in any 001-F, host or regression file. The only failing checks anywhere are the 7 named AC-001D-02b clauses below.

**Closing spot re-run** (supporting only; it reuses fresh acceptance evidence and is not a second acceptance).
- Ran on the macOS host from `FW/scripts`, with `--basetemp` under the session folder `closing-001f/tmp`: `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" tests/presets tests/knowledge/test_exit_preview.py::test_empty_supported_not_unsupported tests/knowledge/test_exit_skill.py`.
- Result: **220 passed, 1 skipped** (the 001-E-conditional test) in 28 s.
- `secure-code preset --help` and `tag --help` list exactly the documented subcommands.
- Toolkit hash unchanged afterwards; no caches inside `ai-secure-code-toolkit/`.

## Superseded Items (never reported as a plain pass)

| Item | Disposition | Evidence |
| --- | --- | --- |
| AC-001F-04h | Superseded by DAO-005: the delivered proposal digest does not cover clue text. Replaced by 04j/04k | no test, by spec |
| AC-001F-09b, 09c | Superseded by DAO-004: no new `preset` scope mode. Replaced by 09e…09g | no test, by spec |
| 001-D AC-001D-02b clauses: `presets`/`tags` = "not checked in this version" | **superseded per AC-001F-06a/06b — re-run** | `rerun-001D-container-linux.jsonl` `f70eabc4…`: TC-D-05…16 pass. TC-D-01…04: 266/273 checks pass; the 7 failing checks are exactly those clauses (TC-D-01 ×1, TC-D-02 ×3 incl. the compound reactivate check, TC-D-03 ×1, TC-D-04 ×2 incl. text). A diagnostic copy narrowing only those clauses to the Reference cache passes 4/4. 001-D spec v1.1 carries the DAO-007 supersession note |
| 001-D TC-D-15 (AC-001D-06c skill text; SKILL.md L110–111 changed) | **superseded per AC-001F-06a/06b — re-run**; passes | `rerun-001D-host-macos.jsonl` `1c1171cd…`, byte-identical to the original host evidence |
| 001-D `test_exit_preview.py::test_empty_supported_not_unsupported` (the one narrowed loop, DAO-006) and `test_exit_skill.py` | **superseded per AC-001F-06a/06b — re-run**; pass (also in the closing spot re-run) | full suite; closing spot re-run |
| 001-C `test_skill_package_describes_scope_selection` (AC-001C-02e) | re-run (Framework skill text changed under DAO-007 (4)); pass | full suite |

Black-box regressions 001-B, 001-C, 002-A and 003-A (container + host, unchanged runners): all 8 logs are **byte-identical** to the original acceptance evidence.

## FEATURE-003-B Test-Helper Maintenance Note (DAO-002, code implementation)

- **The change.** Delivered 003-B test support `tests/carriers/carhelp.py::ERA_001A_REMOVED` received exactly the 5 FEATURE-001-F payload paths (`c661ff55…` → `ed1fc988…`). It was classified as a test-defect fix by the delegated DAO representative, not the human.
- **Why.** The helper had tied a behavioural baseline to the payload file count.
- **Unchanged.** The fixture, the assertions, every AC and the schema.
- **Standing rule.** Every later payload-adding feature appends its payload paths to `ERA_001A_REMOVED`; the fixture and assertions are never re-recorded for this reason.
- **Where recorded.** The rule is in the [FEATURE-003-B technical design](../../EPIC-003/FEATURE-003-B/technical-design.md) history (L1355) and in the 001-F design's Implementation Evidence.
- **Verification.** The full 003-B suite is part of the 001-F regression set, and it passes at `ebe3ce44…`. 003-B remains parked on B7/B11, unchanged.

## Interpretation O-1 (DAO-002, feature acceptance test — accepted)

"Nothing is written" in the 001-F refusal ACs (01b, 01f, 02f, 02g) and in the default-Preset branch (04e/04g) means no Preset or tag file, folder, temp or history file, and no other project change.

- **Excluded:** first-use creation of the existing, delivered knowledge lock file `.x-ipe/private/secure-code/locks/knowledge.lock` and its folder. This is the same lock acquisition as the unchanged 001-C `policy resolve` (TC-F-17 compares both).
- **Consistent with DAO-004 (1):** "no new lock file" means no new lock-file *kind*. So the interpretation also applies to 02h and 02j. Where the lock already exists, refusals are strictly byte-identical (every container case).
- **Status:** an interpretation, not an AC change. Acceptance evidence stays bound to `e00d6721…`.

## Residual Risk O-2 (recorded, not a defect)

- **What.** `preset resolve` keeps the delivered, unchanged 001-C `adoption` text "…then: secure-code scope save --confirmed". Its `next_steps`, the Framework SKILL.md and `references/presets-and-tags.md` direct `secure-code preset scope-save NAME --decisions FILE --confirmed`.
- **Risk.** An agent that follows `adoption` literally gets an **ordinary 001-C clues save without the Preset guarantees** (DAO-006 (1), AC-001F-04i). It does not re-read the Preset under the knowledge lock.
- **Effect.** The adopted references are still exactly those confirmed, and the 001-C digest check still refuses a change of references or rule content.
- **Why not changed.** No v1.5 AC requires it. Changing the field would touch 001-C-owned output (BR-11, 09a).

## Evidence Reuse and Dependency Freshness

| Input / Boundary | At acceptance (TASK-070) | At closing | Disposition |
| --- | --- | --- | --- |
| Toolkit file list (222 files) | `ebe3ce44…` | `ebe3ce44…` | Unchanged → acceptance evidence reused |
| Spec / design (first 585 lines) / whole design | `e00d6721…` / `353b0f30…` / `d2337bf0…` | same | Unchanged |
| Acceptance report and evidence files | `87c08f43…`, hashes as cited | same | Reused; JSONL semantics re-checked |
| Environment | Linux container `fat-uv-git:py312` (Python 3.12.12, uv 0.9.30, `--network none`, offline cache built from current source and hash-verified); macOS host (Python 3.13.3, never-authorized User) | macOS host only for the spot re-run | No product, test or config change since acceptance, so the container evidence stays valid. The container volume used for acceptance was removed and was not rebuilt |

## Review and Documentation Delta

| Reviewer / Method | Scope | Revision / Evidence | Findings / Disposition |
| --- | --- | --- | --- |
| Independent delta re-review of the design (TASK-067) | spec v1.5 + design v1.3 | PASS, no findings, at `e00d6721…` / `353b0f30…` (DAO-009) | Confirmed. The BLK-1 wording erratum is appended to the design history (DAO-009 (5)) |
| Independent code review (TASK-069) | 001-F implementation | PASS-WITH-FIXES | Two findings: Major (deeply nested JSON → `RecursionError`) and Minor ("ask a Maintainer" not first). Both fixed test-first (`review-fix-red.log`, 4 RED → GREEN); full suite 2265/0 at `ebe3ce44…`. **No separate independent re-review of the fix delta is recorded.** It is covered by the black-box acceptance at the final revision (TC-F-08/11 deep nesting, TC-F-16 `ASK_STEP` first) and by the closing self-inspection (`catalog._BAD` and the loader catch `RecursionError`; `tags._authorizer` puts `ASK_STEP` first, deduplicated) |
| Closing self-review (this task; no subagents by instruction) | Framework `SKILL.md`, `references/presets-and-tags.md`, `policy-selection.md`, `cli-contract.md`, toolkit `README.md` against delivered CLI behaviour and the spec | hashes above | No misleading statement found |

**Documentation checked:**
- The SKILL.md "Status of This Skill" names the actual delivered `preset` and `tag` subcommands, which `--help` confirms.
- The no-clues step uses `preset resolve --default` / `preset scope-save default`.
- The "Known limits" section of `presets-and-tags.md` states every honest limit below.
- The toolkit `README.md` lists skills, not features, so no Preset/tag row is expected.

**Documentation delta at closing: none.**
- No x-ipe-docs correction was needed.
- No toolkit doc change is needed.
- The design's Implementation Evidence sections are appended history: the earlier "BLOCKED" and "Status line not changed" text is explicitly superseded by its own DAO-002 update and code-review-fix sections. It was left unedited to keep the bound hashes.

## Honest Limits

- **Tag writes:** Maintainer-only **through the toolkit only** (toolkit-mediated `require_maintainer`). There is no filesystem-level protection (001-A / U-13).
- **Metadata-only drift:** a metadata-only Preset change (summary, query intent, `snapshot_at`) between proposal and save is **not detected** (AC-001F-04k, BR-17). The adopted scope is still exactly what the user confirmed.
- **History:** no Preset/tag history beyond version control. `snapshot_at` is not a history.
- **Provenance clue:** `preset:<slug>@sha256:<digest>` is **information only**: not bound by the proposal digest, not re-checked at save, not tamper-evident. A look-alike user clue is ordinary clue text.
- **Agent behaviour:** the agent-behaviour clauses (02a, 03g, 04d, 04f offer, 05e expansion) were reviewed from the skill text only. No real agent session was run.
- **Windows:** unchecked. Only the Linux container and the macOS host ran; reserved device names are refused by rule, but no Windows path behaviour was executed.
- **Timezone:** the container ran in UTC, so a non-UTC `snapshot_at` offset was not exercised black-box (O-3).
- **Pre-001-F revision:** used for 06e/06j/09a/04e; it is a hash-verified reconstruction, not the historical build artifact.
- **Reference sources:** Reference-source Preset/tag membership waits for FEATURE-001-E.

## Outcome Gaps

| Goal | Delivery | Scenario / Observation | Outcome State |
| --- | --- | --- | --- |
| G-03 | Verified (all in-scope ACs) | Planned scenario executed as delivery checks only; no stakeholder or real-task observation | **not measured** |
| G-03 default branch | Verified | Same | **not measured** |
| G-05 | Verified | Same | **not measured** |

Tests, fixtures, structured review and DAO rulings are engineering delivery evidence, not observed benefits.

## Human CR Candidates (not DAO-decidable; none blocks closing)

1. **Structured, save-validated Preset provenance:** a structured Preset scope mode / scope-record schema v2, or a bound token validated at scope save. Spec Out of Scope; DAO-004 extended by DAO-005.
2. **O-2:** make `preset resolve`'s `adoption` text name `preset scope-save`. This touches a 001-C-owned output field.
3. **Optional spec wording for O-1:** at the next spec revision, state that "nothing is written" excludes first-use creation of the existing knowledge lock file.

## Release Disposition

**Engineering-only closure; release/PR not performed.** No commit, push, PR or release was performed. These need explicit human authority, which DAO cannot grant, and the workspace is not a Git repository.

## Refactoring Assessment

Not assessed in a separate analysis: no refactoring quality goal was named (DAO-002, feature acceptance).
- **Module sizes:** all modules are under 800 lines (`test_module_size` passes): catalog 612, presets 475, tags 205, preset_scope 250, impact 213, exit 659, cli 476.
- **Assessment values:** `overall_quality_score: N/A`; `refactoring_recommended: false` (no evidenced need; not a quality verdict); `top_suggestions: []`.

## Decisions Taken in DAO Mode (for the owner)

1. **Closable:** every in-scope AC passes at unchanged hashes, with no stale or partial evidence. Fresh acceptance evidence was reused, plus only a small spot re-run.
2. **No documentation correction needed** (rationale above).
3. **Code-review fix re-review:** no separate independent re-review exists. I judged the black-box acceptance at the final revision plus the closing self-inspection sufficient for this bounded fix delta. The owner may require an independent re-review before marking Completed.
4. **No DAO consultation was needed:** the only questions (O-1, O-2, route) were already ruled in DAO-002 (feature acceptance).

## Owner Handoff

- The owner alone may set FEATURE-001-F to Completed and complete TASK-071 on the board. This worker wrote no board, Git or memory files.
- Board read-only: 001-F Tested; 002-D and 003-B Implemented (parked on B9/B10 and B7/B11); Planned: 001-E, 001-G, 002-E, 002-F, 002-G, 003-C, 004-A, 004-B.
- Conditional next-feature suggestion: **FEATURE-002-E (Strix Adapter)** is the next in the earlier MVP order (002-D, 002-E, 003-B, 003-C), since 002-D and 003-B are parked. The owner confirms.

## Addendum — Closing Review and Fix (2026-10-23, appended by Sage)

- The independent re-review of the code-review fixes (the gap noted above) was performed: both fixes confirmed correct and complete for every Preset/tag/request JSON parse path.
- It found one more Major issue (non-UTF-8 file name crashing exit preview/confirm on Linux; AC-001F-06f/08a). Fixed test-first in `knowledge/catalog.py` (`824b5106…`); verified by a new unit test and a real raw-bytes file-name check in the offline Linux container (`acceptance/closing-fix-nonutf8-container-linux.jsonl`, 5/5). Full suite 2266 passed, 0 failed; ruff clean.
- The final delta re-review (PASS-WITH-FIXES, two Minor) noted that the stand-in name still raised on Windows for unpaired surrogates other than POSIX raw bytes. Fixed test-first: `_undecodable` falls back to `backslashreplace` (POSIX output unchanged, `\xff`); new parametrized unit test `test_preset_units.py::test_undecodable_name_stand_in` (red `SESSION/impl-001f/closing-fix2-red.log`). Windows itself remains unverified (stated limit).
- Final delivered revision: toolkit file-list hash `0358fd097302938ab2d38c1af9d649213b1bc9ddebd09598c4df6a1d7b6f957c` (222 files); `knowledge/catalog.py` `a21a34d342c53f0419291b36e617eba7dcb62ffc2966dc2009be57341fd1f1d3` (633 lines); full suite **2271 passed, 4 skipped, 23 deselected, 0 failed** (`SESSION/impl-001f/closing-fix2-full.log`); ruff clean.
- Statements in the body above hold at this revision **except** these values, which this addendum replaces: the revision hash `ebe3ce44…` (header and "same, before and after"), the `catalog.py` hash `79e0c69e…`, the catalog module size (612 lines), and the full-suite totals (2265/0). Only `knowledge/catalog.py` and two 001-F test files changed after acceptance; the acceptance evidence at `ebe3ce44…` stands for all other paths, supplemented by `acceptance/closing-fix-nonutf8-container-linux.jsonl` (run at `catalog.py` `824b5106…`; the later change only adds a non-POSIX fallback branch).
- Next feature: FEATURE-002-E is parked on B1 and is not part of the demo; per the agreed queue the next feature is FEATURE-002-F.
