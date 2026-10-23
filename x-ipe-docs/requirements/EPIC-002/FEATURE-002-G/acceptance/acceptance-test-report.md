# Acceptance Test Report — FEATURE-002-G Cross-run Report Comparison

> Feature: FEATURE-002-G Cross-run Report Comparison (EPIC-002) · Task: TASK-091 (Feature Acceptance Test). Lifecycle owner Sage; this report is by a worker, in free mode.
> Interaction mode: `dao-represent-human-to-interact`. No human was waited for; the decisions needed are listed at the end.
> Status: **Verified engineering delivery. All 76 AC rows pass at toolkit revision `15985026…`.** The stakeholder outcome (G-02, G-01 enabling) is **not measured**.
> Revision: toolkit file-list hash `15985026c280e6f530f566318ce73d02b3970824ecaffe0f212ee1869d9b3273` (238 files). It was the same before and after every run.

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | One CLI operation, `secure-code guard compare --earlier X --later Y [--project P] [--json]`. It writes a Markdown and a structured comparison in `reports/guard/comparisons/`. The scope also includes the Guard SKILL.md section "Comparing two reports". |
| Specification | [specification.md](../specification.md) v1.2.4, SHA-256 `476d41566857866c4cfabcb99138813521d3d1884f1b9722e3a9ffb4655ceb6f`. It has 76 AC rows: 01a…01i, 02a…02k, 03a…03g, 04a…04m, 05a…05s, 06a…06f and 07a…07k. |
| Design / Implementation | [technical-design.md](../technical-design.md) v1.3. The first part (bytes before "## Implementation Evidence") is `2d6a05ecd89c410c…`. The appended Implementation Evidence includes the code-review fixes; the whole file is `07c72288…`. Product files match the last evidence rows: `cli.py` `ce386af4…`, `compare.py` `13fbf5c8…`, `compare_bounds.py` `ab421ab3…`, `compare_cover.py` `877e4af9…`, `compare_io.py` `24130a73…`, `compare_match.py` `674a0dac…`, `compare_render.py` `e786a07e…`, `compare_validate.py` `349573b1…`, Guard `SKILL.md` `4bcb188f…` (prefix `cdbfc5bc…` is the delivered file). |
| Rulings | DAO-010…012 for feature refinement (`decisions_made_feature_refinement.md` `2378f22f…`). DAO-010…012 for technical design (`decisions_made_technical_design.md`, now `3d234f27…`; later entries for other features were appended after implementation, and the DAO-010…012 text was read). DAO-002 for code implementation (`d7708266…`). All were made by the delegated DAO representative, not the human. |
| Target URL | N/A. This is a CLI and skill-text feature with no UI. |
| Config / Capability | `x-ipe-docs/config/tools.json` (`6df39210…`), `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true`, so executable Python CLI runners are permitted. The Chrome tools are enabled but do not apply because there is no UI. |
| Planned cases | 24 black-box CLI and structured cases (TC-G-00…23); TC-G-08 is container only. Two suite runs (TC-U-01, TC-U-02), one lint run (TC-L-01) and six regression runners (TC-R-01…06). |

## Goal / Subgoal Frame (copied from the specification; outcome not measured)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-02 | EPIC-002 G-02; FR-23 (R-11, R-12) | Developer | The change between two runs is understood without false "fixed" claims | 01a…07k (all 76) | not measured |
| G-01 (enabling) | EPIC-001 FR-01 | Upstream agent | The comparison writes no business artifacts and changes neither compared run | 01d, 06a, 07e…07g | not measured |

Both planned outcome scenarios in the specification were executed as **delivery** checks:

- **Coverage drop.** A later run whose check ended `unconfirmed` gives "not comparable — check unconfirmed". It never gives "not observed" (TC-G-03).
- **Unchanged-coverage re-run.** The later run passes with the same targets and coverage. The result is "not observed this time" with the annotation "target content unchanged between runs", and the Markdown leads with the not-fixed statement (TC-G-01).

No stakeholder or real-task observation exists, so both outcome states stay **not measured**.

## Environment and Method

**Container** (Maintainer path, Linux):
- Image `fat-uv-git:py312` (`8cbe78fef76e`): Debian, Python 3.12.12, Linux aarch64, uv 0.9.30.
- Flags: `--network none`, `UV_OFFLINE=1`, `FAT_ISOLATED=1`, disposable HOME. Runs as root.
- `auth init` happened only here, at a pseudo-terminal.
- uv cache volume `fat-uv-cache-002g`, created for this task. It was seeded offline by copying `fat-uv-cache-003b`.
- The toolkit was copied from a read-only mount to a fresh path inside the container, so uvx built the current source.
- After all runs, the cache held exactly two builds that contain `guard/compare.py`. Both are byte-identical to the source tree (97 files). The other builds are pre-002-G seed leftovers ([evidence-uv-cache-verify.log](evidence-uv-cache-verify.log)).
- Real Opengrep 1.31.0 from the `og-validate` volume (read-only).

**Host** (macOS 26.6.2 arm64, Python 3.13.3, uv 0.11.23):
- Never-authorized User (`auth status` role `user`). There was no trust-store write on the host.
- `UV_OFFLINE=1`, `UV_REFRESH_PACKAGE=ai-secure-code-toolkit`.
- `TMPDIR` and `FAT_WORK` point into the session folder.
- The host runs on fresh copies of the seed projects that the container handed off. Guard runs need Maintainer setup, which is container-only.

**Runner:** [blackbox.py](blackbox.py) (`0b97856c…`) and [run.sh](run.sh) (`a794ce40…`; `sh run.sh fat` then `sh run.sh regressions`). The runner:
- drives the real `secure-code` subprocess and never imports toolkit code;
- loads the FEATURE-002-A runner (`7dfbd3fe…`) read-only for the Guard `open/plan/attempt/record/review/conclude/cancel/accept-risk` helpers.

**Seed projects** (all produced by the delivered CLI in the container):
- `basic`: E1 Fail, plus L1 pass, unconfirmed, not-covered, Policy N/A, check n/a, excluded, cancelled, disjoint-target pair and one open run.
- `rich`: E3/L3, with a rename, deletions both ways, context-only path, target changed during run, no-line findings, CWE split, risk acceptance and same run-local IDs.
- `policy`: the rule changed through `knowledge update` between runs.
- `merge`: a delivered `guard record` chain M1,M2→M3→M4 and a re-merge M1→M6.
- `opengrep`: four real Opengrep runs (same settings, include-ignored on, a check covering an ignored `tests/` folder).

**Fixture edits** (disclosed, file operations by the runner):
- Structured results are re-serialized canonically. TC-G-00 verifies that the runner's serializer equals the delivered bytes on unedited results.
- Markdown body, footer and section edits. TC-G-09 05l is a *simulated* older renderer: it removes a section, because no older renderer copy exists.
- 31-day ageing of `opened_at`/`ended_at` for real `guard cleanup` expiry.
- Symbolic links, a FIFO, chmod 000, 64 MiB+1 padding and depth-70 nesting.

**Oracles:**
- Envelopes, output files and project trees (path, type, SHA-256 before and after).
- A `sitecustomize` audit hook (via `PYTHONPATH`) in the CLI process. It logs `open`, `listdir`, `scandir`, `socket.*`, subprocess, exec and fork events. It sees Python-level calls only.

**Suites** (product folder `scripts/`):
- Full suite: `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=$SESSION/fat-002g/tmp`.
- Targeted run: the same command with `-rA -s` on the 8 `test_compare_*.py` files, the delivered Guard, Copilot and skeleton skill tests, and `test_module_size.py`.
- Lint: `ruff check --no-cache .`.

## Results Summary

| Group | Planned | Pass | Fail | Partial | Not run | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Black-box CLI + structured (TC-G-00…23) | 24 | 24 | 0 | 0 | 0 | Container 24/24 cases, 182 checks ([jsonl](evidence-container-linux.jsonl) `6840bc9c…`). Host 23/23 cases, 174 checks ([jsonl](evidence-host-macos.jsonl) `c7a481e4…`). Both stderr files empty. |
| Feature + skill tests, targeted (TC-U-01) | 1 | 1 | 0 | 0 | 0 | 249 passed, 0 skipped ([log](evidence-unit-integration.log) `be8ee993…`). Peak RSS 649 510 912 B (byte limit) and 1 599 422 464 B (value limit), both ≤ 3 GiB. |
| Full suite (TC-U-02) | 1 | 1 | 0 | 0 | 0 | **2497 passed, 4 skipped, 23 deselected, 0 failed, exit 0**, 632.95 s ([log](evidence-full-suite.log) `09f61f7a…`) |
| Lint (TC-L-01) | 1 | 1 | 0 | 0 | 0 | `ruff check --no-cache`: all checks passed ([log](evidence-ruff.log)) |
| Regressions (TC-R-01…06) | 6 | 4 | 0 | 2 | 0 | See § Regressions |
| **Total logical TCs** | **33** | **31** | **0** | **2** | **0** | **pass_rate = 31 / 33 = 93.9 %** (Partial = one carried superseded check and one environment-blocked case; no product failure) |
| **AC rows** | **76** | **76** | 0 | 0 | 0 | See § AC → Evidence |

## Test Cases (Integration = real `secure-code` subprocess + filesystem; Structured = skill text)

| TC | ACs | Type | Env | Result |
| --- | --- | --- | --- | --- |
| TC-G-00 | fixture precondition | integration | C+H | The canonical re-serialization equals the delivered bytes on five unedited results. |
| TC-G-01 | 01a, 01d, 01e, 03a, 03b, 03c, 03e, 04m, 05e, 06a, 06e, 06f, 07e, 07i | integration (file-access, audit hook) | C+H | 21 checks pass. They include: only the four twins read; no listing, subprocess or socket; one JSON+MD pair; footer = JSON SHA-256; no other file changed; `comparisons/` absent after init and after a refusal, and a real folder after the first success. |
| TC-G-02 | 06b, 06a | integration | C+H | Two comparisons are identical except ID and time. On the host, comparison data equals the container's for the same results (Linux vs macOS). |
| TC-G-03 | 03b, 04c, 04d, 04h, G-02 scenario | integration | C+H | Reasons by later run: unconfirmed → `check_unconfirmed`; not covered → `not_covered`; excluded → `excluded_by_user`; Policy N/A → `na_other_run` (+ `not_covered`) with the recorded reason; check n/a → `na_other_run` with the reason; cancelled → `check_unconfirmed` + "later run cancelled". |
| TC-G-04 | 04k, 04l, 04a, 02j | integration | C+H | "The runs share no targets"; everything not comparable; `scope_differs` with both values; comparability section present. |
| TC-G-05 | 02e, 02f, 02g, 02j, 02k, 03a, 03b, 03d, 03g, 04a, 04i, 04j, 04l, 04m, 06d | integration | C+H | 14 entries: 3 still present, 4 not observed, 3 new, 4 not comparable. 10 + 7 findings are each referenced once. See the observation list in the container jsonl. |
| TC-G-06 | 03f, 04b | integration | C+H | The pair under a changed Policy stays still present, with a policy note and a count of 1. The unpaired finding is "Policy differs" with both digests. |
| TC-G-07 | 02i, 05s, 03g | integration | C+H | The delivered record flow chain and re-merge are accepted. The survivors M4 (merged M2, M3) and M6 (merged M1) carry a re-merge note on M1. Merged-away findings are never matched. |
| TC-G-08 | 02a, 02b, 02d, 03b, 03f, 04e, 04g | integration (real Opengrep 1.31.0) | C | Exact, `position (line moved 2→4)`, `5 exact / 40→41 position / 90 new`. A clean re-scan gives not observed. include-ignored differs → `method_differs` (pairs: 4 still present, 4 with differences). Skipped items → `tool_coverage_incomplete` with counts. Recorded fingerprints were all `null`. |
| TC-G-09 | 05c, 05g, 05h, 05i, 05j, 05k, 05l | integration | C+H | Each variant gives the exact failed-check set, the warning first, entries referencing `input_integrity`, and nothing written to the run. 05j is consistent. 05k is refused. 05l (simulated) carries no tampering claim. |
| TC-G-10 | 05a, 05b, 05f | integration | C+H | `RESULT_SCHEMA_UNSUPPORTED` (found + supported). `RESULT_INVALID` with rule and path, value not echoed. A v1 result without optional sections → "not recorded in this result". |
| TC-G-11 | 06c | integration | C+H | A token in the title and description is masked and labelled in both outputs. The validation refusal inside that finding does not echo it. |
| TC-G-12 | 05b, 05c, NFR-002G-5 | integration | C+H | A result over 64 MiB → `RESULT_TOO_LARGE` `bound.bytes`, "Comparison not possible", not declared invalid. Depth 70 → `bound.depth`. Markdown over 64 MiB → `markdown_oversized`, unresolved, the comparison completes. |
| TC-G-13…15 | 05m, 05n, 05o, 05p, 05q, 05r, 05s (+05b) | integration | C+H (42 edits each; the host compares the handed-off Opengrep seed results) | Each edit gives `RESULT_INVALID`, the precise rule (e.g. `enum`, `unique.check_id`, `ref.tool_run`, `format.timestamp`, `target.deleted_digest`, `merge.backref`) and the offending JSON path. The project is byte-identical and no `comparisons/` exists. |
| TC-G-16 | 01b, 01c, 01g | integration (audit hook) | C+H | Refusals: one, three, two-earlier, same twice, `.json`/`.md` twins; unknown, open, bad format, outside path (no twin read); reversed order with both end times and "Swap". |
| TC-G-17 | 01g | integration | C+H | Equal end times → `END_ORDER_INVALID` and "name other reports". An unreadable time → `end_times.later = "unknown"`. |
| TC-G-18 | 07a, 07b | integration (audit hook) | C+H | `./`-prefixed `.md` and plain `.json` are accepted. Refused before any read: absolute, `..`, outside, `.txt`, extra characters, `.JSON`, subfolder, `comparisons/`. |
| TC-G-19 | 07c, 07d, 07e | integration | C+H | Each of three path components as a symlink → `PATH_UNSAFE`, by ID and by path. `.md` link and `.json` FIFO → `PATH_UNSAFE` without hanging. Missing `.json` → `NOT_CONCLUDED`/`RUN_NOT_FOUND`. `comparisons/` as a symlink to outside or as a file → refused, nothing written anywhere. |
| TC-G-20 | 07f (partial), 06a | integration | C+H | Existing comparison files and a pre-placed `gc-…json` symlink to outside are never overwritten, replaced or followed. |
| TC-G-21 | 01d | integration (audit hook) | C+H | Targets were modified or deleted, other reports corrupted and run-folder files made chmod 000. The comparison is identical, with no subprocess and everything byte-identical. The unreadable clause is effective on the host only (the container runs as root). |
| TC-G-22 | 06f, 05d | integration | C+H | Real `guard cleanup`: comparison files are kept, unlisted and byte-identical, before and after removing the expired run. Then the comparison reports raw evidence "not available" and "never on raw evidence". |
| TC-G-23 | 01f, 01h, 07k | structured | C+H | Section rules present. The delivered SKILL.md (`cdbfc5bc…`) is a byte-identical prefix with exactly one added section. The pair-validity rule is stated. |
| TC-U-01 | all; sole evidence for 02c, 02h, 04f, 07g, 07h, 07j | unit / integration | H | 249 passed (§ AC table names the tests) |
| TC-U-02 | supporting; 01i | unit / integration | H | 2497 passed / 4 skipped / 23 deselected |
| TC-L-01 | — | lint | H | pass |

## AC → Evidence (all 76 rows; revision `15985026…`)

C = container black-box, H = host black-box, U = named test in [evidence-unit-integration.log](evidence-unit-integration.log) (V/M/CV/R/CLI/F/RG/SK = `test_compare_validate/match/cover/render/cli/files/regression/skill.py`).

| AC | Evidence | Result |
| --- | --- | --- |
| 01a | TC-G-01 C+H: the audit hook shows content opens only for `E/L .json/.md`, metadata folder handles, the root and its own outputs; no listing. U: F `test_01a_reads_only_named_results_and_reports` | Pass |
| 01b | TC-G-16 C+H (5 refusal forms; next step; nothing written). U: CLI `test_01b_…` | Pass |
| 01c | TC-G-16 C+H (unknown, open → `NOT_CONCLUDED` with conclude step, bad format, outside path; no twin read). U: CLI `test_01c_…`, `test_01c_result_vanishing_…` | Pass |
| 01d | TC-G-21 C+H (modified or deleted targets, corrupted other reports, chmod-000 run files on H): identical result, byte-identical tree, no subprocess. U: F `test_01d_…` | Pass |
| 01e | TC-G-01 C (`--network none`: every outbound connection fails; the comparison completes) and C+H audit (no `socket.*` event). U: F `test_01e_no_network` | Pass |
| 01f | TC-G-23 C+H section text. U: SK `test_01f_comparing_section_rules` | Pass |
| 01g | TC-G-16 (reversed → both end times + "Swap") and TC-G-17 (equal; unknown) C+H. U: CLI `test_01g_…` | Pass |
| 01h | TC-G-23 C+H: the delivered SKILL.md `cdbfc5bc…` is a byte prefix; one added section only. U: SK `test_01h_only_added_section` | Pass |
| 01i | Delivered `test_guard_skill.py` `4999c6b4…`, `copilot/test_copilot_skill.py` `3025db4b…` and `test_skill_skeletons.py` `c517fad1…` are byte-identical to the pre-feature hashes and pass (TC-U-01/02). New test SK `test_01f…`. U: SK `test_01i_delivered_skill_tests_unchanged` | Pass |
| 02a | TC-G-08 C (real Opengrep): `py/more.py:2` ↔ `:2`, basis `["exact"]`. U: M `test_02a_…` | Pass |
| 02b | TC-G-08 C: `py/orders.py` 2→4, basis `position (line moved 2→4)`. U: M `test_02b_…` | Pass |
| 02c | U: M `test_02c_fingerprint_first_regardless_of_line`. Not black-box drivable: Opengrep 1.31.0 recorded no valid fingerprint (all `null`), and no offline Trivy is available | Pass (unit) |
| 02d | TC-G-08 C: `py/multi.py` 5 exact, 40→41 position, 90 new. U: M `test_02d_…` | Pass |
| 02e | TC-G-05 C+H: F5/G5, basis includes `declared rename src/old.py→src/new.py` | Pass |
| 02f | TC-G-05 C+H: F3 not observed / G3 new, each `possible_move` referring to the other | Pass |
| 02g | TC-G-05 C+H: F1/G1 (different title, description and ID) paired with `semantic identity (weak)`; F10 CWE-80 vs G10 CWE-83 not paired | Pass |
| 02h | U: M `test_02h_trivy_vuln_version_change_is_attribute`; the validator accepts delivered Trivy results (V realism). No offline Trivy binary or components exist on this machine | Pass (unit) |
| 02i | TC-G-07 C+H: M1, M2, M3 never matched; survivors carry `merged`; merge shown | Pass |
| 02j | TC-G-04 (F1/F1 different paths) and TC-G-05 (F2/F2) C+H: not paired | Pass |
| 02k | TC-G-05 C+H: one `position` + `semantic identity (weak)` pair; the other E no-line finding is not observed this time | Pass |
| 03a | `counts_ok` in TC-G-01/03/05/07/08 C+H (four classes; sums; pairs = still present). U: M `test_03a_…` | Pass |
| 03b | TC-G-01, 05, 08 (comparable → new / not observed) and TC-G-03 (else not comparable) | Pass |
| 03c | TC-G-01 and TC-G-05 C+H: the not-fixed statement precedes `## Runs`; no fixed/resolved/remediated/improved/trend/score/% in either output beyond the fixed negations and the AC-002G-05e report-resolution sentence. U: R `test_03c_…` | Pass |
| 03d | TC-G-05 C+H: `final_severity` high/medium, `review` confirmed/false_positive and `title` with both values; still present | Pass |
| 03e | TC-G-01 C+H: Fail/Pass with the recorded reasons; no derived verdict, trend, score or percentage keys. U: R `test_03e_…` | Pass |
| 03f | TC-G-06 (Policy note, counted, "observed in both runs under the stated identity rule") and TC-G-08 (include-ignored notes counted 4). U: M `test_03f_…` (build, config, Trivy components) | Pass |
| 03g | TC-G-05 (10 + 7) and TC-G-07 (merged-away only via survivor) C+H. U: M `test_03g_…` | Pass |
| 04a | TC-G-05 (path only context in L → `scope_differs`) and TC-G-04 C+H. U: CV `test_04a_…` | Pass |
| 04b | TC-G-06 C+H: "Policy differs" with both `sha256:` digests. U: CV `test_04b_…` | Pass |
| 04c | TC-G-03 C+H: not covered / check unconfirmed / excluded by the user. U: CV `test_04c_…` ×2 | Pass |
| 04d | TC-G-03 C+H: Policy-level and check-level N/A, with the recorded reasons. U: CV `test_04d_…` | Pass |
| 04e | TC-G-08 C: include-ignored differs → "tool or method differs" naming it. U: CV `test_04e_…` ×2 (build, config, no run) | Pass |
| 04f | U: CV `test_04f_tool_data_differs`. No offline Trivy (see 02h) | Pass (unit) |
| 04g | TC-G-08 C: `tool_coverage_incomplete` with counts (skipped). U: CV `test_04g_…` | Pass |
| 04h | TC-G-03 C+H: "check unconfirmed" + "later run cancelled". U: CV `test_04h_…` | Pass |
| 04i | TC-G-05 C+H: "target unstable or incomplete in run earlier" (changed during run). The incomplete branch (outside content, dangling links): U: CV `test_04i_…` | Pass |
| 04j | TC-G-05 C+H: both directions with exact texts | Pass |
| 04k | TC-G-04 C+H. U: CV `test_04k_…` | Pass |
| 04l | TC-G-04/05 C+H: several reasons with both values; comparability section. U: CV `test_04l_…` | Pass |
| 04m | TC-G-01/05 C+H: "target content unchanged between runs". U: M `test_04m_…` | Pass |
| 05a | TC-G-10 C+H | Pass |
| 05b | TC-G-10, 12, 13…15 C+H (invalid JSON, ID mismatch → `$.verification_id`, strict rules; value never echoed; nothing written) | Pass |
| 05c | TC-G-09 (Markdown missing) and TC-G-12 (oversized) C+H: warning first, `input_integrity` per run, entries reference it, structured result used | Pass |
| 05d | TC-G-22 C+H (real cleanup and direct removal) | Pass |
| 05e | TC-G-01 C+H (IDs, end times, SHA-256 of the result files; provenance limits) and TC-G-09 05j | Pass |
| 05f | TC-G-10 C+H. U: CV `test_05f_unit_tool_finding_against_run_without_adapter_records` | Pass |
| 05g | TC-G-09 C+H: only `markdown_canonical_rendering` fails | Pass |
| 05h | TC-G-09 C+H: `footer_digest` + `markdown_canonical_rendering` | Pass |
| 05i | TC-G-09 C+H: the same two checks fail; "cannot be told which file was changed"; "used the structured result" | Pass |
| 05j | TC-G-09 C+H: consistent; limit statement | Pass |
| 05k | TC-G-09 C+H: refused, nothing written | Pass |
| 05l | TC-G-09 C+H (simulated older-renderer output): unresolved; "edited, or the report was rendered by a different toolkit version"; no "tamper". U: CLI `test_05l_…` | Pass |
| 05m | TC-G-13 C+H (10): type, enum, `range.count` | Pass |
| 05n | TC-G-14 C+H (6): `unique.*` | Pass |
| 05o | TC-G-14 C+H (9): `ref.*` | Pass |
| 05p | TC-G-14 C+H (3): `ref.tool_run`, `ref.tool_adapter`, `ref.adapter_run_check`. U: V `test_05p_…` | Pass |
| 05q | TC-G-15 C+H (5): `format.digest`, `format.timestamp`, `order.timestamps` | Pass |
| 05r | TC-G-15 C+H (4): `target.*` | Pass |
| 05s | TC-G-15 C+H (5 refusals: `merge.unknown/self/cycle/backref`) and TC-G-07 (delivered chain and re-merge accepted, resolved, noted) | Pass |
| 06a | TC-G-01/02/20 C+H | Pass |
| 06b | TC-G-02 C+H (+ Linux = macOS data) | Pass |
| 06c | TC-G-11 C+H (title/description masked and labelled; refusal without the value). Nested `tool.secret` (Trivy): U: R `test_06c_masking_and_secret_never_output`, V `test_06c_refusal_inside_secret_finding_has_no_value` | Pass |
| 06d | TC-G-05 C+H: `risk_acceptance {run: earlier, applies_to_later: false}`; "does not apply to the later run" | Pass |
| 06e | TC-G-01 C+H | Pass |
| 06f | TC-G-22 (cleanup and expiry keep the files) and TC-G-01 (envelope fields) C+H | Pass |
| 07a | TC-G-18 C+H | Pass |
| 07b | TC-G-18 C+H | Pass |
| 07c | TC-G-19 C+H (`x-ipe-docs/secure-code`, `…/reports`, `…/reports/guard`) | Pass |
| 07d | TC-G-19 C+H | Pass |
| 07e | TC-G-19 (link or file → refused, nothing written) and TC-G-01 (created as a real folder only on success) C+H. Parent fsync and no-follow creation: U: F `test_07e_…`, `test_07k_write_call_order` | Pass |
| 07f | TC-G-20 C+H (existing entries and links untouched). Collision on the allocated name: U: F `test_07f_existing_name_never_overwritten`, `test_07f_markdown_name_raced_then_new_candidate`, `test_07f_eight_collisions_refused`. The random ID cannot be pre-created black-box | Pass |
| 07g | U: F `test_07g_substitution_never_writes_outside` (4 substitutions × 4 hook points, all passed). A race needs an in-process hook | Pass (integration) |
| 07h | U: RG `test_07h_delivered_commands_unaffected_by_comparisons` (frozen clock is mandatory, FR-002G-10; test-side patching only) | Pass (integration) |
| 07i | TC-G-01 C+H. U: RG `test_07i_…` | Pass |
| 07j | U: F `test_07j_injected_failures_leave_no_partial` (11 points), `test_07j_hardlink_unsupported_refused` (6), `test_07j_failure_right_after_folder_creation_removes_it` (3) | Pass (integration) |
| 07k | U: F `test_07k_write_call_order`, `test_07k_crash_points` (4 `os._exit` points). SK `test_07k_skill_states_pair_validity`, TC-G-23 C+H skill text | Pass |

## Regressions (unchanged runners, run in place; [stderr + build check](regression-stderr-and-build-check.log))

| TC | Runner (hash) | Container (Linux, offline) | Host (macOS) | Compared with | Result |
| --- | --- | --- | --- | --- | --- |
| TC-R-01 | 002-A `7dfbd3fe…` | 26/26, `404ada17…` | 2/2, `b87e492e…` | original 002-A evidence | **byte-identical**, Pass |
| TC-R-02 | 002-B | 9/10, `9239513a…` | 2/2, `290c2607…` | latest 002-B regression (FEATURE-002-D acceptance) | **byte-identical**. The single failing check is TC-B-01 "06b trivy/strix not provided", superseded by FEATURE-002-D (Trivy is now provided), unchanged since then → **Partial (carried superseded check)** |
| TC-R-03 | 002-C | 9/9, `7a21573d…` | 2/2, `b9261d26…` | original 002-C evidence | **byte-identical**, Pass |
| TC-R-04 | 002-D (offline part) | not runnable (see note) | 1/2, `d4fbd245…` | original 002-D host evidence | TC-D-19 (skill and records) line **byte-identical**. TC-H-01 is blocked by the environment: it needs the container's Trivy handoff (`FileNotFoundError …/handoff.json`) → **Partial (environment)** |
| TC-R-05 | 003-A | 11/11, `4b978585…` | 2/2, `e2e89141…` | original 003-A evidence | **byte-identical**, Pass |
| TC-R-06 | 003-B | 23/23, 337 checks, `049f3cf0…` | 24/24, 350 checks, `828f3dd9…` | original 003-B evidence | Same TCs, statuses and check lists. Only the `seconds` and lock-wait timing `notes` values differ. Pass |

**002-D container part.** It needs the real Trivy v0.76.1 binary and the loopback OCI registry. Their Docker volumes (`fat2d-*`) no longer exist, and rebuilding them needs network access, which is outside this task's authority. Trivy behaviour stays covered by the delivered Trivy unit and integration tests in the full suite (TC-U-02).

**Stale-build hazard (caught, discarded).** A first container-regression attempt used the toolkit path `/toolkit`. The seeded cache served a stale pre-002-G build there: `guard compare --help` exited 2 and the old `cli.py` hash showed. Those five logs were discarded (kept in the session folder `fat-002g/discarded-stale/`). The rerun used a fresh in-container path. The build check then passed (`exit=0`, current `cli.py` `ce386af4…`) and the cache verification shows that only source-identical builds contain `compare.py`. The 002-G runs used `guard compare` successfully, so they cannot have run a pre-002-G build.

## Observations (no defect raised)

- **O-1 (03f wording).** The phrase "same issue confirmed" appears only in the fixed negation "it never means the same issue confirmed". The runner asserts that every occurrence is this negation.
- **O-2 (03c wording).** The word "resolved" appears only in the AC-002G-05e sentence "Both reports were resolved from the supplied project's report store". It is about reports, not findings. The runner excludes exactly that sentence; it is listed here for transparency.
- **O-3 (04d).** When the rule has no check in the other run (Policy-level N/A), the reasons are `na_other_run` + `not_covered`. Both are true, and 04l requires all applicable reasons to be listed.
- **O-4 (04g).** For a later run whose covering Adapter run skipped items, the reasons are `tool_coverage_incomplete` (with counts) and `method_differs`. The delivered Adapter marks that run's `method_status` as failed (002-B behaviour).
- **O-5 (02f).** `possible_move` is emitted once per candidate. The new L finding G3 lists both not-observed candidates, as designed ("all candidates").
- **O-6 (TD DAO log hash).** The technical-design DAO log now hashes `3d234f27…`. The implementation recorded `b8e98b61…`, and the difference is later appends for other features. The DAO-010…012 entries were read and are consistent.

## Honest Limits

- **Race window.** 07g (substitution) and 07j/07k (forced failures, crash points) rest on in-process hooks and fail points in the delivered integration tests. Black-box can cover only static links and existing entries. The residual same-user race that the specification states (an empty command-created `comparisons/` may remain where another process moved it) is not measurable portably. Power loss is not simulated.
- **Windows not measured.** There was no Windows host: no path fallback, no `durable.py` Windows branch and no peak RSS. Linux peak RSS was not measured either. RSS was measured on macOS arm64 only: 0.60 GiB and 1.49 GiB, both ≤ 3 GiB.
- **Older renderer.** A report rendered by an older renderer is always "input integrity unresolved", and it cannot be told apart from an edited one. 05l was exercised with a simulated older output because no older renderer copy exists. The optional human CR candidate (record the renderer version) stays open.
- **Provenance.** Provenance is not provable. A report copied in from another project, or a result and Markdown edited consistently (05j), is not detected. The outputs say so.
- **Trivy.** Trivy-specific identity and tool-data paths (02h, 04f, nested `tool.secret` in 06c) and fingerprint pairing (02c) rest on unit tests. No offline Trivy exists on this machine, and Opengrep 1.31.0 records no fingerprints.
- **Audit-hook oracle.** It sees Python-level calls only. 01d's "unreadable" clause is effective on the host only (the container runs as root).
- **Stakeholder outcome.** Not measured. Fixtures, automation and DAO rulings are not stakeholder observations.

## Decisions Needed (DAO mode; none blocks acceptance)

1. **Route (Q1).** No refactoring quality goal has been named, so FEATURE-002-G can go to Feature Closing. Alternatively, the owner records a mandatory `code_refactor` gate if the app requires one. Implemented → Tested is an owner write.
2. **Evidence form (Q2).** Confirm that 02c, 02h, 04f, 07g, 07h and 07j (and the race and crash parts of 07e, 07f and 07k) are accepted on the named delivered integration and unit tests at this revision, because they cannot be driven black-box.
3. **002-D regression (Q3).** Accept host TC-D-19 (byte-identical) plus the full-suite Trivy tests as the offline 002-D regression. The alternative is that the human restores the Trivy and loopback-registry environment (the B9 setting) for a container rerun.
4. **Wording (Q4).** Confirm O-1 and O-2 as interpretations; no AC change.
5. **CR candidates (carried).** Two optional human CR candidates stay recorded: record the renderer or toolkit version in Guard results; forbid chained merges at record time.

## Cleanliness and Input Re-verification (end of task)

The toolkit file-list hash is `15985026…` (238 files) before and after all runs. The specification is `476d4156…` and the design first part is `2d6a05ec…`. Nothing was created inside `ai-secure-code-toolkit/`, the workspace `.x-ipe/` or `x-ipe-docs/secure-code/`; `find -newermt` after the runs is empty. There were no board, Git, memory or `.github/skills` writes. Docker volume `fat-uv-cache-002g` and the session temporary folders were removed after the runs (they were made writable first). The acceptance folder holds only the runner, `run.sh`, the evidence logs and this report.

## Task Completion Output

```yaml
task_completion_output:
  category: feature-stage
  status: completed
  next_task_based_skill:
    - skill: "x-ipe-task-based-code-refactor"
      condition: "Refactor code for quality improvements"
    - skill: "x-ipe-task-based-feature-closing"
      condition: "Close feature if no refactoring needed"
  process_preference:
    interaction_mode: "dao-represent-human-to-interact"
  workflow:
    name: "N/A"
  workflow_action: "acceptance_testing"
  workflow_action_updated: false
  task_output_links:
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-G/acceptance/acceptance-test-report.md"
  feature_id: "FEATURE-002-G"
  feature_title: "Cross-run Report Comparison"
  feature_version: "v1.2.4"
  feature_phase: "Acceptance Testing"
  test_types_tested: ["unit", "integration", "structured-review"]
  test_cases_created: 33
  tests_passed: 31
  tests_failed: 0
  tests_blocked: 0
  pass_rate: "93.9%"
  results_by_type:
    frontend_ui: {passed: 0, failed: 0, blocked: 0}
    backend_api: {passed: 0, failed: 0, blocked: 0}
    unit: {passed: 2, failed: 0, blocked: 0}
    integration: {passed: 28, failed: 0, blocked: 0, partial: 2}
    structured_review: {passed: 1, failed: 0, blocked: 0}
```

`unit` covers TC-U-01/02. `integration` covers TC-G-00…22 (23), TC-L-01 and TC-R-01…06; partial = TC-R-02 and TC-R-04. `structured_review` is TC-G-23. All 76 AC rows pass. The two partials are regression-runner artefacts (one carried superseded check, one environment-blocked case), not product failures.
