# Acceptance Test Report — FEATURE-001-F Presets & Tags

> Feature: FEATURE-001-F Presets & Tags (EPIC-001) · Task: TASK-070 (Feature Acceptance Test), lifecycle owner Sage, worker; free mode
> Interaction mode: `dao-represent-human-to-interact` (no human waited for; decisions listed at the end)
> Status: **Verified delivery — all 63 in-scope AC rows pass at toolkit revision `ebe3ce44…`**; 3 rows superseded (no test); stakeholder outcome **not measured**
> Revision: toolkit file-list hash `ebe3ce4491f1248bb07f7fcf6ac00fadfd979407c7bfd7fb10baec37ee7bb521` (222 files), identical before and after all runs

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-001-F Presets & Tags — CLI (`secure-code preset …`, `secure-code tag …`, the extended `knowledge exit-preview/exit-confirm/links`) and the Framework skill text |
| Specification | [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/specification.md) v1.5, SHA-256 `e00d67215106d60aadeb07fc1f669ba354be593c3e7feb0171b0ee386805d2a9` (66 AC rows; 04h, 09b, 09c superseded) |
| Design / Implementation | [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/technical-design.md) v1.3 — first 585 lines `353b0f30…` (Parts 1 and 2), appended Implementation Evidence incl. DAO-002 update and code-review fixes (whole file `d2337bf0…`). Product files per the design's evidence table (catalog `79e0c69e…`, presets `50cf6cda…`, tags `34b5b8d9…`, preset_scope `aa9b0bbb…`, impact `906c4562…`, exit `165b7865…`, cli `a1e8d924…`) |
| Rulings | DAO-006…DAO-009 (`decisions_made_technical_design.md` `03828e43…`), DAO-002 (`decisions_made_code_implementation.md` `d7708266…`) — delegated DAO representative, not the human |
| Target URL | N/A — CLI and agent-skill feature, no UI |
| Config / Capability | `x-ipe-docs/config/tools.json` `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true` (and general) → executable Python CLI runners permitted; Chrome tools enabled but not applicable (no UI) |
| Planned cases | 18 black-box/structured cases (TC-F-01…18; TC-F-18 runs in both environments) + DAO-009 (3) re-run obligations (§ Re-runs) |

## Goal / Subgoal Frame (copied from the specification; outcome not measured)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-12; FR-07/AC-09 | Developer, Maintainer, upstream agent | Reusable, explicit rule scopes without hidden drift; removing or renaming knowledge never silently breaks or rewrites Presets and tags | 01a…08c, 09a, 09d…09g | not measured |
| G-03 (default-Preset branch) | FR-10 / P-13 via the 001-C deferral (DAO-003) | Developer, upstream agent | With no clues a known default scope is proposed before Apply All and adopted only on confirmation | 04e, 04g | not measured |
| G-05 (enabling) | P-02, U-04, U-05, K-03; 001-C BR-09 | Owner | Scope maintenance never grants knowledge-editing rights; tag writes least-privilege | 07a…07d | not measured |

The spec's planned outcome scenario (save a Preset from clues, change tag membership, reuse the Preset, recompute with a diff, rename a referenced rule) was executed as **delivery** checks (TC-F-01, 05, 06, 09, 10). No stakeholder or real-task observation exists, so every outcome state stays **not measured**; passing checks are engineering delivery only.

## Environment and Method

- **Black-box only.** `acceptance/blackbox.py` (`3fe65523…`) calls the real CLI as a subprocess (`uvx --from <framework>/scripts secure-code …`) against fresh `init`-ed projects; it never imports toolkit code. JSONL per case (`tc`, `acs`, `checks`, `failed`).
- **Container (Maintainer paths):** `fat-uv-git:py312` (Python 3.12.12, uv 0.9.30, Linux arm64), `--network none`, `UV_OFFLINE=1`, `PYTHONDONTWRITEBYTECODE=1`, read-only mounts of the toolkit, the runner folder and the pre-001-F originals, disposable container HOME (`auth init` only there). uv cache volume `fat-uv-cache-001f-fat`: copied from `fat-uv-cache-001f` with every `ai_secure_code_toolkit` archive/sdist/environment removed, then built offline from the current source; the installed `catalog/presets/tags/impact/exit/preset_scope/cli.py` hashes equal the product ([cache-warmup-verify.log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/cache-warmup-verify.log)). The volume was **removed** after the runs.
- **Host (non-Maintainer paths only):** macOS, Python 3.13.3, never-authorized User (`auth status` → `user`); no `auth init`, no trust writes. Disposable projects/temp under the session folder (`fat-001f/`), removed afterwards.
- **Pre-001-F revision (06e, 06j, 09a, 04e):** [prepare_pre001f.sh](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/prepare_pre001f.sh) reconstructs it inside the container from the current tree minus the five 001-F payload files, with the six changed files restored from `impl-001f/orig/` and checked by `sha256sum -c` against the TASK-069 pre-change hashes (`impact 9d1dd81f…`, `exit 384a9853…`, `cli f0f6ca23…`, `SKILL.md 5a444baa…`, `cli-contract.md 54ad66dc…`, `policy-selection.md 5a015418…`; all OK, see `evidence-container-linux.stderr`). This is a faithful reconstruction, not the historical build artifact.
- **Orchestration:** [run.sh](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/run.sh) (`59e185bc…`): `fat` (001-F container + host), `rerun001d`, `regressions`. Fixtures disclosed in the runner docstring (agent-role request/decisions files, hand-damaged files, `flock` on the knowledge lock, documented `SECURE_CODE_TEST_PAUSE_AT` / `SECURE_CODE_TEST_FAIL_AT` hooks, trust folder moved aside and restored for the container User).
- No product code, delivered test, `.github/skills`, board, Git or memory file was changed; nothing was written inside `ai-secure-code-toolkit/`.

## Results Summary

| Run | Result | Evidence (SHA-256) |
| --- | --- | --- |
| 001-F black-box, container (Maintainer + container User) | **17/17 cases, 276/276 checks**, stderr = reconstruction log only | [evidence-container-linux.jsonl](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-container-linux.jsonl) `a87e978b…` |
| 001-F black-box, host (never-authorized User + skill text) | **2/2 cases, 28/28 checks**, stderr empty | [evidence-host-macos.jsonl](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-host-macos.jsonl) `5c5c1350…` |
| Full Framework pytest suite (`FW/scripts`, command as instructed) | **2265 passed, 0 failed, 4 skipped, 23 deselected** (580 s) | [evidence-unit-integration.log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-unit-integration.log) `e7359dd7…`; skip reasons [evidence-skip-reasons.log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-skip-reasons.log) (one conditional on FEATURE-001-E; three pre-existing platform/design skips) |
| `uv run --offline ruff check --no-cache .` | All checks passed | [evidence-ruff.log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-ruff.log) |
| Delivered test files vs TASK-069 baseline (101 files) | 99 byte-identical; only the two sanctioned edits differ: `tests/knowledge/test_exit_preview.py` (DAO-006 superseded loop) and `tests/carriers/carhelp.py` (DAO-002); `tests/policy`, `tests/guard`, `tests/copilot` unchanged | [evidence-delivered-test-hashes.txt](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-delivered-test-hashes.txt) |
| DAO-009 (3) re-runs (001-D acceptance, 001-B/001-C/002-A/003-A regressions) | See § Re-runs: no defect; 001-D AC-001D-02b clauses **superseded per AC-001F-06a/06b — re-run** | `rerun-001D-*.jsonl`, `regression-*.jsonl`, `diag-001D-*` |

Pass rate (planned 001-F cases): 18/18 = 100 % (19 executions incl. TC-F-18 twice). Counts are diagnostics, not goal achievement.

## Test Cases (Integration = real CLI subprocess + filesystem; Structured-review = skill package)

| TC | Env | Type | Prio | ACs | What is driven / asserted | Checks | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TC-F-01 | C | integration | P0 | 01a, 01c, 08b, 02g, 03b | `preset save` with a version-less reference, ACME + CWE namespaces, executable-looking intent, UTF-8 summary; file keys/refs/no content; `snapshot_at` with offset; canonical bytes; two projects, references in another order → identical bytes apart from the time value; `default` announced | 12 | Pass |
| TC-F-02 | C | integration | P0 | 01b, 01f, 02b, 02d, 02f, 02g | 7 dynamic selectors; `not_found`/`pending_decision`/`inconsistent`/`multiple_versions` (both candidates) in one request; Reference ref; empty list; no `--confirmed`; 13 Preset + 4 tag invalid identities; existing and case-variant identity; tree byte-identical | 32 | Pass |
| TC-F-03 | C | integration | P0 | 02b, 02c, 02e, 02f, 02h, 02i, 01g | update/delete without confirmation, without/with stale digest (current digest returned, no new lock file); summary decision; rename refused; empty update; membership update (new `snapshot_at`), keep summary, intent-/summary-only change; show = current only + history note; only the Preset file changed; delete leaves scope record byte-identical and loadable | 21 | Pass |
| TC-F-04 | C | integration | P0 | 01d, 01e, 03a, 03b | list/show/resolve/exit-preview (3 actions)/links (JSON + text) → Preset bytes, `snapshot_at`, whole tree identical; stored list used; rule updated after save → snapshot note + current availability | 9 | Pass |
| TC-F-05 | C | integration | P0 | 03b–03f, 02i, 02f | recompute with valid/invalid candidates → `+`/`-`/count diff, availability, digest, nothing written; invalid addition / missing summary / no confirmation refused; Preset edited or candidate rule changed → `STALE_RECOMPUTE` with new diff; additions-only subset; no-difference path (no write unless `reconfirm`); confirm that would empty → refused; no intent → `QUERY_INTENT_MISSING` | 18 | Pass |
| TC-F-06 | C | integration | P0 | 04a, 04b, 04c, 04i, 04j, 04k, 09e, 09g | `preset resolve` vs `policy resolve` of the same refs (same digest and entries); clue = `preset:web@<file digest>`; `preset scope-save` vs parallel plain `scope save` in a copy (same `created_at` → same id/bytes: observed True); later change/delete keeps record; look-alike user clue; malformed clue; add/remove/content drift → `STALE_CONFIRMATION`; summary/intent/`snapshot_at`-only change → save succeeds (known limit); mixed availability → `partial` | 25 | Pass |
| TC-F-07 | C | integration | P0 | 04e, 04g, 02g | `preset resolve --default`: absent → `no_default_preset` + Apply All step (nothing written); valid → highlighted notice, same Preset path, clues-mode save; malformed / schema-invalid / symlink / all-missing default → refused or `maintenance_needed`, repair-or-choose step, no Apply All; then explicit `policy resolve --all` works | 16 | Pass |
| TC-F-08 | C | integration | P1 | 04f, 08a | list name-sorted on 3 calls with summaries, no rank/score; malformed, schema-invalid, name-mismatch, deeply nested (100 000 `[`), linked Preset files and bad/deep/linked tag files → `invalid` with next step, show/resolve refused with restore/re-save step, no Policies proposed; dot-files and non-JSON ignored; good ones still work; nothing written | 14 | Pass |
| TC-F-09 | C | integration | P0 | 05a–05f, 07c, 02b, 02h | Maintainer tag save across two Local namespaces; Reference member refused; four 001-C reasons; tag changes leave Preset bytes and proposal digest identical; whole proposal identical with/without tags; tag-as-clue expansion → record holds only those refs, unaffected by later tag change; list/show availability read-only; Maintainer update/delete; knowledge/pending untouched | 20 | Pass |
| TC-F-10 | C | integration | P0 | 06a–06e, 06h, 01d | 2+1 Presets, 2+1 tags; deactivate/rename/delete/reactivate previews list exactly p1,p2 / t1,t2; unreferenced rule → explicit empty kinds, Reference cache not checked, text "(none)"; six add/change/remove deltas → `STALE_IMPACT`, nothing changed; confirmed rename/deactivate/delete → stores byte-identical; broken refs in `preset show`, `preset resolve`, `tag show`, `knowledge links` (`renamed_to` information only, never substituted); deactivate→reactivate restores availability, file unchanged | 22 | Pass |
| TC-F-11 | C | integration | P0 | 06f, 06e, 08a | malformed Preset/tag → unreadable findings bound into the impact digest (stale confirm); deeply nested files (review fix) → findings, no crash in preview/links/list; linked `tags/` store → one finding, not followed, preview/links not refused | 8 | Pass |
| TC-F-12 | C | integration | P0 | 02j, 06g, 06i | runner holds `flock` on `knowledge.lock`: six Preset/tag writes wait 10.3 s → `LOCKED`, nothing written, no new lock file; 8 real-process races (Preset create/update/delete, tag create × exit-first / write-first) via pause hooks: serialized, no deadlock (≈3.4 s each), exit-first → write refused `deactivated` (delete succeeds), write-first → exit `STALE_IMPACT`; scope records unchanged | 15 | Pass |
| TC-F-13 | C | integration | P0 | 02k, 08c | link at the Preset file, tag file, `presets/`, `tags/`, `x-ipe-docs/secure-code`, `x-ipe-docs` → every create/update/delete `PATH_UNSAFE`; project and outside trees byte-identical; injected failures at `temp_fsync`/`replace`/`dir_fsync` for Preset and tag updates → `IO_ERROR`, previous or new complete file, no temp left | 12 | Pass |
| TC-F-14 | C | integration | P0 | 06j, 09a, 06e, 04e | pre-001-F preview (`presets`/`tags` "not checked") confirmed by the current CLI → `STALE_IMPACT` once, re-preview step, nothing written; re-preview confirms; reports/scope/Preset files identical (with and without Presets); `policy resolve` clues/missing/`--all` (with and without default) JSON+text byte-identical pre vs post; parallel clues and apply_all scope saves pre vs post: same `created_at`, same id and record bytes; `knowledge links` JSON+text byte-identical pre vs post (empty stores, dot-temp only, stores absent); with a Preset file only `preset_tag_links` appended last | 17 | Pass |
| TC-F-15 | C | integration | P1 | 09f | Preset-based scope, Preset then deleted → `scope show`, Guard `open` (002-A), Copilot `open` (003-A) all succeed | 3 | Pass |
| TC-F-16 | C | integration | P0 | 07a–07d | trust folder moved aside (User): Preset save/update/recompute/recompute-confirm/delete succeed, knowledge/pending untouched; knowledge import/update `NOT_AUTHORIZED`; tag save/update/delete `NOT_AUTHORIZED` with "ask a Maintainer" first; tag list/show and tag-as-clue proposal write nothing; restored Maintainer tag writes succeed; Maintainer revoked while the tag write waits → re-check under lock `NOT_AUTHORIZED` | 15 | Pass |
| TC-F-17 | H | integration | P0 | 07c, 07d, 07a, 02g, 04e, 06e | never-authorized host User: tag writes `NOT_AUTHORIZED` (pre-lock check, nothing written); tag list/show; Preset save refused only by the reference check; `IDENTITY_INVALID`; `no_default_preset`; empty list + history note; links without `preset_tag_links`; lock-file behaviour vs. delivered 001-C (O-1) | 11 | Pass |
| TC-F-18 | C + H | structured-review | P0 | 02a, 03g, 04d, 04f, 04i, 04k, 09g, 05e, 07c, 01g, 04e, 06b | `SKILL.md`, `references/presets-and-tags.md`, `policy-selection.md`, `cli-contract.md` against spec wording; verbatim DAO-008 Q1 block (also found in the design on the host); DAO-007 (4) no-clues text; no stale "no Presets yet"/"Presets, tags, Reference cache"; every bound/verified/tamper sentence negated; 001-C 02e phrases kept; Copilot/Guard text has no Preset text | 17 + 17 | Pass |

C = container (Linux), H = host (macOS). Spec types "Unit" (02f, 02g, 03b, 08b) are verified here through the CLI and additionally by the delivered unit tests (`tests/presets/test_preset_units.py`, inside the passing full suite).

## AC → Evidence (all 66 rows)

Revision for every row: toolkit `ebe3ce44…` (full hash above), spec `e00d6721…`. Delivery states: **Pass** (current black-box/structured evidence, all clauses), **Superseded** (no test by spec), **Conditional-on-001-E** (only for a clause the spec defers). Outcome state for every row: **not measured**.

| AC | Assertion (short) | Evidence (TC → checks) | Delivery | Rev |
| --- | --- | --- | --- | --- |
| 01a | one JSON per Preset, fully qualified refs, no content/example/digest | TC-F-01 (5) | Pass | ebe3ce44 |
| 01b | dynamic selectors refused with reason, nothing written | TC-F-02 (7) | Pass | ebe3ce44 |
| 01c | intent + summary stored as given; `snapshot_at` = confirmation time with offset | TC-F-01 (2) | Pass | ebe3ce44 |
| 01d | list/show/resolve/exit-preview leave file byte-identical, `snapshot_at` unchanged | TC-F-04 (3), TC-F-10 (1) | Pass | ebe3ce44 |
| 01e | show states snapshot meaning, current availability per reference | TC-F-04 (3), TC-F-01 (1) | Pass | ebe3ce44 |
| 01f | `not_found`/`pending_decision`/`inconsistent`/`multiple_versions` refused, nothing written | TC-F-02 (2), TC-F-17 (1) | Pass | ebe3ce44 |
| 01g | current membership only; no-history statement; no history/backup file | TC-F-03 (3), TC-F-18 | Pass | ebe3ce44 |
| 02a | skill: Preset only on explicit request; list + summary first; save after confirmation | TC-F-18 (C+H) | Pass (structured) | ebe3ce44 |
| 02b | save/update/delete without confirmation refused, nothing written | TC-F-02, TC-F-03, TC-F-05, TC-F-09 | Pass | ebe3ce44 |
| 02c | confirmed membership update + new `snapshot_at`; metadata-only keeps both; no rename | TC-F-03 (4) | Pass | ebe3ce44 |
| 02d | existing (incl. case variant) identity refused with update/other-name step | TC-F-02 (2) | Pass | ebe3ce44 |
| 02e | delete removes file; scope records byte-identical and load | TC-F-03 (2) | Pass | ebe3ce44 |
| 02f | empty membership refused on save and update (and recompute confirm) | TC-F-02, TC-F-03, TC-F-05; unit tests in suite | Pass | ebe3ce44 |
| 02g | charset/separator/device names/case collision refused; `default` Preset-only | TC-F-02 (17), TC-F-01, TC-F-07, TC-F-17 | Pass | ebe3ce44 |
| 02h | missing/stale digest → stale with current digest, nothing written, no new lock file; match → locked atomic write | TC-F-03 (6), TC-F-09 (2), TC-F-12/13 | Pass | ebe3ce44 |
| 02i | membership change needs new or kept summary; kept → unchanged + "kept" | TC-F-03 (4), TC-F-05 (1) | Pass | ebe3ce44 |
| 02j | knowledge lock held > `LOCK_TIMEOUT` → `LOCKED`, nothing written, no new lock file | TC-F-12 (7) | Pass | ebe3ce44 |
| 02k | link at file/`presets/`/`tags/`/parents → `PATH_UNSAFE`, nothing written in/out, previous bytes | TC-F-13 (6) | Pass | ebe3ce44 |
| 03a | query never evaluated on list/show/use/preview; stored list used | TC-F-04 (2) | Pass | ebe3ce44 |
| 03b | executable intent never executed (stored or recomputed) | TC-F-01, 04, 05 (marker files never created); unit AST test in suite | Pass | ebe3ce44 |
| 03c | recompute: add/remove/unchanged, availability, digest, file unchanged | TC-F-05 (3) | Pass | ebe3ce44 |
| 03d | confirm with digest (subset) → exactly confirmed, `snapshot_at`; changed → stale + new diff | TC-F-05 (3) | Pass | ebe3ce44 |
| 03e | no difference → "unchanged", no `snapshot_at` change unless re-confirmed | TC-F-05 (2) | Pass | ebe3ce44 |
| 03f | candidates validated, invalid listed + excluded, diff/digest from valid only | TC-F-05 (3) | Pass | ebe3ce44 |
| 03g | skill: intent → candidates via read operations, recompute, diff, confirmation | TC-F-18 (C+H) | Pass (structured) | ebe3ce44 |
| 04a | considered = stored list; 001-C contract; Preset name/snapshot/summary; clue; unchanged digest | TC-F-06 (6), TC-F-14 | Pass | ebe3ce44 |
| 04b | per-reference availability, BR-11 status, file unchanged | TC-F-06 (3) | Pass | ebe3ce44 |
| 04c | unchanged 001-C path, clues record with generated clue + refs, digests; later change never alters it | TC-F-06 (3) | Pass | ebe3ce44 |
| 04d | skill: compare summary with task, explain + wait on clear mismatch | TC-F-18 (C+H) | Pass (structured) | ebe3ce44 |
| 04e | no clues + valid default → highlighted, same Preset path, clues save; no default → Apply All unchanged | TC-F-07 (8), TC-F-14 (byte-identical Apply All pre vs post), TC-F-17, TC-F-18 | Pass | ebe3ce44 |
| 04f | matching Presets name-sorted, no ranking, summary + mismatch, user picks | TC-F-08 (3), TC-F-18 | Pass (CLI + structured) | ebe3ce44 |
| 04g | unusable default → refused/`maintenance_needed`, repair step, no automatic Apply All | TC-F-07 (8) | Pass | ebe3ce44 |
| 04h | — | superseded by DAO-005 | Superseded | — |
| 04i | toolkit-generated clue, stored only as clue text; look-alike user clue ordinary | TC-F-06 (2), TC-F-18 | Pass | ebe3ce44 |
| 04j | reference add/remove or rule content change → `STALE_CONFIRMATION`, nothing written | TC-F-06 (3) | Pass | ebe3ce44 |
| 04k | metadata-only change → save succeeds, undetected (known limit, stated in skill) | TC-F-06 (3), TC-F-18 | Pass | ebe3ce44 |
| 05a | one visible JSON per tag, concrete members across Local namespaces, no content; Reference member refused `invalid_reference` | TC-F-09 (4) | Pass (Reference-source membership itself: conditional on 001-E, skipped unit test) | ebe3ce44 |
| 05b | member not resolving to one formal rule refused with 001-C reason | TC-F-09 (5) | Pass | ebe3ce44 |
| 05c | tag changes never change Preset membership/bytes | TC-F-09 (1) | Pass | ebe3ce44 |
| 05d | resolution identical with and without tags | TC-F-09 (1) | Pass | ebe3ce44 |
| 05e | tag clue expanded at proposal time; record holds refs; later tag change no effect | TC-F-09 (2), TC-F-18 | Pass (agent step emulated by runner + skill text) | ebe3ce44 |
| 05f | list/show members with availability, read-only | TC-F-09 (2) | Pass | ebe3ce44 |
| 06a | `presets`/`tags` kinds list exactly referencing files for all four actions | TC-F-10 (4) | Pass | ebe3ce44 |
| 06b | explicit empty lists; Reference cache still not checked | TC-F-10 (1), TC-F-18; 001-D superseded loop in suite | Pass | ebe3ce44 |
| 06c | Preset/tag add/change/remove after preview → stale, nothing changed | TC-F-10 (6) | Pass | ebe3ce44 |
| 06d | confirmed exits leave every Preset/tag file byte-identical | TC-F-10 (1) | Pass | ebe3ce44 |
| 06e | broken refs (owner, target, reason, `renamed_to` info) in show/resolve/links; never substituted; links byte-identical without Preset/tag files | TC-F-10 (5), TC-F-11, TC-F-14 (pre vs post, 3 variants + appended key), TC-F-17 | Pass | ebe3ce44 |
| 06f | unreadable/malformed file → finding in its kind, bound into digest | TC-F-11 (3) | Pass | ebe3ce44 |
| 06g | Preset/tag save vs exit confirm serialized either way | TC-F-12 (8 races) | Pass | ebe3ce44 |
| 06h | deactivate → reactivate: available again, same identity, file never changed | TC-F-10 (3) | Pass | ebe3ce44 |
| 06i | create/update/delete vs exit confirm serialized, no deadlock; 001-D unchanged except the plug-in | TC-F-12 (8), § Re-runs (001-D) | Pass | ebe3ce44 |
| 06j | pre-upgrade preview refused once stale, re-preview, nothing confirmed; history byte-identical | TC-F-14 (7, genuine pre-001-F preview) | Pass | ebe3ce44 |
| 07a | User Preset save/update/recompute/delete succeed; knowledge/pending untouched | TC-F-16 (3), TC-F-17 | Pass | ebe3ce44 |
| 07b | User knowledge import/update still `NOT_AUTHORIZED` | TC-F-16 (3) | Pass | ebe3ce44 |
| 07c | User tag writes `NOT_AUTHORIZED` + ask-a-Maintainer step, nothing written; Maintainer succeeds; toolkit-mediated only | TC-F-16 (5), TC-F-09 (4), TC-F-17, TC-F-18 | Pass | ebe3ce44 |
| 07d | User list/show tags and tag-as-clue proposal, nothing written | TC-F-16 (3), TC-F-17 | Pass | ebe3ce44 |
| 08a | malformed/schema-invalid/linked file refused with next step; no Policies; others work | TC-F-08 (10), TC-F-11 | Pass | ebe3ce44 |
| 08b | same content → identical bytes (key and reference order) | TC-F-01 (2; bytes compared apart from the `snapshot_at` value); unit test in suite | Pass | ebe3ce44 |
| 08c | interrupted save → previous or new complete version | TC-F-13 (6) | Pass | ebe3ce44 |
| 09a | `clues`/`apply_all` proposals, ids, record bytes identical to pre-001-F; schema/mode set unchanged | TC-F-14 (6, pre vs post byte comparison); fixture unit test in suite | Pass | ebe3ce44 |
| 09b | — | superseded by DAO-004 | Superseded | — |
| 09c | — | superseded by DAO-004 | Superseded | — |
| 09d | delivered 001-C/002-A/003-A suites unchanged and pass | full suite 2265/0 failed; `tests/policy`, `tests/guard`, `tests/copilot` byte-identical; 001-C/002-A/003-A black-box regressions byte-identical | Pass | ebe3ce44 |
| 09e | Preset-based scope = `clues` mode, no new field, generated clue, unchanged id rule | TC-F-06 (3; parallel plain save same id/bytes) | Pass | ebe3ce44 |
| 09f | `scope show`, Guard, Copilot load it, also after Preset delete | TC-F-15 (3) | Pass | ebe3ce44 |
| 09g | provenance only clue text; no bound/verified/tamper-evident claim in output or skill | TC-F-06 (3), TC-F-18 | Pass | ebe3ce44 |

Totals: 63 Pass (agent-behaviour rows 02a, 03g, 04d by structured review as the ACs require "instructions are inspected"; 04f/05e partly agent behaviour, CLI part executed), 3 Superseded, 0 Fail, 0 Blocked. The 05a Reference-source part is a deferred 001-E extension, not an open clause of v1.5.

## Re-runs at this revision (DAO-009 (3))

Runners are the unchanged earlier ones (001-D runner `93a13a31…`); results are new files in this folder; earlier evidence was not edited. All container runs on `fat-uv-git:py312` (same Python 3.12.12 / uv 0.9.30 as the `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` image used originally for 001-B/001-C/002-A).

| Item | Result | Reported as |
| --- | --- | --- |
| 001-D acceptance, container ([rerun-001D-container-linux.jsonl](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/rerun-001D-container-linux.jsonl) `f70eabc4…`, stderr empty) | TC-D-05…16 pass (12 cases); TC-D-01…04: 266/273 checks pass, the 7 failing checks are exactly the AC-001D-02b clauses asserting `presets`/`tags` = "not checked in this version" (TC-D-01 ×1, TC-D-02 ×3 incl. the compound reactivate check whose only `UNSUPPORTED` clause is that one, TC-D-03 ×1, TC-D-04 ×2 incl. the text check). Same check names as the original evidence; byte-identical to the TASK-069 re-run. Diagnostic: a scratch copy narrowing only those clauses to the Reference cache ([diag-001D-runner.diff](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/diag-001D-runner.diff)) passes TC-D-01…04 4/4 ([diag-001D-container-TC01-04.jsonl](x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/diag-001D-container-TC01-04.jsonl)) | TC-D-01…04 / AC-001D-02b: **superseded per AC-001F-06a/06b — re-run** (never a plain pass). Every other 001-D case: pass → **no 001-D defect** |
| 001-D acceptance, host (`rerun-001D-host-macos.jsonl` `1c1171cd…`) | 2/2; byte-identical to the original 001-D host evidence | TC-D-17 pass; TC-D-15 (AC-001D-06c skill text, SKILL.md L110–111 changed) **superseded per AC-001F-06a/06b — re-run**, passes |
| 001-D `test_exit_preview.py::test_empty_supported_not_unsupported`, `test_exit_skill.py`; 001-C `test_skill_package_describes_scope_selection` (02e) | pass inside the full suite | the first two **superseded per AC-001F-06a/06b — re-run**; 001-C 02e re-run (skill text changed, DAO-007 (4)) |
| Black-box regression 001-B (container/host) | 14/14, 1/1 — **byte-identical** to original (`5bca7a83…`, `259f5fb9…`) | pass |
| Black-box regression 001-C | 14/14, 1/1 — **byte-identical** (`03b11dd3…`, `3ef8a509…`) | pass |
| Black-box regression 002-A | 26/26, 2/2 — **byte-identical** (`404ada17…`, `b87e492e…`) | pass |
| Black-box regression 003-A | 11/11 (107 Copilot commands), 2/2 — **byte-identical** (`4b978585…`, `e2e89141…`) | pass |
| Full pytest suite incl. 001-B/C/D, 002-A, 003-A, 003-B carriers, module size | 2265 passed, 0 failed, 4 skipped | pass |
| `ruff check --no-cache` | clean | pass |

## Observations (no defect raised)

- **O-1 Knowledge lock file on first use.** On a project where the knowledge lock was never taken, a refused Preset save (e.g. `REFERENCES_INVALID`) and `preset resolve --default` create `.x-ipe/private/secure-code/locks/knowledge.lock` (and its folder) — exactly like the unchanged 001-C `policy resolve --all` (TC-F-17 compares both). No Preset/tag file, folder, temp or history file is written. The design states this exception (A4 "apart from the knowledge lock file that `session(write=True)` may create"; A3/A7 "lock file only"). Wherever the lock already existed (every container case) refusals left the tree strictly byte-identical. Classified as delivered lock behaviour, not a write of Preset/tag data.
- **O-2 `adoption` text of `preset resolve`.** The unchanged 001-C proposal field `adoption` still reads "…then: secure-code scope save --confirmed", while `next_steps` names `secure-code preset scope-save NAME --decisions FILE --confirmed` and the skill instructs `preset scope-save`. A direct `scope save` stays an ordinary 001-C clues save (DAO-006 (1), AC-001F-04i); keeping 001-C keys unchanged is a design constraint (BR-11). Possible future polish only.
- **O-3 Timezone offset.** The container runs in UTC, so `snapshot_at` carried `+00:00`; a non-UTC offset was not exercised black-box (no Maintainer-free successful save on the macOS host because the host has no knowledge).

## Honest Limits

- Tag writes are Maintainer-only **through the toolkit only** (toolkit-mediated); there is no filesystem-level protection (001-A / U-13). TC-F-16/17 test the toolkit path only.
- A metadata-only Preset change (summary, intent, `snapshot_at`) between proposal and save is **not detected** — asserted as behaviour (TC-F-06) and stated in the skill (TC-F-18). The provenance clue is information-only text, not bound, not re-checked, not tamper-evident.
- No Preset/tag history beyond version control (TC-F-03, TC-F-18).
- Reference-source tag/Preset membership waits for FEATURE-001-E (unit test skipped; black-box shows the `invalid_reference` refusal).
- Agent-behaviour clauses (02a, 03g, 04d, 04f offer, 05e expansion) are verified by structured review of the instructions plus the CLI support they rely on; no real agent session was run.
- The pre-001-F revision used for 06e/06j/09a/04e is a hash-verified reconstruction, not the historical build. Windows path rules are not verified (Linux container and macOS host only).
- **Stakeholder outcome: not measured.** All evidence is engineering delivery evidence.

## Decisions Needed (DAO mode — none blocking acceptance)

1. **Routing (owner):** acceptance found no failing or partial AC and no evidenced quality/preservation problem (modules < 800 lines, ruff clean, suite green). Per the conditional successors: `x-ipe-task-based-code-refactor` only if the owner sees a quality need; otherwise `x-ipe-task-based-feature-closing`, subject to the actual app/workflow gates (free mode here; the owner persists status/board).
2. **O-1 (optional confirmation):** accept that "nothing is written" in 01b/01f/02f/02g refusals and in the default branch excludes the delivered knowledge lock file on first use (as already stated in design A3/A4/A7).
3. **O-2 (optional, human):** whether a later CR should make `preset resolve`'s `adoption` text name `preset scope-save` (would touch a 001-C-owned field; not needed for any v1.5 AC).
4. **Housekeeping (owner):** the TASK-069 docker volume `fat-uv-cache-001f` still exists (not created by this task; left untouched). This task's volume `fat-uv-cache-001f-fat` was removed.

## Cleanliness and Input Re-verification (end of task)

- Toolkit file-list hash after all runs: `ebe3ce4491f1248bb07f7fcf6ac00fadfd979407c7bfd7fb10baec37ee7bb521` (222 files, same method) — unchanged; no `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage` under `ai-secure-code-toolkit/` (`.venv` excluded).
- Spec `e00d6721…`, design first 585 lines `353b0f30…`, DAO records `03828e43…` / `d7708266…` unchanged.
- Disposable projects, temp folders and the uv cache volume removed; marker files of the never-executed intent never existed.

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
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/acceptance-test-report.md"
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/blackbox.py"
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-container-linux.jsonl"
    - "x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/evidence-host-macos.jsonl"
  feature_id: "FEATURE-001-F"
  feature_title: "Presets & Tags"
  feature_version: "v1.5"
  feature_phase: "Acceptance Testing"
  test_types_tested: ["integration", "structured-review"]
  test_cases_created: 18
  tests_passed: 18
  tests_failed: 0
  tests_blocked: 0
  pass_rate: "100%"
  results_by_type:
    frontend_ui: {passed: 0, failed: 0, blocked: 0}
    backend_api: {passed: 0, failed: 0, blocked: 0}
    unit: {passed: 0, failed: 0, blocked: 0}
    integration: {passed: 17, failed: 0, blocked: 0}
    structured_review: {passed: 1, failed: 0, blocked: 0}
```

`unit` is 0 as a black-box case type; the spec's Unit-typed ACs are covered by CLI cases plus the delivered unit tests in the passing suite. Free mode: no board/app status was written; the owner persists the Tested transition if appropriate.

## Addendum — Closing-Review Fix (TASK-071, 2026-10-23, appended by Sage; evidence above unchanged)

After acceptance at `ebe3ce44…`, the closing review found that a non-UTF-8 file name in `presets/`/`tags/` crashed exit preview/confirm on Linux. Fixed in `knowledge/catalog.py` (`824b5106…`) with a new unit test; supplementary black-box check with real raw-bytes file names in the offline Linux container: `closing-fix-nonutf8-container-linux.jsonl` (TC-F-CLOSE-01, AC-001F-06f/06e/08a, 5/5 checks Pass; runner `closing-fix-nonutf8_check.py` reuses `blackbox.py`). Full suite 2266 passed / 0 failed. New toolkit file-list hash `c8da9c6f…`. Only one 001-F product module and one 001-F test changed; all other acceptance evidence stands.

Final delta (closing re-review Minor): non-POSIX surrogate fallback added to the same helper; unit-tested; full suite 2271/0; final toolkit file-list hash `0358fd09…`. The POSIX path checked by `closing-fix-nonutf8-container-linux.jsonl` is unchanged.
