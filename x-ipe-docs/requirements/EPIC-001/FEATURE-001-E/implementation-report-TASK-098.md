# Implementation Report — FEATURE-001-E Reference Knowledge Exploration & Cache

> Feature: FEATURE-001-E (EPIC-001) · Task: TASK-098 (Code Implementation, TDD; resumed after a crashed worker) · lifecycle owner Sage, implementation worker · Date: 2026-10-24
> Mode: free mode, workflow N/A; no board, memory, Git write or successor action was taken by this worker (owner exclusions). Git: read-only `git status`, `git diff`, `git show HEAD:<path>` and `git log` only (`git show` output was used to restore delivered bytes temporarily for RED runs; every restore was reverted and re-hashed).
> Scope: all 81 ACs (AC-001E-01a…09b) of specification v1.1.2 (wording refresh r1), technical design v1.2, rulings DAO-018/019/020 (refinement), DAO-020/021/022 (technical design), human B4 = B, B14 = No, P6 = A (2026-10-24, Step 8 released), B16 = B, P-01 = A (parked).
> **Final state (re-review PASS-WITH-NITS, nits applied; DAO-008; §12 is authoritative):** full suite **3502 passed, 0 failed, 7 skipped** at the final hashes; ruff clean; 267 tests in `tests/reference/`; DEC-I17 approved (erratum E3).
> Previous state (§11): review PASS-WITH-FIXES, both fixes applied RED-first; DEC-I04/I05 maintenance applied; DEC-I06 ratified (erratum §11.5). Full suite **3501 passed, 0 failed, 7 skipped**; ruff clean; 266 tests in `tests/reference/`.
> Initial delivery result (kept for history): **Result:** Engineering delivery of FEATURE-001-E: **verified** for all 81 ACs by 262 new tests (`tests/reference/`, all green) plus the 7 superseded delivered assertions re-run green. Full suite **3495 passed, 2 failed, 7 skipped, 23 deselected** (`log-full-suite.txt`, 37 min). **Regression: blocked by 2 STOP-rule findings** (DEC-I04, DEC-I05): two delivered hash/closed-list guards of other features (001-G `test_08a`, 002-F `test_closed_list_diff`) fail only because of the approved 001-E changes; they were **not edited** (outside the closed list and outside the authorized payload maintenance). One design-means deviation needs ratification (DEC-I06: the loopback GET client lives inside the delimited P6 block of `egress.py`, because a delivered 002-C test forbids network clients in any other module). Stakeholder outcome: **not measured**.

`FW` = `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework`; `EV` = session evidence folder `files/impl-098/` (logs, diffs, hashes, temporary trees — nothing in the repository).

## 1. Authoritative Inputs (verified before any change and re-hashed at the end)

| Input | Expected | Found (start and end) | Match |
| --- | --- | --- | --- |
| [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-E/specification.md) v1.1.2 (r1 wording refresh, DAO-022) | `4c8bba35…` | `4c8bba359cccb4dbe02dd8d8dc5c15cc3d332dd8159f25239012072158a4ce3b` | yes |
| [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-E/technical-design.md) v1.2 | `b6b2806f…` | `b6b2806f28d09aeacb5cc19d277f4ccb48cf06ef830c316dafe6761797decf74` | yes |
| `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` DAO-020/021/022 | read | DEC-01…18 approved with conditions; closed list items 1–7; DAO-022 authorizes the spec wording refresh | — |
| `decisions_made_feature_refinement.md` DAO-018/019/020 | read | — | — |

The design binds spec `1bed3228…`; the current spec `4c8bba35…` is the DAO-022-authorized wording-only refresh (header version line, traceability ranges 07a…07k; no AC text change) — DEC-I01. The specification file is local-only; this report refers to the excluded content only as "the internal policy namespace".

## 2. Resume Verification and Step 0/1 Baselines

- `EV/baseline-step0.sha256` (368 delivered files at HEAD `73fe2dc`) re-verified at resume: **all OK** — the crashed worker had changed no delivered file. At the end exactly the 16 files of §4.1 differ.
- `EV/closed-list-before.sha256`: the four closed-list files equal the design "before" hashes (`49c61bce…`, `6e7a84c9…`, `b4f1832b…`, `414820a3…`).
- `EV/manifest-p6-before.sha256` (egress.py + `tests/guard/` + `tests/adapters/`) re-verified before Step 8; at the end only `src/x_ipe_secure_code/guard/egress.py` differs (all 002-C/002-D test files byte-identical).
- Pre-001-E golden fixtures (`tests/reference/fixtures/golden/pre001e/`, DEC-08/09/14) were captured by the crashed worker; their `MANIFEST.json` source digest `a8a92d6c…` was recomputed from the HEAD `73fe2dc` source tree with the same formula: **equal** — the goldens are from the delivered code.
- Owner-supplied baseline: 3234 passed / 8 skipped.
- Reused crashed-worker work, verified: `reference/__init__.py`, `clock.py`, `urls.py`, `parse.py`, `registry.py` (Step 2 RED 74 failed → GREEN 74 passed, logs present), `cache.py` (written ahead of its tests — see Step 4), test helpers `refhelp.py`, `netguard.py`, `capture_golden.py`, fixture pages, Step 2 tests and the Step 3 registry tests (RED 29 failed logged). One new-test arrange bug fixed (project init creates the empty registry folder; the symlink case now removes it first).

## 3. TDD Steps — RED / GREEN

All runs from `FW/scripts`: `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=$EV/tmp-<name> …`, `TMPDIR=$EV/tmpdir`. Loopback-only network; no downloads.

| Step (design §Implementation Steps) | RED (fails for the right reason) | GREEN |
| --- | --- | --- |
| 1 Baselines/goldens | — (captures, verified above) | — |
| 2 Pure core (urls, parse, clock) | `log-red-step2.txt` 74 failed (modules missing) | `log-green-step2.txt` 74 passed |
| 3 Registry, CLI parser, service reads, P7 status | `log-red-step3.txt` 29 failed | `log-green-step3.txt` 28 passed (+1 waiting for Step 5, green there) |
| 4 Cache | `log-red-step4.txt` 20 failed — `cache.py` (pre-written by the crashed worker) held aside in `EV/hold`, restored unchanged | green with Step 5 |
| 5 Resolution P1 (`policy_view.py`, `resolve.py` hooks) | `log-red-step5.txt` 30 failed / 5 passed with HEAD `resolve.py` restored temporarily | `log-green-step5.txt` 138 passed; delivered `tests/policy` + status 158 passed (`log-p1-policy.txt`) |
| 6 Plug-ins P2–P5 + closed-list items 1–4, 6, 7 | before the edits exactly the closed-list tests failed (`log-step6-before-edits.txt` 9 failed / 789 passed); `log-red-step6.txt` 17 failed / 5 passed with HEAD `impact/exit/catalog` | `log-green-step6.txt` reference + knowledge + presets + policy 1095 passed, 1 skipped |
| 7 Framework skill text + item 5 | `log-red-step7.txt` 4 failed / 9 passed with HEAD skill/references | `log-green-step7.txt` 466 passed |
| 8 Gate (P6 released by the human, P6 = A) | `log-red-step8.txt` 106 failed / 4 passed / 1 error with HEAD `egress.py` and no `fetch.py` | `log-green-step8.txt` `tests/reference` + module size 263 passed |
| 9 Full run | — | `log-full-suite.txt` 3495 passed, 2 failed (STOP-rule findings §5), 7 skipped |

No assertion was weakened, skipped or marked xfail; the conditional delivered test `test_tag_members_across_local_and_reference_sources` now runs and passes (skipped 8 → 7).

## 4. Files

### 4.1 Changed delivered files (16; design change list + closed list + authorized payload maintenance)

| File (FW-relative) | Before (HEAD 73fe2dc) | After |
| --- | --- | --- |
| `SKILL.md` | `3fc74164bc3fa3f9ada83cf11df86bdde088570f727d3dcdfde1cbc152607c80` | `774e642d9682ac5f4750399c80aec7f0f2dcdd48cad92b9ddac223aeea7dc91b` |
| `references/cli-contract.md` | `eda7bd6299a1e2d730bb7b50c52d1eafbd69db280e0db71886bef9572733e4f6` | `930fd035f451e920a9ad04623ae4304de2cfeaefcc7590b085a3e999417d7885` |
| `references/presets-and-tags.md` | `6d4df848809fba768a44a03a759e5d7e31714e438b1316a4a5a2f068477f539e` | `42dff964a2d5c3ae0222b6241e54d45d9ca8c375844e8bd9935c199068d9e7f4` |
| `scripts/src/x_ipe_secure_code/cli.py` | `4f0d63ac5f0b4a0dd88a42f6e463cac5f80c8fa683478acd7d947e2c35e8d0e1` | `f33ea766b59fd396af6cfba6c9939a1f7f32437d06795b9c9a41b776c32caf1f` |
| `scripts/src/x_ipe_secure_code/guard/egress.py` | `836f8b36a35b6418b354a467b1d53c96dfd288606b3bb4a9400d64afbc2ee7bc` | `8ebb3b76681c3dcc7710ae4d5bf38e5a64b543822ad8b107157434b5a451bdd2` |
| `scripts/src/x_ipe_secure_code/knowledge/catalog.py` | `a21a34d342c53f0419291b36e617eba7dcb62ffc2966dc2009be57341fd1f1d3` | `c81fa20db680198430f16717151e9fde8af01df89fa5816d09c8d35b3bf23742` |
| `scripts/src/x_ipe_secure_code/knowledge/exit.py` | `165b78658c361281517e6e899340c864d47d8692bc445ab1f9d6a6904c4906f2` | `91afb99e8b72fc0cb5561fc46ce2f74323ae3fa2fd51715be337aa9dc28218ca` |
| `scripts/src/x_ipe_secure_code/knowledge/impact.py` | `906c4562f13f8aeb906bdef30a8aacbdfbb2b8c5fb5cd4d65fcf3f575c5ba128` | `6c18b768cbfbaf8794cec3d04c960ff4dda8fdecf0d746ce2640b437f62bd473` |
| `scripts/src/x_ipe_secure_code/policy/resolve.py` | `f1dcdd6e3afb9e58388b0de3bd30681ca242d7973eabe922c6cf3794def80f6d` | `4d90e5500f844a6e32a6af7fd2d9df1ee00326c97174c586c15ba3fd392fbd60` |
| `scripts/src/x_ipe_secure_code/status.py` | `10df3fedb25f94448f593c18d8fba691dea85545476792c9f2d773fd29bf146e` | `b15b32184193ab034190fd3e627e0dc9a0b45aec8b4eddf40fcf2d3253002f42` |
| `scripts/tests/carriers/carhelp.py` | `b001244e5fa4a60a37f251117888657a8b7cdc20d4cecd0742609f3c3edb076e` | `770a0b9f0b9ecb56e7b0418cba146caa29ca3ba9e1d50f83b755b77c4b0e001d` |
| `scripts/tests/drafting/drafthelp.py` | `c96b5c72ecd4aafb0cefc45c6bf678a809519b7c535b3b2d7a46e93010641837` | `452e2ef92bb84462f820ded97da2f9d6406908a3fae0ec4e380febea1ab3d8e4` |
| `scripts/tests/knowledge/test_exit_preview.py` | `49c61bce4683dde90fd45294f4ed7598368c6b50d92a3203809f0bfc139104b5` | `c4b475ff2b46aaf499d13cb387798ad3c87c6bae334ad03ff81fcc6b49a69ef3` |
| `scripts/tests/presets/test_preset_impact.py` | `6e7a84c939ab23322c9397c75d62ddf275175cbb85650d380481ea30a461872f` | `bf82f4c30e373d88555ffcebd8ebc27d236e1422bfea4458cc357dbad9c4e9de` |
| `scripts/tests/presets/test_preset_skill.py` | `b4f1832bc93c5e8b4392e89c1476f3d39b96eca7dc2436ce9f0d023e8941fd4b` | `447ed018799e246c460740f50e4e34aecaf3b13dd2edcada156b4df9104f3665` |
| `scripts/tests/presets/test_tags.py` | `414820a3ca7c66b8c9fc9b851408af70eb18a7d1816cddd583a3d6e2ba05cf41` | `572f6790dba5a1890e481f42077a68e8ed538d644f76c3ab95c1d00654ba0721` |

- Product: `cli.py` (+ `knowledge reference` parser registration and dispatch), `status.py` (P7 field only when Reference rules exist), `policy/resolve.py` (P1: `Library.refs/now`, `evaluate` wrapper around the unchanged `_evaluate_local`, version union, `reference:` prefix, candidate kinds, Apply All + `library_sizes`/`counts_by_kind`, Reference next steps), `knowledge/impact.py` (P2: `UNSUPPORTED = ()`, `reference_cache` provider last), `knowledge/exit.py` (P2: invalidation at confirmation after the authorization re-check, before the journaled commit), `knowledge/catalog.py` (P4: registered `reference:` members stored `{rule, source: reference}`), `guard/egress.py` (P6: one delimited additive block; removing it restores `836f8b36…`).
- Framework text: `SKILL.md` items 1–4, `references/cli-contract.md` item 6, `references/presets-and-tags.md` item 7 (design §Framework Skill Text Changes).
- Closed list (DEC-13): items 1–2 `test_exit_preview.py`, 3, 4, 7 `test_preset_impact.py`, 5 `test_preset_skill.py`, 6 `test_tags.py`; each line carries `# superseded per AC-001E-07a|07c — re-run` (own line where inline would exceed 110 columns). Diffs `EV/closed-list-step6.diff`, `EV/closed-list-step7.diff`; after hashes `EV/closed-list-after.sha256`.
- Payload maintenance (owner-authorized, DAO-023/024 precedent): `tests/carriers/carhelp.py` `ERA_001A_REMOVED` + exactly the 12 new payload paths; `tests/drafting/drafthelp.py` `NEW_PAYLOAD` + exactly the 11 new `src/` paths (the new `.md` cannot be expressed there — DEC-I04). Diffs `EV/carhelp.diff`, `EV/drafthelp.diff`.

### 4.2 New files

| New file (FW-relative) | SHA-256 |
| --- | --- |
| `references/reference-knowledge.md` | `2a619aeb46d6e27ce9992ae12de922f7dde91e1bf66ad2da23e85becaf568d02` |
| `scripts/src/x_ipe_secure_code/reference/__init__.py` | `0111ed36b340957afb2501d6f0d8d390ac6e84296eca97c4c12a9a3284c4369d` |
| `scripts/src/x_ipe_secure_code/reference/cache.py` | `62d7e264335187ea993694098d0a4e5c1b2e7f81ce6a5b05777acc9d5ed22634` |
| `scripts/src/x_ipe_secure_code/reference/cli_parser.py` | `bddb25f946ae69e5ddf4bb98347e70ceb0880783942ea6e5a5e30ee7bdd39307` |
| `scripts/src/x_ipe_secure_code/reference/clock.py` | `a1e950344e5e07d1de386975118d1da212681d5293384d4e1a72410003d16545` |
| `scripts/src/x_ipe_secure_code/reference/fetch.py` | `eacda3ec41155646cd16fb4dd5118730b3b5edcf9f6bf889d18412f6d8627dd2` |
| `scripts/src/x_ipe_secure_code/reference/parse.py` | `f6fe9a699ad09ae12c8a45d2d77cc8a65a1c7f8bbc2152e2052bd5b8d212a4ae` |
| `scripts/src/x_ipe_secure_code/reference/policy_view.py` | `0a7b620a151385c26a95d86910e40bb77bf754e0dd601a36801e8a65ae505785` |
| `scripts/src/x_ipe_secure_code/reference/registry.py` | `49bb79a7459c9ad529219bfe6275c2c078294e6573c1136a81f88e3831010371` |
| `scripts/src/x_ipe_secure_code/reference/registry_ops.py` | `fff5155d8660ba06fad8878a09d1f4b713c3f6e67acdc4e6634dd5eecea80225` |
| `scripts/src/x_ipe_secure_code/reference/service.py` | `1f23ffc5d66cd689e648591e192b4636341e904ac8b29439dabca98fed7f1228` |
| `scripts/src/x_ipe_secure_code/reference/urls.py` | `ab3b4a532c93735dec4875ea457b9c9ff4c51c84bc5a163efa0ee0474257193f` |
| `scripts/tests/reference/capture_golden.py` | `b0e537ff17676063e2007688f4294d7a1a6cfbf8623c7a6b4ecb9ab93c74ded7` |
| `scripts/tests/reference/fixtures/golden/MANIFEST.json` | `0918b9c3eadafb9143e586b20d6db2a516e0696b21f76aeb8766140f9f26a7d4` |
| `scripts/tests/reference/fixtures/golden/pre001e/exit-preview.json` | `b59568941a8b8f49d84874eb3766b415a98228ad3c60d5f8038416d2c85f5f58` |
| `scripts/tests/reference/fixtures/golden/pre001e/preset-resolve.json` | `09a1017610501e16fd51b91642907bb69ac0c03379abd38ec5f9622ef06d6837` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-all.json` | `c6bef4421fa72068a60ca0cdd084e98f50fac5a2534c0597156ae922a5ee2876` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-rules.json` | `c8b8c8babb0403562831d9889277b7d33d0e233b9011a904dfade5e570305509` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-versionless.json` | `86deb261979709abcbd515f232461629197c6021c88eb86a05889631efa11eda` |
| `scripts/tests/reference/fixtures/golden/pre001e/scope-save.json` | `6ff0055693fc8442f61f01c39f70fe230dc98dfca538add7883882ee34cb97ae` |
| `scripts/tests/reference/fixtures/golden/pre001e/scope-show.json` | `a4a8afd8a3697316bdf0424ce346f7164bde81d0ab5b3e012d1d285630f9be38` |
| `scripts/tests/reference/fixtures/golden/pre001e/status.json` | `a47f7e10808cc429def77184795879f77146ebb683ea972e0c086ecf0f839b87` |
| `scripts/tests/reference/fixtures/golden/pre001e/tag-show.json` | `ecb22fc8e7ee0839b11b1ec086bff6716a1d3316fd5f3853995faac273dc22d1` |
| `scripts/tests/reference/fixtures/pages/credentials.html` | `dc5eaf17dc01e2aef4d886617bb88758ab2edd251baff93ffac4e60fd6c0e521` |
| `scripts/tests/reference/fixtures/pages/cwe-79-nav-changed.html` | `01b086b658a4944733595d430d9424834464a8e81d69e87778792256438200a1` |
| `scripts/tests/reference/fixtures/pages/cwe-79-req-changed.html` | `402c0b1944e173f17a4369bad5e3b423884dcc923b5eb4d9b539e9532b51ed8e` |
| `scripts/tests/reference/fixtures/pages/cwe-79.html` | `4632315e510f7786ff2f158e3986211991f12d1b9fbb766d2b86b6f7214357af` |
| `scripts/tests/reference/fixtures/pages/cwe-89.html` | `44fba0298d6abc1162a4c6373746ca246ad442beb677151c0a57e1fd05b50bd4` |
| `scripts/tests/reference/fixtures/pages/cwe-top25-list.html` | `8ba9cfabcbbbf4cb982c0d55d78843a6a3edb88cb479c2a815674eca2e5c6fcd` |
| `scripts/tests/reference/fixtures/pages/hidden.html` | `774de649475925add8f20e70064bc1bbd0e20a2df6b994ae5cc2349c6ca48a75` |
| `scripts/tests/reference/fixtures/pages/injection.html` | `01bf54827fce47cbff8582c1c1563a7513a23461ba15a58da0beb01dd72642d1` |
| `scripts/tests/reference/fixtures/pages/latin1.html` | `f6f67bf08b1f3bc83fc4b9d2f5477a658b400588a22eb6a072244e8609db03c7` |
| `scripts/tests/reference/fixtures/pages/nav-only.html` | `bedc68e1c30a6bdfdad4dcfd9621f01652775e375031f8c6f27a137fa9bb5b40` |
| `scripts/tests/reference/fixtures/pages/owasp-2025-a01.md` | `9d1069fac4c0669a57e4a4804cdbdb40ffedc157a609ae12be51baaab6b59a8d` |
| `scripts/tests/reference/netguard.py` | `2f5817892bab821aad2b8044e2926ad83b36c0edd804dcf8b629bd0c3ab6635d` |
| `scripts/tests/reference/refhelp.py` | `7b160262a5f8d27ee3e558ae908dc1c24c9e8a2f887864ef991d753247bdc0c7` |
| `scripts/tests/reference/test_reference_cache.py` | `d421b114bb6da92214803f5fd5fde6d9b6a742ee290844cd671649b76e735810` |
| `scripts/tests/reference/test_reference_e2e.py` | `cf8fe7045ac5d120376c5af987d9ec7a74bd1e03d8df76b6e2fb832af3799994` |
| `scripts/tests/reference/test_reference_fetch.py` | `b11fc78412a213d79d92de29ee6a48f1dfacda3a894b9a26ee8f31ae8a11d18b` |
| `scripts/tests/reference/test_reference_gate.py` | `be50c47fd5639abe4a93f9a03a4d2851f95fff6e5fb1cbb950f1f37fa11057f9` |
| `scripts/tests/reference/test_reference_isolation.py` | `2d1c8b88f149cbe3982ceffa28eb47ed72c0d42c3da100a716899199362d59d7` |
| `scripts/tests/reference/test_reference_parse.py` | `f66b77489485a1a6b5958975bc65e2672475943d3d4757866b0aa2113698c49c` |
| `scripts/tests/reference/test_reference_plugins.py` | `f52b7c2100764c273e056b07afe447069cecee27ebf6d96be43d1a3644a8a3a8` |
| `scripts/tests/reference/test_reference_registry.py` | `d58e27e00655005e27cf40d7aca5a7d6cca6596091272adaf332b05dbe1ef77a` |
| `scripts/tests/reference/test_reference_resolve.py` | `d2bd74a24f319d0a6d6dab0cfca038f418855815744887bd91796b5649e76322` |
| `scripts/tests/reference/test_reference_skill.py` | `6e3f1b1efd672f696fd2154d22481d1dc64140e33a730595561b7db340c611d5` |
| `scripts/tests/reference/test_reference_urls.py` | `6f778961fbc4e642a736a8c867b84aad7bf04d4a1367787eb53f95d1d7213c59` |

Module sizes (800-line rule, `tests/test_module_size.py` green): `registry_ops.py` 782, `cache.py` 551, `fetch.py` 547, `parse.py` 396, `registry.py` 282, `service.py` 271, `urls.py` 217, `policy_view.py` 136, `cli_parser.py` 121; `egress.py` 461 → 640, `resolve.py` 442 → 515, `catalog.py` 633 → 662.

## 5. Delivered-File Parity and STOP-rule Findings

Parity: P6 manifest — only `egress.py` differs; block-removal SHA-256 = delivered `836f8b36…` (test `test_egress_block_removal_restores_delivered_hash`); all `tests/guard/` and `tests/adapters/` bytes unchanged and green. Local-only outputs byte-identical to the pre-001-E goldens except the documented `reference_cache` impact kind and therefore the exit `impact_digest` (`test_local_only_outputs_unchanged`).

### STOP-rule findings (not edited; ruling needed)

1. **DEC-I04 — 001-G `tests/drafting/test_draft_regression.py::test_08a_delivered_suites_unchanged_and_outputs_equal_pre_001g`.** Its first assertion hashes 54 delivered 001-A/B/C/D/F test files (`tests/drafting/fixtures/delivered_tests_001abcdf.json`) and fails for the four approved closed-list files. A probe outside the repository (`EV/probe08a/`) shows that after a rebaseline two more of its parts would differ, both consequences of approved 001-E changes: `pre_001g/exit-preview.json` (`reference_cache` dict instead of "not checked in this version", new `impact_digest`) and `pre_001g/init.json` (new payload file `references/reference-knowledge.md`, which `NEW_REFERENCE` — a single string — cannot filter). Needed (owner/DAO/human): rebaseline 4 hashes in that fixture, rebaseline the 001-G exit-preview golden, and let `drafthelp` filter the new reference document (e.g. a tuple of new references). Its own maintenance point (DAO-004 DEC-I13) requires approval; this task was authorized only for `ERA_001A_REMOVED`/`NEW_PAYLOAD`.
2. **DEC-I05 — 002-F `tests/helpers/test_helper_boundary.py::test_closed_list_diff`.** It compares 291 delivered files with its 002-F step-0 baseline and allows only 002-F's closed list; every file 001-E is designed to change (10 product/docs files, 4 closed-list tests, `drafthelp.py`) is reported. Needed: a ruling to scope that guard to 002-F's own change window (or rebaseline it), as was done for the 002-G guard under DAO-023/024.

Neither suite is in the design's re-run plan; the design rule "any delivered test outside this list that fails → stop, report to the owner → human CR decision" applies. Implementation of the remaining authorized steps continued without touching these files.

## 6. Validation

| Check | Command / evidence | Result |
| --- | --- | --- |
| New tests | `pytest tests/reference tests/test_module_size.py` (`log-green-step8.txt`) | 263 passed |
| Full suite | `pytest` (`log-full-suite.txt`, 22:29–23:06) | 3495 passed, **2 failed (DEC-I04, DEC-I05)**, 7 skipped, 23 deselected; the known-flaky `test_draft_cli_approve::test_02e` passed |
| Lint | `UV_OFFLINE=1 uv run --offline ruff check --no-cache src tests` | All checks passed (new modules/tests formatted with `ruff format`; delivered files not reformatted) |
| Coverage (new code) | `pytest --cov` on `tests/reference` + `tests/presets/test_tags.py` (`log-coverage.txt`, data in `EV/cov/`) | `reference/` ≈ 91% (81–100% per module); `egress.py` 80% (incl. untouched POST code); `resolve.py` 84% |
| Guards | autouse `netguard` in every `tests/reference` module | 0 resolver calls, only `127.0.0.1` connects, 0 processes from fetch stacks (asserted at teardown of every test) |
| Repository hygiene | `git status --short --ignored ai-secure-code-toolkit` | only the 16 changed + new files; ignored: the pre-existing `.venv/` only (no caches, coverage files or bytecode) |
| Forbidden words | case-insensitive search of every written file for the three excluded names | none |

**Delivered acceptance re-run (labels per design, never "pass" alone):**

| Suite | Result | Label |
| --- | --- | --- |
| 001-A status (`tests/test_status*.py`) | pass unchanged | superseded per AC-001E-07i — re-run |
| 001-B knowledge (`tests/knowledge/test_knowledge.py`, `test_units.py`) | pass unchanged | P8: re-run (no supersession) |
| 001-C policy/scope (`tests/policy`) | pass unchanged | superseded per AC-001E-07e — re-run |
| 001-D exits (`tests/knowledge/test_exit_*.py`) | pass with closed-list items 1–2 | superseded per AC-001E-07c/07d — re-run |
| 001-F Presets/tags (`tests/presets`) | pass with items 3–7; conditional test runs and passes | superseded per AC-001E-07a/07c — re-run |
| 002-C / 002-D (`tests/guard`, `tests/adapters`) | pass; manifest hashes identical | re-run unchanged (AC-001E-04m) |
| 003-A Copilot (`tests/copilot`) | pass unchanged | superseded per AC-001E-07h — re-run |
| Module size | pass | — |
| Outside the plan: 001-G drafting, 002-F helpers | 1 failure each | STOP-rule findings DEC-I04/I05 |

## 7. AC-to-Test Traceability (all 81 ACs; files under `tests/reference/`)

| AC | Test(s) | State |
| --- | --- | --- |
| 01a | `test_reference_registry.py::test_register_source_and_rule_formal_no_body_status_line` | verified |
| 01b | `…registry.py::test_registry_writes_need_maintainer[5 ops]` | verified |
| 01c | `…registry.py::test_registration_identity_collisions_refused[exact,case,exited]`, `test_source_collision_and_case_variant_refused` | verified |
| 01d | `…registry.py::test_rule_entry_url_outside_domains_refused` | verified |
| 01e–01h, 01n, 06d | `test_reference_urls.py` (label boundary, IDNA, registration refusals incl. `127.0.0.1.`, port, path prefix, canonical refusals, trailing dot) | verified |
| 01i | `test_reference_gate.py::test_redirect_not_followed_no_location` | verified |
| 01j | `test_reference_urls.py::test_address_class_validator_injected`, `test_reference_isolation.py::test_validator_unreachable_from_fetch_path` | verified |
| 01k | `test_reference_fetch.py::test_explore_links_classified_not_followed` (incl. `#section`) | verified |
| 01l | `test_reference_resolve.py::test_registration_change_invalidates_cache`, `test_reference_cache.py::test_commit_registration_changed_or_superseded` | verified |
| 01m | `test_reference_fetch.py::test_real_domain_parked_production_path_guards` | verified |
| 02a–02h | `test_reference_resolve.py` (Local wins, Reference-only cached, no cross-version + version-less unclear with kinds, broken Local [4], prefix, mixed partial + counts by kind, all with separate sizes, pending label) | verified |
| 03a–03c, 03h–03k | `test_reference_cache.py` (entry fields + digest exclusions, reads never renew, expired [7d, 8d], invalid [4], key mismatch, clean, capacity) | verified |
| 03d–03g | `test_reference_fetch.py` (refresh of expired, digest-change kind, failed refresh keeps unexpired copy [500, timeout, size, type], expired never cached/complete) | verified |
| 04a, 04c, 04e, 04j, 04k | `test_reference_fetch.py` (no grant refused + recorded, no fetch outside verification [4], parked next step + https loopback `scheme_not_allowed`, finished/exhausted [4], cap + cached reads, limits downward only) | verified |
| 04b, 04d, 04f–04i, 04l–04n | `test_reference_gate.py` (single-use bound GET + report, exact request bytes, size limit [3], absolute deadline [3] + connect phase, content-type allowlist [7], status/closed port [4], content encoding [2], block removal + POST region + parity + other purposes + guarantees, allowlisted headers + close [3], strict head grammar unit [13] + raw [13], DEC-03 [2]) | verified |
| 05a | `test_reference_resolve.py::test_reference_policy_structure` | verified |
| 05b–05e, 05g, 05h | `test_reference_parse.py` | verified |
| 05f | `test_reference_registry.py::test_unfetched_rule_listed_content_not_obtained` | verified |
| 06a, 06c | `test_reference_fetch.py::test_prompt_injection_text_is_data`, `test_credentials_masked_in_cache_and_output`, `test_explore_link_secrets_never_retained[5]` | verified |
| 06b | `test_reference_skill.py::test_framework_skill_reference_instructions` (+ document test) | verified |
| 07a | `test_reference_plugins.py::test_tag_preset_reference_member_stored` + delivered conditional `test_tags.py::test_tag_members_across_local_and_reference_sources` | verified |
| 07b–07k | `test_reference_plugins.py` (members Local first; exit preview lists `reference_cache` JSON/text; no unsupported kind; confirm invalidates + `STALE_IMPACT`; Local-only golden; Guard and Copilot consume unchanged; status line; removed never substituted; pre-001-E preview stale once) + `test_reference_resolve.py::test_scope_load_adoption_states_reference` (07f) + `test_reference_skill.py::test_exiting_knowledge_names_reference_cache` | verified |
| 08a, 08b, 08e (cache), 08g, 08h | `test_reference_cache.py` (concurrent same key, interrupted commit, symlinks [4], commit re-checks, kind-aware publication revalidation [7], capacity and clean under one lock) | verified |
| 08c, 08e (registry) | `test_reference_registry.py` | verified |
| 08d, 08f, 08i | `test_reference_isolation.py` | verified |
| 09a, 09b | `test_reference_e2e.py` (+ `test_reference_fetch.py::test_fetch_without_run_refused`) | verified |

Design-condition tests (DEC-01, DEC-02, DEC-03, DEC-06, DEC-17, review findings 1–5) and the seven closed-list pairs are present as named in the design, except that the GET client functions are `EgressGate.require_loopback/parse_head/get_request` (DEC-I06).

## 8. Implementation Decisions (open DECs for the representative/owner)

| ID | Decision (most conservative reading) | Status |
| --- | --- | --- |
| DEC-I01 | Spec bound at `4c8bba35…` (DAO-022 wording refresh of the design's `1bed3228…`; no AC change) | informational |
| DEC-I02 | `policy/scope.py` (not in the change list) rebuilds a pre-exit `Library` positionally, so the scope-save exit exception carries no Reference registrations: a mixed proposal across an exit is refused as stale (safe direction; re-resolve) | ratify |
| DEC-I03 | Closed-list item 6 "one setup line" uses `__import__("reference.refhelp", fromlist=["refhelp"]).register_reference(env, "OWASP/2021/A03")` (an import plus a call would be two lines; `;` is refused by ruff E702) | ratify |
| DEC-I04 | STOP-rule finding: 001-G `test_08a` (fixture hashes, exit-preview golden, init golden for the new `.md`) — not edited (§5) | **blocking — owner/DAO/human** |
| DEC-I05 | STOP-rule finding: 002-F `test_closed_list_diff` — not edited (§5) | **blocking — owner/DAO/human** |
| DEC-I06 | The delivered 002-C test `test_05f_no_network_client_outside_egress_module` forbids `socket` imports outside `egress.py`; the planned `guard/egress_get.py` would have broken a delivered 002-C test (binding constraint 1). The loopback client therefore lives inside the delimited additive P6 block of `egress.py` (`EgressGate.get`, `get_request`, `require_loopback`, `parse_head`, failures as `GuardError("EGRESS_GET_FAILED", data.detail)`); behaviour, contract and block-removal hash unchanged; `egress_get.py` not delivered | **ratify (design means)** |
| DEC-I07 | `tests/support/netguard/sitecustomize.py` not created: no 001-E test spawns the CLI; all run in-process under the autouse guards (`tests/reference/netguard.py`) | ratify |
| DEC-I08 | Exit confirm adds `invalidated_reference_cache` only when entries were invalidated (Local-only output byte-identical); entries of the identity and of a rename target are invalidated (both are listed by the provider) | ratify |
| DEC-I09 | A fetch whose registration changed before publication is refused `FETCH_FAILED` detail `registration_changed` (content of a superseded registration is never returned as a Policy); `superseded_by_newer_fetch` returns the newer cached Policy with the note; `cache_not_written: capacity` returns the fetched Policy uncached | ratify |
| DEC-I10 | Markdown keeps link targets in its text: a target whose link record is omitted (credential-like/invalid) is replaced by `[link omitted]` in the text before masking (review finding 3; 06c) | ratify |
| DEC-I11 | P4 carries the member source with a `str` subclass (`catalog.Member`) so `tags.py`/`presets.py` stay unchanged; a registered `reference:` member needs no cache entry; without prefix the source follows the resolved kind | ratify |
| DEC-I12 | `cache-clean` always takes the cache lock (a linked lock file is `PATH_UNSAFE` even without entries) | informational |
| DEC-I13 | Registry files use the shared-document modes of Presets/tags (0644/0755); cache 0600/0700 | informational |
| DEC-I14 | `cache.py` was written by the crashed worker before its tests; genuine RED was produced by holding it aside (`EV/hold`) | informational |
| DEC-I15 | Fixtures `renv/server/clock` are re-exported by assignment in each test module (no pyproject per-file ignore needed for F811) | informational |
| DEC-I16 | P-notes (design §P-Notes, DEC-12) are appended by the lifecycle owner; P6 notes may now be appended (P6 = A) — not done by this worker | owner action |

## 9. Honest Limits

Real domains, DNS, TLS, certificates and connection pinning are not implemented (P-01; only `http://127.0.0.1[:port]`); a Reference-only library cannot bootstrap (B16); IPv4 loopback only; stylesheet/computed visibility is not evaluated; IDNA uses the platform codec; masking is pattern-based (a secret inside an unmasked Markdown/HTML text that matches no pattern stays); a valid cache entry does not prove the source page is unchanged; `available_count` reads every rule's entry on status (read-only). Coverage figures are delivery evidence only.

## 10. Delivery and Outcome

Engineering delivery: verified for all 81 ACs at the hashes in §4 (fresh runs after the last edit: `log-green-step8.txt`, `log-full-suite.txt`, ruff). Regression: **blocked** by DEC-I04 and DEC-I05 (two delivered guards of other features; no edit made). Design-means deviation DEC-I06 needs ratification. Stakeholder outcome (G-03/G-04/G-05): **not measured** (loopback fixtures only; no real-site observation).

```yaml
task_completion_output:
  category: "feature-stage"
  status: blocked   # engineering delivery verified; regression blocked by DEC-I04/DEC-I05 (no edits made)
  next_task_based_skill:
    - skill: "x-ipe-task-based-feature-acceptance-test"
      condition: "Verify implementation with acceptance tests (after the owner resolves DEC-I04/I05 and ratifies DEC-I06)"
  process_preference:
    interaction_mode: "from the lifecycle owner"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  workflow_action: "implementation"
  workflow_action_updated: false
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/reference/"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/reference/"
  feature_id: "FEATURE-001-E"
  feature_title: "Reference Knowledge Exploration & Cache"
  feature_version: "v1.1.2"
  feature_phase: "Code Implementation"
```

## 11. Owner Follow-up after Review and DAO-007 (2026-10-24) — authoritative current state

This section supersedes §1–§10 where they differ (earlier text kept for history; the first report version was `a7deb22a…`).

### 11.1 Rulings applied (DAO-007 code implementation, `x-ipe-docs/dao/26-10-23/decisions_made_code_implementation.md`)

- Independent code review: **PASS-WITH-FIXES** (2 Medium findings → §11.2).
- DEC-I04 → approved maintenance (DAO-004 DEC-I13 class): 4 fixture hashes, `reference_cache`-only golden change, new reference document. The owner's instruction 3(c) chose to add `references/reference-knowledge.md` to the golden `pre_001g/init.json` instead of DAO-007's `NEW_REFERENCE` tuple variant; `NEW_REFERENCE` and its assertion are unchanged (no `NEW_REFERENCE` change had been made, so nothing was reverted). Applied in §11.3.
- DEC-I05 → later-features allowlist (tripwire kept), in the owner's stricter pinned-hash form. Applied in §11.4.
- DEC-I06 → **ratified** (design erratum §11.5). DEC-I01–I03 and DEC-I07–I16 → ratified/informational. DEC-I11: str-subclass carrier noted (§11.5) and the Local byte-identity test added. DEC-I16: P-notes, including the P6 extension note on 002-C FR-002C-9, are appended by the owner at closing — **not done by this worker**.

### 11.2 Review fixes (RED first)

| Fix | RED (fails for the right reason) | Change | GREEN |
| --- | --- | --- | --- |
| 1a Masking can lengthen text (an AWS-key-like value becomes `[masked:credential.cloud_key]`) | `log-red-fixes.txt`: `test_masked_text_over_limit_is_size_limit` — fetch reported `fetched` for text that was over `max_text` after masking | `reference/fetch.py`: the masked, normalized text is re-checked against `max_text` → `fetch_failed`/`refresh_failed` detail `size_limit`; nothing cached | `log-green-fixes.txt` |
| 1b Entry larger than the 1 MiB read bound (500 links of ~2 KB plus ~86 KB of text) | `log-red-fixes.txt` and `log-red-fix1-entry.txt` (guard held aside): `test_oversized_explore_entry_not_written` — the entry was written (`written: true`, generation 1) although readers refuse it as `cache_invalid` | `reference/cache.py` `publish`: canonical entry bytes > `MAX_ENTRY` → `Published(False, "cache_not_written: entry_size")`; the result is returned uncached, never as a cached entry (same pattern as `cache_not_written: capacity`, DEC-I09) | `log-green-fixes.txt` |
| 2 `presets._accepted` dropped the member source for an explicit `accept_add` list | `log-red-fixes.txt`: first a latent crash `KeyError: 'state_digest'` — a registered but uncached `reference:` candidate in `preset recompute`; then `log-red-fix2-accepted.txt`: the stored member was `{rule, source: local}` | `knowledge/presets.py` (diff below): availability rows read `state_digest` with `.get` (Local rows are always available, so Local output is unchanged) and `_accepted` maps the accepted texts back to the offered `Member` objects | `log-green-fixes.txt` (tests/reference + tests/presets 488 passed) |
| DEC-I11 test | characterization (passes before and after) | — | `test_local_member_serialization_byte_identical` |

```diff
--- a/presets.py
+++ b/presets.py
@@ -323 +323 @@
-            "state_digest": valid_rows[r]["state_digest"],
+            "state_digest": valid_rows[r].get("state_digest"),  # FEATURE-001-E: uncached Reference
@@ -341 +341 @@
-                "valid": [{"rule": r, "state_digest": valid_rows[r]["state_digest"]} for r in valid],
+                "valid": [{"rule": r, "state_digest": valid_rows[r].get("state_digest")} for r in valid],
@@ -406 +406,2 @@
-    return sorted(set(value))
+    by_text = {str(o): o for o in offered}  # FEATURE-001-E: keep the offered member (and its source)
+    return sorted({by_text[v] for v in value})
```

`knowledge/presets.py` therefore joins the delivered change set (owner instruction 2, a review fix within P4; DAO-007's "presets.py unchanged" wording for DEC-I11 predates this finding) — DEC-I17.

### 11.3 DEC-I04 maintenance (001-G `test_08a`) — before/after

The two goldens were regenerated from the live tree with the delivered `pre_001g_outputs` helper outside the repository (`EV/probe08a/regen.py`) and written only after the diff was confirmed to be exactly the lines below. Reason (also as a comment in `drafthelp.py`): "P3: Reference cache became a supported impact kind (AC-001E-07c)".

```diff
--- a/fixtures/delivered_tests_001abcdf.json
+++ b/fixtures/delivered_tests_001abcdf.json
@@ -11 +11 @@
-  "knowledge/test_exit_preview.py": "49c61bce4683dde90fd45294f4ed7598368c6b50d92a3203809f0bfc139104b5",
+  "knowledge/test_exit_preview.py": "c4b475ff2b46aaf499d13cb387798ad3c87c6bae334ad03ff81fcc6b49a69ef3",
@@ -31 +31 @@
-  "presets/test_preset_impact.py": "6e7a84c939ab23322c9397c75d62ddf275175cbb85650d380481ea30a461872f",
+  "presets/test_preset_impact.py": "bf82f4c30e373d88555ffcebd8ebc27d236e1422bfea4458cc357dbad9c4e9de",
@@ -34 +34 @@
-  "presets/test_preset_skill.py": "b4f1832bc93c5e8b4392e89c1476f3d39b96eca7dc2436ce9f0d023e8941fd4b",
+  "presets/test_preset_skill.py": "447ed018799e246c460740f50e4e34aecaf3b13dd2edcada156b4df9104f3665",
@@ -37 +37 @@
-  "presets/test_tags.py": "414820a3ca7c66b8c9fc9b851408af70eb18a7d1816cddd583a3d6e2ba05cf41",
+  "presets/test_tags.py": "572f6790dba5a1890e481f42077a68e8ed538d644f76c3ab95c1d00654ba0721",
--- a/fixtures/pre_001g/exit-preview.json
+++ b/fixtures/pre_001g/exit-preview.json
@@ -49 +49,5 @@
-        "reference_cache": "not checked in this version"
+        "reference_cache": {
+          "count": 0,
+          "items": [],
+          "unreadable": []
+        }
@@ -71 +75 @@
-      "impact_digest": "sha256:a306742186df5e680db40b17709eda5cff16854ba9a08a8b28da5b5a0ed76daa",
+      "impact_digest": "sha256:1983d4986bc53823a75961cdd8fe389f3f5f6aaf926deb4bd554ac5bae7a0a97",
--- a/fixtures/pre_001g/init.json
+++ b/fixtures/pre_001g/init.json
@@ -19,0 +20 @@
+        ".github/skills/x-ipe-secure-code-toolkit-framework/references/reference-knowledge.md",
--- a/drafthelp.py
+++ b/drafthelp.py
@@ -94,0 +95,16 @@
+    # maintenance (DAO-023/024 precedent): FEATURE-001-E new payload files (a later declared growth).
+    # DAO-007 code implementation: fixtures/delivered_tests_001abcdf.json rebaselined for the 4 approved
+    # closed-list test files only; pre_001g/exit-preview.json rebaselined for `reference_cache` (and the
+    # impact digest it feeds) only — P3: Reference cache became a supported impact kind (AC-001E-07c);
+    # pre_001g/init.json lists the new payload file references/reference-knowledge.md.
+    "reference/__init__.py",
+    "reference/cache.py",
+    "reference/cli_parser.py",
+    "reference/clock.py",
+    "reference/fetch.py",
+    "reference/parse.py",
+    "reference/policy_view.py",
+    "reference/registry.py",
+    "reference/registry_ops.py",
+    "reference/service.py",
+    "reference/urls.py",
```

Result: `tests/drafting` 269 passed (`log-dec-i04-drafting.txt`); `test_08a` passes without any assertion change.

### 11.4 DEC-I05 maintenance (002-F `test_closed_list_diff`) — before/after

`CLOSED_LIST` is unchanged. A ruled, pinned allowlist was added: a changed delivered file outside `CLOSED_LIST` is accepted only when its current SHA-256 equals the pinned hash; `egress.py` is hashed with its marked P6 block removed (pinned `836f8b36…`, computed in the test). The engine check is unchanged. The 20 pins are the 001-E changes to files in 002-F's step-0 baseline (`cli.py`, `carhelp.py`, `drafthelp.py` are also in `CLOSED_LIST` and are pinned for completeness). Pins were computed at the end, after all fixes.

```diff
--- a/test_helper_boundary.py
+++ b/test_helper_boundary.py
@@ -38,0 +39,53 @@
+# maintenance: later features append their ruled delivered-file changes here (DAO-007 code implementation).
+# A changed delivered file outside CLOSED_LIST is accepted only when its current SHA-256 equals the pinned,
+# ruled hash; a file listed in BLOCK_PINNED is hashed with its delimited additive block removed.
+LATER_FEATURE_CHANGES: dict[str, dict[str, str]] = {
+    "FEATURE-001-E (DAO-007 code implementation)": {
+        f"{FW}/SKILL.md":
+            "774e642d9682ac5f4750399c80aec7f0f2dcdd48cad92b9ddac223aeea7dc91b",
+        f"{FW}/references/cli-contract.md":
+            "930fd035f451e920a9ad04623ae4304de2cfeaefcc7590b085a3e999417d7885",
+        f"{FW}/references/presets-and-tags.md":
+            "42dff964a2d5c3ae0222b6241e54d45d9ca8c375844e8bd9935c199068d9e7f4",
+        f"{FW}/scripts/src/x_ipe_secure_code/cli.py":
+            "f33ea766b59fd396af6cfba6c9939a1f7f32437d06795b9c9a41b776c32caf1f",
+        f"{FW}/scripts/src/x_ipe_secure_code/guard/egress.py":
+            "836f8b36a35b6418b354a467b1d53c96dfd288606b3bb4a9400d64afbc2ee7bc",
+        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/catalog.py":
+            "c81fa20db680198430f16717151e9fde8af01df89fa5816d09c8d35b3bf23742",
+        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/exit.py":
+            "91afb99e8b72fc0cb5561fc46ce2f74323ae3fa2fd51715be337aa9dc28218ca",
+        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/impact.py":
+            "6c18b768cbfbaf8794cec3d04c960ff4dda8fdecf0d746ce2640b437f62bd473",
+        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/presets.py":
+            "aab7c722aa5e324f1bc02e1e7e0be108846c9bf838495569307ed2e898e2673e",
+        f"{FW}/scripts/src/x_ipe_secure_code/policy/resolve.py":
+            "4d90e5500f844a6e32a6af7fd2d9df1ee00326c97174c586c15ba3fd392fbd60",
+        f"{FW}/scripts/src/x_ipe_secure_code/status.py":
+            "b15b32184193ab034190fd3e627e0dc9a0b45aec8b4eddf40fcf2d3253002f42",
+        f"{FW}/scripts/tests/carriers/carhelp.py":
+            "770a0b9f0b9ecb56e7b0418cba146caa29ca3ba9e1d50f83b755b77c4b0e001d",
+        f"{FW}/scripts/tests/drafting/drafthelp.py":
+            "8a105fb80428bdeb0ffae426b1910241a7884f4b899c33368f08192618bb962a",
+        f"{FW}/scripts/tests/drafting/fixtures/delivered_tests_001abcdf.json":
+            "3d9a15eeb18a6a821e28c6049a7098c0b3a02e6a5d3f74e39099f57322b33987",
+        f"{FW}/scripts/tests/drafting/fixtures/pre_001g/exit-preview.json":
+            "7dd807cb04495cd6e0fb8d3e739ea31bb479e16040ca386547b4d8a3f7aa9cc7",
+        f"{FW}/scripts/tests/drafting/fixtures/pre_001g/init.json":
+            "2b376eb7343c39b2f7800f97be450af88b393d306dc73f2208ee716deb5bed88",
+        f"{FW}/scripts/tests/knowledge/test_exit_preview.py":
+            "c4b475ff2b46aaf499d13cb387798ad3c87c6bae334ad03ff81fcc6b49a69ef3",
+        f"{FW}/scripts/tests/presets/test_preset_impact.py":
+            "bf82f4c30e373d88555ffcebd8ebc27d236e1422bfea4458cc357dbad9c4e9de",
+        f"{FW}/scripts/tests/presets/test_preset_skill.py":
+            "447ed018799e246c460740f50e4e34aecaf3b13dd2edcada156b4df9104f3665",
+        f"{FW}/scripts/tests/presets/test_tags.py":
+            "572f6790dba5a1890e481f42077a68e8ed538d644f76c3ab95c1d00654ba0721",
+    },
+}
+BLOCK_PINNED = {
+    f"{FW}/scripts/src/x_ipe_secure_code/guard/egress.py": (
+        "    # --- P6 GET path (FEATURE-001-E, additive) ---",
+        "    # --- end P6 GET path ---",
+    ),
+}
@@ -39,0 +93,12 @@
+
+def _later_digest(rel: str, raw: bytes) -> str:
+    markers = BLOCK_PINNED.get(rel)
+    if markers is not None:
+        lines = raw.decode("utf-8").split("\n")
+        if lines.count(markers[0]) == 1 and lines.count(markers[1]) == 1:
+            start, end = lines.index(markers[0]), lines.index(markers[1])
+            if start < end:
+                raw = "\n".join(lines[:start] + lines[end + 1 :]).encode("utf-8")
+    return hashlib.sha256(raw).hexdigest()
+
+
@@ -120 +185,6 @@
-    assert changed <= CLOSED_LIST, sorted(changed - CLOSED_LIST)
+    approved = {rel: digest for ruled in LATER_FEATURE_CHANGES.values() for rel, digest in ruled.items()}
+    later = {
+        rel for rel in changed - CLOSED_LIST
+        if rel in approved and _later_digest(rel, (TOOLKIT_ROOT / rel).read_bytes()) == approved[rel]
+    }
+    assert changed <= CLOSED_LIST | later, sorted(changed - CLOSED_LIST - later)
```

Evidence: green (`log-dec-i05-green.txt`, 6 passed). Tripwire probe: one appended comment line outside the P6 block in `egress.py` and one in `status.py` → the test fails naming both (`log-dec-i05-tripwire.txt`); both files restored and re-hashed equal (`8ebb3b76…`, `b15b3218…`).

### 11.5 Design errata for the owner to append (DEC-I06, DEC-I11) and DEC-I14 statement

**Erratum E1 (DEC-01 placement, DAO-007).** In §Gate Extension Contract and §Key Components, "HTTP client in new `guard/egress_get.py`" is replaced by: the body-less loopback GET client (`EgressGate.get`, `EgressGate.get_request`, `EgressGate.require_loopback`, `EgressGate.parse_head`, failures as `GuardError("EGRESS_GET_FAILED", data.detail ∈ {timeout, connection_failed, header_invalid})`) lives **inside the delimited P6 block of `guard/egress.py`** (`    # --- P6 GET path (FEATURE-001-E, additive) ---` … `    # --- end P6 GET path ---`). Reason: the delivered 002-C test `test_05f_no_network_client_outside_egress_module` forbids `socket` imports in every other module (the single-gate rule). Behaviour, contract and order are unchanged. Removing the delimited block restores the delivered `egress.py` SHA-256 `836f8b36a35b6418b354a467b1d53c96dfd288606b3bb4a9400d64afbc2ee7bc` (`test_egress_block_removal_restores_delivered_hash`). The human's P6 = A covers the extension.

**Erratum E2 (DEC-I11 member-source carrier, suggestion).** In §Plug-in Integration P4, add: the member source travels with each identity as `knowledge.catalog.Member`, a `str` subclass carrying `source` (`local`/`reference`). It compares, hashes and sorts like the plain identity, so `tags.py` is unchanged and Local serialization is byte-identical (`test_local_member_serialization_byte_identical`). Stored files are read back into `Member` objects. Where code rebuilds lists from request text it must map back to the offered members — `presets._accepted` (review fix 2) is the one place this was needed.

**DEC-I14 (how RED was produced for Step 4).** The crashed worker had written `reference/cache.py` before its tests existed. To get a genuine RED, this worker moved the pre-written `cache.py` out of the source tree into `EV/hold/`, ran the new cache tests (20 failed: implementation missing, `log-red-step4.txt`), restored the identical file and ran them again (green once the Step 5 resolution hooks existed). Steps 5–8 and the review fixes used the same method, temporarily restoring the HEAD file (or holding the new code aside) and re-hashing after restore.

### 11.6 Validation (final tree)

| Check | Evidence | Result |
| --- | --- | --- |
| Full suite (final tree) | `log-full-suite2.txt` (23:27–00:05, 37 min 34 s) | **3501 passed, 0 failed, 7 skipped, 23 deselected**; the known-flaky `test_draft_cli_approve::test_02e` passed (it did not recur) |
| New tests | `tests/reference/` collection | 266 tests (262 + 4 follow-up tests) |
| Lint | `UV_OFFLINE=1 uv run --offline ruff check --no-cache src tests` | All checks passed |
| P6 manifest | `EV/manifest-p6-before.sha256` | only `src/guard/egress.py` differs; every `tests/guard/` and `tests/adapters/` file unchanged |
| Block removal | `test_egress_block_removal_restores_delivered_hash` | `836f8b36…` restored |
| Inputs re-hashed | spec / design | `4c8bba35…` / `b6b2806f…` unchanged |
| Loopback only (B4 = B) | autouse `netguard` in every `tests/reference` module | 0 resolver calls, only `127.0.0.1` connects, 0 processes from fetch stacks |
| Repository hygiene | `git status --short --ignored ai-secure-code-toolkit` | only the 21 changed and 47 new files; ignored: the pre-existing `.venv/` only |
| Forbidden-substring scan | every changed or new file, case-insensitive, for the three excluded names | none |
| Parity | changed delivered files vs HEAD `73fe2dc` | 21 files: the design change list (P1–P7 product, framework text), closed list items 1–7, ruled maintenance (carhelp/drafthelp payload, DEC-I04 fixtures, DEC-I05 allowlist) and review fix 2 (`presets.py`) — nothing else |

### 11.7 Files (final hashes; supersede §4 tables)

Changed delivered files (21 = the 16 of §4.1 + `knowledge/presets.py`, the three 001-G drafting fixtures and the 002-F boundary test):

| File (FW-relative) | Before (HEAD 73fe2dc) | After |
| --- | --- | --- |
| `SKILL.md` | `3fc74164bc3fa3f9ada83cf11df86bdde088570f727d3dcdfde1cbc152607c80` | `774e642d9682ac5f4750399c80aec7f0f2dcdd48cad92b9ddac223aeea7dc91b` |
| `references/cli-contract.md` | `eda7bd6299a1e2d730bb7b50c52d1eafbd69db280e0db71886bef9572733e4f6` | `930fd035f451e920a9ad04623ae4304de2cfeaefcc7590b085a3e999417d7885` |
| `references/presets-and-tags.md` | `6d4df848809fba768a44a03a759e5d7e31714e438b1316a4a5a2f068477f539e` | `42dff964a2d5c3ae0222b6241e54d45d9ca8c375844e8bd9935c199068d9e7f4` |
| `scripts/src/x_ipe_secure_code/cli.py` | `4f0d63ac5f0b4a0dd88a42f6e463cac5f80c8fa683478acd7d947e2c35e8d0e1` | `f33ea766b59fd396af6cfba6c9939a1f7f32437d06795b9c9a41b776c32caf1f` |
| `scripts/src/x_ipe_secure_code/guard/egress.py` | `836f8b36a35b6418b354a467b1d53c96dfd288606b3bb4a9400d64afbc2ee7bc` | `8ebb3b76681c3dcc7710ae4d5bf38e5a64b543822ad8b107157434b5a451bdd2` |
| `scripts/src/x_ipe_secure_code/knowledge/catalog.py` | `a21a34d342c53f0419291b36e617eba7dcb62ffc2966dc2009be57341fd1f1d3` | `c81fa20db680198430f16717151e9fde8af01df89fa5816d09c8d35b3bf23742` |
| `scripts/src/x_ipe_secure_code/knowledge/exit.py` | `165b78658c361281517e6e899340c864d47d8692bc445ab1f9d6a6904c4906f2` | `91afb99e8b72fc0cb5561fc46ce2f74323ae3fa2fd51715be337aa9dc28218ca` |
| `scripts/src/x_ipe_secure_code/knowledge/impact.py` | `906c4562f13f8aeb906bdef30a8aacbdfbb2b8c5fb5cd4d65fcf3f575c5ba128` | `6c18b768cbfbaf8794cec3d04c960ff4dda8fdecf0d746ce2640b437f62bd473` |
| `scripts/src/x_ipe_secure_code/knowledge/presets.py` | `50cf6cda593eb3fe0476b71aab944ef0eb97f4f81c177602f93aaf5d2f733261` | `aab7c722aa5e324f1bc02e1e7e0be108846c9bf838495569307ed2e898e2673e` |
| `scripts/src/x_ipe_secure_code/policy/resolve.py` | `f1dcdd6e3afb9e58388b0de3bd30681ca242d7973eabe922c6cf3794def80f6d` | `4d90e5500f844a6e32a6af7fd2d9df1ee00326c97174c586c15ba3fd392fbd60` |
| `scripts/src/x_ipe_secure_code/status.py` | `10df3fedb25f94448f593c18d8fba691dea85545476792c9f2d773fd29bf146e` | `b15b32184193ab034190fd3e627e0dc9a0b45aec8b4eddf40fcf2d3253002f42` |
| `scripts/tests/carriers/carhelp.py` | `b001244e5fa4a60a37f251117888657a8b7cdc20d4cecd0742609f3c3edb076e` | `770a0b9f0b9ecb56e7b0418cba146caa29ca3ba9e1d50f83b755b77c4b0e001d` |
| `scripts/tests/drafting/drafthelp.py` | `c96b5c72ecd4aafb0cefc45c6bf678a809519b7c535b3b2d7a46e93010641837` | `8a105fb80428bdeb0ffae426b1910241a7884f4b899c33368f08192618bb962a` |
| `scripts/tests/drafting/fixtures/delivered_tests_001abcdf.json` | `4e1521f46a02bb8d0f83b7c703aa3255bc969eb9aff246126dcaf0e32be5427d` | `3d9a15eeb18a6a821e28c6049a7098c0b3a02e6a5d3f74e39099f57322b33987` |
| `scripts/tests/drafting/fixtures/pre_001g/exit-preview.json` | `af5901bca80c1ba8aa3489d697318404584e0e223e2042020ca0ebe441be269f` | `7dd807cb04495cd6e0fb8d3e739ea31bb479e16040ca386547b4d8a3f7aa9cc7` |
| `scripts/tests/drafting/fixtures/pre_001g/init.json` | `225322dfffe2107062606f977f0966c505f80afa5a4c9222d0e83f65cab6b9ac` | `2b376eb7343c39b2f7800f97be450af88b393d306dc73f2208ee716deb5bed88` |
| `scripts/tests/helpers/test_helper_boundary.py` | `bb952dd940273523f433dd42edee6b663af7707520affea9818d58dc61e48d92` | `38ab9485bc5cf5c5ffd03837448a201e7a4f4f8f3f15a60204d7e4518710a7ba` |
| `scripts/tests/knowledge/test_exit_preview.py` | `49c61bce4683dde90fd45294f4ed7598368c6b50d92a3203809f0bfc139104b5` | `c4b475ff2b46aaf499d13cb387798ad3c87c6bae334ad03ff81fcc6b49a69ef3` |
| `scripts/tests/presets/test_preset_impact.py` | `6e7a84c939ab23322c9397c75d62ddf275175cbb85650d380481ea30a461872f` | `bf82f4c30e373d88555ffcebd8ebc27d236e1422bfea4458cc357dbad9c4e9de` |
| `scripts/tests/presets/test_preset_skill.py` | `b4f1832bc93c5e8b4392e89c1476f3d39b96eca7dc2436ce9f0d023e8941fd4b` | `447ed018799e246c460740f50e4e34aecaf3b13dd2edcada156b4df9104f3665` |
| `scripts/tests/presets/test_tags.py` | `414820a3ca7c66b8c9fc9b851408af70eb18a7d1816cddd583a3d6e2ba05cf41` | `572f6790dba5a1890e481f42077a68e8ed538d644f76c3ab95c1d00654ba0721` |

| New file (FW-relative) | SHA-256 |
| --- | --- |
| `references/reference-knowledge.md` | `2a619aeb46d6e27ce9992ae12de922f7dde91e1bf66ad2da23e85becaf568d02` |
| `scripts/src/x_ipe_secure_code/reference/__init__.py` | `0111ed36b340957afb2501d6f0d8d390ac6e84296eca97c4c12a9a3284c4369d` |
| `scripts/src/x_ipe_secure_code/reference/cache.py` | `3d2adec9f14aa15323d0619a93950fab7523ffb9b9f024140b9ab71ad11e5718` |
| `scripts/src/x_ipe_secure_code/reference/cli_parser.py` | `bddb25f946ae69e5ddf4bb98347e70ceb0880783942ea6e5a5e30ee7bdd39307` |
| `scripts/src/x_ipe_secure_code/reference/clock.py` | `a1e950344e5e07d1de386975118d1da212681d5293384d4e1a72410003d16545` |
| `scripts/src/x_ipe_secure_code/reference/fetch.py` | `c8ad4bf11a970fde49fba11f5b5e78dafa93908f5958462140b4b1d5300f6080` |
| `scripts/src/x_ipe_secure_code/reference/parse.py` | `f6fe9a699ad09ae12c8a45d2d77cc8a65a1c7f8bbc2152e2052bd5b8d212a4ae` |
| `scripts/src/x_ipe_secure_code/reference/policy_view.py` | `0a7b620a151385c26a95d86910e40bb77bf754e0dd601a36801e8a65ae505785` |
| `scripts/src/x_ipe_secure_code/reference/registry.py` | `49bb79a7459c9ad529219bfe6275c2c078294e6573c1136a81f88e3831010371` |
| `scripts/src/x_ipe_secure_code/reference/registry_ops.py` | `fff5155d8660ba06fad8878a09d1f4b713c3f6e67acdc4e6634dd5eecea80225` |
| `scripts/src/x_ipe_secure_code/reference/service.py` | `1f23ffc5d66cd689e648591e192b4636341e904ac8b29439dabca98fed7f1228` |
| `scripts/src/x_ipe_secure_code/reference/urls.py` | `ab3b4a532c93735dec4875ea457b9c9ff4c51c84bc5a163efa0ee0474257193f` |
| `scripts/tests/reference/capture_golden.py` | `b0e537ff17676063e2007688f4294d7a1a6cfbf8623c7a6b4ecb9ab93c74ded7` |
| `scripts/tests/reference/fixtures/golden/MANIFEST.json` | `0918b9c3eadafb9143e586b20d6db2a516e0696b21f76aeb8766140f9f26a7d4` |
| `scripts/tests/reference/fixtures/golden/pre001e/exit-preview.json` | `b59568941a8b8f49d84874eb3766b415a98228ad3c60d5f8038416d2c85f5f58` |
| `scripts/tests/reference/fixtures/golden/pre001e/preset-resolve.json` | `09a1017610501e16fd51b91642907bb69ac0c03379abd38ec5f9622ef06d6837` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-all.json` | `c6bef4421fa72068a60ca0cdd084e98f50fac5a2534c0597156ae922a5ee2876` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-rules.json` | `c8b8c8babb0403562831d9889277b7d33d0e233b9011a904dfade5e570305509` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-versionless.json` | `86deb261979709abcbd515f232461629197c6021c88eb86a05889631efa11eda` |
| `scripts/tests/reference/fixtures/golden/pre001e/scope-save.json` | `6ff0055693fc8442f61f01c39f70fe230dc98dfca538add7883882ee34cb97ae` |
| `scripts/tests/reference/fixtures/golden/pre001e/scope-show.json` | `a4a8afd8a3697316bdf0424ce346f7164bde81d0ab5b3e012d1d285630f9be38` |
| `scripts/tests/reference/fixtures/golden/pre001e/status.json` | `a47f7e10808cc429def77184795879f77146ebb683ea972e0c086ecf0f839b87` |
| `scripts/tests/reference/fixtures/golden/pre001e/tag-show.json` | `ecb22fc8e7ee0839b11b1ec086bff6716a1d3316fd5f3853995faac273dc22d1` |
| `scripts/tests/reference/fixtures/pages/credentials.html` | `dc5eaf17dc01e2aef4d886617bb88758ab2edd251baff93ffac4e60fd6c0e521` |
| `scripts/tests/reference/fixtures/pages/cwe-79-nav-changed.html` | `01b086b658a4944733595d430d9424834464a8e81d69e87778792256438200a1` |
| `scripts/tests/reference/fixtures/pages/cwe-79-req-changed.html` | `402c0b1944e173f17a4369bad5e3b423884dcc923b5eb4d9b539e9532b51ed8e` |
| `scripts/tests/reference/fixtures/pages/cwe-79.html` | `4632315e510f7786ff2f158e3986211991f12d1b9fbb766d2b86b6f7214357af` |
| `scripts/tests/reference/fixtures/pages/cwe-89.html` | `44fba0298d6abc1162a4c6373746ca246ad442beb677151c0a57e1fd05b50bd4` |
| `scripts/tests/reference/fixtures/pages/cwe-top25-list.html` | `8ba9cfabcbbbf4cb982c0d55d78843a6a3edb88cb479c2a815674eca2e5c6fcd` |
| `scripts/tests/reference/fixtures/pages/hidden.html` | `774de649475925add8f20e70064bc1bbd0e20a2df6b994ae5cc2349c6ca48a75` |
| `scripts/tests/reference/fixtures/pages/injection.html` | `01bf54827fce47cbff8582c1c1563a7513a23461ba15a58da0beb01dd72642d1` |
| `scripts/tests/reference/fixtures/pages/latin1.html` | `f6f67bf08b1f3bc83fc4b9d2f5477a658b400588a22eb6a072244e8609db03c7` |
| `scripts/tests/reference/fixtures/pages/nav-only.html` | `bedc68e1c30a6bdfdad4dcfd9621f01652775e375031f8c6f27a137fa9bb5b40` |
| `scripts/tests/reference/fixtures/pages/owasp-2025-a01.md` | `9d1069fac4c0669a57e4a4804cdbdb40ffedc157a609ae12be51baaab6b59a8d` |
| `scripts/tests/reference/netguard.py` | `2f5817892bab821aad2b8044e2926ad83b36c0edd804dcf8b629bd0c3ab6635d` |
| `scripts/tests/reference/refhelp.py` | `7b160262a5f8d27ee3e558ae908dc1c24c9e8a2f887864ef991d753247bdc0c7` |
| `scripts/tests/reference/test_reference_cache.py` | `d421b114bb6da92214803f5fd5fde6d9b6a742ee290844cd671649b76e735810` |
| `scripts/tests/reference/test_reference_e2e.py` | `cf8fe7045ac5d120376c5af987d9ec7a74bd1e03d8df76b6e2fb832af3799994` |
| `scripts/tests/reference/test_reference_fetch.py` | `41261752eb53ebc6cee96415e7087b78444515b08beb7ce752a837b07a84edb8` |
| `scripts/tests/reference/test_reference_gate.py` | `be50c47fd5639abe4a93f9a03a4d2851f95fff6e5fb1cbb950f1f37fa11057f9` |
| `scripts/tests/reference/test_reference_isolation.py` | `2d1c8b88f149cbe3982ceffa28eb47ed72c0d42c3da100a716899199362d59d7` |
| `scripts/tests/reference/test_reference_parse.py` | `f66b77489485a1a6b5958975bc65e2672475943d3d4757866b0aa2113698c49c` |
| `scripts/tests/reference/test_reference_plugins.py` | `9e38721310749584fb473cfea7f6aa492cb297b2de14f1475042bc10b64b5392` |
| `scripts/tests/reference/test_reference_registry.py` | `d58e27e00655005e27cf40d7aca5a7d6cca6596091272adaf332b05dbe1ef77a` |
| `scripts/tests/reference/test_reference_resolve.py` | `d2bd74a24f319d0a6d6dab0cfca038f418855815744887bd91796b5649e76322` |
| `scripts/tests/reference/test_reference_skill.py` | `6e3f1b1efd672f696fd2154d22481d1dc64140e33a730595561b7db340c611d5` |
| `scripts/tests/reference/test_reference_urls.py` | `6f778961fbc4e642a736a8c867b84aad7bf04d4a1367787eb53f95d1d7213c59` |

### 11.8 Delivery and outcome (current)

Engineering delivery: **verified** for all 81 ACs at the hashes in §11.7, with 266 tests in `tests/reference/`. Regression: **0 failures** in the full suite (3501 passed, 7 skipped). Delivered-file change set = design change list (P1–P7 product and framework text) + closed list items 1–7 + ruled maintenance points (carhelp/drafthelp payload, DEC-I04 fixtures, DEC-I05 allowlist) + review fix 2 (`presets.py`, DEC-I17). Stakeholder outcome: **not measured**. Open for the owner: P-notes (incl. P6), design errata E1/E2, local exact-path commit (B8).

```yaml
task_completion_output:
  category: "feature-stage"
  status: completed   # engineering delivery verified, 0 suite failures; owner closing items listed above
  next_task_based_skill:
    - skill: "x-ipe-task-based-feature-acceptance-test"
      condition: "Verify implementation with acceptance tests"
  process_preference:
    interaction_mode: "from the lifecycle owner"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  workflow_action: "implementation"
  workflow_action_updated: false
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/reference/"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/reference/"
  feature_id: "FEATURE-001-E"
  feature_title: "Reference Knowledge Exploration & Cache"
  feature_version: "v1.1.2"
  feature_phase: "Code Implementation"
```

## 12. Re-review Nits and DAO-008 (2026-10-25) — authoritative final state

This section supersedes §11.6–§11.8 where they differ.

### 12.1 Rulings (DAO-008 code implementation)

- Re-review: **PASS-WITH-NITS**; both nits applied (§12.2).
- **DEC-I17 → approved** as review-fix plumbing inside the named P4 plug-in. `knowledge/presets.py` joins the design change list (erratum E3 below), and the closing report lists it under P4. Its `LATER_FEATURE_CHANGES` pin stays exact. DAO-007's "presets.py unchanged" (DEC-I11) is superseded for these edits only; `tags.py` stays unchanged.
- **DEC-I04 variant ratified**: one entry added to the golden `pre_001g/init.json` instead of a `NEW_REFERENCE` tuple. The exit-preview `impact_digest` change is accepted as derived from the ruled `reference_cache` line. Reason note: "P3: Reference cache became a supported impact kind (AC-001E-07c); the impact digest changes because it includes that kind".
- **DEC-I05 variant ratified**: exact per-path pins, with `egress.py` pinned at `836f8b36…` with the P6 block removed. Later features append their own ruled block with exact pins and the ruling reference.

### 12.2 Nits (RED first)

| Nit | RED | Change | GREEN |
| --- | --- | --- | --- |
| 1 Uncached Reference add row lacked `reason` | `log-red-nit1.txt`: `test_recompute_add_row_shape_for_reference_members` — the row was `{rule, availability: missing, state_digest: null}` without `reason` | `presets._diff` add rows copy `reason` from the catalog availability row when present, like stored rows. Local add rows are always available (no `reason` key), so Local output is byte-identical (delivered presets suites and the pre-001-E golden pass unchanged) | `log-green-nits-targeted.txt` |
| 2 A pin must win over `CLOSED_LIST` | Probe (`log-red-nit2-old-accepts.txt`): with the previous logic (only the presets pin updated), an appended line in `carhelp.py` — which is in both `CLOSED_LIST` and the pins — was **accepted** (1 passed) | `test_closed_list_diff`: every pinned changed file must match its pin exactly (`off_pin == []`); unpinned changes must stay within `CLOSED_LIST`; everything else (removed list, engine check, `BLOCK_PINNED`) is unchanged | `log-green-nit2-new-refuses.txt`: the same probe is now refused naming `carhelp.py`; probe file restored and re-hashed (`770a0b9f…`) |

```diff
--- a/presets.py
+++ b/presets.py
@@ -323,0 +324 @@
+            **({"reason": valid_rows[r]["reason"]} if "reason" in valid_rows[r] else {}),
--- a/test_helper_boundary.py
+++ b/test_helper_boundary.py
@@ -61 +61 @@
-            "aab7c722aa5e324f1bc02e1e7e0be108846c9bf838495569307ed2e898e2673e",
+            "7edc7a4c1eea470c361319bb05da509ea03bf4f0fbec43a34c3506825db72df5",
@@ -186,5 +186,7 @@
-    later = {
-        rel for rel in changed - CLOSED_LIST
-        if rel in approved and _later_digest(rel, (TOOLKIT_ROOT / rel).read_bytes()) == approved[rel]
-    }
-    assert changed <= CLOSED_LIST | later, sorted(changed - CLOSED_LIST - later)
+    # a pin wins over CLOSED_LIST: a pinned changed file must match its pin exactly
+    off_pin = sorted(
+        rel for rel in changed & set(approved)
+        if _later_digest(rel, (TOOLKIT_ROOT / rel).read_bytes()) != approved[rel]
+    )
+    assert off_pin == [], off_pin
+    assert changed - set(approved) <= CLOSED_LIST, sorted(changed - set(approved) - CLOSED_LIST)
```

Pins were recomputed at the very end. Only the `presets.py` pin changed (`aab7c722…` → `7edc7a4c…`); the other 19 pins, including `egress.py` = `836f8b36…` with the block removed, were re-verified unchanged.

### 12.3 Design erratum E3 for the owner to append (DEC-I17, DAO-008)

**Erratum E3 (P4 plumbing in `knowledge/presets.py`).** In §Plug-in Integration P4 and the delivered-file change list (§Modules and Sizes), add `knowledge/presets.py` (001-F) with three edits that take effect only for Reference members:
1. In the `preset recompute` diff, availability rows read `state_digest` with `.get`, so a registered but uncached Reference candidate (valid as a `reference:` member per P4) no longer fails with `KeyError`.
2. Its add row carries the catalog `reason` (for example `not_cached`) when present, like stored rows.
3. `_accepted` maps an explicit `accept_add`/`accept_remove` list back to the offered `catalog.Member` objects, so `{rule, source: reference}` survives `recompute-confirm`.

Local members are plain identities that map to themselves and are always available, so Local output is byte-identical (`test_local_member_serialization_byte_identical`, delivered 001-F suites). `tags.py` is unchanged.

### 12.4 Validation (final tree)

| Check | Evidence | Result |
| --- | --- | --- |
| Targeted re-run | `tests/reference tests/presets tests/helpers/test_helper_boundary.py tests/drafting/test_draft_regression.py` (`log-green-nits-targeted.txt`) | 502 passed |
| Full suite at the final hashes | `log-full-suite3.txt` (00:16:55–00:54:40, run once after the last edit; hashes frozen in `EV/final-files-nits.sha256` and re-verified after the run) | **3502 passed, 0 failed, 7 skipped, 23 deselected**; the known-flaky `test_draft_cli_approve::test_02e` passed (it did not recur) |
| New tests | `tests/reference/` collection | 267 tests |
| Lint | `ruff check --no-cache src tests` | All checks passed |
| Inputs | spec / design | `4c8bba35…` / `b6b2806f…` unchanged |
| Repository hygiene | `git status --short --ignored ai-secure-code-toolkit` | 21 changed + 47 new files; ignored: the pre-existing `.venv/` only |
| Forbidden-substring scan | every changed or new file and this report, case-insensitive | none |
| Parity | `test_closed_list_diff` with exact pins; P6 manifest | only the ruled set; `egress.py` block removal = `836f8b36…`; every `tests/guard`/`tests/adapters` file unchanged |

### 12.5 Files (final hashes; supersede §4 and §11.7)

Changed delivered files (21). `presets.py` is listed under P4 (DEC-I17); the drafting fixtures and the boundary test are the DEC-I04/I05 maintenance points; the closed-list tests are items 1–7.

| File (FW-relative) | Before (HEAD 73fe2dc) | After |
| --- | --- | --- |
| `SKILL.md` | `3fc74164bc3fa3f9ada83cf11df86bdde088570f727d3dcdfde1cbc152607c80` | `774e642d9682ac5f4750399c80aec7f0f2dcdd48cad92b9ddac223aeea7dc91b` |
| `references/cli-contract.md` | `eda7bd6299a1e2d730bb7b50c52d1eafbd69db280e0db71886bef9572733e4f6` | `930fd035f451e920a9ad04623ae4304de2cfeaefcc7590b085a3e999417d7885` |
| `references/presets-and-tags.md` | `6d4df848809fba768a44a03a759e5d7e31714e438b1316a4a5a2f068477f539e` | `42dff964a2d5c3ae0222b6241e54d45d9ca8c375844e8bd9935c199068d9e7f4` |
| `scripts/src/x_ipe_secure_code/cli.py` | `4f0d63ac5f0b4a0dd88a42f6e463cac5f80c8fa683478acd7d947e2c35e8d0e1` | `f33ea766b59fd396af6cfba6c9939a1f7f32437d06795b9c9a41b776c32caf1f` |
| `scripts/src/x_ipe_secure_code/guard/egress.py` | `836f8b36a35b6418b354a467b1d53c96dfd288606b3bb4a9400d64afbc2ee7bc` | `8ebb3b76681c3dcc7710ae4d5bf38e5a64b543822ad8b107157434b5a451bdd2` |
| `scripts/src/x_ipe_secure_code/knowledge/catalog.py` | `a21a34d342c53f0419291b36e617eba7dcb62ffc2966dc2009be57341fd1f1d3` | `c81fa20db680198430f16717151e9fde8af01df89fa5816d09c8d35b3bf23742` |
| `scripts/src/x_ipe_secure_code/knowledge/exit.py` | `165b78658c361281517e6e899340c864d47d8692bc445ab1f9d6a6904c4906f2` | `91afb99e8b72fc0cb5561fc46ce2f74323ae3fa2fd51715be337aa9dc28218ca` |
| `scripts/src/x_ipe_secure_code/knowledge/impact.py` | `906c4562f13f8aeb906bdef30a8aacbdfbb2b8c5fb5cd4d65fcf3f575c5ba128` | `6c18b768cbfbaf8794cec3d04c960ff4dda8fdecf0d746ce2640b437f62bd473` |
| `scripts/src/x_ipe_secure_code/knowledge/presets.py` | `50cf6cda593eb3fe0476b71aab944ef0eb97f4f81c177602f93aaf5d2f733261` | `7edc7a4c1eea470c361319bb05da509ea03bf4f0fbec43a34c3506825db72df5` |
| `scripts/src/x_ipe_secure_code/policy/resolve.py` | `f1dcdd6e3afb9e58388b0de3bd30681ca242d7973eabe922c6cf3794def80f6d` | `4d90e5500f844a6e32a6af7fd2d9df1ee00326c97174c586c15ba3fd392fbd60` |
| `scripts/src/x_ipe_secure_code/status.py` | `10df3fedb25f94448f593c18d8fba691dea85545476792c9f2d773fd29bf146e` | `b15b32184193ab034190fd3e627e0dc9a0b45aec8b4eddf40fcf2d3253002f42` |
| `scripts/tests/carriers/carhelp.py` | `b001244e5fa4a60a37f251117888657a8b7cdc20d4cecd0742609f3c3edb076e` | `770a0b9f0b9ecb56e7b0418cba146caa29ca3ba9e1d50f83b755b77c4b0e001d` |
| `scripts/tests/drafting/drafthelp.py` | `c96b5c72ecd4aafb0cefc45c6bf678a809519b7c535b3b2d7a46e93010641837` | `8a105fb80428bdeb0ffae426b1910241a7884f4b899c33368f08192618bb962a` |
| `scripts/tests/drafting/fixtures/delivered_tests_001abcdf.json` | `4e1521f46a02bb8d0f83b7c703aa3255bc969eb9aff246126dcaf0e32be5427d` | `3d9a15eeb18a6a821e28c6049a7098c0b3a02e6a5d3f74e39099f57322b33987` |
| `scripts/tests/drafting/fixtures/pre_001g/exit-preview.json` | `af5901bca80c1ba8aa3489d697318404584e0e223e2042020ca0ebe441be269f` | `7dd807cb04495cd6e0fb8d3e739ea31bb479e16040ca386547b4d8a3f7aa9cc7` |
| `scripts/tests/drafting/fixtures/pre_001g/init.json` | `225322dfffe2107062606f977f0966c505f80afa5a4c9222d0e83f65cab6b9ac` | `2b376eb7343c39b2f7800f97be450af88b393d306dc73f2208ee716deb5bed88` |
| `scripts/tests/helpers/test_helper_boundary.py` | `bb952dd940273523f433dd42edee6b663af7707520affea9818d58dc61e48d92` | `688e2dd6808a9d7f45878cce2db40bb45392d8abc8634ae4313eb46f0f16813c` |
| `scripts/tests/knowledge/test_exit_preview.py` | `49c61bce4683dde90fd45294f4ed7598368c6b50d92a3203809f0bfc139104b5` | `c4b475ff2b46aaf499d13cb387798ad3c87c6bae334ad03ff81fcc6b49a69ef3` |
| `scripts/tests/presets/test_preset_impact.py` | `6e7a84c939ab23322c9397c75d62ddf275175cbb85650d380481ea30a461872f` | `bf82f4c30e373d88555ffcebd8ebc27d236e1422bfea4458cc357dbad9c4e9de` |
| `scripts/tests/presets/test_preset_skill.py` | `b4f1832bc93c5e8b4392e89c1476f3d39b96eca7dc2436ce9f0d023e8941fd4b` | `447ed018799e246c460740f50e4e34aecaf3b13dd2edcada156b4df9104f3665` |
| `scripts/tests/presets/test_tags.py` | `414820a3ca7c66b8c9fc9b851408af70eb18a7d1816cddd583a3d6e2ba05cf41` | `572f6790dba5a1890e481f42077a68e8ed538d644f76c3ab95c1d00654ba0721` |

| New file (FW-relative) | SHA-256 |
| --- | --- |
| `references/reference-knowledge.md` | `2a619aeb46d6e27ce9992ae12de922f7dde91e1bf66ad2da23e85becaf568d02` |
| `scripts/src/x_ipe_secure_code/reference/__init__.py` | `0111ed36b340957afb2501d6f0d8d390ac6e84296eca97c4c12a9a3284c4369d` |
| `scripts/src/x_ipe_secure_code/reference/cache.py` | `3d2adec9f14aa15323d0619a93950fab7523ffb9b9f024140b9ab71ad11e5718` |
| `scripts/src/x_ipe_secure_code/reference/cli_parser.py` | `bddb25f946ae69e5ddf4bb98347e70ceb0880783942ea6e5a5e30ee7bdd39307` |
| `scripts/src/x_ipe_secure_code/reference/clock.py` | `a1e950344e5e07d1de386975118d1da212681d5293384d4e1a72410003d16545` |
| `scripts/src/x_ipe_secure_code/reference/fetch.py` | `c8ad4bf11a970fde49fba11f5b5e78dafa93908f5958462140b4b1d5300f6080` |
| `scripts/src/x_ipe_secure_code/reference/parse.py` | `f6fe9a699ad09ae12c8a45d2d77cc8a65a1c7f8bbc2152e2052bd5b8d212a4ae` |
| `scripts/src/x_ipe_secure_code/reference/policy_view.py` | `0a7b620a151385c26a95d86910e40bb77bf754e0dd601a36801e8a65ae505785` |
| `scripts/src/x_ipe_secure_code/reference/registry.py` | `49bb79a7459c9ad529219bfe6275c2c078294e6573c1136a81f88e3831010371` |
| `scripts/src/x_ipe_secure_code/reference/registry_ops.py` | `fff5155d8660ba06fad8878a09d1f4b713c3f6e67acdc4e6634dd5eecea80225` |
| `scripts/src/x_ipe_secure_code/reference/service.py` | `1f23ffc5d66cd689e648591e192b4636341e904ac8b29439dabca98fed7f1228` |
| `scripts/src/x_ipe_secure_code/reference/urls.py` | `ab3b4a532c93735dec4875ea457b9c9ff4c51c84bc5a163efa0ee0474257193f` |
| `scripts/tests/reference/capture_golden.py` | `b0e537ff17676063e2007688f4294d7a1a6cfbf8623c7a6b4ecb9ab93c74ded7` |
| `scripts/tests/reference/fixtures/golden/MANIFEST.json` | `0918b9c3eadafb9143e586b20d6db2a516e0696b21f76aeb8766140f9f26a7d4` |
| `scripts/tests/reference/fixtures/golden/pre001e/exit-preview.json` | `b59568941a8b8f49d84874eb3766b415a98228ad3c60d5f8038416d2c85f5f58` |
| `scripts/tests/reference/fixtures/golden/pre001e/preset-resolve.json` | `09a1017610501e16fd51b91642907bb69ac0c03379abd38ec5f9622ef06d6837` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-all.json` | `c6bef4421fa72068a60ca0cdd084e98f50fac5a2534c0597156ae922a5ee2876` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-rules.json` | `c8b8c8babb0403562831d9889277b7d33d0e233b9011a904dfade5e570305509` |
| `scripts/tests/reference/fixtures/golden/pre001e/resolve-versionless.json` | `86deb261979709abcbd515f232461629197c6021c88eb86a05889631efa11eda` |
| `scripts/tests/reference/fixtures/golden/pre001e/scope-save.json` | `6ff0055693fc8442f61f01c39f70fe230dc98dfca538add7883882ee34cb97ae` |
| `scripts/tests/reference/fixtures/golden/pre001e/scope-show.json` | `a4a8afd8a3697316bdf0424ce346f7164bde81d0ab5b3e012d1d285630f9be38` |
| `scripts/tests/reference/fixtures/golden/pre001e/status.json` | `a47f7e10808cc429def77184795879f77146ebb683ea972e0c086ecf0f839b87` |
| `scripts/tests/reference/fixtures/golden/pre001e/tag-show.json` | `ecb22fc8e7ee0839b11b1ec086bff6716a1d3316fd5f3853995faac273dc22d1` |
| `scripts/tests/reference/fixtures/pages/credentials.html` | `dc5eaf17dc01e2aef4d886617bb88758ab2edd251baff93ffac4e60fd6c0e521` |
| `scripts/tests/reference/fixtures/pages/cwe-79-nav-changed.html` | `01b086b658a4944733595d430d9424834464a8e81d69e87778792256438200a1` |
| `scripts/tests/reference/fixtures/pages/cwe-79-req-changed.html` | `402c0b1944e173f17a4369bad5e3b423884dcc923b5eb4d9b539e9532b51ed8e` |
| `scripts/tests/reference/fixtures/pages/cwe-79.html` | `4632315e510f7786ff2f158e3986211991f12d1b9fbb766d2b86b6f7214357af` |
| `scripts/tests/reference/fixtures/pages/cwe-89.html` | `44fba0298d6abc1162a4c6373746ca246ad442beb677151c0a57e1fd05b50bd4` |
| `scripts/tests/reference/fixtures/pages/cwe-top25-list.html` | `8ba9cfabcbbbf4cb982c0d55d78843a6a3edb88cb479c2a815674eca2e5c6fcd` |
| `scripts/tests/reference/fixtures/pages/hidden.html` | `774de649475925add8f20e70064bc1bbd0e20a2df6b994ae5cc2349c6ca48a75` |
| `scripts/tests/reference/fixtures/pages/injection.html` | `01bf54827fce47cbff8582c1c1563a7513a23461ba15a58da0beb01dd72642d1` |
| `scripts/tests/reference/fixtures/pages/latin1.html` | `f6f67bf08b1f3bc83fc4b9d2f5477a658b400588a22eb6a072244e8609db03c7` |
| `scripts/tests/reference/fixtures/pages/nav-only.html` | `bedc68e1c30a6bdfdad4dcfd9621f01652775e375031f8c6f27a137fa9bb5b40` |
| `scripts/tests/reference/fixtures/pages/owasp-2025-a01.md` | `9d1069fac4c0669a57e4a4804cdbdb40ffedc157a609ae12be51baaab6b59a8d` |
| `scripts/tests/reference/netguard.py` | `2f5817892bab821aad2b8044e2926ad83b36c0edd804dcf8b629bd0c3ab6635d` |
| `scripts/tests/reference/refhelp.py` | `7b160262a5f8d27ee3e558ae908dc1c24c9e8a2f887864ef991d753247bdc0c7` |
| `scripts/tests/reference/test_reference_cache.py` | `d421b114bb6da92214803f5fd5fde6d9b6a742ee290844cd671649b76e735810` |
| `scripts/tests/reference/test_reference_e2e.py` | `cf8fe7045ac5d120376c5af987d9ec7a74bd1e03d8df76b6e2fb832af3799994` |
| `scripts/tests/reference/test_reference_fetch.py` | `41261752eb53ebc6cee96415e7087b78444515b08beb7ce752a837b07a84edb8` |
| `scripts/tests/reference/test_reference_gate.py` | `be50c47fd5639abe4a93f9a03a4d2851f95fff6e5fb1cbb950f1f37fa11057f9` |
| `scripts/tests/reference/test_reference_isolation.py` | `2d1c8b88f149cbe3982ceffa28eb47ed72c0d42c3da100a716899199362d59d7` |
| `scripts/tests/reference/test_reference_parse.py` | `f66b77489485a1a6b5958975bc65e2672475943d3d4757866b0aa2113698c49c` |
| `scripts/tests/reference/test_reference_plugins.py` | `f75105b1f5697711c930cbc1802a6751fafbbb938450f06c35867579fbf28efb` |
| `scripts/tests/reference/test_reference_registry.py` | `d58e27e00655005e27cf40d7aca5a7d6cca6596091272adaf332b05dbe1ef77a` |
| `scripts/tests/reference/test_reference_resolve.py` | `d2bd74a24f319d0a6d6dab0cfca038f418855815744887bd91796b5649e76322` |
| `scripts/tests/reference/test_reference_skill.py` | `6e3f1b1efd672f696fd2154d22481d1dc64140e33a730595561b7db340c611d5` |
| `scripts/tests/reference/test_reference_urls.py` | `6f778961fbc4e642a736a8c867b84aad7bf04d4a1367787eb53f95d1d7213c59` |

### 12.6 Delivery and outcome (final)

Engineering delivery: **verified** for all 81 ACs at the hashes in §12.5, with 267 tests in `tests/reference/`. Regression: **0 failures** (3502 passed, 7 skipped). The delivered-file change set equals the design change list + E3 (`presets.py`, P4) + closed list items 1–7 + the ruled maintenance points. Stakeholder outcome: **not measured**. Open for the owner at closing: P-notes P1–P9 (incl. the P6 extension note), design errata E1–E3, local exact-path commit (B8 = A), then FEATURE-001-E acceptance.
