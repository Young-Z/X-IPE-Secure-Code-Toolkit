# Implementation Report — FEATURE-002-F Temporary Check Scripts

> Feature: FEATURE-002-F (EPIC-002) · Task: TASK-085 (Code Implementation, TDD), lifecycle owner Sage, implementation worker · Date: 2026-10-24
> Mode: free mode, workflow N/A; no board, memory or successor action was taken by this worker (owner exclusions). Git: one read-only `git log -1` at step 0 and one accidental argument-less `git mv` (refused by git, no repository change); no other Git command.
> Scope: 74 active ACs (AC-002F-01a…12d; AC-002F-05f not applicable, B12 = A). Consumes CR-TASK-077 (TASK-083) unchanged.
> **Current state (DAO-005 follow-up, 2026-10-24 — §12 is authoritative and supersedes §4–§11 where they differ):** Engineering delivery of FEATURE-002-F: **verified** for all 74 active ACs by 353 new tests (349 default + 4 opt-in real-runtime). Spec v1.3.3 (`fcf0f92a…`), design v1.2.1 errata E1–E4 (`8cd4978f…`). Full suite **3234 passed, 0 failed, 8 skipped** (`log-full-dao005`; the flaky delivered `test_02e` passed in this run, no rerun). Real runtime: registration through the command and **all 20 conformance probes pass (P-00…P-18, P-13b) with no seeded record**; full helper flow on the real record. Delivered-file changes = the 11 closed-list files + the 3 DAO-005 maintenance points. **Stakeholder outcome: not measured.**
> Initial delivery result (report `9e5fefcb`, kept for history): **Engineering delivery of FEATURE-002-F: verified** for all 74 active ACs by 324 new tests (320 default + 4 opt-in real-runtime). **Regression: blocked by 3 STOP-rule findings** — three delivered tests (one FEATURE-002-G, two FEATURE-001-G) pin the bytes of the Guard skill package / the `init` payload list and fail only because of design-mandated 002-F changes; they were **not** edited (§5, DEC-I17; minimal edits proposed and scratch-verified). Full suite (final tree, run 3): 3201 passed, 4 failed (3 STOP + 1 flaky delivered drafting test that passes alone), 8 skipped (§6). New-code coverage 92 %. **Stakeholder outcome: not measured.**

## 1. Authoritative Inputs (verified before any change)

| Input | Expected | Found | Match |
| --- | --- | --- | --- |
| [specification.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/specification.md) v1.3.2 | `eafc9894…` | `eafc98944558f4fb98964af8b4fd73a01cfece489c33bd36e42f523e2d02e7f0` | yes |
| [technical-design.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/technical-design.md) v1.2 + Re-review Nits | `4202a1c0…` | `4202a1c06c87f775f2b46184fd7cc440fa43091e8d2298b5118aa19713b6376a` | yes |
| `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` DAO-014/017/018/019 | read | read (guidance sections in full) | — |
| `decisions_made_feature_refinement.md` DAO-007/DAO-014, `human_decisions.md` B12 = A | read | B12 = A row present | — |

Binding rulings applied: DAO-014 TD (DEC-3 variant B: engine `_met`/`conclude` unchanged; T-4 `_relevant_paths` branch only; DEC-2 own walker; DEC-5 image env), DAO-017 (closed list §1.1, byte-identity tests, reservation via `adapters`, fixture-prefix scan), DAO-018 (07c v1.3.1 honest limit and gap line; PID-1 launcher, P-17, ERA maintenance), DAO-019 (implementation gate TASK-083 accepted; closed lists; launcher read-only and digest-verified; P-17 hardening; real runtime only with local images).

## 2. Step 0 — Baseline (before any code change)

- Toolkit tree `ai-secure-code-toolkit/` (excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.git`): **291 files**, per-file SHA-256 list `impl-085/baseline-step0.sha256`; list digest (closing-report method) `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68` — equal to the TASK-084 final tree (HEAD 80ec190). The same list is frozen in the new test fixture `tests/helpers/fixtures/delivered_step0.json` (closed-list test).
- Owner-supplied baseline: 2885 passed / 4 skipped.
- **Golden pre-002-F outputs** captured with the delivered code before any 002-F change, twice, byte-identical between the captures (`tests/helpers/fixtures/pre_002f/`, 33 files): `guard conclude/show` result JSON + Markdown of a Fail run and a Cannot-confirm run, `guard cancel` finalize result + report, plan validation outputs (6 refused, accepted, refused-again), record validation outputs (6 refused, 2 accepted, stored plan), review outputs (refused, accepted) and a further conclude; frozen Guard clock; verification ids, times, project path, footer and renderer digest normalised (the renderer digest changes with any `report.py` byte by CR-TASK-086 design).
- Interface re-read at this revision: `budget.py` (TASK-077 `covers.helpers`, `_known_helpers`), `service.record_review` (`used_items["helpers"]`), `records.py`, `engine.py`, `report.py` (incl. CR-TASK-086 renderer manifest), `targets.py`, `toolrun.py`, `toolctl.py`, `cancel.py`, `adapters/process.py`, `adapters/safe_io.py`, `cli.py`, `tools_service.py`, Guard `SKILL.md` and `references/guard-records.md`. Several delivered files changed after the design was written (FEATURE-002-G, CR-TASK-086, FEATURE-001-G); the conflicts this created are §5 and DEC-I1/I17.

## 3. TDD Steps — RED / GREEN

Logs: session evidence folder `impl-085/log-*.txt`. All runs: `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=$EV/tmp-<name> …` from `FW/scripts` (`FW` = `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework`).

| Design step | Tests | RED evidence | GREEN |
| --- | --- | --- | --- |
| 1 scaffolding | `fake_runtime.py`, `helperhelp.py`, `boundaryhelp.py` (+ step-0 goldens) | — (infrastructure) | used by all |
| 2 `model.py`, `static.py` | `test_helper_static.py` (80) | `log-red-static`: 80 failed, `ModuleNotFoundError …helpers.static` (written and run before the module) | 80 passed |
| 3 reservation, `plan_rules.py`, `records.py` hooks | `test_helper_plan.py` (17), `test_helper_boundary.py` (6) | `log-red-plan`: 17 failed (16 plan + engine-branch test), 6 passed (the regression guards and one delivered unknown-field refusal) before the hooks | 23 passed |
| 4 `registry`, `runtime`, `canonical`, CLI | `test_helper_registry.py` (6), `test_helper_runtime.py` (62) | `log-red-registry`: 5 failed (`register_image` absent), 1 passed (state functions written first) | passed |
| 5 `conformance.py` + probe suite | `test_helper_conformance.py` (3), `test_helper_conformance_real.py` (4, opt-in) | whole-suite reproduction below | passed (real: §7) |
| 6 `snapshot.py` | `test_helper_snapshot.py` (7) | reproduction below | 7 passed |
| 7 launcher, `execute*.py`, `submit.py` | `test_helper_launcher.py` (10), `test_helper_submit.py` (17) | reproduction below | passed |
| 8 `review.py`, `_subject` hook, engine branch | `test_helper_review.py` (7), boundary engine test | `log-red-plan` (engine branch test failed before the edit) | passed |
| 9 `grant.py` | `test_helper_grant.py` (3) | reproduction below | 3 passed |
| 10 run path, `results.py`, `evidence.py` | `test_helper_execute.py` (17), `test_helper_results.py` (40), `test_helper_budget.py` (4), `test_helper_cancel.py` (3) | reproduction below | passed |
| 11 report part + attach + render | `test_helper_report.py` (9), `test_helper_ledger.py` (14), `test_helper_flow.py` (4) | reproduction below | passed |
| 12 skill text | `test_helper_skill.py` (11) | reproduction below (11 failed against the step-0 skill text) | 11 passed |

**Whole-suite RED against the step-0 product tree** (`log-red-baseline-all`): a scratch copy of the toolkit whose product files were restored to their step-0 bytes by reversing exactly the 002-F insertions (every product file then **hash-equal to the step-0 list**, which also proves the delivered deltas are only those insertions), with the final `tests/helpers/`: **209 failed, 96 errors (fixture setup: missing modules), 6 passed, 4 skipped**. The 6 passing are the boundary regression guards (three byte-identity tests, the fixture-prefix scan, the closed-list diff — all expected to pass at the baseline) and one plan refusal the delivered code already produced (unknown field). Honest note: for steps 5–12 the RED evidence is this module-absent/step-0 reproduction, not a capture taken before each module was written.

## 4. Files

`FW` = `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework`. Final toolkit list digest `23b67518cfd91f3f586939a7c55de41177d65f039c45dcc3f912f3f6cba3d05d` (368 files).

### 4.1 Changed delivered files (all additive; exactly the closed list §1.1)

| File | Delta (lines) | SHA-256 (step 0 → final) |
| --- | --- | --- |
| `FW/scripts/src/x_ipe_secure_code/adapters/__init__.py` | +10 −0 | `48f369c5d6b7686a3bad50488c70cc67e00ecf62df075dbcb3163ef9d466319e` → `706daeda760f5420d4c1605e8680cca7be709603b1984eeff203b47564cb5c26` |
| `FW/scripts/src/x_ipe_secure_code/cli.py` | +9 −0 | `3ed4990e46eb5782901740a8d643b2955bd1d848dbd047fa568058fffb5080a0` → `4f0d63ac5f0b4a0dd88a42f6e463cac5f80c8fa683478acd7d947e2c35e8d0e1` |
| `FW/scripts/src/x_ipe_secure_code/guard/cancel.py` | +2 −0 | `f26ed77ddd856f89b1b160532c9b0a6d6ec535b4d9f6fc6f9069d6f13602b6b6` → `981395731b4ebc1e3a92167864815ca2deaf5c1c8dc8b1fd2523c56620e97f12` |
| `FW/scripts/src/x_ipe_secure_code/guard/engine.py` | +3 −0 | `c7d1000299bb4ff7d4e0fea971bbb8cd6297287f98dfab4b07336bb26d8a9606` → `a2bf29b633814d502594ab06f42c04ca2268a75c86fbfd40001ac948c601a88a` |
| `FW/scripts/src/x_ipe_secure_code/guard/records.py` | +14 −1 | `9e976aa0191e4f4ef00496807e3a63369d476383e50f01e89896858745e04157` → `277934c27bbb34648d269a5dbde6d1d4dc36e0b5d27f9dd7f090af9c35b7ecde` |
| `FW/scripts/src/x_ipe_secure_code/guard/report.py` | +12 −0 | `24bd024787463b14240e509eba6e5146506ffd1aeac8904cc75bbf2076537499` → `c30a3ddb17019f9b4ae456030d27a5ecaf07da3294fb662b7995e2eaaac73c70` |
| `FW/scripts/src/x_ipe_secure_code/guard/service.py` | +6 −0 | `40113b940365c66d460801b40b045a88ce07df4cb64b1b6b0c94055b3b2aa8a5` → `4c6935d8b8bccfa67e6de4c19fbb497b852b46e8f5f5ee910d52cc8bb3085e47` |
| `FW/scripts/src/x_ipe_secure_code/tools_service.py` | +14 −0 | `e64e955a6e6186230ab7e87e694dee03087dfd4912ac2af45968e565cfb5eb25` → `5d2b91fab53a88219b5df299b8f189925b5e82f9453bd81dbd2602c7e9fc1d93` |
| `FW/scripts/tests/carriers/carhelp.py` | +21 −0 | `9f97e103b0aa3fa06e89e9fc6b6564b603d9e55d048cb93529ffca1bc450a638` → `b001244e5fa4a60a37f251117888657a8b7cdc20d4cecd0742609f3c3edb076e` |
| `x-ipe-secure-code-toolkit-guard/SKILL.md` | +47 −3 | `4bcb188fa0947dfd01474a4d54df54a6454e67e24fc1c0896c65ccb452da3d50` → `81733a4d41a853853709d90074280118bf538a82f7bee7d0550279b2768071ef` |
| `x-ipe-secure-code-toolkit-guard/references/guard-records.md` | +130 −1 | `868f2da821fd93e54060ea0c707fe0cd84203c4a332d103f865456cf36f33f85` → `766b8def39a8afd0d816b0c05fdc53ba1a9072afc08533cca63e2248e8c42130` |

Deltas: `adapters/__init__.py` two reservation functions (+10); `records.py` plan/method-change `gap` hooks, helper reservation clauses, `_subject` first statement (+14, the import line extended); `engine.py` the `_relevant_paths` helper branch (+3, the only engine edit; tolerant `.get` form, DEC-I2); `service.py` imports, `on_recorded` call in `record_review`, `attach` in `_conclude_open` (+6); `cancel.py` import + `attach` in `finalize_frozen` (+2); `report.py` section call + `_helper_section` (+12, DEC-I1); `cli.py` import, two parser registrations, two tools branches, helper dispatch (+9); `tools_service.py` two delegating functions (+14); Guard `SKILL.md` §14.3 (2 replacements + step 5c, +47/−3); `references/guard-records.md` §14.4 (line-74 coverage text + appended section, +130/−1); `tests/carriers/carhelp.py` ERA append (+21, DEC-I18).

### 4.2 New files

| File | Kind | SHA-256 |
| --- | --- | --- |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/__init__.py` | new | `e0847ee241cbeda8efde0a3acf2f09a032267ab11f93986916104c77ef6aa456` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/canonical.py` | new | `4689eab3e3040901760cb177ee2c62394ea8c2388daa763f665c19d591e9cb7e` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/cli_args.py` | new | `2e6105f5675ecc69919fd457d4bda467b9a5c3ad9d62bfdecdb22cb9f7150328` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/conformance.py` | new | `6772aa174f900cf1f9c8d8e487059924603cdb14fb436ef9978c2f702271cd74` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/evidence.py` | new | `d6e204191b40b23d510f948f8d66caaa9b31159d6cf5d4c2b4d5eb228ce71df0` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/execute.py` | new | `1f94064ae6092abb921f5409684c86cb5650036678d32a1b35a39665ec6b1635` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/execute_io.py` | new | `b8e3948bdbf9bb6bc0395b8b26de283ead99afff13469fca71194313e1a9fe49` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/grant.py` | new | `97467568ce454d2a6210b45d99e2fff50cdca69c7c3e76eedf82316776cc2e83` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/model.py` | new | `8026a441604342608f4931e3ff153cb56e3b291e4bba6eee4e3580c724968774` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/payload/launcher.py` | new | `5e04622572486931eeb6bbc062a70cb96c856415e31ea3bf788031eb580b70bd` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/plan_rules.py` | new | `313e76f0a05fd14cdee0709bef308b37be505123d67ced50304e74b1a60b8562` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/probes/suite.probe` | new | `b053cf0a47713b92b8836e928a4ccee972cdd414a65db2e2185e69fac08ff5af` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/registry.py` | new | `798c09eb2402bf417c1eb982866e311c99abb7cf00466fe17d9cd7667e8f0a52` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/report.py` | new | `0bbf1f7d621f0b263b18e30ea76bd73cbd8a776c51631fd8826909b2229b988c` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/results.py` | new | `786822ee7a2e0144818523bc9777da2d552e3074009dec5a312b2ad35df7e42a` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/review.py` | new | `d50f96c76b733cc35c191009d4b4d5c67ed825bd9495a90298ce5e761384880f` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/runtime.py` | new | `2a061fa281442c95f7d656aaa875f24bbb9f63ef7fb0e904b15526495f5acd46` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/snapshot.py` | new | `d8242fe3866dcd98d4f360273c5194d5b9692d6e3e64fd2d78e3bf25f037fc0c` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/static.py` | new | `d28e349cf342ce395fb8b1f7f3450f9f086d7469499763f12f6fa9b5827ef7ff` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/submit.py` | new | `bdf979a2eff76b1a42a837417312618ffb8b685edfe05b574f6883be9d52e8c9` |
| `FW/scripts/tests/helpers/boundaryhelp.py` | new | `46221fcc60575d5084da383137bafedacd6392c171e0537beb6da1c3d916ed3a` |
| `FW/scripts/tests/helpers/fake_runtime.py` | new | `c6db0b98e70fdd8fce489cc34b1062773474464192446d2cb319fb9e2ffb8030` |
| `FW/scripts/tests/helpers/fixtures/delivered_step0.json` | new | `4f5757c7435d3531265fd16c16acaf3ae265e0a29f84589dd704117a6bc1f010` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/a-conclude.json` | new | `bade0e4658208e82340cee97b58c1b86362210edd208995ef9ad778694e510f3` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/a-report.md` | new | `479532a8b2b1bf0941250aaac3a3215ae0381425e16b45bbc89f3d76d3df4530` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/a-result.json` | new | `149dfca9233db31ae38ad4a032ff2c8d4dfa718cdcd05662174f1da0c9272080` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/a-show.json` | new | `aafc1ea1dbcd0f098a43eb6b39d2453a18e3f1761fb5eaa91d6f4a899ed6fba6` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/b-conclude.json` | new | `e2140ac06dedf224789bf6e045ec400994c8f05e5e9bc6ed78e458614bcde27f` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/b-report.md` | new | `674a9be6e6f3bbece12615e73ceba211729080bd3de90af656dc78146ae92f31` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/b-result.json` | new | `55f14cb29873f9bfb7e7dce4345c4e87309af8407da6cef2131d772947732759` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/c-cancel.json` | new | `87efada5a503342b44b6cdd38b724edfe59be9c144013eee7af90ed9e61d15ba` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/c-report.md` | new | `9c85c85942c48efb804ba371e7e22e05cf0f6e53b0c66192c5d2d1836095869e` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/c-result.json` | new | `10304e3f8526788239c7c71594dea610fe06de6eef44971411b865cc5c4be205` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/c-show-open.json` | new | `07bca178ae22480df3c2f79265b43ff021a1e62425cba8266a7cda819ac19507` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-accepted.json` | new | `e2389fd1d88b7adcf5dc395fc057e8415caaa370df9799873c2c55f33ef66539` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-adapter-kind.json` | new | `e6c5319512b8f3709c328b704359068a66b0410cf2b3f2e51aea9ee370bf8b33` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-choice-missing.json` | new | `4df344e9bce142bca24efbaec8c2b5d0cf2b6e3260b3d6027d867c1af3cc61ba` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-choice-unknown-key.json` | new | `097acb26ca966c72d158c6a9de5fd6a2c973e0dabb887626993072cf09a43332` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-duplicate-method.json` | new | `56e0650f400dbc0b844e279cfc0c2dd36fc94f0c5336ffcda9d97d7b60e1dc7b` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-rule-not-adopted.json` | new | `668c6e2a4d2a949fbc0199e1dfc6cacbcdcda0f37415a39bc3e3af4586fc25b1` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-twice.json` | new | `bc2b2de6113983c99b6bb425113d7735d4e58cc248751dc3855e3d9b0ec7e4ec` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/d-plan-unknown-field.json` | new | `ecaedd3d92f54932bfea91cfaa37b8dc42081a93eb90305b1bc1c79c37510750` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-accepted.json` | new | `c32518a356e09ed16cf9ef55a837c31be8c312d9c6e3b148f9290cc2bfa853ca` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-change-accepted.json` | new | `6d785d781e354aad4c4645b5c736f38b5988ec3c1d590e38756b6720dc44ff8e` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-change-adapter-kind.json` | new | `125fa455eca883e90a05e9fab07f3a15df4e2d8d8a68ce0a8295c2e7c6dd24ae` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-change-unknown-field.json` | new | `c819786f58d682a3af19ac8088c7aa46f03f8e81f3addf8bc03bf445184136b7` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-tool-id.json` | new | `70b042d5ecb48608f750f2f150b44ce2ec6696dedc32d5054d783718d30c3554` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-tool-method.json` | new | `70b042d5ecb48608f750f2f150b44ce2ec6696dedc32d5054d783718d30c3554` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-tool-source.json` | new | `35341b8975cfcf20779806026dff9f687d38570af66e16e2581c3e6ca34d9619` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-record-unknown-check.json` | new | `8acc77f626a0acc51737267fbfe06e49979ddfb5746feff63b4ab132825081a4` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/e-state-plan.json` | new | `737fabe5a37065303e103e09fa2eeddf5967af9b42392df239990bbe0abad055` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/f-conclude.json` | new | `b06f93565260d98f2b3b7bba6f7813eb10f37ea9e60cbc82896e2426329cec5c` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/f-report.md` | new | `2f453ac00b6397fea723f827fca814425e37ea55924bf7062f2e0aa01ecd8e56` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/f-result.json` | new | `6fe7406c035c2b80b94c795f286bc4cc74630ef8916d55d26747eb73c8ed7321` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/f-review-accepted.json` | new | `72e9fd4c44830a389bee3cb5e60e5ac323e9ff2b59d0bad3ec7199807956a757` |
| `FW/scripts/tests/helpers/fixtures/pre_002f/f-review-unknown-type.json` | new | `b3ba1703029d0044b375082694cc57aaa290a9a80df7d2b3dffeaf307c1f9a20` |
| `FW/scripts/tests/helpers/helperhelp.py` | new | `8d609ba1f770a6c943fca20479f39fe416c7292824e3b8456486d52ec2600958` |
| `FW/scripts/tests/helpers/test_helper_boundary.py` | new | `e42dbc8efcc4ea8612631c774aeba4f01cbb08e730ef796e493bd3760536a809` |
| `FW/scripts/tests/helpers/test_helper_budget.py` | new | `ee126a46c6920f687d30136e91df1546c2fe0d277a1f460076568a79bcc71820` |
| `FW/scripts/tests/helpers/test_helper_cancel.py` | new | `d13a4ba9a286713347d5d2bf97b9bd6a7bfaf073c98c47ac601a1bca504fda2e` |
| `FW/scripts/tests/helpers/test_helper_conformance.py` | new | `f2a45bdc4eb0d2ac05d4df0bf8c8b9687ca715dfc16a3b35dee05100e77b4823` |
| `FW/scripts/tests/helpers/test_helper_conformance_real.py` | new | `971ce7f68d03f7cc10ba22843116eb4c500378bee1450f3bb787e9651c00e951` |
| `FW/scripts/tests/helpers/test_helper_execute.py` | new | `d011bfa0d2ec2869cf63ca8cd4f32ccc7b06f3f18b3d04b311c05379516e41fb` |
| `FW/scripts/tests/helpers/test_helper_flow.py` | new | `084fab4820665a79016c306b36b1398ebe66da8c527293b491fc02b4878655c5` |
| `FW/scripts/tests/helpers/test_helper_grant.py` | new | `e81b39cbc583b5f4a378c2464d5fb19dece09b9710796c33c94ca06c6640ae11` |
| `FW/scripts/tests/helpers/test_helper_launcher.py` | new | `f954e03e46774866a5fceca9ee9d00fb9e20e7fdd722cc58302cd1b838584810` |
| `FW/scripts/tests/helpers/test_helper_ledger.py` | new | `c09329185cfbafca87861e2e36b4997817bbf246659ca2f18d08fe4813829e7a` |
| `FW/scripts/tests/helpers/test_helper_plan.py` | new | `65f10001ed878450589737c89c6d96504eead145024b0d35929fa2e516c5ca6a` |
| `FW/scripts/tests/helpers/test_helper_registry.py` | new | `2670ed27f0f7fd44ca619680bd2bfa59df8287956a5558fd662ac077439eeeae` |
| `FW/scripts/tests/helpers/test_helper_report.py` | new | `b5897f523d7da251422e23c1f4547652bf829d04c4049ed61ce0df43b6dc3fac` |
| `FW/scripts/tests/helpers/test_helper_results.py` | new | `979b10dd0ed3f50821d222bf07aaba6f459e1f6edc2af0aad82fe7f6609165ce` |
| `FW/scripts/tests/helpers/test_helper_review.py` | new | `d03c6a962d3467a4751a986e1c11f2128ebd69dbbc1e64c2c65bd7c83c1b6bb6` |
| `FW/scripts/tests/helpers/test_helper_runtime.py` | new | `53185fbdf14180e847f022903795a215dd93e21b291ea7a8a75a3e26594fd512` |
| `FW/scripts/tests/helpers/test_helper_skill.py` | new | `5855084e292e75d8799ce7ac9e37ac07b162c15615ba45c11422e13a8c7bac0d` |
| `FW/scripts/tests/helpers/test_helper_snapshot.py` | new | `eed2e09f00b9aa4e6b9c1bb1846bfafdf6b7089f1c69671529696aeb585c35e8` |
| `FW/scripts/tests/helpers/test_helper_static.py` | new | `ee219f76ab37bda08628c80e67b6356405b8717ae50b168a24d2041042604a47` |
| `FW/scripts/tests/helpers/test_helper_submit.py` | new | `04d9a88a4d3f3c1b359b217c6fc90ea7a00dca4aee088c9ea215324e29a24123` |

Module sizes (800-line rule, `tests/test_module_size.py` passing): `canonical 391`, `cli_args 62`, `conformance 427`, `evidence 105`, `execute 733`, `execute_io 276`, `grant 185`, `model 174`, `plan_rules 102`, `registry 272`, `report 270`, `results 197`, `review 217`, `runtime 272`, `snapshot 272`, `static 286`, `submit 491`, `payload/launcher.py 129`, `probes/suite.probe 395`; delivered: `records 638`, `engine 436`, `service 607`, `cancel 190`, `report 717`, `cli 546`, `tools_service 90`.

## 5. Delivered-File Parity and STOP-rule Findings

Final tree vs step-0 baseline (per-file SHA-256, `impl-085/parity.txt`): **changed = exactly the 11 files of the closed list §1.1** (verified also by `test_helper_boundary.py::test_closed_list_diff`); **removed = none**; **added = 77 files**, all FEATURE-002-F (20 product payload files, 57 test files incl. 33 goldens and the step-0 hash fixture). `engine.py` minus the inserted 3-line branch hashes to its step-0 value (asserted by the boundary test). No other delivered module, test, fixture, skill or reference file changed; `pyproject.toml` and `uv.lock` unchanged; no new dependency.

### STOP-rule findings (not edited; ruling needed — DEC-I17)

The design-mandated Guard skill text (§14.3/§14.4) and the new payload files make three delivered tests fail. They are not in the closed list (only the `ERA_001A_REMOVED` append is), so they were reported, not edited:

1. `tests/guard/test_compare_skill.py::test_01h_only_added_section` (FEATURE-002-G): pins `DELIVERED_SIZE = 12017` / `DELIVERED_SHA256 = cdbfc5bc…`, the Guard `SKILL.md` prefix before "## Comparing two reports". §14.3's replacements and step 5c lie inside that prefix (the design read `SKILL.md` at `cdbfc5bc`, before 002-G pinned it).
2. `tests/drafting/test_draft_regression.py::test_08d_guard_copilot_inputs_lack_block_bytes_skills_unchanged` (FEATURE-001-G): `fixtures/guard_copilot_hashes.json` pins the Guard `SKILL.md` and `guard-records.md` hashes (maintenance point DAO-004 DEC-I13: "if the change is legitimate and approved, update the fixture").
3. `tests/drafting/test_draft_regression.py::test_08a_delivered_suites_unchanged_and_outputs_equal_pre_001g` (FEATURE-001-G): the `init` golden lists every payload file; the 20 new `guard/helpers/` payload files appear (the same class as the ERA maintenance, but in `drafthelp.py`).

Proposed minimal edits (`impl-085/stop-proposed.diff`), verified in a scratch copy of the final tree (`log-stop-scratch.txt`: `test_compare_skill.py` + `test_draft_regression.py` **11 passed**; ruff clean):

```text
tests/guard/test_compare_skill.py
-DELIVERED_SIZE = 12017
-DELIVERED_SHA256 = "cdbfc5bc9c312604641380feff7f8e704a158c97701bacfad7cd4927fd1da292"
+# superseded per FEATURE-002-F §14.3 (Guard skill text before this section) — re-run
+DELIVERED_SIZE = 16160
+DELIVERED_SHA256 = "e24862a3750071d772d6ae6adda5dae832510da4e61f73c15ef9431167083b73"
tests/drafting/fixtures/guard_copilot_hashes.json (DAO-004 DEC-I13 maintenance point)
-  "x-ipe-secure-code-toolkit-guard/SKILL.md": "4bcb188f…3d50",
-  "x-ipe-secure-code-toolkit-guard/references/guard-records.md": "868f2da8…3f85"
+  "x-ipe-secure-code-toolkit-guard/SKILL.md": "81733a4d41a853853709d90074280118bf538a82f7bee7d0550279b2768071ef",
+  "x-ipe-secure-code-toolkit-guard/references/guard-records.md": "766b8def39a8afd0d816b0c05fdc53ba1a9072afc08533cca63e2248e8c42130"
tests/drafting/drafthelp.py (pre_001g_outputs)
-        init["data"]["files"]["created"] = [p for p in created if not _new_payload(p)]
+        # superseded per FEATURE-002-F (its guard/helpers payload is a later declared growth) — re-run
+        later = [p for p in created if "/guard/helpers/" in p]
+        init["data"]["files"]["created"] = [p for p in created if not _new_payload(p) and p not in later]
```

Alternative (if the representative prefers not to touch these tests): keep the delivered skill bytes and move the helper guidance to a new skill reference — but `test_01h` also forbids any new heading/command in the appended part and AC-002F-01c/05d/08e/10a–10d name the skill package, so a skill-text change is unavoidable; the proposed edits are the smallest.

## 6. Validation

| Check | Result |
| --- | --- |
| New tests `tests/helpers` (final tree) | 320 passed (default run), 4 real-runtime tests skipped by default (`SECURE_CODE_HELPER_REAL=1` to run) |
| Real-runtime tests (final tree) — `log-real-final` | **4 passed** in 212 s (Docker Desktop 4.87 / Engine 29.7.2, LinuxKit arm64, `python:3.12-slim` already local, `--network none`, nothing pulled) |
| **Full suite run 3 (final tree) — `log-full-3`** | **3201 passed, 4 failed, 8 skipped, 23 deselected in 2045.4 s** — failures: the 3 STOP findings (§5: `tests/guard/test_compare_skill.py::test_01h_only_added_section`, `tests/drafting/test_draft_regression.py::test_08a_delivered_suites_unchanged_and_outputs_equal_pre_001g`, `::test_08d_guard_copilot_inputs_lack_block_bytes_skills_unchanged`) + the flaky delivered `tests/drafting/test_draft_cli_approve.py::test_02e_equivalent_to_plain_update_time_normalised` (changelog diff hunk differs under full-suite load; re-run alone 5/5 passed after run 3 — `log-flaky02e-1…5`; drafting code untouched by 002-F, see §10). All 320 new default tests and every other delivered test passed |
| Full suite run 2 (tree before the `dont_write_bytecode` test-infra line) — `log-full-2` | 3201 passed, 4 failed (the 3 STOP findings + `tests/drafting/test_draft_cli_approve.py::test_02e_equivalent_to_plain_update_time_normalised`, a delivered time-normalisation test unrelated to 002-F: passed 5/5 when re-run alone, passed in run 1, failed again in run 3 and passed 5/5 alone again — flaky under load, see §10), 8 skipped, 23 deselected, 2013.7 s |
| Full suite run 1 (superseded: probe source still `.py`, real test file edited during the run) — `log-full-1` | 3200 passed, 4 failed (3 STOP findings + `test_guard_egress.py::test_05f_no_network_client_outside_egress_module`, fixed: DEC-I10), 7 skipped |
| Count reconciliation | 2885 + 4 skipped (baseline) + 320 new default tests + 4 new opt-in skipped = 3205 run + 8 skipped |
| `ruff check --no-cache src tests` | All checks passed |
| Module sizes (`tests/test_module_size.py`) | passed (largest new: `execute.py` 733) |
| New-code coverage (`--cov=x_ipe_secure_code.guard.helpers`, tests/helpers, fake runtime) — `log-cov` | 320 passed, 4 skipped (1015.6 s); **92 %** line coverage (2462 statements, 188 missed); per module 85–100 % (`snapshot.py` 85, `runtime.py` 86, `review.py` 87, `cli_args.py` 88, `execute.py` 90, `submit.py` 90, `conformance.py` 91, `registry.py` 91, `execute_io.py` 93, `report.py` 95, `results.py` 95, `canonical.py` 98, `model.py` 98, `grant.py` 99, `static.py` 99, `evidence.py`/`plan_rules.py` 100). `payload/launcher.py` and `probes/suite.probe` run inside the container and are exercised by the real tests, not measured |
| Forbidden-substring scan (case-insensitive, the three hook-rejected strings) over all new/changed toolkit files and this report | 0 hits |
| Artifacts left in `ai-secure-code-toolkit/` (`__pycache__`, `.pytest_cache`, `.ruff_cache`, `*.pyc`, `.coverage*`, temp) | none (a `tests/support/__pycache__` written by the fake runtime's audit join was removed and prevented: `sys.dont_write_bytecode` in the fake header) |
| Runtime objects left (`docker ps -a` / `volume ls --filter label=x-ipe.secure-code=helper`, re-checked after run 3 and coverage) | none (the 2 pre-existing unrelated user containers untouched) |

## 7. Real-Runtime Evidence (DAO-014 binding 3; opt-in, local image only)

Conformance suite on Docker Desktop (LinuxKit arm64) with `python:3.12-slim` (`sha256:a6e34c59…`, already local): P-00 (semantic verifier on every probe container; rendering identical), P-02…P-18 **pass**, including P-08 (NoNewPrivs 1, Seccomp 2, filters 1, `add_key`/`request_key`/`keyctl`/`unshare(CLONE_NEWUSER)` → EPERM, profile builtin), P-09 (fork EAGAIN at 62), P-10 (OOM-killed), P-11 (EMFILE at 253), P-12 (ENOSPC at 16 MiB; exec from `/tmp` EACCES), P-13 (results ENOSPC at 2 MiB, 15 files), P-13b (all 9 malicious result variants rejected by the tar validator), P-14 (time), P-15 (output), P-16 (attach), P-17 (cpu, churn, sleeper, early-exit, attack-pid1: container stopped at ≈5.4 s without the toolkit; ptrace / process_vm_writev against PID 1 refused), P-18 (cleanup normal + cancel).

**P-01 fails under the strict reading**: outbound connect ENETUNREACH and DNS fail, but `/sys/class/net` lists kernel fallback tunnel devices (`erspan0, gre0, gretap0, ip6_vti0, ip6gre0, ip6tnl0, ip_vti0, sit0, tunl0`, all `down`, no address) besides `lo`. The record is therefore `passed: false` and **helpers do not execute on this runtime** (fail closed) — DEC-I5.

Registration: both permitted local Python images (`python:3.12-slim`, `fat-uv-git:py312`) carry `GPG_KEY=<public fingerprint>`, which the credential patterns flag, so DEC-5 refuses them (`HELPER_IMAGE_UNSUPPORTED … GPG_KEY`; the refusal is asserted) — DEC-I4. The real tests therefore write the registration through the library seam after the **real** version probe container, and the full-flow test re-writes the real conformance record (real `rendered`, every probe marked passed, labelled "test seam") to prove the real execution path: compile probe, two sample containers (positive → finding, negative → clean), target container, collection, full coverage, post-run acceptance → `ok` evidence → check `met`; a bad script → `check_failed`; no runtime object left. This is orchestration evidence on a real runtime, **not** acceptance of P-01 or of the registration rule.

## 8. AC-to-Test Traceability (every active AC)

All paths `FW/scripts/tests/helpers/`. State: delivered **verified** (passing at the final tree) for every row; outcome **not measured**. "real" = `test_helper_conformance_real.py` (opt-in, passed at the final tree).

| AC | Tests (assert) |
| --- | --- |
| 01a | `test_helper_submit.py::test_01a_check_binding_refusals` (missing/unknown check, non-helper method, other verification's attempt; nothing stored) |
| 01b | `test_helper_plan.py::test_01b_planned_helper_method_stored_as_auxiliary_with_gap`, `::test_01b_helper_method_rules_refused[5]`, `::test_01b_gap_reason_required_and_validated[5]`, `::test_01b_gap_refused_for_checks_without_helper_method`, `::test_01b_method_change_adds_auxiliary_helper_with_gap` |
| 01c | `test_helper_skill.py::test_01c_real_gap_rules` |
| 01d | `test_helper_budget.py::test_01d_later_method_costs_extra` (planned pair 0 extra; method-change pair 1 extra) |
| 02a | `test_helper_submit.py::test_02a_missing_field_named[6]`, `::test_02a_stored_declaration_has_all_fields` |
| 02b | `test_helper_submit.py::test_02b_scope_rules` (link in a component, `..`, absolute, FIFO, outside target, missing, L-05), `::test_02b_scope_with_a_link_inside_refused` |
| 02c | `test_helper_submit.py::test_02c_compile_probe_syntax_version_unavailable` (one `compile` container only, `/helper` only; syntax, version change, daemon down → `check_failed`); real `test_real_helper_flow_with_seeded_conformance` (real compile probe passes) |
| 02d | `test_helper_static.py::test_02d_denied_modules[35]`, `::test_02d_each_rule[39]` (incl. captured/aliased writes, results-handle aliasing, `functools.partial(open…)`), `::test_m3_allowed_result_forms`, `::test_02d_tomllib_only_for_311_and_later`, `::test_02d_first_violation_deterministic`, `::test_02d_unparseable_fail_closed`, `::test_02d_credential_like_script_refused`; statement + SHA: `test_helper_submit.py::test_02a_stored_declaration_has_all_fields`, `::test_02e_state_checked_not_reviewed` |
| 02e | `test_helper_submit.py::test_02e_state_checked_not_reviewed` |
| 02f | `test_helper_static.py::test_02f_oversize_and_deep`, `test_helper_submit.py::test_02f_oversize_and_deep_no_probe` (no `create` issued) |
| 02g | `test_helper_submit.py::test_02g_sixth_helper_refused` |
| 03a | `test_helper_submit.py::test_03a_samples_origin_limits` (missing pos/neg, target file, byte-identical target copy, unlabelled formal example, outside scope, L-02 count and size; origin + SHA recorded) |
| 03b | `test_helper_execute.py::test_03b_samples_own_containers_mismatch_blocks_target`, `::test_03b_each_sample_own_container_same_configuration`, `::test_m1_samples_mismatch_blocks_and_retry_refused`, `::test_m1_samples_infrastructure_retry_same_attempt`; real flow (sample outcomes finding/clean) |
| 03c | `test_helper_review.py::test_03c_batch_reviewer_helper_subjects`, `::test_03c_subject_validation` |
| 03d | `test_helper_review.py::test_03d_changed_helper_needs_new_review_and_grant` |
| 03e | `test_helper_ledger.py::test_03e_rejected_failed_aux_equals_002a` (ledger and verdict equal the unchanged engine on the stored state) |
| 03f | `test_helper_review.py::test_03f_state_wording_separates` (show + report) |
| 03g | `test_helper_skill.py::test_03g_reviewer_requirement_untrusted` |
| 03h | `test_helper_ledger.py::test_03h_clean_needs_post_run_acceptance_extra`, `test_helper_review.py::test_03h_one_post_run_decision_per_run`, `::test_03h_stale_acceptance_target_changed_after_run` (observations computed once by `record_review`) |
| 04a | `test_helper_execute.py::test_04a_grant_required_toolkit_container` |
| 04b | `test_helper_runtime.py::test_04b_each_invariant[49]` (field named, `rm -f`, no start), `::test_04b_volume_and_holder_verified`, `::test_b1_registration_and_first_conformance_without_record`, `::test_b1_rendering_drift_requires_rerun`; `test_helper_registry.py::test_b1_registration_semantic_verifier_without_record`; real P-00 |
| 04c | `test_helper_runtime.py::test_04c_missing_or_mismatched_image_no_pull`; `test_helper_registry.py::test_11a_register_rules` (missing image) |
| 04d | `test_helper_execute.py::test_04d_targets_identical_no_project_mount` |
| 04e | `test_helper_execute.py::test_04e_time_cap_and_timeout_failed`, `::test_04e_time_limit_capped_by_remaining_budget`, `::test_m4_cpu_ulimit_and_deadline_labels_in_argv`, `::test_m4_orphan_sweep_removes_expired_and_dead_owner`; `test_helper_launcher.py` (digest, arguments, staging listing); real P-14, P-17 |
| 04f | `test_helper_cancel.py::test_04f_cancel_stops_container_or_not_confirmed`, `::test_04f_not_confirmed_when_removal_fails`, `::test_m2_cancel_during_compile_probe`; real P-18 |
| 04g | `test_helper_execute.py::test_04g_paused_or_exhausted_refused` |
| 04h | `test_helper_execute.py::test_04h_cleanup_no_container_stage_raw`, `::test_04h_leftover_staging_swept`; real flow (no runtime object left) |
| 04i | `test_helper_snapshot.py::test_04i_target_changed_since_open`, `::test_04i_manifest_bound`, `::test_dec2_walker_digest_parity_with_open` |
| 04j | `test_helper_snapshot.py::test_04j_swap_to_symlink_during_copy`, `::test_m6_cancel_during_walk` |
| 04k | `test_helper_results.py::test_04k_tar_members_owner_size[12]`, `::test_04k_truncated_or_empty_stream`, `::test_04k_run_with_malicious_results_failed_no_raw_file`, `::test_m5_cp_argv_no_follow_and_after_stop`; real `test_m5_malicious_results_rejected` (P-13b) |
| 04l | real `test_04l_limit_probes` (P-09, P-10, P-11, P-12, P-13, P-14, P-15, P-17); `test_helper_execute.py::test_04l_limit_naming_fake` |
| 04m | `test_helper_execute.py::test_04m_stdout_flood_terminated` (stdout and stderr); real P-15 |
| 04n | `test_helper_execute.py::test_04n_limits_before_container`; `test_helper_snapshot.py::test_m6_small_scope_large_target`, `::test_m6_owning_target_beyond_002b_bounds`; submit-time L-05/L-02 in `test_02b`/`test_03a` |
| 04o | `test_helper_grant.py::test_04o_tty_digests_new_grant_no_egress` |
| 04p | `test_helper_skill.py::test_04p_consent_wording`, `test_helper_grant.py::test_04p_output_wording`, `test_helper_report.py::test_04p_report_wording` |
| 05a | `test_helper_runtime.py::test_05a_no_runtime_no_host_fallback[4]` (daemon down, permission, tcp endpoint, missing socket), `::test_05a_absent_cli_and_no_conformance`; `test_helper_submit.py::test_05a_submit_without_runtime_check_failed_no_host_fallback` |
| 05b | `test_helper_ledger.py::test_05b_every_reason_failed_aux_equals_002a[5]` (not reviewed, not granted, samples, failed run, check failed) |
| 05c | `test_helper_report.py::test_05c_gap_entry_and_verdict`, `::test_05c_uncovered_files_gap_line_md_and_json`, `::test_07e_unsubmitted_helper_method_reported` |
| 05d | `test_helper_skill.py::test_05d_non_execution_rules` |
| 05e | `test_helper_flow.py::test_05e_no_runtime_full_flow_gap` (incl. CLI `guard helper show` black-box) |
| 05f | Not applicable — human chose B12 = A (no test) |
| 05g | `test_helper_grant.py::test_05g_agent_only_not_granted` |
| 06a | `test_helper_budget.py::test_06a_helper_attempt_lease`, `test_helper_execute.py::test_m1_target_failed_then_retry_new_attempt_end_to_end`, `::test_03b_samples_own_containers_mismatch_blocks_target` (attempt stays unfinished) |
| 06b | `test_helper_budget.py::test_06b_time_counts_usage_na` |
| 06c | `test_helper_budget.py::test_06c_generation_attempt_and_extra` |
| 07a | `test_helper_results.py::test_07a_runtime_kind_helper_source_ids`, `test_helper_plan.py::test_07a_agent_reserved_refused[4]` |
| 07b | `test_helper_results.py::test_07b_exit0_without_result_failed` |
| 07c | `test_helper_ledger.py::test_07c_partial_alone_failed_and_unconfirmed`, `::test_07c_partial_plus_other_evidence_on_scanned_file_only` (`met`, report still names the uncovered file), `::test_07c_partial_plus_evidence_covering_every_uncovered_file`, `::test_07c_full_coverage_accepted_usable_runtime_evidence`, `::test_07c_object_too_large_never_counts`, `::test_07c_required_adapter_still_unconfirmed` |
| 07d | `test_helper_ledger.py::test_07d_helper_finding_needs_reviewer` |
| 07e | `test_helper_report.py::test_07e_same_entries_md_and_json`, `::test_07e_unsubmitted_helper_method_reported` |
| 07f | `test_helper_report.py::test_07f_seeded_secret_masked` |
| 07g | `test_helper_results.py::test_07g_schema_violations[19]`, `::test_07g_parse_rules[3]` |
| 08a | `test_helper_flow.py::test_08a_tree_diff_only_run_folder_reports` |
| 08b | `test_helper_flow.py::test_08b_cleanup_keep_release` |
| 08c | `test_helper_review.py::test_08c_earlier_run_helper_not_accepted` |
| 08d | `test_helper_flow.py::test_08d_no_publish_command_no_egress` |
| 08e | `test_helper_skill.py::test_08e_run_artifacts_only` |
| 08f | `test_helper_registry.py::test_08f_own_state_002b_002d_unchanged` |
| 09a | `test_helper_report.py::test_09a_ordered_events` |
| 09b | `test_helper_runtime.py::test_09b_stored_config_equals_inspect` |
| 09c | `test_helper_report.py::test_09c_conclude_twice_identical` |
| 10a | `test_helper_skill.py::test_10a_flow_order_and_task077`, `::test_10a_uncovered_files_guidance` |
| 10b | `test_helper_skill.py::test_10b_host_agent_only` |
| 10c | `test_helper_skill.py::test_10c_not_proof_temporary` |
| 10d | `test_helper_skill.py::test_10d_untrusted` |
| 11a | `test_helper_registry.py::test_11a_register_success_records_digest_and_version`, `::test_11a_register_rules`, `::test_dec5_env_keys_shown_credential_refused` |
| 11b | real `test_11b_suite_on_real_runtime` (every probe recorded and bound; P-01 fails on this runtime → record not usable, DEC-I5); `test_helper_conformance.py::test_11b_probe_failure_recorded_fake_evidence`, `::test_m7_seccomp_needs_behavioural_denials_and_default_profile` |
| 11c | `test_helper_runtime.py::test_11c_identity_change_requires_rerun` |
| 11d | `test_helper_runtime.py::test_11d_allowed_subcommands_only` (run, review, registration and conformance logs) |
| 11e | `test_helper_registry.py::test_11e_edited_record_absent` |
| 11f | `test_helper_conformance.py::test_11f_fake_runtime_cannot_produce_record` (in-process seam refused; fake CLI → `passed: false`, execution refused) |
| 12a | `test_helper_report.py::test_12a_adversarial_names_escaped` |
| 12b | `test_helper_results.py::test_12b_injected_states_ignored` |
| 12c | `test_helper_runtime.py::test_12c_config_independent_of_content` |
| 12d | `test_helper_submit.py::test_12d_declaration_immutable` |

Boundary regression (DAO-014/017 TD), `test_helper_boundary.py`: `::test_show_and_conclude_json_md_byte_identical_without_helpers`, `::test_cancel_finalize_byte_identical_without_helpers`, `::test_plan_and_record_validation_outputs_byte_identical` (all three against the step-0 goldens), `::test_no_delivered_fixture_uses_helper_prefixes`, `::test_relevant_paths_helper_branch_only` (incl. `_judge_review` signature pin), `::test_closed_list_diff`.

## 9. Implementation Decisions (open DECs for the representative)

| ID | Ambiguity / conflict | Conservative choice taken |
| --- | --- | --- |
| DEC-I1 | Design §1.1: `report.render` calls `helper_report.section(...)`. The delivered CR-TASK-086 test `test_guard_renderer.py::test_01l_closure_every_toolkit_import_of_the_renderer_is_in_the_manifest` requires `guard/report.py` to import exactly `__init__.py` and `atomic.py` | The Markdown section is rendered inside `guard/report.py` by a private `_helper_section(part)` (+12 lines, no import) from `statement`/`columns`/`rows`/`gaps`/`notes` of the structured part built by `helpers/report.py`; same file, same hook position, both outputs from the same data. Renderer manifest unchanged |
| DEC-I2 | The delivered CR-TASK-077 tests seed `state["helpers"]` with minimal `{id, check, digest}` entries and inject `helper` subjects without `phase` | 002-F treats only full 002-F records as helpers (`model.helpers`), skips subjects it did not validate, and the engine branch uses a tolerant `.get` form (still 3 lines, the only engine edit). Those delivered tests pass unchanged |
| DEC-I3 | Design path `.x-ipe/private/helpers/…` vs the toolkit's private root | `.x-ipe/private/secure-code/helpers/` (sibling of the 002-B `tools/` registry), consistent with the design's `GUARD_REL` shorthand |
| DEC-I4 | DEC-5 refuses image env entries the credential patterns flag; the official Python images' public `GPG_KEY=<fingerprint>` is flagged, so no permitted local image registers | Rule kept as specified (fail closed). Ruling needed: e.g. exempt documented public variables (`GPG_KEY`) shown to the Maintainer, or a Maintainer-confirmed override. Real tests seed the registration after the real version probe (labelled) |
| DEC-I5 | P-01 "only `lo`": LinuxKit creates fallback tunnel devices (down, no address) in every network namespace | Strict reading kept: P-01 fails → record `passed: false` → no execution on Docker Desktop. Ruling needed (e.g. count only interfaces that are up or carry an address). Real flow test uses a labelled seeded record |
| DEC-I6 | `--ipc private` (design canonical) leaves a 64 MiB `/dev/shm` tmpfs (noexec, nosuid, nodev, charged to the 512 MiB memory cgroup) writable besides `/tmp` | Kept as designed (P-03 lists `/dev/shm` as standard); recorded. Possible tightening: `--ipc none` or `--shm-size` (design change) |
| DEC-I7 | `result.json` must carry the helper id, which is assigned at submission | Ids are deterministic (`h-<n>-<vid8>`); documented in `guard-records.md` so the author can predict it |
| DEC-I8 | Design `write_attribute` list includes `replace` | Refused in every context (also `str.replace`), documented in the reference |
| DEC-I9 | "csv writers on non-results handles" | `writerow`/`writerows` added to the denied attributes (stricter than the design list) |
| DEC-I10 | Design `probes/*.py`; the delivered 002-C test `test_guard_egress.py::test_05f_no_network_client_outside_egress_module` forbids `import socket` in any `src/**/*.py` | One probe source `probes/suite.probe` (Python, data only, never imported, staged with a `PROBE = "<id>"` first line); `conformance.py` uses `platform.node()` |
| DEC-I11 | P-03 closed mount list vs Docker's masked/read-only `/proc` and `/sys` bind mounts | Mount points under `/proc/`, `/sys/`, `/dev/` accepted as runtime masking mounts in addition to the closed list; no socket allowed anywhere |
| DEC-I12 | P-04 `getpid() == 1` — the launcher (PID 1) runs the probe as its child | Judged as: PID 1 is the launcher and the probe's parent, hostname differs, cgroup namespace root `0::/`, namespace ids differ from the host's (Linux hosts only; VM boundary recorded on macOS) |
| DEC-I13 | No interpreter is known before registration | Fixed toolkit candidates `/usr/local/bin/python3`, `/usr/bin/python3` for the version probe; the reported executable must equal the one used |
| DEC-I14 | Refusal code for a sample with the wrong outcome | `HELPER_NOT_EXECUTED` with `reason_code: samples_mismatch` (after the commit that blocks the helper) |
| DEC-I15 | `real_runtime` marker | Expressed as a module-level skip condition (registering a marker would need the delivered `conftest.py`) |
| DEC-I16 | L-03 is checked after storage (design order); unbounded script files | Script files above 4 MiB are refused unstored (`HELPER_LIMIT`); otherwise stored and L-03 → `check_failed` |
| DEC-I17 | STOP-rule findings: 3 delivered tests fail only because of design-mandated changes (§5) | Not edited; proposed minimal edits scratch-verified (11 passed). Ruling needed |
| DEC-I18 | `ERA_001A_REMOVED` (delivered `tests/carriers/carhelp.py`) | Appended the 20 new payload paths under `# FEATURE-002-F.` (owner-stated precedent, DAO-002/DAO-018/DAO-019); nothing else in the file changed; carriers suite green |
| DEC-I19 | New maintenance points created by the design-mandated regression evidence | `tests/helpers/fixtures/pre_002f/` (step-0 goldens) and `fixtures/delivered_step0.json` (closed-list baseline): a later legitimate change of a delivered Guard output or file must update them (the test messages name the files) |
| DEC-I20 | Stage folders of interrupted runs | Swept at the start of `helper run` and of the compile probe (design §9.0); a cleanup that cannot be confirmed adds a report gap line |

## 10. Honest Limits

- Enforcement claims (AC-002F-04l, 11b) rest on one real runtime only: Docker Desktop 4.87 / Engine 29.7.2 on macOS arm64 (LinuxKit kernel). Not run: Linux hosts (host namespace comparison of P-04 only runs there), x86-64, Podman (adapter paths for Podman are written from the design's closed spelling sets but untested), Windows (non-execution only). On the tested runtime P-01 fails strictly (DEC-I5), so no helper can execute there until ruled.
- No permitted local Python image passes registration under DEC-5 (DEC-I4); the real execution path was exercised with seeded registration/conformance records (labelled), never claimed as acceptance.
- Orchestration tests use a fake Docker-compatible CLI that never executes scripts; it proves argv, inspect verification, gates, records and refusals, not isolation. A forged runtime CLI could lie to probes (design honest limit).
- RED for steps 5–12 is a step-0 reproduction (§3), not a pre-implementation capture per module.
- The helper's `result.json` must name its own helper id, which the author predicts (`h-<n>-<vid8>`; DEC-I7).
- `str.replace` is refused with Path.replace (design list; DEC-I8); `/dev/shm` (64 MiB, noexec, memory-cgroup-charged) stays writable under the design's `--ipc private` (DEC-I6).
- Packaging: the probe source is a non-`.py` data file (DEC-I10); the payload copy includes it (carriers tests), but a built wheel was not inspected (no build was run).
- One delivered 001-G test (`test_02e_equivalent_to_plain_update_time_normalised`) failed in full runs 2 and 3 (passed in run 1) and passed in all 10 isolated re-runs; it does not touch Guard or helpers. Its pre-002-F behaviour under full-suite load was not re-measured (baseline 2885 passed reported by the owner), so a load-dependent interaction cannot be fully excluded — not investigated further.
- Real-runtime timing probes (P-14, P-17) were run on an otherwise busy host; they passed, but timing headroom on slower hosts is not measured.

## 11. Delivery and Outcome

Engineering delivery: **verified** for the 74 active ACs at the final tree (324 new tests; real-runtime suite and flow passing with the stated seams); delivered-file parity exact against the closed list; engine boundary respected (only the `_relevant_paths` helper branch); ruff clean; module sizes within limit; nothing left in `ai-secure-code-toolkit/` or in the runtime. **Regression completion is blocked** on the three STOP-rule findings (§5) pending the representative's ruling on the proposed scratch-verified edits; DEC-I4/I5 decide whether helpers can execute on the available runtime and images. Stakeholder outcome: **not measured.**

## 12. DAO-005 Follow-up (2026-10-24) — authoritative current state

Inputs: DAO-005 (`x-ipe-docs/dao/26-10-23/decisions_made_code_implementation.md`, entry at L201–269, read in full) ruling on this report (`9e5fefcb`) and the independent code review (PASS-WITH-FIXES, as relayed by the owner). Same constraints as before (EV folder, no Git/board/memory, local images only, `--network none`, nothing pulled, no forbidden substrings).

### 12.1 Rulings applied

| DAO-005 item | Applied | Status |
| --- | --- | --- |
| (1) DEC-I17 maintenance points (DAO-023/024), 002-F lands first | `test_compare_skill.py::test_01h` scoped to the 002-G section (from `## Comparing two reports` to the next `(?m)^#{1,2} ` heading or EOF; exactly one ATX heading inside; `{compare, cleanup}` command check kept; prefix hash kept) + the prescribed maintenance comment; prefix rebaselined because 002-F changed bytes before offset 12017 (lines 14–15, 111–112, inserted step 5c), reason in a comment: `12017/cdbfc5bc…` → `16160/e24862a3750071d772d6ae6adda5dae832510da4e61f73c15ef9431167083b73`. `drafthelp.NEW_PAYLOAD` + exactly the 20 002-F payload paths (comment). `guard_copilot_hashes.json` Guard entries rebaselined (see DEC-I21); Copilot entries unchanged. Nothing else in those files | done |
| (1) DEC-I18 `ERA_001A_REMOVED` append | already in place (20 paths) | approved |
| (2) snapshot Medium bug (`snapshot.py:82`) | `_Walk.seen()`: every non-excluded entry under `check.object` (and an irregular entry containing an object path) is listed in the object file list — links, FIFOs/special files, unreadable files, non-UTF-8 names (display name) — so it can only be uncovered; clean result ≤ `accepted_partial`, entries named in the report gap line. RED first | done |
| (3) DEC-I4 `GPG_KEY` exemption | `registry.py` only: key exactly `GPG_KEY`/`GPG_KEYS` and whole value `^[0-9A-Fa-f]{40}( [0-9A-Fa-f]{40})*$` (`re.fullmatch`) → not refused, recorded, output `env_labels` = "public key fingerprint (not a secret)"; every other flagged entry still refused; `mask_text` untouched. Design erratum E1 + change-log row | done |
| (4) DEC-I5 → spec clarification | spec **v1.3.3**: AC-002F-11b "network disabled" evidence (ID kept; Version History row attributed to DAO-005); design erratum E2; probe P-01 rewritten (flags, `fib_trie`, `if_inet6`, `route`, `ipv6_route`, CapEff/CapBnd, connect, DNS) and judge `conformance.network_ok` (+ inspect `NetworkMode none`, networks ⊆ {none}, `CapDrop` ALL). RED first; real-runtime re-run | done |
| (5) DEC-I6 `/dev/shm` | `--ipc none` (real conformance passes with it); verifier requires `IpcMode == "none"`; P-02 also writes `/dev/shm/x` (must fail; real: `ENOENT`). Design erratum E3 | done |
| (5) flaky `test_02e` (TASK-110) | reported as is: **passed** in the follow-up full run; no rerun was needed or made | reported |
| (6) other DEC-I | approved as reported; no change | — |

Human-visibility line requested by DAO-005 for the owner's next status summary: "002-F network check clarified from 'only lo exists' to 'no usable non-loopback interface, no routes, no capability to create one'". DAO-005 also requires an **independent delta review** of the spec v1.3.3 + probe change and of the snapshot fix — not performed by this worker (owner action).

### 12.2 RED / GREEN per fix (logs in `impl-085/`)

| Fix | Tests | RED | GREEN |
| --- | --- | --- | --- |
| (1) maintenance | delivered `test_compare_skill.py`, `test_draft_regression.py` | `log-full-3` (the 3 STOP failures); `log-maint1`: **1 failed** — `test_08d` still failed on `guard-records.md` after a SKILL.md-only rebaseline (→ DEC-I21) | `log-maint2`: compare-skill + draft-regression + carriers **263 passed**; scoped-check scratch `log-01h-scope-check`: current True; later `##` section appended True; extra `###` or extra command inside the 002-G section False |
| (2) snapshot | `test_helper_snapshot.py::test_07c_object_entries_seen_but_not_coverable`, `::test_07c_unreadable_object_folder_refused_not_omitted`, `test_helper_ledger.py::test_07c_unreadable_fifo_link_object_entries_only_partial` (repro: object `src/config`, read scope its two readable files, unreadable `locked.yaml`, FIFO `c.fifo`, link `link.yaml`) | `log-red-dao005-snapshot`: **3 failed** — object list `['src/a.py']` only; run `uncovered_count 0 == 3` (accepted_full over-claim); the folder test (first form expected the folder listed; the walker refuses — see DEC-I22, rewritten to assert the fail-closed refusal) | `log-green-snap`: snapshot + ledger + report + review **40 passed** |
| (3) GPG exemption | `test_helper_registry.py::test_dao005_public_fingerprint_registers_labelled[3]`, `::test_dao005_fingerprint_near_misses_still_refused[17]` (other key names `PGP_KEY`, `GPG_KEY_ID`, `MY_GPG_KEY`, `gpg_key`, `API_KEY`; 39/41 hex; non-hex char; `0x`; trailing `x`/space/newline; leading space; double space; comma; short second fingerprint; token value), `::test_dao005_exemption_does_not_hide_other_credentials`, `::test_dao005_mask_text_untouched` | `log-red-dao005-gpg`: **4 failed** (3 exempt cases + mixed env), 18 passed (near-misses already refused) | `log-green-dao005-gpg`: **28 passed** |
| (4) P-01 | `test_helper_conformance.py::test_dao005_p01_network_disabled_judge` (Docker-Desktop-shaped evidence passes; 22 note variants, 9 missing keys, 6 inspect variants fail), `::test_dao005_p01_probe_parsers` (fixtures with/without `eth0`) | `log-red-dao005-p01`: **2 failed** (`network_ok` absent; parsers absent / probe ran on load) | `log-green-dao005-p01`: **5 passed**; real §12.3 |
| (5) `--ipc none` | `test_helper_execute.py::test_dao005_ipc_none_no_shared_memory_mount`, `test_helper_conformance.py::test_dao005_p02_shared_memory_not_writable` | `log-red-dao005-ipc`: **2 failed** (`'private' == 'none'`; `readonly_ok` absent) | after aligning the fake conformance rendering (`helperhelp.RENDERED_FAKE` `IpcMode` → `none`; `log-green-helpers-1` showed 81 failures "runtime rendering differs from the conformance record" before that): `log-green-helpers-2` tests/helpers **349 passed, 4 skipped** (exit 1 only from the suite's write audit, which flagged my own edit of `test_helper_conformance_real.py` during that run; the full suite below re-ran everything clean) |

### 12.3 Real-runtime evidence (opt-in, `SECURE_CODE_HELPER_REAL=1`) — `log-real-dao005`

Docker Desktop 4.87 / Engine 29.7.2, LinuxKit arm64; `python:3.12-slim` (`sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1`, already local); `--network none`; nothing pulled. **4 passed in 212 s.** **No seeded record and no test seam** (the `SEEDED` fixture fallback and the record re-write were removed):

- Registration through `register_image` succeeds in every test; output `env_labels = {"GPG_KEY": "public key fingerprint (not a secret)"}`.
- Conformance (two uncached runs): **all 20 probes pass** (P-00…P-18 incl. P-13b), `passed: true`, valid record. P-01 detail: `ifaces` `erspan0 0x1002, gre0 0x80, gretap0 0x1002, ip6_vti0 0x80, ip6gre0 0x80, ip6tnl0 0x80, ip_vti0 0x80, lo 0x9, sit0 0x80, tunl0 0x80` (IFF_UP clear on all but `lo`), `v4 [] v6 [] route4 [] route6 []`, `CapEff = CapBnd = 0000000000000000`, `connect ENETUNREACH`, `dns gaierror`. P-02 detail: `/dev/shm/x ENOENT`, `/usr/x /input/x /helper/x /x EROFS`.
- `test_real_helper_flow_with_real_conformance` (renamed from `…_with_seeded_conformance`): on the real record — compile probe pass; samples `finding`/`clean`; target `clean`, 0 uncovered; post-run review → `accepted_full`; ledger `met`; broken script → `HELPER_CHECK_FAILED`; no labelled container left.
- After the run: `docker ps -a` / `volume ls` with `label=x-ipe.secure-code=helper` → none.

### 12.4 Files changed in this follow-up (SHA-256 at the final tree)

`FW` = `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework`. No file added or removed (still 368 files).

| File | Kind | SHA-256 |
| --- | --- | --- |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/snapshot.py` | product (fix 2) | `69750e5cc973d8acc91c84bf03ac1904d701db6e00cd7d68e5843623a79f7d1c` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/registry.py` | product (fix 3) | `4573e3896274b5e31ce93dbc5f5fd39944bfe670c0138177729fc009b07796c2` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/conformance.py` | product (fixes 4, 5) | `0a615ccdb456141a4cc172db037b5d91ffc38406c37eecc8dee173f8d623a0c2` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/probes/suite.probe` | product data (fixes 4, 5) | `bc2c6f27a6afc42429a9536336e9334bf559d999212e99a1b609d3297888c724` |
| `FW/scripts/src/x_ipe_secure_code/guard/helpers/canonical.py` | product (fix 5) | `91cec4e57cd667b05d02b786481aa02428fe2947027b38d76a8e78811578c5bf` |
| `FW/scripts/tests/helpers/test_helper_snapshot.py` | test | `29f3fd65c4c75cb63df189bb8cd05a32d40c817e141af32c264ee6d75797c018` |
| `FW/scripts/tests/helpers/test_helper_ledger.py` | test | `ae263ab8cb0027d90a189d6135e1e54c16161161d359e83f92f8cd3498d72748` |
| `FW/scripts/tests/helpers/test_helper_registry.py` | test | `f20f2bcc8300ad1f56866d11bd6bdf57beb584526a9f865986121a3d057fb103` |
| `FW/scripts/tests/helpers/test_helper_conformance.py` | test | `2b27ab96b1648ee5f3d7278d6dce8f83debd279f0cf1538155807dfa7be88273` |
| `FW/scripts/tests/helpers/test_helper_conformance_real.py` | test (seams removed) | `6772d2fbea2f68e355d2164669f246f6226e1033af4f51f4287cc9c05c2bbfc2` |
| `FW/scripts/tests/helpers/test_helper_execute.py` | test | `418ead13216eac1018804a2e7de309443072836b0f513c901a14b164a15d5758` |
| `FW/scripts/tests/helpers/test_helper_boundary.py` | test (closed list + 3 maintenance points) | `bb952dd940273523f433dd42edee6b663af7707520affea9818d58dc61e48d92` |
| `FW/scripts/tests/helpers/helperhelp.py` | test support (`RENDERED_FAKE` IpcMode) | `a873de1f7d95dec55e8d70c00f6974eb36f0ebab55839e7d0cedf17a170967ea` |
| `FW/scripts/tests/guard/test_compare_skill.py` | delivered test — maintenance point (DAO-005) | `9ca6ca5473949389b5cdb587ab6c0ce6053119103edb08c1d5470b956f51112f` |
| `FW/scripts/tests/drafting/drafthelp.py` | delivered test helper — maintenance point | `c96b5c72ecd4aafb0cefc45c6bf678a809519b7c535b3b2d7a46e93010641837` |
| `FW/scripts/tests/drafting/fixtures/guard_copilot_hashes.json` | delivered fixture — maintenance point | `aa0185383f0b4964de6ef56ac5d239d0b24032f05759307385de24db65560243` |
| `x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/specification.md` | spec v1.3.3 | `fcf0f92a2fb62d2030c639baa7d05e2cc65febb5e5e0a25e6217743553b33ae3` (was `eafc9894…`) |
| `x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/technical-design.md` | design v1.2.1 errata E1–E4 (original text kept; header, Version History, Change Log rows, inline erratum pointers, appended "Errata (DAO-005)") | `8cd4978f5f09bea105a0a6447dd4d9a09bccd64b3043508b50d206adfe4a09d9` (was `4202a1c0…`) |

Module sizes: `conformance 461`, `registry 283`, `snapshot 277`, `canonical 391` (all < 800; `tests/test_module_size.py` passed in the full run); `suite.probe` 450 lines (data file).

### 12.5 Delivered-file parity (final tree vs step 0) and maintenance points for closing

Per-file SHA-256 vs `baseline-step0.sha256` (291 files): **14 changed** = the **11 closed-list files** (hashes identical to §4.1 — none touched in this follow-up) **+ the 3 DAO-005 maintenance points**; **removed 0**; **added 77** (same set as §4.2). Final list `impl-085/final-dao005.sha256`, 368 files, list digest `08aaddde406704c9a33e397130a4fda16480abbef96689ac4254312c1fa02d2f`; re-verified unchanged after the full run. `test_helper_boundary.py::test_closed_list_diff` passes with the closed list extended by exactly the 3 maintenance points.

Maintenance points to list in the 002-F closing:
1. `tests/guard/test_compare_skill.py` — `test_01h` scoped to the 002-G section; `DELIVERED_SIZE`/`DELIVERED_SHA256` rebaselined `12017/cdbfc5bc…` → `16160/e24862a3…` (reason in comment).
2. `tests/drafting/drafthelp.py` — `NEW_PAYLOAD` + the 20 002-F payload paths.
3. `tests/drafting/fixtures/guard_copilot_hashes.json` — Guard `SKILL.md` `4bcb188f…` → `81733a4d…` and `references/guard-records.md` `868f2da8…` → `766b8def…` (DEC-I21); Copilot entries unchanged.
4. `tests/carriers/carhelp.py` `ERA_001A_REMOVED` + 20 paths (DEC-I18, approved).
5. 002-F's own (DEC-I19): `tests/helpers/fixtures/pre_002f/` (step-0 goldens), `tests/helpers/fixtures/delivered_step0.json`, `test_helper_boundary.CLOSED_LIST`.

### 12.6 Validation (final tree)

| Check | Result |
| --- | --- |
| **Full suite — `log-full-dao005`** | **3234 passed, 0 failed, 8 skipped, 23 deselected in 2078.3 s**. Reconciliation: 2885 baseline + 349 new default = 3234; skipped 4 baseline + 4 opt-in real. The flaky delivered `tests/drafting/test_draft_cli_approve.py::test_02e_equivalent_to_plain_update_time_normalised` (TASK-110) **passed** in this run; no rerun made. Write audit: no finding |
| New tests | 353 in `tests/helpers` (+29: 2 snapshot, 1 ledger, 22 registry, 3 conformance, 1 execute; real flow test renamed) = 349 default + 4 opt-in |
| Real-runtime tests | 4 passed (§12.3) |
| `ruff check --no-cache src tests` | All checks passed (`log-ruff-dao005`) |
| Forbidden-substring scan (all 368 toolkit files, spec, design, this report) | 0 hits |
| Artifacts in `ai-secure-code-toolkit/` (`__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage*`, `*.pyc`, `*.egg-info`, `build`) | none |
| Runtime objects (`label=x-ipe.secure-code=helper`) | none (2 pre-existing unrelated user containers untouched) |
| New-code coverage | **not re-measured** in this follow-up (§6's 92 % is from the initial delivery) |

### 12.7 AC traceability additions (§8 rows stay; these tests are added)

| AC | Added tests |
| --- | --- |
| 07c (and 04i snapshot binding) | `test_helper_snapshot.py::test_07c_object_entries_seen_but_not_coverable`, `::test_07c_unreadable_object_folder_refused_not_omitted`; `test_helper_ledger.py::test_07c_unreadable_fifo_link_object_entries_only_partial` (≤ `accepted_partial`, failed auxiliary evidence, `unconfirmed`, gap line names `src/config/c.fifo, src/config/link.yaml, src/config/locked.yaml`) |
| 11a | `test_helper_registry.py::test_dao005_public_fingerprint_registers_labelled[3]`, `::test_dao005_fingerprint_near_misses_still_refused[17]`, `::test_dao005_exemption_does_not_hide_other_credentials`, `::test_dao005_mask_text_untouched`; real fixture registers through the command |
| 11b (v1.3.3) | `test_helper_conformance.py::test_dao005_p01_network_disabled_judge`, `::test_dao005_p01_probe_parsers`; real `test_11b_suite_on_real_runtime` now asserts **every** probe passes and the P-01 evidence items |
| 04b (and 04l writes) | `test_helper_execute.py::test_dao005_ipc_none_no_shared_memory_mount`, `test_helper_conformance.py::test_dao005_p02_shared_memory_not_writable`; real P-02 |
| real flow (03b, 04e, 04h, 04k, 07c) | `test_helper_conformance_real.py::test_real_helper_flow_with_real_conformance` replaces `…_with_seeded_conformance` named in §8 |

### 12.8 DEC status after DAO-005

| ID | Status |
| --- | --- |
| DEC-I4 | resolved — exemption E1 (registry only) |
| DEC-I5 | resolved — spec v1.3.3 AC-002F-11b + E2; P-01 passes on the real runtime |
| DEC-I6 | resolved — `--ipc none` (E3); real P-02 `/dev/shm` ENOENT |
| DEC-I17 | resolved — maintenance points applied (§12.5) |
| DEC-I18 | approved |
| DEC-I1–I3, I7–I16, I19, I20 | approved as reported (DAO-005 (6)) |
| **DEC-I21 (open)** | The owner text said "rebaseline the Guard SKILL.md hash only", but `guard_copilot_hashes.json` also pins `references/guard-records.md`, which 002-F changes by design (closed list); with SKILL.md only, `test_08d` still failed (`log-maint1`). Conservative reading of the intent (Guard package changed by 002-F; Copilot unchanged): both Guard entries rebaselined, Copilot entries untouched. Confirmation requested |
| **DEC-I22 (open)** | An unreadable **folder** under the check object (outside the read scope) keeps the walker's fail-closed refusal (`snapshot unsafe`, no run), like the delivered `targets.stage`, instead of being listed as seen-but-not-covered; unreadable/FIFO/link/non-UTF-8 **entries** are listed. No over-claim either way |
| **DEC-I23 (open)** | The semantic verifier now requires `IpcMode == "none"` exactly (design §8.3 allowed {`private`, `none`}) — stricter |
| **DEC-I24 (open)** | P-01: a missing `/proc/net/if_inet6` or `/proc/net/ipv6_route` counts as "no IPv6 address/route"; missing `fib_trie`/`route` fails. IPv4 addresses are detected as `host LOCAL` entries outside 127/8 in `fib_trie` (an address outside 127/8 even on `lo` fails — stricter); interface flags must be a `0x…` hex string |
| **DEC-I25 (open)** | Spec header `Version` line was stale (`v1.3.1` while the status said v1.3.2); set to `v1.3.3` with the status line extended by the DAO-005 attribution; design header bookkeeping (version v1.2.1, spec binding v1.3.3) |

### 12.9 Honest limits (current; replaces §10 where different)

- Enforcement evidence comes from **one runtime only**: Docker Desktop 4.87 / Engine 29.7.2, LinuxKit, macOS arm64, image `python:3.12-slim`. Not run: Linux hosts (P-04 host-namespace comparison only there), x86-64, Podman, other images (`fat-uv-git:py312` not re-tested in this follow-up).
- "Network disabled" is now proven by the stronger evidence set, but the kernel fallback tunnel devices still exist inside the container (down, address-less, route-less, no capability to change them).
- `/dev/mqueue` (POSIX message queues, kernel-bounded) remains present under `--ipc none`.
- The fake-runtime tests prove orchestration, not isolation; a forged runtime CLI could lie to probes (design honest limit).
- Coverage not re-measured after the follow-up; the independent delta review required by DAO-005 is pending (owner).
- The flaky delivered `test_02e` passing in this run is not evidence that TASK-110 is fixed.

Engineering delivery: **verified** for the 74 active ACs at the final tree (353 new tests; full suite 3234 passed / 0 failed / 8 skipped; real-runtime conformance and flow passing without seeded records); delivered-file parity = closed list + the 3 ruled maintenance points; engine boundary unchanged. Stakeholder outcome: **not measured.**
