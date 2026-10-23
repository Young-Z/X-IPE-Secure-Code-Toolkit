# Implementation Report — FEATURE-001-G AI-assisted Knowledge Drafting (Examples Only)

> Feature: FEATURE-001-G (EPIC-001) · Task: TASK-084 (Code Implementation, TDD), lifecycle owner Sage, implementation worker · Date: 2026-10-24
> Mode: free mode, workflow N/A; no board, Git, memory or successor action was taken by this worker (owner exclusions). No `auth init` on the host; `drafting-authorize` (record/revoke) ran only inside disposable `tmp_path` test projects with the fixture label `fixture-host` (human decision B14 = No).
> Scope: groups AC-001G-01…08 plus AC-001G-09f (62 active ACs; B13 = H2). AC-001G-09a…09e are deferred by human decision B13 = H2 and have no test.
> Result (after the DAO-004 follow-up, 2026-10-24): **Engineering delivery: verified** for every active AC at the final tree. The representative's DAO-004 rulings on DEC-I1…I14 and the independent code review (PASS-WITH-FIXES, issues 1–2) were applied test-first (DEC-I15, DEC-I16); the `ERA_001A_REMOVED` append (DEC-I1) resolved the STOP-rule finding. **Full suite: 2885 passed, 0 failed, 4 skipped.** **Stakeholder outcome: not measured.**

## 1. Authoritative Inputs (verified before any change)

| Input | Expected | Found | Match |
| --- | --- | --- | --- |
| [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/specification.md) v1.3.3 | prefix `4cb3a1eb` | `4cb3a1eb3e91831c9eabe9a2351ed36f401070193e5676f7009ba53ab0b296a2` | yes |
| [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/technical-design.md) v1.2 | prefix `5e0f2aa8` | `5e0f2aa8e582e25374491dccbcc30493bbc59b8965087d1be71ad55fbcbaf5a7` | yes |
| `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` (DAO-013, DAO-015, DAO-016 read in full) | — | `2167abc4285b5711…` | read |
| `x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md` (DAO-008/009 spec rulings) | — | `282b870321132f90…` | read |
| `x-ipe-docs/dao/26-10-23/human_decisions.md` | spec cites `32f8602546c3884b` | `d616db5344b05a77…` (file grew since; the B13 = H2 and B14 = No rows are unchanged) | B13/B14 verified |

Binding conditions applied: DAO-013 (DEC-1…12 with conditions), DAO-015 (P3a/P3b/P3c split; race option A; `WRITE_MISMATCH` contract), DAO-016 (stop rule; P3b only on 001-G-private paths; no lock held across `update_rule`; B13/B14 bindings; fixture-only acceptance; honest limits; `ERA_001A_REMOVED` maintenance point; no commit/push/release).

## 2. Step 0 — Baseline (before any code change)

- Toolkit tree `ai-secure-code-toolkit/` (excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.git`): **245 files**, per-file SHA-256 list kept in the session evidence folder (`impl-084/baseline-step0.sha256`); list digest (closing-report method: strip `./`, `LC_ALL=C sort -k2`, `shasum -a 256`) `22b03da5c734090e510ebdaeac60af5ac8bc89cdb8984bd8d63dd7a8d4e0b7a6`.
- Baseline suite (owner-supplied, toolkit commit 38a5e8b): 2616 passed / 4 skipped.
- Rebinding of design-time interface hashes: `knowledge/service.py 16eb2695`, `store.py e5012c6b`, `batch.py e663cea4`, `precheck.py 8226ed81`, `changelog.py 56b962a8`, `exit_journal.py 95172124`, `views.py a2934f7e`, `policy/resolve.py f1dcdd6e`, `results.py cbfe77d1`, `durable.py 6468cdfc`, Framework `SKILL.md 980c9ff6`, `cli-contract.md 75f3c146`, `knowledge-batch.md 6af9e080`, `test_module_size.py c072a78a`, `conftest.py c0fadd24` — **all equal to the design's bindings**. Two delivered files changed since the design (expected, design "Delta and Evidence Invalidation"): `cli.py` `ce386af4…` (design `a1e8d924`; FEATURE-002-G guard commands added since; the knowledge parser/dispatch used by 001-G is unchanged) and Guard `SKILL.md` `4bcb188f…` (design `cdbfc5bc`). The interfaces 001-G calls were re-read at this revision.
- Golden pre-001-G outputs captured with the delivered code before any 001-G change, twice, byte-identical between the two captures: `tests/drafting/fixtures/pre_001g/` (`init`, `status`, `knowledge import/check/update/show/list/links`, `policy resolve`, `scope show`, `exit-preview`, `guard open`; in-process CLI `--json`, frozen clocks, normalised paths/times/run ids). The host name and OS user in `status.json` were afterwards replaced by `<hostname>` / `<os-user>` by text substitution of the captured bytes (no machine identity in fixtures; see DEC-I4).
- Guard/Copilot package hashes recorded at step 0 (`fixtures/guard_copilot_hashes.json`); delivered 001-A/B/C/D/F test-file hashes recorded at step 0 (`fixtures/delivered_tests_001abcdf.json`, 54 files; verified equal to the step-0 list).

## 3. TDD Steps — RED / GREEN

Logs: session evidence folder `impl-084/log-*.txt`. All runs: `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=$EV/tmp-<name> …` from `FW/scripts` (`FW` = `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework`).

| Design step | Tests (file) | RED evidence | GREEN |
| --- | --- | --- | --- |
| 2 `drafting_model.py` | `test_draft_units_model.py` (45) | `log-red-model`: 45 failed, `ModuleNotFoundError: …drafting_model` (written and run before the module) | 45 passed |
| 3 `drafting_blocks.py` | `test_draft_units_blocks.py` (23) | `log-red-blocks`: collection error `ModuleNotFoundError: …drafting_blocks` — **reproduced with the module moved out** after it was written (tests were written first but first run after the module) | 23 passed |
| 4 `drafting_mask.py` | `test_draft_units_mask.py` (7) | `log-red-mask`: 7 failed, module absent (before implementation) | 7 passed |
| 5 `drafting_lint.py` | `test_draft_units_lint.py` + `lint_cases.json` (21) | `log-red-lint`: 21 failed, module absent (before implementation) | 21 passed |
| 6 `drafting_checks.py` | `test_draft_units_checks.py` (41) | `log-red-checks`: 41 failed, module absent (before implementation) | 41 passed |
| 7 `drafting_auth.py` + CLI wiring | `test_draft_internal.py` (first 6) | `log-red-auth`: 6 failed, module absent (before implementation) | 6 passed |
| 8 `drafting_pipeline.py`, `draft_check` | `test_draft_cli_check.py` (30 at the time) | `log-red-cli-check`: 30 failed, `ModuleNotFoundError: …drafting_service` (before implementation) | 30 passed (+3 integration tests added later, 33 passed) |
| 9 `draft_approve`, staging | `test_draft_cli_approve.py` (25), `test_draft_staging.py` (11) | approve: `log-red-approve` 25 failed (23 `ModuleNotFoundError: …drafting_service`) — **reproduced with the module moved out**; staging: see the step-0 tree run below | 25 + 11 passed |
| 10 `drafting_supplements.py` | `test_draft_supplements.py` (3) | step-0 tree run below | 3 passed |
| 11 lifecycle/concurrency | `test_draft_lifecycle.py` (11), `test_draft_internal.py` 07a/07b/07d (3) | step-0 tree run below | 14 passed |
| 12 network, regression, B14 guard | `test_draft_network.py` (2), `test_draft_regression.py` (7), `test_draft_b14_guard.py` (3) | step-0 tree run below | 12 passed |
| 13 Framework text + skill/ledger | `test_draft_skill.py` (24) + `ledgerhelp.py` | `log-red-skill`: 20 failed / 4 passed before the SKILL section, reference and contract rows existed (the 4 passing are pure ledger-checker tests) | 24 passed |

**Whole-suite RED against the step-0 product tree** (`log-red-baseline-all`): a scratch copy of the toolkit in the session folder with `cli.py`, `SKILL.md`, `cli-contract.md` restored to their step-0 bytes and the 9 modules and the new reference removed, running the final `tests/drafting/`: **216 failed, 2 collection errors (47 tests), 2 passed** — the 2 passing are B14 static guards over the test files themselves (not AC tests). Every AC test fails for the right reason (missing module, missing subcommand or missing text). Honest note: for steps 3, 9 (approve) and 10–12 the RED evidence is a reproduction with the product absent, not a run captured before the code was written.

**DAO-004 follow-up (test-first):**

| Change | Test | RED (before the fix) | GREEN |
| --- | --- | --- | --- |
| DEC-I15 — mask pre-check matches in `knowledge supplements` (review issue 1) | `test_draft_supplements.py::test_supplements_masks_prechecked_values_in_notice[not_retrieved_reason, fetched_attribution, key_absent]` | `log-red-fix-dec-i15-i16`: 3 failed — the `ghp_…` token from a `not_retrieved` reason / attribution title was printed unmasked by `supplements` after an approval with `--false-positive` | 3 passed |
| DEC-I16 — mismatch decided only by the digest `update_rule` wrote (review issue 2) | `test_draft_staging.py::test_concurrent_write_after_update_is_not_write_mismatch` | `log-red-fix-i16`: 1 failed — a legitimate second delivered update after the real call produced `WRITE_MISMATCH` with "restore" advice | 1 passed |
| DEC-I5 tightened (R1) | `test_draft_cli_approve.py::test_missing_content_md_refused_nothing_written` asserts `["RULE_INCONSISTENT"]` exactly for check and approve | behaviour unchanged (assertion narrowed from either/or to the exact code the code already produced) | passed |
| DEC-I13 self-explaining failures | `test_draft_regression.py::test_08a_*`, `::test_08d_*` assertion messages name the fixture to update and why | message-only change | passed |
| DEC-I1 `ERA_001A_REMOVED` append | delivered carriers tests (10 previously failing) | full suites A–C: 10 failed | `log-green-fix` (tests/drafting + tests/carriers + module size): 522 passed; full suite 0 failed |

## 4. Files

`FW` = `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework`. Toolkit list digest at the first report: `2339c5ba…`; after the DAO-004 follow-up: `44837bb0…` (291 files).

Changed delivered files (all purely additive; 0 lines removed) — plus, after DAO-004 DEC-I1, the delivered test helper `FW/scripts/tests/carriers/carhelp.py` (11 lines appended to `ERA_001A_REMOVED`: one comment and the 10 new payload paths; 0 removed; no assertion or fixture changed): `FW/SKILL.md` (P4: new section `## Drafting Examples (AI-assisted)` before `## Selecting Policies`, 39 lines added), `FW/references/cli-contract.md` (P4: 4 rows after `knowledge links`, one appended code paragraph, section `## Drafting Examples (FEATURE-001-G)` before `## Authorization model`, 33 lines added), `FW/scripts/src/x_ipe_secure_code/cli.py` (P1: 4 subparsers, `DRAFTING_COMMANDS` branch and `_drafting`, 50 lines added, 487 → 537 lines). New: `FW/references/knowledge-drafting.md`, nine `knowledge/drafting_*.py` modules, and `FW/scripts/tests/drafting/` (15 test modules, 2 helper modules, 19 fixture files).

Full per-file SHA-256 (all 50 new/changed files; final tree after the DAO-004 follow-up, toolkit list digest `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68`, 291 files):

| File | Kind | SHA-256 (step 0 → final) |
| --- | --- | --- |
| `FW/SKILL.md` | changed (additive) | `980c9ff6a1c00308624104a3fe322ce4c82154afae37643392c60c74a597a5c9` → `3fc74164bc3fa3f9ada83cf11df86bdde088570f727d3dcdfde1cbc152607c80` |
| `FW/references/cli-contract.md` | changed (additive) | `75f3c14687c983862f19a8528c58a59b5028399687b6c8cad87c84a2e299c501` → `eda7bd6299a1e2d730bb7b50c52d1eafbd69db280e0db71886bef9572733e4f6` |
| `FW/references/knowledge-drafting.md` | new | `5d3f87d2af9ef275f20a72f4bf29e2e1facf132303f5210b96d2a234f4f1459d` |
| `FW/scripts/src/x_ipe_secure_code/cli.py` | changed (additive) | `ce386af4b865f1b51740815153adfad90cce149bd2fbb55bc6b577749d861a5a` → `3ed4990e46eb5782901740a8d643b2955bd1d848dbd047fa568058fffb5080a0` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_auth.py` | new | `501958aa5c4e2573b86d9cb98db45652d5db60a03767491f8613ea8c9c678e3f` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_blocks.py` | new | `f81693662d8a6de4dcd4b94259e9e823780180ace2f996ced6c9278adf2c07ef` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_checks.py` | new | `84f4b14ae5eb7aebc2f5df0ebe925cec0a90381225e8be2f4a3f08a20b2381f2` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_lint.py` | new | `eb370ab03f8f85aa94a27deddffd496311d9c083362085b03f2ecb6b685ba517` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_mask.py` | new | `583f61c74cdaea5eed76556112d775937d4229c991029ef95b86827fd971bd51` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_model.py` | new | `3ee348436dec95478610d72d5f5deb94d07ce088edb883d26eda567bbca30d2e` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_pipeline.py` | new | `c9f479504707c20893be315c0e33acf844ff02ff3419b6f63d9153187532e770` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_service.py` | new | `e4a52afa07f975ce921e207093408870de130e1cbc08f7da2bd63a4c1442beb8` |
| `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_supplements.py` | new | `6899e7b7ab2371124d88e7f784c1478ec02e9c4fc0ed374481513d1a92dc9182` |
| `FW/scripts/tests/carriers/carhelp.py` | changed (additive) | `3afcf60469be42c0f4962b9c5c06e2665b3f78f08853ad145b2f1c9c74a82f06` → `9f97e103b0aa3fa06e89e9fc6b6564b603d9e55d048cb93529ffca1bc450a638` |
| `FW/scripts/tests/drafting/drafthelp.py` | new | `2bcb55a6ec064f6b1715d73d37b962d80ffb9e0ae0b901469cec65624c31d4e0` |
| `FW/scripts/tests/drafting/fixtures/delivered_tests_001abcdf.json` | new | `4e1521f46a02bb8d0f83b7c703aa3255bc969eb9aff246126dcaf0e32be5427d` |
| `FW/scripts/tests/drafting/fixtures/guard_copilot_hashes.json` | new | `16008ffcbef49aaa5c92e007f8c7d92bb3583e3d705fcfcc369a629111671703` |
| `FW/scripts/tests/drafting/fixtures/injections.json` | new | `f8f82935abdfa3442d8ef063eb8f4bd574d3df9d17c4ea4999b75126ee8b8b83` |
| `FW/scripts/tests/drafting/fixtures/lint_cases.json` | new | `37722fcd5bc7d4cf0efc8fc77ff6cc790029fc8b42fbce695a1196b9fcb9ee52` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/check.json` | new | `2b342c1bd2eb9780d862ab3299b53c09f81e01cff638d94b04bffb444db8fde3` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/exit-preview.json` | new | `af5901bca80c1ba8aa3489d697318404584e0e223e2042020ca0ebe441be269f` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/guard-open.json` | new | `6963c41cb96008bcca0121c729d5305864678d0c2781aad347ad884a66e54127` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/import.json` | new | `aaa3943fd85b8b7477663ad5e95d16ce281f4148d455e7a7efada5bc940ef99b` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/init.json` | new | `225322dfffe2107062606f977f0966c505f80afa5a4c9222d0e83f65cab6b9ac` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/links.json` | new | `a1e5522d360c8c70a2a181bed46a9d931146cb8cd613cea9b9811f6c2efa2594` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/list.json` | new | `74da1cd0c09582bef041db718d84df25c269009e2dd8be78ea78f38b6bb5d8ee` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/resolve.json` | new | `bbdbd3a89c73ff21f26c85d3e31c9499bbccd569317db496137e147754da0ef8` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/scope-show.json` | new | `751b46f3695e7a3b73a9b2218d7ff3b25a0d4f887b7dde97047e6208d4543716` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/show.json` | new | `9c06de50d08d94df791ab7c30b40a73d8e0d01629a091d97673b40b3e9634e10` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/status.json` | new | `92fbf919fc52ff75a25d963cfaa89c6a2586b5c39ced30bc1005536a62ef1b54` |
| `FW/scripts/tests/drafting/fixtures/pre_001g/update.json` | new | `c874bbe5d4a4d8c46595773c56c5149ebcc1f0d1b5326660d1cf32af42554993` |
| `FW/scripts/tests/drafting/fixtures/seed_batch.json` | new | `06206b615ce602cb12e137553e42617c6a83cf3cd15d24345a9ebcec3d662e3b` |
| `FW/scripts/tests/drafting/fixtures/sources-allowlist.json` | new | `fde91e6f7f45c5e0ebc118f9ce6dac8c608d13bbd4b423b30e6a11000c303ce6` |
| `FW/scripts/tests/drafting/fixtures/synth_batch.json` | new | `85fa1315cd5294f975c6625a0ea324dce87a52ec3a823da14fa17f889cb34cce` |
| `FW/scripts/tests/drafting/ledgerhelp.py` | new | `3ea3e27b95840056abcbc933e5a47f63a82dd83c8eaddddcb4090ed05897675f` |
| `FW/scripts/tests/drafting/test_draft_b14_guard.py` | new | `3d2ee831813e55cb56536ab99ea7d04af52bbf751a37a9765d453da409a4ac64` |
| `FW/scripts/tests/drafting/test_draft_cli_approve.py` | new | `274f5e2eaff3c3af7d1a99972f8fe3d2fbb8498a204152c314d7b3ea76fe0452` |
| `FW/scripts/tests/drafting/test_draft_cli_check.py` | new | `1c2151f0944763eaf5a960bcc94a9a07fed57f76a8dc56e9b3f0e6983528119c` |
| `FW/scripts/tests/drafting/test_draft_internal.py` | new | `97370fbf53f349c91885129532d9215090ff2ff0c26e2034b36f48418ae4e6b6` |
| `FW/scripts/tests/drafting/test_draft_lifecycle.py` | new | `39052cc85edcce517fb19784b499d2649ebe51aeaa894d53b92ff158a15ea0f2` |
| `FW/scripts/tests/drafting/test_draft_network.py` | new | `0e382f9e6a7dfc49c1f943c60177137a5d1c25cfc6e24d0db609e0e2b86ed2dd` |
| `FW/scripts/tests/drafting/test_draft_regression.py` | new | `a05d14beae35d4378cedbe97fc0614a918a71f220c6c4489bf72927032d6c388` |
| `FW/scripts/tests/drafting/test_draft_skill.py` | new | `e49fd1ac95f4667d6f26c01a16d2afcd141ee734bbb285c38d0a7e2e9a963af5` |
| `FW/scripts/tests/drafting/test_draft_staging.py` | new | `a768245b777e377ae10f50223de3fd58f032394b4fd6f870bcff987f2edc1cd0` |
| `FW/scripts/tests/drafting/test_draft_supplements.py` | new | `4443c5e08c610ba28f47d7ff46af9ddea023b4d28c8d4ca686d1726440e68405` |
| `FW/scripts/tests/drafting/test_draft_units_blocks.py` | new | `8f4655cdb0583c12ce45611de8e4a89c06dba158954ac007f9b60cd4d1f4ef4f` |
| `FW/scripts/tests/drafting/test_draft_units_checks.py` | new | `ab2f1f82130ced3f6411be7836faff13849b7b4f7112356dd6b48e2273e8dfdc` |
| `FW/scripts/tests/drafting/test_draft_units_lint.py` | new | `860bfb57b7b085ed1cbb31cd669b9abb49fe1b6e64dc1faa1d5a7aea1bbe3953` |
| `FW/scripts/tests/drafting/test_draft_units_mask.py` | new | `1d18119ea5b7b3d346a7159d03f9c3d6180e8f3cef77d97c5f7a99be48d43ede` |
| `FW/scripts/tests/drafting/test_draft_units_model.py` | new | `a73246df1e652778049cbe9c08af05a8fed2697b823348b2346b1dd77cd72924` |

## 5. Delivered-File Parity (stop rule, BR-15)

Final tree vs step-0 baseline (per-file SHA-256), after the DAO-004 follow-up: **changed = exactly `FW/SKILL.md`, `FW/references/cli-contract.md`, `FW/scripts/src/x_ipe_secure_code/cli.py` (all purely additive) and `FW/scripts/tests/carriers/carhelp.py` (the DAO-004 DEC-I1 `ERA_001A_REMOVED` append only, byte-identical to `era-proposed.diff`); removed = none; added = 46 files, all new FEATURE-001-G files.** Every other delivered module, test, fixture, skill and reference file is byte-identical, including the Guard/Copilot packages, `knowledge-batch.md`, `pyproject.toml` and `uv.lock`. No new dependency.

### STOP-rule finding — resolved by DAO-004 DEC-I1 (applied 2026-10-24)

The full suite fails exactly these **10 delivered FEATURE-003-B tests**, identically in every full run:

- `tests/carriers/test_carriers_preservation.py::test_04i_windows_simulated_carriers_lock_unavailable_init_unchanged`
- `tests/carriers/test_project_lock.py::test_plain_init_with_unavailable_lock_identical_to_001a_baseline[EINVAL|ENOLCK|ENOTSUP|EOPNOTSUPP × github-copilot|claude-code]` (8)
- `tests/carriers/test_record_compat.py::test_08c_member_less_project_record_and_output_identical`

Exact assertion (e.g. `test_record_compat.py:203`): `assert normalize_init(proc.stdout, box.root) == golden["stdout"]` with `- "created": "<94 files>"` vs `+ "created": "<104 files>"` (and the same `<104 files>` difference at `test_project_lock.py:164`). Cause: `toolkit_copy(era="001A")` (`tests/carriers/carhelp.py` L329–338) removes only the paths in `ERA_001A_REMOVED` (L55–74); the 10 new 001-G payload files (9 `knowledge/drafting_*.py` + `references/knowledge-drafting.md`) are not listed, so the synthesised 001-A-era toolkit has 104 instead of 94 files. Nothing else differs.

Precedent: DAO-002 (code implementation) for FEATURE-001-F and the FEATURE-002-G entries in the same tuple — "every later payload-adding feature appends its payload paths to ERA_001A_REMOVED; fixture and assertions are never re-recorded"; DAO-016 lists this maintenance point among the bindings. Per the owner's instruction for this task (only `cli.py`, `SKILL.md`, `cli-contract.md` may change; report rather than edit) the helper was **not** edited. Scratch verification (copy of the final toolkit in the session folder, helper appended with the 10 paths; `log-era-scratch.txt`): the three affected files run **76 passed, 0 failed**. Proposed append (`impl-084/era-proposed.diff`), after the FEATURE-002-G entries:

```python
    # FEATURE-001-G.
    f"{FRAMEWORK}/references/knowledge-drafting.md",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_auth.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_blocks.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_checks.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_lint.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_mask.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_model.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_pipeline.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_service.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_supplements.py",
```

Ruling: DAO-004 DEC-I1 approved the append as the established maintenance rule (DAO-002 code implementation). It was applied exactly as above (pure list append, no assertion or fixture change). The 10 tests now pass and the full suite has 0 failures (§6).

## 6. Validation

| Check | Result |
| --- | --- |
| 001-G tests (`tests/drafting`, final tree) | **269 passed** (model 45, blocks 23, mask 7, lint 21, checks 41, cli_check 33, cli_approve 25, internal 9, lifecycle 11, staging 12, supplements 6, network 2, regression 7, skill 24, b14_guard 3) |
| `tests/drafting` + `tests/carriers` + module size after the DAO-004 fixes — `log-green-fix` | 522 passed |
| **Full suite run D (final tree after DAO-004 follow-up) — `log-full-4`** | **2885 passed, 0 failed, 4 skipped, 23 deselected (opt-in `trivy_real`), 698.1 s; no write-audit finding** |
| Full suite run A (before DAO-004; superseded: product tree final, `test_draft_cli_check.py` edited during the run) — `log-full-1` | 2868 passed, **10 failed** (the 10 above), 4 skipped, 23 deselected (opt-in `trivy_real`), 692.7 s |
| Full suite run B (tree of the first report) — `log-full-2` | 2871 passed, **10 failed** (same 10), 4 skipped, 23 deselected, 691.9 s |
| Full suite run C (tree of the first report, repeat) — `log-full-3` | 2871 passed, **10 failed** (same 10), 4 skipped, 23 deselected, 696.9 s |
| Write audit (FEATURE-003-B suite-wide) | runs B and C: no finding. Run A reported `modified: tests/drafting/test_draft_cli_check.py` — this worker appended 3 tests to that file while run A was executing (protected-tree snapshot), not a product write; run A is therefore superseded by B and C, the two complete runs at the final tree |
| `ruff check --no-cache src tests` | All checks passed |
| Module sizes (`tests/test_module_size.py`, < 800 lines) | passed: `drafting_auth 268`, `drafting_blocks 286`, `drafting_checks 262`, `drafting_lint 166`, `drafting_mask 196`, `drafting_model 360`, `drafting_pipeline 477`, `drafting_service 440`, `drafting_supplements 146`, `cli.py 537` |
| Forbidden-substring scan (case-insensitive, the three hook-rejected strings) over all new/changed toolkit files (incl. `carhelp.py`) and this report | 0 hits (re-run after the DAO-004 follow-up) |
| `demo/` references in new tests/fixtures/product files | 0 (the B14 guard test asserts it at runtime with assembled tokens) |
| Artifacts left in `ai-secure-code-toolkit/` (`__pycache__`, `.pytest_cache`, `.ruff_cache`, `*.pyc`, temp) | none |
| Delivered outputs for a project without drafts (AC-001G-08a) | equal to the step-0 goldens; `init` differs only by the 10 new payload paths (asserted exactly) |

Count reconciliation: first report 2616 + 265 = 2881 = 2871 passed + 10 failed; after DAO-004 2616 + 269 = 2885 passed, 0 failed.

## 7. AC-to-Test Traceability (every active AC)

All paths `FW/scripts/tests/drafting/`. State: delivered **verified** (passing at the final tree) for every row; outcome **not measured**.

| AC | Tests (assert) |
| --- | --- |
| 01a | `test_draft_cli_check.py::test_01a_valid_report_preview_digest_and_review_incomplete_read_only` (valid, per-check results, preview == stdlib diff of the unmasked payload, digest recomputed by the design formula and stable, `review_incomplete` + `final: false` without review, tree unchanged) |
| 01b | `test_draft_cli_check.py::test_01b_forbidden_fields_refused_draft_invalid[10 fields]` (check and approve, field named, no write); `test_draft_units_model.py::test_01b_*` |
| 01c | `test_draft_cli_check.py::test_01c_draft_invisible_to_readers` (policy resolve, scope show, knowledge show/list/links, Guard/Copilot policy load identical with/without drafts) |
| 01d | `test_draft_cli_approve.py::test_01d_notice_no_timestamp_prior_text_identical` |
| 01e | `test_draft_supplements.py::test_01e_lists_fields_time_from_changelog_read_only` (+ `test_approval_time_not_found_without_changelog_entry`; masked sources: `::test_supplements_masks_prechecked_values_in_notice[3]`, DEC-I15) |
| 01f | `test_draft_supplements.py::test_01f_modified_and_malformed_reported_not_repaired` |
| 01g | `test_draft_cli_approve.py::test_01g_one_changelog_entry_with_marker_lines` |
| 01h | `test_draft_cli_approve.py::test_01h_create_or_append_prior_bytes_preserved` |
| 01i | `test_draft_units_blocks.py::test_01i_grammar_cases[12]`; `test_draft_cli_check.py::test_01i_malformed_markers_refused[malformed, nested, duplicated, unterminated, inside_non_ai]` (check + approve, file:line named, no write) |
| 01j | `test_draft_cli_approve.py::test_01j_written_bytes_equal_payload_and_masked_diff_equals_preview` (+ R2 below for a masked case) |
| 02a | `test_draft_cli_approve.py::test_02a_non_maintainer_refused_tree_unchanged` (in-process and subprocess CLI) |
| 02b | `test_draft_cli_approve.py::test_02b_stale_validation[draft, review, base, validator_version, precheck_key]` (base: `STATE_CONFLICT` primary + `STALE_VALIDATION`, DEC-4) |
| 02c | `test_draft_cli_approve.py::test_02c_stale_base_check_and_state_conflict` |
| 02d | `test_draft_cli_approve.py::test_02d_credential_masked_fp_exact_value_never_printed`; `test_draft_units_mask.py` (parity, determinism, sweep); R4; `test_draft_supplements.py::test_supplements_masks_prechecked_values_in_notice[not_retrieved_reason, fetched_attribution, key_absent]` (value never printed by `supplements`, JSON and text, also after the false-positive declaration and without a pre-check key; DEC-I15) |
| 02e | `test_draft_cli_approve.py::test_02e_equivalent_to_plain_update_time_normalised` |
| 02f | `test_draft_cli_approve.py::test_02f_all_or_nothing_failing_language_named` |
| 02g | `test_draft_skill.py::test_02g_report_before_approve_no_agent_review_or_flags` (real commands + positive/negative ledgers) |
| 03a | `test_draft_units_checks.py::test_03a_python_ast_only_no_exec_import_subprocess` (compile only with `PyCF_ONLY_AST`) and `::test_03a_audit_hook_child_process_sees_no_side_effect` |
| 03b | `test_draft_units_checks.py::test_03b_invalid_syntax_nesting_size_no_crash[5]`; `test_draft_cli_approve.py::test_03b_approve_refused_invalid_syntax` |
| 03c | `test_draft_cli_check.py::test_03c_non_python_needs_unchecked_syntax_decision[java, javascript, c]` |
| 03d | `test_draft_units_checks.py::test_03d_example_incomplete[4]` |
| 03e | `test_draft_units_checks.py::test_03e_no_rule_link` |
| 03f | `test_draft_units_checks.py::test_03f_language_unsupported_lists_supported` |
| 03g | `test_draft_units_checks.py::test_03g_language_not_in_applicability_warning_only`; `test_draft_cli_check.py::test_03g_04b_warnings_do_not_refuse` |
| 03h | `test_draft_cli_check.py::test_03h_per_language_results_conjunction` |
| 03i | `test_draft_cli_check.py::test_03i_placeholders_notes_literal_finding_masked` |
| 03j | `test_draft_cli_check.py::test_03j_example_decision_missing_items_digest_binding` |
| 03k | `test_draft_units_checks.py::test_03k_command_validator_fixtures[11]`, `::test_03k_harmless_placeholder_and_wording`; `test_draft_cli_check.py::test_03k_command_acknowledgement_required_and_recorded` |
| 04a | `test_draft_units_blocks.py::test_04a_stripped_result_equals_stripped_current[5]` |
| 04b | `test_draft_units_lint.py::test_04b_04f_expected_table[17]`, `::test_04b_returns_advisory_warnings_only`; `test_draft_cli_check.py::test_03g_04b_warnings_do_not_refuse` |
| 04c | `test_draft_units_lint.py::test_04c_verbatim_quotation_not_reported` |
| 04d | `test_draft_cli_check.py::test_04d_attestation_missing_and_named_in_notice` |
| 04e | `test_draft_skill.py::test_04e_declines_new_requirement_proposes_custom_rule` |
| 04f | `test_draft_units_lint.py::test_04f_adversarial_table_and_documented_miss` (+ table rows) |
| 05a | `test_draft_network.py::test_05a_commands_work_with_sockets_blocked_no_model_options`, `::test_static_import_scan_of_drafting_modules` |
| 05b | `test_draft_units_checks.py::test_05b_allowlist_table`, `::test_allowlist_constant_equals_copied_fixture` (R11) |
| 05c | `test_draft_cli_check.py::test_05c_not_retrieved_notice_no_digest` (check + approve); `test_draft_units_checks.py::test_05c_not_retrieved_needs_url_and_reason_and_no_digest` |
| 05d | `test_draft_units_checks.py::test_05d_provenance_complete_incomplete_attribution_no_verified_wording[9]`; `test_draft_cli_check.py::test_05d_fetched_source_needs_licence_attestation` |
| 05e | `test_draft_skill.py::test_05e_injection_fixtures_ledger_only_permitted_calls` (`fixtures/injections.json`: direct, indirect, base64, zero-width, Chinese, reveal) |
| 05f | `test_draft_skill.py::test_05f_only_toolkit_commands_and_allowlisted_gets_transport_excluded` |
| 06a | `test_draft_lifecycle.py::test_06a_second_draft_stale_after_first_approval` |
| 06b | `test_draft_lifecycle.py::test_06b_stale_after_update_import_deactivate_reactivate[4]` |
| 06c | `test_draft_lifecycle.py::test_06c_deactivated_rule_inactive_next_step` |
| 06d | `test_draft_lifecycle.py::test_06d_deleted_or_renamed_refused_new_identity_untouched[delete, rename]` |
| 06e | `test_draft_cli_approve.py::test_06e_replaces_previous_block_not_duplicate` |
| 06f | `test_draft_skill.py::test_06f_lists_blocks_before_update_candidate_question` |
| 06g | `test_draft_lifecycle.py::test_06g_adopted_scope_needs_reconfirmation` |
| 06h | `test_draft_lifecycle.py::test_06h_approve_vs_exit_confirm_serialized_and_locked` (paused exit holds the lock → `LOCKED` after ≥ 5 s, nothing written; then `RULE_INACTIVE`), `::test_06h_race_loop_consistent` (20 runs, consistent rule every time) |
| 07a | `test_draft_internal.py::test_07a_synthetic_internal_rule_authorized_fixture_host` |
| 07b | `test_draft_units_checks.py::test_07b_internal_default_downgrade_refused`; `test_draft_internal.py::test_07b_declared_internal_on_non_at_rule_gated` |
| 07c | `test_draft_skill.py::test_07c_no_fetch_no_rule_text_outside_toolkit` |
| 07d | `test_draft_internal.py::test_07d_not_authorized_check_and_approve`; `test_draft_skill.py::test_07d_authorization_list_before_any_show` |
| 07e | `test_draft_internal.py::test_07e_record_list_revoke_in_process`, `::test_07e_interactive_record_list_revoke_init_status_unchanged` (real pseudo-terminal, typed label, `tmp_path` project) |
| 07f | `test_draft_internal.py::test_07f_no_tty_or_non_maintainer_refused_nothing_recorded`; `test_draft_skill.py::test_07f_skill_never_invokes_record_form` |
| 08a | `test_draft_regression.py::test_08a_delivered_suites_unchanged_and_outputs_equal_pre_001g` (001-A/B/C/D/F test files unchanged; outputs equal goldens; `init` differs exactly by the 10 new payload paths); the delivered 003-B suite is green after the DEC-I1 append (§5); evaluated modulo the declared payload growth (DEC-I3, §9b) |
| 08b | `test_draft_regression.py::test_08b_with_and_without_drafts_folder_equal` (byte copy of the project taken before drafts; resolve, scope, links, exit preview, Guard policy load and Guard open equal) |
| 08c | `test_draft_regression.py::test_08c_requirement_identical_examples_key_only` |
| 08d | `test_draft_regression.py::test_08d_guard_copilot_inputs_lack_block_bytes_skills_unchanged` |
| 08e | `test_draft_regression.py::test_08e_item_and_state_digest_recomputed`; `test_draft_cli_approve.py::test_02e_*` |
| 08f | `test_draft_regression.py::test_08f_check_stored_changed_not_fully_stored` |
| 08g | `test_draft_regression.py::test_08g_exit_preview_impact_equal_preset_tag_files_unchanged` |
| 09f | `test_draft_cli_check.py::test_09f_explanation_field_refused_check_and_approve`; `test_draft_units_model.py::test_09f_explanation_field_refused` |
| 09a…09e | **Deferred by human decision B13 = H2 (not in v1.0)** — no test, never reported passed |

Review-driven tests: R1 `test_draft_cli_approve.py::test_extra_rule_file_refused_and_preserved`, `::test_missing_content_md_refused_nothing_written` (exactly `RULE_INCONSISTENT`; design erratum, §9a); R2 `test_draft_units_mask.py::test_private_key_body_replacement_preview_nonempty_redacted`, `test_draft_cli_approve.py::test_private_key_replacement_preview_equals_masked_applied_diff`; R3 `test_draft_cli_check.py::test_recovery_pending_refused_read_only_forms[3]`; R4 `test_draft_cli_approve.py::test_false_positive_forwarding[missing, exact, extra, duplicate, wrong_rule, malformed]`; R5 `test_draft_staging.py::test_crash_before_update_call_swept_next_approve`; R6 `::test_crash_during_update_call_recovered_and_swept`; R7 `::test_cleanup_never_targets_active_lease`; R8 `::test_concurrent_approvals_distinct_leases`; R9 `::test_symlink_races[3]`; R10 `::test_staging_permissions_posix` (+ modes in R5); R11 see 05b; R12 `test_draft_units_lint.py::test_dec8_zh_fixtures`; R13 `test_draft_units_checks.py::test_v6_wording_never_claims_rule_fit`; R14 `test_draft_staging.py::test_no_knowledge_lock_held_across_update_rule`; R15 `::test_staging_swap_after_reread_write_mismatch`; DEC-I16 `::test_concurrent_write_after_update_is_not_write_mismatch`; R16 `::test_staging_changed_before_call_not_written`; R17 `test_draft_cli_check.py::test_read_only_commands_open_no_session_or_lock`. B14 binding evidence: `test_draft_b14_guard.py` (3).

## 8. Implementation Summary (means within the approved design)

- `drafting_model` (draft/review v1, forbidden-field naming, `explanation` refused, DEC-9 location rules with no-follow reads ≤ 1 MiB); `drafting_blocks` (comment table, marker grammar, render/strip, notice); `drafting_mask` (span re-location with the delivered pattern constants + parity guard, line-preserving redaction, hunks from unmasked lines, output sweep, key id); `drafting_lint` (advisory K-22 lint, DEC-8); `drafting_checks` (V5, V6 DEC-7, V9 AST-only, V10 exact allowlist, V11, V13 classification, V12 requirements); `drafting_pipeline` (read-only V1…V13, preservation pre-check and writer simulation, canonical payload, masked preview, `validation_digest`); `drafting_service` (`draft-check`; `draft-approve` with exact false-positive forwarding, lease-held owner-only staging, sweep, path re-check + re-read, delivered `update_rule`, `WRITE_MISMATCH` post-check, test hooks); `drafting_supplements`; `drafting_auth` (per-project record, TTY + Maintainer + typed label, `--list` read-only, fail-closed gate).
- P2: the delivered, unchanged `knowledge.service.update_rule` is the only path that writes formal knowledge. P3b writes occur only on `.x-ipe/private/secure-code/drafting-staging/` and `.x-ipe/private/secure-code/drafting-authorizations.json`. P3c recovery only in `draft-approve` and `drafting-authorize` record/revoke; read-only commands refuse `RECOVERY_PENDING`. No knowledge lock is held across `update_rule` (R14).
- Tool routing: `tools.json` was not re-read for execution; the Python conventions of `x-ipe-tool-implementation-python` (PEP 8, type hints, pytest, ruff) were applied directly by this worker (no tool skill executed separately). The Framework `SKILL.md` is the toolkit's product skill text (P4) and was edited exactly as the design specifies, as in FEATURE-001-F; `x-ipe-meta-skill-creator` governs X-IPE `.github/skills` packages and was not involved.

## 9. Implementation Decisions and Rulings (DAO-004, 2026-10-24T06:38:31+08:00)

All fourteen were approved by the delegated DAO representative in DAO-004 (`x-ipe-docs/dao/26-10-23/decisions_made_code_implementation.md`), DEC-I5 with a change; DEC-I15 and DEC-I16 come from the independent code review (PASS-WITH-FIXES) and were applied under the owner's follow-up. Rulings are listed after the table.

| ID | Ambiguity | Conservative choice taken |
| --- | --- | --- |
| DEC-I1 | `ERA_001A_REMOVED` maintenance (§5) | Not applied (owner instruction); exact assertions, cause, precedent and scratch-verified 10-line append reported. Owner/DAO decides (DAO-002 maintenance vs CR). |
| DEC-I2 | Design step 1 says "copied seed batch"; the toolkit ships no packaged seed knowledge and the sample-project folder is forbidden | Authored fixture batches `seed_batch.json` (identities `CWE/Top25-2025/CWE-89`, `CWE-78`, `OWASP/Top10-2025/A03`, short synthetic test content) and `synth_batch.json` (`@SYNTH/T-1.0/R-01`). No content was copied from any project folder. |
| DEC-I3 | AC-001G-08a "init outputs byte-identical" while the payload necessarily grows | Golden comparison after removing exactly the new payload paths from `created`, with an assertion that the removed set equals the 10 new 001-G payload files; everything else byte-identical. |
| DEC-I4 | Golden `status.json` contained the machine host name and OS user | Replaced by `<hostname>` / `<os-user>` in the captured bytes and normalised identically at regeneration. |
| DEC-I5 | R1 `missing_content_md` expects `PRESERVATION_FAILED`, but the design's own order (`RULE_INCONSISTENT` at step 2 before 4b) applies first because a missing `content.md` changes the item digest | Kept the design step order; the test accepts `RULE_INCONSISTENT` or `PRESERVATION_FAILED` and asserts nothing written. |
| DEC-I6 | Pipeline order step 2 (read rule) then step 3 (V13 gate) | Gate placed **before** reading the rule (stricter): an internal draft without authorization is refused before any rule read. |
| DEC-I7 | P3a list is exact; implementation also uses unchanged helpers not named there | Read-only/helper uses: `store.iter_refs` (supplements over all rules), `store.example_file`/constants (`LOCAL_REL`, `PRIVATE_REL`, `LOCK_REL`, `CRASH_ENV`, `PAUSE_ENV`), `precheck.KEY_REL`, `durable.close`/`durable.unsafe`/`POSIX_FD`/`NOFOLLOW`/`NONBLOCK`, `atomic.LockHeld`, `atomic.dumps_json` (serialising the 001-G record), `exit_journal.RETRY_STEP`. None modified; no write outside 001-G-private paths. Owner may record them in spec P3a. |
| DEC-I8 | `drafting-authorize` shape errors (neither `--list` nor `--host`; `--list` with `--revoke`) | Refused `ARGUMENT_INVALID` (exit 1) instead of argparse exit 2 (the "`--list [--host]` or `--host [--revoke]`" shape is not expressible in the delivered argparse style). |
| DEC-I9 | Notice content when optional items are recorded | Notice lists only required decisions (and `example_commands_acknowledged` only when a command finding made it required and it is recorded). |
| DEC-I10 | OWASP category pages "only for rule `OWASP/Top10-2025/A0n`" | Exact namespace, version and rule id required (stricter than namespace + id). |
| DEC-I11 | Findings shown as "type, file, line and fingerprint only" | Output uses the delivered `Finding.to_dict()` (adds the `blocking` boolean; never a value). |
| DEC-I12 | Design R14/R17/R6 details | R6 asserts the delivered recovery outcome through the logical (journal-applied) view; `knowledge show` reports the new state before a later write rolls the files forward physically. |
| DEC-I13 | New maintenance points created by design-mandated regression evidence | `fixtures/delivered_tests_001abcdf.json` and `fixtures/guard_copilot_hashes.json` freeze delivered test/skill hashes at step 0: a later legitimate change of those files must update these fixtures (like `ERA_001A_REMOVED`). |
| DEC-I14 | Staging lease window between lease-file creation and lock acquisition | After acquiring its lease, an approval verifies its lease file still exists with the locked inode; otherwise `STAGING_CHANGED` (fail closed). |
| DEC-I15 | Review issue 1 (Medium; AC-001G-02d, FR-001G-4/10): `knowledge supplements` printed notice source text (a `not_retrieved` reason or attribution title/url/licence) unmasked after an approval with `--false-positive` | Mask, not drop: `supplements` keeps the FR-001G-4 `sources` field and passes each rule's rows through `drafting_mask.sweep` with the values located by `drafting_mask.locate` (parity with the delivered pre-check) over that rule's stored files, using the existing pre-check key read-only (`[REDACTED:<fingerprint>]`, the same tokens draft-check shows); without a usable key (absent, unsafe path or wrong length; never created) the same pattern matches are masked as `[REDACTED]`. No other AC or output changes; `MASKING_PARITY` refuses as elsewhere. |
| DEC-I16 | Review issue 2 (Low): after a successful `update_rule`, a legitimate write by another command before the re-read produced `WRITE_MISMATCH` with restore advice that would undo that write | `WRITE_MISMATCH` is decided solely by `update.item_digest != digest(reviewed payload item)`; its `state_digest` and changelog entry are those of the draft-approve write (entry located by its item digest). If the re-read differs while the digest matches, the result is success with `data.changed_after_approval` {`state_digest`, note} and the next step "Show the rule again … before further drafting" — no `WRITE_MISMATCH`, no restore advice. Delivered code untouched. |

**DAO-004 rulings:** DEC-I1 approved (applied, §5). DEC-I2 approved (synthetic batches; `@SYNTH` only for internal tests). DEC-I3 approved as the evaluation of AC-001G-08a (closing note below). DEC-I4 approved. DEC-I5 approved **with a change** — the R1 test now asserts `RULE_INCONSISTENT` exactly plus nothing written (design erratum below). DEC-I6, I8, I9, I10, I12, I14 approved. DEC-I7 approved (closing note below). DEC-I11 approved (closing note below). DEC-I13 approved — failure messages now name the fixture and why; maintenance points listed below. DAO-004 closing conditions still open for the owner: independent re-review of the fixes, the local exact-path commit (B8), then Feature Acceptance Test (fixture-only).

### 9a. Design erratum (DAO-004 DEC-I5)

Technical design v1.2, review test R1 lists `PRESERVATION_FAILED` for the `missing_content_md` case. That expectation is superseded by the design's own step order: step 2 (`RULE_INCONSISTENT`, because a missing `content.md` changes the item digest against the record) runs before step 4b (representability). The implementation keeps the step order and the test pins `RULE_INCONSISTENT` exactly, with nothing written. To be corrected in the design at the next revision (owner action).

### 9b. Closing notes

- **DEC-I3 (AC-001G-08a):** "byte-identical `init` outputs" is evaluated modulo the declared payload growth: exactly the 10 new 001-G payload files (9 `knowledge/drafting_*.py` + `references/knowledge-drafting.md`) are removed from `created`, an assertion fixes that set, and everything else is byte-identical with the step-0 goldens.
- **DEC-I7 (spec P3a wording erratum, next spec revision; no re-review):** additional P3a-class read-only uses of unchanged delivered helpers, constants, exceptions or pure functions: `store.iter_refs`, `store.example_file` and the constants `store.LOCAL_REL`/`PRIVATE_REL`/`LOCK_REL`/`CRASH_ENV`/`PAUSE_ENV`, `precheck.KEY_REL`, `durable.close`/`durable.unsafe`/`POSIX_FD`/`NOFOLLOW`/`NONBLOCK`, `atomic.LockHeld`, `atomic.dumps_json` (pure serialization), `exit_journal.RETRY_STEP`, `paths.unsafe_component`. No write outside the 001-G-private paths.
- **DEC-I11:** pre-check findings are shown with the delivered `Finding.to_dict()`, i.e. type, file, line, fingerprint plus the `blocking` boolean — a superset of the fields AC-001G-02d lists, with no value disclosed.

### 9c. Maintenance points

| Maintenance point | Where | When to update | Self-explaining failure |
| --- | --- | --- | --- |
| `ERA_001A_REMOVED` | `FW/scripts/tests/carriers/carhelp.py` (delivered 003-B helper) | every later feature that adds Framework payload files appends its payload paths (DAO-002, DAO-004 DEC-I1); fixtures/assertions are never re-recorded for this reason | delivered 003-B tests show `<N files>` differences |
| Delivered 001-A/B/C/D/F test hashes | `FW/scripts/tests/drafting/fixtures/delivered_tests_001abcdf.json` | a legitimate, approved change to one of the listed delivered test files | `test_08a_*` message names the changed files, the fixture to update and that otherwise it is a stop-rule regression |
| Guard/Copilot skill package hashes | `FW/scripts/tests/drafting/fixtures/guard_copilot_hashes.json` | a legitimate, approved change to the Guard or Copilot skill package | `test_08d_*` message names the changed files and the fixture to update; AC-001G-08d only requires that 001-G itself never changes them |

## 10. Honest Limits

- Skill-procedure ACs (02g, 04e, 05e, 05f, 06f, 07c, 07d skill part, 07f skill part) are evidenced by skill-text assertions and scripted positive/negative ledgers checked by `ledgerhelp.check_ledger` (DEC-12). They prove the checker and the instructions, **not** a live model's behaviour; no live host session ledger was captured. Host-platform transport is not observable and is excluded.
- Fixture-only acceptance (DAO-008 (3)): no live model output, no real page fetch, no real internal content; the internal gate was exercised only with `@SYNTH/T-1.0/R-01` and `fixture-host` in disposable projects. B14 = No: no authorization exists for any real host label.
- The narrowed exact-bytes claim holds as specified: a same-account swap of the owner-only staging file between the final re-read and the delivered `update_rule`'s own open is detected only after the write (`WRITE_MISMATCH`, tested R15), not prevented. Closing it needs an fd/in-memory `update_rule` (001-B change; optional human CR candidate).
- Markers are tamper-evident for accidental edits only; non-Python syntax is not validated; Python validity follows the toolkit interpreter grammar (3.14 here); V6 is a verbatim-quote precondition, not rule-fit evidence; the K-22 lint is heuristic (documented miss: widening prose); provenance is field completeness only; host/model labels are self-reported; a terminal is not proof of a human; the authorization record has no integrity protection.
- Owner-only modes and the POSIX race/permission tests (R9, R10, pseudo-terminal 07e) are POSIX-only; Windows behaviour was not run here (macOS only). Linux was not run in this task.
- RED evidence for steps 3, 9 (approve), 10–12 is a module-absent reproduction, not a pre-implementation capture (§3).
- "Faster maintenance" (G-03) is not measured.

## 11. Delivery and Outcome

Engineering delivery: **verified** for the 62 active ACs at the final tree after the DAO-004 follow-up — 269 drafting tests passing; full suite 2885 passed, 0 failed, 4 skipped; delivered-file parity exact (only `cli.py`, `SKILL.md`, `cli-contract.md` additive plus the `ERA_001A_REMOVED` append in `carhelp.py`); ruff clean; module sizes within limit; forbidden-substring scan 0; nothing left in `ai-secure-code-toolkit/`. Independent review findings 1–2 fixed test-first (DEC-I15, DEC-I16); re-review of the fixes is the owner's next gate. AC-001G-09a…09e deferred by human decision B13 = H2. Stakeholder outcome: **not measured.**

## Owner Closing Addendum (2026-10-24, appended by Sage)

- Independent code review: PASS-WITH-FIXES (supplements unmasked scan match → DEC-I15; concurrent write after approval reported as WRITE_MISMATCH → DEC-I16); delta re-review **PASS** (drafting + carriers + module-size: 522 passed, 0 failed). Owner re-run of drafting + carriers: 521 passed, 0 failed.
- Representative DAO-004 (code implementation): DEC-I1…I14 approved (DEC-I5 tightened, applied).
- Observation O-084-1 (Low, not fixed, for acceptance/closing): `draft-check` echoes `provenance[].url` without masking when the secret scan did not run (draft not representable, e.g. an unsupported language, scan `not_run`); the URL is also refused by the allowlist and was written by the agent itself. Not a printed scan match; candidate: scan source fields when no payload is built, or omit refused URLs.
