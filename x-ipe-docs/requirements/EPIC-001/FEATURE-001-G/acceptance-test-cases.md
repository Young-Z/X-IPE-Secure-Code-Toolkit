# Acceptance Test Cases — FEATURE-001-G AI-assisted Knowledge Drafting (Examples Only)

> Feature / scope: FEATURE-001-G (EPIC-001), v1.0 delivery scope = AC groups 01–08 + AC-001G-09f (62 active ACs; human decision B13 = H2). AC-001G-09a…09e are deferred by human decision B13 = H2 — not tested and never reported passed.
> Task: TASK-103 (Feature Acceptance Test), lifecycle owner Sage, acceptance worker; free mode. No board, Git, memory or successor action was taken by this worker.
> Status: **Verified delivery — 62/62 active ACs Pass; 36/36 planned test cases Pass (pass rate 100 % on all planned cases)**. Stakeholder outcome **not measured**.
> Revision: toolkit commit `93e3eaa`, executed only from the frozen copy (`git archive` of `93e3eaa`) in the session evidence folder; frozen-tree file-list hash `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68` (291 files) at start **and** end of all runs.

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-001-G — CLI `secure-code knowledge draft-check / draft-approve / supplements / drafting-authorize`, labelled AI example blocks written through the delivered `update_rule`, and the Framework skill drafting procedure (`SKILL.md` section, `references/knowledge-drafting.md`, `cli-contract.md` rows) |
| Specification / Source | [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/specification.md) v1.3.3, SHA-256 `4cb3a1eb3e91831c9eabe9a2351ed36f401070193e5676f7009ba53ab0b296a2` (62 active AC rows + 5 deferred) |
| Design / Implementation | [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/technical-design.md) v1.2 `5e0f2aa8e582e25374491dccbcc30493bbc59b8965087d1be71ad55fbcbaf5a7` (Part 1 and Part 2 incl. Test Plan and coverage table); [implementation-report-TASK-084.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/implementation-report-TASK-084.md) `d656dcdf363d0dc78b5eb096cba6a5aa032803009f7ca7afdb83bdbd8294b112` incl. Owner Closing Addendum (O-084-1). Product files: see Prerequisites |
| Rulings | DAO-013/015/016 ([decisions_made_technical_design.md](x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md) `2167abc4…`), DAO-008 (3)/DAO-009 ([decisions_made_feature_refinement.md](x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md) `282b8703…`), code DAO-004 ([decisions_made_code_implementation.md](x-ipe-docs/dao/26-10-23/decisions_made_code_implementation.md) `7ff59cd3…`) — delegated DAO representative, not the human. Human: B13 = H2, B14 = No ([human_decisions.md](x-ipe-docs/dao/26-10-23/human_decisions.md) `d616db53…`) |
| Target URL | N/A — CLI and agent-skill feature, no UI (no browser test applicable) |
| Config / Capability | `x-ipe-docs/config/tools.json` (`6df39210…`) `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true` (literal) → executable Python CLI runners permitted; Chrome tools enabled but not applicable (no UI) |
| Planned cases / priority | 36 cases: TC-G-01…29 (container, Maintainer paths), TC-G-30…33 (macOS host, never-authorized User + structured), TC-G-34 (frozen drafting suite), TC-G-35 (frozen full suite), TC-G-36 (delivered acceptance runners 001-A/B/C/D/F). P0: 01…12, 19, 24, 25, 29, 30, 33, 35; P1: the rest. Counts are diagnostics, not goals |

## Goal / Subgoal Frame (copied from the specification; outcome not measured)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-08 (K-20, K-21); constraint K-22 | Maintainer | Faster maintenance of examples without unreviewed content (explanations: human-approved deferral, B13 = H2) | Host agent drafts, toolkit validates/binds/labels, Maintainer decides and approves; all example subgoals required | Qualitative scenario executed as delivery checks on fixture drafts; "faster" not measured | No model API/keys/services; no autonomous approval; delivered 001-B/C/D/F unchanged except named plug-in points; stop rule | all active AC-001G-* | not measured |
| G-03.1 | K-20, K-21 | Maintainer, readers | AI text enters formal knowledge only after Maintainer approval of exactly checked bytes and stays labelled | Example blocks + Maintainer-only approval via `update_rule` | TC-G-01…11, 20…23, 25, 27 | Markers tamper-evident for accidental edits only | 01a…01j, 02a…02g, 06a…06h, 08e, 08f | not measured |
| G-03.2 | K-20 | Maintainer, Developer | Approved examples well-formed and confirmed by the Maintainer for the rule and language | Deterministic V1…V13 + structured per-example decisions | TC-G-09, 11…15, 34 | No execution; non-Python syntax not validated | 03a…03k | not measured |
| G-03.3 | K-22; 001-B BR-08 | Owner, Developer | AI text never alters or adds requirements | Construction + advisory lint + recorded attestation; example keys only in Policy | TC-G-02, 04, 16, 17, 26, 29, 32, 34 | Lint heuristic; Maintainer is the final check | 04a…04f, 08c, 08d, 09f | not measured |
| G-03.4 | DAO-001 gate (B5); 6A; OQ-06 | Owner | No new authority, toolkit network, key or third-party surface; internal content only where authorised | Offline toolkit; exact page allowlist; ledger-checked skill procedure; per-project authorization record | TC-G-18, 19, 24, 25, 28, 29, 31…33, 35, 36 | Host-platform transport and model identity unobservable | 05a…05f, 07a…07f, 08a, 08b, 08g | not measured |

Qualitative outcome scenario (spec/design): a Maintainer asks for a Python example for `CWE/Top25-2025/CWE-89`; the agent drafts, the Maintainer sees the masked diff, writes the review, approves; `knowledge show` displays one labelled block, `policy resolve` keeps `requirement` unchanged and lists `python` as an example key. Executed as **delivery** checks (TC-G-01, 04, 29). No stakeholder or real-task observation exists, so every outcome state is **not measured**.

## Full Acceptance / Evidence Map

C = `acceptance/evidence-container-linux.jsonl` (`3bcba75e…`), H = `acceptance/evidence-host-macos.jsonl` (`78f40be0…`), S = frozen `tests/drafting` run (TC-G-34), F = frozen full suite (TC-G-35), R = delivered acceptance runners (TC-G-36). Every row: delivery state **verified (engineering)**, outcome **not measured**.

| AC | Goal | TC / Type | Original assertion (all clauses) | Evidence (actual result) | Status |
| --- | --- | --- | --- | --- | --- |
| 01a | G-03.1 | TC-G-01 integration (CLI) | `valid` + per-check results; preview == mask(diff(unmasked P)); `validation_digest` over P + review; same inputs → same digest; without review `review_incomplete`, preview "not final"; no write | C TC-G-01 (15 checks): status/exit, checks map, preview == stdlib unified diff of the design-rendered payload, digest/preview identical on rerun, `final: false` + null digest + `review_required`, whole tree identical) | Pass |
| 01b | G-03.1 | TC-G-02 integration (CLI) | identity/content/name/source_location/applicability/relations/`examples` text refused `DRAFT_INVALID` naming the field; no write | C TC-G-02: 10 forbidden fields + unknown field + `examples.python` string, each refused on check **and** approve with field named; knowledge/private tree unchanged | Pass |
| 01c | G-03.1 | TC-G-03 integration (CLI) | show/list/links/resolve/scope show/Guard Policy read identical with and without the draft; not listed | C TC-G-03: 8 reader outputs identical (volatile ids/times normalised); not listed as rule/pending | Pass |
| 01d | G-03.1 | TC-G-04 integration (CLI) | exactly one AI block with fixed notice, draft digest, sources, level, decision/attestation codes; no approval time; prior text byte-identical | C TC-G-04: written block == design rendering byte for byte; notice exact; no timestamp in block; strip(new) == old, content.md unchanged | Pass |
| 01e | G-03.1 | TC-G-05 integration (CLI) | lists kind, language, draft digest, sources, state, approval time from the changelog entry (`not_found` if none); read-only; no authorization | C TC-G-05: fields; `approved_at` == time of the entry that added the begin marker; `not_found` for an imported block; identical listing for a never-authorized User; tree identical | Pass |
| 01f | G-03.1 | TC-G-05 | edited body → `modified`; grammar violation → `malformed`; nothing repaired | C TC-G-05: plain `knowledge update` edit → `modified`; removed end marker → `malformed`; tree identical after listing | Pass |
| 01g | G-03.1 | TC-G-04 | one delivered entry `updated` (maintainer, digest line) whose diff contains marker lines | C TC-G-04: +1 entry, heading `— updated (role: maintainer)`, `- item digest:` line, `+# >>>`/`+# <<<` marker lines in the `example-python.md` diff | Pass |
| 01h | G-03.1 | TC-G-04 | missing file created with only the block; existing file appended after existing text | C TC-G-04: CWE-78 `example-python.md` and CWE-89 `example-java.md` created == block only; CWE-89 python appended, prior bytes preserved | Pass |
| 01i | G-03.1 | TC-G-06 integration (CLI); S `test_01i_*` | malformed/nested/duplicated/unterminated/inside non-AI text → `SUPPLEMENT_MARKERS_INVALID` naming file and line; no strip/write | C TC-G-06: all five cases refused on check and approve, file and expected line named, rule files and tree unchanged | Pass |
| 01j | G-03.1 | TC-G-01 | written bytes == P; mask(applied diff) == preview; D == digest(P, R) | C TC-G-01: file bytes == design P; D recomputed with the design formula from the unmasked payload, review/draft digests, base and key id; delivered changelog diff == preview; masked case in TC-G-09 | Pass |
| 02a | G-03.1 | TC-G-07 (container), TC-G-30 (host) | without Maintainer qualification `NOT_AUTHORIZED`; nothing written | C TC-G-07 (trust store moved aside, role user): refused, whole tree identical; H TC-G-30: never-authorized macOS User refused | Pass |
| 02b | G-03.1 | TC-G-08 | draft / review / base / validator version change → `STALE_VALIDATION`, next step check again; base cause: primary `STATE_CONFLICT` + `STALE_VALIDATION` | C TC-G-08: draft change, review byte change and a digest bound to another validator version each refused `STALE_VALIDATION` with "draft-check" next step; base change → primary `STATE_CONFLICT` with `STALE_VALIDATION` in problems; no write. Validator-version cause exercised black-box via the design digest formula (only one interpreter offline); S `test_02b_stale_validation[validator_version]` | Pass |
| 02c | G-03.1 | TC-G-08 | `stale_base` on check; `STATE_CONFLICT` on approve; no write | C TC-G-08 | Pass |
| 02d | G-03.1 | TC-G-09 | findings type/file/line/fingerprint only; preview = deterministic masking `[REDACTED:<fp>]`; approve only with exact `--false-positive`; unmasked value bound and written; value never printed | C TC-G-09: 2 blocking findings (fields ⊆ type/file/line/fingerprint + delivered `blocking`, DEC-I11); preview == masked stdlib diff; deterministic; D over unmasked P; NEEDS_DECISION / ARGUMENT_INVALID (extra fp, other rule) with no write; exact set succeeds; file holds the unmasked value; values absent from 11 outputs (JSON and text) | Pass |
| 02e | G-03.1 | TC-G-10 | files, changelog format, new `state_digest` identical to a plain `knowledge update` of P apart from time | C TC-G-10: twin projects; files and record (minus times) identical; entry identical after time normalisation; digests equal | Pass |
| 02f | G-03.1 | TC-G-11 | python + java, one fails → nothing written, failing language named | C TC-G-11: python `invalid_syntax` → `invalid`, python named, approval refused, no java file; complete draft → both written in one entry | Pass |
| 02g | G-03.1 | TC-G-29 (skill procedure, scripted ledger), TC-G-32 (structured), S `test_02g_*` | shows masked diff, report, lint, statement before approval; approves only after explicit confirmation; never authors review/flags/acks/attestations | C TC-G-29: scripted run, checker finds no violation; CLI supplies all four items; 5 negative ledgers flagged. H TC-G-32: exact SKILL.md section. Live model behaviour **not** verified (DEC-12) | Pass |
| 03a | G-03.2 | TC-G-12 integration; S `test_03a_*` (unit, audit hook) | `syntax_checked`; AST-only, no exec/import/subprocess/side effect | C TC-G-12: example containing `os.system`, `open(..., 'w')`, `subprocess.run`, `exec` → `syntax_checked`; no marker file after check and approve. Instrumented no-exec proof: S (unit) | Pass |
| 03b | G-03.2 | TC-G-12; S `test_03b_*` | syntax error / nesting / size → `invalid_syntax` naming part (+line), no crash; approval refused | C TC-G-12: three cases, part named, line 1 for the syntax error, "nest"/"large" reasons, no Traceback, approval refused | Pass |
| 03c | G-03.2 | TC-G-11 | Java/JavaScript/C `not_syntax_validated`; refused without "unchecked syntax understood"; decision in notice | C TC-G-11: java, javascript, c — level, `EXAMPLE_DECISION_MISSING`, refusal, valid with decision, decision line in notice/preview | Pass |
| 03d | G-03.2 | TC-G-13; S `test_03d_*` | missing/empty part → `example_incomplete` | C TC-G-13: missing safe, empty unsafe, whitespace-only safe | Pass |
| 03e | G-03.2 | TC-G-13; S `test_03e_*` | empty/non-verbatim `demonstrates` → `no_rule_link` (precondition only) | C TC-G-13: both refused; verbatim quote → `quote_present`, no rule-fit claim | Pass |
| 03f | G-03.2 | TC-G-13; S `test_03f_*` | LANG-valid key outside the comment table → `language_unsupported` with list | C TC-G-13: `ruby` refused, supported list printed | Pass |
| 03g | G-03.2 | TC-G-13; S `test_03g_*` | language outside applicability → warning only | C TC-G-13: java on CWE-78 → `language_not_in_applicability`, status `valid` | Pass |
| 03h | G-03.2 | TC-G-11 | per-language result/level/decision; valid only on conjunction | C TC-G-11 | Pass |
| 03i | G-03.2 | TC-G-09 | placeholders → notes only; literal → masked finding; value absent everywhere | C TC-G-09: `<your-password>`, `${DB_PASSWORD}`, `changeme` → non-blocking `note.placeholder`, approval without declaration; literals masked | Pass |
| 03j | G-03.2 | TC-G-14 | missing items named `EXAMPLE_DECISION_MISSING`; approval refused; decision bound into digest and notice | C TC-G-14: each of three items, `false` counts as missing, review-byte change changes D, decisions line in notice | Pass |
| 03k | G-03.2 | TC-G-15; S `test_03k_*` | `example_command` per occurrence for rm -rf, mkfs, dd of=, curl \| sh, Format-Volume, del /s, shutdown; refused unless placeholder or acknowledgement; never claims the pre-check enforced it | C TC-G-15: 7 fixtures one finding each, refusal naming `example_commands_acknowledged`, valid with ack, wording "001-G command validator"; placeholder → no finding; two commands → two findings | Pass |
| 04a | G-03.3 | TC-G-04; S `test_04a_*` (unit, renderer) | stripped(result) == stripped(current) | C TC-G-04: strip(new) == old for appended and created files; content.md identical | Pass |
| 04b | G-03.3 | TC-G-16; S `test_04b_*` (unit, lint) | advisory `normative_language` with positions; never refuses; NFKC, case-insensitive EN terms, whole-token ZH, no single `应`; code tokens not linted | C TC-G-16: expected table matched line by line; every warning has language/part/line/column/term; status `valid` | Pass |
| 04c | G-03.3 | TC-G-16; S `test_04c_*` | verbatim quotation not reported | C TC-G-16 (blockquote comment of a rule line) | Pass |
| 04d | G-03.3 | TC-G-17 | missing attestation → `ATTESTATION_MISSING`, approval refused; present → bound and named in notice | C TC-G-17 | Pass |
| 04e | G-03.3 | TC-G-29, TC-G-32, S `test_04e_*` | agent declines a new company requirement and proposes a custom `@` rule | H TC-G-32 skill step 5 text; C TC-G-29 scripted run (no draft, proposal); S positive/negative ledgers. Live model behaviour not verified | Pass |
| 04f | G-03.3 | TC-G-16; S `test_04f_*` | adversarial table (Must, ＭＵＳＴ, zero-width, 应用/响应 non-hits, code span, quotation + widening prose documented miss) | C TC-G-16: all rows as expected; widening prose yields no warning (documented miss; attestation covers it) | Pass |
| 05a | G-03.4 | TC-G-19 (container), TC-G-31 (host) | the four commands behave as without a socket block; no model/endpoint/key/credential option | C TC-G-19: audit-hook socket block proven active; draft-check, draft-approve, supplements, authorize record (pty) and `--list` succeed; guard loaded in every process, no socket attempt; help options free of model/endpoint/key/token/credential. H TC-G-31 same for User paths | Pass |
| 05b | G-03.4 | TC-G-18, TC-G-24; S `test_05b_*` | exact allowlist (HTTPS, lowercase host, no query/fragment), rule-specific pages match the rule, anything else `source_not_allowed`; any URL on an `@` rule refused | C TC-G-18: 7 allowed / 13 refused URL table (http, upper-case host, query, fragment, other CWE number, other page, other OWASP category, missing slash, other year); C TC-G-24: URL on `@SYNTH` refused | Pass |
| 05c | G-03.4 | TC-G-04 | `not_retrieved` accepted; notice "source page not retrieved; drafted from the stored rule"; no digest | C TC-G-04 | Pass |
| 05d | G-03.4 | TC-G-18; S `test_05d_*` (unit) | `provenance_complete` only with well-formed URL/time/status/body digest/attribution (CWE Terms of Use), else `provenance_incomplete`/`attribution_missing`; licence attestation required; no "verified" wording | C TC-G-18: complete → `provenance_complete`; malformed digest/time/status → `provenance_incomplete`; licence absent / non-CWE licence → `attribution_missing`; empty licence string or null attribution refused earlier by the stricter parse (`DRAFT_INVALID` naming the field, never complete); attestation required; no verified/compliant wording. Validator-level `attribution_missing` for null attribution: S | Pass |
| 05e | G-03.4 | TC-G-29, TC-G-32, S `test_05e_*` | injected instructions (direct/indirect/base64/zero-width/EN-ZH) → ledger shows no unauthorised action, independent of pre-check | C TC-G-29: fixture page with all injection kinds, no violation, injected text in no draft/tool argument; negative ledgers flagged. Live model behaviour not verified | Pass |
| 05f | G-03.4 | TC-G-29, TC-G-32, S `test_05f_*` | only toolkit commands and allowlisted GETs; host-platform transport explicitly excluded | C TC-G-29 ledger allowlist; exclusion stated (Limits) | Pass |
| 06a | G-03.1 | TC-G-08 | second draft `stale_base`; approve `STATE_CONFLICT` | C TC-G-08 | Pass |
| 06b | G-03.1 | TC-G-20 | stale after update, accepted import update, deactivate/reactivate; never auto-applied | C TC-G-20: update, accepted import update (`--accept-update RULE@digest`), deactivate (`rule_inactive`), reactivate (`stale_base`); no block applied | Pass |
| 06c | G-03.1 | TC-G-20 | deactivated → `rule_inactive`, next step reactivate | C TC-G-20 | Pass |
| 06d | G-03.1 | TC-G-20, TC-G-30 | deleted/renamed-away → `RULE_NOT_FOUND`; no transfer | C TC-G-20: delete and rename; new identity byte-identical. H TC-G-30: absent rule | Pass |
| 06e | G-03.1 | TC-G-21 | previous AI python block replaced, not duplicated; non-AI text unchanged | C TC-G-21 (+ preview shows the removal) | Pass |
| 06f | G-03.1 | TC-G-29, TC-G-32, S `test_06f_*` | before accepting a re-import `update_candidate`, the agent lists the AI blocks that would be removed | C TC-G-29: real re-import yields `update_candidate`; `supplements` → present blocks → question, in that order | Pass |
| 06g | G-03.1 | TC-G-22 | adopted scope → `needs_reconfirmation` after approval (unchanged 001-C) | C TC-G-22 | Pass |
| 06h | G-03.1 | TC-G-23 | approval vs exit-confirm serialized by the knowledge lock; timeout `LOCKED`, nothing half-written | C TC-G-23: exit-confirm paused inside the lock (`SECURE_CODE_TEST_PAUSE_AT=exit_locked`), approval `LOCKED` after ≥ 5 s, tree unchanged, exit completes consistent, later approval `RULE_INACTIVE`; 20-run race loop: S | Pass |
| 07a | G-03.4 | TC-G-24 | `@SYNTH` + recorded `fixture-host` authorization → accepted; notice `confidentiality: internal` | C TC-G-24 (disposable container project only) | Pass |
| 07b | G-03.4 | TC-G-24; S `test_07b_*` | `@` default internal; other value `CLASSIFICATION_DOWNGRADE`; declared internal on any rule → gate | C TC-G-24 | Pass |
| 07c | G-03.4 | TC-G-24, TC-G-29, TC-G-32 | no fetch and no rule text outside toolkit commands for `@` rules | C TC-G-29 internal ledger; C TC-G-24 URL source refused | Pass |
| 07d | G-03.4 | TC-G-24, TC-G-29, TC-G-30 | no matching authorization → `INTERNAL_DRAFTING_NOT_AUTHORIZED` on check/approve; skill queries status before reading and stops | C TC-G-24 (before record and after revoke); C TC-G-29: `--list --host` → `not_authorized`, stop, no `knowledge show` | Pass |
| 07e | G-03.4 | TC-G-24 | typed-label record at a terminal; listed read-only; `--revoke`; no init/001-A output change | C TC-G-24: mismatch refused; record fields; `--list` read-only; revoke → `not_authorized`; record under `.x-ipe/private/`, absent from a fresh init, `status` output identical | Pass |
| 07f | G-03.4 | TC-G-24, TC-G-30, TC-G-29, TC-G-32 | no TTY → `INTERACTIVE_REQUIRED`; non-Maintainer → `NOT_AUTHORIZED`; nothing recorded; skill only `--list` | C TC-G-24 and H TC-G-30 (macOS User, disposable project); skill text and ledger | Pass |
| 08a | G-03.4 | TC-G-25, TC-G-33, TC-G-35, TC-G-36 | delivered suites pass unmodified; import/check/update/show/list/links and init outputs byte-identical without drafts; stop rule | C TC-G-25: pre-001-G reconstruction (hash-verified 245 files) vs 001-G: init differs exactly by the 10 payload files (DEC-I3), all other outputs identical after normalising times/ids/paths and two time-bound exit digests (control check proves they are time-bound); H TC-G-33: only the 4 sanctioned delivered files changed, purely additive; F full suite; R delivered runners | Pass |
| 08b | G-03.4 | TC-G-03 | resolve, scope load, links, exit preview, Guard equal with and without the drafts folder | C TC-G-03 | Pass |
| 08c | G-03.3 | TC-G-04 | `requirement` byte-identical; `examples` differs at most by the added key; other fields equal except state digest/time | C TC-G-04 (CWE-89 +java, CWE-78 +python) | Pass |
| 08d | G-03.3 | TC-G-26, TC-G-33; S `test_08d_*` | Guard/Copilot Policy inputs contain no supplement bytes; Guard/Copilot skill texts unchanged | C TC-G-26: guard/copilot open results, their run records, adopted-scope load and `policy resolve` hold the requirement text but no block line/marker/notice; package hashes == pre-001-G baseline. In-process `policy.load_adopted`: S | Pass |
| 08e | G-03.1 | TC-G-10 | item and state digests as the delivered computation of the new files | C TC-G-10 | Pass |
| 08f | G-03.1 | TC-G-27 | `stored_changed` / `not_fully_stored` after one approval | C TC-G-27 | Pass |
| 08g | G-03.4 | TC-G-28 | exit-preview Presets/tags/findings equal apart from digests; Preset/tag files unchanged | C TC-G-28 | Pass |
| 09f | G-03.3 | TC-G-02, TC-G-30 | `explanation` field refused `DRAFT_INVALID` naming it; no write | C TC-G-02 (check and approve); H TC-G-30 | Pass |
| 09a…09e | — | none | Deferred by human decision B13 = H2 (not in v1.0) | not tested, not counted, never reported passed | Deferred |

AC tally: **62 active ACs — 62 Pass, 0 Fail, 0 Blocked, 0 Not run**; 5 deferred rows outside v1.0.

## Prerequisites and Relevant Inputs

- Same task/owner (TASK-103, Sage); implementation TASK-084 done (owner addendum: code review PASS-WITH-FIXES, delta re-review PASS).
- Frozen revision: toolkit commit `93e3eaa` as a `git archive` copy at `<session>/files/fat-001g/frozen/ai-secure-code-toolkit`; the live `ai-secure-code-toolkit/` tree (concurrently edited for FEATURE-002-F) was never read or executed.
- Fixture-only acceptance (DAO-008 (3), DEC-12): no live model output, no real fetch, no real internal content; internal gate only with `@SYNTH/T-1.0/R-01` and `fixture-host` in disposable container projects (B14 = No). `auth init` ran only inside the disposable container HOME; never on the macOS host. `drafting-authorize` record/revoke ran only in disposable projects (container); on the host only refused forms in a disposable project.

| Role | Actual path / boundary | SHA-256 / revision | Dependent ACs / rationale |
| --- | --- | --- | --- |
| specification | `x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/specification.md` v1.3.3 | `4cb3a1eb3e91831c9eabe9a2351ed36f401070193e5676f7009ba53ab0b296a2` | all ACs, original assertions |
| design | `technical-design.md` v1.2 (Parts 1 and 2) | `5e0f2aa8e582e25374491dccbcc30493bbc59b8965087d1be71ad55fbcbaf5a7` | render template, marker grammar, digest formula, allowlist, CLI contract, exact skill section |
| implementation report | `implementation-report-TASK-084.md` | `d656dcdf363d0dc78b5eb096cba6a5aa032803009f7ca7afdb83bdbd8294b112` | O-084-1, DEC-I1…I16 rulings |
| code (frozen, prefix) | `FW/scripts/src/x_ipe_secure_code/knowledge/drafting_{auth 501958aa, blocks f8169366, checks 84f4b14a, lint eb370ab0, mask 583f61c7, model 3ee34843, pipeline c9f47950, service e4a52afa, supplements 6899e7b7}.py`; `cli.py 3ed4990e` | frozen file-list hash `44837bb0…` | all executable ACs |
| skill text (frozen) | `FW/SKILL.md 3fc74164`, `references/knowledge-drafting.md 5d3f87d2`, `references/cli-contract.md eda7bd62`, `references/knowledge-batch.md 6af9e080` (unchanged) | idem | 02g, 04e, 05e, 05f, 06f, 07c, 07d, 07f, FR-001G-7/8 |
| pre-001-G baseline | `<session>/files/impl-084/baseline-step0.sha256` (245 files) + `cli.py.step0`, `SKILL.md.step0`, `cli-contract.md.step0`, `carhelp.py.step0` | list `5e268b99240d11411ed91d29a77262b002808e2aea0dbb7f0b0001f88ad1edcc`; originals equal their baseline entries | 08a, 08d (reconstruction verified by `sha256sum -c`, all 245 entries) |
| config | `x-ipe-docs/config/tools.json` | `6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d` | runner enablement |
| rulings | DAO technical design / refinement / code implementation / human decisions | `2167abc4…` / `282b8703…` / `7ff59cd3…` / `d616db53…` | B13/B14, DEC-12, DEC-I3/I11/I1 evaluations |
| environment (container) | `fat-uv-git:py312` (Python 3.12.12, uv 0.9.30, Linux arm64), `--network none`, `UV_OFFLINE=1`, read-only mounts, disposable HOME; uv cache volume `fat-uv-cache-001g-fat` = fresh copy of `fat-uv-cache-003b` (seed mounted read-only, not mutated) | installed packages verified equal to the copied sources (`prepare.sh`, stderr) | TC-G-01…29 |
| environment (host) | macOS, Python 3.13.3, uv 0.11.23; never-authorized User (`auth status` → `user`, no trust store) | — | TC-G-30…36 |

## Environment and Method

- **Black-box runner** [acceptance/blackbox.py](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/acceptance/blackbox.py) calls the real CLI as a subprocess (`uvx --from <frozen>/x-ipe-secure-code-toolkit-framework/scripts secure-code …`) in fresh `init`-ed projects; it never imports toolkit code. Expected values come from the specification and design (independent re-implementation of the FR-001G-5 block rendering, the design's strip rule, the `validation_digest` composition and stdlib `difflib` unified diffs), never from product code. JSONL per case (`tc`, `acs`, `checks`, `failed`).
- **Container** ([run.sh](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/acceptance/run.sh) `fat`, [prepare.sh](x-ipe-docs/requirements/EPIC-001/FEATURE-001-G/acceptance/prepare.sh)): copies the read-only frozen tree to `/root/toolkit` and reconstructs the pre-001-G revision at `/root/pre001g` (frozen minus the 10 payload files and `tests/drafting`, with the four step-0 originals restored; `sha256sum -c` of all 245 baseline entries OK, 245 files). Owner authorization via `auth init` at a pseudo-terminal in the disposable HOME.
- **Host**: never-authorized User paths, network guard, skill/reference/contract text and delivered-file parity. Temp/projects under `<session>/files/fat-001g/` (TMPDIR there).
- **Agent and Maintainer roles** are played by the runner (draft files; review files, confirmations, false-positive declarations). Skill-procedure ACs use a scripted agent with an instrumented ledger checked by the runner's own policy checker (and five negative ledgers that the checker must flag). This proves the instructions are executable with the real CLI and the checker's discrimination, **not** a live model's behaviour; no live host-session ledger was captured (none reported).
- **Network guard (05a)**: a `sitecustomize` audit hook raising on `socket.__new__/connect/bind/getaddrinfo/…`, loaded through `PYTHONPATH` in every CLI process (load and attempt log checked; a probe shows socket creation fails).
- **Test-only hooks**: `SECURE_CODE_TEST_PAUSE_AT=exit_locked=<path>` on the one exit-confirm subprocess of TC-G-23.
- **Frozen suite runs** (diagnostic + typed evidence): `PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=<session>/… [-rs]` from the frozen `FW/scripts`; `uv run --offline ruff check --no-cache src tests`. `uv run` created `FW/scripts/.venv` inside the frozen copy (excluded from the file-list hash by the prescribed method).
- **Regressions**: the delivered features' own acceptance runners (001-A, 001-B, 001-C, 001-D, 001-F) in host mode with `TOOLKIT_ROOT=<frozen>` (they support a source path); container modes were not run — the Maintainer-path regression is carried by the frozen full suite (TC-G-35) and TC-G-25.

## Typed Test Cases

Status values are from the final runs. "Checks" = assertion count in the JSONL record (diagnostic).

### Integration (CLI subprocess + filesystem) — container, Maintainer paths (`evidence-container-linux.jsonl`)

| TC | ACs | Prio | Preconditions / data | Steps → expected (all original clauses) | Checks | Status |
| --- | --- | --- | --- | --- | --- | --- |
| TC-G-01 | 01a, 01j | P0 | fixture batch (CWE-89 with seed python example, CWE-78, A03); python draft from `stored_rule_content` | check without review → `review_incomplete`, `final: false`, null digest, `review_required`, tree identical; with review → `valid`, checks map, preview == unified diff of design-rendered P, rerun identical, D == design digest; approve → bytes == P, only example/record/changelog changed, changelog diff == preview | 15 | Pass |
| TC-G-02 | 01b, 09f | P0 | drafts carrying each forbidden field / `examples` string / unknown key / `explanation` | check and approve each → `DRAFT_INVALID` naming field; knowledge/private tree unchanged | 13 | Pass |
| TC-G-03 | 01c, 08b | P0 | scope adopting CWE-89/78; drafts + review present, then folder moved aside | show, list, links, resolve, scope show, exit-preview, guard open, copilot open equal (normalised) with drafts, without drafts, and vs. before; drafts not listed | 4 | Pass |
| TC-G-04 | 01d, 01g, 01h, 04a, 05c, 08c | P0 | python draft with `not_retrieved` source; CWE-78 python (file absent); CWE-89 java (file absent) | block == design rendering; notice exact; no timestamp; strip == old; `not_retrieved` notice line, no digest; one `updated` entry with marker diff; created files == block; resolve field-wise comparison | 13 | Pass |
| TC-G-05 | 01e, 01f | P1 | two approvals; trust store moved aside for User listing; plain update edit; update removing an end marker; imported block | fields, `approved_at` == entry time, `not_found`; User listing identical; `modified`, `malformed`; read-only | 9 | Pass |
| TC-G-06 | 01i | P0 | markers set via delivered `knowledge update` (5 projects) | check + approve → `SUPPLEMENT_MARKERS_INVALID` with file and line; files and tree unchanged | 5 | Pass |
| TC-G-07 | 02a | P0 | valid digest; trust store moved aside | approve → `NOT_AUTHORIZED`; whole tree identical | 3 | Pass |
| TC-G-08 | 02b, 02c, 06a | P0 | valid digest D | draft change / review change / other validator version → `STALE_VALIDATION` + check-again step; base change → `stale_base`, primary `STATE_CONFLICT` + `STALE_VALIDATION`; two drafts same base → second `stale_base` / `STATE_CONFLICT`; no writes | 10 | Pass |
| TC-G-09 | 02d, 03i | P0 | unsafe part with password literal and AWS-format key; placeholder draft | findings fields; masked preview == masked stdlib diff; deterministic; D over unmasked P; NEEDS_DECISION / ARGUMENT_INVALID ×2 without write; exact declaration succeeds; unmasked bytes written; changelog lists fps; mask(applied diff) == preview; values absent from all outputs; placeholders → notes only | 14 | Pass |
| TC-G-10 | 02e, 08e | P1 | twin projects, same rule state | approval vs plain `knowledge update` of the written P: files, record (minus times), entry (time-normalised), item/state digests equal | 5 | Pass |
| TC-G-11 | 02f, 03h, 03c | P0 | python+java; invalid python; javascript; c | per-language results; conjunction; refusal naming java item; all-or-nothing with python syntax error; both written in one entry; java/js/c `not_syntax_validated` + decision in notice | 10 | Pass |
| TC-G-12 | 03a, 03b | P0 | side-effect code (os.system, open w, subprocess, exec) with marker paths; syntax error, 150-deep nesting, 240 kB part | `syntax_checked`, no marker created through check and approval; three `invalid_syntax` cases naming part (line 1), no Traceback, approval refused | 6 | Pass |
| TC-G-13 | 03d, 03e, 03f, 03g | P1 | incomplete parts, empty / non-verbatim `demonstrates`, `ruby`, java on CWE-78 | `example_incomplete` ×3; `no_rule_link` ×2; `quote_present` without rule-fit claim; `language_unsupported` + list; applicability warning with `valid` | 8 | Pass |
| TC-G-14 | 03j | P1 | reviews missing each item / `false` | `EXAMPLE_DECISION_MISSING` naming `examples.python.<item>`, no digest, approval refused; digest changes with review bytes; decisions in notice | 6 | Pass |
| TC-G-15 | 03k | P1 | seven command fixtures, placeholder, two commands | one `example_command` each; refusal without ack; valid with ack; wording; placeholder no finding; two findings | 9 | Pass |
| TC-G-16 | 04b, 04c, 04f | P1 | 14-row lint table (authored from the ACs) + code token | warnings == table; fields; `valid`; quotation and widening prose not reported | 6 | Pass |
| TC-G-17 | 04d | P1 | review without / with `non_normative` | `ATTESTATION_MISSING`, refusal; valid with notice line | 3 | Pass |
| TC-G-18 | 05b, 05d | P0 | 20-URL allowlist table on CWE-89/A03; fetched provenance variants | allowlist exact; `provenance_complete`; incomplete/attribution variants; licence attestation; strict-parse refusals; no verified wording | 11 | Pass |
| TC-G-19 | 05a | P0 | socket audit hook via `PYTHONPATH` | probe blocked; four commands (record at pty) succeed; hook loaded everywhere, no attempt; no model/key options | 8 | Pass |
| TC-G-20 | 06b, 06c, 06d | P1 | update, accepted import update, deactivate/reactivate, delete, rename | `stale_base` and never applied; `rule_inactive` + reactivate step; `RULE_NOT_FOUND`; new identity untouched | 6 | Pass |
| TC-G-21 | 06e | P1 | two python approvals | one block (second draft), non-AI unchanged, preview shows removal | 4 | Pass |
| TC-G-22 | 06g | P1 | scope adopting CWE-89/78 | CWE-89 `needs_reconfirmation`, CWE-78 `adopted` | 3 | Pass |
| TC-G-23 | 06h | P1 | exit-confirm paused inside the knowledge lock | approval `LOCKED` ≥ 5 s, no write; exit completes; later `RULE_INACTIVE` | 5 | Pass |
| TC-G-24 | 07a, 07b, 07d, 07e, 07f, 05b | P0 | `@SYNTH` + `fixture-host` in a disposable project | gate refusals; downgrade; CWE internal gated; no-TTY / User / mismatch refused with nothing recorded; record, list (read-only), status unchanged, not in init layout; approval with `confidentiality: internal`; URL on `@` refused; revoke → refused again | 17 | Pass |
| TC-G-25 | 08a | P0 | hash-verified pre-001-G reconstruction | init differs by exactly the 10 payload files; other outputs identical (normalised; time-bound exit digests proven by control) | 4 | Pass |
| TC-G-26 | 08d | P1 | approval with a unique marker line; scope after approval | no block bytes in guard/copilot results, records, scope load, resolve; requirement present; Guard/Copilot package hashes == baseline | 4 | Pass |
| TC-G-27 | 08f | P1 | batch with `source_document_digest` | before `stored_unchanged`/`fully_stored`; after `stored_changed` (CWE-89), `stored_unchanged` (CWE-78), `not_fully_stored` | 3 | Pass |
| TC-G-28 | 08g | P1 | Preset `web-input` (CWE-89, CWE-78), tag `injection` | exit-preview impact equal apart from digests; files byte-identical | 3 | Pass |

### Integration (skill procedure, scripted ledger fixture) — container

| TC | ACs | Prio | Steps → expected | Checks | Status |
| --- | --- | --- | --- | --- | --- |
| TC-G-29 | 02g, 04e, 05e, 05f, 06f, 07c, 07d, 07f | P0 | Scripted agent per the Framework skill: `auth status` → `knowledge show` → GET of the allowlisted CWE-89 page (fixture body with direct/indirect/base64/zero-width/EN-ZH injections, no real fetch) → write draft → `draft-check` → present masked diff/report/lint/statement → Maintainer writes review → `draft-check --review` → present → Maintainer confirms → `draft-approve`; checker: no violation, approval ok, injected text absent from draft and tool arguments; 5 negative ledgers (approve before present, agent-written review, non-allowlisted fetch, agent false positive, record-form authorize) flagged. Internal `@SYNTH`: `drafting-authorize --list --host fixture-host` → real `not_authorized` → stop (no show/fetch; only `--list`); internal-read-first negative flagged. Re-import of the original item → real `update_candidate`; `supplements` → present blocks → question. 04e: scripted decline + custom-rule proposal, no draft | 15 | Pass |

### Integration (CLI) — macOS host, never-authorized User (`evidence-host-macos.jsonl`)

| TC | ACs | Prio | Steps → expected | Checks | Status |
| --- | --- | --- | --- | --- | --- |
| TC-G-30 | 02a, 07f, 09f, 06d | P0 | role `user`; `supplements` and `authorize --list` on a fresh project write nothing (NFR-3); `explanation` draft → `DRAFT_INVALID` naming it; absent rule → `RULE_NOT_FOUND`; approve → `NOT_AUTHORIZED`, only the two draft/review files exist; authorize without TTY → `INTERACTIVE_REQUIRED`; User at a pty in the disposable project → `NOT_AUTHORIZED`; nothing recorded | 7 | Pass |
| TC-G-31 | 05a | P1 | socket audit hook; User-path `supplements` and `authorize --list` succeed; no socket attempt; help options free of model/endpoint/key/token/credential | 5 | Pass |

### Structured review — macOS host

| TC | ACs | Prio | Review scope → expected | Checks | Status |
| --- | --- | --- | --- | --- | --- |
| TC-G-32 | 02g, 04e, 05e, 05f, 06f, 07c, 07d, 07f (+ FR-001G-7/8) | P1 | Frozen `SKILL.md` contains the design's exact `## Drafting Examples (AI-assisted)` section (extracted from the design file) immediately before `## Selecting Policies`; "Do not fetch URLs" unchanged; per-AC instruction sentences present; `knowledge-drafting.md` has the ten designed sections in order, all 38 allowlisted URLs and the honest-limit sentences; `cli-contract.md` has the four rows, the drafting code paragraph and the new section | 13 | Pass |
| TC-G-33 | 08a, 08d | P0 | Frozen tree vs step-0 baseline (245 entries): changed = exactly `cli.py`, `SKILL.md`, `cli-contract.md` and `tests/carriers/carhelp.py` (DAO-004 DEC-I1 append); every change purely additive (no removed/edited line; step-0 originals hash-equal to the baseline); none removed; added = 10 payload files + `tests/drafting`; Guard/Copilot packages unchanged | 5 | Pass |

### Unit (validator / renderer / lint / mask) and skill-ledger tests — frozen `tests/drafting` (TC-G-34)

| TC | ACs | Prio | Command → result | Status |
| --- | --- | --- | --- | --- |
| TC-G-34 | unit-typed 03a, 03b, 03d, 03e, 03f, 03g, 03k, 04a, 04b, 04c, 04f, 05b, 05d, 07b; ledger 02g, 04e, 05e, 05f, 06f, 07c, 07d, 07f; plus every other mapped test in the design coverage table | P1 | `pytest tests/drafting` on the frozen copy (host, Python 3.13.3): **269 passed** in 36.2 s (model 45, blocks 23, mask 7, lint 21, checks 41, cli_check 33, cli_approve 25, internal 9, lifecycle 11, staging 12, supplements 6, network 2, regression 7, skill 24, b14_guard 3); `ruff check --no-cache src tests`: All checks passed. Log `<session>/files/fat-001g/log-drafting-suite.txt` (`b6b59744…`). Fresh execution of the implementation's tests at the frozen revision — the assertions are implementer-authored, so they are corroborating unit-level evidence next to the independent black-box cases | Pass |

### Regression

| TC | ACs | Prio | Command → result | Status |
| --- | --- | --- | --- | --- |
| TC-G-35 | 08a (delivered suites pass without modification) | P0 | Full frozen suite, run 1 (`log-full-suite.txt` `e8b747c2…`): 2883 passed, **1 failed**, 5 skipped, 23 deselected (710 s). The failure, `tests/carriers/test_sandbox_isolation.py::test_07a_dev_repo_carriers_unchanged`, asserts that the *development repository* around the toolkit has `.github/copilot-instructions.md`; the frozen archive sits outside the repository. Diagnostic rerun of that file with the repository's own `.github/copilot-instructions.md` copied beside the frozen tree (layout reproduced, removed afterwards): 28 passed (`log-diag-sandbox-isolation.txt` `43daaad9…`). Full run 2 with that layout: **2884 passed, 0 failed, 5 skipped, 23 deselected** (713 s; `log-full-suite-2.txt` `a2951787…`). Skips: two non-UTF-8 file-name platform skips, one 001-D design skip, one conditional on FEATURE-001-E, and one FEATURE-002 Trivy unit test that needs the repository's `x-ipe-docs` beside the toolkit (environmental, the frozen archive has none); 2884 + 5 = 2889 = the implementation report's 2885 + 4 (one test moves from passed to skipped for that layout reason) | Pass |
| TC-G-36 | 08a (delivered behaviour, black-box) | P1 | Delivered acceptance runners in host mode against the frozen copy: 001-A 12/12 cases, 001-B 1/1, 001-C 1/1, 001-D 2/2, 001-F 2/2 (28/28 checks), stderr empty (`acceptance/regression-001{A,B,C,D,F}-host-macos.jsonl`) | Pass |

## Test Execution Summary

| Test case(s) | ACs | Type | Status | Evidence |
| --- | --- | --- | --- | --- |
| TC-G-01…28 | 01a…01j, 02a…02f, 03a…03k, 04a…04d, 04f, 05a…05d, 06a…06e, 06g, 06h, 07a, 07b, 07d…07f, 08a…08g, 09f | integration (CLI, container) | 28 Pass | `evidence-container-linux.jsonl` (29/29 cases, 222/222 checks), stderr = preparation log only |
| TC-G-29 | 02g, 04e, 05e, 05f, 06f, 07c, 07d, 07f | integration (skill procedure, scripted ledger) | Pass | idem |
| TC-G-30, 31 | 02a, 05a, 06d, 07f, 09f | integration (CLI, host) | 2 Pass | `evidence-host-macos.jsonl` (4/4 cases, 30/30 checks), stderr empty |
| TC-G-32, 33 | 02g, 04e, 05e, 05f, 06f, 07c, 07d, 07f, 08a, 08d | structured-review | 2 Pass | idem |
| TC-G-34 | unit-typed and ledger ACs (see table) | unit | Pass | `log-drafting-suite.txt` 269 passed, ruff clean |
| TC-G-35 | 08a | integration (regression, full suite) | Pass | `log-full-suite.txt`, `log-diag-sandbox-isolation.txt`, `log-full-suite-2.txt` |
| TC-G-36 | 08a | integration (regression, delivered runners) | Pass | `regression-001{A,B,C,D,F}-host-macos.jsonl` |

## Execution Results

**Execution:** 2026-10-24 07:23–08:16 (UTC+8), acceptance worker for owner Sage; final container/host runs 08:00–08:03, regressions 07:56–07:58.
**Environment:** see Prerequisites (container Linux arm64 Python 3.12.12; macOS host Python 3.13.3).

| Type | Total planned | Passed | Failed | Blocked | Partial / Not run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 (no UI) | — | — | — | — |
| backend-api | 0 (no API) | — | — | — | — |
| unit | 1 | 1 | 0 | 0 | 0 |
| integration | 33 (28 CLI container + 1 skill procedure + 2 CLI host + 2 regression) | 33 | 0 | 0 | 0 |
| structured-review | 2 | 2 | 0 | 0 | 0 |
| **TOTAL** | **36** | **36** | **0** | **0** | **0** |

Pass rate = 36 / 36 planned = **100 %** (one denominator: all planned cases). AC tally: 62 / 62 active ACs Pass. Counts are diagnostics, not goal achievement or stakeholder impact.

### Failures / Blockers / Disclosures

| Item | Expected versus actual | Evidence | Disposition |
| --- | --- | --- | --- |
| First full container run, TC-G-25 (08a) | Runner compared `exit-preview` outputs of two projects created in different seconds without normalising `rule_state.fingerprint` / `impact_digest`, which hash record timestamps in delivered behaviour → Fail (28/29). A control with the same 001-G CLI (two projects 1.2 s apart: equal `state_digest`, different fingerprint/impact digest) proved the cause is the runner, not 001-G | `acceptance/evidence-container-linux-run1.jsonl` (`e280bb01…`, produced by an earlier runner revision), control now inside TC-G-25 | Runner fixed (placeholders for the two time-bound digests + control check); complete container and host runs repeated: 29/29 and 4/4 |
| Debug-phase runner corrections (scratch runs, not evidence) | Test-authoring errors corrected before the evidence runs, never by relaxing an AC: an "extra fingerprint" case first declared only the extra one (delivered order reports `NEEDS_DECISION` first; design R4 "extra" = listed + extra); a lint fixture contained the EN term "only"; an A03 fixture example was not valid Python; scope adoption parsing; `--accept-update` needs `RULE@<stored digest>`; reference headings inside a code fence; 08d haystack extended to the adopted-scope load (Guard/Copilot records hold no Policy text) | `<session>/files/fat-001g/scratch/` | Corrected; each corrected case derives its expectation from the spec/design |
| TC-G-35 run 1 | 1 environment failure (development-repository layout precondition of a FEATURE-003-B carriers test) | see TC-G-35 | Layout reproduced; see run 2 |
| AC-001G-05d at the CLI | Null attribution and empty licence string are refused by the stricter draft parse (`DRAFT_INVALID` naming the field) before the validator could report `attribution_missing`; licence absent / wrong licence report `attribution_missing` | TC-G-18 | Not a failure: completeness is never claimed; the validator result for null attribution is covered by TC-G-34 (`test_05d_*`). Owner may note the precedence in the reference |

No product defect was found. No product code, delivered test, `.github/skills`, board, Git or memory file was changed.

### O-084-1 assessment (`draft-check` echoes a refused provenance URL unmasked when the scan did not run)

Reproduced in the container run (record `{"obs": "O-084-1", …}` in `evidence-container-linux.jsonl`): a `not_retrieved` source URL carrying an AWS-format key in its query string (`…/89.html?token=AKIA…`, refused `source_not_allowed`):

- (a) python-only draft → payload built, `checks.precheck = findings`, value **redacted** in every output;
- (b) the same plus an unsupported language (`ruby`) → status `invalid`, `checks.precheck = not_run`, the value is **printed unmasked** in `data.provenance[].url`.

Verdict against AC-001G-02d / FR-001G-10: **Pass**. AC-001G-02d's precondition is "a draft whose rendered result has a pre-check credential finding", and FR-001G-10/BR-14 cover pre-check-*matched* spans; in (b) no rendered result exists and no pre-check match happened, while in every case where the pre-check ran (TC-G-09, case a) matched values are masked in all outputs. The observation is real but outside the AC's letter: a residual **Low** gap — an agent-written, already-refused URL is echoed back to the same local session when the payload cannot be built. Recommendation for the owner (no change made by acceptance): keep O-084-1 as an improvement candidate (scan source fields even when no payload is built, or omit refused URLs from the output).

### Regressions (design 08a…08g)

- Delivered acceptance runners (host mode, frozen copy): 001-A 12/12, 001-B 1/1, 001-C 1/1, 001-D 2/2, 001-F 2/2 cases Pass (TC-G-36).
- Frozen full suite: TC-G-35 (run 2: 2884 passed, 0 failed, 5 skipped; run 1: one layout-precondition failure, see TC-G-35). Delivered test files: only `tests/carriers/carhelp.py` differs from step 0 (DAO-004 DEC-I1 `ERA_001A_REMOVED` append, purely additive); the 001-A/B/C/D/F test files are unchanged (TC-G-33).
- 08b…08g black-box: TC-G-03, 04, 10, 26, 27, 28 Pass.

### Engineering Delivery versus Stakeholder Outcome

| Goal | Delivery evidence / state | Outcome scenario / observation | Outcome state |
| --- | --- | --- | --- |
| G-03.1 | All 01*, 02*, 06*, 08e, 08f ACs Pass (TC-G-01…11, 20…23, 25, 27) | Approval of exactly checked bytes executed on fixtures | not measured |
| G-03.2 | 03a…03k Pass (TC-G-09, 11…15, 34) | — | not measured |
| G-03.3 | 04a…04f, 08c, 08d, 09f Pass | `requirement` unchanged and example key only, on fixtures | not measured |
| G-03.4 | 05a…05f, 07a…07f, 08a, 08b, 08g Pass; skill-procedure ACs by scripted ledgers only | No live session observed | not measured |
| G-03 | **Engineering delivery: verified** for all 62 active ACs at the frozen revision | "Faster maintenance" not observed | **Stakeholder outcome: not measured** |

### Refactor / Closing Recommendation and App Gates

Refactor need: none evidenced by acceptance (no failing assertion, ruff clean, module sizes covered by the passing suite). O-084-1 is an optional improvement candidate, not a refactor prerequisite. Original conditional successors retained for the owner: `x-ipe-task-based-code-refactor` (refactor for quality) / `x-ipe-task-based-feature-closing` (close if no refactoring needed). Free mode: no app/board mutation by this worker; the owner alone decides routing and persists task/feature status.

### Honest Limits

- Fixture-only acceptance (DAO-008 (3), DEC-12): no live model output, no real page fetch, no real internal content. Skill-procedure ACs (02g, 04e, 05e, 05f, 06f, 07c, 07d skill part, 07f skill part) are evidenced by skill text, a scripted-agent ledger with the real CLI and the frozen ledger tests; **live model behaviour is not verified**; no live host-session ledger was captured. Host-platform transport is outside what the feature can observe and is excluded (05f).
- B14 = No respected: authorizations were recorded only in disposable container projects with `fixture-host`; no authorization for any real host label exists or was created.
- Validator-version staleness (02b) was exercised black-box by a digest computed with the design formula for another interpreter version (only one interpreter offline); the real cross-version case is covered by the frozen test. AST-only/no-exec (03a) is observed black-box through absence of side effects; the instrumented proof is the frozen unit test. The 06h 20-run race loop and the in-process `policy.load_adopted` (08d) are covered only by the frozen tests.
- AC-001G-08a "byte-identical init" is evaluated modulo exactly the 10 new payload files (DAO-004 DEC-I3); two exit-preview digests are compared as time-bound placeholders (control in TC-G-25).
- Platforms: Linux container and macOS host; Windows not run.
- TC-G-34 executes implementer-authored tests (corroborating evidence); the independent evidence is the black-box runner.
- Regression runners were executed in host mode only (container modes not run); Maintainer-path regression relies on the frozen full suite and TC-G-25.
- "Faster maintenance" (G-03) is not measured.

## Revision Binding and Files

- Frozen tree file-list hash (prescribed method): start `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68`, end `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68` (identical per-file list) (291 files; `.venv`/caches excluded by the method).
- Inputs re-hashed at the end: specification `4cb3a1eb…`, design `5e0f2aa8…`, implementation report `d656dcdf…`, tools.json `6df39210…` — unchanged.

| File | SHA-256 |
| --- | --- |
| `acceptance/blackbox.py` | `8704fb70c245685d3eed8c87ae88e2923711667a4e1571983d7943474df5aaf1` |
| `acceptance/evidence-container-linux-run1.jsonl` | `e280bb0121910ceebb10963c298b59020d57d1a0ba5eb75b312cec27745f37f2` |
| `acceptance/evidence-container-linux-run1.stderr` | `2c7c85b94a27c33c618e663f7c0c4629eb158c65c5fdf84f765b71c1e7d3b3c3` |
| `acceptance/evidence-container-linux.jsonl` | `3bcba75ee3eccef6d6ef97ea5c871a5ceeb26c00b9c381a5078bf2268ed6083a` |
| `acceptance/evidence-container-linux.stderr` | `2c7c85b94a27c33c618e663f7c0c4629eb158c65c5fdf84f765b71c1e7d3b3c3` |
| `acceptance/evidence-host-macos.jsonl` | `78f40be0ed317a7bb23bafe2c9eb352fbe3a62c93683165c11fc7058e2b8b913` |
| `acceptance/evidence-host-macos.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `acceptance/prepare.sh` | `5317e47f7762460433f5cdfe4ce2ac75280b538ff0887ab910c1ee7e7214ef41` |
| `acceptance/regression-001A-host-macos.jsonl` | `d33b21d25d6f4d9362f2963f1cff79a220521f4f3d71de1374d9dd594491d2a8` |
| `acceptance/regression-001A-host-macos.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `acceptance/regression-001B-host-macos.jsonl` | `259f5fb9e1baaae628405acf10000c67b28b68cb3277c56d9ced4d9fa180b26a` |
| `acceptance/regression-001B-host-macos.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `acceptance/regression-001C-host-macos.jsonl` | `3ef8a509d7c55571b6246069b90bc4a14f97d4da2427f261084dba169d520cf3` |
| `acceptance/regression-001C-host-macos.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `acceptance/regression-001D-host-macos.jsonl` | `1c1171cddb30a35184930f72c6bbd6c890ef06fb005a83371b7bc7be918c07e5` |
| `acceptance/regression-001D-host-macos.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `acceptance/regression-001F-host-macos.jsonl` | `5c5c13506b43f1ecf20e312de75f091d4f2ad72d11e814c67241ca8a52784835` |
| `acceptance/regression-001F-host-macos.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `acceptance/run.sh` | `e8896c8f481e09495f32dcb593c8ac06e1fdc1cf6c3c2978df0d859da07d3c93` |
| this report (`acceptance-test-cases.md`) | reported in the owner handoff (a file cannot contain its own hash) |
