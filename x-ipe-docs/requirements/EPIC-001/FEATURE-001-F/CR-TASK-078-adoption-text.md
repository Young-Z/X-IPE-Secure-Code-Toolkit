# Change Request: CR-TASK-078

> Created: 2026-10-23
> Status: Applied (documents only — specification v1.6 and technical design v1.4 deltas; product code/tests not changed in this step)
> Classification: modification
> Related Feature: FEATURE-001-F (Presets & Tags)

## Request Details

- **Requestor / approver:** the human (CR4 = "yes" in `x-ipe-docs/dao/26-10-23/human_decisions.md`, row CR4: "Change Request: `preset resolve` `adoption` text names `preset scope-save`"). This is the human's own decision, not DAO guidance.
- **Source:** FEATURE-001-F acceptance observation O-2 (`acceptance/acceptance-test-report.md` L171, L188), closing report "Residual Risk O-2" (`closing-report.md` L112–118, L172), DAO-002 (feature acceptance: "O-2 recorded as optional human CR/polish candidate, not a defect").
- **Task:** TASK-078, Change Request, lifecycle owner Sage, free mode, interaction mode `dao-represent-human-to-interact`. No board, Git, memory or `.github/skills` writes; no product code edits in this step.
- **Priority:** medium (supplied none).
- **Owning folder:** `x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/`.

## Description

**Present behaviour.** `secure-code preset resolve NAME` and `preset resolve --default` (with a usable default Preset) build the proposal with the delivered 001-C `resolve.build` (`policy/resolve.py` L353–354), so the `adoption` field reads
`nothing adopted yet — the user must confirm, then: secure-code scope save --confirmed`,
while the same output's `next_steps` (`policy/preset_scope.py` `_steps`, L72–82) and the Framework skill (`SKILL.md` L137–139, `references/presets-and-tags.md` L105–113, `references/policy-selection.md` L20–23) direct `secure-code preset scope-save NAME --decisions FILE --confirmed`.

**Requested change.** In `preset resolve` output only, the `adoption` text names the Preset save command:
`nothing adopted yet — the user must confirm, then: secure-code preset scope-save NAME --decisions FILE --confirmed` (NAME = the resolved Preset's name; `default` for `--default`).

**Explicitly unchanged.** Plain `secure-code policy resolve` output (001-C) stays byte-identical, including its `adoption` text; the `adoption` key, its position and the "nothing adopted yet" prefix stay; `proposal_digest`, entries, notices, `next_steps`, scope records and scope identifiers are unchanged; the no-default-Preset answer (`"adoption": "nothing proposed — no default Preset"`) is unchanged.

## Business Justification

- **Why:** an agent that follows the `adoption` field literally runs an ordinary 001-C `scope save`, which does not re-read the Preset under the knowledge lock (DAO-006 (1), AC-001F-04i) — the Preset-path guarantee of FR-001F-5/AC-001F-04j is bypassed. The adopted references remain exactly those confirmed and the 001-C digest check still applies (closing report "Effect"), so this is a guidance/consistency fix, not a security defect.
- **Alternatives considered:** (a) skill-only warning "ignore `adoption`" — leaves contradictory toolkit output; (b) change `resolve.build` — would change plain `policy resolve` output and break AC-001F-09a fixtures/BR-11; (c) **selected:** override the value in the 001-F `preset_scope._proposal` only.
- **Not changing:** contradictory instructions in one output persist (O-2 residual risk).
- **Compliance/standards:** N/A (no external standard involved).

## Goal / Subgoal Delta

| Goal / Subgoal | Parent / Source | Stakeholder | Before Outcome | Proposed Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | Story / AC Links | Delta Kind | Authority |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| US-02 (pick a Preset as scope input; confirm a known list while still seeing missing/changed rules) | EPIC-001 P-11, FR-001F-5; G-03 coverage unchanged | Developer / upstream agent | `preset resolve` output names two different save commands (`adoption`: `scope save`; `next_steps`: `preset scope-save`) | Every save instruction in `preset resolve` output names `preset scope-save NAME`, so the Preset save path (re-read under lock, AC-001F-04j) is the one followed | Means correction within the existing outcome; selected means (c) above | Planned automated check AC-001F-04l (Integration); no stakeholder outcome observed — not measured | 001-C output/contracts unchanged (BR-11, AC-001F-09a/09d); no new key/field/mode; no skill rewording required | US-02 → AC-001F-04a (unchanged), new AC-001F-04l, BR-18 | changed means / new AC (additive) | Human CR4 = yes |

## Impact Analysis

### Classification

**modification** of FEATURE-001-F. The stakeholder outcome (US-02) and boundaries are unchanged; the change corrects one output value of a 001-F command (`preset resolve`) so it agrees with that command's own `next_steps` and skill. No new user, workflow, data or interface boundary.

### Comparison Matrix

| Aspect | CR Requirement | Existing Feature(s) | Evidence / Boundary Decision |
| --- | --- | --- | --- |
| Users | Developer / upstream agent using a Preset | Same (US-02) | spec v1.5 L42; unchanged |
| Workflow | resolve Preset → confirm → `preset scope-save` | Same; `adoption` text alone pointed to `scope save` | `preset_scope.py` L72–82 vs `resolve.py` L354; flow unchanged, guidance aligned |
| Data Model | `adoption` value differs for `preset resolve` only | 001-C proposal keys (`adoption: "nothing adopted yet"`, 001-C design L165) | No key added/removed/reordered (in-place assignment keeps dict order); records unchanged |
| UI Elements | N/A — CLI JSON/text only, no mockups | N/A | Linked Mockups N/A |
| API Endpoints | `preset resolve` (`--json`, `--output FILE`) value change | `policy resolve` (001-C) untouched; `preset scope-save` untouched | `service._finish` writes the same `data` to `--output`, so the file carries the new text too |

### Conflict Analysis

Inspected: spec 001-F v1.5 (`e00d6721…`), design 001-F v1.3 (`e49f1e87…`), spec 001-C (`6f629d1f…`), design 001-C (`625b05fe…`), `policy/resolve.py` (`f1dcdd6e…`), `policy/preset_scope.py` (`aa9b0bbb…`), `policy/service.py` (`2876bd77…`), `tests/presets/test_preset_scope.py` (`c73264c3…`), `tests/policy/test_policy.py` (`302ae6fc…`), pre-001-F fixtures, acceptance `blackbox.py` (`3fe65523…`), Framework `SKILL.md` (`980c9ff6…`), `references/presets-and-tags.md` (`6d4df848…`), `references/cli-contract.md` (`75f3c146…`). No other CR exists in `x-ipe-docs/requirements` (search for `CR-*.md`: none).

| # | Type | Affected Feature | Severity | Classification | Description | Source / Revision | Resolution / Authority |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | specification | FEATURE-001-F | low | expected | BR-11 / AC-001F-09d: any change to delivered 001-C observable behaviour stops work and needs a human CR. The selected means changes only 001-F `preset resolve` output; plain `policy resolve` and every 001-C test/fixture stay byte-identical, so BR-11 is not triggered; the human CR exists anyway (CR4). | spec v1.5 BR-11 L220, AC-001F-09d L167 | Clarifying rule BR-18 appended (no supersession); human CR4 |
| 2 | specification | FEATURE-001-F | low | expected | AC-001F-04a requires the 001-C proposal contract incl. "nothing adopted yet". New text keeps that prefix. | spec v1.5 L105 | AC-001F-04a unchanged; new AC-001F-04l |
| 3 | specification/test | FEATURE-001-F | low | expected | AC-001F-09a pre-001-F fixtures hold the old text (`fixtures/pre_001f/clues-proposal.json` L18, `apply-all-proposal.json` L24) — these are **plain `policy resolve`** outputs and must stay byte-identical. | fixtures `0343618e…`, `38552284…` | Not changed; regression guard |
| 4 | design | FEATURE-001-C | low | expected | 001-C design L165 documents `adoption: "nothing adopted yet"` (prefix only); closing report said the change "would touch a 001-C-owned field". Only the value on the 001-F command changes; key and prefix keep the 001-C contract. | 001-C design `625b05fe…` | 001-C spec/design untouched |
| 5 | review | FEATURE-001-F | — | gap | No independent Conflict Detector reviewer was run in this step (no subagents allowed). | — | Recorded gap; owner may request independent review of the delta before implementation |

Unexpected conflicts: none.

### Affected Components

| Component | Impact Level | Details |
| --- | --- | --- |
| `scripts/src/x_ipe_secure_code/policy/preset_scope.py` `_proposal` | low | After `resolve.build(...)`, assign `data["adoption"]` the Preset text (named and default paths both use `_proposal`) |
| `scripts/src/x_ipe_secure_code/policy/resolve.py` | none | Must stay unchanged (001-C) |
| `tests/presets/test_preset_scope.py` | low | New AC-001F-04l test |
| Framework skill text | none required | See DEC-3 |

### Dependencies

Callers of `_proposal`: `resolve_preset` and `resolve_default` (`preset_scope.py`). `preset scope-save` (`save`) builds its own `resolve.build` data only for digest comparison — not output `adoption`, unaffected. FEATURE-002-A/003-A consume scope records, not proposals — unaffected.

## Proposed Approach

1. **Code (implementation worker, later):** in `preset_scope.py` add a constant, e.g. `ADOPTION = "nothing adopted yet — the user must confirm, then: secure-code preset scope-save {} --decisions FILE --confirmed"`, and in `_proposal` right after `data = resolve.build(...)` set `data["adoption"] = ADOPTION.format(name)` (in-place, key order unchanged). Do not touch `resolve.py`, `service.py` or any 001-C/002-A/003-A file.
2. **Spec (applied here):** v1.6 — append AC-001F-04l, BR-18, traceability row, Version History row; AC-001F-04a/09a/BR-11 text unchanged.
3. **Design (applied here):** v1.4 — appended "CR-TASK-078 Design Delta" section, Version History and Design Change Log rows.

### Affected Acceptance and Planned Validation

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-001F-04l (new) | GIVEN a saved Preset NAME (or a usable `default` Preset) WHEN `preset resolve NAME` (or `preset resolve --default`) produces a proposal, including a `maintenance_needed` one, THEN its `adoption` field reads exactly `nothing adopted yet — the user must confirm, then: secure-code preset scope-save NAME --decisions FILE --confirmed` (NAME = the resolved Preset's name) in the result and in any `--output` file AND the proposal keys, their order, `proposal_digest`, entries and `next_steps` are otherwise unchanged AND plain `policy resolve` of the same references returns the unchanged 001-C `adoption` text `nothing adopted yet — the user must confirm, then: secure-code scope save --confirmed` AND the no-default-Preset answer keeps `nothing proposed — no default Preset` | Integration |
| AC-001F-04a (unchanged) | existing text; "nothing adopted yet" prefix retained | Integration |
| AC-001F-09a (unchanged) | pre-001-F plain-resolve fixtures byte-identical | Integration |

### Exact Test Changes (for the implementation worker)

Paths relative to `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/`.

| Change | File:line | Detail |
| --- | --- | --- |
| **Add** | `tests/presets/test_preset_scope.py` (new test after the AC-001F-04a test, L58–84) | `# AC-001F-04l` `test_preset_resolve_adoption_names_preset_scope_save`: (1) `env.presolve()` for `web-input` → `data["adoption"] == ADOPTION.format("web-input")` (compare to a literal string in the test, not the product constant); the order of the keys shared with plain `policy.resolve_policies(...)` for the same references equals the plain order (`[k for k in data if k in plain] == list(plain)`) and the full preset key order equals the delivered pre-change `preset resolve` order (the 001-F-only `preset` key keeps its position); `proposal_digest`/`entries` equal; `next_steps` unchanged; (2) plain `policy.resolve_policies` `adoption` equals the exact 001-C literal; (3) `--output` file JSON carries the new text; (4) valid `default` Preset via `resolve_default` → name `default`; (5) no default → `"nothing proposed — no default Preset"`; (6) a `maintenance_needed` Preset proposal (all references missing) carries the same Preset text. Must be red before the code change (failing-before evidence). |
| Keep (passes unchanged) | `tests/presets/test_preset_scope.py:66` | `"nothing adopted yet" in data["adoption"]` — still true; optional tightening not required |
| Keep (must stay byte-identical) | `tests/presets/fixtures/pre_001f/clues-proposal.json:18`, `apply-all-proposal.json:24`; `test_preset_scope.py:284` (`test_pre_001f_fixtures_byte_identical`), `test_preset_impact.py:225` | Plain `policy resolve` regression guard (AC-001F-09a) |
| Keep | `tests/policy/test_policy.py:201` | 001-C substring assertion; untouched (AC-001F-09d) |
| Keep (acceptance evidence) | `x-ipe-docs/requirements/EPIC-001/FEATURE-001-F/acceptance/blackbox.py:906` | substring "nothing adopted" — still passes; no change |

No delivered 001-F test asserts the old `scope save` text for `preset resolve` (search of `tests/` for `scope save` / `nothing adopted` / `"adoption"`: only the rows above, plus 002-A/003-A next-step strings unrelated to `adoption`).

### Skill Text Impact

None required: `SKILL.md` L137–139, `references/presets-and-tags.md` L105–113 and `references/policy-selection.md` L20–23 already instruct `preset scope-save` and "nothing adopted yet". Optional (DEC-3 B): `references/cli-contract.md` L26 could add "; `adoption` names `preset scope-save NAME`". Not applied (product skill files are out of scope for this step).

## Mockup Impact

UI/UX change: No (CLI JSON/text only; specification Linked Mockups N/A).

## Decisions (DAO mode — within-skill means; recommendations applied, owner/DAO to confirm)

| DEC | Question | Options | Recommendation (applied) |
| --- | --- | --- | --- |
| DEC-1 | Exact `adoption` text for `preset resolve` | A: `nothing adopted yet — the user must confirm, then: secure-code preset scope-save NAME --decisions FILE --confirmed`; B: mirror 001-C brevity `… then: secure-code preset scope-save NAME --confirmed` | **A** — matches the `next_steps` save line and skill exactly; keeps the 001-C "nothing adopted yet" prefix (AC-001F-04a) |
| DEC-2 | Where to change | A: override in `preset_scope._proposal` only; B: parameterise `resolve.build` | **A** — `resolve.py`/plain `policy resolve` stay byte-identical (AC-001F-09a, BR-11, 001-C tests unchanged) |
| DEC-3 | Skill text | A: no skill change; B: add one clause to `references/cli-contract.md` L26 | **A** — skill already correct; avoids skill-text churn; B may be taken later by the owner |
| DEC-4 | Status coverage | A: same Preset text for every `_proposal` result incl. `maintenance_needed` (mirrors 001-C, whose text is status-independent); B: Preset text only for `complete`/`partial` | **A** — simplest; consistent with 001-C; `next_steps` still carry the repair guidance |
| DEC-5 | Spec form | A: additive AC-001F-04l + clarifying BR-18 (no supersession); B: supersede/reword BR-11 / AC-001F-09a | **A** — BR-11/09a are not violated (001-C output unchanged), so no supersession is needed |

## Approval

- **Authority:** human CR4 = yes (`human_decisions.md` SHA-256 `32f8602546c3884b494a63820ce476965563c48edad669bf571048f076cefde5`) — authorises this CR and the stated output change. Scope is one output value on one 001-F command; no large-scope change, no goal/acceptance weakening.
- **Means decisions:** DEC-1…DEC-5 above are within-skill recommendations of this worker under `dao-represent-human-to-interact`; they are not human approval. If the owner/DAO picks another option, re-apply only the affected spec/design rows.

## Execution

Classification Result: modification.
Conflicts Resolution: all_expected (one review gap recorded, #5).
Actual Actions Taken:
- Created this CR.
- `specification.md` v1.5 → v1.6: header Version/Last Updated; Version History row v1.6; appended AC-001F-04l after AC-001F-04k; appended BR-18 after BR-17; appended traceability row. No existing AC/BR/FR text changed or retired.
- `technical-design.md` v1.3 → v1.4: header Version; Version History row v1.4; Design Change Log row; appended section "CR-TASK-078 Design Delta (appended)" at end. Earlier evidence sections untouched.
- FEATURE-001-C specification/design: untouched. Product code, tests, skill: untouched (implementation is a later step).
- Evidence invalidation: FEATURE-001-F acceptance/closing evidence for `preset resolve` output (AC-001F-04a scenarios, O-2) becomes stale for the `adoption` value only once code changes; all other evidence stays valid. Feature status not changed here.

### Context and Verification Evidence

Before edits (SHA-256): spec 001-F `e00d67215106d60aadeb07fc1f669ba354be593c3e7feb0171b0ee386805d2a9`; design 001-F `e49f1e870334e429abe5f0a2725fa383faf624bb14eb5fc3b8bf6c2f8d4c4967`; spec 001-C `6f629d1f2514213ad8b69654dbcbcc20637bb23a568789c0c12c32d0bff87c12`; design 001-C `625b05fe2b7949f8d728f788216cad94f3da1802dcc9b184cf6aed5e3b7ae303`; acceptance report `d61591ed5ac517bc5b49f2a2927ff16ea5993c6b9a0b7cb93dc102fb25fea1c6`; closing report `a03858bb38efe6c67516086c69917482aa9caac7429d85e5222a10763a47daf7`; DAO acceptance decisions `8d5d648e72df925a79261a552c0657b768559b3b4dc3ad68ee2e1fdf0ef71761`; `preset_scope.py` `aa9b0bbb27bfa0fc6f8ff8a51b8b8d26ef40c31c1977e771c492709dec755a91`; `resolve.py` `f1dcdd6e3afb9e58388b0de3bd30681ca242d7973eabe922c6cf3794def80f6d`; `test_preset_scope.py` `c73264c31473e4622a923fe3a503c39881ef8945ab6342fb15e04e50e2c6faff`. Product files were read while another worker may be editing product code; implementation must re-hash before starting.

Delivery state: documents updated; code/test change planned, not implemented; no tests run in this step. Outcome: not measured.

## Review Correction (2026-10-23, Sage)

Independent CR review (FAIL, one blocker): the planned key-order assertion compared the full `preset resolve` key list with plain `policy resolve`, which can never hold because `_proposal` appends the 001-F-only `preset` key. Corrected in the test plan above and in the design delta: shared-key order equals plain resolve, and the full key order equals the delivered pre-change `preset resolve` order. The exact `adoption` value is the only assertion expected to be red before the code change.
