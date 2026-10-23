# Change Request: CR-TASK-086 — Renderer identity in Guard results

> Created: 2026-10-23
> Status: Applied, round 2 (documents only; FEATURE-002-A spec v1.1 and design v1.1 deltas inserted; independent review FAIL findings B1, B2, NB3 fixed — re-review pending; DAO-003 approval with conditions recorded; product code not changed in this step)
> Classification: modification (of delivered FEATURE-002-A), with a dependent FEATURE-002-G follow-up proposed here only
> Related Feature: FEATURE-002-A (requested for FEATURE-002-G)

## Request Details

- **Requestor:** FEATURE-002-G refinement — DAO-011 (c) recorded the optional human CR candidate "record the renderer/toolkit version in Guard results" (002-G spec v1.2 history row, Out of Scope, Technical Considerations).
- **Approver (human authority):** the human, C1 = Yes, 2026-10-23 21:58, `x-ipe-docs/dao/26-10-23/human_decisions.md` (sha256 `d4b9bde745d19dda…`): "Guard results record the renderer/toolkit version (002-A) so 002-G can tell older reports from edited ones" → "Change Request opened".
- **Representative approval of the means:** DAO-003 (2026-10-23T22:10:19+08:00, `x-ipe-docs/dao/26-10-23/decisions_made_change_request.md`) — DEC-1…DEC-9 and DEC-G1 all A, with conditions (see "Decisions"). DAO guidance, not human permission beyond C1.
- **Task:** TASK-086, owner Sage, `x-ipe-task-based-change-request`, interaction mode `dao-represent-human-to-interact`; no board/Git/memory/skill writes; no product code edits (TASK-076 is implementing FEATURE-002-G in the same tree).
- **Priority:** medium (FEATURE-002-G v1 is complete without it; it removes an honest limit).
- **Owning folder:** `x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/`.

## Description

**Present behaviour (delivered 002-A + 002-B/C/D additions).** `guard conclude` writes the structured result `reports/guard/<id>.json` (schema `ai-secure-code-toolkit/guard-result/v1`, `guard/model.py` L19; built by `engine.conclude`, `guard/engine.py` L390–425) and renders the Markdown report from it with `report.render` (`guard/report.py` L47–302) ending in `<!-- guard-result-sha256: <hex of the JSON bytes> -->`. Nothing in either file says which toolkit build wrote them. The package version is `0.1.0` in both `__init__.py` L3 and `pyproject.toml` L3, and it was **not** bumped when 002-B/C/D added report sections (design change log, "Additive extensions") — so a version string alone cannot identify the renderer.

**Consequence in FEATURE-002-G.** FR-002G-2b (iii) compares the complete Markdown with `report.render(result)` of the current build. A report written by an earlier renderer and an edited report both fail that check and are indistinguishable: AC-002G-05l states "edited, or rendered by a different toolkit version" (honest limit, spec L260; DAO-011 (c)).

**Requested change (002-A).** Every structured result written from now on records the identity of the toolkit build that wrote it — toolkit version plus a digest of the Guard report renderer — so a reader (FEATURE-002-G) can tell "rendered by a different renderer" from "changed after it was written".

**Explicitly not in this CR.**
- Any FEATURE-002-G behaviour change (proposal section below; separate follow-up CR after TASK-076).
- Copilot reports (FEATURE-003-A, `copilot/service.py` `md_report.render`) — C1 names Guard results only.
- Proof of origin: the identity is self-declared by the writing build; a consistently edited result + Markdown pair stays undetectable (existing 002-G limit).
- Repair of older reports, migration of existing results, schema v2.

## Business Justification

Without it, every report written before a renderer change is permanently "input integrity unresolved" with an ambiguous cause, which over time makes 002-G's integrity warning noise (users learn to ignore it) — the opposite of G-02 "no misleading result; every conclusion traceable". Alternatives considered: (1) toolkit version only — insufficient, see Description; (2) keep the honest limit (DAO-011 (c)) — the human chose C1 = Yes; (3) versioned/old renderers inside 002-G — far larger, needs every historic renderer. Not changing keeps the limit; no safety regression either way. Compliance/standards: N/A (provenance metadata, no external standard).

## Goal / Subgoal Delta

| Goal / Subgoal | Parent / Source | Stakeholder | Before Outcome | Proposed Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | Story / AC Links | Delta Kind | Authority | Affected Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 (unchanged) — enabling subgoal "result provenance" | 002-A spec G-02; US-08; human C1 | Developer, upstream agent, FEATURE-002-G | A result/report does not say which build wrote it | Each newly written result and its report name the writing toolkit version and renderer digest; older results keep working unchanged | Selected means: one optional top-level `renderer` object in the v1 result, shown in the report; all-required: recorded on every result write that renders (conclusion, cancellation conclusion in `cancel.finalize_frozen` — direct `guard cancel` and a pending cancellation finalized by `guard conclude` — and accept-risk) | Scenario: conclude → JSON has `renderer` = current identity, Markdown shows it, footer still the JSON SHA-256; an old result without it shows/concludes/accepts risk/cleans up as before and renders byte-identically | Additive only; schema id stays v1; engine verdict logic untouched; self-declared, not proof; no Copilot reports | US-08; AC-002A-01i, 01j, 01k, 01l (new); 01a, 01b, 01h, 06h unchanged | acceptance (additive) + means | Human C1 = Yes (sha `d4b9bde7…`); option choices DEC-1…DEC-9, DEC-G1 = A by DAO-003 (with conditions) within C1 | 002-A delivered evidence retained (no delivered AC changed); new ACs planned, not delivered | not measured |
| G-02 for FEATURE-002-G (proposal only) | 002-G FR-002G-2b, AC-002G-05l | Developer comparing reports | Older-renderer vs edited indistinguishable | Distinguished when the result carries `renderer` | Follow-up CR on 002-G after TASK-076 | Planned ACs 05t/05u (proposal) | 05l stays valid for results without `renderer` | AC-002G-05c, 05l | proposal (not applied) | Pending — follow-up CR | none now | not measured |

## Impact Analysis

### Classification

**modification** of FEATURE-002-A. Same stakeholders, same report/result boundary (R-01…R-10, US-08), same goal G-02; the change adds one metadata field and one report section. No independent workflow or stakeholder outcome → not new_feature. FEATURE-002-G is a dependent consumer: its use of the field is a separate, later modification (proposal below), not part of this CR's applied scope.

### Comparison Matrix

| Aspect | CR Requirement | Existing Feature(s) | Evidence / Boundary Decision |
| --- | --- | --- | --- |
| Users | Unchanged (Developer, upstream agent; 002-G as reader) | Same | 002-A spec US-08; inside 002-A |
| Workflow | `guard conclude`, cancellation conclusion and `guard accept-risk` stamp `renderer`; `_repair_report`, `show`, `cleanup`, `keep/release` unchanged | conclude → result + md; accept-risk rewrites both; repair renders md only | `service.py` L480–525; `cancel.py` `finalize_frozen` L83–125 (engine call L113, publish L115), reached from `cancel` L172 and `finalize_locked` L128–136 ← `service.conclude` L499; `retention.py` L93–99; `service.py` L450–454 |
| Data Model | Optional `renderer: {toolkit_version: str, renderer_digest: 64-hex \| null}` in `guard-result/v1` | v1 result; additive keys precedent: `adapter_runs`, `budget`, `attempts`, `egress`, `cancellation`, `tool_provisioning` (002-B/C/D, no schema bump) | `engine.py` L390–425; readers: `runs.read_result` checks only schema + id (L150–167); 002-G validator ignores unconsumed keys (002-G design L395) |
| UI Elements | Markdown: final `## Structured Result Origin` section only when `renderer` present | Markdown ends with `## Limits` + footer | `report.py` L285–302; no mockups (N/A) |
| API Endpoints | CLI unchanged; no new command/option/problem code; `--json` envelopes unchanged | `secure-code guard …` | Reasoned N/A: field reaches readers via the result file |

### Conflict Analysis

Inspected: 002-A spec (`ab170f06…`), 002-A design (`56d8e2a4…`), 002-G spec (`476d4156…`), 002-G design (`26c9e20a…`), `requirement-details.md` (`1747efe6…`), code `guard/report.py` (`ce3cc4e5…`), `runs.py` (`3ce5967b…`), `model.py` (`7ff88d5b…`), `service.py` (`8f3d7303…`), `engine.py` (`c7d10002…`), `cancel.py` (`b25af0a6…`), `retention.py` (`7aeefc0c…`), `compare.py` (`9b806682…`, in progress), `__init__.py` (`3ee7c37e…`), `pyproject.toml` (`0905c827…`), tests listed below. Pending CRs on 002-A: none found. Mockups: none.

| # | Type | Affected Feature | Severity | Classification | Description | Source / Revision | Resolution / Authority |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | specification | FEATURE-002-G | medium | expected | AC-002G-05l, Honest Limits ("older renderer indistinguishable"), Out of Scope and DAO-011 (c) "no versioned renderer (would need a 002-A output change)" describe the state this CR removes | 002-G spec L138, L260, L274, L307, L309 (`476d4156…`) | 002-G docs **not edited**; 05l stays true for results without `renderer`; follow-up CR proposed (DEC-9) |
| 2 | dependency | FEATURE-002-G | high if violated | expected | FR-002G-2 supports only `guard-result/v1`; a schema bump would make 002-G refuse every new result | 002-G spec L179 | Schema id stays v1 (DEC-3); additive optional key |
| 3 | dependency | FEATURE-002-G | low | expected | 002-G strict validator walks consumed fields; value-count bound (NFR-002G-5) counts all values | 002-G design L346, L395 | Unconsumed keys ignored; +3 values per result — negligible |
| 4 | dependency | FEATURE-002-G (TASK-076) | high if violated | expected | Another worker is editing the product tree now; CR code touches `report.py`, `service.py`, `cancel.py`, `retention.py` (002-G reuses `report.render` read-only) | TASK-076 in progress; `compare.py` L231 | Implement only after TASK-076 completes (DEC-9) |
| 5 | specification | FEATURE-002-A | low | expected | NFR-002A-1 "same recorded run gives the same … outputs": result bytes now also depend on the writing build | 002-A spec NFR-002A-1 | Clarified additively: "with the same toolkit build"; within one build unchanged (06h) |
| 6 | design | FEATURE-002-A | low | expected | `_repair_report` re-renders a missing/mismatched Markdown with the current build but does not rewrite the result (06h: result bytes unchanged) → after a cross-build repair the recorded identity is the result writer's, not the Markdown renderer's | `service.py` L450–454; 002-A design "Commands" | Repair unchanged (DEC-7); field semantics = "build that wrote the result"; limit stated; 002-G follow-up wording never claims tampering |
| 7 | design | FEATURE-002-A | medium | expected | `renderer_digest` must cover the whole rendering closure; under-inclusion would let 002-G call a report from a changed renderer "edited" (false tamper hint). `report.py` imports `hashlib`, `re`, `typing` and the toolkit module `atomic` (`dumps_json`) | `report.py` L7–13 | (Round 2, review B2, DAO-003 DEC-2 condition) digest over an explicit sorted file manifest of every output-affecting module — today `guard/report.py` and `atomic.py`; later FEATURE-002-F `helper_report` when it exists — with deterministic framing; a closure test fails if `report.py` gains a toolkit-internal import missing from the manifest; an unreadable component gives "renderer unknown" (`null`), never a match |

No unexpected conflict. No delivered AC is changed or retired.

### Affected Components

| Component | Impact Level | Details |
| --- | --- | --- |
| `guard/report.py` | medium | New `RENDERER_MANIFEST` (sorted package-relative paths: `atomic.py`, `guard/report.py`) and `renderer_identity()` (cached; `__version__` + framed SHA-256 over the manifest; any unreadable component → `null`); `render` appends `## Structured Result Origin` only when `result.get("renderer")` |
| `guard/service.py` `_conclude_open` | low | Stamp `result["renderer"]` before `create_result_exclusive` |
| `guard/cancel.py` `finalize_frozen` | low | Stamp immediately after `engine.conclude` (L113) and before `create_result_exclusive` (L115). `finalize_locked` (pending cancellation finalized by `guard conclude`, `service.py` L499) delegates to `finalize_frozen` (L136), so both cancellation paths are covered by this one site; on `FileExistsError` the stored winner is kept unchanged |
| `guard/retention.py` `accept_risk` | low | Re-stamp before `write_result` (the Markdown is re-rendered by the current build) |
| `guard/engine.py`, `runs.py`, `model.py`, CLI, Guard SKILL.md | none | Engine stays pure; schema id unchanged; no CLI/skill change |
| FEATURE-002-G (`compare*.py`) | none now / low later | v1 ignores the key; follow-up consumes it |

### Dependencies

Upstream: `x_ipe_secure_code.__version__` (same source as `secure-code --version`). Downstream: FEATURE-002-G (reader). Shared contract: `guard-result/v1` (additive-key convention of 002-B/C/D). No pending CR on 002-A.

## Proposed Approach

### Exact delta (FEATURE-002-A)

1. **Field.** Top-level, optional `"renderer": {"toolkit_version": "<__version__>", "renderer_digest": "<64 lowercase hex> | null"}`. Semantics: identity of the toolkit build that last wrote this structured result (and rendered its report at that time); a report later re-created by repair under another build is not reflected (DEC-7).
   - **Renderer manifest (round 2, review B2; DAO-003 DEC-2 condition).** `RENDERER_MANIFEST` in `guard/report.py`: the explicit list of every output-affecting module, as package-relative POSIX paths, sorted — today `atomic.py` (`dumps_json`, footer digest) and `guard/report.py`; FEATURE-002-F adds its `helper_report` module when it exists.
   - **Framing.** `renderer_digest = SHA-256( concat over sorted manifest paths p of: UTF-8(p) ‖ 0x00 ‖ ASCII-decimal(len(bytes)) ‖ 0x00 ‖ bytes )`, where `bytes` are the installed file's bytes read in binary mode. Deterministic; a byte change, rename, addition or removal of a component changes the digest.
   - **Unknown.** If any component cannot be read, `renderer_digest` is `null`; the report says "renderer unknown"; a `null` identity never counts as equal to any identity (including another `null`).
   - **Closure guard.** A unit test parses `guard/report.py` (and every manifest module under `guard/`) and fails if it imports a toolkit-internal module (`x_ipe_secure_code.*` or relative) whose file is not in the manifest.
2. **Where.** In the structured result (authoritative) and shown in the Markdown; inside the JSON it is covered by the existing `guard-result-sha256` footer; footer format and `FOOTER` regex unchanged.
3. **Written by.** The three writers that render: conclusion (`service._conclude_open`, before `create_result_exclusive`); cancellation conclusion (`cancel.finalize_frozen`, immediately after `engine.conclude` L113 and before `create_result_exclusive` L115 — covers direct `guard cancel` L172 and a pending cancellation finalized by `guard conclude` via `finalize_locked` L136, round 2 review B1; an already stored winner on `FileExistsError` is not changed); `accept-risk` (re-stamps; verdict, findings and severities unchanged — DAO-003 DEC-6 condition). Not by `_repair_report` (result bytes stay identical, 06h). One helper, applied by callers; `engine.conclude` output unchanged.
4. **Rendering.** If `renderer` present: after `## Limits`, before the footer: `## Structured Result Origin` + bullets `Structured result written by secure-code toolkit <version>; renderer sha256 <digest | "renderer unknown">` and `This identifies the build that wrote the structured result; a report re-created later by repair may come from a different build` (`md_text` applied; round 2, review NB3). If absent: byte-identical to the delivered renderer.
5. **Backward compatibility.** Schema id stays `ai-secure-code-toolkit/guard-result/v1`; `runs.read_result`, `show`, `conclude` (idempotent path), `cleanup`, `keep/release` accept results without `renderer`; `accept-risk` on such a result adds the stamp (it rewrites the result anyway).
6. **No migration**, no repair of old reports, no new command/option/problem code.

### Documents changed in this step

- `FEATURE-002-A/specification.md` — inserted lines only (all delivered lines byte-identical): version row v1.1, amendment note, G-02 coverage note, AC-002A-01i/01j/01k (+ 01l in round 2), FR-002A-10, NFR-002A-1 note, edge-case rows, consumer line, traceability row, evidence row, open-question rows. Round 2 edits only these CR-added lines (01i, FR-002A-10, edge cases, open-question row, traceability/evidence/coverage IDs) and inserts 01l.
- `FEATURE-002-A/technical-design.md` — inserted/appended only: version row v1.1, "CR-TASK-086 Amendment" section, change-log row; round 2 edits only that CR-added section and appends a round-2 change-log row.
- Not changed: `requirement-details.md` (within R-01…R-10 report capability; no new high-level capability/user type/project rule — `requirement_updated: false`), FEATURE-002-G docs (proposal below), product code, tests.

### Affected Acceptance and Planned Validation

| AC ID | Criterion (Given/When/Then) | Test Type |
| --- | --- | --- |
| AC-002A-01i (new; round 2) | GIVEN a verification WHEN it is concluded normally, cancelled directly with `guard cancel`, or has a pending cancellation finalized by `guard conclude` THEN the structured result has `renderer` with the toolkit version reported by `secure-code --version` and the renderer digest over the renderer manifest AND the Markdown report ends, before the footer, with a "Structured Result Origin" section naming both and stating that it identifies the build that wrote the structured result, which may differ from a later report-repair build AND the footer still equals the SHA-256 of the JSON bytes | Integration |
| AC-002A-01j (new) | GIVEN a structured result without `renderer` (written before this change) WHEN it is shown, concluded again, cleaned up or rendered THEN it is accepted with schema `guard-result/v1` unchanged AND its rendering is byte-identical to the rendering before this change AND no result is rewritten except by risk acceptance | Integration / Unit |
| AC-002A-01k (new) | GIVEN a concluded Fail result whose `renderer` is absent or names another build WHEN a risk acceptance is recorded THEN the rewritten result's `renderer` names the current build AND verdict, findings and severities are unchanged | Integration |
| AC-002A-01l (new; round 2) | GIVEN the renderer manifest WHEN the bytes of any listed component (e.g. `guard/report.py` or `atomic.py`) change THEN the renderer identity changes; GIVEN `guard/report.py` imports a toolkit-internal module missing from the manifest WHEN the closure test runs THEN it fails; GIVEN an unreadable component WHEN a result is written THEN `renderer_digest` is `null`, the report says "renderer unknown" AND that identity never matches any identity | Unit |
| AC-002A-01a, 01b, 01h, 06h, 07a (unchanged) | Delivered wording kept; regression only | Integration |

Planned checks (implementation task, not run here): unit — `renderer_identity()` shape; digest equals an independent recomputation of the framed manifest digest; changing either component (temporary copies / patched reader) changes the identity; manifest sorted; closure test (AST import scan vs manifest, plus a negative fixture proving it fails on a missing import); unreadable component → `null`, "renderer unknown", never equal; `render` without `renderer` equals delivered output (existing report tests as regression) and with it adds exactly the final section; integration — normal conclude; direct `guard cancel`; pending cancellation (marker present) finalized through `guard conclude`; accept-risk stamping/re-stamping with verdict/findings/severities unchanged; old-result fixture through show/conclude/cleanup/accept-risk; full suite incl. in-progress 002-G compare tests green.

### Delivered tests: change required vs byte-identical

With DEC-3/5/7/8 (and round-2 B1/B2/NB3), **no delivered test must change**; DAO-003 condition: if implementation finds one that must change, stop. Round 2 re-check: no delivered test calls `finalize_frozen`/`finalize_locked` directly or patches `engine` (grep of `tests/`), and stamping in `finalize_frozen` precedes the (sometimes monkeypatched) `create_result_exclusive`. Regression-relevant (stay byte-identical):

| Test (file:line) | Why it stays green |
| --- | --- |
| `tests/guard/test_guard_report.py:18-38` (exact `## ` heading list, footer = SHA-256 of JSON, render deterministic) | `_result()` = `engine.conclude` output (`test_guard_engine.py:144-152`); engine is not stamped → no `renderer` → no new heading |
| `tests/guard/test_guard_report.py:71-77` (Limits text) | `in` checks; Limits unchanged |
| `tests/guard/test_guard.py:566-575` (06h: conclude twice → identical dict and JSON bytes; repaired md identical) | Same build → same stamp; repair does not stamp |
| `tests/guard/test_guard.py:641` (refused accept-risk leaves JSON bytes) | Refusal happens before any write |
| `tests/guard/test_guard_cancel.py:107-112` (repeat cancel → identical result) | Same build |
| `tests/guard/test_runs_commit.py:53, 92-100` (runs writers with minimal dicts) | `runs` writers not changed |
| `tests/guard/test_guard_budget.py:428-445` (monkeypatched `create_result_exclusive`) | Stamp applied before the call; signature unchanged |
| `tests/guard/test_guard_engine.py` (all) | Engine output unchanged |
| `FEATURE-002-A/acceptance/blackbox.py:440, 846, 896` (md `in` checks; NFR-3 repaired identically) | Same build |
| `tests/guard/test_compare_cli.py:357` (002-G 05l fixture, in progress) | Still "unresolved"; v1 ignores `renderer` |

If DEC-5 B (stamp in engine) were chosen, `test_guard_report.py:22` would fail with DEC-8 A → avoided.

## Decisions (DAO mode — within-skill, inside the C1 scope)

Options applied as recommended in the 002-A deltas. **DAO-003 (2026-10-23T22:10:19+08:00) approved DEC-1…DEC-9 and DEC-G1 = A** as means for human C1 (DAO guidance, not human permission beyond C1).

| DEC | Question | Options | Recommendation |
| --- | --- | --- | --- |
| DEC-1 | Where does the identity live? | A) structured result + shown in Markdown; B) result only; C) Markdown footer comment only (editable, outside the digest) | **A** — result is authoritative and covered by the footer; humans see it |
| DEC-2 | What identifies the renderer? | A) `toolkit_version` + `renderer_digest` (round 2: framed SHA-256 over the sorted renderer manifest — today `atomic.py` + `guard/report.py`); B) version only; C) manual `RENDERER_ID` bumped with a golden test | **A** — version stayed `0.1.0` across 002-B/C/D renderer changes; source digest needs no discipline; worst case (digest change without output change) is harmless because then the Markdown matches |
| DEC-3 | Schema id | A) keep `guard-result/v1`, optional key; B) bump to v2 | **A** — 002-B/C/D precedent; B breaks 002-G v1 (v1-only) and `runs.read_result` |
| DEC-4 | Digest/footer | A) inside JSON → covered by existing footer, format unchanged; B) extra footer comment | **A** |
| DEC-5 | Where is it stamped? | A) callers of the three result writers via one helper, engine pure; B) inside `engine.conclude` (+ accept-risk) | **A** — engine/report unit tests stay byte-identical; engine stays IO-free |
| DEC-6 | Accept-risk | A) re-stamp (it re-renders the Markdown); B) keep the original stamp | **A** — B would let 002-G call a current-build report "edited" when compared by the original build |
| DEC-7 | Cross-build `_repair_report` | A) unchanged (no result rewrite), limit stated; B) re-stamp result when identity differs | **A** — B mutates committed result bytes after conclusion (breaks 06h across builds and SHA-256s recorded by 002-G comparisons) |
| DEC-8 | Markdown display | A) final `## Structured Result Origin` section only when present (round 2 name, review NB3); B) bullet in Scope; C) none | **A** — old results render byte-identically; delivered tests unchanged |
| DEC-9 | Sequencing with TASK-076 (002-G in progress) | A) 002-G v1 unchanged; implement this CR after TASK-076 completes; then a small 002-G follow-up CR; B) fold into TASK-076 now (re-refine/re-design an in-flight feature); C) implement this CR now in parallel (two writers in one product tree) | **A** — least disruptive; v1 already ignores the key and 05l stays true for unstamped results |

**DAO-003 conditions (binding for implementation):**

1. **DEC-2:** `renderer_digest` covers the whole rendering closure via the explicit manifest; a closure test fails when `report.py` gains a toolkit-internal import missing from the manifest; an unreadable component is "renderer unknown" (`null`), never a match. Over-inclusion only yields a harmless "renderer differs"; under-inclusion is forbidden. (Applied: Exact delta 1, AC-002A-01l.)
2. **DEC-6:** risk acceptance re-records the current build; verdict, findings and severities are unchanged (AC-002A-01k).
3. **DEC-7:** the field means "build that wrote the result"; the report says so (NB3); 002-G wording never infers tampering from it.
4. **DEC-9:** implement after TASK-076 completes, in the serialized code queue; the 002-G follow-up CR comes after 002-G's own acceptance; 002-G v1 unchanged.
5. **DEC-G1:** `renderer_differs` is a non-accusatory integrity state; with equal identity but different Markdown the wording is "edited, or changed by an unrecorded renderer change" — never "tampered".
6. **Delivered tests stay byte-identical** (table above); if implementation finds one that must change, **stop** and return to the owner — no silent test edit.
7. New tests for AC-002A-01i/01j/01k/01l plus the closure test.
8. CR documents count as confirmed only after the independent review passes (round-1 FAIL; blocking findings fixed in round 2; re-review pending).
9. Git: B8 = A authorizes local commits only (no push/PR/release); this CR makes no commit.

## Proposal: dependent FEATURE-002-G follow-up (NOT applied; 002-G docs unchanged)

To be raised as its own CR on FEATURE-002-G after TASK-076 and after this CR is implemented:

- **FR-002G-2a addition:** `$.renderer?` — absent allowed; if present: object; `toolkit_version` text ≤ 200; `renderer_digest` 64 lowercase hex or `null`; otherwise refuse per AC-002G-05b (rule/path, never value).
- **FR-002G-2b addition (cause classification):** only when (i) canonical serialization and (ii) footer pass, the Markdown is present and (iii) fails:
  - `renderer` absent, or recorded or current digest `null` ("renderer unknown", never a match) → unchanged: `unresolved`, statement per AC-002G-05l.
  - recorded `renderer_digest` ≠ current `report.renderer_identity()` digest → **"rendered by a different toolkit version"**: notice first naming recorded and current version/digest prefix; "its Markdown body cannot be checked by this build; the structured result passed its checks and was used"; no edit claim.
  - equal → `unresolved`, cause "changed after it was written": wording "the Markdown differs from what this build — the build recorded as writing the result — renders: edited, or changed by an unrecorded renderer change (for example re-created by report repair under another build)"; never "tampered" (DAO-003 DEC-G1 condition).
  - Any other failed check → unchanged `unresolved` regardless of `renderer`.
- **ACs (proposed IDs):** AC-002G-05l narrowed by note to results without a renderer record (wording kept); AC-002G-05t (different renderer digest → "rendered by a different toolkit version"); AC-002G-05u (same digest → "changed after it was written", no tampering claim); `input_integrity` entry gains `cause`.
- **DEC-G1 (approved A by DAO-003, planned follow-up):** state for "different renderer" — A) new non-accusatory `input_integrity` state `renderer_differs` instead of `unresolved` (chosen; matches C1 "tell older reports from edited ones"; honest because the structured result passed (i)/(ii) and is what is compared); B) keep `unresolved` and add `cause` only. No 002-G wording may say "tampered".
- **Tests:** fixtures stamp `renderer` with a foreign digest / the current digest (monkeypatched `renderer_identity`), plus the existing 05l fixture without `renderer`.
- **Honest limit kept:** identity is self-declared; consistently edited pair undetectable; cross-build repair case (DEC-7).

## Mockup Impact

UI/UX change: No (no product UI; Markdown section is a report text change). No mockups exist for FEATURE-002-A (spec Linked Mockups N/A).

## Approval

- Intent and scope: human C1 = Yes (2026-10-23 21:58; `human_decisions.md` sha `d4b9bde745d19dda87c40e58ed2b3b540bb91147156eefa03bca04ab03b577be`). Additive ACs 01i–01l implement exactly that intent on FEATURE-002-A; no delivered AC, goal or constraint is changed.
- Means (DEC-1…DEC-9, DEC-G1): approved A by DAO-003 (2026-10-23T22:10:19+08:00, `decisions_made_change_request.md`) with the conditions listed under "Decisions"; DAO guidance, not human permission beyond C1.
- Confirmation state: documents count as confirmed only after the independent re-review passes (DAO-003 condition 3).
- Not authorized here: 002-G changes (proposal only), product code, Git/board writes.

## Execution

Classification Result: modification. Conflicts Resolution: all_expected.

Actual actions: this CR created; 002-A spec and design deltas inserted/appended (existing lines byte-identical); 002-A delivered evidence retained (no delivered AC changed); new ACs 01i–01l planned, not delivered; round 2 fixed independent-review findings B1, B2, NB3 (below); 002-G docs, requirements, code and tests untouched.

### Context and Verification Evidence

- Pre-change hashes: 002-A spec `ab170f062928d0303c34a61ec5ba47ec7968970566223f903d7303724091acd8`; 002-A design `56d8e2a4e13f3db3291b676a74b3b3f377e75815f07189a194ff35be36647db4`; 002-G spec `476d41566857866c4cfabcb99138813521d3d1884f1b9722e3a9ffb4655ceb6f`; 002-G design `26c9e20a5db37b4429780c98865673b02aebcf9e63507631a266cb752d339fc2`; requirement-details `1747efe61b9c5cf1264e357b2e2dd5e1c3b3da0b2acc05f862a84ad2df1ac65f`.
- Code (read-only): `report.py` `ce3cc4e5…`, `runs.py` `3ce5967b…`, `model.py` `7ff88d5b…`, `service.py` `8f3d7303…`, `engine.py` `c7d10002…`, `cancel.py` `b25af0a6…`, `retention.py` `7aeefc0c…`, `compare.py` `9b806682…`, `__init__.py` `3ee7c37e…`, `pyproject.toml` `0905c827…`.
- Tests (read-only): `test_guard.py` `f3549a28…`, `test_guard_report.py` `6225fc7e…`, `test_guard_engine.py` `e014f94e…`, `test_guard_cancel.py` `f3ef5a4d…`, `test_compare_cli.py` `23ae614b…`.
- Post-change hashes of changed documents: reported by the task return (this file cannot contain its own hash).
- No commands run against product code; no tests executed (documents only). Independent review: round 1 = FAIL (owner-run; findings B1, B2, NB3 dispositioned below); round-2 re-review pending (owner). Stakeholder outcome: not measured.
- Suggested successor (owner decides): `x-ipe-task-based-code-implementation` for FEATURE-002-A CR-TASK-086 after TASK-076 (spec/design already updated here, so refinement is not required); then a FEATURE-002-G follow-up `x-ipe-task-based-change-request`.

### Independent Review (round 1 = FAIL) — dispositions (round 2)

| Finding | Issue | Fix (documents) |
| --- | --- | --- |
| B1 (blocking) | Cancellation stamping named `finalize_locked`, but the cancellation result is created in `cancel.finalize_frozen` (`cancel.py` L113–115); direct `guard cancel` (L172) calls `finalize_frozen` directly, so it would have been unstamped | Stamp in `finalize_frozen` immediately after `engine.conclude` and before `create_result_exclusive`; `finalize_locked` delegates (L136), so pending cancellations finalized by `guard conclude` are covered too; AC-002A-01i and planned tests name both paths |
| B2 (blocking) | Digest of `guard/report.py` alone under-covers the rendering closure (`atomic.dumps_json`; later 002-F `helper_report`) and the import pin was a weak guard | Explicit sorted `RENDERER_MANIFEST` with `path\0len\0bytes` framing; closure test fails on an unlisted toolkit import; component-change tests; unreadable → "renderer unknown", never a match (AC-002A-01l; DAO-003 DEC-2 condition) |
| NB3 (non-blocking) | "Report Origin" suggested the report renderer, but after cross-build repair the Markdown may come from another build | Section renamed "Structured Result Origin" and states it identifies the build that wrote the structured result, which may differ from a later report-repair build |

## Links

- [FEATURE-002-A specification](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/specification.md) · [technical design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/technical-design.md)
- [FEATURE-002-G specification](x-ipe-docs/requirements/EPIC-002/FEATURE-002-G/specification.md) · [technical design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-G/technical-design.md) (unchanged)
- [Human decisions](x-ipe-docs/dao/26-10-23/human_decisions.md) (21:58, C1)
- [DAO decisions — change request](x-ipe-docs/dao/26-10-23/decisions_made_change_request.md) (DAO-003)
- [Requirement details](x-ipe-docs/requirements/requirement-details.md) (unchanged)

## Change History

| Date | Change | By |
| --- | --- | --- |
| 2026-10-23 | CR created and applied to 002-A spec v1.1 / design v1.1 (documents only); 002-G follow-up proposed | Sage (TASK-086) |
| 2026-10-23 | Round 2: independent review FAIL fixes B1 (stamp in `cancel.finalize_frozen`), B2 (renderer manifest digest, closure test, unknown never matches; new AC-002A-01l), NB3 ("Structured Result Origin"); DAO-003 approval and conditions recorded; 002-A spec/design CR-added lines updated | Sage (TASK-086) |

## Implementation Evidence (TASK-090, 2026-10-24)

Code Implementation worker for owner Sage (TASK-090), authority human C1 = Yes and DAO-003 (DEC-1…9, DEC-G1 = A with conditions). No Git, board, memory or skill writes; no network (containers `--network none`).

- **Changed source** (toolkit `x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/`, before → after SHA-256):
  - `guard/report.py` `36a655d9…` → `24bd0247…` (705 lines): `RENDERER_MANIFEST`, `manifest_digest(root, manifest)` (framing `path\0len\0bytes` over sorted paths; any `OSError` → `None`), cached `renderer_identity()`, `stamp(result)`, `same_renderer(a, b)` (never true for a missing identity or a `null` digest), `_origin_section` appended after `## Limits` only when `renderer` is present.
  - `guard/service.py` `fdebb28e…` → `40113b94…`: `report.stamp(result)` in `_conclude_open` after `engine.conclude`, before the barrier and `create_result_exclusive`.
  - `guard/cancel.py` `b25af0a6…` → `f26ed77d…`: `report.stamp(result)` in `finalize_frozen` after `engine.conclude`, before `create_result_exclusive` (direct `guard cancel` and a pending cancellation finalized by `guard conclude`); a stored winner on `FileExistsError` is used unchanged.
  - `guard/retention.py` `7aeefc0c…` → `7ec3dcfc…`: `report.stamp(result)` in `accept_risk` before `write_result` (verdict/findings/severities untouched).
  - Unchanged: `guard/engine.py` `c7d10002…`, `guard/runs.py` `3ce5967b…`, `guard/model.py` `7ff88d5b…`, `guard/compare_validate.py` `349573b1…`, `guard/compare.py` `13fbf5c8…`, `atomic.py` `99f6a11c…`, `__init__.py` `3ee7c37e…`; schema id `guard-result/v1`, footer format/`FOOTER` regex, CLI, problem codes, Guard SKILL.md.
- **Means detail (within the DEC-2 closure rule):** reading `__version__` imports the package `__init__.py` from `guard/report.py`, so the manifest is `("__init__.py", "atomic.py", "guard/report.py")` — the closure test requires it; over-inclusion is harmless (a version bump also changes the digest). Current identity: `{"toolkit_version": "0.1.0", "renderer_digest": "5a22b95ba33e6f0bca8a3398fa05cb2369c139debe59265fc2156b2ccc524f95"}` (same in source and in the uvx-built install). No new payload file → `tests/carriers/carhelp.py` `ERA_001A_REMOVED` not edited.
- **New tests** `tests/guard/test_guard_renderer.py` (`14e02763…`, 30 tests): 01l — manifest sorted/complete, identity shape, independent framed recomputation, CLI `--version` equals the recorded version, change of `guard/report.py`, `atomic.py` or `__init__.py` changes the digest, framing separates components/paths, unreadable component → `null`, `same_renderer` never matches unknown/missing, unreadable component during a real conclusion → `null` + "renderer unknown"; closure — AST scan (all nesting levels, relative and absolute imports) of every manifest module ⊆ manifest, plus 6 negative fixtures proving the check fails on an unlisted import; 01i — render adds exactly the final section, `md_text` neutralization of the recorded version, normal conclusion, direct `guard cancel`, pending cancellation (marker) finalized by `guard conclude`, cancellation race keeps the stored winner; 01j — unstamped rendering equals golden SHA-256s recorded with the delivered renderer (`36a655d9…`) for 3 results (engine Fail, engine plain, 002-G rich result), old result through show / conclude / repair / cleanup with JSON and Markdown bytes unchanged, cross-build repair leaves the result bytes and foreign `renderer` unchanged; 01k — accept-risk on absent and foreign stamps records the current build, verdict/findings/severities and all other keys unchanged; FEATURE-002-G — `compare_validate.validate` accepts results with `renderer` (current, foreign, `null` digest) per its "unconsumed keys are ignored" policy, `guard compare` of fixture results and of two real stamped Guard results gives `input_integrity` consistent for both.
- **TDD:** RED before any source change — 26 failed / 3 passed (the 3 passing are the 01j byte-identity/old-result checks, true by construction before the change); failures were the missing `RENDERER_MANIFEST` / `renderer_identity` / `_PACKAGE_ROOT` and the absent section. After implementation one new-test expectation was corrected (trailing blank line before the footer) and the real-run compare test sleeps 1.1 s (002-G refuses equal end seconds, `END_ORDER_INVALID`). GREEN: 30 passed. Coverage of `guard/report.py` from the new tests 88% with every new line covered.
- **Full suite** (`PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=…`): before 2563 passed, 4 skipped, 23 deselected (exit 1 only from the session write-audit line `new: …/test_guard_renderer.py`, because the new test file was created while that baseline ran); after **2593 passed, 4 skipped, 23 deselected, exit 0** (macOS, Python 3.14). `ruff check --no-cache .`: all checks passed.
- **Delivered tests:** all 130 delivered files under `scripts/tests/` and the 002-A/002-G `acceptance/blackbox.py` (+ 002-G `run.sh`) byte-identical before/after (hash lists in the session folder `impl-cr086/test-hashes-{before,after}.txt`); no delivered test needed a change.
- **Black-box regressions** (real `uvx` CLI, `UV_OFFLINE=1`, `UV_REFRESH_PACKAGE=ai-secure-code-toolkit`, TMPDIR in the session folder, host never authorized/no `auth init`): 002-A host 2/2 Pass; 002-G container (disposable HOME, `--network none`, `fat-uv-git:py312`, disposable uv cache volume seeded offline from `fat-uv-cache-003b` and removed afterwards; build check printed the new manifest/identity) 24/24 Pass, 182 checks — its seed results were written by this build and carry `renderer` and the "Structured Result Origin" section; 002-G host (on those seeds) 23/23 Pass, 174 checks. Per-TC statuses and check lists equal the recorded 002-A/002-G evidence. Outputs: session folder `impl-cr086/bb/` (acceptance folders not overwritten).
- **Toolkit file-list hash** (`find . -type f` excluding `.venv`/`__pycache__`/`.pytest_cache`/`.ruff_cache`/`.coverage*`, `./` stripped, `LC_ALL=C sort -k2`, SHA-256 of the list): 243 files, `272741bc8c8d9213673f47237f777e47ef194e85ae5b13e07fc975c8f3ddac2c`.
- **Not done / open:** independent code review (no sub-agent permitted to this worker) — owner to arrange; feature acceptance test for 01i–01l; 002-G follow-up CR (DEC-G1). Stakeholder outcome: not measured.

## Closing Note (2026-10-24, appended by Sage)

- Renderer manifest as implemented: `("__init__.py", "atomic.py", "guard/report.py")`. `report.py` imports `__version__` from the package, so `__init__.py` belongs to the rendering closure; confirmed by the representative as the DAO-003 DEC-2 rule applied (DAO-003, code implementation). A version bump therefore also changes the renderer digest (at most "renderer differs", never a false "edited").
- Independent code review: **PASS** (byte-identical rendering of old results verified against the pre-change renderer; stamping on all three result-writing paths; unknown identity never matches; delivered tests unchanged).
- Final toolkit file-list hash `272741bc8c8d9213673f47237f777e47ef194e85ae5b13e07fc975c8f3ddac2c`; full suite 2593 passed, 0 failed.
- Follow-up: FEATURE-002-G change request for `renderer_differs` (DEC-G1), to be opened after this CR.
