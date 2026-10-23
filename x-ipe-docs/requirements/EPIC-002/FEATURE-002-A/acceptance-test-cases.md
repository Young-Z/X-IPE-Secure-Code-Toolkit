# Acceptance Test Cases

> Feature: FEATURE-002-A — Guard Semantic Verification & Verdict Reporting (EPIC-002)
> Status: Verified delivery for approved scope (all 54 ACs pass on Linux; never-authorized User path also on macOS; Windows not run — same deferral as FEATURE-001-A CR-002)
> Revision: toolkit tree `a5cc8598ed9e98b7…` · specification `ab170f062928d030…` · design `afb613bb06249eee…` · runner `90f7622853d0ee38…` (SHA-256 prefixes) — rerun after Bug Fix TASK-026; first run at toolkit `e263db91…`, runner `da460853…`

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-002-A, board status Implemented (TASK-023) |
| Specification / Source | [specification.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/specification.md); parent EPIC-001 FR-01, FR-02, FR-14, FR-15, FR-22; AC-01, AC-02, AC-11, AC-16…AC-22 |
| Design / Implementation | [technical-design.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/technical-design.md); `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/`; Guard `SKILL.md`, `references/guard-records.md` |
| Target URL | N/A — CLI/library/skill scope (no UI, no mockups) |
| Config / Capability | `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true` (Chrome tools enabled but not applicable: no frontend). Runner [blackbox.py](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/acceptance/blackbox.py) invokes the real `uvx --from …/scripts secure-code guard|scope|policy|knowledge|auth …` and never imports toolkit code; risk acceptance through a real pseudo-terminal |
| Planned Cases | 28: integration 26 (TC-A-01…24, 27 container; TC-A-26 host), structured-review 1 (TC-S-01 with executable phrase check TC-A-25), unit/library 1 (TC-U-01). The first-run table counted 28 with integration 26 although it held 25 integration cases (TC-A-25 was double-counted); TC-A-27 was added for TASK-026 |

Scenarios needing prepared knowledge run only in an **offline Linux container with a disposable HOME** (a Maintainer authorization is needed to import test rules; the trust store cannot be redirected by design). The macOS host run covers the never-authorized User path. **Fixture disclosure:** the 30-day cleanup cases (01e, 01f) age concluded runs by editing `ended_at` in the run state and structured result; the clock was not advanced.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-02 | Spec G-02; FR-14, FR-15, FR-02, FR-22 | Developer, upstream agent | No misleading "pass"; every conclusion traceable to evidence | TC-A-01…24, 26, TC-S-01, TC-U-01 Pass | 01*…07* | not measured |
| G-01 (enabling) | Spec G-01; FR-01 | Upstream agent | Guard writes no business artifacts | TC-A-01 (08a), TC-S-01 (08b) Pass | 08a, 08b | not measured |

Qualitative outcome scenario (spec): a known-vulnerable sample is not reported Pass; unconfirmed items are listed; a stale review is rejected — exercised with synthetic fixtures (TC-A-01, 18, 19, 20). Real users verifying real projects: **not measured**.

## Full Acceptance / Evidence Map

| AC ID | TC / Type | Original Assertions (summary) | Evidence | Delivery State |
| --- | --- | --- | --- | --- |
| AC-002A-01a | TC-A-01 integration | md + json beside each other, named by id; verdict, ledger, findings, targets, Policies identical (each ledger row state and finding severity/review compared row by row since the TASK-026 rerun) | Pass | verified |
| AC-002A-01b | TC-A-01 integration | id, targets+digests, context, scope id+rules, plan, ledger, findings+severities, Reviewer validity, verdict reasons, acceptances, retention period/location | Pass | verified |
| AC-002A-01c | TC-A-01, TC-A-02 integration | evidence/run state under `.x-ipe/private/secure-code/guard/<id>/`; report refers by location, not raw copy | Pass | verified |
| AC-002A-01d | TC-A-02 integration | token and private key masked in stored evidence, state, result, report; labelled masked | Pass | verified |
| AC-002A-01e | TC-A-03 integration | 31-day removed; 29-day and running kept; all reports remain; reading does not extend | Pass | verified (aged fixture) |
| AC-002A-01f | TC-A-03 integration | keep marker → kept with reason; release → next cleanup removes | Pass | verified (aged fixture) |
| AC-002A-01g | TC-A-03 integration | after removal: findings and verdict shown; "no longer available" stated | Pass | verified |
| AC-002A-01h | TC-A-04 integration | two verifications → own reports; older flagged "does not describe the current version" | Pass | verified |
| AC-002A-02a | TC-A-01 integration | opened without any Copilot report | Pass | verified |
| AC-002A-02b | TC-A-05, TC-A-27 integration | evidence only in Copilot report → check not met; report listed as context, never evidence; an unlisted Copilot report or agent scratch file inside a whole-project target is refused as evidence and never yields Pass | Pass | verified |
| AC-002A-02c | TC-A-06 integration | Apply All + two files → exactly two targets; `.` without flag refused; explicit whole project accepted | Pass | verified |
| AC-002A-02d | TC-A-07 integration | roles separate; context/suggested reported not verified; context-only evidence cannot meet; role conflict refused | Pass | verified |
| AC-002A-02e | TC-A-08 integration | added target with digest; deleted without digest and usable as check object; rename keeps old/new | Pass | verified |
| AC-002A-02f | TC-A-09 integration | missing, outside, symlink refused with path and next step; nothing opened | Pass | verified |
| AC-002A-02g | TC-S-01 structured + executable phrase check | SKILL.md lines 60–65 | Pass | verified |
| AC-002A-03a | TC-A-10 (Linux), TC-A-26 (macOS) integration | no scope / all changed → `MAINTENANCE_NEEDED` with Framework step; no run, report, Pass or 100% | Pass | verified |
| AC-002A-03b | TC-A-11 integration | partial → `SCOPE_PARTIAL` listing adopted / needs_reconfirmation / missing; next step new scope | Pass | verified |
| AC-002A-03c | TC-A-01 integration | scope id, every rule and confirmed digest in run and report | Pass | verified |
| AC-002A-03d | TC-A-12 integration | rule outside adopted scope refused | Pass | verified |
| AC-002A-04a | TC-A-12 integration | entry missing method/object/minimum evidence refused | Pass | verified |
| AC-002A-04b | TC-A-12 integration | N/A needs factual reason; one check per rule enough (no file×rule pairing); uncovered rule refused | Pass | verified |
| AC-002A-04c | TC-A-01 integration; TC-U-01 unit | one state per check with evidence/reason; no percentage | Pass | verified |
| AC-002A-04d | TC-A-13 integration | runtime minimum with reading only → unconfirmed naming runtime | Pass | verified |
| AC-002A-04e | TC-A-13 integration | N/A for unavailable method → `NA_NOT_OBJECTIVE`, must be unconfirmed | Pass | verified |
| AC-002A-04f | TC-A-14 integration | exclusion shown separately from N/A and met | Pass | verified |
| AC-002A-04g | TC-A-13 integration | planned check without state → unconfirmed "not executed" | Pass | verified |
| AC-002A-04h | TC-A-15 integration | unreviewed policy N/A → unconfirmed; confirmed check/policy N/A count; rejected → unconfirmed with reason | Pass | verified |
| AC-002A-04i | TC-A-16 integration | document/reading kept and reported separately; reading cannot be recorded as runtime method | Pass | verified |
| AC-002A-04j | TC-A-13 integration | failed auxiliary substituted and shown; failed required → unconfirmed | Pass | verified |
| AC-002A-05a | TC-A-17 integration | same location/CWE stay separate; merge without evidence refused; merge records evidence, sources kept | Pass | verified |
| AC-002A-05b | TC-A-18 integration | unreviewed High and disputed Low → unconfirmed, no Pass | Pass | verified |
| AC-002A-05c | TC-A-01 integration | confirmed; original source and Reviewer basis both kept | Pass | verified |
| AC-002A-05d | TC-A-18 integration | Reviewer could not confirm → unconfirmed, kept, not false positive | Pass | verified |
| AC-002A-05e | TC-A-19 integration | incomplete record stored with warnings; invalid at conclusion; report says why | Pass | verified |
| AC-002A-05f | TC-A-19 integration | target changed after review → stale, invalid; finding back to unconfirmed | Pass | verified |
| AC-002A-05g | TC-A-19 integration | records setting risk acceptance/targets/ledger refused; nothing stored | Pass | verified |
| AC-002A-05h | TC-S-01 structured + executable phrase check | SKILL.md lines 83–88 | Pass | verified |
| AC-002A-06a | TC-A-01 integration; TC-U-01 unit | confirmed High → Fail | Pass | verified |
| AC-002A-06b | TC-A-20 integration | only Low/Info, all met/reviewed N/A → Pass; Low reported | Pass | verified |
| AC-002A-06c | TC-A-20 integration | confirmed unknown severity → Cannot confirm pass (`SEVERITY_UNKNOWN`) | Pass | verified |
| AC-002A-06d | TC-A-13 integration | zero findings + unconfirmed check → Cannot confirm pass | Pass | verified |
| AC-002A-06e | TC-A-20 integration; TC-U-01 unit | Reviewer Low without evidence → High stands, conflict shown; with bound evidence → Low used, originals kept | Pass | verified |
| AC-002A-06f | TC-A-20 integration | unresolved verdict-affecting conflict → not Pass, listed | Pass | verified |
| AC-002A-06g | TC-A-01, TC-A-14, TC-A-20 integration | every determining reason listed; Fail > Cannot confirm pass > Pass (other blockers kept under Fail) | Pass | verified |
| AC-002A-06h | TC-A-21 integration | conclude twice → identical result and file bytes | Pass | verified |
| AC-002A-06i | TC-A-14 integration | exclusion → Cannot confirm pass; + confirmed High → Fail | Pass | verified |
| AC-002A-06j | TC-A-22 integration | changed target / changed Policy → not Pass, listed by name | Pass | verified |
| AC-002A-06k | TC-A-20 integration | valid false positive (High) and Info never fail; kept with evidence | Pass | verified |
| AC-002A-07a | TC-A-23 integration (real pty) | User types finding id → recorded with role/time/reason; finding, severity, verdict unchanged | Pass | verified |
| AC-002A-07b | TC-A-23 integration | acceptance not applied to another verification | Pass | verified |
| AC-002A-07c | TC-S-01 structured + executable phrase check | SKILL.md lines 93–94 | Pass | verified |
| AC-002A-07d | TC-A-23 (Linux), TC-A-26 (macOS) integration | no terminal → refused although Maintainer authorized; mismatched id refused; nothing recorded | Pass | verified |
| AC-002A-08a | TC-A-01 integration | targets/context byte-identical; only run folder, reports, locks written | Pass | verified |
| AC-002A-08b | TC-S-01 structured + executable phrase check | SKILL.md lines 31–33 | Pass | verified |
| NFR-002A-3 | TC-A-21, TC-A-24 integration | missing report repaired identically; held guard lock → `LOCKED` envelope | Pass | verified |

## Test Cases

| TC | Type | Priority | Command / Method | Result |
| --- | --- | --- | --- | --- |
| TC-A-01…TC-A-25, TC-A-27 | integration (black-box CLI) | P0 (verdict, review, scope), P1 others | `python3 blackbox.py container` in `ghcr.io/astral-sh/uv:python3.12-bookworm-slim`, `--network none`, `UV_OFFLINE=1`, fresh warmed cache volume `fat-uv-cache-ga` (fixed code verified present in cache), toolkit and runner mounted read-only | 26/26 Pass ([evidence](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/acceptance/evidence-container-linux.jsonl)); stderr without tracebacks |
| TC-A-26, TC-A-25 | integration (host User path) + phrase check | P1 | `UV_REFRESH_PACKAGE=ai-secure-code-toolkit python3 blackbox.py host` on macOS (Python 3.13 runner, no trust store) | 2/2 Pass ([evidence](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/acceptance/evidence-host-macos.jsonl)) |
| TC-S-01 | structured-review | P1 | Read complete Guard `SKILL.md` and `references/guard-records.md` against 02g, 05h, 07c, 08b; cited lines above; reference examples parse as the four request schemas (TC-A-25 executable check) | Pass |
| TC-U-01 | unit / library | P1 | `uv run pytest -p no:cacheprovider tests/guard tests/policy -vv` (macOS Python 3.14) | 253 passed, 1 skipped (non-UTF-8 names; runs on Linux) ([log](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/acceptance/evidence-unit-library.log)) |

Runner correction during this task: the first container run failed one check of TC-A-02 because the runner expected `credential.private_key` literally, while the report escapes `_` as `\_` (design: `md_text` neutralization; renders identically). Verified by inspecting the actual report line; only the expected string form was corrected, the assertion (masked label with both types present) is unchanged. Full rerun: 25/25.

## Results

| Type | Planned | Passed | Failed | Blocked |
| --- | --- | --- | --- | --- |
| integration | 26 | 26 | 0 | 0 |
| structured-review | 1 | 1 | 0 | 0 |
| unit | 1 | 1 | 0 | 0 |
| **Total** | **28** | **28** | **0** | **0** |

Pass rate: 28/28 = 100% of planned cases. All 54 ACs and NFR-002A-3 have current passing evidence at the final revision.

**Closing-review rerun (Bug Fix TASK-026):** the closing review found that a whole-project run could Pass on an unlisted Copilot report (BR-02) — a gap the first run missed because TC-A-05 only used a listed report. After the fix, the full black-box set was rerun with a fresh offline cache (TC-A-27 added; 01a strengthened), plus host and unit runs; no assertion was relaxed.

## Gaps and Honest Limits

- Windows: not run (CR-002 deferral); `msvcrt` lock path and Windows paths designed, not verified.
- Reviewer invocation: the script records the agent's declaration bound to digests; whether a real independent sub-agent ran is not provable (spec Technical Considerations). Skill instructions verified structurally only; agent behaviour (plan quality, honest ledger states) is not measured.
- Human presence for risk acceptance: verified as interactive-terminal gate plus typed finding id; a pseudo-terminal counts as interactive (same honest limit as `auth`).
- Evidence ageing used edited `ended_at` fixtures (disclosed above).
- Stakeholder outcome: not measured.
