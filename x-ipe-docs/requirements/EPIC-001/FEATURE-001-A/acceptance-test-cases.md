# Acceptance Test Cases

> Feature / approved standalone scope: FEATURE-001-A — Toolkit Install, Signed Owner Initialization & Status (EPIC-001)
> Status: Verified delivery for approved scope — all ACs pass on macOS and Linux; AC-001A-10a Windows verification deferred by CR-002 (tracked open item)
> Revision: toolkit tree `1bf2a22c64c58a50…` · specification v1.1 `2863bc525fd04d61…` · design `d4032e03eb35177c…` · black-box runner `76e97513ad021b54…` · tools.json `6df39210e203507a…` (SHA-256 prefixes)

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-001-A, board status Implemented (TASK-007) |
| Specification / Source | [specification.md v1.1](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/specification.md) (CR-001); parent [EPIC-001](x-ipe-docs/requirements/requirement-details.md) FR-03, FR-24, NFR-01, FR-01, FR-27/28 (minimal) |
| Design / Implementation | [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md) Parts 1–2; [ai-secure-code-toolkit/](ai-secure-code-toolkit/README.md) (`secure-code` CLI in the Framework skill's `scripts/`, three SKILL.md) |
| Target URL | N/A — CLI/library/skill scope, no UI |
| Config / Capability | `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true` (Python CLI/library checks enabled); Chrome DevTools not applicable (no UI). Runner: black-box script [blackbox.py](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/acceptance/blackbox.py) invoking the real `uvx --from …/scripts secure-code`; existing pytest suite for library-level cases |
| Planned Cases / Priority | 26 cases (P0: 19, P1: 7) — diagnostic only |

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-05 | Spec G-05; EPIC FR-24, FR-03 | Owner / Maintainer | Maintenance authority explicit, verifiable, not self-grantable after first init | Signed init/verify/revoke, interactive + passphrase | Scenario: piped init refused; tampered/foreign/restored grants → User; owner init → Maintainer | U-13 limit; first init detectable not preventable | AC-001A-06a…g, 07a…f, 08a…d | not measured |
| G-03 / G-06 | Spec; EPIC FR-03 | User, upstream agent | Each readiness gap visible with its own next step | Read-only sectioned status | Scenario: fresh project → each condition + next step, no Ready | Not a health certificate | AC-001A-09a…e | not measured |
| G-06 | Spec (CR-001); EPIC FR-27/28 minimal | Maintainer | Agent environment knows the toolkit; user text untouched | Explicit env profile + fragment upsert | Scenario: Copilot project with AGENTS.md → one fragment, user bytes identical | Multi-carrier in 003-B | AC-001A-04f…i | not measured |
| G-08 | Spec; EPIC NFR-01 | Upstream agent | Works in plain repos on macOS/Linux/Windows | Standalone uv project | Scenario: plain repo on each OS | Windows deferred (user) | AC-001A-04e, 10a | not measured |
| Safe upgrade | Spec | Maintainer | Re-init never overwrites edits or data | Install record + plan-then-apply | Scenario: edited skill kept, data identical | — | AC-001A-05a…d | not measured |
| G-01/G-02 enabling | Spec; EPIC FR-01 | All | Skill boundaries explicit from first init | SKILL.md skeletons | Structured review | Behaviour later | AC-001A-04d | not measured |

## Full Acceptance / Evidence Map

| Source / Parent Goal | Story / Subgoal | AC ID | TC / Type | Original Assertions | Evidence / Revision | Delivery State | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-03; O-09, K-29 | US-01 | AC-001A-04a | TC-INT-01 integration | skills in env skills folder; layout 7 folders; no knowledge/Presets | macOS + Linux black-box Pass | verified engineering delivery | not measured |
| S-04 | US-01 | AC-001A-04b | TC-INT-02 integration | refuse + message; write nothing; no parent search | macOS + Linux Pass | verified | not measured |
| O-09, I-20 | US-01 | AC-001A-04c | TC-INT-01, TC-INT-18 integration | no scanner; no auth/key/grant; no package install; no toolkit network request | macOS + Linux Pass (Linux run with `--network none`); socket-blocked child Pass | verified | not measured |
| O-01…O-06 | US-01 | AC-001A-04d | TC-UNIT-06 unit, TC-SR-01 structured-review | each skill states responsibilities and non-responsibilities per O-01…O-06 | unit Pass; review Pass (lines cited) | verified | not measured |
| NFR-01 | US-07 | AC-001A-04e | TC-INT-01 integration | init/auth/status/skill entry work without X-IPE files; none created | macOS + Linux Pass | verified | not measured |
| CR-001 | US-01 | AC-001A-04f | TC-INT-03 integration | explicit env used + named; independent of existing agent files | macOS + Linux Pass | verified | not measured |
| CR-001 | US-01 | AC-001A-04g | TC-INT-04 integration | missing/unsupported env refused; supported listed; nothing written | macOS + Linux Pass | verified | not measured |
| I-12…I-14 | US-08 | AC-001A-04h | TC-INT-05 integration | one fragment; outside content byte-identical | macOS + Linux Pass (CRLF, non-ASCII) | verified | not measured |
| I-12…I-14 | US-08 | AC-001A-04i | TC-INT-06 integration | no second fragment; edited kept + reported; replaced only on choice | macOS + Linux Pass | verified | not measured |
| Safe upgrade | US-02 | AC-001A-05a | TC-INT-07 integration | no file modified; reported current | macOS + Linux Pass | verified | not measured |
| Safe upgrade | US-02 | AC-001A-05b | TC-INT-08 integration | unedited files updated and listed | macOS + Linux Pass | verified | not measured |
| Safe upgrade | US-02 | AC-001A-05c | TC-INT-08 integration | edited kept, reported, replaced only on explicit choice | macOS + Linux Pass | verified | not measured |
| Safe upgrade | US-02 | AC-001A-05d | TC-INT-08 integration | secure-code data byte-identical | macOS + Linux Pass | verified | not measured |
| G-05 | US-03 | AC-001A-06a | TC-INT-14 integration | interactive pristine init with passphrase ×2 → keys + trust outside projects, signed grant, encrypted private key | Linux (pty) Pass | verified | not measured |
| G-05 | US-03 | AC-001A-06b | TC-INT-12 integration | non-interactive refused; nothing created/changed | Linux Pass | verified | not measured |
| G-05 | US-03 | AC-001A-06c | TC-INT-14 integration | valid authorization → refuse, point to status/revoke | Linux Pass | verified | not measured |
| G-05 | US-03 | AC-001A-06d | TC-INT-13 integration | mismatch/abort → nothing created, reason shown | Linux Pass (mismatch) ; abort covered by unit suite | verified | not measured |
| AC-27 | US-03 | AC-001A-06e | TC-INT-14, TC-INT-16 integration | private key/passphrase absent from output, logs, project | Linux Pass | verified | not measured |
| G-05 | US-03 | AC-001A-06f | TC-INT-14 integration | re-auth after revoke only with existing passphrase; no new trust root | Linux Pass | verified | not measured |
| U-15 | US-03 | AC-001A-06g | TC-INT-15 integration | partial state → refuse, no new trust root, recovery deferred | Linux Pass | verified | not measured |
| U-11, I-20 | US-04 | AC-001A-07a | TC-UNIT-01 unit | no authorization → User + next step; nothing created | Pass | verified | not measured |
| U-10 | US-04 | AC-001A-07b | TC-UNIT-02 unit | altered / foreign-key / embedded-key / workspace trust file → invalid, no Maintainer | Pass | verified | not measured |
| U-11, AC-27 | US-04 | AC-001A-07c | TC-UNIT-03 unit | readable private key never opened (instrumented); succeeds when unreadable/absent | Pass | verified | not measured |
| U-07, U-08 | US-04 | AC-001A-07d | TC-INT-14 integration | Maintainer from any workspace without registration | Linux Pass | verified | not measured |
| U-12 | US-04 | AC-001A-07e | TC-UNIT-04 unit | re-verified after revoke → refused | Pass | verified | not measured |
| U-03, U-05 | US-04 | AC-001A-07f | TC-UNIT-05 unit | qualification only, no scope/network/budget/autonomy | Pass | verified | not measured |
| U-12 | US-05 | AC-001A-08a | TC-INT-14 integration | revoke → User "revoked" | Linux Pass | verified | not measured |
| U-12 | US-05 | AC-001A-08b | TC-INT-12, TC-INT-14 integration | non-interactive or wrong passphrase → refused, unchanged | Linux Pass | verified | not measured |
| U-12 | US-05 | AC-001A-08c | TC-INT-13 integration | nothing authorized → reported, nothing changed | Linux Pass | verified | not measured |
| U-12 | US-05 | AC-001A-08d | TC-INT-14 integration | restored pre-revocation grant rejected; valid only via passphrase re-auth | Linux Pass (restored after revoke and over a new grant) | verified | not measured |
| O-10, AC-03 | US-06 | AC-001A-09a | TC-INT-09 integration | separate sections, per-tool next steps, host state, no Ready | macOS + Linux Pass | verified | not measured |
| X-12 | US-06 | AC-001A-09b | TC-INT-09, TC-INT-17 integration | nothing created/modified; business code not scanned | macOS + Linux Pass; open-audit allow-list Pass | verified | not measured |
| X-11 | US-06 | AC-001A-09c | TC-INT-10 integration | root, install entry, default Preset, configuration problems | macOS + Linux Pass | verified | not measured |
| S-04 | US-06 | AC-001A-09d | TC-INT-11 integration | not installed + init next step; no parent report | macOS + Linux Pass | verified | not measured |
| U-11 | US-06 | AC-001A-09e | TC-INT-14, TC-INT-15 integration | invalid/revoked shown with reason + next step, role User | Linux Pass | verified | not measured |
| NFR-001A-4 | US-07 | AC-001A-10a | TC-SR-02 structured-review (platform matrix) | macOS, Linux, Windows; paths with spaces + non-ASCII | macOS + Linux Pass; **Windows Not Run** (user decision) | partial — Windows unverified | not measured |
| AC-27 | US-03/04 | AC-001A-10b | TC-INT-16 integration | no private key/passphrase/model credential in outputs or project files | macOS + Linux Pass | verified | not measured |

## Prerequisites and Relevant Inputs

| Role | Actual Path / Boundary | SHA256 / Environment Revision | Dependent ACs / Rationale |
| --- | --- | --- | --- |
| source | [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) EPIC-001 | parent requirement | all |
| specification | [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/specification.md) v1.1 | `2863bc525fd04d61…` | all 37 ACs |
| design | [technical-design.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md) | `d4032e03eb35177c…` | contracts (CLI, records, algorithms) |
| code | [ai-secure-code-toolkit/](ai-secure-code-toolkit/README.md) (all files excl. `.venv`, caches) | tree `1bf2a22c64c58a50…` (same as implementation evidence) | all |
| config | [tools.json](x-ipe-docs/config/tools.json) `stages.validation.acceptance_test` | `6df39210e203507a…` | capability gate |
| test | [blackbox.py](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/acceptance/blackbox.py); developer suite `scripts/tests/` (in code tree hash) | `76e97513ad021b54…` | TC-INT-*, TC-UNIT-* |
| environment | macOS (Darwin, Python 3.13.3 via uvx, uv 0.11.23); Linux Docker `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` (Python 3.12.12), `--network none`, read-only toolkit mount, disposable HOME | — | platform matrix; Linux isolates the trust store from the developer's real account |
| evidence | [evidence-host-macos.jsonl](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/acceptance/evidence-host-macos.jsonl), [evidence-container-linux.jsonl](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/acceptance/evidence-container-linux.jsonl), [evidence-unit-library.log](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/acceptance/evidence-unit-library.log) | `b33abe6b9f68e85e…`, `93f85dbe7b7a6f29…`, `0d807129ea51fd24…` | per-TC results |

Authorization scenarios were deliberately **not** run on the macOS host: the toolkit resolves its trust store from the OS account (no override by design), so host runs would modify the developer's real authorization. They ran in the disposable Linux container instead.

## Typed Test Cases

### Integration Tests (integration — real CLI via `uvx --from …/scripts secure-code`, temporary projects)

| TC | ACs | Priority | Preconditions / Data | Steps (actual boundary) | Original Assertions | macOS | Linux |
|---|---|---|---|---|---|---|---|
| TC-INT-01 | 04a, 04c, 04e | P0 | fresh plain project "p ü" (non-ASCII + space) | `init --project P --env github-copilot --json` | exit 0; 3 skills in `.github/skills`; framework scripts placed, dev tests not; 7 layout folders, no files; one AGENTS.md fragment; env named; no `.venv`; no X-IPE files; trust store unchanged | Pass | Pass (offline) |
| TC-INT-02 | 04b | P0 | folder with a file | `init` without root / missing / file root | exit 1 `ROOT_REQUIRED`/`ROOT_INVALID`; tree unchanged | Pass | Pass |
| TC-INT-03 | 04f | P0 | AGENTS.md + `.github/` present | `init --env claude-code` | `.claude/skills`, CLAUDE.md fragment, env named, AGENTS.md untouched | Pass | Pass |
| TC-INT-04 | 04g | P0 | fresh project | `init` without env / `--env emacs` | `ENV_REQUIRED` / `ENV_UNSUPPORTED`; supported listed; nothing written | Pass | Pass |
| TC-INT-05 | 04h | P0 | AGENTS.md CRLF, non-ASCII | `init` | original bytes prefix identical; one fragment; CRLF kept | Pass | Pass |
| TC-INT-06 | 04i | P0 | initialized project | rerun; edit fragment; rerun; `--replace AGENTS.md` | no second fragment; edit kept + `FRAGMENT_EDITED`; replaced only on choice | Pass | Pass |
| TC-INT-07 | 05a | P0 | initialized project | rerun same toolkit | exit 0; `already_current`; tree identical | Pass | Pass |
| TC-INT-08 | 05b, 05c, 05d | P0 | report file in data; local edit to Copilot SKILL.md; newer toolkit copy | `init --toolkit-source NEWER`; then `--replace <copilot SKILL.md>` | guard updated + listed; copilot kept + `LOCALLY_EDITED`; replaced on choice; data byte-identical | Pass | Pass |
| TC-INT-09 | 09a, 09b | P0 | initialized project | `status --json`, `status` | sections, next steps, 3 tool lines, host present / effect not verified, no "ready"; project + trust store unchanged | Pass | Pass |
| TC-INT-10 | 09c | P1 | `tags` removed, `presets/default.json` added | `status --json` | root, skills dir, preset true, tags problem | Pass | Pass |
| TC-INT-11 | 09d | P1 | installed parent, empty child | `status --project CHILD` | "not installed", init next step, child root | Pass | Pass |
| TC-INT-12 | 06b, 08b | P0 | pristine trust store | piped `auth init --json` / `auth revoke --json` | `NOT_INTERACTIVE`; no trust files | Not run (host) | Pass |
| TC-INT-13 | 06d, 08c | P0 | pristine trust store | pty `auth init` mismatching passphrases; pty `auth revoke` | `PASSPHRASE_MISMATCH`, nothing created; `nothing_authorized`, nothing changed | Not run (host) | Pass |
| TC-INT-14 | 06a, 06c, 06e, 06f, 07d, 08a, 08b, 08d, 09e | P0 | pristine trust store, two projects | pty init; `auth status` from 2 cwd; init again; revoke wrong / right; status; restore saved grant; pty re-auth; restore old grant over new | see map rows; all checks | Not run (host) | Pass |
| TC-INT-15 | 06g, 09e | P0 | initialized, current grant deleted; then public key corrupted | pty `auth init`; `status --json` | `TRUST_PARTIAL`, trust tree unchanged; status invalid + reason, role User | Not run (host) | Pass |
| TC-INT-16 | 10b (06e) | P0 | `OPENAI_API_KEY` canary in env for every command | scan all command outputs and project files (copied toolkit source excluded) | no canary, passphrase or private-key text | Pass | Pass |
| TC-INT-17 | 09b | P1 | project with business source and a Local rule | developer suite `test_status_changes_nothing_and_reads_only_metadata` (child `open` audit hook) | only allow-listed metadata opened; business file never opened; hashes unchanged | Pass | (suite Pass in implementation evidence) |
| TC-INT-18 | 04c | P1 | socket creation blocked in child | `test_init_copilot_project_creates_skills_layout_fragment` | init succeeds without network | Pass | Pass (whole Linux run `--network none`) |

**Status:** all Pass on the platforms shown. **Environment:** see inputs. **Reuse Disposition:** fresh execution at the stated revision; TC-INT-17/18 freshly executed via the developer suite (log `evidence-unit-library.log`). **Observation Gap:** not measured.

### Unit Tests (unit — library public API, fresh run)

| TC | AC | Priority | Test (scripts/tests/) | Original Assertions | Status |
|---|---|---|---|---|---|
| TC-UNIT-01 | 07a | P0 | `test_auth_service.py::test_verify_no_trust_dir_user_next_step` | User, next step, nothing created | Pass |
| TC-UNIT-02 | 07b | P0 | `::test_verify_rejects_tampered_grant`, `::test_verify_rejects_grant_signed_by_foreign_key`, `::test_verify_rejects_grant_with_embedded_public_key`, `::test_workspace_trust_file_is_ignored` | invalid, no Maintainer | Pass |
| TC-UNIT-03 | 07c | P0 | `::test_verify_never_opens_signing_key`, `::test_verify_module_does_not_import_private_key_helpers` | key never opened when readable; works when absent | Pass |
| TC-UNIT-04 | 07e | P0 | `::test_require_maintainer_reverifies_after_revoke` | re-verified, refused | Pass |
| TC-UNIT-05 | 07f | P1 | `::test_decision_is_qualification_only` | qualification only | Pass |
| TC-UNIT-06 | 04d | P1 | `test_skill_skeletons.py` (3 tests) | frontmatter, sections, O-01…O-06 phrases | Pass |

Command: `uv run pytest -p no:cacheprovider -v <14 node ids>` → `14 passed` (macOS, Python 3.14 project env).

### Structured-Review Tests (structured-review)

**TC-SR-01 — Skill boundaries (AC-001A-04d), P1, Pass.** Reviewed complete SKILL.md files:
- Framework: holds Adapter code (`SKILL.md:28`), *does not decide scan strategy* (`:32-33`, O-06), never auto-creates authorization (`:35`), Reviewers have no extra authority (`:37`, O-05), status not a certificate (`:39`).
- Copilot: in-flow for design, implementation, bug fix and refactor (`:20`, O-02), *not a second business writer* (`:28`, O-04), Reviewers no extra authority (`:33`).
- Guard: verifies on explicit/authorized request (`:21`, O-03), decides scan strategy and calls Framework-held Adapters (`:23`, O-06), *does not fix* (`:28`, O-03), Reviewers no extra authority (`:32`).

**TC-SR-02 — Platform matrix (AC-001A-10a), P0, Partial.** macOS: 12/12 black-box + full suite (Python 3.11, 3.14); Linux: 16/16 black-box offline + full suite (Python 3.12); paths with spaces and non-ASCII exercised in every black-box case. **Windows: Not Run** — no Windows host; user decided 10-19-2026 "no windows test for now". Windows-only code (`trust_store._windows_roaming_app_data`, `getpass.getuser`) remains unexecuted.

## Test Execution Summary

| Test Case | ACs | Title | Type | Priority | Status | Evidence / Gap |
| --- | --- | --- | --- | --- | --- | --- |
| TC-INT-01…11 | 04a–05d, 09a–09d | Project init / re-init / status | integration | P0/P1 | Pass | macOS + Linux jsonl |
| TC-INT-12…15 | 06a–06g, 07d, 08a–08d, 09e | Owner authorization lifecycle | integration | P0 | Pass | Linux jsonl (host excluded to protect real trust store) |
| TC-INT-16 | 10b | No secrets in outputs/project | integration | P0 | Pass | macOS + Linux jsonl |
| TC-INT-17, 18 | 09b, 04c | Read allow-list; offline init | integration | P1 | Pass | unit-library log; Linux offline |
| TC-UNIT-01…06 | 07a–07c, 07e, 07f, 04d | Library verification API, skill content | unit | P0/P1 | Pass | unit-library log |
| TC-SR-01 | 04d | Skill boundaries | structured-review | P1 | Pass | cited lines |
| TC-SR-02 | 10a | Platform matrix | structured-review | P0 | Partial | Windows not run (user decision) |

## Execution Results

**Execution Date / Reviewer:** 2026-10-19, Sage (TASK-007); black-box runner independent of developer test launcher.
**Environment:** macOS Darwin (uv 0.11.23, Python 3.13.3 via uvx); Linux Docker Python 3.12.12, no network.

| Type | Total Planned | Passed | Failed | Blocked | Partial / Not Run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 | 0 | 0 | 0 | 0 |
| backend-api | 0 | 0 | 0 | 0 | 0 |
| unit | 6 | 6 | 0 | 0 | 0 |
| integration | 18 | 18 | 0 | 0 | 0 |
| structured-review | 2 | 1 | 0 | 0 | 1 (Partial) |
| TOTAL | 26 | 25 | 0 | 0 | 1 |

Pass Rate = 25 / 26 = **96.2%** (diagnostic, not goal achievement).

### Failures / Blockers / Review Limits

| TC / AC | Expected versus Actual / Missing Evidence | Evidence | Recommended Bounded Action |
| --- | --- | --- | --- |
| TC-SR-02 / AC-001A-10a | Windows behaviour (Known Folder trust path, console interactivity, CRLF/ACL handling) not executed | No Windows host; user decision 10-19-2026 | Decided: CR-002 (user, 10-19-2026) defers Windows verification to a later phase; tracked open item in the specification |
| Harness notes (resolved) | First host run flagged "PRIVATE KEY" — only inside the copied toolkit's developer tests (`fat-src-*/…/tests`), not outputs/project; first container run failed on a runner path default | runner revisions before `76e97513…` | Runner scope/path fixed; assertions unchanged; reruns Pass |
| Accepted limits | Restoring an older signed trust-state file re-activates access; first init on a pristine machine by a pty-capable agent is detectable, not preventable | design/spec honest limits (U-13) | No action (accepted) |

### Engineering Delivery versus Stakeholder Outcome

| Goal / Subgoal | Delivery Evidence / State | Outcome Scenario / Observation | Outcome State / Gap |
| --- | --- | --- | --- |
| G-05 | All 06*/07*/08* ACs pass (Linux black-box + unit) | Owner keeps maintenance authority; agents cannot self-grant after first init | not measured |
| G-03/G-06 | 09a–09e pass (macOS + Linux) | Users see each gap with its next step | not measured |
| G-06 | 04f–04i pass | Agents find the toolkit; user AGENTS.md text intact | not measured |
| G-08 | 04e pass; 10a partial | Works in plain repos on macOS/Linux; Windows unverified | not measured; Windows delivery gap |
| Safe upgrade | 05a–05d pass | Upgrades never destroy edits/data | not measured |

### Refactor / Closing Recommendation and App Gates

Refactor need: none evidenced — modules ≤ 251 lines, ruff clean, 93% coverage, no duplication found by review; recommend **Feature Closing** (AC-001A-10a Windows gap dispositioned by CR-002). Free-mode: no application workflow mutation (`workflow_action_updated: false`).

> **Note (2026-10-23, TASK-079):** after acceptance, bug fix TASK-079 made plain `init` refuse an unreadable host entry file with `HOST_ENTRY_UNREADABLE` (designed behaviour) instead of crashing. Regression evidence: `acceptance/regression-TASK-079-host-macos.jsonl` (13/13 Pass). The results above are unchanged.

> **Note (2026-10-23, TASK-095):** bug fix TASK-095 made plain `init` refuse unreadable skill targets (`SKILL_NAME_CONFLICT` / `IO_ERROR`) and non-regular host entry files (`HOST_ENTRY_UNREADABLE`) instead of crashing or hanging. Regression evidence: `acceptance/regression-TASK-095-host-macos.jsonl` (statuses identical). The results above are unchanged.
