# Technical Design: Guard Semantic Verification & Verdict Reporting

> Feature ID: FEATURE-002-A | Version: v1.0 | Last Updated: 2026-10-19
> Specification: [specification.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/specification.md) · Task: TASK-022 · Depends on: [FEATURE-001-C design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/technical-design.md), [FEATURE-001-B design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/technical-design.md), [FEATURE-001-A design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md)

## Version History

| Version | Date | Description |
|---------|------|-------------|
| v1.0 | 10-19-2026 | Initial design |
| v1.1 | 10-23-2026 | CR-TASK-086: additive renderer identity (`renderer` in the v1 result, "Structured Result Origin" section; round 2: cancellation stamping in `finalize_frozen`, renderer manifest digest) — see section "CR-TASK-086 Amendment (v1.1)"; delivered v1.0 text kept |

---

## Part 1: Agent-Facing Summary

### Scope & Boundaries

- **Feature:** FEATURE-002-A — `secure-code guard open | plan | record | review | conclude | show | accept-risk | keep | release | cleanup`; Guard `SKILL.md` verification procedure and `references/guard-records.md`.
- **program_type:** `cli` + `library` (Framework `scripts/`, new `guard/` package) + `skills` (Guard agent procedure).
- **tech_stack:** Python ≥ 3.11 stdlib (`json`, `hashlib`, `os`, `pathlib`, `shutil`, `re`, `datetime`), reuse of FEATURE-001-A/B/C modules; pytest, ruff. No new dependency.
- **Non-goals:** Adapters and tool execution (002-B/D/E), helper check scripts (002-F), budget/time limits/cancel (002-C), report comparison (R-11/R-12), JSON exporter (R-14), threshold configuration (V-16), evidence reuse (V-18), non-interactive upstream risk acceptance (deferred), Copilot behaviour (003-A; only the Reviewer envelope is shared).

### Outcome / Goal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 | Spec G-02; FR-14, FR-15, FR-02, FR-22 | Developer, upstream agent | No misleading "pass"; every conclusion traceable to evidence | `guard/engine.py` (deterministic ledger finalization, review validity, severity, verdict + reasons), `guard/records.py` (strict validation of agent-recorded plan/evidence/findings/reviews), `guard/report.py` (Markdown rendered from the structured result), SKILL.md (agent plans, reviews, calls one Reviewer per batch) | Scenario: vulnerable sample with an unreviewed High finding → Cannot confirm pass; confirmed → Fail; stale review rejected; zero findings with an unconfirmed check → Cannot confirm pass | Guard never fixes; no percentage; fixed Medium threshold; Adapters absent → runtime checks unconfirmed | AC-002A-01a…07d | not measured |
| G-01 (enabling) | Spec G-01; FR-01 | Upstream agent | Guard writes no business artifacts | Writes only `.x-ipe/private/secure-code/{guard/<id>/, locks/guard.lock}` and `x-ipe-docs/secure-code/reports/guard/<id>.{json,md}`; targets only read and hashed | Scenario: tree hash of targets/context unchanged after a full run | — | AC-002A-08a, 08b | not measured |

### Design Options and Tradeoffs

| Means | Selection | Rationale |
| --- | --- | --- |
| Agent judges; script records, validates and computes the verdict | selected (user decision) | Deterministic, testable verdict (NFR-002A-1); same split as 001-B/001-C |
| Structured JSON request files per step (`--request FILE`) | selected | Plans, findings and reviews carry nested lists and free text; one validated document per step, like the 001-C decisions file |
| Many CLI flags per item | rejected | Unusable for nested plans; quoting errors |
| Run state `state.json` in the private run folder; structured result `<id>.json` in `reports/guard/` is the canonical conclusion (commit point); Markdown rendered from it | selected | Report and result cannot disagree in content (01a); reports survive evidence cleanup (01g) |
| Markdown embeds the SHA-256 of its result; `conclude` on a concluded run re-renders a missing/mismatched Markdown | selected | Crash between the two writes is repaired deterministically (NFR-002A-3) |
| One global `locks/guard.lock` (`ProcessLock`) for every Guard write and cleanup; interactive prompts happen outside the lock | selected | Serializes commands on one verification (NFR-002A-3) and cleanup vs. recording; lock never inside a folder that cleanup deletes. Tradeoff accepted: unrelated runs of one project are serialized too (local single-user MVP; per-run locks under `locks/guard/` are a later option) |
| Per-run lock file inside the run folder | rejected | Deleting a folder holding its own lock fails on Windows |
| Severity: conservative max unless Reviewer opinion is evidenced | selected (user decision) | AC-002A-06e; unknown never becomes Low |
| Severity conflicts resolved by the rule; requirement/evidence conflicts recorded explicitly by the agent (`conflicts`) | selected | Script cannot detect semantic conflicts; it enforces that unresolved verdict-affecting ones block Pass (06f) |
| Reviewer validity = complete envelope + every reviewed digest equals the current target digest + covers the paths of its subjects | selected (user decision) | AC-002A-05e/05f; invocation is declared, not proven (honest limit) |
| Reviewer record with extra-authority fields is refused entirely | selected | AC-002A-05g; nothing partial is recorded |
| Script never merges findings; a merge is an explicit `merged_from` with `merge_evidence` and is a label only — merged findings still enter the verdict | selected (review fix) | AC-002A-05a; no heuristic dedup; a merge can never hide a severe finding |
| Disagreeing valid Reviewer results for one subject → subject `unconfirmed` + `REVIEW_DISAGREEMENT` blocker (no "last wins") | selected (review fix) | AC-002A-06f; order of recording never decides a verdict |
| No plan cannot pass; plan coverage forces every adopted rule into a check, N/A or exclusion | selected (review fix) | US-03 "no empty check list counts as a pass"; a fully reviewed all-N/A plan may pass (04h, 06b) |
| `not_met` check without a confirmed Medium+ finding → Cannot confirm pass | selected | FR-002A-6 Pass requires every check met/N/A; Fail requires a confirmed finding |
| Masking with the 001-B credential patterns, replacing values by `[masked:<type>]` (private key blocks entirely) | selected | AC-002A-01d; reuses `precheck.CREDENTIALS`, `ASSIGNMENT`, `is_placeholder` |
| Whole-project and directory targets hashed as a tree (regular files only; symlinks never followed; `.git/`, `.x-ipe/private/`, `x-ipe-docs/secure-code/` excluded); symlinks resolving outside the tree, dangling links and special files block Pass (`TARGET_INCOMPLETE`) | selected (review fix) | Guard's own outputs must not change the digest it verifies; content Guard could not read is never silently passed |
| Risk acceptance via interactive terminal and typed finding ID; stored only in the result | selected (user decision) | AC-002A-07a/07d; result outlives evidence cleanup |
| Time-injection environment variable for cleanup tests | rejected | Tests age runs by writing `ended_at` in fixture state; no production test hook |

### Key Components Implemented

All under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/`.

| Component | Responsibility | Scope/Impact | Tags |
|-----------|----------------|--------------|------|
| `guard/model.py` | Constants (states, kinds, severities, schemas, id patterns), small validation helpers, `GuardError` | All guard modules | #contract |
| `guard/targets.py` | Validate open request paths/roles/change meaning; file and tree digests; re-digest at conclusion | open, conclude, show | #input #integrity |
| `guard/mask.py` | Mask credentials in free text with 001-B patterns | record, review, accept-risk, keep | #security |
| `guard/records.py` | Validate plan, record (evidence/findings/ledger/conflicts) and Reviewer envelope against run state | plan, record, review | #validation |
| `guard/engine.py` | Pure conclusion: finalize ledger, review validity, finding review state, severity, verdict + reasons → structured result dict | conclude | #core #deterministic |
| `guard/report.py` | Render Markdown from the structured result (result digest footer) | conclude, accept-risk | #output |
| `guard/runs.py` | Run id allocation, run folder, `state.json` read/write, result/report paths, guard lock, keep marker, cleanup selection | all commands | #storage |
| `guard/service.py` | Command functions → `Result` (root checks, lock, scope load, write order) | CLI/library | #core |
| `policy/service.py` (extended) | `load_adopted(root, scope_id, command)` shared by `scope show` and Guard (no second scope reader) | scope show, guard | #reuse |
| `auth/interaction.py` (extended) | `prompt_text` for the typed finding ID | accept-risk | #interaction |
| `cli.py` (extended) | `guard` sub-commands | Public CLI | #cli |
| Guard `SKILL.md` + `references/guard-records.md`; Framework `references/cli-contract.md`, toolkit `README.md` | Agent procedure and file formats | Agent behaviour | #skills |

### Dependencies

| Dependency | Source | Design Link | Usage |
|---|---|---|---|
| `scope.read_record`, `scope.load_scope`, `policy.service._snapshot` (knowledge lock), `resolve.COMPLETE/PARTIAL/MAINTENANCE_NEEDED` | FEATURE-001-C | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/technical-design.md) | Adopted scope at open; Policy drift at conclude |
| `precheck.CREDENTIALS`, `ASSIGNMENT`, `AWS_DOC_EXAMPLES`, `is_placeholder`; `store.PRIVATE_REL`, `store.ensure_safe` | FEATURE-001-B | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/technical-design.md) | Masking; private layout; symlink-safe paths |
| `projects.knowledge_root`, `paths.safe_relative`, `paths.unsafe_component`, `Result`, `atomic_write_bytes`, `dumps_json`, `ProcessLock`, `LockHeld`, `TerminalInteraction`; layout `x-ipe-docs/secure-code/reports/guard` | FEATURE-001-A | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md) | Root, envelope, atomic writes, lock, interactive gate, report folder |

### Major Flow

1. **Scope (agent):** take explicit targets from the request; ask only for unclear project/baseline/targets; whole project only on explicit choice; get the adopted `scope_id` (Framework "Selecting Policies").
2. **Open (script):** root → request file → paths/roles/change meaning → guard lock → knowledge lock: load scope (must be `complete`) → digests → allocate `gv-…` id → write `state.json` → Result (id, targets, adopted rules).
3. **Plan (agent → script):** agent maps adopted Policies to necessary checks (object, method, minimum evidence), N/A Policies with factual reasons, user exclusions → `guard plan` validates coverage and adopted-only rules → stored once.
4. **Review work (agent → script):** semantic review → `guard record` evidence (masked, stored in `evidence/`), findings, ledger states, conflicts (repeatable, append/replace by id).
5. **Independent review (agent → Reviewer → script):** one read-only Reviewer per batch through the host, given only summaries and evidence locations; agent records its result with reviewed digests → `guard review` (incomplete records stored, flagged at conclusion; extra-authority parts refused).
6. **Conclude (script):** guard lock → re-digest targets, reload scope → `engine.conclude(state, observations)` → write `<id>.json` (commit point) → render `<id>.md` → state `finished` + `ended_at` → Result with verdict and reasons.
7. **Afterwards:** `show` (evidence availability, report consistency, targets changed since), `accept-risk` (User, interactive), `keep`/`release`, `cleanup` (finished > 30 days, no keep marker).

### Usage Example

```bash
FW=.github/skills/x-ipe-secure-code-toolkit-framework
uvx --from $FW/scripts secure-code guard open --project . --request .x-ipe/private/secure-code/tmp/open.json --json
uvx --from $FW/scripts secure-code guard plan --project . --run gv-20261019T081500Z-3fa9c2d1 --request .x-ipe/private/secure-code/tmp/plan.json --json
uvx --from $FW/scripts secure-code guard record --project . --run gv-… --request .x-ipe/private/secure-code/tmp/record-1.json --json
uvx --from $FW/scripts secure-code guard review --project . --run gv-… --request .x-ipe/private/secure-code/tmp/review-1.json --json
uvx --from $FW/scripts secure-code guard conclude --project . --run gv-… --json
uvx --from $FW/scripts secure-code guard show --project . --run gv-… --json
secure-code guard accept-risk --project . --run gv-… --finding F1 --reason "Accepted until Q3 rewrite"   # User, interactive terminal
uvx --from $FW/scripts secure-code guard cleanup --project . --json
```

### Tool Capability Summary

`stages.implement.technical_design`: all implementation tools enabled, consultation only (`_extra_instruction`: informational, no code execution). Matched: `x-ipe-tool-implementation-python` (PEP 8, type hints, pytest, ruff, TDD). Not matched: html5, typescript, java, mcp, general (no other stack). Toolkit remains a standalone product, not built via skill-creator (FEATURE-001-A user decision).

---

## Part 2: Implementation Guide

### Files and Layout

```text
.x-ipe/private/secure-code/locks/guard.lock                  # global Guard lock (created on first use)
.x-ipe/private/secure-code/guard/<id>/state.json             # run state (private 0600)
.x-ipe/private/secure-code/guard/<id>/evidence/<E-id>.txt    # masked raw evidence
.x-ipe/private/secure-code/guard/<id>/keep.json              # keep marker {reason, set_at}
x-ipe-docs/secure-code/reports/guard/<id>.json               # structured result (canonical)
x-ipe-docs/secure-code/reports/guard/<id>.md                 # Markdown report rendered from it
scripts/src/x_ipe_secure_code/guard/{__init__,model,targets,mask,records,engine,report,runs,service}.py
scripts/tests/guard/test_guard_engine.py                     # unit: verdict, severity, review validity, ledger
scripts/tests/guard/test_guard_units.py                      # unit: targets/digests, mask, records validation
scripts/tests/guard/test_guard.py                            # integration: service + CLI subprocess per AC
<guard skill>/references/guard-records.md                    # request file formats for the agent
```

Estimated sizes: engine ~280, records ~320, service ~380, others < 200 lines (all < 800).

Verification id: `gv-<UTC YYYYMMDDTHHMMSSZ>-<8 hex>` (regex `gv-\d{8}T\d{6}Z-[0-9a-f]{8}`); allocated under the guard lock with exclusive `mkdir`. Any `--run` not matching the regex → `RUN_NOT_FOUND` (never used as a path).

### Input Bounds (all request files, `records.py`)

| Limit | Value | Refusal |
|---|---|---|
| Request file (open, plan, record, review) | ≤ 4 MiB | command's `*_INVALID` / `REQUEST_INVALID` |
| Items per list (targets, checks, evidence, findings, ledger, conflicts, subjects, …) | ≤ 1000 | same |
| Free-text field (everything masked except evidence `content`) | ≤ 8 KiB | same |
| Evidence `content` (inline) | ≤ 1 MiB (exempt from the 8 KiB rule) | `RECORD_INVALID` |
| Evidence `content_file` | ≤ 16 MiB | `RECORD_INVALID` |
| Stored evidence per run (cumulative) | ≤ 256 MiB | `EVIDENCE_QUOTA` |
| `--reason` (keep, accept-risk) | ≤ 8 KiB | `REQUEST_INVALID` |

Unit tests at limit / just above for each row; cumulative quota across two records (integration).

### Open Request (`guard open --request FILE`)

```json
{"schema": "ai-secure-code-toolkit/guard-open/v1",
 "scope_id": "sha256:…",
 "request": "Verify the login change before merge",
 "baseline": "main@4be1c0d (recorded only)",
 "whole_project": false,
 "targets": [{"path": "src/login.py", "change": "modified"},
             {"path": "src/tokens.py", "change": "added"},
             {"path": "src/legacy_auth.py", "change": "deleted"},
             {"path": "src/session.py", "change": "renamed", "old_path": "src/sess.py"},
             {"path": "docs/design/login.md"}],
 "context": [{"path": "README.md"}],
 "suggested": [{"path": "src/util.py", "reason": "called by login"}],
 "copilot_reports": [{"path": "x-ipe-docs/secure-code/reports/copilot/c-1.md"}]}
```

Validation (`targets.py`, all refusals name the path and give one next step):

| Rule | Code |
|---|---|
| Request file ≤ 4 MiB, UTF-8 JSON object, `schema` exact, unknown keys refused | `REQUEST_INVALID` |
| `scope_id` absent/empty | `MAINTENANCE_NEEDED` (next: Framework "Selecting Policies") |
| `targets` empty and `whole_project` false | `TARGETS_REQUIRED` |
| target path `.`/empty-equivalent without `whole_project: true` | `WHOLE_PROJECT_NOT_EXPLICIT` (02c) |
| `whole_project: true` with other targets | `REQUEST_INVALID` |
| path not project-relative (`safe_relative`), any existing component a symlink (`unsafe_component`) | `TARGET_INVALID` (02f) |
| non-deleted target / context / suggested / copilot report does not exist | `TARGET_INVALID` (02f) |
| `deleted` target that exists | `TARGET_INVALID` |
| `renamed` without `old_path`; `old_path` on other changes | `REQUEST_INVALID` |
| same path in two roles or twice in one role | `ROLE_CONFLICT` (02d) |
| path under `.x-ipe/private/` | `TARGET_INVALID` (private toolkit data) |

`change` ∈ `added | modified | deleted | renamed | unspecified` (default `unspecified`: verify the artifact as it is).

Digests: file → `sha256:<hex of bytes>`; directory (incl. whole project `.`) → `sha256:` of canonical sorted lines — regular file `"<rel>\0file\0<sha256>\n"`, symlink `"<rel>\0link\0<readlink text>\n"`, other entry `"<rel>\0special\n"` — so adding, removing or retargeting a link or special entry changes the digest (re-review fix), over regular files only, never following symlinks, skipping the excluded prefixes `.git/`, `.x-ipe/private/`, `x-ipe-docs/secure-code/`; symlinks are listed in `not_followed` with `inside_tree: bool` (resolved target inside the directory target), special files and dangling links in `unreadable`; any outside/dangling/special entry → `incomplete: true`. The target entry stores `incomplete`, `not_followed` and `unreadable` at open and again at conclusion; `TARGET_INCOMPLETE` if **either** snapshot is incomplete (re-review fix). Tree mutation while hashing yields a digest that differs at conclusion → `TARGET_CHANGED` (fail closed). `deleted` → `null`. Context and Copilot reports are hashed too (reported, not verified). Suggested files are recorded without digest (not verified).

Scope: `policy.service.load_adopted(root, scope_id, command)` (new shared helper extracted from `show_scope`; reads the record, snapshots under the knowledge lock, returns `load_scope` data or a refused `Result`). `complete` → proceed; `partial` → `SCOPE_PARTIAL` with `entries` grouped `adopted / needs_reconfirmation / missing` and next step "confirm a new scope (secure-code scope save)" (03b); `maintenance_needed` → `MAINTENANCE_NEEDED` (03a); unknown id → `SCOPE_NOT_FOUND`. No report or run folder is written on refusal.

State written at open:

```json
{"schema": "ai-secure-code-toolkit/guard-run/v1", "verification_id": "gv-…", "status": "open",
 "opened_at": "2026-10-19T08:15:00Z", "ended_at": null, "request": "…", "baseline": "…",
 "scope": {"scope_id": "sha256:…", "mode": "clues", "adopted": [{"rule": "CWE/4.14/CWE-79", "state_digest": "sha256:…"}]},
 "artifact": {"whole_project": false,
              "targets": [{"path": "src/login.py", "kind": "file", "change": "modified", "old_path": null, "digest": "sha256:…", "incomplete": false, "not_followed": [], "unreadable": []}],
              "context": [{"path": "README.md", "kind": "file", "digest": "sha256:…"}],
              "suggested": [{"path": "src/util.py", "reason": "called by login"}],
              "copilot_reports": [{"path": "…", "digest": "sha256:…"}]},
 "plan": null, "evidence": [], "findings": [], "ledger": {}, "conflicts": [], "reviews": []}
```

### Plan (`guard plan --request FILE`, once per run)

```json
{"schema": "ai-secure-code-toolkit/guard-plan/v1",
 "checks": [{"id": "C1", "rule": "CWE/4.14/CWE-79", "object": ["src/login.py"], "object_part": "render_error()",
             "methods": [{"name": "semantic-review", "kind": "reading", "required": true},
                         {"name": "opengrep", "kind": "runtime", "required": false}],
             "minimum_evidence": ["reading", "runtime"], "description": "Output encoding of user input"}],
 "not_applicable": [{"rule": "CWE/4.14/CWE-89", "reason": "No database access in the targets"}],
 "exclusions": [{"rule": "@ACME/v1/ACME-7", "reason": "User: verify later with the platform team"},
                {"check": "C4", "reason": "User excluded for this run"}]}
```

Validation (`records.validate_plan`) → `PLAN_INVALID` naming the entry (nothing stored):
- ids `[A-Za-z0-9._-]{1,40}`, unique across checks; `rule` (checks, N/A, exclusions) must be in `scope.adopted` (03d); `object` non-empty, each path a recorded target (deleted allowed for impact checks); `methods` non-empty, `kind` ∈ `document | reading | runtime | reviewer`, method names unique per check; `minimum_evidence` non-empty subset of kinds (04a); N/A `reason` non-empty (04b); exclusions name exactly one of `rule`/`check` (existing) with non-empty `reason` (04f).
- Coverage: every adopted rule appears in ≥ 1 check, N/A entry or rule exclusion → else `PLAN_INCOMPLETE` listing rules (no silent omission). The plan need not pair every file with every rule (04b).
- Second plan → `PLAN_EXISTS`; `record`/`review` before a plan → `PLAN_REQUIRED`.

### Record (`guard record --request FILE`, repeatable until conclusion)

```json
{"schema": "ai-secure-code-toolkit/guard-record/v1",
 "evidence": [{"id": "E1", "kind": "reading", "method": "semantic-review", "method_status": "ok",
               "checks": ["C1"], "paths": ["src/login.py"], "lines": "40-58",
               "summary": "error message echoes the username without encoding",
               "content": "optional raw excerpt", "content_file": null}],
 "findings": [{"id": "F1", "rule": "CWE/4.14/CWE-79", "check": "C1", "location": {"path": "src/login.py", "line": 52},
               "cwe": "CWE-79", "title": "Reflected XSS in error page", "description": "…", "source": "semantic",
               "severity": "high", "evidence": ["E1"], "disputed": false, "related": [],
               "merged_from": [], "merge_evidence": []}],
 "ledger": [{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"], "reason": "…"},
            {"check": "C2", "state": "n/a", "reason_type": "objective", "reason": "no template output in object"}],
 "conflicts": [{"id": "K1", "kind": "requirement", "description": "…", "verdict_affecting": true,
                "resolved": false, "resolution": null, "evidence": []}]}
```

Validation (`records.validate_record`) → `RECORD_INVALID` naming the entry; the whole file is applied atomically or not at all:
- Ids (evidence, finding, conflict, check): regex `[A-Za-z0-9][A-Za-z0-9._-]{0,39}` (no separators, no leading dot), unique run-wide per kind.
- Evidence: `kind` ∈ kinds; `method` must be a method of **every** listed check and its declared `kind` must equal the evidence `kind` (review fix: a reading item can never stand for a runtime method); `method_status` ∈ `ok | failed`; `paths` non-empty, each a recorded path (target, path under a directory target, context, Copilot report); `summary` non-empty. `content` ≤ 1 MiB or `content_file` = project-relative `safe_relative` path, every component non-symlink (`unsafe_component`), regular file ≤ 16 MiB, not under `.x-ipe/private/secure-code/guard/` (agents write tool output to `.x-ipe/private/secure-code/tmp/`), read UTF-8 `errors="replace"` → masked and stored to `evidence/<id>.txt` (destination resolved and checked to stay inside the run's `evidence/`); item stores `stored`, `masked: bool`, `masked_types` (01c, 01d). Raw output never enters `state.json` or reports.
- Bounds: see Input Bounds.
- Findings: adopted `rule`, optional `check` must exist, `location.path` a target or a path under a directory target, `severity` ∈ `critical | high | medium | low | info | unknown`, `source` non-empty (`semantic` or a tool name), `evidence` ids exist; `merged_from` ids must exist and differ from the finding, with ≥ 1 `ok` `merge_evidence` item whose paths include the location of every merged finding (05a). A merge is a label (`merged_into` on the sources): every finding, merged or not, still enters review and verdict (review fix).
- Ledger: `check` exists; `state` ∈ `met | not_met | unconfirmed | n/a`; `met` needs ≥ 1 evidence id; `not_met` needs evidence or findings; `unconfirmed` needs `reason`; `n/a` needs `reason_type: "objective"` and `reason` — `reason_type` `method_unavailable | not_executed | evidence_missing` → refused `NA_NOT_OBJECTIVE`, next step "record it as unconfirmed" (04e). A later entry for the same check replaces the earlier one (history kept as `superseded` count only).
- Conflicts: unique id or replacement of the same id; `kind` ∈ `requirement | severity | evidence`; resolving needs `resolution` and ≥ 1 evidence id.
- Strings are classified centrally (`records.py` schema tables): structural values (ids, paths, enums, digests, rule refs, line numbers) must match strict patterns; **every other string** in open/plan/record/review/keep/accept-risk inputs (request, baseline, object part, descriptions, method names and sources are both pattern-checked `[A-Za-z0-9._-]{1,60}`, summaries, titles, reasons, bases, resolutions, suggested reasons, invocation host/agent text, content) passes through `mask.mask_text` before persistence (review fix).

### Reviewer Record (`guard review --request FILE`) — shared envelope

```json
{"schema": "ai-secure-code-toolkit/reviewer-record/v1",
 "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": true, "invoked_at": "2026-10-19T08:40:00Z"},
 "requirement": "Re-check F1, F2 and the N/A decision for C2 against CWE-79",
 "reviewed_targets": [{"path": "src/login.py", "digest": "sha256:…"}],
 "subjects": [{"type": "finding", "id": "F1", "result": "confirmed", "basis": "…", "evidence": ["E1"],
               "severity_opinion": {"severity": "medium", "evidence": ["E3"]}},
              {"type": "na_decision", "id": "C2", "result": "confirmed", "basis": "…"},
              {"type": "na_decision", "id": "policy:CWE/4.14/CWE-89", "result": "rejected", "basis": "…"}]}
```

- **Refused** (`REVIEW_AUTHORITY`, nothing stored) if it carries any of `targets`, `scope`, `scope_id`, `plan`, `ledger`, `findings`, `evidence`, `conflicts`, `risk_acceptances`, `exclusions` (05g); `REVIEW_INVALID` if not a JSON object, wrong schema, or a subject type other than `finding | na_decision` (`adoption` belongs to FEATURE-003-A) or unknown subject id.
- **Stored but incomplete** (validity decided at conclusion, `completeness` warnings returned now): missing/empty `invocation.host`, `invocation.agent`, `invocation.read_only is true`, `requirement`, `reviewed_targets`, any subject `result` (05e). `result` values: finding `confirmed | false_positive | unconfirmed`; na_decision `confirmed | rejected`. `false_positive` needs ≥ 1 evidence id; `severity_opinion.severity` must be a known severity (not `unknown`).
- `false_positive` and evidenced `severity_opinion` need evidence ids that exist, have `method_status: ok` and whose paths include the finding's location path (or its owning directory target) — otherwise `REVIEW_INVALID` naming the subject (review fix: unrelated evidence never dismisses or lowers a finding).
- Text fields masked; record stored with `index` (order of recording).

### Conclusion Engine (`engine.conclude(state, now_digests, policy_state) -> dict`)

Pure function; inputs are the run state, current target digests (from `targets.redigest`) and current adopted state per rule (from `load_adopted`: `unchanged | changed | missing`). No clock, no I/O; `ended_at` is passed in. Steps:

1. **Review validity** (in recording order): invalid reasons = incomplete fields (05e); any reviewed path not a target, or reviewed digest ≠ current digest → `stale` (05f); a subject whose relevant path (finding location; check object; all targets for `policy:` N/A) is not in `reviewed_targets` → `not_bound`; relevant path of a descendant location is its owning directory target. Only valid records apply. For each subject, all valid records must agree on `result` and on `severity_opinion.severity`; any disagreement → subject `unconfirmed` and blocker `REVIEW_DISAGREEMENT` (review fix, 06f). Recording order never decides.
2. **Severity** per finding (06e/06c): `opinion` from the winning finding subject.

   | Original | Opinion | Evidence for opinion | Final | `severity_conflict` |
   |---|---|---|---|---|
   | any | none | — | original | false |
   | any | X | yes (bound evidence, see Reviewer Record) | X | X ≠ original |
   | unknown | ≥ medium | no | X | true |
   | unknown | low/info | no | unknown | true |
   | known | X | no | higher of the two | X ≠ original |

3. **Finding review state:** `requires_review` = final or original severity `unknown` or ≥ medium, or `disputed`. Winning subject `confirmed`/`false_positive`/`unconfirmed` → that state; no valid subject → `unconfirmed` if `requires_review`, else `not_required` (05b, 05d). Merged findings keep their own review state (merge is a label).
4. **Ledger finalization** per planned check (04c…04j):
   - excluded check → `excluded` (separate from N/A and met, 04f);
   - no entry → `unconfirmed`, reason `not executed` (04g);
   - `n/a` → kept only if a valid winning `na_decision` subject is `confirmed`, else `unconfirmed` with reason `N/A not confirmed by a valid review` / `N/A rejected by review` (04h);
   - `met` → accepted only if (a) ≥ 1 referenced evidence item has `method_status: ok`, `kind` ∈ `minimum_evidence`, lists this check and has a path in the check object or under it (context/Copilot-only paths never count, 02b/02d), and (b) every `required` method has ≥ 1 `ok` evidence item of that method (kind equal by validation) listing this check with an object path; else `unconfirmed` naming the missing kind/method (04d, 04j). Failed auxiliary methods with substitution are listed as `substitution` (04j).
   - Policy-level N/A → `policy:<rule>` ledger row `n/a` if confirmed, else `unconfirmed`.
   - Output row keeps `recorded_state` and final `state`; evidence grouped by kind (04i).
5. **Changes:** target digest differs (incl. deleted re-appearing, existing target vanished) → `TARGET_CHANGED`; adopted rule `changed`/`missing` → `POLICY_CHANGED` (06j).
6. **Verdict** (06a…06k, BR-08):
   - `fail` = confirmed findings with final severity ∈ {medium, high, critical} (not false positive; Info/Low never) → **Fail**, reason `CONFIRMED_FINDING` per finding.
   - `blockers` = `CHECK_UNCONFIRMED` per check, `CHECK_NOT_MET` (not met and no confirmed Medium+ finding), `SCOPE_EXCLUSION` per exclusion, `FINDING_UNCONFIRMED` per verdict-affecting unconfirmed finding, `SEVERITY_UNKNOWN` per confirmed unknown-severity finding, `CONFLICT_UNRESOLVED` per unresolved verdict-affecting conflict, `TARGET_CHANGED`, `POLICY_CHANGED`, `NO_PLAN` when no plan was recorded (plan coverage guarantees every adopted rule is a check, N/A or exclusion; a plan whose rules are all reviewed objective N/A can Pass).
   - `TARGET_INCOMPLETE` per directory target with symlinks outside the tree, dangling links or special files; `REVIEW_DISAGREEMENT` per disagreeing subject.
   - verdict = `fail` if fail reasons; else `cannot_confirm_pass` if blockers; else `pass` with reason `ALL_CHECKS_SATISFIED`. Reasons always list the determining group; `other_blockers` lists remaining blockers under Fail (06g).
7. Output: structured result (below), keys and lists in deterministic order (sorted by id/path; reviews by index). Same inputs → identical bytes via `dumps_json` (06h).

### Structured Result (`reports/guard/<id>.json`)

```json
{"schema": "ai-secure-code-toolkit/guard-result/v1", "verification_id": "gv-…",
 "opened_at": "…", "ended_at": "…", "verdict": "fail | cannot_confirm_pass | pass",
 "reasons": [{"code": "CONFIRMED_FINDING", "subject": "F1", "detail": "high, confirmed"}], "other_blockers": [],
 "scope": {"scope_id": "…", "mode": "clues", "adopted": [{"rule": "…", "state_digest": "…", "at_conclusion": "unchanged"}]},
 "artifact": {"whole_project": false, "targets": [{"path": "…", "change": "…", "old_path": null, "digest_at_open": "…", "digest_at_conclusion": "…", "changed": false, "incomplete": false, "not_followed": [], "unreadable": []}],
              "context": [], "suggested": [], "copilot_reports": [], "not_verified": ["context and suggested files are not verified"]},
 "plan": {…}, "ledger": [{"check": "C1", "rule": "…", "object": [], "state": "…", "recorded_state": "…", "reason": "…", "evidence_by_kind": {"reading": ["E1"]}, "findings": [], "substitution": []}],
 "evidence": [{"id": "E1", "kind": "reading", "method": "…", "method_status": "ok", "paths": [], "lines": "…", "summary": "…", "stored": "evidence/E1.txt", "masked": false}],
 "findings": [{"id": "F1", "…": "…", "original_severity": "high", "severity_opinion": null, "final_severity": "high", "severity_conflict": false, "requires_review": true, "review": "confirmed", "review_basis": "…", "review_record": 0}],
 "reviews": [{"index": 0, "valid": true, "invalid_reasons": [], "invocation": {"…": "…", "declared": true}, "requirement": "…", "subjects": []}],
 "conflicts": [], "risk_acceptances": [],
 "evidence_retention": {"location": ".x-ipe/private/secure-code/guard/gv-…/", "days_after_end": 30, "removal": "explicit secure-code guard cleanup"},
 "limits": ["Reviewer invocation is declared by the agent, not proven", "Adapters not available: runtime checks need FEATURE-002-B/D/E"]}
```

### Markdown Report (`report.render(result) -> str`)

Order (UI/UX requirement): title + verification id → **Verdict** and every reason (and other blockers) → Scope (targets with digests and change meaning; read-only context, suggested and Copilot reports marked *not verified*; adopted scope id and rules) → Check plan → Ledger (state, evidence by kind, reasons, substitutions; no percentage) → Findings (original/final severity, conflict, review state and basis, evidence locations) → Reviewer records (validity and reasons; "invocation declared, not proven") → Conflicts → Risk acceptances (or "none") → Evidence retention (location, 30 days, explicit cleanup). Footer: `<!-- guard-result-sha256: <hex of the JSON bytes> -->`. All text comes from the (already masked) result. Every inserted agent string is neutralized by one `md_text()` helper: control characters stripped, newlines collapsed to spaces, `\ ` `` ` `` `* _ [ ] < > # | !` escaped (no raw HTML, headings, links or images), so agent text can never spoof a verdict line or section (review fix).

### Commands and Write Order (`service.py`)

All writes under `ProcessLock(locks/guard.lock, create=True)`; `LockHeld` → `LOCKED`. Paths checked with `store.ensure_safe` (no symlinked `guard/`, run folder, `reports/guard/`).

| Command | Options | Behaviour | Exit |
|---|---|---|---|
| `guard open` | `--project`, `--request FILE`, `--json` | Validate → scope load (knowledge lock nested inside guard lock; fixed order) → mkdir run → `state.json` | 0 opened; 1 refusal |
| `guard plan` | `--project`, `--run ID`, `--request FILE`, `--json` | Validate vs state → store plan | 0 / 1 |
| `guard record` | same | Validate all → write evidence files → state (atomic) | 0 / 1 |
| `guard review` | same | Validate envelope → append with `index`; data `completeness` | 0 / 1 |
| `guard conclude` | `--project`, `--run ID`, `--json` | If `<id>.json` exists (the commit point, authoritative even when `state.json` still says `open`): repair `.md` if missing/mismatched, set state finished if needed, return stored result (idempotent). Else redigest + `load_adopted` (scope missing/unreadable → all rules `missing`) → engine → write `<id>.json` (commit point) → `<id>.md` → state `finished`, `ended_at` | 0 concluded (any verdict); 1 refusal |
| `guard show` | `--project`, `--run ID`, `--json` | Read result; `evidence_available` (run folder exists, 01g); `report_consistent` (md footer); `targets_now`: `unchanged | changed` by redigest (01h: "this report does not describe the current version" when changed). Read-only | 0 / 1 |
| `guard accept-risk` | `--project`, `--run ID`, `--finding F`, `--reason TEXT` | Interactive check first (`INTERACTIVE_REQUIRED`, nothing recorded, regardless of Maintainer authorization, 07d) → result must exist (`NOT_CONCLUDED`) with verdict `fail` (`NOT_ACCEPTABLE`, 07a) → finding exists (`FINDING_NOT_FOUND`) → prompt "Type the finding ID to confirm" **outside the lock** → mismatch `CONFIRMATION_MISMATCH` → take lock, re-read and revalidate the result → delete `<id>.md` → atomically write JSON with appended `{finding, reason (masked), role: "user", recorded_at}` → render md (a crash leaves md missing, never contradictory; `conclude` repairs). Verdict/findings untouched (07a); never copied to other runs (07b) | 0 / 1 |
| `guard keep` | `--project`, `--run ID`, `--reason TEXT` | Run folder must exist; write `keep.json` | 0 / 1 |
| `guard release` | `--project`, `--run ID` | Remove `keep.json` (absent → ok, `released: false`) | 0 / 1 |
| `guard cleanup` | `--project`, `--json` | For each run folder (valid id, real non-symlink dir; otherwise `skipped`): concluded = `<id>.json` exists or state `finished` (`ended_at` from the result when present); not concluded → kept `running`; `keep.json` → kept with reason; finished and `now − ended_at > 30 days` → `shutil.rmtree`; else kept `retained until <date>`. Unknown entries listed `skipped`. Never touches reports. Reading never changes `ended_at` (01e) | 0 / 1 |

`plan/record/review` check result existence as well as state: either → `RUN_FINISHED` (review fix: no record after the commit point). Unknown/invalid id → `RUN_NOT_FOUND`. `state.json` unreadable/invalid → `RUN_INVALID`.

Interaction: `auth.interaction.Interaction` gains `prompt_text(prompt) -> str | None` (`input()`, EOF/interrupt → None); `accept_risk(..., interaction=TerminalInteraction())` for test injection like `auth.service`.

### CLI Contract (additions)

New problem codes: `TARGETS_REQUIRED`, `WHOLE_PROJECT_NOT_EXPLICIT`, `TARGET_INVALID`, `ROLE_CONFLICT`, `SCOPE_PARTIAL`, `RUN_NOT_FOUND`, `RUN_INVALID`, `RUN_FINISHED`, `PLAN_REQUIRED`, `PLAN_EXISTS`, `PLAN_INVALID`, `PLAN_INCOMPLETE`, `RECORD_INVALID`, `NA_NOT_OBJECTIVE`, `REVIEW_INVALID`, `REVIEW_AUTHORITY`, `NOT_CONCLUDED`, `NOT_ACCEPTABLE`, `EVIDENCE_QUOTA`, `FINDING_NOT_FOUND`, `INTERACTIVE_REQUIRED`, `CONFIRMATION_MISMATCH`; reused `REQUEST_INVALID`, `MAINTENANCE_NEEDED`, `SCOPE_NOT_FOUND`, `SCOPE_INVALID`, `PROJECT_NOT_INITIALIZED`, `LOCKED`, `PATH_UNSAFE`, `IO_ERROR`. Every refusal has exactly one next step.

### Guard SKILL.md Procedure (02g, 05h, 07c, 08b)

Replace "Status of This Skill" with "Verifying" sections: (1) readiness `status`; (2) artifact scope — use explicit targets as given, ask only for unclear project/baseline/targets, whole project only on an explicit user choice, list context and suggested files separately, record change meaning; (3) adopted scope via Framework "Selecting Policies" (`maintenance_needed`/`partial` → stop and report, never verify against invented rules); (4) plan necessary checks with object, method, minimum evidence; N/A only with a factual reason; user exclusions as exclusions; (5) review and record evidence/findings/ledger — say `unconfirmed` when evidence is missing; until Adapters exist runtime evidence is unavailable; (6) one independent read-only Reviewer per batch through the host with only relevant summaries and evidence locations (bounded context, R-09), record its result with the reviewed digests; (7) conclude and present the verdict with reasons; (8) risk acceptance only by the User at a terminal — never by the agent or Reviewer, Maintainer authorization is not consent; (9) Guard and its Reviewer never edit business artifacts, never start remediation or automatic re-scans; fixes belong to the current task executor. Keep the existing boundary phrases tested by `test_skill_skeletons.py`. `references/guard-records.md` holds the four request formats with examples.

### Implementation Steps

1. `policy.service.load_adopted` extracted from `show_scope` (001-C tests unchanged = regression).
2. `guard/model.py`, `guard/mask.py` + unit tests (private key block, token, assignment, placeholder untouched).
3. `guard/targets.py` + unit tests (validation table, file/tree digests, exclusions, symlink not followed, deleted/renamed).
4. `guard/records.py` + unit tests (plan coverage, adopted-only, N/A reason types, evidence/finding/ledger refs, merge evidence, reviewer authority/completeness).
5. `guard/engine.py` + unit tests per 06a…06k, 04c…04j, 05b…05f (table-driven).
6. `guard/report.py` (render, footer) + unit test (all sections, identical render twice).
7. `guard/runs.py`, `guard/service.py`, `cli.py`, `auth/interaction.prompt_text`; integration tests per AC through service functions and CLI subprocess (`--json`, exit codes, refusal next steps).
8. Guard `SKILL.md`, `references/guard-records.md`, Framework `references/cli-contract.md`, toolkit `README.md`; skill-package tests (02g, 05h, 07c, 08b).
9. ruff, full suite on macOS 3.14/3.11 and Linux 3.12.

### Edge Cases & Error Handling

| Case | Handling |
|---|---|
| Not initialized / root invalid | `PROJECT_NOT_INITIALIZED` / root error (via `knowledge_root`) |
| Symlinked `guard/`, run folder, `reports/guard/`, evidence file | `PATH_UNSAFE`, nothing written |
| Targets change during the run | Detected at conclusion; reviews stale; `TARGET_CHANGED` |
| Scope record deleted/tampered before conclusion | All recorded rules `missing` → `POLICY_CHANGED` (no crash) |
| Concluded twice / crash after result write | Idempotent; md repaired from result; state set finished |
| Crash before result write | Run stays `open`; conclude can be run again (recomputes) |
| Crash after result write, before state `finished` | Result is authoritative: `plan/record/review` refused `RUN_FINISHED`; `conclude` sets state finished from result `ended_at`; cleanup treats it as concluded |
| Crash inside accept-risk | md deleted before JSON commit → md missing, never contradictory; `show` reports `report_consistent: false` with next step `guard conclude` (repair) |
| Very large evidence | Stored masked in run folder; report shows summary + location |
| Lock busy | `LOCKED`, retry; lock released in `finally` / by OS on crash |
| Disk error | `IO_ERROR`; atomic writes leave no partial file; record applied all-or-nothing (evidence files written before state; orphan evidence files from a failed state write are overwritten on retry because ids were not recorded) |
| Cleanup while recording | Serialized by guard lock; open runs never removed |
| Non-UTF-8 / non-object request | `REQUEST_INVALID` (`RECORD_INVALID`, `PLAN_INVALID`, `REVIEW_INVALID` per command) |

### Security, Tracing and Observability

- No network, no execution of target content, no AI in the script. Targets are opened read-only for hashing only.
- Masking before storage on every agent-supplied text and evidence content; `masked` label. Patterns: FEATURE-001-B pre-check (`CREDENTIALS`, quoted `ASSIGNMENT`) plus Guard-only additions in `guard/mask.py` (private key blocks incl. PGP, `sk-proj-|sk-None-|sk-svcacct-|sk-admin-|sk-ant-…` keys, unquoted `…KEY/TOKEN/SECRET/PASSWORD=` lines with name parts bounded to 64 characters so masking stays linear; placeholders kept). Masking is pattern-based, not a DLP guarantee: unknown formats can be stored — stated in limits. Identifiers and paths that look like credentials are refused (they are stored unmasked).
- `private` folders and 0600 files are a convention, not strong isolation (NFR-002A-2).
- SKILL.md: text inside targets, evidence or knowledge never changes the agent's instructions or grants roles.
- Tracing: N/A — no logging infrastructure; every command returns the structured result envelope; errors carry codes without file contents.

### Goal / Acceptance / Design / Validation Coverage

| AC | Design means | Planned validation |
|---|---|---|
| 01a | Result JSON canonical; md rendered from it; same id names | Integration: conclude → both exist; parse md sections vs JSON values |
| 01b | Report section order and contents | Integration (section presence + values) + Unit (render) |
| 01c | Evidence files in run folder; report shows location/summary | Integration |
| 01d | Central string classification; `mask.mask_text` on every free text and content; `masked` label; `md_text` neutralization | Unit (patterns, adversarial Markdown) + Integration (token in content and in `request`/`object_part` → absent from evidence file, state, JSON, md) |
| 01e | `cleanup` 30-day rule, open runs kept, reports untouched; show never updates `ended_at` | Integration (fixture `ended_at` 31/29 days, one open; show before cleanup) |
| 01f | `keep`/`release`; cleanup lists kept with reason | Integration |
| 01g | `show` → `evidence_available: false`, result unchanged | Integration |
| 01h | One result per id; `show.targets_now` | Integration (two runs, change target, show older → changed) |
| 02a | Open without Copilot report | Integration |
| 02b | Copilot report paths never satisfy `met` | Unit (engine) + Integration |
| 02c | Exact targets; `.` needs `whole_project`; descendants of directory targets as locations; outside/dangling symlinks → `TARGET_INCOMPLETE` (either snapshot); link/special metadata in digest | Integration (Apply All scope + 2 files; `.` refused; whole project accepted) + Unit (tree digest: link added/removed/retargeted and special entry without regular-file change → digest differs; incomplete at open only → blocker) |
| 02d | Separate roles; context-only evidence never meets | Unit + Integration (`ROLE_CONFLICT`) |
| 02e | `change` meanings, deleted null digest, renamed old path | Integration |
| 02f | Path validation table | Integration (missing, `../x`, absolute, symlink) |
| 02g | SKILL.md instructions | Skill-package test |
| 03a | `MAINTENANCE_NEEDED` no run folder | Integration (no scope id; scope with all rules changed) |
| 03b | `SCOPE_PARTIAL` with grouped entries | Integration |
| 03c | Scope id, rules, digests in state and result | Integration |
| 03d | Plan rules must be adopted | Integration |
| 04a | Plan field validation | Unit + Integration |
| 04b | N/A reasons; no file×rule pairing; coverage | Unit |
| 04c | One final state per check; no percentage | Unit (engine) + Integration (no `%`/score key) |
| 04d | `met` requires accepted kind; evidence kind must equal method kind | Unit (engine) + Unit (records: reading item naming runtime method refused) |
| 04e | `NA_NOT_OBJECTIVE` | Integration |
| 04f | `excluded` row, `SCOPE_EXCLUSION` blocker | Unit |
| 04g | Missing entry → `unconfirmed` not executed | Unit |
| 04h | N/A needs confirmed valid `na_decision` (check and policy level) | Unit |
| 04i | `evidence_by_kind`, report separate kinds | Unit + Integration |
| 04j | Required vs auxiliary failed methods, substitution | Unit |
| 05a | No auto-merge; merge needs bound evidence; merge is a label (sources still judged) | Unit (records + engine: High merged into Low still blocks/fails) + Integration |
| 05b | `requires_review` → `unconfirmed` without valid review | Unit |
| 05c | Review states + basis kept with original; false positive needs bound ok evidence; disagreeing reviews → unconfirmed | Unit |
| 05d | Reviewer `unconfirmed` stays unconfirmed, never removed | Unit |
| 05e | Incomplete → invalid with reasons | Unit + Integration |
| 05f | Stale digests → invalid, findings back to unconfirmed | Integration (modify target after review) |
| 05g | `REVIEW_AUTHORITY` | Integration |
| 05h | SKILL.md Reviewer instructions | Skill-package test |
| 06a, 06b, 06c, 06d, 06e, 06f, 06g, 06i, 06k | Engine verdict/severity table | Unit (table-driven, one case per AC clause) |
| 06h | Pure engine + `dumps_json`; idempotent conclude | Unit (engine twice) + Integration (conclude twice → identical bytes) |
| 06j | Redigest + `load_adopted` comparison | Integration (edit target; update rule via 001-B) |
| 07a | accept-risk record (Fail only); verdict/findings unchanged | Integration (fake interactive interaction; non-Fail → `NOT_ACCEPTABLE`) |
| 07b | Acceptance only in that result | Integration (second run has none) |
| 07c | SKILL.md prohibition | Skill-package test |
| 07d | Non-interactive / mismatch refused; Maintainer authorization irrelevant | Integration (CLI subprocess non-tty; mismatch with fake; authorized trust store) |
| 08a | Only allowed paths written | Integration (tree hash outside allowed paths before/after) |
| 08b | SKILL.md statement | Skill-package test |
| NFR-002A-3 | Guard lock; result commit point; md repair | Integration (held lock → `LOCKED`; delete md → conclude repairs identical) |

### Outcome Scenario and Evidence Gaps

Scenario (G-02): a Developer asks Guard to verify a login change; Guard opens with two explicit targets and the adopted CWE scope, plans checks, records an XSS finding (High), the Reviewer confirms it → **Fail** with reason; without Reviewer → **Cannot confirm pass**; a check requiring runtime evidence stays unconfirmed until Adapters exist. Observation with real users: **not measured**. Agent behaviour (plan quality, honest ledger states, real Reviewer invocation) is checked only as skill instructions; the script cannot prove a Reviewer sub-agent ran or that a human typed at the terminal beyond the tty check (spec Technical Considerations). Windows behaviour (paths, `msvcrt` lock) designed, not verified (FEATURE-001-A CR-002 deferral).

### Test Plan

`tests/guard/test_guard_engine.py` (pure engine, table-driven), `tests/guard/test_guard_units.py` (targets, mask, records, report), `tests/guard/test_guard.py` (integration per AC; fixtures import rules via the 001-B service with the test trust store and save scopes via 001-C). Existing 241 tests must pass unchanged. Acceptance later reuses the 001-C black-box pattern (real `uvx` CLI; Maintainer fixture steps in the offline container; accept-risk via a pseudo-terminal).

### Mockup-to-Component Mapping

N/A — no UI; no mockups linked.

### Delta and Evidence Invalidation

New feature; no prior 002-A design. Extracting `load_adopted` in `policy/service.py` and adding `prompt_text` to `Interaction` touch 001-C/001-A code without behaviour change; their full test suites are the regression check (their acceptance evidence stays valid only if those tests pass unchanged). The Guard `SKILL.md` skeleton text "Status of This Skill" is replaced; `test_skill_skeletons.py` boundary phrases stay.

## Implementation Evidence (TASK-023, 2026-10-19)

- Files: `guard/{model (≈170 lines), mask (48), targets (≈310), records (≈540), engine (405), report (299), runs (158), service (≈650)}.py`; `policy/service.py` (`load_adopted` extracted, `show_scope` unchanged in behaviour); `auth/interaction.py` (`prompt_text`); `cli.py` (`guard` sub-commands); Guard `SKILL.md` (Verifying procedure) and `references/guard-records.md`; Framework `references/cli-contract.md`; toolkit `README.md`. All modules < 800 lines.
- Tests: `tests/guard/test_guard_units.py` (mask, targets/digests, plan/record/review validation), `test_guard_engine.py` (table-driven verdict/severity/ledger/review rules), `test_guard_report.py` (sections, footer digest, Markdown neutralization), `test_guard.py` (integration per AC via service + CLI subprocess + real pseudo-terminal accept-risk), `test_guard_skill.py` (02g, 05h, 07c, 08b, command names, reference examples are valid requests). TDD: RED = missing modules (`ImportError`) / skill phrases absent before implementation; review regressions RED before each fix (unhashable lookups → traceback, lone-surrogate paths, case-colliding evidence ids, credential-shaped identifiers and paths, wrong digest source in docs). The non-UTF-8 tree-name regression cannot run on macOS (APFS rejects such names); its failure was shown by direct `dumps_json` call and the test runs green on Linux.
- Results (toolkit tree `e263db91…`): **401 passed** on Linux Docker Python 3.12; **400 passed, 1 skipped** (non-UTF-8 names) on macOS Python 3.14 and 3.11; pre-existing 241 tests unchanged and passing; `ruff check` clean. Coverage of new code: engine 98%, mask 100%, model 87%, records 91%, report 99%, runs 88%, service 91%, targets 90%; total 91%.
- Independent code review: 5 findings (unhashable request shapes, lone-surrogate paths and orphan run folder, case-insensitive evidence-id collision, credential-shaped identifiers unmasked, docs naming `guard show` as digest source) fixed test-first; focused re-review confirmed all 5 and found 2 more (credential-shaped paths; non-UTF-8 names inside folder targets) fixed test-first. No false-Pass path found by either review.
- Honest limits unchanged: Reviewer invocation declared not proven; tty check is the only human-presence gate; Windows unverified (CR-002 deferral); stakeholder outcome not measured.

## Design Change Log

| Date | Version | Change | Reason |
|------|---------|--------|--------|
| 10-19-2026 | v1.0 | Initial design | TASK-022 |
| 10-19-2026 | v1.0 | Independent review fixes (10 blocking, 3 non-blocking): evidence kind = method kind; bound evidence for false positive / lower severity; disagreeing reviews → unconfirmed + `REVIEW_DISAGREEMENT`; merge is a label only; `NO_PLAN` replaces `NO_CHECKS` (reviewed all-N/A can pass); tree targets: outside/dangling symlinks and special files → `TARGET_INCOMPLETE`, descendant locations; `content_file` project-relative and safe ids; result JSON authoritative for all mutating commands and cleanup; accept-risk deletes md before JSON commit and prompts outside the lock; central masking of every free-text field and Markdown neutralization; accept-risk only on Fail; input bounds and evidence quota | Rubber-duck design review |
| 10-19-2026 | v1.0 | Re-review fixes: tree digest includes symlink/special metadata and `TARGET_INCOMPLETE` uses both snapshots; one Input Bounds table for all request files (evidence `content` exempt from text limit) with boundary tests | Rubber-duck focused re-review |
| 10-19-2026 | v1.0 | Implementation review fixes (TASK-023): structural identifiers (ids, method names, sources, CWE) that match credential patterns are **refused** rather than masked (masking would break the identifier pattern); evidence ids unique ignoring case (file names on case-insensitive file systems); non-UTF-8 paths refused `REQUEST_INVALID`; state serialized before the run folder is allocated (no orphan folder); unexpected request shapes refused `REQUEST_INVALID` instead of a traceback; reviewed digests come from `guard open` (not `guard show`) | Independent code review |
| 10-19-2026 | v1.0 | Re-review fixes: credential-shaped paths refused in `targets.normalize` (all path fields); non-UTF-8 names found inside folder targets stored escaped (`display_name`) so state/result stay serializable | Focused code re-review |
| 10-19-2026 | v1.0 | Bug Fix TASK-026 (closing review): paths under `.x-ipe/private/`, `x-ipe-docs/secure-code/` or any `.git` component never belong to a folder/whole-project target (`targets.not_in_tree`), so unlisted Copilot reports, Guard reports and agent scratch files cannot meet a check (BR-02); request-file paths in README/design/command hints moved to `.x-ipe/private/secure-code/tmp/`; Guard-only masking patterns added; deeply nested request JSON refused `REQUEST_INVALID`; NFR-002A-2 wording corrected to an honest limit | Closing review |
| 10-19-2026 | v1.0 | Additive extensions by FEATURE-002-B (see [its design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/technical-design.md)): plan `method_choice` (required for several or tool methods), record `method_changes`, reserved Adapter namespace in `guard record`, `adapter_runs` and `next_adapter_run` in run state/result, report sections "Method Choices and Changes" and "Adapter Runs" (shown only when present); 002-A ACs unchanged | FEATURE-002-B TASK-030 |
| 10-19-2026 | v1.0 | TASK-026 fix-review iterations: unquoted-assignment name parts bounded `{0,64}` (quadratic backtracking on degenerate lines, e.g. 78 s for 200 KB → 0.03 s per MiB); `sk-` additions limited to known key prefixes (ordinary `sk-…` slug file names were refused as credentials); `sk-None-` prefix added | Independent fix reviews |
| 10-23-2026 | v1.1 | CR-TASK-086 (human C1 = Yes): additive `renderer` identity in the v1 result and a final report section; see the amendment section below | [CR-TASK-086](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/CR-TASK-086-renderer-version.md) |
| 10-23-2026 | v1.1 | CR-TASK-086 round 2 (independent review FAIL; DAO-003 approval with conditions): B1 stamp in `cancel.finalize_frozen` (both cancellation paths); B2 renderer manifest digest + closure test, unknown never matches; NB3 section "Structured Result Origin" | [CR-TASK-086](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/CR-TASK-086-renderer-version.md) |

## CR-TASK-086 Amendment (v1.1): Renderer Identity

Source: [CR-TASK-086](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/CR-TASK-086-renderer-version.md) (DEC-1…DEC-9 = A by DAO-003, with conditions; round 2 fixes B1, B2, NB3); spec FR-002A-10, AC-002A-01i/01j/01k/01l. Not implemented yet — implement after TASK-076 (FEATURE-002-G) completes, in the serialized code queue (DEC-9).

**Field (structured result, schema id unchanged `ai-secure-code-toolkit/guard-result/v1`, optional key):**

```json
"renderer": {"toolkit_version": "0.1.0", "renderer_digest": "<64 lowercase hex> | null"}
```

- `toolkit_version` = `x_ipe_secure_code.__version__` (what `secure-code --version` prints). It was not bumped across the 002-B/C/D renderer changes, hence the digest.
- **Renderer manifest.** `RENDERER_MANIFEST` in `guard/report.py`: package-relative POSIX paths of every module that affects the report output, kept sorted — today `("atomic.py", "guard/report.py")` (`atomic.dumps_json` produces the footer digest). Any module later imported by `report.py` for rendering (e.g. FEATURE-002-F `helper_report`) is added in the same change. Over-inclusion is allowed (only causes a harmless "renderer differs"); under-inclusion is not (it could make 002-G call a report from a changed renderer "edited").
- **Digest framing.** `renderer_digest = sha256(b"".join(p.encode() + b"\0" + str(len(data)).encode("ascii") + b"\0" + data for p in sorted(RENDERER_MANIFEST)))` where `data` is the binary content of the installed file `<package root>/<p>`. Computed once per process (cached).
- **Unknown.** Any `OSError` reading a component → `renderer_digest = null`; the report shows "renderer unknown"; a `null` identity never counts as equal to any identity (002-G follow-up must treat it as "not recorded").
- Semantics: the build that last wrote this structured result. Declared, not proof. A report re-created later by `_repair_report` under another build is not reflected (DEC-7).

**Component changes (all additive):**

| Module | Change |
|---|---|
| `guard/report.py` | `RENDERER_MANIFEST`; `renderer_identity() -> dict` (cached); `render`: after `## Limits`, before the footer, if `result.get("renderer")`: `## Structured Result Origin` + bullets `Structured result written by secure-code toolkit <md_text(version)>; renderer sha256 <digest or "renderer unknown">` and `This identifies the build that wrote the structured result; a report re-created later by repair may come from a different build`. Without the key: output byte-identical to v1.0 |
| `guard/service.py` `_conclude_open` | `result["renderer"] = report.renderer_identity()` before `runs.create_result_exclusive` |
| `guard/cancel.py` `finalize_frozen` | Same stamp **immediately after** `engine.conclude(...)` (L113) and **before** `runs.create_result_exclusive` (L115). Covers direct `guard cancel` (`cancel` L172 → `finalize_frozen`) and a pending cancellation finalized by `guard conclude` (`service.conclude` L499 → `finalize_locked` L136 → `finalize_frozen`). On `FileExistsError` the stored winner is used unchanged |
| `guard/retention.py` `accept_risk` | Same on the deep-copied result before `runs.write_result` (re-stamp: the Markdown is re-rendered by the current build); verdict, findings and severities untouched (DAO-003 DEC-6 condition) |
| unchanged | `engine.conclude` (pure; output unchanged), `runs.*` (readers check only schema + id), `_repair_report` (renders Markdown only; result bytes unchanged, 06h), `show`, `cleanup`, `keep/release`, CLI, problem codes, Guard SKILL.md |

The key is inside the JSON, so the existing footer `guard-result-sha256` covers it; footer format and `FOOTER` regex unchanged. No migration of existing results.

**Backward compatibility.** Results without `renderer` load, show, conclude (idempotent path), clean up and render exactly as before; `accept-risk` on them adds the stamp. FEATURE-002-G v1 (`guard-result/v1` only; strict validator ignores unconsumed keys) is unaffected; its AC-002G-05l remains true for unstamped results. The 002-G follow-up (DEC-G1 = A) adds the non-accusatory state `renderer_differs`; with equal identity and different Markdown its wording is "edited, or changed by an unrecorded renderer change" — never "tampered".

**Honest limits.** Identity declared by the writing build; a cross-build report repair leaves `renderer` naming the result writer, not the Markdown renderer (DEC-7, stated in the report section); Copilot reports (FEATURE-003-A) out of scope.

**Coverage / planned validation.**

| AC | Design means | Planned validation |
|---|---|---|
| 01i | Stamp at conclusion and in `finalize_frozen`; Structured Result Origin section; footer over JSON incl. `renderer` | Integration: normal conclude; direct `guard cancel`; pending cancellation (marker present) finalized through `guard conclude` → `renderer` == `renderer_identity()`, version == `secure-code --version`; section present with the build-that-wrote wording; footer == SHA-256 of JSON |
| 01j | Optional key; conditional section; readers unchanged | Unit: `render(r)` without key equals delivered output (existing `test_guard_report.py` unchanged) and with key adds exactly the final section; Integration: unstamped fixture through show / conclude / cleanup, bytes unchanged |
| 01k | Re-stamp in `accept_risk` | Integration (`FakeInteraction`): unstamped and foreign-stamped Fail results → current identity; verdict/findings/severities unchanged |
| 01l | Manifest, framing, closure, unknown | Unit: digest equals an independent framed recomputation; changing `guard/report.py` or `atomic.py` bytes (copied package root / patched reader) changes the identity; manifest sorted; closure test: AST scan of `guard/report.py` (and manifest modules under `guard/`) for `x_ipe_secure_code.*` / relative imports ⊆ manifest, with a negative fixture proving the check fails on an unlisted import; unreadable component → `null`, "renderer unknown", never equal |

**Delivered tests.** None must change (CR "Delivered tests" table); DAO-003 condition: if one must change, stop and return to the owner. `test_guard_report.py:18-38` heading list uses unstamped engine output; `test_guard.py:566-575` (06h), `test_guard_cancel.py:107-112`, blackbox NFR-3 run within one build; `test_runs_commit.py` writers untouched; no delivered test calls `finalize_frozen`/`finalize_locked` directly or patches `engine`.

**Delta and evidence invalidation.** Delivered v1.0 implementation/acceptance evidence for AC-002A-01a…08b stays valid until the code changes; after implementation it is re-confirmed by the full suite (no delivered test changes expected). New ACs 01i–01l: planned, not delivered. Documents count as confirmed only after the independent re-review passes (DAO-003 condition 3).
