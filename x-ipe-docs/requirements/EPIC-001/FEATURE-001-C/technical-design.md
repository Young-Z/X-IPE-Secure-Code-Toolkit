# Technical Design: Policy Resolution & Adoption Scope Selection

> Feature ID: FEATURE-001-C | Version: v1.0 | Last Updated: 2026-10-19
> Specification: [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md) · Task: TASK-016 · Depends on: [FEATURE-001-B design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/technical-design.md), [FEATURE-001-A design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md)

## Version History

| Version | Date | Description |
|---------|------|-------------|
| v1.0 | 10-19-2026 | Initial design |

---

## Part 1: Agent-Facing Summary

### Scope & Boundaries

- **Feature:** FEATURE-001-C — `secure-code policy resolve` and `secure-code scope save | show`; Framework SKILL.md "Selecting Policies" section.
- **program_type:** `cli` + `library` (Framework `scripts/`) + `skills` (instructions for the agent).
- **tech_stack:** Python ≥ 3.11 stdlib (`json`, `hashlib`, `os`, `pathlib`), reuse of FEATURE-001-A/B modules; pytest, ruff.
- **Non-goals:** Presets/default Preset/tags (001-F), Reference (001-E), precedence (D-09), policy domains (D-10), recommender (X-13), artifact scope and check plans (002-A), Copilot empty-library wording (D-24), scope-record cleanup.

### Outcome / Goal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 | Spec G-03; FR-09, FR-10 | Developer, upstream agent | Library ≠ suggested ≠ adopted; nothing invented; adopted scope traceable | `policy/resolve.py` (deterministic availability + Policy structure + proposal digest), `policy/scope.py` (decisions → digest-identified record, load with drift detection), SKILL.md procedure (agent interprets clues, asks for confirmation) | Scenario: empty/partial/full libraries; confirm a scope; change a rule; load shows `needs_reconfirmation` | Language advisory; Apply All ≠ artifact scope; no Presets | AC-001C-01*, 02a…02e, 02g, 03*, 04*, 05* | not measured |
| G-05 (enabling) | Spec G-05; P-02 | Owner | Choosing Policies grants no editing rights | No `require_maintainer` call and no knowledge-store write anywhere in `policy/` | Scenario: User saves scope, import still refused | — | AC-001C-01e, 02f | not measured |

### Design Options and Tradeoffs

| Means | Selection | Rationale |
| --- | --- | --- |
| Agent turns clues into concrete references; script resolves deterministically | selected (user decision) | Same split as 001-B; script stays testable and AI-free (NFR-001C-2) |
| Script keyword matching of natural language | rejected (user decision) | Untestable relevance, false confidence |
| Rule state digest = 001-B `item_digest` (already the update base digest) | selected | One concept; no new digest; changes in content, metadata or examples all change it |
| Proposal digest over considered references, their availability and state digests (Apply All: whole library) | selected (review fix) | Detects drift between what the user saw and the save (AC-001C-05f) without storing the proposal |
| Scope record JSON in `x-ipe-docs/secure-code/scopes/<hex>.json`, id = SHA-256 of canonical record without `created_at` | selected (user decision + review fix) | Reports cite a stable identifier; idempotent; tamper-evident; not a Preset/knowledge folder |
| Result-only hand-over, no record | rejected (user decision) | Guard/Copilot are separate invocations; nothing to verify later |
| Store confirmed content snapshot in the scope record | rejected | Would create a second copy of knowledge (snapshot chain, K-12); drift is reported instead |
| Decisions file (JSON) for `scope save` instead of many flags | selected | Notes, reasons and clue text contain spaces/newlines; one validated document |
| Publish under an OS scope lock (`ProcessLock` on `locks/scopes.lock`): check → verify existing → atomic write | selected (review fix) | First writer wins on every OS; identical second save keeps the first `created_at` (AC-001C-05c); crash releases the lock |
| `os.link(temp, final)` with `os.replace` fallback | rejected (review) | Fallback loses exclusivity; filesystem-dependent |
| Policy reads take the knowledge lock creating the lock file if absent (`store.lock(root, write=True)` used only to open/create the lock; no knowledge write) | selected (review fix) | 001-B readers skip locking when the lock file is absent; a snapshot across many rules must not interleave with the first import (NFR-001C-1). Only `.x-ipe/private/secure-code/locks/knowledge.lock` may be created |
| Add `scopes` to the 001-A init layout | rejected | Existing projects would report `LAYOUT_MISSING`; folder is created on first save |

### Key Components Implemented

All under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/`.

| Component | Responsibility | Scope/Impact | Tags |
|-----------|----------------|--------------|------|
| `policy/refs.py` | Parse requested references (`NS/VER/ID`, `NS/ID`) with 001-B component rules | resolve, save | #identity #input |
| `policy/resolve.py` | Library snapshot, per-reference availability, Policy structure, language notes, status truth table, notices, proposal digest | resolve, save, show | #core #contract |
| `policy/scope.py` | Decisions file validation, decision coverage checks, canonical record + id, exclusive publish, record verification, load comparison | save, show | #storage #integrity |
| `policy/service.py` | `resolve`, `save_scope`, `show_scope` → `Result`; root checks, knowledge read lock, `--output` file | CLI/library | #core |
| `cli.py` (extended) | `policy resolve`, `scope save`, `scope show` sub-commands | Public CLI | #cli |
| `results.py` (extended) | Section title for `notices` (highlighted in text output) | All commands | #output |
| SKILL.md + `references/policy-selection.md` (Framework) | Agent procedure: clues → references → resolve → present → confirm → save; decisions file format | Agent behaviour | #skills |

### Dependencies

| Dependency | Source | Design Link | Usage |
|---|---|---|---|
| `store.iter_refs`, `read_rule` (roll-forward read view), `list_pending`, `lock(write=False)`, `ensure_safe`, `LOCAL_REL`; `RuleRef`, identity `_check` rules | FEATURE-001-B | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/technical-design.md) | Formal rules, consistency, pending exclusion |
| `validate_root`, `Result`, `atomic_write_bytes`, `dumps_json`, `unsafe_component`, `LockHeld` | FEATURE-001-A | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md) | Root, envelope, writes, paths |
| `service._root` (knowledge) | FEATURE-001-B | same | Reused for the "not initialized" refusal (moved to a shared helper, no behaviour change) |

### Major Flow

1. **Propose (agent):** read clues → `knowledge list` (+ `show` where needed) → pick concrete references with reasons; no clues → `policy resolve --all`.
2. **Resolve (script):** validate root → read lock → snapshot library (formal rules, pending count) → per reference: parse → availability → Policy entry → status (BR-11) → notices → proposal digest → release → Result (optionally full output to file).
3. **Present and confirm (agent):** show suggested Policies with reasons, language notes, missing/unclear items, agent-judged unclear/conflicts as questions, Apply All highlight; user decides per reference.
4. **Save (script):** `--confirmed` required → load decisions file → read lock → re-resolve considered references → proposal digest must match (else `STALE_CONFIRMATION` naming drift) → coverage checks → release → canonical record → id → exclusive publish → Result with id/path.
5. **Show/load (Guard, Copilot, agent):** read record → verify schema and id → read lock → resolve each adopted reference exactly → compare `item_digest` → adopted / `needs_reconfirmation` / `missing` → load status → Result.

### Usage Example

```bash
FW=.github/skills/x-ipe-secure-code-toolkit-framework
uvx --from $FW/scripts secure-code policy resolve --project . --rule CWE/4.14/CWE-79 --rule @ACME/CWE-89 \
    --language java --json
uvx --from $FW/scripts secure-code policy resolve --project . --all --output .x-ipe/private/secure-code/tmp/all.json --json
uvx --from $FW/scripts secure-code scope save --project . --decisions decisions.json --confirmed --json
uvx --from $FW/scripts secure-code scope show --project . --scope sha256:4be1… --json
```

### Tool Capability Summary

`stages.implement.technical_design`: all implementation tools enabled, consultation only (`_extra_instruction`: informational use, no code execution). Matched: `x-ipe-tool-implementation-python` (PEP 8, type hints, pytest, ruff). Not matched: html5, typescript, java, mcp, general (no other stack). Toolkit remains a standalone product, not built via skill-creator (FEATURE-001-A user decision).

---

## Part 2: Implementation Guide

### Files and Layout

```text
x-ipe-docs/secure-code/scopes/<64-hex>.json          # scope records (created on first save)
scripts/src/x_ipe_secure_code/policy/__init__.py
scripts/src/x_ipe_secure_code/policy/refs.py         # ~60 lines
scripts/src/x_ipe_secure_code/policy/resolve.py      # ~260 lines
scripts/src/x_ipe_secure_code/policy/scope.py        # ~260 lines
scripts/src/x_ipe_secure_code/policy/service.py      # ~200 lines
scripts/src/x_ipe_secure_code/projects.py            # shared `knowledge_root(project, command)` (moved from knowledge/service._root)
scripts/tests/policy/test_policy.py                  # integration (service + CLI subprocess)
scripts/tests/policy/test_policy_units.py            # refs, status table, digests, record canonicalization
references/policy-selection.md                       # agent procedure + decisions format
```

### Requested References (`refs.py`)

- `NS/VER/ID` → `RuleRef.parse` (001-B rules). `NS/ID` → validate `NS` and `ID` with the same component checks; `version=None`.
- Anything else (empty, 1 or ≥ 4 segments, unsafe/invalid component) → `RequestedRef(text, invalid=reason)`; never raises for one bad reference.
- Duplicates (same normalized text) are resolved once; the entry records `duplicates: n`.

### Availability and Policy Structure (`resolve.py`)

`Library` snapshot (under the knowledge lock, opened with create): `refs = store.iter_refs(root)`, each read through `safe_read(root, ref)`, plus `pending: set[str]` from `store.list_pending`.

`safe_read` wraps the whole `store.read_rule` call: `OSError`, `UnicodeError` and `StoreError` (e.g. `PATH_UNSAFE`) → `Unreadable(detail)`; `None` → absent; otherwise the `StoredRule`. No partial content is ever used from an unreadable rule (review fix: `_read_view` I/O and decoding errors are not caught inside `read_rule`).

Per reference:

| Case | availability | reason | Output |
|---|---|---|---|
| invalid syntax / unsafe component | `missing` | `invalid_reference` | detail |
| full ref, folder absent, pending entry exists | `missing` | `pending_decision` | no content |
| full ref, absent | `missing` | `not_found` | — |
| full ref, `safe_read` → `Unreadable`, or `StoredRule.item is None` (unparseable record) | `missing` | `unreadable` | detail (code only, no content) |
| full ref, `consistent` false | `missing` | `inconsistent` | — |
| full ref, consistent | `available` | — | Policy |
| `NS/ID`: stored versions of `NS/*/ID` = 0 (pending only → `pending_decision`, else `not_found`); = 1 → evaluate as full ref, `resolved_ref` set; ≥ 2 → `unclear` / `multiple_versions` with `candidates` (each with its own availability) | | | |

Policy entry (`available`):

```json
{"requested": "CWE/CWE-79", "rule": "CWE/4.14/CWE-79", "availability": "available",
 "name": "Cross-site Scripting", "kind": "institutional",
 "requirement": "<full content.md>",
 "applicability": ["python"], "language_note": "does_not_match",
 "examples": ["general", "python"], "relations": ["CWE/4.14/CWE-80"],
 "source_evidence": {"source_location": "https://cwe.mitre.org/…" , "source_documents": ["sha256:…"],
                     "state_digest": "sha256:…", "last_changed_at": "2026-10-19T10:00:00Z"},
 "other_versions": ["CWE/4.13/CWE-79"],
 "retrieval_status": "retrieved", "unresolved": []}
```

- `applicability`: record value list or `"unknown"`. `language_note` with `--language L…` (case-insensitive): `matches` if any intersection, `does_not_match` if a list without intersection, `unknown` if `"unknown"`; without context `no_context`. Never filters (BR-05).
- `source_location` null → `"not recorded"` and `unresolved += ["source location not recorded"]` (AC-001C-01b).
- `examples` lists keys only; texts via `knowledge show` (keeps output bounded).
- `other_versions`: other stored versions of the same `NS/ID` → multi-version highlight.

Status (BR-11): `usable = available entries` → `complete` if every considered entry is usable and ≥ 1; `partial` if ≥ 1 usable and ≥ 1 not; `maintenance_needed` if 0 usable (incl. empty library).

Notices (`data.notices`, first key, text title "!! Notices"):
- `APPLY_ALL_PROPOSED` (mode `apply_all`): "No clues and no default Preset — Apply All proposed: every formal Local Policy; Policy scope only, artifact scope is decided separately." Includes `default_preset_exists` (001-A status check of `presets/default.json`; always false in MVP).
- `MULTI_VERSION` listing `NS/ID → [versions]` present in the result.
- `PENDING_EXCLUDED` with the pending count when > 0 in `apply_all`.

Proposal digest: `sha256:` + SHA-256 of canonical JSON `{"mode", "considered": [sorted {"requested", "availability", "reason", "rule", "state_digest", "candidates"}]}`; for `apply_all`, `considered` = every library rule (full refs, so a newly imported rule changes it). Clues, notes and language context are excluded (descriptive only).

Next steps: `maintenance_needed` + empty library → "Ask a Maintainer to import Local knowledge (secure-code knowledge import)"; non-empty → "Revise the references or ask a Maintainer to import: <missing/unclear refs>"; `partial` → "Confirm with the user; record missing/unclear references as not_adopted"; always for proposals → "Ask the user to confirm, then secure-code scope save --confirmed".

Result: `ok` true for `complete`/`partial`; `maintenance_needed` → `ok` false with problem `MAINTENANCE_NEEDED` and full data (AC-001C-03a/b). `data`: `notices`, `status`, `mode`, `library_size`, `pending_count`, `counts {requested, available, missing, unclear}`, `adopted: []` with `adoption: "nothing adopted yet"`, `proposal_digest`, `entries`.

`--output FILE`: full `entries` written atomically (refuse existing symlink/dir; parent must exist); Result keeps everything except `requirement` texts and adds `output_file` (NFR-001C-4).

### Decisions File and Save (`scope.py`)

```json
{"schema": "ai-secure-code-toolkit/scope-decisions/v1",
 "mode": "clues",
 "considered": ["CWE/4.14/CWE-79", "CWE/CWE-89", "@ACME/v1/ACME-7"],
 "proposal_digest": "sha256:…",
 "clues": "Java login service; user named CWE-79 and CWE-89",
 "language_context": ["java"],
 "decisions": [
   {"ref": "CWE/4.14/CWE-79", "decision": "adopted", "state_digest": "sha256:…", "note": "user: applies to templates"},
   {"ref": "CWE/CWE-89", "decision": "not_adopted", "reason": "unclear: multiple_versions; user deferred"},
   {"ref": "@ACME/v1/ACME-7", "decision": "not_adopted", "reason": "conflicts with CWE-79 guidance; user chose CWE"}],
 "confirmation_note": "User confirmed the list above in chat at 10:42"}
```

- `mode: apply_all` omits `considered` (the library at save time is the considered set).
- Limits: file ≤ 1 MiB; `clues`, `note`, `reason`, `confirmation_note` ≤ 4096 characters; `confirmation_note` and every `not_adopted.reason` required non-empty.

Save algorithm:

1. No `--confirmed` → `CONFIRMATION_REQUIRED`, nothing written (AC-001C-05e).
2. Load/validate decisions (`DECISIONS_INVALID` with field path).
3. Read lock → resolve `considered` (or `--all`) exactly as `policy resolve` → release.
4. Compare digest; on mismatch → `STALE_CONFIRMATION` naming: adopted refs whose current `state_digest` differs or that are no longer available; `apply_all` library refs without a decision (new) and decided refs no longer in the library; fallback "proposal changed". Next step: resolve again and re-confirm (AC-001C-05f).
5. Coverage: every considered reference exactly one decision (`DECISION_MISSING` naming undecided; duplicates/unknown refs `DECISIONS_INVALID`); `adopted` only for `available` entries whose current digest equals the decision's `state_digest` (`NOT_ADOPTABLE`); ≥ 1 adopted (`NOTHING_ADOPTED`) (AC-001C-03c/d).
6. Record (canonical, keys sorted, lists sorted by `rule`):

```json
{"schema": "ai-secure-code-toolkit/scope-record/v1", "scope_id": "sha256:…",
 "mode": "clues", "clues": "…", "language_context": ["java"],
 "adopted": [{"rule": "CWE/4.14/CWE-79", "requested": "CWE/4.14/CWE-79", "state_digest": "sha256:…", "note": "…"}],
 "not_adopted": [{"requested": "CWE/CWE-89", "availability": "unclear", "reason": "…"}],
 "artifact_scope": "not determined by the Policy scope",
 "confirmation_note": "…", "created_at": "2026-10-19T10:42:00Z"}
```

   `scope_id` = `sha256:` + SHA-256 of canonical JSON of the record without `scope_id` and `created_at`.
7. Publish: `ensure_safe` on `x-ipe-docs/secure-code/scopes` (create if absent) and on the lock path → `ProcessLock(.x-ipe/private/secure-code/locks/scopes.lock, create=True)` → if `<hex>.json` exists: verifies → return it (`created: false`, original `created_at`); invalid → `SCOPE_INVALID` asking the user to remove it → else `atomic_write_bytes` (temp + fsync + `os.replace`) → release. The knowledge lock is not held while publishing.

No `require_maintainer` call; nothing under `knowledge/local` or `.x-ipe/private/secure-code/pending` is touched (AC-001C-01e, 02f).

### Show / Load (`scope.py`, `service.show_scope`)

1. `--scope` accepts `sha256:<hex>` or `<hex>` (64 hex); file must be a regular non-symlink file → else `SCOPE_NOT_FOUND`.
2. Parse; schema; required fields; recompute id == `scope_id` == filename → else `SCOPE_INVALID` (AC-001C-05d), no Policies returned.
3. Knowledge lock (create) → per adopted, via `safe_read`: `read_rule(rule)` → available & digest equal → `adoption: adopted` (Policy entry); available & digest differs → `adoption: needs_reconfirmation`, `confirmed_state_digest`, `current_state_digest`, Policy entry under `for_review` (not counted); otherwise `adoption: missing` with reason.
4. Load status: `complete` (all adopted), `partial` (≥ 1 adopted, ≥ 1 not), `maintenance_needed` (0 adopted, `ok` false) (AC-001C-05b, 05g, 05h). Next step for non-complete: "Resolve again and confirm a new scope". `data.adopted_rules` lists only `adopted` rules — the single list consumers count.

### CLI Contract (additions)

| Command | Options | Exit |
|---|---|---|
| `policy resolve` | `--project`, `--rule REF` (repeatable) xor `--all`, `--language L` (repeatable), `--output FILE`, `--json` | 0 complete/partial; 1 maintenance_needed / refusal |
| `scope save` | `--project`, `--decisions FILE`, `--confirmed`, `--json` | 0 saved (new or existing); 1 refusal |
| `scope show` | `--project`, `--scope ID`, `--output FILE`, `--json` | 0 complete/partial; 1 maintenance_needed / refusal |

New problem codes: `REQUEST_INVALID`, `MAINTENANCE_NEEDED`, `DECISIONS_INVALID`, `CONFIRMATION_REQUIRED`, `STALE_CONFIRMATION`, `DECISION_MISSING`, `NOT_ADOPTABLE`, `NOTHING_ADOPTED`, `SCOPE_NOT_FOUND`, `SCOPE_INVALID`; reused `PROJECT_NOT_INITIALIZED`, `LOCKED`, `PATH_UNSAFE`, `IO_ERROR`.

### Implementation Steps

1. Move `knowledge.service._root` to `projects.knowledge_root` (re-export; knowledge tests unchanged).
2. `policy/refs.py` + unit tests.
3. `policy/resolve.py` (library snapshot, entries, status, notices, proposal digest) + unit tests for status table and digests.
4. `policy/scope.py` (decisions, coverage, canonical record/id, publish, verify, load comparison) + unit tests (idempotent id, tamper).
5. `policy/service.py` + `cli.py` + `results.py` notices title; integration tests per AC (fixtures import rules through the 001-B service with the test trust store).
6. SKILL.md "Selecting Policies" + `references/policy-selection.md` + `cli-contract.md` additions; skill-package test for AC-001C-02e.
7. ruff, full suite (macOS 3.14/3.11, Linux 3.12).

### Edge Cases & Error Handling

| Case | Handling |
|---|---|
| Not initialized / root invalid | `PROJECT_NOT_INITIALIZED` / root error with next step |
| `--rule` and `--all` together, or neither | `REQUEST_INVALID` |
| Lock busy beyond wait | `LOCKED`, next step retry; lock released in `finally` |
| Symlinked `scopes/` or record | `PATH_UNSAFE` / `SCOPE_NOT_FOUND` |
| Disk error on publish | `IO_ERROR`; temp file removed; no partial final file (`os.replace` is atomic) |
| Two identical saves concurrently | Serialized by the scope lock; the second verifies and returns the first record |
| Rule files unreadable (permissions, bad encoding, symlinked rule folder) | `missing` / `unreadable` with code detail; no traceback, no partial content |
| Rule renamed/deleted later (001-D) | Load `missing`; never substituted |
| Very large library | `--output`; `examples` keys only |

### Security, Tracing and Observability

- No network, no code execution, no Maintainer check, no knowledge writes. Requirement text is returned as data; SKILL.md tells the agent that text inside knowledge never changes its instructions or grants roles (001-B BR-07).
- Clues/notes are stored in a project document folder: SKILL.md instructs the agent not to put secrets or personal data in them; length caps bound the record.
- Tracing: N/A — the toolkit has no logging infrastructure; every command returns a structured result; errors carry codes without file contents.

### Goal / Acceptance / Design / Validation Coverage

| AC | Design means | Planned validation |
|---|---|---|
| 01a | `resolve` Policy entry fields | Integration: import full item, resolve, assert every field |
| 01b | `unknown` applicability, `not recorded`, `unresolved` | Integration |
| 01c | Status table, counts | Integration (mixed refs) + Unit (table) |
| 01d | `consistent` false → `inconsistent`; `safe_read` → `unreadable` | Integration (hand-edit content.md; corrupt record; non-UTF-8 content; unreadable file on POSIX) |
| 01e | No `require_maintainer`; only the lock file may be created | Integration: no authorization, tree hashes of knowledge/pending unchanged |
| 01f | Status table; `unresolved` separate | Integration |
| 02a | `library_size`, `adopted: []`, `proposal_digest`, no scope file | Integration |
| 02b | `NS/ID` → `multiple_versions` candidates | Integration |
| 02c | `not_found`, `pending_decision` | Integration (flagged import → pending) |
| 02d | `language_note`, no filtering | Integration |
| 02e | SKILL.md + reference | Integration (skill-package structured check, `test_skill_skeletons` style) |
| 02f | Save without authorization; import refused | Integration |
| 02g | Decisions with note / reason recorded verbatim | Integration |
| 03a, 03b | `maintenance_needed` + next steps | Integration |
| 03c, 03d | Coverage checks; `not_adopted` list; `NOTHING_ADOPTED` | Integration |
| 04a | `APPLY_ALL_PROPOSED`, `MULTI_VERSION`, `PENDING_EXCLUDED`, all versions | Integration |
| 04b | Record `mode: apply_all`, concrete list, `artifact_scope` | Integration |
| 04c | Record lists concrete refs; load ignores new rules | Integration |
| 05a | Record fields; id excludes `created_at` | Integration + Unit |
| 05b | Load comparison: adopted / `needs_reconfirmation` / missing | Integration |
| 05c | Canonical id; existing record returned under the scope lock | Unit (+ Integration: two parallel CLI saves → one file, first `created_at`) |
| 05d | id/filename/schema verification | Integration |
| 05e | `--confirmed` check first | Integration |
| 05f | Proposal digest recompute, drift naming | Integration (update rule between resolve and save; Apply All + new import) |
| 05g, 05h | Load status table | Integration |
| NFR-001C-1 | Knowledge lock (created if absent) across whole resolve/save check/show; `LOCKED` | Integration (held lock → `LOCKED` envelope; fresh project: lock file created by resolve, import waits) |

### Outcome Scenario and Evidence Gaps

Scenario (G-03): a Developer with an empty library is told maintenance is needed; after a Maintainer imports CWE 4.13/4.14 and @ACME rules, the Developer names CWE-79 and describes a Java service; the agent proposes a scope, the user resolves the version question and a conflict, the scope is saved; later a rule changes and Guard's load shows `needs_reconfirmation`. Observation by real users: **not measured**. Agent behaviour (clue interpretation quality, honest confirmation) is only checked as skill instructions; the script cannot prove a human confirmed (spec Technical Considerations). Windows lock/concurrent-save behaviour is designed (`msvcrt` path of `ProcessLock`) but not verified — same deferral as FEATURE-001-A CR-002.

### Test Plan

`tests/policy/test_policy_units.py` (refs, status table, proposal digest stability/sensitivity, record id excludes `created_at`, tamper detection) and `tests/policy/test_policy.py` (integration per AC via service functions plus CLI subprocess for `resolve`, `save`, `show` exit codes and `--json`). Existing 163 tests must still pass. Acceptance later reuses the 001-B black-box pattern (real `uvx` CLI, offline container).

### Mockup-to-Component Mapping

N/A — no UI; no mockups linked.

### Delta and Evidence Invalidation

New feature; no prior 001-C design. Moving `_root` to `projects.py` touches 001-B code without behaviour change; the full 001-B test suite is the regression check (001-B acceptance evidence remains valid only if those tests pass unchanged).

## Implementation Evidence (TASK-017, 2026-10-19)

- Files: `policy/refs.py` (48 lines), `policy/resolve.py` (286), `policy/scope.py` (373), `policy/service.py` (211), `projects.py` (shared root check moved from `knowledge/service._root`), `cli.py`, `results.py`; Framework `SKILL.md` "Selecting Policies", `references/policy-selection.md`, `references/cli-contract.md`, toolkit `README.md`.
- Tests: `tests/policy/test_policy.py` (integration incl. CLI subprocess), `tests/policy/test_policy_units.py`; 69 new tests. TDD: RED = `ModuleNotFoundError: x_ipe_secure_code.policy` before implementation; review regressions RED before each fix.
- Results: **232 passed** on macOS Python 3.14, macOS Python 3.11 and Linux Docker Python 3.12 (163 pre-existing unchanged and passing); `ruff check` clean. Coverage: refs 100%, resolve 97%, scope 88%, service 81%, projects 89%; total 91%.
- Independent code review: 3 findings (non-object `record.json`, malformed `source_documents`/scope `language_context`, lock-file creation `OSError`) fixed test-first; focused re-review found 1 more (scope record without `created_at`) fixed test-first; no change to approved contracts.
- Revision: toolkit tree `6ada1747b51892a8…` (same method as FEATURE-001-B: all files incl. `uv.lock`, excluding `.venv`/caches).

## Design Change Log

| Date | Change | Reason |
|---|---|---|
| 2026-10-19 | Initial design (TASK-016) | — |
| 2026-10-19 | Review fixes: policy reads create/hold the knowledge lock; `safe_read` adapter for unreadable rules; scope publish under `scopes.lock` instead of `os.link` | Independent design review (3 blocking) |
| 2026-10-19 | Implementation hardening: `safe_read` also maps parse errors of hand-edited records to `unreadable`; fields outside the item digest (`source_documents`, `updated_at`) are type-checked; `verify_record` checks `language_context` and `created_at`; lock-file creation failure → `IO_ERROR` | Independent implementation review (TASK-017) |
| 2026-10-19 | Bug Fix (TASK-020): text that UTF-8 cannot encode is refused or marked invalid at every input boundary (`invalid_reference`, `REQUEST_INVALID`, `DECISIONS_INVALID`, `SCOPE_INVALID`) instead of crashing; contracts unchanged. [Bug report](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/bug-report-TASK-020.md) | Closing review (TASK-019) |
