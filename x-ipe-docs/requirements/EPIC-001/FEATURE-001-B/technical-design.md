# Technical Design: Local Knowledge Maintenance & Changelog

> Feature ID: FEATURE-001-B | Version: v1.0 | Last Updated: 2026-10-19
> Specification: [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/specification.md) · Task: TASK-010 · Depends on: [FEATURE-001-A design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md)

## Version History

| Version | Date | Description |
|---------|------|-------------|
| v1.0 | 10-19-2026 | Initial design |

---

## Part 1: Agent-Facing Summary

### Scope & Boundaries

- **Feature:** FEATURE-001-B — `secure-code knowledge check | import | update | list | show`, Local rules only.
- **program_type:** `cli` + `library` (inside the Framework skill's `scripts/`); Framework SKILL.md gains a "Maintaining knowledge" section for the agent.
- **tech_stack:** Python ≥ 3.11 stdlib (`json`, `hashlib`, `difflib`, `re`, `os`, `shutil`), reuse of FEATURE-001-A modules; pytest, ruff.
- **Non-goals:** deactivate/delete/rename (001-D), Reference/URLs (001-E), Presets/tags (001-F), AI-drafted supplements (001-G), restore command (K-15), draft/activation (D-08), aliases (D-06).

### Outcome / Goal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-03 | Spec G-03; FR-04, FR-05, FR-07 | Maintainer | Traceable, maintainable knowledge | `identity`, `store` (redo-log commit inside the rule folder), `changelog` (append-only unified diffs) | Scenario: import + update + show; diffs match | No restore; no snapshot chain | AC-001B-02*, 03*, 06*, 07*, 09* | not measured |
| G-04 | Spec G-04; FR-06 | Maintainer | Unchanged work never repeated | Canonical item digest; source-document digests; `check` | Scenario: resubmission all `current`; `check` reports fully stored documents | No count limit | AC-001B-04* | not measured |
| G-05 | Spec G-05; FR-24, K-32, K-33 | Owner / Maintainer | Only Maintainer writes; suspicious content needs a decision | `require_maintainer` per commit; `precheck` + pending metadata | Scenario: User refused; flagged item held until false-positive declaration | Not DLP | AC-001B-01, 05*, 08* | not measured |

### Design Options and Tradeoffs

| Means | Selection | Rationale |
| --- | --- | --- |
| JSON batch file (`ai-secure-code-toolkit/knowledge-batch/v1`) | selected | Agent-friendly, stdlib, strict validation |
| YAML / Markdown front-matter batch | rejected | Extra dependency / ambiguous multi-rule parsing |
| Item digest = SHA-256 of canonical item JSON; same value is the update base "state digest" | selected | One concept for idempotency (K-25, K-27) and optimistic concurrency (AC-07a) |
| Per-rule redo log inside the rule folder (`*.new` files → commit journal → replace) with roll-forward recovery; all reads and writes under an OS-managed knowledge lock | selected (after review) | All-or-nothing per rule (D-04, AC-07b); one folder = one filesystem; readers never see mixed or missing state; crashed processes release the lock |
| Staging folder + directory swap | rejected (review) | Ambiguous crash phases, reader-visible absence, possible cross-filesystem rename |
| Revision folders / `current` pointer | rejected | Forbidden snapshot chain (K-12); symlinks not portable |
| Exclusive-create lock file (001-A `ExclusiveLock`) for knowledge | rejected (review) | Never reclaimed after a crash → recovery blocked |
| Pending decisions store metadata only (no content) | selected | Never persist a suspected secret outside the batch the Maintainer controls |
| Pre-check: maintained regex catalogue, strict whole-value placeholders, project-keyed HMAC fingerprints without line numbers | selected (after review) | Lightweight and testable (K-32); real secrets never suppressed by substring; declarations stable across line shifts; fingerprints not guessable |
| Changelog in Markdown with fenced unified diffs (`difflib`) | selected | Human-readable, full before/after (K-13, K-14) |

### Key Components Implemented

All under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/`.

| Component | Responsibility | Scope/Impact | Tags |
|-----------|----------------|--------------|------|
| `identity.py` | `RuleRef` parse/format, component validation (charset, dots, Windows reserved names, length), case-insensitive collision lookup | All knowledge ops | #identity #safety |
| `batch.py` | Load/validate batch and update inputs, canonical item, item digest, size limits | check/import/update | #input #contract |
| `precheck.py` | Findings (credential / instruction / placeholder note), fingerprints, locations | import/update | #security |
| `store.py` | Rule folder read/write, item ↔ files mapping, redo-log commit and roll-forward recovery, pending metadata, document index | All writes/reads | #storage #reliability |
| `atomic.py` (extended) | `ProcessLock`: OS-managed advisory lock (`fcntl.flock` / `msvcrt.locking`) released on process exit | Knowledge lock | #reliability |
| `changelog.py` | Entry rendering with unified diffs, append | import/update | #history |
| `service.py` | `check`, `import_batch`, `update_rule`, `list_rules`, `show_rule` → `Result` | CLI/library | #core |
| `cli.py` (extended) | `knowledge` sub-commands | Public CLI | #cli |
| SKILL.md (Framework) | "Maintaining knowledge" procedure for the agent | Agent behaviour | #skills |

### Dependencies

| Dependency | Source | Design Link | Usage |
|---|---|---|---|
| `require_maintainer`, `atomic_write_bytes`, `ExclusiveLock`, `unsafe_component`, `validate_root`, `Result` | FEATURE-001-A | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/technical-design.md) | Authority, writes, locking, paths, output |
| Status rule counting (depth `<ns>/<ver>/<id>`) | FEATURE-001-A `status.py` | same | AC-001B-09c without change |

### Major Flow

1. `check`: parse identities/digests → read stored records → classify → Result (no lock, no writes).
2. `import`: validate root, load batch (whole-file errors refuse) → per item: identity & field validation → duplicate-in-batch → size → pre-check → under the knowledge lock: recover → read stored state → decide outcome (accepted updates must name the observed digest) → `require_maintainer` → redo-log commit incl. changelog entry → release; after all items, update the document index.
3. `update`: authority → load partial input → lock → recover → read current item → base digest must equal → merge → pre-check → no-op? → commit with changelog.
4. `list` / `show` / `check`: strictly read-only. If the lock file exists they hold the lock while reading (opening an existing file, no write); a rule with a pending commit journal is read through an in-memory roll-forward view (verified `.new` files, else final files). Physical recovery happens only in write commands. `show` verifies stored digest consistency.

### Usage Example

```bash
FW=.github/skills/x-ipe-secure-code-toolkit-framework
uvx --from $FW/scripts secure-code knowledge check  --project . --input ids.json --json
uvx --from $FW/scripts secure-code knowledge import --project . --batch batch.json --json
uvx --from $FW/scripts secure-code knowledge import --project . --batch batch.json \
    --accept-update CWE/4.14/CWE-79@sha256:<stored digest from the report> --false-positive @ACME/v1/ACME-7:3f9a1c2b4d5e6f70
uvx --from $FW/scripts secure-code knowledge update --project . --rule CWE/4.14/CWE-79 \
    --base-state <item digest from show> --input change.json --json
uvx --from $FW/scripts secure-code knowledge show --project . --rule CWE/4.14/CWE-79
```

### Tool Capability Summary

`stages.implement.technical_design`: all implementation tools enabled, consultation only. Matched: `x-ipe-tool-implementation-python` (PEP 8, type hints, pytest, ruff). Not matched: html5, typescript, java, mcp, general. Toolkit is a standalone product (no skill-creator flow, user decision for FEATURE-001-A).

---

## Part 2: Implementation Guide

### Files and Layout

```text
x-ipe-docs/secure-code/knowledge/local/<namespace>/<version>/<rule-id>/
├── record.json            # identity + metadata (below)
├── content.md             # current formal content
├── example.md             # optional general example
├── example-<lang>.md      # optional per-language examples (lang: lowercase [a-z0-9+#-]{1,20})
├── changelog.md           # append-only
└── (transient) *.new, .commit-journal.json   # only during a commit; resolved by recovery

.x-ipe/private/secure-code/
├── locks/knowledge.lock           # ProcessLock (OS-managed, never deleted)
├── precheck-key                   # 32 random bytes, owner-only; HMAC key for fingerprints
├── knowledge-documents.json       # source-document index (derived)
└── pending/<ns>/<ver>/<id>.json   # needs-decision metadata (no content)
```

`record.json` (`ai-secure-code-toolkit/local-rule/v1`): `schema`, `namespace`, `version`, `rule_id`, `kind` (`institutional` | `custom`), `name` (string or null), `source_location` (string or `"missing"`), `applicability` (list of languages or `"unknown"`), `relations` (list of rule refs), `item_digest`, `source_documents` (sorted list of document digests that produced this content), `created_at`, `updated_at`.

**Text normalization:** content and example texts are stored and digested with `\n` line endings and exactly one trailing newline; `null`/missing optional fields are normalized identically before digesting, so a stored rule always round-trips to the same canonical item (no false update candidates).

### Batch and Update Inputs (`batch.py`)

```json
{
  "schema": "ai-secure-code-toolkit/knowledge-batch/v1",
  "expected_count": 2,
  "items": [
    {
      "namespace": "CWE", "version": "4.14", "rule_id": "CWE-79",
      "name": "Improper Neutralization of Input During Web Page Generation",
      "source_location": "https://cwe.mitre.org/data/definitions/79.html",
      "source_document_digest": "sha256:…",
      "content": "…markdown…",
      "examples": {"general": "…", "python": "…"},
      "applicability": ["python", "javascript"],
      "relations": ["CWE/4.14/CWE-80"]
    }
  ]
}
```

- Unknown top-level or item fields → item (or file) refused. `name` required for `@` namespaces; `content` required, non-empty.
- **Canonical item** = `{namespace, version, rule_id, name|null, source_location|null, content, examples (sorted by key), applicability|null, relations (sorted)}` after text normalization; **item digest** = `"sha256:" + sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False))`. `source_document_digest` is provenance, not part of the digest: same content from a new document → outcome `stored` with operation `provenance_added` (record diff in the changelog), never a silent `current`.
- **Document index** (`knowledge-documents.json`): `{document digest: {items: [{rule, item_digest}], complete: bool, updated_at}}`, rewritten atomically under the lock after each import and **merged** with earlier batches: a failed item's rule stays in `failed` until that same rule later succeeds; failures of items without a usable identity are counted (`unidentified_failures`) and reset only by a later failure-free batch for that document with at least as many items as its largest batch; `complete` = no failures of either kind. `check` reports a document `fully_stored` only if `complete` and every listed rule is currently stored with exactly the recorded `item_digest`.
- **Provenance lifecycle:** `record.source_documents` lists documents whose content equals the current canonical item. An `update` that changes the canonical item clears it (`[]`, visible in the record diff); an accepted import update sets it to that batch's document (or `[]`); `provenance_added` only appends when the digest is unchanged.
- Limits: item size (content + examples, UTF-8) ≤ 1 MiB (`ITEM_TOO_LARGE`); identity component ≤ 100 characters.
- `check` input: `{"schema": "ai-secure-code-toolkit/knowledge-check/v1", "items": [{"rule": "NS/VER/ID", "item_digest": "sha256:…"}], "source_documents": ["sha256:…"]}`.
- `update` input (`ai-secure-code-toolkit/knowledge-update/v1`): any of `name`, `source_location`, `content`, `applicability`, `relations`, `examples` (map lang → text, or `null` to delete that example). Identity fields not allowed.

### Identity Rules (`identity.py`)

- Component regex `^[A-Za-z0-9._-]{1,100}$`; namespace may have a single leading `@` then the same rule.
- Reject `.`/`..`, leading/trailing `.`, Windows reserved names `CON PRN AUX NUL COM1–COM9 LPT1–LPT9` (case-insensitive, also with any extension, e.g. `nul.txt`).
- After building the path, `unsafe_component(root, rel, expect_dir=True)` (001-A) must return None.
- **Collision:** for each level, list existing directory names; an existing name equal case-insensitively but not exactly → `IDENTITY_COLLISION`.
- `RuleRef` string form `NS/VER/ID` (IDs cannot contain `/`).

### Pre-check (`precheck.py`)

| Finding type | Detection (applies to content and every example) | Blocking |
|---|---|---|
| `credential.private_key` | `-----BEGIN (RSA \|EC \|DSA \|OPENSSH \|ENCRYPTED )?PRIVATE KEY-----` | always |
| `credential.cloud_key` | `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}` | yes, except the exact documented AWS examples `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| `credential.token` | `gh[pousr]_[A-Za-z0-9]{36,}`, `xox[abprs]-[A-Za-z0-9-]{10,}`, `sk-[A-Za-z0-9]{20,}` | always |
| `credential.assignment` | `(password\|passwd\|secret\|api[_-]?key\|token)\s*[:=]\s*["']([^"'\s]{8,})["']` | yes, unless the **whole** value is a strict placeholder |
| `instruction.agent` | `ignore (all )?(previous\|prior\|above) instructions`, `disregard .{0,30}instructions`, `you are now `, `reveal (the )?system prompt` | always (anywhere) |
| `instruction.shell` | `rm -rf /`, `mkfs`, `curl … \| (ba)?sh`, `wget … \| (ba)?sh`, `:\(\)\s*\{` | in `content.md`; note only in examples |

**Strict placeholders** (whole value only, case-insensitive): angle-bracket templates `<…>`, `${NAME}` / `$NAME` variables, repeated `x`/`*` characters, or one of `changeme`, `example`, `placeholder`, `redacted`, `dummy`, `password`, `secret`, `your-password`, `your-api-key`. A value merely *containing* these words is still blocking. Matches become `note.placeholder` (informational).

**Finding** = `{type, file, line, fingerprint}`; `fingerprint = HMAC-SHA256(precheck-key, type ∥ file ∥ matched value ∥ occurrence)[:16]`, where `occurrence` is the 1-based ordinal of that identical (type, file, value) within the file — no line number (stable when lines shift), a second identical secret gets a new fingerprint and stays undeclared (AC-05d), keyed so low-entropy values cannot be guessed from it; the key is created on first use with owner-only permissions and never printed. Matched values are never returned or stored. Acceptance: `--false-positive NS/VER/ID:FINGERPRINT` (repeatable); the item is stored only if every blocking finding is declared, otherwise `needs_decision` (new undeclared findings keep it held).

### Store, Commit and Recovery (`store.py`)

**Lock:** `ProcessLock(.x-ipe/private/secure-code/locks/knowledge.lock)` — `fcntl.flock(LOCK_EX)` on POSIX, `msvcrt.locking(LK_NBLCK)` retried on Windows, with a bounded wait (default 10 s) → `LOCKED`. The OS releases it when a process dies, so a crash never blocks recovery. Write operations create the lock file if needed and hold the lock while they recover, read and commit; read operations lock only if the lock file already exists (so they never create files).

**Commit (one rule, redo log):**
1. Ensure the rule folder exists (`unsafe_component` check).
2. For every file to create or change, write `<file>.new` (fsync). Deletions need no file.
3. Write `.commit-journal.json` atomically: `{rule, base_digest, new_digest, replace: [{file, sha256}], delete: [file]}` — **commit point**.
4. `os.replace(<file>.new, <file>)` for each entry; delete listed files.
5. Delete the journal (fsync folder on POSIX).

**Recovery (write commands only, under the lock, before touching a rule; import recovers every rule it touches):**
- Journal present → roll forward: for each `replace` entry, if `<file>.new` exists its SHA-256 must equal the journal value before `os.replace` (mismatch → keep journal, `RULE_INCONSISTENT`); if it is absent, `<file>`'s SHA-256 must equal the journal value (already replaced); delete listed files; delete journal. No guessing.
- Read commands apply the same rules in memory only (no file changes); an unverifiable journal is shown as `inconsistent`.
- No journal → delete stray `*.new` files (commit never reached its commit point = previous state). A rule folder left with no `record.json` and no other files is removed.
- A failed `os.replace` (e.g. a Windows file held open by another program) leaves the journal in place; the command reports `IO_ERROR` and the next locked operation completes the roll-forward.

**Concurrency:** under the lock the stored digest is re-read; `update --base-state` and `import --accept-update RULE@DIGEST` must equal it, else `STATE_CONFLICT` with the current digest — so exactly one of several competing writes based on the same state commits, and an accepted import can never overwrite a newer change.

**Consistency check on read:** recompute item digest from files; mismatch with `record.item_digest` → `inconsistent` (show/list mark it; update/import of that identity refused `RULE_INCONSISTENT`).

**Test-only crash points:** the store calls `_crash_point(name)` at each boundary (after `.new` files, after journal, after each replace, before journal delete); it exits the process only when `SECURE_CODE_TEST_CRASH_AT` equals that name. It cannot change data, only stop the process, and is used by kill/restart tests.

### Changelog (`changelog.py`)

```markdown
## 2026-10-19T10:00:00Z — updated (role: maintainer)

- item digest: sha256:… (base sha256:…)
- source document digest: sha256:… | none
- declared false positives: credential.assignment @ example-python.md:3 (3f9a1c2b4d5e6f70)

### content.md
````diff
--- a/content.md
+++ b/content.md
@@ …
````
```

Operations: `created`, `updated`, `accepted_update`, `accepted_flagged` (combined as `accepted_update+flagged` when both). Added files diff from `/dev/null`, deleted to `/dev/null`. Fence length = longest backtick run in the diff + 1 (minimum 4). New entries are appended; previous bytes are kept verbatim (AC-06d).

### Algorithms — import outcome per item

| Order | Condition | Outcome |
|---|---|---|
| 1 | invalid structure / fields / identity / unsafe path | `refused` (`ITEM_INVALID`, `IDENTITY_INVALID`, `PATH_UNSAFE`) |
| 2 | same identity twice in batch | both `refused` (`DUPLICATE_IN_BATCH`) |
| 3 | > 1 MiB | `refused` (`ITEM_TOO_LARGE`) |
| 4 | case-insensitive collision | `refused` (`IDENTITY_COLLISION`) |
| 5 | stored rule inconsistent | `refused` (`RULE_INCONSISTENT`) |
| 6 | stored digest == item digest | `current` if provenance already recorded; otherwise `stored` with operation `provenance_added`; pending record removed if any |
| 7 | stored exists, digest differs, no `--accept-update RULE@<stored digest>` for it | `update_candidate` (result lists the stored digest to accept) |
| 7b | `--accept-update` digest ≠ stored digest under the lock | `refused` (`STATE_CONFLICT`) |
| 8 | blocking pre-check findings not all declared | `needs_decision` (pending metadata written/replaced; nothing else) |
| 9 | no Maintainer qualification | `refused` (`NOT_AUTHORIZED`) — checked immediately before each commit |
| 10 | lock busy / I/O failure | `not_processed` (`LOCKED` / `IO_ERROR`); remaining items continue (I/O failure stops the batch: rest `not_processed`) |
| 11 | otherwise | commit → `stored` (created / accepted_update / accepted_flagged); pending record removed |

Batch result: `ok` (and exit code 0) means no item ended `refused` or `not_processed`; per-outcome counts and `items[]` carry the per-item truth (AC-04a), never a single batch-wide success claim. `update_candidate` and `needs_decision` are decisions, not failures. `expected_count` mismatch → problem `EXPECTED_COUNT_MISMATCH` (non-blocking).

### CLI Contract (additions)

| Command | Arguments | Notes |
|---|---|---|
| `secure-code knowledge check` | `--project`, `--input FILE`, `--json` | read-only |
| `secure-code knowledge import` | `--project`, `--batch FILE`, `--accept-update RULE@DIGEST` (rep.), `--false-positive RULE:FP` (rep.), `--json` | Maintainer |
| `secure-code knowledge update` | `--project`, `--rule RULE`, `--base-state DIGEST`, `--input FILE`, `--false-positive RULE:FP` (rep.), `--json` | Maintainer |
| `secure-code knowledge list` | `--project`, `--namespace`, `--version`, `--json` | read-only, includes pending |
| `secure-code knowledge show` | `--project`, `--rule RULE`, `--json` | read-only, includes changelog |

New problem codes: `BATCH_INVALID`, `ITEM_INVALID`, `IDENTITY_INVALID`, `IDENTITY_COLLISION`, `DUPLICATE_IN_BATCH`, `ITEM_TOO_LARGE`, `EXPECTED_COUNT_MISMATCH`, `RULE_NOT_FOUND`, `RULE_INCONSISTENT`, `STATE_CONFLICT`, `NEEDS_DECISION`, plus 001-A codes (`NOT_AUTHORIZED`, `LOCKED`, `IO_ERROR`, `PATH_UNSAFE`).

### Implementation Steps

1. Tests first (RED) under `scripts/tests/knowledge/`.
2. `identity.py`, `batch.py`, `precheck.py` (pure, unit-tested).
3. `store.py` (layout, read, commit/recover, pending, lock), `changelog.py`.
4. `service.py`, CLI wiring, references (`cli-contract.md`, new `knowledge-batch.md`), Framework SKILL.md section.
5. Full suite, ruff, coverage ≥ 80% new code; macOS + Linux container run.

Estimated sizes: each module < 300 lines.

### Edge Cases & Error Handling

| Scenario | Behaviour |
|---|---|
| Batch file unreadable / bad JSON / wrong schema | `BATCH_INVALID`, nothing written |
| Unknown `--accept-update` / `--false-positive` target | Reported as problem `UNKNOWN_ACCEPT`, no effect |
| Crash at any commit boundary | Before journal: previous state; after journal: new state after roll-forward; never mixed (kill tests at every crash point) |
| Process killed while holding the lock | OS releases the lock; next command recovers |
| Hand-edited rule | `inconsistent`; writes for that identity refused |
| Update with stale base | `STATE_CONFLICT` with current digest |
| Update deleting a missing example | `ITEM_INVALID` (nothing to delete) |

### Security, Tracing and Observability

- No network, no execution of imported content; pre-check values never echoed (fingerprints only). Pending metadata stores no content.
- Writes re-verify the Maintainer qualification per commit (AC-08b).
- Tracing N/A (short-lived CLI; results are the record), as in FEATURE-001-A.

### Goal / Acceptance / Design / Validation Coverage

| AC ID | Component / Flow | Contract | Planned Validation (scripts/tests/knowledge/) | Delivery | Outcome |
|---|---|---|---|---|---|
| AC-001B-08a (refines AC-001B-01) | service + require_maintainer | NOT_AUTHORIZED | Integration `test_cli_knowledge.py::test_user_cannot_write_but_can_read` | planned | not measured |
| AC-001B-02a | store, service | layout, record | Integration `test_import_creates_rule_folder_and_created_entry` | planned | not measured |
| AC-001B-02b | identity, record.kind | custom ns | Integration `test_custom_namespaces_coexist_marked_custom` | planned | not measured |
| AC-001B-02c | identity | component rules | Unit `test_identity.py` (parametrized) + Integration `test_invalid_identity_refused_others_stored` | planned | not measured |
| AC-001B-02d | identity collision | lookup | Integration `test_case_insensitive_collision_refused` | planned | not measured |
| AC-001B-02e | batch validation | name/id required | Integration `test_missing_name_or_id_refused` | planned | not measured |
| AC-001B-02f | record.source_location | "missing" | Integration `test_source_location_missing_marked` | planned | not measured |
| AC-001B-03a | store | versions | Integration `test_two_versions_coexist` | planned | not measured |
| AC-001B-03b | store | no revisions | Integration `test_single_current_no_revision_folders` | planned | not measured |
| AC-001B-03c | store examples | files | Integration `test_examples_separate_files` | planned | not measured |
| AC-001B-03d | record.applicability | unknown | Integration `test_applicability_advisory_unknown` | planned | not measured |
| AC-001B-03e | batch/relations | refs only | Unit `test_relations_are_references_only` | planned | not measured |
| AC-001B-03f | batch | one primary identity | Integration `test_items_separate_and_primary_identity_required` | planned | not measured |
| AC-001B-04a | service outcomes | items[] | Integration `test_mixed_batch_per_item_outcomes` | planned | not measured |
| AC-001B-04b | check | digests | Integration `test_check_items_and_source_documents_read_only` | planned | not measured |
| AC-001B-04c | digest compare | current | Integration `test_resubmit_identical_all_current_no_change` | planned | not measured |
| AC-001B-04d | accept-update | candidate | Integration `test_changed_input_candidate_then_accept` | planned | not measured |
| AC-001B-04e | no merge | — | Unit `test_similar_content_not_merged` | planned | not measured |
| AC-001B-04f | expected_count, size | problems | Integration `test_expected_count_and_oversize` | planned | not measured |
| AC-001B-04g | commit/recovery | journal | Integration `test_interrupted_import_resumes` (fault injection) | planned | not measured |
| AC-001B-05a | precheck credential | finding | Integration `test_credential_held_others_stored` | planned | not measured |
| AC-001B-05b | precheck instruction | finding | Integration `test_instruction_held` | planned | not measured |
| AC-001B-05c | placeholder note | note | Integration `test_placeholder_note_stored` | planned | not measured |
| AC-001B-05d | false-positive declaration | fingerprints | Integration `test_false_positive_declaration_and_new_finding` | planned | not measured |
| AC-001B-05e | authority independent of text | — | Unit `test_role_claims_in_content_grant_nothing` | planned | not measured |
| AC-001B-05f | precheck on update | needs_decision | Integration `test_update_with_secret_refused_unchanged` | planned | not measured |
| AC-001B-06a | changelog | entry fields + content diff | Integration `test_update_content_appends_entry_with_diff` | planned | not measured |
| AC-001B-06b | changelog | metadata diff, added/deleted example | Integration `test_update_metadata_and_examples_single_entry` | planned | not measured |
| AC-001B-06c | service no-op | no entry | Integration `test_noop_update_no_entry` | planned | not measured |
| AC-001B-06d | changelog append | prior bytes kept | Integration `test_changelog_append_only` | planned | not measured |
| AC-001B-07a | lock + base digest | STATE_CONFLICT | Integration `test_concurrent_updates_exactly_one_commits` (parallel subprocesses) | planned | not measured |
| AC-001B-07b | redo-log commit/recovery | crash points | Integration `test_crash_at_every_point_recovers_previous_or_new` (killed subprocesses) + `test_readers_never_see_mixed_state` | planned | not measured |
| AC-001B-08b | per-commit re-verify | — | Unit `test_revoked_mid_batch_stops_writes` | planned | not measured |
| AC-001B-09a | list | filters, pending, read-only | Integration `test_list_filters_and_pending_read_only` | planned | not measured |
| AC-001B-09b | show | metadata/content/examples/changelog | Integration `test_show_rule_read_only` | planned | not measured |
| AC-001B-09c | status (001-A) | Local count | Integration `test_status_counts_local_rules` | planned | not measured |

### Outcome Scenario and Evidence Gaps

A Maintainer imports CWE excerpts and two company rules, resubmits after an interruption, updates one rule and reads its changelog; a User can only read. Outcome: **not measured** (no stakeholder observation yet).

### Test Plan

`scripts/tests/knowledge/` with unit tests for identity, batch, precheck (positive and negative samples), recovery phases; CLI integration tests via the existing test launcher (temporary project + trust dir). Concurrency via parallel subprocesses sharing a project, plus a reader loop asserting every `show` is digest-consistent while writers run. Crash tests: run import/update with `SECURE_CODE_TEST_CRASH_AT` set to each crash point (process exits), then verify the next command recovers to exactly the previous or new state. Run on macOS and the Linux container; Windows not available (same deferral as FEATURE-001-A CR-002) — the `msvcrt` lock path and Windows replace behaviour stay unverified.

### Mockup-to-Component Mapping

N/A — no UI.

### Delta and Evidence Invalidation

New feature; FEATURE-001-A behaviour unchanged except additions to `cli.py`, Framework SKILL.md and references; FEATURE-001-A tests rerun as regression.

## Implementation Evidence (TASK-011, 2026-10-19)

- **Source:** `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/` (identity, batch, precheck, store, changelog, service), `atomic.ProcessLock`, `cli.py` knowledge commands; Framework SKILL.md "Maintaining Knowledge"; references `knowledge-batch.md`, `cli-contract.md`. Toolkit tree fingerprint `6b7848fdc1950d65…`. Largest module `service.py` 584 lines.
- **TDD:** RED — knowledge test modules failed at collection before implementation; review regressions (7 + 4) written first and failing before each fix round.
- **Results at current revision:** `uv run pytest --cov` macOS Python 3.14 **160 passed, 91% coverage** (knowledge modules 84–100%); macOS Python 3.11 **160 passed**; Linux Docker Python 3.12 **160 passed**; `ruff check` clean.
- **Crash/concurrency evidence:** kill tests at all four commit boundaries plus a mid-batch kill; four parallel updates with a concurrent reader (exactly one commit, reader never inconsistent); three parallel first imports (key created once).
- **Reviews:** design review (6 blocking) + re-review (3 blocking) before coding; code review (2 High, 3 Medium, 1 Low) and fix verification (1 High, 3 Medium) — all fixed with regression tests.
- **Adjusted assertion (FEATURE-001-A test and acceptance runner):** the "no private key material" check now looks for the PEM header `-----BEGIN ENCRYPTED PRIVATE KEY-----`; the shipped pre-check pattern legitimately contains the words "PRIVATE KEY" and is not key material.
- **Not verified:** Windows (`msvcrt` lock path, replace behaviour) — same deferral as FEATURE-001-A CR-002. Tracing N/A.
- **Outcome state:** not measured.

---

## Design Change Log

| Date | Phase | Change Summary |
|------|-------|----------------|
| 2026-10-19 | Bug Fix (TASK-014) | `check`/`list` return `LOCKED` instead of a traceback on a held lock; document-index entries from before the counters existed keep their failures (legacy defaults). [Bug report](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/bug-report-TASK-014.md). |
| 2026-10-19 | Implementation review fixes (TASK-011) | Code review (2 High, 3 Medium, 1 Low) + fix verification (1 High, 3 Medium): source location stored as null + `source_location_status`; document index merged with per-rule failure tracking and counted unidentified failures; `ensure_safe` before every private-store/rule-folder access and caught in every command; non-UTF-8 text refused per item; strict `$`-placeholders; pre-check key created under the write lock atomically. |
| 2026-10-19 | Implementation (TASK-011) | `Result.ok` for import = no `refused`/`not_processed` item (same as exit code); crash points accept `NAME@N` (N-th occurrence) for batch interruption tests; changelog diffs use the stored `record.json` text. |
| 2026-10-19 | Initial Design (re-review fixes) | Fingerprint occurrence ordinal; document-index edges with item digests and provenance lifecycle; read commands read-only via in-memory roll-forward view; `.new` hash verified before install. |
| 2026-10-19 | Initial Design (review fixes) | Independent review (6 blocking, 2 non-blocking) applied: OS-managed `ProcessLock`; redo-log commit inside the rule folder with roll-forward recovery and locked reads (replaces staging/swap); `--accept-update RULE@DIGEST`; provenance list + document index; strict placeholders and keyed HMAC fingerprints without line numbers; kill-point crash tests and concurrent-reader test; Windows gap recorded. |
| 2026-10-19 | Initial Design | Initial technical design created. |
