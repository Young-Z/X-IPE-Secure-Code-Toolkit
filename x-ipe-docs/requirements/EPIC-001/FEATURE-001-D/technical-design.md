# Technical Design: Knowledge Exit Impact & Broken-Link Handling

> Feature ID: FEATURE-001-D | Version: v1.3 | Last Updated: 10-22-2026
> Specification: [specification.md](x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/specification.md) (`fb74bfe2…`) · Task: TASK-049 (refinement), TASK-050 (design), TASK-051 (implementation)

## Version History

| Version | Date | Description |
| --- | --- | --- |
| v1.0 | 10-22-2026 | Initial design, revised after independent design review |
| v1.1 | 10-22-2026 | Human-authorized amendment during TASK-051: handle-relative 001-B recovery in exit-confirm; pending-absent journal invariant limited to delete/rename |
| v1.2 | 10-22-2026 | Human decision (TASK-051): version-less references with a remaining stored version keep existing resolution and list exited identities as information |
| v1.3 | 10-22-2026 | Owner means-level adjustments during TASK-051 implementation (no contract/AC change): exit-confirm scope lock not created when absent; recover_at roll-forward primitive; directory rows in folder fingerprints; existing lock tests retargeted to DirLock |

## Part 1: Agent-Facing Summary

### Scope & Boundaries

**In scope.** All 30 ACs (AC-001D-01a…06c), FR-001D-1…8, BR-01…10, NFR-001D-1…4:
- two-step exit commands (`knowledge exit-preview`, `knowledge exit-confirm`) for deactivate, reactivate, delete and rename;
- the extensible impact-provider list and the impact digest;
- the lifecycle marker and lifecycle revision inside the rule record, and the rule state digest that includes it;
- the private exit memory (reserved identities) and tombstones;
- the project-level exit journal with durable, no-follow file primitives, its validation and the bounded recovery hook in every knowledge and Policy command;
- the read-only link check (`knowledge links`), list/show markers;
- additive changes to FEATURE-001-B (update base state, import refusals, document check), FEATURE-001-C (new `missing` reasons, "all" limited to active rules, scope save under both locks with the not-adopted exception) and a small next-step pass-through in Copilot's Policy-failure wrapping (FEATURE-003-A);
- the Framework SKILL.md "Exiting Knowledge" section, CLI contract and README rows.

**Out of scope** (specification "Out of Scope"): restore of deleted or renamed rules (K-15), automatic or assisted reference repair, Preset/tag/Reference-cache providers (FEATURE-001-E/F only plug into the list), batch exits, namespace/version exits. Guard and Copilot Policy-change semantics are not changed.

**Program type:** cli + library + skill. **Tech stack:** Python ≥ 3.11 (uv-managed `x_ipe_secure_code`, standard library only), pytest, ruff; SKILL.md Markdown.

### Outcome / Goal Frame

| Goal | Parent / Source | Contribution of this design | Planned evidence | Outcome state |
| --- | --- | --- | --- | --- |
| G-03 | EPIC-001 G-03; FR-07 (K-34, K-35, K-36, X-15 exit part, D-04); AC-09, AC-10 | Impact shown and digest-bound before any exit; exits change only the exited rule, its private records and known caches; dependents are reported broken with a reason, never substituted; a lifecycle revision makes every exit visible to scopes, Guard and Copilot; a durable journal makes interrupted exits complete or never happen | Integration tests per AC (incl. crash injection at every journal step of all four actions, recovery fixtures for every progress state, injected I/O failures, symlink canaries, process races with scope save and update); black-box CLI acceptance on the rename scenario of the specification | not measured |

### Design Options and Tradeoffs

| Decision | Selected | Rejected / deferred | Reason |
| --- | --- | --- | --- |
| Command shape | Two flat subcommands `knowledge exit-preview` / `knowledge exit-confirm` with `--action`; `knowledge links` | One command with an optional `--confirm` flag; nested `knowledge exit preview` | A confirmation without a digest must be refusable (AC-001D-02d); flat names fit the existing two-level parser and the `_authorize` action naming |
| Deactivated marker and lifecycle revision | Optional `lifecycle` object inside `record.json`; absent = active, revision 0 | Separate marker file in the rule folder; marker in the exit memory | A file in the folder would be deleted by `_write_rule` (it deletes unknown old files) and shown as an example; the record already moves with rename and is outside the item digest. Absent field keeps every existing record byte-identical |
| Rule state digest | `state_digest = item_digest` when `revision == 0`; else `sha256(canonical {"item_digest", "lifecycle_revision"})` | Always hashing item + revision | Additive: every never-exited rule keeps its digest, so existing scope records, decisions files, Guard and Copilot states stay valid (verified below) |
| Base state scope | Only `knowledge update --base-state` uses the state digest; import `update_candidate.stored_digest` and `--accept-update` stay item-digest based | State digest everywhere | Spec FR-001D-5 names only the update base state; the FEATURE-001-B import contract stays unchanged |
| Exit transaction | One project-level redo journal (`exits/journal.json`) = commit point; ordered, idempotent steps with per-op validation contracts; paths derived from the request, never read from the journal | Reusing the per-rule `store.commit` journal; staging folder with full copies | Exits span the rule folder, pending, index, memory and tombstone; a single commit point gives "fully exited or fully as before"; deriving paths limits a forged journal to the known files (U-13 limit stays) |
| File primitives | New `knowledge/durable.py`: directory-handle-relative, no-follow operations (POSIX `dir_fd`, `O_NOFOLLOW`), fsync of the file and of every containing directory after replace/unlink/move/mkdir | `atomic_write_bytes` + path-based `ensure_safe` | `atomic_write_bytes` does not fsync the parent folder and path checks race with link swaps; the exit is a multi-file commit that must survive power loss and link swaps (NFR-001D-1) |
| Locks and reads | `durable.DirLock`: knowledge and scope lock files opened `O_NOFOLLOW` relative to a no-follow-walked parent handle; one `durable.Tree` (root handle) used for the whole exit snapshot, rule iteration/reads, pending and index, and for `resolve.snapshot` | `ProcessLock(nofollow)` on a path; path-based `safe_read`/`iter_refs` | A no-follow final component does not stop a swapped parent: two processes could lock different files, or the digest could be computed over files outside the library |
| Recovery placement | `exit_journal.ensure_recovered(root)` before authorization in write commands, and `exit_journal.session(root, write=…)` replacing every `store.lock(...)` call in knowledge and Policy services | Recovery only in write commands | FR-001D-6: every knowledge and Policy command recovers first; read-only commands never show a half state |
| Lock order | Knowledge lock → scope lock, in exit-confirm and in scope save; impact reads Guard/Copilot states without their locks | Locking Guard/Copilot; a new global lock | Guard/Copilot take `guard.lock`/`copilot.lock` → knowledge lock; never the scope lock. No cycle (checked below). Open runs detect changes through their existing Policy-change handling |
| Scope-save race (AC-001D-02f) | Under both locks, the proposal digest is re-checked; on mismatch, the latest exit's integrity-checked **transition record** (private, journaled, keyed by `exit_id`) reconstructs the complete pre-action library view (for rename: old source restored and new target removed); publication is allowed only if that view reproduces the confirmed proposal digest **and** the exit's source identity was explicitly decided `not_adopted`; adopted exits, reactivations in `apply_all` and any other change → `STALE_CONFIRMATION` | Plain proposal-digest refusal for every change; per-reference "previous" entries in `record.json` | Follows the spec exception exactly; nothing outside the record's allowed rename changes is added to `record.json` (AC-001D-03d); the view is deterministic and one exit deep |
| Impact digest | Canonical JSON of request + rule-state fingerprint + one fingerprint per provider | Storing previews server-side | Stateless, deterministic (NFR-001D-2); any change of the rule or a provider's view refuses the confirmation |
| Rule-state fingerprint | Logical file view for a consistent rule (stable across a pending 001-B commit); physical walk of every entry that will move (no links followed, residue included, every regular file byte-hashed; deletion refused if one cannot be read) for an inconsistent or unreadable rule | Physical walk always; metadata markers for unreadable files | A pending per-rule commit would otherwise make every preview stale after the confirm's own physical recovery; AC-001D-03h binds the folder "as found", which needs the bytes |
| Delete storage | Move the rule folder (one `rename`) into `exits/tombstones/<exit_id>/rule/` + `exit-record.json` | Copy then delete | Atomic, keeps files "as found" for inconsistent rules (AC-001D-03h), no partial copy |
| Index | Strict reader for planning (malformed → reported `unreadable`, confirmation `INDEX_INVALID`); invalidation moves the rule's edge to the entry's `failed` list and sets `complete: false` | Lenient reader (malformed = empty); removing the whole entry | Never pretend an unreadable cache is empty; keeps the existing `_update_index` semantics and other rules' edges |
| Reserved identities | Exit memory lookup by `rel.lower()` | Keeping empty folders as reservation | Case-insensitive (FR-001D-8), private, survives without polluting formal knowledge |
| Link check / show reasons | Reuse `policy.resolve.evaluate` (one reason table) | A second reason implementation in knowledge | DRY; the same reason in resolve, scope load, show and links |

### Key Components Implemented

| Component | Tags | Responsibility | Spec link |
| --- | --- | --- | --- |
| `knowledge/store.py` (extended) | data, compat | `lifecycle_of(record)`, `state_digest(stored)`, lifecycle validity in `consistent`, `record_text(..., lifecycle=None)`, `rule_from_files(ref, files)` (shared by path and handle reads), `read_rule_at(tree, ref)`, `iter_refs_at(tree)`, `list_pending_at(tree)`; `lock()` returns `durable.DirLock`; `_pause_point` test hook, `StoreError.next_step` | FR-001D-5 |
| `knowledge/durable.py` (new) | fs, durability, security | `Tree` (root handle, no-follow walks), `DirLock`, durable write/append/unlink/move/mkdir-chain with directory fsync, no-follow reads and entry stat, Windows fallback | FR-001D-6, NFR-001D-1 |
| `knowledge/lifecycle.py` (new) | data, identity | Exit-memory and transition-log read/serialize, reserved lookup (case-insensitive), exit IDs, paths, fingerprints, strict index reader, reason validation | FR-001D-4, FR-001D-8 |
| `knowledge/exit_journal.py` (new) | transaction, recovery | Journal schema, op validation contracts, progress check, roll-forward / narrow roll-back, `ensure_recovered`, `session` hook, crash points | FR-001D-6, AC-001D-06a |
| `knowledge/impact.py` (new) | impact, extensible | `Provider` list (relations, scopes, Guard runs, Copilot collaborations, pending decisions, document index), unsupported kinds, digest | FR-001D-1, FR-001D-2 |
| `knowledge/exit.py` (new) | command | `preview`, `confirm`, `links`: authorization, request validation, locks, action plans, results | FR-001D-1, 3, 4, 7 |
| `knowledge/changelog.py` (extended) | history | `lifecycle_entry(...)` for deactivated / reactivated / renamed | AC-001D-03a, 03b, 03d |
| `knowledge/service.py` (extended) | compat | Recovery hook; update base = state digest; import refuses deactivated and reserved identities; check never `fully_stored` for deactivated rules; list/show markers and broken relations | FR-001D-5, 7, 8 |
| `policy/resolve.py` (extended) | compat | Handle-based `snapshot(tree)`; `Library.exited` and `Library.overrides` (pre-action view); reasons `deactivated`/`deleted`/`renamed` (+`renamed_to`); "all" active-only + `inactive` counts; `state_digest` via store | FR-001D-7 |
| `policy/scope.py`, `policy/service.py` (extended) | compat, concurrency | `renamed_to` passthrough in load; scope save under knowledge → scope lock (`DirLock`) with the transition-based not-adopted exception; recovery hook in `_snapshot`; `EXIT_JOURNAL_INVALID` passthrough in `adoption_now` | FR-001D-3, AC-001D-02f |
| `copilot/service.py` (small change) | compat | `_policy_now` and `open` keep the Policy refusal's next step for `EXIT_JOURNAL_INVALID`, `PATH_UNSAFE`, `LOCKED`, `IO_ERROR` | FR-001D-6 |
| `cli.py` (extended) | cli | `knowledge exit-preview`, `exit-confirm`, `links` | UI/UX |
| Framework `SKILL.md`, `references/cli-contract.md`, `references/policy-selection.md`, toolkit `README.md` | skill, docs | "Exiting Knowledge" procedure and boundaries; commands and codes; new reasons | AC-001D-06c |

### Dependencies

| Dependency | Use | Link |
| --- | --- | --- |
| FEATURE-001-B | Rule folder layout, `read_rule`/`recover`/`iter_refs`, knowledge lock, pending files, document index, `_authorize`, `_crash_point` | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/technical-design.md) · [spec](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/specification.md) |
| FEATURE-001-C | `resolve.snapshot/evaluate/build`, scope records, `load_scope`, `scope.publish` and scope lock, `adoption_now` | [design](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/technical-design.md) · [spec](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md) |
| FEATURE-002-A | Read-only: `GUARD_REL`, `RUN_ID`, `SCHEMA_RUN`; `fsync_dir` pattern (`guard/runs.py`); unchanged Policy-change handling (`_refusal` already keeps next steps) | [design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/technical-design.md) |
| FEATURE-003-A | Read-only: `COPILOT_REL`, `COLLAB_ID`, `SCHEMA_STATE`; unchanged `policy_changed`; next-step pass-through | [design](x-ipe-docs/requirements/EPIC-003/FEATURE-003-A/technical-design.md) |
| FEATURE-001-A / Adapters | `require_maintainer`, `knowledge_root`, `Result`, `dumps_json`, `unsafe_component`; `adapters/safe_io.open_dir_nofollow` pattern | — |

### Major Flow

1. **Preview.** The agent, on a real Maintainer request, runs `exit-preview --rule R --action A [--to R2] --reason T`. The command recovers a pending exit, checks the Maintainer authorization, validates the action against the rule, collects every provider under the knowledge lock (and the scope lock if present) and returns the impact first, the unsupported kinds, what the action will do and `impact_digest`. Nothing is written except completion of an earlier authorized exit, if recovery was needed.
2. **Decision.** The agent shows the impact to the Maintainer. References never block; the Maintainer decides.
3. **Confirm.** `exit-confirm` with the same arguments and `--impact-digest`. Recover → verify authorization → knowledge lock → recover again → scope lock → recompute the impact → refuse `STALE_IMPACT` if the digest differs → handle-relative per-rule 001-B recovery (`store.recover_at`) → plan → authorization re-check → durable journal → durable steps → durable journal removal → success with removed pending decisions and invalidated index entries.
4. **Afterwards.** Resolve, scope load, show and `knowledge links` report broken references with the reason; a reactivated rule loads as `needs_reconfirmation`; open Guard/Copilot runs report `changed`/`missing` at their next conclusion or report.

### Usage Example

```bash
SC="uvx --from .github/skills/x-ipe-secure-code-toolkit-framework/scripts secure-code"
$SC knowledge exit-preview --project . --rule CWE/4.14/CWE-89 --action rename \
    --to CWE/4.14/CWE-89-SQL --reason "Split into SQL-specific rule" --json      # impact + impact_digest
# … agent shows the impact; the Maintainer explicitly confirms …
$SC knowledge exit-confirm --project . --rule CWE/4.14/CWE-89 --action rename \
    --to CWE/4.14/CWE-89-SQL --reason "Split into SQL-specific rule" --impact-digest sha256:… --json
$SC knowledge links --project . --json        # CWE/4.14/CWE-20 → CWE/4.14/CWE-89: renamed (renamed_to CWE/4.14/CWE-89-SQL)
$SC scope show --project . --scope sha256:…   # CWE-89 missing (renamed); status partial; record unchanged
```

### Tool Capability Summary

| Tool | Enabled (`stages.implement.technical_design` in [tools.json](x-ipe-docs/config/tools.json)) | Matched | Use |
| --- | --- | --- | --- |
| x-ipe-tool-implementation-python | true | yes (Python CLI/library) | Consulted for practices (type hints, pytest, ruff, stdlib only); informational only (`_extra_instruction`: consultation mode, no execution) |
| x-ipe-tool-implementation-general | true | fallback, not needed | — |
| html5, typescript, java, mcp | true | no (no such stack) | — |

## Part 2: Implementation Guide

### Files and Layout

```
ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/
  knowledge/store.py         # 311 → ~400: lifecycle_of, state_digest, record_text(lifecycle), rule_from_files, *_at handle readers,
                             #             lock() → DirLock, _pause_point, StoreError.next_step
  knowledge/durable.py       # new ~330: Tree, DirLock, durable write/append/unlink/move/mkdir, reads, walk, Windows fallback
  knowledge/lifecycle.py     # new ~260: paths, exit memory, transition log, reserved, ids, fingerprints, strict index, reasons
  knowledge/exit_journal.py  # new ~500: journal, op contracts, progress check, recover, ensure_recovered, session
  knowledge/impact.py        # new ~300: providers, unsupported kinds, digest
  knowledge/exit.py          # new ~450: preview, confirm, links, plans (incl. transition entries), results
  knowledge/changelog.py     # 57 → ~90: lifecycle_entry
  knowledge/service.py       # 588 → ~665: hook, base state, import refusals, check, list/show markers
  policy/resolve.py          # 286 → ~360: handle-based snapshot, exited reasons, overrides (pre-action view), active-only "all"
  policy/scope.py            # 378 → ~430: renamed_to passthrough, transition-based not-adopted exception; publish under DirLock
  policy/service.py          # 262 → ~305: _snapshot hook, save under both locks, adoption_now passthrough
  copilot/service.py         # 678 → ~684: next-step pass-through
  cli.py                     # 303 → ~335
tests/knowledge/{exithelp,test_exit_preview,test_exit_actions,test_exit_recovery,test_exit_journal_fixtures,
                 test_exit_durable,test_exit_concurrency,test_exit_links,test_exit_units,test_exit_skill}.py
tests/policy/{test_policy_exit,test_exit_runs}.py
ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/SKILL.md, references/{cli-contract,policy-selection}.md
ai-secure-code-toolkit/README.md
```

Every module stays below 800 lines (`tests/test_module_size.py`). If `knowledge/service.py` would pass ~750 lines, `list_rules`/`show_rule` move to `knowledge/views.py` and `service` re-exports them (CLI unchanged). `atomic.py` (`ProcessLock`) is unchanged; Guard and Copilot keep their own locks.

Import direction (no cycles): `durable` (stdlib only) ← `store` ← `lifecycle` ← `exit_journal` ← {`knowledge.service`, `policy.service`}; `policy.resolve` imports `store`/`lifecycle`/`durable`; `impact` and `exit` import `policy.resolve`/`policy.scope` at module level and only constants of `guard.model`/`copilot.model` lazily inside the providers (Guard and Copilot import `policy.service`).

### Storage Formats

**Rule record** (`record.json`, schema unchanged `local-rule/v1`; `lifecycle` present only after the first exit action):

```json
{"schema": "ai-secure-code-toolkit/local-rule/v1", "namespace": "CWE", "version": "4.14", "rule_id": "CWE-89",
 "…": "existing fields unchanged",
 "lifecycle": {"state": "deactivated", "revision": 1}}
```

- `lifecycle` holds exactly two keys: `state` (`active`/`deactivated`) and `revision` (int ≥ 1). Times, reasons and pre-action entries live in the changelog and in the private transition log, so a rename changes only `rule_id`, `item_digest`, `updated_at` and `lifecycle.revision` (for a never-exited rule the object is introduced with its unchanged state `active` and revision 1) — the exhaustive list of AC-001D-03d.
- `store.lifecycle_of(record)` → `None` when absent (active, revision 0), else the validated dict; extra keys or bad values make `StoredRule.consistent` false (reason `inconsistent`; update/import refuse `RULE_INCONSISTENT`).
- `store.state_digest(stored)` = `stored.digest` if revision 0; else `"sha256:" + sha256(json.dumps({"item_digest": d, "lifecycle_revision": n}, sort_keys=True, separators=(",", ":")))`. The revision grows by one per action (deactivate, reactivate, rename; delete records `to` in the exit record) and never decreases, so a state digest never returns to an earlier lifecycle value.
- `store.record_text(item, …, lifecycle=None)` adds the key only when not `None`; `_write_rule` passes the stored lifecycle unchanged, so an update keeps the marker (AC-001D-05a).

**Private exit area** (`.x-ipe/private/secure-code/exits/`, folders `0700`, files `0600`):

```
exits/journal.json                         # at most one pending exit
exits/memory.json                          # reserved identities
exits/transitions.json                     # transition log: pre/post-action proposal delta per exit
exits/tombstones/<exit_id>/rule/           # the rule folder as found (every entry, incl. residue)
exits/tombstones/<exit_id>/exit-record.json
```

`exit_id` = `ex-YYYYMMDDTHHMMSSZ-<8 hex>` (same pattern as Guard/Copilot ids). Exit-owned temporary files have deterministic names `.exit-<exit_id>.<step>.tmp` in the folder they replace into.

**Exit memory** (`exit-memory/v1`, sorted by `rule`, one entry per identity):

```json
{"schema": "ai-secure-code-toolkit/exit-memory/v1",
 "exited": [{"rule": "CWE/4.14/CWE-89", "action": "renamed", "renamed_to": "CWE/4.14/CWE-89-SQL",
             "exit_id": "ex-…", "at": "…Z", "reason": "…", "tombstone": null, "transition": "sha256:…"},
            {"rule": "CWE/4.14/CWE-77", "action": "deleted", "renamed_to": null, "exit_id": "ex-…", "at": "…Z",
             "reason": "…", "tombstone": ".x-ipe/private/secure-code/exits/tombstones/ex-…", "transition": "sha256:…"}]}
```

`lifecycle.reserved(memory, ref)` returns the entry whose `rule.lower() == ref.rel.lower()`. Missing file = empty. Unreadable or invalid: write paths (import, delete/rename confirm) refuse `EXIT_MEMORY_INVALID` (next step: restore the file from a backup or ask the Maintainer to inspect it); read paths treat it as empty and add notice `EXIT_MEMORY_UNREADABLE` (reasons degrade to `not_found`; still `missing`).

**Transition log** (`exit-transitions/v1`; one entry per committed exit, appended by the journaled `transitions` step of **every** action):

```json
{"schema": "ai-secure-code-toolkit/exit-transitions/v1",
 "entries": [{"exit_id": "ex-…", "action": "rename", "rule": "CWE/4.14/CWE-89", "target": "CWE/4.14/CWE-89-SQL",
              "at": "…Z", "digest": "sha256:…",
              "identities": {
                "CWE/4.14/CWE-89":     {"before": {"present": true,  "active": true, "availability": "available",
                                                   "reason": null, "state_digest": "sha256:A"},
                                        "after":  {"present": false, "active": false, "availability": "missing",
                                                   "reason": "renamed", "state_digest": null}},
                "CWE/4.14/CWE-89-SQL": {"before": {"present": false, "active": false, "availability": "missing",
                                                   "reason": "not_found", "state_digest": null},
                                        "after":  {"present": true,  "active": true, "availability": "available",
                                                   "reason": null, "state_digest": "sha256:B"}}}}]}
```

- `before`/`after` describe each affected identity exactly as `resolve.evaluate` sees it (`present` = in `Library.rules`; `active` = member of the "all" set). This is the complete pre-action proposal delta: every proposal (clues, version-less candidates, "all") is a function of these per-identity views plus the unchanged rest of the library.
- Projection adapter: `Library.overrides` maps these fields to the exact `proposal_digest` inputs (`availability`, `reason`, `rule`, `source_evidence.state_digest`), and its `present`/`active` flags control version-candidate and "all" enumeration. It reconstructs only proposal identity/state, never a usable requirement or adopted Policy. Current unaffected adopted entries always come from the real library.
- `digest` = `sha256` of the canonical entry without `digest`. It is bound three ways: the journal's `transitions` write step (payload digest = `after` of the whole file), the exit's changelog entry (`- transition: sha256:…`; deactivate, reactivate, rename) and the exit-memory / exit-record entry (delete, rename). A transition is **valid** for the scope-save exception only if its recomputed digest equals its `digest` and the bound copy in the changelog or memory.

**Exit record** (`exit-record/v1`, delete only):

```json
{"schema": "ai-secure-code-toolkit/exit-record/v1", "exit_id": "ex-…", "action": "delete", "rule": "CWE/4.14/CWE-77",
 "reason": "…", "at": "…Z", "role": "maintainer", "consistent": false, "pending_commit": false,
 "state_digest": null, "lifecycle_revision": {"from": 0, "to": 1}, "folder_fingerprint": "sha256:…",
 "impact_digest": "sha256:…", "transition": "sha256:…", "impact_counts": {"relations": 1, "scopes": 0, "guard_runs": 0,
 "copilot_collaborations": 0, "pending_decisions": 1, "document_index": 1},
 "removed_pending": ["CWE/4.14/CWE-77"], "invalidated_index": ["sha256:<document>"],
 "special_entries": [{"path": "fifo", "kind": "fifo"}]}
```

**Exit journal** (`exit-journal/v1`):

```json
{"schema": "ai-secure-code-toolkit/exit-journal/v1", "exit_id": "ex-…", "action": "rename",
 "rule": "CWE/4.14/CWE-89", "target": "CWE/4.14/CWE-89-SQL", "reason": "…", "at": "…Z",
 "impact_digest": "sha256:…", "transition_digest": "sha256:…",
 "pre_state": {"pending": "sha256:…|null", "index_edges": ["sha256:<document>"]},
 "steps": [
   {"name": "record",      "op": "write",  "before": "sha256:…", "after": "sha256:…", "text": "{…}"},
   {"name": "changelog",   "op": "append", "before": "sha256:…", "after": "sha256:…",
                           "suffix": "## …", "suffix_digest": "sha256:…"},
   {"name": "move",        "op": "move",   "fingerprint": "sha256:…"},
   {"name": "pending",     "op": "remove", "before": "sha256:…"},
   {"name": "index",       "op": "write",  "before": "sha256:…", "after": "sha256:…", "text": "{…}"},
   {"name": "memory",      "op": "write",  "before": null,       "after": "sha256:…", "text": "{…}"},
   {"name": "transitions", "op": "write",  "before": "sha256:…", "after": "sha256:…", "text": "{…}"}]}
```

Step paths are **derived** from `(action, rule, target, exit_id)` by `exit_journal.path_of(name)`; the journal carries no paths.

| Action | Required steps (in order) | Optional steps (present iff `pre_state` says so) |
| --- | --- | --- |
| deactivate | `record` → `changelog` → … → `transitions` | `index` (before `transitions`) iff `pre_state.index_edges` non-empty |
| reactivate | `record` → `changelog` → `transitions` | — |
| delete | `tombstone_dir` (`mkdir`) → `move` (rule folder → `tombstones/<id>/rule`) → `tombstone_record` (new file) → … → `memory` → `transitions` | `pending` iff `pre_state.pending` non-null; `index` iff `index_edges` non-empty (both before `memory`) |
| rename | `record` → `changelog` (both in the old folder) → `move` (old → new folder) → … → `memory` → `transitions` | `pending`, `index` as for delete |

For rename, `path_of` maps a path under the old folder to the new folder once `move` is done. The rename `move` fingerprint is the folder fingerprint after the preceding writes (computed from the planned entry list); the delete `move` fingerprint is the folder as found (after the 001-B recovery of a consistent rule). The `transitions` step's `text` must contain exactly the previous entries plus one entry whose `digest` equals `transition_digest`.

**Fingerprints** (`lifecycle.py`, walking through `durable.Tree` handles; never following links):
- `files_fingerprint({name: text})` (logical view) and `folder_fingerprint(dir_fd)` both produce `sha256` of canonical JSON `[[relpath, kind, value]]` sorted by `relpath`.
- `folder_fingerprint` covers **every** entry that a move would carry, including dot files and atomic residue (`.x.tmp-…`, `.new`, `.commit-journal.json`), recursing into real subfolders through `open(name, O_DIRECTORY|O_NOFOLLOW, dir_fd=…)`:
  - regular file → `["file", "sha256:…"]` of its bytes (opened `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`; `fstat` identity must equal the `lstat` identity, else `PATH_UNSAFE`). A regular file that **cannot be opened and fully read** (permission, I/O error) refuses the operation with `RULE_FOLDER_UNREADABLE` — content is always bound by its bytes, never by metadata;
  - symbolic link → `["link", sha256(readlink(name, dir_fd=…))]`, never followed;
  - non-content objects only (FIFO, socket, character/block device) → `[kind, "meta:size=<n>;mode=<o>"]` from `lstat`, never opened (a FIFO cannot block); they are listed in the preview `rule_state.special_entries` and in the exit record;
  - a subfolder that cannot be listed → `RULE_FOLDER_UNREADABLE` (next step: fix the permissions), because its moving content cannot be bound.
- Only exit-owned temporaries (`.exit-<exit_id>.*.tmp` of the journal's own exit) are excluded, and only during recovery after they were removed.

### Durable No-Follow Primitives and Handle-Based Reads (`durable.py`)

POSIX (`os.supports_dir_fd` covers `open`, `mkdir`, `rename`, `unlink`, `stat`, `readlink`, and `os.scandir` accepts a descriptor; same check as `adapters/safe_io.POSIX_FD`):

```python
class Tree:                                             # one per command; holds the project-root descriptor
    def __init__(self, root: Path) -> None              # os.open(root, O_RDONLY|O_DIRECTORY); root itself was realpath-validated
    def dir(self, rel: str, *, create: bool = False, mode: int = 0o700) -> int
        # safe_io.open_dir_nofollow pattern relative to the root handle: each component O_RDONLY|O_DIRECTORY|O_NOFOLLOW;
        # with create, a missing component is os.mkdir(part, mode, dir_fd=parent), then fsync(parent) before descending
    def list(self, dfd: int) -> list[tuple[str, os.stat_result]]   # os.scandir(dfd) + stat(follow_symlinks=False)
    def close(self) -> None

class DirLock:                                          # replaces ProcessLock for the knowledge and scope locks
    def __init__(self, tree: Tree, rel: str, *, create: bool, timeout: float = 10.0) -> None
    # parent = tree.dir(parent_of(rel), create=create); fd = os.open(name, O_RDWR|O_NOFOLLOW|(O_CREAT if create), 0o600,
    # dir_fd=parent); fstat must be a regular file; same flock/msvcrt retry loop and LockHeld as atomic.ProcessLock;
    # create=False and absent → proceed unlocked (existing ProcessLock semantics)

def read(dfd: int, name: str) -> bytes | None          # O_RDONLY|O_NOFOLLOW; None if absent; refuses non-regular
def entry(dfd: int, name: str) -> os.stat_result | None # os.stat(name, dir_fd=dfd, follow_symlinks=False)
def write(dfd: int, name: str, data: bytes, tmp: str) -> None
    # tmp: O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW (0600) relative to dfd; write all; fsync(file); close;
    # os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd); fsync(dfd)
def unlink(dfd: int, name: str) -> None                 # entry must be a regular file; os.unlink(name, dir_fd=dfd); fsync(dfd)
def move(src_dfd: int, name: str, dst_dfd: int, new: str) -> None
    # source must be a real folder, destination absent (entry is None); same st_dev of both handles, else EXDEV;
    # os.rename(name, new, src_dir_fd=src_dfd, dst_dir_fd=dst_dfd); fsync(dst_dfd); fsync(src_dfd)
def rmdir_empty(dfd: int, name: str) -> None            # roll-back of an exit-owned empty tombstone folder; fsync(dfd)
```

- **Locks:** both lock files are reached by a no-follow walk from the command's root handle. A replacement link encountered during the walk fails with `ELOOP`/`ENOTDIR` → `PATH_UNSAFE`; a replacement after opening does not redirect the held descriptor. `store.lock(root, write)` owns a `Tree` and returns `DirLock(tree, LOCK_REL, create=write)`; sessions pass their already-opened `Tree` to `DirLock` directly, and `scope.publish` uses that same tree. The lock is taken before any read used for a digest, and every later read and write of the command uses the same `Tree`. Cooperating processes never rename or replace the lock files or their parent directories. Arbitrary replacement with new real directories by a local writer is outside this serialization guarantee (U-13), not prevented by `O_NOFOLLOW`.
- **Handle-based reads:** `store.rule_from_files(ref, files)` holds the existing `_read_view`/`read_rule` logic over a `{name: text}` map (incl. the 001-B journal view). `store.read_rule_at(tree, ref)` fills that map through `tree.dir(rule_rel)` + `read`; `store.iter_refs_at(tree)` lists namespace/version/rule folders via `tree.list` (link entries skipped, as `iter_refs` does today); `store.list_pending_at(tree)` reads pending files the same way. `resolve.snapshot(tree)` and `resolve.safe_read(tree, ref)` use them (path-based `read_rule`/`iter_refs` remain for callers outside this feature). The exit's `prepare`, providers, plan and journal validation use only the command's `Tree`.
- **Handle-based 001-B commit recovery:** `store.recover_at(tree, ref)` applies the existing per-rule commit-journal semantics of `store.recover` (same roll-forward/roll-back decisions and outcomes) but opens the rule folder once through `tree.dir(rule_rel)` and performs every read, replace and unlink relative to that descriptor with `durable.read`/`write`/`unlink`; a link at any component or entry → `PATH_UNSAFE`, nothing written outside. Exit-confirm calls only `recover_at` and then re-reads the rule with `read_rule_at` through the same `Tree`; path-based `store.recover` remains for callers outside this feature.
- `fsync(dfd)` follows the `guard/runs.fsync_dir` pattern (directory descriptor, `os.fsync`).
- **Ordering:** durable journal publication (`write` in `exits/` incl. its directory fsync) → each step durable in order → durable journal removal (`unlink` + directory fsync) → only then the success result. A crash at any point leaves either no journal (nothing changed) or a durable journal whose done-prefix is durable.
- All exit-time mutations go through these primitives: journal, exit memory, transition log, tombstone folder and record, rule `record.json`/`changelog.md`, the rule-folder move, pending removal and index replacement.
- **Windows (honest limit):** no directory descriptors and no directory fsync. `Tree` falls back to paths with an `lstat` check per component (link or reparse-point attribute → `PATH_UNSAFE`) and an identity check (`st_dev`, `st_ino` before/after open) like `safe_io.open_nofollow`; `DirLock` opens the lock path after the same checks; `os.replace`/`os.rename` by path; directory-entry durability relies on NTFS metadata journaling. This narrows but does not close link-swap races; the guarantee is the toolkit's cooperative-writer boundary, not a hard one. Tests marked POSIX-only where they need `dir_fd`.

### Command Contract

| Command | Flags | Result data (success) | Exit |
| --- | --- | --- | --- |
| `secure-code knowledge exit-preview` | `--project`, `--rule NS/VER/ID`, `--action deactivate\|reactivate\|delete\|rename`, `--to NS/VER/ID` (rename only), `--reason TEXT`, `--json` | `impact` (first key), `action`, `rule`, `target`, `reason`, `rule_state`, `will`, `impact_digest`, `references_block: false`, `recovered_exit`? | 0 / 1 |
| `secure-code knowledge exit-confirm` | the same + `--impact-digest DIGEST` | `outcome` (`deactivated`/`reactivated`/`deleted`/`renamed`), `rule`, `target`, `exit_id`, `lifecycle_revision`, `state_digest` (null for delete), `removed_pending`, `invalidated_index`, `tombstone`, `impact` (as committed) | 0 / 1 |
| `secure-code knowledge links` | `--project`, `--json` | `broken_relations: [{source, source_state, target, reason, renamed_to?}]`, `scopes: [{scope_id, rule, reason, renamed_to?}]`, `unreadable_scopes`, `counts` (read-only, no authorization) | 0 / 1 |

Preview `impact` shape (text output renders each kind with `count` and items; an empty list prints `(none)`, an unsupported kind prints its string):

```json
{"relations": {"count": 1, "items": [{"source": "CWE/4.14/CWE-20", "self": false}],
               "pointing_to_target": [], "unreadable_sources": []},
 "scopes": {"count": 1, "items": [{"scope_id": "sha256:…", "created_at": "…"}], "unreadable": []},
 "guard_runs": {"count": 0, "items": [], "unreadable": []},
 "copilot_collaborations": {"count": 0, "items": [], "unreadable": []},
 "pending_decisions": {"count": 0, "items": []},
 "document_index": {"count": 1, "items": [{"document": "sha256:…", "edge": true}], "unreadable": null},
 "presets": "not checked in this version", "tags": "not checked in this version",
 "reference_cache": "not checked in this version"}
```

`will` lists the effects in words (e.g. "move the rule folder to …/CWE-89-SQL", "remove 1 pending decision", "invalidate 1 index entry", "reserve CWE/4.14/CWE-89 as renamed to …", "no other rule, scope record, run or report is changed").

**Refusals** (one next step each; "nothing written" except recovery):

| Code | When | Next step |
| --- | --- | --- |
| `PROJECT_NOT_INITIALIZED` | existing `knowledge_root` | `secure-code init` |
| `NOT_AUTHORIZED` | no valid Maintainer authorization (preview and confirm; re-checked before the journal) | existing authorization step |
| `ARGUMENT_INVALID` / `ACTION_INVALID` | unknown action; `--to` without rename or missing for rename | fix the arguments |
| `REASON_REQUIRED` / `REASON_INVALID` | missing or blank; > 1000 characters, control characters or line breaks | give a one-line reason |
| `IMPACT_DIGEST_REQUIRED` | confirm without `--impact-digest` or not `sha256:<64 hex>` | run `exit-preview` and show the impact |
| `RULE_NOT_FOUND` | no rule folder; exited identities add `data.exited` (action, time, reason, `renamed_to`) | preview an existing rule |
| `RULE_INCONSISTENT` | deactivate/reactivate/rename on an inconsistent or unreadable rule | restore the rule files (e.g. from version control) or delete the rule |
| `RULE_FOLDER_UNREADABLE` | delete of an inconsistent/unreadable rule while a regular file in its folder cannot be opened and fully read, or a subfolder cannot be listed | fix the permissions, then preview again |
| `ACTION_NOT_APPLICABLE` | deactivate a deactivated rule; reactivate an active rule | preview the action that matches the rule's current state (state shown) |
| `RENAME_TARGET_INVALID` | other namespace or version; same ID | rename within `NS/VER` to a new ID |
| `RENAME_TARGET_EXISTS` | target folder exists (active, deactivated or leftover) or held as a pending decision | choose another ID |
| `IDENTITY_RESERVED` | target (or an import item) equals an exited identity, ignoring case | choose another ID |
| `IDENTITY_COLLISION`, `IDENTITY_INVALID` | existing 001-B checks on the target | choose another ID |
| `STALE_IMPACT` | recomputed digest ≠ given (impact changed, or digest of another rule/action/reason/target) — data: the new `impact` (no digest) | preview again and show the new impact to the Maintainer |
| `INDEX_INVALID` | confirm of deactivate/delete/rename while the document index is unreadable or malformed (preview still shows it as `unreadable`) | restore `.x-ipe/private/secure-code/knowledge-documents.json` or remove it (later imports rebuild it), then preview again |
| `LOCKED` | knowledge or scope lock (`DirLock`) not obtained within the timeout (also when recovery cannot run) | retry when the other operation finished |
| `EXIT_JOURNAL_INVALID` | journal fails validation | "A Maintainer must inspect `.x-ipe/private/secure-code/exits/journal.json` against the rule files, restore them (e.g. from version control) and move the journal aside; no knowledge was changed" |
| `EXIT_MEMORY_INVALID` | memory unreadable on a write path | restore or inspect the memory file |
| `EXIT_TRANSITION_INVALID` | the transition used for the scope-save exception is malformed or its digest/binding does not match | ask a Maintainer to inspect the exit transition and its changelog or memory binding; do not publish a scope |
| `PATH_UNSAFE` | any symbolic link, wrong kind or swapped component on a used path (rule, target, exits, tombstone, memory, journal, pending, index, scopes, locks, Guard/Copilot state roots) | replace the link with a real folder/file |
| `IO_ERROR` | OS error (incl. `EXDEV` detected before the journal); after the journal: "re-run any knowledge command; it completes the exit" | as stated |

Authorization actions: `knowledge.exit-preview`, `knowledge.exit-confirm` (via `_authorize`).

### Impact Providers (`impact.py`)

```python
@dataclass(frozen=True)
class Context:
    root: Path
    tree: durable.Tree             # the command's opened root; all provider I/O uses this
    ref: RuleRef
    target: RuleRef | None
    lib: resolve.Library           # snapshot taken under the knowledge lock

@dataclass
class Found:
    items: list[dict[str, Any]]
    extra: dict[str, Any] = field(default_factory=dict)   # unreadable lists, pointing_to_target
    def fingerprint(self) -> str: ...                      # sha256 of canonical {"items", **extra}

@dataclass(frozen=True)
class Provider:
    kind: str
    collect: Callable[[Context], Found]

PROVIDERS: tuple[Provider, ...] = (relations, scopes, guard_runs, copilot_collaborations,
                                   pending_decisions, document_index)
UNSUPPORTED: tuple[str, ...] = ("presets", "tags", "reference_cache")
```

| Provider | Reads (read-only, through `durable` no-follow handles) | Items (sorted) and fingerprint content |
| --- | --- | --- |
| `relations` | `lib.rules` records | sources whose `relations` contain `ref.rel` (`self: true` once for a self-relation); `unreadable_sources`; for rename `pointing_to_target` (relations that would start to resolve) |
| `scopes` | `x-ipe-docs/secure-code/scopes/<64 hex>.json` read no-follow, verified with `scope.verify_record` | records whose `adopted` contains the rule: `scope_id`, `created_at`; invalid files and link entries in `unreadable` |
| `guard_runs` | `.x-ipe/private/secure-code/guard/<RUN_ID>/state.json` read no-follow; schema `SCHEMA_RUN` and id checked | `status == "open"` and rule in `scope.adopted`: `verification_id`, confirmed `state_digest`; unreadable states and link entries in `unreadable` |
| `copilot_collaborations` | `.x-ipe/private/secure-code/copilot/<COLLAB_ID>/state.json` likewise (`SCHEMA_STATE`) | same for `status == "open"`: `collaboration_id`, `state_digest` |
| `pending_decisions` | `pending/<NS>/<VER>/<ID>.json` | `rule`, `held_at`, file SHA-256 |
| `document_index` | `lifecycle.read_index_strict` | documents whose `items` or `failed` mention `ref.rel`: `document`, `edge` (bool), SHA-256 of the canonical entry; malformed/unreadable file → `items: []`, `unreadable: {"detail", "sha256" of the raw bytes or error code}` (fingerprinted; never treated as empty) |

A link at a provider root (`scopes/`, `guard/`, `copilot/`, `pending/`, the index file) refuses the preview/confirm with `PATH_UNSAFE`; a link entry inside a root is listed as `unreadable` and never followed.

**Digest** (`impact.digest`): `"sha256:" + sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False))` with

```
canonical = {"schema": "ai-secure-code-toolkit/exit-impact/v1", "action", "rule", "target", "reason",
             "rule_state": {"consistent", "state", "revision", "state_digest", "fingerprint"},
             "providers": {kind: found.fingerprint() for each provider}, "unsupported": UNSUPPORTED}
```

`fingerprint` is the logical `files_fingerprint` (record + files of `read_rule`, including `changelog.md`) for a consistent rule, else the physical `folder_fingerprint` (every moving entry incl. residue). Later features append a provider and drop its kind from `UNSUPPORTED`; the contract is unchanged (new digests make older previews stale, which is safe).

### Preview and Confirm Algorithms (`exit.py`)

```python
def preview(project, rule, action, target, reason, *, trust_paths=None) -> Result
def confirm(project, rule, action, target, reason, impact_digest, *, trust_paths=None) -> Result
def links(project) -> Result
```

**Shared `prepare(tree, req)`** (called under the locks, with the command's single `durable.Tree`; never writes):
1. `store.read_rule_at(tree, ref)` via `resolve.safe_read(tree, ref)`; folder absent → `RULE_NOT_FOUND` (+ exit-memory info). Path errors → `PATH_UNSAFE`.
2. Consistency: `Unreadable`, `item is None` or `consistent` false → refuse unless `action == delete`.
3. Lifecycle: deactivate needs `active`; reactivate needs `deactivated`; delete any; rename keeps the current state (a deactivated rule may be renamed and stays deactivated).
4. Rename target: `RuleRef.parse` (`IDENTITY_INVALID`) → same `NS/VER`, different ID (`RENAME_TARGET_INVALID`) → `lifecycle.reserved` (`IDENTITY_RESERVED`) → `find_collision` (`IDENTITY_COLLISION`, also catches a case-only rename) → folder or pending file exists (`RENAME_TARGET_EXISTS`).
5. Snapshot `lib = resolve.snapshot(tree)` (handle-based rules, pending, exit memory), run every provider through the same `tree`, compute `rule_state` (incl. `special_entries`), `impact`, `digest`.

**Preview:** root → `ensure_recovered` → `_authorize("knowledge exit-preview")` → validate arguments and reason → `session(write=False)` (opens the `Tree` and `DirLock(knowledge.lock)`) + `DirLock(scopes.lock, create=False)` → `prepare` → result. No lock file is created, nothing else is written.

**Confirm** (fixed order; bracketed names are pause/crash test points):

```mermaid
sequenceDiagram
    participant M as Maintainer via agent
    participant X as exit-confirm
    participant K as knowledge.lock
    participant S as scopes.lock
    participant J as exits/journal.json
    M->>X: rule, action, target, reason, impact_digest
    X->>X: ensure_recovered (before auth)
    X->>X: _authorize (NOT_AUTHORIZED)
    X->>K: session(write=True) + recover again
    X->>S: DirLock(create=<scopes.lock exists>) via same Tree [exit_locked]
    X->>X: prepare → digest differs → STALE_IMPACT (new impact)
    X->>X: INDEX_INVALID if index unreadable and action writes it
    X->>X: store.recover_at(tree, rule) unless delete-of-inconsistent; re-read via read_rule_at(tree)
    X->>X: plan steps, pre_state, EXDEV device check; _authorize again
    X->>J: durable write (commit point) [exit_after_journal]
    X->>X: durable steps in order [exit_after_step]
    X->>J: durable unlink [exit_before_journal_delete precedes]
    X-->>M: success only now
```

Per action, the plan builds (every action also appends one transition-log entry whose `before`/`after` views are computed with `resolve.evaluate` on the locked snapshot and on the planned post-action snapshot, for the rule and, on rename, the target):
- **deactivate:** new record (`lifecycle = {state: deactivated, revision: n+1}`, `updated_at` unchanged), changelog entry `deactivated`, index entries with an edge for the rule → edge removed, label added to `failed`, `complete: false`, `updated_at` = exit time. Pending decisions kept.
- **reactivate:** record `lifecycle = {state: active, revision: n+1}`, changelog entry `reactivated`.
- **delete:** tombstone folder, move to tombstone, `exit-record.json`, pending removed, index invalidated, memory entry `deleted`.
- **rename:** record = old record with `rule_id`, `item_digest` (recomputed for the new ref), `updated_at`, `lifecycle.revision` (+ 1) changed only; content, examples, `name`, `applicability`, `source_location`, `source_documents`, `relations` (including a self-relation to the old ID), `created_at` unchanged in value; changelog entry `renamed` (old → new; the header line stays); move old → new folder; pending removed; index invalidated for the old label; memory entry `renamed` with `renamed_to`.

`changelog.lifecycle_entry(time, operation, exit_id, reason, revision_from, revision_to, state_before, state_after, impact_digest, old_id=None, new_id=None, changes=[record diff])` appends:

```
## 2026-10-22T10:15:00Z — renamed (role: maintainer)

- exit id: ex-…
- rule id: CWE/4.14/CWE-89 → CWE/4.14/CWE-89-SQL
- reason: Split into SQL-specific rule
- lifecycle revision: 1 → 2; state digest: sha256:… → sha256:…
- impact digest: sha256:…

### record.json
````diff
…
````
```

### Exit Journal: Apply, Validate, Recover (`exit_journal.py`)

```python
def ensure_recovered(root: Path) -> dict | None        # brief knowledge lock only if a journal or exit temp exists
@contextmanager
def session(root: Path, *, write: bool) -> Iterator[Session]   # lock(create=write or journal exists) + recover; Session.recovered
def run(root: Path, journal: dict) -> None             # durable journal, steps, durable removal (caller holds both locks)
def recover_locked(root: Path) -> dict | None          # validate everything, then apply; returns {"exit_id","action","rule","target","outcome"}
```

Crash points use the existing `store._crash_point` (`SECURE_CODE_TEST_CRASH_AT=name[@n]`): `exit_after_journal`, `exit_after_record`, `exit_after_changelog`, `exit_after_tombstone_dir`, `exit_after_move`, `exit_after_tombstone_record`, `exit_after_pending`, `exit_after_index`, `exit_after_memory`, `exit_after_transitions`, `exit_before_journal_delete`. A failure-injection hook (`SECURE_CODE_TEST_FAIL_AT=<primitive>:<step>[@n]`, test-only) raises `OSError` inside `durable` at: temp-file fsync, `replace`, directory fsync, `move` (incl. `EXDEV`), `unlink`, and the final journal removal.

**Op validation contracts** (checked for every step before anything is applied; each step is classified *done* or *not done*, anything else is invalid):

| Op | Journal fields checked | *done* | *not done* | Otherwise |
| --- | --- | --- | --- | --- |
| `write` | `sha256(text) == after`; `before` is a digest or null | target is a regular file with SHA = `after` | SHA = `before`, or absent when `before` is null | invalid |
| `append` | `sha256(suffix) == suffix_digest`; target bytes at classification | SHA = `after` | SHA = `before` **and** `sha256(current_bytes + suffix) == after` | invalid |
| `remove` | `before` digest | absent | regular file with SHA exactly `before` | invalid (other content, other kind) |
| `move` | `fingerprint` | source absent **and** destination present with fingerprint exactly `fingerprint` | source present with fingerprint exactly `fingerprint` **and** destination absent | invalid (both present, both absent, or any fingerprint mismatch) |
| `mkdir` (`tombstone_dir`) | — | folder present (empty, or containing only entries of later done steps) | absent | invalid (a link or a file) |

Text payloads are also structurally validated: `record` parses as `local-rule/v1` for the expected ID and its `item_digest` recomputes against the folder's content files; `memory` is `exit-memory/v1` containing exactly the previous entries plus this exit's entry; `index` is the strict-read before-index with exactly the `pre_state.index_edges` invalidated; `tombstone_record` is `exit-record/v1` for this exit.

**Journal-level checks:** schema; known `action`; `exit_id`, `at`, `impact_digest` and `transition_digest` patterns; `reason` rules; `rule`/`target` parse and match the action (target only for rename, same `NS/VER`); step names are unique, in the table order, include every required step, and every optional step is present exactly when `pre_state` requires it. The appended transition's digest equals `transition_digest`, and its binding in the planned changelog or exit-memory/exit-record payload matches. An **omitted** optional step is valid only if the actual state agrees: for delete and rename only (where `pending` is an optional removal step), no `pending` step ⇒ the rule's pending file is absent; deactivate and reactivate never carry a `pending` step and leave any pending file unchanged, so its presence or absence is not checked for them (AC-001D-03f); for every action with an optional `index` step, no `index` step ⇒ the current index contains no edge for the rule. Every derived path is opened through `Tree.dir` (no links). A truncated or partially edited journal that still parses fails one of these checks.

**Recovery** (under the knowledge lock; bounded to one journal):
1. No journal: remove exit-owned temporaries (`exits/.exit-*.journal.tmp`) → **roll back** (nothing had changed); return `{"outcome": "rolled_back"}` when any existed, else `None`.
2. Remove the journal's own exit temporaries (`.exit-<exit_id>.*.tmp`) in the derived folders, then run the journal-level checks and classify every step. The sequence must be a done-prefix followed by a not-done suffix; otherwise `EXIT_JOURNAL_INVALID` with nothing changed.
3. **Roll forward** the not-done suffix with the durable primitives, then durably remove the journal. Return `{"outcome": "completed", …}`; commands add it as `data.recovered_exit`.
4. **Narrow roll-back:** if the delete `move` fails with `EXDEV` while only `tombstone_dir` is done, recovery removes the empty exit-owned tombstone folder (`rmdir_empty`) and the journal (both durable) → `{"outcome": "rolled_back", "reason": "tombstone on another device"}`. No other roll-back after the journal exists.
5. Any other `OSError` → `IO_ERROR` with the journal kept (the next command retries); `LockHeld` → `LOCKED`.

Recovery is never an authorization decision: it only completes a journal a Maintainer already confirmed (honest limit U-13: not cryptographically bound).

### Recovery Hook Placement

| Command | Hook |
| --- | --- |
| `knowledge import`, `update`, `exit-preview`, `exit-confirm` | `ensure_recovered` before `_authorize`; each later `store.lock(root, write=True)` → `session(root, write=True)` |
| `knowledge check`, `list`, `show`, `links` | `store.lock(root, write=False)` → `session(root, write=False)` |
| `policy resolve`, `scope save`, `scope show` (and Guard/Copilot via `load_adopted`/`adoption_now`) | `policy.service._snapshot` uses `session(root, write=True)` (it already created only the lock file) |

`StoreError` gains `next_step` (default `None`); every mapping site passes it to `Result.refused`. `adoption_now` passes `EXIT_JOURNAL_INVALID` through with `LOCKED`/`IO_ERROR`. `status` (FEATURE-001-A) is not a knowledge command and is not hooked; its count stays correct because folder moves are atomic.

**Next-step propagation (small Copilot change):** Guard's `_refusal(loaded)` already carries `loaded.next_steps[0]` for `open` and for `_policy_now` (no Guard change). Copilot's `_policy_now` (`copilot/service.py` ~113–116) and `open` (~331–335) currently replace the step with `RETRY`/`SELECT_STEP`; they will use `loaded.next_steps[0]` when present for `EXIT_JOURNAL_INVALID`, `PATH_UNSAFE`, `LOCKED` and `IO_ERROR`, keeping their current step otherwise.

### Locking and Deadlock Analysis

| Path | Locks, in order |
| --- | --- |
| exit-confirm | knowledge → scopes |
| exit-preview, links | knowledge (`create=False` unless a journal exists) → scopes (`create=False`) |
| scope save (changed) | knowledge → scopes (publication inside) |
| policy resolve, scope show | knowledge |
| knowledge import/update/check/list/show | knowledge |
| guard open/conclude, cancel | guard → knowledge (via `load_adopted`) |
| copilot open/report/close | copilot → knowledge |

No path takes scopes before knowledge, and no knowledge or scope holder takes the guard or copilot lock (impact reads their state files, written by atomic replace, without locks). The order graph is acyclic; `ProcessLock` timeouts (10 s) bound any wait with `LOCKED`. `ProcessLock` uses `flock` per open file, so the same process must not re-open a held lock: `save_scope` calls `resolve.snapshot` directly inside its session instead of `_snapshot`.

### Changes to FEATURE-001-C

- **`resolve.Library`** gains `exited: dict[str, dict] = field(default_factory=dict)` (from the exit memory) and `notices`; `snapshot` fills them.
- **`evaluate`** precedence: absent → `exited` exact match → `deleted` / `renamed` (+ `renamed_to`, information only) → `pending_decision` → `not_found`; unreadable → `unreadable`; inconsistent (incl. malformed lifecycle) → `inconsistent`; consistent and `deactivated` → `deactivated`; else available with `state_digest = store.state_digest(stored)`. No content for any `missing`; the new ID's rule is never returned.
- **Version-less refs** with no stored versions but exited identities `NS/*/ID` → `missing` with the reason of the most recent exit and `exited: [{rule, reason, renamed_to}]`.
- **Version-less refs with a remaining stored version** (human decision, BR-04 reading): resolution is unchanged (one stored version → that version; several → `unclear` with candidates, a deactivated version being a `missing`/`deactivated` candidate). When the exit memory holds exited identities `NS/*/ID` (deleted or renamed away), the entry additionally carries the informational `exited: [{rule, reason, renamed_to}]` (sorted by `rule`; `renamed_to` is `null` for deletions) and the text output adds one line naming them. `exited` is information only: it never changes `availability`, `reason`, `rule`, `candidates`, counts, status or the `proposal_digest` inputs, and the version-less reference is not a broken reference. Explicit references to an exited identity stay `missing` and are never substituted by another source version.
- **"All"** (`apply_all`): requested = stored rules except consistent deactivated ones; data gains `inactive: {"deactivated": n, "deleted": n, "renamed": n}` (informational; `counts`, `status` and `proposal_digest` unaffected). `library_size` keeps its meaning (stored rules). If every stored rule is deactivated, the next step is "All Local rules are deactivated: ask a Maintainer to reactivate or import rules".
- **`proposal_digest`** is unchanged (no new keys), so existing decisions files and digests stay valid.
- **`load_scope`**: `missing` entries copy `renamed_to` when present. Status rules unchanged (`partial` / `maintenance_needed`); the record file is only read.
- **Scope save** (`policy/service.save_scope`): `with session(root, write=True) as session: lib = resolve.snapshot(session.tree); data = build; [pause scope_save_locked]; scope.check_decisions(dec, data, lib); build_record; [pause scope_save_before_publish]; scope.publish(...)`. The knowledge lock is held across the final re-check and the publication (scope lock inside `publish`, acquired through `DirLock` relative to `session.tree`).
- **Not-adopted exception** (`scope.check_decisions`, AC-001D-02f): when `data.proposal_digest != dec.proposal_digest`:
  1. Read the latest committed transition for the affected identity through the command's `Tree`. Verify its canonical digest against both the entry's `digest` and its binding in the exit changelog or exit memory; invalid data refuses with `EXIT_TRANSITION_INVALID`. Its complete `after` identity views must still match the current library. A later content edit or another lifecycle action is not explained by this transition.
  2. Build a transient pre-action view of the **whole library**: apply every `before` identity view from this single transition, keeping the rest unchanged. For rename this restores the old source and removes the newly introduced target; for deactivate/delete it restores the source's previous membership and state. `Library.overrides` supplies these views to `evaluate`, version-candidate enumeration and active-rule enumeration without changing files. Only the projection consumed by `proposal_digest` is reconstructed, not Policy content.
  3. Rebuild the full original request from that view, with the same mode and language context. It must reproduce `dec.proposal_digest` exactly. Every originally considered reference whose entry or membership changed must have an explicit `not_adopted` decision; any adopted affected reference, unrelated delta, ambiguous explanation or multiple-action chain gives `STALE_CONFIRMATION`, with no publication.
  4. For `apply_all`, a rename's newly introduced target is also removed in step 2, even though it has no prior decision. It is **not adopted** implicitly: publication uses only the original confirmed reference set, and the result reports the new target as outside that confirmed scope. A reactivation under `apply_all` always gives `STALE_CONFIRMATION`: the formerly deactivated rule was absent from the original active set and had no explicit not-adopted decision. Reactivation in clues mode can use the exception when that reference was explicitly considered and decided `not_adopted`.
  5. Run the normal decision validation against the reconstructed considered set, then build the scope using the actual current state of each originally considered reference. Unaffected adopted entries must still have their confirmed digests; not-adopted entries retain the user's reason and current availability. New targets are never added to adoption, and all other decision/zero-adoption checks remain in force.

  The exception changes no rule or reference and is limited to one integrity-checked transition; it is never backed by a `previous` field in formal rule metadata. Never-exited libraries use the existing path unchanged.

### Changes to FEATURE-001-B

- **Update base state:** `update_rule` compares `--base-state` with `store.state_digest(stored)`; `STATE_CONFLICT` data adds `state_digest` next to `item_digest`. For never-exited rules both are equal.
- **Import contract unchanged:** `update_candidate.stored_digest` and `--accept-update RULE@DIGEST` stay item-digest (content) based. Remaining limitation (documented in the skill and CLI contract): an update candidate obtained before a deactivate→reactivate cycle can still be accepted after reactivation, because the content it was compared with did not change; a deactivated identity itself is refused (below), and a concurrent exit is serialized by the knowledge lock.
- **Import refusals** in `_import_one` (under the lock, before the digest comparison): exit-memory match ignoring case → `IDENTITY_RESERVED` (reason: deleted at … / renamed to …); stored and deactivated → `RULE_DEACTIVATED` (reason names the reactivate step); the result's `next_steps` adds "Reactivate RULE first with secure-code knowledge exit-preview --action reactivate" once. Other items follow the existing partial-import rules; tombstone and memory are untouched.
- **Check:** a document is `fully_stored` only if every edge's rule is stored, consistent, equal and **not deactivated** (defence in depth beside the index invalidation). `check` and import keep the existing lenient index reader.
- **List:** each rule adds `state` (`active`/`deactivated`), `state_digest`, `lifecycle_revision`; data adds `exited: [{rule, action, renamed_to, at, reason}]`.
- **Show:** adds `state`, `state_digest`, `lifecycle_revision`, `relations_status: [{target, availability, reason?, renamed_to?}]` (via `resolve.evaluate` on a partial library of the relation targets) and `broken_relations` (the non-available ones). An exited identity → `RULE_NOT_FOUND` with `data.exited`.

### Broken-Link Check (`exit.links`)

1. Root → recovery via `session(write=False) as session` (+ scopes `DirLock` relative to `session.tree`, `create=False`) → `lib = resolve.snapshot(session.tree)`.
2. For every stored rule (active or deactivated; unreadable ones listed in `unreadable_sources`), for each relation string: `parse_requested` + `resolve.entry_for`; not `available` → `{source, source_state, target, reason, renamed_to?}` (reasons include `not_found`, `deactivated`, `deleted`, `renamed`, `inconsistent`, `unreadable`, `invalid_reference`).
3. For every scope record file (64-hex name, regular file, read no-follow): verify (invalid → `unreadable_scopes`); each adopted rule evaluated; reasons `deactivated`, `deleted`, `renamed`, `not_found` → listed.
4. Sorted output, `counts`; `ok: true`; next step "Repairing references is a separate, explicit decision by an authorized person". Nothing is substituted or written.

### Framework SKILL.md — "Exiting Knowledge" (new section after "Maintaining Knowledge")

1. Only on a real Maintainer request to deactivate, reactivate, delete or rename one Local rule; never on your own initiative. Ask for the reason.
2. Run `secure-code knowledge exit-preview` and **show the whole impact to the Maintainer first** (relations, adopted scopes, open Guard verifications and Copilot collaborations, pending decisions, index entries, and the kinds "not checked in this version").
3. State clearly that **references do not block the decision**, and that nothing else will be changed: other rules, scopes, runs and reports keep pointing to the old rule and are reported broken.
4. Run `exit-confirm` with the shown `impact_digest` **only after the Maintainer explicitly confirms**; never confirm on the Maintainer's behalf. On `STALE_IMPACT`, preview again and show the new impact.
5. **Never repair references automatically** (no edits to relations, scopes or batches to point to another rule or version). Use `secure-code knowledge links` to list broken references; repair is a separate explicit choice.
6. Deleted and renamed identities are reserved; restore is not available (reactivate undoes only a deactivation). `EXIT_JOURNAL_INVALID`, `INDEX_INVALID` or `LOCKED`: report to the Maintainer; do not edit private files yourself.

Also: step 7 of "Maintaining Knowledge" uses `state_digest` as `--base-state` (imports keep `--accept-update RULE@<stored_digest>`); "Selecting Policies" lists the new `missing` reasons and that "all" covers active rules only; "Status of This Skill" names FEATURE-001-D as delivered. `references/cli-contract.md` gains the three rows and codes; `references/policy-selection.md` the reasons and the not-adopted exception.

### Implementation Steps (test-first)

1. **Characterization (green before change):** capture fixed vectors — record bytes, item and state digests, proposal digests and scope IDs of a fixture library; Guard/Copilot `adoption_now` results; import `update_candidate`/accept outputs — into `test_exit_units.py`.
2. `durable.py` (no-follow handles, `DirLock`, durable primitives, failure-injection hook) with `test_exit_durable.py` RED first. `atomic.ProcessLock` stays unchanged.
3. `store` lifecycle helpers, handle-relative `read_rule_at`/`iter_refs_at`/`list_pending_at`/`recover_at`, `record_text(lifecycle)`, `_pause_point`, `StoreError.next_step`; `lifecycle.py` (memory, reserved, fingerprints, strict index, reasons) — unit tests.
4. `exit_journal.py`: op contracts, progress check, roll-forward/roll-back, `session`, `ensure_recovered` — `test_exit_journal_fixtures.py` with hand-built journals and states.
5. Hook replacement in `knowledge/service.py` and `policy/service.py`; base state, import refusals, check, list/show; resolve/scope changes incl. the not-adopted exception; Copilot next-step pass-through — existing 001-B/001-C/003-A suites stay green plus new tests.
6. `impact.py` and `exit.py` (preview, confirm, links), CLI — integration tests per AC.
7. Crash matrix, failure injection, symlink canaries and concurrency tests (subprocess with crash/fail/pause hooks).
8. Guard/Copilot integration (`test_exit_runs.py`, next-step propagation) and their full suites.
9. SKILL.md, references, README; skill phrase tests. Module-size test; `ruff check`; full suites (macOS 3.14/3.11, Linux 3.12).

### Edge Cases & Error Handling

| Case | Handling |
| --- | --- |
| Rule relates to itself | Listed once (`self: true`); on rename the relation stays pointing to the old ID and is reported `renamed` |
| Relations of the renamed rule to other rules | Unchanged, move with the record |
| Relations elsewhere already pointing to the rename target | Shown as `pointing_to_target` in the preview (they will start to resolve) |
| Rename only in letter case | `IDENTITY_COLLISION` (the old folder collides) |
| Rename / delete of a deactivated rule | Allowed; rename keeps `deactivated` |
| Rule with a pending 001-B commit journal | Preview uses the logical view; confirm runs handle-relative `store.recover_at` through the command's `Tree` after the digest check (delete of an inconsistent rule moves it as found, `pending_commit` recorded) |
| Atomic residue in an inconsistent rule changes between preview and confirm | Physical fingerprint differs → `STALE_IMPACT`; for a consistent rule residue is not knowledge (logical view), it moves with the folder and is bound by the journal's `move` fingerprint |
| Permission-unreadable regular file in a rule being deleted | `RULE_FOLDER_UNREADABLE`; no metadata-only substitute for its content digest; fix permissions and preview again |
| FIFO/device/socket in a rule being deleted | Its entry kind and metadata are fingerprinted and listed, never opened; moved as found |
| Inconsistent rule, deactivate/reactivate/rename | `RULE_INCONSISTENT` with the restore-or-delete step |
| Exit while Guard/Copilot run is open | Allowed; listed; run reports `changed`/`missing` at its next conclusion or report |
| Guard/Copilot opened while a confirm holds the knowledge lock | Waits (≤ 10 s) in `load_adopted`, then sees the new state (`SCOPE_PARTIAL`/maintenance) or `LOCKED` |
| Renamed-away label in a document entry | Stays in `failed`; the document stays not fully stored until its source no longer names the old ID (conservative) |
| Index malformed | Preview shows `document_index.unreadable`; confirm of deactivate/delete/rename → `INDEX_INVALID`; reactivate unaffected |
| Tombstone, exits, memory, journal, pending, index, lock or rule component replaced by a link | `PATH_UNSAFE`; nothing written outside (no-follow handles; swapped components fail with `ELOOP`/`ENOTDIR`) |
| Knowledge and private folders on different devices (delete) | Detected before the journal → `IO_ERROR`, nothing written; `EXDEV` after the journal → narrow roll-back |
| Journal hand-edited or truncated | `EXIT_JOURNAL_INVALID`; all knowledge and Policy commands refuse until the Maintainer resolves it |
| Exit memory unreadable | Writes refuse `EXIT_MEMORY_INVALID`; reads degrade with notice |

### Security, Tracing and Observability

- POSIX: every exit mutation and read of toolkit files uses directory-handle-relative, no-follow operations (`durable.py`); fingerprints and moves never follow links; journal paths are derived, not trusted. Windows: `lstat`/identity checks only (narrower, cooperative-writer limit stated above). Tombstones, memory and journal are owner-only under `.x-ipe/private/secure-code/`. No network; only toolkit files are read (NFR-001D-4).
- The reason is single-line, ≤ 1000 characters, stored in changelog, memory and exit record; it is Maintainer-authored data.
- The preview exposes private run, collaboration and decision identifiers only to a verified Maintainer (FR-001D-1).
- Honest limit U-13: a local writer could forge a structurally valid journal, as they could edit rule files directly.
- Tracing: N/A — the toolkit has no tracing infrastructure; the result envelope, changelog entries, exit records and `recovered_exit` are the observable record; no logging of free text.

### Goal / Acceptance / Design / Validation Coverage

Test paths are under `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/`. Delivery state: planned for every row. Outcome: not measured.

| AC | Design means | Planned validation |
| --- | --- | --- |
| 01a | `confirm` with no reference-based refusal; steps touch only the rule, its pending/index/memory/tombstone | `knowledge/test_exit_actions.py`: rule with incoming relation + adopted scope; deactivate, delete, rename each succeed; `tree_hashes` of other rules, scopes, guard/copilot private states and reports byte-identical |
| 01b | `ensure_recovered` → `_authorize` before any read | `test_exit_preview.py`: missing/invalid/revoked trust → `NOT_AUTHORIZED`, no `impact` key, tree unchanged |
| 01c | authorization at entry and again before the journal | `test_exit_preview.py`: confirm without auth; preview with auth, revoke, confirm → refused, tree unchanged |
| 02a | six providers, `will`, digest; preview writes nothing | `test_exit_preview.py` per action with one item of every kind (Guard and Copilot open states via their services); tree unchanged incl. no lock files created |
| 02b | `UNSUPPORTED` strings | preview data/text contain "not checked in this version" for presets, tags, reference_cache |
| 02c | provider fingerprints + rule-state fingerprint | between preview and confirm: update rule, add/remove relation on another rule, save scope, write pending, change index entry, make the index malformed → each `STALE_IMPACT` with new impact; tree unchanged |
| 02d | `IMPACT_DIGEST_REQUIRED`, digest binds rule/action/reason/target, `RULE_NOT_FOUND` | confirm without digest; with digest of other rule/action/reason/target; unknown rule |
| 02e | empty `items`, confirm still required | isolated rule preview: every supported count 0; confirm without digest refused |
| 02f | lock order; scope save under both locks with the transition-based not-adopted exception; pause points | `test_exit_concurrency.py` (subprocesses + `SECURE_CODE_TEST_PAUSE_AT`): (a) save first → confirm `STALE_IMPACT`; (b) confirm first, rule **adopted** → `STALE_CONFIRMATION`, no scope file; (c) confirm first, rule decided **not_adopted**: deactivate/delete/rename in clues and `apply_all` → published using only the original confirmed references; rename removes the new target from the reconstructed proposal and never adopts it; (d) reactivate with clues and explicit `not_adopted` → published; reactivate under `apply_all` → `STALE_CONFIRMATION`; (e) not-adopted exit plus another content change or a second exit → `STALE_CONFIRMATION`; (f) save paused before publish blocks the confirm; (g) Guard/Copilot open during confirm → waits then `SCOPE_PARTIAL`; open before → conclude/report `changed`/`policy_changed` |
| 03a | deactivate plan | record marker, content/changelog kept, changelog entry with time and reason, state digest changed |
| 03b | reactivate plan, revision monotonic | reactivate → available; changelog; state digest ≠ both earlier values; reactivate active → `ACTION_NOT_APPLICABLE` |
| 03c | tombstone + exit record + memory | rule folder gone; tombstone holds content, examples, record, full changelog bytes; exit record fields |
| 03d | rename plan | new folder only; content/examples bytes equal; record diff limited to `rule_id`, `item_digest`, `updated_at`, `lifecycle`; changelog old→new; memory `renamed_to`; self-relation reported `renamed` |
| 03e | `prepare` target checks | existing active, deactivated, deleted, renamed-away, case variant of each, other NS, other version, invalid ID, same ID → refused in preview and confirm; tree unchanged |
| 03f | pending/index steps per action; check change | delete/rename remove and report pending; deactivate keeps it; index edges moved to `failed`; `knowledge check` of the document → `not_fully_stored` in all three |
| 03g | `REASON_REQUIRED` | confirm with none/blank reason; tree unchanged |
| 03h | consistency gate; physical fingerprint of every moving entry; as-found move | corrupt `content.md` / unparsable record / malformed lifecycle: deactivate/reactivate/rename previews refused with restore-or-delete step; delete preview digest changes when any readable file, link text, residue file or entry kind changes; an unreadable regular file or unlistable subfolder → `RULE_FOLDER_UNREADABLE`, no journal or move; FIFO/device/socket is listed, never opened; tombstone bytes equal the readable folder as found; `consistent: false` |
| 04a | `evaluate` reasons | resolve explicit refs: `deactivated`, `deleted`, `renamed` + `renamed_to`; no `requirement`; new ID not returned for the old ref |
| 04b | active-only "all", `inactive` | `policy/test_policy_exit.py`: `--all` with one deactivated, one deleted, one renamed → only active entries; counts informational; status unaffected |
| 04c | `load_scope` reasons | scope show after each exit: `missing` with reason; record bytes equal; `partial`/`maintenance_needed` |
| 04d | lifecycle revision in state digest | deactivate+reactivate unchanged content → `needs_reconfirmation`, `partial`, re-confirm step |
| 04e | `links`, show `broken_relations` | links lists source/target/reason; show marks; relation bytes unchanged |
| 04f | no report/scope writes; open runs via `adoption_now` | `policy/test_exit_runs.py`: report and scope tree hashes equal after each action; open Guard conclude and Copilot report show the change incl. after deactivate→reactivate |
| 05a | `_write_rule` keeps lifecycle; base = state digest | update deactivated rule with its `state_digest` → updated, still deactivated; current state no longer matches an old transition's `after`, so that transition cannot justify a later stale scope save |
| 05b | `RULE_DEACTIVATED` | batch with deactivated identity + valid item → refused with reactivate step; other stored |
| 05c | `IDENTITY_RESERVED` (case-insensitive) | import exact and case variant of deleted and renamed-away identities; tombstone/memory hashes unchanged; others stored |
| 05d | list/show markers | list: `state: deactivated`, `exited` with reason and time; show exited → `RULE_NOT_FOUND` + `exited` |
| 06a | durable journal, op contracts, progress check, hook everywhere | `test_exit_recovery.py`: every crash point of all four actions, including the transition-log step (exit code 86, no success output); next command rotates over import, update, exit-preview, check, list, show, links, resolve, scope save, scope show; invariant helper checks folder/marker, tombstone or new ID, changelog, revision, memory, transition log and its binding, pending, index and `not_fully_stored`; held lock with a journal → `LOCKED`. `test_exit_journal_fixtures.py`: per action, every done-prefix (0…n) and the all-done state complete; tampered suffix and tampered prefix, omitted required step, omitted optional step while the pre-state has it, duplicate/out-of-order steps, payload/suffix/transition digest mismatch, malformed and truncated-but-parseable journals → `EXIT_JOURNAL_INVALID` with tree unchanged; stray exit temporaries roll back |
| 06b | single knowledge lock; base state includes revision | concurrent exit + update and exit + exit processes: serialized; stale update `STATE_CONFLICT`; second exit `STALE_IMPACT`; no half state |
| 06c | SKILL.md section | `knowledge/test_exit_skill.py`: preview-and-show, never confirm without real request, never repair automatically, references do not block |

**Risk-focused tests in addition** (`test_exit_durable.py`, `test_exit_units.py`, `test_exit_runs.py`):
- **Symlink canaries:** each of — a source-rule path component (namespace, version, rule folder), the rename target's parent, `exits/`, `journal.json`, `memory.json`, `transitions.json`, `tombstones/`, a tombstone folder, the pending folder and file, the index file, the parent lock directory and `knowledge.lock`/`scopes.lock`, `scopes/`, the Guard and Copilot state roots and one run/collaboration folder — replaced by a link to an outside canary folder/file: `PATH_UNSAFE` (or `unreadable` entry for in-root links), canary bytes unchanged. POSIX-only **component swap** tests replace a folder with a link before the no-follow walk (refusal) and after a handle was opened (operation stays on that original directory, never follows the replacement link). Lock tests also hold one lock while a second process tries it and assert exclusion.
- **Transition integrity and preservation:** rename changes only the allowed formal-record fields; no `lifecycle.previous` is added. Hand-edit a transition without updating its journal/changelog/memory binding → `EXIT_TRANSITION_INVALID`, no scope publication. Reconstruct rename in `apply_all` with both old and new identities; reactivate in `apply_all` stays stale. A later content edit cannot reuse an older transition.
- **Durability ordering:** a fake `os.fsync`/`os.replace` recorder asserts journal write+dir fsync precede the first step, each step's dir fsync precedes the next, journal unlink+dir fsync precede the success result; new tombstone folders fsync their parent.
- **Injected failures** (`SECURE_CODE_TEST_FAIL_AT`): temp fsync, replace, directory fsync, move, unlink and final journal removal, at each step of each action → `IO_ERROR`, never success; the next command completes the exit. Mocked `EXDEV` before the journal (device check) → nothing written; after the journal → narrow roll-back, rule unchanged.
- **Determinism and compatibility:** digest stable across runs and provider order; characterization vectors unchanged; import `update_candidate`/accept unchanged (item digest).
- **Next-step propagation:** Policy refusals `EXIT_JOURNAL_INVALID`, `PATH_UNSAFE`, `LOCKED`, `IO_ERROR` keep their next step through `guard open`, guard conclude, `copilot open` and copilot report.

### Outcome Scenario and Evidence Gaps

On a copy of the marathon sample: rule `CWE/4.14/CWE-20` relates to `CWE/4.14/CWE-89`, which a confirmed scope adopts and an open Guard verification uses. The Maintainer previews the rename to `CWE-89-SQL` and sees the relation, the scope and the run; confirms; then `knowledge links` and `scope show` report `renamed` (to `CWE-89-SQL`, not substituted), the scope loads `partial`, the verification concludes with the Policy change and earlier reports stay byte-identical. Planned as black-box acceptance; real Maintainer use: **not measured**. Preset/tag impact with non-empty fixtures awaits FEATURE-001-F. Power-loss durability is evidenced only by fsync-ordering tests (no real power-cut test); Windows link-swap resistance is limited as stated.

### Test Plan

Test-first per implementation step. Integration tests call service functions on temporary initialized projects (fixtures from `tests/knowledge/test_knowledge.py` and `tests/conftest.py`: `env`, `item`, `write_batch`, `tree_hashes`, `run_cli`); crash and race tests use `run_cli` subprocesses with `SECURE_CODE_TEST_CRASH_AT`, the new `SECURE_CODE_TEST_FAIL_AT` and `SECURE_CODE_TEST_PAUSE_AT=<point>=<path>` (writes `<path>.ready`, waits ≤ 30 s for `<path>.go`; test-only, never changes data). Knowledge/scope `LOCKED` paths use a held `DirLock` in process tests or a `DirLock.__enter__` monkeypatch; existing Guard/Copilot lock tests remain unchanged. Journal fixtures build states by applying the first *k* planned steps with the durable primitives, then tamper. Black-box acceptance later runs the CLI through `uvx` (host and Linux container).

### Mockup-to-Component Mapping

N/A — no UI.

### Delta and Evidence Invalidation

Additive changes to completed features:

| Feature | Changed | Evidence to rerun |
| --- | --- | --- |
| FEATURE-001-A | `atomic.ProcessLock` unchanged; knowledge and scope consumers use new `durable.DirLock` | `tests/test_*` (status, init), module-size test |
| FEATURE-001-B | lock hook, update base state, import refusals (import digest contract unchanged), check, list/show fields, `record_text` | `tests/knowledge`; [acceptance/blackbox.py](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/acceptance/blackbox.py) host + container |
| FEATURE-001-C | reasons, "all", `inactive`, `renamed_to`, `_snapshot` hook, save locking and not-adopted exception, `adoption_now` passthrough | `tests/policy`; [acceptance/blackbox.py](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/acceptance/blackbox.py) |
| FEATURE-002-A | none in code; behaviour via `load_adopted`/`adoption_now` (next steps already kept by `_refusal`) | `tests/guard` + new propagation tests; [acceptance/blackbox.py](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/acceptance/blackbox.py) |
| FEATURE-003-A | `copilot/service.py` next-step pass-through for four Policy refusal codes | `tests/copilot` + new propagation tests; [acceptance/blackbox.py](x-ipe-docs/requirements/EPIC-003/FEATURE-003-A/acceptance/blackbox.py) |

**Backward compatibility, verified against the code:**
- `policy/resolve._policy` sets `source_evidence.state_digest = stored.digest` (the item digest); `scope.check_decisions`/`load_scope` and Guard/Copilot `adoption_now` compare only that value. With `state_digest()` returning `stored.digest` for records without `lifecycle`, every existing scope record, decisions file, proposal digest and run state stays valid; no existing record gains a key (`record_text` omits `lifecycle` when `None`).
- `proposal_digest` keys are unchanged; "all" filters only deactivated rules and the not-adopted exception needs exited identities, neither of which can exist before this feature.
- Import `update_candidate.stored_digest` and `--accept-update` remain item-digest based (FEATURE-001-B contract).
- Guard (`guard/service._policy_now`) and Copilot (`copilot/service._policy_now`) map `missing`/`changed` already; the new reasons arrive as `missing` and reactivation as `changed`. Only Copilot's next-step text for four refusal codes changes.
- Read-only guarantees of 001-B/001-C hold: the hook writes only when a journal exists (spec reading of "nothing written").

Stakeholder outcome evidence of 001-B/001-C/002-A/003-A is not affected (not measured).

## Design Verification (TASK-050)

- Resume: original task/role retained (`TASK-050`, Sage). Human confirmed this design and authorized test-first implementation on 10-22-2026; the lifecycle owner hands the feature to Designed. Free-mode, `interact-with-human`; no application workflow or Git writes.
- Specification SHA-256: `fb74bfe254d3a6cbd373e5deb743c279fc2292e2e8bf97c12aa75bf2e06abcc2`; technical-design configuration source (`tools.json`) SHA-256: `6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d`.
- Mechanical coverage check: all 30 leaf AC IDs have distinct rows in the planned validation table. This is coverage consistency, not passing implementation evidence.
- Independent focused re-review of design SHA-256 `84889e3ded9fcafbeddd4c02f54e53feb65e0290f15481d23faba392024974a3`: all four remaining blockers resolved; no remaining or new blocking issues within that scope. Reviewed scope: complete scope-save projection, private transition integrity/rename preservation, no-follow locks and snapshots, unreadable-file refusal. Prior reviews and their fixes remain recorded below.
- Post-review documentation-only changes: this verification record and the lock-test helper name aligned to the already-reviewed `DirLock` design; no algorithm or acceptance change.
- Implementation, crash injection, durability checks and acceptance tests: not run at design stage. Stakeholder outcome: not measured.

## Implementation Evidence (TASK-051)

Stage A (tests) and Stage B (product implementation, groups G1–G6 authorized by the owner)
by the retained worker under Sage; standalone Python CLI/library. Specification input SHA-256
`fb74bfe254d3a6cbd373e5deb743c279fc2292e2e8bf97c12aa75bf2e06abcc2`;
approved design input SHA-256 (v1.0, Stage A)
`92f49ee0adc3d230befc7ff926dc1b4c7e39ccaa7c6591c86f228a7786231a7a`; Stage A'
(review test fixes) design input v1.1 SHA-256
`4ae37fd072930a9a88e103d1b4da59e2baa7dc3d5125b1455ac6e154a09ca184` (before this
evidence-section update).
The table below is the assertion inventory written before implementation; the passing
evidence is "Stage B GREEN results" at the end of this section. Every leaf AC retains its original **Integration** type.
Supplementary primitive tests do not replace service/CLI integration checks.
Parent/source: EPIC-001 G-03 / FR-07; stakeholder outcome remains **not measured**.

Paths below are relative to Framework `scripts/tests/`; `K` means `knowledge/`,
`P` means `policy/`. Each test uses Arrange (real initialized local fixture), Act
(service/CLI operation), Assert (listed observable contracts). Tests' docstrings
retain AC links and AAA intent; helpers never grant production authorization.

| AC / story | AAA scenario / test inventory | Assertions retained |
| --- | --- | --- |
| 01a / US-02 | K/test_exit_actions.py `test_references_never_block_or_cascade` | Incoming relation, adopted scope, open private Guard/Copilot runs and real prior reports; deactivate/delete/rename each succeed; every dependent byte remains unchanged. |
| 01b / US-02 | K/test_exit_preview.py `test_preview_authorization` | Missing/invalid/revoked authorization refuses NOT_AUTHORIZED with next step, no impact, no current-request writes. Recovery exception independently exercised in recovery tests. |
| 01c / US-02 | K/test_exit_preview.py `test_confirm_authorization`, `test_revoked_after_preview` | Missing/invalid/revoked confirmation refuses without writes; authorization revoked after a valid preview is re-verified. |
| 02a / US-01 | K/test_exit_preview.py `test_all_providers_and_read_only_preview`, `test_confirm_success_contract`, `test_cli_commands_json_and_text` | Every action including reactivate; six non-empty providers identify incoming source, adopted scope, open Guard/Copilot, pending and index; digest and no writes. Preview data keys exactly the Command Contract set (+ optional `recovered_exit`), `rule`/`target`/`rule_state`; `will` words state no other rule/scope/run/report changes, index invalidation (deactivate/delete/rename), pending removal and reservation (delete/rename), rename target. Confirm data keys exactly the Command Contract set; outcome, rule, target, exit-id pattern, lifecycle revision, `state_digest` (null for delete, else the shown state digest), removed pending, invalidated index, tombstone path, committed `impact` equal to the previewed impact. |
| 02b / US-01 | K/test_exit_preview.py `test_empty_supported_not_unsupported` | Presets/tags/Reference cache explicitly not checked, never empty; JSON and text distinguish supported empty lists. |
| 02c / US-01 | K/test_exit_preview.py `test_changed_impact_is_stale` | Rule update, relation add/remove, adopted-scope publication, pending/index changes and malformed index each stale, no mutation; refusal carries the NEW `impact` (no digest), equal to a fresh preview of the changed state whose digest differs from the confirmed one; for every provider delta the impact differs from the confirmed preview (a rule-only change alters only the digest-bound `rule_state`). |
| 02d / US-01 | K/test_exit_preview.py `test_confirmation_digest_binding` | Missing/malformed digest, other rule/action/reason/target, missing source; refusal reason, preview next step and no changes. |
| 02e / US-01 | K/test_exit_preview.py `test_empty_supported_not_unsupported` | Dependency-free rule: all supported items/counts empty; still requires confirm digest. |
| 02f / US-02 | K/test_exit_concurrency.py; P/test_policy_exit.py scope-transition tests; P/test_exit_runs.py concurrent-open tests | Both process orderings, knowledge→scope locks held through publication; adopted exit stale/no publication; single verified transition allows explicitly not-adopted deactivate/delete/rename in clues/all; rename restores old and removes new target, never adopts it; reactivate all stale, clues not-adopted succeeds; unrelated delta/multiple exits stale; concurrent run open waits and reports Policy change. Every race uses a bounded handshake instead of fixed sleeps: the holder pauses at a designed point (`exit_locked`, `scope_save_locked`, `scope_save_before_publish`) and a test-side subprocess wrapper (`exithelp.PROBE`, wraps OS `flock`/`lockf`/`msvcrt.locking`; no production API) proves the contender reached acquisition of the knowledge lock file (same inode) and is blocked, still without a result, before release. |
| 03a / US-04 | K/test_exit_actions.py `test_deactivate_and_reactivate_history` | Stored content/examples and prior log retained; state deactivated; action/time/reason in log; revision/state digest changes. |
| 03b / US-05 | K/test_exit_actions.py `test_deactivate_and_reactivate_history`, `test_action_state_guards` | Reactivation preview/confirm with reason makes available; history and non-repeating revision/digest; active reactivation refused. |
| 03c / US-04 | K/test_exit_actions.py `test_delete_tombstone` | Formal folder absent; private tombstone preserves last record/content/examples/full changelog; exit action/time/reason and owner-only modes. |
| 03d / US-04 | K/test_exit_actions.py `test_rename_preserves_non_identity_metadata` | Only new ID exists; byte-identical content/examples; record differences exactly `rule_id`, `item_digest`, `updated_at`, `lifecycle` (`updated_at` arranged earlier and must change to a new UTC time); new state digest differs and equals the confirm result; source/name/applicability/documents/relations retained, including self-relation broken renamed; old→new log and exit memory. No lifecycle.previous. |
| 03e / US-02 | K/test_exit_actions.py `test_rename_target_refusals` | Preview and confirm reject active/deactivated/deleted/renamed identities and case variants; namespace/version/same/invalid/pending targets; reason and no mutation. Case variants keep `CWE/4.14/` and change only the rule-ID case, so the design order parse → same NS/VER → reserved → collision → exists yields `IDENTITY_COLLISION` (active, deactivated, case-only rename of the rule itself) or `IDENTITY_RESERVED` (deleted, renamed-away). |
| 03f / US-03 | K/test_exit_actions.py `test_pending_and_index_per_action` | Delete/rename remove and report pending, deactivate retains it; index invalidated immediately, failed label retained, later document check not fully stored. |
| 03g / US-02 | K/test_exit_preview.py `test_reason_required` | Missing/blank reasons refused without writes (also malformed/overlong/control reasons). |
| 03h / US-04 | K/test_exit_actions.py corrupt-folder tests; K/test_exit_durable.py | Inconsistent/unreadable deactivate/reactivate/rename refuses with restore-or-delete step; delete binds every residue/hidden/nested file/link/kind, moves as found, labels inconsistent; unreadable regular file or folder refuses RULE_FOLDER_UNREADABLE (no metadata fallback); symlinks never followed and FIFO never opened. |
| 04a / US-03 | P/test_policy_exit.py `test_explicit_missing_never_substituted` | Deactivated/deleted/renamed missing reason; renamed_to only information; no requirement/content/source evidence or substituted target/version. Explicit references: a real other-version candidate `CWE/4.13/CWE-79` exists and is never returned. Version-less references: the "no stored versions but exited identities" branch (alternate `CWE/4.13/CWE-79-OTHER`) asserts the informational `exited` entry; `test_versionless_remaining_version_lists_exited` (delete/rename, owner-authored v1.2): resolves to the remaining `CWE/4.13/CWE-79` exactly as before, `exited` names the exited identity with reason/renamed_to, no substitution of explicit references. |
| 04b / US-03 | P/test_policy_exit.py `test_all_active_only_informational_counts` | All includes only active formal rules; deactivated/deleted/renamed informational counts separate from status/counts; all-deactivated maintenance next step. |
| 04c / US-03 | P/test_policy_exit.py `test_scope_missing_and_immutable` | Each exited reference missing with same reason/renamed_to; record bytes unchanged; partial and maintenance_needed branches. |
| 04d / US-03 | P/test_policy_exit.py `test_cycle_requires_reconfirmation` | Content unchanged after deactivate/reactivate; old scope needs_reconfirmation, partial, next step to confirm, immutable record. |
| 04e / US-03 | K/test_exit_links.py | Links and show identify every broken source/target/reason, scope links, no auto repair; original relation bytes unchanged. |
| 04f / US-04 | P/test_exit_runs.py | All four actions and cycle: before the exit, non-empty Markdown and JSON reports exist for both Guard and Copilot and the scope record exists; those exact files byte-identical afterwards (and scopes/private states); real open Guard conclusion and Copilot report detect missing/changed/Policy change. |
| 05a / US-05 | K/test_exit_actions.py `test_update_deactivated_revision` | Correct current deactivated base updates, retains deactivated state and log; pre-lifecycle base STATE_CONFLICT without writes; edited state cannot reuse old transition. |
| 05b / US-03 | K/test_exit_actions.py `test_partial_import_refusals` | Deactivated exact/case identity per-item refusal, reactivate next step, valid other item stored. |
| 05c / US-03 | K/test_exit_actions.py `test_partial_import_refusals` | Deleted/renamed exact/case imports reserved; private tombstone/memory unchanged; valid other item follows partial import. |
| 05d / US-04 | K/test_exit_links.py `test_list_show_lifecycle` | List/show mark deactivated; exited identities separate with time/reason; show exited missing + exit information. |
| 06a / US-06 | K/test_exit_recovery.py; K/test_exit_journal_fixtures.py; K/test_exit_durable.py | All actions, every documented durable boundary incl transitions; crash never success; next knowledge/Policy command recovery or LOCKED; no half state across record/tombstone/rename/history/revision/memory/transition/pending/index; all commands hooked; prefix fixtures and malformed/tampered/omitted/duplicate/out-of-order/payload/suffix/transition cases refuse without mutation; fsync order/failures, EXDEV pre/post commit; bounded earlier recovery before current auth. Design v1.1 D2: `test_deactivate_reactivate_keep_pending_without_pending_step` — deactivate/reactivate journals at every done-prefix with a retained pending decision and no `pending` step (with `pre_state.pending` recorded or null) are valid, recovery completes and the pending file is byte-unchanged. |
| 06b / US-06 | K/test_exit_concurrency.py | Process exit/update and exit/exit serialization; second evaluated on first result; pre-deactivate/reactivate update base stale; no half state. Contenders proven blocked at knowledge-lock acquisition by the bounded probe handshake (no fixed sleeps). |
| 06c / US-02 | K/test_exit_skill.py | Framework Exiting Knowledge section instructs preview and full impact shown first, real request and explicit Maintainer confirmation only, no automatic reference repair, references do not block. |

Additional NFR/design inventory: K/test_exit_units.py fixed never-exited record,
item/proposal/scope vectors and import candidate/accept semantics; adopted-state
compatibility through actual Guard/Copilot. K/test_exit_durable.py no-follow
canaries for every named path, before/after parent swaps, handle-relative I/O and
lock exclusion; POSIX integration swaps at `exit_locked` (after the confirm opened its
Tree and locks): rule-folder parent (deactivate/delete/rename), pending root (delete)
and pending parent (delete/rename) become links to an outside copy → `PATH_UNSAFE`
(in-root pending link: `PATH_UNSAFE` or `STALE_IMPACT`) with nothing written, or the
original handle was used; outside canaries unchanged. A pending 001-B per-rule commit
journal (real update crashed at `after_journal`) plus a rule-folder swap at
`exit_locked` (before the handle-relative `store.recover_at`) never replaces or unlinks
outside; symlink-creating tests skip at runtime when links cannot be created
(`exithelp.need_symlinks`); transition integrity/binding, strict index failures and deterministic
impact. P/test_exit_runs.py Policy refusal next-step propagation through open and
conclusion/report. All filesystem fixtures must stay beneath the project-local
pytest basetemp; no network or dependency installation is needed.

### Stage A execution results

Stage A' (review test fixes; no production code; executed 10-22-2026, macOS, Python via
`uv run --offline`). Commands run from Framework `scripts/`, with
`S=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files`:

- Lint: `PYTHONDONTWRITEBYTECODE=1 uv run --offline ruff check --no-cache .` → All checks passed.
- New suite (11 files): `PYTHONDONTWRITEBYTECODE=1 uv run --offline pytest -p no:cacheprovider
  -o addopts="" --basetemp=$S/bt-red -q --junitxml=$S/stageA2-red-junit.xml
  tests/knowledge/test_exit_{units,preview,actions,recovery,journal_fixtures,durable,concurrency,links,skill}.py
  tests/policy/test_policy_exit.py tests/policy/test_exit_runs.py` → **503 failed, 12 passed** (RED).
- Rest of the suite: `UV_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1 uv run --offline pytest -p no:cacheprovider
  -o addopts="" --basetemp=$S/bt-base -q --junitxml=$S/stageA2-baseline-junit.xml tests` with
  `--ignore=` for each of the 11 files → **882 passed, 2 skipped**. (A first run without
  `UV_OFFLINE=1` had `test_payload.py::test_uvx_end_to_end_init_and_status` fail only because
  `uvx` tried to reach pypi.org — connection reset; it passes offline from the local cache.)
- Hygiene: `find ai-secure-code-toolkit -newer technical-design.md` lists only the 8 edited test
  files (plus two `.ruff_cache` entries of the earlier cached lint run, removed; `.ruff_cache`
  pre-exists and is a payload-excluded directory). Logs, JUnit, basetemp and probe markers are
  only under `$S`.

Characterization (GREEN before change): K/test_exit_units.py 4 passed (record bytes and item
digest, proposal/all/scope identity, never-exited Guard/Copilot adoption, import candidate and
accept by item digest). P/test_exit_runs.py `test_policy_refusal_next_step_passthrough` Guard
8 passed (Guard already keeps the Policy next step).

| File | Failed | Passed | Failure reasons |
| --- | --- | --- | --- |
| K/test_exit_units.py | 0 | 4 | — (characterization) |
| K/test_exit_preview.py | 42 | 0 | 41 `ModuleNotFoundError: knowledge.exit`; 1 CLI parser has no `exit-preview` |
| K/test_exit_actions.py | 59 | 0 | 57 no `knowledge.exit`; 1 update base ignores lifecycle revision (no `STATE_CONFLICT`); 1 check reports deactivated rule `fully_stored` |
| K/test_exit_recovery.py | 78 | 0 | 43 no `knowledge.exit`; 1 no `knowledge.durable`; 34 hand-built journal not recovered by existing commands (`assert_completed`) |
| K/test_exit_journal_fixtures.py | 126 | 0 | 29 journal not rolled forward; 78 invalid journals not refused (`list` ok, no `EXIT_JOURNAL_INVALID`); 19 no `recovered_exit` (18 D2 fixtures, 1 stray exit temporary) |
| K/test_exit_durable.py | 108 | 0 | 101 no `knowledge.exit`; 6 no `knowledge.durable`; 1 tombstone link not refused (`list` ok, no `PATH_UNSAFE`) |
| K/test_exit_concurrency.py | 22 | 0 | 21 no `knowledge.exit`; 1 no `knowledge.durable` |
| K/test_exit_links.py | 4 | 0 | 4 no `knowledge.exit` |
| K/test_exit_skill.py | 5 | 0 | 5 SKILL.md has no "Exiting Knowledge" section |
| P/test_policy_exit.py | 44 | 0 | 42 no `knowledge.exit`; 1 resolver ignores lifecycle marker; 1 "all" includes deactivated rule / no `inactive` |
| P/test_exit_runs.py | 15 | 8 | 7 no `knowledge.exit`; 8 Copilot replaces the Policy refusal next step |
| **Total** | **503** | **12** | 316 + 8 missing modules; 179 behavioural assertions on existing services/CLI/skill |

Every failure is for a missing designed module or missing designed behaviour; no failure is in
Arrange (new Arrange steps on existing services were checked: prior Guard/Copilot Markdown+JSON
reports exist, the crashed 001-B update leaves its commit journal, the real `CWE/4.13/CWE-79`
candidate imports).

SHA-256 (Framework `scripts/tests/`):

| File | SHA-256 |
| --- | --- |
| knowledge/exithelp.py | `03a375e02f79c863e4a1ecc7add960815b1554fc36367241c92723d3471f3076` |
| knowledge/exitjournalhelp.py | `fc4e2c490e50d37f75b87e9e0ea85117c8e3b165e8211a7004e0e60fe3a34ae2` |
| knowledge/test_exit_units.py | `e4a0d3d92dc5f21dfb210c57792aea9c1ed57c70f34d79ddfbcdb0858998324e` |
| knowledge/test_exit_preview.py | `87c33f156edc447c8c9145ee1f0613b776326e1d6ea71e9f139d9e8ac3891215` |
| knowledge/test_exit_actions.py | `6e224d90a36674912bdb55c8d839bcc05fd0268abec8cd1c10e662d8c13461d5` |
| knowledge/test_exit_recovery.py | `e8856e30df2c7bf4e9267c8ba906951a53a61ab6abf91c95745f4fa19a311bbd` |
| knowledge/test_exit_journal_fixtures.py | `492037510ddf298e38e0cd8cdd4873eb06eea6d7eb7bb6d1854f0bfbd8b9b32d` |
| knowledge/test_exit_durable.py | `663e8507b5a5548b04cd7303fbf94310bd1ff5dd3d12e7d0d3278728b2450e38` |
| knowledge/test_exit_concurrency.py | `e6566f327f0bdca4374c14ddd572c35c76fa3af7623f1bd31e76fc46731e1b14` |
| knowledge/test_exit_links.py | `f82c461866b8090a376990f0e85647b921ff757913d5d3a188c2e47b9310cfbe` |
| knowledge/test_exit_skill.py | `2b928e5f580a4c9ed8a4b7570a08f0393cd3516a9160dd8644b77130d91d4a87` |
| policy/test_policy_exit.py | `325cd166c0372b716763528e9a36c4cda37a2b800b7ef8dbf489973aeac0a697` |
| policy/test_exit_runs.py | `1bbeeb80f36c4678d227e7fb1d33e32aeb5b9023e9399cee9636422372e86717` |
| Inputs: specification.md | `fb74bfe254d3a6cbd373e5deb743c279fc2292e2e8bf97c12aa75bf2e06abcc2` |
| Inputs: technical-design.md v1.1 (before this section update) | `4ae37fd072930a9a88e103d1b4da59e2baa7dc3d5125b1455ac6e154a09ca184` |

Open design ambiguities found (reported to the lifecycle owner, not resolved by relaxing
acceptance): (1) `STALE_IMPACT` returns only the new `impact`; for a rule-only change the provider
lists are identical and the changed `rule_state` is not part of the refusal data; (2) a
version-less reference whose exited source version has another stored version resolves by the
existing version-less rules (single remaining version → that version); whether BR-04 forbids this
is not stated; (3) the content of `pre_state.pending` for deactivate/reactivate journals is not
specified (tests accept recorded or null, per "presence or absence is not checked"); (4) no named
pause exists inside `store.recover_at`, so the recovery swap is injected at `exit_locked`;
(5) `will` wording is given only as examples; tests assert key words, not exact sentences.
No GREEN feature claim is made; stakeholder outcome: not measured.

### Stage B GREEN results (TASK-051)

Executed 10-22-2026 on macOS (Python via `uv run --offline`, `UV_OFFLINE=1`,
`PYTHONDONTWRITEBYTECODE=1`, basetemp/logs/JUnit/coverage data only in the session folder
`$S=/Users/yzhang/.copilot/session-state/081276d7-fac0-4983-a366-46d60bec1fe5/files`). Inputs:
specification `fb74bfe2…` (unchanged); design v1.3 as amended by the owner (SHA-256 before this
section update `412620b1225b948473b923d39d55dad6b193ba8c1957ff45b815ea19aa739c3e`). No test or
helper was edited by the worker; the owner retargeted the four existing lock tests (v1.3) and
added the two v1.2 version-less assertions.

Commands (Framework `scripts/`):

- `uv run --offline ruff check --no-cache .` → All checks passed.
- Full suite, twice consecutively: `pytest -p no:cacheprovider -o addopts="" --basetemp=$S/bt-fullN
  -q --junitxml=$S/final-fullN-junit.xml tests` → run 1 **1399 passed, 2 skipped**; run 2
  **1399 passed, 2 skipped** (incl. `tests/test_module_size.py`, every module < 800 lines).
- Coverage: `COVERAGE_FILE=$S/cov/.coverage pytest … --cov=x_ipe_secure_code.knowledge
  --cov=x_ipe_secure_code.policy --cov-report=term-missing tests` → 1399 passed, 2 skipped;
  knowledge + policy total 91 %.
- Race/durability/runs/recovery files repeated 3× at G3 (231 passed each); all seven
  parent/rule-folder swap tests end in the `PATH_UNSAFE` refusal with nothing written.

| Test file (new) | Passed | Failed |
| --- | --- | --- |
| K/test_exit_units.py | 4 | 0 |
| K/test_exit_preview.py | 42 | 0 |
| K/test_exit_actions.py | 59 | 0 |
| K/test_exit_recovery.py | 78 | 0 |
| K/test_exit_journal_fixtures.py | 126 | 0 |
| K/test_exit_durable.py | 108 | 0 |
| K/test_exit_concurrency.py | 22 | 0 |
| K/test_exit_links.py | 4 | 0 |
| K/test_exit_skill.py | 5 | 0 |
| P/test_policy_exit.py | 46 | 0 |
| P/test_exit_runs.py | 23 | 0 |
| Rest of the suite | 882 (+2 skipped) | 0 |

Coverage of new/changed modules (statements): `knowledge/durable.py` 86 %, `lifecycle.py` 92 %,
`exit_journal.py` 93 %, `impact.py` 91 %, `exit.py` 95 %, `views.py` 93 %, `store.py` 84 %,
`service.py` 86 %, `changelog.py` 100 %; `policy/resolve.py` 98 %, `scope.py` 90 %,
`service.py` 87 %. Notable uncovered branches (reported, no tests added): `store.recover_at`
roll-forward of a pending 001-B commit inside a successful confirm (only the refusal path and a
worker scratch equivalence check exercise it); `impact` rename `pointing_to_target`, invalid or
linked scope files and non-run entries; journal field checks for malformed time/digests/
pre_state/op/before/move fingerprint, foreign tombstone entries and the planned-journal
self-check; `ACTION_INVALID`/`ARGUMENT_INVALID`/rule-parse refusals; malformed exit memory,
transition log and index readers; the `SECURE_CODE_TEST_FAIL_AT` hook (tests inject by
monkeypatch) and the Windows fallback.

Delivery state: all 30 ACs have passing integration tests at the hashes below. Stakeholder
outcome: **not measured**. Black-box `uvx` acceptance (host/container) and Windows runs: not run.

SHA-256 of new/changed product, documentation and test files (Framework `scripts/` unless noted):

| File | SHA-256 |
| --- | --- |
| src/x_ipe_secure_code/knowledge/durable.py (new) | `6468cdfca71645f2df13e48b9cb5445ebfc99c10fadd0b0cf1c0f433fe0ca4ad` |
| src/x_ipe_secure_code/knowledge/lifecycle.py (new) | `3fef41d1144c8d8a17d7237ee0a0aef808030e70790cb3c7d421ddac96e6615e` |
| src/x_ipe_secure_code/knowledge/exit_journal.py (new; Stage C) | `95172124d6c3484aa78a5877e43204d9c1455c57df5087578f0b3cb51dd71f45` |
| src/x_ipe_secure_code/knowledge/impact.py (new) | `9d1dd81fee1e7bf1c9e04cafff53bdb3fb09f19e02d35a0e269c7f9753ae51ef` |
| src/x_ipe_secure_code/knowledge/exit.py (new; Stage C) | `8064183f849d83c4a3aa7e74423e8b29a1dfff757a0b3b3177921a07129094b2` |
| src/x_ipe_secure_code/knowledge/views.py (new) | `a2934f7e537accecbf5cbbd342281862c8335c9b6111a1cba8e57a63cee85c6a` |
| src/x_ipe_secure_code/knowledge/store.py (Stage C, re-review fix) | `877dd739948603d27b5ed508a9354e9a546c0753cc4f5b1aafc3146547ea99bd` |
| src/x_ipe_secure_code/knowledge/service.py | `16eb269545057e407329ce5429774623dca4fc02a70b35b3d1958b7070cf7d6a` |
| src/x_ipe_secure_code/knowledge/changelog.py | `56b962a821557b6e801942c571f2c4b58b647aefc58761fa1d238d66a3abe63f` |
| src/x_ipe_secure_code/policy/resolve.py | `f1dcdd6e3afb9e58388b0de3bd30681ca242d7973eabe922c6cf3794def80f6d` |
| src/x_ipe_secure_code/policy/scope.py | `1c5aa564b559462150227fb45e8c21a945ec505ac0a3f41f5c52cab94c0df38a` |
| src/x_ipe_secure_code/policy/service.py | `2876bd77a7fcc64d542ee6384c2d0ded88dc3ffc87d41c989046260265e23bb0` |
| src/x_ipe_secure_code/copilot/service.py | `d4c9a70e76f9331f077898dcdb84b7877f34100a976fda22ab93291ac93349af` |
| src/x_ipe_secure_code/cli.py | `fb8a385cd6d2e8d3771cc543223183e387978a8ae08877a2d0c3b2c8b8f5ced8` |
| Framework SKILL.md | `4592c02d7375a42d7435b82a21a0416b1c9a7770a491801b596514e9ee6775a8` |
| Framework references/cli-contract.md | `a0d31b1b1bedd744a727e47e84b8630e30fcab392a2f88017f3ebeeaf97010ab` |
| Framework references/knowledge-batch.md | `6af9e08008086b8caf762e105b762f371216c908c301903f13fc7df04ee570d8` |
| Framework references/policy-selection.md | `5a015418cb4c424dd17747ed7459c0bb4557fae67bb11509e560ef3211262c81` |
| toolkit README.md | `18b44eb6f932435bf29aed91eb47894d59d5a3007b0506a164b59d33592e9faa` |
| tests/knowledge/exithelp.py | `03a375e02f79c863e4a1ecc7add960815b1554fc36367241c92723d3471f3076` |
| tests/knowledge/exitjournalhelp.py | `fc4e2c490e50d37f75b87e9e0ea85117c8e3b165e8211a7004e0e60fe3a34ae2` |
| tests/knowledge/test_exit_units.py | `e4a0d3d92dc5f21dfb210c57792aea9c1ed57c70f34d79ddfbcdb0858998324e` |
| tests/knowledge/test_exit_preview.py | `87c33f156edc447c8c9145ee1f0613b776326e1d6ea71e9f139d9e8ac3891215` |
| tests/knowledge/test_exit_actions.py | `6e224d90a36674912bdb55c8d839bcc05fd0268abec8cd1c10e662d8c13461d5` |
| tests/knowledge/test_exit_recovery.py | `e8856e30df2c7bf4e9267c8ba906951a53a61ab6abf91c95745f4fa19a311bbd` |
| tests/knowledge/test_exit_journal_fixtures.py | `492037510ddf298e38e0cd8cdd4873eb06eea6d7eb7bb6d1854f0bfbd8b9b32d` |
| tests/knowledge/test_exit_durable.py (+ owner test `test_confirm_rolls_forward_pending_commit_through_handle_then_exits`) | `76f10b5206e4133f0075c9a60decdf7feb2592cf7d118fd960cfe70971955536` |
| tests/knowledge/test_exit_review_fixes.py (new, Stage C incl. re-review) | `21551e09edfade5ef3d8d2b4fed4aa13306fa1783ff34b3162349e709829698c` |
| tests/knowledge/test_exit_concurrency.py | `e6566f327f0bdca4374c14ddd572c35c76fa3af7623f1bd31e76fc46731e1b14` |
| tests/knowledge/test_exit_links.py | `f82c461866b8090a376990f0e85647b921ff757913d5d3a188c2e47b9310cfbe` |
| tests/knowledge/test_exit_skill.py | `2b928e5f580a4c9ed8a4b7570a08f0393cd3516a9160dd8644b77130d91d4a87` |
| tests/knowledge/test_knowledge.py (owner-retargeted) | `63a7fde5fdeda770dc4b2831f218658d133937ae852c6245eb589e9fb6ec819b` |
| tests/policy/test_policy_exit.py (owner-strengthened) | `96f5762f51f1a6af6e179ea2f022bdfd50521bc8d40aa256016002d346f50700` |
| tests/policy/test_exit_runs.py | `1bbeeb80f36c4678d227e7fb1d33e32aeb5b9023e9399cee9636422372e86717` |
| tests/policy/test_policy.py (owner-retargeted) | `302ae6fcca12ce4b65ccd30efa4d5239cfcdd36a4d2d2dbe423abb4990dcced5` |

Hygiene: under `ai-secure-code-toolkit/` only the files above changed; no links, FIFOs,
caches, logs or coverage data were added (the pre-existing `scripts/.coverage` from Oct 22 01:54
is unchanged and payload-excluded).

### Stage C review fixes (TASK-051)

Independent code review findings fixed test-first (design input SHA-256 before this section
update `4df5a6cb1f2f4aa119eb6ae0c967cab86be316213f54add78052164cce6ef249`; no design contract
changed). Regression tests: K/test_exit_review_fixes.py (40 cases), written before each fix.

| Finding | Fix | Regression tests (RED before → GREEN after) |
| --- | --- | --- |
| 1 (blocking) A waiter skipped recovery of a journal published while it waited for the knowledge lock; `run()` replaced an existing journal (lost exit memory/transition, identity reusable) | `exit_journal.session` re-checks `has_pending` under the lock and recovers; `run()` refuses `IO_ERROR` ("re-run any knowledge command; it completes the exit") when a journal or exit temporary already exists, before any write | `test_waiting_confirm_recovers_failed_exit_before_its_own`, `test_waiting_read_command_recovers_failed_exit` (process level: rename failing at `replace:memory` after the commit point, waiter proven blocked by the lock probe; waiter reports `recovered_exit` completed, exit memory/transitions/list/re-import correct), `test_session_rechecks_pending_journal_under_the_lock` (thread level), `test_run_refuses_to_overwrite_a_pending_journal` — RED: `KeyError 'recovered_exit'`, `NoneType`, "DID NOT RAISE" |
| 2 (blocking, security) Names in a per-rule 001-B `.commit-journal.json` were used unchecked (absolute, `..`, symlinked subfolder) by `recover_at` and path-based `recover` | Shared `store.commit_entries`, checked before any I/O, otherwise `RULE_INCONSISTENT` with the restore-or-delete next step (the logical view marks such a rule inconsistent). Re-review fix: names are derived from the writer — `replace` must be a name `_write_rule` stages (`record.json`, `changelog.md`, `content.md`, `example.md`, `example-<batch.LANG>.md`, so `c#`/`f#` stay valid); `delete` must be a plain visible rule-folder file other than record/changelog (the writer deletes every stored visible file the new item no longer has, incl. hand-added extras); both must be one component without `/`, `\`, NUL, drive, dot prefix or `.new` suffix and not absolute | `test_exit_never_follows_hostile_commit_journal_names`, `test_recover_at_rejects_names_before_any_io`, `test_path_based_recovery_rejects_hostile_names` × {absolute, `..`, symlinked `sub/`} × {delete, replace}; outside canary and project tree unchanged — RED: confirm succeeded and deleted/replaced the outside canary, "DID NOT RAISE". The three replace variants through exit-confirm were already refused by the logical view (GREEN before) |
| 3 (non-blocking) Parseable journals with missing keys raised `KeyError` (traceback) | `pre_state` must be exactly `{pending, index_edges}`; each step must carry its operation's keys; `recover_locked` maps `KeyError`/`TypeError`/`AttributeError` to `EXIT_JOURNAL_INVALID` | `test_missing_journal_keys_are_invalid_not_traceback` (delete/rename × missing `pre_state.pending`/`index_edges`, `before` of write/remove/append, write `text`; `knowledge list` and `policy resolve` envelopes, no mutation), `test_cli_list_with_missing_key_is_an_envelope` — RED: `KeyError 'pending'`/`'before'`, CLI traceback; other cases were already refused |

Commands (Framework `scripts/`, session basetemp, `UV_OFFLINE=1`, `PYTHONDONTWRITEBYTECODE=1`):
RED `pytest … tests/knowledge/test_exit_review_fixes.py` → 24 failed, 10 passed, 1 skipped
(the skip: delete has no append step); GREEN same command → **34 passed, 1 skipped**. Re-review
regression (fix 2 rejected `#`): new `test_interrupted_commit_with_hash_example_rolls_forward_path_based`
and `…_in_exit` (`c#`, `f#`; real update crashed after its commit journal; show/list consistent,
ordinary `knowledge update` and exit-confirm roll forward) and
`test_interrupted_commit_deleting_a_visible_extra_file_rolls_forward` — RED 5 failed (rule reported
inconsistent / preview `RULE_INCONSISTENT`), GREEN after the writer-derived names: file
**39 passed, 1 skipped** (all escape tests still refused); full suite twice → **1441 passed,
3 skipped** each run (earlier Stage C runs: 1436 passed, 3 skipped); `ruff check --no-cache .` → All checks passed; module
sizes < 800 (largest touched: `exit.py` and `exit_journal.py` 656; `store.py` 588). Hygiene: only the three source
files and the new test file changed under `ai-secure-code-toolkit/`; no links, FIFOs, caches or
coverage data added. Additive behaviour: path-based recovery refusals (`RULE_INCONSISTENT`) now
carry the restore-or-delete next step.

### Owner verification (TASK-051, Sage)

- Resume check (10-22-2026): the earlier TASK-051 run used an unintended model (gpt-6.1-sol). The owner
  verified that the spec stayed `fb74bfe2…` and that the only design change was the evidence section.
  No product or existing test files had been touched. The cancelled worker's pytest basetemp
  (`tests/knowledge/.task051-runtime/`, containing FIFOs and links) and its logs were removed from the
  product package because they broke `test_project_init`.
- Independent cross-model review of the earlier corrections and of the Stage A tests found 2 design
  defects. With human authorization they were fixed as v1.1 and a focused re-review found both
  resolved. It also found 6 blocking and 3 minor test defects, which were fixed by strengthening the
  tests only. Human decision A on version-less references became v1.2. Owner-accepted changes to
  means only are recorded as v1.3. None of these changes a contract or an AC.
- Tests the owner wrote or adjusted:
  - v1.2 version-less tests, RED first.
  - The three existing lock tests retargeted to `DirLock` as the Test Plan prescribes; assertions
    unchanged.
  - `test_confirm_rolls_forward_pending_commit_through_handle_then_exits`, written after the code
    existed to cover a gap, not RED first.
  The worker edited no existing test. The SHA-256 of all 16 tracked test files was checked at every
  checkpoint.
- Independent code review of the final code found 2 blocking issues (a lost-journal race, and
  per-rule commit-journal names escaping the rule folder) and 1 non-blocking issue (journals with
  missing keys). Fixing them introduced a `#` example-name regression, which was also fixed (Stage C).
  Final re-review: all resolved, no blocking issue.
- Owner re-run at design `05addde4…`, after the re-review:
  - `uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=$S/bt-final2`
    → **1441 passed, 3 skipped**.
  - `ruff check --no-cache .` → clean.
  - Test-file hashes match the baseline.
  - No links, FIFOs or scratch files exist under `ai-secure-code-toolkit/`.
- Not run: black-box `uvx` acceptance (host and container) and Windows; these are left to Feature
  Acceptance Test. Stakeholder outcome: **not measured**.

### Bug Fix TASK-054 (rename-target collision lookup)

[Bug report](bug-report-TASK-054.md). `exit._target_checks` used the path-based
`identity.find_collision(store.local_root(tree.root), …)`, which followed a swapped `knowledge/local`
root or ancestor (outside folder listed; NFR-001D-1/4, "Locks and reads", Security). Fix: the
prepare step 4 collision rule is now evaluated by `store.find_collision_at(tree, ref)` through the
command's Tree (same case-insensitive rule, codes, messages and order; a link component →
`PATH_UNSAFE`). The import path (`knowledge/service.py`) keeps the path-based helper (outside this
feature's exit path). Regression `K/test_exit_bugfix_task054.py` (6 cases): RED on unfixed
`exit.py` `8064183f…` — 4 failed (outside listed for local root/ancestor × preview/confirm), 2
version-component guards passed (not exploitable: link entries were never followed); GREEN 6 passed;
`test_rename_target_refusals` unchanged 15 passed; full suite twice 1447 passed, 3 skipped; ruff
clean. SHA-256: `knowledge/exit.py` `384a98531dd9fa72004e7e3987e288a924c02f66df7a3eaf3f214887a1198d64`,
`knowledge/store.py` `e5012c6b5f9c4c71479bf81bc594070280cad5b65a740158a58c16936c26f10a`,
`tests/knowledge/test_exit_bugfix_task054.py`
`863aaa0ecd7d98dcdc931b45a48ee69f3aa03437ced567925c97138c38096b6f` (these supersede the `exit.py`
and `store.py` rows of the Stage B table). Independent review: pending (owner).

## Design Change Log

| Date | Version | Change | Reason |
|------|---------|--------|--------|
| 10-22-2026 | v1.0 | Initial design: flat exit-preview/exit-confirm/links commands; lifecycle in `record.json` with additive state digest; project redo journal with derived paths and progress validation; knowledge → scope lock order; extensible providers; tombstone move; case-insensitive exit memory | TASK-050 |
| 10-22-2026 | v1.0 | Design review fixes (6 blocking, 3 non-blocking): (1) new `durable.py` primitives with file and directory fsync after every replace/unlink/move/mkdir chain and fixed ordering journal → steps → journal removal → success, Windows limit stated; (2) explicit per-op validation contracts (write payload digest, append suffix digest and `sha256(before+suffix)`, remove exact-or-absent, move mutually exclusive exact fingerprints), `pre_state` validation of omitted optional steps, recovery fixtures for every progress state and tampering; (3) AC-001D-02f not-adopted exception implemented via persisted `previous` entries, adopted exits → `STALE_CONFIRMATION`, both branches tested; (4) delete fingerprint covers every moving entry incl. residue, link text and kind, metadata marker for permission-unreadable entries, `RULE_FOLDER_UNREADABLE` for unlistable folders; (5) POSIX directory-handle-relative no-follow operations for all exit mutations and provider reads, `ProcessLock(nofollow)`, Windows lstat/identity fallback with cooperative-writer limit; (6) import `stored_digest`/`--accept-update` stay item-digest based, only `update --base-state` uses the state digest (remaining limitation noted); (7) strict index reader, `unreadable` in impact, `INDEX_INVALID`; (8) Copilot next-step pass-through (Guard already keeps it), claim of unchanged Guard/Copilot code dropped, propagation tests added; (9) symlink canaries for every named path, component-swap, EXDEV before/after journal, injected fsync/replace/move/unlink failures, residue changes, malformed journals. Delete steps reordered (`tombstone_dir` → `move` → `tombstone_record`) to allow the narrow EXDEV roll-back | Independent design review |
| 10-22-2026 | v1.0 | Re-review fixes (4 blocking): complete private transition delta restores source and removes rename target for the scope-save exception; reactivation in `apply_all` remains stale; `lifecycle.previous` removed from formal metadata in favor of a journaled transition log bound to changelog/memory; no-follow `Tree`/`DirLock` and handle-based rule/pending snapshots replace final-component-only locks and path-based exit reads; unreadable regular files refuse deletion instead of using metadata-only fingerprints. Algorithms, error codes, implementation steps and planned tests aligned | Focused design re-review; resumed TASK-050 |
| 10-22-2026 | v1.1 | Cross-model review fixes (2 blocking), human-authorized in TASK-051: (D1) exit-confirm's per-rule 001-B commit recovery is the handle-relative `store.recover_at(tree, ref)` (same semantics as `store.recover`, all reads/replaces/unlinks via the rule-folder descriptor of the command's `Tree`, then `read_rule_at`), closing the path-based gap in the no-follow single-`Tree` rule; (D2) the omitted-step journal invariant "no `pending` step ⇒ pending file absent" applies only to delete/rename; deactivate/reactivate never carry a `pending` step and keep any pending file (AC-001D-03f). No specification or AC change | Independent cross-model review of the wrong-model TASK-050 corrections and Stage A tests |
| 10-22-2026 | v1.2 | Human decision on version-less references after an exit (option A): existing version-less resolution kept when another stored version remains; informational `exited` list (deleted/renamed-away identities `NS/*/ID`) added to the entry and text output, outside `proposal_digest` inputs; explicit references unchanged (`missing`, never substituted). Test `test_versionless_remaining_version_lists_exited` added by the owner, RED first | Ambiguity reported by the TASK-051 implementation worker; BR-04 interpretation confirmed by the human |
| 10-22-2026 | v1.3 | Owner means-level adjustments (no contract, error-code or AC change): (1) exit-confirm takes `DirLock(scopes.lock)` with `create=False` when the lock file is absent, so a refused confirm writes nothing attributable to the request ("nothing changed" ACs); safe because every scope-lock holder (scope save, exit-confirm, preview, links) takes the knowledge lock first and scope save creates the scope lock under it; (2) `recover_at` rolls a staged 001-B file forward with a durable temp write + replace and unlinks the staged copy instead of a rename (same outcome, descriptor-relative); (3) delete/inconsistent folder fingerprints add a `[path, "dir", ""]` row per subfolder so an added empty folder is bound; (4) the three existing knowledge/policy `LOCKED`/`IO_ERROR` tests monkeypatch `durable.DirLock.__enter__` instead of `atomic.ProcessLock.__enter__`, as this design's Test Plan prescribes; assertions unchanged | TASK-051 G1 checkpoint |
| 10-22-2026 | v1.3 | Owner-accepted G2 means (no contract/AC change): (5) transition `before`/`after` identity views of a present but not-available rule carry its real `state_digest` (not null) so a later content edit of a deactivated rule is not explained by the transition (AC-001D-05a/02f); `proposal_digest` inputs unchanged; (6) `scope show` reads the immutable scope record before `ensure_recovered` (keeps the existing no-lock-file behaviour for unknown scope IDs); recovery still precedes every knowledge read | TASK-051 G2 checkpoint |
| 10-22-2026 | v1.3 | Owner-accepted G3 means (no AC change; additive result fields): (7) `durable.write` keeps the mode of the file it replaces, new files 0600 (formal `record.json`/`changelog.md` keep their existing mode; private exit files stay owner-only); (8) `ACTION_NOT_APPLICABLE` carries one next step like every refusal (envelope contract), table updated; (9) a link at the exited rule's own pending file is a used path → `PATH_UNSAFE`; links elsewhere in provider folders are reported `unreadable`, other `pending/` links skipped; (10) `exit_journal.run` validates the planned journal before publishing it (planner mismatch → `EXIT_JOURNAL_INVALID`, nothing written); (11) additive fields `links.unreadable_sources`, preview `rule_state.special_entries`/`pending_commit` | TASK-051 G3 checkpoint |
