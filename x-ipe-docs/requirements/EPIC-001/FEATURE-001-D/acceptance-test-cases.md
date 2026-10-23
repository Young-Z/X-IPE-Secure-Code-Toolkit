# Acceptance Test Cases

> Feature: FEATURE-001-D — Knowledge Exit Impact & Broken-Link Handling (EPIC-001)
> Status: Verified delivery for the approved scope. All 30 ACs pass: 29 through black-box CLI runs in an offline Linux container (Maintainer path) and on the macOS host (never-authorized User path), and AC-001D-06c through structured package inspection. The Framework suite (supporting evidence) passes, and the FEATURE-001-B, 001-C, 002-A and 003-A acceptance runners pass unchanged. Windows was not run.
> Revision: toolkit file list `a63578d7…` (139 files; unchanged from start to end of the TASK-054 runs) · specification `fb74bfe2…` · design v1.3 `c052ed3c…` · runner `93a13a31…` (SHA-256 prefixes; full values in Relevant Inputs).
> History: acceptance TASK-052 (owner Sage, free-mode, interact-with-human), 2026-10-22; independent closing review TASK-053 found evidence gaps and one product defect; **Bug Fix TASK-054** (closing-review fixes, human-approved): product fix of the rename-target collision lookup in `knowledge/exit.py` (handle-relative, no links followed; [bug-report-TASK-054.md](bug-report-TASK-054.md)) with `store.py` and a new test `tests/knowledge/test_exit_bugfix_task054.py`; acceptance runner strengthened (AC-001D-06a byte-level snapshot invariants, exact preview contract for all four actions incl. reactivate); report denominator and evidence kinds clarified; **full rerun** of the black-box evidence, Framework suite and all four regressions at the fixed code.


## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-001-D, implemented in TASK-051 (Stage A/B/C and owner verification in the design's Implementation Evidence) |
| Specification / Source | [specification.md](specification.md): 30 ACs AC-001D-01a…06c, all Integration; FR-001D-1…8, BR-01…10, NFR-001D-1…4, US-01…06. Parent: [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) EPIC-001 G-03, FR-07, AC-09, AC-10 (exit part) |
| Design / Implementation | [technical-design.md](technical-design.md) v1.3, Part 1 and Part 2: Command Contract, refusal codes, Storage Formats, Recovery Hook Placement, Delta and Evidence Invalidation, Implementation Evidence incl. Stage C and Owner verification. Product: Framework `knowledge/{exit,impact,exit_journal,lifecycle,durable,store,service,views,changelog}.py`, `policy/{resolve,scope,service}.py`, `copilot/service.py`, `cli.py`; Framework `SKILL.md` "Exiting Knowledge", `references/cli-contract.md` |
| Target URL | N/A: CLI, library and skill scope (no UI, no browser needed) |
| Config / Capability | `stages.validation.acceptance_test` in `x-ipe-docs/config/tools.json` (`6df39210…`) enables `x-ipe-tool-implementation-python` (`true`), used as the Python test-runner capability. The black-box runner [blackbox.py](acceptance/blackbox.py) calls the real CLI only through `uvx --from <framework>/scripts secure-code …` and never imports toolkit code. Chrome DevTools is enabled but not applicable (no UI) |
| Planned Cases | **Denominator: 22 logical TCs** (TC-D-01…17, TC-U-01, TC-R-01…04); a logical TC passes only if every one of its environment executions passes. Diagnostic only: **27 case × environment executions** = black-box CLI container 15 (TC-D-01…14, 16) + host 1 (TC-D-17) + TC-D-15 × 2 (container, host) + TC-U-01 × 1 + TC-R-01…04 × 2 (container, host). Priorities: P0 TC-D-01…03, 05, 06, 12, 13, 14, 16, TC-R-*; P1 TC-D-04, 07…11, 15, 17, TC-U-01 |

**Environment.**
- **Container (Maintainer path):** image `fat-uv-git:py312` (`8cbe78fe…`, Python 3.12.12, Linux aarch64, uv 0.9.30).
  - Offline: `--network none`, `UV_OFFLINE=1`; disposable HOME and `FAT_ISOLATED=1`.
  - Read-only toolkit mount (`/toolkit`) and runner mount (`/fat`). The project folders are named `proj ü`.
  - `FAT_WORK=/root/fat-work` and `TMPDIR=/root/fat-tmp` inside the container.
  - Uv cache volume `fat-uv-cache-001d`, newly created and verified (see "Cache freshness" below).
- **Host (User path):** macOS 26.6.2 arm64. Runner on Python 3.13.3; CLI environment on Python 3.14; uv 0.11.23.
  - `UV_REFRESH_PACKAGE=ai-secure-code-toolkit` and `UV_OFFLINE=1`.
  - `TMPDIR` and `FAT_WORK` inside the session folder.
  - Never-authorized User role (`auth status` → `user`, `not_initialized`); no trust writes.
- **Cache freshness (deviation, disclosed).** PyPI was unreachable during this task: TLS reset through the host proxy, on both the host and the container.
  - The online warm-up used before was therefore not possible. The new volume was seeded with the third-party packages of `fat-uv-cache-ca`.
  - Every toolkit entry was removed (`uv cache clean ai-secure-code-toolkit` plus leftover archives; 0 entries left).
  - The toolkit was then built offline from the current source, with both images.
  - Verification (TASK-054 rerun): the cached `x_ipe_secure_code/knowledge/exit.py` (`384a9853…`, TASK-054 fix) and `store.py` (`e5012c6b…`) are byte-identical to the toolkit files and to the hashes the owner verified.
  - The volume was recreated again for the TASK-054 rerun, after the product fix (log in the session folder `fat-001d/cache-warmup-verify-054.log`).
  - Host: `uvx -v` shows the tool environment `archive-v0/i4WVW8F-…`, which holds the same `store.py` and `exit.py` hashes (`fat-001d/host-cache-verify-054.log`).

**Fixtures (disclosed).**
- **Container setup:** `auth init` at a pseudo-terminal (owner authorization), then `knowledge import` of placeholder CWE rules:
  - `CWE/4.14/CWE-89` has two examples, applicability `python`, relations to `CWE-79` and to itself, and `source_document_digest` D;
  - `CWE/4.14/CWE-20` relates to `CWE-89` and comes from the same document D;
  - `CWE/4.14/CWE-79` has no relations.
  - Then `policy resolve` and `scope save --confirmed` (the user's confirmation flag).
- **Rich projects (TC-D-01…03):**
  - a concluded Guard verification (historical Markdown + JSON report);
  - one or two open Guard verifications (open → plan → record → Reviewer record);
  - an open Copilot collaboration with round r1 (historical report). S1 is on `CWE-89` and S2 on `CWE-79`;
  - a pending decision for `CWE-89`. A Maintainer update import with a credential-shaped line gives `needs_decision`.
  - Guard and Copilot are driven with the request shapes of the FEATURE-002-A and FEATURE-003-A runners. Reviewer records are written by the runner (invocation declared, not proven).
- **Damaged rules (03h):** written by the runner, standing in for hand edits:
  - a hand-edited `content.md`;
  - non-UTF-8 bytes;
  - an atomic-residue file `.content.md.tmp-123`;
  - a symbolic link to an outside canary.
- **Test hooks (06a, 06b, 02f):** the design's documented test-only environment hooks, set only on the one CLI subprocess concerned:
  - `SECURE_CODE_TEST_CRASH_AT=<point>`: the process exits with code 86 at that point;
  - `SECURE_CODE_TEST_PAUSE_AT=<point>=<marker>`: the process waits at `exit_locked`, `scope_save_locked`, … until the runner writes `<marker>.go`.
  - The installed CLI honours these hooks because the runner passes its environment.
- **Held lock (06a LOCKED):** the runner holds `flock` on `.x-ipe/private/secure-code/locks/knowledge.lock`.
- **Authorization (TC-D-16, container only, last case):**
  - *missing*: the trust folder is moved aside, then restored;
  - *invalid*: one character of a grant signature is changed, then the original bytes are restored. `auth status` is `maintainer` again before the next step;
  - *revoked*: `auth revoke` at a pseudo-terminal.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-03 | Spec G-03; EPIC-001 G-03, FR-07 (K-34, K-35, K-36, X-15 exit part, D-04); AC-09, AC-10 | Maintainer, Developer, upstream agent | Removing or renaming knowledge never silently breaks or rewrites dependent work; history stays traceable | Specification scenario run end to end (TC-D-01) plus TC-D-02…17, TC-U-01, TC-R-01…04 | AC-001D-01a…06c (all 30) | not measured |

The specification's outcome scenario was run with the real CLI (TC-D-01):
1. **Impact first.** `CWE/4.14/CWE-20` relates to `CWE/4.14/CWE-89`, and a confirmed scope adopts `CWE-89`. The rename preview to `CWE-89-SQL` lists every dependency with its identifier:
   - the relation from CWE-20 and the self-relation;
   - the scope;
   - the open Guard verification (not the concluded one);
   - the open Copilot collaboration;
   - the pending decision;
   - the index entry.
   The kinds "not checked in this version" are also stated. The preview writes nothing.
2. **Confirm.** With the shown digest, the rename is performed. No other rule, scope record, run state or report changes.
3. **Afterwards:**
   - `knowledge links`, `knowledge show CWE-20`, `policy resolve` and `scope show` report `CWE-89` as `missing`/`renamed` with `renamed_to` as information, never substituted;
   - the scope loads `partial`;
   - the open Guard verification concludes with `POLICY_CHANGED`, and the Copilot round marks S1 `policy_changed`;
   - all earlier reports and the scope record are byte-identical.

Real Maintainers, Developers or agents using exits: **not measured**.

## Full Acceptance / Evidence Map

All rows: Source/Parent G-03 (FR-07); original test type **Integration** retained for every AC. **Evidence kind:** every AC except 06c is proven by **black-box CLI** cases (the real installed CLI via `uvx`, subprocesses, files); AC-001D-06c is proven by **structured package inspection** of the installed `SKILL.md` text. Framework-suite results (TC-U-01) are cited only as supporting design-level evidence and are never counted as black-box evidence for an AC. Delivery State is **verified engineering delivery** at the revision in the header; Outcome State **not measured**. "Container" = [evidence-container-linux.jsonl](acceptance/evidence-container-linux.jsonl), "host" = [evidence-host-macos.jsonl](acceptance/evidence-host-macos.jsonl).

| AC ID | TC / Type | Original Assertions (as checked) | Result |
| --- | --- | --- | --- |
| AC-001D-01a | TC-D-01 (rename), TC-D-02 (deactivate, and reactivate), TC-D-03 (delete); integration | The rule has an incoming relation (CWE-20), an adopted scope, open Guard/Copilot runs and a pending decision. Confirm with the current digest succeeds for each action; references never block. The tree of the other rules, `scopes/`, Guard and Copilot private states and every report is byte-identical before and after each confirm | Pass |
| AC-001D-01b | TC-D-16 (container), TC-D-17 (host); integration | Preview with **missing** (trust folder aside), **invalid** (tampered grant), **revoked** (`auth revoke`) and **never-initialized** (host) authorization → `NOT_AUTHORIZED`, next step, no `impact` key, no traceback; project tree unchanged. Bounded recovery exception: a refused preview first completes an earlier authorized exit interrupted at `exit_after_record` (`recovered_exit.outcome = completed`; rule then deactivated, journal gone) and still returns no impact | Pass |
| AC-001D-01c | TC-D-16, TC-D-17; integration | Confirm with missing, invalid and never-initialized authorization → `NOT_AUTHORIZED`, nothing written. A valid preview, then `auth revoke`, then confirm with that digest → `NOT_AUTHORIZED` (re-verified); tree unchanged | Pass |
| AC-001D-02a | TC-D-01 (rename), TC-D-02 (deactivate, reactivate), TC-D-03 (delete); integration | Preview of every action: `impact` is the first key, and the data keys are exactly the Command Contract set. The six providers list their identifiers: relations `[CWE-20, CWE-89 (self)]`, scope id, open Guard verification ids (the concluded one is excluded), Copilot collaboration id, pending decision, index entry (document, edge; after deactivation the label is in `failed`). Counts equal the items. `impact_digest` is `sha256:<64 hex>`, `references_block: false`, and `will` states the effects and "no other rule, scope record, run or report is changed". The whole project tree (incl. private files and locks) is identical before and after each preview. The confirm contract keys are exact (rename: revision 1, `removed_pending` [CWE-89], `invalidated_index` [D], `tombstone` null, committed impact = previewed impact). Every preview (incl. **reactivate**, TASK-054) also passes the exact preview contract values (action, rule `CWE/4.14/CWE-89`, target, reason, `rule_state` keys, consistent, state) and the exact pending item `CWE/4.14/CWE-89` with counts equal to items | Pass |
| AC-001D-02b | TC-D-01…04; integration | `presets`, `tags`, `reference_cache` = "not checked in this version" in JSON and in text output, never an empty list | Pass |
| AC-001D-02c | TC-D-05; integration | Six deltas between preview and confirm, each in a fresh copy: rule updated (deactivate); a relation to it added by a new rule (delete); CWE-20's relation removed (rename); a scope adopting it saved (deactivate); a pending decision created (delete); an index entry changed by importing the same item from document D2 (rename). Each → `STALE_IMPACT`; `data.impact` equals a fresh preview's impact; no digest is returned; the fresh digest differs; the provider impact differs (rule-only change: digest-bound rule state); the tree is unchanged; next step says to preview again | Pass |
| AC-001D-02d | TC-D-06; integration | Confirm without digest and with a malformed digest → `IMPACT_DIGEST_REQUIRED`. A digest of another rule / action / reason / rename target → `STALE_IMPACT`. An unknown rule → `RULE_NOT_FOUND`. Each has a message and a next step to preview; nothing changed | Pass |
| AC-001D-02e | TC-D-04; integration | Dependency-free rule: all six supported lists `count 0`, `items []`. Confirm without digest is refused (`IMPACT_DIGEST_REQUIRED`), and the rule is unchanged after the preview | Pass |
| AC-001D-02f | TC-D-12; integration (real processes with pause hooks) | (1) Exit committed first, decision marked CWE-89 `not_adopted` → scope published with only CWE-79 adopted and the user's reason kept (deactivate and rename; the rename target is not adopted). (2) Exit first, CWE-89 adopted → `STALE_CONFIRMATION`, no scope file. (3) **Process race, exit first:** confirm paused at `exit_locked`; a concurrent `scope save` is still running 3 s later; after release the confirm commits and the save is refused with `STALE_CONFIRMATION`, no scope published. (4) **Process race, save first:** save paused at `scope_save_locked`; the concurrent confirm waits; the save publishes; the confirm is refused with `STALE_IMPACT`, whose new impact names the new scope; the rule stays active. (5) `guard open` and `copilot open` started while the confirm holds the lock wait, then refuse `SCOPE_PARTIAL` with `missing: [CWE-89]` (their existing Policy handling) | Pass |
| AC-001D-03a | TC-D-02; integration | Content and examples byte-identical, changelog kept as a prefix; record `lifecycle {deactivated, 1}`; `show` state deactivated, revision 1; new changelog entry with "deactivated", reason and UTC time; state digest changed and equals the confirm result | Pass |
| AC-001D-03b | TC-D-02; integration | Reactivate preview and confirm (with reason) → `reactivated`; resolve `available`; changelog entry "reactivated" with reason; revision 2; state digest differs from both the original and the deactivated value. Reactivate of an active rule and deactivate of a deactivated rule → `ACTION_NOT_APPLICABLE` | Pass |
| AC-001D-03c | TC-D-03; integration | Rule folder gone, not listed. Tombstone `…/exits/tombstones/<exit_id>/rule/` holds record, content, both examples and the full changelog byte-identical. The exit record has action, rule, reason, UTC time, exit id, consistent, removed pending, invalidated index and impact counts. Exit area `0700`, exit record `0600`. Exit memory `deleted` | Pass |
| AC-001D-03d | TC-D-01; integration | Only `CWE-89-SQL` exists. Content and examples byte-identical. The record differs in exactly `rule_id`, `item_digest`, `updated_at`, `lifecycle`; name, applicability, source location, source documents, relations (incl. the self-relation to the old ID) and created_at are unchanged. The self-relation is reported broken `renamed` (`renamed_to` the new ID). The changelog is kept and records old and new ID, reason and time. The state digest equals the confirm result. Memory `renamed_to`; `show` of the old ID → `RULE_NOT_FOUND` with `exited.renamed_to` | Pass |
| AC-001D-03e | TC-D-07; integration | 14 targets, each refused in **preview and confirm** with a reason: existing active / deactivated → `RENAME_TARGET_EXISTS`; deleted / renamed-away and their case variants → `IDENTITY_RESERVED`; case variants of active / deactivated / of itself → `IDENTITY_COLLISION`; other namespace, other source version, same ID → `RENAME_TARGET_INVALID`; invalid ID → `IDENTITY_INVALID`; identity held as a pending decision → `RENAME_TARGET_EXISTS`. Tree unchanged. The case-variant collision refusals are now decided by the TASK-054 handle-relative lookup (same codes; swapped-component behaviour is covered by the Framework suite's `test_exit_bugfix_task054.py`, supporting evidence only) | Pass |
| AC-001D-03f | TC-D-01 (rename), TC-D-02 (deactivate), TC-D-03 (delete); integration | Before: document D `fully_stored` and the pending decision held. Rename/delete: pending file removed and reported (`removed_pending`). Deactivate: pending file byte-identical, `removed_pending []`. All: `invalidated_index [D]`, the CWE-89 edge moved to `failed`, and a later `knowledge check` of D → `not_fully_stored` | Pass |
| AC-001D-03g | TC-D-08; integration | Preview without reason; confirm without, blank, empty → `REASON_REQUIRED`; multi-line → `REASON_INVALID`; each with a next step; tree unchanged | Pass |
| AC-001D-03h | TC-D-09; integration | Inconsistent (hand-edited) and unreadable (non-UTF-8) rules: deactivate, reactivate and rename previews → `RULE_INCONSISTENT` with a next step to restore the files (version control) or delete the rule. Delete preview allowed: `rule_state.consistent false`, fingerprint. Changing the residue file changes the digest, and the old digest is refused `STALE_IMPACT`. After confirm the tombstone tree equals the folder as found (tampered file, residue, link with the same target, not followed). The exit record has `consistent: false` and `folder_fingerprint` = the previewed fingerprint. The outside canary is unchanged. The unreadable rule's bytes are moved as found | Pass |
| AC-001D-04a | TC-D-01/02/03, TC-D-10; integration | Explicit refs → `missing` with `deactivated` / `deleted` / `renamed` (+ `renamed_to`); no `requirement`/`source_evidence`, no body text; the new ID's rule and the other stored version `CWE/4.13/CWE-79` are never returned. Design v1.2: version-less `CWE/CWE-79` resolves to the remaining `CWE/4.13/CWE-79` with `exited: [{CWE/4.14/CWE-79, deleted, null}]`; `CWE/CWE-77` (no version left) → `missing`/`deleted` with `exited` | Pass |
| AC-001D-04b | TC-D-10; integration | `--all` resolves only active rules (CWE-1, CWE-4-NEW, 4.13/CWE-79); `inactive = {deactivated 1, deleted 3, renamed 1}`; status `complete`, `missing` count 0. All rules deactivated → `maintenance_needed` with a reactivate/import next step | Pass |
| AC-001D-04c | TC-D-01/02/03; integration | `scope show`: CWE-89 `missing` with the same reason (+ `renamed_to`), status `partial`, only CWE-79 adopted; scope record file byte-identical | Pass |
| AC-001D-04d | TC-D-02; integration | Deactivate then reactivate with unchanged content → `needs_reconfirmation`, status `partial`, next step to confirm a new scope, exit 0, record byte-identical | Pass |
| AC-001D-04e | TC-D-01/02/03, TC-D-17; integration | `knowledge links` lists CWE-20 → CWE-89 (source, target, reason, `renamed_to`) and the scope adopting it; `show CWE-20` marks the broken relation and its `relations` stay `[CWE-89]`; the links text output names the reason and the "separate, explicit" repair step. Host: links runs read-only without authorization | Pass |
| AC-001D-04f | TC-D-01 (rename), TC-D-02 (deactivate, reactivate, cycle), TC-D-03 (delete); integration | The earlier Guard report (MD + JSON), Copilot round r1 (MD + JSON) and the scope record are byte-identical after each action and after later conclusions. An open Guard verification concludes not Pass with `POLICY_CHANGED` for CWE-89 (deactivate, delete, rename); a verification opened before the deactivation and concluded after the reactivation also reports `POLICY_CHANGED`. Copilot S1 `policy_changed` with `now` = `missing`, and after the cycle `changed`; S2 stays `adopted` | Pass |
| AC-001D-05a | TC-D-11; integration | `knowledge update` with the deactivated revision's `state_digest` → updated (new content, changelog entry), still deactivated | Pass |
| AC-001D-05b | TC-D-11; integration | Batch [deactivated CWE-89, new CWE-30]: CWE-89 refused `RULE_DEACTIVATED`, next step "reactivate … first"; CWE-30 stored (partial import, exit 1) | Pass |
| AC-001D-05c | TC-D-11; integration | Deleted CWE-77 and renamed-away CWE-78, exact and case variants (separate batches) → `IDENTITY_RESERVED`; other items stored; `exits/` tree (tombstones, memory, transitions) unchanged | Pass |
| AC-001D-05d | TC-D-01/02/03/11; integration | `list`: deactivated rule `state: deactivated`, the rename target active; `exited` lists deleted and renamed identities with action, `renamed_to`, reason and UTC time, apart from the rules. `show` of an exited identity → `RULE_NOT_FOUND` with exit information | Pass |
| AC-001D-06a | TC-D-13 (+ TC-D-16 bounded recovery); integration (real crashes via the documented hook) | All 29 documented points: deactivate 6, reactivate 5, delete 9, rename 9 — `exit_after_journal`, every `exit_after_<step>` and `exit_before_journal_delete`. Each crashed confirm exits 86 with empty stdout (never success) and leaves the journal. The next command rotates over import, update, exit-preview, check, list, show, links, resolve, scope save and scope show; it reports `recovered_exit {completed, rule, action}`. Then the state is fully exited and consistent: no journal and no `.exit-*` temporaries; marker and revision, changelog entry; tombstone or new ID; memory; one transition entry; pending kept (deactivate) or removed; index edge in `failed`; document `not_fully_stored`; `show` consistent. Recovery while another process holds the knowledge lock → `LOCKED` with next step for `list` and `resolve`, no data shown, tree unchanged; once free, the next command completes the exit. **Byte-level proof (TASK-054):** before every crash case (and the LOCKED case) the runner snapshots the complete pre-exit state: every file of the rule folder (content, examples, `record.json`, `changelog.md`), pending bytes, document index, exit memory, transition log, the CWE-20 rule and the scope records. After recovery it byte-compares: **delete** → the tombstoned `rule/` equals the pre-exit folder byte for byte, and the exit record has action, rule, time, reason, exit id, last state digest, revision from/to, transition binding, removed pending and invalidated index; **rename** → the destination has the same file set, byte-identical content/examples, a record differing only in `rule_id`/`item_digest`/`updated_at`/`lifecycle` with all non-identity metadata unchanged, and the old changelog plus exactly one appended `renamed` entry (old → new, reason, exit id); **deactivate/reactivate** → same file set, byte-identical content/examples, record differing only in `lifecycle` (and `updated_at`), old changelog plus exactly one appended entry. All actions: one transition entry for the action appended (earlier entries unchanged); full exit-memory entry (rule, action, `renamed_to`, time = transition time, reason, exit id, tombstone, transition digest) for delete/rename, memory unchanged otherwise; pending kept byte-identical (deactivate/reactivate) or removed (delete/rename); index edge moved to `failed`, other documents unchanged (reactivate: index unchanged); CWE-20 and earlier scope records untouched | Pass |
| AC-001D-06b | TC-D-14, TC-D-11; integration (real processes) | (1) Exit + update: the confirm paused holding the lock; a concurrent `knowledge update` with the pre-deactivation base waits, then `STATE_CONFLICT`; the rule is deactivated with its original content and no journal. (2) Two exits: deactivate paused; a concurrent rename confirm waits, then `STALE_IMPACT` (evaluated against the deactivation); no rename target, no exit memory, no journal. (3) An update whose base predates a reactivation → `STATE_CONFLICT`, tree unchanged; also an update with the pre-deactivation base (TC-D-11) | Pass |
| AC-001D-06c | TC-D-15; **structured package inspection** (executable phrase checks over the installed `SKILL.md` and `cli-contract.md` text, run in container and host; original AC type Integration retained; not a black-box CLI behaviour test) | Framework `SKILL.md` "Exiting Knowledge" (lines 89–114, after "Maintaining Knowledge"): real Maintainer request, never own initiative (l. 94–95); run exit-preview and show the whole impact first incl. "not checked" kinds (l. 96–100); references do not block, nothing else changed (l. 101–103); confirm only after explicit Maintainer confirmation, never on the Maintainer's behalf, re-preview on `STALE_IMPACT` (l. 104–106); never repair references automatically, `knowledge links` (l. 107–109); reserved identities, no restore, report journal/index/lock codes (l. 110–114). `references/cli-contract.md` documents the commands | Pass |

## Typed Test Cases and Execution Summary

| TC | ACs | Type | Priority | Command / Method | Result |
| --- | --- | --- | --- | --- | --- |
| TC-D-01 Rename: specification scenario end to end | 01a, 02a, 02b, 03d, 03f, 04a, 04c, 04e, 04f, 05d | integration | P0 | container runner | Pass (35 checks) |
| TC-D-02 Deactivate → reactivate (incl. cycle) | 01a, 02a, 02b, 03a, 03b, 03f, 04a, 04c, 04d, 04e, 04f, 05d | integration | P0 | container runner | Pass (52) |
| TC-D-03 Delete with tombstone | 01a, 02a, 02b, 03c, 03f, 04a, 04c, 04e, 04f, 05d | integration | P0 | container runner | Pass (31) |
| TC-D-04 Dependency-free rule; text output of preview and confirm | 02b, 02e | integration | P1 | container runner | Pass (5) |
| TC-D-05 Stale impact (six deltas) | 02c | integration | P0 | container runner | Pass (6) |
| TC-D-06 Digest binding | 02d | integration | P0 | container runner | Pass (8) |
| TC-D-07 Rename target refusals (14 targets × preview/confirm) | 03e | integration | P1 | container runner | Pass (15) |
| TC-D-08 Reason required | 03g | integration | P1 | container runner | Pass (6) |
| TC-D-09 Inconsistent / unreadable rules | 03h | integration | P1 | container runner | Pass (12) |
| TC-D-10 Resolve: explicit, all, version-less (v1.2) | 04a, 04b | integration | P1 | container runner | Pass (8) |
| TC-D-11 Use after exit: update, import refusals, list/show | 05a, 05b, 05c, 05d, 06b | integration | P1 | container runner | Pass (9) |
| TC-D-12 Exit / scope-save serialization incl. process races | 02f | integration | P0 | container runner (pause hooks) | Pass (6) |
| TC-D-13 Crash at every documented journal step + LOCKED | 06a | integration | P0 | container runner (crash hook) | Pass (61: 29 recovery + 29 byte-level snapshot + LOCKED + completion + LOCKED snapshot) |
| TC-D-14 Concurrent knowledge writes | 06b | integration | P0 | container runner (pause hook) | Pass (3) |
| TC-D-15 Framework skill "Exiting Knowledge" | 06c | structured package inspection (executable phrase checks; original AC type Integration) | P1 | container and host runner | Pass (7) in both |
| TC-D-16 Authorization: missing / invalid / revoked after preview; bounded recovery | 01b, 01c | integration | P0 | container runner (last case) | Pass (9) |
| TC-D-17 Never-authorized User | 01b, 01c, 04e | integration | P1 | host runner | Pass (7) |
| TC-U-01 Framework unit/integration suite (supporting, not black-box AC evidence) | design-level (NFR-001D-1…4, FR-001D-6 means) | unit / integration | P1 | `uv run --offline python -m pytest` (macOS, Python 3.14.6) | 1447 passed, 3 skipped |
| TC-R-01 FEATURE-001-B regression | 001-B | integration | P0 | 001-B runner, container `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` (`e5b65587…`) + host | 14/14 + 1/1 |
| TC-R-02 FEATURE-001-C regression | 001-C | integration | P0 | 001-C runner, same image + host | 14/14 + 1/1 |
| TC-R-03 FEATURE-002-A regression | 002-A | integration | P0 | 002-A runner, same image + host | 26/26 + 2/2 |
| TC-R-04 FEATURE-003-A regression | 003-A | integration | P0 | 003-A runner, container `fat-uv-git:py312`, marathon sample mounted at `/samples/m` + host | 11/11 (107 Copilot commands) + 2/2 |

Commands (from the workspace root; `A=x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/acceptance`, `S=<session folder>/files/fat-001d`):
- **Container:** `docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/toolkit -e UV_OFFLINE=1 -e FAT_WORK=/root/fat-work -e TMPDIR=/root/fat-tmp -e PYTHONDONTWRITEBYTECODE=1 -v fat-uv-cache-001d:/root/.cache/uv -v $PWD/ai-secure-code-toolkit:/toolkit:ro -v $PWD/$A:/fat:ro fat-uv-git:py312 sh -c 'mkdir -p /root/fat-tmp && python3 /fat/blackbox.py container'`
- **Host:** `cd $A && TMPDIR=$S/tmp FAT_WORK=$S/work UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit PYTHONDONTWRITEBYTECODE=1 python3 blackbox.py host`
- **Unit/integration:** `cd ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts && UV_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR=$S/tmp uv run --offline python -m pytest -p no:cacheprovider -q -o addopts="" --basetemp=$S/bt` (`uv sync --dry-run` beforehand: "Would make no changes", so the project `.venv` was not rewritten)
- **Regression containers:** the same offline pattern with each runner folder mounted read-only at `/fat`, the same cache volume `fat-uv-cache-001d`, the image named in the table (003-A adds `-v $PWD/study-case/secure-coding-guidance/playground/shanghai-marathon-registration:/samples/m:ro`). **Regression hosts:** `TMPDIR=$S/tmp-<f> FAT_WORK=$S/work-<f> UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit python3 blackbox.py host` in each runner folder. The four regression runners were run in place and not modified (hashes below).

## Relevant Inputs and Evidence

| Role | Path | SHA-256 |
| --- | --- | --- |
| source | [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) (EPIC-001 G-03, FR-07, AC-09, AC-10) | `1747efe61b9c5cf1264e357b2e2dd5e1c3b3da0b2acc05f862a84ad2df1ac65f` |
| specification | [specification.md](specification.md) | `fb74bfe254d3a6cbd373e5deb743c279fc2292e2e8bf97c12aa75bf2e06abcc2` |
| design | [technical-design.md](technical-design.md) v1.3 (incl. TASK-054 records) | `c052ed3c3449def4012268dc7818fef39a6be21f949b699896e73e01d8d7b171` |
| config | `x-ipe-docs/config/tools.json` | `6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d` |
| toolkit file list | `ai-secure-code-toolkit/` — SHA-256 of the `shasum -a 256` list of all 139 files, relative paths from `ai-secure-code-toolkit/`, sorted by path (excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage`); identical at start and end of the TASK-054 runs (TASK-052 value before the fix: `6fdb5b15…`, 138 files) | `a63578d7bfbbde2079e05e1c802694a6a942e6f93edb566fd1ae5aaff1e5c7cb` |
| code | `…/x_ipe_secure_code/knowledge/exit.py` (TASK-054 fix; was `8064183f…`) | `384a98531dd9fa72004e7e3987e288a924c02f66df7a3eaf3f214887a1198d64` |
| code | `…/knowledge/impact.py` | `9d1dd81fee1e7bf1c9e04cafff53bdb3fb09f19e02d35a0e269c7f9753ae51ef` |
| code | `…/knowledge/exit_journal.py` | `95172124d6c3484aa78a5877e43204d9c1455c57df5087578f0b3cb51dd71f45` |
| code | `…/knowledge/lifecycle.py` | `3fef41d1144c8d8a17d7237ee0a0aef808030e70790cb3c7d421ddac96e6615e` |
| code | `…/knowledge/durable.py` | `6468cdfca71645f2df13e48b9cb5445ebfc99c10fadd0b0cf1c0f433fe0ca4ad` |
| code | `…/knowledge/store.py` (TASK-054; was `877dd739…`) | `e5012c6b5f9c4c71479bf81bc594070280cad5b65a740158a58c16936c26f10a` |
| code | `…/knowledge/service.py` | `16eb269545057e407329ce5429774623dca4fc02a70b35b3d1958b7070cf7d6a` |
| code | `…/knowledge/views.py` | `a2934f7e537accecbf5cbbd342281862c8335c9b6111a1cba8e57a63cee85c6a` |
| code | `…/knowledge/changelog.py` | `56b962a821557b6e801942c571f2c4b58b647aefc58761fa1d238d66a3abe63f` |
| code | `…/policy/resolve.py` | `f1dcdd6e3afb9e58388b0de3bd30681ca242d7973eabe922c6cf3794def80f6d` |
| code | `…/policy/scope.py` | `1c5aa564b559462150227fb45e8c21a945ec505ac0a3f41f5c52cab94c0df38a` |
| code | `…/policy/service.py` | `2876bd77a7fcc64d542ee6384c2d0ded88dc3ffc87d41c989046260265e23bb0` |
| code | `…/copilot/service.py` | `d4c9a70e76f9331f077898dcdb84b7877f34100a976fda22ab93291ac93349af` |
| code | `…/cli.py` | `fb8a385cd6d2e8d3771cc543223183e387978a8ae08877a2d0c3b2c8b8f5ced8` |
| skill | Framework `SKILL.md` | `4592c02d7375a42d7435b82a21a0416b1c9a7770a491801b596514e9ee6775a8` |
| skill reference | Framework `references/cli-contract.md` | `a0d31b1b1bedd744a727e47e84b8630e30fcab392a2f88017f3ebeeaf97010ab` |
| skill reference | Framework `references/policy-selection.md` | `5a015418cb4c424dd17747ed7459c0bb4557fae67bb11509e560ef3211262c81` |
| test (runner) | [acceptance/blackbox.py](acceptance/blackbox.py) (TASK-054 strengthened) | `93a13a3117eb4ae257ffa5e7bc9bf3839820861914c66ee5ce771365fd351468` |
| test (Framework, TASK-054) | `…/scripts/tests/knowledge/test_exit_bugfix_task054.py` (supporting) | `863aaa0ecd7d98dcdc931b45a48ee69f3aa03437ced567925c97138c38096b6f` |
| test (regression runners, unchanged) | 001-B / 001-C / 002-A / 003-A `acceptance/blackbox.py` | `f0e5d389…` / `e5550429…` / `7dfbd3fe…` / `7a4cd98c…` |
| environment | `fat-uv-git:py312` `8cbe78fe…`; `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` `e5b65587…`; volume `fat-uv-cache-001d` (verified as above) | — |
| evidence | [acceptance/evidence-container-linux.jsonl](acceptance/evidence-container-linux.jsonl) (16/16, 273 checks) | `e61dd9cceb052754a051f21fcddbd0afbe5b0687b7640e18d71c584a29c2cdac` |
| evidence | [acceptance/evidence-container-linux.stderr](acceptance/evidence-container-linux.stderr) (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| evidence | [acceptance/evidence-host-macos.jsonl](acceptance/evidence-host-macos.jsonl) (2/2, 14 checks) | `1c1171cddb30a35184930f72c6bbd6c890ef06fb005a83371b7bc7be918c07e5` |
| evidence | [acceptance/evidence-host-macos.stderr](acceptance/evidence-host-macos.stderr) (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| evidence | [acceptance/evidence-unit-integration.log](acceptance/evidence-unit-integration.log) (1447 passed, 3 skipped) | `cd5b286d31e388e783ccf483055da6baf76f90ab15795847b071cdd0177d28b0` |
| regression | [regression-001B-container-linux.jsonl](acceptance/regression-001B-container-linux.jsonl) (14/14) | `5bca7a8331f6d488516a2affa82b46f08b53d6bca3c80f040ba32a65b946d3fe` |
| regression | [regression-001B-host-macos.jsonl](acceptance/regression-001B-host-macos.jsonl) (1/1) | `259f5fb9e1baaae628405acf10000c67b28b68cb3277c56d9ced4d9fa180b26a` |
| regression | [regression-001C-container-linux.jsonl](acceptance/regression-001C-container-linux.jsonl) (14/14) | `03b11dd364dad5ae29ca7970207be57740b31c92513a5e8736b755f029f75a51` |
| regression | [regression-001C-host-macos.jsonl](acceptance/regression-001C-host-macos.jsonl) (1/1) | `3ef8a509d7c55571b6246069b90bc4a14f97d4da2427f261084dba169d520cf3` |
| regression | [regression-002A-container-linux.jsonl](acceptance/regression-002A-container-linux.jsonl) (26/26) | `404ada17d57738f443ed3398aa79b9f96bf21cd0a286eb00cc6a7d5e0b87b611` |
| regression | [regression-002A-host-macos.jsonl](acceptance/regression-002A-host-macos.jsonl) (2/2) | `b87e492ec1ccacd5328687f24f8c5cb33914ae246429e0fc537ff397e62fd6e2` |
| regression | [regression-003A-container-linux.jsonl](acceptance/regression-003A-container-linux.jsonl) (11/11) | `4b978585269bdb2e5cf866d4029cc48db002a81440e1fddd8732ec310a4c7a51` |
| regression | [regression-003A-host-macos.jsonl](acceptance/regression-003A-host-macos.jsonl) (2/2) | `e2e89141e8ecdcee286d14b0e2af2b3fef6cd02d2f214d9fdfb753992cfb566e` |

The product hashes equal those in the design's Implementation Evidence (TASK-051, Stage C), except `exit.py` and `store.py`, which carry the TASK-054 fix (hashes as verified by the owner). The host evidence log is byte-identical to the TASK-052 host run (no timestamps or generated ids). All eight regression logs are **byte-identical** to the original acceptance evidence of those features (same SHA-256 as `5bca7a83…`, `259f5fb9…`, `03b11dd3…`, `3ef8a509…`, `404ada17…`, `b87e492e…`, `4b978585…`, `e2e89141…` recorded in the FEATURE-001-B/001-C/002-A/003-A reports). The regression runs had empty stderr; those files were not kept.

## Execution Results

**Execution date / executor:** 2026-10-22, TASK-052 acceptance worker under owner Sage; evidence rerun under Bug Fix TASK-054. **Environment:** as above.

| Type | Total Planned | Passed | Failed | Blocked | Partial / Not Run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 | 0 | 0 | 0 | 0 |
| backend-api | 0 | 0 | 0 | 0 | 0 |
| integration — black-box CLI (TC-D-01…14, 16 container; TC-D-17 host) | 16 | 16 | 0 | 0 | 0 |
| structured-review — package inspection (TC-D-15; 2 executions: container, host) | 1 | 1 | 0 | 0 | 0 |
| unit / integration — Framework suite, supporting (TC-U-01) | 1 | 1 | 0 | 0 | 0 |
| integration — black-box regression (TC-R-01…04; 8 executions: container, host) | 4 | 4 | 0 | 0 | 0 |
| **TOTAL (logical TCs)** | **22** | **22** | **0** | **0** | **0** |

Pass rate: 22/22 logical TCs = 100% (TASK-054 rerun; all 27 case × environment executions passed). Denominator = all planned logical TCs incl. blocked/not-run; a logical TC passes only if all its environment executions pass. All 30 ACs have current passing evidence at the revision above: 29 by black-box CLI cases (287 checks: 273 container, 14 host) and AC-001D-06c by structured package inspection. These counts are diagnostic and do not measure goal achievement.

**Runner corrections before the evidence runs (no product change, no product assertion weakened):**
- First host dry run:
  - Without `UV_OFFLINE=1`, uv tried to reach PyPI (unreachable) and `init` failed. All host runs then used `UV_OFFLINE=1` together with `UV_REFRESH_PACKAGE`.
  - The runner's own text check expected the refusal header `knowledge exit-preview: REFUSED`. The CLI prints the shared authorization envelope `require maintainer: REFUSED` with `action: knowledge.exit-preview` and `[NOT_AUTHORIZED]`. `knowledge import` (FEATURE-001-B) prints the same envelope.
  - The specification requires only the envelope, `NOT_AUTHORIZED` and a next step; it does not specify this header. The check now asserts the envelope, the action, the code and the next steps.
- Container dry runs: two runs (2/2 and 16/16) on the first warm-up of the cache volume. They were not kept as evidence. The volume was then recreated and re-verified before the evidence run.
- TASK-054 strengthening (dry runs not kept as evidence): the first dry run of the new AC-001D-06a snapshot checks failed 21 sub-checks because the runner counted changelog headers as `\n## ` while an appended entry starts the tail with `## `. This was a runner bug; the count now includes the first line. A scratch negative control then recovered one crash per action and altered the result (content byte, removed pending, truncated changelog, tombstone example, memory reason, renamed-rule metadata, index `failed` label). Each alteration was detected by the intended sub-check and restoring it returned to clean.
- TASK-054 evidence: the cache volume was recreated after the product fix and verified against `exit.py` `384a9853…` / `store.py` `e5012c6b…`; product files were identical at the start and end of all runs.

### Failures / Blockers

None.

### Gaps and Honest Limits

- **Windows:** not run (macOS host and Linux container only); the Windows `lstat`/identity fallback of `durable.py` is not black-box tested.
- **Crash = process crash, not power loss:** the 06a matrix interrupts the real CLI with the documented `SECURE_CODE_TEST_CRASH_AT` hook (`os._exit(86)`). Durability against power loss is evidenced only by the fsync-ordering tests in TC-U-01, as the design states.
- **Framework-suite citations only (TC-U-01) — not black-box CLI evidence:**
  - injected I/O failures (`SECURE_CODE_TEST_FAIL_AT`, EXDEV before/after the journal);
  - symlink canaries and component swaps on private paths;
  - tampered, truncated or out-of-order journals (`EXIT_JOURNAL_INVALID`);
  - `EXIT_MEMORY_INVALID`, `INDEX_INVALID`, `EXIT_TRANSITION_INVALID`;
  - FIFO/device entries and `RULE_FOLDER_UNREADABLE`.
  These are design-level means for NFR-001D-1 and FR-001D-6. They are not separate ACs, and the suite passed at the same hashes.
- **Serialization proof (02f, 06b):** the black-box shows that the contender is still running 3 s after it starts while the other command holds the lock, and that the final outcomes follow the serialized order. The bounded lock-acquisition probe handshake is only in the unit tests (`K/test_exit_concurrency.py`).
- **Skill AC 06c:** structured package inspection of the installed text, not a CLI behaviour test. Agent conduct (showing the impact, waiting for a real Maintainer confirmation) is not observable by the script.
- **Preset, tag and Reference-cache impact:** "not checked in this version" by design, until FEATURE-001-E/F.
- **Cache warm-up deviation:** offline seeding instead of an online warm-up (PyPI unreachable), with the current toolkit build verified in the cache; disclosed above.
- **Earlier runners' removal fixtures:** the FEATURE-001-C and FEATURE-003-A runners still stand in for a removed rule by deleting its folder (they predate the exit commands). They were rerun unchanged, as required.
- **Independent review of this acceptance evidence:** not performed by the acceptance worker; left to the owner.

### Engineering Delivery versus Stakeholder Outcome

| Goal | Delivery Evidence / State | Outcome Scenario | Outcome State |
| --- | --- | --- | --- |
| G-03 | All 30 ACs pass (29 by black-box CLI in container + host, AC-001D-06c by structured package inspection); Framework suite 1447 passed / 3 skipped (supporting only); 001-B/001-C/002-A/003-A regressions pass byte-identically: verified engineering delivery (Linux container, macOS User path and suite) | Specification rename scenario (TC-D-01): impact shown first, relation reported "renamed to CWE-89-SQL" (not substituted), scope loads partial, old reports unchanged | not measured |

### Refactor / Closing Recommendation and App Gates

Acceptance found no evidenced quality or preservation need: all assertions pass, and the module sizes are enforced by `tests/test_module_size.py` (largest touched modules: `exit.py` and `exit_journal.py`, 656 lines each; `store.py` 610; all under 800). The two conditional successors (code refactor, feature closing) are returned to the lifecycle owner. If `code_refactor` is mandatory in the app workflow, that gate applies. This worker made no board, workflow, memory or Git writes and changed no product, product documentation or existing test.

## Acceptance Evidence Record

```yaml
acceptance_evidence:
  feature_id: "FEATURE-001-D"
  inputs:
    - {role: source, path: "x-ipe-docs/requirements/requirement-details.md", sha256: "1747efe61b9c5cf1264e357b2e2dd5e1c3b3da0b2acc05f862a84ad2df1ac65f"}
    - {role: specification, path: "x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/specification.md", sha256: "fb74bfe254d3a6cbd373e5deb743c279fc2292e2e8bf97c12aa75bf2e06abcc2"}
    - {role: design, path: "x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/technical-design.md", sha256: "c052ed3c3449def4012268dc7818fef39a6be21f949b699896e73e01d8d7b171"}
    - {role: config, path: "x-ipe-docs/config/tools.json", sha256: "6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d"}
    - {role: code, path: "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/exit.py", sha256: "384a98531dd9fa72004e7e3987e288a924c02f66df7a3eaf3f214887a1198d64"}
    - {role: code, path: "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/exit_journal.py", sha256: "95172124d6c3484aa78a5877e43204d9c1455c57df5087578f0b3cb51dd71f45"}
    - {role: code, path: "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/knowledge/store.py", sha256: "e5012c6b5f9c4c71479bf81bc594070280cad5b65a740158a58c16936c26f10a"}
    - {role: code, path: "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/SKILL.md", sha256: "4592c02d7375a42d7435b82a21a0416b1c9a7770a491801b596514e9ee6775a8"}
    - {role: test, path: "x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/acceptance/blackbox.py", sha256: "93a13a3117eb4ae257ffa5e7bc9bf3839820861914c66ee5ce771365fd351468"}
    - {role: evidence, path: "x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/acceptance/evidence-container-linux.jsonl", sha256: "e61dd9cceb052754a051f21fcddbd0afbe5b0687b7640e18d71c584a29c2cdac"}
    - {role: evidence, path: "x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/acceptance/evidence-host-macos.jsonl", sha256: "1c1171cddb30a35184930f72c6bbd6c890ef06fb005a83371b7bc7be918c07e5"}
    - {role: evidence, path: "x-ipe-docs/requirements/EPIC-001/FEATURE-001-D/acceptance/evidence-unit-integration.log", sha256: "cd5b286d31e388e783ccf483055da6baf76f90ab15795847b071cdd0177d28b0"}
    # all further product files, regression logs and stderr files: see "Relevant Inputs and Evidence"
  cases:
    - {tc_id: TC-D-01, ac_ids: [AC-001D-01a, AC-001D-02a, AC-001D-02b, AC-001D-03d, AC-001D-03f, AC-001D-04a, AC-001D-04c, AC-001D-04e, AC-001D-04f, AC-001D-05d], test_type: integration, status: Pass, command_or_review: "container: python3 /fat/blackbox.py container", result: "35/35 checks", environment: "fat-uv-git:py312, offline, disposable HOME", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-02, ac_ids: [AC-001D-01a, AC-001D-02a, AC-001D-02b, AC-001D-03a, AC-001D-03b, AC-001D-03f, AC-001D-04a, AC-001D-04c, AC-001D-04d, AC-001D-04e, AC-001D-04f, AC-001D-05d], test_type: integration, status: Pass, result: "52/52", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-03, ac_ids: [AC-001D-01a, AC-001D-02a, AC-001D-02b, AC-001D-03c, AC-001D-03f, AC-001D-04a, AC-001D-04c, AC-001D-04e, AC-001D-04f, AC-001D-05d], test_type: integration, status: Pass, result: "31/31", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-04, ac_ids: [AC-001D-02b, AC-001D-02e], test_type: integration, status: Pass, result: "5/5", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-05, ac_ids: [AC-001D-02c], test_type: integration, status: Pass, result: "6/6", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-06, ac_ids: [AC-001D-02d], test_type: integration, status: Pass, result: "8/8", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-07, ac_ids: [AC-001D-03e], test_type: integration, status: Pass, result: "15/15", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-08, ac_ids: [AC-001D-03g], test_type: integration, status: Pass, result: "6/6", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-09, ac_ids: [AC-001D-03h], test_type: integration, status: Pass, result: "12/12", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-10, ac_ids: [AC-001D-04a, AC-001D-04b], test_type: integration, status: Pass, result: "8/8", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-11, ac_ids: [AC-001D-05a, AC-001D-05b, AC-001D-05c, AC-001D-05d, AC-001D-06b], test_type: integration, status: Pass, result: "9/9", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-12, ac_ids: [AC-001D-02f], test_type: integration, status: Pass, result: "6/6 (two real process races + Guard/Copilot open during confirm)", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-13, ac_ids: [AC-001D-06a], test_type: integration, status: Pass, result: "61/61 (29 crash points with recovery + byte-level snapshot checks, LOCKED, completion, LOCKED snapshot)", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-14, ac_ids: [AC-001D-06b], test_type: integration, status: Pass, result: "3/3", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-15, ac_ids: [AC-001D-06c], test_type: structured-review (package inspection), status: Pass, result: "7/7 in container and host", evidence_paths: [acceptance/evidence-container-linux.jsonl, acceptance/evidence-host-macos.jsonl]}
    - {tc_id: TC-D-16, ac_ids: [AC-001D-01b, AC-001D-01c], test_type: integration, status: Pass, result: "9/9", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-D-17, ac_ids: [AC-001D-01b, AC-001D-01c, AC-001D-04e], test_type: integration, status: Pass, command_or_review: "host: python3 blackbox.py host", result: "7/7", environment: "macOS, never-authorized User", evidence_paths: [acceptance/evidence-host-macos.jsonl]}
    - {tc_id: TC-U-01, ac_ids: [supporting, design-level], test_type: unit, status: Pass, result: "1447 passed, 3 skipped", evidence_paths: [acceptance/evidence-unit-integration.log]}
    - {tc_id: TC-R-01..04, ac_ids: [regression 001-B, 001-C, 002-A, 003-A], test_type: integration, status: Pass, result: "14/14+1/1, 14/14+1/1, 26/26+2/2, 11/11+2/2; byte-identical to original evidence", evidence_paths: [acceptance/regression-*.jsonl]}
```

This record shows hash and coverage consistency only. The executed artifacts above are the proof, and stakeholder outcome is **not measured**.
