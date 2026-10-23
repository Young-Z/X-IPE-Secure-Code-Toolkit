# Bug Report — TASK-014 (FEATURE-001-B)

> Severity: **Medium** (partial behavior: no data loss; one command crashes, one status can be over-reported) · Mode: free-mode, interact-with-human · Found by: independent closing review (TASK-013)

## Bugs, Expected versus Actual

| # | Reported deviation | Expected (source) | Actual (reproduced) |
|---|---|---|---|
| 1 | `knowledge check` / `knowledge list` crash when another process holds the knowledge lock past the timeout | Every command returns the result envelope with one next step for each refusal ([spec](x-ipe-docs/requirements/EPIC-001/FEATURE-001-B/specification.md) UI/UX Requirements); design: busy lock → `LOCKED` | Uncaught `LockHeld` traceback, no envelope |
| 2 | Old-format document-index entries (written before `unidentified_failures`/`largest_batch` existed) lose failures of items without identity | A document is `fully_stored` only when every item from it is stored unchanged (AC-001B-04b) | After any failure-free batch, `check` reported `fully_stored` while an earlier item had failed |

## Source / Goal Frame

Stakeholder: Maintainer and upstream agent (FEATURE-001-B G-04 — unchanged work not repeated, and nothing lost). Restoration contributes by keeping `check` truthful and all commands well-behaved. Constraints unchanged; no AC modified. Outcome state: not measured.

## Reproduction (failing before fix)

- Source revision before fix: `service.py` `2d6f6e4936e209d9…`.
- `uv run pytest tests/knowledge/test_knowledge.py -k "held_lock or old_format"` → 3 failed: `LockHeld` raised from `check` and `list` (bug 1); `assert 'fully_stored' == 'not_fully_stored'` (bug 2).

## Root Cause

1. `check`/`list_rules` caught only `StoreError` from creating the lock object; `LockHeld` is raised later by entering the lock (`with lock:`), outside any handler (implementation error).
2. `_update_index` dropped `#N` labels from old `failed` lists and defaulted the new counters (`unidentified_failures` → 0, `largest_batch` → 0), so a one-item failure-free batch reset completeness (implementation error in the format migration).

## Fix (minimal)

- `check`/`list_rules`: enter the lock explicitly; `LockHeld` → refused `LOCKED` with next step; release in `finally`.
- `_update_index`: for entries without the new keys, count old `#N` failures (or 1 if the old entry was incomplete without identified failures) and default `largest_batch` to the document's known size (stored items + recorded failures).
- No interface, data-model or workflow contract change; new-format entries behave as before. Design Change Log updated.

## Conflict Analysis

Inspected: `service.check`, `service.list_rules`, `service._update_index`, `cli._knowledge`, `store.lock`, tests. Expected consequence only: refusals instead of tracebacks; conservative completeness for legacy entries. No unexpected conflicts.

## Verification (after fix)

- `service.py` `e4ad948c1d0dddb8…`, `test_knowledge.py` `973dd277546cc996…`; the same three tests pass unchanged.
- Full suite: macOS Python 3.14 **163 passed**, macOS Python 3.11 **163 passed**, Linux Python 3.12 **163 passed**; `ruff check` clean.
- FEATURE-001-B black-box acceptance rerun at toolkit tree `7dd48feeef45bd09…`: offline Linux **14/14**, macOS **1/1** (logs unchanged in content).
