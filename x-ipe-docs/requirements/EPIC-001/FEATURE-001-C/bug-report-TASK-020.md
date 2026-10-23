# Bug Report — TASK-020 (FEATURE-001-C)

> Severity: **Medium** (partial behavior: crash with traceback on malformed input; no data written or lost) · Mode: free-mode, interact-with-human · Found by: independent closing review (TASK-019)

## Bugs, Expected versus Actual

| # | Reported deviation | Expected (source) | Actual (reproduced) |
|---|---|---|---|
| 1 | Text that UTF-8 cannot encode (lone surrogates: invalid bytes in command-line arguments on macOS/Linux, or `\ud800`-style JSON escapes) crashes `policy resolve`, `scope save` and `scope show` | Every command returns the result envelope with one next step per refusal ([spec](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md) UI/UX); invalid references are `missing`/`invalid_reference` while others are processed (Edge Cases); a changed or malformed scope record is refused as `SCOPE_INVALID` (AC-001C-05d) | Uncaught `UnicodeEncodeError: surrogates not allowed` traceback |
| 2 | Evidence gap: AC-001C-05f "rule removed before save" not exercised by the acceptance runner | Every AC clause has acceptance evidence | Only "updated" and "added (Apply All)" were checked |

## Source / Goal Frame

Stakeholder: Developer and upstream agent (FEATURE-001-C G-03 — adopted scope traceable, refusals well-formed). Restoration keeps every command inside its result-envelope contract; no AC, contract or scope change. Outcome state: not measured.

## Reproduction (failing before fix)

- Unfixed `policy/` sources: `refs.py` `c7b4575f…`, `resolve.py` `4e47dff3…`, `scope.py` `4c4927f2…`, `service.py` `9c9633f9…`.
- `uv run pytest tests/policy -k surrogate` → **9 failed**, all with `UnicodeEncodeError` (service-level resolve with a surrogate reference; real CLI subprocess with byte `\xff` in `--rule`; surrogate `--language` with `--output`; decisions file with `\ud800` in `clues`/`considered`/`note`; scope record hand-edited with `\ud800` in `clues`/`created_at`; rule record with a surrogate in `source_documents` plus `--output`).
- Black-box: the offline container run against a stale pre-fix build reproduced bug 1 at the real CLI (TC-C-11 new check failed with the same traceback).

## Root Cause

Implementation error: untrusted text reached strict UTF-8 encoding — `resolve.proposal_digest` and `scope._canonical` (`json.dumps(..., ensure_ascii=False).encode("utf-8")`) and the `--output` writer — without being validated at the input boundaries (command-line references/languages, decisions file, stored scope record, rule-record fields outside the item digest). `created_at` was outside the canonical digest, so a surrogate there passed verification.

## Fix (minimal)

- `refs.is_utf8(value)` (recursive) and `parse_requested`: non-encodable reference → `invalid_reference` with a backslash-escaped `requested` text.
- `service.resolve_policies`: non-encodable `--language` → `REQUEST_INVALID`.
- `scope.load_decisions`: non-encodable text anywhere → `DECISIONS_INVALID`; `scope.verify_record`: → `SCOPE_INVALID` (covers `created_at`).
- `resolve._strings` (fields outside the item digest): non-encodable strings dropped.
- No interface, data-model or workflow contract change; Design Change Log updated.
- Acceptance runner: TC-C-12 adds the 05f removed-rule case; TC-C-11 adds the non-UTF-8 record case.

## Conflict Analysis

Inspected: `refs.parse_requested`, `resolve.build/_strings/proposal_digest`, `scope.load_decisions/verify_record/with_id`, `service.resolve_policies/save_scope/show_scope`, `cli.main` (stdout already `errors="replace"`), knowledge `read_rule` (UnicodeError is a ValueError → already `inconsistent`). Expected consequences only: such input is refused or marked invalid instead of crashing. Valid UTF-8 input (all existing tests) unaffected. No unexpected conflicts.

## Verification (after fix)

- Fixed sources: `refs.py` `5c2cd32a…`, `resolve.py` `9e3894c8…`, `scope.py` `10482753…`, `service.py` `dd7dce69…`; tests `test_policy.py` `7143a93c…` (regression assertions unchanged since RED; formatter only).
- Full suite **241 passed** on macOS Python 3.14, macOS Python 3.11 and Linux Python 3.12; `ruff check` clean; policy coverage 82–100%.
- Black-box acceptance at toolkit tree `e9fdecb199e2ff43…`: offline Linux **14/14** (fresh uv cache, verified to contain the fix), macOS host **1/1** (refreshed build), unit/skill evidence **29/29**.
- Environment note: `uvx` reused a tool environment built before the fix despite changed sources; acceptance now re-warms the container cache and refreshes the host package (`UV_REFRESH_PACKAGE`) before each run.
- Independent review of the fix delta: crash paths closed, no valid-input behaviour change. It found the two new acceptance checks under-asserted their ACs (05d next step / no Policies; 05f re-confirm next step); assertions added (strengthened, not relaxed) and the container run repeated: **14/14**.
