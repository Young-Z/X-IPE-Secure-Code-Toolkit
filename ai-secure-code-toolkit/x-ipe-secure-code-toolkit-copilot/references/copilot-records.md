# Copilot Request Files and Records

Request files for `secure-code copilot` (FEATURE-003-A). Write them under
`.x-ipe/private/secure-code/tmp/`, never inside the artifacts. Every command returns the toolkit
result envelope (`--json` for the structured form) with one next step per refusal. Free text
(task, location, action, reason, Reviewer requirement and basis, host and agent) is masked when it
looks like a credential; masked fields are labelled in the state, the structured result and the
Markdown report. Masking is pattern-based, not a complete data-loss-prevention guarantee. Text that already
contains a mask marker (`[masked:...]`) is refused, so only the toolkit produces masked values.

## Open (`secure-code copilot open --request FILE`)

```json
{
  "schema": "ai-secure-code-toolkit/copilot-open/v1",
  "scope_id": "sha256:3f1c0d2a9b8e7f6a5d4c3b2a1908f7e6d5c4b3a291807f6e5d4c3b2a19087f6e",
  "stage": "implementation",
  "task": "Add user registration with e-mail confirmation",
  "artifacts": [
    {"path": "src/register.py", "change": "modified"},
    {"path": "src/signup.py", "change": "renamed", "old_path": "src/join.py"},
    {"path": "src/legacy.py", "change": "deleted"},
    {"path": "docs/registration", "change": "modified"}
  ],
  "context": [{"path": "README.md"}]
}
```

- `scope_id` comes from the Framework skill (`secure-code scope save`). Missing →
  `SCOPE_REQUIRED`; unknown → `SCOPE_NOT_FOUND`; no usable Policy → `MAINTENANCE_NEEDED`; changed
  or missing Policies → `SCOPE_PARTIAL` (the refusal lists `adopted`, `needs_reconfirmation` and
  `missing`). Nothing is created on a refusal.
- `stage`: `design`, `implementation`, `bug_fix` or `refactor`.
- `artifacts` (required, explicit): files with `change` `added`, `modified`, `deleted`, `renamed`
  (with `old_path`) or `unspecified` (default); existing folders only with `added`, `modified` or
  `unspecified`. `.` or `whole_project` is refused (`WHOLE_PROJECT_REFUSED`); an empty list is
  `ARTIFACTS_REQUIRED`. Paths must be inside the project, without symbolic links, and not toolkit
  data (`.x-ipe/private/…`, `x-ipe-docs/secure-code/…`) or Git internals.
- Every artifact file and every regular file inside a folder becomes a member of the per-file
  manifest with its digest (deleted files and renamed-away old paths without digest). Links and
  special entries inside folders are listed as `not_bindable`. At most 5000 files
  (`MANIFEST_TOO_LARGE`: name narrower artifacts).
- `context`: read-only paths; never manifest members, never reviewed.

The result returns `collaboration_id` (`cp-YYYYMMDDTHHMMSSZ-<8 hex>`), the manifest and the adopted
rules with their confirmed state digests.

## Artifact update (`secure-code copilot artifacts --id ID --request FILE`)

```json
{
  "schema": "ai-secure-code-toolkit/copilot-artifacts/v1",
  "artifacts": [
    {"path": "src/mailer.py", "change": "added"},
    {"path": "src/accounts.py", "change": "renamed", "old_path": "src/register.py"},
    {"path": "docs/registration", "change": "modified"}
  ]
}
```

Same entry rules as at open. The listed paths overwrite their manifest entries (new paths are
added and become bindable). A deleted or renamed folder is refused: list its files. An update never
changes a suggestion's state by itself; staleness is always computed against the reviewed digests.

## Suggestions (`secure-code copilot suggest --id ID --request FILE`)

```json
{
  "schema": "ai-secure-code-toolkit/copilot-suggest/v1",
  "suggestions": [
    {
      "id": "S1",
      "rule": "CWE/4.14/CWE-89",
      "files": ["src/register.py"],
      "location": "register(), INSERT statement",
      "action": "Use a parameterized query for the INSERT instead of string formatting",
      "reason": "The e-mail address from the request reaches the SQL text",
      "severity": "high"
    },
    {
      "id": "S2",
      "rule": "CWE/4.14/CWE-79",
      "files": ["src/register.py", "docs/registration/flow.md"],
      "location": "confirmation page template",
      "action": "Escape the user name when rendering the confirmation page",
      "reason": "The user name is echoed back"
    }
  ]
}
```

- One adopted `rule`; `files` are manifest members (a recorded deleted file is allowed); `location`,
  `action` and `reason` are required, non-empty texts (at most 8192 characters).
- `severity`: `critical`, `high`, `medium`, `low`, `info` or `unknown` (default `unknown`, never
  `low`). `stage` defaults to the collaboration stage.
- IDs are unique within the collaboration. Any invalid suggestion refuses the whole batch
  (`SUGGESTION_INVALID`); nothing is stored.

## Reviewer record (`secure-code copilot review --id ID --request FILE`)

The shared `reviewer-record/v1` envelope (also used by Guard) with `adoption` subjects:

```json
{
  "schema": "ai-secure-code-toolkit/reviewer-record/v1",
  "invocation": {"host": "github-copilot", "agent": "copilot-reviewer", "read_only": true,
                 "invoked_at": "2026-10-21T10:40:00Z"},
  "requirement": "Check in the formed artifact whether suggestions S1 and S2 were adopted",
  "reviewed_targets": [
    {"path": "src/register.py", "digest": "sha256:9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
    {"path": "docs/registration/flow.md", "digest": "absent"}
  ],
  "subjects": [
    {"type": "adoption", "id": "S1", "result": "adopted", "basis": "register.py line 14 uses a bound parameter"},
    {"type": "adoption", "id": "S2", "result": "cannot_verify", "basis": "the template is not part of the artifacts"}
  ],
  "reviewed_at": "2026-10-21T10:44:00Z"
}
```

- `result`: `adopted`, `partial`, `not_adopted`, `not_applicable` or `cannot_verify`; every subject
  needs a `basis` (for `adopted`: where the measure is found). A subject without basis, naming an
  unknown suggestion or given twice refuses the whole record (`REVIEW_INVALID`).
- `reviewed_targets` carries the digest the Reviewer saw for every bound file of each covered
  suggestion, or `absent` for a file that no longer exists. When the list is present, a missing
  bound file refuses the whole record; every path must be a manifest member.
- A record without host, agent, `read_only: true`, `invoked_at`, requirement, the reviewed-digest
  list as a whole, subjects or a result is kept but is not a valid review (the report says why).
  Reviewed digests that already differ from the files when recorded are a wrong version: the record
  does not count for the suggestions bound to them.
- No extra authority: `suggestions`, `artifacts`, `manifest`, `stage`, `scope`, `scope_id` and the
  Guard parts (`plan`, `findings`, …) are refused (`REVIEW_AUTHORITY`). Copilot has no budget, so
  Guard's `attempt` and `usage` are refused too (`REVIEW_INVALID`).

## Suggestion States

Computed by `report`, `show` and `close`, in this precedence:

1. `policy_changed` — the suggestion's rule changed or was removed since the collaboration was
   opened. Permanent for this collaboration, even if the Policy returns to its old state; next step:
   re-confirm the scope and open a new collaboration.
2. From the most recent valid Reviewer record covering it: its result (`adopted`, `partial`,
   `not_adopted`, `not_applicable`, `cannot_verify`) when the current digests of all bound files
   equal the reviewed ones (a still-missing file matches `absent`); otherwise `stale`, naming each
   changed file as `modified`, `deleted` or `renamed_away`.
3. `not_reviewed` — no valid record covers it.

Earlier results of stale and Policy-changed suggestions (and results superseded by a later valid
record) are shown as history, never as current adoption. `show` lists `stale` and `not_reviewed`
suggestions as needing re-review; send only those (and new suggestions) to the Reviewer.

## Attention Rule

- **Attention:** suggestions of severity high, critical or unknown whose state is `partial`,
  `not_adopted`, `cannot_verify`, `not_reviewed`, `stale` or `policy_changed`, with the reason;
  ordered critical, high, unknown.
- **Gaps:** every other suggestion in one of those states.
- Only `adopted` and `not_applicable` suggestions appear in neither list.

Copilot does not pause the work: the upstream caller reads the attention list and gaps and decides.

## Report Rounds

`secure-code copilot report` publishes `x-ipe-docs/secure-code/reports/copilot/<id>-r<n>.json`
(`copilot-result/v1`) and `<id>-r<n>.md`, rendered from the same data, only when the state
(suggestions, reviews, manifest, current digests, Policy states) changed since the latest round;
otherwise it returns the latest pair. Earlier rounds are never modified; the latest is current.
The round is committed when it is recorded in the private state after both files exist. Files of an
interrupted round are completed or refused (`REPORT_CONFLICT`: move the named files away manually)
before the next change; nothing is overwritten.

Both outputs show every Reviewer record in full: validity with its reasons, the declared invocation
(host, agent, read-only flag, invocation time; declared, not proven), the requirement, the reviewed and
recorded times, the reviewed targets with the digest the Reviewer saw (or `absent`), the subjects with
result, basis and masked labels, and the suggestions each record counts or does not count for.

The structured result contains no pass, approved or verdict field. Both outputs state that the
report is not a pass or security verification and does not replace Guard, and that reports and
the private collaboration data (`.x-ipe/private/secure-code/copilot/<id>/`) stay until the user
removes them (statements about their existence are as of publication). `secure-code copilot show`
says whether the private data and each report still exist.
