# Presets and Tags

A **Preset** is a reusable, named Policy scope: a saved list of concrete rule references
(`NAMESPACE/VERSION/RULE_ID`). A **tag** classifies rules (inside one source or across Local
namespaces) for lookup and as a clue. Both are visible JSON files, one per Preset or tag:
`x-ipe-docs/secure-code/presets/<name>.json` and `x-ipe-docs/secure-code/tags/<name>.json`. JSON is
the only authoritative format; never keep a second Markdown list.

Names are lowercase `a-z`, `0-9` and hyphens (1-64 characters, unique ignoring letter case, no
Windows device names). `default` is reserved for the default Preset and cannot name a tag. There is
no rename and no separate display label: delete and create instead.

## Commands

All commands take `--project DIR` and `--json`; write commands need `--confirmed` (your statement
that the user confirmed) and update/delete need the current `--digest` (the `file_digest` shown by
`show`/`list`; a changed file is refused as `STALE_DIGEST` with the current digest — show the
current content again, never merge silently).

```bash
secure-code preset list | show NAME
secure-code preset save --request FILE --confirmed
secure-code preset update NAME --request FILE --digest D --confirmed
secure-code preset delete NAME --digest D --confirmed
secure-code preset recompute NAME --request FILE
secure-code preset recompute-confirm NAME --request FILE --confirmed
secure-code preset resolve NAME [--language L] [--output FILE]   # or: preset resolve --default
secure-code preset scope-save NAME --decisions FILE --confirmed
secure-code tag list | show NAME
secure-code tag save --request FILE --confirmed                 # Maintainer
secure-code tag update NAME --request FILE --digest D --confirmed   # Maintainer
secure-code tag delete NAME --digest D --confirmed              # Maintainer
```

Request files (write them under `.x-ipe/private/secure-code/`):

```json
{"schema": "ai-secure-code-toolkit/preset-request/v1", "name": "web-input",
 "rules": ["CWE/4.14/CWE-79", "CWE/CWE-89"], "query_intent": "injection rules for HTTP input",
 "applicability_summary": "Web request handlers in Java/Python services"}
```

Preset update: give `rules` (a membership change, with either a new `applicability_summary` or
`"keep_summary": true`), or only `query_intent` / `applicability_summary` (membership and
`snapshot_at` unchanged). Tag request: `{"schema": "ai-secure-code-toolkit/tag-request/v1",
"name": "injection", "members": ["CWE/4.14/CWE-79"]}`.

Every reference is checked like `policy resolve` (`not_found`, `pending_decision`, `inconsistent`,
`multiple_versions` with candidates, `deactivated`, `deleted`, `renamed`). Tag names, expressions,
wildcards or other selectors are refused as `dynamic_selector`; a Reference member is refused
`invalid_reference` until FEATURE-001-E delivers Reference knowledge. Stored references are always
fully qualified; no rule content, example or state digest is stored.

## Save as Preset

1. Create a Preset only when the user explicitly asks to make the clues reusable. Clues without
   that request remain a temporary scope for this task.
2. Turn the clues into concrete references (`secure-code knowledge list` / `show`) and show the
   user the concrete list with the reason for each rule, plus an applicability summary you wrote
   (which work the Preset fits, e.g. "Web request handlers in Python services").
3. Only after the user confirms the list and the summary, write the request file and run
   `secure-code preset save --request FILE --confirmed`. `snapshot_at` is set to the confirmation
   time; it is the time of the last confirmed list change and does not freeze rule content.
4. Saving `default` makes it the default Preset (proposed when no clues are given).

Preset maintenance needs no Maintainer authorization and grants none: it never changes knowledge.

## Recompute

The `query_intent` is intent text only. The toolkit never runs it as a program or query; it is never
run implicitly when a Preset is listed, shown or used.

1. Recompute only when the user explicitly asks. Turn the intent into candidate references
   yourself, using only the existing read operations: `secure-code knowledge list`,
   `secure-code knowledge show`, `secure-code tag show` and `secure-code policy resolve`.
2. Submit them with `secure-code preset recompute NAME --request FILE`
   (`{"schema": "ai-secure-code-toolkit/preset-recompute/v1", "candidates": [...]}`). The toolkit
   validates every candidate, lists invalid ones with their reason (never confirmable) and returns
   the diff: `+` additions, `-` removals, the unchanged count, and a `recompute_digest`. Nothing is
   written.
3. Show the diff and ask for explicit confirmation (the user may accept only some additions or
   removals). If the list changes, also ask for a new applicability summary or the decision to keep
   the current one.
4. Then run `secure-code preset recompute-confirm NAME --request FILE --confirmed` with the same
   candidates, `recompute_digest`, `accept_add` / `accept_remove` (`"all"` or a list) and
   `applicability_summary` or `"keep_summary": true`. `STALE_RECOMPUTE` means the Preset or a rule
   changed: show the new diff and ask again. An unchanged list writes nothing unless the user
   explicitly re-confirms it (`"reconfirm": true`).

## Applicability

When a Preset is saved or its list changes, summarize its applicability. When a Preset is used,
compare its applicability summary with the current task. If they clearly mismatch, explain the
difference and wait for the user's decision to continue or adjust before you propose the scope for
confirmation.

## Offering Presets

When the clues match several Presets, list all matching Presets by name in the fixed name order of
`secure-code preset list`, with no ranking of your own. Show each entry's applicability summary and
any clear mismatch with the current task; the user picks.

## Using a Preset as Scope

1. Run `secure-code preset resolve NAME`. The result is the normal Policy proposal (library size,
   availability of each stored reference, `proposal_digest`, nothing adopted yet) plus the Preset's
   name, `snapshot_at`, applicability summary and a clue `preset:<name>@sha256:<digest>` that the
   toolkit generates from the file it read. Never compose this clue yourself.
2. Show missing or changed references as for any proposal. After the user confirms, write the
   decisions file (mode `clues`, `clues` = the generated clue copied exactly, `considered` = the
   proposed references, one decision per reference) and run
   `secure-code preset scope-save NAME --decisions FILE --confirmed`. It reads the Preset again; if
   its references or a rule's state changed since the proposal, the save is refused as
   `STALE_CONFIRMATION`: resolve again.
3. No clues: follow [policy selection](policy-selection.md) step 1 (`preset resolve --default`).

The saved scope is an ordinary `clues` record holding the adopted references; later Preset changes
or deletion never change it.

## Tags

Everyone may list and show tags and use them as clues. A tag clue is expanded into concrete
references at proposal time (`secure-code tag show`, then `policy resolve --rule ...`); the scope
record holds only those references, so later tag changes never change it. Tags never change
severity, mandatory marking or Presets.

Creating, updating or deleting a tag needs a Maintainer: a User is refused `NOT_AUTHORIZED` — ask a
Maintainer, or save the rules as a Preset instead. This restriction covers toolkit-mediated
operations only (toolkit-mediated tag writes); it is no filesystem-level protection of the files.

## Exits and Broken References

`knowledge exit-preview` lists the Presets and tags that reference the rule (unreadable files are
findings and part of the impact digest). Exits never edit Presets or tags: afterwards
`preset show`, `preset resolve`, `tag show` and `knowledge links` (`preset_tag_links`) report the
reference as broken with its reason; `renamed_to` is information only, never a substitute. Update a
Preset only on the user's explicit request.

## Known limits

- Drift is detected only for the concrete references and their rule state digests. A metadata-only
  change of the Preset (applicability summary, query intent, `snapshot_at`) between `preset resolve`
  and `preset scope-save` is not detected; the adopted scope is still exactly what the user
  confirmed.
- The `preset:<name>@sha256:<digest>` clue is information-only text. It is not bound by the proposal
  digest, not re-checked when the scope is saved and not tamper-evident; a clue typed by a user that
  looks the same is ordinary clue text.
- The toolkit keeps no Preset/tag change history; version control is the history, and
  snapshot_at is not a history.
- The Maintainer-only rule for tags applies to toolkit-mediated operations only.
