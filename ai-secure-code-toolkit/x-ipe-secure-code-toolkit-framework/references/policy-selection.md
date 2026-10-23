# Policy Selection and Adopted Scope

Guard and Copilot use only Policies the user adopted. This reference describes how the agent
proposes a scope, how the user confirms it, and the files involved.

## Three Scopes

| Scope | Meaning | Where it comes from |
|---|---|---|
| Library | Every formal Local rule stored | `knowledge import` (FEATURE-001-B) |
| Suggested | What the agent proposes for this work | Your interpretation of the user's clues, or Apply All |
| Adopted | What the user confirmed | `scope save --confirmed` → scope record |

Importing, listing or suggesting a rule never adopts it. Confirming a scope needs no Maintainer
authorization and grants none.

## Procedure

1. **Collect clues.** Rule IDs, a description of the work, the artifact languages. If the user
   gives no clues, run `secure-code preset resolve --project . --default --json` first:
   - **A default Preset exists:** show its highlighted notice and propose it; nothing is adopted
     until the user confirms, then save with
     `secure-code preset scope-save default --decisions FILE --confirmed`.
   - **No default Preset** (`no_default_preset`): go to step 3 with `--all` (Apply All).
   - **The default Preset is unusable** (refused or `maintenance_needed`): explain the reason and
     offer to repair it or to choose another scope. Never propose Apply All automatically; go to
     step 3 with `--all` only when the user separately and explicitly chooses Apply All.
2. **Turn clues into concrete rule references.** Use `secure-code knowledge list` (and `show`
   when needed). Use `NAMESPACE/VERSION/RULE_ID`, or `NAMESPACE/RULE_ID` when the user did not
   name a version. Keep a short reason for each suggestion. Never invent rules or versions.
3. **Resolve.**

   ```bash
   secure-code policy resolve --project . --rule CWE/4.14/CWE-79 --rule CWE/CWE-89 --language java --json
   secure-code policy resolve --project . --all --output .x-ipe/private/secure-code/all-policies.json --json
   ```

   - `status`: `complete` (all available), `partial` (some missing/unclear) or
     `maintenance_needed` (nothing usable — tell the user a Maintainer must import knowledge;
     do not continue with invented rules).
   - Each entry: `available` (a Policy with the requirement text, applicability, language note,
     source evidence and `state_digest`), `missing` (reason `not_found`, `pending_decision`,
     `inconsistent`, `unreadable`, `invalid_reference`, `deactivated`, `deleted` or `renamed`
     with `renamed_to` as information only) or `unclear` (`multiple_versions` with candidates).
     An exited rule is never replaced by another ID or source version.
   - Version-less references (`NAMESPACE/RULE_ID`) keep their resolution; when the exit memory
     holds exited identities `NAMESPACE/*/RULE_ID`, the entry adds the informational
     `exited: [{rule, reason, renamed_to}]` (no stored version left: `missing` with the reason of
     the most recent exit). It never changes availability, counts, status or the digest.
   - `--all` resolves active rules only; `inactive: {deactivated, deleted, renamed}` counts are
     informational. If every rule is deactivated, ask a Maintainer to reactivate or import rules.
   - `notices`: `APPLY_ALL_PROPOSED` (show it highlighted: Policy scope only — the artifact
     scope is decided separately), `MULTI_VERSION`, `PENDING_EXCLUDED`, `EXITED_IDENTITIES`,
     `EXIT_MEMORY_UNREADABLE`.
4. **Present the proposal.** For each Policy: the reason and the language note. The language
   note is advisory: never drop a rule because of it; if you suggest an exclusion, present it as
   a suggestion the user can reverse. List every missing and unclear reference. Policies you
   judge ambiguous, contradictory, lacking context or in conflict with another Policy are
   **unclear**: ask the user a question. Apply no precedence of your own.
5. **Confirm.** Ask the user to confirm which Policies are adopted. Never create a Preset from
   clues unless the user explicitly asks to make them reusable (then follow
   [presets and tags](presets-and-tags.md): show the concrete list with reasons and the
   applicability summary, and save only after the user confirms). Only after the user confirms,
   write the decisions file and save:

   ```bash
   secure-code scope save --project . --decisions decisions.json --confirmed --json
   ```

   The script cannot see the conversation: `--confirmed` is your statement that the user
   confirmed. Never pass it otherwise.
6. **Hand over.** Give the returned `scope_id` to Guard or Copilot:

   ```bash
   secure-code scope show --project . --scope sha256:<id> --json
   ```

   Consumers count only `adopted_rules`. Policies changed since confirmation are
   `needs_reconfirmation` (current text is for review only; also a rule deactivated and then
   reactivated) and removed or exited ones `missing` with their reason (and `renamed_to`); the
   status is then `partial` or `maintenance_needed` and the user must confirm a new scope. The
   scope record itself is never changed.

## Decisions File (`ai-secure-code-toolkit/scope-decisions/v1`)

```json
{
  "schema": "ai-secure-code-toolkit/scope-decisions/v1",
  "mode": "clues",
  "considered": ["CWE/4.14/CWE-79", "CWE/CWE-89", "@ACME/v1/ACME-7"],
  "proposal_digest": "sha256:<from policy resolve>",
  "clues": "Java login service; user named CWE-79 and CWE-89",
  "language_context": ["java"],
  "decisions": [
    {"ref": "CWE/4.14/CWE-79", "decision": "adopted", "state_digest": "sha256:<from the entry>",
     "note": "user: applies to templates"},
    {"ref": "CWE/CWE-89", "decision": "not_adopted", "reason": "unclear: two versions; user deferred"},
    {"ref": "@ACME/v1/ACME-7", "decision": "not_adopted", "reason": "conflicts with CWE-79; user chose CWE"}
  ],
  "confirmation_note": "User confirmed the list above in chat"
}
```

| Field | Rule |
|---|---|
| `mode` | `clues` (with `considered` = exactly the references given to `resolve`) or `apply_all` (no `considered`; every library rule needs a decision) |
| `proposal_digest` | From the `resolve` result the user saw |
| `decisions` | Exactly one per considered reference. `adopted` only for `available` entries, with their `state_digest`; `not_adopted` needs the user's `reason` |
| `note`, `reason`, `clues`, `confirmation_note` | At most 4096 characters; `confirmation_note` and every `reason` are required. No secrets or personal data |

Refusals (nothing is written): `CONFIRMATION_REQUIRED`, `DECISIONS_INVALID`,
`STALE_CONFIRMATION` (knowledge changed after the proposal — resolve and confirm again),
`DECISION_MISSING`, `NOT_ADOPTABLE`, `NOTHING_ADOPTED`, `LOCKED`, `EXIT_TRANSITION_INVALID`.

Scope save re-checks the proposal under the knowledge lock. One exception: if exactly the latest
knowledge exit (deactivate, delete or rename; reactivate only in `clues` mode) explains the
change and the user explicitly decided every affected reference `not_adopted`, the scope is
saved with the original confirmed references only. A rename's new ID is never adopted
implicitly (reported as `outside_confirmed_scope`). Any other change, or an exit of an adopted
reference, is `STALE_CONFIRMATION`; a damaged exit transition is `EXIT_TRANSITION_INVALID`.

## Scope Record

Stored at `x-ipe-docs/secure-code/scopes/<hex>.json` (created on first save; not a Preset and not
knowledge). `scope_id` = `sha256:` + SHA-256 of the canonical record without `scope_id` and
`created_at`, so saving the same confirmed scope twice returns the same record, and a changed
file is refused as `SCOPE_INVALID`. Records are kept until the user removes them.
