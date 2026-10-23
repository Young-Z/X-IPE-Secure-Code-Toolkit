# CLI Contract — `secure-code`

| Command | Arguments | Behaviour | Exit |
|---|---|---|---|
| `secure-code init` | `--project PATH`, `--env github-copilot\|claude-code`, `--replace PATH` (repeatable, project-relative), `--toolkit-source DIR`, `--json` | Project initialization / safe re-initialization | 0 ok · 1 refused · 2 usage |
| `secure-code status` | `--project PATH`, `--json` | Read-only sectioned status; `tools.trivy` adds `execution`, `components` (per component state, registry, `repository:tag`, `content_digest`, metadata, database age, `disk_bytes`, next step), `cache_disk_bytes_total` and `recovery_pending`; never executes a tool | 0 produced · 1 invalid root |
| `secure-code carriers` | `--project PATH`, `--env github-copilot\|claude-code`, `--select KIND` / `--deselect KIND` (repeatable; not combined), `--system-prompt-host NAME`, `--regenerate KIND` / `--accept KIND` (repeatable, per carrier), `--json`; `KIND` = `host-entry`, `github-instructions` (`github-copilot` only), `system-prompt` | Generates and checks the host integration carriers from the single routing definition under the project lock: plans every selected carrier first and refuses the whole run on any blocked carrier; writes only the selected carrier files and the install record (never the skills folder, never deletes a carrier). Per carrier: `state` (`created`, `appended`, `current`, `updated`, `kept-differs`, `replaced`, `customized`, `no longer managed`), `front_matter`, `user_content`, one next step; secret-masked `differences` with the five choices; `system_prompt` content and the manual step; `integration_declaration`; `routing_identity`; `host_effect` "written / component-checked; host effect not verified"; `notices` when the record holds the `carriers` member | 0 completed (kept differences included) · 1 refused or failed · 2 usage |
| `secure-code auth init` | `--json` | First authorization or re-authorization after revocation (interactive owner only) | 0 / 1 |
| `secure-code auth revoke` | `--json` | Revoke the authorization (interactive owner only) | 0 / 1 |
| `secure-code auth status` | `--json` | Verified role only | 0 |
| `secure-code knowledge check` | `--project`, `--input FILE`, `--json` | Stored/changed/new per item; fully stored source documents (read-only) | 0 / 1 |
| `secure-code knowledge import` | `--project`, `--batch FILE`, `--accept-update RULE@DIGEST`, `--false-positive RULE:FINGERPRINT`, `--json` | Per-item outcomes: stored, current, update_candidate, needs_decision, refused, not_processed (Maintainer); deactivated identities refused `RULE_DEACTIVATED` (next step: reactivate first), exited identities (ignoring letter case) `IDENTITY_RESERVED` | 0 none refused/not processed · 1 otherwise |
| `secure-code knowledge update` | `--project`, `--rule`, `--base-state DIGEST`, `--input FILE`, `--false-positive`, `--json` | One rule; `--base-state` is the rule's `state_digest` (item digest + lifecycle revision); refused `STATE_CONFLICT` on a stale base (data: `item_digest`, `state_digest`); a deactivated rule stays deactivated (Maintainer) | 0 / 1 |
| `secure-code knowledge list` | `--project`, `--namespace`, `--version`, `--json` | Rules (incl. `state` active/deactivated, `state_digest`, `lifecycle_revision`), pending decisions and `exited` identities (`rule`, `action` deleted/renamed, `renamed_to`, `at`, `reason`) (read-only) | 0 / 1 |
| `secure-code knowledge show` | `--project`, `--rule`, `--json` | Record, content, examples, changelog, digest, consistency, `state`, `state_digest`, `lifecycle_revision`, `relations_status`, `broken_relations` (read-only); an exited identity is `RULE_NOT_FOUND` with `data.exited` | 0 / 1 |
| `secure-code knowledge exit-preview` | `--project`, `--rule NS/VER/ID`, `--action deactivate\|reactivate\|delete\|rename`, `--to NS/VER/ID` (rename only), `--reason TEXT`, `--json` | Impact first, then what the action will do and `impact_digest`; writes nothing (Maintainer) — see [Exiting Knowledge](#exiting-knowledge) | 0 / 1 |
| `secure-code knowledge exit-confirm` | the same + `--impact-digest DIGEST` | Performs the previewed exit through the exit journal; success only after the commit (Maintainer, explicit confirmation) | 0 / 1 |
| `secure-code knowledge links` | `--project`, `--json` | Broken relations, scope references and (when Preset/tag files exist) `preset_tag_links` with reasons; never repairs (read-only, no authorization) | 0 / 1 |
| `secure-code policy resolve` | `--project`, `--rule REF` (repeatable) or `--all`, `--language L`, `--output FILE`, `--json` | Structured Policies, missing/unclear references, notices, proposal digest (read-only, no authorization) | 0 complete/partial · 1 maintenance_needed or refused |
| `secure-code scope save` | `--project`, `--decisions FILE`, `--confirmed`, `--json` | Saves the user-confirmed adopted scope; returns `scope_id` ([policy selection](policy-selection.md)) | 0 / 1 |
| `secure-code scope show` | `--project`, `--scope ID`, `--output FILE`, `--json` | Adopted / needs_reconfirmation / missing per Policy; `adopted_rules` | 0 complete/partial · 1 maintenance_needed or refused |
| `secure-code preset list` / `preset show NAME` | `--project`, `--json` | Presets in fixed name order / one Preset with current availability, `snapshot_at` meaning, intent (not run), broken references ([presets and tags](presets-and-tags.md); read-only, no authorization) | 0 / 1 |
| `secure-code preset save` | `--project`, `--request FILE`, `--confirmed`, `--json` | Saves a confirmed Preset of concrete, available references (no Maintainer authorization) | 0 / 1 |
| `secure-code preset update NAME` / `preset delete NAME` | `--project`, `--request FILE` (update), `--digest D`, `--confirmed`, `--json` | Digest-guarded change or removal; scope records are never changed | 0 / 1 |
| `secure-code preset recompute NAME` / `preset recompute-confirm NAME` | `--project`, `--request FILE`, `--confirmed` (confirm), `--json` | Diff of agent-produced candidates (read-only) / apply the confirmed diff with its `recompute_digest` | 0 / 1 |
| `secure-code preset resolve NAME` / `preset resolve --default` | `--project`, `--language L`, `--output FILE`, `--json` | The `policy resolve` proposal for the Preset's stored references plus `preset` (generated information-only clue); `--default`: the default Preset or `no_default_preset` | 0 complete/partial/no default · 1 maintenance_needed or refused |
| `secure-code preset scope-save NAME` | `--project`, `--decisions FILE`, `--confirmed`, `--json` | Saves the confirmed Preset-based scope as a `clues` record (references re-read from the Preset; drift → `STALE_CONFIRMATION`) | 0 / 1 |
| `secure-code tag list` / `tag show NAME` | `--project`, `--json` | Tags / one tag with current availability (read-only, everyone) | 0 / 1 |
| `secure-code tag save` / `tag update NAME` / `tag delete NAME` | `--project`, `--request FILE` (save/update), `--digest D` (update/delete), `--confirmed`, `--json` | Maintainer-only tag writes (toolkit-mediated) | 0 / 1 |
| `secure-code guard open` | `--project`, `--request FILE`, `--json` | Opens a verification of explicit targets against a complete adopted scope with a budget (defaults or less); returns `verification_id`, target digests and the budget ([Guard request files](../../x-ipe-secure-code-toolkit-guard/references/guard-records.md)) | 0 / 1 |
| `secure-code guard plan` | `--project`, `--run ID`, `--request FILE`, `--json` | Records the check plan once (adopted rules only, every rule covered) | 0 / 1 |
| `secure-code guard record` | `--project`, `--run ID`, `--request FILE`, `--json` | Records masked evidence, findings, ledger states and conflicts (all or nothing); evidence and findings cite a registered attempt | 0 / 1 |
| `secure-code guard attempt` | `--project`, `--run ID`, `--request FILE`, `--json` | Registers one unit of work before it starts; returns its id, extra-attempt cost and deadline; refused when paused or the budget is used up | 0 / 1 |
| `secure-code guard pause` / `resume` | `--project`, `--run ID`, (`--reason TEXT`), `--json` | Stops / restarts the budget clock while waiting for the user; nothing can be recorded while paused | 0 / 1 |
| `secure-code guard extend` | `--project`, `--run ID`, `--minutes N`, `--attempts N`, `--reason TEXT`, `--json` | User at an interactive terminal types the verification id; adds time and/or extra attempts (max 480 minutes, 20 attempts) | 0 / 1 |
| `secure-code guard cancel` | `--project`, `--run ID`, `--reason TEXT`, `--json` | Cancels one verification at once; stops a tool it runs (termination confirmed only when observed); one final partial result, never Pass; `finalization: pending` while another commit is in progress | 0 / 1 |
| `secure-code guard allow-egress` | `--project`, `--run ID`, `--purpose P`, `--recipient ORIGIN`, `--data CATS`, `--scope S` (repeatable), `--reason TEXT`, `--json` | User at an interactive terminal grants one outbound purpose for one verification | 0 / 1 |
| `secure-code guard egress` | `--project`, `--run ID`, `--request FILE`, `--json` | Declares one outbound call; recorded masked as allowed (single-use id) or refused (`EGRESS_NOT_AUTHORIZED`) | 0 allowed · 1 refused |
| `secure-code guard review` | `--project`, `--run ID`, `--request FILE`, `--json` | Records one Reviewer record citing its reviewer attempt; validity decided at conclusion | 0 / 1 |
| `secure-code guard conclude` | `--project`, `--run ID`, `--json` | Deterministic verdict (pass / fail / cannot_confirm_pass) with reasons; writes `x-ipe-docs/secure-code/reports/guard/<id>.json` and `.md`; repeated runs return the same result | 0 concluded (any verdict) · 1 refused |
| `secure-code guard show` | `--project`, `--run ID`, `--json` | Concluded result, evidence availability, report consistency, targets changed since; for an open verification a `NOT_CONCLUDED` refusal carrying the budget state | 0 / 1 |
| `secure-code guard accept-risk` | `--project`, `--run ID`, `--finding F`, `--reason TEXT`, `--json` | User at an interactive terminal types the finding id; recorded separately on a Fail verification; verdict unchanged | 0 / 1 |
| `secure-code guard keep` / `release` | `--project`, `--run ID`, (`--reason TEXT`), `--json` | Set / remove a keep marker on a verification's evidence | 0 / 1 |
| `secure-code guard tool` | `--project`, `--run ID`, `--request FILE`, `--json` | Runs an Adapter (Opengrep or Trivy; Trivy offline on Linux x86-64/arm64 with provisioned components, `filesystem` or `image_archive` mode) for planned, selected checks on a staged copy; records per-check runtime evidence (`ok` only with complete accounting) and tool findings; pre-check gaps (e.g. `TOOL_HOME_UNSUPPORTED`: system temporary folder path not ASCII-only) are recorded as failed evidence; a tool exit without output is a failed method | 0 recorded (any outcome) · 1 refused (nothing recorded) |
| `secure-code tools register` | `--project`, `--tool opengrep\|trivy`, `--path PATH`, `--json` | Maintainer registers an official tool binary; its SHA-256 must match the toolkit's official release digests for this platform (Trivy: Linux x86-64/arm64 only); never executed | 0 / 1 |
| `secure-code tools provision` | `--project`, `--tool trivy`, `--run ID`, `--component C` (repeatable: `vulnerability_db`, `java_db`, `checks_bundle`), `--registry mirror.gcr.io\|ghcr.io` (default `mirror.gcr.io`), `--time-limit SECONDS` (1…3600, default 600), `--json` | Maintainer downloads Trivy components with the registered binary as one budgeted `tool_update` attempt of an open verification; each operation is declared and needs the user's `tool_update` grants for every known host of the repository (`ghcr.io` also `pkg-containers.githubusercontent.com`); a component replaces the previous one only after verification; interrupted runs are rolled back or forward | 0 provisioned or recorded failure · 1 refused |
| `secure-code tools remove-components` | `--project`, `--tool trivy`, `--component C` (repeatable) or `--all`, `--json` | Maintainer removes provisioned Trivy components from the project's private cache | 0 / 1 |
| `secure-code guard cleanup` | `--project`, `--json` | Removes evidence of finished verifications ended more than 30 days ago without keep marker; never reports or running runs | 0 / 1 |
| `secure-code copilot open` | `--project`, `--request FILE`, `--json` | Opens a collaboration on explicit changed artifacts against a complete adopted scope; records the stage, task, artifacts and a per-file manifest with digests; returns `collaboration_id` (`cp-YYYYMMDDTHHMMSSZ-<8 hex>`); scope refusals (`SCOPE_REQUIRED`, `SCOPE_NOT_FOUND`, `MAINTENANCE_NEEDED`, `SCOPE_PARTIAL`) create nothing ([Copilot request files](../../x-ipe-secure-code-toolkit-copilot/references/copilot-records.md)) | 0 / 1 |
| `secure-code copilot artifacts` | `--project`, `--id ID`, `--request FILE`, `--json` | Records added, modified, deleted or renamed artifacts in the manifest (folders only added/modified); never changes a suggestion state by itself | 0 / 1 |
| `secure-code copilot suggest` | `--project`, `--id ID`, `--request FILE`, `--json` | Records one batch of suggestions (adopted rule, manifest files, location, action, reason, severity default `unknown`); all or nothing; free text masked with labels | 0 / 1 |
| `secure-code copilot review` | `--project`, `--id ID`, `--request FILE`, `--json` | Records one shared Reviewer record with `adoption` subjects bound to reviewed digests (`absent` allowed); incomplete records kept but invalid; wrong-version paths listed | 0 / 1 |
| `secure-code copilot report` | `--project`, `--id ID`, `--json` | Publishes round n+1 (`x-ipe-docs/secure-code/reports/copilot/<id>-r<n>.json` and `.md`, created exclusively, never overwritten) only when the state changed; else returns the latest pair; states, attention list and gaps; no pass field | 0 / 1 |
| `secure-code copilot show` | `--project`, `--id ID`, `--json` | Read-only current state: suggestion states, stale and not-reviewed suggestions to re-review, latest round, whether the private data and each report exist | 0 / 1 |
| `secure-code copilot close` | `--project`, `--id ID`, `--json` | Publishes a final round if the state changed, closes the collaboration and returns the latest pair; later recordings are refused (`COLLAB_CLOSED`) | 0 / 1 |

No option accepts a passphrase, key or trust-folder path.

## Result envelope

```json
{
  "schema": "ai-secure-code-toolkit/result/v1",
  "command": "init",
  "ok": false,
  "data": {},
  "problems": [{"code": "ENV_REQUIRED", "message": "No environment given; supported: github-copilot, claude-code"}],
  "next_steps": ["Re-run with --env github-copilot or --env claude-code"]
}
```

Text output carries the same content.

## Problem codes

`ROOT_REQUIRED`, `ROOT_INVALID`, `PATH_INVALID`, `ENV_REQUIRED`, `ENV_UNSUPPORTED`,
`PAYLOAD_INCOMPLETE`, `PAYLOAD_SYMLINK`, `RECORD_INVALID`, `PATH_UNSAFE`, `SKILL_NAME_CONFLICT`,
`LOCALLY_EDITED`, `FRAGMENT_EDITED`, `FRAGMENT_DUPLICATE`, `FRAGMENT_MALFORMED`,
`HOST_ENTRY_UNREADABLE`, `NOT_INTERACTIVE`, `ABORTED`, `PASSPHRASE_MISMATCH`,
`PASSPHRASE_WRONG`, `PASSPHRASE_TOO_SHORT`, `ALREADY_INITIALIZED`, `TRUST_PARTIAL`,
`NOT_AUTHORIZED`, `LOCKED`, `IO_ERROR`; status-only: `FRAGMENT_UNREADABLE` (host entry file not UTF-8
or cannot be opened), `TOOLKIT_FILES_CHANGED`,
`LAYOUT_MISSING`, `TRUST_INVALID`; knowledge: `PROJECT_NOT_INITIALIZED`, `ARGUMENT_INVALID`,
`BATCH_INVALID`, `ITEM_INVALID`, `IDENTITY_INVALID`, `IDENTITY_COLLISION`, `DUPLICATE_IN_BATCH`,
`ITEM_TOO_LARGE`, `EXPECTED_COUNT_MISMATCH`, `UNKNOWN_ACCEPT`, `RULE_NOT_FOUND`, `RULE_INCONSISTENT`,
`STATE_CONFLICT`, `NEEDS_DECISION`, `INDEX_NOT_UPDATED`, `RULE_DEACTIVATED`, `IDENTITY_RESERVED`;
knowledge exits: `ACTION_INVALID`, `REASON_REQUIRED`, `REASON_INVALID`, `IMPACT_DIGEST_REQUIRED`,
`ACTION_NOT_APPLICABLE`, `RENAME_TARGET_INVALID`, `RENAME_TARGET_EXISTS`, `RULE_FOLDER_UNREADABLE`,
`STALE_IMPACT`, `INDEX_INVALID`, `EXIT_JOURNAL_INVALID`, `EXIT_MEMORY_INVALID`,
`EXIT_TRANSITION_INVALID`; policy/scope: `REQUEST_INVALID`,
`MAINTENANCE_NEEDED`, `DECISIONS_INVALID`, `CONFIRMATION_REQUIRED`, `STALE_CONFIRMATION`,
`DECISION_MISSING`, `NOT_ADOPTABLE`, `NOTHING_ADOPTED`, `SCOPE_NOT_FOUND`, `SCOPE_INVALID`; guard:
`TARGETS_REQUIRED`, `WHOLE_PROJECT_NOT_EXPLICIT`, `TARGET_INVALID`, `ROLE_CONFLICT`, `SCOPE_PARTIAL`,
`RUN_NOT_FOUND`, `RUN_INVALID`, `RUN_FINISHED`, `PLAN_REQUIRED`, `PLAN_EXISTS`, `PLAN_INVALID`,
`PLAN_INCOMPLETE`, `RECORD_INVALID`, `NA_NOT_OBJECTIVE`, `EVIDENCE_QUOTA`, `REVIEW_INVALID`,
`REVIEW_AUTHORITY`, `NOT_CONCLUDED`, `NOT_ACCEPTABLE`, `FINDING_NOT_FOUND`, `INTERACTIVE_REQUIRED`,
`CONFIRMATION_MISMATCH`; tools/Adapters: `TOOL_UNKNOWN`, `TOOL_PATH_INVALID`, `TOOL_DIGEST_UNKNOWN`,
`TOOL_PLATFORM_MISMATCH`, `TOOL_NOT_REGISTERED`, `TOOL_RECORD_INVALID`, `TOOL_DIGEST_MISMATCH`,
`ADAPTER_PLATFORM_UNSUPPORTED`, `TOOL_REQUEST_INVALID`, `METHOD_NOT_PLANNED`, `METHOD_NOT_SELECTED`,
`RULE_FILE_SHARED`, `RULE_FILE_INVALID`, `RULE_ID_DUPLICATE`, `RULE_ID_AMBIGUOUS`, `TARGETS_MISMATCH`,
`STAGE_TOO_LARGE`, `STAGE_UNSAFE`, `STAGING_LEFTOVER`, `EVIDENCE_QUOTA`, `ORIGINALS_CHANGED`, `ID_COLLISION`;
Trivy: `IMAGE_ARCHIVE_INVALID`, `IMAGE_ARCHIVE_TOO_LARGE`, `TRIVY_COMPONENT_MISSING`, `TRIVY_COMPONENT_UNREADABLE`,
`TRIVY_CACHE_BUSY`, `TRIVY_KNOWN_HOSTS_UNKNOWN`, `PROVISION_REQUEST_INVALID`, `STAGE_NO_SPACE`, `STAGING_UNEXPECTED`,
`EGRESS_NOT_AUTHORIZED` (provisioning without grants); copilot:
`SCOPE_REQUIRED`, `ARTIFACTS_REQUIRED`, `WHOLE_PROJECT_REFUSED`, `MANIFEST_TOO_LARGE`, `COLLAB_NOT_FOUND`,
`COLLAB_INVALID`, `COLLAB_CLOSED`, `SUGGESTION_INVALID`, `REPORT_CONFLICT` (and the shared `REQUEST_INVALID`,
`TARGET_INVALID`, `ROLE_CONFLICT`, `REVIEW_INVALID`, `REVIEW_AUTHORITY`, `MAINTENANCE_NEEDED`, `SCOPE_PARTIAL`,
`SCOPE_NOT_FOUND`, `PATH_UNSAFE`, `LOCKED`, `IO_ERROR`).

## Host integration carriers (FEATURE-003-B)

- `carriers` problem codes: `CARRIER_UNSUPPORTED` (unknown kind or not supported for the environment;
  `data.supported_carriers`), `ARGUMENT_INVALID`, `LOCKED` (project lock still held after the
  10-second bounded wait), `LOCK_UNAVAILABLE` (no file-free lock on this platform or file system,
  including Windows: interim refusal, open gap B11; no lock file, nothing written),
  `PROJECT_NOT_INITIALIZED`, `RECORD_INVALID`, `ENV_MISMATCH` (record of another environment),
  `SKILLS_INVALID` / `ROUTING_DEFINITION_INVALID` (next step `secure-code init`; no implicit
  reinstall), `PATH_UNSAFE`, `FRAGMENT_DUPLICATE`, `FRAGMENT_MALFORMED`, `HOST_ENTRY_UNREADABLE`,
  `CARRIER_UNREADABLE`, `DECISION_NOT_APPLICABLE` (accept without a reported difference), `IO_ERROR`
  (`data.written_before_failure`; the install record is not updated); informational on success:
  `FRAGMENT_EDITED`, `FRONT_MATTER_DRIFT`.
- `init` additions (exception and contention paths only): `LOCKED` after the bounded wait where the
  project lock is available; `ROUTING_DEFINITION_INVALID` for a toolkit source whose routing
  definition is present but invalid (refused before any write); for an exactly matching accepted
  host-entry customization `data.fragment` is `customized` with `data.fragment_note`, plus
  `CUSTOMIZATION_ROUTING_CHANGED` and a `carriers` next step when the routing identity changed since
  acceptance; an explicit `--replace <host entry file>` over an accepted customization adds
  `data.replaced_customization` (statement and secret-masked difference) and lapses the acceptance.
  A toolkit source without a routing definition (FEATURE-001-A era) renders the FEATURE-001-A
  fragment unchanged.
- `status`: `host_integration` keeps its fields and adds `routing_identity`, per-carrier `carriers`
  entries (`fragment`: present / absent / missing file / modified / customized / no longer managed /
  malformed / unreadable; `identity`, `front_matter`, `user_content`, `host_effect: not verified`,
  `next_step`), `integration_declaration`, secret-masked `differences` and `record_compatibility`.
- Install record: the optional `carriers` member is omitted while no optional carrier or
  customization is recorded. Toolkit versions before the carriers operation cannot read a record
  that holds the `carriers` member and refuse it with `RECORD_INVALID`; there is no forward
  compatibility.

## Exiting Knowledge

`exit-preview` data (impact first): `impact`, `action`, `rule`, `target`, `reason`, `rule_state`,
`will`, `impact_digest`, `references_block: false`, and `recovered_exit` when an earlier exit was
completed first.

- `impact`: `relations` (`items: [{source, self}]`, `pointing_to_target`, `unreadable_sources`),
  `scopes` (`items: [{scope_id, created_at}]`, `unreadable`), `guard_runs`
  (`[{verification_id, state_digest}]`, `unreadable`), `copilot_collaborations`
  (`[{collaboration_id, state_digest}]`, `unreadable`), `pending_decisions`
  (`[{rule, held_at, sha256}]`), `document_index` (`[{document, edge, sha256}]`, `unreadable`);
  `presets` / `tags` (`items: [{name, file_digest}]` of the Presets/tags referencing the rule,
  `unreadable: [{file, detail, content_digest?}]`, FEATURE-001-F); each with `count` (empty lists
  print `(none)`). `reference_cache`: "not checked in this version". Links inside these folders
  are listed as unreadable, never followed.
- `rule_state`: `consistent`, `state`, `revision`, `state_digest`, `fingerprint`,
  `special_entries` (FIFO/socket/device entries of an inconsistent rule, never opened),
  `pending_commit`.
- `impact_digest` binds the action, rule, target, reason, rule state and every provider; any
  change refuses the confirmation with `STALE_IMPACT` (data: the new `impact`, no digest).

`exit-confirm` data: `outcome` (`deactivated`/`reactivated`/`deleted`/`renamed`), `rule`,
`target`, `exit_id`, `lifecycle_revision`, `state_digest` (null for delete), `removed_pending`,
`invalidated_index`, `tombstone` (delete), `impact` (as committed).

`links` data: `broken_relations` (`source`, `source_state`, `target`, `reason`, `renamed_to`?),
`scopes` (`scope_id`, `rule`, `reason`, `renamed_to`?), `unreadable_sources`, `unreadable_scopes`,
`counts`. Only when Preset or tag files exist (FEATURE-001-F): `preset_tag_links` (`presets` and `tags`:
`owner`, `name`, `target`, `reason`, `renamed_to`?; `unreadable: [{kind, file, detail}]`; `counts`),
appended last; without Preset/tag files the output is unchanged.

| Code | When | Next step |
|---|---|---|
| `NOT_AUTHORIZED` | preview or confirm without a valid Maintainer authorization (re-checked before the commit) | the authorization step |
| `ACTION_INVALID` / `ARGUMENT_INVALID` | unknown action; `--to` without rename or missing for rename | fix the arguments |
| `REASON_REQUIRED` / `REASON_INVALID` | no or blank reason; over 1000 characters or control characters | give a one-line reason |
| `IMPACT_DIGEST_REQUIRED` | confirm without a `sha256:` digest | preview and show the impact |
| `RULE_NOT_FOUND` | no rule folder (exited identities add `data.exited`) | preview an existing rule |
| `RULE_INCONSISTENT` | deactivate/reactivate/rename of an inconsistent or unreadable rule | restore the files or delete the rule |
| `RULE_FOLDER_UNREADABLE` | delete while a file or subfolder of the rule cannot be read | fix the permissions, preview again |
| `ACTION_NOT_APPLICABLE` | deactivate a deactivated rule; reactivate an active rule | preview the action matching the state |
| `RENAME_TARGET_INVALID`, `IDENTITY_INVALID`, `IDENTITY_RESERVED`, `IDENTITY_COLLISION`, `RENAME_TARGET_EXISTS` | other namespace/version or same ID; invalid ID; exited identity (ignoring case); case-only clash; target folder or pending decision exists | choose another ID |
| `STALE_IMPACT` | the impact changed, or the digest is of another rule/action/reason/target | preview again and show the new impact |
| `INDEX_INVALID` | confirm (not reactivate) while the document index is malformed | restore or remove the index, preview again |
| `EXIT_JOURNAL_INVALID` | a left-over exit journal fails validation (every knowledge/Policy command) | a Maintainer inspects `.x-ipe/private/secure-code/exits/journal.json`; no knowledge was changed |
| `EXIT_MEMORY_INVALID` | exit memory unreadable on a write path (reads degrade with notice `EXIT_MEMORY_UNREADABLE`) | restore or inspect the memory file |
| `PATH_UNSAFE` | a symbolic link or wrong kind on a used path | replace it with a real folder/file |
| `LOCKED` / `IO_ERROR` | lock not obtained / OS error (also different devices before the commit) | retry / re-run any knowledge command, which completes the exit |

## Authorization model

- Trust folder: per-OS user configuration folder resolved from the OS account database (POSIX)
  or the RoamingAppData Known Folder (Windows); environment variables are ignored.
- Ed25519 signatures; the signing key is stored as passphrase-encrypted PKCS#8.
- `trust-state.json` (signed) is the commit point; it names the current authorization and its
  generation. Restoring an older authorization file never passes verification.
- Limit: local workflow-level protection only; someone with write access to the owner account
  can replace the whole trust configuration. A first initialization on a machine that has never
  been initialized cannot be prevented from an agent that controls a pseudo-terminal, but it is
  visible in status (`created_at`, `created_by`).

## Library use (later features)

```python
from x_ipe_secure_code.auth.service import require_maintainer

decision = require_maintainer(action="knowledge.import")  # verifies again on every call
if not decision.allowed:
    result = decision.to_result()  # NOT_AUTHORIZED with the next step
```
