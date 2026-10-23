# Technical Design: Copilot In-flow Suggestions & Adoption Review

> Feature ID: FEATURE-003-A | Version: v1.0 | Last Updated: 10-21-2026
> Specification: [specification.md](x-ipe-docs/requirements/EPIC-003/FEATURE-003-A/specification.md) (`e8ea2f75…`) · Task: TASK-043 (refinement), TASK-044 (design)

## Version History

| Version | Date | Description |
| --- | --- | --- |
| v1.0 | 10-21-2026 | Initial design |

## Part 1: Agent-Facing Summary

### Scope & Boundaries

**In scope.** All 42 ACs of the specification:
- the `secure-code copilot` command group (open, artifacts, suggest, review, report, show, close);
- the Copilot collaboration state;
- per-file manifests;
- the shared Reviewer-record envelope (extracted from Guard and reused);
- adoption-state computation, the attention list and gaps;
- immutable numbered report rounds;
- the Copilot SKILL.md procedure and `references/copilot-records.md`.

**Out of scope** (specification "Out of Scope"):
- the requirement-analysis stage (C-03);
- budget and cancel for Copilot;
- host carriers (FEATURE-003-B);
- automatic cleanup;
- Lessons (FEATURE-004-A);
- Reference knowledge and Presets.

**Program type:** cli + library + skills. **Tech stack:** Python ≥ 3.11 (uv-managed `x_ipe_secure_code` namespace, standard library only), pytest, ruff; SKILL.md Markdown.

### Outcome / Goal Frame

| Goal | Parent / Source | Contribution of this design | Planned evidence | Outcome state |
| --- | --- | --- | --- | --- |
| G-01 | EPIC-001 G-01; FR-13, FR-02, FR-22, AC-11 | The script makes adoption verifiable rather than claimed: suggestions are bound to files and Policies, Reviewer results to digests, and states and attention are computed deterministically. The skill gives the agent the in-flow procedure | Integration tests per AC; black-box CLI acceptance on the marathon sample | not measured |
| G-01 (enabling) | FR-01 (O-04, O-05), I-08…I-10 | The script writes only the private folder and reports; skill boundaries | Byte-identity integration test; skill phrase checks | not measured |

### Design Options and Tradeoffs

| Decision | Selected | Rejected / deferred | Reason |
| --- | --- | --- | --- |
| Responsibility split | Agent suggests and reviews; script validates, binds and renders (user decision) | Skill-only | Only a script can bind digests and detect staleness deterministically |
| Reviewer-record reuse | Extract the envelope validation (invocation, requirement, reviewed digests, time, authority refusal) from `guard/records.validate_review` into `x_ipe_secure_code/reviewer.py`; Guard and Copilot add their own subject validation | Copying the code; one validator with a subject-type switch inside Guard | DRY without making Guard depend on Copilot; Guard behavior unchanged (its tests are the regression) |
| Folder artifacts | Per-file manifest at open/update (walk shared with Guard's tree digest) | Tree digest only | Per-suggestion staleness needs per-file digests (spec AC-003A-03a) |
| Round creation | Publish only when the *state signature* (digest of the round-independent structured content) differs from the latest round's | Publish on every request | Spec AC-003A-05f; makes "no change → same pair" exact and testable |
| Round commit point | Structured JSON created exclusively by a Copilot publisher (temp file + `os.link`, the Guard pattern; Guard's `create_result_exclusive` is not reused because it is bound to verification IDs). The state entry, written after both files exist and match, is the commit point; residue is reconciled under the lock before any change; files are never replaced | JSON file as commit point; Markdown first | Readers never see a half round; contiguous immutable rounds even after crashes (NFR-003A-3) |
| Locking | One project-wide `locks/copilot.lock` (`ProcessLock`) around every mutating command and report | Per-collaboration locks | KISS; Copilot commands are short; same pattern as Guard |
| Shared helpers | Import `guard.model.Checker`, `guard.mask.mask_text`, `guard.targets` path helpers and `policy.service.load_adopted` | Moving them to a neutral package now | Avoids a broad refactor; the import direction stays copilot → guard/policy (no cycle) |
| Policy-now check | Move Guard's `_policy_now` body to `policy/service.adoption_now()` and call it from both | Duplicate | DRY; Guard keeps a thin wrapper |
| Manifest size | At most 5000 files per collaboration; larger folders refused with a "name narrower artifacts" next step | Unlimited | Bounded state and report; C-02 favours change-focused scope |

### Key Components Implemented

| Component | Tags | Responsibility | Spec link |
| --- | --- | --- | --- |
| `reviewer.py` (new, shared) | shared, validation | `envelope(ck, doc, allow_absent)`: authority-key refusal, invocation, requirement, reviewed digests (`sha256:` or, when allowed, `absent`), reviewed_at, completeness warnings | FR-003A-3; FR-002A-4 |
| `copilot/model.py` | data | Schemas, IDs (`cp-YYYYMMDDTHHMMSSZ-<8 hex>`), enums, limits, paths, `CopilotError` alias of `GuardError` | all |
| `copilot/manifest.py` | data, fs | Artifact parsing, per-file manifest, updates, current digests | 03a, 03c, 03i |
| `copilot/records.py` | validation | Open/suggest/review request validation; masking with masked-field labels | 03b…03g, 04a…04d, 04f |
| `copilot/engine.py` | algorithm | Per-suggestion state, attention/gaps, Reviewer validity, state signature, structured result | 01a…01d, 02d, 04e…04i, 05a, 05c, 05e, 05g |
| `copilot/report.py` | render | Markdown from the structured result, footer digest | 05a…05d, 05g |
| `copilot/service.py` | command | open, artifacts, suggest, review, report, show, close under the lock; state files | FR-003A-1…6 |
| `cli.py` | cli | `secure-code copilot …` subcommands | UI/UX |
| Copilot `SKILL.md`, `references/copilot-records.md` | skill | Agent procedure and request formats | 01e, 03h, 04j, 06b, 06c |

### Dependencies

| Dependency | Use | Link |
| --- | --- | --- |
| FEATURE-001-C | `load_adopted` (status, entries, confirmed digests) | [spec](x-ipe-docs/requirements/EPIC-001/FEATURE-001-C/specification.md) |
| FEATURE-002-A | Reviewer envelope, `Checker`, masking, path rules, exclusive publish and footer pattern | [design](x-ipe-docs/requirements/EPIC-002/FEATURE-002-A/technical-design.md) |
| FEATURE-001-A | `knowledge_root`, result envelope (`Result`), atomic writes, `ProcessLock`, layout | — |

### Major Flow

1. **Open.** The agent writes `copilot-open/v1` → `secure-code copilot open`. The adopted scope must be complete; the manifest is recorded and a collaboration ID returned.
2. **Suggest.** The agent writes `copilot-suggest/v1` (a batch) → `copilot suggest`. It is validated against the scope and manifest, masked and stored.
3. **Executor works.** The current task executor applies the suggestions; Copilot writes nothing.
4. **Review.** The agent calls one read-only Reviewer per batch through the host, writes a `reviewer-record/v1` with `adoption` subjects → `copilot review`.
5. **Report.** `copilot report` computes states and publishes round `r<n>` if the state changed; the agent hands the attention list and gaps to the upstream caller.
6. **Later changes.** `copilot show` lists stale suggestions; steps 4–5 run for those only. New files are added with `copilot artifacts`.
7. **Close.** `copilot close` publishes a final round if needed and closes the collaboration.

### Usage Example

```bash
SC="uvx --from .github/skills/x-ipe-secure-code-toolkit-framework/scripts secure-code"
$SC copilot open --project . --request .x-ipe/private/secure-code/tmp/open.json --json
$SC copilot suggest --project . --id cp-20261021T101500Z-1a2b3c4d --request .x-ipe/private/secure-code/tmp/s1.json
# … executor edits src/register.py …
$SC copilot review --project . --id cp-20261021T101500Z-1a2b3c4d --request .x-ipe/private/secure-code/tmp/r1.json
$SC copilot report --project . --id cp-20261021T101500Z-1a2b3c4d --json   # → reports/copilot/cp-…-r1.{json,md}
$SC copilot show   --project . --id cp-20261021T101500Z-1a2b3c4d          # stale suggestions after edits
$SC copilot close  --project . --id cp-20261021T101500Z-1a2b3c4d
```

### Tool Capability Summary

| Tool | Enabled (`stages.implement.technical_design`) | Matched | Use |
| --- | --- | --- | --- |
| x-ipe-tool-implementation-python | true | yes (Python CLI/library) | Consulted for practices (type hints, pytest, ruff); informational only |
| x-ipe-tool-implementation-general | true | fallback, not needed | — |
| html5, typescript, java, mcp | true | no (no such stack) | — |

## Part 2: Implementation Guide

### Files and Layout

```
ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/
  reviewer.py              # new shared envelope (~110 lines)
  copilot/__init__.py
  copilot/model.py         # ~110
  copilot/manifest.py      # ~200
  copilot/records.py       # ~260
  copilot/engine.py        # ~260
  copilot/report.py        # ~230
  copilot/service.py       # ~420
  guard/records.py         # validate_review uses reviewer.envelope (behaviour unchanged)
  guard/targets.py         # _tree split: _walk() yields entries; tree_files() for manifests
  guard/service.py         # _policy_now → policy.service.adoption_now
  policy/service.py        # + adoption_now()
  cli.py                   # + copilot subcommands
tests/copilot/{test_copilot_open,test_copilot_suggest,test_copilot_review,test_copilot_report,
               test_copilot_skill,test_copilot_units}.py
tests/test_reviewer_envelope.py
ai-secure-code-toolkit/x-ipe-secure-code-toolkit-copilot/SKILL.md (rewrite), references/copilot-records.md (new)
ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/references/cli-contract.md (+ copilot rows), README.md
```

All modules stay below 800 lines (enforced by `tests/test_module_size.py`).

### Storage

- **Private state:** `.x-ipe/private/secure-code/copilot/<cid>/state.json` (`copilot-collab/v1`, owner-only, atomic replace, `revision` incremented per write). Paths are checked with `store.ensure_safe`.
- **Reports:** `x-ipe-docs/secure-code/reports/copilot/<cid>-r<n>.json` (`copilot-result/v1`) and `.md`.
- **Lock:** `.x-ipe/private/secure-code/locks/copilot.lock`.
- **Path safety** (`copilot/model.py` helpers, like Guard's `run_dir`/`_report_path`/`_locked`): `store.ensure_safe` is called on the lock path, `copilot/`, the collaboration folder and `state.json`, and on `reports/copilot/` plus each final `.json`/`.md` path, before any `mkdir`, temp-file creation, `os.link` or replace. Temp files are created only inside an already-checked folder. Any symbolic link component refuses the command (`PATH_UNSAFE`, mapped by `_call`) with nothing written outside. Tests replace the reports folder, the private `copilot/` folder and the locks folder with links to an outside folder and assert refusal and an untouched outside folder.

```json
{"schema": "ai-secure-code-toolkit/copilot-collab/v1", "collaboration_id": "cp-…", "status": "open|closed",
 "opened_at": "…Z", "closed_at": null, "revision": 3, "stage": "implementation",
 "task": "…(masked)", "masked": ["task"],
 "scope": {"scope_id": "sha256:…", "mode": "…", "adopted": [{"rule": "CWE/4.14/CWE-89", "state_digest": "sha256:…"}]},
 "artifacts": [{"path": "src/app.py", "kind": "file", "change": "modified", "old_path": null, "recorded_at": "…Z"}],
 "manifest": {"src/app.py": {"digest": "sha256:…", "change": "modified", "old_path": null, "source": "src/app.py", "recorded_at": "…Z"},
              "src/old.py": {"digest": null, "change": "deleted", …}},
 "context": [{"path": "README.md"}],
 "suggestions": [{"id": "S1", "rule": "…", "files": ["src/app.py"], "location": "…", "action": "…", "reason": "…",
                  "severity": "high", "stage": "implementation", "masked": ["action"], "batch": 1, "recorded_at": "…Z"}],
 "reviews": [{"seq": 1, "invocation": {…}, "requirement": "…", "reviewed": [{"path": "src/app.py", "digest": "sha256:…|absent"}],
              "reviewed_at": "…", "subjects": [{"type": "adoption", "id": "S1", "result": "adopted", "basis": "…"}], "masked": ["requirement", "subjects[0].basis"],
              "completeness": [], "wrong_version": ["src/app.py"], "recorded_at": "…Z"}],
 "invalidated_rules": {"CWE/4.14/CWE-89": {"detected_at": "…Z", "now": "changed"}},
 "rounds": [{"n": 1, "signature": "sha256:…", "published_at": "…Z"}]}
```

### Request Formats (documented in `references/copilot-records.md`)

- **`copilot-open/v1`:** `{scope_id, stage, task, artifacts:[{path, change?, old_path?}], context?:[{path}]}`.
  - `stage` ∈ design, implementation, bug_fix, refactor.
  - `change` ∈ `guard.model.CHANGES` (default `unspecified`).
  - A folder may only be `added`, `modified` or `unspecified`.
  - `.` (the whole project) is refused with `WHOLE_PROJECT_REFUSED`.
  - Paths follow `targets.normalize`/`kind_of` (no links, inside the project, not private data).
- **`copilot-artifacts/v1`:** `{artifacts:[…same entries…]}` for an open collaboration.
- **`copilot-suggest/v1`:** `{suggestions:[{id, rule, files:[path], location, action, reason, severity?, stage?}]}`.
  - `severity` ∈ `SEVERITY_VALUES`, default `unknown`.
  - `stage` defaults to the collaboration stage.
- **`reviewer-record/v1`:** the shared envelope with subjects `[{type:"adoption", id:"S1", result, basis}]`; this canonical shape is stored, evaluated, rendered and documented unchanged.
  - `reviewed_targets[].digest` may be `absent`.
  - `attempt` and `usage` are refused for Copilot (`REVIEW_INVALID`).

### Shared Reviewer Envelope (`reviewer.py`)

```python
def envelope(ck: Checker, doc: Any, *, authority_keys: tuple[str, ...], allowed_extra: set[str], allow_absent: bool,
             require_invoked_at: bool, normalize_path: Callable[[Any, str], str]
             ) -> tuple[dict[str, Any], list[str]]:
    """Validate invocation/requirement/reviewed_targets/reviewed_at; return (envelope, warnings).
    Raises REVIEW_AUTHORITY for authority keys; unknown top-level keys refused via ck.obj."""
```

- **Authority keys are caller-specific.** Guard passes its existing `records.AUTHORITY_KEYS` tuple unchanged (same order, so the same `REVIEW_AUTHORITY` message). Copilot passes `copilot.model.AUTHORITY_KEYS` = Guard's tuple + `suggestions`, `artifacts`, `manifest`, `stage`, `scope`. Unknown other keys stay `REVIEW_INVALID` via `ck.obj`.
- **Mask labels:** `envelope` takes whatever `Checker` the caller passes. Copilot passes `copilot.records.LabellingChecker(Checker)`, whose `text()` calls `mask_text` once and appends the field path (e.g. `requirement`, `subjects[2].basis`) to `self.masked` when anything was masked. Guard passes its plain `Checker` and is unaffected.
- **Byte compatibility:** a Guard regression test (`tests/test_reviewer_envelope.py`) checks fixed vectors (valid record, each warning, unknown field, each authority key) produce exactly the pre-refactor record, warnings, codes and messages (vectors captured from the current code before the refactor).
- **Guard:** `validate_review` calls it with `allowed_extra={"attempt", "usage"}`, `allow_absent=False` and `require_invoked_at=False`, keeping its own subject loop. Its output is byte-compatible: same keys, same warning texts, no behavior change to completed FEATURE-002-A.
- **Copilot:** calls it with `allowed_extra=set()`, `allow_absent=True` and `require_invoked_at=True` (spec AC-003A-04f).
- **Warnings** (record kept, invalid): missing host or agent, read_only not true, missing invoked_at (Copilot only), missing requirement, an absent or empty reviewed_targets list, missing subjects or results.

### Manifest (`copilot/manifest.py`)

```python
MAX_MANIFEST_FILES = 5000
def parse_entries(root, raw_list, where, *, allow_empty: bool) -> list[dict]      # path/kind/change/old_path checks
def expand(root, entries, now) -> dict[str, dict]                                # path -> manifest record
def current(root, paths: Iterable[str]) -> dict[str, str | None]                 # digest or None (absent)
```

- **Files:** `targets.file_digest` → `sha256:…`.
- **Folders:** `targets.tree_files(root, rel)` returns `{rel_path: digest}` for every regular file (the same exclusions as `_tree`: `.git`, private toolkit data, reports). Links and special files inside the folder are listed in `not_bindable` and are never manifest members (the open/update result reports them).
- **Deleted file:** a manifest entry with digest `None`. **Renamed file:** the new path has its digest and `old_path`; the old path gets an entry with `change: "renamed_away"` and digest `None`.
- **Updates** (`copilot artifacts`) overwrite the manifest entries of the paths given, adding new paths. Suggestions are not touched.
- **Limits:** the total number of entries must be ≤ 5000, else `MANIFEST_TOO_LARGE`.

### Suggestions (`copilot/records.py`)

`validate_suggest(state, doc) -> list[dict]`:
- The whole batch is atomic, and each item is checked:
  - `id` matches `ITEM_ID` and is unique among existing and batch ids;
  - `rule` is in `state.scope.adopted`;
  - `files` is non-empty and every file is a manifest key;
  - `location`, `action` and `reason` are required texts (≤ `MAX_TEXT`);
  - `severity` and `stage` are valid choices.
- **Masking:** all free text is validated through `LabellingChecker`; masked field paths are stored (`task` and context in the collaboration `masked`, `location`/`action`/`reason` per suggestion, `requirement`/`basis` per review). The masked text is what is stored, put in the JSON and rendered; the JSON and Markdown show a "masked" label per affected field (AC-003A-03g). Tests cover each field separately in state, JSON and Markdown.

### Review (`copilot/records.py`)

`validate_review(root, state, doc) -> dict`:
1. `reviewer.envelope(...)`.
2. **Subjects:** `type == "adoption"`; `id` is a known suggestion and unique in the record; `result` ∈ `ADOPTION_RESULTS`; `basis` is required for every result (refused with `REVIEW_INVALID`). A missing `result` is a completeness warning. If `subjects` is absent or empty, that is a warning too.
3. **Coverage:** when `reviewed_targets` is present and non-empty, every bound file of every covered suggestion must appear in it (else `REVIEW_INVALID`, nothing stored). Every reviewed path must be a manifest key.
4. **Wrong version:** current digests of the reviewed paths are computed under the lock. Paths whose current state differs from the reviewed one (an `absent` marker matches a current `None`) go into `wrong_version`.
5. The record is appended with the next `seq`.

### State Computation (`copilot/engine.py`)

```python
STATES = ("adopted", "partial", "not_adopted", "not_applicable", "cannot_verify",
          "not_reviewed", "stale", "policy_changed")
NEEDS_ATTENTION = {"partial", "not_adopted", "cannot_verify", "not_reviewed", "stale", "policy_changed"}
HIGH_RISK = {"high", "critical", "unknown"}
def invalidated(state, policy_now) -> dict[str, dict]      # persisted invalidated_rules ∪ rules now not 'unchanged'
def evaluate(state, current_digests, policy_now) -> dict    # round-independent structured content
def signature(content: dict) -> str                          # sha256 of dumps_json(content)
```

**Per suggestion `s`, in order:**
1. If `s.rule` is in `invalidated(state, policy_now)`: state `policy_changed` (monotonic: every mutating command, `report` and `close` persist newly detected rules into `state.invalidated_rules` under the lock, and nothing ever removes them, so a Policy that changes and later returns to its old digest keeps its suggestions `policy_changed`; `show` uses the union without writing). `next_step` of the result: "Re-confirm the scope with the Framework skill (secure-code policy resolve, scope save) and open a new collaboration".
2. Otherwise, take the record `r` = the latest review by `seq` that contains `s` and is **valid for `s`**:
   - `r.completeness` is empty;
   - the subject has a result;
   - none of `s.files` is in `r.wrong_version`.
3. If no such record exists: state `not_reviewed`.
4. If some file `f` in `s.files` has a current state that differs from `r.reviewed[f]`: state `stale`, with `changed` listing `{path, change: modified|deleted|renamed_away}`.
5. Otherwise the state is `r`'s result, with its basis and the review `seq`.
6. **History:** every valid result for `s` (seq, result, basis) that is not the current state is kept in `history`, including the latest one when `stale` or `policy_changed` displaced it.

**Attention and gaps:**
- **Attention:** suggestions with `state ∈ NEEDS_ATTENTION` and `severity ∈ HIGH_RISK`, sorted by severity rank (critical, high, unknown), then id.
- **Gaps:** the other suggestions in `NEEDS_ATTENTION`.
- **Re-review list** (for `show` and the report): the suggestions with state `stale` or `not_reviewed`.

**Review validity listing:** for each record, the result shows `valid` (complete), its `reasons` (completeness warnings plus wrong-version paths) and, per covered suggestion, whether it counted.

**Structured result content** (`copilot-result/v1`, without round fields):
- collaboration identity, stage, task, `opened_at`;
- scope (id, rules, digests, `policy_now`);
- artifacts and manifest with recorded and current digests;
- suggestions with state, basis, changed, history and masked;
- attention, gaps and re-review lists;
- reviews with validity;
- `boundaries`: fixed statements (not a pass or approval; review not a correctness guarantee; does not replace Guard; for `design`, "adoption in the design does not show implementation");
- `retention`: `{"reports": "kept until the user removes them", "private_data": "kept until the user removes it; no automatic expiry"}`;
- `snapshot_before_review`: true when no valid record exists.

The result contains no pass, approved or verdict key (AC-003A-05e). The signature covers exactly this content.

**Round fields** (added at publication, outside the signature): `collaboration_id` is part of the content; added are `round`, `supersedes` (`r<n-1>` or null), `published_at`, `private_data_present_as_of_publication: true` and `state_signature` (the signature of the content, for validation and no-change comparison).

### Commands (`copilot/service.py`)

Every command uses `_call` (the Guard pattern: `knowledge_root`, error mapping to a refused `Result` with one next step) and holds the copilot lock for its whole body.

| Command | Behaviour | Refusals (code → next step) |
| --- | --- | --- |
| `copilot open --request F` | Load the request (`copilot-open/v1`). Scope checks run **before** any allocation (nothing is created on refusal): see Scope Refusal Mapping below. Then parse the artifacts, build the manifest, allocate the ID (`mkdir` exclusive under the checked `copilot/` parent, as `runs.allocate`) and write the state | `REQUEST_INVALID`, `TARGET_INVALID`, `WHOLE_PROJECT_REFUSED`, `MANIFEST_TOO_LARGE`, `NOT_INITIALIZED`, scope codes below |
| `copilot artifacts --id C --request F` | The collaboration must be open; merge entries; write the state | `COLLAB_CLOSED`, `COLLAB_NOT_FOUND` |
| `copilot suggest --id C --request F` | Open; `validate_suggest`; append; write | `SUGGESTION_INVALID` |
| `copilot review --id C --request F` | Open; `validate_review`; append; write; returns the record's warnings and wrong-version paths | `REVIEW_INVALID`, `REVIEW_AUTHORITY` |
| `copilot report --id C` | Allowed when open or closed: reconcile (below), persist newly invalidated rules, compute → `signature`. If it equals the last round's signature, return that round. Otherwise publish round n+1 (Publication Protocol) | `COLLAB_NOT_FOUND` |
| `copilot show --id C` | Read-only: compute without publishing (no state write); also returns `reports` with existence flags, `private_data_present`, `latest_round` | — |
| `copilot close --id C` | Open: run the report step, then set `status=closed` and `closed_at`; returns the latest pair | — |

**Scope Refusal Mapping** (`copilot open`; data always carries `adopted`, `needs_reconfirmation`, `missing` rule groups when a scope was loaded):

| Case | Code | Next step |
| --- | --- | --- |
| `scope_id` absent from the request | `SCOPE_REQUIRED` | "Resolve, select and confirm Policies with the Framework skill (secure-code policy resolve, then secure-code scope save), then pass its scope_id" |
| `load_adopted` refused (unknown or unreadable scope) | its own code (e.g. `SCOPE_NOT_FOUND`) | the same select-and-confirm step |
| loaded, status `maintenance_needed` | `MAINTENANCE_NEEDED` | "Knowledge maintenance is needed: an authorized Maintainer imports or fixes Local rules with the Framework skill, then a scope is confirmed" |
| loaded, status `partial` | `SCOPE_PARTIAL` | "Re-propose and confirm a new scope (secure-code policy resolve, scope save), then open again" |

Tests assert, for each case, the code, the single next step, the groups and that no `copilot/` folder entry was created.

**Publication Protocol (one round).** The commit point is the atomic state write that appends the round to `state.rounds`; it happens only after both files exist and match. Readers (`report`, `show`, `close`, the latest-round lookup) count only rounds listed in `state.rounds`. Files of an uncommitted round are residue.
1. Under the lock, compute `content` (the round-independent structured content above) and `state_signature = "sha256:" + sha256(dumps_json(content))`. Build the result = `content` + `{collaboration_id, round: n, supersedes: "r<n-1>" | null, published_at, private_data_present_as_of_publication: true, state_signature}`.
2. Both final paths `<cid>-r<n>.json` and `<cid>-r<n>.md` must be absent (after `ensure_safe`); otherwise `REPORT_CONFLICT`. Nothing is ever replaced.
3. Create the JSON exclusively (temp file in the checked folder + `os.link`), then the Markdown exclusively the same way, with a footer digest of the JSON bytes; fsync the folder.
4. Append `{n, signature: state_signature, published_at}` to `state.rounds` and write the state atomically: the round is now published.

**Reconcile** runs first in every command that holds the lock (`artifacts`, `suggest`, `review`, `report`, `close`). `show` never writes and simply ignores residue.
- Only k = len(rounds)+1 can hold residue (rounds are published one at a time under the lock).
- If neither file exists: nothing to do.
- If `<cid>-r<k>.json` exists, it must parse as `copilot-result/v1` with the same `collaboration_id`, `round == k`, the expected `supersedes`, and a `state_signature` equal to the recomputed signature of its own round-independent content. Then:
  - if the Markdown is absent, create it exclusively from the JSON;
  - if the Markdown is present, its footer must match the JSON digest;
  - then commit as step 4 with the file's signature, *whatever the current state*.
- Any other combination (invalid JSON, Markdown without JSON, mismatched footer) refuses with `REPORT_CONFLICT` and a next step to move the named files away manually. Nothing is overwritten.
- Tests crash (monkeypatched exceptions) after the JSON link, after the Markdown link and before the state write, then run a mutating command. They assert contiguous rounds, unchanged earlier files, correct Markdown, `show` ignoring residue, and `REPORT_CONFLICT` for a planted foreign `r<k>.md` or a tampered JSON.

### Result and Report (`copilot/report.py`)

Markdown sections, in order:
1. title `# Copilot Adoption Report <cid> — round n`;
2. Attention (table: id, severity, state, rule, files, reason/basis), with the Policy next step when any is `policy_changed`;
3. Gaps;
4. Collaboration (ID, round, stage, task, opened time, scope ID, snapshot-before-review note when applicable);
5. Suggestions (all, with state, basis, changed files, history, masked labels);
6. Re-review needed;
7. Artifacts (path, change, recorded and current digest);
8. Adopted Policies (`policy_now`, invalidated rules);
9. Reviewer records with validity: a summary row per record (validity, reasons, declared invocation host/agent/read-only/time, reviewed and recorded times, requirement, counted and not counted suggestions, masked labels), then per record its reviewed targets (path with the digest seen or `absent`) and its subjects (suggestion id, type, result, basis, masked labels) (TASK-048);
10. Boundaries (fixed statements, incl. the design-stage statement);
11. Retention (with "as of publication <time>");
12. Supersedes.

Tests compare the Markdown with the JSON field by field (each suggestion's id, state, severity and basis; attention and gap ids; stage, task, scope ID; every Reviewer-record field), not only by snapshot.

`md_text` escaping is reused from `guard/report.py`. The footer is `<!-- copilot-result-sha256: … -->`.

### CLI Contract (additions)

`secure-code copilot {open,artifacts,suggest,review,report,show,close}`. Each accepts `--project`, `--json`, and `--id` (except open) or `--request` where applicable. Exit code 0 means ok and non-zero means refused, as in the existing contract.

### Copilot SKILL.md and Reference

The SKILL.md is rewritten from the skeleton. It keeps the frontmatter name and description (FEATURE-001-A placement tests) and contains:
- **When to Use:** design, implementation, bug fix and refactor work, including design changes; not plain questions or read-only lookups (I-05).
- **Procedure:**
  1. Check status.
  2. Get the adopted scope through the Framework skill; on "maintenance needed" or scope refusals, report and stop; never invent Policies.
  3. Open with the explicitly changed artifacts; no whole project.
  4. Give concrete suggestions tied to a location and a Policy, focusing on the change and its impact.
  5. Leave all edits to the current executor; never pause or block.
  6. After the artifact is formed, call ONE read-only Reviewer per batch with only the task, the suggestions, locations and digests. The Reviewer checks the actual files, not the executor's claim, never edits, never widens the review, never starts agents and must not trigger the Copilot or Guard flow.
  7. Record the review, run report, and hand the attention list and gaps to the upstream caller.
  8. After relevant changes, use show and re-review only the stale ones; never re-review after every edit.
  9. Close.
- **Boundaries:** a decision to continue is not adoption or a pass; failed or old reports don't count for the current version; Copilot does not replace Guard.

`references/copilot-records.md` documents the request formats with examples, the states and the attention rule.

### Implementation Steps

1. Capture Guard review vectors from the current code (`tests/test_reviewer_envelope.py`), then extract `reviewer.envelope` with caller-specific authority keys; refactor Guard `validate_review` (vectors and all Guard tests green, no behavior change).
2. `targets._walk`/`tree_files`; `policy.service.adoption_now` + Guard wrapper.
3. `copilot/model.py`, `manifest.py` with unit tests (RED first).
4. `records.py` (open, suggest, review validation) with tests.
5. `engine.py` with unit tests for every state and precedence rule.
6. `report.py`, `service.py`, CLI, with integration tests per AC.
7. SKILL.md, reference, CLI contract, README; skill phrase tests.
8. Module-size test; ruff; full suites (macOS 3.14/3.11, Linux 3.12).

### Edge Cases & Error Handling

| Case | Handling |
| --- | --- |
| Unknown or invalid collaboration ID | `COLLAB_NOT_FOUND` with next step `copilot open` |
| Manifest file unreadable at report | Current digest `unreadable` → differs from the reviewed one → `stale` (honest) |
| A non-UTF-8 file name inside a folder | `display_name` escapes it; a member that cannot be stored is listed in `not_bindable` |
| Reviewed path not in manifest | `REVIEW_INVALID` |
| Suggestion binds a deleted file (recorded deleted) | Allowed; a review must give `absent` |
| Concurrent report requests | Serialized by the lock; exclusive link prevents a duplicate number |
| Report files removed by the user | `show` reports them missing; `report` does not recreate old rounds (only the latest `.md`, if its JSON exists) |
| Scope record deleted after open | `adoption_now` returns `{}` → every rule treated as `missing` → `policy_changed` |

### Security, Tracing and Observability

- No network and no execution of artifact content. Masking of all free text uses the Guard patterns (pattern-based limit stated). Ids and paths that look like credentials are refused (`Checker.pattern`, `targets.normalize`).
- State files are owner-only; report files use normal permissions (as Guard's).
- Tracing: N/A. The toolkit has no tracing infrastructure, and command results (the `--json` envelope) are the observable record. No logging of free text.

### Goal / Acceptance / Design / Validation Coverage

| AC group | Design means | Planned validation |
| --- | --- | --- |
| 01a…01d (targeted re-review) | engine per-file comparison, history, re-review list; review coverage | `test_copilot_report.py`: unrelated edit, bound edit/delete/rename, partial re-review |
| 01e, 03h, 04j, 06b, 06c (skill) | SKILL.md procedure/boundaries | `test_copilot_skill.py` phrase checks (structured) |
| 02a, 02b, 02e (scope precondition) | open: `load_adopted` status mapping | `test_copilot_open.py` with empty, partial, missing scope fixtures |
| 02c, 02d | scope in state; `adoption_now` → `policy_changed` | open + report tests (update and remove a rule) |
| 03a, 03b, 03c, 03i | manifest parse/expand/update | open and artifacts tests incl. folder manifest, whole project, link, folder delete refused |
| 03d…03g | `validate_suggest`, masking | suggest tests incl. atomic batch refusal, unknown severity, masked labels in state/JSON/MD |
| 04a…04d, 04f, 04h | `reviewer.envelope` + Copilot subjects, coverage, wrong version | review tests incl. authority keys, missing basis, missing invoked_at, wrong version |
| 04e, 04g, 04i | engine states, attention/gaps | engine unit tests (state × severity matrix) + report integration |
| 05a…05c, 05f, 06f | signature, exclusive publish, footer, repair, close | report tests: identical JSON/MD, immutability, no-change no-round, crash repair (monkeypatched), close final round |
| 05d, 05e, 05g | boundaries, no pass key, retention and show existence | report and show tests |
| 06a | write-scope discipline | integration: byte digests of artifacts before/after every command; only private/report paths changed |
| 06d | closed refusals | close tests |
| 06e | Guard accepts the Copilot report as context | integration: Guard open with `copilot_reports` → context only (existing 002-A behavior) |
| Regression | shared envelope refactor | full Guard test suite unchanged + `test_reviewer_envelope.py` |

Black-box acceptance later runs the real CLI through `uvx` on a copy of the marathon sample.

### Outcome Scenario and Evidence Gaps

On a copy of the marathon sample:
1. A registration change gets suggestions bound to `register.py` with CWE rules.
2. The executor adopts one suggestion and not another.
3. The Reviewer record yields adopted / not adopted.
4. An edit to an unrelated file keeps both results current; an edit to `register.py` makes both stale.

Planned as acceptance evidence. Real Developer use: **not measured**. Real host Reviewer invocation cannot be proven by the script (declared; honest limit).

### Test Plan

Test-first per implementation step. Risk-focused tests in addition to the coverage table:
- concurrency with processes: report vs report, report vs suggest/review (no lost update, no duplicate or skipped round);
- crash recovery with a mutation before recovery (Publication Protocol);
- Policy changed and then restored to the exact old digest stays `policy_changed`; the latest displaced result appears in history;
- every masked field separately (task, location, action, reason, requirement, basis) in state, JSON and Markdown;
- symlinked reports, private and lock folders;
- Guard byte-compatibility vectors (valid, each warning, unknown field, each authority key).

Unit tests cover the engine, manifest and envelope; integration tests call the service functions on temporary projects (fixtures from Guard tests: initialized project, adopted scope); CLI round trip for one flow. Skill phrase tests use the same structured approach as the Guard skill tests.

### Mockup-to-Component Mapping

N/A — no UI.

### Delta and Evidence Invalidation

New feature. Shared, behavior-preserving changes affect FEATURE-002-A:
- the envelope extraction;
- `_policy_now` moving to `policy/service.py`;
- the `targets._walk` split.

The Guard unit and integration suites are rerun in full, and the FEATURE-002-A black-box runner is rerun at acceptance.

## Implementation Evidence (TASK-045)

Test-first per step (RED reason recorded before each implementation; Engineering delivery evidence only — stakeholder outcome: not measured).

| Step | RED (before implementation) | GREEN |
| --- | --- | --- |
| 1 Shared envelope | `tests/test_reviewer_envelope.py`: 50 Guard vectors + key order captured from the pre-refactor `validate_review` (passed as characterization); 13 envelope tests failed with `ImportError: cannot import name 'reviewer'` | `reviewer.envelope`; Guard `validate_review` delegates with its unchanged `AUTHORITY_KEYS`; vectors and all Guard tests green |
| 2 Walk split, `adoption_now` | `tests/copilot/test_copilot_units.py`: `_tree` digest captured pre-refactor (passed); 8 failed with `AttributeError` (`tree_files`, `policy.service.adoption_now`, `guard.service.adoption_now`) | `targets._walk`/`tree_files`; `policy.service.adoption_now`; Guard `_policy_now` delegates |
| 3–4 Copilot package, CLI, AC and risk tests | 6 test modules failed at collection with `ModuleNotFoundError: No module named 'x_ipe_secure_code.copilot'`; later edge tests failed on missing Markdown repair, missing `result_exists`, `modified` instead of `unreadable` | `copilot/{model,manifest,records,engine,report,service}.py`, `cli.py` `copilot` group |
| 5 Skill and docs | `tests/copilot/test_copilot_skill.py`: 7 failed (skeleton text lacks the required instructions; `references/copilot-records.md` missing) | SKILL.md rewrite, reference, CLI contract rows, README section |

**Commands and results** (from `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts`, 10-21-2026):

| Command | Result |
| --- | --- |
| `uv run pytest -p no:cacheprovider -q` (macOS, Python 3.14.6) | 878 passed, 2 skipped (baseline before TASK-045: 661 passed, 2 skipped) |
| `UV_PROJECT_ENVIRONMENT=<session folder>/venv311 uv run --python 3.11 --group dev pytest -p no:cacheprovider -q` (Python 3.11.15; venv outside the system temporary folder) | 877 passed, 3 skipped (the third skip is the pre-existing `os.waitid` adapter test) |
| `uv run ruff check .` | All checks passed |
| `uv run pytest -p no:cacheprovider --cov=x_ipe_secure_code.copilot --cov=x_ipe_secure_code.reviewer --cov-report=term-missing tests/copilot tests/test_reviewer_envelope.py` | 217 passed; coverage 95% (engine 99%, manifest 90%, model 96%, records 94%, report 97%, service 95%, reviewer 100%) |
| `tests/test_module_size.py` | passed; largest new module `copilot/service.py` < 700 lines |
| After the code review fix (owner rerun) | macOS 3.14: 880 passed, 2 skipped; macOS 3.11: 879 passed, 3 skipped; Linux 3.12 (docker): 881 passed, 1 skipped; `ruff check` clean; copilot + reviewer coverage 95% (219 tests) |
| Independent code review (code-review agent) | 1 non-blocking finding (mask-marker link injection), fixed test-first; no other issues; Guard vectors confirmed against a pre-refactor copy |

**Files.** New: `src/x_ipe_secure_code/reviewer.py`, `src/x_ipe_secure_code/copilot/{__init__,model,manifest,records,engine,report,service}.py`, `tests/test_reviewer_envelope.py`, `tests/copilot/{cphelp,test_copilot_open,test_copilot_suggest,test_copilot_review,test_copilot_report,test_copilot_risks,test_copilot_skill,test_copilot_units}.py`, `x-ipe-secure-code-toolkit-copilot/references/copilot-records.md`. Changed: `guard/records.py` (envelope extraction), `guard/targets.py` (`_walk`, `tree_files`), `guard/service.py` (`_policy_now` wrapper), `policy/service.py` (`adoption_now`), `cli.py` (`copilot` group), `x-ipe-secure-code-toolkit-copilot/SKILL.md` (rewritten), `x-ipe-secure-code-toolkit-framework/references/cli-contract.md`, toolkit `README.md`.

**Not yet evidenced:** black-box `uvx` acceptance on the marathon sample, Linux and Windows runs, real host Reviewer invocation (declared only; honest limit).

### Bug Fix TASK-048 (closing review TASK-047) — evidence

Markdown "Reviewer Records" now renders the full Reviewer record (AC-003A-05a). Engineering delivery evidence only; stakeholder outcome: not measured.

| Step | Evidence |
| --- | --- |
| RED | `tests/copilot/test_copilot_report.py::test_05a_reviewer_records_identical_in_markdown` and `::test_05a_reviewer_record_values_shown_raw` against the unfixed `copilot/report.py` (`76ea28ca…`): 2 failed, 28 passed. The summary row lacked the reviewed/recorded times (`AssertionError` on the row), and no per-record block with reviewed targets and subjects existed (`IndexError` on `### Reviewer record 1`) |
| GREEN | Same test bytes (`368eab5a…`) against the fixed `copilot/report.py` (`660fcd06…`, 264 lines): 30 passed |
| Full suites | macOS Python 3.14.6: 882 passed, 2 skipped; macOS Python 3.11.15: 881 passed, 3 skipped; Linux Python 3.12.12 (docker): 883 passed, 1 skipped; `ruff check .` clean |
| Coverage | copilot + reviewer 95% (221 tests); `copilot/report.py` 98% |
| Acceptance rerun | Container 11/11 (391 checks, 107 Copilot commands, stderr empty); host 2/2; unit/integration 221 passed; regressions 002-A 26/26 + 2/2, 002-B 10/10 + 2/2 (fresh caches). See [acceptance-test-cases.md](acceptance-test-cases.md) |
| Runner | `acceptance/blackbox.py` assertions added for 01d, 02b, 02d, 03a, 04b, 04f, 05a, 06a, 06f; the new 05a checks fail on the pre-fix renderer output (4 checks) and pass on the fixed one |

## Design Change Log

| Date | Version | Change | Reason |
|------|---------|--------|--------|
| 10-21-2026 | v1.0 | Initial design. User decisions from refinement: agent/script split, high-risk High/Critical/unknown, per-suggestion file staleness, immutable rounds | TASK-044 |
| 10-21-2026 | v1.0 | Design review fixes (7 blocking, 1 non-blocking; re-review 2 blocking: state entry as commit point after both files exist, `state_signature` in each result and validated reconcile, both report paths created exclusively): persisted monotonic `invalidated_rules` and displaced-result history; Copilot publisher with JSON commit point and reconcile-before-mutate; caller-specific authority keys and Guard byte-compatibility vectors; canonical typed subjects; `LabellingChecker` mask labels for every free-text field; report section order per spec with field-by-field tests; `ensure_safe` on lock, private and report paths; explicit scope refusal mapping; risk-focused tests | Independent design review |
| 10-21-2026 | v1.0 | Implementation deviations (TASK-045), all ACs kept: (1) `reviewer.envelope` takes a keyword `subjects` callback and returns the whole record, so Guard's validation order (a bad subject is reported before a bad `reviewed_at`) stays byte-identical; (2) Reconcile is stricter: the JSON bytes must equal their canonical form and an existing Markdown must equal the render of the JSON (not only its footer); (3) `supersedes` holds the full round name `<cid>-r<n-1>`; (4) toolkit data (`x-ipe-docs/secure-code/…`) and `.git` paths are refused as artifacts, and a renamed file's `old_path` must no longer exist; (5) extra codes `ARTIFACTS_REQUIRED`, `COLLAB_INVALID`, `ROLE_CONFLICT` (artifact vs context); closing a closed collaboration is `COLLAB_CLOSED`; (6) a review row is `valid` only when complete and without wrong-version paths, with per-suggestion `counted`/`not_counted` reasons; `snapshot_before_review` means no valid result exists for any suggestion; stale change labels also include `unreadable`, `unsafe`, `not_a_file`; (7) Markdown shows ids, states, paths, digests and generated reasons as code spans (free text through `md_text`; mask markers stay readable); report results add `report_exists`/`result_exists`; (8) `tree_files(root, rel, limit)` returns `truncated` and lists credential-like or non-UTF-8 names as not bindable; (9) extra test module `test_copilot_risks.py` and helper `cphelp.py` | TASK-045 implementation |
| 10-21-2026 | v1.0 | Code review fix (TASK-045): mask markers in the Markdown are rendered as code spans (no inline link can form after them), and agent free text that already contains a `[masked:…]` marker is refused, so only the toolkit produces masked values; tests `test_labelling_checker_refuses_literal_mask_markers`, `test_report_mask_marker_never_forms_a_link` (RED → GREEN) | Independent code review |
| 10-22-2026 | v1.0 | Bug fix TASK-048 (closing review TASK-047): the Markdown "Reviewer Records" section renders every field of each Reviewer record, as in the structured result (AC-003A-05a): summary row adds reviewed and recorded times; per record a `### Reviewer record <seq>` block states the declared invocation and lists the reviewed targets (path, digest or `absent`) and the subjects (id, type, result, basis, masked labels). Free text through `cell`, identifiers/paths/digests through `code` (no links, no HTML). AC-003A-06a wording clarified by the user (the project-wide Copilot lock file `.x-ipe/private/secure-code/locks/copilot.lock` is Copilot private data); behaviour unchanged. No interface, schema or data change | Closing review TASK-047; user decisions |
