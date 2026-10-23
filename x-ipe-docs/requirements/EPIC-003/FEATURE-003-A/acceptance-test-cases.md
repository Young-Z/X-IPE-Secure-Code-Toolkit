# Acceptance Test Cases

> Feature: FEATURE-003-A — Copilot In-flow Suggestions & Adoption Review (EPIC-003)
> Status: Verified delivery for the approved scope. All 42 ACs pass in the black-box runs: offline Linux container (Maintainer path) and macOS host (never-authorized User path). Windows was not run.
> Revision: toolkit tree `5c3d186c…` · specification `4c647c8c…` · design `aeff9718…` · runner `7a4cd98c…` (SHA-256 prefixes; full values in Relevant Inputs). Acceptance task TASK-046; closing-review rerun Bug Fix TASK-048 (2026-10-22).

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-003-A, board status Implemented (TASK-045); acceptance task TASK-046 |
| Specification / Source | [specification.md](specification.md) (42 ACs AC-003A-01a…06f, all Integration); parent EPIC-001 FR-13, FR-02, FR-22, FR-09/FR-10; AC-01, AC-02, AC-11, AC-13…AC-15 |
| Design / Implementation | [technical-design.md](technical-design.md) Part 1 and Part 2, including the Change Log deviations (TASK-045) and Implementation Evidence; `reviewer.py`, `copilot/{model,manifest,records,engine,report,service}.py`, `cli.py` (`copilot` group), Guard `records.py`/`targets.py`/`service.py`, `policy/service.py`; Copilot `SKILL.md`, `references/copilot-records.md`, framework `references/cli-contract.md` |
| Target URL | N/A: CLI, library and skill scope (no UI, no browser needed) |
| Config / Capability | `stages.validation.acceptance_test` in `x-ipe-docs/config/tools.json` enables `x-ipe-tool-implementation-python` (`true`), used as the Python test runner capability. Black-box runner [blackbox.py](acceptance/blackbox.py) calls the real CLI only through `uvx --from <framework>/scripts secure-code …` and never imports toolkit code. Chrome DevTools is enabled but not applicable (no UI) |
| Planned Cases | 16 planned executions: black-box 13 (TC-CA-01…11 in the container; TC-CA-12 and TC-CA-11 on the host), unit/integration 1 (TC-U-01), regression 2 (TC-R-01 FEATURE-002-A, TC-R-02 FEATURE-002-B). The skill-instruction ACs (01e, 03h, 04j, 06b, 06c) are structured checks on the installed package text, run in both modes inside TC-CA-11 |

**Environment.**
- **Container (Maintainer path):** image `fat-uv-git:py312` (`8cbe78fe…`, Python 3.12.12, Linux aarch64). Offline: `--network none`, `UV_OFFLINE=1`. Disposable HOME and `FAT_ISOLATED=1`. Fresh cache volume `fat-uv-cache-ca` (removed and recreated for the TASK-048 rerun), warmed online with the current toolkit; the warm-up found `x_ipe_secure_code/copilot/report.py` containing the TASK-048 function `def _review_detail` in the cache before the offline run. The marathon sample is mounted read-only at `/samples/m`; the project path contains `ü`.
- **Host (User path):** macOS, runner on Python 3.13.3, `UV_REFRESH_PACKAGE=ai-secure-code-toolkit`, uv 0.11.23. Never-authorized User role; no trust writes.
- **Scratch folders:** to avoid writing in the workspace or the system temporary folder, the project copies were placed outside both:
  - Container runs added `-e FAT_WORK=/root/fat-work`.
  - The host run used `FAT_WORK=<session folder>/files/fat-work`.
  - The 002-A/002-B host regressions used `TMPDIR=<session folder>/files/fat-tmp`.

  Otherwise the commands are exactly those requested.

**Fixtures (disclosed).**
- **Container setup:** the Maintainer path is prepared exactly as in the FEATURE-002-A container mode:
  - `auth init` at a pseudo-terminal (owner authorization);
  - `knowledge import` of three Local rules, CWE-89, CWE-79 and CWE-312, with placeholder bodies;
  - `policy resolve` and `scope save --confirmed` (the user's confirmation flag).
- **Projects:** copies of the marathon sample under `app/` (without `data/` and `__pycache__`).
- **Executor edits:** the runner acts as the current executor with plain file writes between Copilot commands:
  - adds `export.py`;
  - deletes `tests/test_portal_contract.py`;
  - renames `tests/test_server.py` to `tests/test_http_server.py`;
  - adds a link `public/app-link.js` inside the folder artifact;
  - later edits `registration.py`, `export.py`, `app.js` and `styles.css`, deletes `server.py`, renames `export.py` → `exporter.py`, and adds `audit.py` and `public/new.js`.
- **Reviewer records:** written by the runner in the shape a host read-only Reviewer sub-agent returns. The invocation is declared, not proven (the toolkit's honest limit).
- **Policy change (02d):** a real Maintainer `knowledge update` of CWE-312 (new body). A second `knowledge update` restores the original body to show the state is permanent.
- **Maintenance needed and partial scopes (02a, 02b):** a rule adopted in a saved scope is changed with `knowledge update` (in separate projects).
- **Removed Policy (02b missing list, 02d removed; TASK-048):** the toolkit has no knowledge removal or deactivation command (CLI `knowledge` offers check, import, update, list, show). The runner therefore deletes the rule's folder under `x-ipe-docs/secure-code/knowledge/local/`, standing in for the Maintainer removing it. This is the fixture the FEATURE-001-C runner uses for removed rules (the FEATURE-002-A runner has no missing-rule fixture). Done in a separate project copy.
- **TASK-048 executor edits:** in the `bug_fix` collaboration the runner edits `app/public/app.js` and `app/public/index.html` between the reviews.
- **User removal (05g):** the runner deletes one report file and then the private collaboration folder, standing in for the user.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-01 | Spec G-01; EPIC-001 G-01; FR-13 (C-01, C-02, C-04…C-12), FR-02 (O-07, O-08), FR-22 (R-01, R-02, R-06…R-09), FR-09/FR-10 (AC-11) | Developer, upstream agent | Security measures are applied during the work and adoption is verified, not claimed | Qualitative scenario on the marathon copy (TC-CA-01…08), TC-U-01 | 01a…01e, 02a…02e, 03a…03i, 04a…04j, 05a…05g, 06a…06f | not measured |
| G-01 (enabling) | Spec; EPIC-001 FR-01 (O-04, O-05), FR-27 (I-08…I-10) | Upstream agent | The executor stays the single business writer; Reviewers gain no authority and trigger no recursion | TC-CA-10 (artifact bytes before/after each of 107 Copilot commands), TC-CA-11 | 06a…06f | not measured |

The source outcome scenario was exercised with the real CLI on a copy of the marathon sample:
1. **Specific suggestions.** A registration-export change got suggestions bound to the changed files with CWE rules imported as Local knowledge:
   - S1 CWE-89 on `registration.py`;
   - S2 CWE-79 on `app.js`;
   - S3 CWE-312 on `registration.py` and `server.py`;
   - S4 CWE-79 on `index.html`;
   - S5 CWE-89 on `export.py` (no severity, so `unknown`).
2. **Review after the executor applied some.** The Reviewer record distinguishes adopted (S1, S5), not adopted (S2), cannot verify (S3) and partial (S4), bound to the current digests.
3. **Unrelated edit.** An edit to `styles.css` and to a context file keeps all results current with no re-review.
4. **Relevant edits.** An edit to `app.js`, the deletion of `server.py` and the rename of `export.py` make only S2, S3 and S5 stale. A targeted re-review of those (plus the new S6) leaves S1 and S4 untouched.
5. **Policy change.** The CWE-312 change makes S3 and S7 `policy_changed`, permanently.
6. **Close.** Closing publishes the final round.

Real Developers or upstream agents using Copilot: **not measured**.

## Full Acceptance / Evidence Map

All rows: Source/Parent G-01; Delivery State is **verified engineering delivery** at the revision in the header; Outcome State **not measured**.

| AC ID | TC / Type | Original Assertions (as checked) | Evidence |
| --- | --- | --- | --- |
| AC-003A-01a | TC-CA-06 integration | Edit to an unbound folder member and a context file. `show` and the new round r3 keep S1…S5 results with review seq 8; `re_review` is empty and no re-review next step is given | Pass |
| AC-003A-01b | TC-CA-06 integration | Stale state for a bound file that was modified (S2), deleted (S3) or renamed away (S5, after the update). Each names the file and change (`modified`/`deleted`/`renamed_away`). r4: S2 `stale`, basis not current, history `{seq 8, not_adopted}` in JSON and Markdown ("Earlier results (history, not current adoption)"); only S1 counted adopted | Pass |
| AC-003A-01c | TC-CA-06 integration | `show` lists `re_review` = S2, S3, S5 (then S2, S3, S5, S6, S7 after new suggestions), not S1/S4; the next step names them | Pass |
| AC-003A-01d | TC-CA-06 integration | Main copy: record 9 covers S2, S3, S5 (stale) and the new S6, with `server.py` and `export.py` as `absent`; r5 shows the new results (seq 9) while S1 and S4 keep their seq-8 results. **Stale-only record (TASK-048, `bug_fix` collaboration):** after edits to `app.js` and `index.html`, `show` lists exactly B2 and B3 for re-review. Record 6 covers only B2 and B3; no new suggestion exists or is covered. r3 shows B2 `not_adopted` and B3 `adopted` from seq 6, with B2's seq-5 result as history. The unaffected B1 keeps `adopted` from seq 5 (same basis, no history), and nothing needs re-review | Pass |
| AC-003A-01e | TC-CA-11 structured (container + host) | Skill: do not re-review after every edit; after a relevant change see which suggestions are stale; send only the stale and new suggestions to the Reviewer | Pass |
| AC-003A-02a | TC-CA-09 integration | Scope whose only rule changed: `MAINTENANCE_NEEDED` with one Framework/Maintainer next step; no collaboration folder entry, no suggestion, no report | Pass |
| AC-003A-02b | TC-CA-09 integration | **Changed:** one of two rules changed → `SCOPE_PARTIAL` with `adopted` [CWE-89], `needs_reconfirmation` [CWE-79], `missing` []. **Missing (TASK-048):** in a three-rule scope, CWE-312 removed (disclosed fixture) and CWE-79 changed → `SCOPE_PARTIAL` with `adopted` [CWE-89], `needs_reconfirmation` [CWE-79], `missing` [CWE-312]. Each refusal has one next step to re-propose and confirm (`scope save`); nothing is opened and no report is written | Pass |
| AC-003A-02c | TC-CA-01 integration | Scope id and every adopted rule with the confirmed state digest from `policy resolve` recorded at open. The same id and digests appear in the JSON and Markdown of all 8 rounds | Pass |
| AC-003A-02d | TC-CA-07 integration | **Changed:** after the Maintainer's update of CWE-312, S3 and S7 are `policy_changed`; S3 history keeps `{seq 9, not_applicable}`; not counted as adoption. S3 (critical) is in attention and S7 (low) a gap. The next step (re-confirm the scope, open a new collaboration) appears in the result, Markdown and CLI. After the original body is restored, both stay `policy_changed`. **Removed (TASK-048):** P1…P3 adopted in r1; CWE-312 is then removed (disclosed fixture). r2: P1 and P3 `policy_changed`, P1 history `{seq 1, adopted}`, CWE-312 `now` = `missing` and invalidated. Adopted count is 1; P1 (critical) is in attention and P3 (low) a gap. The same next step appears in the result, Markdown and CLI | Pass |
| AC-003A-02e | TC-CA-09 integration; TC-CA-12 host | No `scope_id` → `SCOPE_REQUIRED`; unknown scope → `SCOPE_NOT_FOUND`. Both carry the resolve/select/confirm step (`scope save`) and no maintenance step, and open nothing | Pass |
| AC-003A-03a | TC-CA-01 integration | Collaboration id, stage, task, artifacts recorded with change meanings (`added`, `modified`, `deleted`, `renamed` + old path, `unspecified`, folder `modified`). The per-file manifest equals every artifact file plus every regular file of `app/public`, with SHA-256 digests. Deleted entries carry no digest; the old path is `renamed_away`; a link inside the folder is `not_bindable`. **TASK-048:** a `bug_fix` collaboration with the folder `app/public` given without a change meaning records it as `unspecified`. Its manifest equals every regular file of the folder, with digest, change `unspecified` and source `app/public`; the link is listed not bindable. Its suggestions take stage `bug_fix`. A `refactor` collaboration is recorded, and its published round states `refactor` in JSON and Markdown | Pass |
| AC-003A-03b | TC-CA-09 integration; TC-CA-12 host | `[]` and missing artifacts → `ARTIFACTS_REQUIRED`; `.` and `whole_project: true` → `WHOLE_PROJECT_REFUSED`. The next step is to name the changed artifacts ("no automatic whole-project review") | Pass |
| AC-003A-03c | TC-CA-09 integration; TC-CA-12 host | `TARGET_INVALID`, naming the path with one next step, for: a missing path; `../outside.py`; a symbolic link; a folder declared deleted; a folder declared renamed; private toolkit data. Updates refuse a deleted folder, a renamed folder and a link, and change nothing. Deleted folder files recorded individually are accepted. Nothing is opened by refusals | Pass |
| AC-003A-03d | TC-CA-02 integration | Batch S1…S5 stored with id, one adopted rule, manifest-member files, location, action, reason, severity and stage (default `implementation`) | Pass |
| AC-003A-03e | TC-CA-02 integration | `SUGGESTION_INVALID` with the reason, refusing the whole batch with nothing stored, for: a rule outside the scope; empty files; a context file that is not a manifest member; an empty location; a blank action; an id reused in the batch; an id reused in the collaboration | Pass |
| AC-003A-03f | TC-CA-02 integration | S5 without severity stored as `unknown` (and listed in attention) | Pass |
| AC-003A-03g | TC-CA-03 integration | A GitHub-token-shaped value was placed in the task, location, action, reason, Reviewer requirement and basis. It is absent from the state, the JSON, the Markdown and all command output. Labels: state and JSON `masked` = `task`, per suggestion `location`/`action`/`reason`, per review `requirement`, `subjects[0].basis`; Markdown "Task (masked):" and `masked: …` labels. Agent text containing a `[masked:…]` marker is refused | Pass |
| AC-003A-03h | TC-CA-11 structured (both modes) | Skill: collaborate during design, implementation, bug fix and refactor, including changes to an existing design; load the adopted Policies through the Framework; give concrete suggestions tied to an artifact location and a Policy source, no generic checklist; focus on the change and its related impact; leave all edits to the current executor | Pass |
| AC-003A-03i | TC-CA-06 integration | Update records the rename (new path digest + `old_path`; old path `renamed_away`, no digest), the deletion (no digest), the addition and the modification. Added and renamed files become bindable (S6, S7); an unrecorded new folder file is not. Suggestion states are identical before and after the update. r4 names `app/export.py (renamed_away)` and `app/server.py (deleted)` | Pass |
| AC-003A-04a | TC-CA-04 integration | Stored record: invocation (host, agent, read-only, invocation time), requirement, reviewed digests and `adoption` subjects with result and basis. Results used across the scenario: adopted, partial, not_adopted, not_applicable, cannot_verify. `attempt` refused | Pass |
| AC-003A-04b | TC-CA-04 integration | `REVIEW_INVALID`, nothing stored, for: a subject without basis for each result (adopted, not_adopted, and since TASK-048 partial, not_applicable, cannot_verify); an unknown suggestion | Pass |
| AC-003A-04c | TC-CA-04, TC-CA-06 integration | A digest list lacking `server.py` for the covered S3 refuses the whole record; `absent` accepted for removed files | Pass |
| AC-003A-04d | TC-CA-04 integration | Records with `suggestions`, `artifacts`, `scope`, `stage` or `manifest` → `REVIEW_AUTHORITY`, nothing stored | Pass |
| AC-003A-04e | TC-CA-05 integration | Snapshot r1: all `not_reviewed`, 0 adopted; S7 `not_reviewed` in r4/r5 | Pass |
| AC-003A-04f | TC-CA-04 integration | Six records each kept (seq 1…6), not valid, with the reason. Missing: invoked_at; host/agent; read-only declaration (false); requirement; whole reviewed-digest list; result. r2 JSON `reasons` and the Markdown "no" row say why. **Single missing fields (TASK-048, `bug_fix` collaboration):** four records, each missing only one field, each kept (seq 1…4), not valid, with exactly that one reason, named in the r1 JSON `reasons` and in the Markdown row. The fields: agent only (host present), read-only declaration (key absent), invocation time, requirement. For the missing agent the row shows host `github-copilot` and agent `—` | Pass |
| AC-003A-04g | TC-CA-06 integration | r4: record 8 does not count for S2 ("stale: app/public/app.js modified since the review") in JSON and Markdown | Pass |
| AC-003A-04h | TC-CA-04 integration | Record bound to the pre-edit `registration.py` digest: kept, `wrong_version` = that path, not valid. The report says "wrong version" and S1 is not counted from it | Pass |
| AC-003A-04i | TC-CA-05 integration | Attention (critical, high, unknown order) with reasons and gaps, as exact lists:<br>- r1: attention S3, S1, S2, S5; gap S4;<br>- r2: attention S3 cannot_verify, S2 not_adopted; gap S4 partial;<br>- r4: attention S3, S2 stale, S6 not_reviewed, S5 stale; gaps S4, S7;<br>- r5: attention empty; gaps S4, S7;<br>- r6: S3 `policy_changed` attention, S7 gap.<br>Adopted and not_applicable suggestions appear in neither list | Pass |
| AC-003A-04j | TC-CA-11 structured (both modes) | Skill: one independent read-only Reviewer per batch through the host, not one per rule; pass only the task, relevant suggestions, locations and digests; check the actual artifact, not the executor's claim; never edit, widen the review or start further agents | Pass |
| AC-003A-05a | TC-CA-05 integration | Rounds `<cid>-r1…r8.{json,md}` in `reports/copilot`; footer = SHA-256 of the JSON bytes; contiguous numbering. Field-by-field, for every round: suggestions with state, severity, Policy and basis; attention and gaps (order); artifacts and manifest digests; adopted Policies; stage, task, scope and round. **Reviewer records, every field (TASK-048):**<br>- the summary row: seq, validity, host, agent, read-only, invocation time, reviewed and recorded times, requirement, reasons, counted, not counted, masked labels;<br>- the declared-invocation statement;<br>- the reviewed targets: path with the digest seen or `absent`, same order;<br>- the subjects: id, type, result, basis, masked labels, same order;<br>- no JSON record key without a rendered field.<br>Applied to 15 rounds: main r1…r8, masking r1, `bug_fix` r1…r3, `refactor` r1, removed-Policy r1…r2 (13 comparisons each). The expected Markdown is built from the documented format (code spans; escaped free text), not from toolkit code. These checks fail on the pre-fix renderer output and pass on the fixed one | Pass |
| AC-003A-05b | TC-CA-06, TC-CA-10 integration | r1 byte-identical after r2, and r1…r4 after r5; the next number states which round it supersedes. No existing report file rewritten by any of 107 commands | Pass |
| AC-003A-05c | TC-CA-05 integration | Report states id and round, stage, task, artifacts with digests, scope id and rules, every suggestion with state and Reviewer basis, history, attention and gaps. r1 states "snapshot before review" | Pass |
| AC-003A-05d | TC-CA-05, TC-CA-08 integration | Both outputs state: not a pass, approval or security verification; review not a correctness guarantee; does not replace Guard. The design-stage collaboration adds "adoption in the design does not show the measure is implemented"; the implementation stage does not | Pass |
| AC-003A-05e | TC-CA-05 integration | Structured result has suggestions, states, counts, attention and gaps. No `pass`/`passed`/`approved`/`approval`/`verdict`/`completed_safely`/`safe` key in any round or CLI result | Pass |
| AC-003A-05f | TC-CA-08 integration | Report with no change → round 2, `published: false`, files unchanged. The removed r2 Markdown is re-rendered from the same JSON byte-identically | Pass |
| AC-003A-05g | TC-CA-08 integration | Both outputs state reports and private data stay until the user removes them (no automatic expiry), with "present as of publication <time>". `show` reports the private data and each report present, then the removed Markdown, then the removed private data | Pass |
| AC-003A-06a | TC-CA-10 integration | Across 107 Copilot commands (container), no project path changed outside Copilot's private data and the report files. Private data here means the collaboration folder and the project-wide Copilot lock file `.x-ipe/private/secure-code/locks/copilot.lock` (with its `locks` folder). So every artifact is byte-identical before and after each command. Inside those areas, only the collaboration's own folder, the lock file and its own `<cid>-r<n>` files were written. The lock file was written (created on first use). Host: 6 commands, same | Pass |
| AC-003A-06b | TC-CA-11 structured (both modes) | Skill: Copilot and its Reviewer never edit business artifacts; the current executor makes all changes; Copilot does not pause or block; the upstream caller decides from the attention list | Pass |
| AC-003A-06c | TC-CA-11 structured (both modes) | Skill: a continue decision is not adoption or a pass; the Reviewer must not trigger the Copilot or Guard flow again; failed or old reports never count as done for the current version; never invent Policies from memory | Pass |
| AC-003A-06d | TC-CA-08 integration | After close, `suggest`, `review`, `artifacts` and `close` → `COLLAB_CLOSED` with the next step "open a new collaboration (copilot open)"; reports byte-identical | Pass |
| AC-003A-06e | TC-CA-10 integration | Guard opened with the final Copilot Markdown as `copilot_reports`: recorded as context. A ledger citing it leaves C1 not met, the verdict is not `pass`, the Guard report says "never evidence of a pass", and the Copilot files are unchanged | Pass |
| AC-003A-06f | TC-CA-08 integration | Close with an unreported change publishes final r8 (supersedes r7), closes and returns that pair (both exist). Design collaboration closed with no change since r1 → no new round, r1 returned. **No prior report (TASK-048):** a `refactor` collaboration closed without any report publishes round 1 (`published: true`, supersedes none) before closing. Both files exist and are returned; the state is `closed` with exactly one round | Pass |

## Test Cases

| TC | ACs | Type | Priority | Command / Method | Result |
| --- | --- | --- | --- | --- | --- |
| TC-CA-01 Open on real files incl. folder artifact; `bug_fix`/`refactor` stages | 02c, 03a | integration | P0 | container runner | Pass (17 checks) |
| TC-CA-02 Suggestion batches | 03d, 03e, 03f | integration | P0 | container runner | Pass (11) |
| TC-CA-03 Masking in every free-text field | 03g | integration | P0 | container runner | Pass (6) |
| TC-CA-04 Reviewer records | 04a, 04b, 04c, 04d, 04f, 04h | integration | P0 | container runner | Pass (32) |
| TC-CA-05 Rounds, states, attention, report/JSON consistency (full Reviewer records) | 04e, 04i, 05a, 05c, 05d, 05e | integration | P0 | container runner | Pass (216) |
| TC-CA-06 Targeted re-review (incl. stale-only record) and artifact updates | 01a, 01b, 01c, 01d, 03i, 04g, 05b | integration | P0 | container runner | Pass (21) |
| TC-CA-07 Policy changed or removed | 02d | integration | P0 | container runner | Pass (8) |
| TC-CA-08 No-change, close (incl. without report), closed, design, retention | 05d, 05f, 05g, 06d, 06f | integration | P0 | container runner | Pass (16) |
| TC-CA-09 Open and update refusals (incl. missing Policy) | 02a, 02b, 02e, 03b, 03c | integration | P0 | container runner | Pass (26) |
| TC-CA-10 No business writes (lock file per 06a); Guard context only | 06a, 06e | integration | P0 | container runner | Pass (19) |
| TC-CA-11 Skill package instructions | 01e, 03h, 04j, 06b, 06c | structured (executable phrase checks) | P1 | container and host runner | Pass (19) in both |
| TC-CA-12 Never-authorized User path | 02e, 03b, 03c | integration | P1 | host runner | Pass (7) |
| TC-U-01 Unit / integration suites | all (design-level) | unit / integration | P1 | `uv run pytest -p no:cacheprovider -o addopts="" -v tests/copilot tests/test_reviewer_envelope.py` (macOS, Python 3.14.6) | 221 passed |
| TC-R-01 FEATURE-002-A regression (shared envelope and Guard refactor) | 002-A | integration | P0 | 002-A runner: container `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` (`e5b65587…`), fresh `fat-uv-cache-ga`; host | 26/26 + 2/2 |
| TC-R-02 FEATURE-002-B regression | 002-B | integration | P1 | 002-B runner: container `fat-uv-git:py312`, fresh `fat-uv-cache-gb`, real Opengrep (`og-validate`), samples m and w; host | 10/10 + 2/2 |

Commands (from the workspace root, `A=x-ipe-docs/requirements/EPIC-003/FEATURE-003-A/acceptance`):
- **Container:** `docker run --rm --network none -e FAT_ISOLATED=1 -e TOOLKIT_ROOT=/toolkit -e UV_OFFLINE=1 -e FAT_WORK=/root/fat-work -v fat-uv-cache-ca:/root/.cache/uv -v $PWD/ai-secure-code-toolkit:/toolkit:ro -v $PWD/$A:/fat:ro -v $PWD/study-case/secure-coding-guidance/playground/shanghai-marathon-registration:/samples/m:ro fat-uv-git:py312 python3 /fat/blackbox.py container`
- **Host:** `cd $A && FAT_WORK=<session>/files/fat-work UV_REFRESH_PACKAGE=ai-secure-code-toolkit python3 blackbox.py host`
- **Regression containers:** same pattern, offline, with the images, cache volumes and mounts listed above. Regression hosts: `TMPDIR=<session>/files/fat-tmp UV_REFRESH_PACKAGE=ai-secure-code-toolkit python3 blackbox.py host` in each runner folder.

## Relevant Inputs and Evidence

| Role | Path | SHA-256 |
| --- | --- | --- |
| toolkit tree | `ai-secure-code-toolkit/` (find/sort/shasum, excluding `.venv`, caches, coverage) | `5c3d186ca9138787481a9e143ba352111510527783852a9e4d2f9b9ccf4cdaa3` |
| specification | [specification.md](specification.md) (AC-003A-06a clarified) | `4c647c8c4faac1c13b65345df76bf22728120cf35b4e4a4f41afc06a65ed9f88` |
| design | [technical-design.md](technical-design.md) (TASK-048 Change Log row and evidence) | `aeff97182bc094e15674f7ff59c7db996bbe5a442e05120ad741f7c914c7acf1` |
| fixed source | `…/scripts/src/x_ipe_secure_code/copilot/report.py` (264 lines; pre-fix `76ea28ca…`) | `660fcd06f0b8f2b59f9d8e920cb7b83c16714b6a7ad5f0a2074ab7782f244ee3` |
| regression tests | `…/scripts/tests/copilot/test_copilot_report.py` | `368eab5a54e59c5b0cf56f151d8b36482f618a3caccb0fa0c4df28ab3a31ffd1` |
| skill | `ai-secure-code-toolkit/x-ipe-secure-code-toolkit-copilot/SKILL.md` | `8b954e90ec4426b7487e0340fa01e9e5c76b546a0d2b08181613c95240d71520` |
| skill reference | `…-copilot/references/copilot-records.md` (report content sentence added) | `3fac165e4099d043681ff5db205a49f6659a74b59c276e8c8ba4891530fff5f6` |
| runner | [acceptance/blackbox.py](acceptance/blackbox.py) (TASK-048 additions) | `7a4cd98cf3335b94dca85f4c615f14f2708efd034c2be79a7a0b650595cb351e` |
| evidence | [acceptance/evidence-container-linux.jsonl](acceptance/evidence-container-linux.jsonl) (11/11, 391 checks; `.stderr` empty) | `4b978585269bdb2e5cf866d4029cc48db002a81440e1fddd8732ec310a4c7a51` |
| evidence | [acceptance/evidence-host-macos.jsonl](acceptance/evidence-host-macos.jsonl) (2/2; `.stderr` empty) | `e2e89141e8ecdcee286d14b0e2af2b3fef6cd02d2f214d9fdfb753992cfb566e` |
| evidence | [acceptance/evidence-unit-integration.log](acceptance/evidence-unit-integration.log) (221 passed) | `2fd939023584af64600028ac3bd63ac0687d8ed2e9fe1f992318260d154e3615` |
| regression | [acceptance/regression-002A-container-linux.jsonl](acceptance/regression-002A-container-linux.jsonl) (26/26) | `404ada17d57738f443ed3398aa79b9f96bf21cd0a286eb00cc6a7d5e0b87b611` |
| regression | [acceptance/regression-002A-host-macos.jsonl](acceptance/regression-002A-host-macos.jsonl) (2/2) | `b87e492ec1ccacd5328687f24f8c5cb33914ae246429e0fc537ff397e62fd6e2` |
| regression | [acceptance/regression-002B-container-linux.jsonl](acceptance/regression-002B-container-linux.jsonl) (10/10) | `3a256de87a38ec838bca0ec1d41052184e5614793b14cfc766fa5a0aeaef3feb` |
| regression | [acceptance/regression-002B-host-macos.jsonl](acceptance/regression-002B-host-macos.jsonl) (2/2) | `290c260700e86553d8d3cf8438e8280190e94aa025711e76ffc1a85fbf3a3805` |
| regression runners | FEATURE-002-A / 002-B `acceptance/blackbox.py` (unchanged) | `7dfbd3fe…` / `da3f8859…` |
| bug report | [bug-report-TASK-048.md](bug-report-TASK-048.md) | (written after this report) |

The empty `.stderr` files hash to `e3b0c442…` (empty). The regression runs also had empty stderr; those files were not kept. The TASK-048 rerun overwrote the host and all four regression files; their bytes are identical to the TASK-046 runs, because those runners print no timestamps or generated identifiers.

## Results

| Type | Planned | Passed | Failed | Blocked | Not Run |
| --- | --- | --- | --- | --- | --- |
| integration (black-box CLI) | 11 (TC-CA-01…10, 12) | 11 | 0 | 0 | 0 |
| structured (skill package, executable phrase checks; container + host) | 2 (TC-CA-11 × 2 modes) | 2 | 0 | 0 | 0 |
| unit / integration (pytest) | 1 | 1 | 0 | 0 | 0 |
| regression | 2 | 2 | 0 | 0 | 0 |
| **Total** | **16** | **16** | **0** | **0** | **0** |

Pass rate: 16/16 = 100% (passed / all planned executions, counting TC-CA-11 once per mode). All 42 ACs have current passing evidence at the revision above. These counts are diagnostic and do not measure goal achievement.

**Closing-review rerun (Bug Fix TASK-048).** The closing review (TASK-047) found one product defect and three coverage or wording gaps. Fixes:
- **Product (AC-003A-05a):** the Markdown "Reviewer Records" section left out reviewed targets, subjects, reviewed/recorded times and the invocation declaration. It now renders every field of each record. Test-first: RED 2 failed, then GREEN.
- **Runner additions** (black-box, real CLI only; all with real assertions):
  - 01d: a record covering only the stale suggestions;
  - 02b: a partial scope with a non-empty `missing` list;
  - 02d: a removed Policy;
  - 03a: `bug_fix` and `refactor` stages and an `unspecified` folder with its per-file manifest;
  - 04b: missing basis for partial, not_applicable and cannot_verify;
  - 04f: agent-only, read-only, invocation-time and requirement each missing alone and named;
  - 05a: every Reviewer-record field compared on 15 rounds;
  - 06a: the assertion now names the project-wide lock file as private data, matching the clarified wording, plus a check that it is written;
  - 06f: close without any prior report.
- **Freshness:** all runs were repeated with fresh caches: `fat-uv-cache-ca`, `-ga` and `-gb` were removed and recreated, and the fixed code was confirmed in each cache. No product check failed, so there is no `run1-FAIL` evidence. A debug dry run of the new runner (same image, not kept as evidence) also passed 11/11 before the cache was recreated for the evidence run.

**Runner correction (not a product change):** the first container invocation crashed at import, before any check ran: `Path(__file__).parents[5]` does not exist at `/fat`. The workspace default is now computed only when the path is deep enough, and the run was repeated; no assertion changed. No product failure occurred, so there is no `run1-FAIL` evidence. `ruff` reports three cosmetic line-length (E501) findings in the runner; they were left so the evidenced runner hash stays valid.

### Failures / Blockers

None.

### Engineering Delivery versus Stakeholder Outcome

| Goal | Delivery Evidence / State | Outcome Scenario | Outcome State |
| --- | --- | --- | --- |
| G-01 | All 42 ACs pass (black-box, structured, unit/integration); FEATURE-002-A/B regressions pass | Marathon-copy scenario above (suggest, apply, review, unrelated vs relevant edit, targeted re-review, Policy change, close) | not measured |
| G-01 (enabling) | TC-CA-10 byte-identity across 107 + 6 commands; TC-CA-11 | Artifact bytes unchanged by Copilot; Guard takes the report as context only | not measured |

### Refactor / Closing Recommendation

No evidenced quality or preservation need was found during acceptance (all assertions pass; module sizes are enforced by `tests/test_module_size.py`). The two conditional successors (code refactor, feature closing) are returned to the lifecycle owner. If `code_refactor` is mandatory in the app workflow, that gate applies. This executor made no board, workflow or Git writes.

## Gaps and Honest Limits

- **Windows:** not run (macOS host and Linux container only).
- **Reviewer invocation:** declared, not proven. The script records the agent's declaration (host, agent, read-only, time) and binds it to file digests. That a separate read-only sub-agent really ran is not verifiable (spec "Unprovable invocation").
- **Removed Policy fixture:** no toolkit command removes or deactivates a rule. The 02b missing list and the 02d removal are produced by deleting the rule folder (disclosed above); a real Maintainer removal path is not exercised.
- **Masking:** pattern-based (FEATURE-002-A patterns). It was verified with a GitHub-token-shaped value; it is not a complete data-loss-prevention guarantee.
- **Skill-instruction ACs (01e, 03h, 04j, 06b, 06c):** verified as text in the installed package. Agent behaviour following them is not observed.
- **Host routing:** real host Copilot routing and automatic triggering are FEATURE-003-B; not in scope.
- **Concurrency and crash repair (NFR-003A-3):** verified in TC-U-01 (process-level and monkeypatched tests), not in the black-box runs.
- **Independent review of this acceptance evidence:** not performed by the acceptance executor; left to the owner.
- **Stakeholder outcome:** not measured.
