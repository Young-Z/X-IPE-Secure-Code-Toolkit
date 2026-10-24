# Acceptance Test Cases — FEATURE-002-F Temporary Check Scripts (helpers)

> Feature / scope: FEATURE-002-F (EPIC-002), specification v1.3.3 — 74 active ACs (AC-002F-01a…12d); AC-002F-05f is **not applicable** (human decision B12 = A) and is never reported passed.
> Task: TASK-111 (Feature Acceptance Test), lifecycle owner Sage, acceptance worker (resumed after earlier workers stopped); free mode. No board, Git, memory or successor action was taken by this worker.
> Status: **Blocked — 73 / 74 active ACs Pass, 1 Fail (AC-002F-04l: a helper exceeding the results area is failed and nothing is kept, but the limit is named "tmp limit reached" instead of the results-size limit).** 46 / 51 planned test cases Pass (pass rate 90.2 % on all planned cases); 1 Fail, 4 Partial (regression runners: change-set pins and one environment precondition). Stakeholder outcome **not measured**.
> Revision: toolkit commit `73fe2dc6751fb002a9cde903ab598371a0cd8341`, executed only from the frozen copy (`git archive` of `73fe2dc`) in the session evidence folder; frozen-tree file-list hash `f7a155a4e7089a36f20cae746af43523ea4907d8f9a7f51ef138410bd4c13589` (368 files) at start **and** end of all runs. The live `ai-secure-code-toolkit/` tree was never executed or hashed.

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-002-F — `secure-code guard helper submit / show / grant / run`, `secure-code tools register-helper-image / helper-conformance`, helper records in the run state, the "Temporary helper checks" part of the Markdown/structured Guard report, and the Guard skill text (`x-ipe-secure-code-toolkit-guard/SKILL.md` step 5c, `references/guard-records.md`) |
| Specification / Source | [specification.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/specification.md) v1.3.3, SHA-256 `fcf0f92a2fb62d2030c639baa7d05e2cc65febb5e5e0a25e6217743553b33ae3` (AC-002F-11b "network disabled", DAO-005, human-confirmed intent) |
| Design / Implementation | [technical-design.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/technical-design.md) v1.2.1 (errata E1–E4 + honest-limit note) `9139ed25feda02706a3c23e4af17cff7429c0d0b56a0630484f09d73ef08eeab` (Part 1 and Part 2 incl. §15 honest limits and the AC→test table); [implementation-report-TASK-085.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/implementation-report-TASK-085.md) `4615d45dba99373a8238cc81c185dabeb8d3892b338766a1679acfbca046ea2a`; consumed CR [CR-TASK-077-helpers-coverage.md](x-ipe-docs/requirements/EPIC-002/FEATURE-002-C/CR-TASK-077-helpers-coverage.md) `d262a869fc0f70ccf92e8f99f4b257534a322e346831613ee5e315f7423c975d` (the `helpers` Reviewer coverage item is proven black-box here: batch pre-execution coverage, post-run re-coverage counted extra) |
| Rulings | DAO-005 / DAO-006 code implementation ([decisions_made_code_implementation.md](x-ipe-docs/dao/26-10-23/decisions_made_code_implementation.md) `7a8c36ee…`: local-only acceptance, public `GPG_KEY` fingerprint exemption, 11b clarification); DAO-014/017/018/019 ([decisions_made_technical_design.md](x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md) `7b2e4a36…`); DAO-007/014 ([decisions_made_feature_refinement.md](x-ipe-docs/dao/26-10-23/decisions_made_feature_refinement.md) `89996e49…`); human B12 = A ([human_decisions.md](x-ipe-docs/dao/26-10-23/human_decisions.md) `ae80d5c1…`) |
| Mockups | N/A — CLI and skill-text feature; the specification links no mockup |
| Target URL | N/A — no UI (no browser test applicable) |
| Config / Capability | `x-ipe-docs/config/tools.json` (`6df39210…`) `stages.validation.acceptance_test`: `x-ipe-tool-implementation-python: true` (literal) → executable Python CLI runners permitted; Chrome tools enabled but not applicable (no UI) |
| Planned cases / priority | 51 cases: TC-F-01…12 (macOS host, no runtime CLI / never-authorized User / skill text), TC-F-20…37 (macOS host, **real Docker Desktop runtime, local image only**), TC-F-40…43 (Linux container, Maintainer CLI and non-execution path), TC-F-50/51 (frozen delivered helper tests, default and opt-in real runtime), TC-F-52 (frozen full suite, diagnostic), TC-F-60…73 (delivered acceptance runners as regressions). P0: 09, 20, 21, 23, 24, 26, 27, 30, 32, 33, 34, 37, 40, 41, 51; P1: the rest. Counts are diagnostics, not goals |

## Goal / Subgoal Frame (copied from the specification; outcome not measured)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 | Requirement G-02; FR-19 (A-13…A-17; A-18 by DAO-007) | Developer, Maintainer, upstream agent | Real coverage gaps checked without unsafe ad-hoc code; no misleading "pass" from a helper not run, not reviewed, merely exited cleanly or reporting no findings | All required G-02.1…G-02.8 | Spec scenario executed as **delivery** checks on fixture projects (TC-F-23 positive path; TC-F-09/24/25/34 non-execution paths) | Not formal knowledge; not the FR-29 sandbox; no new network/model/keys/services; grant is not a security boundary | 01a…12d | not measured |
| G-02.1 | FR-19 A-13 | Developer | Helper only as a gap-bound auxiliary method of one planned check | Plan/method-change rules, generation attempt | TC-F-01, 02, 03, 11, 42 | Guard never fixes | 01a…01d, 06c | not measured |
| G-02.2 | A-14 layer 1 | Developer, Maintainer | Declared, syntax-checked by the image's own interpreter, static rules (defence in depth) | Compile probe in a toolkit container + toolkit parser | TC-F-04…08, 22, 43 | Static rules never prove safety | 02a…02g | not measured |
| G-02.3 | A-14 layer 2, B12 = A (CR-077) | Developer | Independent read-only Reviewer with known samples | Batch `helper` subjects; samples in own containers | TC-F-07, 23, 24, 25, 26, 28 | Reviewer acceptance is a model judgement | 03a…03h | not measured |
| G-02.4 | A-15, A-16, DAO-001 | Owner | Execution only after a typed user grant, on a conformance-proven runtime, under inspect-verified limits inside the 002-C budget/cancel | Grant, conformance record, canonical config read-back, snapshot | TC-F-20…24, 27, 30…37, 51 | Grant is cooperative consent; kernel/runtime escapes outside protection | 04a…04p, 06a, 06b, 11a…11f | not measured |
| G-02.5 | A-16 | Developer | Non-execution with a reported gap, never a host fallback | Failed auxiliary method + gap entry | TC-F-09, 24, 25, 34, 40, 41 | — | 05a…05e, 05g (05f N/A) | not measured |
| G-02.6 | A-16, FR-22 | Report reader | Labelled, snapshot-bound, auditable helper results under unchanged 002-A rules | `runtime` evidence, helper source, events, config read-back | TC-F-12, 23, 26…29, 37 | Per-file coverage not enforced for any method (honest limit) | 07a…07g, 09a…09c | not measured |
| G-02.7 | A-17, A-18 | Maintainer | Run-only artifacts; Maintainer-registered image | Run folder retention; 002-F-owned state | TC-F-20, 21, 24, 36 | — | 08a…08f | not measured |
| G-02.8 | A-16 | Owner | Untrusted content cannot steer scope, policy, ledger or report | Constants-only config, schema-only reading, escaping/masking | TC-F-11, 28 | — | 12a…12d, 03g, 10d | not measured |

Qualitative outcome scenario (specification Goal/Subgoal row): on a conformance-passing local runtime with a registered local image, a gap check gets a helper whose positive sample is detected and negative sample is clean; after the user's grant it runs on a link-free read-only snapshot bound to the target version and its labelled result appears in the report; the same request with no runtime, no conformance or no grant leaves a failed auxiliary method with a reported gap. Executed as **delivery** checks (TC-F-23, TC-F-09, TC-F-24, TC-F-34). No stakeholder session was observed.

## Full Acceptance / Evidence Map

Evidence files are in [acceptance/](x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance/): host `evidence-host-macos.jsonl` (H), container `evidence-container-linux.jsonl` (C), delivered tests `evidence-delivered-helpers-default.log` (D) and `-real.log` (DR). "TC-F-50 `test_x`" names a frozen delivered test (fake runtime, orchestration) cited as corroboration for clauses that cannot be produced black-box on this host; every AC also has its own black-box evidence.

| Subgoal | AC ID | TC / Type | Original assertion (abridged) | Evidence (actual) | Delivery |
| --- | --- | --- | --- | --- | --- |
| G-02.1 | AC-002F-01a | TC-F-01 (H), TC-F-42 (C) · integration black-box | Missing/unknown/foreign check refused naming it; nothing stored | `HELPER_INVALID` naming `check`, `C9`, `C2`; foreign attempt and non-helper method refused; no helper record/folder | Pass |
| G-02.1 | AC-002F-01b | TC-F-02 · integration | Auxiliary `runtime` helper method with gap reason stored; required / non-runtime / no gap refused | `PLAN_INVALID` ("auxiliary", "kind runtime", "gap is required"), plan stays null; method change without gap refused, with gap adds `required:false` | Pass |
| G-02.1 | AC-002F-01c | TC-F-11 · structured (skill-text) | Skill states real gap only, not convenience, not instead of an Adapter, never fix | SKILL.md (`81733a4d…`) step 5c, every phrase found | Pass |
| G-02.1 | AC-002F-01d | TC-F-03 · integration | Later-added helper method costs extra exactly as 002-C | planned pair first generation attempt extra 0; method-change-added pair extra 1 | Pass |
| G-02.2 | AC-002F-02a | TC-F-04 · integration | Each missing field refused naming it | `check, goal, read_scope, judgement_basis, language, script_file` each → `HELPER_INVALID` naming it, nothing stored; non-python and incomplete basis refused | Pass |
| G-02.2 | AC-002F-02b | TC-F-05 · integration | Link component, escape, absolute, special file, outside, missing, L-05 → refused, nothing stored | 8 cases refused (`HELPER_INVALID`/`HELPER_LIMIT`; 2,001 files → `HELPER_LIMIT`) | Pass |
| G-02.2 | AC-002F-02c | TC-F-22 (H real), TC-F-09/41, TC-F-34, TC-F-20; TC-F-50 `test_02c_compile_probe_syntax_version_unavailable` | Compile only with the image's interpreter in a canonical container; syntax error with parser message; outside/unknown version or unavailable probe refused | real probe: image `sha256:a6e34c59…`, CPython 3.12.15, launcher mode `compile`, `--network none`, event `compile_probe` + config digest; `x = (` → `HELPER_CHECK_FAILED` "parse … SyntaxError (line 2)"; no runtime / image missing / no conformance → refused with reason; busybox (no CPython) refused at registration; outside-L-12 image: no such local image (never pulled) → delivered test | Pass |
| G-02.2 | AC-002F-02d | TC-F-06 (H), TC-F-43 (C), TC-F-22 | Each violation refused naming the rule; parse fail closed; defence-in-depth statement; accepted script stored with SHA-256 | 11 deny cases named (`import_denied`, `name_denied`, `dunder`, `import_star`, `import_relative`, `open_form`, `write_attribute`) + `parse`; statement recorded; stored `script.py` SHA-256 = submitted bytes | Pass |
| G-02.2 | AC-002F-02e | TC-F-22 | State after checks = checked | `status: checked`; show: "not reviewed / not granted / not executed" | Pass |
| G-02.2 | AC-002F-02f | TC-F-06, TC-F-43 | >L-03 / AST >L-04 refused before compile and rules | 2,001 lines, 60-deep list, 65 KiB → refused, no `compile` check, no `compile_probe` event | Pass |
| G-02.2 | AC-002F-02g | TC-F-08 | Sixth helper refused | 5 stored, 6th `HELPER_LIMIT`, nothing stored | Pass |
| G-02.3 | AC-002F-03a | TC-F-07 | Missing positive/negative, target file as sample, unlabeled formal example, L-02 count/size refused; origin + SHA-256 recorded | 6 refusals, nothing stored; accepted samples carry origin + SHA-256 (TC-F-23 report) | Pass |
| G-02.3 | AC-002F-03b | TC-F-23, TC-F-25 (real) | Each sample in its own container under the same config; outcomes stored, attempt not finished; mismatch → helper fails on samples, no target run | 2 sample containers (distinct names) then 1 target; positive → finding, negative → clean; never-matching script → `samples_mismatch`, shown "blocked: samples failed" (design naming of `samples_failed`), no target container, attempt reported unfinished, re-run refused | Pass |
| G-02.3 | AC-002F-03c | TC-F-23, TC-F-26/27/37 (batch of 5) | Batch review under a `reviewer` attempt covering the helpers; one `helper` subject per helper | reviewer attempt `covers.helpers` = the helper ids; record accepted | Pass |
| G-02.3 | AC-002F-03d | TC-F-24 | Changed after review → not executed | stored `script.py` edited → `helper files changed after submission`, no container | Pass |
| G-02.3 | AC-002F-03e | TC-F-24, TC-F-25 | Rejected / samples failed → not executed, failed auxiliary method, 002-A state, gap | rejected → no container; conclude: helper evidence `failed`, C1 `unconfirmed`, gap "rejected by the Reviewer" / "samples failed" | Pass |
| G-02.3 | AC-002F-03f | TC-F-23 | Reviewed never presented as permission | show and report: "accepted (not permission to execute)" | Pass |
| G-02.8 | AC-002F-03g | TC-F-11 | Reviewer requirement states untrusted-data rules | `references/guard-records.md` (`766b8def…`) phrase found | Pass |
| G-02.3 | AC-002F-03h | TC-F-23 | Clean result without accepted post-run subject does not count | before post-run review all helper evidence `failed`; after `post_run` accepted (re-coverage extra) → `accepted_full` | Pass |
| G-02.4 | AC-002F-04a | TC-F-23 | Without grant not executed; with grant toolkit-owned container run | not reviewed / not granted → `HELPER_NOT_EXECUTED`, no container; granted → toolkit containers | Pass |
| G-02.4 | AC-002F-04b | TC-F-23, TC-F-34 (real, fault at the CLI boundary); TC-F-50 `test_04b_each_invariant` | Every canonical field read back from inspect; any deviation → no start, field named, removed | create flags (`--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `65534:65534`, limits) on all 236 creates; 108 stored fields equal the runtime's own inspect output; inspect patched to `NetworkMode=bridge` / `PidsLimit=65` → "configuration mismatch: network" / "pids limit", never started, `rm -f` issued | Pass |
| G-02.4 | AC-002F-04c | TC-F-20, TC-F-34; TC-F-50 `test_04c_missing_or_mismatched_image_no_pull` | Only the registered local image; never pulled/built | absent image refused at registration; image reported missing at execution → "not present locally (never pulled)"; 2,525 runtime calls: no pull/build/load/import/push, every create `--pull=never` | Pass |
| G-02.4 | AC-002F-04d | TC-F-23 | Targets/context byte-identical; only snapshot mounted | `src/` tree and README identical; every bind source under `<run>/helper-stage-*` | Pass |
| G-02.4 | AC-002F-04e | TC-F-30 (real) | L-10 capped by remaining time; overrun → failed, never clean | 1-minute budget: `time_limit 53`, `time_limit_capped: true`; busy target → `failed` "time limit (L-10)" after 54.2 s | Pass |
| G-02.4 | AC-002F-04f | TC-F-32 (real) | Cancel stops/removes the owned container; confirmed only when the runtime reports it | target running → `guard cancel` → run returns `termination: confirmed` "helper containers stopped and removed"; no labelled object left; later record refused `RUN_CANCELLED`, result unchanged, verdict Cannot confirm pass | Pass |
| G-02.4 | AC-002F-04g | TC-F-30, TC-F-31 | Exhausted budget / paused → refused, no container | `BUDGET_TIME_EXHAUSTED`; paused → submit, run and attempt `RUN_PAUSED`, no container | Pass |
| G-02.4 | AC-002F-04h | TC-F-23, 26, 27, 37, 32 | Container, snapshot and staging removed; only normalized records | after every run: no labelled container/volume, no `stage-*`/`helper-stage-*`, no raw `result.json` (normalized `run-N-result.json` only) | Pass |
| G-02.4 | AC-002F-04i | TC-F-23, TC-F-33 (real) | Manifest (path, size, SHA-256) bound to attempt/evidence/audit; changed target → "target changed since open" | manifest files equal targets at open; digest on evidence and events; Reviewer reviewed the changed bytes → `target changed since open: src`, no target container (changed after review → "not reviewed", also refused) | Pass |
| G-02.4 | AC-002F-04j | TC-F-33, TC-F-05; TC-F-50 `test_04j_swap_to_symlink_during_copy` | Links/special files/path change during copy/L-05 abort the run | file replaced by a symlink → "snapshot unsafe: … is a symbolic link", no link in the run folder, no target container; the during-copy race is not reproducible black-box → delivered test | Pass |
| G-02.4 | AC-002F-04k | TC-F-37, TC-F-21 (P-13b), TC-F-23 | Only regular `result.json` within L-08; anything else failed; no raw file kept | 1.5 MiB `result.json` → "larger than 1048576 bytes (L-08)"; real P-13b (extra file, extra directory, hard link, FIFO, four symlink variants, too many entries) all rejected; no raw result file | Pass |
| G-02.4 | **AC-002F-04l** | TC-F-21 (real conformance), TC-F-27 (real helper runs), TC-F-51 | Each limit → failed method **naming the limit**; nothing beyond limit stored | conformance P-09…P-15, P-17 pass on the real runtime; memory hog → "memory limit (L-06)"; **3 MiB write to the results area → `failed` "tmp limit reached" (`limit: tmp`)**: the method fails and nothing is kept, but the results-size limit is misnamed (ENOSPC is mapped to `/tmp` regardless of the path; design §9 says "ENOSPC on `/tmp`") | **Fail** |
| G-02.4 | AC-002F-04m | TC-F-27 (real) | Flood → terminated, failed, diagnostics ≤ L-09 | `failed` "output limit exceeded (L-09)", `limit: output`; stored diagnostics 0 bytes (≤ L-09, none of the excess kept) | Pass |
| G-02.4 | AC-002F-04n | TC-F-05, TC-F-07; TC-F-50 `test_04n_limits_before_container` | Over L-02/L-05 refused before any container | L-05 (2,001 files) and L-02 count/size refused before any probe; the execution-time re-check is unreachable black-box without changing the target (then 04i applies) → delivered test | Pass |
| G-02.4 | AC-002F-04o | TC-F-23, TC-F-24 | Non-tty refused; grant lists digests; changed/new helper needs a new grant; no egress | non-tty `INTERACTIVE_REQUIRED`; wrong typed id refused; pty grant shows check, goal, scope, script/declaration/sample SHA-256s; record bound to them; egress lists empty; second helper → "not granted" | Pass |
| G-02.4 | AC-002F-04p | TC-F-11, TC-F-23 | Consent wording in skill, command output and report; limits are the boundary | all three contain "cooperative consent … not a security boundary … enforced container limits are the security boundary" | Pass |
| G-02.5 | AC-002F-05a | TC-F-09, TC-F-40, TC-F-41, TC-F-34 | No usable runtime → no execution any other way; reason | no runtime CLI → compile probe `fail` "no container runtime CLI"; show "not ready"; no conformance / image → refused | Pass |
| G-02.5 | AC-002F-05b | TC-F-09/41, 24, 25 | Failed auxiliary method; 002-A state; no override | C1 `unconfirmed` exactly as 002-A computes (helper evidence `failed`) | Pass |
| G-02.5 | AC-002F-05c | TC-F-09/41, 24 | Gap entry with check, goal, reason; verdict per 002-A | gap "Gap: helper … (check C1, goal: …): <reason>" in JSON and Markdown; verdict `cannot_confirm_pass` | Pass |
| G-02.5 | AC-002F-05d | TC-F-11 | Skill states intended non-execution, no other means, review ≠ authorization, agent-only path | phrases found | Pass |
| G-02.5 | AC-002F-05e | TC-F-09, TC-F-41 | Full flow without runtime concludes with the gap | conclude exit 0, no traceback, gap shown | Pass |
| — | AC-002F-05f | — | Not applicable (B12 = A) | — | N/A |
| G-02.5 | AC-002F-05g | TC-F-24 | No grant → "not granted", gap, no target run | reviewed never-granted helper: gap "not granted", no container | Pass |
| G-02.4 | AC-002F-06a | TC-F-23, TC-F-25 | Own `helper` attempt per execution; samples do not finish it; re-execution extra; unfinished listed; bad citations refused | no / generation / foreign / finished attempt refused; executed attempt `finished`, not-executed ones `unfinished`; every helper attempt after the pair's first is `extra: 1` | Pass |
| G-02.4 | AC-002F-06b | TC-F-23, TC-F-30 | Container time counted; helper usage not applicable | consumed seconds ≥ run seconds; `not_applicable_attempts` = number of helper attempts | Pass |
| G-02.1 | AC-002F-06c | TC-F-03, TC-F-23 | Submission needs a `generation` attempt; extra counts; usage summed or unknown | no attempt → `ATTEMPT_REQUIRED`, nothing stored; wrong kind refused; re-citing refused; re-authoring new attempt; usage recorded | Pass |
| G-02.6 | AC-002F-07a | TC-F-23, TC-F-28, TC-F-12 | `runtime` evidence with the helper's own method; helper source; ids + digests; reserved names refused | evidence `kind runtime`, method `helper.yaml-debug`, helper id, script SHA-256, manifest digest; finding source `helper.yaml-debug`; agent records with helper method/id/source → `RECORD_INVALID` "recorded only by secure-code guard helper run" | Pass |
| G-02.6 | AC-002F-07b | TC-F-26 (real) | Missing/empty/unparseable/invalid/`error` → failed; exit 0 never evidence | 5 cases `failed` with named reasons; samples passed first | Pass |
| G-02.6 | AC-002F-07c | TC-F-23, TC-F-29 (real) | Full coverage + acceptance usable; partial → failed naming uncovered, 002-A state; never substitutes a required Adapter | full → `met`; partial alone → failed evidence naming `src/config/db.yaml`, `unconfirmed`; partial + reading evidence on the scanned file → `met`, report still names the file; required opengrep → `unconfirmed` "required method opengrep" | Pass |
| G-02.6 | AC-002F-07d | TC-F-28 (real) | Unconfirmed helper finding does not drive Fail; Reviewer `finding` decision does | unreviewed: `cannot_confirm_pass` + `FINDING_UNCONFIRMED`; confirmed `finding` subject → `fail` | Pass |
| G-02.6 | AC-002F-07e | TC-F-23 | Both reports list every helper field with the marking, same data | structured `helpers` entry fields present; Markdown table carries id, SHA-256, manifest, conformance, marking "temporary, run-only — not a formal rule or Adapter" | Pass |
| G-02.6 | AC-002F-07f | TC-F-28 | Masked like all Guard evidence | seeded token absent from state, structured result, Markdown and stored diagnostics; script text with a credential is refused at submission | Pass |
| G-02.6 | AC-002F-07g | TC-F-26, 27, 37; TC-F-50 `test_07g_schema_violations` | Exact schema; each violation failed naming it | unknown key, wrong rule, path/scanned outside manifest, >500 findings, title >200, notes >2 KiB, >1 MiB → each `failed` naming it; JSON depth not producible schema-valid → delivered test | Pass |
| G-02.7 | AC-002F-08a | TC-F-09/41, TC-F-23 | No write outside run folder/report files | project tree outside run folder/reports/tmp identical | Pass |
| G-02.7 | AC-002F-08b | TC-F-36 | Helper artifacts follow `cleanup/keep/release` | young run kept; aged (ended_at edited, 002-A precedent) + keep → kept; release + cleanup → run folder incl. helpers removed | Pass |
| G-02.7 | AC-002F-08c | TC-F-24 | Earlier helper not accepted in a new run | run/show with earlier ids → `HELPER_UNKNOWN` | Pass |
| G-02.7 | AC-002F-08d | TC-F-36 + run-wide log | No promote/export/upload/publish; no egress | help texts: helper subcommands exactly submit/show/grant/run, no such word; egress empty; all 236 creates `--network none` | Pass |
| G-02.7 | AC-002F-08e | TC-F-11 | Skill states run artifacts only, formal path via maintenance | phrases found | Pass |
| G-02.7 | AC-002F-08f | TC-F-20, TC-F-21 | 002-F state in its own file; 002-B/002-D files unchanged | registration and conformance changed only `.x-ipe/private/secure-code/helpers/` | Pass |
| G-02.6 | AC-002F-09a | TC-F-23 | Ordered events with time, attempt, outcome, script SHA-256, grant/conformance/manifest | 19 events in order submitted…post_run_review; snapshot_built carries grant, conformance, manifest, attempt | Pass |
| G-02.6 | AC-002F-09b | TC-F-23 | Stored config = runtime inspect; runtime identity kept | 108 stored `config`/`host` fields equal the inspect JSON captured by the wrapper; run `runtime.server_version` 29.7.2 | Pass |
| G-02.6 | AC-002F-09c | TC-F-23 | Concluded twice → identical helper part | twin copy concluded: `helpers`, `ledger`, `verdict` identical | Pass |
| G-02.1/5 | AC-002F-10a…10d | TC-F-11 | Flow order + TASK-077 dependency; host session; no-proof; untrusted data | all phrases found; 11 flow steps in order | Pass (4 ACs) |
| G-02.4 | AC-002F-11a | TC-F-20 (real), TC-F-10, TC-F-40; TC-F-50 `test_11a_register_rules` | Maintainer only; local image only; digest + CPython micro version; outside L-12 refused; nothing pulled | registration digest = local image id, CPython 3.12.15 = image `PYTHON_VERSION`, `GPG_KEY` labelled public fingerprint (DAO-005); absent image `HELPER_IMAGE_UNAVAILABLE`; busybox `HELPER_IMAGE_UNSUPPORTED`; never-authorized host User and container non-Maintainer `NOT_AUTHORIZED`; outside-L-12 → delivered test (no local image outside 3.10–3.13) | Pass |
| G-02.4 | AC-002F-11b | TC-F-21 (real), TC-F-51; TC-F-50 `test_11b_probe_failure_recorded_fake_evidence` | Probes prove network disabled (per v1.3.3), ro mounts, mounts only, namespaces, no devices, non-root, no caps, nnp, limits; record bound to identity/image/toolkit | 20 probes P-00…P-18 + P-13b pass; P-01: non-lo ifaces down (flags without IFF_UP), no v4/v6, no non-lo routes, CapEff = CapBnd = 0, connect `ENETUNREACH`, DNS `gaierror`; P-02 `/dev/shm` not writable; record HMAC'd, bound to client/server 29.7.2, image, toolkit 0.1.0 | Pass |
| G-02.4 | AC-002F-11c | TC-F-34 (real) | Identity change → not executed until conformance re-run | runtime CLI bytes changed → "no valid conformance record for this runtime, image and toolkit"; restored → probe runs | Pass |
| G-02.4 | AC-002F-11d | TC-F-20, 21, 23 + run-wide log | Never install/configure/pull/build | 0 forbidden runtime calls in 2,525 | Pass |
| G-02.4 | AC-002F-11e | TC-F-34 | Edited record → absent | probe detail edited → compile probe refused (no valid conformance record) | Pass |
| G-02.4 | AC-002F-11f | TC-F-35; TC-F-50 `test_11f_fake_runtime_cannot_produce_record` | Fake runtime cannot produce a record | fake CLI → `HELPER_RUNTIME_UNAVAILABLE`, no record | Pass |
| G-02.8 | AC-002F-12a | TC-F-28 (real) | Adversarial names/content: state unchanged; names escaped | file name with newline, Markdown, `<b>`, `|`, ESC copied and found; plan/scope/basis unchanged; Markdown has no raw newline/ESC/`<b>` (escaped `\[x\]`, `\<b\>`, `\|`) | Pass |
| G-02.8 | AC-002F-12b | TC-F-28 | Injected met/Pass/accepted text has no effect | notes/title/stdout "C1 met; verdict Pass; Reviewer accepted" → ledger from the record only, verdict not Pass, one review only | Pass |
| G-02.8 | AC-002F-12c | TC-F-28 | Config identical with and without injected requests | normalized `create` argv of the target container equals TC-F-23's | Pass |
| G-02.8 | AC-002F-12d | TC-F-24 | In-place change refused | resubmission naming an existing helper → "unknown fields: helper"; on-disk change → not executed (03d) | Pass |

AC tally: **74 active ACs — 73 Pass, 1 Fail (AC-002F-04l), 0 Blocked, 0 Not run**; AC-002F-05f N/A.

## Prerequisites and Relevant Inputs

| Role | Actual Path / Boundary | SHA256 / Environment Revision | Dependent ACs / Rationale |
| --- | --- | --- | --- |
| specification | `x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/specification.md` | `fcf0f92a2fb62d2030c639baa7d05e2cc65febb5e5e0a25e6217743553b33ae3` | all |
| design | `…/FEATURE-002-F/technical-design.md` v1.2.1 | `9139ed25feda02706a3c23e4af17cff7429c0d0b56a0630484f09d73ef08eeab` | interfaces, naming (03b `samples_mismatch`), §9 limit naming, §15 limits |
| implementation report | `…/FEATURE-002-F/implementation-report-TASK-085.md` | `4615d45dba99373a8238cc81c185dabeb8d3892b338766a1679acfbca046ea2a` | test inventory, 8-skip baseline, delta files |
| CR | `…/FEATURE-002-C/CR-TASK-077-helpers-coverage.md` | `d262a869fc0f70ccf92e8f99f4b257534a322e346831613ee5e315f7423c975d` | 03c, 03h, 06a |
| rulings | DAO decisions (code implementation / technical design / refinement), human decisions | `7a8c36ee…`, `7b2e4a36…`, `89996e49…`, `ae80d5c1…` | 11a (GPG_KEY), 11b, 07c, B12 |
| config | `x-ipe-docs/config/tools.json` | `6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d` | capability gate |
| code / skill (frozen) | `git archive 73fe2dc` → session `fat-002f/frozen/ai-secure-code-toolkit` (+ `.github/copilot-instructions.md` `db317ea5…` for the carriers tests) | file-list hash `f7a155a4…3589` (368 files) start = end; Guard `SKILL.md` `81733a4d…`, `guard-records.md` `766b8def…` | all |
| runtime | Docker Desktop on macOS 26.6.2 arm64: client/server 29.7.2, API 1.55, LinuxKit aarch64; local image `python:3.12-slim` `sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1` (CPython 3.12.15) — local images only, nothing pulled/built | — | 02c, 03b…04p, 06*, 07*, 09*, 11*, 12* |
| host | macOS host Python 3.13.3 (runner), toolkit via `uvx --from <frozen>/scripts` (uv 0.11.23, `UV_OFFLINE=1`) | — | H cases |
| container | `fat-uv-git:py312` (`8cbe78fe…`), `--network none`, CPython 3.12.12, uv cache volume `fat-uv-cache-002f` (copy of seed `fat-uv-cache-003b`, seed mounted read-only only; removed at the end) | — | C cases, 002-G container regression |
| Maintainer seam | `acceptance/maint.py`: the same public service functions the CLI dispatches to, with an explicit disposable trust store under the session folder — the documented library/test form (`trust_store.resolve(app_dir)`) used by the delivered opt-in real tests. `auth init` was never run on the macOS host (the host account has no trust root; TC-F-10 proves the host CLI is never-authorized); Maintainer CLI paths ran in the container (TC-F-40). Helper records are project-local and HMAC'd with the project key, so the User/agent CLI on the host uses them unchanged | — | 11a, 11b, 08f |

## Typed Test Cases

All runner steps are actual subprocesses of `secure-code` (black-box), except the Maintainer seam on the host (see above) and the delivered test suites. Every toolkit runtime call on the host passed through a logging wrapper (`docker` first on PATH; argv, return code and `inspect` output captured; optional fault injection read from a control file so the wrapper bytes — part of the runtime identity — never change during a run). Expected values come from the specification/design, never from the implementation's output.

### Integration (CLI) — macOS host, no runtime CLI on PATH, never-authorized User (`evidence-host-macos.jsonl`)

| TC | ACs | Steps (abridged) | Expected | Status |
| --- | --- | --- | --- | --- |
| TC-F-01 | 01a | seed copy → open/plan → submit with no / unknown / foreign check, foreign attempt, non-helper method | refusals naming the check; nothing stored | Pass |
| TC-F-02 | 01b | plans with required / reading / gap-less helper; method change with and without gap | refusals; stored auxiliary method + gap | Pass |
| TC-F-03 | 01d, 06c | generation attempts on planned and later-added pairs; submissions without / wrong / re-cited attempts | extra 0 / 1; refusals | Pass |
| TC-F-04 | 02a | each declaration field removed | refusal naming it | Pass |
| TC-F-05 | 02b, 04j, 04n | link component, escape, absolute, FIFO, outside, missing, 2,001 files | refused, nothing stored | Pass |
| TC-F-06 | 02d, 02f | 11 denied snippets + parse error; 2,001 lines, deep AST, 65 KiB | rule named; no compile | Pass |
| TC-F-07 | 03a, 04n | sample rule violations, L-02 | refused, nothing stored | Pass |
| TC-F-08 | 02g | six submissions | sixth `HELPER_LIMIT` | Pass |
| TC-F-09 | 05a, 05b, 05c, 05e, 08a | full flow without runtime | non-execution with gap, conclude ok, tree unchanged | Pass |
| TC-F-10 | 11a | host register/conformance as never-authorized User | `NOT_AUTHORIZED`, nothing written, no trust root created | Pass |
| TC-F-12 | 07a | agent `guard record` with helper method / id / source | `RECORD_INVALID`, nothing stored | Pass |

### Structured review — host

| TC | ACs | Method | Status |
| --- | --- | --- | --- |
| TC-F-11 | 01c, 03g, 04p (skill), 05d, 08e, 10a, 10b, 10c, 10d | whitespace-normalised phrase search of frozen `SKILL.md` and `references/guard-records.md`; flow order checked by position; citations (file, line) in the summary `info.skill_citations` | Pass |

### Integration — macOS host, real Docker Desktop runtime, local image only (`evidence-host-macos.jsonl`, `evidence-host-docker-calls.jsonl`)

| TC | ACs | Steps (abridged) | Status |
| --- | --- | --- | --- |
| TC-F-20 | 11a, 11d, 08f, 04c | disposable trust store; register absent image, busybox, then `python:3.12-slim` | Pass (9 checks) |
| TC-F-21 | 11b, 04l, 08f, 11d | offline conformance suite on the real runtime (95.5 s, 64 probe containers) | Pass (11) |
| TC-F-22 | 02c, 02d, 02e | real compile probe; syntax error | Pass (7) |
| TC-F-23 | 03b, 03c, 03f, 03h, 04a, 04b, 04d, 04h, 04i, 04o, 04p, 06a, 06b, 07a, 07c, 07e, 08a, 09a, 09b, 09c, 11d | end-to-end: submit → run refused (not reviewed) → batch review → run refused (not granted) → grant (non-tty, wrong id, pty) → bad attempts → granted run (2 samples + target) → post-run acceptance → ledger → conclude (twin copy concluded too) | Pass (37) |
| TC-F-24 | 04o, 12d, 03d, 03e, 05b, 05c, 05g, 08c | new helper without grant; in-place resubmission; script edited after review; rejected helper; never-granted run; earlier ids | Pass (9) |
| TC-F-25 | 03b, 03e, 05b, 06a | never-matching script | Pass (6) |
| TC-F-26 | 07b, 07g | 5 target-only result faults (batch of 5) | Pass (7) |
| TC-F-27 | 07g, 04m, 04l, 04k | wrong rule, path outside manifest, stdout flood, 700 MiB allocation, 3 MiB results write | **Fail** (6/7: results-size limit named "tmp limit reached") |
| TC-F-37 | 04k, 07g | 1.5 MiB result, 501 findings, 201-char title, 2,049-byte notes, scanned path outside manifest | Pass (7) |
| TC-F-28 | 12a, 12b, 12c, 07f, 07a, 07d | adversarial file name/content, injected script comments, fake states, token built at run time; twin with confirmed `finding` subject | Pass (9) |
| TC-F-29 | 07c | partial alone; partial + reading evidence; required opengrep | Pass (3) |
| TC-F-30 | 04e, 04g, 06b | 1-minute budget, busy target | Pass (5) |
| TC-F-31 | 04g | pause, then submit / run / attempt | Pass (3) |
| TC-F-32 | 04f, 04h | cancel while the target container runs | Pass (4) |
| TC-F-33 | 04i, 04j | target modified / replaced by a symlink after open | Pass (4) |
| TC-F-34 | 04b, 04c, 11c, 11e | image reported missing; inspect reports network `bridge` / PIDs 65; conformance record edited; runtime CLI bytes changed; restore | Pass (7) |
| TC-F-35 | 11f | fake runtime CLI on PATH, conformance | Pass (1) |
| TC-F-36 | 08b, 08d | cleanup/keep/release on a copy; help texts; egress; network mode | Pass (5) |

Run-wide (summary record): 2,525 runtime calls, 236 container creates — all `--network none` and `--pull=never`; 0 pull/build/load/import/push/daemon/context calls; no labelled container or volume left.

### Integration (CLI) — Linux container, Maintainer paths and non-execution (`evidence-container-linux.jsonl`)

| TC | ACs | Status |
| --- | --- | --- |
| TC-F-40 | 11a, 11d, 05a — `auth init` in a disposable container HOME; Maintainer register/conformance without runtime CLI → `HELPER_RUNTIME_UNAVAILABLE` "never installs, configures, pulls or builds"; non-Maintainer `NOT_AUTHORIZED`; nothing written | Pass |
| TC-F-41 | 05a, 05b, 05c, 05e, 08a — full non-execution flow | Pass |
| TC-F-42 | 01a | Pass |
| TC-F-43 | 02d, 02f | Pass |

The container also produced the seed project (knowledge R1/R2 + saved scope, `sha256:d961a5ee…`) used by the host cases.

### Delivered tests (frozen, corroborating) and regression

| TC | Scope | Result | Status |
| --- | --- | --- | --- |
| TC-F-50 | `tests/helpers` default (fake runtime, orchestration) | 349 passed, 4 skipped (the opt-in real tests), exit 0 — `evidence-delivered-helpers-default.log` | Pass |
| TC-F-51 | `tests/helpers/test_helper_conformance_real.py` with `SECURE_CODE_HELPER_REAL=1` (real runtime, local image) | 4 passed (11b suite, 04l probes, M5 P-13b, full flow with real conformance → `accepted_full`, C1 `met`, no leftovers), exit 0 — `evidence-delivered-helpers-real.log` | Pass |
| TC-F-52 | frozen full suite (diagnostic, reused from the earlier worker on the same frozen tree; start stamp 04:52Z is the script start, end 12:26Z after 53 min of wall time — the gap is not explained by the log and is disclosed) | 3,233 passed, 0 failed, 9 skipped, 23 deselected, exit 0 — `evidence-full-suite.log`; the 9 skips are listed by `evidence-skip-reasons.log` | Pass |
| TC-F-60…73 | delivered acceptance runners, host mode, frozen copy | see Regressions | 10 Pass, 4 Partial |

**9 versus 8 skipped (TC-F-52).** The implementation report's final full suite had 3,234 passed / 8 skipped. The 9 skips at the frozen revision are: 4 opt-in real-runtime helper tests, 2 "file system rejects non-UTF-8 names" (macOS APFS), 1 "delete has no append step", 1 "conditional on FEATURE-001-E" — the same 8 — plus `tests/adapters/test_trivy_units.py::test_07a_validation_record_complete_and_bound_to_driver`, which skips because a `git archive` of the toolkit has no `x-ipe-docs/` beside it. Run separately with a copy of `x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/tool-validation` (tree hash `b4dc5b7a…`) beside the frozen toolkit (removed afterwards) it **passed** (1 passed). 3,233 + 1 = 3,234, matching the implementation baseline; not a 002-F test.

## Test Execution Summary

| Test case(s) | ACs | Type | Status | Evidence |
| --- | --- | --- | --- | --- |
| TC-F-01…10, 12 | 01a, 01b, 01d, 02a, 02b, 02d, 02f, 02g, 03a, 04j, 04n, 05a…05c, 05e, 06c, 07a, 08a, 11a | integration (CLI, host, no runtime) | 11 Pass | `evidence-host-macos.jsonl` |
| TC-F-11 | 01c, 03g, 04p, 05d, 08e, 10a…10d | structured-review | Pass | idem |
| TC-F-20, 22…26, 28…37 | see map | integration (CLI, host, real runtime) | 16 Pass, 1 Fail (TC-F-27) | idem + `evidence-host-docker-calls.jsonl` |
| TC-F-21 | 11b, 04l, 08f, 11d | integration · conformance (real runtime) | Pass | idem |
| TC-F-40…43 | 01a, 02d, 02f, 05a…05c, 05e, 08a, 11a, 11d | integration (CLI, container) | 4 Pass | `evidence-container-linux.jsonl` (4/4, 35 checks) |
| TC-F-50 | corroborating, all ACs | unit / integration (fake runtime) | Pass | `evidence-delivered-helpers-default.log` |
| TC-F-51 | 11b, 04l, full flow | integration · conformance (real runtime) | Pass | `evidence-delivered-helpers-real.log` |
| TC-F-52 | regression (diagnostic) | integration (full suite) | Pass | `evidence-full-suite.log`, `evidence-skip-reasons.log` |
| TC-F-60…73 | regression | integration (delivered runners) | 10 Pass, 4 Partial | `regression-*.jsonl` |

## Execution Results

**Execution:** 2026-10-24 21:39–23:00 (UTC+8) by this resumed worker; official runs: container 14:06Z, host (final) 14:44:46Z–14:52:16Z, delivered helper tests 14:15Z–14:36Z, regressions 14:36Z–14:37Z and 002-G seeds/regression (about 14:39Z–14:41Z), skip probe 14:41Z–14:44Z. A first official host run (14:06:47Z–14:14:15Z, 28/29) was superseded by the final run after TC-F-12 and one 06a check were added; its only failure was the same TC-F-27 check.
**Environment:** see Prerequisites.

| Type | Total planned | Passed | Failed | Blocked | Partial / Not run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 (no UI) | — | — | — | — |
| backend-api | 0 (no API) | — | — | — | — |
| unit | 1 (TC-F-50) | 1 | 0 | 0 | 0 |
| integration | 49 (28 host CLI incl. 17 real-runtime + 2 conformance + 4 container + 1 full suite + 14 regression) | 44 | 1 | 0 | 4 Partial |
| structured-review | 1 (TC-F-11) | 1 | 0 | 0 | 0 |
| **TOTAL** | **51** | **46** | **1** | **0** | **4** |

Pass rate = 46 / 51 planned = **90.2 %** (one denominator: all planned cases; Partial counts as not passed). AC tally: 73 / 74 active ACs Pass, 1 Fail. Counts are diagnostics, not goal achievement or stakeholder impact.

### Failures / Blockers / Disclosures

| Item | Expected versus actual | Evidence | Disposition |
| --- | --- | --- | --- |
| **D-1 (AC-002F-04l, TC-F-27)** | A helper that writes 3 MiB into `/results/result.json` (results area 2 MiB): expected a failed method **naming the results-size limit**; actual `outcome: failed`, `limit: tmp`, reason "tmp limit reached" (stderr `OSError: [Errno 28] No space left on device` in `json.dump(doc, out)` on the results file). The static rules forbid any helper write to `/tmp`, so a helper ENOSPC is almost always the results area. Cause: `execute_io.ERRNO_HINTS` maps every `ENOSPC` to `tmp`; design §9 classifies "`ENOSPC` on `/tmp`" only. Safety holds (failed method, nothing over the limit kept; conformance P-13 proves enforcement) — the defect is the reported limit name | `evidence-host-macos.jsonl` TC-F-27, `info.results_b` | **Fail**, minor. Proposed fix for the owner (not applied — acceptance grants no code change): classify ENOSPC by the failing path (results vs `/tmp`) or report "results area limit (L-08)" when the results volume is full, plus a regression test |
| Earlier worker's container evidence (13:02) | 2/4 Pass: TC-F-41 and TC-F-43 failed against a then-stale runner (the AST-depth fixture used parentheses, which create no AST nesting; corrected to nested lists 13:09) | superseded by the 14:06Z container run (4/4) | Runner error, not product |
| Debug-phase runner corrections (scratch runs, not evidence) | Test-authoring errors fixed before the evidence runs, never by relaxing an AC: result-fault scripts first opened the results file twice (static rule `results_handle` refused them — correct product behaviour); a fixture file name contained `/`; `egress` is a dict of lists; run staging lives in `<run>/helper-stage-*`; the ageing edit must also touch the report JSON (002-A precedent); target-change ordering — a target changed after the review invalidates the review first (002-A review binding), so 04i's "target changed since open" reason is exercised with the Reviewer reviewing the changed bytes; the 03b state name follows the design (`blocked: samples_mismatch`, shown "samples failed") | `dev/` scratch folders (session) | Not failures |
| Fault injection | 04b/04c/11c were exercised by making the real runtime CLI report a deviating inspect field / a missing image (wrapper control file) or by changing the CLI bytes (runtime identity) — the runtime itself was never misconfigured | TC-F-34 | Disclosed method |

### Regressions

| TC | Runner (host mode, frozen copy) | Now | Baseline (own evidence) | Status | Note |
| --- | --- | --- | --- | --- | --- |
| TC-F-60 | 001-A | 12/12 (59 checks) | 12/12 | Pass | statuses equal |
| TC-F-61 | 001-B | 1/1 | 1/1 | Pass | |
| TC-F-62 | 001-C | 1/1 | 1/1 | Pass | |
| TC-F-63 | 001-D | 2/2 | 2/2 | Pass | |
| TC-F-64 | 001-F | 2/2 | 2/2 | Pass | |
| TC-F-65 | 001-G | 3/4 | 4/4 | Partial (expected change-set pin) | TC-G-33 compares the delivered files with the **pre-001-G** step-0 baseline ("changed files = exactly cli.py, SKILL.md, cli-contract.md…", "Guard/Copilot packages unchanged"). The frozen tree differs from the 001-G delivery only by the 002-F files (14 changed, 77 added; `regression-delta-since-001G.txt`, every changed file listed in the TASK-085 report). The implementation updated the equivalent delivered unit tests (DAO-005 follow-up); this acceptance runner still pins the old bytes. Not a behaviour regression |
| TC-F-66 | 002-A | 2/2 | 2/2 | Pass | |
| TC-F-67 | 002-B | 2/2 | 2/2 | Pass | |
| TC-F-68 | 002-C | 2/2 | 2/2 | Pass | CR-077 coverage path also proven by TC-F-23/26 |
| TC-F-69 | 002-D | 1/2 | 2/2 | Partial (environment) | TC-H-01 needs the container-made Trivy handoff; the B17 assets (real Trivy binary, loopback registry volumes) were removed — same result as the 002-G acceptance precedent (TC-R-04); TC-D-19 Pass. 002-D container regression not run (host only) |
| TC-F-70 | 002-G (container mode, seeds) | 23/24 (182 checks) | 24/24 | Partial (expected change-set pin) | run against the frozen copy with a fresh uv cache copy and read-only `og-validate`; TC-G-23 checks that SKILL.md is "the pre-002-G file + one added section" — 002-F legitimately adds step 5c and edits steps 3/5 (76 diff lines) |
| TC-F-71 | 002-G (host, seeds from TC-F-70) | 22/23 (174 checks) | 23/23 | Partial (expected change-set pin) | same TC-G-23 |
| TC-F-72 | 003-A | 2/2 | 2/2 | Pass | |
| TC-F-73 | 003-B | 24/24 (350 checks) | 24/24 | Pass | |

All other cases have statuses identical to their own acceptance evidence. No behaviour regression was found.

### Engineering Delivery versus Stakeholder Outcome

| Goal | Delivery evidence / state | Outcome scenario / observation | Outcome state |
| --- | --- | --- | --- |
| G-02.1, G-02.2, G-02.3, G-02.5, G-02.6, G-02.7, G-02.8 | all mapped ACs Pass | executed on fixture projects only | not measured |
| G-02.4 | 15/16 of 04a…04p Pass + 06a, 06b, 11a…11f Pass; **04l Fail (limit misnamed)** | real runtime enforced every limit (conformance + real runs) | not measured |
| G-02 | **Engineering delivery: blocked by D-1 (one clause of AC-002F-04l)**; every other active AC verified at the frozen revision, including the real-runtime path end-to-end with Reviewer acceptance (`accepted_full`, `accepted_partial`) | no live developer session observed | **Stakeholder outcome: not measured** |

### Refactor / Closing Recommendation and App Gates

Delivery is not complete while D-1 stands: the owner decides between a bug fix (small, in `guard/helpers/execute_io.py` classification + test; then re-run TC-F-27 and TC-F-21/51) or an explicit DAO/human acceptance of the misnamed limit. Refactor need: none evidenced by acceptance. Original conditional successors retained for the owner: `x-ipe-task-based-code-refactor` (refactor for quality) / `x-ipe-task-based-feature-closing` (close if no refactoring needed) — closing is not supported until D-1 is resolved; any mandatory app gate stays with the owner.

### Honest Limits

- **One runtime only:** Docker Desktop 29.7.2 on macOS 26.6.2 arm64 (LinuxKit kernel). Linux hosts (native Docker/rootless), x86-64, and Podman were **not run**; Windows is a non-execution platform only (not run). The conformance record is runtime-specific by design.
- Local images only (`python:3.12-slim`); no image outside CPython 3.10–3.13 exists locally, so the "outside L-12" refusal (02c, 11a) is evidenced by the delivered fake-runtime tests only; nothing was pulled.
- "A runtime ignoring a limit fails that probe" (11b), every single 04b field, the copy-time swap race (04j), the execution-time L-02/L-05 re-check (04n) and JSON depth (07g) cannot be produced black-box on a conforming runtime; they rest on the delivered fake-runtime tests (TC-F-50) plus the black-box samples listed.
- Maintainer steps on the host used the library seam with a disposable trust store (same service functions as the CLI); the Maintainer CLI itself was exercised in the Linux container without a runtime. The grant was typed through a pseudo-terminal by the runner — exactly the cooperative-consent limit the feature discloses.
- Retention ageing edits `ended_at` in copies (002-A precedent); the 09c twin is a byte copy concluded separately.
- TC-F-50/51 execute implementer-authored tests (corroborating); the independent evidence is the black-box runner. TC-F-52 is reused diagnostic evidence from the earlier worker on the identical frozen tree.
- Regression runners ran in host mode (plus the 002-G container mode needed for its seeds); other container modes were not run.
- Stakeholder benefit (G-02 "real gaps checked without unsafe ad-hoc code") is not measured.

### Cleanup

Docker objects after the work equal the pre-run baseline (containers, volumes, networks, images): the volume `fat-uv-cache-002f` (created by the earlier worker as a copy of the seed) was removed; seed volumes `fat-uv-cache-003b` and `og-validate` were only mounted read-only. No toolkit-labelled container or volume remained after any case.

## Revision Binding and Files

- Frozen tree file-list hash (sorted `shasum -a 256` list, `.venv`/caches excluded): start `f7a155a4e7089a36f20cae746af43523ea4907d8f9a7f51ef138410bd4c13589` (earlier worker; equal to a fresh `git archive` of `73fe2dc`), end `f7a155a4e7089a36f20cae746af43523ea4907d8f9a7f51ef138410bd4c13589` (368 files).
- Inputs re-hashed at the end: specification `fcf0f92a…`, design `9139ed25…`, implementation report `4615d45d…`, CR-077 `d262a869…`, tools.json `6df39210…` — unchanged.
- Full runtime-call log (with `inspect` output, 5.9 MB) kept in the session evidence folder (`fat-002f/evidence-host-docker-calls.full.jsonl`); the repository copy replaces each `inspect` output by its SHA-256.

File SHA-256s are listed in the owner handoff (written after this report was finalised).
