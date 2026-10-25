# Feature Closing Report

> Feature: FEATURE-002-F — Temporary Check Scripts (helpers) (EPIC-002) · specification v1.3.3 · board record v1.0, status at closing start: Implemented (read-only)
> Task: TASK-114 (Feature Closing), lifecycle owner Sage, closing worker · Date: 2026-10-25 · free mode, workflow N/A · interaction mode as delegated (`dao-represent-human-to-interact`; no within-skill question arose, no human waited for, no new DAO consultation)
> Closure scope: engineering delivery only. This worker made no board, Git, memory, push, PR or release change. Human B8 allows exact-path local commits by the owner only.
> Delivery: **verified engineering delivery** at implementation `73fe2dc` plus the D-1 fix `c6c1ad7` (toolkit tree at `HEAD` = `c6c1ad7`). Specification `fcf0f92a…`, design `57194cc4…` (v1.2.1, errata E1–E4, honest-limit note, §9.3 TASK-112 erratum). **74/74 active ACs pass.** AC-002F-05f is **not applicable** (human B12 = A) and is never counted as passed. AC-002F-04l failed at acceptance (D-1); that Fail is kept in history, and the D-1 re-run passes. **Stakeholder outcome: not measured.**

## Inputs Re-verified at Closing (SHA-256)

| Input | Cited by acceptance / bug fix / owner | At closing | Match |
| --- | --- | --- | --- |
| [specification.md](specification.md) v1.3.3 (75 AC IDs: 74 active + 05f N/A) | `fcf0f92a…` | `fcf0f92a2fb62d2030c639baa7d05e2cc65febb5e5e0a25e6217743553b33ae3` (same at `73fe2dc`, `c6c1ad7`, `HEAD`) | yes |
| [technical-design.md](technical-design.md) at the acceptance run | `9139ed25…` | `9139ed25feda02706a3c23e4af17cff7429c0d0b56a0630484f09d73ef08eeab` (`git show 73fe2dc:` and `41bdbde:`) | yes |
| technical-design.md now | §9.3 erratum (bug-fix DAO-006 DEC-3) | `57194cc44e68a12e9f539667ea1c577254119c804d723632f712bb9fad59f43a`; `41bdbde → c6c1ad7`: 2 lines added, 0 deleted (§9.3 step 5 erratum + Change Log row) | additive only |
| [implementation-report-TASK-085.md](implementation-report-TASK-085.md) | `4615d45d…` | `4615d45dba99373a8238cc81c185dabeb8d3892b338766a1679acfbca046ea2a` | yes |
| [acceptance-test-cases.md](acceptance-test-cases.md) | `e58c0bc4…` (TASK-111 end, `bc165eb`) → `a435ae10…` (bug report) | `a435ae1030a544f08a998161b585864ba4a3f32285f1f085fb821d57dd8e388d`; `bc165eb → c6c1ad7`: 19 lines appended, 0 deleted ("D-1 Re-run") | yes; original Fail unchanged |
| [bug-report-TASK-112.md](bug-report-TASK-112.md) | `7e062e35…` (144 lines, read by bug-fix DAO-006) | `8b2af8e3f056674b7f939983072b3b139f0e9485f72d13e9bd7b6c4ff795368d` (150 lines; the owner addendum appended) | appended only |
| CR [CR-TASK-077-helpers-coverage.md](../FEATURE-002-C/CR-TASK-077-helpers-coverage.md) | `d262a869…` | `d262a869fc0f70cc…` | yes |
| `x-ipe-docs/config/tools.json` | `6df39210…` | `6df39210e203507a…` | yes |
| Guard `SKILL.md` / `references/guard-records.md` | `81733a4d…` / `766b8def…` | same at `73fe2dc` and `c6c1ad7` | yes |
| `human_decisions.md` (B8, B12; 2026-10-24 12:24 P-01; local-only log) | `ae80d5c1…` | `ae80d5c102899012630f58f32e1c143157bbb9ebad92dcb3eef43b8a86ba4ae8` | yes |
| `decisions_made_code_implementation.md` (DAO-005, DAO-006) | `7a8c36ee…` at acceptance (`bc165eb`) | `fba41c0cfb27828231d1bb946a76dfda07ba336c69376fea64330aca94958de9` | appended since (later features); 002-F entries read in full |
| `decisions_made_feature_acceptance_test.md` (DAO-007) | — | `43e4b834aaa7a2967b6486c2f8e71c1b060591910806aa3d5161540e8f7b87e4` | read in full for 002-F |
| `decisions_made_bug_fix.md` (DAO-006) | — | `757e8dee06f11a613d56048fae842d2cd78368387c7b3822a5e44fde3bdab8e6` | read in full for 002-F |
| `decisions_made_technical_design.md` (DAO-014, 017, 018, 019, 023, 024; local-only log) | `7b2e4a36…` | `7b2e4a3643ca26f78413d79bb1a7a2ee16bbcb8cb154f334ebdf20fab68d8982` | yes |

**Toolkit revision binding (recomputed from `git archive`, both acceptance methods).**

| Tree | Files | `find . -type f \| LC_ALL=C sort \| xargs shasum -a 256 \| shasum -a 256` | `./` stripped, sorted by path | Cited by |
| --- | --- | --- | --- | --- |
| `73fe2dc` (git tree `c2c16d89…`) | 368 | `f7a155a4e7089a36f20cae746af43523ea4907d8f9a7f51ef138410bd4c13589` | `08aaddde406704c9a33e397130a4fda16480abbef96689ac4254312c1fa02d2f` | acceptance TASK-111 (start = end); implementation report §12.5 final list |
| `c6c1ad7` (git tree `e8ca9ec0…`) | 415 | `e8a8bc44e52d49a696f8a5e7363c58a225bd662ca880826dd413cf744ecd15f8` | `80b7bd54b665091d821045fea5346158dfab9e1e8336654b1e3519ad339c3050` | D-1 re-run frozen copy (start = end); bug report |

- `git diff --stat c6c1ad7 HEAD -- ai-secure-code-toolkit` is empty; the toolkit tree object is `e8ca9ec0…` at both. `HEAD` adds only two commits that untrack board lock files.
- `41bdbde → c6c1ad7` toolkit delta is exactly 4 files, all 002-F-owned: `guard/helpers/execute_io.py` `b8e3948b… → 9b427c83…`, `guard/helpers/results.py` `786822ee… → 17d84545…`, `tests/helpers/test_helper_execute.py` `→ 9aead73f…`, `tests/helpers/test_helper_results.py` `→ 580c05fb…` (all equal to the bug report's "after" values).
- `73fe2dc → 41bdbde` is FEATURE-001-E (its own rulings and acceptance). It touches shared files (`cli.py`, `status.py`, `carhelp.py`, `drafthelp.py`) and 002-F's `tests/helpers/test_helper_boundary.py` (001-E's later-features allowlist, DAO-007 code implementation). These are not 002-F changes and are outside this closing's byte-pin set (see "Regression partials").

**Live working tree not used.** Another worker edits `ai-secure-code-toolkit/` for TASK-110. This worker neither executed nor hashed it. Everything here is bound to `git archive 73fe2dc` / `git archive c6c1ad7` copies in the session scratch folder (removed after use). At the end of closing, read-only `git status` shows uncommitted TASK-110 edits to `tests/drafting/test_draft_cli_approve.py` and to 002-F's `tests/helpers/test_helper_boundary.py`, plus `decisions_made_bug_fix.md`. They are not part of this closing (see Residual Follow-ups 2).

**Closing semantic check (not a re-run).**
- `evidence-host-macos.jsonl` (`f0b3c6f2…`): 30 TCs, 29 Pass, 226 checks. The only non-pass is TC-F-27 with exactly one failed check, "04l/04k results over L-08 … [failed: tmp limit reached]" (recorded `limit: tmp`, diagnostics 243 bytes).
- `evidence-host-macos-d1.jsonl` (`cb3f8ef8…`): TC-F-20 Pass (9), TC-F-21 Pass (11), TC-F-27 Pass (7). The same case now records `outcome: failed`, `limit: results`, reason "results area limit (L-08)", diagnostics 243 bytes. Conformance record `cf-f7bf9244c7fd7e79`, all 20 probes P-00…P-18 + P-13b `true`, 95.8 s, identity client/server 29.7.2, API 1.55, linux/aarch64.
- `evidence-container-linux.jsonl` (`187ded44…`): 4/4, 35 checks.
- Runtime-call logs: `evidence-host-docker-calls.jsonl` (`1d1f9073…`) 2,525 calls, 236 `create`; `-d1.jsonl` (`fb1b91cd…`) 1,050 calls, 102 `create`. Every `create` carries `--network none` and `--pull=never`. Subcommands are only `inspect`, `kill`, `create`, `start`, `rm`, `volume create/inspect/rm/ls`, `cp`, `ps`, `version`, `info`, `image inspect` and read-only `context inspect` (§8.1 discovery). No pull, build, load, import, push or context change.
- Delivered tests: default `349 passed, 4 skipped`; real `4 passed` (`00b54102…`); D-1 real `4 passed` (`2c42fbf5…`); full suite at `73fe2dc` `3233 passed, 9 skipped, 23 deselected`, exit 0 (`a71bb0e8…`), plus the separately run 9th skip (`1 passed`).
- Runner unchanged: `blackbox.py` `e0c255ca…` is identical before and after the D-1 re-run; `run-d1.py` `43456da2…` imports it.
- Environment re-read (read-only `docker version` / `image inspect`): Docker Desktop client/server 29.7.2, API 1.55, linux/arm64; `python:3.12-slim` = `sha256:a6e34c59…`; macOS 26.6.2 arm64; no toolkit-labelled container or volume present. Same as the runs.
- Every AC ID in the specification except 05f (N/A) and 04n is tagged on a black-box TC record. 04n is exercised by checks inside TC-F-05 ("02b L-05 file count (2001) refused") and TC-F-07 ("03a over L-02 count/size refused"), tagged with their primary ACs, plus the delivered test `test_04n_limits_before_container` (present at `c6c1ad7`). This matches the acceptance map; it is a tagging detail, not an evidence gap.

## Goal / Subgoal Frame

From the specification § Goal / Subgoal Coverage and User Stories US-01…US-06. The parent is requirement G-02 / FR-19 (A-13…A-17; A-18 by refinement DAO-007).

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Delivery Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-02 | G-02; FR-19 | Developer, Maintainer, upstream agent | Real coverage gaps checked without unsafe ad-hoc code; no misleading "pass" from a helper that was not run, not reviewed, merely exited cleanly or reported no findings | All 74 active ACs pass (below) | not measured |
| G-02.1 | A-13 (US-01) | Developer | Helper only as a gap-bound auxiliary method of one planned check | 01a…01d, 06c pass | not measured |
| G-02.2 | A-14 layer 1 (US-02) | Developer, Maintainer | Declared, syntax-checked by the image's own interpreter, static rules (defence in depth) | 02a…02g pass | not measured |
| G-02.3 | A-14 layer 2, B12 = A, CR-077 (US-02) | Developer | Independent read-only Reviewer with known samples | 03a…03h pass | not measured |
| G-02.4 | A-15, A-16, workflow DAO-001 (US-03) | Owner | Execution only after a typed user grant, on a conformance-proven runtime, under inspect-verified limits inside the 002-C budget and cancel | 04a…04p (04l via the D-1 re-run), 06a, 06b, 11a…11f pass | not measured |
| G-02.5 | A-16 (US-04) | Developer | Non-execution with a reported gap, never a host fallback | 05a…05e, 05g pass; 05f N/A | not measured |
| G-02.6 | A-16, FR-22 (US-05) | Report reader | Labelled, snapshot-bound, auditable helper results under unchanged 002-A rules | 07a…07g, 09a…09c pass | not measured |
| G-02.7 | A-17, A-18 (US-06) | Maintainer | Run-only artifacts; Maintainer-registered image | 08a…08f pass | not measured |
| G-02.8 | A-16 | Owner | Untrusted content cannot steer scope, policy, ledger or report | 12a…12d, 03g, 10d pass | not measured |

All eight subgoals are **all-required** (spec "Contribution / Selection"). **Selected means (bounded, not backlog):**
- one Docker- or Podman-compatible CLI, with a Maintainer-registered local image (CPython 3.10–3.13), never pulled or built;
- an offline conformance suite per runtime identity;
- an inspect-verified canonical configuration with a trusted PID-1 launcher;
- a link-free read-only snapshot bound to the target version;
- typed pseudo-terminal consent (cooperative, not a security boundary);
- batch `helper` Reviewer subjects through the 002-C CR-077 coverage item.

Constraints and non-goals kept: not formal knowledge; not the FR-29 sandbox; no new network, model, keys or services; Guard never fixes.

**Human-confirmed intent (12:24, 2026-10-24).** The human confirmed DAO-005's clarification of AC-002F-11b: helpers require "network disabled, proven by a stronger probe". This replaced the proxy "no interface other than loopback", which cannot hold on Docker Desktop because LinuxKit creates down, address-less tunnel devices in every namespace. Spec v1.3.3 and design erratum E2 implement it. The real P-01 passes with all evidence items, at acceptance and again in the D-1 re-run.

**Qualitative scenario** (spec "Success Evidence"), executed as **delivery checks only** on fixture projects:
- on a conformance-passing local runtime with a registered local image, a gap check's helper detects its positive sample and leaves its negative sample clean (TC-F-23);
- after the typed grant it runs on a link-free read-only snapshot, and its labelled result appears in the report (TC-F-23);
- with no runtime, no conformance or no grant, the helper stays a failed auxiliary method with a reported gap and no execution (TC-F-09/41, TC-F-24, TC-F-34).

No Developer, Maintainer, Owner or agent session was observed.

## Goal → AC → Evidence (74/74 active)

Per-AC original assertions and actual results are in the acceptance report's [Full Acceptance / Evidence Map](acceptance-test-cases.md). This table reuses them.

Abbreviations:
- **H** = macOS host black-box, no runtime CLI, never-authorized User.
- **R** = macOS host black-box on the **real Docker Desktop runtime**, local image only.
- **C** = Linux container black-box (Maintainer CLI paths, non-execution).
- **S** = structured skill-text review.
- **D** = frozen delivered tests, fake runtime (corroborating).
- **DR** = delivered opt-in real-runtime tests.
- **R-d1** = D-1 re-run at `c6c1ad7` (`e8a8bc44…`).

Original test types are kept from the specification: 60 Integration · black-box, 3 Unit · black-box (02d, 02f, 07g), 9 Unit · skill-text (01c, 03g, 04p, 05d, 08e, 10a…10d), 2 Integration · conformance (04l, 11b), and 05f Not applicable.

| Subgoal | Spec AC group (all IDs) | Acceptance evidence | Delivery |
| --- | --- | --- | --- |
| G-02.1 | 01 When a helper may be proposed: 01a, 01b, 01c, 01d (+ 06c) | H: TC-F-01, 02, 03; C: TC-F-42; S: TC-F-11 (Guard `SKILL.md` `81733a4d…` step 5c) | Pass (4/4) |
| G-02.2 | 02 Declaration, syntax, static checks: 02a, 02b, 02c, 02d, 02e, 02f, 02g | H: TC-F-04…08; R: TC-F-22 (real compile probe in CPython 3.12.15, `--network none`), TC-F-20/34 (refusals); C: TC-F-43. The outside-L-12 image case is D only (no such local image; nothing pulled) | Pass (7/7) |
| G-02.3 | 03 Samples and independent review: 03a, 03b, 03c, 03d, 03e, 03f, 03g, 03h | H: TC-F-07; R: TC-F-23 (batch `reviewer` attempt `covers.helpers`; post-run acceptance → `accepted_full`), 24, 25 (`samples_mismatch`, no target container), 26/27/37 (batch of 5); S: 03g | Pass (8/8) |
| G-02.4 | 04 Authorization and execution under enforced limits: 04a, 04b, 04c, 04d, 04e, 04f, 04g, 04h, 04i, 04j, 04k, **04l**, 04m, 04n, 04o, 04p | R: TC-F-23 (grant, canonical create flags on all 236 creates, 108 stored fields = inspect), 30 (L-10 capped, `time limit (L-10)` after 54.2 s), 31, 32 (cancel → `termination: confirmed`), 33 (target changed / symlink), 34 (inspect deviation → no start, field named), 37 (L-08 result size), 21 (conformance P-09…P-15, P-17); H: TC-F-05, 07; S: 04p. **04l: Fail at `73fe2dc` (D-1), Pass in R-d1** (TC-F-21 11/11, TC-F-27 7/7, TC-F-51 4/4). D for the copy-time swap race (04j), the execution-time re-check (04n) and every single 04b field | Pass (16/16) |
| G-02.5 | 05 Non-execution and gap reporting: 05a, 05b, 05c, 05d, 05e, 05g; 05f N/A | H: TC-F-09; C: TC-F-40, 41; R: TC-F-24, 25, 34; S: 05d | Pass (6/6); 05f N/A (B12 = A) |
| G-02.4 / G-02.1 | 06 Budget, attempts, model usage: 06a, 06b, 06c | R: TC-F-23 (own `helper` attempt per execution, re-execution `extra: 1`), 25, 30 (consumed seconds ≥ run seconds; `not_applicable_attempts`); H: TC-F-03 | Pass (3/3) |
| G-02.6 | 07 Result handling and labelling: 07a, 07b, 07c, 07d, 07e, 07f, 07g | R: TC-F-23 (`runtime` evidence, method `helper.yaml-debug`, script and manifest digests; both reports labelled "temporary, run-only — not a formal rule or Adapter"), 26 (5 result faults → failed), 28 (masking; unreviewed finding not Fail), 29 (partial coverage → `unconfirmed`, names the uncovered file), 27/37 (schema violations); H: TC-F-12 (agent records with helper names → `RECORD_INVALID`); D: JSON depth (07g) | Pass (7/7) |
| G-02.7 | 08 Retention, no promotion, no publication: 08a, 08b, 08c, 08d, 08e, 08f | H: TC-F-09; C: TC-F-41; R: TC-F-20/21 (only `.x-ipe/private/secure-code/helpers/` changed), 24, 36 (cleanup/keep/release; help texts; egress empty); S: 08e | Pass (6/6) |
| G-02.6 | 09 Auditability: 09a, 09b, 09c | R: TC-F-23 (19 ordered events; stored config = runtime inspect; twin conclusion identical) | Pass (3/3) |
| G-02.1 / G-02.5 / G-02.8 | 10 Skill package guidance: 10a, 10b, 10c, 10d | S: TC-F-11 (11 flow steps in order; TASK-077 dependency; host session; no-proof; untrusted data) | Pass (4/4) |
| G-02.4 | 11 Image registration and conformance: 11a, 11b, 11c, 11d, 11e, 11f | R: TC-F-20 (digest = local image id; CPython 3.12.15; `GPG_KEY` labelled public fingerprint, E1), 21 (20/20 probes; P-01 per v1.3.3), 34 (CLI bytes changed → no valid record; edited record → absent), 35 (fake CLI → no record); H: TC-F-10; C: TC-F-40; DR: TC-F-51; R-d1: TC-F-21 again 11/11 | Pass (6/6) |
| G-02.8 | 12 Untrusted content: 12a, 12b, 12c, 12d | R: TC-F-28 (adversarial names escaped; injected "met/Pass/accepted" text ignored; create argv identical), 24 (in-place change refused) | Pass (4/4) |

Totals: **74 active AC rows: 74 Pass, 0 Fail, 0 Not executed; 05f N/A.** 04l passes on the D-1 re-run evidence. Its original Fail stays in the acceptance report.

### D-1 history (AC-002F-04l)

| Step | Revision / evidence | Result |
| --- | --- | --- |
| Acceptance TASK-111 | `73fe2dc` / `f7a155a4…`; TC-F-27 in `evidence-host-macos.jsonl` | **Fail.** A 3 MiB write into `/results/result.json` (area 2 MiB) gave `failed`, `limit: tmp`, "tmp limit reached". Safety held: the method failed and nothing over the limit was kept. Cause: `execute_io.ERRNO_HINTS` mapped every `ENOSPC` to `tmp` |
| Ruling, acceptance DAO-007 | — | Option (a), bug fix. Option (b), accepting the wrong name, was rejected: a failed AC clause is not waived by representative approval |
| Bug fix TASK-112 | `bug-report-TASK-112.md` | RED (fake runtime): 2 behavioural failures (`'tmp' == 'results'`) plus 9 new-seam `AttributeError`s; GREEN 12 passed. Helpers suite 361 passed / 4 skipped. Full suite 3513 passed / 1 failed (flaky `test_02e`) / 7 skipped |
| D-1 re-run | `c6c1ad7` toolkit / `e8a8bc44…`; `evidence-host-macos-d1.jsonl`, `evidence-delivered-helpers-real-d1.log` | **Pass.** TC-F-27 7/7 (`limit: results`, "results area limit (L-08)", nothing kept); TC-F-21 11/11 (20/20 probes); TC-F-51 4/4; 102 creates, all `--network none`; no leftovers |
| Independent review, bug-fix DAO-006, design | bug report owner addendum; design §9.3 erratum | Review **PASS** (no findings). DEC-1/2/4 approved; DEC-3 applied as the §9.3 step 5 erratum and a Change Log row |

### Logical TCs (diagnostic, from the acceptance report)

| TC | State | Closing note |
| --- | --- | --- |
| TC-F-01…12, 20…26, 28…37, 40…43, 50…52 | Pass | TC-F-52 (full suite at `73fe2dc`): 3233 passed, 9 skipped (the 9th, a 002-D test needing `x-ipe-docs/` beside the archive, passed separately). Its start/end stamp gap is disclosed in the acceptance report |
| TC-F-27 | Fail at `73fe2dc` → **Pass** at `c6c1ad7` (R-d1) | D-1 above |
| TC-F-60…64, 66…68, 72, 73 | Pass | Statuses equal to each runner's own baseline |
| TC-F-65 (001-G TC-G-33), TC-F-70/71 (002-G TC-G-23) | **Partial (expected 002-F change)** | Byte pins, justified file by file below (acceptance DAO-007). Never counted as passed |
| TC-F-69 (002-D TC-H-01) | **Partial (environment)** | The B17 container-made Trivy handoff and assets were removed; no new download (code-implementation DAO-006). TC-D-19 passes; the 002-D container regression was not run |

pass_rate at acceptance = 46/51 = 90.2 %. After the D-1 re-run, TC-F-27 passes, so 47/51 logical TCs pass and 4 are Partial (diagnostic only; not a goal measure).

## Regression Partials — Byte Pins, File by File (acceptance DAO-007 condition)

**Method.** Independent `git diff --name-status` over the toolkit:
- `93e3eaa` (001-G acceptance revision) = `f18423e` = `230aa49`: the same toolkit tree `9a1bda21…`, i.e. the post-001-G and post-002-D tree that these runners last passed on.
- `230aa49 → 73fe2dc`: exactly **14 modified + 77 added, 0 removed**.

This equals `regression-delta-since-001G.txt` (`c1e0383b…`). The runners themselves only report what changed against older baselines; they cannot tell which feature changed it.

**001-G TC-G-33** failed 3 checks:
- 08a, delivered files changed versus the pre-001-G step 0 ≠ exactly 001-G's own set;
- 08a, added files beyond the drafting set;
- 08d, Guard/Copilot packages changed.

Its own `changed` list has 14 entries. Two are 001-G's own legitimate changes, unchanged since `93e3eaa`: framework `SKILL.md` and `references/cli-contract.md`. `cli.py` and `carhelp.py` are changed by both features. `drafthelp.py` and `guard_copilot_hashes.json` sit under 001-G's own added `tests/drafting/` area, so TC-G-33 does not list them as changed, but they are in the 002-F delta.

**002-G TC-G-23** failed 1 check: 01h, Guard `SKILL.md` "is the pre-002-G file plus one section". Closing check on the bytes:
- the old prefix (12,017 bytes) hashes `cdbfc5bc…`;
- the new prefix (16,160 bytes) hashes `e24862a3…`;
- the first differing byte is at offset 737;
- 002-G's own section ("## Comparing two reports" to the next level-1/2 heading or EOF, 2,128 bytes) is **byte-identical** in `230aa49`, `73fe2dc` and `c6c1ad7`.

| # | Toolkit file (framework `scripts/` abbreviated `F/`) | `230aa49 → 73fe2dc` (+/−) | Why it differs | Authority | Within closed list / ruled point? |
| --- | --- | --- | --- | --- | --- |
| 1 | `F/src/x_ipe_secure_code/adapters/__init__.py` | +10 / 0 | `reserved_helper_name`, `reserved_helper_id` (additive) | design §1.1; TD DAO-017 condition 3 | yes — closed list |
| 2 | `F/src/x_ipe_secure_code/cli.py` | +9 / 0 | new subcommands only | §1.1 | yes — closed list |
| 3 | `F/src/x_ipe_secure_code/guard/cancel.py` | +2 / 0 | `helper_report.attach` after conclude in `finalize_frozen` | §1.1 (07e) | yes — closed list |
| 4 | `F/src/x_ipe_secure_code/guard/engine.py` | +3 / 0 | the `helper` branch in `_relevant_paths` only (diff inspected; `_met`/`conclude` untouched) | §1.1; TD DAO-014 T-4 | yes — closed list (the only engine edit) |
| 5 | `F/src/x_ipe_secure_code/guard/records.py` | +14 / −1 | `_subject` first statement; `plan_rules` hooks and `gap`; reservation clauses (the one deletion is the extended import line) | §1.1; TD DAO-017 | yes — closed list |
| 6 | `F/src/x_ipe_secure_code/guard/report.py` | +12 / 0 | `helper_report.section` in `render` | §1.1 | yes — closed list |
| 7 | `F/src/x_ipe_secure_code/guard/service.py` | +6 / 0 | `record_review` `observed`/`on_recorded`; `_conclude_open` attach | §1.1 | yes — closed list |
| 8 | `F/src/x_ipe_secure_code/tools_service.py` | +14 / 0 | `register-helper-image`, `helper-conformance` | §1.1 | yes — closed list |
| 9 | `x-ipe-secure-code-toolkit-guard/SKILL.md` | +47 / −3 | §14.3: step 5c added; step 3 and 5 lines edited | §1.1; spec 10a–10d | yes — closed list |
| 10 | `x-ipe-secure-code-toolkit-guard/references/guard-records.md` | +130 / −1 | §14.4 "Temporary helper checks" | §1.1; spec 03g | yes — closed list |
| 11 | `F/tests/carriers/carhelp.py` | +21 / 0 | `ERA_001A_REMOVED` append: `# FEATURE-002-F.` plus 20 payload paths | §1.1 (the only delivered test-file edit); code-implementation DAO-005 DEC-I18 | yes — closed list and ruled point |
| 12 | `F/tests/drafting/drafthelp.py` | +21 / 0 | `NEW_PAYLOAD` + comment + the 20 002-F payload paths | code-implementation DAO-005 (1); TD DAO-023/024 | yes — ruled maintenance point |
| 13 | `F/tests/drafting/fixtures/guard_copilot_hashes.json` | +2 / −2 | Guard `SKILL.md` `4bcb188f… → 81733a4d…`, `guard-records.md` `868f2da8… → 766b8def…`; Copilot entries unchanged | code-implementation DAO-005 (1) + DAO-006 (DEC-I21) | yes — ruled maintenance point |
| 14 | `F/tests/guard/test_compare_skill.py` | +11 / −4 | `test_01h` scoped to 002-G's section (`^#{1,2} `); prefix rebaseline 12017 / `cdbfc5bc…` → 16160 / `e24862a3…`, with the reason in a comment | code-implementation DAO-005 (1) + DAO-006; TD DAO-023 corrected by DAO-024 | yes — ruled maintenance point |
| 15–34 | 20 added under `F/src/x_ipe_secure_code/guard/helpers/` (18 modules, `payload/launcher.py`, `probes/suite.probe`) | added | feature code | design §1 module layout | yes — 002-F-owned new files (the closed list governs edits outside `guard/helpers/`) |
| 35–91 | 57 added under `F/tests/helpers/` (23 test and helper modules, `fixtures/delivered_step0.json`, 33 `fixtures/pre_002f/` goldens) | added | feature tests and step-0 goldens | design §16; code-implementation DAO-005 (6) I19 | yes — 002-F-owned |

**Result: every differing file is within the closed list §1.1 or a ruled maintenance point. No defect; closing is not stopped.** The D-1 fix adds only 4 more 002-F-owned files under `guard/helpers/` and `tests/helpers/`. It does not touch Guard `SKILL.md` or any pinned file, so it cannot change these partials.

FEATURE-001-E's later changes (`41bdbde`) are not part of this set; 001-E's own acceptance must account for them.

**002-D TC-H-01** fails with `FileNotFoundError` on the container-made handoff `handoff.json`, which needs the removed B17 Trivy assets. This is an environment partial (acceptance DAO-007; same precedent as the 002-G acceptance). TC-D-19 (skill text and validation record) passes in the same run.

## Delivered-Test Maintenance Points (code-implementation DAO-005/006; TD DAO-023/024)

These are the only delivered-test edits besides the closed-list `carhelp.py` append. No assertion was weakened for the protected feature's own scope (diffs inspected).

1. `tests/guard/test_compare_skill.py`:
   - `test_01h` is scoped to 002-G's section, from "## Comparing two reports" to the next `^#{1,2} ` heading or EOF.
   - Within that span there must still be exactly one ATX heading of any level, and the command set must be exactly {`compare`, `cleanup`}.
   - The prefix hash check is kept, rebaselined 12017 → 16160 with the recorded reason. The DAO-023/024 maintenance comment is added.
2. `tests/drafting/drafthelp.py` `NEW_PAYLOAD`: +20 002-F payload paths (21 added lines with the comment), append-only.
3. `tests/drafting/fixtures/guard_copilot_hashes.json`: both Guard entries rebaselined (DEC-I21); Copilot entries untouched.
4. `tests/carriers/carhelp.py` `ERA_001A_REMOVED`: +20 paths under `# FEATURE-002-F.` (DEC-I18), append-only.
5. 002-F's own (DEC-I19): `tests/helpers/fixtures/pre_002f/`, `tests/helpers/fixtures/delivered_step0.json`, `test_helper_boundary.CLOSED_LIST`. At `c6c1ad7`, `test_helper_boundary.py` also carries 001-E's later-features allowlist (DAO-007 code implementation, 001-E's ruling).

## CR-077 Helper Path (002-C, TASK-077) — Proven Black-Box

Code-implementation DAO-006 asked that the consumed 002-C CR be proven black-box here. It is:
- TC-F-23: a batch `reviewer` attempt with `covers.helpers` = the helper ids, recorded and accepted before execution. The post-run acceptance is a re-coverage counted `extra`, and every helper attempt after a pair's first is `extra: 1`.
- TC-F-26/27/37: a batch of 5 helpers under one Reviewer attempt.
- TC-F-68: the 002-C runner passes 2/2.

No further 002-C change was made (design header; TASK-077 evidence unchanged).

## Evidence Reuse and Dependency Freshness

| Input / Boundary | At acceptance / D-1 re-run | At closing | Disposition |
| --- | --- | --- | --- |
| Toolkit, all TCs except D-1's | `73fe2dc`, `f7a155a4…` start = end | recomputed `f7a155a4…` from `git archive 73fe2dc` | **Reused.** `73fe2dc → c6c1ad7` changed only `execute_io.py` and `results.py` among 002-F product files (+ FEATURE-001-E). The `execute_io` change runs only when `limit == "tmp"` and a results volume exists (diff inspected); every other path is unchanged. Corroborated at the fixed tree by the full suite (3513 passed incl. 361 helpers tests and `test_helper_boundary.py`; 1 known flaky) |
| Toolkit, D-1 scope (TC-F-21, 27, 51; 20 as prerequisite) | `c6c1ad7`-equivalent copy `e8a8bc44…` start = end | recomputed `e8a8bc44…` from `git archive c6c1ad7`; `HEAD` toolkit tree identical | **Reused** (current) |
| Spec | `fcf0f92a…` | same | Unchanged |
| Design | `9139ed25…` | `57194cc4…` | Additive §9.3 erratum only. It describes the fixed behaviour that R-d1 verified; no Part 1 or Part 2 behaviour text changed elsewhere |
| Acceptance report / bug report | `e58c0bc4…` / `7e062e35…` | `a435ae10…` / `8b2af8e3…` | Append-only (D-1 re-run section; owner addendum) |
| Evidence files | as cited | unchanged since `bc165eb`, D-1 files added (`cb3f8ef8…`, `fb1b91cd…`, `2c42fbf5…`, `43456da2…`) | Reused; semantics re-checked above |
| Environment | Docker Desktop 29.7.2 / API 1.55, LinuxKit aarch64, `python:3.12-slim` `a6e34c59…`, macOS 26.6.2 arm64; container `fat-uv-git:py312` | Same values on read-only re-read | Unchanged; no re-run needed |
| Regression runners | `73fe2dc` only | — | Not re-run at `c6c1ad7`. The D-1 delta does not touch any file they pin or exercise outside `guard/helpers` (disclosed in the bug report) |

## Review and Documentation Delta

| Reviewer / Method | Scope | Revision / Evidence | Findings / Disposition |
| --- | --- | --- | --- |
| Independent design reviews (v1.0 FAIL → v1.1 FAIL → v1.2 PASS-WITH-NITS) | design + spec | design §21, §21.1, "Re-review Nits" | Resolved before implementation; TD DAO-017/018/019 confirmed |
| Independent code review of TASK-085 | 002-F code | **Owner-relayed** in code-implementation DAO-005 ("Code review PASS-WITH-FIXES") | Medium finding `snapshot.py:82` (entries silently omitted) fixed RED first (erratum E4). Other fixes applied |
| Independent delta re-review of TASK-085 (spec v1.3.3, P-01 probe, snapshot fix) | delta | **Owner-relayed** in code-implementation DAO-006 ("delta re-review PASS-WITH-NITS (nit → honest limit)") | Nit recorded as the owner's honest-limit note (`fib_trie` cannot show IPv4 on a down interface) |
| Independent review of the TASK-112 D-1 fix | `execute_io.py`, `results.py`, tests | bug report owner addendum: **PASS** (no findings); bug-fix DAO-006 | Applied: §9.3 erratum (DEC-3) |
| Closing self-review (this task) | AC wording vs evidence; design §9.3 and §15 vs code at `c6c1ad7`; DAO conditions; byte pins | hashes above | Observation O-1 and corrections C-1…C-4 below. None reverses an AC result |

**Review provenance.** All three code-level review verdicts are owner-recorded in DAO messages and the bug-report addendum. No standalone review artifact is kept in the repository, and no review file was present in the session `bugfix-112/` folder at closing (a transient `review*` entry was listed once, then absent). This is a provenance note, not a delivery gap. The fixed behaviour is executed end to end on the real runtime (R-d1), and the TASK-085 behaviour by the full acceptance run.

**O-1 (closing observation, test depth for AC-002F-04l naming).**
- AC-002F-04l lists memory, PIDs, open files, CPU-time-bounded wall time, `/tmp` size and results size.
- **Enforcement** of each is proven on the real runtime by the conformance probes P-09…P-15 and P-17 (TC-F-21, TC-F-51, R-d1).
- **Naming** in a helper run's failed method was produced on the real runtime for `memory`, `output`, `time` (wall) and `results`.
- `open_files` and `tmp` naming are fake-runtime orchestration tests only: `test_04l_limit_naming_fake`; `test_04l_enospc_with_room_in_results_area_names_tmp_limit`, which is the unchanged `/tmp` branch.
- The `pids` hint (`EAGAIN`) and the CPU-time reason (exit 152, "cpu time limit (L-10)") have **no test at any level** at `c6c1ad7`. The code paths exist in `execute_io._classify`/`ERRNO_HINTS`.
- Reachability: the static rules' allowed modules (`static.ALLOWED`: no `os`, `subprocess`, `threading` or `multiprocessing`) leave an accepted helper no way to create processes or threads. PIDs exhaustion by an accepted helper is therefore not producible.
- Design §9.3/§15 already makes PIDs/open-files/`/tmp` naming best-effort ("named only when stderr shows the errno; otherwise 'script error under enforced limits'").
- The acceptance accepted 04l on the specified style (Integration · conformance), and the DAO rulings settled 04l only on the results naming.
- **Disposition:** recorded limit; it does not change the 74/74 result. Optional follow-up for the owner: two fake-runtime naming tests (`EAGAIN` → `pids`, exit 152 → `time` "cpu time limit (L-10)").

**Documentation delta at closing: none made.** This worker only writes this report. Proposed corrections for the owner follow. All are append-only, change no AC or behaviour, and would change only the hash of the edited document.

| ID | Artifact | Misleading statement | Proposed correction |
| --- | --- | --- | --- |
| C-1 | acceptance-test-cases.md header "Status: **Blocked — 73 / 74**" and the D-1 re-run's last sentence ("Independent review … remain with the owner") | Correct when written. A reader of this file alone would still see 002-F as blocked | Append an owner note: "D-1 closed: independent review PASS; bug-fix DAO-006; 74/74 active ACs; see bug-report addendum and closing-report.md". The header stays untouched (history) |
| C-2 | acceptance-test-cases.md Regressions TC-F-65/70/71 | Labelled "Partial (expected change-set pin)"; the file-by-file closed-list mapping that acceptance DAO-007 conditioned on is not in that file (it points to `regression-delta-since-001G.txt` and the TASK-085 report) | Optional append: relabel as "Partial (expected 002-F change)" per DAO-007 and link this report's file-by-file table. The condition is satisfied here |
| C-3 | implementation-report-TASK-085.md §12.9 (L460) | "the independent delta review required by DAO-005 is pending (owner)" | Append a dated note: delta re-review PASS-WITH-NITS (code-implementation DAO-006), nit recorded as the owner's honest-limit note |
| C-4 | technical-design.md header / Version History | Header says "v1.2.1 (errata E1–E4 …) · Last Updated: 2026-10-24". The 2026-10-25 §9.3 erratum is only in the Change Log | Optional: add a Version History row or header suffix ("+ §9.3 erratum, TASK-112, 2026-10-25") |

## Honest Limits

- **One real runtime.** Docker Desktop 29.7.2 on macOS 26.6.2 arm64 (LinuxKit kernel, 4 KiB pages), local image `python:3.12-slim` (CPython 3.12.15) only.
  - Not run: Linux hosts (native or rootless Docker), x86-64 and Podman. P-04's host-namespace comparison applies only on Linux hosts.
  - Windows is a non-execution platform only, and was not run.
  - The conformance record is runtime-specific by design.
- **"Network disabled" (P-01, spec v1.3.3, human-confirmed).**
  - Proven by: interfaces down, no addresses, loopback-only routes, CapEff = CapBnd = 0, connect and DNS failing, and inspect network mode `none`.
  - Docker Desktop's down tunnel devices still exist.
  - `fib_trie` cannot show an IPv4 address on a *down* interface (owner honest-limit note); netlink `RTM_GETADDR` would give exact proof (not implemented).
- **D-1 fix limits (bug-fix DAO-006: DEC-2, DEC-4).**
  - **The mount is inferred after the stop.** The results area is read once through the holder (`cp`, capped, in memory, nothing kept); the errno text names no path.
  - **Unreadable area → no limit named** ("script error under enforced limits (exit N)"). This is reachable only when the holder `cp` fails, and it was shown by an injected unit test only.
  - **`/tmp` exhaustion while results are within 64 KiB of full** is named `results` (the area is "full" at ≥ 16 entries or regular bytes > 2 MiB − 64 KiB).
  - In every ambiguous case the method still fails and nothing is kept; no safety claim depends on the name.
- **`/tmp`-named branch verified on the fake runtime only.** No real-runtime `/tmp` naming run exists. For `pids` and CPU-time naming, see O-1.
- **Black-box-unproducible clauses rest on delivered fake-runtime tests:**
  - a runtime ignoring a limit fails its probe (11b);
  - every single 04b field;
  - the copy-time swap race (04j);
  - the execution-time L-02/L-05 re-check (04n);
  - JSON depth (07g);
  - the outside-L-12 image (02c, 11a; no such local image, nothing pulled).
- **Method notes (acceptance DAO-007, accepted).**
  - Maintainer steps on the host ran via a throwaway trust store (`maint.py`, the same service functions as the CLI); `auth init` was never run on the host. The Maintainer CLI itself ran in the Linux container.
  - The grant was typed by the runner through a pseudo-terminal. That is exactly the cooperative-consent limit the feature discloses (04p).
- **Regression scope.**
  - Runners ran in host mode at `73fe2dc` (plus the 002-G container mode), and were not re-run at `c6c1ad7`.
  - 002-D's container regression was not run (B17 assets removed).
  - For the D-1 re-run, the seeds were a byte copy of the TASK-111 container-made handoff.
- **Flaky delivered test.** `tests/drafting/test_draft_cli_approve.py::test_02e_equivalent_to_plain_update_time_normalised` (FEATURE-001-G; TASK-110, in progress) is reported with every observed run:

  | When | Full-suite runs | Isolated runs |
  | --- | --- | --- |
  | TASK-085 | run 1 pass, run 2 fail, run 3 fail, final (DAO-005) pass | 10/10 pass |
  | TASK-111 (TC-F-52) | pass | — |
  | TASK-112 | fail (3513 passed / 1 failed) | file re-run ×3: 25 passed, 25 passed, 24 passed + **1 failed** (`flaky-rerun.log` `6cef4a15…`, session folder) |

  It reproduces alone 1 in 3, so it is not a load-only effect. It does not touch Guard or `guard/helpers`; 002-F's only shared-path change it could reach is `cli.py`, which adds new subcommands only. Bug-fix DAO-006 rules it not caused by 002-F and not blocking. It was never silently retried away. A clean full suite for later features still needs TASK-110.
- **Implementer-authored tests.** TC-F-50/51 are corroborating; the independent evidence is the black-box runner.
- **Stakeholder outcome: not measured.** Fixtures, automation, reviews and DAO rulings are not stakeholder observations.

## Outcome Gaps

| Goal | Delivery | Scenario / Observation | Outcome State |
| --- | --- | --- | --- |
| G-02 | Verified (74/74 active ACs at `73fe2dc` + `c6c1ad7`) | Spec scenario executed as delivery checks on fixture projects only; no Developer, Maintainer, Owner or upstream-agent use observed | **not measured** |
| G-02.1 … G-02.8 | Verified (all mapped ACs pass) | Same | **not measured** |

Helper usefulness for real coverage gaps, and Reviewer and user behaviour around grants, remain unobserved. The default 002-C budget's fit for helpers is not sized from real use (follow-up TASK-088).

## Residual Follow-ups (do not block this closing)

1. **TASK-088 (board: pending).** C6, the helper-aware default budget in FEATURE-002-C (human "yes", 2026-10-23 21:58), sized from real use; starts after 002-F delivery. Design §11.3 records the current default-budget consequence.
2. **TASK-110 (board: in progress).** Flaky `test_02e` (above), first in the Low bug queue per bug-fix DAO-006. Its uncommitted edits include 002-F's `tests/helpers/test_helper_boundary.py`. That change is outside this closing's evidence. TASK-110's own review should confirm it only extends the later-features allowlist and leaves 002-F's closed-list guarantee intact.
3. **O-1** (optional): fake-runtime naming tests for `pids` (`EAGAIN`) and the CPU-time reason (exit 152).
4. **C-1…C-4** documentation notes (owner's choice).
5. **Further runtimes** (Linux host, x86-64, Podman) remain unverified; a conformance run on each is required before use there, by design.

## Release Disposition

**Engineering-only closure; nothing released.**
- Git strategy `main-branch-only` (`.x-ipe.yaml`). Branch `main`; read-only status `main...origin/main [ahead 6]`. The local tracking ref `origin/main` = `230aa49` (not refreshed; no network used).
- The 6 local commits ahead are `73fe2dc`, `bc165eb`, `41bdbde` (FEATURE-001-E), `c6c1ad7`, `82bd3d3` and `91a2ba8` (lock-file untracking). The working tree also has FEATURE-001-E's untracked acceptance files, an untracked TASK-110 bug report and the uncommitted TASK-110 edits named above.
- Human B8: commit, push, PR and release need explicit human instruction; the owner may make an exact-path local commit of this report. This worker ran no Git write.
- Human approval: none required for engineering closure beyond the recorded B12 = A and the 12:24 P-01 confirmation. No stakeholder acknowledgment is claimed.

## Refactoring Assessment

Not assessed in a separate analysis: no refactoring quality goal was named, and acceptance found no evidenced need.
- Every module is below 800 lines at `c6c1ad7`: the largest are `execute.py` 741, `submit.py` 492 and `conformance.py` 461; after the fix `execute_io.py` is 289 and `results.py` 213. `tests/test_module_size.py` passes in the full suites.
- Original output fields:
  - `overall_quality_score: N/A`
  - `refactoring_recommended: false` (no evidenced need; not a quality verdict)
  - `top_suggestions: []`

## Decisions for the Owner

1. **Closable: yes.**
   - All 74 active ACs pass with current, revision-bound evidence: `73fe2dc` (`f7a155a4…`) for 73 ACs, and the D-1 re-run at `c6c1ad7` (`e8a8bc44…`) for 04l.
   - The toolkit at `HEAD` equals `c6c1ad7`.
   - 05f is N/A (B12 = A).
   - Not counted as passed and disclosed: TC-F-65/70/71 (expected 002-F byte pins) and TC-F-69 (environment).
2. **Acceptance DAO-007 conditions met.**
   - D-1 was fixed by a bug fix, not waived.
   - The re-run is on a new frozen copy, and the original Fail is kept.
   - Every byte-pin differing file is within the closed list or a ruled maintenance point. The file-by-file table is above; no defect.
3. **Bug-fix DAO-006 conditions met.**
   - Review PASS.
   - §9.3 erratum + Change Log present (`57194cc4…`).
   - Closing records the D-1 history, DEC-2/DEC-4 limits, the inference after stop, the `/tmp` fake-only branch, the expected partials and the flaky test with run counts.
4. **Code-implementation DAO-005/006 conditions met.**
   - Stop rule held: closed list plus the ruled maintenance points.
   - Engine edit limited to the `helper` branch.
   - CR-077 helper path proven black-box.
   - One-runtime limits stated.
   - 002-D regression run host-only and recorded.
5. **O-1** is the only new closing observation. It is recorded as a limit; the owner may queue the optional test follow-up.
6. **No documentation was edited** by this worker; C-1…C-4 are proposals.

## Owner Handoff

- Only the owner may set FEATURE-002-F to Completed and complete TASK-114. This worker wrote no board, Git or memory files.
- Board (read-only): FEATURE-002-F `Implemented` (v1.0); TASK-085, TASK-111 and TASK-112 completed; TASK-114 in progress; TASK-088 pending; TASK-110 in progress.
- Free mode: no app action write. The closing report is a task artifact; there is no closing-report deliverable tag (the current `feature_closing` deliverables are `[]`; specification required, refactor-report optional).

```yaml
task_completion_output:
  category: "feature-stage"
  status: completed
  next_task_based_skill:
    - skill: "x-ipe-task-based-feature-refinement"
      condition: "Start the next unstarted feature from backlog. Continue the feature-by-feature pipeline (refinement → design → implementation → testing → closing)."
  process_preference:
    interaction_mode: "dao-represent-human-to-interact"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/closing-report.md"
  feature_id: "FEATURE-002-F"
  feature_title: "Temporary Check Scripts"
  feature_version: "v1.0"
  feature_phase: "Feature Closing"
  refactoring_analysis:
    overall_quality_score: "N/A"
    refactoring_recommended: "false"
    top_suggestions: []
```

The `status: completed` above is the closing worker's domain result. The board transition (Completed / task completed) is the owner's single write after the owner's own gate check. Conditional next-feature suggestion: `x-ipe-task-based-feature-refinement` for the next unstarted feature in the owner's queue; the owner confirms the queue position.
