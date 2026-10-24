# DAO Decisions: Code Implementation

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-23T11:11:10+08:00 | TASK-062 | x-ipe-task-based-code-implementation | approval | 0.82 | FEATURE-003-B: status._host unreadable-AGENTS.md change accepted as a defect fix (A) with conditions: correct next step for the OSError case only, regression test, document FRAGMENT_UNREADABLE in cli-contract, init traceback recorded as separate defect candidate |
| DAO-002 | 2026-10-23T15:28:27+08:00 | TASK-069 | x-ipe-task-based-code-implementation | approval | 0.84 | FEATURE-001-F: Q1 A — append the 5 new 001-F payload paths to delivered 003-B test helper ERA_001A_REMOVED as a test-defect fix (no assertion/fixture/AC change); DAO-009 (2) amended; maintenance point noted in 003-B/001-F designs; Q2 Framework Status line updated honestly |
| DAO-003 | 2026-10-24T02:56:11+08:00 | TASK-090 | x-ipe-task-based-code-implementation | approval | 0.88 | CR-TASK-086 renderer identity: three-file RENDERER_MANIFEST (__init__.py, atomic.py, guard/report.py) confirmed as exactly the DAO-003 (CR) DEC-2 closure rule; over-inclusion is the safe direction; design note to record it; closure test must enforce it |
| DAO-004 | 2026-10-24T06:38:31+08:00 | TASK-084 | x-ipe-task-based-code-implementation | approval | 0.84 | FEATURE-001-G implementation DEC-I1…I14 approved with conditions: I1 ERA_001A_REMOVED append (DAO-002 precedent); I5 assert the design-order code exactly (no either/or) + R1 design erratum; I3/I7/I11/I13 recorded as closing notes; I13 fixtures named in maintenance notes with self-explaining failure messages; closing after independent code review |
| DAO-005 | 2026-10-24T10:57:12+08:00 | TASK-085 | x-ipe-task-based-code-implementation | approval | 0.80 | FEATURE-002-F implementation: (1) DEC-I17 maintenance points + DEC-I18 approved per DAO-023/024; (2) snapshot Medium bug fixed here RED-first; (3) DEC-I4 narrow GPG_KEY fingerprint exemption within authority + design erratum; (4) DEC-I5 → (b) as spec clarification v1.3.x within authority (intent 'network disabled'), stronger probe evidence incl. CapEff, delta review, human visibility; (5) flaky 001-G test → separate Low task; (6) other DEC-I approved, DEC-I6 tighten /dev/shm if conformance passes else honest limit |

---

<!-- Detail sections are appended below this line -->

## DAO-001
- **Timestamp:** 2026-10-23T11:11:10+08:00
- **Task ID:** TASK-062
- **Feature ID:** FEATURE-003-B
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-code-implementation
- **Source:** ai (lifecycle owner "Sage"); mode dao-represent-human-to-interact (human returned 11:03 and is answering pending decisions; delegation stands until they choose otherwise)
- **Disposition:** approval
- **Confidence:** 0.82

### Message
> Code-review fix for an unreadable carrier file (chmod 000): besides the new 003-B code paths, the worker changed one read in FEATURE-001-A's `status._host` (status.py:73): with AGENTS.md unreadable, status previously crashed with a PermissionError traceback (no result at all); now it reports the host entry as `unreadable` with the EXISTING 001-A problem code FRAGMENT_UNREADABLE and still produces full status output. Only this input changes; no 001-A test changed; plain init on an unreadable AGENTS.md is untouched (still raises as delivered). Full suite 2048 passed. (A) acceptable defect fix within confirmed scope, or (B) 001-A behaviour change to revert and park as CR? Owner recommendation: A.

### Guidance Returned
> Choose A. A traceback with no output violates the delivered status contract: AC-001A-09a/09c say status reports each condition separately with a next step, including obvious configuration problems such as unreadable files, and US-06 calls status read-only. Turning the crash into a reported problem is a defect fix. No delivered assertion changes. Conditions:
> 1. Evidence precision: DAO checked the code. `FRAGMENT_UNREADABLE` is the status code built as "FRAGMENT_" + state for the state `inspect()` already returns for non-UTF-8 host entries, so it is existing status output. It is not listed in `references/cli-contract.md` (which lists `HOST_ENTRY_UNREADABLE` for init/carriers). Say exactly this in the evidence, and add `FRAGMENT_UNREADABLE` to the cli-contract status problem list as documentation of existing output.
> 2. Next step: for the new OSError case only, do not point to "Run project initialization". Plain init on that file still raises, so that guidance would be wrong. Use "Make <host_entry> readable, then re-run status". The existing non-UTF-8 case stays byte-identical.
> 3. Tests: a 001-A-level status regression with chmod-000 AGENTS.md (RED-before = the traceback, recorded), asserting full output, the problem code, the corrected next step, and no writes (AC-001A-09b). All existing 001-A tests stay unchanged and pass.
> 4. Scope: plain `init` raising on an unreadable AGENTS.md is a separate pre-existing 001-A defect. Do not fix it inside 003-B. Record it as a bug candidate for the human or a later Bug Fix task.

### Rationale
> The change restores documented status behavior for an input that produced no result, uses status output that already existed, and changes no delivered assertion, so it is a defect fix, not a CR. The conditions keep the evidence accurate and the next step truthful.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "Continue TASK-062 with the bounded status fix, test and contract doc line"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Write failing test then fix (TDD)"

### Follow-up
> Owner records "plain init raises PermissionError on unreadable AGENTS.md (001-A)" as a bug candidate for the human.

## DAO-002
- **Timestamp:** 2026-10-23T15:28:27+08:00
- **Task ID:** TASK-069
- **Feature ID:** FEATURE-001-F
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-code-implementation
- **Source:** ai (lifecycle owner "Sage"); delegation continues (human confirmed 13:16 and 14:00)
- **Disposition:** approval
- **Confidence:** 0.84

### Message
> Implementation complete; full suite 2254 passed / 4 skipped / 10 failed; DAO-009 (2) stop triggered. Q1: the 10 failures are delivered FEATURE-003-B tests (test_project_lock::test_plain_init_with_unavailable_lock_identical_to_001a_baseline ×8, test_carriers_preservation::test_04i…, test_record_compat::test_08c_member_less…). They synthesise a "001-A-era" toolkit by copying the current tree and deleting carhelp.py ERA_001A_REMOVED (only the 4 003-B files), then compare to a fixture recording "<94 files>"; the 5 new 001-F payload files make it 99; nothing else differs. Candidate: append those 5 paths to ERA_001A_REMOVED (scratch: 76/76 pass); no assertion/fixture/AC/schema change. Options: A) test-support helper maintenance within DAO authority (amend DAO-009 (2); record in 003-B design as a maintenance point); B) re-record the fixture count (rejected: weakens baseline); C) escalate as CR and park. Q2: Framework SKILL.md "Status of This Skill" still says Presets/tags come in later features; allow updating it (Framework only)?

### Guidance Returned
> DAO verified the following:
> - `carhelp.py` L54-60: ERA_001A_REMOVED lists only the 4 FEATURE-003-B paths. `toolkit_copy(era="001A")` (L321-323) unlinks them from a full copy of the current tree.
> - `fixtures/init_001a_baseline.json` records only the count placeholder `<94 files>`, not file contents. The test asserts `steps == baseline_001a()`, so any newly added payload file breaks it.
> - The candidate diff adds exactly the 5 FEATURE-001-F paths, and those files exist (new today).
> - 003-B design L1041 defines era="001A" as "the payload without the FEATURE-003-B additions".
> - The Framework SKILL.md L166-173 Status line still says Presets/tags come in later features. Only the Copilot and Guard skill tests mention a Status section, and they assert it is absent there.
> Q1: Choose A, classified as a test-defect fix in delivered test support. The helper ties a behavioral baseline (plain init without a lock = 001-A behavior) to the current payload size. Any later payload-adding feature therefore produces false failures, while the behavior under test is unchanged. The fix restores the exact baseline the fixture recorded, and leaves every assertion, the fixture, every AC and the schema unchanged. This is within delegated authority (defect fixes). DAO-009 (2) is amended to allow exactly this.
> Conditions:
> 1. Apply exactly the 5-path append from the reviewed diff. A comment may clarify that the list removes every payload file added after the recorded baseline. No other 003-B test or helper change.
> 2. Append a non-destructive maintenance note to the 003-B technical design. Attribute it to the DAO representative under delegation (DAO-002 code implementation). Text: "every later payload-adding feature appends its payload paths to ERA_001A_REMOVED; fixture and assertions are never re-recorded for this reason". Mention it in the 001-F design/implementation notes too.
> 3. Re-run the full suite at the implementation revision. It must have 0 failures. The full 003-B suite is now part of the 001-F regression set, alongside 001-B/C/D, 002-A and 003-A (DAO-009 (3)). Do not edit earlier 003-B acceptance evidence; append a note citing the helper change and the re-run. 003-B stays parked on B7/B11, unchanged.
> 4. If any of the 10 tests still fails after the append, or any other difference appears, stop: that would be a real behavior difference, and goes to the human as a CR.
> B is rejected because it weakens the baseline. C is unnecessary because no delivered behavior or AC changes.
> Q2: Approved, Framework SKILL.md only. State that FEATURE-001-F delivers Presets and tags, using the actual delivered command names. Keep Reference knowledge (001-E) and Adapters as later features. Keep "status reports them honestly as empty or not provided" only if it is still true for what remains; do not claim status-command changes that were not implemented. Do not change Copilot or Guard skill text. Re-run the Framework skill tests (test_preset_skill consistency, 001-C 02e, 001-D test_exit_skill) and the Copilot/Guard skill tests.
> No commit, push or release is implied.

### Rationale
> The failing check is coupled to payload size, not to the behavior it guards. Restoring the recorded baseline preserves the assertion's strength, whereas re-recording would weaken it. This is a defect fix with a stop condition if anything else differs. The Status line is a factual consistency update for the feature being delivered, with precedent in 001-D.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "Apply helper fix and Status line, re-run full suite, continue to completion"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Apply fix, full regression, independent code review"
>   - skill_name: "x-ipe-task-based-feature-acceptance-test"
>     match_strength: "partial"
>     reason: "Engineering-next after implementation, with DAO-007/009 re-run obligations"

### Follow-up
> 003-B design maintenance note (ERA_001A_REMOVED) to be appended by the owner.

## DAO-003
- **Timestamp:** 2026-10-24T02:56:11+08:00
- **Task ID:** TASK-090
- **Feature ID:** FEATURE-002-A (CR-TASK-086)
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-code-implementation
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human C1 = yes
- **Disposition:** approval
- **Confidence:** 0.88

### Message
> CR-TASK-086 implemented test-first: full suite 2593/0; delivered tests byte-identical; 002-A host 2/2 and 002-G host 23/23 + container 24/24 regressions match; toolkit file-list 272741bc…; independent code review running. Deviation for DEC-2 condition: reading the toolkit version makes report.py import the package __init__.py, so the closure manifest is ("__init__.py", "atomic.py", "guard/report.py") — one file more than the design names; a version bump also changes the renderer digest. Alternative: keep two files and obtain the version outside report.py (changes report.renderer_identity() interface). Confirm the three-file manifest is within the DEC-2 condition.

### Guidance Returned
> DAO verified that delivered-candidate `guard/report.py` L16–17 imports `__version__` from the package and `dumps_json` from `atomic`, and that L26–27 define `RENDERER_MANIFEST = ("__init__.py", "atomic.py", "guard/report.py")` with the comment "over-inclusion is harmless". The package `__init__.py` is 3 lines.
> **Confirmed: the three-file manifest is exactly what the DAO-003 (change request) DEC-2 condition requires.** The rule was "report.py plus every toolkit-internal module it imports for rendering". Since report.py now imports `__init__` for the version, including it is the rule applied, not a deviation from it.
> The effect is in the safe direction: a version bump changes the digest, so 002-G (after its follow-up CR) will at most say "renderer differs". It can never produce a false "edited" claim.
> The alternative (moving version retrieval out of report.py) is rejected: it changes the designed interface to save one harmless file.
> Conditions:
> 1. Record this in the 002-A design/CR implementation notes, so the manifest list matches the code.
> 2. The closure test must parse report.py's toolkit-internal imports and fail if any import is missing from `RENDERER_MANIFEST`. It must also fail if a manifest entry is unreadable without reporting "renderer unknown".
> 3. The CR closes only after the running independent code review passes (or its findings are fixed and re-reviewed).
> 4. Local exact-path commit only (B8).

### Rationale
> The closure rule was set precisely so that every rendering dependency is covered; including `__init__.py` follows it and errs only toward a benign "renderer differs".

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "Finish TASK-090 after the code review"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Review fixes, full regression, then acceptance of the CR"

### Follow-up
> 002-G renderer_differs follow-up CR after this CR is accepted (DAO-003 change request DEC-G1).

## DAO-004
- **Timestamp:** 2026-10-24T06:38:31+08:00
- **Task ID:** TASK-084
- **Feature ID:** FEATURE-001-G
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-code-implementation
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B13 = H2, B14 = No
- **Disposition:** approval
- **Confidence:** 0.84

### Message
> Implementation per design v1.2 5e0f2aa8 / spec v1.3.3 4cb3a1eb: 9 drafting_* modules + knowledge-drafting.md + additive changes to cli.py/SKILL.md/cli-contract.md only (all other delivered files byte-identical vs step-0); 265 new tests pass (216 fail / 2 collection errors at step-0); ruff clean; forbidden-substring scan zero. Full suite: 2871 passed, 10 failed (delivered 003-B carriers tests "created <94 files>" vs <104> because carhelp.py ERA_001A_REMOVED lacks the 10 new payload files). Report implementation-report-TASK-084.md §9 DEC-I1…I14. Rulings needed (owner recs: approve I1, I2, I3, I4, I5/I6, I7, I13; others per report). Independent code review running.

### Guidance Returned
> DAO verified:
> - report SHA 2d668124… (§9 L237–254);
> - `ARGUMENT_INVALID` is an existing code in the delivered `cli-contract.md` at HEAD;
> - design R1 / step order (4b representability, 6b writer simulation).
> - **DEC-I1 → approved.** This is the established maintenance rule (DAO-002 code implementation; noted in the 003-B design): append exactly the 10 new 001-G payload paths to `ERA_001A_REMOVED` as a pure list append, with no assertion or fixture change. It is scratch-verified (76/76). Re-run the full suite to 0 failures.
> - **DEC-I2 → approved.**
>   - Synthetic fixture batches with seeded-style identities and short synthetic content; nothing copied from `demo/` or any internal source.
>   - `@SYNTH` only for internal-drafting tests (B14).
> - **DEC-I3 → approved as the evaluation of AC-001G-08a.** "Byte-identical init outputs" is assessed modulo the declared payload growth: exactly the 10 new payload files are removed from `created`, an assertion fixes that set, and everything else is byte-identical with the goldens. Record this interpretation in the closing report.
> - **DEC-I4 → approved** (privacy; normalized identically at regeneration).
> - **DEC-I5 → approved with a change.** The test must assert the code the design's step order actually produces (`RULE_INCONSISTENT`) exactly, plus "nothing written". An either/or assertion would hide a future order change. Record a design erratum: R1's listed expectation is superseded by the step order (step 2 before 4b).
> - **DEC-I6 → approved.** Gate before any rule read is stricter and matches B14 = No ("refused before reading any internal rule content").
> - **DEC-I7 → approved.** All listed items are unchanged helpers, constants, exceptions or pure functions used read-only (`atomic.dumps_json` is pure serialization); no write outside 001-G-private paths. Record them in the closing report as additional P3a-class read-only uses (wording erratum to the spec P3a list at the next revision; no re-review).
> - **DEC-I8 → approved.** `ARGUMENT_INVALID` is an existing delivered code; exit 1 with the result envelope.
> - **DEC-I9 → approved.**
> - **DEC-I10 → approved** (stricter allowlist).
> - **DEC-I11 → approved.** The delivered `Finding.to_dict()` adds only the `blocking` boolean, never a value. Note it in the closing report as a superset of the AC's listed fields with no disclosure.
> - **DEC-I12 → approved.**
> - **DEC-I13 → approved.** These are new maintenance points like `ERA_001A_REMOVED`. Name both fixtures in the maintenance notes (001-G design/closing) and make their test failure messages say exactly which fixture to update and why, so future legitimate changes aren't mistaken for regressions.
> - **DEC-I14 → approved** (fail closed).
> Closing conditions:
> - the independent code review passes (or its findings are fixed and re-reviewed);
> - full suite 0 failures after DEC-I1;
> - 001-A/B/C/D/F, 002-A and 003-A/B regressions as the design requires;
> - the stop rule held (only cli.py/SKILL.md/cli-contract.md additive changes, plus the ERA list);
> - B13/B14 bindings verified in tests;
> - local exact-path commit (B8).
> Then Feature Acceptance Test (fixture-only).

### Rationale
> All deviations are either established maintenance (ERA list), privacy normalization, stricter behavior or honest test interpretations. DEC-I5 is tightened so the test pins the actual behavior instead of tolerating two outcomes.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "Apply DEC-I1/I5 changes, finish review, full regression"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Apply ruled changes, full suite, independent review"
>   - skill_name: "x-ipe-task-based-feature-acceptance-test"
>     match_strength: "partial"
>     reason: "Next after implementation (fixture-only acceptance)"

### Follow-up
> Design erratum (R1) and spec P3a wording erratum at next sync; maintenance notes for the two hash fixtures.

## DAO-005
- **Timestamp:** 2026-10-24T10:57:12+08:00
- **Task ID:** TASK-085
- **Feature ID:** FEATURE-002-F
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-code-implementation
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B12 = A
- **Disposition:** approval
- **Confidence:** 0.80

### Message
> Implementation per spec eafc9894 / design 4202a1c0: 324 new tests (4 opt-in real Docker passed with local python:3.12-slim --network none, nothing pulled), 74/74 active ACs traced, only the 11 closed-list delivered files changed (+77 added), engine edit limited to the helper branch; full suite 3201/4 failed/8 skipped. Report implementation-report-TASK-085.md (9e5fefcb; §9 DEC-I1…I20). Code review PASS-WITH-FIXES. Rulings: (1) DEC-I17 STOP — test_01h, drafting test_08a, test_08d fail by design → apply DAO-023/024 maintenance points now; DEC-I18 ERA_001A_REMOVED append. (2) Review Medium bug helpers/snapshot.py:82 (unreadable/FIFO/symlink/non-UTF-8 entries outside read scope silently omitted → accepted_full while files never seen) → fix here, RED first. (3) DEC-I4 GPG_KEY=<40-hex> false positive → narrow registry-only exemption — within authority? (4) DEC-I5 P-01 /sys/class/net == [lo] fails on Docker Desktop (down address-less tunnel devices) → (a) strict, (b) relax AC-002F-11b to "no interface up / with address / route" + stronger probes, (c) other; owner rec (b) via human unless clarification of intent. (5) Flaky delivered test_02e under load → separate Low task. (6) Other DEC-I per §9.

### Guidance Returned
> DAO verified:
> - report SHA 9e5fefcb… (§9 DEC-I1…I20; limits: one real runtime, Docker Desktop on macOS arm64; no permitted Python image registers under DEC-5);
> - spec SHA eafc9894…: AC-002F-11b (L187, "no network interface other than loopback and failed outbound connection and DNS … no capabilities …") and AC-002F-04b (L106, canonical config incl. network `none`, all capabilities dropped, `no-new-privileges`, non-root).
> **(1) DEC-I17 → approved; 002-F lands first, so it makes the edits:**
> - `test_compare_skill.py::test_01h` is scoped per DAO-024: 002-G's section ends at the next `^#{1,2} ` heading or EOF; exactly one ATX heading inside; the compare/cleanup command check stays; the prefix hash check stays. Rebaseline `DELIVERED_SIZE`/`DELIVERED_SHA256` only if 002-F changed bytes before offset 12017, with the recorded reason in a comment. Add the DAO-023 maintenance comment.
> - `drafthelp.NEW_PAYLOAD` gains exactly the 002-F new payload paths.
> - `guard_copilot_hashes.json` is rebaselined for Guard SKILL.md only (Copilot unchanged).
> - No other assertion changes. List all three in the 002-F closing as maintenance points.
> **DEC-I18 → approved** (pure append, DAO-002 precedent).
> **(2) snapshot.py:82 → fix in this task, RED first.** Every non-excluded entry under the check object (unreadable, FIFO, symlink, non-UTF-8 name) must be recorded as seen-but-not-covered. It counts as uncovered, so a clean result is at most `accepted_partial` (AC-002F-07c v1.3.1), with the uncovered entries named in the report gap line. Re-review this delta.
> **(3) DEC-I4 → within DAO authority (clarifies my own DEC-5 condition in DAO-014 TD, whose intent is credentials, not public key fingerprints).** The exemption sits in `registry.py` only, with `mask_text` untouched. Exactly:
> - key `GPG_KEY` or `GPG_KEYS`;
> - whole value `^[0-9A-Fa-f]{40}( [0-9A-Fa-f]{40})*$`;
> - not refused, still shown to the Maintainer labelled "public key fingerprint (not a secret)";
> - every other flagged entry is still refused.
> Add tests for the exempt case plus near-misses (other key names, wrong lengths, extra characters). Design erratum (DAO-attributed); the design's own example at L267 already shows `GPG_KEY` recorded.
> **(4) DEC-I5 → (b), as a clarification within DAO authority, with stronger evidence.** The human-confirmed requirement (A-15; workflow DAO-001 gate) is "network disabled", and AC-002F-11b's "no interface other than loopback" was the DAO-confirmed spec's proxy for it. 002-F is undelivered, so its wording can be clarified to the intent without a human CR. The new probe must prove ALL of:
> - every non-loopback interface is administratively down (no IFF_UP) and has no IPv4/IPv6 address (`/proc/net/if_inet6`, `fib_trie`);
> - no routes other than loopback (`/proc/net/route`, `ipv6_route`);
> - the process lacks CAP_NET_ADMIN/NET_RAW (`/proc/self/status` CapEff/CapBnd = 0, matching inspect CapDrop ALL), so the devices cannot be brought up;
> - outbound connect and DNS fail;
> - network mode `none` per inspect.
> Any failure means non-execution. Apply as spec v1.3.x (11b wording, Version History attributed to the DAO representative, DAO-005 code implementation), with an independent delta review of spec + probe change. Keep the honest limit that evidence comes from one runtime (Docker Desktop/LinuxKit, macOS arm64). For human visibility, put a line in the next status summary ("002-F network check clarified from 'only lo exists' to 'no usable non-loopback interface, no routes, no capability to create one'"); the human may overrule.
> **(5) Flaky `test_draft_cli_approve::test_02e` → a separate Low bug task** (001-G test robustness; reproduce under load first). It does not block 002-F. Every 002-F full-suite run must report it honestly: any rerun is documented, and it is never silently retried away.
> **(6) Other DEC-I → approved as reported, with these notes:**
> - **I1:** inlining the section keeps the renderer manifest truthful (DAO-003 code implementation).
> - **I2:** the tolerant `.get` stays within the single 3-line engine edit; the delivered CR-077 tests pass unchanged.
> - **I6:** tighten `/dev/shm` with `--ipc none` (or a minimal `--shm-size`) if the real-runtime conformance passes, since AC-002F-04b intends results-only writes beyond the declared `/tmp`. Otherwise keep it as a recorded honest limit.
> - **I8/I9:** stricter, documented.
> - **I10:** the probe is a data file, never imported, consistent with the 002-C no-socket test.
> - **I11:** masking mounts only under `/proc`, `/sys`, `/dev`, and no sockets.
> - **I19:** new maintenance points, named in the closing notes with self-explaining test messages.
> - **I3, I7, I12–I16, I20:** approved.
> Closing conditions for TASK-085:
> - code-review fixes and the snapshot fix re-reviewed;
> - full suite with only the documented flaky exception;
> - 001-A/B/C/D/F, 002-A/B/C/G and 003-A/B regressions as required;
> - stop rule held (closed list plus the ruled maintenance points);
> - local exact-path commit (B8).
> Then acceptance (real-runtime cases need a registrable image, now possible via DEC-I4, and P-01 under the clarified 11b).

### Rationale
> The maintenance points and ERA append follow established rulings; the snapshot fix closes a real coverage over-claim; the GPG_KEY exemption and the 11b clarification realize the intents (no credentials, network disabled) with stronger, narrower evidence instead of proxies that make the feature unusable on the only available runtime.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "Apply rulings, RED-first snapshot fix, spec 11b clarification, re-review"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Apply ruled changes, full suite, independent delta review"

### Follow-up
> Spec v1.3.x 11b clarification + delta review; human visibility note on the network-check clarification; Low bug task for the flaky 001-G test.
