# DAO Decisions: Feature Acceptance Test

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-23T06:06:53+08:00 | TASK-058 | x-ipe-task-based-feature-acceptance-test | approval | 0.84 | FEATURE-002-D: Bug Fix for F-1 (9 misconfig types incl. ansible) and F-2 (exact-match WARN allow-list, fail-closed) without spec change; rerun; park at acceptance under existing status (B9); then FEATURE-003-B |
| DAO-002 | 2026-10-23T17:47:54+08:00 | TASK-070 | x-ipe-task-based-feature-acceptance-test | approval | 0.85 | FEATURE-001-F acceptance PASS accepted (63/63, 3 superseded, 001-D 02b clauses superseded/re-run) → Feature Closing; O-1 interpretation confirmed (existing knowledge lock file on first use, consistent with DAO-004 (1)); O-2 recorded as optional human CR/polish candidate, not a defect |
| DAO-003 | 2026-10-24T00:06:26+08:00 | TASK-091 | x-ipe-task-based-feature-acceptance-test | approval | 0.86 | FEATURE-002-G acceptance PASS (76/76 at 15985026…) accepted → Feature Closing; unit/integration evidence accepted (02c/02h/04f are Unit by spec; 07g/07h/07j Integration via in-process hooks; 05l simulated + limit); host-only 002-D regression accepted (no 002-D code touched; container re-run at 002-D B9 acceptance; no new downloads now); wording readings confirmed |
| DAO-004 | 2026-10-24T05:15:42+08:00 | TASK-058 | x-ipe-task-based-feature-acceptance-test | critique | 0.86 | FEATURE-002-D B9 run: re-downloading the Trivy binary (GitHub) and Python deps (PyPI) is NOT covered by B9 (DB download via tool_update only; acceptance downloads were already ruled outside tool-validation authority in DAO-002 TD) → (B) escalate as human B17; park TASK-058 at existing status; no partial closing (C rejected); queue reorder to TASK-084 next confirmed |
| DAO-005 | 2026-10-24T08:19:17+08:00 | TASK-103 | x-ipe-task-based-feature-acceptance-test | approval | 0.86 | FEATURE-001-G acceptance (62/62 active, 09a–e deferred by human B13) accepted → Feature Closing; O-084-1 → (a) separate Low bug-fix task (mask/omit refused provenance URLs, existing masking, no new output) after TASK-102, disclosed in closing; closing review = code review PASS + acceptance if both bound to 93e3eaa, else delta review; local commit (B8) |
| DAO-006 | 2026-10-24T10:30:26+08:00 | TASK-058 | x-ipe-task-based-feature-acceptance-test | approval | 0.80 | FEATURE-002-D B17 run (46/46 ACs, TC-L-01 live pass): (a) accepted with conditions — design's 'mandatory real-binary gate before closing' amended (DAO design erratum) to TC-G-01 or a check-by-check executed equivalent confirmed by the independent evidence review; uncovered TC-G-01 assertions become disclosed limits; TC-G-01 recorded 'not executed — human scoped B17 = A', never passed; human told B17-B remains available |
| DAO-007 | 2026-10-24T23:01:15+08:00 | TASK-111 | x-ipe-task-based-feature-acceptance-test | critique | 0.86 | FEATURE-002-F acceptance 73/74: D-1 (AC-002F-04l limit misnamed) → (a) bug fix after TASK-098, RED first, re-run TC-F-27/21/51 on a new frozen copy; (b) rejected (AC requires naming the limit); 001-G TC-G-33 / 002-G TC-G-23 partials accepted as expected change-set pins if every differing file is in 002-F's closed list + ruled maintenance points; 002-D TC-H-01 environment partial recorded |

---

<!-- Detail sections are appended below this line -->

## DAO-001
- **Timestamp:** 2026-10-23T06:06:53+08:00
- **Task ID:** TASK-058
- **Feature ID:** FEATURE-002-D
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-feature-acceptance-test
- **Source:** ai (lifecycle owner "Sage"); mode dao-represent-human-to-interact by explicit human delegation
- **Disposition:** approval
- **Confidence:** 0.84

### Message
> Acceptance (real Trivy v0.76.1, offline Linux arm64 container): 46 ACs → 42 Pass; 02b/02c Pass against a loopback stand-in registry with live provisioning NOT EXECUTED (B9); 2 Fail: F-1 AC-002D-03d real `trivy fs --help` lists 9 misconfiguration types incl. `ansible`, toolkit accepts 8 → valid `ansible` override refused; F-2 AC-002D-05b benign WARNs ('license detection skipped' when Python absent; 'Using severities from other vendors') classified as analysis-degrading → fully analysed checks end as failed method. Real-binary gate test file blocked (needs live downloads B9, Docker CLI in container, binary on host path, iptables); gate-equivalent items reproduced offline. Fact-finding: clean .tf files get no per-file result → always a named gap (honest per spec); cold-cache re-hash ≈0.5 s/DB; x86-64 binary runs only under emulation (not claimed). Regressions: 002-A/002-C/003-A byte-identical; 002-B 9/10 + 2/2 (failing check is the 'Trivy not provided' assertion superseded by AC-002D-08a). Framework suite 1777 passed. Owner recommendation: register Bug Fix (no spec change) for F-1 and F-2, RED-first, rerun affected acceptance + regressions; then park FEATURE-002-D at acceptance (NOT Tested/Completed) for B9; move to FEATURE-003-B. Record clean-.tf as known limitation in notes only; record gate-test environment prerequisites for when B9 is granted.

### Guidance Returned
> Approve the owner's plan, with these conditions:
> 1. F-1 is a defect against AC-002D-03d as written ("types supported by the verified tool version"), so no spec change is needed. The accepted list becomes exactly the 9 types from real v0.76.1 help, recorded in the tool-validation evidence and pinned to that version (compose stays refused). RED test first. When acceptance is rerun, actually execute an `ansible` override offline on the real binary (sinkhole: zero outbound), not just validate the request.
> 2. F-2 is a defect against AC-002D-05b/05f. Use a bounded allow-list: exact message patterns for the two observed WARNs, pinned to v0.76.1 and cited to validation evidence. Any other or unknown WARN/ERROR stays analysis-degrading (fail-closed). RED tests cover both allowed WARNs (check succeeds) plus an unlisted WARN and a version mismatch (still failed method). Do not widen to message classes.
> 3. 002-B regression: the failing check is the Trivy part of AC-002B-06b, which the 002-D spec explicitly supersedes, so it is not a 002-B regression. Update that test assertion within this feature to the superseding expectation (Trivy provided per AC-002D-08a; Strix still not provided). Report it as "superseded per spec", not "pass". Any other 002-B change → stop, human CR.
> 4. Rerun the affected acceptance cases plus 002-A/B/C, 003-A and framework regressions at the fixed revision; keep independent review of the fix.
> 5. Park FEATURE-002-D using an existing board status for the last truthfully reached stage (implemented), with acceptance recorded as partial. Do not invent a status value and do not mark it Tested/Completed. Live provisioning (02b/02c live branch) and the mandatory real-binary gate are reported as not executed. The real-binary gate test must show as skipped/not executed with reason B9, never counted as passed.
> 6. Record without changing anything: clean-.tf per-file gap as a known limitation (candidate for a future human-decided CR); gate-test environment prerequisites (Docker CLI in container, binary path, iptables) under B9. x86-64 adapter execution stays unverified. Record it as gap B10 (needs a native x86-64 Linux environment or human acceptance of emulated evidence). Optionally run the offline acceptance subset under emulation only if the amd64 image and binary are already local (no new download), and label it "emulated".
> 7. Then proceed to FEATURE-003-B.

### Rationale
> Both failures contradict ACs as written, so a Bug Fix restores approved behavior without a CR. An exact, version-pinned, fail-closed allow-list keeps the "no misleading pass" goal. Parking with an existing status and explicit not-executed evidence stays honest about B9/B10.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-bug-fix"
>     match_strength: "strong"
>     reason: "Acceptance failures F-1/F-2 against approved ACs; failing-before/fixed-after regression evidence"
>     execution_steps:
>       - phase: "1. Reproduce"
>         step: "1.1 Write failing (RED) tests for F-1 and F-2"
>   - skill_name: "x-ipe-task-based-feature-acceptance-test"
>     match_strength: "strong"
>     reason: "Rerun affected acceptance cases and regressions at the fixed revision"
>     execution_steps:
>       - phase: "1. Execute"
>         step: "1.1 Rerun 03d (incl. real ansible override) and 05b cases"
>   - skill_name: "x-ipe-task-based-feature-refinement"
>     match_strength: "partial"
>     reason: "Next feature FEATURE-003-B after 002-D is parked"

### Follow-up
> Owner records B9 (live provisioning + real-binary gate environment) and B10 (x86-64 execution) as human blockers. FEATURE-002-D closing waits for the human.

## DAO-002
- **Timestamp:** 2026-10-23T17:47:54+08:00
- **Task ID:** TASK-070
- **Feature ID:** FEATURE-001-F
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-feature-acceptance-test
- **Source:** ai (lifecycle owner "Sage"); delegation continues (human confirmed 13:16 and 14:00)
- **Disposition:** approval
- **Confidence:** 0.85

### Message
> Acceptance PASS at toolkit revision ebe3ce44… (verified unchanged by Sage): 63/63 in-scope ACs pass (04h/09b/09c superseded, no test); container 17/17 cases (276/276 checks), host 2/2 (28/28). DAO-009 (3) re-runs: 001-D TC-D-05…16 pass; TC-D-01…04 fail only on the 7 AC-001D-02b "not checked" clauses → reported "superseded per AC-001F-06a/06b — re-run" (narrowed diagnostic copy 4/4); host byte-identical; 001-B/C/002-A/003-A regressions 8/8 byte-identical; pytest 2265 passed, 0 failed; ruff clean; code-review fixes applied before acceptance. Q1 route: Feature Closing vs Refactoring. Q2 (O-1): the knowledge lock file is created on first use by a refused Preset save and by `preset resolve --default` (delivered `policy resolve` does the same; design allows it) — confirm "nothing is written" excludes it? Q3 (O-2): `preset resolve` keeps the delivered 001-C `adoption` text "scope save" while next steps say "preset scope-save" — candidate CR for the human?

### Guidance Returned
> DAO verified:
> - The report (87c08f43…, 237 lines) states 63 Pass, 3 Superseded, 0 Fail, outcome not measured, at toolkit ebe3ce44… and spec e00d6721… (spec hash re-verified).
> - It records O-1 and O-2 as observations.
> - Design L345 states the refusal exception "apart from the knowledge lock file that `session(write=True)` may create".
> - Spec OQ-04, as clarified by DAO-004, defines "no *new* lock files" as "reuse the existing knowledge lock".
> I did not recompute the toolkit file-list hash; that relies on Sage's verification.
> Q1: Route to Feature Closing. No refactoring quality goal has been named, and code review fixes were already applied. Closing must carry:
> - the superseded rows (04h/09b/09c, plus the 001-D AC-001D-02b clauses "superseded per AC-001F-06a/06b — re-run");
> - the 003-B helper maintenance note (DAO-002 code implementation);
> - the honest limits: tag writes are toolkit-mediated only, metadata-only drift is undetected, there is no history beyond version control, and the provenance clue is information only;
> - stakeholder outcome not measured;
> - the future human CR candidates: structured, save-validated Preset provenance, and O-2.
> Closing requires no commit, push, PR or release without explicit human authority.
> Q2 (O-1): Confirmed as an interpretation, not an AC change. "Nothing is written" in the 001-F refusal and default-branch ACs means no Preset/tag file, folder, temp or history file, and no other project change. It excludes creation of the existing, delivered knowledge lock file on its first use. This is the same lock-acquisition behavior as unchanged 001-C `policy resolve`. It is consistent with DAO-004 (1), where "no new lock file" means no new lock-file kind (per-Preset or otherwise), so the interpretation also applies to 02h/02j. Where the lock already exists, refusals stay strictly byte-identical, as tested. State the interpretation in the closing report. A wording clarification in the spec is optional and should be folded into the next spec revision, not made now; acceptance evidence stays bound to e00d6721….
> Q3 (O-2): Agree, it is not a defect. No v1.5 AC requires it. Delivered 001-C keys/text stay unchanged by design (BR-11, 09a). The skill and `next_steps` direct `preset scope-save`, and a direct `scope save` is honestly an ordinary clues save without Preset guarantees (DAO-006 (1), 04i). Record it as an optional human CR/polish candidate. Rewriting the field would touch 001-C-generated output and is not within DAO authority as an AC change. Name the residual risk in the closing report: an agent that follows `adoption` literally gets an ordinary clues save.

### Rationale
> Acceptance evidence is complete, revision-bound and honest about superseded clauses, so closing is the engineering-next step. O-1 matches the reviewed design and the meaning DAO-004 gave "no new lock file". O-2 involves delivered 001-C output and no failing AC, so it belongs with the human as a candidate rather than as a DAO-ordered change.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-feature-closing"
>     match_strength: "strong"
>     reason: "Engineering-next after passing acceptance; no refactor goal named"
>     execution_steps:
>       - phase: "1. Verify"
>         step: "1.1 Verify goals/AC/evidence at current revision; record limits, superseded items and candidates"

### Follow-up
> Human CR candidates for later: structured save-validated Preset provenance; O-2 `adoption` text for Preset proposals. Optional spec wording clarification for O-1 at next spec revision.

## DAO-003
- **Timestamp:** 2026-10-24T00:06:26+08:00
- **Task ID:** TASK-091
- **Feature ID:** FEATURE-002-G
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-feature-acceptance-test
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B8 = A (local commits only)
- **Disposition:** approval
- **Confidence:** 0.86

### Message
> Acceptance PASS at toolkit 15985026… (unchanged throughout): 76/76 ACs pass; black-box container 24/24 (182 checks, real Guard runs, real Opengrep 1.31.0), host 23/23 (174); feature+skill tests 249 passed; full suite 2497/0; ruff clean; peak RSS 0.60/1.49 GiB (macOS only); regressions 002-A/B/C, 003-A byte-identical, 003-B pass; 2 partials: 002-B container 9/10 = known superseded "Trivy not provided" check (byte-identical to last regression), 002-D host-only (TC-D-19 byte-identical; TC-H-01 needs Trivy binary + loopback registry volumes no longer present). Local Git repo exists per B8 (17 local commits, nothing pushed). Decide: (1) route Feature Closing; (2) accept named unit/integration tests as evidence for 02c, 02h, 04f, 07g, 07h, 07j (05l via simulated older report); (3) accept host-only 002-D regression now vs restore Trivy/registry now; (4) confirm wording readings ("same issue confirmed" only in a "never means" sentence; "resolved" only in the required "resolved from the project's report store" sentence).

### Guidance Returned
> DAO verified:
> - report SHA 099a20c3… (285 lines): status "Verified engineering delivery… not measured"; revision 15985026… (238 files) unchanged; 31/33 logical TCs pass with 2 regression partials and 0 product failures; the AC evidence table (02c L136, 02h L141, 04f L157, 05l L176, 07g–07j L196–199); limits L228–234; O-1/O-2 L219–220;
> - spec test types: 02c, 02h and 04f are **Unit**; 07g and 07j are Integration (file-access); 07h is Integration (regression); 05l is Integration (CLI);
> - spec BR-03 bans "fixed/resolved/remediated/improved" as a class, count or description of findings.
> **(1) Route to Feature Closing.** No refactor goal is named. Closing must carry:
> - the two regression partials, with their causes;
> - the honest limits: Windows/Linux RSS not measured; Trivy paths unit-only; simulated older renderer; the residual same-user race; stakeholder outcome not measured;
> - the planned C1 follow-up (renderer_differs after CR-086);
> - B8 (local commits only, no push, PR or release).
> **(2) Accepted.** 02c, 02h and 04f are Unit-typed in the spec, so the named unit tests are their specified primary validation. 07g, 07h and 07j are specified with in-process hooks, fail points or a frozen clock, so the named integration tests are the correct evidence. 05l passes with a simulated older-renderer report, with the limit stated; CR-086/C1 later makes it observable for real. Add a supplementary (non-blocking) item: when FEATURE-002-D's B9 acceptance re-establishes the Trivy container environment, run one 002-G black-box comparison over real Trivy results (02h/04f/06c paths) and append that evidence. Never edit this report.
> **(3) Accept the host-only 002-D regression now; do not restore Trivy/registry now.** Restoring would need new downloads. The human's B9 authorization covers only 002-D's own acceptance-time DB download, so restoring now would be new network use outside the authorization. 002-G touched no 002-D code (closed plug-in list), and the full suite (2497/0) includes 002-D's fake-based tests. Conditions:
> - closing records the SHA-256 of 002-D-owned modules, unchanged versus the 002-D acceptance revision (or an empty diff list);
> - the container regression is re-run inside 002-D's B9 acceptance and noted there.
> **(4) Both readings confirmed.** "same issue confirmed" appearing only inside the fixed negation "it never means the same issue confirmed" satisfies DAO-010 (OQ-03), which forbids the claim, not its denial. "resolved" appearing only in AC-002G-05e's required sentence about reports being resolved from the report store does not describe a finding, so it is compliant with BR-03. The runner's exact-sentence exclusion is acceptable, provided any other occurrence fails the check.
> No push, PR or release (B8).

### Rationale
> Evidence types match the spec's declared validation types at an unchanged, hash-bound revision. The partials are environment or superseded regression artefacts with no product failure. Restoring the 002-D environment now would exceed the human's network authorization.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-feature-closing"
>     match_strength: "strong"
>     reason: "Engineering-next after passing acceptance"
>     execution_steps:
>       - phase: "1. Verify"
>         step: "1.1 Verify goals/AC/evidence at current revision; record limits, partials, follow-ups"

### Follow-up
> Supplementary real-Trivy 002-G comparison during 002-D B9 acceptance; 002-G C1 follow-up CR after CR-086.

## DAO-004
- **Timestamp:** 2026-10-24T05:15:42+08:00
- **Task ID:** TASK-058
- **Feature ID:** FEATURE-002-D
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-feature-acceptance-test
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B9 = A, B10 = A
- **Disposition:** critique
- **Confidence:** 0.86

### Message
> Human B9=A: "one-time acceptance-time Trivy DB download via the toolkit's tool_update path inside a disposable container for FEATURE-002-D"; B10=A. At resumption, the TASK-058/059 Docker assets (fat2d-* images, uv cache volume, binary volumes with the official Trivy v0.76.1 linux/arm64 binary sha256:b422130e…) were removed. Running TC-L-01 now would additionally need (1) re-download of the same digest-pinned Trivy v0.76.1 asset from GitHub and (2) re-seeding a uv/pip cache from PyPI to build the image; TC-G-01 further needs iptables + Docker CLI via apt (clearly outside B9). Options: (A) treat (1)+(2) as within B9 and run TC-L-01; (B) escalate (1)+(2) to the human, park TASK-058, run TASK-084 (001-G) next; (C) close acceptance as partial. Owner recommends (B); confirm queue reorder.

### Guidance Returned
> DAO verified the B9 wording in human_decisions.md L14: "Authorize one-time acceptance-time Trivy DB download via the toolkit's `tool_update` path inside a disposable container for FEATURE-002-D".
> **(1)+(2) are NOT covered by B9 → (B).**
> - B9 authorizes exactly one kind of egress: the Trivy vulnerability-DB download through the toolkit's own `tool_update` path. Re-fetching the Trivy binary from GitHub and the Python dependencies from PyPI are different recipients and purposes.
> - DAO-002 (technical design) already ruled that acceptance-time downloads fall outside the earlier tool-validation authorization: "same kind of download" does not extend a purpose-bound grant, and 002-C itself defines egress authorization per purpose. Treating them as covered now would contradict that ruling and the feature's own principle.
> - No representative grant of new network access is possible.
> **Escalate as human item B17**, phrased for a quick answer:
> "For FEATURE-002-D acceptance in a disposable container, authorize re-downloading:
> - (1) the official Trivy v0.76.1 linux/arm64 binary (same pinned digest sha256:b422130e…, GitHub release);
> - (2) the toolkit's Python dependency packages from PyPI to build the test image;
> - optionally (3) apt packages (iptables, Docker CLI) for the real-binary gate case TC-G-01.
> Answer A = (1)+(2), B = (1)+(2)+(3), or C = keep 002-D parked."
> Downloads go into disposable containers/volumes only, never into the repository or the host project tree, with digests recorded.
> **Park TASK-058** at its existing status (FEATURE-002-D stays Implemented / parked on B17; B10 is accepted as a limit). Record the missing-assets finding and that nothing was run.
> **(C) is rejected:** closing acceptance as partial with in-scope ACs unexecuted would be a false completion. The 002-D container regression and the supplementary real-Trivy 002-G comparison (DAO-003 acceptance) stay deferred with it.
> **Queue reorder confirmed: TASK-084 (001-G, demo-relevant) runs next,** then the rest of the code queue as ordered. Include B17 in the next human status summary, alongside B15, B16 and the P6 classification note.

### Rationale
> The human's grant is purpose-specific, and re-acquiring a binary and build dependencies are separate egress purposes, consistent with DAO-002 and the 002-C principle. Parking keeps the evidence honest and lets demo-relevant work proceed.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-code-implementation"
>     match_strength: "strong"
>     reason: "TASK-084 FEATURE-001-G implementation next in the reordered queue"
>     execution_steps:
>       - phase: "1. Implement"
>         step: "1.1 Write failing tests then code (TDD)"

### Follow-up
> Human item B17 (re-download authorization for 002-D acceptance); TASK-058 parked.

## DAO-005
- **Timestamp:** 2026-10-24T08:19:17+08:00
- **Task ID:** TASK-103
- **Feature ID:** FEATURE-001-G
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-feature-acceptance-test
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B13 = H2, B14 = No, B8 = A
- **Disposition:** approval
- **Confidence:** 0.86

### Message
> Acceptance at toolkit 93e3eaa from a frozen git-archive copy (start/end hash identical 44837bb0…): 62/62 active ACs Pass (09a–09e deferred by B13=H2, not counted), 36/36 TCs Pass (container Linux 29, host User 4, frozen drafting tests 269, frozen full suite 2884/0/5 skipped, delivered runners 001-A/B/C/D/F pass). Disclosures: run1 runner bug fixed + rerun (run1 kept); full-suite run1 env failure (frozen copy lacked repo .github/copilot-instructions.md) → run2 clean; AC-05d nuance. No product defect. O-084-1: when an unsupported language prevents the pre-check, draft-check prints the refused provenance URL unmasked — outside AC-001G-02d precondition → AC Pass, residual Low gap. Committed 5df4967 (acceptance-test-cases.md 712bf597…). Questions: (1) proceed to Feature Closing? (2) O-084-1 routing (a) Low bug task after TASK-102, (b) known limit only, (c) CR candidate; owner rec (a). (3) Closing: proportionate review = code review (PASS) + acceptance; closing report + board Completed + local commit.

### Guidance Returned
> DAO verified:
> - acceptance doc SHA 712bf597…: status "Verified delivery — 62/62 active ACs Pass; 36/36 TCs Pass… Stakeholder outcome not measured" (L5); 09a–09e "deferred by human decision B13 = H2 — not tested and never reported passed" (L3); spec v1.3.3 4cb3a1eb… and design v1.2 5e0f2aa8… bound (L13–14);
> - git log: 93e3eaa (implementation), 5df4967 (acceptance).
> **(1) Accepted → Feature Closing for FEATURE-001-G.** The evidence is revision-bound (frozen copy, identical start/end hash), the disclosures are honest (run1 kept, not overwritten), and there is no product defect. The closing report must carry:
> - 09a–09e as "deferred by human decision B13 = H2" (never passed; any future explanation work needs a new human decision or CR);
> - B14 = No (internal drafting refused in this environment; tests used `@SYNTH` only);
> - the DAO-004 code-implementation closing notes (I3 AC-08a interpretation, I7 extra read-only helpers, I11 `blocking` field, I13 hash-fixture maintenance points, the R1 design erratum, the P3a spec wording erratum);
> - the honest limits (tamper-evident markers only, heuristic lint, non-Python syntax not validated, scripted ledgers not live-model proof, no-egress claim bounded);
> - stakeholder outcome not measured;
> - the O-084-1 residual;
> - the human follow-up C4 (relabel CWE/OWASP seed content after 001-G ships).
> **(2) O-084-1 → (a), a separate Low bug-fix task after TASK-102, within DAO defect-fix authority.** Echoing agent-supplied provenance text unmasked when the pre-check is skipped is inconsistent with the feature's display-masking intent (AC-001G-02d/03i: values never appear in output). Scope:
> - apply the existing deterministic masking (or omit the refused URL value and show only host + reason) to every displayed draft-derived text, regardless of whether the pre-check ran;
> - no new output kind or code;
> - test first, with a credential-like token in a refused URL plus an unsupported language;
> - re-run the 001-G drafting tests.
> Disclose it in the closing report as a known Low residual until fixed.
> **(3) Closing review → accepted as proportionate,** on the condition that the passed independent code review and the acceptance are bound to the same revision (93e3eaa or the code-review revision with no product change since).
> - If any product file changed after the code review, an independent delta review of that change is required before Completed.
> - Then the closing report, the board set to Completed (owner's single writer), and a local exact-path commit (B8, no push).

### Rationale
> Acceptance is complete and honest at a pinned revision with human-deferred items clearly excluded; the residual is a small secret-hygiene inconsistency best fixed as its own reproduced task; closing relies on reviews already bound to the accepted revision.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-feature-closing"
>     match_strength: "strong"
>     reason: "Engineering-next after passing acceptance"
>     execution_steps:
>       - phase: "1. Verify"
>         step: "1.1 Verify goals/AC/evidence at current revision; record limits, deferrals, residuals"
>   - skill_name: "x-ipe-task-based-bug-fix"
>     match_strength: "partial"
>     reason: "O-084-1 Low bug task after TASK-102"

### Follow-up
> Low bug task O-084-1 (mask refused provenance URLs) after TASK-102; human follow-up C4 after 001-G closing.

## DAO-006
- **Timestamp:** 2026-10-24T10:30:26+08:00
- **Task ID:** TASK-058
- **Feature ID:** FEATURE-002-D
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-feature-acceptance-test
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B9 = A, B10 = A, B17 = A (apt not authorized)
- **Disposition:** approval
- **Confidence:** 0.80

### Message
> B17 = A run at frozen f18423e (hash 44837bb0… start=end), committed c567207; doc acceptance-test-cases.md 1cad05c3…: archive e174dff2… and binary b422130e… matched pins before use; PyPI not needed. TC-L-01 live provisioning via the adapter (one-time B9 grant) PASS 17/17 (DNS only mirror.gcr.io, SNI ×3, destinations only that IP:443 + Docker resolver; offline scan afterwards zero frames; ghcr.io loopback only). ACs 46/46 Pass (01a on arm64; x86-64 = B10 limit). TCs 25/29 (Partial TC-D-01 444/445 — non-AC x86-64 check; Partial TC-R-01 superseded 002-B check; TC-G-01 real-binary gate not executed — needs apt, not authorized; TC-X-01 B10 limit). Suite 2884/5 skipped; 8 regressions byte-identical. Limits: live failure branches loopback-only; observation-only network evidence; no independent review of the evidence yet. DAO-002 said 002-D must not be marked done while B9/B10 not executed. Rule: (a) accept → independent evidence review → Feature Closing (TC-G-01 human-scoped non-execution); (b) keep parked until TC-G-01 runs (human B17-B); (c) other. Owner rec (a).

### Guidance Returned
> DAO verified:
> - acceptance doc SHA 1cad05c3… (status L4: 46/46 ACs pass, TC-L-01 live pass, TC-G-01 not executed because apt was not authorized, outcome not measured; resumed-run section L302 ff.: pinned archive/binary verified before execution, one B9 provisioning request, offline scan with zero frames, container 444/445 with the one failing non-AC x86-64 check, observation limits stated at L61);
> - human_decisions.md L56: B17 = A, with "apt packages (iptables, Docker CLI) NOT authorized";
> - 002-D design L678/L684: "Mandatory real-binary acceptance … required before closing; not skippable".
> **Decision: (a), with conditions.**
> - DAO-002's condition is now met for every in-scope AC: all 46 ACs executed and pass, B9's live branch ran for real (TC-L-01), and B10 is a human-accepted limit.
> - The remaining obstacle is TC-G-01, a verification means that the DAO-confirmed design made mandatory, not an AC. The human was offered B17-B (which would enable it) and chose A, so its non-execution is human-scoped and must never be reported as passed.
> - Re-scoping a DAO-confirmed design gate, with an equivalence check, is within DAO authority. Option (b) would hold a 46/46-AC feature hostage to a means the human declined to authorize.
> Conditions:
> 1. **Design erratum (DAO-attributed, non-destructive):** the "mandatory real-binary gate before closing" becomes "TC-G-01, or an executed check-by-check equivalent from real-binary evidence (TC-L-01 + TC-D container cases with the official binary), confirmed by the independent evidence review; any TC-G-01 assertion without executed equivalent evidence is a disclosed limit".
> 2. **Independent review of the acceptance evidence before closing.** It must explicitly map every assertion of `tests/guard/test_trivy_real.py` to executed evidence or list it as uncovered. If an uncovered assertion is verdict-relevant for a confirmed AC, closing stops and that AC goes back to the human (B17-B).
> 3. Report TC-G-01 as "not executed — human-scoped (B17 = A, apt not authorized)", TC-X-01 as "B10 accepted limit", and TC-D-01's single failing check as non-AC (x86-64, outside B17). Keep the limits: live failure/timeout/cancel branches loopback-only; network evidence is observation-only, with no enforcement claim; Host headers inside TLS are not observable.
> 4. **Deferred items now unblocked:** run the supplementary real-Trivy 002-G comparison (DAO-003 acceptance), using the provisioned local components only, with no new download beyond B9/B17. Run it if feasible before closing; otherwise run it as a separate small task.
> 5. **Human status summary:** say that 002-D closes without TC-G-01, per their B17 = A choice, and that B17-B (apt) remains available to run it later.
> Then Feature Closing (proportionate review = the evidence review), the board set to Completed by the owner, and a local exact-path commit (B8).

### Rationale
> Every confirmed AC is executed and passing, including the real live provisioning the human authorized; the only gap is a DAO-mandated verification means whose prerequisites the human explicitly chose not to authorize. Replacing it with a reviewed, check-by-check equivalent keeps assurance honest without overriding the human's network decision.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-feature-closing"
>     match_strength: "strong"
>     reason: "After the independent evidence review with the TC-G-01 equivalence map"
>     execution_steps:
>       - phase: "1. Verify"
>         step: "1.1 Verify goals/AC/evidence; record limits and human-scoped non-execution"

### Follow-up
> Supplementary real-Trivy 002-G comparison; human informed that B17-B can still enable TC-G-01.

## DAO-007
- **Timestamp:** 2026-10-24T23:01:15+08:00
- **Task ID:** TASK-111
- **Feature ID:** FEATURE-002-F
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-feature-acceptance-test
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human B12 = A, P-01 clarification confirmed (12:24)
- **Disposition:** critique
- **Confidence:** 0.86

### Message
> Acceptance at frozen 73fe2dc (hash f7a155a4… start=end): 73/74 active ACs Pass, AC-002F-04l FAIL on one clause (D-1, minor): TC-F-27 helper writing 3 MiB into the results area is stopped and nothing over the limit kept, but the reported limit is "tmp limit reached" instead of the results-size limit (execute_io.ERRNO_HINTS maps every ENOSPC to /tmp). TCs 51: 46 Pass, 1 Fail, 4 Partial. Real runtime Docker Desktop: registration (GPG_KEY labelled public), 20/20 probes, Guard flow accepted_full/partial, timeout and cancel kill, 236 containers all --network none, no leftovers. Regression partials: 001-G TC-G-33 and 002-G TC-G-23 pin pre-002-F bytes; 002-D TC-H-01 needs removed B17 assets. Maintainer steps via throwaway trust store, never auth init on host. TASK-098 (001-E) owns the live tree now. Options: (a) bug-fix task for D-1 after TASK-098 (RED first on TC-F-27; re-run TC-F-27/21/51 on a new frozen copy), then closing; (b) accept the wrong name as limit. Also: accept 001-G/002-G byte-pin partials as expected?

### Guidance Returned
> DAO verified:
> - acceptance doc SHA e58c0bc4…: status "Blocked — 73/74"; D-1 detail L241; regression partials L255–261;
> - spec AC-002F-04l (L117): "the method is failed naming the limit AND no oversized output is retained".
> **D-1 → (a).** AC-002F-04l explicitly requires naming the limit, so the misnamed limit fails a confirmed clause. (b) is rejected: accepting it would rewrite a failed AC by representative approval, which DAO may not do.
> Bug-fix task right after TASK-098 releases the live tree (serialization respected):
> - RED first on the TC-F-27 scenario;
> - classify ENOSPC by the failing path/mount (results area → results-size limit L-07/L-08 as specified; `/tmp` → tmp limit), with no new output kind, only the correct existing limit name;
> - re-run TC-F-27, TC-F-21 and TC-F-51 on a new frozen copy at the fixed revision, plus the full suite;
> - append the new evidence to the acceptance doc (never edit the original Fail);
> - an independent review of the fix.
> FEATURE-002-F stays Implemented and is not closed until D-1 passes. Then Feature Closing.
> **Regression partials:**
> - **001-G TC-G-33 and 002-G TC-G-23 → accepted as expected change-set pins,** on the condition that the acceptance doc lists every differing file and shows each is within 002-F's closed list §1.1 (DAO-017) or a ruled maintenance point (DAO-005/006 code implementation). They are reported as "Partial (expected 002-F change)", never as Pass, and the original 001-G/002-G evidence is not edited. Any differing file outside that set is a defect and stops closing.
> - **002-D TC-H-01 → environment partial, recorded** (same precedent as the 002-G acceptance; the container regression stays host-only, with no new download).
> **Method notes accepted:** Maintainer steps via a throwaway trust store, following the delivered real-runtime test method; no `auth init` on the host; one-runtime honest limits.

### Rationale
> A failed explicit AC clause must be fixed, not waived by the representative; the fix is small and correctly sequenced behind the live-tree owner. The byte-pin partials are expected consequences of ruled 002-F changes, acceptable only with an explicit file-by-file justification.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-bug-fix"
>     match_strength: "strong"
>     reason: "D-1 fix after TASK-098 (RED first), then re-run affected TCs"
>     execution_steps:
>       - phase: "Reproduce"
>         step: "Write a failing test first, then fix"
>   - skill_name: "x-ipe-task-based-feature-closing"
>     match_strength: "partial"
>     reason: "After D-1 passes"

### Follow-up
> D-1 bug task queued after TASK-098; 002-F closing after D-1 evidence.
