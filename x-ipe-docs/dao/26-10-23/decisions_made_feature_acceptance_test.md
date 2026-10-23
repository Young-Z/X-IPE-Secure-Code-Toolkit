# DAO Decisions: Feature Acceptance Test

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-23T06:06:53+08:00 | TASK-058 | x-ipe-task-based-feature-acceptance-test | approval | 0.84 | FEATURE-002-D: Bug Fix for F-1 (9 misconfig types incl. ansible) and F-2 (exact-match WARN allow-list, fail-closed) without spec change; rerun; park at acceptance under existing status (B9); then FEATURE-003-B |
| DAO-002 | 2026-10-23T17:47:54+08:00 | TASK-070 | x-ipe-task-based-feature-acceptance-test | approval | 0.85 | FEATURE-001-F acceptance PASS accepted (63/63, 3 superseded, 001-D 02b clauses superseded/re-run) → Feature Closing; O-1 interpretation confirmed (existing knowledge lock file on first use, consistent with DAO-004 (1)); O-2 recorded as optional human CR/polish candidate, not a defect |
| DAO-003 | 2026-10-24T00:06:26+08:00 | TASK-091 | x-ipe-task-based-feature-acceptance-test | approval | 0.86 | FEATURE-002-G acceptance PASS (76/76 at 15985026…) accepted → Feature Closing; unit/integration evidence accepted (02c/02h/04f are Unit by spec; 07g/07h/07j Integration via in-process hooks; 05l simulated + limit); host-only 002-D regression accepted (no 002-D code touched; container re-run at 002-D B9 acceptance; no new downloads now); wording readings confirmed |

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
