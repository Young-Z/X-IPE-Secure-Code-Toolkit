# DAO Decisions: Feature Acceptance Test

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-23T06:06:53+08:00 | TASK-058 | x-ipe-task-based-feature-acceptance-test | approval | 0.84 | FEATURE-002-D: Bug Fix for F-1 (9 misconfig types incl. ansible) and F-2 (exact-match WARN allow-list, fail-closed) without spec change; rerun; park at acceptance under existing status (B9); then FEATURE-003-B |
| DAO-002 | 2026-10-23T17:47:54+08:00 | TASK-070 | x-ipe-task-based-feature-acceptance-test | approval | 0.85 | FEATURE-001-F acceptance PASS accepted (63/63, 3 superseded, 001-D 02b clauses superseded/re-run) → Feature Closing; O-1 interpretation confirmed (existing knowledge lock file on first use, consistent with DAO-004 (1)); O-2 recorded as optional human CR/polish candidate, not a defect |

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
