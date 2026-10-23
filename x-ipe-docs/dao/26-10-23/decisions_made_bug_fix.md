# DAO Decisions: Bug Fix

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-24T00:57:38+08:00 | TASK-079 | x-ipe-task-based-bug-fix | approval | 0.86 | FEATURE-001-A unreadable AGENTS.md: DEC-1…3 A approved (refuse like non-UTF-8, file + OS reason, existing next step); DEC-4 → separate bug-fix task (reproduce first) for the unopenable skills-folder file, a defect against 001-A edge case L192 within DAO defect-fix authority; TASK-079 closes after the running independent code review |
| DAO-002 | 2026-10-24T01:45:57+08:00 | TASK-095 | x-ipe-task-based-bug-fix | approval | 0.84 | FEATURE-001-A unreadable skill target + FIFO host entry: DEC-1 (SKILL_NAME_CONFLICT + reason), DEC-2 (existing design code IO_ERROR, blocking even with --replace), DEC-3 (HOST_ENTRY_UNREADABLE 'not a regular file' before open) approved; optional O_NONBLOCK+fstat hardening against check-then-open race; DEC-4 FIFO at install record → separate low-priority candidate with a sweep of init-path reads, reproduce first |

---

<!-- Detail sections are appended below this line -->

## DAO-001
- **Timestamp:** 2026-10-24T00:57:38+08:00
- **Task ID:** TASK-079
- **Feature ID:** FEATURE-001-A
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-bug-fix
- **Source:** ai (lifecycle owner "Sage"); delegation continues; human "bug yes" (human_decisions.md 20:38)
- **Disposition:** approval
- **Confidence:** 0.86

### Message
> Bug: plain init crashed on unreadable AGENTS.md. Root cause: project_init._plan_and_apply host.read_bytes() unguarded; 001-A spec/design already require HOST_ENTRY_UNREADABLE refusal before any write. Fix (project_init.py +8 lines, 7a66080e→65100976): refuse like non-UTF-8 host file — fragment: unreadable, problem HOST_ENTRY_UNREADABLE naming the file + OS reason, existing next step "Resolve the listed problems; nothing was written", exit 1, nothing written. 4 new tests red→green; delivered tests and 001-A baselines byte-identical; full suite 2502/0; ruff clean. Report bug-report-TASK-079.md. Independent code review running. Decide DEC-1 unopenable = non-UTF-8 handling; DEC-2 message names file + OS reason; DEC-3 reuse existing refusal next step; DEC-4 unopenable file in the skills folder probably still crashes init (unreproduced) — fix here or separate bug candidate?

### Guidance Returned
> DAO verified:
> - bug report SHA ca4907cb… (112 lines; DEC-1…4 at L86–89; observation L40);
> - `project_init.py` SHA 65100976…: L169–175 catch OSError on the host read and emit `HOST_ENTRY_UNREADABLE`;
> - 001-A design L210 lists the code, and L266 ("decode as UTF-8 (strict) else HOST_ENTRY_UNREADABLE");
> - 001-A spec L192: "Read-only filesystem or permission denied during install → Fail with reason; no partial install reported as success".
> - **DEC-1 → A.** This is a defect fix that restores designed behavior: the same code, `fragment: "unreadable"` and blocked outcome as non-UTF-8, consistent with carriers. No AC text changes.
> - **DEC-2 → A.** The message names the file and the OS reason (e.g. "Permission denied"), never file content. The non-UTF-8 message is unchanged.
> - **DEC-3 → A.** Reuse the existing refusal next step; no new output kind.
> - **DEC-4 → a separate bug-fix task, not folded into TASK-079.** It is a distinct code path (`_plan_file` hashing a skill target), it is unreproduced, and the human-approved bug is specifically the host entry. Keeping TASK-079 bounded keeps its review and evidence clean. The candidate does contradict delivered 001-A behaviour if reproduced (spec L192: permission denied during install → fail with reason, not a traceback), so it falls within DAO defect-fix authority and needs no new human approval. Open it as a separate bug-fix task in the serialized code queue:
>   - reproduce first with a failing test;
>   - if it is not reproducible, record it as not a defect and close;
>   - if it is reproduced, refuse with a reason before any write, using an existing problem code if one fits (no new output kind without a design note), and keep delivered tests and baselines byte-identical.
>   Mention it to the human in the next status summary.
> TASK-079 closes after the running independent code review passes. Then re-run the 001-A regression (black-box) and the full suite at the final revision, and append a note to the 001-A evidence citing TASK-079 (never edit old results). Commit locally only, by exact path (B8).

### Rationale
> The fix restores behavior the delivered 001-A spec and design already require, with no contract change. The skills-folder case is a separate defect candidate that the bug-fix procedure must reproduce first; delegated defect-fix authority covers it without widening the human-approved task.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-bug-fix"
>     match_strength: "strong"
>     reason: "Finish TASK-079 after review; open a separate bug-fix task for the skills-folder read"
>     execution_steps:
>       - phase: "Reproduce"
>         step: "Write a failing test first, then fix"

### Follow-up
> Separate bug-fix candidate: unopenable skill target file in `_plan_file` (reproduce first).

## DAO-002
- **Timestamp:** 2026-10-24T01:45:57+08:00
- **Task ID:** TASK-095
- **Feature ID:** FEATURE-001-A
- **Workflow:** N/A
- **Calling Skill:** x-ipe-task-based-bug-fix
- **Source:** ai (lifecycle owner "Sage"); defect fix authorized by DAO-001 (bug fix); delegation continues
- **Disposition:** approval
- **Confidence:** 0.84

### Message
> Fix in project_init.py (+17/−4), 8 new tests red→green, full suite 2511/0, ruff clean, delivered tests + 001-A baselines byte-identical; report bug-report-TASK-095.md; independent code review running. Decide: DEC-1 fresh project, foreign unreadable file at a skill path → SKILL_NAME_CONFLICT (existing message + "; it cannot be read (<OS reason>)"); DEC-2 re-init, toolkit-installed skill file unreadable → IO_ERROR (existing 001-A code?) under files.conflicts, refused even with --replace; DEC-3 non-regular host entry (FIFO) → HOST_ENTRY_UNREADABLE "(not a regular file)", checked before opening; DEC-4 a FIFO at the install-record path may still block init (unreproduced) → separate candidate or fold in?

### Guidance Returned
> DAO verified:
> - bug report SHA d7773225…: reproduction of the unreadable skill-file traceback, the FIFO host block and the observation at L44;
> - `project_init.py` (now ac770f8f…): L47–51 (`_plan_file` regular-file check, OSError → conflict with read_error), L174–180 (host regular-file check before read → `HOST_ENTRY_UNREADABLE`) and L192–200 (recorded file → `IO_ERROR`, otherwise `SKILL_NAME_CONFLICT` with the reason appended);
> - 001-A design L210 (problem codes include `SKILL_NAME_CONFLICT`, `LOCALLY_EDITED`, `HOST_ENTRY_UNREADABLE`), L258 (no record and differing file → `SKILL_NAME_CONFLICT`, blocking) and L346 (`IO_ERROR` is an existing designed code for permission denied);
> - 001-A spec L191 (non-toolkit same-named skill → refuse, report conflict) and L192 (permission denied during install → fail with reason, no partial install).
> Decisions:
> - **DEC-1 → approved.** No install record means the design table classifies the file as a conflict, and an unreadable file cannot be shown to equal the payload. So it is a blocking `SKILL_NAME_CONFLICT`, with the OS reason appended (no content). Nothing is written.
> - **DEC-2 → approved.**
>   - `IO_ERROR` is an existing designed 001-A code (design L346), so this adds no new output kind.
>   - Refusing even with `--replace` is the conservative reading of spec L192, because the toolkit cannot compare or safely replace a file it cannot read. The next step names restoring readability/permissions, then re-running.
>   - `LOCALLY_EDITED` is correctly not used: it would keep and continue, implying the file was compared.
> - **DEC-3 → approved.** It matches `status`/`carriers` (`is_file()`), and the lock is never held on a blocking read.
>   - Optional hardening, if trivial and still byte-identical for regular files: close the check-then-open window by opening with `O_NONBLOCK` and confirming `S_ISREG` via `fstat` on the opened descriptor.
>   - Otherwise state the residual race as a Low honest limit.
> - **DEC-4 → separate low-priority bug candidate, not folded in.** It is a different module (`install_record.load`), it is unreproduced, and the independent review of TASK-095 is already running. The candidate should:
>   - reproduce first;
>   - sweep every path `init`/`status` reads (toolkit-owned files under `.x-ipe/private/secure-code/` and the payload) for exists-then-read patterns, so the regular-file check is applied once, consistently;
>   - use existing problem codes only.
>   It stays within DAO defect-fix authority under spec L192/NFR-001A-5. It joins the code queue after the current items.
> Closing conditions for TASK-095 (same as DAO-001):
> - independent code review passes (or its findings are fixed and re-reviewed);
> - 001-A black-box regression and full suite at the final revision;
> - a non-destructive evidence note citing TASK-095;
> - local commit by exact path only (B8).

### Rationale
> All three outcomes use designed 001-A codes and restore the spec's "fail with reason, nothing written" behavior without contract change; the remaining FIFO case is a distinct, unreproduced path best handled as a bounded sweep rather than expanding a task under review.

### Suggested Skills
> suggested_skills:
>   - skill_name: "x-ipe-task-based-bug-fix"
>     match_strength: "strong"
>     reason: "Close TASK-095 after review; open the install-record/read-path sweep candidate (reproduce first)"
>     execution_steps:
>       - phase: "Reproduce"
>         step: "Write a failing test first, then fix"

### Follow-up
> Low-priority bug candidate: FIFO/non-regular toolkit-owned files read by init/status (install record and similar), reproduce first.
