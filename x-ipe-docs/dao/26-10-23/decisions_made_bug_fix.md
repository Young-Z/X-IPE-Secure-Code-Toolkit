# DAO Decisions: Bug Fix

> Semantic log of human representative interactions grouped by task type.
> Each entry records a DAO interaction with full context and rationale.

| Entry | Timestamp | Task ID | Calling Skill | Disposition | Confidence | Summary |
|-------|-----------|---------|---------------|-------------|------------|---------|
| DAO-001 | 2026-10-24T00:57:38+08:00 | TASK-079 | x-ipe-task-based-bug-fix | approval | 0.86 | FEATURE-001-A unreadable AGENTS.md: DEC-1…3 A approved (refuse like non-UTF-8, file + OS reason, existing next step); DEC-4 → separate bug-fix task (reproduce first) for the unopenable skills-folder file, a defect against 001-A edge case L192 within DAO defect-fix authority; TASK-079 closes after the running independent code review |

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
