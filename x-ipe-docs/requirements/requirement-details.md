# Requirement Summary

> Part 1 (single active file). Language: English; stable IDs, paths and schema keys are not translated.

## EPIC-001: AI-secure-code-toolkit-v2

> Task: TASK-002 (Requirement Gathering) · Created: 2026-10-18 · Source idea: [idea-summary-v2](<x-ipe-docs/ideas/Draft Idea - 10142026 153612/refined-idea/idea-summary-v2.md>) · Detailed decision baseline: [feature inventory v2](<x-ipe-docs/ideas/Draft Idea - 10142026 153612/secure-code-toolkit-v2-feature-inventory-v2.md>)

### Project Overview

**What.** AI-secure-code-toolkit-v2 is a security-quality toolkit for AI-assisted development, made of three self-contained skills that cooperate:

| Skill | Responsibility | Not responsible for |
|---|---|---|
| **Framework** | Formal security knowledge (Local, later Reference), Policy resolution and scope selection, structured knowledge output, status, local signed authorization verification, tool profiles and the prebuilt scanner **Adapters** (code lives in Framework `scripts/`), single-source host integration | Deciding scan strategy (that is Guard's) |
| **Copilot** | In-flow collaborator during design, implementation, bug fix and refactor: concrete Policy-based suggestions, then an independent read-only adoption review | Writing business artifacts (the current executor does), passing/approving work |
| **Guard** | Verifies already-formed designs or implementations: builds a check plan, chooses methods/parameters, calls Adapters or semantic review, independently re-checks findings, reports a three-state conclusion | Fixing or orchestrating remediation |

**Who.** Developers/Users, Maintainers/Admins, upstream development agents/workflows and read-only Reviewer sub-agents (see idea summary "Target Users").

**Why.** The legacy toolkit (`study-case/secure-coding-guidance`) mixed responsibilities and timing, conflated imported/selected/adopted rules, trusted verbal claims ("adopted", "reviewer passed", "tool exited 0") as evidence, let suggestions pile up, relied on prompts for authority, and let host integrations conflict. v2's upgrade goal: **maintainable knowledge, context-aware invocation, bounded execution, evidence-backed results, controlled cost**.

**Form.** An X-IPE-named skill package set, implemented as SKILL.md skills plus a **uv-managed Python namespace of scripts**. The toolkit's runtime **must not hard-depend on X-IPE task boards, workflows or lifecycle skills**; it must be usable by any upstream agent that can call skills/scripts.

### User Request

- Original request: [new idea.md](<x-ipe-docs/ideas/Draft Idea - 10142026 153612/new idea.md>) — build an upgraded secure-code skills toolkit based on the legacy version, using an interactive capability checklist.
- Ideation (TASK-001, completed 2026-10-18) produced the refined summary v2 and inventory v2: 207 confirmed, 40 undecided, 5 unapproved suggested defaults, 5 deferred, 6 excluded items.
- User decision 2026-10-18: leave undecided and suggested-default items open (suggested defaults are **not** in scope) and proceed to build via the standard process.
- Delta type: **standard new** (empty requirement inventory; first Epic).

### Clarifications

| Question / Decision | Answer | Evidence / Rationale |
|---|---|---|
| Handle 40 undecided (待定) + 5 suggested-default (建议默认) inventory items now? | No. Keep them open; resolve in refinement/technical design as needed. Suggested defaults are not approved and not in scope. | User, 2026-10-18 (TASK-001 / TASK-002 chat), interact-with-human |
| MVP phasing | Three phases: MVP / Phase 2 / Phase 3 (see Scope). Copilot and Guard both in MVP. | User accepted recommendation |
| Scanner Adapters in MVP | **All three: Opengrep, Trivy, Strix** | User chose (over recommendation "Opengrep only") |
| Maintainer authorization in MVP | **Local signed authorization (U-07…U-13) in MVP** | User chose (over recommendation "simple init") |
| Implementation form | X-IPE package naming; SKILL.md skills + standalone uv Python script namespace; no hard dependency on X-IPE tasks/workflows/board | User |
| Requirement document language | English | User |
| Strix-related safety items | Budget/cancel (B), network/data-egress purposes (E-01/E-02) and Strix read-only-original feasibility move **into MVP** | User accepted recommendation |
| Host integration carriers in MVP | **All three**: system-prompt fragment, AGENTS.md entry, GitHub instructions — generated from one source | User chose |
| AI hosts verified in MVP | GitHub Copilot (CLI + VS Code) only | User accepted recommendation |
| MVP acceptance samples | `study-case/secure-coding-guidance/playground/shanghai-marathon-registration` (Python) and `study-case/secure-coding-guidance/playground/test-projects/WebGoat` (Java) | User accepted recommendation |
| Ideation critique items carried here | MVP slicing defined here; host-loading **automatic** acceptance stays deferred (I-19); MVP still needs manual/E2E smoke evidence that the toolkit is actually invocable on GitHub Copilot | Idea summary v2 critique decisions |

### High-Level Requirements

Each FR lists its delivery phase and the inventory IDs it covers (the inventory row text is the detailed, authoritative wording). Excluded (不纳入), deferred (暂缓), undecided (待定) and suggested-default (建议默认) items are **not** included unless explicitly noted.

| FR | Phase | Requirement (summary) | Inventory IDs |
|---|---|---|---|
| FR-01 | MVP | **Three-skill roles & boundaries**: Framework / Copilot / Guard responsibilities; executor is the single business writer; Reviewers hold no extra authority | O-01…O-06 |
| FR-02 | MVP | **Shared Reviewer record**: real host invocation source, review requirement, target revision/digest and actual result bound together; unknown-source, incomplete, wrong-version or stale passes are invalid | O-07, O-08 |
| FR-03 | MVP | **First-use path & status**: controlled install of toolkit + prebuilt Adapters → explicit owner initialization → maintain Policies → select scope → explicit host integration → authorized collaboration/verification → report; status reports install / authorization / Policies / tool conditions / host-effect separately (no single "Ready") | O-09, O-10, X-11, X-12, I-20 |
| FR-04 | MVP | **Local knowledge identity**: institution/source-version/rule-ID organization; `@CUSTOM` and custom `@namespace`; traceable source location | K-01 (Local part), K-02…K-08 |
| FR-05 | MVP | **Local content, versions & changelog**: coexisting source versions, one current formal content per source version, no local snapshot chain, full before/after changelog covering body, metadata and examples; optional safe/unsafe examples; advisory language field never hard-excludes; simple rule relations; new enterprise requirements become custom rules | K-11…K-14, K-16…K-19, K-22 |
| FR-06 | MVP | **Import, retry & pre-check**: batch import storing each rule separately; partial import with per-item status; idempotent resubmission skipping completed unchanged items; prepared-but-uncommitted reuse; identity-based positioning; no auto-merge across sources; empty library on install; formal-knowledge-only verification; lightweight pre-check (suspected secrets etc.) before entry | K-23…K-30, K-32, K-33 |
| FR-07 | MVP | **Knowledge exit & consistency**: maintainer-initiated deactivate/delete/rename with prior impact list (Presets, tags, relations, caches); broken links reported, never silently substituted; known changes invalidate dependent caches; historical reports untouched; single-record update and changelog stay consistent under concurrency/interruption | K-34…K-36, X-15, D-04 |
| FR-08 | Phase 2 | **AI-assisted knowledge drafting**: AI-drafted examples and explanations, labelled and approved by maintainer | K-20, K-21 |
| FR-09 | MVP | **Policy resolution & structured output** (Local): identity, actual requirement, applicability notes, source evidence, retrieval status, unresolved items; no ID-only or "all done" on partial results; Policy availability check (formal source, retrievable content, …) | X-09, X-10 (Local part), X-14 |
| FR-10 | MVP | **Adoption scope selection without Presets**: distinguish library / suggested / adopted scope; user confirms actual adopted scope; selection branches for "clues given but not saved", "no clues", "no default Preset" (Apply All = Policy scope, not artifact scope) | P-01, P-02, P-12…P-14 |
| FR-11 | Phase 2 | **Reference knowledge & exploration**: registered domains/subdomains only; Local-first; cross-call cache (7 days, no renewal on read, explicit refresh) | K-01 (Reference part), X-01…X-03, X-05…X-07, X-10 (Reference part) |
| FR-12 | Phase 2 | **Presets & tags**: one JSON per Preset with concrete rule refs only; `query` intent recomputed only on request with diff; `snapshot_at`; AI-summarized applicability; save-as-Preset branch; JSON tags in `tags/`, exact rule membership, tags never change severity | P-03…P-07, P-09, P-11, T-01…T-04 |
| FR-13 | MVP | **Copilot in-flow collaboration**: covers design, implementation, bug fix, refactor and design changes; concrete artifact-specific suggestions from Framework Policies; one independent read-only Reviewer per batch checks adoption (adopted / partial / not adopted / N/A / cannot verify); high-risk non-adoption and gaps reported to upstream; targeted re-review after relevant change; Markdown report + same-source structured result | C-01, C-02, C-04…C-12 |
| FR-14 | MVP | **Guard input, scope & check plan**: independent invocation; artifact scope separate from Policy scope; artifact-first inputs (design docs, files/dirs, upstream handoff); target vs. read-only context; change semantics (add/delete/rename); Policies → lightweight check list with object, method, required evidence; semantic review + applicable executable checks; formal Policies required, partial availability confirmed with user | V-01…V-10, V-23 |
| FR-15 | MVP | **Finding review & verdict**: normalize/deduplicate with evidence; independent read-only Reviewer for verdict-affecting or disputed items; confirmed / evidenced false positive / unconfirmed kept distinct; verified Medium+ → **Fail**, Low reported; unknown severity never defaults Low; tool exit 0 / zero findings / cancel never equals pass; four-state ledger (met / not met / unconfirmed / N/A) with evidence; objective N/A vs. scope exclusion vs. risk acceptance recorded separately; conflicts kept explicit; minimum evidence per necessary check | V-11…V-17, V-19…V-22, V-24, V-25 |
| FR-16 | MVP | **Prebuilt Adapters — Opengrep, Trivy, Strix**: code in Framework `scripts/`; Guard decides parameters/targets/mode/budget; typed parameter validation, interface wrapping, status and result parsing; no fixed Policy→rule mapping; cheapest sufficient method first; programmatic pre-check (real tool source, verified compatible version, …); failed pre-check never auto-downloads/upgrades/relaxes | A-01…A-09, inventory §9.3 table |
| FR-17 | MVP | **Original-project protection for Strix**: first prove enforced read-only access to the original project (acceptance shows writes are *rejected*); otherwise run on an explicit working copy; never silently relax permissions; no write-back of fixes; report copy scope and environment differences | inventory §9.3 items 1–5 |
| FR-18 | MVP | **Tool feasibility & performance evaluation**: public screening → sandbox tool-level feasibility → thin Adapter → measurement before declaring formal delivery; measure detection, FP/FN, coverage, time, CPU/memory, completion, retries, model usage per tool on the MVP samples; no vendor claims as results | inventory §9.4, S-07 |
| FR-19 | Phase 2 | **Temporary check scripts**: one-off helper scripts only when existing checks are insufficient, with syntax/logic check, independent Reviewer + known positive/negative samples, real execution limits; not auto-promoted to formal knowledge | A-13…A-17 |
| FR-20 | MVP | **Network & data egress**: separate authorization for Reference fetching, tool/vuln-DB updates, requests to the target under test, and submissions to models/third-party services; declare necessary data, recipient and scope before calling; minimize and mask sensitive values; no default source/credential egress, no silent service switch or telemetry | E-01, E-02 |
| FR-21 | MVP | **Shared budget & cancel**: one total budget per verification (semantic review, generation, Reviewer, tools); total time + limited extra attempts; method switches/resumes don't reset; model usage aggregated where measurable, unknown stated; exhaustion stops new attempts with partial results; user cancel stops new calls, requests termination of owned tools, keeps completed results, reports unconfirmed termination honestly | B-01…B-06, B-08…B-10 |
| FR-22 | MVP | **Evidence & reports**: Copilot and Guard Markdown reports + same-source structured return in `reports/copilot/` and `reports/guard/`; raw Guard evidence kept 30 days (no renewal on read; dependency check before cleanup); reports kept until user cleans; retention stated in report; sensitive values masked, no private keys/model credentials; only relevant summaries passed on; risk acceptance recordable by User/authorized upstream without changing facts | R-01…R-09, R-13 |
| FR-23 | Phase 3 | **Cross-run report comparison** on explicit request: new / still present / not observed this time / not comparable | R-11, R-12 |
| FR-24 | MVP | **Roles & local signed authorization**: separate User / Maintainer module; Maintainer has full secure-code maintenance rights; agents act only on real requests or signed pre-authorization; local authorization file verified by Framework scripts with standard digital signature and fixed trusted public key; owner explicit first initialization, no external issuer; normal verification reads only authorization + public key; valid until explicitly revoked, re-checked before maintenance; honest statement that it does not resist someone with local write access | U-01…U-05, U-07…U-13, U-15 |
| FR-25 | Phase 3 | **Bounded improvement suggestions & Lessons**: strict admission, max 10 active, 30-day expiry, 30-day terminal retention, one Markdown per suggestion in `improvements/`, user suggestions must be reviewed, candidate ≠ applied | L-01…L-13 |
| FR-26 | Phase 3 | **Controlled autonomous optimization**: Lesson is evidence not authority; separately signed autonomy policy; explicit trigger; ≤3 Lessons per run; idempotent; auto-apply only low-risk local explanations/examples; skill/Adapter changes only as candidates; protection rules of inventory §13.3/§13.4 | AU-01…AU-13, §13.3, §13.4 |
| FR-27 | MVP | **Single-source host integration (all three carriers)**: Framework keeps one routing definition and generates a system-prompt fragment, default AGENTS.md entry and optional GitHub instructions; skills remain self-contained; Copilot auto-triggers for design/implementation/fix/refactor, Guard only on explicit/authorized verification; de-duplication and no recursion for read-only Reviewers; failed/old reports never count as done; minimal handoff contract per inventory §14.2 | I-01…I-11, §14.2 |
| FR-28 | MVP | **Fragment-level idempotency & maintainer choice**: idempotency only on explicit toolkit-owned fragments (never lock the whole file); edits outside the fragment preserved; no duplicate insertion; differences reported to Maintainer who may ignore/modify/regenerate/accept; first version checks files, managed boundaries and required host metadata only | I-12…I-16, I-18 |
| FR-29 | MVP | **Development sandbox**: maintainer dev/debug installs candidate skills into `.x-ipe/private/secure-code/sandboxes/<id>/`; candidate-package flow; explicit root and artifact scope; workspace isolation is not OS/process/network isolation; small tool-level validation before full Adapter; minimal normal and negative acceptance defined | S-01…S-04, S-06, S-07, S-09 |

### Outcome / Goal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-01 | new idea.md; idea summary v2 "Problem Statement" 1, 3 | Developer, upstream agent | Security measures are applied *during* design/implementation instead of only at a final gate, and adoption is verified rather than claimed | Copilot (FR-13) + Reviewer record (FR-02) + Framework Policies (FR-09) | Qualitative scenario: on an MVP sample change, Copilot gives artifact-specific suggestions, executor applies some, Reviewer report distinguishes adopted / not adopted / cannot verify bound to the current revision | Copilot never writes business code; not a pass/approval | AC-13…AC-15, AC-02 | not measured |
| G-02 | idea summary v2 Problem 3 | Developer, Maintainer, upstream agent | Verification results are trustworthy: no misleading "pass" from tool exit, zero findings, cancellation or stale reviews | Guard (FR-14, FR-15), Adapters (FR-16, FR-17), evidence/reports (FR-22) | Scenario: Guard on WebGoat/marathon samples yields three-state conclusion and four-state ledger consistent with findings, cancel/failure and risk acceptance; known-vulnerable sample is not reported as Pass | Guard never fixes; no percentage coverage score | AC-16…AC-24, AC-28 | not measured |
| G-03 | idea summary v2 Problem 2, 5 | Maintainer | Security knowledge is maintainable and scope-explicit: imported ≠ selected ≠ adopted; changes are traceable and reversible to understand | Framework knowledge (FR-04…FR-07), scope selection (FR-10) | Scenario: maintainer imports, edits, renames and deactivates rules; changelog matches; impact list shown before exit; adopted scope recorded in reports | Empty library on install; no starter pack; no snapshot chain | AC-04…AC-12 | not measured |
| G-04 | idea summary v2 Problem 4 | Developer, Maintainer | Cost is controlled without lowering requirements: repeated imports/tool runs skipped, budget respected, unverified items kept | Idempotent import (FR-06), cheapest-sufficient method + budget/cancel (FR-16, FR-21) | Scenario: resubmitting the same import batch skips unchanged items; a budget-limited Guard run stops new attempts and reports partial results honestly. Per-tool time/cost measured on samples (FR-18) | No complex cost prediction or strict monetary cap | AC-07, AC-25, AC-26, AC-30 | not measured |
| G-05 | idea summary v2 Problem 6; inventory §11 | Maintainer/Owner | Maintenance authority is real, not prompt-claimed; data never leaves without purpose-specific authorization | Signed authorization (FR-24), egress (FR-20), Strix protection (FR-17) | Scenario: without valid signed authorization, maintenance actions are refused with a clear next step; Strix cannot write to the original project or falls back to a working copy; a run without egress permission does not submit source to a model | Local workflow-level only; no enterprise identity service; does not resist local-write attackers | AC-03, AC-23, AC-27, AC-29 | not measured |
| G-06 | idea summary v2 Problem 7 | Maintainer, Developer | Host integrations do not fight each other or overwrite user content | Single-source carriers + fragment-level idempotency (FR-27, FR-28) | Scenario: regenerating carriers changes only toolkit fragments; user edits elsewhere in AGENTS.md survive; differences reported to the Maintainer; manual smoke test shows Copilot/Guard are invocable on GitHub Copilot | Automatic host-loading acceptance deferred (I-19) | AC-31…AC-33 | not measured |
| G-07 | idea summary v2 Problem 5; inventory §12–13 | Maintainer | Learning stays small and useful; autonomous optimization never exceeds signed delegation | FR-25, FR-26 (Phase 3) | Defined during Phase 3 refinement | Phase 3; not part of MVP acceptance | Refinement gap (Phase 3) | not measured |
| G-08 | User decision 2026-10-18 | Upstream agent / any host | The toolkit is usable without X-IPE task/workflow infrastructure | Standalone uv Python namespace + self-contained skills (Constraints) | Scenario: toolkit scripts run and skills are invocable in a project with no X-IPE board/workflow files | — | AC-34 | not measured |

### Requirement Mapping

| Requirement ID | Goal ID | Source / Evidence | Constraints |
|---|---|---|---|
| FR-01, FR-02 | G-01, G-02 | Inventory §2.2; planned evidence AC-01, AC-02 | Reviewer holds no extra authority |
| FR-03 | G-03, G-05, G-06 | O-09/O-10; AC-03 | No single Ready flag; no auto-install of scanners |
| FR-04…FR-07 | G-03 | Inventory §4; AC-04…AC-12 | Empty install; formal knowledge only |
| FR-08 | G-03 | K-20/K-21 | Phase 2 |
| FR-09, FR-10 | G-03 | Inventory §5, §6.2; AC-10…AC-12 | Apply All ≠ artifact scope |
| FR-11, FR-12 | G-03, G-04 | Inventory §5, §6 | Phase 2 |
| FR-13 | G-01 | Inventory §7; AC-13…AC-15 | Executor is single writer |
| FR-14, FR-15 | G-02 | Inventory §8; AC-16…AC-22 | Guard does not fix |
| FR-16…FR-18 | G-02, G-04 | Inventory §9.1, §9.3, §9.4; AC-23, AC-24, AC-28 | No auto-download/upgrade |
| FR-19 | G-02 | Inventory §9.2 | Phase 2 |
| FR-20 | G-05 | Inventory §9.5; AC-29 | No heavy DLP platform |
| FR-21 | G-04 | Inventory §10.1, §10.2; AC-25, AC-26 | Estimates, not hard money caps |
| FR-22 | G-02 | Inventory §10.3; AC-21, AC-22 | Reports not auto-deleted |
| FR-23 | G-02 | R-11/R-12 | Phase 3 |
| FR-24 | G-05 | Inventory §11; AC-27 | Local workflow-level only |
| FR-25, FR-26 | G-07 | Inventory §12, §13 | Phase 3 |
| FR-27, FR-28 | G-06 | Inventory §14; AC-31…AC-33 | Auto host-loading acceptance deferred |
| FR-29 | G-02, G-05 | Inventory §15; AC-30, AC-35 | Workspace ≠ OS isolation |
| NFR-01 (standalone form) | G-08 | User decision; AC-34 | No hard X-IPE runtime dependency |

### Acceptance Criteria

MVP acceptance criteria (Given/When/Then). Phase 2/3 FRs receive acceptance criteria during their feature refinement. Concrete schemas, command names, budgets and thresholds are set in technical design or first measurement, not here.

**Roles, first use, status**
- **AC-01** (FR-01) Given a Copilot or Guard run, When it completes, Then no business artifact was written by Copilot, Guard or a Reviewer; only the current executor modified artifacts.
- **AC-02** (FR-02) Given a Reviewer result whose source is unknown, incomplete, or bound to an older target revision/digest, When Copilot or Guard consumes it, Then it is not counted as a valid review and the report says so.
- **AC-03** (FR-03, FR-24) Given a fresh install, When the user asks for status or tries to verify, Then status reports install, authorization, Policies, tool conditions and host-effect separately, and each missing condition (no authorization, empty library, missing tool) gets its own accurate next step; the toolkit never self-authorizes or self-installs scanners.

**Knowledge**
- **AC-04** (FR-04) Given rules from an institution source version and from `@CUSTOM`, When imported, Then each is addressable by namespace/source-version/rule-ID and keeps its source location (or an explicit "missing" mark).
- **AC-05** (FR-05) Given a formal rule edit, When it is saved, Then exactly one current content exists for that source version and the changelog holds the full before/after for body, metadata and examples.
- **AC-06** (FR-06) Given a batch with some invalid items, When imported, Then valid items are stored individually and the result lists succeeded / failed / unprocessed items with reasons.
- **AC-07** (FR-06) Given the same batch is resubmitted after interruption, When processed, Then completed unchanged items are skipped and reused; changed inputs are not silently overwritten.
- **AC-08** (FR-06) Given knowledge containing a suspected secret or an uncertain item, When pre-checked, Then entry is flagged for the maintainer instead of silently accepted.
- **AC-09** (FR-07) Given a maintainer deactivates, deletes or renames a rule that other rules relate to, When the action is requested, Then an impact list (rule relations and caches in MVP; the impact contract stays extensible) is shown first; afterwards broken references are reported, never silently substituted, and historical reports are unchanged. Preset and tag impact detection is verified with non-empty fixtures when FR-12 lands in Phase 2.
- **AC-10** (FR-07) Given concurrent or interrupted updates to one rule, When they finish, Then body, metadata, examples and changelog are consistent and a half-written update is never reported as success.

**Scope & Policy resolution**
- **AC-11** (FR-09, FR-10) Given no formal usable Policies, When Copilot or Guard is invoked, Then it returns "maintenance needed" and invents no rules; Given partially usable Policies, Then available / missing / unclear items are listed and work proceeds only after user confirmation, with the actual adopted scope in the report.
- **AC-12** (FR-10) Given no clues and no default Preset, When scope is selected, Then Apply All applies to Policy scope only, and the artifact scope is still determined separately.

**Copilot**
- **AC-13** (FR-13) Given a design/implementation/bug-fix/refactor task with usable Policies, When Copilot assists, Then suggestions are concrete and tied to the specific artifact and Policy source.
- **AC-14** (FR-13) Given the artifact is formed, When adoption is reviewed, Then one independent read-only Reviewer checks the batch and each suggestion is marked adopted / partial / not adopted / N/A / cannot verify; high-risk non-adoption is reported to upstream.
- **AC-15** (FR-13, FR-22) Given a Copilot run, When finished, Then a Markdown report in `reports/copilot/` and a same-source structured result are produced.

**Guard**
- **AC-16** (FR-14) Given Guard is invoked without a Copilot report, When scope is explicit, Then Guard verifies independently; an existing Copilot report is used only as context, never as a pass.
- **AC-17** (FR-14) Given Apply All, When Guard plans, Then the artifact scope is not expanded to the whole project unless explicitly requested.
- **AC-18** (FR-14, FR-15) Given usable Policies, When Guard plans, Then each necessary check declares object, method and minimum evidence, and the ledger records met / not met / unconfirmed / N/A with evidence and reasons.
- **AC-19** (FR-15) Given the default threshold and a verified Medium/High/Critical finding, When concluded, Then the conclusion is **Fail**; Low findings are reported without failing; unknown severity is not treated as Low. (Threshold configuration authority/interface remains open per V-16; risk acceptance never alters findings or conclusions.)
- **AC-20** (FR-15) Given a tool exits 0 with zero findings but necessary evidence is missing, When concluded, Then the conclusion is **Cannot confirm pass**, not Pass.
- **AC-21** (FR-15, FR-22) Given a recorded risk acceptance, When reported, Then the finding, severity and conclusion are unchanged and the acceptance is recorded separately.
- **AC-22** (FR-15) Given verdict-affecting or disputed findings, When reviewed, Then an independent read-only Reviewer re-checks them in batch and unconfirmed items are not deleted as false positives.

**Adapters, protection, egress, budget**
- **AC-23** (FR-16, FR-17) Given the Strix Adapter targets an original project, When it runs, Then either writes to the original are demonstrably *rejected* (tested write attempt), or the run uses an explicit working copy and reports copy scope and environment differences; the toolkit never claims isolation without that proof.
- **AC-24** (FR-16) Given each of Opengrep, Trivy and Strix, When the Adapter is called, Then named parameters are validated, real tool output is normalized into status and results, and a tool failure is reported honestly rather than as success; When pre-check finds an unverified or incompatible version, Then the gap is reported and nothing is auto-downloaded or upgraded. (A detailed malformed/partial-write/timeout test matrix is the unapproved suggested default D-18 and stays open.)
- **AC-25** (FR-21) Given a total budget, When Guard switches methods or retries, Then consumption is not reset; on exhaustion new attempts stop and a partial report lists unverified items.
- **AC-26** (FR-21) Given the user cancels a verification, When cancel is processed, Then new calls stop, termination of owned tool processes is requested, completed results are kept, and unconfirmed termination is reported honestly; only this run is affected.
- **AC-27** (FR-24) Given no valid signed local authorization (missing, tampered or revoked), When a maintenance action is requested, Then it is refused with a clear next step; normal verification never reads the signing private key and no private key or model credential appears in context or reports.
- **AC-28** (FR-18) Given the MVP samples (marathon registration, WebGoat), When each Adapter is evaluated in the sandbox, Then detection, false positives/negatives, coverage, time, CPU/memory, completion and model usage are recorded; an Adapter not meeting the agreed bar is not declared formally delivered.
- **AC-29** (FR-20) Given only "network allowed" without a data-submission authorization, When a step would send source, findings or credentials to a model/third party, Then it is not sent; each outbound call states its purpose, data and recipient.
- **AC-30** (FR-29, FR-06, FR-21) Given defined normal and negative acceptance cases (empty library, no maintenance authorization, missing tool, partial Policies, cancel, budget exhaustion), When run, Then each has a fixed input and an observable expected result.

**Host integration & standalone form**
- **AC-31** (FR-27) Given one routing definition, When carriers are generated, Then the system-prompt fragment, AGENTS.md entry and GitHub instructions come from the same source and do not trigger duplicate or recursive security flows.
- **AC-32** (FR-28) Given a user edited AGENTS.md outside the toolkit fragment, When carriers are regenerated, Then those edits are preserved and only toolkit fragment differences are reported to the Maintainer for a decision.
- **AC-33** (FR-27) Given GitHub Copilot (CLI and VS Code), When a manual smoke test is run on an MVP sample, Then Copilot (for an implementation task) and Guard (on an explicit verification request) are actually invoked and produce reports; automatic host-loading acceptance remains deferred (I-19).
- **AC-34** (NFR-01) Given a project without X-IPE task board/workflow files, When the toolkit's scripts and skills are used, Then they work without requiring those files.
- **AC-35** (FR-29) Given maintainer development, When candidate skills are tested, Then they run from `.x-ipe/private/secure-code/sandboxes/<id>/` with an explicit root, and the sandbox is not claimed as OS/process/network isolation.

### Scope

**In scope — MVP (Phase 1):** FR-01…FR-07, FR-09, FR-10, FR-13…FR-18, FR-20…FR-22, FR-24, FR-27…FR-29, NFR-01.

**Phase 2:** FR-08 (AI-assisted drafting), FR-11 (Reference exploration + cache), FR-12 (Presets & tags), FR-19 (temporary check scripts).

**Phase 3:** FR-23 (cross-run comparison), FR-25 (suggestions/Lessons), FR-26 (controlled autonomous optimization).

**Out of scope (whole Epic, per inventory 不纳入/暂缓):** knowledge licence review module (K-10); using non-formal text as Policies (K-31); Preset body fingerprints (P-08); dedicated integration JSON exporter (R-14); legacy assist/verify/both/off modes (I-22); waiver-based severity downgrade (D-11); management PPT (R-15); legacy Codex/Semgrep package projection (A-12); automatic host-loading acceptance (I-19, S-05); failure-maintenance recovery and auto-uninstall (I-21); enterprise identity service; heavy DLP; complex cost prediction / coverage percentage score; auto commit/push/publish.

**Open (not decided; not in scope until decided):** 40 待定 items and 5 建议默认 items (D-01, D-02, D-03, D-18, D-26) in inventory v2, including C-03 (Copilot in requirement analysis), V-18 (reuse of old evidence), A-11 (runtime custom tool rules), X-13 (scenario Policy recommender), D-10 (application/system policy domains), D-25 (agent persona files). Many (U-14/D-22 signing details, A-10 tool versions, B-07 budgets, R-10 schemas, I-17 install record, D-12…D-17, D-19) must be **decided in technical design before the corresponding MVP feature is implemented**.

### Constraints

- Empty library on first install; no CWE/OWASP starter pack; only formally maintained knowledge is used (K-29…K-31).
- Guard never fixes business artifacts or orchestrates remediation; Copilot is not a second business writer.
- Authorization is local workflow-level; it does not resist anyone with local write access to replace trust configuration; no enterprise identity service (U-13).
- Maintainer has full maintenance authority, but agents still need a real request or signed pre-authorization; role claims inside data grant nothing.
- Adapter code location in Framework does not make Framework the scan strategist (O-06).
- Cost interfaces are estimates; no strict monetary hard cap guarantee.
- No automatic commit, push or publish; signing private keys and model credentials never enter model context or reports.
- **Implementation form:** SKILL.md skills + uv-managed standalone Python namespace; no hard runtime dependency on X-IPE task/workflow/board. *Clarified 10-19-2026 (user, TASK-006):* the toolkit is a standalone product named `x-ipe-secure-code-toolkit-{framework,copilot,guard}` with source in `ai-secure-code-toolkit/`; it is not built through the `x-ipe-meta-skill-creator` candidate flow (its validator requires X-IPE subtype prefixes) and is validated by its own tests plus independent review; development uses the sandbox (FR-29).
- **Hosts:** GitHub Copilot (CLI + VS Code) is the only host verified in MVP; carriers stay host-neutral where possible.
- **Acceptance samples:** shanghai-marathon-registration (Python) and WebGoat (Java) under `study-case/secure-coding-guidance/playground/`.
- Knowledge store lives under `x-ipe-docs/secure-code/` (knowledge/local, knowledge/reference, presets, tags, improvements, reports/copilot, reports/guard); private runtime data under `.x-ipe/private/secure-code/`.

### Feasibility and Risks

| Risk | Impact | Mitigation / Assumption |
|---|---|---|
| MVP is large (three Adapters + signed auth + all carriers + budget/egress) | Long time to first usable loop | Feature Breakdown orders features so the Local-knowledge → Guard (Opengrep) → report path lands first; Trivy, Strix, signing and carriers follow inside MVP |
| Strix writes to mounted target dirs; calls LLMs; variable cost | Original project modification, data egress, cost overrun | FR-17 read-only feasibility gate before integration; working-copy fallback; FR-20 egress authorization; FR-21 budget/cancel |
| Strix/Trivy require Docker, model keys or vulnerability DB downloads | Adapters unusable in some environments | Programmatic pre-check (A-08/A-09) reports gaps; no auto-download; S-08 environment details decided in design |
| Signing design still open (U-14, D-22) | Blocks FR-24 implementation | Decide algorithm, key paths, revocation in technical design before FR-24 implementation; assumption: standard library-available signature scheme |
| Host enforcement of execution entry points is unproven | Prompt-only controls could be bypassed | Claim only what is verified (inventory §13.4); report workflow-level constraints honestly |
| Many schemas undecided (R-10, D-12…D-14, I-17) | Inconsistent outputs across skills | Technical design defines shared result/report schemas once in Framework |
| Tool effectiveness unknown (no local measurements yet) | Over-promising detection | FR-18 measurement on samples before declaring formal delivery; no vendor numbers as results |
| WebGoat is large | Slow/expensive runs | Use bounded target subsets and budgets; marathon sample for fast loops |

Design assumptions (nonblocking): Python ≥ 3.11 with uv; Opengrep/Trivy invoked as CLIs with JSON/SARIF output; Strix invoked via its CLI in Docker.

### Related Features

| Feature ID | Affected FRs / ACs | Conflict / Dependency | Decision and Rationale | Requirement Link |
|---|---|---|---|---|
| None | — | Requirement inventory was empty before EPIC-001 | Independent new work; no CR | N/A |

Legacy toolkit in `study-case/secure-coding-guidance` is a study reference, not an X-IPE feature of this project; it is not modified.

### Impact Updates

- N/A — zero conflicts (first Epic, empty inventory).

### Open Questions

- None blocking for the MVP requirement. The open inventory items listed under Scope are tracked for feature refinement/technical design and are explicitly not in scope until decided.

### Linked Mockups

| Mockup Function Name | Mockup Link |
|---|---|
| N/A — the toolkit has no product UI (skills + scripts + Markdown reports) | N/A |

### Context and Verification Evidence

```yaml
requirement_review:
  sources:
    - path: "x-ipe-docs/ideas/Draft Idea - 10142026 153612/refined-idea/idea-summary-v2.md"
      sha256: "9a7db37ebf2f31acb80314344a5119eab3d1f14151aa06f3a4eb8813f168fbf8"
    - path: "x-ipe-docs/ideas/Draft Idea - 10142026 153612/secure-code-toolkit-v2-feature-inventory-v2.md"
      sha256: "f36a27538196f35162be4e6a335e52e61d725149a444b7059e57980db794d435"
    - path: "x-ipe-docs/ideas/Draft Idea - 10142026 153612/new idea.md"
      sha256: "3c45a2965b609418b09a5b247baa10aea4ad5809f1dd937ccd6fb46188e7e6e5"
  parts: []            # empty first-project inventory before EPIC-001 (x-ipe-docs/requirements/ was empty)
  index_sha256: absent
  config_sha256:
    tools.json: "6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d"
    workflow-template.json: "ab2e1563a0d4a9246b050b7cf779c676035345e78e29d88c10a0d556e20f6db1"
  delta: "New EPIC-001 from refined idea v2 plus 2026-10-18 scope decisions"
  reused_sections: ["idea summary v2", "inventory v2 confirmed items"]
  refreshed_sections: []
  invalidation_reasons: []
  conflicts: []        # zero conflicts — reviewed conclusion on an empty inventory
  unresolved_material_questions: []
  research: "stages.requirement.gathering has no enabled tools; no external research needed (domain facts reused from ideation)"
```

- Execution mode: free-mode (no application workflow write; `workflow_action_updated: false`).
- Mechanical checks (2026-10-18): every 已确认 inventory ID is cited by an FR; no 待定/建议默认/暂缓/不纳入 ID is cited in the FR table; all Markdown links resolve; file < 500 lines (no split).
- Independent review (rubber-duck sub-agent, 2026-10-18): no High findings; 3 Medium accepted and fixed — AC-24 no longer imports unapproved D-18 test matrix; AC-09 limits MVP impact verification to relations/caches with Preset/tag fixtures in Phase 2; AC-19 states Medium+ → Fail as the default threshold (V-15/V-16).

---

## Feature Breakdown — EPIC-001 intake (TASK-003)

> Requirement ID: N/A (Epic-only input) · Epic context: EPIC-001 (intake) plus EPIC-002, EPIC-003, EPIC-004 allocated by this breakdown and linked to EPIC-001 · Created: 2026-10-18 · Confirmed by user 2026-10-18 (interact-with-human)

### Overview and Scoped Delta

Standard new breakdown of [EPIC-001](x-ipe-docs/requirements/requirement-details.md) (FR-01…FR-29, NFR-01, AC-01…AC-35). No existing features or conflicts. Requirement findings (scope, phases, risks, decisions) are reused unchanged from the EPIC-001 section above.

### Epic Assessment and Delivery Order

Scope signals: 4+ domains (knowledge/authorization, verification/tools, collaboration/host integration, learning/autonomy), ~19 features → **multiple Epics, each ≤ 7 features**. All new Epics derive from the EPIC-001 intake requirement; FR/AC IDs stay those of EPIC-001.

| Epic | Title | Domain responsibility | Features |
|---|---|---|---|
| EPIC-001 | Framework: Knowledge, Authorization & Policy | Install, signed authorization, status, Local/Reference knowledge, Policy resolution, Presets/tags | 001-A…001-G |
| EPIC-002 | Guard: Verification & Scanner Adapters | Check plan, verdict, Reviewer record, reports, Adapters, budget/cancel/egress | 002-A…002-G |
| EPIC-003 | Copilot Collaboration & Host Integration | In-flow suggestions, adoption review, host carriers, sandbox and MVP acceptance harness | 003-A…003-C |
| EPIC-004 | Learning & Controlled Autonomous Optimization | Suggestions/Lessons and signed autonomy (Phase 3) | 004-A…004-B |

**Delivery order (topological, MVP first):**

1. MVP: FEATURE-001-A → 001-B → 001-C → 002-A → 002-B → 003-A *(first usable Framework → Guard/Copilot → report loop)* → 001-D → 002-C → 002-D → 002-E → 003-B → 003-C
2. Phase 2: FEATURE-001-E, 001-F, 001-G, 002-F
3. Phase 3: FEATURE-002-G, 004-A, 004-B

Priority: P0 = 001-A, 001-B, 001-C, 002-A, 002-B, 003-A; P1 = 001-D, 002-C, 002-D, 002-E, 003-B, 003-C (still MVP scope); P2 = Phase 2; P3 = Phase 3.

Rationale for authorization first: importing knowledge is a maintenance action that needs a real Maintainer authorization (U-03, U-05); building signed initialization first (O-09 order) avoids a stubbed or fake permission check.

### Feature List

| Feature ID | Epic ID | Feature Title | Version | Brief Description | Feature Dependency |
| --- | --- | --- | --- | --- | --- |
| FEATURE-001-A | EPIC-001 | Toolkit Install, Signed Owner Initialization & Status | v1.0 | Initializes a project for the agent-specified environment: places the pre-generated Framework, Copilot and Guard skills, creates the empty layout and host-entry fragment, lets the owner explicitly initialize signed Maintainer authorization, and reports status separately. | None |
| FEATURE-001-B | EPIC-001 | Local Knowledge Maintenance & Changelog | v1.0 | Authorized Maintainers import and edit Local rules by namespace/source-version/rule-ID with one current content, full changelog, examples, partial and idempotent batch import, pre-check and consistent single-record writes. | FEATURE-001-A |
| FEATURE-001-C | EPIC-001 | Policy Resolution & Adoption Scope Selection | v1.0 | Resolves formal Local Policies into structured output, checks availability, and lets the user confirm the adopted scope via clues, no clues, or Apply All without Presets. | FEATURE-001-B |
| FEATURE-001-D | EPIC-001 | Knowledge Exit Impact & Broken-Link Handling | v1.0 | Maintainer-initiated deactivate, delete or rename shows an impact list first, reports broken references without silent substitution, invalidates known dependent caches and leaves historical reports untouched. | FEATURE-001-B |
| FEATURE-001-E | EPIC-001 | Reference Knowledge Exploration & Cache | v1.0 | Phase 2: explores maintained Reference sources only within registered domains, prefers formal Local content, and caches results for 7 days with explicit refresh. | FEATURE-001-C |
| FEATURE-001-F | EPIC-001 | Presets & Tags | v1.0 | Phase 2: reusable Presets holding concrete rule references with query intent and snapshot_at, plus JSON tags for lookup that never change severity or Presets implicitly. | FEATURE-001-C, FEATURE-001-D |
| FEATURE-001-G | EPIC-001 | AI-assisted Knowledge Drafting | v1.0 | Phase 2: AI drafts examples and explanations for specified rules, clearly labelled, validated and approved by a Maintainer before entering formal knowledge. | FEATURE-001-B |
| FEATURE-002-A | EPIC-002 | Guard Semantic Verification & Verdict Reporting | v1.0 | Guard verifies formed artifacts against adopted Policies through a check plan and semantic review, re-checks findings with an independent Reviewer, and reports a three-state verdict with a four-state ledger and evidence. | FEATURE-001-C |
| FEATURE-002-B | EPIC-002 | Adapter Contract & Opengrep Adapter | v1.0 | Defines the shared Adapter contract in Framework scripts and delivers the Opengrep Adapter with pre-check, typed parameters and normalized results, measured on the MVP samples. | FEATURE-002-A |
| FEATURE-002-C | EPIC-002 | Verification Budget, Cancel & Data-Egress Control | v1.0 | One shared budget per verification, user cancellation with honest partial results, and purpose-specific network and data-submission authorization for every outbound call. | FEATURE-002-A |
| FEATURE-002-D | EPIC-002 | Trivy Adapter | v1.0 | Trivy Adapter for dependency, container, configuration and secret checks under the shared contract, with vulnerability-DB updates only under explicit update authorization. | FEATURE-002-B, FEATURE-002-C |
| FEATURE-002-E | EPIC-002 | Strix Adapter with Original-Project Protection | v1.0 | Strix Adapter that first proves read-only access to the original project or else runs on an explicit working copy, within budget and egress authorization. | FEATURE-002-B, FEATURE-002-C |
| FEATURE-002-F | EPIC-002 | Temporary Check Scripts | v1.0 | Phase 2: one-off helper check scripts generated only for real gaps, reviewed with known positive/negative samples and executed under actual limits. | FEATURE-002-A, FEATURE-002-C |
| FEATURE-002-G | EPIC-002 | Cross-run Report Comparison | v1.0 | Phase 3: on explicit request compares two specified Guard reports as new, still present, not observed this time, or not comparable. | FEATURE-002-A |
| FEATURE-003-A | EPIC-003 | Copilot In-flow Suggestions & Adoption Review | v1.0 | Copilot gives concrete Policy-based suggestions during design, implementation, bug fix and refactor, then an independent read-only Reviewer checks adoption and the result is reported. | FEATURE-001-C, FEATURE-002-A |
| FEATURE-003-B | EPIC-003 | Single-source Host Integration Carriers | v1.0 | Generates system-prompt fragment, AGENTS.md entry and GitHub instructions from one routing definition, extending the minimal fragment written by FEATURE-001-A, with maintainer-decided differences. | FEATURE-002-A, FEATURE-003-A |
| FEATURE-003-C | EPIC-003 | Development Sandbox & MVP Acceptance Harness | v1.0 | Maintainer sandbox for candidate skills plus fixed normal and negative acceptance cases and cross-Adapter evaluation on the marathon and WebGoat samples. | FEATURE-001-C, FEATURE-002-B, FEATURE-002-C, FEATURE-002-D, FEATURE-002-E |
| FEATURE-004-A | EPIC-004 | Bounded Improvement Suggestions & Lessons | v1.0 | Phase 3: strictly admitted improvement suggestions, at most 10 active, 30-day expiry and terminal retention, mandatory review of user suggestions. | FEATURE-002-A, FEATURE-003-A |
| FEATURE-004-B | EPIC-004 | Controlled Autonomous Optimization | v1.0 | Phase 3: explicitly triggered optimization from at most 3 Lessons under a separately signed autonomy policy; only low-risk local changes auto-apply, others stay candidates. | FEATURE-004-A, FEATURE-003-C |

### Feature Details

All features: Outcome State = **not measured**; Mockup Links = N/A (no product UI). AC IDs `AC-nn` are EPIC-001 acceptance criteria above; `AC-<feature>-nn` are feature-level additions derived from the cited inventory rows. Phase 2/3 ACs are preliminary and finalized in Feature Refinement.

#### FEATURE-001-A: Toolkit Install, Signed Owner Initialization & Status

**Version:** v1.0 · **Phase:** MVP (P0, Minimum Runnable Feature of EPIC-001)
**Scope:** Runnable: install → `init` (owner, explicit) → `status`. Includes uv namespace package, three skill skeletons declaring FR-01 boundaries, signed authorization verify/revoke, status. Out: knowledge maintenance (001-B), failure-maintenance recovery and auto-uninstall (I-21, deferred).

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-05, G-08 | FR-03, FR-24, NFR-01, FR-01 | Owner/Maintainer, upstream agent | Authority is real and explicit from the first use; toolkit runs without X-IPE infrastructure | Foundation for every maintenance action and status | Scenario: fresh install shows separate missing conditions; init produces verifiable authorization; tampered file rejected | Local workflow-level only (U-13); no self-authorization | AC-03, AC-27, AC-34, AC-001A-01…03 | not measured |

**Acceptance Criteria:**
- [ ] AC-03, AC-27, AC-34 (EPIC-001)
- [ ] AC-001A-01: GIVEN the owner runs explicit initialization WHEN it completes THEN a local authorization signed with a standard digital signature is verifiable with the fixed trusted public key, stays valid until explicitly revoked, and is re-checked before each maintenance action (U-07, U-09…U-12).
- [ ] AC-001A-02: GIVEN an authorization file that was altered or signed by a non-trusted key WHEN verified THEN it is rejected and maintenance is refused (U-10).
- [ ] AC-001A-03: GIVEN a fresh install WHEN inspected THEN knowledge and Preset stores are empty and the Framework, Copilot and Guard skills declare their responsibilities and non-responsibilities (K-29, O-01…O-06).

**CR impact note (CR-001, 10-19-2026, TASK-005):** "Install" means project initialization — pre-generated skills and scripts placed in the skills folder of the environment passed explicitly by the calling agent (`--env`), folder structure created, and a minimal toolkit fragment written into the environment's host entry file with fragment-level idempotency (FR-27/FR-28 minimal part moved from FEATURE-003-B). No package install. Specification updated to v1.1: [specification](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/specification.md).

**CR impact note (CR-002, 10-19-2026, TASK-007):** Windows verification of AC-001A-10a deferred to a later phase (tracked open item); macOS and Linux verified in [acceptance](x-ipe-docs/requirements/EPIC-001/FEATURE-001-A/acceptance-test-cases.md).

**Dependencies:** None.
**Technical Considerations:** Signing algorithm, canonicalization, key format/paths, revocation and rotation (U-14, D-22) and install record (I-17) must be decided in technical design before implementation. Private keys never enter model context. Skills built via `x-ipe-meta-skill-creator` candidate flow.
**Mockup Links:** N/A

#### FEATURE-001-B: Local Knowledge Maintenance & Changelog

**Version:** v1.0 · **Phase:** MVP (P0)
**Scope:** Local rules only (Reference type is FEATURE-001-E). Identity, single current content, changelog, optional examples, batch/partial/idempotent import, pre-check, single-record consistency, maintainer-only writes. Out: AI-assisted drafting (001-G), exit operations (001-D).

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-03, G-04 | FR-04, FR-05, FR-06, FR-07 (K-36, D-04) | Maintainer | Knowledge is maintainable, traceable and cheap to re-import | Formal Local knowledge base that all Policies come from | Scenario: import a mixed batch, resubmit after interruption, edit a rule; changelog and statuses match | Empty install; no snapshot chain; no auto-merge across sources | AC-04…AC-08, AC-10, AC-001B-01 | not measured |

**Acceptance Criteria:**
- [ ] AC-04, AC-05, AC-06, AC-07, AC-08, AC-10 (EPIC-001)
- [ ] AC-001B-01: GIVEN a User without valid Maintainer authorization WHEN they try to import or edit formal knowledge THEN the write is refused while reading remains available (U-04, U-05).

**Dependencies:** FEATURE-001-A — maintenance writes require verified Maintainer authorization.
**Technical Considerations:** Open items for design: K-15 diff format, D-05 batch limits, D-06/D-07/K-09 ID disambiguation, D-08 draft/activation schema. Consistency without full batch transactions (inventory §18.1 item 5).
**Mockup Links:** N/A

#### FEATURE-001-C: Policy Resolution & Adoption Scope Selection

**Version:** v1.0 · **Phase:** MVP (P0)
**Scope:** Local Policy structured output, availability check, scope branches P-12…P-14 and adopted-scope confirmation. Out: Presets/tags/query (001-F), Reference exploration (001-E).

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-03 | FR-09, FR-10 | Developer, upstream agent | Imported, suggested and adopted scope are never confused; missing knowledge is never invented | Single Policy entry point consumed by Guard and Copilot | Scenario: empty, partial and full libraries each produce the correct response and recorded adopted scope | Apply All ≠ artifact scope; language field advisory only | AC-12, AC-001C-01…03 | not measured |

**Acceptance Criteria:**
- [ ] AC-12 (EPIC-001)
- [ ] AC-001C-03: GIVEN no formal usable Policies or only partially usable ones WHEN Framework resolves a request THEN it returns a "maintenance needed" status without inventing rules, or lists available / missing / unclear items for confirmation (Framework part of AC-11; K-30, X-14, V-23).
- [ ] AC-001C-01: GIVEN a Policy request WHEN resolved THEN each Policy includes identity, actual requirement, applicability notes, source evidence, retrieval status and unresolved items; partial retrieval is never reported as complete (X-09, X-10).
- [ ] AC-001C-02: GIVEN rule or natural-language clues without a save request WHEN scope is proposed THEN the user confirms the actual adopted scope, and a missing or mismatched language field never auto-excludes a rule (P-01, P-02, P-12, K-17, K-18).

**Dependencies:** FEATURE-001-B — Policies come only from formal Local knowledge.
**Technical Considerations:** D-09 precedence and D-24 Copilot empty-library message to settle in design. X-13 scenario recommender stays open (not in scope).
**Mockup Links:** N/A

#### FEATURE-001-D: Knowledge Exit Impact & Broken-Link Handling

**Version:** v1.0 · **Phase:** MVP (P1)
**Scope:** Deactivate/delete/rename initiated by Maintainer; impact list over rule relations and known caches in MVP (Preset/tag impact added with 001-F); broken-link reporting; history preserved.

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-03 | FR-07 (K-34, K-35, X-15) | Maintainer | Removing or renaming knowledge never silently breaks or rewrites dependent work | Exit operations with impact preview | Scenario: rename a related rule; impact shown, reference reported broken, old report unchanged | No automatic cascade edits; Maintainer keeps the decision | AC-09, AC-001D-01 | not measured |

**Acceptance Criteria:**
- [ ] AC-09 (EPIC-001)
- [ ] AC-001D-01: GIVEN references exist to a rule WHEN the Maintainer confirms deletion THEN the decision is not blocked by the references and no other record is modified automatically (K-34).

**Dependencies:** FEATURE-001-B — operates on formal Local knowledge and its changelog.
**Technical Considerations:** K-15 rename/delete expression and restore semantics open for design.
**Mockup Links:** N/A

#### FEATURE-001-E: Reference Knowledge Exploration & Cache

**Version:** v1.0 · **Phase:** Phase 2 (P2)
**Scope:** Reference knowledge type (K-01 Reference part), on-demand exploration, Local-first, 7-day cache.

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-03, G-04 | FR-11 | Maintainer, Developer | Maintained external sources are usable without copying them, at bounded cost | Exploration + cache feeding Policy resolution | Defined in refinement | Registered domains only; cache never becomes formal knowledge | AC-001E-01…03 | not measured |

**Acceptance Criteria (preliminary):**
- [ ] AC-001E-01: GIVEN a Reference source WHEN explored THEN only registered domains and their subdomains are accessed (X-03).
- [ ] AC-001E-02: GIVEN formal Local content exists for the same source/version/rule WHEN resolved THEN Local is used first (X-02).
- [ ] AC-001E-03: GIVEN a cached result WHEN read within 7 days THEN it is reused without renewing expiry; an explicit refresh failure is reported and not masked by stale cache (X-05…X-07).

**Dependencies:** FEATURE-001-C — extends Policy resolution with Reference sources.
**Technical Considerations:** X-04, X-08 open; reference fetching requires E-01 purpose authorization (002-C).
**Mockup Links:** N/A

#### FEATURE-001-F: Presets & Tags

**Version:** v1.0 · **Phase:** Phase 2 (P2)
**Scope:** P-03…P-07, P-09, P-11, T-01…T-04; extends exit impact (001-D) to Presets/tags.

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-03 | FR-12 | Developer, Maintainer | Reusable, explicit rule scopes without hidden drift | Preset and tag stores | Defined in refinement | No body fingerprints (P-08); tags never change severity | AC-001F-01…04 | not measured |

**Acceptance Criteria (preliminary):**
- [ ] AC-001F-01: GIVEN a saved Preset WHEN read THEN its effective membership is only concrete rule references (it may also hold query intent, snapshot_at and an AI applicability summary), and reading does not refresh snapshot_at (P-04, P-05, P-07, P-09).
- [ ] AC-001F-02: GIVEN a Preset query WHEN not explicitly requested THEN it is not executed; on request candidates are recomputed with an add/remove diff for confirmation (P-05, P-06).
- [ ] AC-001F-03: GIVEN tag membership changes WHEN a Preset is used THEN its rule list is unchanged unless explicitly updated (T-04, P-04).
- [ ] AC-001F-04: GIVEN non-empty Presets and tags referencing a rule WHEN the rule is renamed or deleted THEN they appear in the impact list (completes AC-09).

**Dependencies:** FEATURE-001-C (scope selection branch P-11), FEATURE-001-D (exit impact contract).
**Technical Considerations:** P-10, T-05 open for design.
**Mockup Links:** N/A

#### FEATURE-001-G: AI-assisted Knowledge Drafting

**Version:** v1.0 · **Phase:** Phase 2 (P2)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-03 | FR-08 (K-20, K-21) | Maintainer | Faster maintenance of examples and explanations without unreviewed content | AI drafts, Maintainer approves | Defined in refinement | Explanations must not smuggle new requirements (K-22) | AC-001G-01, AC-001G-02 | not measured |

**Acceptance Criteria (preliminary):**
- [ ] AC-001G-01: GIVEN an AI-drafted example or explanation WHEN stored THEN it is labelled as AI-generated and enters formal knowledge only after Maintainer approval (K-20, K-21).
- [ ] AC-001G-02: GIVEN a drafted safe/unsafe example WHEN approved THEN it has passed validation for the specified rule and language (K-20).

**Dependencies:** FEATURE-001-B — drafts enter the maintained Local store.
**Mockup Links:** N/A

#### FEATURE-002-A: Guard Semantic Verification & Verdict Reporting

**Version:** v1.0 · **Phase:** MVP (P0, Minimum Runnable Feature of EPIC-002)
**Scope:** Runnable: artifact + adopted Policies → check plan → semantic review → independent finding review → verdict, ledger, Markdown + structured report, raw evidence retention. Defines the shared Reviewer record (FR-02) and report/evidence store reused by Copilot. Out: tool Adapters (002-B/D/E), budget/cancel (002-C).

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-02 | FR-14, FR-15, FR-02, FR-22, FR-01 | Developer, upstream agent | No misleading "pass"; every conclusion traceable to evidence | Guard verdict engine and report | Scenario: known-vulnerable marathon sample is not reported Pass; ledger lists unconfirmed items | Guard never fixes; no coverage percentage | AC-01, AC-02, AC-11, AC-16…AC-22, AC-002A-01 | not measured |

**Acceptance Criteria:**
- [ ] AC-01 (Guard part), AC-02, AC-11 (Guard part: no/partial Policies, V-10, V-23), AC-16, AC-17, AC-18, AC-19, AC-20, AC-21, AC-22 (EPIC-001)
- [ ] AC-002A-01: GIVEN a Guard run WHEN finished THEN a Markdown report in `reports/guard/` and a same-source structured result are produced, raw evidence is retained 30 days with the retention stated in the report, and sensitive values are masked (R-01…R-04, R-07, R-08).

**Dependencies:** FEATURE-001-C — Guard requires resolved formal Policies and adopted scope.
**Technical Considerations:** D-12…D-14, R-10 schemas and V-18 evidence reuse open for design; Reviewer independence via host sub-agent invocation.
**Mockup Links:** N/A

#### FEATURE-002-B: Adapter Contract & Opengrep Adapter

**Version:** v1.0 · **Phase:** MVP (P0)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-02, G-04 | FR-16, FR-18 (Opengrep) | Developer, Maintainer | Executable rule-driven evidence at low cost | Shared Adapter contract + first Adapter | Scenario: Opengrep tool-level validation on both samples (S-07) | No fixed Policy→rule mapping; no auto-download | AC-24, AC-002B-01…03 | not measured |

**Acceptance Criteria:**
- [ ] AC-24 for Opengrep (EPIC-001)
- [ ] AC-002B-03: GIVEN Opengrep WHEN the Adapter is built THEN a small tool-level validation on the MVP samples precedes the full Adapter and its observed results and known issues are recorded; formal-delivery evaluation (AC-28) happens in FEATURE-003-C (S-07, inventory §9.4).
- [ ] AC-002B-01: GIVEN a Guard check plan WHEN Opengrep is used THEN Guard supplies parameters, targets and mode through the Adapter, and no pre-maintained Policy-to-rule mapping is required (A-02…A-04, O-06).
- [ ] AC-002B-02: GIVEN multiple capable methods WHEN Guard plans THEN it prefers the cheapest sufficient method and reports any switch or supplement with reasons (A-05…A-07).

**Dependencies:** FEATURE-002-A — Adapters are invoked from Guard check plans and feed its ledger.
**Technical Considerations:** A-10 versions/rule sets and A-11 runtime rule generation open; S-07 tool-level validation precedes full Adapter.
**Mockup Links:** N/A

#### FEATURE-002-C: Verification Budget, Cancel & Data-Egress Control

**Version:** v1.0 · **Phase:** MVP (P1)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-04, G-05 | FR-20, FR-21 | Developer, Owner | Runs stay within agreed cost and never leak data without purpose-specific permission | Shared budget/cancel and egress gate around all Guard methods | Scenario: budget exhaustion and cancel give honest partial reports; source not sent without submission authorization | Estimates, not hard money caps; no heavy DLP | AC-25, AC-26, AC-29 | not measured |

**Acceptance Criteria:**
- [ ] AC-25, AC-26, AC-29 (EPIC-001)

**Dependencies:** FEATURE-002-A — budget, cancel and egress wrap Guard runs and reports.
**Technical Considerations:** B-07 defaults, B-11 cancel interface, D-16, D-17, D-19 open for design.
**Mockup Links:** N/A

#### FEATURE-002-D: Trivy Adapter

**Version:** v1.0 · **Phase:** MVP (P1)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-02 | FR-16, FR-18 (Trivy) | Developer | Dependency/config/secret risks covered alongside code rules | Second Adapter on shared contract | Scenario: Trivy tool-level validation on both samples (S-07) | No silent DB update | AC-24, AC-002D-01, AC-002D-02 | not measured |

**Acceptance Criteria:**
- [ ] AC-24 for Trivy (EPIC-001)
- [ ] AC-002D-02: GIVEN Trivy WHEN the Adapter is built THEN a small tool-level validation on the MVP samples precedes the full Adapter and its observed results and known issues are recorded; formal-delivery evaluation (AC-28) happens in FEATURE-003-C (S-07, inventory §9.4).
- [ ] AC-002D-01: GIVEN no "tool/vulnerability-DB update" network authorization WHEN Trivy needs its database THEN it does not download, and the run reports the DB state or gap honestly (E-01, A-09).

**Dependencies:** FEATURE-002-B (Adapter contract), FEATURE-002-C (update-purpose network authorization).
**Mockup Links:** N/A

#### FEATURE-002-E: Strix Adapter with Original-Project Protection

**Version:** v1.0 · **Phase:** MVP (P1)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-02, G-05 | FR-16, FR-17, FR-18 (Strix) | Developer, Owner | Deep autonomous verification without risking the original project or uncontrolled egress/cost | Read-only feasibility gate, working-copy fallback | Scenario: write attempt to original rejected, or explicit copy used and reported | No write-back fixes; no isolation claim without proof | AC-23, AC-24, AC-002E-01, AC-002E-02 | not measured |

**Acceptance Criteria:**
- [ ] AC-23, AC-24 for Strix (EPIC-001)
- [ ] AC-002E-02: GIVEN Strix WHEN the Adapter is built THEN a small tool-level validation on the MVP samples precedes the full Adapter and its observed results and known issues are recorded; formal-delivery evaluation (AC-28) happens in FEATURE-003-C (S-07, inventory §9.4).
- [ ] AC-002E-01: GIVEN a Strix run WHEN it calls models or the target THEN each call declares purpose, data and recipient under granted authorization, consumes the shared budget, and is stopped on cancel (E-02, B-01, B-08).

**Dependencies:** FEATURE-002-B (Adapter contract), FEATURE-002-C (budget, cancel, egress).
**Technical Considerations:** Docker and model credentials (D-17), copy/isolation failure handling (inventory §9.3 item 5) open for design.
**Mockup Links:** N/A

#### FEATURE-002-F: Temporary Check Scripts

**Version:** v1.0 · **Phase:** Phase 2 (P2)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-02 | FR-19 (A-13…A-17) | Developer | Real coverage gaps can be checked without unsafe ad-hoc code | Constrained helper scripts | Defined in refinement | Not auto-promoted to formal knowledge | AC-002F-01…03 | not measured |

**Acceptance Criteria (preliminary):**
- [ ] AC-002F-01: GIVEN existing methods are insufficient WHEN a helper script is generated THEN its check goal is stated and it passes syntax/logic checks and independent review with known positive and negative samples (A-13, A-14).
- [ ] AC-002F-02: GIVEN execution limits (read targets, write results, network) cannot be reliably enforced WHEN the script would run THEN it is not executed and the gap is reported (A-15, A-16).
- [ ] AC-002F-03: GIVEN a run finishes WHEN scripts remain THEN they are not written into formal knowledge or published (A-17).

**Dependencies:** FEATURE-002-A (check plan), FEATURE-002-C (budget and limits).
**Technical Considerations:** A-18 language/runner/retention open.
**Mockup Links:** N/A

#### FEATURE-002-G: Cross-run Report Comparison

**Version:** v1.0 · **Phase:** Phase 3 (P3)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-02 | FR-23 (R-11, R-12) | Developer | Change between two runs is understood without false "fixed" claims | On-request comparison | Defined in refinement | Not observed ≠ fixed | AC-002G-01, AC-002G-02 | not measured |

**Acceptance Criteria (preliminary):**
- [ ] AC-002G-01: GIVEN an explicit request naming two Guard reports WHEN compared THEN only those reports are read and findings are classified new / still present / not observed this time / not comparable (R-11, R-12).
- [ ] AC-002G-02: GIVEN differing scope or coverage between runs WHEN compared THEN affected findings are "not comparable", never "fixed" (R-12).

**Dependencies:** FEATURE-002-A — compares its reports.
**Mockup Links:** N/A

#### FEATURE-003-A: Copilot In-flow Suggestions & Adoption Review

**Version:** v1.0 · **Phase:** MVP (P0, Minimum Runnable Feature of EPIC-003)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-01 | FR-13, FR-01, FR-02 | Developer, upstream agent | Security measures are applied during the work and adoption is verified, not claimed | Copilot suggestions + adoption review + report | Scenario: marathon sample change gets specific suggestions; Reviewer distinguishes adopted / not adopted / cannot verify | Copilot never writes business code | AC-01, AC-11, AC-13, AC-14, AC-15, AC-003A-01 | not measured |

**Acceptance Criteria:**
- [ ] AC-01 (Copilot part), AC-11 (Copilot empty/partial library), AC-13, AC-14, AC-15 (EPIC-001)
- [ ] AC-003A-01: GIVEN later edits WHEN they are unrelated to reviewed suggestions THEN no re-review is triggered; WHEN relevant changes occur THEN a targeted re-review runs (C-11).

**Dependencies:** FEATURE-001-C (Policies and adopted scope), FEATURE-002-A (shared Reviewer record and report store).
**Technical Considerations:** C-03 (requirement-analysis stage) stays open, not in scope.
**Mockup Links:** N/A

#### FEATURE-003-B: Single-source Host Integration Carriers

**Version:** v1.0 · **Phase:** MVP (P1)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-06 | FR-27, FR-28 | Maintainer, Developer | Integrations route to the right skill without conflicts or overwriting user content | One routing definition, three carriers | Scenario: regenerate carriers after user edits; only fragment diffs reported; manual smoke on GitHub Copilot | Automatic host-loading acceptance deferred (I-19) | AC-31, AC-32, AC-33, AC-003B-01 | not measured |

**Acceptance Criteria:**
- [ ] AC-31, AC-32, AC-33 (EPIC-001)
- [ ] AC-003B-01: GIVEN generated carriers WHEN a design/implementation/fix/refactor task runs THEN Copilot is triggered; Guard is triggered only by an explicit or authorized verification request (I-05, I-06).

**CR impact note (CR-001, 10-19-2026, TASK-005):** FEATURE-001-A now writes the minimal toolkit fragment for the detected environment with fragment-level idempotency. This feature keeps single-source generation of all three carriers, carrier selection and Maintainer difference handling, and must reuse/extend the 001-A fragment rather than add a second writer. AC-31…AC-33 unchanged.

**Dependencies:** FEATURE-002-A, FEATURE-003-A — carriers route to working Guard and Copilot skills.
**Technical Considerations:** I-17 install record and D-25 persona files open; GitHub Copilot is the only verified host in MVP.
**Mockup Links:** N/A

#### FEATURE-003-C: Development Sandbox & MVP Acceptance Harness

**Version:** v1.0 · **Phase:** MVP (P1)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-02, G-04, G-05 | FR-29, FR-18, AC-30 | Maintainer | Candidate skills and Adapters are validated safely against fixed cases and measured before formal delivery | Sandbox + fixed acceptance cases + cross-Adapter evaluation on samples | Scenario: each negative case yields its expected observable result | Workspace sandbox ≠ OS isolation | AC-28, AC-30, AC-35, AC-003C-01 | not measured |

**Acceptance Criteria:**
- [ ] AC-28 (all three Adapters), AC-30, AC-35 (EPIC-001)
- [ ] AC-003C-01: GIVEN a candidate skill package WHEN tested THEN an installed copy in the sandbox is used and the development source is not edited in place by the run (S-03).

**Dependencies:** FEATURE-001-C (empty/partial Policy cases), FEATURE-002-B (missing-tool case), FEATURE-002-C (cancel/budget cases), FEATURE-002-D and FEATURE-002-E (Adapters evaluated for AC-28).
**Technical Considerations:** S-08 dependencies/images/cleanup open; samples under `study-case/secure-coding-guidance/playground/`.
**Mockup Links:** N/A

#### FEATURE-004-A: Bounded Improvement Suggestions & Lessons

**Version:** v1.0 · **Phase:** Phase 3 (P3, Minimum Runnable Feature of EPIC-004)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-07 | FR-25 (L-01…L-13) | Maintainer | Few, useful, expiring suggestions instead of a backlog of thousands | Admission + capped queue | Defined in refinement | Candidate ≠ applied | AC-004A-01…03 | not measured |

**Acceptance Criteria (preliminary):**
- [ ] AC-004A-01: GIVEN a proposed suggestion WHEN admitted THEN it has concrete evidence, value and verification; generic or duplicate items are not queued; active items never exceed 10 (L-01…L-04).
- [ ] AC-004A-02: GIVEN an ordinary unadopted suggestion WHEN 30 days pass from first queueing THEN it expires, except evidenced severe security issues, which do not expire under the ordinary TTL; terminal items (rejected / expired / applied) are cleaned after a further 30 days (L-05…L-07).
- [ ] AC-004A-03: GIVEN a user suggestion WHEN submitted THEN it requires review, and an approved candidate is not reported as applied until actually changed and verified (L-10, L-13).

**Dependencies:** FEATURE-002-A, FEATURE-003-A — sources of run feedback.
**Technical Considerations:** L-14, L-15 open.
**Mockup Links:** N/A

#### FEATURE-004-B: Controlled Autonomous Optimization

**Version:** v1.0 · **Phase:** Phase 3 (P3)

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
|---|---|---|---|---|---|---|---|---|
| G-07 | FR-26 (AU-01…AU-13, §13.3, §13.4) | Maintainer | Toolkit improves itself only within signed delegation | Signed autonomy policy + bounded runs | Defined in refinement | No self-relaxed protections; no commit/push | AC-004B-01…03 | not measured |

**Acceptance Criteria (preliminary):**
- [ ] AC-004B-01: GIVEN no valid separately signed autonomy policy WHEN optimization is triggered THEN no autonomous formal change is made (AU-02…AU-04).
- [ ] AC-004B-02: GIVEN an explicit trigger WHEN optimization runs THEN at most 3 eligible Lessons are processed, unchanged already-applied Lessons are skipped, and failures are not retried indefinitely (AU-05…AU-08).
- [ ] AC-004B-03: GIVEN an eligible change WHEN applied THEN only low-risk local explanations/examples become formal automatically; skill/Adapter changes remain candidates; protections, thresholds and budgets are never relaxed (AU-10…AU-13, §13.3).

**Dependencies:** FEATURE-004-A (Lessons), FEATURE-003-C (sandbox for candidate validation).
**Technical Considerations:** D-23 autonomy policy schema; execution-entry enforcement feasibility (§13.4).
**Mockup Links:** N/A

### Coverage and Split Decisions

| Source Requirement / AC | Covered By | Decision / Gap |
|---|---|---|
| FR-01 | 001-A (skeleton boundaries), 002-A, 003-A (AC-01) | covered |
| FR-02 | 002-A (defines), 003-A (reuses) | covered |
| FR-03, FR-24, NFR-01 | 001-A | covered |
| FR-04, FR-05, FR-06 | 001-B | covered |
| FR-07 | 001-B (K-36, D-04, AC-10), 001-D (K-34, K-35, X-15, AC-09); Preset/tag impact 001-F | covered |
| FR-08 | 001-G | covered (Phase 2) |
| FR-09, FR-10 | 001-C | covered |
| FR-11 | 001-E | covered (Phase 2) |
| FR-12 | 001-F | covered (Phase 2) |
| FR-13 | 003-A | covered |
| FR-14, FR-15 | 002-A | covered |
| FR-16, FR-18 | 002-B (contract + Opengrep), 002-D (Trivy), 002-E (Strix) — tool-level validation; 003-C — formal evaluation (AC-28) | covered |
| FR-17 | 002-E | covered |
| FR-19 | 002-F | covered (Phase 2) |
| FR-20, FR-21 | 002-C | covered |
| FR-22 | 002-A (Guard + store), 003-A (Copilot, AC-15) | covered |
| FR-23 | 002-G | covered (Phase 3) |
| FR-25 | 004-A | covered (Phase 3) |
| FR-26 | 004-B | covered (Phase 3) |
| FR-27, FR-28 | 003-B | covered |
| FR-29 | 003-C | covered |
| AC-01…AC-35 | AC-01: 002-A/003-A · AC-02: 002-A · AC-03: 001-A · AC-04…08, AC-10: 001-B · AC-09: 001-D · AC-11: 001-C (Framework output), 002-A (Guard), 003-A (Copilot) · AC-12: 001-C · AC-13…15: 003-A · AC-16…22: 002-A · AC-23: 002-E · AC-24: 002-B/D/E · AC-28: 003-C · AC-25, 26, 29: 002-C · AC-27, AC-34: 001-A · AC-30, AC-35: 003-C · AC-31…33: 003-B | all covered |

No parent split, retirement or dedup gap (new breakdown).

### Context and Integration Evidence

- Source: `x-ipe-docs/requirements/requirement-details.md` EPIC-001 section (sha256 before breakdown append: 5379f4a3504f8e50acd11df693b00812ec7447f566300497d97cb90885ca7133); single part, no index.
- Board baseline: `x-ipe-docs/planning/features/features.json` valid, 0 features, no reservations; EPIC-002…004 not previously used in folders, headers or board.
- Folders: `x-ipe-docs/requirements/EPIC-00N/FEATURE-00N-X/` created for all 19 features; no specification or feature.md files (Feature Refinement owns them).
- Free-mode: no application workflow write (`workflow_action_updated: false`).
- Board registration (2026-10-18): 19 × `feature_create.py` in topological order, each followed by `feature_query.py` readback matching epic_id, title, version v1.0, status Planned and dependencies — 19/19 verified.
- Independent review (rubber-duck, 2026-10-18): 2 blocking + 2 non-blocking findings fixed — AC-28 moved to FEATURE-003-C (now depends on 002-D, 002-E) with tool-level validation ACs on each Adapter; AC-11 split into Framework (AC-001C-03), Guard (002-A) and Copilot (003-A) parts; AC-001F-01 allows query/snapshot_at/summary metadata; AC-004A-02 severe-issue exception placed on expiry.
- Mechanical checks: Epic number matches each Feature ID; all descriptions ≤ 50 words (max 32); dependency graph acyclic with all targets existing; every FEATURE has a details section; every EPIC-001 FR and AC-01…AC-35 mapped in Coverage.
