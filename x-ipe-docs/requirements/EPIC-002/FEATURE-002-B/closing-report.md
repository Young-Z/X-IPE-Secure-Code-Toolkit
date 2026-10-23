# Feature Closing Report

> Feature: FEATURE-002-B — Adapter Contract & Opengrep Adapter (EPIC-002) · version v1.0
> Task: TASK-033 (resumed after Bug Fix TASK-034) · Date: 2026-10-20 · Mode: free-mode, interact-with-human
> Closure scope: engineering delivery only. No release, commit, push or PR: the workspace is not a Git repository and no release was requested.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Delivery Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- |
| G-02 | EPIC-001 FR-16, FR-18; A-01…A-09, S-07; AC-24 | Developer, upstream agent | Trustworthy rule-driven evidence: real output, complete accounting, honest failure | AC-002B-02*, 03* Pass (real binary) | not measured |
| G-04 | EPIC-001 FR-16 (cheapest sufficient method), FR-18 | Developer, Maintainer | Low cost without lowering the requirement; recorded method choice | AC-002B-04* Pass | not measured |
| G-05 (enabling) | EPIC-001 FR-24, FR-17 principle, E-01, A-08, A-09 | Owner, Maintainer, Developer | Only the authentic registered tool runs; the original project is never written; no silent download | AC-002B-01*, 03a, 03b, 03i, 05*, 06* Pass | not measured |

The qualitative scenario from the specification was exercised with the real Opengrep v1.31.0 binary on the real MVP samples (WebGoat, shanghai-marathon-registration) in an offline container: a modified binary is refused without being executed, a known CWE-89 is reported with provenance, and the originals stay byte-identical. Use by real Developers or Maintainers on their own projects: **not measured**.

## Complete Acceptance and Actual Evidence

All 32 specification ACs (AC-002B-01a…06b) map to 14 test cases with their original assertions and types in the [acceptance report](acceptance-test-cases.md): 14 Pass, 0 Fail, 0 Blocked.

- **Real-binary black-box** (`uvx --from …/scripts secure-code …`, offline Linux aarch64 container, project `proj ü`): 10/10 ([evidence](acceptance/evidence-container-linux.jsonl)). Clean scans are now proven independently from the retained tool output and manifest, digests are recomputed from the original files, and the tool home is observed during the run and confirmed removed.
- **macOS host**, never-authorized User path: 2/2 ([evidence](acceptance/evidence-host-macos.jsonl)).
- **Unit/library and fake-tool integration:** 112 passed, 1 skipped ([log](acceptance/evidence-unit-library.log)). Covers AC-002B-03f/03j error modes and the TASK-032/034 regressions.
- **Structured review:** 05a/05b. All 7 digest-table entries match the official-digest table of the tool-validation record byte for byte.
- **FEATURE-002-A regression runner:** container 26/26, host 2/2.
- **Full suites:** macOS Python 3.14 and 3.11: 523 passed, 2 skipped each. Linux Python 3.12: 525 passed. `ruff check` clean.

## Evidence Reuse and Dependency Freshness

| Input | At acceptance (TASK-031) | At closing | Disposition |
| --- | --- | --- | --- |
| Toolkit tree | `30346157…` | `7cdc906c…` | Changed by TASK-034 (`safe_io.py`, `toolrun.py`, tests, test double, Guard/framework docs, README) → complete black-box rerun with fresh offline caches (fixed code confirmed in the cache), full suites in 3 environments |
| Specification | `deab5ce3…` | `deab5ce3…` | Unchanged; no AC changed |
| Technical design | `537861ca…` | `1ee056d3…` | Design Change Log TASK-034 (write-all copy, executed-config digest and parse-back check), updated before the code |
| Runner `blackbox.py` | `59796b04…` | `1f491d21…` | Stronger, independent checks added; no assertion relaxed |
| Environment | Linux container Python 3.12 offline + real binary; macOS host | same | Cache volumes recreated for each rerun |

## Review and Documentation Delta

- **Reviews during delivery:** specification (rubber-duck, 10 + 2 findings fixed; re-review 2 more); design (three rounds); implementation code review (5 fixes) and re-review (1 fix).
- **Acceptance:** the first real-binary run failed 5/10, because Opengrep exits 0 with no output when its cache path is non-ASCII. [Bug Fix TASK-032](bug-report-TASK-032.md) fixed this test-first; its independent review found no issues.
- **Closing review (TASK-033):** 3 blocking and 2 non-blocking findings: short writes in `copy_hash`, no binding between the recorded rule digest and the executed config, clean-scan acceptance checks trusting the product status, overstated evidence for tool-home removal, and missing user docs. The user chose to fix all → [Bug Fix TASK-034](bug-report-TASK-034.md), test-first (4 RED → GREEN). The fix review found no issues. The focused closing re-review confirmed all 5 resolved, with no new issues.
- **Documentation delta at closing:** Guard SKILL.md step 5a, `references/guard-records.md` (provenance, runtime home, `TOOL_HOME_UNSUPPORTED`, no-output gap, kill limit), the `cli-contract.md` `guard tool` row and the README "Register Opengrep" section.
- **Cross-feature:** FEATURE-002-A additive extensions (method choices and changes, `adapter_runs`, Adapter section in the report). 002-A ACs are unchanged and its black-box regression passes.

## Outcome Gaps and Honest Limits

- **Stakeholder outcome:** not measured.
- **Platforms:** the real binary was executed only on Linux aarch64 (the only tool-level validated platform). Other builds are registered from official digests but not executed. Windows Adapter execution is refused by design (NFR-002B-4).
- **Isolation:** the tool's file system and network access are not enforced at OS level (network enforcement is deferred to FEATURE-002-C). The container's `--network none` is a property of the test environment.
- **Opengrep cannot prove analysis of other-language files or files with syntax errors.** Python files are parse-checked; for other languages the stated limit applies.
- **Leftover tool home:** a killed toolkit process can leave a tool home (runtime cache only) in the system temporary folder. Manual removal is documented.
- **Rules containing U+0085** cannot be staged faithfully and are refused with a visible gap.
- **Agent behavior** (choosing the cheapest sufficient method, asking before adding more) was verified structurally only.
- **Formal tool evaluation (AC-28)** is pending in FEATURE-003-C.

## Release Disposition

Engineering-only closure. No commit, push, PR or release was performed or requested; the workspace is not a Git repository.

## Refactoring Assessment

Not assessed in a separate analysis (no compulsory refactor). Inspected: all new modules are under 800 lines (largest `guard/toolrun.py` ≈ 750); coverage of the new code is 84–100% (92% overall: adapters, toolrun, tools_service). `overall_quality_score: N/A`, `refactoring_recommended: false` (no evidenced need; this is not a quality verdict), `top_suggestions: []`.

## Next Feature Suggestion

Per the MVP order: FEATURE-002-C. Pending separately: knowledge seeding TASK-028, once the user provides the policy websites.
