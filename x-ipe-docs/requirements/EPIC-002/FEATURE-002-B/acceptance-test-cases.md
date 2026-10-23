# Acceptance Test Cases

> Feature: FEATURE-002-B — Adapter Contract & Opengrep Adapter (EPIC-002)
> Status: verified delivery for the approved scope. All 32 ACs pass. The real Opengrep v1.31.0 binary was executed on Linux aarch64. The never-authorized User path was also run on macOS. Windows execution is refused by design (NFR-002B-4).
> Revision: toolkit tree `7cdc906c…` · specification `deab5ce3…` · design `1ee056d3…` · runner `1f491d21…` (SHA-256 prefixes). Final run after Bug Fix TASK-034 (closing-review findings). Earlier: the first real-binary run failed and was fixed by TASK-032; the post-TASK-032 run (toolkit `30346157…`, runner `59796b04…`) passed 10/10 with weaker clean-scan checks (see Results).

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-002-B, board status Implemented (TASK-030); acceptance task TASK-031 |
| Specification / Source | [specification.md](specification.md); parent EPIC-001 FR-16, FR-18, FR-24; AC-24; S-07 |
| Design / Implementation | [technical-design.md](technical-design.md); `scripts/src/x_ipe_secure_code/adapters/`, `guard/toolrun.py`, `tools_service.py`; Guard `SKILL.md` (Choosing methods, Running a tool), `references/guard-records.md` |
| Target URL | N/A: CLI, library and skill scope (no UI) |
| Config / Capability | Python implementation tool. Real Opengrep binary (official release, digest checked) in the docker volume `og-validate`. Runner [blackbox.py](acceptance/blackbox.py) calls the real CLI through `uvx` and never imports toolkit code |
| Planned Cases | 14: black-box integration 11 (TC-B-01…10 container, TC-B-11 + TC-B-10 host), structured review 1 (TC-S-01), unit/library 1 (TC-U-01), regression 1 (TC-R-01, FEATURE-002-A runner) |

Tool runs need a registered binary, which needs Maintainer authorization. They therefore run only in an **offline Linux container (`--network none`, `UV_OFFLINE=1`) with a disposable HOME**. The project folder is named `proj ü` (non-ASCII). The samples are the real MVP projects shanghai-marathon-registration and WebGoat, mounted read-only.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-02 | Spec G-02; FR-16, FR-18, AC-24 | Developer, upstream agent | Trustworthy rule-driven evidence: real output, complete accounting, honest failure | TC-B-02, 03, 04, 07, 09; TC-U-01 (03f, 03j) | 02*, 03* | not measured |
| G-04 | Spec G-04; FR-16 | Developer, Maintainer | Lowest-cost method that is sufficient, without lowering the requirement; recorded choice | TC-B-05, 08, 10 | 04* | not measured |
| G-05 (enabling) | Spec G-05; FR-24, FR-17 | Owner, Maintainer, Developer | Only an authentic registered tool runs; the original project is unchanged; no silent download | TC-B-01, 02, 06, 11; TC-S-01 | 01*, 03a, 03b, 03i, 05*, 06* | not measured |

The qualitative scenario from the spec was exercised with the real binary on the real samples: a known CWE-89 in WebGoat is reported, a modified binary is refused without being executed, and the original files stay byte-identical (TC-B-01, TC-B-02, TC-B-06). Use by real people on real projects: **not measured**.

## Full Acceptance / Evidence Map

| AC ID | TC / Type | Original Assertions (summary) | Evidence | Delivery State |
| --- | --- | --- | --- | --- |
| AC-002B-01a | TC-B-01 integration | Official binary registered with digest, version, platform, validation state | Pass | verified |
| AC-002B-01b | TC-B-11 integration (host) | Registration refused without Maintainer authorization; nothing recorded | Pass | verified |
| AC-002B-01c | TC-B-01 integration | Fake binary printing `1.31.0`, modified official binary, symlink, relative path: refused, never executed | Pass | verified |
| AC-002B-01d | TC-B-06 integration | Swapped binary → precheck_failed, failed method, no findings; unregistered tool → precheck gap | Pass | verified |
| AC-002B-01e | TC-B-06 integration | Next step names Maintainer registration; nothing downloaded or re-registered | Pass | verified |
| AC-002B-01f | TC-B-09 integration | Clean tool evidence alone is not a pass (ledger still needs a state) | Pass | verified |
| AC-002B-02a | TC-B-03, TC-B-05 integration | Scan mode `include_ignored` scans ignored folders; unknown fields (shell text) refused | Pass | verified |
| AC-002B-02b | TC-B-05 integration | Registry name, URL, folder or symlink as rules refused; unsupported rule feature refused | Pass | verified |
| AC-002B-02c | TC-B-05 integration | Targets wider than the check object refused | Pass | verified |
| AC-002B-02d | TC-B-02 integration; TC-U-01 | Rule-file digests recorded and equal to the recomputed digests of the original files; the digest of each executed single-rule config is recorded per rule id (run entry = manifest); a config that does not re-read as exactly its rule is not run (TASK-034) | Pass | verified |
| AC-002B-02e | TC-B-05 integration | Time limit 0 and 1801 refused; refusals execute and record nothing | Pass | verified |
| AC-002B-03a | TC-B-02 integration | Originals byte-identical; staging removed; real HOME untouched; disposable tool home observed in a dedicated system temporary folder during the run (Opengrep cache inside) and removed afterwards, with a non-ASCII project | Pass | verified |
| AC-002B-03b | TC-B-02 integration | Only staged paths passed; no tool logs retained | Pass | verified |
| AC-002B-03c | TC-B-02 integration | Real CWE-89 finding on WebGoat with provenance; Python finding attributed to C2 only | Pass | verified |
| AC-002B-03d | TC-B-02 integration | Evidence for each check, with provenance | Pass | verified |
| AC-002B-03e | TC-B-03, TC-B-04 integration | Unreported files fail with a hint; Python syntax error gives a "not analysable" gap; ignored `tests/` skipped by default; git-ignored staged files still scanned; other checks unaffected | Pass | verified |
| AC-002B-03f | TC-U-01 integration (fake tool) | Exit 7, unparseable output → failed; error entries → completed_with_errors with partial findings kept; exit 0 with no output → failed with an explicit gap (TASK-032) | Pass | verified (fake tool; the real binary's error modes were observed in the tool-level validation) |
| AC-002B-03g | TC-B-07 integration | Time limit reached → timed_out, failed method | Pass | verified |
| AC-002B-03h | TC-B-03, TC-B-09 integration | Clean zero results → ok, independently proven from the retained tool output and manifest: the expected file is in `paths.scanned` for every rule; nothing skipped, unaccounted, in error or in `skipped_rules`; every rule completed with exit 0; manifest digest = run entry | Pass | verified |
| AC-002B-03i | TC-B-02 integration | Token in the matched line never stored; matched source removed | Pass | verified |
| AC-002B-03j | TC-U-01 integration | Failed auxiliary tool method may be substituted; a failed required one may not | Pass | verified (fake tool) |
| AC-002B-03k | TC-B-07 integration | Target changed after planning → not run, failed evidence | Pass | verified |
| AC-002B-04a | TC-B-02 integration | Guard supplies parameters, targets and mode; no mapping from Policy to rule | Pass | verified |
| AC-002B-04b | TC-B-05 integration | Tool method that was not selected is refused | Pass | verified |
| AC-002B-04c | TC-B-08 integration | Agent cannot record `opengrep` evidence itself; reviewed high tool finding → Fail by the 002-A rules | Pass | verified |
| AC-002B-04d | TC-B-05 integration | Method choice recorded; tool method that was not selected refused | Pass | verified |
| AC-002B-04e | TC-B-08 integration | Added (supplementary) method recorded and activates the tool; report shows method choices, changes and Adapter runs | Pass | verified |
| AC-002B-04f | TC-B-10 integration (container + host) | Skill: cheapest sufficient method, no "all tools" default, ask before adding more, record choice/changes, local rules only; reference documents the tool request | Pass | verified (agent behavior not measured) |
| AC-002B-05a | TC-S-01 structured | [tool-validation/README.md](tool-validation/README.md) dated 2026-10-19 (TASK-027, before implementation): version, official digest matched, environment, rules, commands, results on both samples, timings, known issues | Pass | verified |
| AC-002B-05b | TC-S-01 structured + TC-U-01 | All 7 digest-table entries match the README official-digest table byte for byte (cross-check run 10-20-2026). Only `opengrep_manylinux_aarch64` is marked validated. AC-28 stated pending in FEATURE-003-C (README header) | Pass | verified |
| AC-002B-06a | TC-B-01, TC-B-06, TC-B-11 integration | Status: provided/registered/digest ok/validated; failing digest check reported; not registered + next step | Pass | verified |
| AC-002B-06b | TC-B-01 integration | trivy/strix reported as not provided | Pass | verified |

## Test Cases

| TC | Type | Priority | Command / Method | Result |
| --- | --- | --- | --- | --- |
| TC-B-01…TC-B-10 | integration (black-box CLI, real binary) | P0 (01c/01d, 03a, 03c, 03e, 03f-class failures), P1 others | `python3 blackbox.py container` in `fat-uv-git:py312` (uv Python 3.12 bookworm + git), `--network none`, `UV_OFFLINE=1`, `OPENGREP=/og/opengrep` (official v1.31.0 manylinux aarch64, digest `2b713a29…`). Fresh uv cache volume `fat-uv-cache-gb`, warmed online with the fixed toolkit; the fixed code was checked to be present in the cache | 10/10 Pass, stderr empty ([evidence](acceptance/evidence-container-linux.jsonl), `3a256de8…`) |
| TC-B-11, TC-B-10 | integration (host User path) | P1 | `UV_REFRESH_PACKAGE=ai-secure-code-toolkit python3 blackbox.py host` on macOS (Python 3.13 runner, no trust store) | 2/2 Pass ([evidence](acceptance/evidence-host-macos.jsonl), `290c2607…`) |
| TC-S-01 | structured review | P1 | Read the tool-validation README against 05a. Cross-check the toolkit digest table (`adapters/digests.py`) against the README official-digest table (7/7 identical) | Pass |
| TC-U-01 | unit / library + integration (fake tool) | P1 | `uv run pytest -p no:cacheprovider -o addopts="" -v tests/adapters tests/guard/test_guard_tool.py tests/test_status.py` (macOS Python 3.14) | 112 passed, 1 skipped (non-UTF-8 file names; run on Linux) ([log](acceptance/evidence-unit-library.log), `f5bd065a…`) |
| TC-R-01 | regression (FEATURE-002-A black-box) | P1 | FEATURE-002-A runner (updated for the 002-B contract: `custom-scan` method, method choice, reference schema), container with a fresh `fat-uv-cache-ga` cache, plus host | container 26/26, host 2/2 Pass ([container](acceptance/regression-002A-container-linux.jsonl), [host](acceptance/regression-002A-host-macos.jsonl)) |

Full suites at the final revision: macOS Python 3.14 and 3.11: 523 passed, 2 skipped each. Linux Python 3.12: 525 passed. `ruff check` clean.

## Results

| Type | Planned | Passed | Failed | Blocked |
| --- | --- | --- | --- | --- |
| integration (black-box) | 11 | 11 | 0 | 0 |
| structured review | 1 | 1 | 0 | 0 |
| unit / library | 1 | 1 | 0 | 0 |
| regression | 1 | 1 | 0 | 0 |
| **Total** | **14** | **14** | **0** | **0** |

Pass rate: 14/14 at the final revision. All 32 ACs have current passing evidence.

**First real-binary run (failed, kept as evidence):** [evidence-container-linux-run1-FAIL.jsonl](acceptance/evidence-container-linux-run1-FAIL.jsonl) (`cb531fbe…`): 5/10. Every case that ran Opengrep failed. Cause: Opengrep v1.31.0 exits 0 with no output when its cache path (`XDG_CACHE_HOME`) contains non-ASCII characters. The toolkit had placed the tool's home inside the staging folder under the project `proj ü`. No false Pass resulted, because empty output was already a failed method. A diagnostic run with an ASCII project passed 10/10; it was used only to confirm the cause and is not acceptance evidence. Fixed in Bug Fix TASK-032 ([bug report](bug-report-TASK-032.md)): the disposable home is now created privately in the system temporary folder, a non-ASCII temporary folder is refused before execution, and "exit 0 with no output" is an explicit gap. Afterwards the complete acceptance set was rerun with fresh caches.

**Closing-review rerun (Bug Fix TASK-034):** the closing review (TASK-033) found that `copy_hash` ignored short writes, that the executed re-serialized rule configs had no recorded digest or equivalence check, that the clean-scan acceptance checks trusted the product's `ok`, and that this report overstated the real-binary evidence for removal of the tool home. All were fixed test-first ([bug report](bug-report-TASK-034.md)). The runner gained independent checks (retained output and manifest, recomputed rule digests, executed-config digests, a tool-home watch in a dedicated temporary folder); no assertion was relaxed. Everything was rerun with fresh offline caches: container 10/10, host 2/2, FEATURE-002-A regression 26/26 + 2/2.

## Gaps and Honest Limits

- Platforms: the real binary was executed only on Linux aarch64 (the only tool-level validated platform). The macOS and other Linux builds are registered from official digests but were not executed. Windows Adapter execution is refused by design (NFR-002B-4).
- Isolation: the tool's file system and network access are not enforced at OS level. The container used `--network none`, but that is a property of the test environment, not the toolkit. Network enforcement is deferred to FEATURE-002-C.
- A rule containing the character U+0085 cannot be staged faithfully (YAML writes it raw) and is not run; this shows as a failed method with a gap, never as an altered run.
- AC-002B-03f/03j were verified with the fake tool. The real binary's error modes (exit 7, exit 2, JSON errors) were observed in the tool-level validation, not in this black-box run.
- If the toolkit process is killed during a run, the tool home (Opengrep runtime cache only) can remain in the system temporary folder; the next run sweeps only the project's private staging, so it must be removed manually (documented in guard-records.md).
- Skill instructions (04f) were verified structurally. Agent behavior (choice of the cheapest method, asking before adding more) is not measured.
- Formal tool evaluation (AC-28) is pending in FEATURE-003-C.
- Stakeholder outcome: not measured.

> **Note (2026-10-24, TASK-100):** bug fix TASK-100 makes the shared no-follow open (`safe_io`) and the Guard staging walk refuse a FIFO without blocking, with the existing refusals. Regression evidence: `acceptance/regression-TASK-100-host-macos.jsonl` (identical to the original host evidence). The results above are unchanged.
