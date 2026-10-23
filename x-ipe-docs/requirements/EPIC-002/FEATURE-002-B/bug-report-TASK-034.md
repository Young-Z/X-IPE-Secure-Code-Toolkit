# Bug Report — TASK-034: Staged-byte integrity and rule provenance (closing review findings)

## Reported Behavior

- **Source:** independent closing review for FEATURE-002-B (TASK-033, 10-20-2026), findings 1–5. User decision: fix all
  (including recording the digest of the executed rule configuration), strengthen the acceptance runner, correct the
  docs, rerun acceptance, then resume closing.
- **Severity:** Medium. Finding 1 can break the digest-to-staged-bytes binding; it was not observed in practice
  (short writes to regular files are rare). Finding 2 is a provenance gap: AC-002B-02d was already met. Finding 3 is
  test strength. Findings 4–5 are documentation.
- **Expected (spec):** AC-002B-01d/03k: the snapshotted bytes are the bytes recorded and scanned. AC-002B-02d: the
  digest of every rule file used is recorded. G-02: trustworthy evidence, with no false clean result.
- **Actual:** (1) `safe_io.copy_hash` hashed every chunk but ignored the return value of `os.write`, so a short
  write would leave a truncated copy whose recorded digest still matched. (2) Each parsed rule is re-serialized into
  a single-rule config (approved design), but neither the executed config's digest nor its equivalence to the source
  rule was recorded or checked. (3) The runner's clean-scan checks trusted the product's `ok`. (4) The acceptance map
  claimed real-binary evidence that the tool home is removed, but the runner did not observe it. (5) The user docs did
  not describe the TASK-032 behavior.
- **Mode:** free-mode, interact-with-human. Write scope: `adapters/safe_io.py`, `guard/toolrun.py`, their tests and
  test double, the acceptance runner, the 002-B design, and the Guard/framework docs and README.

## Goal / Subgoal Restoration

| Goal / Subgoal | Parent / Source | Stakeholder | Intended Behavior | Contribution / Selection | Constraints / Non-goals | Story / AC / Type | Failing Scenario | Fixed / Regression Evidence | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-02 trustworthy tool evidence; G-05 the scanned bytes are the recorded bytes | specification.md G-02, G-05 | Developer, Owner | Recorded digests describe exactly the bytes the tool scanned and executed | Write-all copy; executed-config digest bound to the rule id, with a parse-back equality check | No AC changed; additive evidence fields only; the approved design (one process per rule) is kept | AC-002B-01d, 02d, 03a, 03h, 03k / Integration | Short write → truncated staged copy with a matching digest; an altered rule config runs unnoticed | RED/GREEN below; real-binary rerun 10/10 | not measured |

## Reproduction

- Finding 1: a unit test forces `os.write` to write at most 7 bytes per call → on the unfixed code the destination is
  a 7-byte prefix while the returned digest covers all 10,240 bytes. A forced zero-byte write raised no error.
- Finding 2: an integration test replaces `dump_single` with one that alters the rule message → on the unfixed code
  the altered config was executed (fake tool invoked). The run entry had no `config_digests`.

## Root Cause

- `copy_hash` assumed that `os.write` always writes the whole buffer (implementation error).
- The design selected re-serialized single-rule files but defined no binding between the recorded source digest and
  the executed bytes (design gap, now closed in the design).
- Acceptance checks for clean scans read only the derived product status (test design gap).

Callers inspected: `copy_hash` is used by binary snapshotting (`registry_store`) and target staging (`targets.stage`,
in two places). The rule staging loop in `toolrun._stage_and_run`. The manifest and run-entry builders. The report's
Adapter section (unchanged: it does not read `rules`).

## Scope and Conflicts

- **Expected consequences:** the run entry `rules[]` items gain `config_digests`, and the manifest rule entries gain
  `config_digest` (additive; old states read unchanged). A rule whose config does not parse back to exactly itself is
  not run. The independent review fuzzed ~50,000 generated rules plus edge cases (dates, special floats, regex
  characters, CJK/emoji, multi-line strings) and found no false rejection. The only exception is strings containing
  U+0085 (NEL): PyYAML writes it raw, so the rule fails visibly with the gap instead of running altered (honest limit).
- **Unaffected:** binary snapshots and target staging produce identical bytes (only completeness is now enforced).
  The manifest size bound (4 KiB per rule) easily covers the ~90 extra bytes.
- **Unexpected conflicts:** none. Inspected: spec AC-002B-01d/02d/03a/03h/03k, the design's Safe I/O, Execution and
  Recording sections, and the code paths above.

## Fix and Design Impact

- Design updated before the code (Safe I/O `copy_hash` bullet, Execution single-rule bullet, Recording run entry,
  Design Change Log row TASK-034).
- `safe_io._write_all`: loops over a `memoryview` until every byte is written; a zero-byte write raises `OSError`.
- `toolrun`: writes the config as exact bytes; `_faithful(config, rule)` re-reads it with `rules.load_rules`, and the
  result must equal `[rule]`, else the status is `failed` with the gap "rule could not be staged faithfully" and the
  rule is not run. `config_digest` is recorded per rule; `config_digests` per rule file in the run entry.
- Runner: `stored` (manifest digest checked against the run entry), `complete_clean` (tool output non-empty and
  well-formed, the expected file in `paths.scanned` for every rule, nothing skipped, unaccounted, in error or in
  `skipped_rules`, every rule `completed` with exit 0), `HomeWatch` (dedicated ASCII `TMPDIR`; the tool home is
  observed during the run with the Opengrep cache inside, and is gone afterwards). The rule digest is recomputed
  from the original file.
- Docs: Guard SKILL.md step 5a, guard-records.md "Tool run" (provenance, runtime home, `TOOL_HOME_UNSUPPORTED`,
  no-output gap, kill limit), the cli-contract.md `guard tool` row, README "Register Opengrep".

## Mini AAA and Actual Routing

| Scenario / AC | Arrange | Act | Assert Clauses | Domain Type / Tool / Operation | Actual Evidence |
| --- | --- | --- | --- | --- | --- |
| Short writes (01d/03k) | 10,240-byte file; `os.write` limited to 7 bytes | `copy_hash` | Destination bytes = source; digest and size correct | pytest unit | RED → GREEN |
| Zero-byte write | `os.write` returns 0 | `copy_hash` | Raises `OSError` | pytest unit | RED → GREEN |
| Config digest (02d) | Fake tool logs the SHA-256 of the config it receives | `guard tool` | Run entry `config_digests` = digest seen by the tool; manifest `config_digest` equal | pytest integration | RED → GREEN |
| Non-faithful config not run (02d/G-02) | `dump_single` alters the rule | `guard tool` | Tool not invoked; status failed; gap names "staged faithfully" | pytest integration | RED → GREEN |
| Real binary (02d, 03a, 03h) | Container, real Opengrep v1.31.0, project `proj ü` | Runner TC-B-02/03/09 | New independent checks (listed above) | Black-box | 10/10 Pass |

## Verification

- **RED:** unfixed `safe_io.py` `509e9826…`, `toolrun.py` `d79d9d1a…`; tests `test_guard_tool.py` `a1c39e9d…`,
  `test_adapters_units.py` `fc291c10…`, fake `acbbfe77…` → 4 failures, all behavioral (truncated copy, no error,
  missing `config_digests`, altered rule executed).
- **GREEN:** `safe_io.py` `d4fee549…`, `toolrun.py` `475ba8a2…`, the same test files (hashes unchanged) → pass.
- **Full suites:** macOS Python 3.14 and 3.11: 523 passed, 2 skipped. Linux Python 3.12: 525 passed. `ruff check`
  clean.
- **Real-binary acceptance** (fresh offline cache, the fixed code confirmed in the cache): container 10/10, host 2/2.
  FEATURE-002-A regression: container 26/26, host 2/2. Toolkit tree `7cdc906c…`; design `1ee056d3…`;
  runner `1f491d21…`.
- **Independent review** (code-review subagent, 10-20-2026): no significant issues. U+0085 limit noted as above.
- **Engineering delivery:** verified. **Stakeholder outcome:** not measured.

## Original Output and Owner Handoff

```yaml
task_completion_output:
  category: "standalone"
  status: completed
  next_task_based_skill: null
  process_preference:
    interaction_mode: "interact-with-human"
  execution_mode: "free-mode"
  workflow:
    name: "N/A"
  task_output_links:
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/safe_io.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/guard/toolrun.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/adapters/test_adapters_units.py"
    - "ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts/tests/guard/test_guard_tool.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/acceptance/blackbox.py"
    - "x-ipe-docs/requirements/EPIC-002/FEATURE-002-B/bug-report-TASK-034.md"
  bug_severity: "Medium"
  root_cause: "copy_hash ignored short os.write results; the re-serialized single-rule configs had no recorded digest or equivalence check; acceptance clean-scan checks trusted the derived status"
  conflicts_found: []
```

The owner (Sage) resumes Feature Closing TASK-033.
