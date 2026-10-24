# Guard Verification Report gv-20261024T010000Z-<vid8>

## Verdict

**Verdict: Cannot confirm pass**

Reasons that determined the verdict:

- `CHECK_UNCONFIRMED` C1: not executed: no ledger state was recorded
- `CHECK_UNCONFIRMED` policy:CWE/4.14/CWE-89: N/A not confirmed by a valid review (recorded reason: no database access in the target)
- `CANCELLED` verification: cancelled by the user; unfinished work was not verified

## Scope

- Verification: gv-20261024T010000Z-<vid8>
- Opened: <time>
- Ended: <time>
- Request: —
- Baseline: —
- Whole project: no

### Targets (verified)

| Path | Change | Old path | Digest at open | Digest at conclusion | Changed | Incomplete | Not followed / unreadable |
|---|---|---|---|---|---|---|---|
| src/login.py | modified | — | sha256:d32ccff0f4d1aae6ee690f089982efda18a915793f4906bd2068d584dfc0000f | sha256:d32ccff0f4d1aae6ee690f089982efda18a915793f4906bd2068d584dfc0000f | no | no | — |

### Read-only context (not verified)

| Path | Digest |
|---|---|
| README.md | sha256:4b2b418bbeeb44157535c731f489f6e1dc506a2acd39171ca9afef9f5d17aa7d |

### Suggested files (not verified)

(none)

### Copilot reports (context only, never evidence of a pass)

(none)

### Adopted Policies

Adopted scope: sha256:4fde2cd9696dfadca1d86d784f55532b8ada7bd28602569bb8b5f322046f7308 (mode clues)

| Rule | Confirmed state digest | At conclusion |
|---|---|---|
| CWE/4.14/CWE-79 | sha256:86bced7be9c890f32aa0cd3d675a935c61ee108bff75a5c4413fb6cc1ca25fe6 | unchanged |
| CWE/4.14/CWE-89 | sha256:fa34cf85c790e231ad645a6f870c9ea6c2feeb095e2d0b3c5f463beedd2b0344 | unchanged |

## Check Plan

| Check | Policy | Object | Part | Methods | Minimum evidence |
|---|---|---|---|---|---|
| C1 | CWE/4.14/CWE-79 | src/login.py | — | semantic-review (reading, required) | reading |

Policies judged not applicable:

| Policy | Factual reason |
|---|---|
| CWE/4.14/CWE-89 | no database access in the target |

User scope exclusions (not N/A, not met):

(none)

## Ledger

States: met, not_met, unconfirmed, n/a, excluded. No percentage is computed.

| Check | Policy | State | Recorded state | Evidence by kind | Findings | Reason | Substitution |
|---|---|---|---|---|---|---|---|
| C1 | CWE/4.14/CWE-79 | unconfirmed | — | — | — | not executed: no ledger state was recorded | — |
| policy:CWE/4.14/CWE-89 | CWE/4.14/CWE-89 | unconfirmed | n/a | — | — | N/A not confirmed by a valid review (recorded reason: no database access in the target) | — |

## Findings

(none)

## Reviewer Records

Invocation is declared by the agent, not proven by the script.

(none)

## Conflicts

(none)

## Risk Acceptances

Recorded separately; findings, severities and the verdict are unchanged.

(none)

## Evidence

| Evidence | Kind | Method | Status | Paths | Lines | Summary | Stored | Masking |
|---|---|---|---|---|---|---|---|---|
| E1 | reading | semantic-review | ok | src/login.py | — | read login() | — | not masked |

## Budget

| Limit | Value |
|---|---|
| Total time | 60.0 min (toolkit default) |
| Extra attempts | 3 |
| Consumed time | 0.0 min |
| Extra attempts used | 0 |
| Budget of a verification opened before budgets existed | no |

Extensions (by the user):

(none)

Pauses (excluded from the consumed time):

(none)

Attempts:

| Id | Kind | Covers | Extra | Status | Overrun |
|---|---|---|---|---|---|
| a-1-<vid8> | semantic\_review | C1/semantic-review | 0 | finished | — |

- Model usage reported by the host: 0 requests, 0 input and 0 output tokens; unknown for 1 attempt(s); not applicable for 0 attempt(s) without a model

## Cancellation

- Cancelled at <time> — reason: user stopped
- Tool: no tool was running
- Agent work in progress —: stop requested, not confirmed by the toolkit
- remote requests already sent may continue or be billed; the toolkit cannot stop them
- Results recorded before the cancellation are kept; a cancelled verification is never a pass

## Outbound Calls (Egress)

Grants (by the user, this verification only):

(none)

Declared or gated calls:

(none)

- Agent declarations are an audit record, not enforced blocking
- Network access is not OS-enforced (including by tools the Adapters launch); calls that were not declared cannot be observed by the toolkit

## Evidence Retention

- Raw evidence location: .x-ipe/private/secure-code/guard/gv-20261024T010000Z-<vid8>/
- Kept 30 days after the verification ended, then removable
- Removal: only by the explicit command secure-code guard cleanup; this report stays until the user removes it

## Limits

- Reviewer invocation is declared by the agent and bound to target digests; the script cannot prove it ran
- Adapters: Opengrep and Trivy run only as the registered official binaries on staged copies; their file-system and network access are not OS-enforced; Trivy runs on Linux x86-64/arm64 only, scans offline, reads the provisioned components in place (changes are detected by re-hashing after each scan, not prevented) and its provisioning hosts are a configuration-level expectation; Strix is not available yet
- Masking uses pattern-based credential detection, not a complete data-loss-prevention guarantee
- Budget: only work registered as attempts and tool runs is counted; work done without an attempt or while paused cannot be observed; time is wall-clock minus pauses, not a money cap
- Egress: agent declarations are an audit record; network access (including by tools the Adapters launch) is not OS-enforced and undeclared calls cannot be observed
- Budget extensions, egress grants and risk acceptance need an interactive confirmation; this is a cooperative control (a program driving a pseudo-terminal could pass it), not an authorization boundary
- Termination is confirmed when the tool's process group was seen exiting; processes that left the group are not tracked

## Structured Result Origin

- Structured result written by secure-code toolkit 0.1.0; renderer sha256 <renderer>
- This identifies the build that wrote the structured result; a report re-created later by repair may come from a different build

<!-- guard-result-sha256: <footer> -->

