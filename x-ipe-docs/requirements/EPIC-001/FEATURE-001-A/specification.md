# Feature Specification: Toolkit Install, Signed Owner Initialization & Status

> Feature ID: FEATURE-001-A  
> Epic: EPIC-001 (Framework: Knowledge, Authorization & Policy)  
> Version: v1.2  
> Status: Refined (v1.0 confirmed 10-18-2026 in TASK-004; v1.1 change CR-001 decided by user 10-19-2026 in TASK-005)  
> Last Updated: 10-19-2026 (v1.2: CR-002)

## Version History

| Version | Date | Description | Change Request |
| --- | --- | --- | --- |
| v1.0 | 10-18-2026 | Initial specification | N/A |
| v1.2 | 10-19-2026 | Windows verification of AC-001A-10a deferred to a later phase as a tracked open item; Windows remains a supported-platform requirement. No other AC changed. | CR-002 (user decision during TASK-007 acceptance, 10-19-2026) |
| v1.1 | 10-19-2026 | "Install" redefined as **project initialization**: skills and their scripts are pre-generated (no package install); initialization places skills in the skills folder of the environment passed explicitly by the calling agent (`--env`; no auto-detection, user clarification 10-19-2026), creates the folder structure and writes the toolkit fragment into the environment's host entry file with fragment-level idempotency. Command names separated (`init` vs `auth init/revoke`). | CR-001 (user decisions during TASK-005 Technical Design, 10-19-2026); moves the minimal host-entry write from FEATURE-003-B into this feature |

## Linked Mockups

| Mockup | Type | Path | Description | Status | Linked Date |
|--------|------|------|-------------|--------|-------------|
| N/A | — | — | No product UI: the feature is a command-line installer, authorization commands and a text status report. Bounded discovery: EPIC-001 has no mockups (`x-ipe-docs/requirements/EPIC-001/mockups/` is empty) and the idea folder has no mockups. | — | — |

## Overview

This feature is the **Minimum Runnable Feature of EPIC-001** and the first step of the confirmed first-use path (O-09): *controlled install → explicit owner initialization → maintain Policies → select scope → host integration → collaboration/verification → report*.

It delivers three things:

1. **Project initialization ("install").** The three self-contained skills — **Framework, Copilot, Guard** — ship pre-generated, including the Framework scripts; nothing is package-installed. Initializing an explicitly named project root: (a) takes the agent environment explicitly from the caller — the calling agent knows its own environment, so nothing is auto-detected, (b) places the three skills in that environment's skills folder, (c) creates the empty secure-code knowledge layout, and (d) writes a toolkit-owned fragment into the environment's host entry file (e.g. AGENTS.md) with fragment-level idempotency. It never downloads scanners, never adds starter knowledge and never creates authorization.
2. **Signed owner initialization, verification and revocation.** The machine owner explicitly initializes a local Maintainer authorization that is signed with a standard digital signature and checked against a fixed trusted public key. Initialization and revocation need an interactive terminal and an owner-set passphrase that protects the signing private key, so an AI agent cannot authorize itself. Every maintenance action re-verifies the authorization; ordinary verification never touches the private key.
3. **Separated status.** A read-only status command reports install, authorization, Policies, tool conditions and host integration separately, each with its own next step. There is no single "Ready" flag.

The toolkit must work in any project — macOS, Linux and Windows — without X-IPE task boards or workflow files.

**Terminology.** *Project initialization* (also "install") prepares a project; *authorization initialization* creates the owner's signed Maintainer authorization. Acceptance groups AC-001A-04/05 concern project initialization; AC-001A-06…08 concern authorization initialization, verification and revocation.

**Who:** machine owner / Maintainer (installs, initializes, revokes), Users and upstream agents (status, role check), and later features (FEATURE-001-B onward) that consume the authorization check.

## User Stories

- **US-01:** As a machine owner, I want to initialize an explicitly named project root for my agent environment, so that the three skills sit where my agent finds them and an empty secure-code layout exists, without touching any other project.
- **US-02:** As a Maintainer, I want re-running install to update only toolkit-owned files and report my local edits instead of overwriting them, so that upgrades never destroy my changes or my security data.
- **US-03:** As a machine owner, I want to explicitly initialize Maintainer authorization in an interactive terminal protected by my passphrase, so that no AI agent or script can make itself a Maintainer.
- **US-04:** As a Maintainer, I want every maintenance action to re-verify my signed authorization against the fixed trusted public key, so that a missing, tampered, revoked or foreign authorization never grants maintenance rights.
- **US-05:** As a machine owner, I want to explicitly revoke the authorization, so that maintenance rights end immediately on this machine.
- **US-06:** As a User or upstream agent, I want a read-only status that reports each readiness condition separately with a next step, so that I know exactly what is missing without a misleading "Ready".
- **US-08:** As a Maintainer, I want initialization to add the toolkit entry to my environment's host entry file without duplicating it or overwriting my own content, so that my agent routes to the toolkit while my instructions stay intact.
- **US-07:** As an upstream agent in any project, I want the toolkit to work without X-IPE task or workflow infrastructure, so that I can use it in plain repositories.

## Goal / Subgoal Coverage

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Contribution / Selection | Success Evidence | Constraints / Non-goals | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-05 | EPIC-001 G-05; FR-24, FR-03 (U-01…U-13, U-15, I-20, O-09) | Owner / Maintainer | Maintenance authority is explicit, verifiable and cannot be self-granted by an agent | Signed init / verify / revoke with interactive + passphrase protection (selected over terminal-only or flag-only, 10-18-2026 decision) | Qualitative scenario: agent-style non-interactive init is refused; tampered or revoked grants yield User; owner init yields Maintainer | Local workflow-level only; does not resist someone with local write access (U-13); no enterprise identity | AC-001A-06a…g, AC-001A-07a…f, AC-001A-08a…d | not measured |
| G-03 / G-06 | EPIC-001 FR-03 (O-09, O-10, X-11, X-12, K-29) | User, upstream agent | Readiness gaps are visible separately, with the correct next step | Separated read-only status | Scenario: fresh install shows install OK and each other condition missing with its own next step | No dashboard/monitoring; status is not a security-health certificate | AC-001A-09a…e | not measured |
| G-08 | EPIC-001 NFR-01 | Upstream agent / any host | Toolkit usable without X-IPE infrastructure on macOS, Linux, Windows | Standalone uv namespace and self-contained skills | Scenario: install/init/verify/revoke/status in a plain repository on each OS | — | AC-001A-04e, AC-001A-10a | not measured |
| G-01 / G-02 (enabling) | EPIC-001 FR-01 (O-01…O-06) | All | Each skill's responsibility boundary is explicit from the first install, enabling later Copilot/Guard features | Installed skill skeletons declare responsibilities and non-responsibilities | Scenario: installed skills state roles; Guard declares it never fixes, Copilot declares it is not a business writer | Skeleton content only; behaviour delivered by later features | AC-001A-04d | not measured |
| G-06 | EPIC-001 G-06; FR-27, FR-28 (I-03, I-04, I-12…I-14) — minimal part moved here by CR-001 | Maintainer, Developer | After initialization the agent environment knows the toolkit, and user content in the host entry file is never overwritten | Explicit environment profile + one toolkit-owned fragment with fragment-level idempotency; single-source generation of all carriers and diff handling stay in FEATURE-003-B | Scenario: initialize a Copilot project with an existing AGENTS.md; fragment added once; rerun adds nothing; user text unchanged | Host effect not verified here (I-19, AC-33 in 003-B) | AC-001A-04f…i | not measured |
| Safe upgrade | EPIC-001 FR-28 principle (I-12…I-16), user decision 10-18-2026 | Maintainer | Upgrades never overwrite local edits or security data | Idempotent safe reinstall | Scenario: reinstall after local edit reports the file, data byte-identical | Not a general file-sync tool | AC-001A-05a…d | not measured |

## Acceptance Criteria

### AC-001A-04: Project Initialization ("install")

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001A-04a | GIVEN an explicit, existing project root AND an explicitly given supported environment WHEN project initialization runs for that root THEN the pre-generated Framework, Copilot and Guard skills (including the Framework scripts) exist in that environment's skills folder (for `github-copilot`: `<root>/.github/skills/`) AND the layout `x-ipe-docs/secure-code/{knowledge/local, knowledge/reference, presets, tags, improvements, reports/copilot, reports/guard}` exists AND it contains no knowledge entries and no Presets | Integration |
| AC-001A-04b | GIVEN install is invoked without an explicit project root, or with a root that does not exist or is not a directory WHEN it runs THEN it refuses with an explanatory message AND writes nothing AND does not search parent directories for a project | Integration |
| AC-001A-04c | GIVEN a successful project initialization WHEN its effects are inspected THEN no scanner (Opengrep, Trivy, Strix) was installed or downloaded AND no authorization, key or grant was created AND no package install step was performed AND the toolkit itself made no network request | Integration |
| AC-001A-04d | GIVEN the installed skills WHEN their skill definitions are read THEN Framework, Copilot and Guard each state their responsibilities and non-responsibilities as defined in O-01…O-06 (e.g. Guard does not fix, Copilot is not a second business writer, Reviewers have no extra authority) | Unit |
| AC-001A-04e | GIVEN a plain repository with no X-IPE task board, workflow or `.x-ipe.yaml` files WHEN install, initialization, verification, revocation, status and each installed skill's documented toolkit entry point are used THEN they complete without requiring, reading or creating those files | Integration |
| AC-001A-04f | GIVEN an explicitly given supported environment WHEN project initialization runs THEN that environment's skills folder and host entry file are used and the environment is named in the result AND the result does not depend on which agent-specific files already exist in the project | Integration |
| AC-001A-04g | GIVEN no environment is given, or the given environment is not supported WHEN project initialization runs THEN it refuses, lists the supported environments, and writes nothing | Integration |
| AC-001A-04h | GIVEN the environment's host entry file exists with user content (or does not exist) WHEN project initialization runs THEN exactly one clearly delimited toolkit-owned fragment is present afterwards AND all content outside the fragment is byte-identical (or the file contains only the fragment if newly created) | Integration |
| AC-001A-04i | GIVEN the toolkit fragment is already present and unchanged WHEN initialization runs again THEN no second fragment is added and the file is unchanged; GIVEN the fragment was edited by the user THEN it is not overwritten AND it is reported as a difference for the Maintainer, replaced only on explicit choice | Integration |

### AC-001A-05: Safe Re-install

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001A-05a | GIVEN the same toolkit version is already installed and unchanged WHEN install runs again THEN no file is modified AND the result reports the installation as already current | Integration |
| AC-001A-05b | GIVEN a newer toolkit version AND toolkit-owned files that were not edited locally WHEN install runs THEN those files are updated AND the result lists each updated file | Integration |
| AC-001A-05c | GIVEN a toolkit-owned file that was edited locally WHEN install runs THEN that file is not overwritten AND the result reports it as a difference for the Maintainer to decide AND it is replaced only when the Maintainer explicitly chooses to replace that file | Integration |
| AC-001A-05d | GIVEN existing content under `x-ipe-docs/secure-code/` (knowledge, presets, tags, improvements, reports) WHEN install runs in any mode THEN that content is byte-identical afterwards | Integration |

### AC-001A-06: Explicit Owner Initialization

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001A-06a | GIVEN an interactive terminal and a pristine machine state (no trusted public key, no signing key, no authorization and no revocation record for this owner account) WHEN the owner runs initialization and sets and confirms a passphrase THEN a signing key pair and a fixed trusted public key are created outside every project directory AND a Maintainer authorization signed with a standard digital signature is created AND the private key is stored only in passphrase-protected form | Integration |
| AC-001A-06b | GIVEN initialization is invoked without an interactive terminal (e.g. piped input or an agent tool call) WHEN it runs THEN it refuses AND creates or changes no key, trusted public key or authorization | Integration |
| AC-001A-06c | GIVEN a valid authorization already exists WHEN initialization is run THEN it refuses to replace the trust root or authorization AND points the owner to status and revoke | Integration |
| AC-001A-06d | GIVEN the passphrase and its confirmation differ, or the owner aborts WHEN initialization runs THEN nothing is created and the reason is shown | Integration |
| AC-001A-06e | GIVEN initialization completes WHEN its output, logs and the project directory are inspected THEN neither the private key nor the passphrase appears in any of them | Integration |
| AC-001A-06f | GIVEN the authorization was revoked WHEN the owner runs initialization interactively AND enters the correct existing passphrase of the signing private key THEN a new valid authorization signed by the existing trust root is created AND no new trust root is created; WHEN the passphrase is wrong THEN nothing changes | Integration |
| AC-001A-06g | GIVEN partial, missing or corrupted trust state (e.g. authorization deleted but trusted public key or signing key present, or trust files unreadable) WHEN initialization runs THEN it refuses AND creates no new trust root, key or authorization AND reports the state as needing recovery, which is deferred (U-15, I-21) | Integration |

### AC-001A-07: Authorization Verification

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001A-07a | GIVEN no authorization file exists WHEN the role is verified THEN the role is User AND maintenance actions are refused with the next step "owner must run initialization" AND nothing is created automatically | Unit |
| AC-001A-07b | GIVEN an authorization whose content was altered, or which is signed by a key other than the fixed trusted public key, or which carries its own public key, or a same-named trust file placed inside a workspace WHEN verified THEN it is reported as invalid with the reason AND no Maintainer role is granted | Unit |
| AC-001A-07c | GIVEN a valid authorization AND a readable signing private key file WHEN ordinary verification runs under file-access instrumentation THEN the private key file is never opened AND verification also succeeds when the private key file is unreadable or absent | Unit |
| AC-001A-07d | GIVEN a valid authorization WHEN verified from any toolkit workspace or sandbox on the same machine THEN the Maintainer qualification is granted without per-project registration | Integration |
| AC-001A-07e | GIVEN a Maintainer role verified earlier in a session AND the authorization has since been revoked or altered WHEN the next maintenance action requests verification THEN verification is performed again and refuses | Unit |
| AC-001A-07f | GIVEN a valid Maintainer qualification WHEN any verification result is returned THEN it states the qualification only and does not by itself authorize scan scope, network, budget or autonomous actions | Unit |

### AC-001A-08: Explicit Revocation

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001A-08a | GIVEN a valid authorization AND an interactive terminal WHEN the owner runs revocation and enters the correct passphrase THEN the authorization is revoked AND subsequent verification on this machine returns User with reason "revoked" | Integration |
| AC-001A-08b | GIVEN revocation is invoked without an interactive terminal, or with a wrong passphrase WHEN it runs THEN it refuses AND the authorization remains unchanged | Integration |
| AC-001A-08c | GIVEN no authorization exists WHEN revocation runs THEN it reports that nothing is authorized and changes nothing | Integration |
| AC-001A-08d | GIVEN the authorization was revoked WHEN a saved copy of the pre-revocation authorization is restored to its location AND a new process verifies it THEN it is still rejected as revoked; it becomes valid again only through passphrase-confirmed re-authorization (AC-001A-06f). (Replacing the whole trust configuration by someone with local write access is outside protection, U-13.) | Integration |

### AC-001A-09: Separated Read-only Status

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001A-09a | GIVEN a fresh install with no authorization WHEN status runs THEN it reports separately: install (installed, version), authorization (not initialized → next step: owner runs initialization), Policies (Local 0 / Reference 0 → next step: Maintainer maintains Policies), tool conditions (each of Opengrep, Trivy, Strix on its own line: "Adapter not provided by this toolkit version" → next step: install a toolkit version that provides it; no scanner is checked or installed), host integration (environment, host entry fragment present / absent / modified; host effect not verified → next step for absent: run project initialization) AND no single overall "Ready" flag is shown | Integration |
| AC-001A-09b | GIVEN any project state WHEN status runs THEN no file in the project or toolkit configuration is created, modified or deleted AND no business code is scanned | Integration |
| AC-001A-09c | GIVEN an installed project WHEN status runs THEN it also reports the resolved project root (or sandbox), the install entry location, whether a default Preset exists, and obvious configuration problems (e.g. missing layout folders, unreadable trust file) | Integration |
| AC-001A-09d | GIVEN a directory where the toolkit is not installed WHEN status runs for it THEN it reports "not installed" with the install next step and does not report on a parent directory's installation | Integration |
| AC-001A-09e | GIVEN an invalid or revoked authorization WHEN status runs THEN the authorization line shows "invalid" or "revoked" with the reason and the next step, and the role shown is User | Integration |

### AC-001A-10: Platforms and Secrets

| AC ID | Criterion (Given/When/Then) | Test Type |
|-------|-------------------------------|-----------|
| AC-001A-10a | GIVEN macOS, Linux and Windows WHEN install, initialization, verification, revocation and status are run in a project path containing spaces and non-ASCII characters THEN each behaves as specified in AC-001A-04…09 | Integration |
| AC-001A-10b | GIVEN any toolkit command in this feature, including when model credentials are present in the environment WHEN it produces text output, structured results, logs, errors or files under the project THEN no private key material, passphrase or model credential is included | Integration |

> **Test Type Legend:** UI — browser/DOM; API — HTTP request/response; Unit — isolated function/module; Integration — multi-component interaction (CLI process + filesystem + OS terminal behaviour). This feature has no UI or HTTP API.

## Functional Requirements

- **FR-001A-1 Project initialization.** Input: explicit project root, optional explicit environment, the pre-generated toolkit skills. Process: validate root (exists, directory, explicit); resolve the environment (FR-001A-8); copy the three skill folders into the environment's skills folder; create the empty secure-code layout; write the host entry fragment (FR-001A-9); record what was placed (toolkit version and per-file identity) for later re-initialization/status. Output: list of created items or a refusal reason. Never package-installs anything, never installs scanners, knowledge, Presets or authorization; the toolkit makes no network request.
- **FR-001A-8 Environment resolution.** Supported environments are defined as profiles (skills folder, host entry file). The calling agent must pass the environment explicitly; it must be a supported profile. No detection from project files is performed. MVP profiles: `github-copilot` (verified host in MVP) and `claude-code` (unverified); further profiles can be added without changing the behaviour above.
- **FR-001A-9 Host entry fragment.** Writes one clearly delimited toolkit-owned fragment that points the agent to the three skills into the environment's host entry file. Idempotent: unchanged fragment → no change; absent → added; user-edited → reported and kept unless the Maintainer explicitly chooses replacement. Content outside the fragment is never modified. Generation of all three carriers from one routing definition and richer difference handling remain in FEATURE-003-B.
- **FR-001A-2 Safe reinstall.** Input: project root with existing install. Process: compare each toolkit-owned file against the install record and the new package: unchanged → skip; changed upstream and not edited locally → update; edited locally → report as a difference and keep unless the Maintainer explicitly chooses replacement for that file. Output: per-file result (current / updated / locally edited – kept / replaced on request). Never reads or writes data under `x-ipe-docs/secure-code/`.
- **FR-001A-3 Owner initialization.** Input: interactive terminal session, owner passphrase (entered twice for first initialization; the existing passphrase for re-authorization after revocation). Process: refuse if non-interactive or if a valid authorization exists; first initialization only from a pristine state (no trust root, key, authorization or revocation record), otherwise refuse partial/corrupted state as deferred recovery; after revocation, re-authorize only with the correct existing passphrase and the existing trust root; first initialization creates the signing key pair and fixed trusted public key outside any project; store the private key only passphrase-protected; create and sign the Maintainer authorization. Output: confirmation including where the trust files are, without key material.
- **FR-001A-4 Verification (reusable check).** Input: the authorization and the fixed trusted public key only. Process: verify signature, trust root identity and revocation state on every call; no session caching. Output: role (Maintainer / User) plus state (valid / not initialized / invalid with reason / revoked). Exposed as a reusable check for later maintenance features (FEATURE-001-B onward) and status.
- **FR-001A-5 Revocation.** Input: interactive terminal, passphrase. Process: refuse if non-interactive or the passphrase is wrong; record the revocation durably so that verification fails thereafter, including for restored copies of the pre-revocation authorization, across processes and restarts. Output: confirmation or refusal.
- **FR-001A-6 Status.** Input: explicit project root (or sandbox). Process: read-only collection of install, authorization, Policies counts (Local/Reference), default Preset presence, tool conditions per scanner, host-integration state and obvious configuration problems. Output: a sectioned report with one state and one next step per condition, both as human-readable text and as a structured result.
- **FR-001A-7 Skill skeletons.** The three installed skills each declare purpose, trigger conditions, responsibilities and explicit non-responsibilities (O-01…O-06) and point to the toolkit CLI; behaviour beyond this feature is delivered by later features.

## Non-Functional Requirements

- **NFR-001A-1 Security — key protection.** The signing private key is never stored unencrypted, is stored outside every project directory with owner-only file permissions where the OS supports it, and is read only by initialization and revocation.
- **NFR-001A-2 Security — no self-authorization.** No code path creates or repairs authorization implicitly (missing file → User). Only interactive, passphrase-confirmed owner commands change the trust root or authorization.
- **NFR-001A-3 Honest limits.** Documentation and status state that protection is local workflow-level and does not resist a person or process with local write access replacing the trust configuration (U-13), and that interactive-terminal detection is a guard against accidental agent self-authorization, not a sandbox.
- **NFR-001A-4 Portability.** Supported on macOS, Linux and Windows, including paths with spaces and non-ASCII characters, managed through uv.
- **NFR-001A-5 Reliability.** Writes of the install record, keys and authorization are atomic: an interrupted command leaves either the previous state or the complete new state, never a half-written file reported as success.
- **NFR-001A-6 Independence.** No runtime dependency on X-IPE task boards, workflow files or lifecycle skills.
- **NFR-001A-7 Performance.** Status reads metadata only and never scans business code; no numeric threshold is set in this specification.

## UI/UX Requirements

No graphical UI. Command-line user experience:

- Each command prints a short result and, when something is missing or refused, the reason and exactly one next step.
- Status output is sectioned (Install, Authorization, Policies, Tools, Host integration, Problems) with one state per line; no aggregate "Ready".
- Interactive prompts (passphrase, confirmation, per-file replacement choice) are explicit and never default to a destructive or authorizing choice.
- Every command also offers a structured (machine-readable) result for upstream agents, with the same content as the text output.

## Dependencies

- **Internal:** None (first feature). Consumers: FEATURE-001-B (maintenance authorization check), FEATURE-001-C/002-*/003-* (status sections they later populate), FEATURE-003-B (host integration state), FEATURE-003-C (sandbox verification).
- **External:** Python and uv on macOS, Linux and Windows (uv resolves the Framework scripts' dependencies on first run; no separate install step); a standard digital-signature implementation available to the toolkit (selected in technical design); OS facilities for interactive-terminal detection and owner-only file permissions.

## Business Rules

- **BR-01:** Missing authorization means role User; it is never generated or repaired automatically (U-09, U-11, I-20).
- **BR-02:** Only the fixed trusted public key outside the project decides trust; public keys carried inside an authorization or files inside a workspace never replace it (U-10).
- **BR-03:** Maintainer qualification is valid until explicitly revoked and is re-checked before every maintenance action (U-12).
- **BR-04:** Maintainer qualification is not an action authorization: scan scope, network, budget and autonomy need their own authorization (U-03, U-05).
- **BR-05:** One authorization covers all toolkit workspaces and sandboxes on the machine; it is not a pass for arbitrary filesystem locations or third-party targets (U-08).
- **BR-06:** Project initialization never adds knowledge, Presets, scanners or authorization and performs no package install (K-29, O-09, CR-001).
- **BR-09:** Environment is never guessed; the caller must pass a supported environment (CR-001).
- **BR-10:** Only the delimited toolkit fragment in a host entry file is toolkit-owned; everything else belongs to the user (I-12, I-13).
- **BR-07:** Install and reinstall never modify `x-ipe-docs/secure-code/` data; locally edited toolkit files are replaced only by explicit Maintainer choice.
- **BR-08:** Status is read-only and is not a security-health certificate (X-12).

## Edge Cases & Constraints

| Scenario | Expected behaviour |
|---|---|
| Project root is a symlink or nested inside another installed project | Uses exactly the given root after normalization; never relocates to a parent install (S-04) |
| The environment's skills folder already contains a non-toolkit skill with the same name | Refuse to overwrite it; report the conflict for the Maintainer |
| Read-only filesystem or permission denied during install | Fail with reason; no partial install reported as success (NFR-001A-5) |
| Two initializations started concurrently | At most one succeeds; the other refuses; trust root never left half-written |
| Authorization present but trusted public key missing or unreadable | Verification: invalid with reason; status shows "invalid"; role User |
| Trust files corrupted or partially deleted | Verification: invalid; initialization refuses (AC-001A-06g); no automatic repair (I-21 recovery is deferred) |
| Owner forgets passphrase | Revocation and new signing impossible; recovery is out of scope for MVP (U-15); status explains the state |
| Different OS user on the same machine | Sees no authorization (trust files are per owner account) → User |
| Host entry file has two toolkit fragments (e.g. manual copy) | Not repaired silently; reported as a problem for the Maintainer; initialization does not add a third |
| Host entry file is not valid UTF-8 or not writable | Refuse the fragment step with reason; nothing reported as success |
| Agent pseudo-terminal appears interactive | Authorization initialization proceeds only with passphrase entry; first initialization on a pristine machine is therefore not preventable but is detectable: status shows creation time and OS user (accepted residual risk, 10-19-2026) |
| Windows console without a real TTY | Treated as non-interactive → init/revoke refuse |
| Status in a sandbox directory | Reports the sandbox root, not the host project |

## Out of Scope

- Knowledge maintenance (FEATURE-001-B) and Policy resolution (FEATURE-001-C).
- Single-source generation of all three carriers (system-prompt fragment, AGENTS.md, GitHub instructions) from one routing definition, carrier choice and richer difference handling (FEATURE-003-B). This feature writes only the minimal fragment for the resolved environment (CR-001).
- Development sandbox creation (FEATURE-003-C).
- Installing or downloading any scanner; Adapter availability checks beyond "not available yet" (FEATURE-002-B/D/E).
- Uninstall, failure-maintenance recovery and passphrase or key recovery (I-21, U-15, deferred).
- Key rotation, backup and replay-protection details beyond what technical design selects as MVP minimum (U-14, D-22 open).
- Separately signed autonomy policy (FEATURE-004-B).
- Multi-user accounts, enterprise identity, or protection against local-write attackers (U-01, U-13).

## Technical Considerations

- Decide in technical design (U-14, D-22): signature algorithm, canonical form of the signed content, key and file formats, exact trust-file locations per OS (illustrative: `~/.config/ai-secure-code-toolkit/`), how revocation is represented, and replay protection.
- Install record format, location and per-file identity (I-17) are decided in technical design; they must support safe reinstall and status.
- Interactive-terminal detection must behave consistently across macOS, Linux and Windows consoles.
- The verification check must be importable by later features and callable from the CLI; it must not need the private key.
- The toolkit is a standalone product (user decision 10-19-2026): skills named `x-ipe-secure-code-toolkit-{framework,copilot,guard}`, source in `ai-secure-code-toolkit/`, not built through `x-ipe-meta-skill-creator`; the uv namespace is standalone.

## Open Questions

**Tracked open item (CR-002):** Windows verification of AC-001A-10a (Known Folder trust path, console interactivity, ACL/CRLF behaviour) is deferred to a later phase; acceptance verified macOS and Linux only.

**Tracked open items from closing review (TASK-008, 10-19-2026, user decision):**
- Initialization refuses symbolic links on any written path, including links that stay inside the project (e.g. `CLAUDE.md -> AGENTS.md`); support for in-project links is a candidate follow-up (e.g. with FEATURE-003-B). Behaviour is documented in the Framework environments reference.
- When writing the install record fails, the failure result does not list layout folders created earlier in the same run (failure is still reported; nothing is misreported as success).

Otherwise none material. Decisions taken in this refinement (10-18-2026, interact-with-human):

| Question | Decision |
|---|---|
| Install method (v1.0; superseded by CR-001 below) | uv-managed toolkit CLI install with explicit `--project` root copying skills to `<root>/.github/skills/` and creating the empty layout |
| Preventing agent self-authorization | Interactive terminal plus owner-set passphrase protecting the signing private key, stored outside the project |
| Re-install behaviour | Idempotent safe update; locally edited toolkit files reported, replaced only on explicit choice; data never touched |
| Supported OS in MVP | macOS, Linux and Windows |
| Meaning of "install" (CR-001, 10-19-2026) | Project initialization: place pre-generated skills by environment, create folder structure, write host entry fragment; no package install |
| Environment selection (CR-001) | Passed explicitly by the calling agent (`--env`); no auto-detection (user clarification 10-19-2026, replacing an earlier auto-detect choice in the same session) |
| Who writes host entries (CR-001) | This feature writes the minimal fragment with idempotency; FEATURE-003-B keeps single-source generation of all carriers and difference handling |
| Command names (CR-001) | Project: `secure-code init`; owner authorization: `secure-code auth init` / `auth revoke`; status: `secure-code status` |

Technical-design items listed above (U-14, D-22, I-17) are design choices, not open requirements.

## Acceptance Traceability

| Source Requirement / FR / NFR | User Story | AC ID | Mockup Element / Status | Primary Validation | Coverage / CR Decision |
| --- | --- | --- | --- | --- | --- |
| O-09, K-29, S-04; FR-001A-1 | US-01 | AC-001A-04a, 04b, 04c | N/A | Integration (CLI + temp project) | covered |
| O-01…O-06; FR-001A-7 | US-01 | AC-001A-04d | N/A | Unit (skill-definition content check) | covered |
| NFR-01 (EPIC AC-34); NFR-001A-6 | US-07 | AC-001A-04e | N/A | Integration | covered |
| User decision (reinstall); I-12…I-16 principle; FR-001A-2 | US-02 | AC-001A-05a…d | N/A | Integration | covered |
| U-09, I-20, U-10, U-15; FR-001A-3; NFR-001A-1/2 | US-03 | AC-001A-06a…g | N/A | Integration (pseudo-terminal and non-terminal runs) | covered |
| U-07, U-08, U-10, U-11, U-12, U-03, U-05; FR-001A-4 | US-04 | AC-001A-07a…f | N/A | Unit | covered |
| U-12; FR-001A-5 | US-05 | AC-001A-08a…d | N/A | Integration | covered |
| O-10, X-11, X-12, K-30; FR-001A-6 (EPIC AC-03) | US-06 | AC-001A-09a…e | N/A | Integration | covered |
| EPIC AC-27; NFR-001A-1 | US-03, US-04 | AC-001A-06e, 10b | N/A | Integration | covered |
| FR-001A-8 (CR-001) | US-01 | AC-001A-04f, 04g | N/A | Integration | covered |
| FR-001A-9; I-12…I-14 (CR-001) | US-08 | AC-001A-04h, 04i, 09a | N/A | Integration | covered |
| NFR-001A-4 (user decision: all OS) | US-07 | AC-001A-10a | N/A | Integration on each OS | covered |
| U-13 honesty | US-04 | (documentation check in NFR-001A-3) | N/A | Unit (doc/status text check) | covered by NFR |
| U-14, D-22, I-17 | — | — | N/A | — | open design details; not requirements |
| I-21, U-15 recovery | — | — | N/A | — | deferred (out of scope) |

EPIC-001 acceptance mapping: AC-03 → AC-001A-09a/09e; AC-27 → AC-001A-07a/07b/07c, 06e, 10b; AC-34 → AC-001A-04e. Breakdown-reserved IDs (stable, kept as parent criteria): AC-001A-01 (signed init, re-check before maintenance) → AC-001A-06a, 07e; AC-001A-02 (altered / non-trusted signature rejected) → AC-001A-07b; AC-001A-03 (empty stores, skill responsibilities) → AC-001A-04a, 04d.

## Context and Verification Evidence

- CR-001 (10-19-2026): v1.0 human confirmation covered v1.0 only; v1.1 changes were decided explicitly by the user in TASK-005 and are re-presented for confirmation with the technical design. No downstream evidence existed to invalidate.

- Independent review (rubber-duck, 10-18-2026): 2 High + 2 Medium findings fixed — first initialization only from pristine state and partial state refused (AC-001A-06a, 06g); post-revocation re-authorization requires the existing passphrase (06f); revocation durable against restored grants (08d); no private-key access during verification under instrumentation (07c) and no model credentials in outputs (10b); per-tool next steps (09a); standalone scenario extended to verification and skill entry points (04e).

- Sources: `x-ipe-docs/requirements/requirement-details.md` (EPIC-001 + breakdown, FEATURE-001-A details), inventory v2 rows O-01…O-10, U-01…U-15, X-11, X-12, K-29, K-30, I-20, I-21, S-04, D-22 and §3 layout. Hashes recorded in the TASK-004 completion evidence.
- Board: FEATURE-001-A, EPIC-001, v1.0, status Planned, no dependencies (queried 10-18-2026).
- Mockups: none (bounded discovery: Epic mockups folder empty; idea folder has no mockups).
- Execution mode: free-mode; no application workflow write.

| AC ID | Validation Evidence | Delivery State | Outcome State |
| --- | --- | --- | --- |
| AC-001A-04a…10b | Planned per Test Type above; no tests exist yet | planned | not measured |
