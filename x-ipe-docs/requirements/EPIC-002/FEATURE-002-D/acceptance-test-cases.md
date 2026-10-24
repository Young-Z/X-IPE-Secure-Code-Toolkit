# Acceptance Test Cases

> Feature: FEATURE-002-D — Trivy Adapter (EPIC-002)
> **Current status (2026-10-24 B17 run, see the section "Resumed Run 2026-10-24 (B9, B10, B17)" at the end; it supersedes the results below for the frozen revision `44837bb0…`):** all **46 of 46 ACs pass** on Linux arm64 at the frozen toolkit revision — the live branch of AC-002D-02b/02c now **executed against the real `mirror.gcr.io` through the adapter (TC-L-01 Pass, real-host DNS/SNI/IP observation)**; Linux x86-64 is a human-accepted unverified limit (B10, TC-X-01 not executed); the real-binary gate file TC-G-01 is **not executed — human-scoped (B17 = A, apt not authorized)**; its assertions are partially covered by executed real-binary evidence (check-by-check gate map, independent evidence review PASS-WITH-NITS, DAO-006). TC tally 25/29 = 86.2 % on the same 29-case denominator. Stakeholder outcome not measured. The closing evidence holds for toolkit revision `f18423e`. Status transition is the owner's decision.
> Previous status (2026-10-23 rerun, kept for history): **Acceptance partial — B9 and B10 not executed; delivery NOT Completed.** At the fixed revision (Bug Fix TASK-059), 44 of 46 ACs pass with current black-box evidence (real Trivy v0.76.1 binary, real CLI, offline Linux arm64 container; macOS host for the Linux-only refusal). F-1 (AC-002D-03d) and F-2 (AC-002D-05b) from TASK-058 are fixed and verified with the real binary. **AC-002D-02b and 02c pass only against a loopback registry**; their live branch (provisioning from the real `mirror.gcr.io` / `ghcr.io` with real-host observation) and the mandatory real-binary gate file are **not executed (B9)**. The adapter on **Linux x86-64 is not executed (B10)**.
> Revision: toolkit file list `2fc16db8…` (181 files; identical at the start and end of the rerun) · specification `229cc76e…` · design `cb2cd1cf…` · runner `66b42dce…` (SHA-256 prefixes; full values in Relevant Inputs).
> History: acceptance **TASK-058** (2026-10-23, toolkit `8bf12b50…`: 42 Pass, 2 Fail F-1/F-2, 2 loopback-only) → DAO-001 of `x-ipe-docs/dao/26-10-23/decisions_made_feature_acceptance_test.md` → **Bug Fix TASK-059** ([bug-report-TASK-059.md](bug-report-TASK-059.md): `CONFIG_TYPES` = the 9 real v0.76.1 types incl. `ansible`; exact, version-pinned, fail-closed WARN allow-list for the two observed benign messages) → **full rerun** of this acceptance (all black-box cases, regressions, Framework suite) at the fixed revision, under the same DAO-002 rules. TASK-058's failing container evidence is kept as [evidence-container-linux-run1-TASK058-FAIL.jsonl](acceptance/evidence-container-linux-run1-TASK058-FAIL.jsonl).
> Task: TASK-058 rerun, owner Sage, free-mode, interaction mode `dao-represent-human-to-interact` (owner relays). Binding rules: DAO-002 in `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md`. Rerun executed 2026-10-23 (UTC 2026-10-22 22:22–23:17).

## Overview

| Attribute | Value |
| --- | --- |
| Feature / Scope | FEATURE-002-D, implemented in TASK-057, fixed in Bug Fix TASK-059 (design Implementation Evidence, section "Bug Fix TASK-059") |
| Specification / Source | [specification.md](specification.md): 46 ACs AC-002D-01a…08c (45 Integration, 01f Unit); FR-002D-1…10, NFR-002D-1…5, BR-01…13, US-01…09. Parent: [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) EPIC-001 G-02/G-04/G-05, FR-16, FR-18, FR-20, AC-24 |
| Design / Implementation | [technical-design.md](technical-design.md) Part 1 and Part 2 and Implementation Evidence (TASK-057, Bug Fix TASK-059). Product: Framework `adapters/trivy*.py`, `adapters/{__init__,digests,registry_store,process}.py`, `guard/{toolrun,toolreq,toolctl,report,engine}.py`, `status.py`, `tools_service.py`, `cli.py`; Guard `SKILL.md` step 5b, `references/guard-records.md`; Framework `references/cli-contract.md` |
| Tool-level validation | [tool-validation/README.md](tool-validation/README.md), [validate.py](tool-validation/validate.py), [results-linux-aarch64.jsonl](tool-validation/results-linux-aarch64.jsonl); acceptance-time tool-level records in [acceptance/tool-level/](acceptance/tool-level/) |
| Target URL | N/A: CLI, library and skill scope (no UI, no browser needed) |
| Config / Capability | `stages.validation.acceptance_test` in `x-ipe-docs/config/tools.json` (`6df39210…`) enables `x-ipe-tool-implementation-python` (`true`), used as the Python test-runner capability. The black-box runner [acceptance/blackbox.py](acceptance/blackbox.py) calls the real CLI only through `uvx --from <framework>/scripts secure-code …` and never imports toolkit code. Chrome DevTools: not applicable (no UI) |
| Planned Cases | **Denominator: 29 logical TCs** (same for TASK-058 and the rerun; TC-X-01 for B10 added at the rerun and back-counted): black-box integration TC-D-00…TC-D-18 (19, container), TC-H-01 (host), structured package inspection TC-D-19 (container + host), Framework unit/integration TC-U-01, real-binary gate TC-G-01, live provisioning TC-L-01, Linux x86-64 adapter TC-X-01, regressions TC-R-01…04. A logical TC passes only if every one of its environment executions passes. Tool-level fact-finding FF-01…FF-07 (DAO-002) is reported separately and not counted |

### Environment

- **Container (Maintainer path, real binary):** image `fat-uv-git:py312` (`8cbe78fe…`, Python 3.12.12, Linux aarch64, uv 0.9.30), Docker 29.7.2 (Docker Desktop on macOS 26.6.2 arm64).
  - **Offline:** attached only to the Docker `--internal` network `fat2d-int`, whose single peer is the loopback registry container `fat2d-reg` (`python:3.12-slim` `a6e34c59…`, [harness/registry.py](acceptance/harness/registry.py)). No route out: the positive control `getent ahostsv4 check.trivy.dev` fails and is captured as a DNS frame (TC-D-00).
  - `UV_OFFLINE=1`, disposable HOME (trust store), `FAT_ISOLATED=1`, non-ASCII project folders (`proj ü`, …) in the disposable volume `fat2d-work`. Trivy runs with the toolkit's minimal `PATH=/bin:/usr/bin`; this image has no Python there (Python is in `/usr/local/bin`), so the real pip license WARN occurs (asserted in TC-D-07).
  - Read-only mounts: toolkit, runner, FEATURE-002-D docs, MVP samples (`study-case/secure-coding-guidance/playground` → `/samples`), the validation's misconfiguration fixtures, volumes `fat2d-bin` (Trivy archives and binaries) and `fat2d-img` (image archives).
  - uv cache volume `fat2d-uv-cache`, recreated for the rerun: seeded with the third-party wheels of `fat-uv-cache-001d`, every toolkit entry removed, the toolkit built offline from the fixed source; the built `x_ipe_secure_code` tree equals the source file by file (`trivy.py` `b06073d8…`, `trivy_log.py` `44ff4d1e…`).
- **Loopback registry (DAO-002 option "loopback registry that needs no new download"):** serves OCI artifacts rebuilt from the components fetched by the tool-level validation method. It answers TLS for `mirror.gcr.io`, `ghcr.io` and `pkg-containers.githubusercontent.com` with a certificate from a new disposable test CA (3-day validity, generated in the session folder, deleted afterwards). The CA was appended only to the disposable runner container's `/etc/ssl/certs/ca-certificates.crt`; the three names are mapped with `--add-host`. `ghcr.io` blob requests are redirected (307) to `pkg-containers.githubusercontent.com`. It logs SNI and requests and supports refusal and throttling.
- **Observation (harness, inside the runner container):** an `AF_PACKET` sniffer (every frame sent on any interface, incl. loopback DNS), a `/proc` watcher (1 ms; argv, environment, working folder, `--cache-dir` entries of every `trivy` process), and the registry log. "Zero outbound attempts" = no IP frame of any protocol/port and no registry request in the window (ARP housekeeping reported, never an IP attempt).
- **Host (User path):** macOS 26.6.2 arm64, runner Python 3.13.3, CLI via `uvx` (Python 3.14), uv 0.11.23, `UV_OFFLINE=1`, `UV_REFRESH_PACKAGE=ai-secure-code-toolkit`, `TMPDIR`/`FAT_WORK` in the session folder; never-authorized User.
- **Downloads (DAO-002, tool-level validation only, disposable containers):** for the rerun, the official Trivy v0.76.1 Linux archives were downloaded again (digests re-verified against GitHub release metadata, `checksums.txt` and the toolkit table) and the three components fetched again from `mirror.gcr.io` with the validated argv (not the adapter): [toolval-binaries-r2.jsonl](acceptance/tool-level/toolval-binaries-r2.jsonl), [toolval-components-r2.jsonl](acceptance/tool-level/toolval-components-r2.jsonl). Binaries and components stayed in Docker volumes and were removed at the end.

### Fixtures (disclosed)

- **MVP samples:** WebGoat (copied without `.x-ipe`/`.git`: `pom.xml`, `Dockerfile`, `Dockerfile_desktop`, `src/` 1,198 files) and shanghai-marathon-registration (23 files).
- **Secrets:** a fake AWS key id and a fake GitHub token generated at run time inside the disposable container; never printed or stored outside it.
- **Misconfiguration:** the validation fixtures (`Dockerfile`, `deployment.yaml`, `main.tf`, `docker-compose.yml`), a clean `clean.tf`, 2,000 copies of `deployment.yaml` (≈20 s real scan for timeout, cancel and busy cases), and a **self-authored Ansible playbook** `fixtures/ansible/site.yml` (task `amazon.aws.s3_bucket` with every public-access block disabled; rerun).
- **Dependencies:** `requirements.txt` `six==1.17.0` (clean) and `requests==2.19.0` (vulnerable; rerun), `package-lock.json` (`ms` 2.1.3), `go.mod` (`golang.org/x/text v0.21.0`), **`composer.lock` `guzzlehttp/guzzle` 6.5.0** (rerun; the only probed manifest whose real scan emits the vendor-severity WARN with no other gap, FF-07).
- **Project-supplied Trivy configuration:** `trivy.yaml`, `.trivyignore`, `trivy-secret.yaml` that would suppress findings if loaded.
- **Image archives (no pulls):** `docker save` of the local `redis:6-alpine` and `hello-world:latest`, a `FROM scratch` image with WebGoat's `maven-wrapper.jar`, a `FROM scratch` image with a 600 MB random blob (all Docker ≥ 25 archives), and runner-generated malformed archives (pure OCI, links, devices, FIFO, `..`, absolute, duplicate, dangling `Config`/`Layers`, non-`docker save` manifest, non-tar, gzip, truncated, global pax, sparse 8 GiB + 1 byte).
- **Outdated database:** the loopback registry serves a DB variant whose `metadata.json` says `UpdatedAt 2019-05-01`, `NextUpdate 2019-05-02`.
- **Handoff for the macOS pre-check:** a Linux-registered project with an open, planned verification created at the end of the container run in the session folder.

## Goal / Subgoal Frame

| Goal ID | Parent / Source | Stakeholder | Desired Observable Outcome | Success Evidence | AC Links | Outcome State |
| --- | --- | --- | --- | --- | --- | --- |
| G-02 | Spec G-02; EPIC-001 G-02, FR-16, FR-18, AC-24 | Developer, upstream agent | Dependency, container, configuration and secret risks covered by trustworthy evidence: real output, complete accounting, honest failure, no false pass | TC-D-06…15, 17, 18 | 01a…01f, 03*, 04*, 05*, 06*, 08* | not measured |
| G-05 (enabling) | Spec G-05; EPIC-001 G-05, FR-20, FR-24, A-08, A-09 | Owner, Maintainer, Developer | No download or network use without a purpose grant; only the authentic tool runs; secrets and originals protected | TC-D-00…05, 10, 12, 16, 18; TC-H-01; live branch TC-L-01 and gate TC-G-01 not executed (B9) | 01*, 02*, 04a…04c, 05c | not measured |
| G-04 (supporting) | Spec G-04; FR-16, FR-21 | Developer | Trivy only where cheapest sufficient, within the shared budget | TC-D-03, 05, 06, 15, 18 | 02b, 04d, 04e, 06c, 06d | not measured |

The specification's outcome scenarios were run with the real binary on the real samples: the WebGoat `pom.xml` check yields 36 findings while the 18 packages Trivy could not version offline make it a failed method naming them; the `WebGoat/src` secret check names the 246 files the tool did not report as scanned; a compose file in a misconfiguration check is an unsupported-type gap; without a grant covering the Java DB repository its provisioning is refused and nothing is downloaded; a project without a database fails the vulnerability check while the secret check runs; the fake credential never appears in evidence or reports; a cancelled provisioning keeps the previous database. Real Developers, Maintainers or agents using the adapter: **not measured**.

## Full Acceptance / Evidence Map

All rows: original test type **Integration** retained (AC-002D-01f **Unit**). **Evidence kind:** black-box CLI (the real installed CLI via `uvx`, subprocesses, files, `/proc`, frames) unless stated; structured package inspection for 06d, 07a, 07b; the Framework suite (TC-U-01) is primary only for the Unit AC 01f and otherwise supporting. "Loopback" = provisioning through the real `secure-code tools provision` and the real binary against the loopback registry. Results are at the fixed revision (rerun).

| AC ID | TC / Type | Original Assertions (as checked) | Result |
| --- | --- | --- | --- |
| AC-002D-01a | TC-D-01 integration | Official v0.76.1 linux/arm64 binary registered without any `trivy` process appearing (digest compared before execution); record: path, digest `sha256:b422130e…`, version 0.76.1, `asset` `trivy_0.76.1_Linux-ARM64.tar.gz`, platform `{linux, aarch64, libc: null}`, `platform_validated: true`; explicit re-registration. Linux x86-64: not executed (B10, TC-X-01) | Pass (arm64); x86-64 not executed (B10) |
| AC-002D-01b | TC-D-01 integration | Refused with reason and next step, nothing recorded, not executed: no Maintainer (`NOT_AUTHORIZED`); script printing 0.76.1 (marker never created), modified official binary, release archive (`TOOL_DIGEST_UNKNOWN`); x86-64 binary on arm64 (`TOOL_PLATFORM_MISMATCH`); symlink, missing path, folder, relative path (`TOOL_PATH_INVALID`) | Pass |
| AC-002D-01c | TC-H-01 integration (macOS host) | Registration and provisioning refused `ADAPTER_PLATFORM_UNSUPPORTED` with the exact gap text and next step before anything (marker script never executed; nothing recorded); an otherwise valid run request accepted with run-level gap `ADAPTER_PLATFORM_UNSUPPORTED` and failed `trivy` evidence (`precheck_failed`) per requested check | Pass |
| AC-002D-01d | TC-D-12, TC-D-11 integration | Unregistered → every check `precheck_failed` (`TOOL_NOT_REGISTERED`), nothing executed; registered binary replaced → `TOOL_DIGEST_MISMATCH` for every check, no `trivy` process; a missing component fails only the checks needing it | Pass |
| AC-002D-01e | TC-D-01, 02, 11, 12 integration | Next steps name the Maintainer action (register; provision under a covering `tool_update` grant); nothing downloaded, registered or installed automatically; no "pass" wording for a successful pre-check | Pass |
| AC-002D-01f | TC-U-01 **unit** (primary) + TC-D-01, TC-R-01 | `test_01f_static_build_matches_any_libc_opengrep_exact`, `test_01f_trivy_build_matches_host_of_any_libc`, `test_07b_…`, `test_digest_table_matches_validation_record` passed at the fixed revision ([log](acceptance/evidence-unit-01f-task059.log)); black-box: libc-less entry matched the glibc container; Opengrep exact matching unchanged (002-B registration checks pass). No musl host (gap) | Pass |
| AC-002D-02a | TC-D-02 integration (+ TC-H-01 platform) | After acceptance each refusal recorded one toolkit declaration per requested component (`refused`, `used: false`, missing element), no attempt, no budget, no process, no contact, no cache: no grant, other origin, other purpose, data without `metadata`, scope not covering path/tag, one component uncovered, unknown component, time limit 0/3601, registry `docker.io`, no Maintainer, unregistered binary. Unknown, concluded, cancelled, paused, out-of-time verification → refused, state byte-identical | Pass |
| AC-002D-02b | TC-D-03, 04, 05 integration (loopback); TC-L-01, TC-G-01 | Exactly one repository argument per component (from `/proc`), version check and telemetry off, no project path, minimal environment, private op folder; SNI/Host only `mirror.gcr.io`, only the three exact repositories, frames only to the registry on 443; one allowed `used: true` declaration per operation listing every known host and grant; one `tool_update` attempt charged; refused repository → no fallback. `ghcr.io`: refused without (or with a narrower) blob-host grant naming `pkg-containers.githubusercontent.com`; with both grants executed, both hosts listed and seen (SNI); registry/repository/digest recorded per component; report shows provisioning and the configuration-level limit. **Live branch (real registries, real-host observation): not executed (B9)** | Pass (loopback); live branch not executed (B9) |
| AC-002D-02c | TC-D-03, 05 integration (loopback) | Result fields incl. metadata equal to the installed `metadata.json`; refused repository → `failed`, previous kept; checks bundle exit 0 with embedded fallback → `failed`, previous kept; no previous Java DB → `missing`; throttled download over the limit → `timed_out`, previous kept; toolkit killed mid-download → previous generation still used, leftover swept by the next provisioning. **Real-registry download through the adapter: not executed (B9)** | Pass (loopback); live branch not executed (B9) |
| AC-002D-02d | TC-D-00, 06…11, 13…15 integration | Every scan argv carries the six validated offline flags; every scan window: zero IP frames, zero registry requests, also with `tool_update` grants present; scans ran without any grant | Pass |
| AC-002D-02e | TC-D-11, TC-D-14 integration | Missing DB / bundle / Java DB fail only the checks needing them, naming the component, state and provisioning step; the secret check of the same request runs; corrupted DB (both bolt meta pages zeroed) → the tool's FATAL recorded, failed method, component `unreadable` | Pass |
| AC-002D-02f | TC-D-06, 13, 17, 18 integration | Component metadata and age (= scan time − `UpdatedAt`, checked independently) in evidence; bundle `MajorVersion/Digest/DownloadedAt` and source; no threshold; a 2019 DB used as is (age 2731 d) | Pass |
| AC-002D-02g | TC-D-06, 09, 14, 18 integration | Per-scan `--cache-dir` holds only symlinks to current generations (read in place); re-hash `unchanged`; a same-size edit is detected after the scan, the component becomes `unreadable` "invalid … re-provision" until re-provisioned; report states detection, not prevention | Pass |
| AC-002D-02h | TC-D-16 integration (+ TC-H-01) | Remove one / all: bytes freed, status `missing`, nothing else changed or executed; refused without Maintainer, for an unknown component, during a scan and during a provisioning (`TRIVY_CACHE_BUSY`) | Pass |
| AC-002D-03a | TC-D-10 integration | `TOOL_REQUEST_INVALID`, nothing recorded, not executed: unknown fields, free-form `args`, severity, ignore file, VEX, skip pattern, `license`, empty/string scanners, unknown mode, missing targets, shell text, duplicate checks, wrong adapter spelling | Pass |
| AC-002D-03b | TC-D-10 integration | Targets not covering the object, a context file, an unrelated path → refused, nothing recorded; targets inside folder targets accepted. Deleted/suggested paths: Framework suite | Pass |
| AC-002D-03c | TC-D-09, TC-D-10 integration | `image_archive` with `secret`/`misconfig`, folder, image names, digest, socket, URL, `oci-archive:` → refused; pure OCI → `IMAGE_ARCHIVE_INVALID`; valid archives scanned as `image --input <staged snapshot> --cache-backend memory`, vuln only; no contact | Pass |
| AC-002D-03d | TC-D-08, TC-D-10, TC-D-06 integration | **All 9 types of the verified version** (`ansible, azure-arm, cloudformation, dockerfile, helm, kubernetes, terraform, terraformplan-json, terraformplan-snapshot`) accepted as override types and passed to the real binary as `--file-patterns <type>:<path>` (each used by the tool as that type; a mismatching Dockerfile content gives that type's parser error, recorded as a failed method). **Actual `ansible` override run offline (TC-D-08):** `fixtures/ansible/site.yml` with `config_types` `ansible` → argv `--file-patterns ansible:fixtures/ansible/site\.yml`, file analysed (0 passed / 6 failed), findings `AWS-0086, 0087, 0089, 0090, 0091, 0093`, method `ok`, zero outbound attempts. `dockerfile` override makes `Dockerfile_desktop` analysed. Refused: path outside the object, no `misconfig` scanner, `compose`/`docker-compose`/`yaml`, duplicate. (TASK-058: Fail F-1, `ansible` refused) | Pass |
| AC-002D-03e | TC-D-10, TC-D-15 integration | Missing, 0, −5, 1801, `"600"`, 10.5, `true` → refused; 600 s on a 1-minute budget → `time_limit` ≤ 60, `time_limit_capped: true` | Pass |
| AC-002D-03f | TC-D-10 integration | Not planned, not selected, no plan, concluded → refused with reason and next step, state byte-identical, no attempt, not executed | Pass |
| AC-002D-03g | TC-D-10, 09, 15 integration | Sparse 8 GiB + 1 byte → `IMAGE_ARCHIVE_TOO_LARGE` naming 8589934593 bytes and 8 GiB; 600 MB `docker save` archive staged and scanned; 600 MB non-archive folder still `STAGE_TOO_LARGE` | Pass |
| AC-002D-03h | TC-D-10, TC-D-09 integration | `IMAGE_ARCHIVE_INVALID` naming each of 14 violations; Docker ≥ 25 archives accepted with structure counts | Pass |
| AC-002D-03i | TC-D-10, TC-D-07 integration | `.tar` inside a folder target refused in `image_archive`; in `filesystem` mode an ordinary file, no `image` process | Pass |
| AC-002D-04a | TC-D-06…09 integration | Staged snapshot executed; disposable per-check tree, cache, HOME, TMPDIR and empty cwd under `adapter-stage/trivy/stage-*`; environment exactly HOME/XDG_CONFIG_HOME/XDG_CACHE_HOME/TMPDIR/PATH/LANG/TZ; empty `--config`, `--ignorefile`, `--secret-config`; project Trivy configuration not loaded; staging removed; originals byte-identical | Pass |
| AC-002D-04b | TC-D-12 integration | Target changed after open → not scanned, failed method naming the change | Pass |
| AC-002D-04c | TC-D-13 integration | 2019 DB used offline (zero frames), findings, age reported | Pass |
| AC-002D-04d | TC-D-15 integration | 5 s limit on a ≈20 s real scan → `timed_out`, failed, no process left, staging removed. Tool-internal deadline branch: Framework fake (supporting) | Pass |
| AC-002D-04e | TC-D-15, TC-D-05 integration | Cancel during a real scan and during a throttled provisioning: termination confirmed, `RUN_CANCELLED`, no new evidence or provisioning entry, previous component kept, staging removed | Pass |
| AC-002D-05a | TC-D-06…09 integration | Per check × scanner accounting only from the tool's statements (manifests with packages; config files with pass/fail counts; secret streaming lines — WebGoat/src 952 of 1,198, marathon 8 of 23; images with OS/package types or "OS not detected"); clean `.tf` → named gap (known limitation, FF-02) | Pass |
| AC-002D-05b | TC-D-07 integration | Fully analysed objects with no tool error → `ok`: secret fixture, Dockerfile, K8s/Terraform set, npm lockfile, **pip `requirements.txt` (clean) with the real WARN "[pip] Unable to find python `site-packages` directory. License detection is skipped." for both `vuln` and `secret`**, **vulnerable pip manifest with the same WARN (findings recorded)**, **`composer.lock` with the real WARN "Using severities from other vendors for some vulnerabilities…" and findings** — each `completed`, method `ok`, the WARN kept in the process messages. Gaps still fail only their check. (TASK-058: Fail F-2) | Pass |
| AC-002D-05c | TC-D-07, TC-D-18 integration | Secret findings keep rule, category, severity, location/line and masked length only; no `Match`/`Code`/`Offset`; byte search of private data, run folder, evidence, findings, reports and temp folder for both fake values: none; context line not stored | Pass |
| AC-002D-05d | TC-D-06, 07, 09 integration | Findings `source: trivy`, scanner, tool id, project-relative location, package fields, tool severity and fixed map, CWE, title, attributed to the producing check/Policy; count equals the vulnerabilities in the retained output (36/36 on WebGoat) | Pass |
| AC-002D-05e | TC-D-06 integration | One `runtime` evidence per check referring to the shared masked output; run entry provenance complete; manifest digest verified | Pass |
| AC-002D-05f | TC-D-06, 07, 10, 14 integration | Fail-closed at the fixed revision: an unlisted real WARN ("[pom] Dependency version cannot be determined…") still yields `completed_with_errors` and a named gap; real parser ERRORs and FATALs (override type mismatch, invalid DB) recorded with masked messages as failed methods; findings in partial output kept. Unlisted WARN variants, ERROR level and a version mismatch also stay degrading in the Framework tests `test_trivy_bugfix_task059.py` (fake, supporting). Empty/unparseable output: Framework fake | Pass |
| AC-002D-05g | TC-D-07, TC-D-18 integration | Clean runs → `ok`, no findings; verdict `cannot_confirm_pass` without a ledger; a ledger `met` on failed `trivy` evidence is not counted | Pass |
| AC-002D-05h | TC-D-08 integration | Compose in a misconfig check → `unsupported` gap with next step, failed; other files' findings kept; in a secret check analysed as text | Pass |
| AC-002D-05i | TC-D-11, TC-D-05 integration | Missing checks bundle → misconfig failed naming it; bundle download falling back to embedded checks → failed provisioning. Fallback line during a scan: Framework fake | Pass |
| AC-002D-06a | TC-D-06, TC-D-10 integration | Runs only for planned, selected `trivy` runtime methods in an open planned verification; plan refuses a non-runtime `trivy` method | Pass |
| AC-002D-06b | TC-D-18 integration | Agent cannot record `trivy` evidence or add/rewrite a `trivy` finding; unreviewed verdict-affecting findings → verdict not Pass | Pass |
| AC-002D-06c | TC-D-06, TC-D-18 integration | Method choice in plan and report with reason | Pass |
| AC-002D-06d | TC-D-19 structured (container + host; original type Integration) | Guard `SKILL.md` step 5b phrases (never by default, scope, object listing, compose, DB-age judgement, grants for every known host, Maintainer provisioning, never proceed without); `guard-records.md` documents request, archive rules, override types (now 9) and per-host grants | Pass |
| AC-002D-07a | TC-D-19 structured + tool-level re-check | Validation README complete and dated before implementation; driver hash equal; archive and binary digests re-verified at the rerun ([toolval-binaries-r2.jsonl](acceptance/tool-level/toolval-binaries-r2.jsonl)) | Pass |
| AC-002D-07b | TC-D-19 structured | `digests.TRIVY`: exactly the arm64 (validated) and x86-64 (not validated) entries, libc `None`, official assets; archive digests equal; AC-28 pending in FEATURE-003-C | Pass |
| AC-002D-08a | TC-D-17, 01, 03, 12, TC-H-01 integration | Status: provided, registration, digest pre-check (failing reason + register step), validation state, execution support (macOS: not supported), per-component state/metadata/age/source, next steps; nothing executed or sent | Pass |
| AC-002D-08b | TC-D-17, TC-H-01 integration | Strix "adapter not provided by this toolkit version"; the superseded Trivy part of AC-002B-06b re-checked per AC-002D-08a in TC-D-17 (Trivy `provided`, Strix still not provided) | Pass |
| AC-002D-08c | TC-D-17 integration | `disk_bytes` per component equal to the independently summed `st_blocks × 512`; total reported | Pass |

**AC totals (46) at the fixed revision:** Pass 44 (01a with the x86-64 path not executed, B10) · Pass on loopback with the live branch not executed (B9) 2 (02b, 02c) · Fail 0. TASK-058 (before the fix): 42 Pass · 2 loopback · 2 Fail (03d, 05b).

## Typed Test Cases and Execution Summary

| TC | ACs | Type | Priority | Command / Method | Result (rerun) |
| --- | --- | --- | --- | --- | --- |
| TC-D-00 Observation controls | 02d | integration | P0 | container runner | Pass (5) |
| TC-D-01 Registration with the real binary | 01a, 01b, 01e, 01f, 08a | integration | P0 | container runner | Pass (15) |
| TC-D-02 Provisioning refusals | 02a, 01e | integration | P0 | container runner | Pass (18) |
| TC-D-03 Provisioning `mirror.gcr.io` (loopback) | 02b, 02c, 08a | integration | P0 | container runner | Pass (15) |
| TC-D-04 `ghcr.io` known hosts (loopback) | 02b | integration | P0 | container runner | Pass (6) |
| TC-D-05 Provisioning failure, timeout, kill, cancel | 02b, 02c, 04e | integration | P0 | container runner | Pass (12) |
| TC-D-06 Scans of the MVP samples | 02d, 02f, 02g, 03d, 04a, 05a, 05b, 05d, 05e, 05f, 06a, 06c | integration | P0 | container runner | Pass (74) |
| TC-D-07 Secrets, clean runs, real benign WARNs, unlisted WARN, project config, `.tar` in folder | 03i, 04a, 05b, 05c, 05d, 05f, 05g | integration | P0 | container runner | Pass (87) — TASK-058: Fail (F-2) |
| TC-D-08 Misconfiguration fixtures, compose, clean `.tf`, actual `ansible` override | 03d, 05a, 05h, 05i | integration | P0 | container runner | Pass (46) |
| TC-D-09 Image archives | 02g, 03c, 03g, 03h, 04a, 05a | integration | P0 | container runner | Pass (41) |
| TC-D-10 Request refusals and the 9 override types on the real binary | 03a…03i, 06a | integration | P0 | container runner | Pass (66) — TASK-058: Fail (F-1) |
| TC-D-11 Missing components | 01d, 01e, 02e, 05i | integration | P0 | container runner | Pass (7) |
| TC-D-12 Pre-check failures, changed target | 01d, 01e, 04b, 08a | integration | P0 | container runner | Pass (6) |
| TC-D-13 Outdated database | 02f, 04c | integration | P1 | container runner | Pass (3) |
| TC-D-14 Re-hash invalidation, tool-reported invalid DB | 02e, 02g | integration | P0 | container runner | Pass (8) |
| TC-D-15 Timeout, scan cancel, staging limit, budget cap | 03e, 03g, 04d, 04e | integration | P0 | container runner | Pass (5) |
| TC-D-16 Component removal | 02h | integration | P1 | container runner | Pass (7) |
| TC-D-17 Status (incl. AC-002B-06b supersession re-check) | 02f, 08a, 08b, 08c | integration | P1 | container runner | Pass (7) |
| TC-D-18 Report, verdict rules, masking end to end | 02b, 02f, 02g, 05c, 05g, 06b, 06c | integration | P0 | container runner | Pass (11) |
| TC-D-19 Guard skill, guard-records, validation record, digest table | 06d, 07a, 07b | structured package inspection (original type Integration) | P1 | container + host runner | Pass (6 + 6) |
| TC-H-01 macOS Linux-only refusal and status | 01c, 08a, 08b | integration | P0 | host runner | Pass (6) |
| TC-U-01 Framework suite (supporting; primary for 01f) | 01f + design-level | unit / integration | P1 | `uv run --offline python -m pytest` (macOS, Python 3.14.6) | Pass: 1796 passed, 3 skipped, 23 deselected; targeted 01f + TASK-059 tests 24 passed |
| TC-G-01 Mandatory real-binary gate `tests/guard/test_trivy_real.py --require-real-trivy` | 02b, 02d, 03d, 05* (gate) | integration | P0 | — | **Not executed (B9)** |
| TC-L-01 Live provisioning from the real registries with real-host observation | 02b, 02c (live branch) | integration | P0 | — | **Not executed (B9)** |
| TC-X-01 Adapter on Linux x86-64 | 01a, NFR-002D-5 | integration | P1 | — | **Not executed (B10)** |
| TC-R-01 FEATURE-002-B regression | 002-B (01f supporting) | integration | P0 | historical 002-B runner, unchanged, container (real Opengrep `og-validate`) + host | **Partial**: 9/10 + 2/2; the failing check "06b trivy/strix not provided" is **superseded per AC-002D-08a (not counted as pass)**; Trivy provided and Strix not provided are asserted in TC-D-17 |
| TC-R-02 FEATURE-002-C regression | 002-C | integration | P0 | unchanged runner, container + host | Pass 9/9 + 2/2 (byte-identical to original evidence) |
| TC-R-03 FEATURE-002-A regression | 002-A | integration | P0 | unchanged runner, container + host | Pass 26/26 + 2/2 (byte-identical) |
| TC-R-04 FEATURE-003-A regression | 003-A | integration | P0 | unchanged runner, container + host | Pass 11/11 + 2/2 (byte-identical) |

Commands (from the workspace root; `A=x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance`; scripts in [acceptance/harness/](acceptance/harness/)):
- **Container:** `harness/run-container.sh OUT` (offline `--network fat2d-int` with `--add-host` for the three registry names, `FAT_ISOLATED=1`, `UV_OFFLINE=1`, `fat2d-uv-cache`, read-only toolkit/runner/samples/volumes, `fat-uv-git:py312 python3 /fat/blackbox.py container`).
- **Host:** `harness/run-host.sh OUT` (`UV_OFFLINE=1 UV_REFRESH_PACKAGE=ai-secure-code-toolkit python3 blackbox.py host`).
- **Unit/integration:** `cd ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework/scripts && PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 TMPDIR=<session>/tmp-suite uv run --offline python -m pytest -p no:cacheprovider -o addopts="" -q --basetemp=<session>/bt-suite` (`uv sync --offline --dry-run`: "Would make no changes"); targeted: `-v -k "01f or test_07b or test_digest_table_matches_validation_record or task059" tests/adapters tests/guard`.
- **Regressions:** `harness/run-regressions.sh OUT` (each unchanged runner offline in its original image with `fat2d-uv-cache`, `og-validate`, samples `m`/`w`, then on the host).

## Real-binary Gate (TC-G-01), Live Provisioning (TC-L-01) and x86-64 (TC-X-01)

- **TC-G-01 — not executed (B9).** The gate provisions live from the real registries, which DAO-002 parks as human blocker B9. Its environment prerequisites, recorded under B9 for when B9 is granted: a Docker CLI available to the gate's pytest process (no Linux Docker CLI exists locally; running pytest inside a container fails with "prerequisite missing: docker CLI"), the official binary on a path that the pytest process and the Docker daemon both see (DAO-002 keeps binaries in Docker volumes only), `iptables` in `SECURE_CODE_TRIVY_IMAGE` for the observer (absent from every local image; installing it is a download outside the authorization), `SECURE_CODE_TRIVY_DOWNLOAD_AUTHORIZED=1` (the B9 grant), samples and image archives. TASK-058's two literal invocations stopped at these prerequisites with 23/23 errors ([container](acceptance/gate-real-trivy-container-linux.log), [host](acceptance/gate-real-trivy-host-macos.log)); they are records of the prerequisites, not executions. Never counted as passed.
- **Gate-equivalent offline evidence (not the gate file):** controls TC-D-00; registration TC-D-01; provisioning per registry and component TC-D-03/04 (loopback; ghcr `java_db` not run); refused repository TC-D-05 (loopback); the nine scans TC-D-06/07/09 (36 pom findings and 18 skipped packages, as in the validation; `Dockerfile_desktop` override `ok`; hello-world "OS not detected"); offline and timeouts TC-D-00/06/15; secret never stored TC-D-18; config types equal the help list FF-01 + TC-D-10 (now **Pass**).
- **TC-L-01 — not executed (B9):** no real-registry contact through the adapter.
- **TC-X-01 — not executed (B10).** The adapter on Linux x86-64 needs a native x86-64 Linux environment (or the human's acceptance of emulated evidence). The optional emulated subset was **not run** at the rerun: the amd64 image used in TASK-058 (`fat2d-trivy-amd64:local`) had been removed and no amd64 image is local; building or pulling one was not undertaken. TASK-058 FF-04 (tool level, emulated, not the adapter) stays the only x86-64 observation.

## Tool-level Fact-finding (DAO-002; real binary, offline, never the adapter)

| ID | Question | Method | Result |
| --- | --- | --- | --- |
| FF-01 (TASK-058) | Misconfiguration types of v0.76.1 | `trivy fs|config|image --help` | 9 types incl. `ansible` → F-1; fixed in TASK-059 ([ff-help-tf.jsonl](acceptance/tool-level/ff-help-tf.jsonl)) |
| FF-02 (TASK-058) | Clean `.tf` results | `fs --scanners misconfig` on single-file folders | A `.tf` without failures has no per-file result (only module target `.`). **Known limitation, recorded without change; candidate for a future human-decided CR**: a clean Terraform file is always a named gap and a failed misconfiguration method (TC-D-08 C12) |
| FF-03 (TASK-058) | Cold-cache re-hash time | VM page-cache drop, SHA-256 1 MiB reads | ≈0.5 s per DB, CPU-bound ≈3 GB/s; proxy (host cache of the VM disk not controllable) ([ff-rehash.txt](acceptance/tool-level/ff-rehash.txt)) |
| FF-04 (TASK-058) | Linux x86-64 | x86-64 binary under Docker Desktop emulation | Tool runs **emulated**; adapter on x86-64 not executed (B10) |
| FF-05 (TASK-058, rerun) | Digests and components | Re-download in a disposable container | Archives/checksums/binaries equal the official values again at the rerun; DB `UpdatedAt` 2026-10-22T19:14:47Z, bundle digest `b591e919…` |
| FF-06 (rerun, owner steer) | Does real v0.76.1 accept each `CONFIG_TYPES` name as the type in `--file-patterns <type>:<regex>`? | Per type: `fs --scanners misconfig --file-patterns <type>:nomatch\.zzz` (syntax), then a fixture with a non-default name scanned without and with `--file-patterns <type>:<name>` (effect) ([ff06-file-patterns.jsonl](acceptance/tool-level/ff06-file-patterns.jsonl), [harness](acceptance/harness/toolval_ff06_file_patterns.py)) | **Syntax:** all 9 accepted (exit 0, no WARN/ERROR) — but so are `compose` and `bogus`: Trivy does not validate the type, so the toolkit's `CONFIG_TYPES` check is the only guard. **Effect** (default → with pattern): `dockerfile` (`Dockerfile_desktop`), `kubernetes` (`deploy.manifest`), `cloudformation` (`stack.cfn`), `azure-arm` (`arm.tmpl`): not analysed → analysed with failures; `terraformplan-json` (`plan.out`): not analysed → analysed (9 failures) **but reported under the synthetic targets `main.tf` and `.`, not under the file**; `terraform` (`bucket.tfx`): no effect; `ansible` (`site.playbook`): no effect — YAML playbooks are detected without any pattern (`site.yml` analysed with or without it); `helm`, `terraformplan-snapshot`: effect not determined (no chart/plan-snapshot fixture authored). Adapter level (TC-D-10): every type reaches the tool; on a Dockerfile, `terraformplan-json`/`terraformplan-snapshot` FATAL from their own parsers ("terraformplan-json scan error …"), `azure-arm`/`cloudformation`/`kubernetes` log parser ERRORs — all recorded as failed methods, never `ok` |
| FF-07 (rerun) | A real case for each allow-listed WARN without other gaps | Vulnerability scans of 7 manifests with `PATH=/bin:/usr/bin` ([ff07-warn-probe.jsonl](acceptance/tool-level/ff07-warn-probe.jsonl)) | pip manifests always emit the license WARN; only `composer.lock` (guzzle 6.5.0) emitted the vendor-severity WARN with no skipped package (npm, Cargo, Gemfile: no WARN; `go.mod` has a skipped module) → used in TC-D-07 |

**Finding F-3 (from FF-06; reported, not fixed; no AC fails):** `CONFIG_TYPES` names are all accepted by the real tool, but an override does not always make Trivy produce a per-file result for the overridden file: `terraform` (non-`.tf` name) and `ansible` (non-YAML name) have no effect; `terraformplan-json` analyses the plan but attributes results to a synthetic `main.tf`. Under tool-statement accounting the toolkit then records the overridden file as a gap (failed method) — honest, no false pass — but such overrides cannot yield complete evidence. Owner decision (documentation note, guard-records guidance, or a future CR).

## Relevant Inputs and Evidence

| Role | Path | SHA-256 |
| --- | --- | --- |
| source | [requirement-details.md](x-ipe-docs/requirements/requirement-details.md) | `1747efe61b9c5cf1264e357b2e2dd5e1c3b3da0b2acc05f862a84ad2df1ac65f` |
| specification | [specification.md](specification.md) (unchanged) | `229cc76e4ff651a7474da288371fc37865701413be02bfaa776ac7c170f213fe` |
| design | [technical-design.md](technical-design.md) (incl. TASK-057 and Bug Fix TASK-059 evidence) | `cb2cd1cfb60f4e782d14c1d442a5942328b5aca0a509209418204d755e70c65d` |
| bug report | [bug-report-TASK-059.md](bug-report-TASK-059.md) | `0723ef6dd3c1607df4afcc45f4a21c5dc17e0c0be6bd8f4fba852022134fffaf` |
| tool validation | [README](tool-validation/README.md) / [validate.py](tool-validation/validate.py) / [results](tool-validation/results-linux-aarch64.jsonl) | `4857937097c98d58df59d00ce192d2da29b9d92cb1b1343b5e67916d4a8ed11f` / `32017334a1fdcad1c37cc13bb9a5c960d7adc5e85177828967c7ceb7303c23ca` / `00f432845f13bef02a1e55eec0011c78a3c1457643345cc7c3d52ef7dbc182ed` |
| DAO logs | `x-ipe-docs/dao/26-10-23/decisions_made_technical_design.md` (DAO-002) / `decisions_made_feature_acceptance_test.md` (DAO-001) | `172ba1090d6999b2cd225422eacecd8f0a25ce939785e8de8abed018a9c08a4d` / `fd3f55fe9693759a8e193e230bea78ee50c36bad23f27b285b41c72a003609a3` |
| config | `x-ipe-docs/config/tools.json` | `6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d` |
| toolkit file list | `ai-secure-code-toolkit/` — SHA-256 of the sorted `shasum -a 256` list of all 181 files (relative paths, excluding `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage`); identical at the start and end of the rerun; the path/mtime/size listing of `ai-secure-code-toolkit/` and `study-case/` (excluding `.venv`) also identical. TASK-058 value: `8bf12b50…` (180 files); the difference is exactly the TASK-059 change set | `2fc16db8cb05f0b0d5a9bd6e87ce7f0cc13ebea7237cf43b4d90f92b33ec1d74` |
| code (TASK-059) | `adapters/trivy.py` / `trivy_log.py` / `trivy_run.py`; Guard `references/guard-records.md` | `b06073d86f87d321925d8d672d1337cf80b24ddd379510bc075c7965a78d7e09` / `44ff4d1e3fb1077f37999b4fd47f2e88e01871f7fbc2233e7f4c4f7737910b16` / `7b1072c73a9d3f11797b76172fceecc0e3c6697dd3f21c6bd4dc6c6946636192` / `868f2da821fd93e54060ea0c707fe0cd84203c4a332d103f865456cf36f33f85` |
| test (TASK-059) | `tests/guard/test_trivy_bugfix_task059.py` / `tests/adapters/fake_trivy.py` | `2374100f863b221f637498e9cb1de9d2ba721e51381ab22b9d6d43e93b46f7b0` / `1d1f0fcea229fef09f95233c3e57190e91611c24e348b81d1b5062dd620d5cf5` |
| code (unchanged since TASK-058) | `trivy_provision.py` / `trivy_cache.py` / `trivy_account.py` / `trivy_archive.py` / `trivy_fs.py` / `trivy_journal.py` / `trivy_record.py` / `trivy_request.py`; `digests.py` / `registry_store.py` / `process.py`; `guard/toolrun.py` / `report.py`; `status.py` / `cli.py`; Guard `SKILL.md` | `70ededeb…` / `af45f45b…` / `bea0d9d8…` / `abafe8e6…` / `da57c4a3…` / `269c68e4…` / `86023a92…` / `416bf338…`; `4e949cf3…` / `e26a36ac…` / `8890554a…`; `06d1fdd1…` / `ce3cc4e5…`; `1966adeb…` / `f5136106…`; `cdbfc5bc…` |
| test (gate, unchanged) | `tests/guard/test_trivy_real.py` / `tests/support/obs_relay.py` | `a02faa0d…` / `bc7b16c0…` |
| test (runner) | [acceptance/blackbox.py](acceptance/blackbox.py) | `66b42dce8dd0cfb9cdc018555966ba374761c17890e72356ce43103f1d63063a` |
| harness | [registry.py](acceptance/harness/registry.py) / [run-container.sh](acceptance/harness/run-container.sh) / [run-host.sh](acceptance/harness/run-host.sh) / [run-regressions.sh](acceptance/harness/run-regressions.sh) / [toolkit_list.sh](acceptance/harness/toolkit_list.sh) / [toolval_fetch.py](acceptance/harness/toolval_fetch.py) / [toolval_factfinding.py](acceptance/harness/toolval_factfinding.py) / [toolval_ff06_file_patterns.py](acceptance/harness/toolval_ff06_file_patterns.py) / [toolval_ff06_detail.py](acceptance/harness/toolval_ff06_detail.py) / [toolval_ff07_warn_probe.py](acceptance/harness/toolval_ff07_warn_probe.py) | `d1377bf7…` / `0251c6b2…` / `d29d4ab3…` / `c1421bb5…` / `008f67e0…` / `aebb0fa0…` / `c9af800f…` / `a0322518…` / `11536bf6…` / `9947ac47…` |
| test (regression runners, unchanged) | 002-B / 002-C / 002-A / 003-A `acceptance/blackbox.py` | `da3f8859…` / `34756ef9…` / `7dfbd3fe…` / `7a4cd98c…` |
| environment | `fat-uv-git:py312` `8cbe78fe…`; `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` `e5b65587…`; `python:3.12-slim` `a6e34c59…`; Trivy archives `e174dff2…` (ARM64) / `c7cbe313…` (64bit) | — |
| evidence | [evidence-container-linux.jsonl](acceptance/evidence-container-linux.jsonl) (rerun: 20/20, 445 checks) | `152a0dbebb3026568f693ce2596f2273c5423e7ecc4af8ff612477135db88f56` |
| evidence | [evidence-container-linux.stderr](acceptance/evidence-container-linux.stderr) / [evidence-host-macos.stderr](acceptance/evidence-host-macos.stderr) (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| evidence | [evidence-host-macos.jsonl](acceptance/evidence-host-macos.jsonl) (2/2, 12 checks) | `b26ac8147a30f18a402af565febedd06118147a68394600ef19cd2773abf3b58` |
| evidence | [evidence-unit-integration.log](acceptance/evidence-unit-integration.log) (1796 passed, 3 skipped, 23 deselected) / [evidence-unit-01f-task059.log](acceptance/evidence-unit-01f-task059.log) (24 passed) | `8eaf9b79ec4367178eef0754b51bc837c4c161168200c777b54d37832cd8e602` / `eb8170eb68c3262eaeddd6429153fd3b889f7469094c9517df2d33a9336df1f3` |
| evidence (history) | [evidence-container-linux-run1-TASK058-FAIL.jsonl](acceptance/evidence-container-linux-run1-TASK058-FAIL.jsonl) (TASK-058: 18/20) | `6fe87590ed1fe2b85b1bf3091dc0334b1536c7ce2834e2ce0ca0bf5402139db3` |
| evidence (B9 prerequisites record) | [gate-real-trivy-container-linux.log](acceptance/gate-real-trivy-container-linux.log) / [gate-real-trivy-host-macos.log](acceptance/gate-real-trivy-host-macos.log) (TASK-058) | `5e4c2abd…` / `47b650b9…` |
| evidence (tool level, rerun) | [toolval-binaries-r2.jsonl](acceptance/tool-level/toolval-binaries-r2.jsonl) / [toolval-components-r2.jsonl](acceptance/tool-level/toolval-components-r2.jsonl) / [oci-build-r2.jsonl](acceptance/tool-level/oci-build-r2.jsonl) / [ff06-file-patterns.jsonl](acceptance/tool-level/ff06-file-patterns.jsonl) / [ff07-warn-probe.jsonl](acceptance/tool-level/ff07-warn-probe.jsonl) | `7415ab73…` / `ade0d0ff…` / `8c5f24e7…` / `e40aaf5c…` / `bcfac2c3…` |
| evidence (tool level, TASK-058) | `toolval-binaries.jsonl` / `toolval-components.jsonl` / `oci-build.jsonl` / `ff-help-tf.jsonl` / `ff-rehash.txt` / `ff-x86.txt` / `ff-x86-results.jsonl` | `7415ab73…` / `cd8aaa66…` / `67008430…` / `ca18e1cf…` / `9886aa4c…` / `776c3292…` / `8cc6c6df…` |
| regression | [002-B container](acceptance/regression-002B-container-linux.jsonl) (9/10) / [host](acceptance/regression-002B-host-macos.jsonl) (2/2) | `9239513a3e0544e2e53faddb0c693ec45e2cc9e7780edcf11933da7827386e05` / `290c260700e86553d8d3cf8438e8280190e94aa025711e76ffc1a85fbf3a3805` |
| regression | [002-C container](acceptance/regression-002C-container-linux.jsonl) (9/9) / [host](acceptance/regression-002C-host-macos.jsonl) (2/2) | `7a21573db608b8f111f5214673cac526579520af4fa8bed416ca3d5518c4e027` / `b9261d26dfdedd608d6b5d2eaa56e94375a57b3765d1615540da8525ae728db8` |
| regression | [002-A container](acceptance/regression-002A-container-linux.jsonl) (26/26) / [host](acceptance/regression-002A-host-macos.jsonl) (2/2) | `404ada17d57738f443ed3398aa79b9f96bf21cd0a286eb00cc6a7d5e0b87b611` / `b87e492ec1ccacd5328687f24f8c5cb33914ae246429e0fc537ff397e62fd6e2` |
| regression | [003-A container](acceptance/regression-003A-container-linux.jsonl) (11/11) / [host](acceptance/regression-003A-host-macos.jsonl) (2/2) | `4b978585269bdb2e5cf866d4029cc48db002a81440e1fddd8732ec310a4c7a51` / `e2e89141e8ecdcee286d14b0e2af2b3fef6cd02d2f214d9fdfb753992cfb566e` |

Seven of the eight regression logs are byte-identical to the original acceptance evidence of their features; the 002-B container log differs only in TC-B-01's check "06b trivy/strix not provided" and the summary line, and is byte-identical to the TASK-058 regression log (`9239513a…`). All regression stderr files were empty.

## Execution Results

**Execution date / executor:** rerun 2026-10-23 (UTC 22:22–23:17), acceptance worker under owner Sage, after Bug Fix TASK-059. **Environment:** as above.

| Type | Total Planned | Passed | Failed | Blocked | Partial / Not Run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 | 0 | 0 | 0 | 0 |
| backend-api | 0 | 0 | 0 | 0 | 0 |
| integration — black-box CLI (TC-D-00…18 container; TC-H-01 host) | 20 | 20 | 0 | 0 | 0 |
| structured-review — package inspection (TC-D-19; container + host) | 1 | 1 | 0 | 0 | 0 |
| unit / integration — Framework suite (TC-U-01) | 1 | 1 | 0 | 0 | 0 |
| integration — real-binary gate file (TC-G-01) | 1 | 0 | 0 | 0 | 1 not executed (B9) |
| integration — live provisioning (TC-L-01) | 1 | 0 | 0 | 0 | 1 not executed (B9) |
| integration — Linux x86-64 adapter (TC-X-01) | 1 | 0 | 0 | 0 | 1 not executed (B10) |
| integration — black-box regression (TC-R-01…04; container + host) | 4 | 3 | 0 | 0 | 1 partial (TC-R-01, superseded check) |
| **TOTAL (logical TCs)** | **29** | **25** | **0** | **0** | **4** |

**pass_rate = 25 / 29 = 86.2 %** (one denominator: all planned logical TCs incl. not executed and partial). TASK-058 on the same 29-case denominator: 23/29 = 79.3 % (2 failed: TC-D-07, TC-D-10; the gate was then labelled "blocked", now "not executed", both not passed). Diagnostic only: 445 container + 12 host black-box checks; 16 regression case × environment executions. These counts do not measure goal achievement.

**Runner changes for the rerun (no product change, no product assertion relaxed):** added the TASK-059 scope — real pip license WARN for a clean and a vulnerable pip manifest (with a precondition check that Trivy's `PATH` has no Python), a real vendor-severity WARN case (`composer.lock`), the explicit fail-closed check on the real unlisted pom WARN, the actual `ansible` override run on a self-authored playbook, the per-type adapter outcome for all 9 override types, and the AC-002B-06b supersession re-check. Two runner-side defects were found in the rerun's dry/evidence runs and corrected before the final run: `guard extend --attempts 20` was refused because the total extra attempts (3 default + 20) exceed the documented maximum of 20 (now 17), which left later override-type runs with `ATTEMPTS_EXHAUSTED`; and a new per-type check wrongly expected exit 0 when a Dockerfile is forced through the `terraformplan-*` parsers, whose FATAL ("terraformplan-json scan error …") actually proves the type was used — the check now asserts the type is used and the result is never a successful method. The final evidence is one complete run after these corrections (TASK-058's failing run is kept separately).

### Failures / Blockers

- **F-1 (AC-002D-03d) — fixed (Bug Fix TASK-059), verified:** all 9 types accepted; actual `ansible` override analysed the playbook offline with 6 AWS findings, zero outbound attempts (TC-D-08, TC-D-10).
- **F-2 (AC-002D-05b) — fixed (Bug Fix TASK-059), verified:** with the real license WARN (no Python on the minimal `PATH`) and the real vendor-severity WARN, fully analysed checks are `completed`/`ok`; the unlisted real pom WARN still fails (TC-D-07); unlisted variants, ERROR level and version mismatch stay degrading in the Framework tests (fake).
- **F-3 (from FF-06, informational, not fixed):** some override types (`terraform` on non-`.tf` names, `ansible` on non-YAML names, `terraformplan-json`) do not give a per-file result for the overridden file; the toolkit records a gap (no false pass). Owner decision.
- **B9 (human blocker):** live provisioning (TC-L-01; live branch of 02b/02c) and the real-binary gate (TC-G-01) not executed; gate prerequisites recorded above.
- **B10 (human blocker):** adapter on Linux x86-64 (TC-X-01) not executed; no emulated subset run (no local amd64 image).
- **TC-R-01 partial:** the historical 002-B runner (unchanged, not edited) still asserts "trivy/strix not provided"; that check is **superseded per AC-002D-08a** and not counted as passed. Trivy `provided` and Strix still not provided are asserted in TC-D-17 (and TC-H-01). Every other 002-B check passed.

### Gaps and Honest Limits

- **Live registries (B9):** no real `mirror.gcr.io`/`ghcr.io` contact through the adapter; the loopback registry served rebuilt artifacts (same file content, different layer/manifest digests; checks-bundle manifest annotated `org.opencontainers.image.version 2.0.0` so Trivy records `MajorVersion 2`). It proves the toolkit's configuration and records, not the real registries' behaviour.
- **x86-64 (B10):** not claimed; only TASK-058's emulated tool-level run exists.
- **Clean `.tf` (known limitation, CR candidate):** clean Terraform files never yield a successful misconfiguration method (tool gives no per-file result).
- **Other environments:** musl Linux, Windows, and a host whose Python is on `/usr/bin` were not run.
- **Framework-only branches (supporting, fake binary):** tool-internal deadline, empty/unparseable/oversized output, unrecognized log format, embedded-fallback line during a scan, unknown tool version for the known-host list, journal crash points, deleted/suggested-path refusals, staging-identity races, unlisted WARN variants and version mismatch for the allow-list.
- **Observation scope:** the sniffer sees the runner container only; isolation is a property of the test environment, never of the toolkit.
- **Skill AC 06d:** structured text inspection; agent conduct not observed.
- **Independent review of this acceptance evidence:** not performed by the acceptance worker; left to the owner.

### Hygiene

- No write inside `ai-secure-code-toolkit/` or `study-case/`: toolkit file list `2fc16db8…` (181 files) identical at the start and end of the rerun; path/mtime/size listing of both trees (excluding `.venv`) identical (0 diff lines). `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`.
- Scratch, basetemps, test-CA keys, handoff project and logs only under `<session>/files/fat-002d/`; deliverables only in this report and `acceptance/`; no credential-shaped string in any deliverable (regex scan for AWS key id and GitHub token formats: none).
- Downloaded binaries/components only in Docker volumes. Removed at the end: container `fat2d-reg`, network `fat2d-int`, volumes `fat2d-bin`, `fat2d-comp`, `fat2d-oci`, `fat2d-img`, `fat2d-work`, `fat2d-reglog`, `fat2d-uv-cache`, images `fat2d-jar:local`/`fat2d-big:local` (right after `docker save`), and the 5 BuildKit cache entries of these builds (pruned by id; no other cache touched); the test-CA keys and scratch temporary folders deleted. Verified afterwards: no `fat2d` container, network, volume, image or build-cache entry left.
- No board, Git, `.github/skills`, memory, product, product-doc or existing-test change; the historical 002-B, 002-C, 002-A and 003-A runners were run unchanged.

### Engineering Delivery versus Stakeholder Outcome

| Goal | Delivery Evidence / State | Outcome Scenario | Outcome State |
| --- | --- | --- | --- |
| G-02 | 44/46 ACs pass at the fixed revision, 02b/02c loopback-only; acceptance **partial** (B9, B10 not executed) | WebGoat `pom.xml`: findings + named unversioned packages; secret coverage gaps; compose gap; benign WARNs no longer fail complete checks | not measured |
| G-05 | Refusals, offline scans, masking, digest trust, removal pass; live provisioning and gate not executed (B9) | Java DB refused without its grant; no fake credential anywhere | not measured |
| G-04 | Budget charge, cancel, timeout and method choice pass | Cancelled provisioning keeps the previous DB | not measured |

### Refactor / Closing Recommendation and App Gates

Acceptance is **partial**: every executed in-scope assertion passes at the fixed revision, but the live branch of 02b/02c and the real-binary gate (B9) and the x86-64 adapter execution (B10) are not executed. Per DAO-002 and DAO-001 (feature acceptance), FEATURE-002-D must **not** be marked Tested/Completed; it stays parked at the last truthfully reached stage until the human decides B9/B10. No code-refactor need was evidenced (module sizes enforced by `tests/test_module_size.py`, passing). F-3 and the clean-`.tf` limitation are returned to the owner as notes/CR candidates. The two conditional successors (code refactor, feature closing) are returned to the lifecycle owner; closing is blocked by B9/B10.

## Acceptance Evidence Record

```yaml
acceptance_evidence:
  feature_id: "FEATURE-002-D"
  history: ["TASK-058 acceptance (42 Pass, 2 Fail, 2 loopback)", "Bug Fix TASK-059 (F-1, F-2)", "rerun at the fixed revision"]
  inputs:
    - {role: specification, path: "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/specification.md", sha256: "229cc76e4ff651a7474da288371fc37865701413be02bfaa776ac7c170f213fe"}
    - {role: design, path: "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/technical-design.md", sha256: "cb2cd1cfb60f4e782d14c1d442a5942328b5aca0a509209418204d755e70c65d"}
    - {role: bug-report, path: "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/bug-report-TASK-059.md", sha256: "0723ef6dd3c1607df4afcc45f4a21c5dc17e0c0be6bd8f4fba852022134fffaf"}
    - {role: dao, path: "x-ipe-docs/dao/26-10-23/decisions_made_feature_acceptance_test.md", sha256: "fd3f55fe9693759a8e193e230bea78ee50c36bad23f27b285b41c72a003609a3"}
    - {role: config, path: "x-ipe-docs/config/tools.json", sha256: "6df39210e203507a79023cc9c3d4aff4e93456f63f623e9b01c58a091b49e36d"}
    - {role: toolkit-file-list, path: "ai-secure-code-toolkit/ (181 files)", sha256: "2fc16db8cb05f0b0d5a9bd6e87ce7f0cc13ebea7237cf43b4d90f92b33ec1d74"}
    - {role: test, path: "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance/blackbox.py", sha256: "66b42dce8dd0cfb9cdc018555966ba374761c17890e72356ce43103f1d63063a"}
    - {role: evidence, path: "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance/evidence-container-linux.jsonl", sha256: "152a0dbebb3026568f693ce2596f2273c5423e7ecc4af8ff612477135db88f56"}
    - {role: evidence, path: "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance/evidence-host-macos.jsonl", sha256: "b26ac8147a30f18a402af565febedd06118147a68394600ef19cd2773abf3b58"}
    - {role: evidence, path: "x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/acceptance/evidence-unit-integration.log", sha256: "8eaf9b79ec4367178eef0754b51bc837c4c161168200c777b54d37832cd8e602"}
    # all product files, harness, tool-level records, gate prerequisite logs and regression logs: see "Relevant Inputs and Evidence"
  cases:
    - {tc_id: TC-D-00..TC-D-18, test_type: integration, status: "19 Pass", environment: "fat-uv-git:py312, internal network + loopback registry, real Trivy v0.76.1 linux/arm64", evidence_paths: [acceptance/evidence-container-linux.jsonl]}
    - {tc_id: TC-H-01, ac_ids: [AC-002D-01c, AC-002D-08a, AC-002D-08b], test_type: integration, status: Pass, evidence_paths: [acceptance/evidence-host-macos.jsonl]}
    - {tc_id: TC-D-19, ac_ids: [AC-002D-06d, AC-002D-07a, AC-002D-07b], test_type: structured-review, status: Pass, evidence_paths: [acceptance/evidence-container-linux.jsonl, acceptance/evidence-host-macos.jsonl]}
    - {tc_id: TC-U-01, ac_ids: [AC-002D-01f, supporting], test_type: unit, status: Pass, result: "1796 passed, 3 skipped, 23 deselected; targeted 24 passed", evidence_paths: [acceptance/evidence-unit-integration.log, acceptance/evidence-unit-01f-task059.log]}
    - {tc_id: TC-G-01, test_type: integration, status: "Not executed (B9)"}
    - {tc_id: TC-L-01, ac_ids: [AC-002D-02b, AC-002D-02c], test_type: integration, status: "Not executed (B9)"}
    - {tc_id: TC-X-01, ac_ids: [AC-002D-01a], test_type: integration, status: "Not executed (B10)"}
    - {tc_id: TC-R-01..04, test_type: integration, status: "TC-R-01 Partial (superseded per AC-002D-08a); TC-R-02..04 Pass, byte-identical", evidence_paths: [acceptance/regression-*.jsonl]}
  pass_rate: "25/29 = 86.2%"
  acceptance_state: "partial - B9 and B10 not executed; delivery not Completed"
  stakeholder_outcome: "not measured"
```

This record shows hash and coverage consistency only. The executed artifacts above are the proof, and stakeholder outcome is **not measured**.

> **Note (2026-10-24, resumption after B9/B10):** the human granted B9 = A (one-time Trivy DB download via `tool_update` in a disposable container) and B10 = A (Apple Silicon arm64 evidence accepted; x86-64 recorded as an unverified limit — TC-X-01 stays not executed as an accepted limit). At resumption the Docker assets of TASK-058/059 (official v0.76.1 binary volume, uv cache, images) had been removed; re-downloading them is outside B9, so TASK-058 is parked on human item **B17** (representative DAO-004, feature acceptance test). Nothing was run; the results above are unchanged.

## Resumed Run 2026-10-24 (B9, B10, B17)

**Executed 2026-10-24 (UTC 01:26–02:26) by the acceptance worker for owner Sage, task TASK-058 (free-mode, mode `dao-represent-human-to-interact`, owner relays). No board, Git, memory, product, product-doc or existing-test change; no successor run.**

### Authorizations applied (exact scope)

| Item | Human decision (`x-ipe-docs/dao/26-10-23/human_decisions.md`) | How it was applied |
| --- | --- | --- |
| B9 = A | One-time acceptance-time Trivy DB download through the toolkit's `tool_update` path in a disposable container | **One** provisioning request (`secure-code tools provision --component vulnerability_db --component java_db --component checks_bundle`) from the validated default registry `mirror.gcr.io`, under a Maintainer authorization created inside the container (`auth init`, never on the macOS host) and one FEATURE-002-C `tool_update` grant (`metadata`, exact scopes of the three repositories) given at a terminal. No retry. `ghcr.io` was **not** contacted live (a second registry would be a second download). `SECURE_CODE_TRIVY_DOWNLOAD_AUTHORIZED` is the gate file's switch (TC-G-01), not used because TC-G-01 did not run. |
| B10 = A | arm64 evidence accepted; x86-64 an unverified limit | TC-X-01 → **Not executed — accepted limit (B10)**; not counted as passed. |
| B17 = A | Re-download, in disposable containers/volumes only, (1) the official Trivy v0.76.1 linux/arm64 asset (pinned digest), (2) the toolkit's Python packages from PyPI; apt NOT authorized | (1) downloaded once, digest-verified before extraction and before any execution (below). (2) **not needed**: every runtime dependency was already in a local seed cache, so PyPI was not contacted. No apt package, no x86-64 asset, no `checksums.txt`, no GitHub API call. |

Network use: only the two explicit steps (binary download; TC-L-01). Every other container ran with `--network none` or on the Docker `--internal` network `b17-int` whose single peer was the loopback registry; host runs used `UV_OFFLINE=1`.

### Frozen revision

- Executed only against the frozen copy `files/fat-002d-b17/frozen/ai-secure-code-toolkit` (session folder; git archive of toolkit HEAD `f18423e`); the live `ai-secure-code-toolkit/` tree was neither executed nor hashed. The copy was kept read-only during the run.
- File-list hash (method: `find . -type f` without `.venv`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.coverage` → `shasum -a 256` → `sed` → `LC_ALL=C sort -k2` → `shasum -a 256`): **start `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68` (291 files, 01:26 UTC) = end `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68` (291 files, 02:25 UTC)**; the per-file lists are byte-identical.
- Versus the TASK-059 rerun revision (`2fc16db8…`, 181 files): 110 files added and 27 changed (later features, e.g. FEATURE-001-G and the TASK-097/100 work). Changed files shared with this adapter: `cli.py`, `status.py`, `guard/report.py`, `guard/service.py`, `guard/targets.py`, `guard/budget.py`, `guard/cancel.py`, `guard/retention.py`, `adapters/safe_io.py`, `atomic.py`, `payload.py`, `pyproject.toml`, Guard `SKILL.md`, Framework `SKILL.md`/`cli-contract.md`. Unchanged: every `adapters/trivy*.py` (`trivy.py` `b06073d8…`, `trivy_log.py` `44ff4d1e…`, `trivy_run.py` `7b1072c7…`, `trivy_provision.py` `70ededeb…`, …), `digests.py` `4e949cf3…`, `registry_store.py` `e26a36ac…`, `process.py` `8890554a…`, `guard/toolrun.py` `06d1fdd1…`, gate `tests/guard/test_trivy_real.py` `a02faa0d…`. Because shared modules changed, **every** executable group was re-run at the frozen revision (no reuse of earlier results).

### Environment rebuild (all removed at the end; digests recorded)

| Asset | Source / method | Digest / identity |
| --- | --- | --- |
| Trivy v0.76.1 linux/arm64 archive | B17 download in a disposable `python:3.12-slim` container into volume `b17-bin` ([harness/fetch_trivy_arm64_b17.py](acceptance/harness/fetch_trivy_arm64_b17.py)); `https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-ARM64.tar.gz` (redirect host `release-assets.githubusercontent.com`), 47,434,511 bytes, 20.1 s | `sha256:e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f` = pinned value of tool-validation and `digests.TRIVY` (checked **before** extraction) |
| Trivy binary (extracted) | from the verified archive | `sha256:b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85`, 162,857,120 bytes = pinned (checked **before** any execution) ([toolval-binary-b17.jsonl](acceptance/tool-level/toolval-binary-b17.jsonl)) |
| uv cache `b17-uv-cache` | fresh volume; seed `fat-uv-cache-001d` copied through a read-only mount (seed never mutated); every cached toolkit build removed; toolkit built **offline** from the frozen copy | wheels `cffi`, `cryptography`, `pycparser`, `pyyaml` from the seed; built `x_ipe_secure_code` tree equals the frozen source file by file (106 files); PyPI not contacted |
| Images (local, no pull) | `fat-uv-git:py312` `8cbe78fe…` (Python 3.12.12, uv 0.9.30); `python:3.12-slim` `a6e34c59…`; `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` `e5b65587…` (002-A regression); `busybox` `c9fccaa6…` (only to stream `docker save` into a volume) | — |
| Image archives `b17-img` ([image-archives-b17.txt](acceptance/tool-level/image-archives-b17.txt)) | `docker save` of local `redis:6-alpine` (`efecd39d…`) and `hello-world:latest` (`7e1a4e2d…`); `FROM scratch` images built locally with WebGoat's `maven-wrapper.jar` and with a 600 MB random blob (no base image, no pull; images and their 7 BuildKit cache entries deleted after `docker save`) | `redis-6-alpine.tar` `df0f77c7…`, `hello-world.tar` `68869b3b…`, `jar-only.tar` `59be28be…`, `big-600m.tar` `dc9450bd…` |
| Trivy components for the loopback registry | **no new download**: the generations the adapter itself provisioned live in TC-L-01, copied to `b17-comp`, rebuilt as OCI artifacts by the unchanged [registry.py](acceptance/harness/registry.py) `build` ([oci-build-b17.jsonl](acceptance/tool-level/oci-build-b17.jsonl)) | `db/trivy.db` `6fd7f9c4…`, `java-db/trivy-java.db` `9c17cf95…`, `db/metadata.json` `d6595a0a…`, `java-db/metadata.json` `1511c594…`, `policy/metadata.json` `9d172818…` (642 files); manifests: vulnerability DB `f5c551bd…` (old variant `93aa0c8d…`), Java DB `2084133a…`, checks bundle `0d665ebe…` |
| Test CA | new disposable CA + leaf (`mirror.gcr.io`, `ghcr.io`, `pkg-containers.githubusercontent.com`; 3-day validity), generated with OpenSSL in the session folder, trusted only inside the disposable runner container; keys deleted after the run | — |
| Opengrep (002-B regression) | existing local volume `og-validate`, mounted read-only | unchanged |

New harness files (existing harness files unchanged): [fetch_trivy_arm64_b17.py](acceptance/harness/fetch_trivy_arm64_b17.py), [tc_live_b17.py](acceptance/harness/tc_live_b17.py), [setup-loopback-b17.sh](acceptance/harness/setup-loopback-b17.sh), [run-container-b17.sh](acceptance/harness/run-container-b17.sh), [run-host-b17.sh](acceptance/harness/run-host-b17.sh), [run-regressions-b17.sh](acceptance/harness/run-regressions-b17.sh) — the `*-b17.sh` scripts are the earlier scripts with `TOOLKIT_ROOT` pointing at the frozen copy and the `b17-*` volumes. The runner [blackbox.py](acceptance/blackbox.py) (`66b42dce…`) and the four regression runners were run **unchanged**.

### TC-L-01 — Live provisioning from the real registry through the adapter: **Pass (17/17)**

[evidence-live-provisioning-b17.jsonl](acceptance/evidence-live-provisioning-b17.jsonl) · harness [tc_live_b17.py](acceptance/harness/tc_live_b17.py) (imports the unchanged runner's helpers; never imports toolkit code) · container `fat-uv-git:py312` on Docker's default `bridge` network, `UV_OFFLINE=1` (this only stops uv from fetching packages; the CLI and the `trivy` processes shared the container's network), disposable HOME/trust store, project `live ü` · run 01:34:16–01:41:55 UTC.

- **Before the live run:** the observers were self-tested offline (`--network none`: a loopback TLS ClientHello with SNI and a crafted DNS answer; the self-test reported Pass on the console, but its output was **not kept as an evidence file** — the decoded SNI and DNS answers in the live evidence show the observers worked), and the whole flow was dry-run with `--network none` ([evidence-live-provisioning-dryrun-networknone-b17.jsonl](acceptance/evidence-live-provisioning-dryrun-networknone-b17.jsonl): the same three argv, every operation `failed` (the tool's OCI download error; for the bundle "download did not produce exactly the policy/ subtree"), previous `missing`, zero IP frames — no egress was possible). A first dry run stopped on a harness `None` check (fixed in the harness before the live run; not a product finding).
- **Flow (real CLI):** `auth init` (in the container) → `init` → `tools register` (official binary) → scope, `guard open`/`plan` (one `trivy` runtime check on `app/requirements.txt`) → `guard extend` → `guard allow-egress --purpose tool_update --recipient https://mirror.gcr.io --data metadata --scope …trivy-db:2 --scope …trivy-java-db:1 --scope …trivy-checks:2` (grant `g-1`, typed at a terminal) → **one** `tools provision` (448.3 s) → offline scan → `guard conclude`.
- **Result:** exit 0; three operations (run in parallel), each `completed`, previous `missing`:

| Component | Repository:tag | Size | Time | Content digest | Metadata (equal to the installed `metadata.json`) |
| --- | --- | --- | --- | --- | --- |
| vulnerability_db | `mirror.gcr.io/aquasec/trivy-db:2` | 1,628,737,686 B | 56.9 s | `sha256:7b2d0198…` | Version 2, UpdatedAt 2026-10-23T19:15:43Z, NextUpdate 2026-10-24T19:15:43Z, DownloadedAt 2026-10-24T01:35:18Z |
| java_db | `mirror.gcr.io/aquasec/trivy-java-db:1` | 1,561,686,169 B | 385.0 s | `sha256:d1cd6216…` | Version 1, UpdatedAt 2026-10-24T01:07:32Z, NextUpdate 2026-10-27T01:07:32Z, DownloadedAt 2026-10-24T01:41:44Z |
| checks_bundle | `mirror.gcr.io/aquasec/trivy-checks:2` | 1,056,303 B | 3.8 s | `sha256:32d9f2fb…` | MajorVersion 2, Digest `sha256:b591e919…` (same bundle digest as FF-05), DownloadedAt 2026-10-24T01:41:49Z |

- **Adapter records (02b/02c):** exactly three `trivy` processes; argv `image --download-db-only --db-repository mirror.gcr.io/aquasec/trivy-db:2`, `image --download-java-db-only --java-db-repository mirror.gcr.io/aquasec/trivy-java-db:1`, `fs --scanners misconfig --checks-bundle-repository mirror.gcr.io/aquasec/trivy-checks:2 --skip-db-update --skip-java-db-update --offline-scan … <op>/empty`, each with `--skip-version-check --disable-telemetry`, exactly one repository flag, no project path; environment exactly HOME/XDG_CONFIG_HOME/XDG_CACHE_HOME/TMPDIR/PATH/LANG/TZ; working folder the private `staging/op-*`; three `allowed`, `used: true` declarations `eg-1…3` listing known host `mirror.gcr.io` with grant `g-1` and the configuration-level note; one finished `tool_update` attempt `a-1-8a811cb9`; provisioning entry with Maintainer action `tools.provision`, grants and the limit text; staging removed; `status`: the three components `present`, registry `mirror.gcr.io`, generation, age; report sections "Tool Provisioning", "Trivy Component State", "Outbound Calls (Egress)" with repository, known hosts and "configuration-level".
- **Real-host observation (no iptables, no proxy, no sinkhole):**

| Observable | Observed during the provisioning window |
| --- | --- |
| DNS queries (outgoing UDP/53, decoded) | only `mirror.gcr.io`, to Docker Desktop's resolver `192.168.65.7` |
| DNS answers (incoming, decoded) | `mirror.gcr.io` CNAME `googlecode.l.googleusercontent.com` → A `173.194.43.82` |
| TLS ClientHello SNI (outgoing TCP payload) | 3 ClientHellos (one per process), all `mirror.gcr.io`; no `ghcr.io`, no `pkg-containers.githubusercontent.com`, no other server name |
| IP destinations (outgoing IPv4/IPv6 frames delivered to the AF_PACKET socket, 67,248 frames; the socket's drop counter was not read, so lost frames under load cannot be excluded) | exactly `173.194.43.82:443/tcp` (the address returned for `mirror.gcr.io`) and `192.168.65.7:53/udp`; no other address, port or protocol; no IPv6 frame |
| Offline scan after provisioning (02d) | 1 `trivy` process with the six offline flags, method `ok`, **zero IP frames** |

  **Not observable** with this method: HTTP `Host` headers, paths and redirect targets inside TLS (a redirect to another host would have shown as a new DNS query and SNI — none occurred; a redirect within `mirror.gcr.io` would be invisible); traffic of other containers or of the macOS host; enforcement (the toolkit does not gate the launched tool's network use — the configuration-level limit stated by AC-002D-02b). The DNS-level name `googlecode.l.googleusercontent.com` is the CNAME of `mirror.gcr.io` and never appeared as a connection server name. This agrees with tool-validation Known Issue 17 (`mirror.gcr.io` operations contacted only `mirror.gcr.io:443`).

### Refreshed offline black-box at the frozen revision

| Run | Result | Evidence |
| --- | --- | --- |
| Container (TC-D-00…19; `run-container-b17.sh`, offline `b17-int` + loopback registry, 01:44–01:51 UTC) | **19/20 cases Pass; 444/445 checks**; the check-name lists of all 20 cases are identical to the TASK-059 rerun. The one failing check is TC-D-01 "01b x86-64 official binary on an arm64 host: refused TOOL_PLATFORM_MISMATCH": its fixture `/tv/64bit/trivy` (the official x86-64 binary) was **not available — the x86-64 asset is outside B17**; the path was missing, so the refusal code was presumably `TOOL_PATH_INVALID` (the evidence records only the failed check name; the code is stated in this report, not in the evidence). Not a product defect. AC-002D-01b passes **on the specification text** (other version, custom build, modified file, archive, path cases — all passed); the **x86-64 assertion of the AC map above (`TOOL_PLATFORM_MISMATCH`) was not re-executed (B17 scope)**; it concerns the x86-64 table entry (B10). Supporting unit evidence at this revision: `test_01f_static_build_matches_any_libc_opengrep_exact` passed ([evidence-unit-01f-b17.log](acceptance/evidence-unit-01f-b17.log)). It last passed in the TASK-059 rerun; `digests.py` and `registry_store.py` are unchanged since, `cli.py` changed | [evidence-container-linux-b17.jsonl](acceptance/evidence-container-linux-b17.jsonl) (`a8abebb6…`); stderr empty |
| Host macOS (TC-H-01, TC-D-19; `run-host-b17.sh`, `UV_OFFLINE=1`, frozen copy) | **2/2, 12 checks** | [evidence-host-macos-b17.jsonl](acceptance/evidence-host-macos-b17.jsonl) (`c2b9c056…`); stderr empty |

Observed values (loopback rebuilt from the live components): WebGoat `pom.xml` 36 findings, 18 packages skipped offline (unchanged), `completed_with_errors` with the unlisted pom WARN (fail-closed); 2019 DB variant used offline, age 2733 d; status `disk_bytes` equal to the summed blocks; zero IP frames and zero registry requests in every scan window; loopback provisioning (TC-D-03) SNI only `mirror.gcr.io`, frames only to the registry on 443.

### TC-U-01 — Framework suite at the frozen revision: **Pass**

- `uv run --offline python -m pytest -p no:cacheprovider -o addopts="" -q` in a disposable copy of the frozen tree (identical file-list hash `44837bb0…`) on macOS (CPython 3.14.6, uv 0.11.23, `uv sync --offline` from the host cache, no download): **2884 passed, 5 skipped, 23 deselected** (02:12–02:24 UTC) ([evidence-unit-integration-b17.log](acceptance/evidence-unit-integration-b17.log), `1964f4ff…`).
- A first run in the bare copy had **1 failure, 2883 passed**: FEATURE-003-B's `test_07a_dev_repo_carriers_unchanged` requires the development repository's `.github/copilot-instructions.md` next to the toolkit folder, which the session-folder copy lacked (layout dependency of the copy, not of the product; [evidence-unit-integration-b17-run1-layout-fail.log](acceptance/evidence-unit-integration-b17-run1-layout-fail.log)). The workspace file was placed beside the copy (read-only use; removed afterwards) and the full suite re-run → the result above.
- Targeted (AC-002D-01f and TASK-059): `-v -k "01f or test_07b or test_digest_table_matches_validation_record or task059" tests/adapters tests/guard` → **26 passed** ([evidence-unit-01f-b17.log](acceptance/evidence-unit-01f-b17.log), `ed8582cf…`).

### Regressions at the frozen revision (TC-R-01…04)

`run-regressions-b17.sh` (unchanged runners; container `--network none` + macOS host): **all eight logs are byte-identical to the TASK-059 rerun evidence** — 002-A 26/26 + 2/2, 002-B 9/10 + 2/2 (the one failing check is the superseded "06b trivy/strix not provided", per AC-002D-08a, not counted as passed), 002-C 9/9 + 2/2, 003-A 11/11 + 2/2; all stderr empty. Files: `acceptance/regression-{002A,002B,002C,003A}-{container-linux,host-macos}-b17.jsonl`.

### TC-G-01 — Real-binary gate: **Not executed — human-scoped (B17 = A, apt not authorized)**

Prerequisites of `tests/guard/test_trivy_real.py --require-real-trivy` (unchanged, `a02faa0d…`), recorded: `SECURE_CODE_TRIVY_IMAGE` must contain Python ≥ 3.11, `cryptography`, `pyyaml` **and `iptables`** — no local image has `iptables` and installing it needs apt (not authorized); a `docker` CLI for the pytest process (present on the macOS host, absent in every local Linux image); the official binary on a path shared by the pytest process and the Docker daemon; samples and image archives; `SECURE_CODE_TRIVY_DOWNLOAD_AUTHORIZED=1`. Never counted as passed. Its assertions are **partially covered** by executed real-binary evidence (TC-L-01 and the TC-D container cases with the official binary) — see the gate map below; that evidence is not the gate file.

#### TC-G-01 check-by-check gate map (independent evidence review, DAO-006)

Independent evidence review of this run: verdict **PASS-WITH-NITS**; it classified `ghcr.io` Java DB as uncovered and the control windows, `ghcr.io` ×2, refused repository ×2 and the network-none variant as partial, none blocking a confirmed AC. The rows below apply that classification to every gate test item; the remaining items are covered (tally 16 covered, 6 partial, 1 uncovered). Evidence references compiled by the acceptance worker. Gate file `tests/guard/test_trivy_real.py` (`a02faa0d…`, 23 test items at the frozen revision).

| Gate test item | Gate assertion (short) | State | Executed evidence |
| --- | --- | --- | --- |
| `test_control_windows_are_silent` | observer name lookup and a 10 s idle window: no DNS, SNI, catch-all or UDP | **Partial** | TC-D-00 control windows (internal network: DNS frame captured, idle window silent) and the TC-L-01 `--network none` dry run; the gate's own DNS-sinkhole/SNI-observer control was not run, and TC-L-01 had no idle control window |
| `test_register_real_binary` | official binary registered, version 0.76.1, `platform_validated` on arm64, libc `None` | Covered | TC-D-01 (record checks), TC-L-01 (registration before provisioning) |
| `test_open_verification_for_the_gate` | verification opened and planned for the nine gate objects | Covered | TC-D-03/TC-D-06 main verification (same samples and archives), TC-L-01 |
| `test_provisioning_contacts_exactly_the_known_hosts[mirror.gcr.io-vulnerability_db]` | completed, content digest, metadata, known hosts = {mirror.gcr.io}; observed names/SNI = known hosts | Covered | TC-L-01 (live, real-host DNS/SNI/IP) + TC-D-03 (loopback) |
| `…[mirror.gcr.io-java_db]` | same | Covered | TC-L-01 + TC-D-03 |
| `…[mirror.gcr.io-checks_bundle]` | same | Covered | TC-L-01 + TC-D-03 (TC-L-01 ran the three components in one request, not one request each) |
| `…[ghcr.io-vulnerability_db]` | completed with both grants; observed SNI = {ghcr.io, pkg-containers.githubusercontent.com} | **Partial** | TC-D-04 loopback only (no live `ghcr.io` contact) |
| `…[ghcr.io-checks_bundle]` | same | **Partial** | TC-D-04 loopback only |
| `…[ghcr.io-java_db]` | same | **Uncovered** | no adapter-level evidence (live or loopback) for the `ghcr.io` Java DB repository |
| `test_refused_repository_fails_without_fallback[vulnerability_db]` | refused repository → `failed`, previous `kept`, only `mirror.gcr.io` contacted | **Partial** | TC-D-05 loopback only (refusal by the loopback registry) |
| `test_refused_repository_fails_without_fallback[checks_bundle]` | same (tool exits 0 with embedded fallback, yet `failed`) | **Partial** | TC-D-05 loopback only |
| `test_scans_are_offline_and_match_the_validation[C1…C9]` (9 items) | each scan silent; re-hash `unchanged`; C1 36 vuln findings and 18 skipped packages; C3 `Dockerfile_desktop` override `ok`; C8 "OS not detected"; project `.trivyignore` not loaded | Covered | TC-D-06, TC-D-07, TC-D-09 with the official binary and the live-provisioned component files (36 findings / 18 skipped; override `ok`; hello-world "OS not detected"; zero frames; re-hash `unchanged`; project Trivy configuration not loaded) |
| `test_network_none_scan_and_timeouts_mapped` | scan completes with the runner disconnected from every network | **Partial** | scans on the `--internal` network with no route out (TC-D-00/06) and timeouts (TC-D-15); no scan with the network disconnected (`--network none` was used only for the TC-L-01 provisioning dry run) |
| `test_secret_never_stored_and_components_unchanged` | fake key never stored; all components `present` | Covered | TC-D-18 (byte search: none), TC-D-17 / TC-L-01 status |
| `test_config_types_equal_the_help_list` | `CONFIG_TYPES` = misconfiguration types of `trivy fs --help` | Covered | FF-01 help list of the same binary digest + TC-D-10 (all 9 types to the real binary); `trivy.py` unchanged |

Uncovered and partial items are disclosed limits; per DAO-006 an uncovered assertion that matters for a confirmed AC would stop closing — the review found none.

### TC-X-01 — Linux x86-64: **Not executed — accepted limit (B10)**

No x86-64 asset was downloaded (outside B17) and no emulated run was made. Not counted as passed.

### Supplementary 002-G comparison on real Trivy results

Not run in this pass (not cheap: it needs its own comparison setup); stays deferred as noted in DAO-004.

### AC changes at the frozen revision

| AC ID | Result (2026-10-24) |
| --- | --- |
| AC-002D-01a | **Pass (arm64)**: registration of the official arm64 binary with digest before execution and full record (TC-D-01). Linux x86-64: accepted unverified limit (B10, TC-X-01); the cross-architecture refusal check was not re-run (x86-64 asset outside B17) |
| AC-002D-02b | **Pass**: live `mirror.gcr.io` branch through the adapter with real-host DNS/SNI/IP observation (TC-L-01) + loopback for refusals and the two-host `ghcr.io` branch (TC-D-02…05). Limit: `ghcr.io`/`pkg-containers.githubusercontent.com` not contacted live (one-time grant used for the validated default registry) |
| AC-002D-02c | **Pass**: live result fields and metadata equal to the installed files (TC-L-01); failed, cancelled, timed-out, killed and partial branches on the loopback registry (TC-D-03, TC-D-05) |
| AC-002D-01b | **Pass on the specification text** (no Maintainer, other version/custom build, modified file, release archive, symlink, missing path, folder, relative path — TC-D-01). The AC map's additional x86-64 assertion (`TOOL_PLATFORM_MISMATCH`) was **not re-executed** (x86-64 asset outside B17); supporting unit test `test_01f_static_build_matches_any_libc_opengrep_exact` passed |
| all other 42 ACs | **Pass**, re-executed at the frozen revision with the assertions of the AC map above (TC-D-00…19, TC-H-01, TC-U-01); exceptions are the rows of this table |

**AC totals (46) at the frozen revision `44837bb0…`: Pass 46 · Fail 0 · Not executed 0** (01a on arm64 only; x86-64 is the human-accepted limit B10). Before (TASK-059 rerun): 44 Pass + 2 loopback-only (02b, 02c).

### Execution Results (2026-10-24, same 29-case denominator)

| Type | Total Planned | Passed | Failed | Blocked | Partial / Not Run |
| --- | --- | --- | --- | --- | --- |
| frontend-ui | 0 | 0 | 0 | 0 | 0 |
| backend-api | 0 | 0 | 0 | 0 | 0 |
| integration — black-box CLI (TC-D-00…18 container; TC-H-01 host) | 20 | 19 | 0 | 0 | 1 partial (TC-D-01: one non-AC check without its x86-64 fixture) |
| structured-review — package inspection (TC-D-19; container + host) | 1 | 1 | 0 | 0 | 0 |
| unit / integration — Framework suite (TC-U-01) | 1 | 1 | 0 | 0 | 0 |
| integration — real-binary gate file (TC-G-01) | 1 | 0 | 0 | 0 | 1 not executed — human-scoped (B17 = A, apt not authorized) |
| integration — live provisioning (TC-L-01) | 1 | 1 | 0 | 0 | 0 |
| integration — Linux x86-64 adapter (TC-X-01) | 1 | 0 | 0 | 0 | 1 not executed — accepted limit (B10) |
| integration — black-box regression (TC-R-01…04; container + host) | 4 | 3 | 0 | 0 | 1 partial (TC-R-01, superseded check) |
| **TOTAL (logical TCs)** | **29** | **25** | **0** | **0** | **4** |

**pass_rate = 25 / 29 = 86.2 %** (all planned logical TCs, incl. not executed and partial). Compared with the TASK-059 rerun (25/29): TC-L-01 moved to Pass, TC-D-01 moved to Partial (missing x86-64 fixture, environment only). Diagnostic only: 17 live + 445 container + 12 host black-box checks; 16 regression case × environment executions; 2884 suite tests.

### Honest limits (this run)

- **Live branch scope:** one provisioning from `mirror.gcr.io`; the live `ghcr.io` two-origin branch, live refusal/failure/timeout/cancel branches and a second live provisioning (replacing a previous generation) were not executed live (loopback only).
- **Observation scope:** inside the runner container only (DNS, SNI, IP/port of the frames delivered to the AF_PACKET socket; its drop counter was not read); TLS content, HTTP hosts/paths/redirects not observable; no enforcement claim. The macOS host and Docker VM traffic were not observed.
- **Loopback artifacts** are rebuilt from the live-downloaded component files (same file content, different layer/manifest digests; checks-bundle manifest annotated `2.0.0`); they prove the toolkit's behaviour, not the real registries'.
- **x86-64:** neither the adapter (B10) nor the registration cross-architecture refusal was re-run at this revision.
- **TC-G-01** gate file not executed — human-scoped (B17 = A, apt not authorized); per the gate map 6 items are only partially covered (control windows, `ghcr.io` ×2 loopback-only, refused repository ×2 loopback-only, network-none scan variant).
- **`ghcr.io` Java DB:** no adapter-level evidence at all (neither live nor loopback) — the one uncovered gate item.
- **Clean `.tf`** known limitation and **F-3** unchanged (informational).
- **Framework-only branches** (fake binary) as listed above; musl, Windows and a host with Python on `/usr/bin` not run.
- **Host uv cache:** the macOS host runs built the frozen toolkit into the host's uv cache offline (as in earlier runs); no package was downloaded onto the host.
- **Independent review** of this evidence: performed afterwards for the owner (PASS-WITH-NITS, DAO-006); this worker did not review its own evidence. **Stakeholder outcome: not measured.**

### Hygiene and cleanup

- Frozen copy hash identical at start and end (above); no `__pycache__`/`.venv` created in it. Scratch only under `files/fat-002d-b17/` of the session folder; deliverables only in this report and new `-b17` files under `acceptance/` (no earlier evidence overwritten). Credential-shaped strings (AWS key id, GitHub token formats) in the new evidence: none; the Maintainer passphrase appears in no evidence file.
- Removed at the end: container `b17-reg`; network `b17-int`; volumes `b17-bin` (binary and archive), `b17-uv-cache`, `b17-comp` (live components), `b17-oci`, `b17-img`, `b17-work`, `b17-work-live`, `b17-reglog`; images `b17-jar:local`, `b17-big:local` and their 7 BuildKit cache entries (pruned by id); test-CA keys and certificates, handoff project, work/temp folders and the suite copy. Verified afterwards: no `b17` container, network, volume, image or build-cache entry left; seed volumes `fat-uv-cache-*` still present and never mounted writable.

### Relevant inputs (2026-10-24)

| Role | Path | SHA-256 |
| --- | --- | --- |
| toolkit (frozen) | `files/fat-002d-b17/frozen/ai-secure-code-toolkit` file list (291 files), start = end | `44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68` |
| specification / design / bug report | unchanged | `229cc76e…` / `cb2cd1cf…` / `0723ef6d…` |
| tool validation README / driver / results | unchanged | `48579370…` / `32017334…` / `00f43284…` |
| config | `x-ipe-docs/config/tools.json` (`stages.validation.acceptance_test` → `x-ipe-tool-implementation-python: true`) | `6df39210…` |
| human decisions (B9, B10, B17) | `x-ipe-docs/dao/26-10-23/human_decisions.md` | `62615b94d18ab9c78165a5e0026606de5a316bb6086478ec9a173ef58d503632` |
| DAO logs | `decisions_made_feature_acceptance_test.md` (DAO-004) / `decisions_made_technical_design.md` (DAO-002; file appended by other tasks during this run, value at the end) | `880e1f7a686ea66bfb9107545c531a85b39bedab2201bad4f3b7172c1830dc20` / `766d7a867899cfb4a10156181e9cfd6504d6ab6f24759aa47fceb31f35fe2b2c` |
| runner (unchanged) | [blackbox.py](acceptance/blackbox.py) | `66b42dce8dd0cfb9cdc018555966ba374761c17890e72356ce43103f1d63063a` |
| harness (new) | [fetch_trivy_arm64_b17.py](acceptance/harness/fetch_trivy_arm64_b17.py) / [tc_live_b17.py](acceptance/harness/tc_live_b17.py) / [setup-loopback-b17.sh](acceptance/harness/setup-loopback-b17.sh) / [run-container-b17.sh](acceptance/harness/run-container-b17.sh) / [run-host-b17.sh](acceptance/harness/run-host-b17.sh) / [run-regressions-b17.sh](acceptance/harness/run-regressions-b17.sh) | `39fd7f84…` / `36713caa…` / `29b133a9…` / `53e8b3a7…` / `00687816…` / `89437be0…` |
| evidence (live) | [evidence-live-provisioning-b17.jsonl](acceptance/evidence-live-provisioning-b17.jsonl) / [dry run, no network](acceptance/evidence-live-provisioning-dryrun-networknone-b17.jsonl) | `6e6b7ade2cbe494816b8f748793d1c316f15bf3530cb311de08a890bb2401177` / `3df320c6d852ca487877992b17ac5eb773e6104b17852e7cd9bb0dca391cb75e` |
| evidence (black-box) | [evidence-container-linux-b17.jsonl](acceptance/evidence-container-linux-b17.jsonl) / [evidence-host-macos-b17.jsonl](acceptance/evidence-host-macos-b17.jsonl) | `a8abebb6695c45ae5d63a2ccc42c0ede0f749f4047a6443afa28677ea1717b09` / `c2b9c056150f4538c45a04eaab9474d7486d01f53aa01aaaf0ef2754931840e4` |
| evidence (suite) | [evidence-unit-integration-b17.log](acceptance/evidence-unit-integration-b17.log) / [run 1](acceptance/evidence-unit-integration-b17-run1-layout-fail.log) / [01f targeted](acceptance/evidence-unit-01f-b17.log) | `1964f4ff70f3b6cfb89fb96354ae022d3c7f92dcd3943554e1a1783f673d3d47` / `10cd44e7ee1ce3b646caf78d3416b004ce4b7eba8b4dd71d0760f1ba70b4e7b5` / `ed8582cfca07d14dd2e24b1127b049cfd17f7a575d89ca489f23342b8b5ec0d1` |
| evidence (regressions) | `regression-*-b17.jsonl` (8 files) | byte-identical to the TASK-059 rerun files: 002-A `404ada17…`/`b87e492e…`, 002-B `9239513a…`/`290c2607…`, 002-C `7a21573d…`/`b9261d26…`, 003-A `4b978585…`/`e2e89141…` |
| evidence (tool level) | [toolval-binary-b17.jsonl](acceptance/tool-level/toolval-binary-b17.jsonl) / [oci-build-b17.jsonl](acceptance/tool-level/oci-build-b17.jsonl) / [image-archives-b17.txt](acceptance/tool-level/image-archives-b17.txt) | `f991601a1cfae57cd83ca100ed121f2386c8acad4603179069e391799f9c645c` / `1e83d9cd6d2982ace5ae92d2cc27eef618e1777196ab25dcabb1b5a44fd43fcf` / `75cccb994ce35c2ac8bb2689f2013d68b22b97dbd3834c55fa9b729aafddbc81` |

### Acceptance state and handoff (2026-10-24)

- **Engineering delivery:** every scoped AC (46/46) has current passing evidence at the frozen revision on Linux arm64 (macOS for the Linux-only refusal), including the previously parked live branch of AC-002D-02b/02c. Not counted as passed: TC-G-01 (not executed — human-scoped (B17 = A, apt not authorized); partially covered per the gate map), TC-X-01 (accepted limit B10), TC-D-01 partial (one non-AC check without its x86-64 fixture), TC-R-01 partial (superseded check).
- **Stakeholder outcome:** not measured.
- **DAO-006 (2026-10-24):** ruled (a) with conditions — TC-G-01 is replaced by the reviewed check-by-check equivalent above (design erratum in [technical-design.md](technical-design.md)); independent evidence review PASS-WITH-NITS (nits applied in this report). The closing evidence holds for toolkit revision `f18423e` (frozen file list `44837bb0…`).
- **Owner decision:** status transition and Feature Closing; F-3 and clean-`.tf` CR candidates. Conditional successors returned unchanged: code refactor (no evidenced need) and feature closing. No board, Git or successor action taken.

```yaml
acceptance_evidence_2026_10_24:
  feature_id: "FEATURE-002-D"
  task: "TASK-058 (resumed; B9 = A, B10 = A, B17 = A)"
  toolkit_frozen_file_list: {start: "44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68", end: "44837bb074771c70e3c78cd9a1307e5dbf6f67e58e4786363f3efd0a73b46c68", files: 291}
  downloads:
    - {what: "trivy_0.76.1_Linux-ARM64.tar.gz (GitHub)", sha256: "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f", pinned_match: true}
    - {what: "trivy binary (extracted)", sha256: "b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85", pinned_match: true}
    - {what: "PyPI packages", status: "not needed; not contacted"}
    - {what: "TC-L-01 tool_update (mirror.gcr.io)", trivy_db: "6fd7f9c44ff3120e0d15d5b5b2234e1ff1c9e7a6b56b4e776041f93faf1f6f17", trivy_java_db: "9c17cf958a0fc2c74d5457ac33d2eb3ef71b170b49cadf9c465ecb9de7d66924", checks_bundle_digest: "sha256:b591e9190cff4aa4e385b1a25bccfd9ecf178d3c77fd194e1410b7ce7e1df058"}
  cases:
    - {tc_id: TC-L-01, ac_ids: [AC-002D-02b, AC-002D-02c, AC-002D-08a], status: Pass, checks: "17/17", evidence: acceptance/evidence-live-provisioning-b17.jsonl}
    - {tc_id: "TC-D-00..18", status: "18 Pass, TC-D-01 Partial (x86-64 fixture outside B17)", evidence: acceptance/evidence-container-linux-b17.jsonl}
    - {tc_id: TC-H-01, status: Pass, evidence: acceptance/evidence-host-macos-b17.jsonl}
    - {tc_id: TC-D-19, status: Pass, evidence: [acceptance/evidence-container-linux-b17.jsonl, acceptance/evidence-host-macos-b17.jsonl]}
    - {tc_id: TC-U-01, status: Pass, result: "2884 passed, 5 skipped, 23 deselected; targeted 26 passed", evidence: acceptance/evidence-unit-integration-b17.log}
    - {tc_id: "TC-R-01..04", status: "TC-R-01 Partial (superseded); TC-R-02..04 Pass; byte-identical to the TASK-059 rerun", evidence: "acceptance/regression-*-b17.jsonl"}
    - {tc_id: TC-G-01, status: "Not executed - human-scoped (B17 = A, apt not authorized); partially covered per gate map (16 covered, 6 partial, 1 uncovered: ghcr.io java_db)"}
    - {tc_id: TC-X-01, status: "Not executed - accepted limit (B10)"}
  ac_totals: {pass: 46, fail: 0, not_executed: 0, note: "01a arm64 only; x86-64 accepted limit B10"}
  pass_rate: "25/29 = 86.2%"
  stakeholder_outcome: "not measured"
```
