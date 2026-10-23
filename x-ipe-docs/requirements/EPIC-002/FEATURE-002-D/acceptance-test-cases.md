# Acceptance Test Cases

> Feature: FEATURE-002-D — Trivy Adapter (EPIC-002)
> Status: **Acceptance partial — B9 and B10 not executed; delivery NOT Completed.** At the fixed revision (Bug Fix TASK-059), 44 of 46 ACs pass with current black-box evidence (real Trivy v0.76.1 binary, real CLI, offline Linux arm64 container; macOS host for the Linux-only refusal). F-1 (AC-002D-03d) and F-2 (AC-002D-05b) from TASK-058 are fixed and verified with the real binary. **AC-002D-02b and 02c pass only against a loopback registry**; their live branch (provisioning from the real `mirror.gcr.io` / `ghcr.io` with real-host observation) and the mandatory real-binary gate file are **not executed (B9)**. The adapter on **Linux x86-64 is not executed (B10)**.
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
