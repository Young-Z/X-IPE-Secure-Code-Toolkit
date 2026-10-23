# AI Secure Code Toolkit

A standalone set of three agent skills for AI-assisted secure development:

| Skill | Role |
|---|---|
| `x-ipe-secure-code-toolkit-framework` | Project initialization, owner-signed Maintainer authorization, security knowledge, Policies, status, scanner Adapter code |
| `x-ipe-secure-code-toolkit-copilot` | In-flow security collaborator during design, implementation, bug fix and refactor |
| `x-ipe-secure-code-toolkit-guard` | Evidence-based verification of finished artifacts; reports, never fixes |

The skills and their scripts are pre-generated; nothing is package-installed. You need
[uv](https://docs.astral.sh/uv/) and Python 3.11+ (macOS, Linux or Windows).

## Initialize a project

```bash
FW=/path/to/ai-secure-code-toolkit/x-ipe-secure-code-toolkit-framework
uvx --from "$FW/scripts" secure-code init --project /path/to/project --env github-copilot
```

This places the three skills in the environment's skills folder, creates the empty
`x-ipe-docs/secure-code/` layout and adds one toolkit fragment to the host entry file
(`AGENTS.md` for `github-copilot`, `CLAUDE.md` for `claude-code`). Re-running it is safe:
unchanged files are skipped, locally edited files are reported and kept, and security data is
never touched.

## Host integration carriers

```bash
uvx --from "$FW/scripts" secure-code carriers --project /path/to/project --env github-copilot
uvx --from "$FW/scripts" secure-code carriers --project /path/to/project --env github-copilot \
  --select github-instructions --select system-prompt --system-prompt-host copilot-cli
```

All toolkit carriers are rendered from one routing definition
(`x-ipe-secure-code-toolkit-framework/references/routing-definition.json`) and form one integration
declaration: Copilot for design, implementation, bug fix and refactor work, Guard only on an explicit
or authorized verification request. The host entry fragment is the default; the GitHub instructions
file and the system-prompt fragment are generated only when selected. Text outside the toolkit's
managed boundaries is never changed; an edited toolkit fragment is kept and reported with a
secret-masked difference until you choose `--regenerate KIND` or `--accept KIND`. A deselected
carrier is left in place. Status lists every carrier with "host effect: not verified": the toolkit
checks files, not whether a host reads them. On platforms without the file-free project lock
(including Windows) `carriers` currently refuses with `LOCK_UNAVAILABLE` (open gap B11). See
[environments](x-ipe-secure-code-toolkit-framework/references/environments.md).

## Authorize yourself as Maintainer (owner only, interactive)

```bash
uvx --from "$FW/scripts" secure-code auth init     # choose a passphrase (12+ characters)
uvx --from "$FW/scripts" secure-code auth status
uvx --from "$FW/scripts" secure-code auth revoke   # needs the passphrase
```

Keep the passphrase safe: recovery is not automated in this version.

## Check status

```bash
uvx --from "$FW/scripts" secure-code status --project /path/to/project
```

## Select Policies

Agents resolve formal Local knowledge into Policies and save the scope the user confirmed:

```bash
uvx --from "$FW/scripts" secure-code policy resolve --project . --rule CWE/4.14/CWE-79 --json
uvx --from "$FW/scripts" secure-code scope save --project . --decisions decisions.json --confirmed --json
uvx --from "$FW/scripts" secure-code scope show --project . --scope sha256:<id> --json
```

See [policy selection](x-ipe-secure-code-toolkit-framework/references/policy-selection.md).

## Exit knowledge (Maintainer)

Deactivate, reactivate, delete or rename one Local rule: preview the impact, show it, and confirm
only with the Maintainer's explicit decision. References never block and are never repaired
automatically; they are reported broken.

```bash
uvx --from "$FW/scripts" secure-code knowledge exit-preview --project . --rule CWE/4.14/CWE-89 \
    --action rename --to CWE/4.14/CWE-89-SQL --reason "Split into SQL-specific rule" --json
uvx --from "$FW/scripts" secure-code knowledge exit-confirm --project . --rule CWE/4.14/CWE-89 \
    --action rename --to CWE/4.14/CWE-89-SQL --reason "Split into SQL-specific rule" --impact-digest sha256:<from preview> --json
uvx --from "$FW/scripts" secure-code knowledge links --project . --json   # broken references, read-only
```

Deleted rules are kept in a private tombstone under `.x-ipe/private/secure-code/exits/`; deleted
and renamed identities are reserved. See
[CLI contract](x-ipe-secure-code-toolkit-framework/references/cli-contract.md#exiting-knowledge).

## Verify with Guard

The Guard skill plans and reviews; the script records its work and computes the verdict
(Pass / Fail / Cannot confirm pass) by fixed rules:

```bash
uvx --from "$FW/scripts" secure-code guard open --project . --request .x-ipe/private/secure-code/tmp/open.json --json
uvx --from "$FW/scripts" secure-code guard plan --project . --run <id> --request .x-ipe/private/secure-code/tmp/plan.json --json
uvx --from "$FW/scripts" secure-code guard attempt --project . --run <id> --request .x-ipe/private/secure-code/tmp/attempt.json --json
uvx --from "$FW/scripts" secure-code guard record --project . --run <id> --request .x-ipe/private/secure-code/tmp/record.json --json
uvx --from "$FW/scripts" secure-code guard review --project . --run <id> --request .x-ipe/private/secure-code/tmp/review.json --json
uvx --from "$FW/scripts" secure-code guard conclude --project . --run <id>
uvx --from "$FW/scripts" secure-code guard accept-risk --project . --run <id> --finding F1 --reason "..."  # user, interactive
uvx --from "$FW/scripts" secure-code guard tool --project . --run <id> --request .x-ipe/private/secure-code/tmp/tool.json --json
uvx --from "$FW/scripts" secure-code guard cleanup --project .   # evidence older than 30 days
uvx --from "$FW/scripts" secure-code guard extend --project . --run <id> --minutes 30 --reason "..."  # user, interactive
uvx --from "$FW/scripts" secure-code guard cancel --project . --run <id> --reason "..."
uvx --from "$FW/scripts" secure-code guard allow-egress --project . --run <id> --purpose submission \
  --recipient https://api.example.com --data findings --scope src/login.py --reason "..."  # user, interactive
```

Each verification has one budget (by default 60 minutes and 3 extra attempts; only the user can
extend it, confirming at an interactive terminal — a cooperative control, not an authorization
boundary) and grants no outbound data by default; the agent registers each unit of work as an
attempt, pauses while waiting for you and declares every outbound call. See
[Budget, pause, extension and cancel](x-ipe-secure-code-toolkit-guard/references/guard-records.md#budget-pause-extension-and-cancel)
and [Outbound calls](x-ipe-secure-code-toolkit-guard/references/guard-records.md#outbound-calls-egress).

Write request files under `.x-ipe/private/secure-code/tmp/` — never inside the targets (a file written
into a verified folder changes its digest). Reports: `x-ipe-docs/secure-code/reports/guard/<id>.md` and `.json`. Raw evidence:
`.x-ipe/private/secure-code/guard/<id>/`. See
[Guard request files](x-ipe-secure-code-toolkit-guard/references/guard-records.md).

## Collaborate with Copilot

During design, implementation, bug fix and refactor work the Copilot skill gives concrete
suggestions from the adopted Policies, and one independent read-only Reviewer checks adoption.
The script records the suggestions, binds them and the Reviewer results to file digests and
publishes numbered report rounds; Copilot never edits business artifacts and gives no pass:

```bash
uvx --from "$FW/scripts" secure-code copilot open --project . --request .x-ipe/private/secure-code/tmp/open.json --json
uvx --from "$FW/scripts" secure-code copilot suggest --project . --id <id> --request .x-ipe/private/secure-code/tmp/suggest.json --json
uvx --from "$FW/scripts" secure-code copilot review --project . --id <id> --request .x-ipe/private/secure-code/tmp/review.json --json
uvx --from "$FW/scripts" secure-code copilot report --project . --id <id> --json
uvx --from "$FW/scripts" secure-code copilot show --project . --id <id>          # stale suggestions after edits
uvx --from "$FW/scripts" secure-code copilot artifacts --project . --id <id> --request .x-ipe/private/secure-code/tmp/artifacts.json
uvx --from "$FW/scripts" secure-code copilot close --project . --id <id>
```

Reports: `x-ipe-docs/secure-code/reports/copilot/<id>-r<n>.md` and `.json` (a new round only when
the state changed; earlier rounds are never modified). Private data:
`.x-ipe/private/secure-code/copilot/<id>/`. Both stay until you remove them. See
[Copilot request files](x-ipe-secure-code-toolkit-copilot/references/copilot-records.md).

## Register Opengrep (Maintainer)

Install the official Opengrep v1.31.0 release yourself (the toolkit never downloads it), then:

```bash
uvx --from "$FW/scripts" secure-code tools register --project . --tool opengrep --path /path/to/opengrep
```

The binary's SHA-256 must match the official release digest for your platform; it is never executed
during registration. Tool runs (`guard tool`) are supported on macOS and Linux; on Windows they are
refused in this version. The tool's caches live in a disposable folder in the system temporary
folder, which must have an ASCII-only path (else set `TMPDIR`; gap `TOOL_HOME_UNSUPPORTED`); see
[Tool run](x-ipe-secure-code-toolkit-guard/references/guard-records.md#tool-run-guard-tool---run-id---request-file).

## Register and provision Trivy (Maintainer)

Trivy v0.76.1 runs only on Linux x86-64/arm64. Install the official static release binary yourself
(the toolkit never downloads it) and register it:

```bash
uvx --from "$FW/scripts" secure-code tools register --project . --tool trivy --path /path/to/trivy
```

Scans are offline and need provisioned components (`vulnerability_db`, `java_db` for image archives,
`checks_bundle` for misconfigurations). Within an open verification the user grants `tool_update` for
every known host of the repository (for `ghcr.io` also `pkg-containers.githubusercontent.com`), then a
Maintainer provisions:

```bash
uvx --from "$FW/scripts" secure-code guard allow-egress --project . --run <id> --purpose tool_update \
  --recipient https://mirror.gcr.io --data metadata --scope https://mirror.gcr.io/aquasec/trivy-db:2 \
  --reason "Trivy vulnerability database"
uvx --from "$FW/scripts" secure-code tools provision --project . --tool trivy --run <id> --component vulnerability_db
uvx --from "$FW/scripts" secure-code tools remove-components --project . --tool trivy --all
```

Components live in `.x-ipe/private/secure-code/tools/trivy-cache/`; `secure-code status` shows their
state, registry, digest, database age and disk use. No staleness threshold is applied: Guard judges
whether the database age is sufficient. See
[Trivy run](x-ipe-secure-code-toolkit-guard/references/guard-records.md#trivy-run-guard-tool---run-id---request-file-adapter-trivy).

## Development

```bash
cd x-ipe-secure-code-toolkit-framework/scripts
uv sync --group dev
uv run pytest --cov=x_ipe_secure_code
uv run ruff check src tests
```

See [CLI contract](x-ipe-secure-code-toolkit-framework/references/cli-contract.md) and
[environments](x-ipe-secure-code-toolkit-framework/references/environments.md).
