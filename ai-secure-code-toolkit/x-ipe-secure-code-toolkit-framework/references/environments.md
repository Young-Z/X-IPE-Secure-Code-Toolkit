# Agent Environments

The calling agent passes its environment explicitly with `--env`; nothing is auto-detected.

| Environment | Skills folder | Host entry file | Verified host in MVP |
|---|---|---|---|
| `github-copilot` | `.github/skills/` | `AGENTS.md` | yes |
| `claude-code` | `.claude/skills/` | `CLAUDE.md` | no |

## Host entry fragment

Initialization keeps exactly one toolkit-owned fragment in the host entry file, delimited by:

```text
<!-- BEGIN ai-secure-code-toolkit: managed fragment, edits are reported not overwritten -->
...
<!-- END ai-secure-code-toolkit -->
```

- Missing file: created with only the fragment.
- No fragment: appended after a blank line; existing bytes stay identical; the file's newline
  style (LF or CRLF) is used.
- Unchanged fragment: nothing is written.
- Fragment edited by a user: kept and reported (`FRAGMENT_EDITED`); replaced only with
  `--replace <host entry file>`.
- Unmatched, reversed or duplicate markers: refused, nothing written.
- Content outside the fragment is never modified.

## Symbolic links are refused

Initialization never writes through a symbolic link. If the host entry file, the skills folder,
`x-ipe-docs/secure-code/`, `.x-ipe/` or any folder on those paths is a symbolic link - even one
pointing inside the project, such as `CLAUDE.md -> AGENTS.md` - initialization refuses with
`PATH_UNSAFE` and writes nothing. Replace the link with a regular file or folder and run it
again. Support for links that stay inside the project is a tracked open item.

## Integration carriers (FEATURE-003-B)

`secure-code carriers --project PATH --env ENV` generates and checks the toolkit's host
integration carriers. Every carrier is rendered from one routing definition and states the same
routing identity; together they are one integration declaration.

| Carrier | `github-copilot` | `claude-code` | Default | Managed boundaries |
|---|---|---|---|---|
| `host-entry` | `AGENTS.md` | `CLAUDE.md` | always (the fragment that `init` writes) | the marker-delimited fragment |
| `github-instructions` | `.github/instructions/x-ipe-secure-code-toolkit.instructions.md` | not supported | `--select` | the exact front matter at file start and the marker-delimited body |
| `system-prompt` | `.x-ipe/private/secure-code/carriers/system-prompt.md` | same | `--select` with `--system-prompt-host NAME` | the marker-delimited fragment |

- The GitHub instructions file starts with exactly this toolkit-owned front matter (see below). A
  removed, altered or moved front matter is reported as front-matter drift and kept;
  `--regenerate github-instructions` restores it at file start. Text you add outside the two
  managed boundaries is yours and is reported as user content, never changed.
- The system-prompt fragment is also shown in the result. Adding it to a host is your manual step;
  the toolkit never changes host, global or user-level configuration. Its folder holds no key,
  trust or authorization material.
- The selection is stored in the install record; a later run without `--select` checks the stored
  set again. `--deselect KIND` (or a `--select` list without it) leaves the file in place and reports
  it as "no longer managed"; the toolkit never deletes a carrier.
- `carriers` writes only the selected carrier files and the install record. It never writes the
  skills folder; a missing or invalid installed skill or routing definition is refused with
  `secure-code init` as the next step.
- Carriers are files. The toolkit checks files, boundaries and the front matter only; it never
  verifies that a host reads them (host effect: not verified).

Exact front matter of the GitHub instructions file (GitHub Copilot path-specific instructions):

```text
---
applyTo: "**"
---
```

## Routing definition

`x-ipe-secure-code-toolkit-framework/references/routing-definition.json` (schema
`ai-secure-code-toolkit/routing-definition/v1`) holds, once, the routing statements: Copilot for
design, implementation, bug fix and refactor work; Guard only on an explicit or authorized
verification request; one flow per stage and context; failed or old reports never count as done;
roles only from actual verification; the minimal handoff; pointers to the three skills and the
status command. Its identity is the running toolkit version plus the SHA-256 of the definition's
canonical JSON. A Maintainer may edit the installed copy; `init` keeps the edit (reported as locally
edited) and every carrier renders from it. An edit that breaks the validity rules (exact keys and
sections, no line breaks, markers, braces, absolute paths or credential-like text) makes `carriers`
refuse with `ROUTING_DEFINITION_INVALID`.

## Differences and choices

A toolkit fragment (or front matter) that differs from both the recorded and the current toolkit
rendering is kept and reported on every run and in status, with a secret-masked difference
(`[masked:<kind>]` markers; pattern-based masking, not a complete data-loss-prevention guarantee)
and the choices: keep (default), modify then keep or accept, change the routing definition,
`--regenerate KIND`, `--accept KIND`. An accepted customization is reported as "customized
(accepted) — not synced with the routing definition"; it is reported again as a difference when the
fragment or the routing identity changes. Plain `init` honours only an exactly matching accepted
host-entry customization (it reports `customized`, never current) and replaces it only with an
explicit `--replace <host entry file>`, which lapses the acceptance.

## Install record `carriers` member

The install record keeps the `install-record/v1` schema. It gains one optional `carriers` member
(the stored selection, per-carrier digests and routing identity, any accepted customization); the
top-level `host_entry` and `fragment_sha256` stay authoritative for the host entry. The member is
omitted while no optional carrier or customization is recorded, so such records are byte-equal to
FEATURE-001-A records. One install record covers one environment: `carriers` with another
environment is refused (`ENV_MISMATCH`), and `init` switching the environment drops the member.

Toolkit versions before the carriers operation cannot read an install record that holds the
`carriers` member and refuse it with `RECORD_INVALID`; there is no forward compatibility.

## Project lock and platforms

`init` and `carriers` run under a file-free lock on the project root folder (`flock`; no lock file
is ever created). A run that cannot take it waits up to 10 seconds, then refuses with `LOCKED` and
writes nothing. On platforms or file systems where that lock is not available, including Windows,
`carriers` currently refuses with `LOCK_UNAVAILABLE` and writes nothing; this is an open gap pending a
decision (B11), not a statement about supported platforms. Plain `init` there behaves exactly as
before, without the lock.
