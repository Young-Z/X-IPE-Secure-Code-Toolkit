# Reference Knowledge (FEATURE-001-E)

Reference rules are Maintainer-registered **pointers** to maintained external sources (for example
the CWE Top 25 or the OWASP Top 10): an identity `NAMESPACE/VERSION/RULE_ID`, a title and an entry
URL. No rule body is stored. The requirement text is fetched on request inside a Guard verification,
cached privately for 7 days and offered as a Policy through the normal `policy resolve` path.

## Registration (Maintainer)

`secure-code knowledge reference register --project P --batch FILE` with:

```json
{"schema": "ai-secure-code-toolkit/reference-batch/v1",
 "items": [
   {"type": "source", "namespace": "CWE", "version": "2024-top25", "domains": ["127.0.0.1"],
    "scheme": "http", "port": 8123, "path_prefix": "/docs/cwe/", "display_name": "CWE Top 25 (2024)"},
   {"type": "rule", "rule": "CWE/2024-top25/CWE-79", "title": "Cross-site Scripting",
    "entry_url": "http://127.0.0.1:8123/docs/cwe/79.html", "applicability": "unknown"}]}
```

- Items are processed in order and each is validated and written on its own; the result lists every
  item as `registered` or `refused` with a code and reason. Unknown fields are refused.
- A source registers its domains (lower-case IDNA A-labels without a trailing dot), its scheme
  (`https`; `http` only when every domain is exactly `127.0.0.1`), an optional port and an optional
  path prefix that starts and ends with `/`.
- A rule's entry URL must pass the target checks below against its source. The title is one line of
  at most 300 characters without credential-like values; applicability is `unknown` or a list of
  language names (advisory).
- Identities that already exist (also by letter case) are refused `IDENTITY_COLLISION`; identities
  of deleted or renamed Local rules are refused `IDENTITY_RESERVED`.
- `update` (with the current `--registration-digest` from `show`) and the two-step removal
  (`remove-preview`, then `remove-confirm` with `--impact-digest` and `--registration-digest`)
  invalidate the cache entries of the old registration first. A removed rule is reported `deleted`
  wherever it is referenced; references elsewhere are not edited. `remove-source` is refused while
  rules of the source remain.

Layout: `x-ipe-docs/secure-code/knowledge/reference/<NS>/<VER>/.source.json`,
`<NS>/<VER>/.changelog.md`, `<NS>/<VER>/<RULE_ID>/reference.json` and `.removed.json`
(tombstones). The status Policies count includes registered Reference rules; status adds the line
"Reference rules: registered N, available M" when Reference rules exist.

## Target checks

Every target is first checked by the toolkit's canonical-URL rules (no user information, query,
fragment, encoded separators, backslashes or dot segments; their delivered reasons are reported).
Then, in this order:

1. the scheme equals the registered scheme (`scheme_not_allowed`);
2. the host equals a registered domain or is a subdomain of it at a label boundary
   (`unregistered_host`; a subdomain never authorizes its parent); the only IP literal is the exact
   `127.0.0.1` (`ip_literal_not_allowed`);
3. the port equals the registered port, or the scheme default when none is registered
   (`port_not_registered`);
4. the decoded path equals or starts with the registered path prefix (`path_not_registered`).

In this version only `http://127.0.0.1[:port]/…` is fetched. Any other host is refused
`real_fetch_parked` and a registered `https://127.0.0.1` target is refused `scheme_not_allowed`,
both before any name resolution, connection or egress authorization (human item P-01: real domains,
HTTPS, certificates and connection pinning are decided before enablement).

## Fetching (inside a Guard verification)

1. Open a Guard verification on an available scope (for example a Local scope).
2. The User grants the purpose at their own terminal:
   `secure-code guard allow-egress --run V --purpose reference_fetch --recipient http://127.0.0.1:8123
   --data public_query --scope http://127.0.0.1:8123/docs/cwe/ --reason "..."`.
3. `secure-code knowledge reference fetch --run V --rule CWE/2024-top25/CWE-79 [--refresh]`.
4. Conclude the verification, resolve and save a scope adopting the Reference Policy, then open a
   new verification with it.

A formal Local rule with the same identity always wins: when usable it is used and nothing is
fetched (`local_used`); when broken or exited its problem is reported (`LOCAL_FIRST_BROKEN`) and the
Reference is not substituted. Every fetch is one body-less GET through the Guard egress gate with a
single-use authorization bound to the exact URL; only the URL and fixed toolkit headers are sent.
Redirects are never followed (`redirect_not_followed`), only `text/html`, `text/plain` and
`text/markdown` without content encoding are accepted, and at most 20 fetches are made per
verification (`fetch_cap_reached`). A fetch without `--run` is refused `RUN_REQUIRED`: a library
with only Reference rules cannot start this in this version (human item B16).

`explore --run V --source NS/VER --url URL` returns one registered-domain page as untrusted text and
classifies its links as `registered_candidate`, `outside_registered_domains_not_followed` or
`invalid_url_not_followed`. No link is ever fetched; credential-like or invalid link URLs are
omitted (`url: null`).

## Results and reasons

A Reference Policy carries `knowledge_kind: reference`, `content_label: untrusted_external`, the
masked requirement text and source evidence: entry URL, `fetched_at`, `expires_at`,
`response_digest` (received bytes), `policy_state_digest` (identity, title, applicability, entry URL,
parser version and the normalized requirement text only), registration digest, parser version and
cache state. A scope adopts the `policy_state_digest`: a change of the requirement text needs
re-confirmation; a change of other page bytes (for example navigation) does not.

`missing` reasons: `not_cached`, `cache_expired`, `cache_invalid`, `refresh_failed`,
`real_fetch_parked`, `parse_failed`, `deleted`, `unreadable`. Fetch failure details: `timeout`,
`connection_failed`, `header_invalid`, `http_status`, `redirect_not_followed`, `size_limit`,
`content_type_not_allowed`, `content_encoding_not_allowed`, `decode_failed`, `parse_failed`.

## Cache

`.x-ipe/private/secure-code/reference-cache/` (owner-only). An entry is valid from the successful
fetch for exactly 7 days; reading never renews it. `--refresh` fetches again; a failed refresh is
reported `refresh_failed` and never hidden by the older copy (an unexpired older copy is kept and is
used only by a later request without `--refresh`). Entries in the future, with a wrong digest or
schema are `cache_invalid`. `cache-clean` removes expired, invalid and orphaned entries and stale
temporary files only. The cache capacity is 64 MiB: expired entries are evicted first; a result
that does not fit is returned but not cached (`cache_not_written: capacity`). The cache never
becomes formal knowledge.

## Honest limits

Real domains are not fetched in this version (P-01); a Reference-only library cannot bootstrap
(B16); IPv4 loopback only; visibility set by stylesheets is not evaluated; IDNA uses the platform
codec; credential masking is pattern-based; a valid cache entry does not prove the source page is
unchanged.
