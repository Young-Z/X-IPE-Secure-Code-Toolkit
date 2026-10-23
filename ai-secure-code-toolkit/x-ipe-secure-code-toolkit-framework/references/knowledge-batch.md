# Knowledge Batch, Check and Update Formats

## Batch (`secure-code knowledge import --batch FILE`)

```json
{
  "schema": "ai-secure-code-toolkit/knowledge-batch/v1",
  "expected_count": 2,
  "items": [
    {
      "namespace": "CWE",
      "version": "4.14",
      "rule_id": "CWE-79",
      "name": "Improper Neutralization of Input During Web Page Generation",
      "source_location": "https://cwe.mitre.org/data/definitions/79.html",
      "source_document_digest": "sha256:<64 hex of the source document>",
      "content": "Markdown body of the rule",
      "examples": {"general": "…", "python": "…"},
      "applicability": ["python", "javascript"],
      "relations": ["CWE/4.14/CWE-80"]
    }
  ]
}
```

- Exactly one identity per item: `namespace`, `version`, `rule_id` - each 1-100 characters from
  `A-Z a-z 0-9 . _ -`, not starting/ending with a dot, not a Windows device name (`CON`, `NUL`,
  `COM1`…). Custom namespaces start with `@` and need a `name`.
- Several rule sets of one institution are distinguished in `version` (e.g. `ASVS-4.0.3`).
- `content` is required; examples are optional (`general` or a lowercase language);
  `applicability` is advisory (missing = unknown); `relations` are references only.
- One item may hold at most 1 MiB of text. Unknown fields are refused.
- Text is normalized to `\n` line endings with one trailing newline before digesting.

## Check (`secure-code knowledge check --input FILE`)

```json
{
  "schema": "ai-secure-code-toolkit/knowledge-check/v1",
  "items": [{"rule": "CWE/4.14/CWE-79", "item_digest": "sha256:…"}],
  "source_documents": ["sha256:…"]
}
```

Item digests are returned by `import` and `show`. Results: items `stored_unchanged | stored_changed
| new`; documents `fully_stored | not_fully_stored`.

## Update (`secure-code knowledge update --input FILE`)

```json
{
  "schema": "ai-secure-code-toolkit/knowledge-update/v1",
  "content": "New body",
  "examples": {"python": "new example", "java": null},
  "applicability": ["python"]
}
```

Any of `name`, `source_location`, `content`, `examples` (`null` deletes that example),
`applicability`, `relations`. Identity cannot change here (renaming is a knowledge exit).
`--base-state` is the rule's `state_digest` from `show`/`list` (item digest plus lifecycle
revision), so an update prepared before a deactivation or reactivation is refused as stale.

## Exited and deactivated identities

Import refuses an item whose identity is deactivated (`RULE_DEACTIVATED`: reactivate it first)
or was deleted or renamed away, also when it differs only in letter case (`IDENTITY_RESERVED`).
Other items of the batch follow the normal partial-import rules.

## Pre-check

Suspected real credentials (private keys, cloud keys, tokens, password/secret/token assignments)
and embedded operating instructions (agent prompt overrides; destructive shell commands in the
rule body) hold an item as `needs_decision`. Values are never printed; each finding has a
fingerprint. Clearly marked placeholders whose whole value is a template (`<your-password>`,
`${VAR}`, `changeme`, `xxxx`, `redacted`, the documented AWS example keys) are informational notes.
