"""Unit tests of example blocks: comment table, rendering, strip and marker grammar (drafting_blocks).

AC-001G-04a (renderer), AC-001G-01i (grammar, unit level), FR-001G-5; design Implementation Step 3.
"""

from __future__ import annotations

import pytest
from drafthelp import NOTICE, mod

from x_ipe_secure_code.knowledge.batch import normalize_text

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
SEED = "# human seed example\nrows = run(query, (name,))\n"


def block(lang="python", digest=D1, unsafe="bad()", safe="good()", **notice):
    blocks = mod("drafting_blocks")
    lines = blocks.notice_lines(
        draft_digest=digest,
        sources=[{"kind": "stored_rule_content"}],
        level="syntax_checked",
        decisions=set(blocks.DECISION_ORDER[:3]),
        attestations={"non_normative"},
        acknowledgements=set(),
        confidentiality=notice.get("confidentiality"),
    )
    return blocks.render_block(lang, digest, lines, unsafe, safe)


def test_comment_table_and_supported_list():
    blocks = mod("drafting_blocks")
    assert blocks.COMMENT == {
        "python": "#",
        "java": "//",
        "javascript": "//",
        "typescript": "//",
        "c": "//",
        "cpp": "//",
        "csharp": "//",
        "go": "//",
    }
    assert blocks.SUPPORTED == tuple(sorted(blocks.COMMENT))


def test_rendered_block_shape_and_body_digest():
    blocks = mod("drafting_blocks")
    text = block(confidentiality="internal")
    lines = text.split("\n")
    assert lines[0].startswith(
        f"# >>> x-ipe-ai-supplement v1 kind=example lang=python draft={D1} body=sha256:"
    )
    assert lines[1] == "# " + NOTICE and lines[2] == f"# draft: {D1}"
    assert "# confidentiality: internal" in lines
    assert lines[-2] == f"# <<< x-ipe-ai-supplement v1 end draft={D1}" and lines[-1] == ""
    assert "bad()" in lines and "good()" in lines
    assert lines.index("# --- unsafe example (violates the rule) ---") < lines.index("bad()")
    assert lines.index("# --- safe example (addresses the rule) ---") < lines.index("good()")
    body = "".join(line + "\n" for line in lines[1:-2])
    assert lines[0].endswith(blocks.sha256_text(body))
    found = blocks.scan_markers("example-python.md", text)
    assert [b.state for b in found] == ["intact"]
    assert not any(t in text for t in ("2026-", "approved"))  # no approval time or late-bound value


# AC-001G-04a: stripped(result) == stripped(current) for create, append and replace.
@pytest.mark.parametrize(
    "current", [None, SEED, SEED + "\n" + "{old}", "{old}", SEED + "\n" + "{old}" + "# later\n"]
)
def test_04a_stripped_result_equals_stripped_current(current):
    blocks = mod("drafting_blocks")
    old = block(digest=D2, unsafe="older()")
    current = None if current is None else current.replace("{old}", old)
    new_block = block()
    result = blocks.render_file(current, new_block)
    assert blocks.strip(result) == (blocks.strip(current) if current else "")
    assert normalize_text(result) == result
    assert result.endswith(new_block)
    assert [b.draft_digest for b in blocks.scan_markers("example-python.md", result)] == [D1]


def test_strip_of_block_only_file_is_empty():
    blocks = mod("drafting_blocks")
    assert blocks.strip(block()) == ""
    assert blocks.render_file(None, block()) == block()
    assert blocks.render_file(SEED, block()) == SEED + "\n" + block()


def test_modified_body_is_reported_modified():
    blocks = mod("drafting_blocks")
    text = block().replace("good()", "good(edited)")
    assert [b.state for b in blocks.scan_markers("example-python.md", text)] == ["modified"]


# AC-001G-01i (unit): malformed, nested, duplicated, unterminated, inside non-AI text; file + 1-based line.
def grammar_cases():
    good = block()
    lines = good.split("\n")
    java = block("java")
    return {
        "malformed": (SEED + "# >>> x-ipe-ai-supplement v2 kind=example\n", "example-python.md", 3),
        "nested": ("\n".join(lines[:2] + [lines[0]] + lines[1:]), "example-python.md", 3),
        "duplicated": (good + "\n" + block(digest=D2), "example-python.md", len(lines) + 1),
        "unterminated": (SEED + "\n" + "\n".join(lines[:-2]) + "\n", "example-python.md", 4),
        "end_without_begin": (SEED + lines[-2] + "\n", "example-python.md", 3),
        "end_draft_mismatch": (
            good.replace(f"end draft={D1}", f"end draft={D2}"),
            "example-python.md",
            len(lines) - 1,
        ),
        "wrong_comment_token": (java.replace("// ", "# ", 1), "example-java.md", 1),
        "wrong_language": (good, "example-java.md", 1),
        "inside_non_ai_content": ("Rule text.\n" + good, "content.md", 2),
        "inside_general_example": (good, "example.md", 1),
        "unsupported_language_file": (good.replace("lang=python", "lang=ruby"), "example-ruby.md", 1),
        "case_insensitive_markerish": (SEED + "# X-IPE-AI-SUPPLEMENT mention\n", "example-python.md", 3),
    }


@pytest.mark.parametrize("case", sorted(grammar_cases()))
def test_01i_grammar_cases(case):
    blocks = mod("drafting_blocks")
    text, name, line = grammar_cases()[case]
    with pytest.raises(blocks.MarkerError) as caught:
        blocks.scan_markers(name, text)
    assert caught.value.file == name and caught.value.line == line, caught.value.reason


def test_draft_parts_with_marker_lines_refused_naming_part():
    blocks = mod("drafting_blocks")
    with pytest.raises(blocks.MarkerError) as caught:
        blocks.check_part("python", "safe", "ok()\n# x-ipe-ai-supplement trick")
    assert caught.value.file == "examples.python.safe" and caught.value.line == 2


def test_notice_fields_parse_back():
    blocks = mod("drafting_blocks")
    lines = blocks.notice_lines(
        draft_digest=D1,
        sources=[
            {"kind": "not_retrieved", "url": "https://cwe.mitre.org/top25/", "reason": "HTTP 403"},
            {
                "kind": "fetched",
                "url": "https://cwe.mitre.org/data/definitions/89.html",
                "fetched_at": "2026-10-23T11:58:02Z",
                "http_status": 200,
                "body_sha256": D2,
                "attribution": {
                    "title": "CWE-89",
                    "url": "https://cwe.mitre.org/data/definitions/89.html",
                    "licence": "CWE Terms of Use",
                },
            },
        ],
        level="not_syntax_validated",
        decisions={
            "unsafe_violates_rule",
            "safe_addresses_rule",
            "language_correct",
            "unchecked_syntax_understood",
        },
        attestations={"non_normative", "licence_and_original_wording"},
        acknowledgements={"example_commands_acknowledged"},
        confidentiality=None,
    )
    text = blocks.render_block("java", D1, lines, "a();", "b();")
    found = blocks.scan_markers("example-java.md", text)[0]
    fields = blocks.parse_notice(found)
    assert fields["validation_level"] == "not_syntax_validated"
    assert fields["decisions"] == [
        "unsafe_violates_rule",
        "safe_addresses_rule",
        "language_correct",
        "unchecked_syntax_understood",
    ]
    assert fields["attestations"] == ["non_normative", "licence_and_original_wording"]
    assert fields["acknowledgements"] == ["example_commands_acknowledged"]
    assert fields["sources"][0].startswith("source page not retrieved; drafted from the stored rule")
    assert "sha256" not in fields["sources"][0]
    assert fields["confidentiality"] is None
