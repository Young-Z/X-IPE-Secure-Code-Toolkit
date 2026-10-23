"""Integration tests of `knowledge draft-check` (FEATURE-001-G; design Implementation Step 8).

AC-001G-01a, 01b, 01c, 01i, 03c, 03h, 03i, 03j, 04d, 05c, 09f; R3, R17. In-process CLI (`--json`)
with this test's own trust root; draft files live in the disposable project's drafts folder.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import sys

import pytest
from drafthelp import (
    DRAFTS,
    JAVA,
    NOTICE,
    PY,
    QUOTE,
    R78,
    R89,
    DEnv,
    dump,
    mod,
    sha,
)

from x_ipe_secure_code.knowledge import precheck
from x_ipe_secure_code.policy import service as policy

PASSWORD = "Tr0ub4dor" + "&3xyz"


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path)


def problem_codes(out):
    return [p["code"] for p in out["problems"]]


def stdlib_diff(old, new, name):
    lines = difflib.unified_diff(
        (old or "").splitlines(True),
        new.splitlines(True),
        "/dev/null" if old is None else f"a/{name}",
        f"b/{name}",
    )
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


# AC-001G-01a
def test_01a_valid_report_preview_digest_and_review_incomplete_read_only(env):
    draft, review = env.drafted()
    before = env.tree()
    code, out = env.cli_check(draft, review)
    assert code == 0 and out["ok"], out
    data = out["data"]
    assert data["status"] == "valid" and data["base"] == "current"
    assert set(data["checks"]) == {
        "target",
        "markers",
        "shape",
        "preservation",
        "precheck",
        "provenance",
        "review",
    }
    assert all(v == "passed" for v in data["checks"].values()), data["checks"]
    assert data["languages"]["python"]["level"] == "syntax_checked"
    assert data["languages"]["python"]["decision"] == "complete"
    assert data["preview"]["final"] is True
    report = mod("drafting_pipeline").run(env.project, str(draft), str(review))
    payload = report.payload
    old = env.rule_files()["example-python.md"].decode()
    assert data["preview"]["masked_diff"] == stdlib_diff(
        old, payload["example-python.md"], "example-python.md"
    )
    key = precheck.read_key(env.project)
    body = {
        "schema": "ai-secure-code-toolkit/knowledge-draft-validation/v1",
        "validator_version": f"001g.1/py{sys.version_info.major}.{sys.version_info.minor}",
        "rule": R89,
        "base_state": env.state(),
        "draft_digest": sha(draft.read_bytes()),
        "review_digest": sha(review.read_bytes()),
        "precheck_key_id": hmac.new(key, b"x-ipe-secure-code/001g/key-id", hashlib.sha256).hexdigest()[:16],
        "payload": payload,
    }
    expected = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )
    assert (
        data["validation_digest"] == expected == env.cli_check(draft, review)[1]["data"]["validation_digest"]
    )
    assert data["non_normative_statement"] == NOTICE
    code, out = env.cli_check(draft)
    assert code == 1 and out["data"]["status"] == "review_incomplete"
    assert out["data"]["preview"]["final"] is False and out["data"]["validation_digest"] is None
    assert problem_codes(out)[0] == "REVIEW_INCOMPLETE"
    assert out["data"]["review_required"]["examples"]["python"] == [
        "unsafe_violates_rule",
        "safe_addresses_rule",
        "language_correct",
    ]
    assert out["data"]["review_required"]["attestations"] == ["non_normative"]
    assert env.tree() == before


# AC-001G-01b: replacement/identity fields refused, named, nothing written (check and approve).
@pytest.mark.parametrize(
    "field",
    [
        "content",
        "examples-text",
        "name",
        "source_location",
        "applicability",
        "relations",
        "namespace",
        "version",
        "rule_id",
        "source_document_digest",
    ],
)
def test_01b_forbidden_fields_refused_draft_invalid(env, field):
    if field == "examples-text":
        doc, named = env.draft_doc(examples={"python": "print('x')\n"}), "examples.python"
    else:
        doc, named = env.draft_doc(**{field: "x"}), f"'{field}'"
    draft = env.write_draft(doc)
    review = env.write_review(
        draft,
        {
            "schema": "ai-secure-code-toolkit/knowledge-draft-review/v1",
            "draft_digest": sha(draft.read_bytes()),
        },
    )
    before = env.tree()
    for code, out in (env.cli_check(draft, review), env.cli_approve(draft, review, "sha256:" + "0" * 64)):
        assert code == 1 and problem_codes(out) == ["DRAFT_INVALID"], out
        assert named in out["problems"][0]["message"]
    assert env.tree() == before


# AC-001G-09f: explanation field refused (B13 = H2), check and approve, nothing written.
def test_09f_explanation_field_refused_check_and_approve(env):
    draft = env.write_draft(env.draft_doc(explanation="Risk: attackers can read every table."))
    review = env.write_review(
        draft,
        {
            "schema": "ai-secure-code-toolkit/knowledge-draft-review/v1",
            "draft_digest": sha(draft.read_bytes()),
        },
    )
    before = env.tree()
    for code, out in (env.cli_check(draft, review), env.cli_approve(draft, review, "sha256:" + "0" * 64)):
        assert code == 1 and problem_codes(out) == ["DRAFT_INVALID"]
        assert "'explanation'" in out["problems"][0]["message"]
    assert env.tree() == before


# AC-001G-01c: drafts are invisible to every reader.
def test_01c_draft_invisible_to_readers(env):
    saved = env.save(env.decisions((R89, R78)))
    assert saved.ok, saved.to_dict()
    scope_id = saved.data["scope_id"]
    p = str(env.project)

    def outputs():
        result = {}
        for name, args in (
            ("resolve", ["policy", "resolve", "--project", p, "--rule", R89]),
            ("scope", ["scope", "show", "--project", p, "--scope", scope_id]),
            ("show", ["knowledge", "show", "--project", p, "--rule", R89]),
            ("list", ["knowledge", "list", "--project", p]),
            ("links", ["knowledge", "links", "--project", p]),
        ):
            result[name] = json.dumps(env.cli(*args))
        result["guard_policy_load"] = json.dumps(policy.load_adopted(env.project, scope_id, "guard open"))
        return result

    without = outputs()
    draft, review = env.drafted()
    assert env.check(draft, review).ok
    with_draft = outputs()
    assert with_draft == without
    assert "x-ipe-ai-supplement" not in "".join(with_draft.values())
    assert (env.project / DRAFTS).is_dir()


# AC-001G-01i: malformed existing markers refused (check and approve), human text untouched.
def malformed_cases(blocks):
    lines = blocks.render_block(
        "python",
        "sha256:" + "1" * 64,
        blocks.notice_lines(
            draft_digest="sha256:" + "1" * 64,
            sources=[{"kind": "stored_rule_content"}],
            level="syntax_checked",
            decisions=set(),
            attestations=set(),
            acknowledgements=set(),
            confidentiality=None,
        ),
        "bad()",
        "good()",
    ).split("\n")
    seed = "# human example\nrun()\n"
    good = "\n".join(lines)
    return {
        "malformed": ("examples", seed + "# >>> x-ipe-ai-supplement v9\n", "example-python.md", 3),
        "nested": ("examples", "\n".join(lines[:2] + [lines[0]] + lines[1:]), "example-python.md", 3),
        "duplicated": ("examples", good + "\n" + good, "example-python.md", len(lines) + 1),
        "unterminated": ("examples", seed + "\n".join(lines[:-2]) + "\n", "example-python.md", 3),
        "inside_non_ai": ("content", f"- {QUOTE}, never by string concatenation.\n" + good, "content.md", 2),
    }


@pytest.mark.parametrize("case", ["malformed", "nested", "duplicated", "unterminated", "inside_non_ai"])
def test_01i_malformed_markers_refused(env, case):
    kind, text, name, line = malformed_cases(mod("drafting_blocks"))[case]
    changes = {"content": text} if kind == "content" else {"examples": {"python": text}}
    assert env.update(R89, env.state(), **changes).ok
    draft, review = env.drafted()
    before, files = env.tree(), env.rule_files()
    for code, out in (env.cli_check(draft, review), env.cli_approve(draft, review, "sha256:" + "0" * 64)):
        assert code == 1 and problem_codes(out) == ["SUPPLEMENT_MARKERS_INVALID"], out
        assert f"{name}:{line}" in out["problems"][0]["message"], out["problems"]
    assert env.tree() == before and env.rule_files() == files


# AC-001G-03c: non-Python examples need "unchecked syntax understood"; the decision is in the notice.
@pytest.mark.parametrize("lang", ["java", "javascript", "c"])
def test_03c_non_python_needs_unchecked_syntax_decision(env, lang):
    example = (
        dict(JAVA)
        if lang == "java"
        else {"unsafe": "run(query + name);", "safe": "run(query, [name]);", "demonstrates": [QUOTE]}
    )
    draft = env.write_draft(env.draft_doc(examples={lang: example}), f"cwe-89--{lang}")
    without = env.write_review(
        draft, env.review_doc(draft, {lang: env.decision(lang, drop=("unchecked_syntax_understood",))})
    )
    code, out = env.cli_check(draft, without)
    assert code == 1 and out["data"]["languages"][lang]["level"] == "not_syntax_validated"
    assert problem_codes(out) == ["EXAMPLE_DECISION_MISSING"]
    assert f"examples.{lang}.unchecked_syntax_understood" in out["problems"][0]["message"]
    with_decision = env.write_review(draft)
    code, out = env.cli_check(draft, with_decision)
    assert code == 0, out
    assert (
        "maintainer decisions: unsafe_violates_rule, safe_addresses_rule, language_correct, "
        "unchecked_syntax_understood" in out["data"]["preview"]["masked_diff"]
    )
    assert "validation: not_syntax_validated (not executed)" in out["data"]["preview"]["masked_diff"]


# AC-001G-03h: per-language results; valid only as a conjunction.
def test_03h_per_language_results_conjunction(env):
    draft = env.write_draft(env.draft_doc(examples={"python": dict(PY), "java": dict(JAVA)}), "cwe-89--two")
    partial = env.write_review(
        draft,
        env.review_doc(
            draft,
            {"python": env.decision("python"), "java": env.decision("java", drop=("language_correct",))},
        ),
    )
    code, out = env.cli_check(draft, partial)
    languages = out["data"]["languages"]
    assert code == 1 and out["data"]["status"] == "review_incomplete"
    assert languages["python"]["level"] == "syntax_checked" and languages["python"]["decision"] == "complete"
    assert languages["java"]["level"] == "not_syntax_validated"
    assert languages["java"]["decision"] == {"missing": ["language_correct"]}
    complete = env.write_review(draft)
    code, out = env.cli_check(draft, complete)
    assert code == 0 and out["data"]["status"] == "valid"
    bad = dict(PY, unsafe="def broken(:")
    draft = env.write_draft(env.draft_doc(examples={"python": bad, "java": dict(JAVA)}), "cwe-89--two")
    code, out = env.cli_check(draft, env.write_review(draft))
    assert code == 1 and out["data"]["status"] == "invalid"
    assert out["data"]["languages"]["python"]["level"] == "invalid_syntax"
    assert out["data"]["languages"]["java"]["results"] == []
    assert problem_codes(out)[0] == "DRAFT_CHECK_FAILED" and "python" in out["problems"][0]["message"]


# AC-001G-03i: placeholders → notes only; literal → masked finding, value printed nowhere.
def test_03i_placeholders_notes_literal_finding_masked(env):
    unsafe = 'password = "<your-password>"\ntoken = "${DB_PASSWORD}"\nsecret = "changeme"\n' + PY["unsafe"]
    draft = env.write_draft(env.draft_doc(examples={"python": dict(PY, unsafe=unsafe)}))
    code, out = env.cli_check(draft, env.write_review(draft))
    findings = out["data"]["precheck"]["findings"]
    assert code == 0 and findings and all(not f["blocking"] for f in findings)
    assert {f["type"] for f in findings} == {"note.placeholder"}
    unsafe = f'password = "{PASSWORD}"\n' + PY["unsafe"]
    draft = env.write_draft(env.draft_doc(examples={"python": dict(PY, unsafe=unsafe)}))
    review = env.write_review(draft)
    result = env.check(draft, review)
    findings = result.data["precheck"]["findings"]
    blocking = [f for f in findings if f["blocking"]]
    assert [f["type"] for f in blocking] == ["credential.assignment"]
    assert set(blocking[0]) == {"type", "file", "line", "fingerprint", "blocking"}
    printed = dump(result) + json.dumps(env.cli_check(draft, review)[1])
    assert PASSWORD not in printed
    assert f"[REDACTED:{blocking[0]['fingerprint']}]" in result.data["preview"]["masked_diff"]


# AC-001G-03j: missing items named; complete decisions bound into the digest and the notice.
def test_03j_example_decision_missing_items_digest_binding(env):
    draft = env.write_draft(env.draft_doc())
    partial = env.write_review(draft, env.review_doc(draft, {"python": {"unsafe_violates_rule": True}}))
    code, out = env.cli_check(draft, partial)
    assert code == 1 and problem_codes(out) == ["EXAMPLE_DECISION_MISSING"]
    for item in ("examples.python.safe_addresses_rule", "examples.python.language_correct"):
        assert item in out["problems"][0]["message"]
    complete = env.review_doc(draft)
    first = env.cli_check(draft, env.write_review(draft, complete))[1]
    complete["examples"]["python"]["example_commands_acknowledged"] = False
    second = env.cli_check(draft, env.write_review(draft, complete))[1]
    assert first["data"]["validation_digest"] and second["data"]["validation_digest"]
    assert first["data"]["validation_digest"] != second["data"]["validation_digest"]
    assert (
        "maintainer decisions: unsafe_violates_rule, safe_addresses_rule, language_correct"
        in first["data"]["preview"]["masked_diff"]
    )


# AC-001G-04d: the non-normative attestation is required, bound and named in the notice.
def test_04d_attestation_missing_and_named_in_notice(env):
    draft = env.write_draft(env.draft_doc())
    code, out = env.cli_check(draft, env.write_review(draft, attest={}))
    assert code == 1 and problem_codes(out) == ["ATTESTATION_MISSING"]
    assert "non_normative" in out["problems"][0]["message"]
    code, out = env.cli_check(draft, env.write_review(draft))
    assert code == 0 and "maintainer attestations: non_normative" in out["data"]["preview"]["masked_diff"]


# AC-001G-05c: a not_retrieved source is accepted; the notice says so and carries no digest.
def test_05c_not_retrieved_notice_no_digest(env):
    source = {
        "kind": "not_retrieved",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
        "reason": "HTTP 403 from the host agent fetch",
    }
    draft = env.write_draft(env.draft_doc(sources=[source]))
    review = env.write_review(draft)
    code, out = env.cli_check(draft, review)
    assert code == 0, out
    line = next(ln for ln in out["data"]["preview"]["masked_diff"].splitlines() if "source:" in ln)
    assert "source page not retrieved; drafted from the stored rule" in line and "sha256" not in line
    assert out["data"]["provenance"] == [
        {"kind": "not_retrieved", "url": source["url"], "result": "not_retrieved"}
    ]
    code, out = env.cli_approve(draft, review, out["data"]["validation_digest"])
    assert code == 0, out
    text = env.rule_files()["example-python.md"].decode()
    assert "source page not retrieved; drafted from the stored rule" in text


# R3: read-only forms refuse while an exit is pending; they never recover.
@pytest.mark.parametrize("form", ["draft-check", "supplements", "drafting-authorize --list"])
def test_recovery_pending_refused_read_only_forms(env, form):
    draft, review = env.drafted()
    env.interrupt_exit()
    before = env.tree()
    p = str(env.project)
    args = {
        "draft-check": ["knowledge", "draft-check", "--project", p, "--draft", str(draft)],
        "supplements": ["knowledge", "supplements", "--project", p],
        "drafting-authorize --list": ["knowledge", "drafting-authorize", "--project", p, "--list"],
    }[form]
    code, out = env.cli(*args)
    assert code == 1 and problem_codes(out) == ["RECOVERY_PENDING"]
    assert "secure-code knowledge list" in out["next_steps"][0]
    assert env.tree() == before


# R17: read-only commands open no session or lock and create no private folder.
def test_read_only_commands_open_no_session_or_lock(project, tmp_path):
    env = DEnv(project, tmp_path)
    locks = env.project / ".x-ipe/private/secure-code/locks"
    if locks.exists():
        for child in locks.iterdir():
            child.unlink()
        locks.rmdir()
    draft, review = env.drafted()
    before = env.tree()
    p = str(env.project)
    env.cli_check(draft, review)
    env.cli("knowledge", "supplements", "--project", p)
    env.cli("knowledge", "drafting-authorize", "--project", p, "--list", "--host", "fixture-host")
    assert env.tree() == before and not locks.exists()
    assert not (env.project / ".x-ipe/private/secure-code/drafting-staging").exists()


# AC-001G-03k (integration): a command finding needs the per-example acknowledgement (or a harmless
# placeholder); the wording never claims that the delivered pre-check enforced it.
def test_03k_command_acknowledgement_required_and_recorded(env):
    draft = env.write_draft(
        env.draft_doc(examples={"python": dict(PY, unsafe="import os\nos.system('rm -rf ' + path)")})
    )
    review = env.write_review(draft)
    code, out = env.cli_check(draft, review)
    assert code == 1 and problem_codes(out) == ["EXAMPLE_DECISION_MISSING"]
    assert "examples.python.example_commands_acknowledged" in out["problems"][0]["message"]
    findings = out["data"]["command_findings"]
    assert [(f["part"], f["line"], f["pattern"]) for f in findings] == [("unsafe", 2, "rm_recursive")]
    assert all("does not enforce example commands" in f["note"] for f in findings)
    assert "pre-check enforced" not in json.dumps(out).lower()
    code, refused = env.cli_approve(draft, review, "sha256:" + "6" * 64)
    assert code == 1 and problem_codes(refused)[:2] == ["STALE_VALIDATION", "EXAMPLE_DECISION_MISSING"]
    acked = env.write_review(draft, env.review_doc(draft, {"python": env.decision("python", ack=True)}))
    code, out = env.cli_check(draft, acked)
    assert (
        code == 0
        and "maintainer acknowledgements: example_commands_acknowledged"
        in out["data"]["preview"]["masked_diff"]
    )
    harmless = env.write_draft(
        env.draft_doc(examples={"python": dict(PY, unsafe="os.system('<command> ' + path)")})
    )
    code, out = env.cli_check(harmless, env.write_review(harmless))
    assert code == 0 and out["data"]["command_findings"] == []


# AC-001G-03g / 04b (integration): advisory warnings never change the status.
def test_03g_04b_warnings_do_not_refuse(env):
    go = {
        "unsafe": "// Must not do this\n"
        'rows, _ := db.Query("SELECT id FROM users WHERE name = \'" + name + "\'")',
        "safe": 'rows, _ := db.Query("SELECT id FROM users WHERE name = ?", name)',
        "demonstrates": [QUOTE],
    }
    draft = env.write_draft(env.draft_doc(examples={"go": go}), "cwe-89--go")
    code, out = env.cli_check(draft, env.write_review(draft))
    assert code == 0 and out["data"]["status"] == "valid"
    assert out["data"]["warnings"]["language_not_in_applicability"] == ["go"]
    assert [w["term"] for w in out["data"]["warnings"]["normative_language"]] == ["must not"]


# AC-001G-05d (integration): a fetched source needs the licence/original-wording attestation; no output
# claims verified provenance or licence compliance.
def test_05d_fetched_source_needs_licence_attestation(env):
    url = "https://cwe.mitre.org/data/definitions/89.html"
    source = {
        "kind": "fetched",
        "url": url,
        "fetched_at": "2026-10-23T11:58:02Z",
        "http_status": 200,
        "body_sha256": "sha256:" + "c" * 64,
        "attribution": {"title": "CWE-89 (fixture)", "url": url, "licence": "CWE Terms of Use"},
    }
    draft = env.write_draft(env.draft_doc(sources=[source]))
    code, out = env.cli_check(draft, env.write_review(draft))
    assert code == 1 and problem_codes(out) == ["ATTESTATION_MISSING"]
    assert "licence_and_original_wording" in out["problems"][0]["message"]
    assert out["data"]["provenance"][0]["result"] == "provenance_complete"
    review = env.write_review(draft, attest={"non_normative": True, "licence_and_original_wording": True})
    code, out = env.cli_check(draft, review)
    assert code == 0, out
    text = json.dumps(out).lower()
    assert "verified provenance" not in text and "licence compliant" not in text
    assert 'attribution: \\"cwe-89 (fixture)\\"' in text
