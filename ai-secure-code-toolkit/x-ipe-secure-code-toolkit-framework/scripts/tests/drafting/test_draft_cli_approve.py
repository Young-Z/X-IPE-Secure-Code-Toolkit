"""Integration tests of `knowledge draft-approve` (FEATURE-001-G; design Implementation Step 9).

AC-001G-01d, 01g, 01h, 01j, 02a…02f, 03b (approve), 06e; review tests R1, R2, R4. The only write path
is the delivered, unchanged `update_rule`. Secret-looking values are assembled at runtime.
"""

from __future__ import annotations

import json
import re

import pytest
from conftest import run_cli
from drafthelp import JAVA, NOTICE, PY, R78, R89, STAGING, DEnv, codes, dump, mod

from x_ipe_secure_code.auth.trust_store import resolve
from x_ipe_secure_code.knowledge import precheck

PASSWORD = "Tr0ub4dor" + "&3xyz"
TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path)


def entries(log: str) -> list[str]:
    return re.split(r"(?m)^(?=## )", log)[1:]


def section(entry: str, name: str) -> str:
    """Diff body of one file inside a changelog entry (between the fences)."""
    part = entry.split(f"### {name}\n", 1)[1]
    fence = part.split("diff\n", 1)[0]
    return part.split("diff\n", 1)[1].split(fence + "\n", 1)[0]


def approve_ok(env, draft, review, *fps):
    result = env.checked_approve(draft, review, fps)
    assert result.ok, result.to_dict()
    return result


# AC-001G-01d
def test_01d_notice_no_timestamp_prior_text_identical(env):
    old = env.rule_files()["example-python.md"].decode()
    approve_ok(env, *env.drafted())
    text = env.rule_files()["example-python.md"].decode()
    blocks = mod("drafting_blocks")
    found = blocks.scan_markers("example-python.md", text)
    assert len(found) == 1 and text.endswith(
        "x-ipe-ai-supplement v1 end draft=" + found[0].draft_digest + "\n"
    )
    block_text = "\n".join(text.split("\n")[found[0].begin : found[0].end + 1])
    assert f"# {NOTICE}" in block_text and f"# draft: {found[0].draft_digest}" in block_text
    assert "# source: stored rule content (drafted from the stored rule)" in block_text
    assert "# validation: syntax_checked" in block_text
    assert "# maintainer decisions: unsafe_violates_rule, safe_addresses_rule, language_correct" in block_text
    assert "# maintainer attestations: non_normative" in block_text
    assert not TIME.search(block_text)
    assert blocks.strip(text) == old


# AC-001G-01g
def test_01g_one_changelog_entry_with_marker_lines(env):
    before = entries(env.rule_files()["changelog.md"].decode())
    approve_ok(env, *env.drafted())
    after = entries(env.rule_files()["changelog.md"].decode())
    assert after[: len(before)] == before and len(after) == len(before) + 1
    new = after[-1]
    assert re.match(r"## \S+ — updated \(role: maintainer\)\n\n- item digest: sha256:[0-9a-f]{64}", new)
    diff = section(new, "example-python.md")
    assert "\n+# >>> x-ipe-ai-supplement v1 kind=example lang=python" in diff
    assert "\n+# <<< x-ipe-ai-supplement v1 end draft=" in diff


# AC-001G-01h
def test_01h_create_or_append_prior_bytes_preserved(env):
    assert "example-python.md" not in env.rule_files(R78)
    quote = "MUST NOT pass untrusted input to a command interpreter."
    example = {
        "unsafe": "subprocess.run('ls ' + name, shell=True)",
        "safe": "subprocess.run(['ls', name])",
        "demonstrates": [quote],
    }
    approve_ok(env, *env.drafted(R78, {"python": example}, name="cwe-78--python"))
    created = env.rule_files(R78)["example-python.md"].decode()
    found = mod("drafting_blocks").scan_markers("example-python.md", created)
    assert found[0].begin == 0 and created.count("\n") == found[0].end + 1
    old = env.rule_files()["example-python.md"]
    approve_ok(env, *env.drafted())
    appended = env.rule_files()["example-python.md"]
    assert appended.startswith(old + b"\n# >>> x-ipe-ai-supplement")


# AC-001G-01j: written bytes == P; mask(applied diff) == displayed preview; D == digest(P, R).
def test_01j_written_bytes_equal_payload_and_masked_diff_equals_preview(env):
    draft, review = env.drafted()
    shown = env.check(draft, review)
    report = mod("drafting_pipeline").run(env.project, str(draft), str(review))
    key = precheck.read_key(env.project)
    pipeline = mod("drafting_pipeline")
    assert shown.data["validation_digest"] == pipeline.validation_digest(
        report.draft, report.review, key, report.payload
    )
    approved = env.approve(draft, review, shown.data["validation_digest"])
    assert approved.ok, approved.to_dict()
    for name, text in report.payload.items():
        assert env.rule_files()[name] == text.encode("utf-8")
    applied = section(entries(env.rule_files()["changelog.md"].decode())[-1], "example-python.md")
    assert shown.data["preview"]["masked_diff"] == applied


# AC-001G-02a
def test_02a_non_maintainer_refused_tree_unchanged(env, tmp_path):
    draft, review = env.drafted()
    digest = env.check(draft, review).data["validation_digest"]
    before = env.tree()
    refused = env.approve(draft, review, digest, paths=resolve(tmp_path / "no-trust"))
    assert codes(refused) == ["NOT_AUTHORIZED"]
    cli = run_cli(
        [
            "knowledge",
            "draft-approve",
            "--project",
            str(env.project),
            "--draft",
            str(draft),
            "--review",
            str(review),
            "--validation-digest",
            digest,
            "--json",
        ],
        tmp_path / "other-trust",
    )
    assert cli.returncode == 1 and json.loads(cli.stdout)["problems"][0]["code"] == "NOT_AUTHORIZED"
    assert env.tree() == before


# AC-001G-02b: each of the four causes; base-rule cause carries STALE_VALIDATION with STATE_CONFLICT primary.
@pytest.mark.parametrize("cause", ["draft", "review", "base", "validator_version", "precheck_key"])
def test_02b_stale_validation(env, cause, monkeypatch):
    draft, review = env.drafted()
    digest = env.check(draft, review).data["validation_digest"]
    if cause == "draft":
        draft = env.write_draft(env.draft_doc(examples={"python": dict(PY, safe=PY["safe"] + "\nlog(rows)")}))
        review = env.write_review(draft)
    elif cause == "review":
        doc = env.review_doc(draft)
        doc["examples"]["python"]["example_commands_acknowledged"] = False
        review = env.write_review(draft, doc)
    elif cause == "base":
        assert env.update(R89, env.state(), examples={"java": "// other\nrun();\n"}).ok
    elif cause == "validator_version":
        monkeypatch.setattr(mod("drafting_pipeline"), "VALIDATOR_VERSION", "001g.1/py9.99")
    else:
        (env.project / precheck.KEY_REL).write_bytes(bytes(range(32)))
    before = env.tree()
    refused = env.approve(draft, review, digest)
    assert not refused.ok and "STALE_VALIDATION" in codes(refused), refused.to_dict()
    if cause == "base":
        assert codes(refused)[0] == "STATE_CONFLICT"
        assert set(refused.data) >= {"item_digest", "state_digest"}
    else:
        assert codes(refused)[0] == "STALE_VALIDATION"
        assert "draft-check again" in refused.next_steps[0]
    assert env.tree() == before


# AC-001G-02c
def test_02c_stale_base_check_and_state_conflict(env):
    draft, review = env.drafted()
    digest = env.check(draft, review).data["validation_digest"]
    assert env.update(R89, env.state(), examples={"java": "// other\nrun();\n"}).ok
    checked = env.check(draft, review)
    assert checked.data["status"] == "stale_base" and checked.data["base"] == "stale_base"
    assert codes(checked) == ["STALE_BASE"] and checked.data.get("validation_digest") is None
    before = env.tree()
    refused = env.approve(draft, review, digest)
    assert codes(refused) == ["STATE_CONFLICT", "STALE_VALIDATION"]
    assert env.tree() == before


# AC-001G-02d: masked findings; exact declaration; unmasked value bound and written; never printed.
def test_02d_credential_masked_fp_exact_value_never_printed(env):
    unsafe = f'password = "{PASSWORD}"\n' + PY["unsafe"]
    draft = env.write_draft(env.draft_doc(examples={"python": dict(PY, unsafe=unsafe)}))
    review = env.write_review(draft)
    checked = env.check(draft, review)
    again = env.check(draft, review)
    assert checked.data["preview"] == again.data["preview"]
    finding = next(f for f in checked.data["precheck"]["findings"] if f["blocking"])
    token = f"[REDACTED:{finding['fingerprint']}]"
    assert token in checked.data["preview"]["masked_diff"]
    digest = checked.data["validation_digest"]
    undeclared = env.approve(draft, review, digest)
    assert codes(undeclared) == ["NEEDS_DECISION"]
    assert undeclared.data["findings"] == [finding]
    declared = env.approve(draft, review, digest, (f"{R89}:{finding['fingerprint']}",))
    assert declared.ok, declared.to_dict()
    assert PASSWORD in env.rule_files()["example-python.md"].decode()
    assert finding["fingerprint"] in entries(env.rule_files()["changelog.md"].decode())[-1]
    listed = env.supplements()
    process = run_cli(
        [
            "knowledge",
            "draft-check",
            "--project",
            str(env.project),
            "--draft",
            str(draft),
            "--review",
            str(review),
        ],
        env.trust,
    )
    printed = (
        "".join(dump(r) for r in (checked, undeclared, declared, listed)) + process.stdout + process.stderr
    )
    assert PASSWORD not in printed


# AC-001G-02e (and 08e): equal to a plain `knowledge update` of the same payload, apart from time.
def test_02e_equivalent_to_plain_update_time_normalised(env, tmp_path):
    twin_root = tmp_path / "twin"
    twin_root.mkdir()
    twin = DEnv(twin_root, tmp_path / "twin-work")
    draft, review = env.drafted()
    report = mod("drafting_pipeline").run(env.project, str(draft), str(review))
    approved = approve_ok(env, draft, review)
    plain = twin.update(R89, twin.state(), examples={"python": report.payload["example-python.md"]})
    assert plain.ok, plain.to_dict()
    assert approved.data["update"]["item_digest"] == plain.data["item_digest"]
    assert approved.data["update"]["state_digest"] == plain.data["state_digest"]
    mine, theirs = env.rule_files(), twin.rule_files()
    assert set(mine) == set(theirs)
    for name in mine:
        assert TIME.sub("<t>", mine[name].decode()) == TIME.sub("<t>", theirs[name].decode()), name


# AC-001G-02f: all-or-nothing; the failing language is named.
def test_02f_all_or_nothing_failing_language_named(env):
    draft = env.write_draft(env.draft_doc(examples={"python": dict(PY), "java": dict(JAVA)}), "two")
    review = env.write_review(draft)
    digest = env.check(draft, review).data["validation_digest"]
    assert digest
    draft = env.write_draft(
        env.draft_doc(examples={"python": dict(PY), "java": dict(JAVA, safe="  ")}), "two"
    )
    review = env.write_review(draft)
    before = env.tree()
    refused = env.approve(draft, review, digest)
    assert codes(refused)[0] == "STALE_VALIDATION" and "DRAFT_CHECK_FAILED" in codes(refused)
    failed = next(p for p in refused.problems if p.code == "DRAFT_CHECK_FAILED")
    assert "java" in failed.message and "example_incomplete" in failed.message
    assert env.tree() == before


# AC-001G-03b (approve)
def test_03b_approve_refused_invalid_syntax(env):
    draft = env.write_draft(env.draft_doc(examples={"python": dict(PY, unsafe="def broken(:")}))
    review = env.write_review(draft)
    before = env.tree()
    refused = env.approve(draft, review, "sha256:" + "1" * 64)
    assert "DRAFT_CHECK_FAILED" in codes(refused) and "invalid_syntax" in dump(refused)
    assert env.tree() == before


# AC-001G-06e: a new Python draft replaces the previous AI Python block, never duplicates it.
def test_06e_replaces_previous_block_not_duplicate(env):
    seed = env.rule_files()["example-python.md"].decode()
    approve_ok(env, *env.drafted())
    approve_ok(env, *env.drafted(examples={"python": dict(PY, safe=PY["safe"] + "\nconnection.close()")}))
    text = env.rule_files()["example-python.md"].decode()
    blocks = mod("drafting_blocks")
    assert len(blocks.scan_markers("example-python.md", text)) == 1 and "connection.close()" in text
    assert blocks.strip(text) == seed


# R1: a hand-added rule file is never deleted; refused before any digest.
def test_extra_rule_file_refused_and_preserved(env):
    extra = env.folder() / "notes.md"
    extra.write_text("Maintainer notes.\n")
    draft, review = env.drafted()
    before, log = env.tree(), env.rule_files()["changelog.md"]
    checked = env.check(draft, review)
    assert codes(checked) == ["PRESERVATION_FAILED"] and "notes.md" in checked.problems[0].message
    assert checked.data.get("validation_digest") is None
    refused = env.approve(draft, review, "sha256:" + "2" * 64)
    assert codes(refused) == ["PRESERVATION_FAILED"]
    assert extra.read_text() == "Maintainer notes.\n" and env.tree() == before
    assert env.rule_files()["changelog.md"] == log


def test_missing_content_md_refused_nothing_written(env):
    (env.folder() / "content.md").unlink()
    draft, review = env.drafted()
    before = env.tree()
    for result in (env.check(draft, review), env.approve(draft, review, "sha256:" + "2" * 64)):
        # Design erratum (DAO-004 DEC-I5): R1 listed PRESERVATION_FAILED, but the design's own step order
        # (step 2 RULE_INCONSISTENT before step 4b) applies first, since the item digest no longer matches.
        assert codes(result) == ["RULE_INCONSISTENT"], result.to_dict()
    assert env.tree() == before


# R2 (CLI): a private-key body replaced under the same header: non-empty, fully redacted preview equal to
# the masking of the applied diff.
def key_python(body: str) -> str:
    begin, end = "-----BEGIN RSA " + "PRIVATE KEY-----", "-----END RSA " + "PRIVATE KEY-----"
    return f'key = """{begin}\n{body}\n{body[::-1]}\n{end}"""\n' + PY["unsafe"]


def test_private_key_replacement_preview_equals_masked_applied_diff(env):
    first = env.write_draft(env.draft_doc(examples={"python": dict(PY, unsafe=key_python("A1b2" * 10))}))
    review = env.write_review(first)
    checked = env.check(first, review)
    fps = tuple(f"{R89}:{f['fingerprint']}" for f in checked.data["precheck"]["findings"] if f["blocking"])
    assert fps and env.approve(first, review, checked.data["validation_digest"], fps).ok
    second = env.write_draft(env.draft_doc(examples={"python": dict(PY, unsafe=key_python("Z9y8" * 10))}))
    review = env.write_review(second)
    checked = env.check(second, review)
    preview = checked.data["preview"]["masked_diff"]
    assert preview and "Z9y8" not in preview and "A1b2" not in preview and "PRIVATE KEY" not in preview
    fps = tuple(f"{R89}:{f['fingerprint']}" for f in checked.data["precheck"]["findings"] if f["blocking"])
    approved = env.approve(second, review, checked.data["validation_digest"], fps)
    assert approved.ok, approved.to_dict()
    applied = section(entries(env.rule_files()["changelog.md"].decode())[-1], "example-python.md")
    shown, real = preview.splitlines(), applied.splitlines()
    assert len(shown) == len(real)
    for masked, line in zip(shown, real, strict=True):
        if masked != line:
            assert any(s in line for s in ("PRIVATE KEY", "A1b2", "Z9y8", "2b1A", "8y9Z")), line
            assert masked[0] == line[0] and "[REDACTED:" in masked
    assert "Z9y8" not in dump(approved) and "A1b2" not in dump(approved)


# R4: false-positive forwarding through the real update_rule.
@pytest.mark.parametrize("case", ["missing", "exact", "extra", "duplicate", "wrong_rule", "malformed"])
def test_false_positive_forwarding(env, case):
    unsafe = f'password = "{PASSWORD}"\n' + PY["unsafe"]
    draft = env.write_draft(env.draft_doc(examples={"python": dict(PY, unsafe=unsafe)}))
    review = env.write_review(draft)
    checked = env.check(draft, review)
    fp = next(f["fingerprint"] for f in checked.data["precheck"]["findings"] if f["blocking"])
    declarations = {
        "missing": (),
        "exact": (f"{R89}:{fp}",),
        "extra": (f"{R89}:{fp}", f"{R89}:{'0' * 16}"),
        "duplicate": (f"{R89}:{fp}", f"{R89}:{fp}"),
        "wrong_rule": (f"{R78}:{fp}",),
        "malformed": (fp,),
    }[case]
    before, log = env.tree(), env.rule_files()["changelog.md"]
    result = env.approve(draft, review, checked.data["validation_digest"], declarations)
    if case == "exact":
        assert result.ok, result.to_dict()
        assert f"({fp})" in entries(env.rule_files()["changelog.md"].decode())[-1]
        return
    assert codes(result) == ["NEEDS_DECISION" if case == "missing" else "ARGUMENT_INVALID"], result.to_dict()
    assert env.tree() == before and env.rule_files()["changelog.md"] == log
    assert not (env.project / STAGING).exists() or not list((env.project / STAGING).iterdir())
