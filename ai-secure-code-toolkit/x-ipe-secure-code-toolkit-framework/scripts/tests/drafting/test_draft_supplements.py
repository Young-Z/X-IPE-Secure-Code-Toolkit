"""Integration tests of `knowledge supplements` (FEATURE-001-G, FR-001G-4; design Implementation Step 10).

AC-001G-01e, 01f.
"""

from __future__ import annotations

import json
import re

import pytest
from conftest import run_cli
from drafthelp import R78, R89, DEnv, dump, mod

from x_ipe_secure_code.knowledge import precheck


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path)


def approved(env):
    result = env.checked_approve(*env.drafted())
    assert result.ok, result.to_dict()
    return result


# AC-001G-01e: fields, approval time from the delivered changelog entry, read-only, no authorization.
def test_01e_lists_fields_time_from_changelog_read_only(env, tmp_path):
    approved(env)
    log = env.rule_files()["changelog.md"].decode()
    entry_time = re.findall(r"(?m)^## (\S+) — updated \(role: maintainer\)$", log)[-1]
    before = env.tree()
    listed = run_cli(
        ["knowledge", "supplements", "--project", str(env.project), "--rule", R89, "--json"],
        tmp_path / "no-trust-at-all",
    )
    assert listed.returncode == 0, listed.stdout + listed.stderr
    rows = json.loads(listed.stdout)["data"]["supplements"]
    assert len(rows) == 1
    row = rows[0]
    assert (row["rule"], row["file"], row["kind"], row["language"], row["state"]) == (
        R89,
        "example-python.md",
        "example",
        "python",
        "intact",
    )
    assert row["draft_digest"].startswith("sha256:") and row["approved_at"] == entry_time
    assert row["sources"] == ["stored rule content (drafted from the stored rule)"]
    assert row["validation_level"] == "syntax_checked"
    assert row["decisions"] == ["unsafe_violates_rule", "safe_addresses_rule", "language_correct"]
    assert row["attestations"] == ["non_normative"] and row["confidentiality"] is None
    assert env.tree() == before
    everything = env.supplements(None)
    assert everything.ok and [r["rule"] for r in everything.data["supplements"]] == [R89]
    assert env.supplements(R78).data["supplements"] == []


def test_approval_time_not_found_without_changelog_entry():
    supplements = mod("drafting_supplements")
    assert supplements.approved_at("# Changelog\n", "example-python.md", "# >>> marker") == "not_found"


# AC-001G-01f: modified and malformed are reported, never repaired, removed or relabelled.
def test_01f_modified_and_malformed_reported_not_repaired(env):
    approved(env)
    text = env.rule_files()["example-python.md"].decode()
    edited = text.replace("fetchall()\n# <<<", "fetchall()  # edited by hand\n# <<<")
    assert edited != text
    assert env.update(R89, env.state(), examples={"python": edited}).ok
    files = env.rule_files()
    rows = env.supplements().data["supplements"]
    assert [r["state"] for r in rows] == ["modified"]
    assert env.rule_files() == files
    broken = edited.split("# <<<")[0]
    assert env.update(R89, env.state(), examples={"python": broken}).ok
    files = env.rule_files()
    rows = env.supplements().data["supplements"]
    assert len(rows) == 1 and rows[0]["state"] == "malformed" and rows[0]["file"] == "example-python.md"
    assert isinstance(rows[0]["line"], int) and rows[0]["reason"]
    assert env.rule_files() == files


# DEC-I15 (independent review issue 1; AC-001G-02d, FR-001G-4/10): pre-check-matched values inside the
# notice (source reason or attribution) are never printed by `knowledge supplements`, also after a
# false-positive declaration, and also when the pre-check key is absent.
@pytest.mark.parametrize("where", ["not_retrieved_reason", "fetched_attribution", "key_absent"])
def test_supplements_masks_prechecked_values_in_notice(env, tmp_path, where):
    token = "gh" + "p_" + "Q7w" * 12
    url = "https://cwe.mitre.org/data/definitions/89.html"
    if where == "fetched_attribution":
        source = {
            "kind": "fetched",
            "url": url,
            "fetched_at": "2026-10-23T11:58:02Z",
            "http_status": 200,
            "body_sha256": "sha256:" + "c" * 64,
            "attribution": {"title": f"CWE-89 {token}", "url": url, "licence": "CWE Terms of Use"},
        }
        attest = {"non_normative": True, "licence_and_original_wording": True}
    else:
        source = {"kind": "not_retrieved", "url": url, "reason": f"proxy answered {token}"}
        attest = None
    draft = env.write_draft(env.draft_doc(sources=[source]))
    review = env.write_review(draft, attest=attest)
    checked = env.check(draft, review)
    fps = tuple(f"{R89}:{f['fingerprint']}" for f in checked.data["precheck"]["findings"] if f["blocking"])
    assert fps and token not in dump(checked)
    assert env.approve(draft, review, checked.data["validation_digest"], fps).ok
    assert token in env.rule_files()["example-python.md"].decode()
    if where == "key_absent":
        (env.project / precheck.KEY_REL).unlink()
    listed = env.supplements()
    assert listed.ok and len(listed.data["supplements"]) == 1
    process = run_cli(["knowledge", "supplements", "--project", str(env.project)], tmp_path / "no-trust")
    as_json = run_cli(
        ["knowledge", "supplements", "--project", str(env.project), "--json"], tmp_path / "no-trust"
    )
    printed = dump(listed) + process.stdout + process.stderr + as_json.stdout + as_json.stderr
    assert token not in printed
    assert "[REDACTED" in json.dumps(listed.data["supplements"][0]["sources"])
