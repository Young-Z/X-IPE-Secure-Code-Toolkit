"""Integration tests for FEATURE-001-C policy resolution and adoption scope (service + CLI)."""

from __future__ import annotations

import json
import subprocess
import sys
import threading

import pytest
from conftest import LAUNCHER, PASSPHRASE, SRC, TOOLKIT_ROOT, FakeInteraction, run_cli, tree_hashes

from x_ipe_secure_code.auth.service import initialize_authorization, revoke_authorization
from x_ipe_secure_code.auth.trust_store import resolve as resolve_trust
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import service
from x_ipe_secure_code.project_init import initialize_project

LOCAL = "x-ipe-docs/secure-code/knowledge/local"
SCOPES = "x-ipe-docs/secure-code/scopes"
SECRET = 'password = "Zq8vLr2mNp4tXw9y"\n'


@pytest.fixture
def env(project, tmp_path):
    assert initialize_project(str(project), "github-copilot").ok
    trust_dir = tmp_path / "trust-app"
    paths = resolve_trust(trust_dir)
    assert initialize_authorization(paths=paths, interaction=FakeInteraction(answers=[PASSPHRASE] * 2)).ok
    return project, paths, trust_dir


def item(rule="CWE/4.14/CWE-79", **over):
    ns, ver, rid = rule.split("/")
    data = {
        "namespace": ns,
        "version": ver,
        "rule_id": rid,
        "content": f"Rule {rid} body.\n",
        "source_location": "https://example.org/" + rid,
    }
    if ns.startswith("@"):
        data["name"] = f"Custom {rid}"
    data.update(over)
    return data


_batches = {"n": 0}


def load(env, tmp_path, *items):
    _batches["n"] += 1
    path = tmp_path / f"batch-{_batches['n']}.json"
    path.write_text(json.dumps({"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": list(items)}))
    return knowledge.import_batch(str(env[0]), str(path), [], [], trust_paths=env[1])


def res(env, *rules, all_=False, languages=(), output=None):
    return service.resolve_policies(str(env[0]), list(rules), all_, list(languages), output)


def entry(result, requested):
    return next(e for e in result.data["entries"] if e["requested"] == requested)


def write_decisions(
    tmp_path,
    proposal,
    decisions,
    *,
    mode="clues",
    considered=None,
    note="User confirmed in chat",
    clues="Java login service",
    name="decisions.json",
):
    doc = {
        "schema": "ai-secure-code-toolkit/scope-decisions/v1",
        "mode": mode,
        "proposal_digest": proposal.data["proposal_digest"],
        "clues": clues,
        "language_context": ["java"],
        "decisions": decisions,
        "confirmation_note": note,
    }
    if mode == "clues":
        doc["considered"] = (
            considered if considered is not None else [e["requested"] for e in proposal.data["entries"]]
        )
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def adopt(proposal, requested, note=None):
    e = entry(proposal, requested)
    decision = {"ref": requested, "decision": "adopted", "state_digest": e["source_evidence"]["state_digest"]}
    if note:
        decision["note"] = note
    return decision


def skip(requested, reason):
    return {"ref": requested, "decision": "not_adopted", "reason": reason}


def save(env, path, confirmed=True):
    return service.save_scope(str(env[0]), str(path), confirmed)


def show(env, scope_id, output=None):
    return service.show_scope(str(env[0]), scope_id, output)


def protected(project):
    return tree_hashes(project / LOCAL, project / store.PENDING_REL)


# AC-001C-01a
def test_resolved_policy_carries_requirement_and_evidence(env, tmp_path):
    full = item(
        examples={"general": "Encode output.\n", "python": "escape(x)\n"},
        applicability=["python"],
        relations=["CWE/4.14/CWE-80"],
    )
    assert load(env, tmp_path, full).ok
    r = res(env, "CWE/4.14/CWE-79")
    e = entry(r, "CWE/4.14/CWE-79")
    assert e["rule"] == "CWE/4.14/CWE-79" and e["availability"] == "available"
    assert e["kind"] == "institutional" and "name" in e
    assert e["requirement"] == "Rule CWE-79 body.\n"
    assert e["applicability"] == ["python"]
    assert e["examples"] == ["general", "python"]
    assert e["relations"] == ["CWE/4.14/CWE-80"]
    evidence = e["source_evidence"]
    assert evidence["source_location"] == "https://example.org/CWE-79"
    assert evidence["state_digest"].startswith("sha256:") and evidence["last_changed_at"]
    assert e["retrieval_status"] == "retrieved"
    assert e["unresolved"] == []


# AC-001C-01b, 01f
def test_missing_applicability_and_location_are_explicit_gaps(env, tmp_path):
    assert load(env, tmp_path, item(source_location=None)).ok
    r = res(env, "CWE/4.14/CWE-79")
    e = entry(r, "CWE/4.14/CWE-79")
    assert e["applicability"] == "unknown"
    assert e["source_evidence"]["source_location"] == "not recorded"
    assert "source location not recorded" in e["unresolved"]
    assert e["availability"] == "available"
    assert r.ok and r.data["status"] == "complete"


# AC-001C-01c
def test_partial_request_is_never_complete(env, tmp_path):
    assert load(env, tmp_path, item(), item("CWE/4.13/CWE-89"), item("CWE/4.14/CWE-89")).ok
    r = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-1", "CWE/CWE-89")
    assert r.ok and r.data["status"] == "partial"
    assert r.data["counts"] == {"requested": 3, "available": 1, "missing": 1, "unclear": 1}
    by = {e["availability"] for e in r.data["entries"]}
    assert by == {"available", "missing", "unclear"}


# AC-001C-01d
def test_inconsistent_and_unreadable_rules_are_missing_without_content(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("CWE/4.14/CWE-89")).ok
    (project / LOCAL / "CWE/4.14/CWE-79/content.md").write_text("tampered by hand\n")
    (project / LOCAL / "CWE/4.14/CWE-89/content.md").write_bytes(b"\xff\xfe broken")
    r = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89")
    a, b = entry(r, "CWE/4.14/CWE-79"), entry(r, "CWE/4.14/CWE-89")
    assert (a["availability"], a["reason"]) == ("missing", "inconsistent")
    assert (b["availability"], b["reason"]) == ("missing", "unreadable")
    assert "requirement" not in a and "requirement" not in b
    assert "tampered by hand" not in json.dumps(r.to_dict())
    assert r.data["status"] == "maintenance_needed"


# AC-001C-01e
def test_user_without_authorization_resolves_without_writes(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    load(env, tmp_path, item("CWE/4.14/CWE-798", content=SECRET))
    revoke_authorization(paths=env[1], interaction=FakeInteraction(answers=[PASSPHRASE]))
    before = protected(project)
    r = res(env, "CWE/4.14/CWE-79")
    assert r.ok and entry(r, "CWE/4.14/CWE-79")["availability"] == "available"
    assert res(env, all_=True).data["status"] == "complete"
    assert protected(project) == before


# AC-001C-02a
def test_clue_resolution_proposes_without_adopting(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("CWE/4.14/CWE-89"), item("@ACME/v1/A-1")).ok
    r = res(env, "CWE/4.14/CWE-79")
    assert r.data["library_size"] == 3
    assert [e["requested"] for e in r.data["entries"]] == ["CWE/4.14/CWE-79"]
    assert r.data["proposal_digest"].startswith("sha256:")
    assert r.data["adopted"] == [] and "nothing adopted" in r.data["adoption"]
    assert not (project / SCOPES).exists()
    assert list((project / "x-ipe-docs/secure-code/presets").iterdir()) == []


# AC-001C-02b
def test_versionless_reference_with_two_versions_is_unclear(env, tmp_path):
    assert load(env, tmp_path, item("CWE/4.13/CWE-79"), item("CWE/4.14/CWE-79")).ok
    e = entry(res(env, "CWE/CWE-79"), "CWE/CWE-79")
    assert (e["availability"], e["reason"]) == ("unclear", "multiple_versions")
    assert sorted(c["rule"] for c in e["candidates"]) == ["CWE/4.13/CWE-79", "CWE/4.14/CWE-79"]
    assert "rule" not in e and "requirement" not in e


def test_versionless_reference_with_one_version_resolves(env, tmp_path):
    assert load(env, tmp_path, item("@ACME/v1/A-1")).ok
    e = entry(res(env, "@ACME/A-1"), "@ACME/A-1")
    assert e["availability"] == "available" and e["rule"] == "@ACME/v1/A-1" and e["kind"] == "custom"


# AC-001C-02c
def test_unknown_and_pending_references_are_missing(env, tmp_path):
    assert load(env, tmp_path, item()).ok
    held = load(env, tmp_path, item("CWE/4.14/CWE-798", content=SECRET))
    assert held.data["items"][0]["outcome"] == "needs_decision"
    r = res(env, "CWE/4.14/CWE-1", "CWE/4.14/CWE-798")
    assert (entry(r, "CWE/4.14/CWE-1")["reason"]) == "not_found"
    pending = entry(r, "CWE/4.14/CWE-798")
    assert (pending["availability"], pending["reason"]) == ("missing", "pending_decision")
    assert "Zq8vLr2mNp4tXw9y" not in json.dumps(r.to_dict())


# AC-001C-02d
def test_language_context_annotates_and_never_excludes(env, tmp_path):
    assert load(
        env,
        tmp_path,
        item("CWE/4.14/A", applicability=["python"]),
        item("CWE/4.14/B", applicability=["java"]),
        item("CWE/4.14/C"),
    ).ok
    r = res(env, "CWE/4.14/A", "CWE/4.14/B", "CWE/4.14/C", languages=["java"])
    notes = {e["requested"]: e["language_note"] for e in r.data["entries"]}
    assert notes == {"CWE/4.14/A": "does_not_match", "CWE/4.14/B": "matches", "CWE/4.14/C": "unknown"}
    assert all(e["availability"] == "available" for e in r.data["entries"])
    assert r.data["status"] == "complete"


# AC-001C-02e
def test_skill_package_describes_scope_selection():
    framework = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework"
    text = (framework / "SKILL.md").read_text(encoding="utf-8")
    section = text.split("## Selecting Policies", 1)[1].split("\n## ", 1)[0].lower()
    reference = (framework / "references" / "policy-selection.md").read_text(encoding="utf-8").lower()
    combined = section + reference
    for phrase in (
        "concrete rule references",
        "knowledge list",
        "reason",
        "language note",
        "exclusion",
        "reverse",
        "unclear",
        "conflict",
        "no precedence",
        "confirm",
        "--confirmed",
        "never create a preset",
        "apply all",
    ):
        assert phrase in combined, phrase
    assert "policy-selection.md" in section


# AC-001C-02f
def test_scope_confirmation_needs_and_grants_no_maintenance_rights(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    revoke_authorization(paths=env[1], interaction=FakeInteraction(answers=[PASSPHRASE]))
    p = res(env, "CWE/4.14/CWE-79")
    saved = save(env, write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")]))
    assert saved.ok and (project / saved.data["path"]).is_file()
    denied = load(env, tmp_path, item("CWE/4.14/CWE-89"))
    assert not denied.ok and denied.problems[0].code == "NOT_AUTHORIZED"


# AC-001C-02g
def test_user_decisions_on_conflicts_are_recorded_verbatim(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("@ACME/v1/A-1")).ok
    p = res(env, "CWE/4.14/CWE-79", "@ACME/v1/A-1")
    path = write_decisions(
        tmp_path,
        p,
        [
            adopt(p, "CWE/4.14/CWE-79", note="user: applies to templates only"),
            skip("@ACME/v1/A-1", "conflicts with CWE-79 guidance; user chose CWE"),
        ],
    )
    saved = save(env, path)
    record = json.loads((project / saved.data["path"]).read_text())
    assert record["adopted"] == [
        {
            "rule": "CWE/4.14/CWE-79",
            "requested": "CWE/4.14/CWE-79",
            "state_digest": entry(p, "CWE/4.14/CWE-79")["source_evidence"]["state_digest"],
            "note": "user: applies to templates only",
        }
    ]
    assert record["not_adopted"] == [
        {
            "requested": "@ACME/v1/A-1",
            "availability": "available",
            "reason": "conflicts with CWE-79 guidance; user chose CWE",
        }
    ]


# AC-001C-03a
def test_empty_library_needs_maintenance(env, tmp_path):
    load(env, tmp_path, item("CWE/4.14/CWE-798", content=SECRET))  # pending only
    for r in (res(env, all_=True), res(env, "CWE/4.14/CWE-79")):
        assert not r.ok and r.data["status"] == "maintenance_needed"
        assert r.problems[0].code == "MAINTENANCE_NEEDED"
        assert [e for e in r.data["entries"] if e["availability"] == "available"] == []
        assert any("Maintainer" in s and "import" in s for s in r.next_steps)


# AC-001C-03b
def test_no_requested_reference_available_names_them(env, tmp_path):
    assert load(env, tmp_path, item(), item("CWE/4.13/CWE-89"), item("CWE/4.14/CWE-89")).ok
    r = res(env, "CWE/4.14/CWE-1", "CWE/CWE-89")
    assert not r.ok and r.data["status"] == "maintenance_needed"
    assert any("CWE/4.14/CWE-1" in s and "CWE/CWE-89" in s for s in r.next_steps)


# AC-001C-03c, 03d
def test_missing_and_unclear_must_be_decided_not_adopted(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("CWE/4.13/CWE-89"), item("CWE/4.14/CWE-89")).ok
    p = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-1", "CWE/CWE-89")
    undecided = save(env, write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")]))
    assert not undecided.ok and undecided.problems[0].code == "DECISION_MISSING"
    assert "CWE/4.14/CWE-1" in undecided.problems[0].message and "CWE/CWE-89" in undecided.problems[0].message
    assert not (project / SCOPES).exists()
    wrong = save(
        env,
        write_decisions(
            tmp_path,
            p,
            [
                adopt(p, "CWE/4.14/CWE-79"),
                skip("CWE/4.14/CWE-1", "missing"),
                {"ref": "CWE/CWE-89", "decision": "adopted", "state_digest": "sha256:x"},
            ],
        ),
    )
    assert not wrong.ok and wrong.problems[0].code == "NOT_ADOPTABLE"
    nothing = save(
        env,
        write_decisions(
            tmp_path, p, [skip("CWE/4.14/CWE-79", "no"), skip("CWE/4.14/CWE-1", "m"), skip("CWE/CWE-89", "u")]
        ),
    )
    assert not nothing.ok and nothing.problems[0].code == "NOTHING_ADOPTED"
    ok = save(
        env,
        write_decisions(
            tmp_path,
            p,
            [
                adopt(p, "CWE/4.14/CWE-79"),
                skip("CWE/4.14/CWE-1", "missing: not_found; user agreed"),
                skip("CWE/CWE-89", "unclear: two versions; user deferred"),
            ],
        ),
    )
    assert ok.ok
    record = json.loads((project / ok.data["path"]).read_text())
    assert [a["rule"] for a in record["adopted"]] == ["CWE/4.14/CWE-79"]
    assert {n["requested"]: n["availability"] for n in record["not_adopted"]} == {
        "CWE/4.14/CWE-1": "missing",
        "CWE/CWE-89": "unclear",
    }
    loaded = show(env, ok.data["scope_id"])
    assert loaded.data["adopted_rules"] == ["CWE/4.14/CWE-79"]


# AC-001C-04a
def test_apply_all_proposal_is_highlighted_and_complete(env, tmp_path):
    assert load(env, tmp_path, item("CWE/4.13/CWE-79"), item("CWE/4.14/CWE-79"), item("@ACME/v1/A-1")).ok
    load(env, tmp_path, item("CWE/4.14/CWE-798", content=SECRET))
    r = res(env, all_=True)
    codes = {n["code"]: n for n in r.data["notices"]}
    assert list(r.data)[0] == "notices"
    assert "Apply All" in codes["APPLY_ALL_PROPOSED"]["message"]
    assert "no clues" in codes["APPLY_ALL_PROPOSED"]["message"].lower()
    assert codes["APPLY_ALL_PROPOSED"]["default_preset_exists"] is False
    assert sorted(e["rule"] for e in r.data["entries"]) == [
        "@ACME/v1/A-1",
        "CWE/4.13/CWE-79",
        "CWE/4.14/CWE-79",
    ]
    assert codes["MULTI_VERSION"]["rules"] == {"CWE/CWE-79": ["4.13", "4.14"]}
    assert codes["PENDING_EXCLUDED"]["count"] == 1 and r.data["pending_count"] == 1
    assert "!! Notices" in r.to_text()


# AC-001C-04b, 04c
def test_apply_all_scope_lists_concrete_rules_and_ignores_later_imports(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("@ACME/v1/A-1")).ok
    p = res(env, all_=True)
    path = write_decisions(
        tmp_path, p, [adopt(p, "CWE/4.14/CWE-79"), adopt(p, "@ACME/v1/A-1")], mode="apply_all", clues=""
    )
    saved = save(env, path)
    assert saved.ok
    record = json.loads((project / saved.data["path"]).read_text())
    assert record["mode"] == "apply_all"
    assert sorted(a["rule"] for a in record["adopted"]) == ["@ACME/v1/A-1", "CWE/4.14/CWE-79"]
    assert record["artifact_scope"] == "not determined by the Policy scope"
    assert load(env, tmp_path, item("CWE/4.14/CWE-89")).ok
    loaded = show(env, saved.data["scope_id"])
    assert loaded.data["status"] == "complete"
    assert sorted(loaded.data["adopted_rules"]) == ["@ACME/v1/A-1", "CWE/4.14/CWE-79"]


# AC-001C-05a
def test_scope_record_contents_and_location(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("CWE/4.14/CWE-89")).ok
    p = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89", languages=["java"])
    saved = save(
        env,
        write_decisions(
            tmp_path, p, [adopt(p, "CWE/4.14/CWE-79", note="n"), skip("CWE/4.14/CWE-89", "not relevant")]
        ),
    )
    path = project / saved.data["path"]
    assert path.parent == project / SCOPES and path.name == saved.data["scope_id"].split(":")[1] + ".json"
    record = json.loads(path.read_text())
    assert record["scope_id"] == saved.data["scope_id"]
    assert record["mode"] == "clues" and record["clues"] == "Java login service"
    assert record["adopted"][0]["state_digest"].startswith("sha256:") and record["adopted"][0]["note"] == "n"
    assert record["not_adopted"][0]["reason"] == "not relevant"
    assert record["confirmation_note"] == "User confirmed in chat" and record["created_at"]
    assert not any("presets" in str(p) or "knowledge" in str(p) for p in [path.relative_to(project)])


# AC-001C-05b
def test_load_reports_changed_and_removed_policies(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("CWE/4.14/CWE-89"), item("CWE/4.14/CWE-22")).ok
    p = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89", "CWE/4.14/CWE-22")
    saved = save(
        env,
        write_decisions(
            tmp_path, p, [adopt(p, r) for r in ("CWE/4.14/CWE-79", "CWE/4.14/CWE-89", "CWE/4.14/CWE-22")]
        ),
    )
    confirmed = entry(p, "CWE/4.14/CWE-89")["source_evidence"]["state_digest"]
    change = tmp_path / "change.json"
    change.write_text(
        json.dumps({"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": "New body.\n"})
    )
    assert knowledge.update_rule(
        str(project), "CWE/4.14/CWE-89", confirmed, str(change), [], trust_paths=env[1]
    ).ok
    import shutil

    shutil.rmtree(project / LOCAL / "CWE/4.14/CWE-22")
    loaded = show(env, saved.data["scope_id"])
    by = {e["rule"]: e for e in loaded.data["entries"]}
    assert by["CWE/4.14/CWE-79"]["adoption"] == "adopted"
    assert by["CWE/4.14/CWE-79"]["policy"]["requirement"] == "Rule CWE-79 body.\n"
    changed = by["CWE/4.14/CWE-89"]
    assert changed["adoption"] == "needs_reconfirmation" and changed["changed_since_confirmation"] is True
    assert changed["confirmed_state_digest"] == confirmed
    assert changed["current_state_digest"] != confirmed
    assert changed["for_review"]["requirement"] == "New body.\n"
    assert by["CWE/4.14/CWE-22"]["adoption"] == "missing"
    assert loaded.ok and loaded.data["status"] == "partial"
    assert loaded.data["adopted_rules"] == ["CWE/4.14/CWE-79"]
    assert any("confirm a new scope" in s for s in loaded.next_steps)


# AC-001C-05c (integration part): parallel identical saves
def test_identical_saves_keep_one_record_and_first_time(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    p = res(env, "CWE/4.14/CWE-79")
    path = write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")])
    results = []
    threads = [threading.Thread(target=lambda: results.append(save(env, path))) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r.ok for r in results) and len({r.data["scope_id"] for r in results}) == 1
    assert sum(r.data["created"] for r in results) == 1
    files = list((project / SCOPES).glob("*.json"))
    assert len(files) == 1
    first = json.loads(files[0].read_text())["created_at"]
    again = save(env, path)
    assert again.data["created"] is False and json.loads(files[0].read_text())["created_at"] == first


# AC-001C-05d
@pytest.mark.parametrize("damage", ["tamper", "malformed"])
def test_invalid_scope_record_is_refused(env, tmp_path, damage):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    p = res(env, "CWE/4.14/CWE-79")
    saved = save(env, write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")]))
    path = project / saved.data["path"]
    if damage == "tamper":
        record = json.loads(path.read_text())
        record["adopted"][0]["rule"] = "CWE/4.14/CWE-89"
        path.write_text(json.dumps(record))
    else:
        path.write_text("{not json")
    r = show(env, saved.data["scope_id"])
    assert not r.ok and r.problems[0].code == "SCOPE_INVALID" and r.next_steps
    assert "entries" not in r.data


# AC-001C-05e
def test_save_without_confirmation_flag_is_refused(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    p = res(env, "CWE/4.14/CWE-79")
    r = save(env, write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")]), confirmed=False)
    assert not r.ok and r.problems[0].code == "CONFIRMATION_REQUIRED"
    assert not (project / SCOPES).exists()


# AC-001C-05f
def test_changed_proposal_is_stale_confirmation(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item(), item("CWE/4.14/CWE-89")).ok
    p = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89")
    path = write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79"), adopt(p, "CWE/4.14/CWE-89")])
    change = tmp_path / "change.json"
    change.write_text(
        json.dumps({"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": "Changed.\n"})
    )
    base = entry(p, "CWE/4.14/CWE-89")["source_evidence"]["state_digest"]
    assert knowledge.update_rule(
        str(project), "CWE/4.14/CWE-89", base, str(change), [], trust_paths=env[1]
    ).ok
    r = save(env, path)
    assert not r.ok and r.problems[0].code == "STALE_CONFIRMATION"
    assert "CWE/4.14/CWE-89" in r.problems[0].message and "CWE/4.14/CWE-79" not in r.problems[0].message
    assert any("resolve" in s.lower() and "confirm" in s.lower() for s in r.next_steps)
    assert not (project / SCOPES).exists()


def test_apply_all_with_new_rule_is_stale_confirmation(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    p = res(env, all_=True)
    path = write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")], mode="apply_all")
    assert load(env, tmp_path, item("CWE/4.14/CWE-89")).ok
    r = save(env, path)
    assert (
        not r.ok and r.problems[0].code == "STALE_CONFIRMATION" and "CWE/4.14/CWE-89" in r.problems[0].message
    )
    assert not (project / SCOPES).exists()


# AC-001C-05g, 05h
def test_load_status_complete_and_maintenance_needed(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    p = res(env, "CWE/4.14/CWE-79")
    saved = save(env, write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")]))
    loaded = show(env, saved.data["scope_id"].split(":")[1])
    assert (
        loaded.ok
        and loaded.data["status"] == "complete"
        and loaded.data["adopted_rules"] == ["CWE/4.14/CWE-79"]
    )
    import shutil

    shutil.rmtree(project / LOCAL / "CWE/4.14/CWE-79")
    gone = show(env, saved.data["scope_id"])
    assert not gone.ok and gone.data["status"] == "maintenance_needed" and gone.data["adopted_rules"] == []


# NFR-001C-1 / edge cases
def test_held_lock_returns_locked(env, tmp_path, monkeypatch):
    from x_ipe_secure_code import atomic
    from x_ipe_secure_code.knowledge import durable

    assert load(env, tmp_path, item()).ok

    def held(self):
        raise atomic.LockHeld(self.rel, "held by another process")

    monkeypatch.setattr(durable.DirLock, "__enter__", held)
    r = res(env, "CWE/4.14/CWE-79")
    assert not r.ok and r.problems[0].code == "LOCKED" and r.next_steps


def test_fresh_project_resolve_creates_only_the_lock_file(env):
    project = env[0]
    lock = project / store.LOCK_REL
    assert not lock.exists()
    r = res(env, all_=True)
    assert r.data["status"] == "maintenance_needed" and lock.is_file()


def test_request_validation_and_uninitialized_project(env, tmp_path):
    assert res(env).problems[0].code == "REQUEST_INVALID"
    assert res(env, "CWE/4.14/CWE-79", all_=True).problems[0].code == "REQUEST_INVALID"
    bare = tmp_path / "bare"
    bare.mkdir()
    r = service.resolve_policies(str(bare), [], True, [], None)
    assert r.problems[0].code == "PROJECT_NOT_INITIALIZED"
    assert show(env, "sha256:" + "0" * 64).problems[0].code == "SCOPE_NOT_FOUND"
    assert show(env, "../../etc/passwd").problems[0].code == "SCOPE_NOT_FOUND"


def test_invalid_reference_and_duplicates(env, tmp_path):
    assert load(env, tmp_path, item()).ok
    r = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-79", "../x")
    assert r.data["counts"]["requested"] == 2
    assert entry(r, "CWE/4.14/CWE-79")["duplicates"] == 1
    assert entry(r, "../x")["reason"] == "invalid_reference"


def test_output_file_receives_full_entries(env, tmp_path):
    assert load(env, tmp_path, item()).ok
    out = tmp_path / "all.json"
    r = res(env, all_=True, output=str(out))
    assert r.ok and r.data["output_file"] == str(out)
    assert all("requirement" not in e for e in r.data["entries"])
    full = json.loads(out.read_text())
    assert full["entries"][0]["requirement"] == "Rule CWE-79 body.\n"


def test_decisions_file_errors(env, tmp_path):
    assert load(env, tmp_path, item()).ok
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    assert save(env, bad).problems[0].code == "DECISIONS_INVALID"
    p = res(env, "CWE/4.14/CWE-79")
    no_note = write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")], note="")
    assert save(env, no_note).problems[0].code == "DECISIONS_INVALID"
    stranger = write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79"), skip("CWE/4.14/CWE-2", "x")])
    assert save(env, stranger).problems[0].code == "DECISIONS_INVALID"


# CLI boundary (exit codes, --json)
def test_cli_resolve_save_show_round_trip(env, tmp_path):
    project, _, trust_dir = env
    assert load(env, tmp_path, item()).ok
    out = run_cli(
        ["policy", "resolve", "--project", str(project), "--rule", "CWE/4.14/CWE-79", "--json"], trust_dir
    )
    assert out.returncode == 0, out.stderr
    proposal = json.loads(out.stdout)
    assert proposal["command"] == "policy resolve" and proposal["data"]["status"] == "complete"
    e = proposal["data"]["entries"][0]
    doc = {
        "schema": "ai-secure-code-toolkit/scope-decisions/v1",
        "mode": "clues",
        "considered": ["CWE/4.14/CWE-79"],
        "proposal_digest": proposal["data"]["proposal_digest"],
        "clues": "",
        "decisions": [
            {
                "ref": "CWE/4.14/CWE-79",
                "decision": "adopted",
                "state_digest": e["source_evidence"]["state_digest"],
            }
        ],
        "confirmation_note": "confirmed",
    }
    path = tmp_path / "d.json"
    path.write_text(json.dumps(doc))
    refused = run_cli(
        ["scope", "save", "--project", str(project), "--decisions", str(path), "--json"], trust_dir
    )
    assert (
        refused.returncode == 1
        and json.loads(refused.stdout)["problems"][0]["code"] == "CONFIRMATION_REQUIRED"
    )
    saved = run_cli(
        ["scope", "save", "--project", str(project), "--decisions", str(path), "--confirmed", "--json"],
        trust_dir,
    )
    assert saved.returncode == 0, saved.stdout
    scope_id = json.loads(saved.stdout)["data"]["scope_id"]
    shown = run_cli(["scope", "show", "--project", str(project), "--scope", scope_id], trust_dir)
    assert shown.returncode == 0 and "complete" in shown.stdout
    empty = run_cli(["policy", "resolve", "--project", str(project), "--rule", "X/1/Y"], trust_dir)
    assert empty.returncode == 1 and "MAINTENANCE_NEEDED" in empty.stdout


def test_policy_package_has_no_maintainer_check():
    text = "".join(p.read_text(encoding="utf-8") for p in (SRC / "x_ipe_secure_code" / "policy").glob("*.py"))
    assert "require_maintainer" not in text
    assert "import_batch" not in text and "update_rule" not in text


def test_launcher_runs(tmp_path):
    r = subprocess.run(
        [sys.executable, str(LAUNCHER), "--test-trust-dir", str(tmp_path), "scope", "--help"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0 and "save" in r.stdout


# Implementation review regressions (TASK-017)
@pytest.mark.parametrize("raw", ["[]", "null", '"x"'])
def test_non_object_record_is_unreadable_not_traceback(env, tmp_path, raw):
    project = env[0]
    assert load(env, tmp_path, item(), item("CWE/4.14/CWE-89")).ok
    p = res(env, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89")
    saved = save(
        env, write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79"), adopt(p, "CWE/4.14/CWE-89")])
    )
    (project / LOCAL / "CWE/4.14/CWE-89/record.json").write_text(raw)
    r = res(env, "CWE/4.14/CWE-89", "CWE/4.14/CWE-79")
    assert (entry(r, "CWE/4.14/CWE-89")["availability"], entry(r, "CWE/4.14/CWE-89")["reason"]) == (
        "missing",
        "unreadable",
    )
    loaded = show(env, saved.data["scope_id"])
    assert loaded.data["status"] == "partial" and loaded.data["adopted_rules"] == ["CWE/4.14/CWE-79"]


def test_malformed_source_documents_do_not_break_policy(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    path = project / LOCAL / "CWE/4.14/CWE-79/record.json"
    record = json.loads(path.read_text())
    record["source_documents"] = None
    record["updated_at"] = 5
    path.write_text(json.dumps(record))
    e = entry(res(env, "CWE/4.14/CWE-79"), "CWE/4.14/CWE-79")
    assert e["availability"] == "available"
    assert e["source_evidence"]["source_documents"] == [] and e["source_evidence"]["last_changed_at"] is None


def test_lock_creation_failure_is_io_error(env, tmp_path, monkeypatch):
    from x_ipe_secure_code.knowledge import durable

    assert load(env, tmp_path, item()).ok

    def denied(self):
        raise PermissionError("read-only checkout")

    monkeypatch.setattr(durable.DirLock, "__enter__", denied)
    r = res(env, "CWE/4.14/CWE-79")
    assert not r.ok and r.problems[0].code == "IO_ERROR" and r.next_steps


# Bug fix TASK-020 regressions: text that UTF-8 cannot encode (lone surrogates)
def test_surrogate_reference_is_invalid_not_traceback(env, tmp_path):
    assert load(env, tmp_path, item()).ok
    out = tmp_path / "o.json"
    r = res(env, "CWE/4.14/CWE-79", "CWE/\udcff", output=str(out))
    assert r.ok and r.data["status"] == "partial"
    bad = [e for e in r.data["entries"] if e["availability"] == "missing"][0]
    assert bad["reason"] == "invalid_reference"
    json.dumps(r.to_dict(), ensure_ascii=False).encode("utf-8")
    assert out.is_file()


def test_surrogate_reference_via_cli_bytes(env, tmp_path):
    import os

    project, _, trust_dir = env
    assert load(env, tmp_path, item()).ok
    args = [
        "policy",
        "resolve",
        "--project",
        str(project),
        "--rule",
        "CWE/4.14/CWE-79",
        "--rule",
        os.fsdecode(b"CWE/\xff"),
        "--json",
    ]
    out = run_cli(args, trust_dir)
    assert out.returncode == 0 and "Traceback" not in out.stderr
    assert json.loads(out.stdout)["data"]["counts"]["missing"] == 1


def test_surrogate_language_is_request_invalid(env, tmp_path):
    assert load(env, tmp_path, item()).ok
    r = res(env, "CWE/4.14/CWE-79", languages=["\udcff"], output=str(tmp_path / "o.json"))
    assert not r.ok and r.problems[0].code == "REQUEST_INVALID"


@pytest.mark.parametrize("field", ["clues", "considered", "note"])
def test_surrogate_in_decisions_is_invalid(env, tmp_path, field):
    assert load(env, tmp_path, item()).ok
    p = res(env, "CWE/4.14/CWE-79")
    path = write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79", note="NOTE")], clues="CLUES")
    text = path.read_text()
    marker = {"clues": '"CLUES"', "considered": '"CWE/4.14/CWE-79"]', "note": '"NOTE"'}[field]
    replacement = {"clues": '"\\ud800"', "considered": '"CWE/4.14/CWE-79", "\\ud800"]', "note": '"\\ud800"'}[
        field
    ]
    path.write_text(text.replace(marker, replacement, 1))
    r = save(env, path)
    assert not r.ok and r.problems[0].code == "DECISIONS_INVALID"


@pytest.mark.parametrize("field", ["clues", "created_at"])
def test_surrogate_in_scope_record_is_invalid(env, tmp_path, field):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    p = res(env, "CWE/4.14/CWE-79")
    saved = save(env, write_decisions(tmp_path, p, [adopt(p, "CWE/4.14/CWE-79")]))
    path = project / saved.data["path"]
    record = json.loads(path.read_text())
    record[field] = "SURROGATE"
    path.write_text(json.dumps(record).replace('"SURROGATE"', '"\\ud800"'))
    r = show(env, saved.data["scope_id"], output=str(tmp_path / "o.json"))
    assert not r.ok and r.problems[0].code == "SCOPE_INVALID"


def test_surrogate_in_rule_source_documents_is_dropped(env, tmp_path):
    project = env[0]
    assert load(env, tmp_path, item()).ok
    path = project / LOCAL / "CWE/4.14/CWE-79/record.json"
    record = json.loads(path.read_text())
    record["source_documents"] = ["SURROGATE", "sha256:ok"]
    path.write_text(json.dumps(record).replace('"SURROGATE"', '"\\ud800"'))
    r = res(env, "CWE/4.14/CWE-79", output=str(tmp_path / "o.json"))
    assert r.ok and entry(r, "CWE/4.14/CWE-79")["source_evidence"]["source_documents"] == ["sha256:ok"]
