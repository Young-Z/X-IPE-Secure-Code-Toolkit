"""FEATURE-001-E integration tests: Reference registry (AC-001E-01a…01d, 01l, 05f, 08c, 08e; DEC-06/07)."""

from __future__ import annotations

import json
import os
import threading

import pytest
import refhelp
from conftest import PASSPHRASE, FakeInteraction, tree_hashes
from knowledge.exithelp import item, need_symlinks
from netguard import network_guards  # noqa: F401 - autouse guards
from refhelp import (
    CWE79,
    CWE89,
    LOCAL,
    REGISTRY,
    mod,
    rule_item,
    source_item,
)

from x_ipe_secure_code.auth.service import revoke_authorization

clock, renv, server = refhelp.clock, refhelp.renv, refhelp.server  # pytest fixtures


def codes(result):
    return [i.get("code") for i in result.data["items"]]


# AC-001E-01a
def test_register_source_and_rule_formal_no_body_status_line(renv, clock):
    result = renv.register(
        source_item(port=renv.srv.port, display_name="CWE Top 25 (2024)"),
        rule_item(CWE79, renv.url("/docs/cwe/79.html")),
    )
    assert result.ok, result.to_dict()
    assert [(i["type"], i["id"], i["outcome"]) for i in result.data["items"]] == [
        ("source", "CWE/2024-top25", "registered"),
        ("rule", CWE79, "registered"),
    ]
    base = renv.project / REGISTRY / "CWE" / "2024-top25"
    source = json.loads((base / ".source.json").read_text())
    rule = json.loads((base / "CWE-79" / "reference.json").read_text())
    assert source["schema"] == "ai-secure-code-toolkit/reference-source/v1" and source["domains"] == [
        "127.0.0.1"
    ]
    assert set(rule) == {
        "schema",
        "rule",
        "title",
        "entry_url",
        "applicability",
        "revision",
        "registered_at",
        "updated_at",
    }
    assert rule["entry_url"] == renv.url("/docs/cwe/79.html") and rule["applicability"] == "unknown"
    assert sorted(os.listdir(base / "CWE-79")) == ["reference.json"]
    log = (base / ".changelog.md").read_text()
    assert "registered source CWE/2024-top25" in log and f"registered rule {CWE79}" in log
    status = mod("status").collect(str(renv.project), trust_paths=renv.paths)
    assert status.data["policies"]["reference"] == 1 and status.data["policies"]["local"] == 1
    assert status.data["policies"]["reference_rules"] == "Reference rules: registered 1, available 0"
    assert "Reference rules: registered 1, available 0" in status.to_text()


# AC-001E-01b
@pytest.mark.parametrize("op", ["register", "update", "remove-preview", "remove-confirm", "remove-source"])
def test_registry_writes_need_maintainer(renv, op):
    renv.standard(CWE79)
    digest = renv.registration_digest()
    assert revoke_authorization(paths=renv.paths, interaction=FakeInteraction(answers=[PASSPHRASE])).ok
    before = tree_hashes(renv.project / "x-ipe-docs")
    ops = mod("reference.registry_ops")
    p = str(renv.project)
    result = {
        "register": lambda: renv.register(rule_item(CWE89, renv.url("/docs/cwe/89.html"))),
        "update": lambda: ops.update(
            p, rule=CWE79, registration_digest=digest, changes={"title": "X"}, trust_paths=renv.paths
        ),
        "remove-preview": lambda: ops.remove_preview(p, CWE79, "withdrawn", trust_paths=renv.paths),
        "remove-confirm": lambda: ops.remove_confirm(
            p, CWE79, "withdrawn", "sha256:" + "0" * 64, digest, trust_paths=renv.paths
        ),
        "remove-source": lambda: ops.remove_source(p, "CWE/2024-top25", digest, trust_paths=renv.paths),
    }[op]()
    assert not result.ok and result.problems[0].code == "NOT_AUTHORIZED", result.to_dict()
    assert len(result.next_steps) == 1
    assert tree_hashes(renv.project / "x-ipe-docs") == before


# AC-001E-01c
@pytest.mark.parametrize("case", ["exact", "case", "exited"])
def test_registration_identity_collisions_refused(renv, case):
    renv.standard(CWE79)
    if case == "exited":
        assert renv.load(item("CWE/2024-top25/CWE-22")).ok
        renv.exit("delete", "CWE/2024-top25/CWE-22")
    before = renv.registry_files()
    rule = {"exact": CWE79, "case": "CWE/2024-top25/cwe-79", "exited": "CWE/2024-top25/CWE-22"}[case]
    result = renv.register(rule_item(rule, renv.url("/docs/cwe/x.html")))
    assert not result.ok
    item_ = result.data["items"][0]
    assert item_["code"] == ("IDENTITY_RESERVED" if case == "exited" else "IDENTITY_COLLISION")
    assert ("CWE-22" if case == "exited" else "CWE-79") in item_["reason"]
    assert renv.registry_files() == before


def test_source_collision_and_case_variant_refused(renv):
    renv.standard()
    before = renv.registry_files()
    for ns_ver in ("CWE/2024-top25", "cwe/2024-TOP25"):
        result = renv.register(source_item(ns_ver, port=renv.srv.port))
        assert codes(result) == ["IDENTITY_COLLISION"], result.to_dict()
    assert renv.registry_files() == before


# AC-001E-01d
def test_rule_entry_url_outside_domains_refused(renv):
    renv.standard(CWE79)
    before = renv.registry_files()
    result = renv.register(rule_item(CWE89, "https://evil.example.test/docs/cwe/89.html"))
    assert (
        codes(result) == ["REGISTRATION_INVALID"]
        and result.data["items"][0]["reason"] == "scheme_not_allowed"
    )
    result = renv.register(rule_item(CWE89, f"http://127.0.0.1:{renv.srv.port}/other/89.html"))
    assert result.data["items"][0]["reason"] == "path_not_registered"
    result = renv.register(
        source_item("OWASP/2025", ["owasp.example.test"], scheme="https"),
        rule_item("OWASP/2025/A01", "https://evil.example.test/a01"),
    )
    assert result.data["items"][1]["reason"] == "unregistered_host"
    assert not (renv.project / REGISTRY / "OWASP" / "2025" / "A01").exists()
    upd = mod("reference.registry_ops").update(
        str(renv.project),
        rule=CWE79,
        registration_digest=renv.registration_digest(),
        changes={"entry_url": "https://evil.example.test/x"},
        trust_paths=renv.paths,
    )
    assert upd.problems[0].code == "REGISTRATION_INVALID"
    assert {k: v for k, v in renv.registry_files().items() if not k.startswith("OWASP")} == before


def test_batch_refuses_unknown_keys_and_reports_each_item(renv):
    renv.standard()
    result = renv.register(
        rule_item(CWE79, renv.url("/docs/cwe/79.html"), resolver="8.8.8.8"),
        rule_item(CWE89, renv.url("/docs/cwe/89.html"), title="SQL Injection"),
        {"type": "rule", "rule": "CWE/2024-top25/X", "title": "t", "entry_url": "x", "opener": "fixture"},
    )
    assert codes(result) == ["REQUEST_INVALID", None, "REQUEST_INVALID"]
    assert [i["outcome"] for i in result.data["items"]] == ["refused", "registered", "refused"]
    bad = renv.req({"schema": "ai-secure-code-toolkit/reference-batch/v1", "items": [], "clock": "x"})
    refused = mod("reference.registry_ops").register_batch(str(renv.project), bad, trust_paths=renv.paths)
    assert refused.problems[0].code == "REQUEST_INVALID"


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("title", "", "title_invalid"),
        ("title", "x" * 301, "title_invalid"),
        ("title", "token ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "title_invalid"),
        ("applicability", "python", "applicability_invalid"),
    ],
)
def test_rule_field_refusals(renv, field, value, reason):
    renv.standard()
    result = renv.register(rule_item(CWE79, renv.url("/docs/cwe/79.html"), **{field: value}))
    assert result.data["items"][0]["reason"] == reason


def test_source_registration_field_refusals(renv):
    result = renv.register(
        source_item("A/1", ["localhost"]),
        source_item("B/1", ["127.0.0.1"], port="x"),
        source_item("C/1", ["127.0.0.1"], path_prefix="docs"),
        source_item("D/1", ["example.test"]),
        source_item("E/1", ["Bücher.test."], scheme="https"),
    )
    assert [i.get("reason") for i in result.data["items"]] == [
        "localhost_not_allowed",
        "port_invalid",
        "path_prefix_invalid",
        "scheme_not_allowed",
        None,
    ]
    shown = renv.service.show(str(renv.project), source="E/1")
    assert shown.data["source"]["domains"] == ["xn--bcher-kva.test"]


# AC-001E-05f
def test_unfetched_rule_listed_content_not_obtained(renv):
    renv.standard(CWE79)
    listed = renv.service.list_references(str(renv.project))
    assert listed.ok
    (rule,) = listed.data["rules"]
    assert rule["rule"] == CWE79 and rule["cache_state"] == "content not obtained"
    assert rule["title"] == "Cross-site Scripting" and rule["entry_url"] == renv.url("/docs/cwe/79.html")
    shown = renv.show()
    assert shown.data["label"] == "content not obtained" and shown.data["source"]["domains"] == ["127.0.0.1"]
    assert shown.data["registration"]["entry_url"] == renv.url("/docs/cwe/79.html")
    code, out, text = renv.cli("knowledge", "reference", "list", "--project", str(renv.project), "--json")
    assert code == 0 and out["data"]["rules"][0]["cache_state"] == "content not obtained"
    code, _, text = renv.cli(
        "knowledge", "reference", "show", "--project", str(renv.project), "--rule", CWE79
    )
    assert code == 0 and "content not obtained" in text


# AC-001E-08c
def test_concurrent_maintainer_updates_conflict(renv):
    renv.standard(CWE79)
    digest = renv.registration_digest()
    ops = mod("reference.registry_ops")
    results = []
    barrier = threading.Barrier(2)

    def update(title):
        barrier.wait()
        results.append(
            ops.update(
                str(renv.project),
                rule=CWE79,
                registration_digest=digest,
                changes={"title": title},
                trust_paths=renv.paths,
            )
        )

    workers = [threading.Thread(target=update, args=(t,)) for t in ("Title A", "Title B")]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    oks = [r for r in results if r.ok]
    refused = [r for r in results if not r.ok]
    assert len(oks) == 1 and [r.problems[0].code for r in refused] == ["STALE_REGISTRATION"]
    record = json.loads((renv.project / REGISTRY / CWE79 / "reference.json").read_text())
    assert record["title"] == oks[0].data["record"]["title"] and record["revision"] == 2
    log = (renv.project / REGISTRY / "CWE/2024-top25/.changelog.md").read_text()
    assert log.count(f"updated rule {CWE79}") == 1


# AC-001E-08e (registry part)
@pytest.mark.parametrize("where", ["registry", "namespace", "rule"])
def test_symlinks_refused_registry(renv, tmp_path, where):
    need_symlinks(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("untouched")
    if where == "registry":
        (renv.project / REGISTRY).rmdir()  # created empty by project initialization
        (renv.project / REGISTRY).symlink_to(outside, target_is_directory=True)
        result = renv.register(source_item(port=renv.srv.port))
    elif where == "namespace":
        (renv.project / REGISTRY).mkdir(parents=True, exist_ok=True)
        (renv.project / REGISTRY / "CWE").symlink_to(outside, target_is_directory=True)
        result = renv.register(source_item(port=renv.srv.port))
    else:
        renv.standard()
        (renv.project / REGISTRY / "CWE/2024-top25/CWE-79").symlink_to(outside, target_is_directory=True)
        result = renv.register(rule_item(CWE79, renv.url("/docs/cwe/79.html")))
    assert not result.ok
    found = result.problems[0].code if not result.data.get("items") else result.data["items"][-1]["code"]
    assert found in ("PATH_UNSAFE", "IDENTITY_COLLISION"), result.to_dict()
    assert sorted(os.listdir(outside)) == ["sentinel.txt"] and sentinel.read_text() == "untouched"


# DEC-06 (DAO-020 TD): hidden registry files never change the delivered status count
def test_hidden_registry_files_do_not_affect_status_count(renv):
    renv.standard(CWE79, CWE89)
    digest = renv.registration_digest(CWE89)
    ops = mod("reference.registry_ops")
    preview = ops.remove_preview(str(renv.project), CWE89, "withdrawn", trust_paths=renv.paths)
    assert preview.ok, preview.to_dict()
    removed = ops.remove_confirm(
        str(renv.project), CWE89, "withdrawn", preview.data["impact_digest"], digest, trust_paths=renv.paths
    )
    assert removed.ok, removed.to_dict()
    (renv.project / REGISTRY / ".stray-hidden").write_text("x")
    (renv.project / REGISTRY / "CWE" / ".hidden").write_text("x")
    assert (renv.project / REGISTRY / ".removed.json").is_file()
    assert (renv.project / REGISTRY / "CWE/2024-top25/.source.json").is_file()
    status = mod("status").collect(str(renv.project), trust_paths=renv.paths)
    assert status.data["policies"]["reference"] == 1
    assert status.data["policies"]["reference_rules"] == "Reference rules: registered 1, available 0"


def test_update_source_and_rule_with_current_digest(renv, clock):
    renv.standard(CWE79)
    ops = mod("reference.registry_ops")
    p = str(renv.project)
    stale = ops.update(
        p,
        rule=CWE79,
        registration_digest="sha256:" + "1" * 64,
        changes={"title": "New"},
        trust_paths=renv.paths,
    )
    assert stale.problems[0].code == "STALE_REGISTRATION"
    upd = ops.update(
        p,
        rule=CWE79,
        registration_digest=renv.registration_digest(),
        changes={"title": "New title", "applicability": ["python"]},
        trust_paths=renv.paths,
    )
    assert upd.ok, upd.to_dict()
    assert (
        upd.data["record"]["revision"] == 2 and upd.data["registration_digest"] == renv.registration_digest()
    )
    narrowed = ops.update(
        p,
        source="CWE/2024-top25",
        registration_digest=renv.source_digest(),
        changes={"path_prefix": "/other/"},
        trust_paths=renv.paths,
    )
    assert narrowed.problems[0].code == "REGISTRATION_INVALID" and CWE79 in narrowed.problems[0].message
    shown = renv.show()
    assert shown.data["registration"]["title"] == "New title"
    assert shown.data["registration"]["applicability"] == ["python"]


# AC-001E-07j (registry part) + DEC-07: removal leaves a tombstone, re-registration drops it
def test_remove_two_step_and_reregister(renv):
    renv.standard(CWE79)
    ops = mod("reference.registry_ops")
    p = str(renv.project)
    digest = renv.registration_digest()
    preview = ops.remove_preview(p, CWE79, "withdrawn", trust_paths=renv.paths)
    assert preview.ok and "reference_cache" in preview.data["impact"]
    stale = ops.remove_confirm(p, CWE79, "withdrawn", "sha256:" + "2" * 64, digest, trust_paths=renv.paths)
    assert stale.problems[0].code == "STALE_IMPACT"
    done = ops.remove_confirm(
        p, CWE79, "withdrawn", preview.data["impact_digest"], digest, trust_paths=renv.paths
    )
    assert done.ok, done.to_dict()
    assert not (renv.project / REGISTRY / CWE79).exists()
    removed = json.loads((renv.project / REGISTRY / ".removed.json").read_text())
    assert [r["rule"] for r in removed["removed"]] == [CWE79]
    log = (renv.project / REGISTRY / "CWE/2024-top25/.changelog.md").read_text()
    assert removed["removed"][0]["removal_id"] in log
    has_rules = ops.remove_source(p, "CWE/2024-top25", renv.source_digest(), trust_paths=renv.paths)
    assert has_rules.ok, has_rules.to_dict()
    again = renv.standard(CWE79)
    assert again.ok
    assert json.loads((renv.project / REGISTRY / ".removed.json").read_text())["removed"] == []


def test_remove_source_refused_while_rules_exist(renv):
    renv.standard(CWE79)
    result = mod("reference.registry_ops").remove_source(
        str(renv.project), "CWE/2024-top25", renv.source_digest(), trust_paths=renv.paths
    )
    assert result.problems[0].code == "SOURCE_HAS_RULES"


def test_interrupted_removal_completed_by_next_write(renv, monkeypatch):
    renv.standard(CWE79, CWE89)
    ops = mod("reference.registry_ops")
    p = str(renv.project)
    digest = renv.registration_digest()
    preview = ops.remove_preview(p, CWE79, "withdrawn", trust_paths=renv.paths)

    def crash(*args, **kwargs):
        raise OSError("simulated crash after the tombstone")

    monkeypatch.setattr(ops, "_delete_rule_files", crash)
    failed = ops.remove_confirm(
        p, CWE79, "withdrawn", preview.data["impact_digest"], digest, trust_paths=renv.paths
    )
    assert not failed.ok
    assert (renv.project / REGISTRY / CWE79 / "reference.json").exists()
    monkeypatch.undo()
    later = ops.update(
        p,
        rule=CWE89,
        registration_digest=renv.registration_digest(CWE89),
        changes={"title": "SQLi"},
        trust_paths=renv.paths,
    )
    assert later.ok, later.to_dict()
    assert not (renv.project / REGISTRY / CWE79).exists()
    log = (renv.project / REGISTRY / "CWE/2024-top25/.changelog.md").read_text()
    assert f"removed rule {CWE79}" in log
    assert renv.entry(CWE79)["reason"] == "deleted"


def test_local_rule_paths_untouched_by_registry(renv):
    before = tree_hashes(renv.project / "x-ipe-docs/secure-code/knowledge/local")
    renv.standard(CWE79, CWE89)
    assert tree_hashes(renv.project / "x-ipe-docs/secure-code/knowledge/local") == before
    assert renv.resolve(LOCAL).data["entries"][0]["availability"] == "available"
