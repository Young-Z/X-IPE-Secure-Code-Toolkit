"""FEATURE-001-E integration tests: plug-ins P1–P9 (AC-001E-07a…07k) and Local-only byte identity.

Paired tests of the closed list of superseded delivered assertions (DEC-13): items 1 and 3 →
`test_exit_preview_lists_reference_cache`, item 2 → `test_exit_preview_text_lists_reference_cache`,
item 4 → `test_no_impact_kind_unsupported`, item 6 → `test_tag_preset_reference_member_stored`, item 7 →
`test_pre_001e_preview_stale_after_upgrade` (item 5 is paired in `test_reference_skill.py`).
"""

from __future__ import annotations

import json

import capture_golden
import refhelp
from knowledge.exithelp import files, item
from netguard import network_guards  # noqa: F401 - autouse guards
from refhelp import (
    CWE79,
    CWE89,
    LOCAL,
    RefEnv,
    mod,
    preset_save,
    rule_item,
    seed,
    tag_save,
)

clock, renv, server = refhelp.clock, refhelp.renv, refhelp.server  # pytest fixtures

NOT_CHECKED = "not checked in this version"
REPORTS = "x-ipe-docs/secure-code/reports"
EMPTY_CACHE_IMPACT = {"count": 0, "items": [], "unreadable": []}


def preview(env, rule=CWE79, action="deactivate"):
    result = mod("knowledge.exit").preview(
        str(env.project), rule, action, None, "fixture reason", trust_paths=env.paths
    )
    assert result.ok, result.to_dict()
    return result


def confirm(env, digest, rule=CWE79, action="deactivate"):
    return mod("knowledge.exit").confirm(
        str(env.project), rule, action, None, "fixture reason", digest, trust_paths=env.paths
    )


def local_and_cached_reference(env):
    """Reference CWE-79 with a cache entry, then a formal Local CWE-79 (Local first from then on)."""
    env.standard(CWE79)
    assert seed(env).written
    assert env.load(item(CWE79)).ok


# AC-001E-07i
def test_status_line_only_with_reference_rules(project, tmp_path, server, clock):
    env = RefEnv(project, tmp_path, server)
    before = mod("status").collect(str(project), trust_paths=env.paths)
    assert "reference_rules" not in before.data["policies"]
    assert "Reference rules" not in before.to_text()
    first = json.dumps(before.to_dict(), sort_keys=True)
    again = mod("status").collect(str(project), trust_paths=env.paths)
    assert json.dumps(again.to_dict(), sort_keys=True) == first
    env.standard(CWE79, CWE89)
    after = mod("status").collect(str(project), trust_paths=env.paths)
    assert after.data["policies"]["local"] == before.data["policies"]["local"] == 1
    assert after.data["policies"]["reference"] == 2
    assert after.data["policies"]["reference_rules"] == "Reference rules: registered 2, available 0"
    assert after.to_text().count("Reference rules:") == 1
    assert seed(env).written
    cached = mod("status").collect(str(project), trust_paths=env.paths)
    assert cached.data["policies"]["reference_rules"] == "Reference rules: registered 2, available 1"
    clock.advance(days=7)
    expired = mod("status").collect(str(project), trust_paths=env.paths)
    assert expired.data["policies"]["reference_rules"] == "Reference rules: registered 2, available 0"


# AC-001E-07c (paired with closed-list items 1 and 3)
def test_exit_preview_lists_reference_cache(renv, clock):
    local_and_cached_reference(renv)
    shown = preview(renv).data["impact"]["reference_cache"]
    assert shown["count"] == 1 and shown["unreadable"] == []
    (entry,) = shown["items"]
    assert entry["rule"] == CWE79 and entry["kind"] == "rule" and entry["state"] == "valid"
    assert entry["fetched_at"] == "2026-10-24T01:00:00Z" and entry["expires_at"] == "2026-10-31T01:00:00Z"
    assert len(entry["key"]) == 64
    assert preview(renv, LOCAL).data["impact"]["reference_cache"] == EMPTY_CACHE_IMPACT
    assert NOT_CHECKED not in json.dumps(preview(renv).to_dict())


# AC-001E-07c (paired with closed-list item 2)
def test_exit_preview_text_lists_reference_cache(renv, clock):
    local_and_cached_reference(renv)
    code, _, text = renv.cli(
        "knowledge",
        "exit-preview",
        "--project",
        str(renv.project),
        "--rule",
        CWE79,
        "--action",
        "deactivate",
        "--reason",
        "fixture reason",
    )
    assert code == 0 and "reference_cache:" in text and NOT_CHECKED not in text
    assert renv.entry_files()[0].stem in text


# AC-001E-07c (paired with closed-list item 4)
def test_no_impact_kind_unsupported(renv):
    impact = mod("knowledge.impact")
    assert impact.UNSUPPORTED == ()
    assert [p.kind for p in impact.PROVIDERS][-1] == "reference_cache"
    shown = preview(renv, LOCAL)
    assert shown.data["impact"]["reference_cache"] == EMPTY_CACHE_IMPACT
    assert NOT_CHECKED not in shown.to_text() and "(none)" in shown.to_text()


# AC-001E-07d
def test_exit_confirm_invalidates_and_stale_impact(renv, clock):
    local_and_cached_reference(renv)
    first = preview(renv)
    clock.advance(days=8)  # the cache entry changes state (valid → expired) after the preview
    stale = confirm(renv, first.data["impact_digest"])
    assert not stale.ok and stale.problems[0].code == "STALE_IMPACT"
    assert len(renv.entry_files()) == 1
    again = preview(renv)
    assert again.data["impact"]["reference_cache"]["items"][0]["state"] == "expired"
    done = confirm(renv, again.data["impact_digest"])
    assert done.ok, done.to_dict()
    assert len(done.data["invalidated_reference_cache"]) == 1 and renv.entry_files() == []


# AC-001E-07a (paired with closed-list item 6)
def test_tag_preset_reference_member_stored(renv):
    renv.standard(CWE79)
    saved = tag_save(renv, "injection", [LOCAL, f"reference:{CWE79}"])
    assert saved.ok, saved.to_dict()
    stored = json.loads((renv.project / "x-ipe-docs/secure-code/tags/injection.json").read_text())
    assert stored["members"] == [{"rule": CWE79, "source": "reference"}, {"rule": LOCAL, "source": "local"}]
    assert "content" not in json.dumps(stored) and "requirement" not in json.dumps(stored)
    preset = preset_save(renv, "web-input", [f"reference:{CWE79}", LOCAL])
    assert preset.ok, preset.to_dict()
    stored = json.loads((renv.project / "x-ipe-docs/secure-code/presets/web-input.json").read_text())
    assert stored["rules"] == [{"rule": CWE79, "source": "reference"}, {"rule": LOCAL, "source": "local"}]
    refused = tag_save(renv, "other", [LOCAL, "reference:CWE/2024-top25/CWE-1"])
    assert not refused.ok and refused.problems[0].code == "REFERENCES_INVALID" and refused.next_steps
    (ref,) = refused.data["references"]
    assert ref["reason"] == "invalid_reference" and "not a registered reference rule" in ref["detail"].lower()
    shown = mod("knowledge.tags").show_tag(str(renv.project), "injection")
    assert [(m["rule"], m["source"]) for m in shown.data["members"]] == [
        (CWE79, "reference"),
        (LOCAL, "local"),
    ]


# AC-001E-07b
def test_tag_preset_members_resolved_local_first(renv, clock):
    renv.standard(CWE79, CWE89)
    assert seed(renv, CWE89).written
    assert renv.load(item(CWE79)).ok
    assert tag_save(renv, "injection", [CWE79, CWE89]).ok
    assert preset_save(renv, "web-input", [CWE79, CWE89]).ok
    before = files(renv.project / "x-ipe-docs/secure-code")
    resolved = mod("policy.preset_scope").resolve_preset(str(renv.project), "web-input", ["python"])
    assert resolved.ok, resolved.to_dict()
    entries = {e["requested"]: e for e in resolved.data["entries"]}
    assert entries[CWE79]["retrieval_status"] == "retrieved" and "knowledge_kind" not in entries[CWE79]
    assert entries[CWE89]["retrieval_status"] == "cached" and entries[CWE89]["knowledge_kind"] == "reference"
    shown = mod("knowledge.tags").show_tag(str(renv.project), "injection")
    assert {m["rule"]: m["source"] for m in shown.data["members"]} == {CWE79: "local", CWE89: "reference"}
    assert files(renv.project / "x-ipe-docs/secure-code") == before
    assert renv.srv.count == 0


# AC-001E-07e (DEC-08/09/14): Local-only outputs byte-identical to the pre-001-E golden capture
def test_local_only_outputs_unchanged(tmp_path):
    outputs = capture_golden.local_only_outputs(tmp_path)
    golden = {p.name: p.read_text(encoding="utf-8") for p in sorted(capture_golden.GOLDEN.glob("*.json"))}
    assert sorted(outputs) == sorted(golden)
    for name, text in outputs.items():
        if name != "exit-preview.json":
            assert text + "\n" == golden[name], name
    now, then = json.loads(outputs["exit-preview.json"]), json.loads(golden["exit-preview.json"])
    assert then[1]["data"]["impact"]["reference_cache"] == NOT_CHECKED
    assert now[1]["data"]["impact"]["reference_cache"] == EMPTY_CACHE_IMPACT
    for doc in (now, then):
        doc[1]["data"]["impact"].pop("reference_cache")
        doc[1]["data"].pop("impact_digest")
    assert now == then
    joined = "".join(outputs.values())
    for key in (
        "knowledge_kind",
        "notes",
        "requested_kind",
        "library_sizes",
        "counts_by_kind",
        "reference_rules",
    ):
        assert f'"{key}"' not in joined, key


def scope_with_reference(env):
    env.standard(CWE79)
    assert seed(env).written
    return env.save_scope(LOCAL, CWE79)


# AC-001E-07g
def test_guard_consumes_reference_policy_unchanged_report(renv, clock):
    scope_id = scope_with_reference(renv)
    policy = renv.entry(CWE79)
    vid = renv.opened(scope_id)
    adopted = renv.state(vid)["scope"]["adopted"]
    digests = {a["rule"]: a["state_digest"] for a in adopted}
    assert digests[CWE79] == policy["source_evidence"]["policy_state_digest"]
    local_vid = renv.opened(renv.save_scope(LOCAL))
    assert set(renv.state(vid)) == set(renv.state(local_vid))
    assert [set(a) for a in adopted] == [set(renv.state(local_vid)["scope"]["adopted"][0])] * 2
    for run in (vid, local_vid):
        assert renv.conclude(run).ok
    report = json.loads((renv.project / REPORTS / "guard" / f"{vid}.json").read_text())
    local_report = json.loads((renv.project / REPORTS / "guard" / f"{local_vid}.json").read_text())
    assert set(report) == set(local_report)
    assert all(set(a) == {"rule", "state_digest", "at_conclusion"} for a in report["scope"]["adopted"])
    assert "knowledge_kind" not in json.dumps(report) and "reference_cache" not in json.dumps(report)
    shown = mod("policy.service").show_scope(str(renv.project), scope_id)
    evidence = next(e for e in shown.data["entries"] if e["rule"] == CWE79)["policy"]["source_evidence"]
    for key in ("entry_url", "fetched_at", "response_digest", "policy_state_digest", "parser_version"):
        assert evidence[key], key
    assert renv.srv.count == 0


# AC-001E-07h
def test_copilot_consumes_reference_policy_never_fetches(renv, clock):
    scope_id = scope_with_reference(renv)
    copilot = mod("copilot.service")
    opened = copilot.open_collaboration(str(renv.project), renv.open_request(scope_id, "copilot"))
    assert opened.ok, opened.to_dict()
    cid = opened.data["collaboration_id"]
    state = json.loads((renv.project / ".x-ipe/private/secure-code/copilot" / cid / "state.json").read_text())
    digests = {a["rule"]: a["state_digest"] for a in state["scope"]["adopted"]}
    assert digests[CWE79] == renv.entry(CWE79)["source_evidence"]["policy_state_digest"]
    assert all(set(a) == set(state["scope"]["adopted"][0]) for a in state["scope"]["adopted"])
    assert copilot.close(str(renv.project), cid).ok
    assert renv.srv.count == 0 and "knowledge_kind" not in json.dumps(state)


# AC-001E-07j
def test_removed_reference_broken_never_substituted(renv, clock):
    renv.standard(CWE79)
    assert seed(renv).written
    scope_id = renv.save_scope(LOCAL, CWE79)
    assert tag_save(renv, "injection", [LOCAL, f"reference:{CWE79}"]).ok
    tag_file = renv.project / "x-ipe-docs/secure-code/tags/injection.json"
    kept = tag_file.read_bytes()
    ops = mod("reference.registry_ops")
    p = str(renv.project)
    shown = ops.remove_preview(p, CWE79, "withdrawn", trust_paths=renv.paths)
    assert shown.data["impact"]["scopes"]["count"] == 1 and shown.data["impact"]["tags"]["count"] == 1
    assert ops.remove_confirm(
        p, CWE79, "withdrawn", shown.data["impact_digest"], renv.registration_digest(), trust_paths=renv.paths
    ).ok
    found = renv.entry(CWE79)
    assert found["availability"] == "missing" and found["reason"] == "deleted" and found["removed_at"]
    loaded = mod("policy.service").show_scope(p, scope_id).data["entries"]
    assert {e["rule"]: (e["adoption"], e.get("reason")) for e in loaded}[CWE79] == ("missing", "deleted")
    broken = mod("knowledge.tags").show_tag(p, "injection").data["broken"]
    assert [(b["target"], b["reason"]) for b in broken] == [(CWE79, "deleted")]
    assert tag_file.read_bytes() == kept and renv.entry_files() == []
    assert renv.register(rule_item(CWE79, renv.url("/docs/cwe/79.html"))).ok
    assert renv.entry(CWE79)["reason"] == "not_cached"


# AC-001E-07k (paired with closed-list item 7)
def test_pre_001e_preview_stale_after_upgrade(renv, monkeypatch, clock):
    scope_id = renv.save_scope(LOCAL)
    guard_run = renv.opened(scope_id)
    assert renv.conclude(guard_run).ok
    copilot = mod("copilot.service")
    collab = copilot.open_collaboration(str(renv.project), renv.open_request(scope_id, "copilot"))
    assert collab.ok, collab.to_dict()
    assert copilot.close(str(renv.project), collab.data["collaboration_id"]).ok
    impact = mod("knowledge.impact")
    with monkeypatch.context() as old:
        old.setattr(impact, "PROVIDERS", tuple(p for p in impact.PROVIDERS if p.kind != "reference_cache"))
        old.setattr(impact, "UNSUPPORTED", ("reference_cache",))
        before_upgrade = preview(renv, LOCAL)
        assert before_upgrade.data["impact"]["reference_cache"] == NOT_CHECKED
    before = files(renv.project / "x-ipe-docs")
    assert (renv.project / REPORTS / "guard" / f"{guard_run}.json").is_file()
    for _ in range(2):
        stale = confirm(renv, before_upgrade.data["impact_digest"], LOCAL)
        assert not stale.ok and stale.problems[0].code == "STALE_IMPACT"
        assert "preview again" in stale.next_steps[0].lower()
        assert files(renv.project / "x-ipe-docs") == before
    again = preview(renv, LOCAL)
    assert again.data["impact"]["reference_cache"] == EMPTY_CACHE_IMPACT
    assert confirm(renv, again.data["impact_digest"], LOCAL).ok


def recompute_request(env, candidates, **over):
    return env.req({"schema": "ai-secure-code-toolkit/preset-recompute/v1", "candidates": candidates, **over})


def intent_preset(env, rules):
    path = env.req(
        {
            "schema": "ai-secure-code-toolkit/preset-request/v1",
            "name": "web-input",
            "rules": rules,
            "query_intent": "input handling rules",
            "applicability_summary": "web",
        }
    )
    assert mod("knowledge.presets").save_preset(str(env.project), path, True).ok


# review fix 2 (DAO-007): an explicit accept_add keeps the Reference member source
def test_recompute_confirm_explicit_accept_keeps_reference_source(renv, clock):
    renv.standard(CWE79, CWE89)
    assert seed(renv).written
    intent_preset(renv, [LOCAL])
    presets = mod("knowledge.presets")
    candidates = [LOCAL, f"reference:{CWE79}", f"reference:{CWE89}"]
    shown = presets.recompute(str(renv.project), "web-input", recompute_request(renv, candidates))
    assert shown.ok, shown.to_dict()
    assert [a["rule"] for a in shown.data["add"]] == [CWE79, CWE89]
    done = presets.recompute_confirm(
        str(renv.project),
        "web-input",
        recompute_request(
            renv,
            candidates,
            recompute_digest=shown.data["recompute_digest"],
            accept_add=[CWE79],
            keep_summary=True,
        ),
        True,
    )
    assert done.ok, done.to_dict()
    stored = json.loads((renv.project / "x-ipe-docs/secure-code/presets/web-input.json").read_text())
    assert stored["rules"] == [{"rule": CWE79, "source": "reference"}, {"rule": LOCAL, "source": "local"}]


# DEC-I11 (DAO-007): the str-subclass carrier leaves Local member serialization byte-identical
def test_local_member_serialization_byte_identical():
    catalog = mod("knowledge.catalog")
    rels = ["CWE/4.14/CWE-89", "@ACME/v1/A-1", "CWE/4.14/CWE-79", "CWE/4.14/CWE-79"]
    delivered = [{"rule": rel, "source": "local"} for rel in sorted(set(rels))]
    for given in (rels, [catalog.Member(r) for r in rels], [catalog.Member(r, "local") for r in rels]):
        assert catalog._members(given) == delivered
        doc = catalog.serialize(catalog.tag_doc("injection", given))
        expected = (
            json.dumps(
                {"schema": catalog.TAG.schema, "name": "injection", "members": delivered},
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
        assert doc == expected
    assert catalog.Member("CWE/4.14/CWE-79", "reference") == "CWE/4.14/CWE-79"
    assert hash(catalog.Member("CWE/4.14/CWE-79", "reference")) == hash("CWE/4.14/CWE-79")


# re-review nit (DAO-008): an uncached Reference add row carries the reason, like stored rows
def test_recompute_add_row_shape_for_reference_members(renv, clock):
    renv.standard(CWE79, CWE89)
    assert seed(renv).written
    intent_preset(renv, [LOCAL])
    candidates = [LOCAL, f"reference:{CWE79}", f"reference:{CWE89}"]
    shown = mod("knowledge.presets").recompute(
        str(renv.project), "web-input", recompute_request(renv, candidates)
    )
    assert shown.ok, shown.to_dict()
    cached, uncached = shown.data["add"]
    digest = renv.entry(CWE79)["source_evidence"]["state_digest"]
    assert cached == {"rule": CWE79, "availability": "available", "state_digest": digest}
    assert uncached == {
        "rule": CWE89,
        "availability": "missing",
        "state_digest": None,
        "reason": "not_cached",
    }
