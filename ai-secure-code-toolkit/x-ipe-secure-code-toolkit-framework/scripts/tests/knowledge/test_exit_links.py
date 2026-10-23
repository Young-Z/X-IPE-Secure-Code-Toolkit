"""AC-001D-04e,05d Integration: read-only links/show and lifecycle inventory.

Arrange actual incoming/self relations and scope; Act exit, links/list/show;
Assert broken identifiers/reasons, no substitutions and byte-identical relations.
"""

from __future__ import annotations

import re

import pytest
from knowledge.exithelp import R1, R2, REASON, TARGET, Env, files, module, refusal

from x_ipe_secure_code.knowledge import service


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate(rich=True)
    return result


@pytest.mark.parametrize("action,reason", [
    ("deactivate", "deactivated"), ("delete", "deleted"), ("rename", "renamed"),
])
def test_links_and_show_report_broken_without_repair(env, action, reason):
    saved = env.save()
    assert saved.ok
    original = (env.folder(R2) / "record.json").read_bytes()
    env.exit(action)
    before = files(env.project)
    links = module("exit").links(str(env.project))
    assert links.ok, links.to_dict()
    found = next(b for b in links.data["broken_relations"] if b["source"] == R2 and b["target"] == R1)
    assert found["reason"] == reason
    if action == "rename":
        assert found["renamed_to"] == TARGET
        self_link = next(b for b in links.data["broken_relations"] if b["source"] == TARGET)
        assert self_link["target"] == R1 and self_link["reason"] == "renamed"
    scope_link = next(s for s in links.data["scopes"] if s["scope_id"] == saved.data["scope_id"])
    assert scope_link["rule"] == R1
    assert scope_link["reason"] == reason
    shown = env.show(R2)
    assert shown.ok
    relation = next(b for b in shown.data["broken_relations"] if b["target"] == R1)
    assert relation["reason"] == reason
    assert shown.data["record"]["relations"] == [R1]
    assert (env.folder(R2) / "record.json").read_bytes() == original
    assert any("separate" in s.lower() and "explicit" in s.lower() for s in links.next_steps)
    assert files(env.project) == before


def test_list_show_lifecycle(env):
    env.exit("deactivate", R1)
    env.exit("delete", R2)
    env.exit("rename", "CWE/4.14/CWE-22", target="CWE/4.14/NEW-22")
    before = files(env.project)
    listed = service.list_rules(str(env.project))
    inactive = next(r for r in listed.data["rules"] if r["rule"] == R1)
    assert inactive["state"] == "deactivated"
    assert inactive["lifecycle_revision"] == 1
    assert inactive["state_digest"] != inactive["item_digest"]
    exited = {r["rule"]: r for r in listed.data["exited"]}
    assert set(exited) == {R2, "CWE/4.14/CWE-22"}
    assert exited[R2]["action"] == "deleted"
    assert exited["CWE/4.14/CWE-22"]["action"] == "renamed"
    for rule, entry in exited.items():
        assert entry["reason"] == REASON
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["at"])
        shown = env.show(rule)
        refusal(shown, "RULE_NOT_FOUND")
        assert shown.data["exited"]["reason"] == REASON
        assert shown.data["exited"]["at"] == entry["at"]
    assert env.show().data["state"] == "deactivated"
    assert files(env.project) == before
