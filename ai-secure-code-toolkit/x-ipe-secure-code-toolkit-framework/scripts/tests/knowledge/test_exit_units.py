"""G-03 compatibility characterization (run GREEN before new lifecycle APIs).

Arrange: fixed import clock and controlled never-exited library.
Act: import/show/resolve/save/open real Guard and Copilot and accept an import.
Assert: captured constants, not expectations recomputed by production algorithms.
"""

from __future__ import annotations

import pytest
from knowledge.exithelp import AT, R1, R3, Env, files, item, sha

from x_ipe_secure_code.copilot import model
from x_ipe_secure_code.copilot import service as copilot
from x_ipe_secure_code.guard import runs
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.policy import service as policy

ITEM = "sha256:503911fce4a38fa985b9504e7a7dbca4c9b45fb7936573cedf7b4ca383856df2"
CHANGED = "sha256:a4227fd895731430dc81f4d67a84b53a149c8047b78dcd6c5e882fa7fda9f59a"
PROPOSAL = "sha256:e837a9c847439044fd41019a7007f23e1ddcb30b063387f635a38f6ebf36306f"
ALL = "sha256:eb82b432acc89c62396c70b0100875de284967802b2955f0af66a9a33e85b188"
SCOPE = "sha256:34b911a13fb1d3339d87fde3d3f4525a48c78e6ca0dc795efc73077629a533c6"
ADOPTED = [
    {"rule": R3, "state_digest": "sha256:206f739064aa2a4d1056cdafef5fb1b25969c304e70a3ad009a7643a393d1d73"},
    {"rule": R1, "state_digest": ITEM},
]


@pytest.fixture
def env(project, tmp_path, monkeypatch):
    monkeypatch.setattr(knowledge, "_now", lambda: AT)
    result = Env(project, tmp_path)
    result.populate()
    return result


def test_characterization_rule_bytes_and_item_digest(env):
    assert {p.name: sha(p.read_bytes()) for p in env.folder().iterdir()} == {
        "record.json": "sha256:9a0c1326e61386d17332ce0da97f99e018b5823050150c1dcd57506d3da9cc66",
        "example.md": "sha256:e5d3a75f96154e69e67f2766de19e8bea932583b259eaf009b40fe1a72a84034",
        "changelog.md": "sha256:8ea859f62135d4d598bc346e3804304cc82f0afd76032f48564b335f1d1db1aa",
        "content.md": "sha256:86498eca97d0c7fef5eb565bacf16ed0eb26412031e9897fb25c85c84f969558",
        "example-python.md": "sha256:11e4ddf5d6575778e814a4554d91bf02df9c0f8094e898018dd3234d3c3c419f",
    }
    assert env.show().data["item_digest"] == ITEM
    assert "lifecycle" not in env.show().data["record"]


def test_characterization_proposals_and_scope_identity(env):
    before = files(env.folder())
    assert env.proposal().data["proposal_digest"] == PROPOSAL
    assert env.proposal(all_=True).data["proposal_digest"] == ALL
    saved = env.save()
    assert saved.ok
    assert saved.data["scope_id"] == SCOPE
    assert env.proposal().data["entries"][0]["source_evidence"]["state_digest"] == ITEM
    assert files(env.folder()) == before


def test_characterization_guard_copilot_never_exited_adoption(env):
    saved = env.save()
    g, c = env.open_runs(saved.data["scope_id"])
    gs = runs.read_state(env.project, g)
    cs = model.read_state(env.project, c)
    assert gs["scope"]["adopted"] == ADOPTED
    assert cs["scope"]["adopted"] == ADOPTED
    assert policy.adoption_now(env.project, SCOPE, ADOPTED, "guard conclude") == {
        R1: "unchanged", R3: "unchanged",
    }
    assert guard._policy_now(env.project, gs, "guard conclude") == {R1: "unchanged", R3: "unchanged"}
    assert copilot._policy_now(env.project, cs, "copilot report") == {R1: "unchanged", R3: "unchanged"}


def test_characterization_import_candidate_accept_uses_item_digest(env):
    before = files(env.folder())
    candidate = env.load(item(content="Replacement body.\n"))
    assert candidate.ok
    assert candidate.data["items"] == [{
        "rule": R1, "outcome": "update_candidate", "stored_digest": ITEM, "item_digest": CHANGED,
        "reason": "same identity, different input; accept explicitly to update",
    }]
    assert candidate.data["counts"] == {"update_candidate": 1}
    assert files(env.folder()) == before
    stale = env.load(item(content="Replacement body.\n"), accept=(R1 + "@sha256:" + "0" * 64,))
    assert stale.data["items"][0]["code"] == "STATE_CONFLICT"
    assert files(env.folder()) == before
    accepted = env.load(item(content="Replacement body.\n"), accept=(R1 + "@" + ITEM,))
    assert accepted.data["items"] == [{
        "rule": R1, "outcome": "stored", "operation": "accepted_update", "item_digest": CHANGED,
    }]
    assert (env.folder() / "content.md").read_bytes() == b"Replacement body.\n"
