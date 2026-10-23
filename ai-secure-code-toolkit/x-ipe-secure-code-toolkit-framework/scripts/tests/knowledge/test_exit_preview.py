"""AC-001D-01b/c,02a-e,03g Integration: authenticated read-only, digest-bound decisions.

Arrange actual imports, scopes and private runs; Act preview/confirm; Assert every
provider/authorization/request branch and exact no-current-request-write snapshots.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from conftest import run_cli
from knowledge.exithelp import (
    DOC,
    R1,
    R2,
    R3,
    REASON,
    SUPPORTED,
    TARGET,
    Env,
    files,
    refusal,
)

from x_ipe_secure_code.auth.trust_store import resolve
from x_ipe_secure_code.knowledge import store

# Design "Command Contract" result data (success); `recovered_exit` only when recovery ran.
PREVIEW_KEYS = {
    "impact", "action", "rule", "target", "reason", "rule_state", "will", "impact_digest",
    "references_block",
}
CONFIRM_KEYS = {
    "outcome", "rule", "target", "exit_id", "lifecycle_revision", "state_digest", "removed_pending",
    "invalidated_index", "tombstone", "impact",
}
OUTCOMES = {
    "deactivate": "deactivated", "reactivate": "reactivated", "delete": "deleted", "rename": "renamed",
}


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate(rich=True)
    return result


def unqualified(env, kind):
    if kind == "missing":
        return resolve(env.work / "no-qualification")
    if kind == "invalid":
        env.paths.state.write_text('{"signature":"invalid"}')
    else:
        env.revoke()
    return env.paths


@pytest.mark.parametrize("kind", ["missing", "invalid", "revoked"])
def test_preview_authorization(env, kind):
    paths = unqualified(env, kind)
    before = files(env.project)
    result = env.preview(paths=paths)
    refusal(result, "NOT_AUTHORIZED")
    assert "impact" not in result.data
    assert "impact_digest" not in result.data
    assert files(env.project) == before


@pytest.mark.parametrize("kind", ["missing", "invalid", "revoked"])
def test_confirm_authorization(env, kind):
    paths = unqualified(env, kind)
    before = files(env.project)
    result = env.confirm("sha256:" + "0" * 64, paths=paths)
    refusal(result, "NOT_AUTHORIZED")
    assert files(env.project) == before


def test_revoked_after_preview(env):
    preview = env.preview()
    assert preview.ok
    env.revoke()
    before = files(env.project)
    result = env.confirm(preview.data["impact_digest"])
    refusal(result, "NOT_AUTHORIZED")
    assert files(env.project) == before


@pytest.mark.parametrize("action", ["deactivate", "reactivate", "delete", "rename"])
def test_all_providers_and_read_only_preview(env, action):
    saved = env.save()
    assert saved.ok
    vid, cid = env.open_runs(saved.data["scope_id"], history=True)
    env.pending()
    if action == "reactivate":
        env.exit("deactivate")
    before = files(env.project)
    target = TARGET if action == "rename" else None
    result = env.preview(action, target=target)
    assert result.ok, result.to_dict()
    assert next(iter(result.data)) == "impact"
    impact = result.data["impact"]
    assert {i["source"] for i in impact["relations"]["items"]} == {R1, R2}
    assert sum(i["self"] for i in impact["relations"]["items"]) == 1
    assert impact["scopes"]["items"][0]["scope_id"] == saved.data["scope_id"]
    assert [i["verification_id"] for i in impact["guard_runs"]["items"]] == [vid]
    assert [i["collaboration_id"] for i in impact["copilot_collaborations"]["items"]] == [cid]
    assert [i["rule"] for i in impact["pending_decisions"]["items"]] == [R1]
    assert [i["document"] for i in impact["document_index"]["items"]] == [DOC]
    for kind in SUPPORTED:
        assert impact[kind]["count"] == len(impact[kind]["items"]) > 0
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", result.data["impact_digest"])
    assert result.data["references_block"] is False
    assert result.data["action"] == action
    assert result.data["reason"] == REASON
    assert set(result.data) - {"recovered_exit"} == PREVIEW_KEYS
    assert result.data["rule"] == R1
    assert result.data["target"] == target
    assert {"consistent", "state", "revision", "state_digest", "fingerprint"} <= set(
        result.data["rule_state"]
    )
    assert result.data["rule_state"]["consistent"] is True
    assert result.data["rule_state"]["state"] == ("deactivated" if action == "reactivate" else "active")
    will = result.data["will"]
    assert isinstance(will, list) and will and all(isinstance(w, str) and w for w in will)
    said = " ".join(will).lower()
    assert "no other rule" in said, will
    assert all(word in said for word in ("scope", "run", "report")), will
    if action in ("deactivate", "delete", "rename"):
        assert "invalidate" in said and "index" in said, will
    if action in ("delete", "rename"):
        assert "pending" in said and "reserve" in said, will
    if action == "rename":
        assert TARGET.split("/")[-1].lower() in said, will
    assert files(env.project) == before
    again = env.preview(action, target=target)
    assert again.data["impact"] == impact
    assert again.data["impact_digest"] == result.data["impact_digest"]
    assert files(env.project) == before


@pytest.mark.parametrize("action", ["deactivate", "reactivate", "delete", "rename"])
def test_confirm_success_contract(env, action):
    """AC-02a/03a-d: confirm returns exactly the Command Contract fields, impact as committed."""
    env.pending()
    if action == "reactivate":
        env.exit("deactivate")
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    assert preview.ok, preview.to_dict()
    result = env.confirm(preview.data["impact_digest"], action, target=target)
    assert result.ok, result.to_dict()
    data = result.data
    assert set(data) - {"recovered_exit"} == CONFIRM_KEYS
    assert data["outcome"] == OUTCOMES[action]
    assert data["rule"] == R1
    assert data["target"] == target
    assert re.fullmatch(r"ex-\d{8}T\d{6}Z-[0-9a-f]{8}", data["exit_id"])
    assert data["lifecycle_revision"] == (2 if action == "reactivate" else 1)
    assert data["impact"] == preview.data["impact"]
    if action == "delete":
        assert data["state_digest"] is None
        assert data["tombstone"] == f".x-ipe/private/secure-code/exits/tombstones/{data['exit_id']}"
    else:
        assert data["tombstone"] is None
        assert data["state_digest"] == env.show(target or R1).data["state_digest"]
    assert data["removed_pending"] == ([R1] if action in ("delete", "rename") else [])
    assert data["invalidated_index"] == ([] if action == "reactivate" else [DOC])


def test_empty_supported_not_unsupported(project, tmp_path):
    env = Env(project, tmp_path)
    assert env.load({
        "namespace": "CWE", "version": "4.14", "rule_id": "CWE-79", "content": "Isolated.\n",
    }).ok
    before = files(project)
    preview = env.preview()
    assert preview.ok
    for kind in SUPPORTED:
        assert preview.data["impact"][kind]["items"] == []
        assert preview.data["impact"][kind]["count"] == 0
    # superseded per AC-001F-06a/06b (anticipated by 001-D)
    for kind in ("reference_cache",):
        assert preview.data["impact"][kind] == "not checked in this version"
    for kind in ("presets", "tags"):
        assert preview.data["impact"][kind]["count"] == 0
        assert preview.data["impact"][kind]["items"] == []
    assert "(none)" in preview.to_text()
    assert "not checked in this version" in preview.to_text()
    assert files(project) == before
    denied = env.confirm(None)
    refusal(denied, "IMPACT_DIGEST_REQUIRED", step="preview")
    assert files(project) == before


@pytest.mark.parametrize("delta", [
    "rule", "relation_add", "relation_remove", "scope", "pending", "index", "malformed_index",
])
def test_changed_impact_is_stale(env, delta):
    if delta == "pending":
        env.pending()
    preview = env.preview()
    assert preview.ok
    if delta == "rule":
        assert env.update(R1, env.show().data["item_digest"], content="New rule body.\n").ok
    elif delta.startswith("relation"):
        rule = R3 if delta == "relation_add" else R2
        relations = [R1] if delta == "relation_add" else []
        assert env.update(rule, env.show(rule).data["item_digest"], relations=relations).ok
    elif delta == "scope":
        assert env.save(env.decisions((R1, R2))).ok
    elif delta == "pending":
        p = env.project / store.PENDING_REL / (R1 + ".json")
        data = json.loads(p.read_text())
        data["held_at"] = "2026-10-22T09:00:00Z"
        p.write_text(json.dumps(data))
    else:
        p = env.project / store.INDEX_REL
        if delta == "malformed_index":
            p.write_text("{broken")
        else:
            data = json.loads(p.read_text())
            data[DOC]["updated_at"] = "2026-10-22T09:00:00Z"
            p.write_text(json.dumps(data))
    before = files(env.project)
    result = env.confirm(preview.data["impact_digest"])
    refusal(result, "STALE_IMPACT", step="preview")
    assert "impact" in result.data
    assert "impact_digest" not in result.data
    assert files(env.project) == before
    fresh = env.preview()
    assert fresh.ok, fresh.to_dict()
    assert fresh.data["impact_digest"] != preview.data["impact_digest"]
    assert result.data["impact"] == fresh.data["impact"], "refusal must carry the NEW impact"
    if delta != "rule":
        # A rule-only change alters rule_state (digest-bound) but no provider list.
        assert result.data["impact"] != preview.data["impact"]
    assert files(env.project) == before


@pytest.mark.parametrize("mismatch", ["none", "malformed", "rule", "action", "reason", "target", "unknown"])
def test_confirmation_digest_binding(env, mismatch):
    action = "rename" if mismatch == "target" else "deactivate"
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    assert preview.ok
    digest = preview.data["impact_digest"]
    kwargs = {"action": action, "target": target}
    code = "STALE_IMPACT"
    if mismatch == "none":
        digest, code = None, "IMPACT_DIGEST_REQUIRED"
    elif mismatch == "malformed":
        digest, code = "not-a-digest", "IMPACT_DIGEST_REQUIRED"
    elif mismatch == "rule":
        kwargs["rule"] = R2
    elif mismatch == "action":
        kwargs["action"] = "delete"
    elif mismatch == "reason":
        kwargs["reason"] = "Different actual decision"
    elif mismatch == "target":
        kwargs["target"] = "CWE/4.14/OTHER"
    else:
        kwargs["rule"], code = "CWE/4.14/ABSENT", "RULE_NOT_FOUND"
    before = files(env.project)
    refusal(env.confirm(digest, **kwargs), code, step="preview")
    assert files(env.project) == before


@pytest.mark.parametrize("reason", [None, "", " ", "\t", "\n"])
def test_reason_required(env, reason):
    before = files(env.project)
    result = env.confirm("sha256:" + "0" * 64, reason=reason)
    refusal(result, "REASON_REQUIRED")
    assert files(env.project) == before


@pytest.mark.parametrize("reason", ["x" * 1001, "line\nbreak", "nul\x00byte", "control\x01"])
def test_invalid_reason(env, reason):
    before = files(env.project)
    refusal(env.preview(reason=reason), "REASON_INVALID")
    assert files(env.project) == before


def test_malformed_index_is_visible_not_empty_and_confirm_refuses(env):
    (env.project / store.INDEX_REL).write_text("{broken")
    before = files(env.project)
    preview = env.preview()
    assert preview.ok
    assert preview.data["impact"]["document_index"]["unreadable"]
    refusal(env.confirm(preview.data["impact_digest"]), "INDEX_INVALID")
    assert files(env.project) == before


def test_cli_commands_json_and_text(env):
    """AC-02a/b/e: real parser, JSON envelope, digest and human impact rendering."""
    before = files(env.project)
    cli = run_cli(env.cli_args("deactivate"), env.trust)
    assert cli.returncode == 0, cli.stdout + cli.stderr
    payload = json.loads(cli.stdout)
    assert payload["command"] == "knowledge exit-preview"
    assert payload["ok"] is True
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", payload["data"]["impact_digest"])
    text = run_cli(env.cli_args("deactivate")[:-1], env.trust)
    assert text.returncode == 0
    assert text.stdout.index("impact:") < text.stdout.index("impact_digest:")
    assert "not checked in this version" in text.stdout
    assert "(none)" in text.stdout
    assert files(env.project) == before
    confirmed = run_cli(env.cli_args("deactivate", payload["data"]["impact_digest"]), env.trust)
    assert confirmed.returncode == 0, confirmed.stdout + confirmed.stderr
    committed = json.loads(confirmed.stdout)
    assert committed["command"] == "knowledge exit-confirm"
    assert set(payload["data"]) - {"recovered_exit"} == PREVIEW_KEYS
    assert set(committed["data"]) - {"recovered_exit"} == CONFIRM_KEYS
    assert committed["data"]["outcome"] == "deactivated"
    assert committed["data"]["impact"] == payload["data"]["impact"]
    assert committed["data"]["rule"] == R1
    assert committed["data"]["target"] is None
    assert committed["data"]["state_digest"] == env.show().data["state_digest"]
    linked = run_cli(["knowledge", "links", "--project", str(env.project), "--json"], env.trust)
    assert linked.returncode == 0
    assert json.loads(linked.stdout)["command"] == "knowledge links"


def test_preview_does_not_scan_business_code(env, monkeypatch):
    business = env.project / "business-canary.txt"
    business.write_bytes(b"not toolkit data")
    real = Path.open

    def checked(path, *args, **kwargs):
        assert path != business, "impact provider read business code"
        return real(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked)
    assert env.preview().ok
