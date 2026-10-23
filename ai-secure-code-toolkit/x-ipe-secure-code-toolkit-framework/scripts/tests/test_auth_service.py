"""Unit tests for owner authorization (AC-001A-06*, 07*, 08*)."""

from __future__ import annotations

import base64
import json
import shutil

import pytest
from conftest import PASSPHRASE, FakeInteraction

from x_ipe_secure_code.auth import service, verify
from x_ipe_secure_code.auth.service import (
    initialize_authorization,
    require_maintainer,
    revoke_authorization,
)


def _init(paths, passphrase=PASSPHRASE):
    return initialize_authorization(
        paths=paths, interaction=FakeInteraction(answers=[passphrase, passphrase])
    )


def _revoke(paths, passphrase=PASSPHRASE, interactive=True):
    return revoke_authorization(
        paths=paths, interaction=FakeInteraction(interactive=interactive, answers=[passphrase])
    )


def _problem_codes(result):
    return [p.code for p in result.problems]


# AC-001A-06a
def test_first_init_creates_encrypted_key_signed_state_grant(trust_paths):
    result = _init(trust_paths)
    assert result.ok, result.to_dict()
    assert trust_paths.public_key.is_file()
    key_pem = trust_paths.signing_key.read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in key_pem
    state = json.loads(trust_paths.state.read_text())
    assert state["status"] == "active" and state["generation"] == 1
    assert trust_paths.grant(state["current_grant_id"]).is_file()
    status = verify.verify(trust_paths)
    assert status.role == "maintainer" and status.state == "valid"
    assert status.created_at and status.created_by


def test_first_init_never_inside_project(trust_paths, project):
    _init(trust_paths)
    assert not any(project.rglob("*.pem"))


# AC-001A-06b (unit side; CLI side in test_auth_cli)
def test_init_non_interactive_refused_creates_nothing(trust_paths):
    result = initialize_authorization(
        paths=trust_paths, interaction=FakeInteraction(interactive=False, answers=[PASSPHRASE] * 2)
    )
    assert not result.ok and "NOT_INTERACTIVE" in _problem_codes(result)
    assert not trust_paths.app_dir.exists() or not trust_paths.trust_dir.exists()


# AC-001A-06c
def test_init_when_active_refused(trust_paths):
    _init(trust_paths)
    before = trust_paths.state.read_bytes()
    result = _init(trust_paths)
    assert not result.ok and "ALREADY_INITIALIZED" in _problem_codes(result)
    assert trust_paths.state.read_bytes() == before
    assert any("revoke" in step for step in result.next_steps)


# AC-001A-06d
@pytest.mark.parametrize(
    "answers,code",
    [
        ([PASSPHRASE, PASSPHRASE + "x"], "PASSPHRASE_MISMATCH"),
        ([None], "ABORTED"),
        (["short", "short"], "PASSPHRASE_TOO_SHORT"),
    ],
)
def test_init_mismatch_abort_short_creates_nothing(trust_paths, answers, code):
    result = initialize_authorization(paths=trust_paths, interaction=FakeInteraction(answers=answers))
    assert not result.ok and code in _problem_codes(result)
    assert not trust_paths.trust_dir.exists()


# AC-001A-06f
def test_reauth_after_revoke_requires_existing_passphrase_same_key(trust_paths):
    _init(trust_paths)
    pub_before = trust_paths.public_key.read_bytes()
    assert _revoke(trust_paths).ok
    wrong = initialize_authorization(
        paths=trust_paths, interaction=FakeInteraction(answers=["wrong passphrase!!"])
    )
    assert not wrong.ok and "PASSPHRASE_WRONG" in _problem_codes(wrong)
    assert verify.verify(trust_paths).state == "revoked"
    right = initialize_authorization(paths=trust_paths, interaction=FakeInteraction(answers=[PASSPHRASE]))
    assert right.ok, right.to_dict()
    assert trust_paths.public_key.read_bytes() == pub_before
    state = json.loads(trust_paths.state.read_text())
    assert state["status"] == "active" and state["generation"] == 3
    assert verify.verify(trust_paths).role == "maintainer"


# AC-001A-06g
@pytest.mark.parametrize("damage", ["no_grant", "no_state", "no_pubkey", "no_key", "bad_state_sig"])
def test_init_partial_state_refused(trust_paths, damage):
    _init(trust_paths)
    state = json.loads(trust_paths.state.read_text())
    if damage == "no_grant":
        trust_paths.grant(state["current_grant_id"]).unlink()
    elif damage == "no_state":
        trust_paths.state.unlink()
    elif damage == "no_pubkey":
        trust_paths.public_key.unlink()
    elif damage == "no_key":
        trust_paths.signing_key.unlink()
    else:
        state["generation"] = 99
        trust_paths.state.write_text(json.dumps(state))
    snapshot = sorted(p.name for p in trust_paths.trust_dir.rglob("*"))
    result = _init(trust_paths)
    assert not result.ok and "TRUST_PARTIAL" in _problem_codes(result)
    assert sorted(p.name for p in trust_paths.trust_dir.rglob("*")) == snapshot


def test_revoked_state_with_foreign_grant_is_partial(trust_paths, tmp_path):
    from x_ipe_secure_code.auth.trust_store import resolve

    other = resolve(tmp_path / "other")
    _init(other)
    _init(trust_paths)
    _revoke(trust_paths)
    state = json.loads(trust_paths.state.read_text())
    foreign = next(other.grants_dir.iterdir())
    shutil.copy(foreign, trust_paths.grant(state["current_grant_id"]))
    result = initialize_authorization(paths=trust_paths, interaction=FakeInteraction(answers=[PASSPHRASE]))
    assert not result.ok and "TRUST_PARTIAL" in _problem_codes(result)


# AC-001A-07a
def test_verify_no_trust_dir_user_next_step(trust_paths):
    status = verify.verify(trust_paths)
    assert status.role == "user" and status.state == "not_initialized"
    assert "auth init" in status.next_step
    assert not trust_paths.app_dir.exists()


# AC-001A-07b
def _tamper_grant(paths):
    state = json.loads(paths.state.read_text())
    grant_path = paths.grant(state["current_grant_id"])
    grant = json.loads(grant_path.read_text())
    return grant_path, grant


def test_verify_rejects_tampered_grant(trust_paths):
    _init(trust_paths)
    path, grant = _tamper_grant(trust_paths)
    grant["issued_to"]["os_user"] = "mallory"
    path.write_text(json.dumps(grant))
    status = verify.verify(trust_paths)
    assert status.role == "user" and status.state == "invalid"


def test_verify_rejects_grant_signed_by_foreign_key(trust_paths, tmp_path):
    from x_ipe_secure_code.auth.trust_store import resolve

    other = resolve(tmp_path / "other")
    _init(other)
    _init(trust_paths)
    other_state = json.loads(other.state.read_text())
    path, _ = _tamper_grant(trust_paths)
    path.write_bytes(other.grant(other_state["current_grant_id"]).read_bytes())
    assert verify.verify(trust_paths).role == "user"


def test_verify_rejects_grant_with_embedded_public_key(trust_paths):
    _init(trust_paths)
    path, grant = _tamper_grant(trust_paths)
    grant["public_key"] = base64.b64encode(b"x" * 32).decode()
    path.write_text(json.dumps(grant))
    assert verify.verify(trust_paths).state == "invalid"


def test_workspace_trust_file_is_ignored(trust_paths, project):
    (project / "trusted-public-key.pem").write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n")
    (project / "maintainer-grant.json").write_text("{}")
    assert verify.verify(trust_paths).state == "not_initialized"


# AC-001A-07c
def test_verify_never_opens_signing_key(trust_paths, monkeypatch):
    _init(trust_paths)
    opened: list[str] = []
    import io
    import os

    real_io_open, real_os_open = io.open, os.open

    def spy_io_open(file, *a, **k):
        opened.append(str(file))
        return real_io_open(file, *a, **k)

    def spy_os_open(file, *a, **k):
        opened.append(str(file))
        return real_os_open(file, *a, **k)

    monkeypatch.setattr(io, "open", spy_io_open)
    monkeypatch.setattr(os, "open", spy_os_open)
    assert verify.verify(trust_paths).role == "maintainer"
    assert str(trust_paths.signing_key) not in opened
    monkeypatch.undo()
    trust_paths.signing_key.unlink()
    assert verify.verify(trust_paths).role == "maintainer"


def test_verify_module_does_not_import_private_key_helpers():
    import inspect

    source = inspect.getsource(verify)
    assert "keys" not in {
        line.split()[1].split(".")[-1]
        for line in source.splitlines()
        if line.startswith(("import ", "from "))
    }
    assert "decrypt" not in source


# AC-001A-07e
def test_require_maintainer_reverifies_after_revoke(trust_paths):
    _init(trust_paths)
    assert require_maintainer("knowledge.import", paths=trust_paths).allowed
    _revoke(trust_paths)
    decision = require_maintainer("knowledge.import", paths=trust_paths)
    assert not decision.allowed and decision.status.state == "revoked"
    assert decision.to_result().problems[0].code == "NOT_AUTHORIZED"


# AC-001A-07f
def test_decision_is_qualification_only(trust_paths):
    _init(trust_paths)
    data = require_maintainer("knowledge.import", paths=trust_paths).to_result().to_dict()["data"]
    for forbidden in ("scope", "network", "budget", "autonomy"):
        assert forbidden not in json.dumps(data)
    assert data["qualification"] == "maintainer"


# AC-001A-08a
def test_revoke_then_verify_user_revoked(trust_paths):
    _init(trust_paths)
    assert _revoke(trust_paths).ok
    status = verify.verify(trust_paths)
    assert status.role == "user" and status.state == "revoked"


# AC-001A-08b (unit side)
def test_revoke_wrong_passphrase_or_non_interactive_unchanged(trust_paths):
    _init(trust_paths)
    before = trust_paths.state.read_bytes()
    assert "PASSPHRASE_WRONG" in _problem_codes(_revoke(trust_paths, "not the passphrase"))
    assert "NOT_INTERACTIVE" in _problem_codes(_revoke(trust_paths, interactive=False))
    assert trust_paths.state.read_bytes() == before


# AC-001A-08c
def test_revoke_nothing_authorized(trust_paths):
    result = _revoke(trust_paths)
    assert result.ok and result.data["outcome"] == "nothing_authorized"
    assert not trust_paths.trust_dir.exists()


def test_revoke_twice_is_noop(trust_paths):
    _init(trust_paths)
    _revoke(trust_paths)
    before = trust_paths.state.read_bytes()
    result = _revoke(trust_paths)
    assert result.ok and result.data["outcome"] == "already_revoked"
    assert trust_paths.state.read_bytes() == before


# AC-001A-08d
def test_restored_pre_revocation_grant_rejected(trust_paths):
    _init(trust_paths)
    state = json.loads(trust_paths.state.read_text())
    old_grant_path = trust_paths.grant(state["current_grant_id"])
    saved = old_grant_path.read_bytes()
    _revoke(trust_paths)
    old_grant_path.write_bytes(saved)
    assert verify.verify(trust_paths).state == "revoked"
    initialize_authorization(paths=trust_paths, interaction=FakeInteraction(answers=[PASSPHRASE]))
    new_state = json.loads(trust_paths.state.read_text())
    trust_paths.grant(new_state["current_grant_id"]).write_bytes(saved)
    status = verify.verify(trust_paths)
    assert status.role == "user"


# Atomicity: interrupted re-auth leaves previous state valid
def test_interrupted_reauth_keeps_previous_state(trust_paths, monkeypatch):
    _init(trust_paths)
    _revoke(trust_paths)
    before = trust_paths.state.read_bytes()

    def boom(*_a, **_k):
        raise OSError("simulated crash")

    monkeypatch.setattr(service, "_commit_state", boom)
    result = initialize_authorization(
        paths=trust_paths, interaction=FakeInteraction(answers=[PASSPHRASE])
    )
    assert not result.ok and "IO_ERROR" in _problem_codes(result)
    monkeypatch.undo()
    assert trust_paths.state.read_bytes() == before
    assert verify.verify(trust_paths).state == "revoked"


def test_lock_held_refuses(trust_paths):
    trust_paths.app_dir.mkdir(parents=True)
    trust_paths.lock.write_text("pid=1")
    result = _init(trust_paths)
    assert not result.ok and "LOCKED" in _problem_codes(result)
    assert not trust_paths.trust_dir.exists()
