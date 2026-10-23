"""Unit tests for FEATURE-001-C policy resolution and scope records."""

from __future__ import annotations

import pytest

from x_ipe_secure_code.policy import refs, resolve, scope


@pytest.mark.parametrize(
    ("text", "version"),
    [("CWE/4.14/CWE-79", "4.14"), ("CWE/CWE-79", None), ("@ACME/ACME-7", None), ("@ACME/v1/ACME-7", "v1")],
)
def test_requested_reference_forms(text, version):
    ref = refs.parse_requested(text)
    assert ref.invalid is None
    assert ref.version == version


@pytest.mark.parametrize("text", ["", "CWE", "a/b/c/d", "CWE/../CWE-79", "CWE/4.14/CON", "C W E/X", "CWE//X"])
def test_invalid_references_never_raise(text):
    ref = refs.parse_requested(text)
    assert ref.invalid


@pytest.mark.parametrize(
    ("availabilities", "status"),
    [
        (["available", "available"], "complete"),
        (["available", "missing"], "partial"),
        (["available", "unclear"], "partial"),
        (["missing", "unclear"], "maintenance_needed"),
        ([], "maintenance_needed"),
    ],
)
def test_status_truth_table(availabilities, status):
    entries = [{"availability": a} for a in availabilities]
    assert resolve.overall_status(entries) == status


def test_proposal_digest_ignores_order_and_descriptions_but_not_state():
    a = {
        "requested": "CWE/4.14/CWE-79",
        "availability": "available",
        "rule": "CWE/4.14/CWE-79",
        "source_evidence": {"state_digest": "sha256:1"},
        "name": "x",
        "language_note": "matches",
    }
    b = {"requested": "CWE/CWE-89", "availability": "missing", "reason": "not_found"}
    first = resolve.proposal_digest("clues", [a, b])
    assert first == resolve.proposal_digest("clues", [b, dict(a, language_note="unknown")])
    changed = dict(a, source_evidence={"state_digest": "sha256:2"})
    assert first != resolve.proposal_digest("clues", [b, changed])
    assert first != resolve.proposal_digest("apply_all", [a, b])


def _record(**over):
    record = {
        "schema": scope.RECORD_SCHEMA,
        "mode": "clues",
        "clues": "java login",
        "language_context": ["java"],
        "adopted": [
            {
                "rule": "CWE/4.14/CWE-79",
                "requested": "CWE/4.14/CWE-79",
                "state_digest": "sha256:1",
                "note": None,
            }
        ],
        "not_adopted": [],
        "artifact_scope": scope.ARTIFACT_SCOPE,
        "confirmation_note": "user confirmed",
        "created_at": "2026-10-19T10:00:00Z",
    }
    record.update(over)
    return scope.with_id(record)


# AC-001C-05a, 05c
def test_scope_id_excludes_creation_time_and_detects_changes():
    first = _record()
    later = _record(created_at="2026-10-20T00:00:00Z")
    assert first["scope_id"] == later["scope_id"]
    assert first["scope_id"].startswith("sha256:") and len(first["scope_id"]) == 71
    assert _record(confirmation_note="other")["scope_id"] != first["scope_id"]


def test_tampered_record_fails_verification():
    record = _record()
    record["adopted"][0]["state_digest"] = "sha256:2"
    with pytest.raises(scope.ScopeError) as exc:
        scope.verify_record(record, record["scope_id"].split(":", 1)[1])
    assert exc.value.code == "SCOPE_INVALID"


@pytest.mark.parametrize(
    ("applicability", "languages", "note"),
    [
        (["python"], ["java"], "does_not_match"),
        (["python", "java"], ["Java"], "matches"),
        ("unknown", ["java"], "unknown"),
        (["python"], [], "no_context"),
    ],
)
def test_language_notes_never_filter(applicability, languages, note):
    assert resolve.language_note(applicability, languages) == note


@pytest.mark.parametrize("languages", [[1], 5, "java"])
def test_record_with_bad_language_context_is_invalid(languages):
    record = _record(language_context=languages)
    with pytest.raises(scope.ScopeError) as exc:
        scope.verify_record(record, record["scope_id"].split(":", 1)[1])
    assert exc.value.code == "SCOPE_INVALID"


@pytest.mark.parametrize("created", [None, 5])
def test_record_without_valid_creation_time_is_invalid(created):
    record = _record()
    if created is None:
        del record["created_at"]
    else:
        record["created_at"] = created
    with pytest.raises(scope.ScopeError) as exc:
        scope.verify_record(record, record["scope_id"].split(":", 1)[1])
    assert exc.value.code == "SCOPE_INVALID"
