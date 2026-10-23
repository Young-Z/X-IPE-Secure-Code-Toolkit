"""Unit tests of the FEATURE-001-G draft/review model (drafting_model; design Implementation Step 2).

AC-001G-01b, AC-001G-09f (unit level), FR-001G-1 formats, NFR-001G-5 sizes, DEC-9 locations.
"""

from __future__ import annotations

import json
import os

import pytest
from drafthelp import DRAFT_SCHEMA, DRAFTS, PY, R89, REVIEW_SCHEMA, mod, sha

BASE = "sha256:" + "a" * 64


def doc(**over):
    data = {
        "schema": DRAFT_SCHEMA,
        "rule": R89,
        "base_state": BASE,
        "drafted_by": {"host": "fixture-host", "model": "fixture model 1"},
        "created_at": "2026-10-23T12:00:00Z",
        "sources": [{"kind": "stored_rule_content"}],
        "examples": {"python": dict(PY)},
    }
    data.update(over)
    return {k: v for k, v in data.items() if v is not None}


def raw(data) -> bytes:
    return json.dumps(data).encode("utf-8")


def refused(data, code="DRAFT_INVALID"):
    model = mod("drafting_model")
    with pytest.raises(model.DraftError) as caught:
        model.parse_draft(data if isinstance(data, bytes) else raw(data))
    assert caught.value.code == code, caught.value.message
    return caught.value.message


def test_valid_draft_parses_with_digest_and_normalised_parts():
    model = mod("drafting_model")
    data = doc(
        examples={
            "python": {"unsafe": "a = 1\r\n\r\n", "safe": "b = 2\n", "demonstrates": [PY["demonstrates"][0]]}
        }
    )
    draft = model.parse_draft(raw(data))
    assert draft.ref.rel == R89 and draft.base_state == BASE and draft.host == "fixture-host"
    assert draft.model == "fixture model 1" and draft.confidentiality is None
    assert draft.digest == sha(raw(data))
    assert draft.examples["python"].unsafe == "a = 1" and draft.examples["python"].safe == "b = 2"
    assert draft.examples["python"].demonstrates == (PY["demonstrates"][0],)


# AC-001G-01b (unit): every replacement/identity field is refused and named.
@pytest.mark.parametrize(
    "field",
    [
        "content",
        "name",
        "source_location",
        "applicability",
        "relations",
        "namespace",
        "version",
        "rule_id",
        "source_document_digest",
    ],
)
def test_01b_forbidden_fields_named(field):
    message = refused(doc(**{field: "x"}))
    assert f"'{field}'" in message


def test_01b_example_replacement_text_refused_naming_path():
    message = refused(doc(examples={"python": "print('replacement text')\n"}))
    assert "examples.python" in message


# AC-001G-09f (unit): the v1 schema has no explanation field (B13 = H2).
def test_09f_explanation_field_refused():
    message = refused(doc(explanation="Risk: injection."))
    assert "'explanation'" in message and "explanation" in message.lower()


@pytest.mark.parametrize(
    "over, path",
    [
        ({"surprise": 1}, "surprise"),
        ({"schema": "ai-secure-code-toolkit/knowledge-draft/v2"}, "schema"),
        ({"rule": "CWE/89"}, "rule"),
        ({"base_state": "sha256:xyz"}, "base_state"),
        ({"drafted_by": {"host": "Bad Host"}}, "drafted_by.host"),
        ({"drafted_by": {"host": "h", "extra": 1}}, "drafted_by"),
        ({"drafted_by": {"host": "h", "model": "two\nlines"}}, "drafted_by.model"),
        ({"created_at": "2026-10-23 12:00"}, "created_at"),
        ({"sources": []}, "sources"),
        ({"sources": [{"kind": "rumour"}]}, "sources[0].kind"),
        ({"sources": [{"kind": "stored_rule_content", "url": "https://x/"}]}, "sources[0]"),
        (
            {"sources": [{"kind": "not_retrieved", "url": "https://x/", "reason": "a\u202eb"}]},
            "sources[0].reason",
        ),
        (
            {"sources": [{"kind": "fetched", "url": "https://x/", "http_status": "200"}]},
            "sources[0].http_status",
        ),
        (
            {"sources": [{"kind": "fetched", "attribution": {"title": "t", "who": "x"}}]},
            "sources[0].attribution",
        ),
        (
            {"sources": [{"kind": "not_retrieved", "url": "x-ipe-ai-supplement", "reason": "r"}]},
            "sources[0].url",
        ),
        ({"examples": {}}, "examples"),
        ({"examples": {"Python": dict(PY)}}, "examples"),
        ({"examples": {"python": {"unsafe": "a", "safe": "b", "extra": 1}}}, "examples.python"),
        ({"examples": {"python": {"unsafe": 1, "safe": "b"}}}, "examples.python.unsafe"),
        (
            {"examples": {"python": {"unsafe": "a", "safe": "b", "demonstrates": "q"}}},
            "examples.python.demonstrates",
        ),
    ],
)
def test_shape_errors_name_json_path(over, path):
    assert path in refused(doc(**over))


def test_unreadable_json_and_non_object_refused():
    refused(b"\xff\xfe not utf-8")
    refused(b"{not json")
    refused(raw([1, 2]))


def test_missing_parts_parse_for_v5():
    model = mod("drafting_model")
    draft = model.parse_draft(raw(doc(examples={"python": {"safe": "x = 1"}})))
    assert draft.examples["python"].unsafe == "" and draft.examples["python"].demonstrates == ()


# AC-001G-07b (model part): confidentiality is absent or internal; a lower value on an @ rule is a downgrade.
def test_confidentiality_values():
    model = mod("drafting_model")
    assert model.parse_draft(raw(doc(confidentiality="internal"))).confidentiality == "internal"
    refused(doc(rule="@SYNTH/T-1.0/R-01", confidentiality="public"), "CLASSIFICATION_DOWNGRADE")
    refused(doc(confidentiality="public"))


def review(**over):
    data = {
        "schema": REVIEW_SCHEMA,
        "draft_digest": BASE,
        "examples": {"python": {"unsafe_violates_rule": True, "safe_addresses_rule": False}},
        "attestations": {"non_normative": True},
    }
    data.update(over)
    return data


def test_review_parses_only_literal_true_as_recorded():
    model = mod("drafting_model")
    parsed = model.parse_review(raw(review()))
    assert parsed.draft_digest == BASE and parsed.digest == sha(raw(review()))
    assert parsed.recorded("python") == {"unsafe_violates_rule"}
    assert parsed.attested() == {"non_normative"}


@pytest.mark.parametrize(
    "over",
    [
        {"schema": "x"},
        {"draft_digest": "nope"},
        {"extra": 1},
        {"examples": {"python": {"unknown_item": True}}},
        {"examples": {"python": {"language_correct": 1}}},
        {"attestations": {"non_normative": "yes"}},
        {"attestations": {"everything_fine": True}},
    ],
)
def test_review_invalid(over):
    model = mod("drafting_model")
    with pytest.raises(model.DraftError) as caught:
        model.parse_review(raw(review(**over)))
    assert caught.value.code == "DRAFT_REVIEW_INVALID"


# DEC-9, FR-001G-1 / NFR-001G-5: location, kind and size rules.
def test_locations_sizes_and_links(tmp_path):
    model = mod("drafting_model")
    root = tmp_path / "proj"
    drafts = root / DRAFTS
    drafts.mkdir(parents=True)
    good = drafts / "a.draft.json"
    good.write_bytes(b"{}")
    assert model.read_input(root, str(good), "draft") == b"{}"
    outside = root / "a.draft.json"
    outside.write_bytes(b"{}")
    wrong_suffix = drafts / "a.json"
    wrong_suffix.write_bytes(b"{}")
    big = drafts / "big.draft.json"
    big.write_bytes(b" " * (model.MAX_FILE_BYTES + 1))
    for path, kind in ((outside, "draft"), (wrong_suffix, "draft"), (good, "review"), (big, "draft")):
        with pytest.raises(model.DraftError) as caught:
            model.read_input(root, str(path), kind)
        assert caught.value.code == ("DRAFT_REVIEW_INVALID" if kind == "review" else "DRAFT_INVALID")
    if os.name != "nt":
        link = drafts / "l.draft.json"
        link.symlink_to(good)
        with pytest.raises(model.DraftError):
            model.read_input(root, str(link), "draft")


def test_missing_drafts_folder_reported_not_created(tmp_path):
    model = mod("drafting_model")
    root = tmp_path / "proj"
    root.mkdir()
    with pytest.raises(model.DraftError) as caught:
        model.read_input(root, str(root / DRAFTS / "a.draft.json"), "draft")
    assert "x-ipe-docs/secure-code/drafts" in caught.value.message
    assert not (root / "x-ipe-docs").exists()
