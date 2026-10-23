"""Shared Reviewer-record envelope (FEATURE-003-A design, step 1).

The Guard vectors below were captured from `guard.records.validate_review` BEFORE the envelope was
extracted into `x_ipe_secure_code.reviewer`; Guard must keep producing exactly these records,
warnings, refusal codes, messages and next steps.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from x_ipe_secure_code.guard import records
from x_ipe_secure_code.guard.model import Checker, GuardError

SCHEMA = "ai-secure-code-toolkit/reviewer-record/v1"
TOKEN = "ghp_" + "c" * 36
DIG = "sha256:" + "a" * 64

STATE: dict[str, Any] = {
    "artifact": {
        "whole_project": False,
        "targets": [{"path": "src/login.py", "kind": "file"}],
        "context": [],
        "suggested": [],
        "copilot_reports": [],
    },
    "findings": [{"id": "F1", "location": {"path": "src/login.py", "line": 2}}],
    "evidence": [{"id": "E1", "method_status": "ok", "paths": ["src/login.py"]}],
    "plan": {"checks": [{"id": "C1"}], "not_applicable": [{"rule": "CWE/4.14/CWE-89"}]},
}


def _valid(**over: Any) -> dict[str, Any]:
    doc = {
        "schema": SCHEMA,
        "invocation": {
            "host": "github-copilot",
            "agent": "guard-reviewer",
            "read_only": True,
            "invoked_at": "2026-10-21T10:00:00Z",
        },
        "requirement": "Re-check findings",
        "reviewed_targets": [{"path": "src/login.py", "digest": DIG}],
        "subjects": [
            {
                "type": "finding",
                "id": "F1",
                "result": "confirmed",
                "basis": "input reaches HTML",
                "evidence": ["E1"],
                "severity_opinion": {"severity": "high", "evidence": ["E1"]},
            },
            {"type": "na_decision", "id": "policy:CWE/4.14/CWE-89", "result": "confirmed", "basis": "no SQL"},
        ],
        "reviewed_at": "2026-10-21T10:05:00Z",
        "attempt": "a1",
        "usage": {"tokens": 3},
    }
    doc.update(over)
    return doc


def _without(key: str) -> dict[str, Any]:
    doc = _valid()
    del doc[key]
    return doc


def _inv(**over: Any) -> dict[str, Any]:
    inv = dict(_valid()["invocation"])
    for k, v in over.items():
        if v is None:
            inv.pop(k, None)
        else:
            inv[k] = v
    return _valid(invocation=inv)


VECTORS: dict[str, Any] = {
    "valid": _valid(),
    "minimal_valid": {
        "schema": SCHEMA,
        "invocation": {"host": "h", "agent": "a", "read_only": True},
        "requirement": "r",
        "reviewed_targets": [{"path": "./src\\login.py", "digest": DIG}],
        "subjects": [{"type": "finding", "id": "F1", "result": "unconfirmed"}],
    },
    "missing_host": _inv(host=None),
    "missing_agent": _inv(agent=None),
    "read_only_false": _inv(read_only=False),
    "read_only_absent": _inv(read_only=None),
    "read_only_text": _inv(read_only="true"),
    "missing_invoked_at": _inv(invoked_at=None),
    "missing_invocation": _without("invocation"),
    "missing_requirement": _without("requirement"),
    "empty_requirement": _valid(requirement=""),
    "missing_reviewed_targets": _without("reviewed_targets"),
    "empty_reviewed_targets": _valid(reviewed_targets=[]),
    "missing_subjects": _without("subjects"),
    "empty_subjects": _valid(subjects=[]),
    "missing_result": _valid(subjects=[{"type": "finding", "id": "F1", "basis": "b"}]),
    "all_warnings": {"schema": SCHEMA},
    "unknown_field": _valid(extra=1),
    "unknown_invocation_field": _inv(model="x"),
    "invocation_not_object": _valid(invocation="host"),
    "not_object": ["x"],
    "bad_digest": _valid(reviewed_targets=[{"path": "src/login.py", "digest": "md5:1"}]),
    "absent_digest": _valid(reviewed_targets=[{"path": "src/login.py", "digest": "absent"}]),
    "missing_digest": _valid(reviewed_targets=[{"path": "src/login.py"}]),
    "outside_path": _valid(reviewed_targets=[{"path": "../x.py", "digest": DIG}]),
    "path_not_text": _valid(reviewed_targets=[{"path": 3, "digest": DIG}]),
    "reviewed_targets_not_list": _valid(reviewed_targets={"path": "a"}),
    "host_too_long": _inv(host="h" * 201),
    "host_not_text": _inv(host=5),
    "reviewed_at_not_text": _valid(reviewed_at=7),
    "reviewed_at_and_bad_subject": _valid(reviewed_at=7, subjects=[{"type": "finding", "id": "F9"}]),
    "masked_texts": _valid(
        requirement=f"token {TOKEN}",
        subjects=[{"type": "finding", "id": "F1", "result": "confirmed", "basis": f"key {TOKEN}"}],
    ),
    "unknown_subject_type": _valid(subjects=[{"type": "adoption", "id": "S1", "result": "adopted"}]),
    "unknown_finding": _valid(subjects=[{"type": "finding", "id": "F9", "result": "confirmed"}]),
    "unknown_na": _valid(subjects=[{"type": "na_decision", "id": "policy:X", "result": "confirmed"}]),
    "duplicate_subject": _valid(subjects=[{"type": "finding", "id": "F1"}, {"type": "finding", "id": "F1"}]),
    "bad_result": _valid(subjects=[{"type": "finding", "id": "F1", "result": "adopted"}]),
    "false_positive_without_evidence": _valid(
        subjects=[{"type": "finding", "id": "F1", "result": "false_positive"}]
    ),
    **{f"authority_{k}": _valid(**{k: "x"}) for k in records.AUTHORITY_KEYS},
    "authority_two": _valid(plan={}, targets=[]),
    "authority_and_unknown": _valid(ledger={}, extra=1),
}


def outcome(doc: Any) -> dict[str, Any]:
    try:
        record, warnings = records.validate_review(copy.deepcopy(STATE), copy.deepcopy(doc))
    except GuardError as exc:
        return {"code": exc.code, "message": exc.message, "next_step": exc.next_step}
    return {"record": record, "warnings": warnings}


# Captured from the pre-refactor Guard code (do not edit by hand).
EXPECTED: dict[str, Any] = {
    "absent_digest": {
        "code": "REVIEW_INVALID",
        "message": "reviewed_targets[0].digest id or name is not valid: 'absent'",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "all_warnings": {
        "record": {
            "completeness": [
                "invocation.host is missing",
                "invocation.agent is missing",
                "invocation.read_only is not true",
                "requirement is missing",
                "reviewed_targets is missing",
                "subjects is missing",
            ],
            "invocation": {
                "agent": None,
                "declared": True,
                "host": None,
                "invoked_at": None,
                "read_only": False,
            },
            "requirement": None,
            "reviewed_at": None,
            "reviewed_targets": [],
            "subjects": [],
        },
        "warnings": [
            "invocation.host is missing",
            "invocation.agent is missing",
            "invocation.read_only is not true",
            "requirement is missing",
            "reviewed_targets is missing",
            "subjects is missing",
        ],
    },
    "authority_and_unknown": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set ledger: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_conflicts": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set conflicts: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_evidence": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set evidence: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_exclusions": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set exclusions: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_findings": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set findings: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_ledger": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set ledger: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_plan": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set plan: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_risk_acceptances": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set risk_acceptances: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_scope": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set scope: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_scope_id": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set scope_id: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_targets": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set targets: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "authority_two": {
        "code": "REVIEW_AUTHORITY",
        "message": "A Reviewer record cannot set targets, plan: Reviewers have no extra authority",
        "next_step": "Remove those parts and record only the review result",
    },
    "bad_digest": {
        "code": "REVIEW_INVALID",
        "message": "reviewed_targets[0].digest id or name is not valid: 'md5:1'",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "bad_result": {
        "code": "REVIEW_INVALID",
        "message": "subjects[0].result must be one of confirmed, false_positive, unconfirmed (got 'adopted')",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "duplicate_subject": {
        "code": "REVIEW_INVALID",
        "message": "subjects[1] is a duplicate subject",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "empty_requirement": {
        "record": {
            "completeness": ["requirement is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": None,
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["requirement is missing"],
    },
    "empty_reviewed_targets": {
        "record": {
            "completeness": ["reviewed_targets is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["reviewed_targets is missing"],
    },
    "empty_subjects": {
        "record": {
            "completeness": ["subjects is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [],
        },
        "warnings": ["subjects is missing"],
    },
    "false_positive_without_evidence": {
        "code": "REVIEW_INVALID",
        "message": "subjects[0]: false_positive needs evidence",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "host_not_text": {
        "code": "REVIEW_INVALID",
        "message": "invocation.host must be text",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "host_too_long": {
        "code": "REVIEW_INVALID",
        "message": "invocation.host is longer than 200 characters",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "invocation_not_object": {
        "code": "REVIEW_INVALID",
        "message": "invocation must be an object",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "masked_texts": {
        "record": {
            "completeness": [],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "token [masked:credential.token]",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "key [masked:credential.token]",
                    "evidence": [],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "finding",
                }
            ],
        },
        "warnings": [],
    },
    "minimal_valid": {
        "record": {
            "completeness": [],
            "invocation": {
                "agent": "a",
                "declared": True,
                "host": "h",
                "invoked_at": None,
                "read_only": True,
            },
            "requirement": "r",
            "reviewed_at": None,
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": None,
                    "evidence": [],
                    "id": "F1",
                    "result": "unconfirmed",
                    "severity_opinion": None,
                    "type": "finding",
                }
            ],
        },
        "warnings": [],
    },
    "missing_agent": {
        "record": {
            "completeness": ["invocation.agent is missing"],
            "invocation": {
                "agent": None,
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["invocation.agent is missing"],
    },
    "missing_digest": {
        "code": "REVIEW_INVALID",
        "message": "reviewed_targets[0] is missing: digest",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "missing_host": {
        "record": {
            "completeness": ["invocation.host is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": None,
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["invocation.host is missing"],
    },
    "missing_invocation": {
        "record": {
            "completeness": [
                "invocation.host is missing",
                "invocation.agent is missing",
                "invocation.read_only is not true",
            ],
            "invocation": {
                "agent": None,
                "declared": True,
                "host": None,
                "invoked_at": None,
                "read_only": False,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": [
            "invocation.host is missing",
            "invocation.agent is missing",
            "invocation.read_only is not true",
        ],
    },
    "missing_invoked_at": {
        "record": {
            "completeness": [],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": None,
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": [],
    },
    "missing_requirement": {
        "record": {
            "completeness": ["requirement is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": None,
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["requirement is missing"],
    },
    "missing_result": {
        "record": {
            "completeness": ["subjects[0].result is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "b",
                    "evidence": [],
                    "id": "F1",
                    "result": None,
                    "severity_opinion": None,
                    "type": "finding",
                }
            ],
        },
        "warnings": ["subjects[0].result is missing"],
    },
    "missing_reviewed_targets": {
        "record": {
            "completeness": ["reviewed_targets is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["reviewed_targets is missing"],
    },
    "missing_subjects": {
        "record": {
            "completeness": ["subjects is missing"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [],
        },
        "warnings": ["subjects is missing"],
    },
    "not_object": {
        "code": "REVIEW_INVALID",
        "message": "Reviewer record must be a JSON object",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "outside_path": {
        "code": "REVIEW_INVALID",
        "message": "reviewed_targets[0]: '../x.py' is not a project-relative path inside the project",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "path_not_text": {
        "code": "REVIEW_INVALID",
        "message": "reviewed_targets[0].path must be text",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "read_only_absent": {
        "record": {
            "completeness": ["invocation.read_only is not true"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": False,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["invocation.read_only is not true"],
    },
    "read_only_false": {
        "record": {
            "completeness": ["invocation.read_only is not true"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": False,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["invocation.read_only is not true"],
    },
    "read_only_text": {
        "record": {
            "completeness": ["invocation.read_only is not true"],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": False,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": ["invocation.read_only is not true"],
    },
    "reviewed_at_and_bad_subject": {
        "code": "REVIEW_INVALID",
        "message": "subjects[0].id: unknown finding 'F9'",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "reviewed_at_not_text": {
        "code": "REVIEW_INVALID",
        "message": "reviewed_at must be text",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "reviewed_targets_not_list": {
        "code": "REVIEW_INVALID",
        "message": "reviewed_targets must be a list",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "unknown_field": {
        "code": "REVIEW_INVALID",
        "message": "review has unknown fields: extra",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "unknown_finding": {
        "code": "REVIEW_INVALID",
        "message": "subjects[0].id: unknown finding 'F9'",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "unknown_invocation_field": {
        "code": "REVIEW_INVALID",
        "message": "invocation has unknown fields: model",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "unknown_na": {
        "code": "REVIEW_INVALID",
        "message": "subjects[0].id: unknown N/A decision 'policy:X'",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "unknown_subject_type": {
        "code": "REVIEW_INVALID",
        "message": "subjects[0].type must be one of finding, na_decision (got 'adoption')",
        "next_step": "Fix the Reviewer record file and record it again",
    },
    "valid": {
        "record": {
            "completeness": [],
            "invocation": {
                "agent": "guard-reviewer",
                "declared": True,
                "host": "github-copilot",
                "invoked_at": "2026-10-21T10:00:00Z",
                "read_only": True,
            },
            "requirement": "Re-check findings",
            "reviewed_at": "2026-10-21T10:05:00Z",
            "reviewed_targets": [{"digest": DIG, "path": "src/login.py"}],
            "subjects": [
                {
                    "basis": "input reaches HTML",
                    "evidence": ["E1"],
                    "id": "F1",
                    "result": "confirmed",
                    "severity_opinion": {"evidence": ["E1"], "severity": "high"},
                    "type": "finding",
                },
                {
                    "basis": "no SQL",
                    "evidence": [],
                    "id": "policy:CWE/4.14/CWE-89",
                    "result": "confirmed",
                    "severity_opinion": None,
                    "type": "na_decision",
                },
            ],
        },
        "warnings": [],
    },
}


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_guard_review_vectors_unchanged(name):
    assert outcome(VECTORS[name]) == EXPECTED[name]


def test_guard_record_key_order_unchanged():
    record, _ = records.validate_review(copy.deepcopy(STATE), _valid())
    assert list(record) == [
        "invocation",
        "requirement",
        "reviewed_targets",
        "subjects",
        "reviewed_at",
        "completeness",
    ]
    assert list(record["invocation"]) == ["host", "agent", "read_only", "invoked_at", "declared"]
    assert list(record["subjects"][0]) == ["type", "id", "result", "basis", "evidence", "severity_opinion"]


# --------------------------------------------------------------------------- shared envelope (Copilot use)
def _envelope(doc: Any, **over: Any) -> tuple[dict[str, Any], list[str]]:
    from x_ipe_secure_code import reviewer
    from x_ipe_secure_code.guard.targets import normalize

    ck = Checker("REVIEW_INVALID", "fix it")
    kwargs: dict[str, Any] = {
        "authority_keys": (*records.AUTHORITY_KEYS, "suggestions", "artifacts", "manifest", "stage"),
        "allowed_extra": set(),
        "allow_absent": True,
        "require_invoked_at": True,
        "normalize_path": normalize,
        "subjects": lambda raw, warnings: list(raw),
    }
    kwargs.update(over)
    return reviewer.envelope(ck, doc, **kwargs)


def _copilot_doc(**over: Any) -> dict[str, Any]:
    doc = _valid(subjects=[{"type": "adoption", "id": "S1", "result": "adopted", "basis": "b"}])
    del doc["attempt"], doc["usage"]
    doc.update(over)
    return doc


def test_envelope_copilot_accepts_absent_marker():
    record, warnings = _envelope(_copilot_doc(reviewed_targets=[{"path": "src/old.py", "digest": "absent"}]))
    assert record["reviewed_targets"] == [{"path": "src/old.py", "digest": "absent"}] and warnings == []


def test_envelope_absent_refused_when_not_allowed():
    with pytest.raises(GuardError) as err:
        _envelope(_copilot_doc(reviewed_targets=[{"path": "a.py", "digest": "absent"}]), allow_absent=False)
    assert err.value.code == "REVIEW_INVALID" and "digest" in err.value.message


def test_envelope_requires_invoked_at_for_copilot():
    doc = _copilot_doc()
    del doc["invocation"]["invoked_at"]
    _, warnings = _envelope(doc)
    assert warnings == ["invocation.invoked_at is missing"]
    _, guard_warnings = _envelope(doc, require_invoked_at=False)
    assert guard_warnings == []


@pytest.mark.parametrize("key", ["suggestions", "artifacts", "manifest", "stage", "scope", "plan"])
def test_envelope_caller_authority_keys(key):
    with pytest.raises(GuardError) as err:
        _envelope(_copilot_doc(**{key: []}))
    assert err.value.code == "REVIEW_AUTHORITY" and key in err.value.message


@pytest.mark.parametrize("key", ["attempt", "usage"])
def test_envelope_copilot_refuses_attempt_and_usage(key):
    with pytest.raises(GuardError) as err:
        _envelope(_copilot_doc(**{key: "x"}))
    assert err.value.code == "REVIEW_INVALID" and f"unknown fields: {key}" in err.value.message


def test_envelope_subject_callback_runs_before_reviewed_at():
    def bad(raw: list, warnings: list[str]) -> list:
        raise GuardError("REVIEW_INVALID", "subject first")

    with pytest.raises(GuardError) as err:
        _envelope(_copilot_doc(reviewed_at=7), subjects=bad)
    assert err.value.message == "subject first"


def test_envelope_missing_subjects_warning_then_callback_warnings():
    def collect(raw: list, warnings: list[str]) -> list:
        warnings.append("subjects[0].result is missing")
        return []

    _, warnings = _envelope(_copilot_doc(subjects=[]), subjects=collect)
    assert warnings == ["subjects is missing", "subjects[0].result is missing"]
