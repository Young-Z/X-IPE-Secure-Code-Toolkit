"""Read-only draft check pipeline V1…V13, canonical payload and `validation_digest` (FEATURE-001-G).

`run` never writes, never creates folders and never creates the pre-check key. It renders the
canonical final payload P (`{"example-<lang>.md": full new text}`), checks it, and binds the
unmasked P plus the review inputs into `validation_digest` (only when the status is `valid`).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..paths import unsafe_component
from ..results import Problem
from . import drafting_blocks as blocks
from . import drafting_checks as checks
from . import drafting_lint, drafting_mask, durable, exit_journal, precheck, store
from .batch import LANG, MAX_ITEM_BYTES, ItemError, apply_update, normalize_text
from .drafting_auth import is_authorized
from .drafting_model import Draft, DraftError, Review, parse_draft, parse_review, read_input

VALIDATOR_VERSION = f"001g.1/py{sys.version_info.major}.{sys.version_info.minor}"
VALIDATION_SCHEMA = "ai-secure-code-toolkit/knowledge-draft-validation/v1"
REPRESENTABLE = re.compile(rf"changelog\.md|content\.md|example\.md|example-(?:{LANG.pattern})\.md")
LIMITS = [
    "Python examples are parsed (AST only) and never executed; other languages are not syntax-validated.",
    "The normative-language lint is advisory; the Maintainer's attestation is the binding check.",
    "Provenance is checked for field completeness only; licence and original wording are attested by the "
    "Maintainer.",
    "The rule-link check shows only that a verbatim rule quote is present (precondition only).",
    "Markers are tamper-evident for accidental edits only.",
    "Host and model labels are self-reported.",
]
RECOVERY_STEP = (
    "Run `secure-code knowledge list --project <path>`, which completes the interrupted "
    "operation, then check again"
)
STALE_STEP = "Show the rule again and draft against its current state_digest"
INACTIVE_STEP = "Reactivate the rule first (knowledge exit-preview --action reactivate)"
KEY_STEP = (
    "Restore .x-ipe/private/secure-code/precheck-key or let a Maintainer run a delivered knowledge "
    "import/update, which creates it; draft-check never creates it"
)
PRESERVE_STEP = (
    "Move or remove the listed file(s) yourself — draft approval never deletes or changes rule "
    "files other than the drafted example files — then check again"
)
MARKER_STEP = "Repair the markers manually, then check again"
INTERNAL_STEP = (
    "Stop: internal drafting needs the Maintainer's recorded authorization of this host "
    "(knowledge drafting-authorize at an interactive terminal)"
)


class Refusal(Exception):
    """A fatal input refusal (no preview, no digest)."""

    def __init__(
        self, code: str, message: str, next_step: str | None = None, data: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.code, self.message, self.next_step, self.data = code, message, next_step, data or {}


@dataclass
class Report:
    status: str
    data: dict[str, Any]
    problems: list[Problem]
    draft: Draft
    review: Review | None
    stored: Any = None
    new_item: Any = None
    payload: dict[str, str] = field(default_factory=dict)
    blocking: list[precheck.Finding] = field(default_factory=list)
    pairs: list[tuple[str, str]] = field(default_factory=list)

    @property
    def validation_digest(self) -> str | None:
        return self.data.get("validation_digest")


def validation_digest(draft: Draft, review: Review, key: bytes, payload: dict[str, str]) -> str:
    body = {
        "schema": VALIDATION_SCHEMA,
        "validator_version": VALIDATOR_VERSION,
        "rule": draft.ref.rel,
        "base_state": draft.base_state,
        "draft_digest": draft.digest,
        "review_digest": review.digest,
        "precheck_key_id": drafting_mask.key_id(key),
        "payload": payload,
    }
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _inputs(root: Path, draft_path: str, review_path: str | None) -> tuple[Draft, Review | None, bool]:
    try:
        draft = parse_draft(read_input(root, draft_path, "draft"))
        review = parse_review(read_input(root, review_path, "review")) if review_path else None
    except DraftError as exc:
        raise Refusal(exc.code, exc.message, exc.next_step) from None
    if review is not None and review.draft_digest != draft.digest:
        return draft, None, True
    if review is not None:
        extra = sorted(set(review.examples) - set(draft.examples))
        if extra:
            raise Refusal(
                "DRAFT_REVIEW_INVALID",
                f"the review names example(s) {extra} that the draft does not contain",
                "The Maintainer corrects the review file",
            )
    return draft, review, False


def _rule(root: Path, draft: Draft) -> Any:
    stored = store.read_rule(root, draft.ref)
    if stored is None or (stored.digest is None and not stored.files):
        raise Refusal(
            "RULE_NOT_FOUND",
            f"{draft.ref} is not stored (a draft never follows a rename)",
            "Draft for a stored rule; a renamed rule needs a new draft for its new identity",
        )
    if not stored.consistent:
        raise Refusal("RULE_INCONSISTENT", f"{draft.ref} does not match its record; resolve before drafting")
    return stored


def _gate(root: Path, draft: Draft) -> str | None:
    classification = checks.classification(draft)
    if classification == "internal":
        allowed, reason = is_authorized(root, draft.host)
        if not allowed:
            detail = f" ({reason})" if reason else ""
            raise Refusal(
                "INTERNAL_DRAFTING_NOT_AUTHORIZED",
                f"No active internal drafting authorization for host '{draft.host}'{detail}",
                INTERNAL_STEP,
            )
    return classification


def _markers(draft: Draft, files: dict[str, str]) -> None:
    try:
        for lang, example in sorted(draft.examples.items()):
            blocks.check_part(lang, "unsafe", example.unsafe)
            blocks.check_part(lang, "safe", example.safe)
        targets = ["content.md"] + [
            store.example_file(lang) for lang in sorted(draft.examples) if lang in blocks.COMMENT
        ]
        for name in targets:
            if name in files:
                blocks.scan_markers(name, files[name])
    except blocks.MarkerError as exc:
        raise Refusal("SUPPLEMENT_MARKERS_INVALID", str(exc), MARKER_STEP) from None


def _representable(files: dict[str, str]) -> None:
    odd = sorted(n for n in files if not REPRESENTABLE.fullmatch(n))
    if odd or "content.md" not in files:
        listed = odd or ["content.md (missing)"]
        raise Refusal(
            "PRESERVATION_FAILED",
            f"rule files the delivered writer would delete or cannot keep: {listed}",
            PRESERVE_STEP,
            {"files": listed},
        )


def _key(root: Path) -> bytes:
    reason = unsafe_component(root, precheck.KEY_REL, expect_dir=False)
    if reason:
        raise Refusal("PATH_UNSAFE", reason, "Replace the symbolic link with a real file")
    try:
        key = precheck.read_key(root)
    except OSError:
        key = None
    if key is None or len(key) != 32:
        raise Refusal(
            "PRECHECK_KEY_UNAVAILABLE", "The pre-check key is absent, unreadable or invalid", KEY_STEP
        )
    return key


def run(root: Path, draft_path: str, review_path: str | None) -> Report:
    """V1…V13 for one draft (read-only). Raises Refusal for fatal input problems."""
    with durable.Tree(root) as tree:
        if exit_journal.has_pending(tree):
            raise Refusal(
                "RECOVERY_PENDING",
                "An interrupted knowledge exit is pending; read-only drafting commands do not complete it",
                RECOVERY_STEP,
            )
    draft, review, mismatch = _inputs(root, draft_path, review_path)
    classification = _gate(root, draft)
    stored = _rule(root, draft)
    state = store.state_digest(stored)
    base = "current" if state == draft.base_state else "stale_base"
    data: dict[str, Any] = {
        "rule": draft.ref.rel,
        "status": None,
        "base": base,
        "base_state": draft.base_state,
        "state_digest": state,
        "draft_digest": draft.digest,
        "review_digest": review.digest if review else None,
        "validator_version": VALIDATOR_VERSION,
    }
    problems = (
        [
            Problem(
                "DRAFT_REVIEW_MISMATCH",
                "This review names another draft digest; the Maintainer must review this draft",
            )
        ]
        if mismatch
        else []
    )
    if store.lifecycle_state(stored.record)[0] == "deactivated":
        data["status"] = "rule_inactive"
        return Report(
            "rule_inactive",
            data,
            [Problem("RULE_INACTIVE", f"{draft.ref} is deactivated")] + problems,
            draft,
            review,
            stored,
        )
    if base == "stale_base":
        data["status"] = "stale_base"
        return Report(
            "stale_base",
            data,
            [Problem("STALE_BASE", f"{draft.ref} changed since {draft.base_state}")] + problems,
            draft,
            review,
            stored,
        )
    _representable(stored.files)
    _markers(draft, stored.files)
    key = _key(root)
    return _evaluate(root, draft, review, classification, stored, key, data, problems)


def _evaluate(
    root: Path,
    draft: Draft,
    review: Review | None,
    classification: str | None,
    stored: Any,
    key: bytes,
    data: dict[str, Any],
    problems: list[Problem],
) -> Report:
    files = stored.files
    non_ai = [files["content.md"]] + [
        blocks.strip(t) for n, t in sorted(files.items()) if n.startswith("example")
    ]
    rule_corpus = checks.corpus(non_ai)
    rule_lines = [line for text in non_ai for line in text.split("\n")]
    applicability = stored.record.get("applicability")
    languages: dict[str, Any] = {}
    warnings: dict[str, list[Any]] = {
        "normative_language": [],
        "language_not_in_applicability": [],
        "replaces_modified_block": [],
    }
    command_findings: list[dict[str, Any]] = []
    rendered: dict[str, str] = {}
    failed: list[str] = []
    recorded_att = review.attested() if review else set()
    for lang, example in sorted(draft.examples.items()):
        results = [{"result": r} for r in checks.structure(lang, example)]
        if any(r["result"] == "language_unsupported" for r in results):
            results[0]["message"] = checks.unsupported_message(lang)
        level, syntax = checks.python_syntax(example, lang) if not results else (None, [])
        results += syntax
        link = checks.rule_link(example, rule_corpus)
        if link == "no_rule_link":
            results.append(
                {
                    "result": "no_rule_link",
                    "message": "no `demonstrates` entry quotes the rule's "
                    "non-AI text verbatim (≥ 16 characters)",
                }
            )
        found = checks.commands(lang, example)
        command_findings += [dict(f, note=checks.COMMAND_NOTE) for f in found]
        for part in ("unsafe", "safe"):
            warnings["normative_language"] += drafting_lint.lint(
                lang, part, getattr(example, part), rule_lines
            )
        if checks.applicability_warning(lang, applicability):
            warnings["language_not_in_applicability"].append(lang)
        required = checks.required_items(lang, has_commands=bool(found))
        recorded = review.recorded(lang) if review else set()
        missing = [i for i in required if i not in recorded]
        languages[lang] = {
            "level": level,
            "rule_link": link,
            "results": results,
            "decision": "complete" if not missing else {"missing": missing},
            "required": required,
        }
        if results:
            failed.append(lang)
        if level is not None:
            file_name = store.example_file(lang)
            notice = blocks.notice_lines(
                draft_digest=draft.digest,
                sources=draft.sources,
                level=level,
                decisions=recorded & set(required),
                attestations=recorded_att,
                acknowledgements=recorded & set(required),
                confidentiality=classification,
            )
            block = blocks.render_block(lang, draft.digest, notice, example.unsafe, example.safe)
            old = files.get(file_name)
            if old and any(b.state == "modified" for b in blocks.scan_markers(file_name, old)):
                warnings["replaces_modified_block"].append(file_name)
            rendered[lang] = blocks.render_file(old, block)
    provenance = [
        checks.provenance(draft.ref, s, internal=classification == "internal") for s in draft.sources
    ]
    bad_sources = [
        p["result"]
        for p in provenance
        if p["result"] in ("source_not_allowed", "provenance_incomplete", "attribution_missing")
    ]
    attestations = checks.required_attestations(draft)
    missing_att = [a for a in attestations if a not in recorded_att]
    data.update(
        languages=languages,
        warnings=warnings,
        command_findings=command_findings,
        provenance=provenance,
        non_normative_statement=blocks.NOTICE,
        limits=LIMITS,
        review_required={
            "examples": {k: v["required"] for k, v in languages.items()},
            "attestations": attestations,
        },
    )
    report = Report("", data, problems, draft, review, stored)
    payload, new_item, too_large = (
        _payload(stored, rendered) if len(rendered) == len(draft.examples) else ({}, None, False)
    )
    shape_ok = (
        not any(
            r["result"] in ("language_unsupported", "example_incomplete")
            for v in languages.values()
            for r in v["results"]
        )
        and not too_large
    )
    if too_large:
        failed.append("item_too_large")
    data["checks"] = {
        "target": "passed",
        "markers": "passed",
        "shape": "passed" if shape_ok else "failed",
        "preservation": "passed" if payload else "not_run",
        "precheck": "not_run",
        "provenance": "failed" if bad_sources else "passed",
        "review": "passed"
        if review and not missing_att and not any(v["decision"] != "complete" for v in languages.values())
        else "incomplete",
    }
    data["precheck"] = {"findings": []}
    data["preview"] = {"final": False, "masked_diff": None}
    if payload:
        _masked(report, key, payload, new_item)
    status = _status(report, failed, bad_sources, missing_att)
    report.status = data["status"] = status
    if status == "valid":
        data["validation_digest"] = validation_digest(draft, review, key, payload)
        data["preview"]["final"] = True
    else:
        data["validation_digest"] = None
    return report


def _payload(stored: Any, rendered: dict[str, str]) -> tuple[dict[str, str], Any, bool]:
    payload = {store.example_file(lang): text for lang, text in sorted(rendered.items())}
    try:
        new_item = apply_update(stored.item, {"examples": dict(rendered)})
    except ItemError as exc:
        raise Refusal("DRAFT_INVALID", f"rendered example cannot be stored: {exc.message}") from None
    for lang, text in rendered.items():
        if normalize_text(text) != text or new_item.examples.get(lang) != text:
            raise Refusal("DRAFT_INVALID", "rendering not normalisation-stable")
        name = store.example_file(lang)
        if blocks.strip(text) != blocks.strip(stored.files.get(name)):
            raise Refusal("PRESERVATION_FAILED", f"{name}: non-AI text would change", PRESERVE_STEP)
    files_new = store.item_files(new_item)
    deletes = set(stored.files) - {"changelog.md"} - set(files_new)
    changed = {n for n, t in files_new.items() if stored.files.get(n) != t}
    if deletes or changed - set(payload):
        listed = sorted(deletes | (changed - set(payload)))
        raise Refusal(
            "PRESERVATION_FAILED",
            f"the delivered writer would delete or change {listed}",
            PRESERVE_STEP,
            {"files": listed},
        )
    return payload, new_item, new_item.size() > MAX_ITEM_BYTES


def _masked(report: Report, key: bytes, payload: dict[str, str], new_item: Any) -> None:
    stored = report.stored
    old_files = store.item_files(stored.item)
    new_files = store.item_files(new_item)
    try:
        old_spans = drafting_mask.locate(old_files, key)
        new_spans = drafting_mask.locate(new_files, key)
    except drafting_mask.MaskingParity as exc:
        raise Refusal(
            "MASKING_PARITY", str(exc), "Report this to the Maintainer; nothing was written"
        ) from None
    findings = [s.finding for name in sorted(new_spans) for s in new_spans[name]]
    report.blocking = [f for f in findings if f.blocking]
    report.pairs = drafting_mask.values(old_spans, old_files) + drafting_mask.values(new_spans, new_files)
    report.pairs.sort(key=lambda kv: (-len(kv[0]), kv[0]))
    report.payload, report.new_item = payload, new_item
    report.data["precheck"] = {"findings": [f.to_dict() for f in findings]}
    report.data["checks"]["precheck"] = "findings" if report.blocking else "passed"
    old = {name: stored.files.get(name) for name in payload}
    report.data["preview"]["masked_diff"] = drafting_mask.masked_diff(old, payload, old_spans, new_spans)


def _status(report: Report, failed: list[str], bad_sources: list[str], missing_att: list[str]) -> str:
    data, problems = report.data, report.problems
    if failed or bad_sources:
        names = sorted(
            {r["result"] for v in data["languages"].values() for r in v["results"]}
            | set(bad_sources)
            | ({"item_too_large"} if "item_too_large" in failed else set())
        )
        langs = [lang for lang in failed if lang != "item_too_large"]
        problems.insert(
            0,
            Problem(
                "DRAFT_CHECK_FAILED",
                f"failed checks {names}" + (f" for language(s) {langs}" if langs else ""),
            ),
        )
    missing = [
        f"examples.{lang}.{item}"
        for lang, v in sorted(data["languages"].items())
        if v["decision"] != "complete"
        for item in v["decision"]["missing"]
    ]
    if report.review is None:
        problems.append(
            Problem(
                "REVIEW_INCOMPLETE",
                "No usable review file: the Maintainer writes the review "
                "file (review_required lists the exact items)",
            )
        )
    else:
        if missing:
            problems.append(Problem("EXAMPLE_DECISION_MISSING", f"missing Maintainer decisions: {missing}"))
        if missing_att:
            problems.append(Problem("ATTESTATION_MISSING", f"missing Maintainer attestations: {missing_att}"))
    if failed or bad_sources:
        return "invalid"
    if report.review is None or missing or missing_att:
        return "review_incomplete"
    return "valid"
