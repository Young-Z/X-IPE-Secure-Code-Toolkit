"""`secure-code guard compare`: compare two concluded Guard reports of one project (FEATURE-002-G).

Read-only on both runs: only the two structured results and their Markdown reports are read; nothing
is scanned, executed or sent. Every refusal precedes the write stage, so a refused request writes
nothing; a successful one writes exactly one comparison pair into `reports/guard/comparisons/`.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ..atomic import dumps_json
from ..knowledge import durable
from ..paths import RootError, validate_root
from ..results import Result
from . import compare_io, compare_match, compare_render, report
from . import model as guard_model
from .compare_bounds import MAX_INPUT_BYTES, Invalid, TooLarge, check_encodable, prescan
from .compare_io import OVERSIZE, Inputs, WriteFailed, sha256_hex
from .compare_validate import validate
from .mask import mask_text
from .model import REPORTS_REL, RUN_ID, SCHEMA_RESULT, GuardError, parse_time

COMMAND = "guard compare"
COMPARISON_ID = re.compile(r"gc-\d{8}T\d{6}Z-[0-9a-f]{8}")
REPORT_FILE = re.compile(r"(gv-\d{8}T\d{6}Z-[0-9a-f]{8})\.(json|md)")
REPORT_PARTS = tuple(REPORTS_REL.split("/"))
NAME_STEP = "Name a verification ID (gv-…) or <id>.json/.md directly in x-ipe-docs/secure-code/reports/guard/"
REQUEST_STEP = "Name exactly two different reports: --earlier <id> --later <id>"
INVALID_STEP = "Name another report, or restore this result from the toolkit's own output"
TOO_LARGE_STEP = "Name other reports to compare; these limits are fixed (NFR-002G-5)"
UNRESOLVED = (
    "Input integrity unresolved for run {role} ({vid}): failed checks {checks}. The Markdown report or the "
    "structured result was edited, or the report was rendered by a different toolkit version; it cannot be "
    "told which file was changed. This comparison used the structured result after it passed strict "
    "validation; nothing was repaired or written in that run."
)


class _Refusal(Exception):
    def __init__(self, code: str, message: str, next_step: str, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code, self.message, self.next_step, self.data = code, message, next_step, data or {}


@dataclass
class Loaded:
    role: str
    vid: str
    doc: dict[str, Any]
    raw: bytes
    canonical: bytes


def _names(value: Sequence[str] | str | None) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _shown(names: list[str]) -> list[str]:
    return [mask_text(str(n))[0][:300] for n in names]


def resolve_name(raw: Any, role: str) -> str:
    """Verification ID of a report name (pure string rules, before any file-system access)."""

    def bad() -> _Refusal:
        return _Refusal(
            "REPORT_NAME_INVALID",
            f"The {role} report name is not a verification ID or an exact "
            "report file directly in the project's Guard report folder",
            NAME_STEP,
            {"role": role},
        )

    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise bad()
    if RUN_ID.fullmatch(raw):
        return raw
    text = raw.replace("\\", "/")
    if text.startswith("/") or re.match(r"[A-Za-z]:", text) or text.endswith("/"):
        raise bad()
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if ".." in parts or len(parts) != 5 or tuple(parts[:-1]) != REPORT_PARTS:
        raise bad()
    match = REPORT_FILE.fullmatch(parts[-1])
    if match is None:
        raise bad()
    return match.group(1)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("json.duplicate_key", "$")
        result[key] = value
    return result


def _refuse_constant(name: str) -> Any:
    raise Invalid("json.constant", "$")


def _too_large(exc: TooLarge, role: str, vid: str) -> _Refusal:
    return _Refusal(
        "RESULT_TOO_LARGE",
        f"Comparison not possible: the structured result of {role} ({vid}) exceeds the comparison limit "
        f"{exc.limit} ({exc.limit_value}). The verification and its result are not affected and are not "
        "declared invalid.",
        TOO_LARGE_STEP,
        {
            "role": role,
            "verification_id": vid,
            "limit": exc.limit,
            "limit_value": exc.limit_value,
            "rule": exc.rule,
            "json_path": "$",
            "byte_offset": exc.byte_offset,
        },
    )


def load_result(raw: Any, role: str, vid: str) -> Loaded:
    """Bounded parse: pre-scan, JSON, encodability, schema, ID and canonical serialization."""
    if raw is None:  # removed between the metadata check and the read
        raise _Refusal(
            "RUN_NOT_FOUND",
            f"The {role} verification {vid} was not found in this project",
            "Name a concluded verification of this project",
            {"role": role, "verification_id": vid},
        )
    try:
        if raw is OVERSIZE:
            raise TooLarge("max_input_bytes")
        prescan(raw)
        try:
            doc = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_refuse_constant
            )
        except (UnicodeError, ValueError):
            raise Invalid("json.syntax", "$") from None
        except RecursionError:
            raise TooLarge("max_depth") from None
        except MemoryError:
            raise TooLarge("memory") from None
        if not isinstance(doc, dict):
            raise Invalid("json.object", "$")
        check_encodable(doc)
        if doc.get("schema") != SCHEMA_RESULT:
            found = doc.get("schema")
            shown = (
                mask_text(found)[0][:120] if isinstance(found, str) and found.isprintable() else "<not text>"
            )
            raise _Refusal(
                "RESULT_SCHEMA_UNSUPPORTED",
                f"The {role} result has an unsupported schema",
                "Name a report written by a supported toolkit version",
                {"role": role, "verification_id": vid, "found": shown, "supported": [SCHEMA_RESULT]},
            )
        if doc.get("verification_id") != vid:
            raise Invalid("id.file_name", "$.verification_id")
        try:
            canonical = dumps_json(doc)
        except (RecursionError, MemoryError):
            raise TooLarge("memory") from None
        except (ValueError, TypeError, UnicodeError, OverflowError):
            raise Invalid("canonical.serialization", "$") from None
    except TooLarge as exc:
        raise _too_large(exc, role, vid) from None
    except Invalid as exc:
        raise _invalid(exc, role, vid) from None
    return Loaded(role, vid, doc, raw, canonical)


def _invalid(exc: Invalid, role: str, vid: str, data: dict[str, Any] | None = None, step: str = INVALID_STEP):
    return _Refusal(
        "RESULT_INVALID",
        f"The {role} result ({vid}) is invalid: rule {exc.rule} at {exc.path}",
        step,
        {"role": role, "verification_id": vid, "rule": exc.rule, "json_path": exc.path, **(data or {})},
    )


def _end_time(doc: dict[str, Any]) -> str:
    value = doc.get("ended_at")
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        try:
            parse_time(value)
            return value
        except ValueError:
            pass
    return "unknown"


def _validate(loaded: Loaded, other: Loaded) -> None:
    try:
        validate(loaded.doc, loaded.vid)
    except Invalid as exc:
        if exc.path != "$.ended_at":
            raise _invalid(exc, loaded.role, loaded.vid) from None
        times = {loaded.role: _end_time(loaded.doc), other.role: _end_time(other.doc)}
        if exc.rule != "order.timestamps":
            times[loaded.role] = "unknown"
        raise _invalid(
            exc,
            loaded.role,
            loaded.vid,
            {"end_times": times},
            f"Name other reports; the end time of {loaded.role} is not readable",
        ) from None


def integrity(loaded: Loaded, md: Any) -> tuple[list[str], str | None]:
    """Failed integrity checks of one run (FR-002G-2b) and its fixed statement."""
    failed = []
    if md is OVERSIZE:
        failed.append("markdown_oversized")
    elif md is None:
        failed.append("markdown_missing")
    if loaded.canonical != loaded.raw:
        failed.append("result_canonical_serialization")
    if isinstance(md, bytes):
        try:
            text = md.decode("utf-8")
        except UnicodeError:
            text = None
        if text is None or report.footer_digest(text) != sha256_hex(loaded.raw):
            failed.append("footer_digest")
        source = loaded.doc if loaded.canonical == loaded.raw else json.loads(loaded.canonical)
        try:
            canonical_md = report.render(source)  # pure: reads the result, writes nothing
        except Exception:  # noqa: BLE001 - any render failure is an unresolved integrity check (05c)
            canonical_md = None
        if text is None or canonical_md != text:
            failed.append("markdown_canonical_rendering")
    if not failed:
        return [], None
    return failed, UNRESOLVED.format(role=loaded.role, vid=loaded.vid, checks=", ".join(failed))


def _candidate_factory(base: dict[str, Any]) -> Callable[[], tuple[str, bytes, Callable[[str], bytes]]]:
    def factory() -> tuple[str, bytes, Callable[[str], bytes]]:
        stamp = guard_model.utc_now()
        cid = f"gc-{stamp.replace('-', '').replace(':', '')}-{secrets.token_hex(4)}"
        doc = {**base, "comparison_id": cid, "created_at": stamp}
        json_bytes = dumps_json(doc)

        def markdown_factory(json_sha256: str) -> bytes:
            return compare_render.markdown(doc, json_sha256).encode("utf-8")

        return cid, json_bytes, markdown_factory

    return factory


def _resolve(earlier: Any, later: Any) -> tuple[str, str]:
    e_names, l_names = _names(earlier), _names(later)
    if len(e_names) != 1 or len(l_names) != 1:
        raise _Refusal(
            "COMPARE_REQUEST_INVALID",
            "A comparison needs exactly one --earlier and one --later report",
            REQUEST_STEP,
            {"earlier": _shown(e_names), "later": _shown(l_names)},
        )
    e_id, l_id = resolve_name(e_names[0], "earlier"), resolve_name(l_names[0], "later")
    if e_id == l_id:
        raise _Refusal(
            "COMPARE_REQUEST_INVALID",
            "The same verification was named twice",
            REQUEST_STEP,
            {"earlier": _shown(e_names), "later": _shown(l_names)},
        )
    return e_id, l_id


def _check_inputs(inputs: Inputs, ids: dict[str, str]) -> dict[str, str]:
    availability = {}
    for role, vid in ids.items():
        folder = inputs.run_folder(vid)
        if inputs.twin(f"{vid}.json") is None:
            if folder == "available":
                raise _Refusal(
                    "NOT_CONCLUDED",
                    f"The {role} verification {vid} is not concluded",
                    f"Conclude it first: secure-code guard conclude --run {vid}",
                    {"role": role, "verification_id": vid},
                )
            raise _Refusal(
                "RUN_NOT_FOUND",
                f"The {role} verification {vid} was not found in this project",
                "Name a concluded verification of this project",
                {"role": role, "verification_id": vid},
            )
        inputs.twin(f"{vid}.md")
        availability[role] = folder
    inputs.comparisons_precheck()
    return availability


def _compare(root: Any, earlier: Any, later: Any) -> Result:
    e_id, l_id = _resolve(earlier, later)
    ids = {"earlier": e_id, "later": l_id}
    with durable.Tree(root) as tree:
        try:
            inputs = Inputs(tree)
        except GuardError as exc:
            if exc.code == "RUN_NOT_FOUND":
                exc.data = {"role": "earlier", "verification_id": e_id}
            raise
        try:
            availability = _check_inputs(inputs, ids)
            raws = {role: inputs.read(f"{vid}.json", MAX_INPUT_BYTES) for role, vid in ids.items()}
            mds = {role: inputs.read(f"{vid}.md", MAX_INPUT_BYTES) for role, vid in ids.items()}
            loaded = {role: load_result(raws[role], role, vid) for role, vid in ids.items()}
            del raws
            _validate(loaded["earlier"], loaded["later"])
            _validate(loaded["later"], loaded["earlier"])
            facts = {}
            for role in ("earlier", "later"):
                failed, statement = integrity(loaded[role], mds[role])
                facts[role] = {
                    "state": "unresolved" if failed else "consistent",
                    "failed_checks": failed,
                    "markdown_present": mds[role] is not None,
                    "statement": statement,
                    "result_sha256": sha256_hex(loaded[role].raw),
                    "raw_evidence": availability[role],
                }
            del mds
            ends = {role: loaded[role].doc["ended_at"] for role in ("earlier", "later")}
            if parse_time(ends["later"]) <= parse_time(ends["earlier"]):
                equal = ends["later"] == ends["earlier"]
                raise _Refusal(
                    "END_ORDER_INVALID",
                    "The later run ended at the same second as the earlier run"
                    if equal
                    else "The later run ended before the earlier run; roles are never reordered",
                    "Name other reports; equal end times cannot be ordered"
                    if equal
                    else "Swap --earlier and --later",
                    {
                        role: {"verification_id": ids[role], "ended_at": ends[role]}
                        for role in ("earlier", "later")
                    },
                )
            base = compare_match.build(loaded["earlier"].doc, loaded["later"].doc, facts)
            del loaded
            cid, collisions = compare_io.write_pair(tree, inputs.reports_fd, _candidate_factory(base))
        finally:
            inputs.close()
    files = {
        "structured": f"{compare_io.COMPARISONS_REL}/{cid}.json",
        "markdown": f"{compare_io.COMPARISONS_REL}/{cid}.md",
    }
    data = {
        "comparison_id": cid,
        **{
            role: {
                "verification_id": ids[role],
                "ended_at": ends[role],
                "input_integrity": facts[role]["state"],
            }
            for role in ("earlier", "later")
        },
        "counts": base["counts"],
        "files": files,
        "collisions": collisions,
        "statements": [base["statements"]["not_observed_meaning"], base["statements"]["not_evidence"]],
    }
    return Result(
        COMMAND,
        True,
        data,
        [],
        [
            f"Read {files['markdown']}; report any input-integrity statement first",
            '"Not observed this time" does not mean fixed; do not report a trend or score',
        ],
    )


def compare(
    project: str | None, earlier: Sequence[str] | str | None, later: Sequence[str] | str | None
) -> Result:
    """Compare two concluded Guard results of one project (FEATURE-002-G).

    Args:
        project: Explicit project root (`--project`).
        earlier: The earlier report: verification ID or exact `<id>.json|.md` path (one value).
        later: The later report, same forms.

    Returns:
        Result `guard compare`; refusals write nothing; success writes exactly one comparison pair.
    """
    try:
        root = validate_root(project)
    except RootError as exc:
        return Result.refused(COMMAND, exc.code, exc.message, "Pass an existing project with --project")
    try:
        return _compare(root, earlier, later)
    except _Refusal as exc:
        return Result.refused(COMMAND, exc.code, exc.message, exc.next_step, exc.data)
    except GuardError as exc:
        return Result.refused(COMMAND, exc.code, exc.message, exc.next_step, exc.data)
    except WriteFailed as exc:
        step = (
            "Use a project folder on a file system that supports hard links (the same requirement as "
            "secure-code guard conclude)"
            if exc.code == "HARDLINK_UNSUPPORTED"
            else compare_io.WRITE_STEP
        )
        return Result.refused(
            COMMAND,
            exc.code,
            f"The comparison was not written ({exc.message}); everything this command created was removed",
            step,
            {"step": exc.step},
        )
    except durable.StoreError as exc:
        return Result.refused(COMMAND, "PATH_UNSAFE", exc.message, compare_io.UNSAFE_STEP)
    except OSError as exc:
        return Result.refused(
            COMMAND,
            "IO_ERROR",
            f"Could not read the Guard reports ({exc.strerror})",
            "Check the permissions of x-ipe-docs/secure-code/reports/guard",
        )
