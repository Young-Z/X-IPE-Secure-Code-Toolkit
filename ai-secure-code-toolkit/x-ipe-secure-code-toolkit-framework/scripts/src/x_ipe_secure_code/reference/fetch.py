"""Fetching Reference content inside an open Guard verification (FEATURE-001-E, FR-001E-4/4a, X-01).

Ordered flow (design §Fetch Flow): run id → Local first (no run state, network or budget touched) →
registration and cache → target checks → v1.0 transport decision (`real_fetch_parked` before any resolver,
socket or authorization) → per-verification cap and `EgressGate.authorize` under the fetch-slot lock →
`EgressGate.get` (loopback GET, absolute deadline) → response checks → bounded parse (same deadline) →
masking and digests → generation- and registration-checked publication. The network is reached only
through the toolkit egress gate; no lock is held across it; nothing is retried or followed.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..guard import runs
from ..guard.egress import EgressGate
from ..guard.mask import mask_text
from ..guard.model import GuardError
from ..knowledge import durable, exit_journal
from ..knowledge.identity import IdentityError, RuleRef
from ..policy import resolve
from ..projects import knowledge_root
from ..results import Result
from . import FETCH_LOCK_REL, cache, clock, parse, policy_view, registry, urls
from .registry import Bad
from .service import LimitInvalid, check_limits, limit_refusal

PURPOSE = "reference_fetch"
B16_STEP = (
    "v1.0 fetches only inside a Guard verification opened on an available scope (for example a Local "
    "scope); a Reference-only library cannot bootstrap in v1.0 (human item B16)"
)
GRANT_STEP = (
    "Ask the user to grant this purpose: secure-code guard allow-egress --purpose reference_fetch "
    "--recipient {origin} --data public_query --scope {url} (their own terminal)"
)
CAP_STEP = "Cached Reference content can still be resolved; open a new verification for more fetches"
LOCAL_STEP = (
    "Report the Local problem to the Maintainer; the Reference is not substituted (Local first, X-02)"
)
NEXT = {
    "redirect_not_followed": "Register the final URL as the entry URL; redirects are never followed",
    "content_type_not_allowed": "Only text/html, text/plain and text/markdown are fetched",
    "content_encoding_not_allowed": "The server must answer without content encoding (identity)",
    "size_limit": "The page or its text is larger than the limit; register a smaller entry page",
    "timeout": "The absolute deadline was reached; retry later or check the fixture server",
    "connection_failed": "Check that the fixture server is running on the registered port",
    "header_invalid": "The response head was refused; check the fixture server",
    "http_status": "The server answered with an error status; check the entry URL",
    "decode_failed": "Declare a valid charset in Content-Type",
    "parse_failed": "No requirement text could be extracted; register an entry page with requirement text",
    "registration_changed": "Show the registration again and fetch again",
}
UNEXPIRED_NOTE = "used only by a later request without --refresh"


class Stop(Exception):
    """A refusal of the fetch flow (code, message, next step, data)."""

    def __init__(self, code: str, message: str, step: str | None, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code, self.message, self.step, self.data = code, message, step, data or {}


@dataclass
class Job:
    """What the network part needs to know about one rule or explore target."""

    command: str
    root: Path
    vid: str
    kind: str  # rule | explore
    source: dict[str, Any]
    target: urls.Target | None
    key: str
    start_generation: int
    fetch_digest: str
    refresh: bool
    limits: dict[str, Any]
    rule: dict[str, Any] | None = None
    previous: dict[str, Any] | None = None
    previous_state: str | None = None
    info: dict[str, Any] = field(default_factory=dict)


def _failure(job: Job, detail: str, message: str) -> Stop:
    """`fetch_failed`/`refresh_failed`/`parse_failed` with the detail; an unexpired old copy is named."""
    if job.refresh:
        code, reason = "REFRESH_FAILED", "refresh_failed"
    elif detail == "parse_failed":
        code, reason = "PARSE_FAILED", "parse_failed"
    else:
        code, reason = "FETCH_FAILED", "fetch_failed"
    data: dict[str, Any] = {"reason": reason, "detail": detail, **job.info}
    if job.kind == "rule":
        data["reference"] = {
            "availability": "missing",
            "reason": reason,
            "detail": detail,
            "knowledge_kind": "reference",
        }
    if job.refresh and job.previous is not None and job.previous_state == "valid":
        data["unexpired_copy"] = {
            "fetched_at": job.previous["fetched_at"],
            "expires_at": job.previous["expires_at"],
            "note": UNEXPIRED_NOTE,
        }
    return Stop(code, f"{reason}: {detail} ({message})", NEXT.get(detail, NEXT["http_status"]), data)


def _refusal(command: str, exc: BaseException) -> Result:
    if isinstance(exc, Stop):
        return Result.refused(command, exc.code, exc.message, exc.step, exc.data)
    if isinstance(exc, GuardError):
        return Result.refused(command, exc.code, exc.message, exc.next_step, exc.data)
    if isinstance(exc, (LockHeld, durable.StoreError, exit_journal.JournalInvalid)):
        return exit_journal.refusal(command, exc)
    if isinstance(exc, OSError):
        return Result.refused(
            command, "IO_ERROR", f"{exc.strerror or exc}", "Check folder permissions and retry"
        )
    raise exc


def _start(
    command: str, project: str | None, run_id: str | None, given: dict[str, Any]
) -> tuple[Path, str, dict[str, Any]] | Result:
    try:
        limits = check_limits(**given)
    except LimitInvalid as exc:
        return limit_refusal(command, exc)
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    if not run_id:
        return Result.refused(
            command, "RUN_REQUIRED", "A fetch needs an open Guard verification (--run)", B16_STEP
        )
    try:
        vid = runs.check_id(run_id)
    except GuardError as exc:
        return _refusal(command, exc)
    return root, vid, limits


# --------------------------------------------------------------------------- network part (shared)
def _fetches_used(state: dict[str, Any]) -> int:
    return sum(
        1
        for d in state["egress"]["declarations"]
        if d.get("by") == "toolkit" and d.get("purpose") == PURPOSE and d.get("decision") == "allowed"
    )


def _authorize(job: Job) -> tuple[EgressGate, Any]:
    """Steps 5–6 under the short fetch-slot lock: cap, then the delivered gate authorization."""
    with durable.Tree(job.root) as tree, durable.DirLock(tree, FETCH_LOCK_REL, create=True):
        state = runs.read_state(job.root, job.vid)
        used = _fetches_used(state)
        job.info["fetches_cap"] = job.limits["max_fetches"]
        if used >= job.limits["max_fetches"]:
            raise Stop(
                "FETCH_CAP_REACHED",
                f"{used} Reference fetches were made in this verification (cap {job.limits['max_fetches']})",
                CAP_STEP,
                {"reason": "fetch_cap_reached", **job.info},
            )
        gate = EgressGate(str(job.root), job.vid)
        url = job.target.url
        try:
            auth = gate.authorize(PURPOSE, url, [{"category": "public_query", "ref": url, "content": url}])
        except GuardError as exc:
            if exc.code != "EGRESS_NOT_AUTHORIZED":
                raise
            missing = exc.message.rsplit("covers the ", 1)[-1]
            raise Stop(
                "FETCH_NOT_AUTHORIZED",
                f"fetch_not_authorized: no reference_fetch grant covers the {missing} "
                f"(recipient {job.target.origin})",
                GRANT_STEP.format(origin=job.target.origin, url=url),
                {
                    "reason": "fetch_not_authorized",
                    "missing": missing,
                    "recipient": job.target.origin,
                    "purpose": PURPOSE,
                },
            ) from None
        job.info["egress"] = {"declaration": auth.id, "verification_id": job.vid}
        job.info["fetches_used"] = used + 1
    return gate, auth


def _checked(job: Job, response: dict[str, Any]) -> tuple[bytes, str]:
    """Step 8: status, encoding, size and media type (no decompression, nothing cached on failure)."""
    status, headers = response["status"], response["headers"]
    if response["redirect_not_followed"]:
        raise _failure(job, "redirect_not_followed", f"HTTP {status}; the redirect was not followed")
    if not 200 <= status < 300:
        job.info["http_status"] = status
        raise _failure(job, "http_status", f"HTTP {status}")
    encoding = headers.get("content-encoding")
    if encoding is not None and encoding.strip().lower() != "identity":
        raise _failure(job, "content_encoding_not_allowed", "a content encoding was used")
    if response["truncated"]:
        raise _failure(job, "size_limit", f"more than {job.limits['max_bytes']} bytes")
    content_type = headers.get("content-type", "")
    if parse.media_type(content_type)[0] not in parse.MEDIA_TYPES:
        raise _failure(
            job, "content_type_not_allowed", "the media type is not text/html, text/plain or text/markdown"
        )
    return response["body"], content_type


def _links(job: Job, hrefs: list[str | None]) -> list[dict[str, Any]]:
    out, seen = [], set()
    for href in hrefs:
        record = urls.classify_link(job.source, job.target.url, href)
        marker = (record["class"], record["url"]) if record["url"] is not None else None
        if marker is not None and marker in seen:
            continue
        if marker is not None:
            seen.add(marker)
        out.append(record)
    return out


def _omit_link_targets(job: Job, extracted: parse.Extracted, content_type: str) -> str:
    """Markdown keeps link targets in its text: a target whose link record is omitted (credential-like or
    invalid) is never retained there either (review finding 3). HTML hrefs are attributes, never text."""
    text = extracted.text
    if parse.media_type(content_type)[0] != "text/markdown":
        return text
    for href in extracted.links:
        if href and urls.classify_link(job.source, job.target.url, href)["url"] is None:
            text = text.replace(href, "[link omitted]")
    return text


def _network(job: Job) -> tuple[dict[str, Any], cache.Published]:
    """Steps 4–11: transport decision, cap + authorization, GET, checks, parse, mask, digests, publish."""
    assert job.target is not None
    parked = urls.transport_v1(job.target)
    if parked is not None:
        if parked.reason == "real_fetch_parked":
            raise Stop(
                "REAL_FETCH_PARKED",
                f"real_fetch_parked: {parked.message}",
                urls.P01,
                {"reason": "real_fetch_parked", "human_item": "P-01"},
            )
        raise _failure(job, parked.reason, parked.message)
    gate, auth = _authorize(job)
    deadline = time.monotonic() + job.limits["timeout"]
    try:
        response = gate.get(auth, limit=job.limits["max_bytes"], deadline=deadline)
    except GuardError as exc:
        if exc.code != "EGRESS_GET_FAILED":
            raise
        raise _failure(job, exc.data["detail"], exc.message) from None
    body, content_type = _checked(job, response)
    rule = job.rule
    try:
        extracted = parse.extract(
            body,
            content_type,
            deadline=deadline,
            max_text=job.limits["max_text"],
            title=rule["title"] if rule else None,
            rule_id=RuleRef.parse(rule["rule"]).rule_id if rule else None,
            base_url=job.target.url,
            want_links=True,
        )
    except parse.ParseError as exc:
        raise _failure(job, exc.detail, exc.cause or exc.detail) from None
    masked, kinds = mask_text(_omit_link_targets(job, extracted, content_type))
    text = parse.normalize(masked)
    if len(text.encode("utf-8")) > job.limits["max_text"]:  # masking can lengthen the text
        raise _failure(job, "size_limit", "the masked text is larger than the limit")
    links = _links(job, extracted.links) if job.kind == "explore" else []
    entry = cache.build_entry(
        kind=job.kind,
        rule=rule,
        explore_url=None if rule else job.target.url,
        canonical_url=job.target.url,
        reg_digest=job.fetch_digest,
        fetched_at=clock.utc_now(),
        http_status=response["status"],
        content_type=content_type,
        response_digest="sha256:" + hashlib.sha256(body).hexdigest(),
        text=text,
        masking={"applied": bool(kinds), "kinds": kinds},
        links=links,
        links_truncated=extracted.links_truncated,
    )
    published = cache.publish(
        job.root,
        entry,
        start_generation=job.start_generation,
        fetch_digest=job.fetch_digest,
        capacity=job.limits["cache_capacity"],
    )
    if published.note == "registration_changed":
        raise _failure(job, "registration_changed", "the registration changed during the fetch; not cached")
    return entry, published


def _cache_info(published: cache.Published) -> dict[str, Any]:
    return {"written": published.written, "note": published.note, "generation": published.generation}


def _digest_changes(job: Job, entry: dict[str, Any]) -> dict[str, bool] | None:
    if job.previous is None:
        return None
    return {
        "policy_state_digest_changed": job.previous.get("policy_state_digest")
        != entry["policy_state_digest"],
        "response_digest_changed": job.previous.get("response_digest") != entry["response_digest"],
    }


# --------------------------------------------------------------------------- rule fetch
def _local_first(command: str, lib: resolve.Library, ref: RuleRef) -> Result | None:
    """DEC-17: neither outcome reads or writes the run state, records a declaration or opens a socket."""
    if ref not in lib.rules and ref.rel not in lib.exited:
        return None
    found = resolve.evaluate(lib, ref, [])
    if found["availability"] == "available":
        return Result(
            command,
            True,
            {
                "rule": ref.rel,
                "outcome": "local_used",
                "reference": found,
                "notes": [policy_view.LOCAL_NOTE],
                "cache": None,
                "egress": None,
            },
            [],
            [],
        )
    return Result.refused(
        command,
        "LOCAL_FIRST_BROKEN",
        f"The formal Local rule {ref.rel} is {found['reason']}; the Reference is not substituted",
        LOCAL_STEP,
        {"rule": ref.rel, "reference": found},
    )


def _rule_job(
    command: str, root: Path, vid: str, rule: str, refresh: bool, limits: dict[str, Any]
) -> Job | Result:
    """Steps 1–3 under the knowledge lock (read-only snapshot)."""
    try:
        ref = RuleRef.parse(rule)
    except IdentityError as exc:
        return Result.refused(command, exc.code, exc.message, "Use NAMESPACE/VERSION/RULE_ID")
    with exit_journal.session(root, write=False) as session:
        tree = session.tree
        lib = resolve.snapshot(tree)
        local = _local_first(command, lib, ref)
        if local is not None:
            return local
        usable = lib.refs.usable(ref)
        if isinstance(usable, Bad):
            code = "RULE_NOT_REGISTERED" if ref.rel not in lib.refs.rules else "REGISTRY_INVALID"
            data = {
                "rule": ref.rel,
                **({"removed": lib.refs.removed[ref.rel]} if lib.refs.is_removed(ref) else {}),
            }
            return Result.refused(
                command,
                code,
                f"{ref.rel}: {usable.detail}",
                "Ask a Maintainer to register it (secure-code knowledge reference register)",
                data,
            )
        record, source = usable
        state = lib.refs.states[ref.rel]
        if state.state == "valid" and not refresh:
            found = resolve.evaluate(lib, ref, [])
            return Result(
                command,
                True,
                {
                    "rule": ref.rel,
                    "outcome": "cached",
                    "reference": found,
                    "notes": found.get("notes", []),
                    "cache": None,
                    "egress": None,
                },
                [],
                [],
            )
        key = cache.rule_key(record, source)
        generation = cache.current_generation(tree, key)
    previous = state.entry if state.state in ("valid", "expired") else None
    job = Job(
        command,
        root,
        vid,
        "rule",
        source,
        None,
        key,
        generation,
        registry.registration_digest(record, source),
        refresh,
        limits,
        record,
        previous,
        state.state,
        {"rule": ref.rel},
    )
    try:
        job.target = urls.check_target(source, record["entry_url"])
    except urls.UrlRefusal as exc:
        return _refusal(command, _failure(job, exc.reason, exc.message))
    return job


def fetch_command(
    project: str | None, run_id: str | None, rule: str, *, refresh: bool = False, **given: Any
) -> Result:
    """`knowledge reference fetch --run ID --rule REF [--refresh] [limits]`."""
    command = "knowledge reference fetch"
    started = _start(command, project, run_id, given)
    if isinstance(started, Result):
        return started
    root, vid, limits = started
    try:
        job = _rule_job(command, root, vid, rule, refresh, limits)
        if isinstance(job, Result):
            return job
        entry, published = _network(job)
        if published.local:
            with exit_journal.session(root, write=False) as session:
                local = _local_first(command, resolve.snapshot(session.tree), RuleRef.parse(job.rule["rule"]))
            assert local is not None
            local.data["cache"] = _cache_info(published)
            return local
        lib_entry = {**entry, "generation": published.generation or 0}
        with exit_journal.session(root, write=False) as session:
            lib = resolve.snapshot(session.tree)
        ref = RuleRef.parse(job.rule["rule"])
        if published.note == "superseded_by_newer_fetch":
            policy = resolve.evaluate(lib, ref, [])
        else:
            policy = {**policy_view._policy(lib, ref, lib_entry, []), "retrieval_status": "fetched"}
            if ref.rel in lib.pending:
                policy["notes"] = [policy_view.PENDING_NOTE]
    except (Stop, GuardError, LockHeld, durable.StoreError, exit_journal.JournalInvalid, OSError) as exc:
        return _refusal(command, exc)
    data = {
        "rule": ref.rel,
        "outcome": "fetched",
        "reference": policy,
        "notes": [],
        "cache": _cache_info(published),
        "digest_changes": _digest_changes(job, entry),
        **job.info,
    }
    if published.note:
        data["notes"].append(published.note)
    return Result(command, True, data, [], [])


# --------------------------------------------------------------------------- explore
def explore_command(
    project: str | None, run_id: str | None, source: str, url: str, *, refresh: bool = False, **given: Any
) -> Result:
    """`knowledge reference explore --run ID --source NS/VER --url URL`: untrusted text and classified
    links of one registered-domain page; never a Policy; no link is followed."""
    command = "knowledge reference explore"
    started = _start(command, project, run_id, given)
    if isinstance(started, Result):
        return started
    root, vid, limits = started
    try:
        parts = source.split("/") if isinstance(source, str) else []
        if len(parts) != 2:
            return Result.refused(
                command,
                "REQUEST_INVALID",
                f"A source is NAMESPACE/VERSION: {source!r}",
                "Use NAMESPACE/VERSION",
            )
        with exit_journal.session(root, write=False) as session:
            tree = session.tree
            view = registry.view_at(tree)
            record = view.sources.get(source)
            if record is None or isinstance(record, Bad):
                return Result.refused(
                    command,
                    "SOURCE_NOT_FOUND",
                    f"Reference source {source} is not usable",
                    "Ask a Maintainer to register it (secure-code knowledge reference register)",
                )
            try:
                target = urls.check_target(record, url)
            except urls.UrlRefusal as exc:
                if exc.delivered:
                    return Result.refused(command, exc.reason, exc.message, "Use a canonical registered URL")
                return Result.refused(
                    command,
                    "FETCH_FAILED",
                    f"fetch_failed: {exc.reason} ({exc.message})",
                    "Explore only URLs on the registered domains, port and path prefix",
                    {"reason": "fetch_failed", "detail": exc.reason},
                )
            key = cache.explore_key(target.url, record)
            state = cache.read_state(tree, key, clock.utc_now())
            generation = cache.current_generation(tree, key)
        if state.state == "valid" and not refresh:
            return Result(command, True, _explore_data(state.entry, "cached", None, {}), [], [])
        previous = state.entry if state.state in ("valid", "expired") else None
        job = Job(
            command,
            root,
            vid,
            "explore",
            record,
            target,
            key,
            generation,
            registry.source_digest(record),
            refresh,
            limits,
            None,
            previous,
            state.state,
            {"source": source},
        )
        entry, published = _network(job)
    except (Stop, GuardError, LockHeld, durable.StoreError, exit_journal.JournalInvalid, OSError) as exc:
        return _refusal(command, exc)
    return Result(command, True, _explore_data(entry, "fetched", published, job.info), [], [])


def _explore_data(
    entry: dict[str, Any], outcome: str, published: cache.Published | None, info: dict[str, Any]
) -> dict[str, Any]:
    return {
        "url": entry["canonical_url"],
        "outcome": outcome,
        "text": entry["text"],
        "content_label": policy_view.CONTENT_LABEL,
        "links": entry["links"],
        "links_truncated": entry["links_truncated"],
        "masking": entry["masking"],
        "fetched_at": entry["fetched_at"],
        "expires_at": entry["expires_at"],
        "cache": _cache_info(published) if published else None,
        **info,
    }
