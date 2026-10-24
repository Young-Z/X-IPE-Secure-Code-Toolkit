"""Purpose-specific data egress (FEATURE-002-C): grants, agent declarations and the toolkit egress gate.

Four purposes are authorized separately, per verification, by the user at an interactive terminal.
Agents declare every outbound call before making it (an audit record, not enforced blocking). The
toolkit's own network clients send only through `EgressGate`: a single-use authorization bound to the
exact URL and the masked payload built from authorized items, with its own no-proxy, no-redirect
opener. Network access by tools that Adapters launch is not isolated (stated limit).
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import unquote, urlsplit

from .. import adapters
from ..auth.interaction import Interaction, TerminalInteraction
from ..results import Problem, Result
from . import budget, runs, targets
from .mask import PRIVATE_KEY_BLOCK, mask_text
from .model import MAX_TEXT, Checker, GuardError, load_request
from .service import _call, _locked, _mutate, consumed, now

SCHEMA_EGRESS = "ai-secure-code-toolkit/guard-egress/v1"
PURPOSES = ("reference_fetch", "tool_update", "target_requests", "submission")
CATEGORIES = (
    "metadata",
    "public_query",
    "target_traffic",
    "dependency_manifest",
    "findings",
    "source_excerpts",
)
PROHIBITED = ("credentials", "signing_key", "model_credentials")
SUBMISSION_ONLY = {"findings", "source_excerpts"}
CONTENT_PURPOSES = {"dependency_manifest": {"tool_update", "submission"}}
MODEL_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")
MAX_ITEMS, MAX_ITEM = 50, 500
TIMEOUT = 30
STEP = "Ask the user to grant this purpose: secure-code guard allow-egress (their own terminal)"


class ExecutionMode(NamedTuple):
    mode: str
    argv_extra: list[str]


# --------------------------------------------------------------------------- URLs and scope
def _invalid(message: str, code: str = "EGRESS_INVALID") -> GuardError:
    return GuardError(code, message, "Fix the purpose, recipient, data or scope")


def canonical_url(url: Any) -> tuple[str, str]:
    """(origin, decoded path) of an http(s) URL; refuses credentials, queries and ambiguous paths."""
    origin, path, _ = _parse_url(url)
    return origin, path


def _parse_url(url: Any) -> tuple[str, str, str]:
    """(origin, decoded path for scope checks, raw percent-encoded path to send)."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise _invalid("a URL must be text of at most 2048 characters")
    if mask_text(url)[1] or mask_text(unquote(url))[1]:
        raise _invalid(
            "the URL contains a credential (also checked after percent-decoding)", "EGRESS_URL_CREDENTIALS"
        )
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise _invalid(f"{url!r} is not an http(s) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise _invalid(
            f"{url!r} must not carry user information, a query or a fragment", "EGRESS_URL_CREDENTIALS"
        )
    host = parts.hostname.encode("idna").decode("ascii").lower()
    port = parts.port
    default = {"http": 80, "https": 443}[parts.scheme]
    origin = f"{parts.scheme}://{host}" + (f":{port}" if port and port != default else "")
    raw = parts.path or "/"
    if re.search(r"%(?:2[fF]|5[cC]|25)", raw) or "\\" in raw or any(ord(c) <= 32 for c in raw):
        raise _invalid(f"{url!r} has an encoded separator, space or control character in its path")
    if not raw.isascii():
        raise _invalid(f"{url!r} must be percent-encoded (ASCII only)")
    path = unquote(raw)
    if any(seg in (".", "..") for seg in path.split("/")):
        raise _invalid(f"{url!r} has dot segments in its path")
    return origin, path, raw


def _origin(url: Any) -> str:
    origin, path = canonical_url(url)
    if path not in ("", "/"):
        raise _invalid("a recipient is an origin (scheme, host and port) without a path")
    return origin


def _scope_entry(raw: Any) -> str:
    if isinstance(raw, str) and "://" in raw:
        origin, path = canonical_url(raw)
        return origin + path
    try:
        entry = targets.normalize(raw, "scope")
    except GuardError as exc:
        raise _invalid(exc.message) from None
    if mask_text(entry)[1]:
        raise _invalid("a scope entry contains a credential", "EGRESS_URL_CREDENTIALS")
    return entry


def _under(entry: str, granted: str) -> bool:
    """A scope entry is covered by an equal granted entry or one above it at a `/` boundary."""
    is_url = "://" in entry
    if is_url != ("://" in granted):
        return False
    if entry == granted:
        return True
    if not is_url:
        return granted == "." or entry.startswith(granted + "/")
    return entry.startswith(granted if granted.endswith("/") else granted + "/")


def _categories(raw: Any) -> list[str]:
    ck = Checker("EGRESS_INVALID", STEP)
    items = ck.items(raw, "data", required=True)
    out = []
    for item in items:
        if item in PROHIBITED:
            raise GuardError(
                "EGRESS_PROHIBITED",
                f"{item} can never be sent: keys and credentials are never granted",
                "Remove it; such data never leaves the project",
            )
        if item not in CATEGORIES:
            raise _invalid(f"data category {item!r} is not one of {', '.join(CATEGORIES)}")
        if item not in out:
            out.append(item)
    return out


def coverage(
    state: dict[str, Any], purpose: str, origin: str, data: list[str], scope: list[str], url_path: str | None
) -> tuple[str | None, str | None]:
    """(missing element, grant id): the first missing of purpose, recipient, data, scope; else the grant."""
    grants = [g for g in state["egress"]["grants"] if g["purpose"] == purpose]
    if not grants:
        return "purpose", None
    grants = [g for g in grants if g["recipient"] == origin]
    if not grants:
        return "recipient", None
    grants = [g for g in grants if set(data) <= set(g["data"])]
    if not grants:
        return "data", None
    for g in grants:
        if not all(any(_under(s, e) for e in g["scope"]) for s in scope):
            continue
        urls = [e for e in g["scope"] if "://" in e]
        if url_path is not None and urls and not any(_under(origin + url_path, e) for e in urls):
            continue
        return None, g["id"]
    return "scope", None


# --------------------------------------------------------------------------- grants (user only)
def allow_egress(
    project: str | None,
    run_id: str,
    purpose: str,
    recipient: str,
    data: list[str],
    scope: list[str],
    reason: str,
    interaction: Interaction | None = None,
) -> Result:
    """The user grants one outbound purpose for one verification at an interactive terminal."""
    command = "guard allow-egress"
    interaction = interaction or TerminalInteraction()
    if not interaction.is_interactive():
        return Result.refused(
            command,
            "INTERACTIVE_REQUIRED",
            "Only the user at an interactive terminal can grant outbound data; agents cannot",
            "Ask the user to run this command in their own terminal",
        )

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        if purpose not in PURPOSES:
            raise _invalid(f"purpose must be one of {', '.join(PURPOSES)}")
        origin = _origin(recipient)
        cats = _categories(data)
        for c in cats:
            allowed = {"submission"} if c in SUBMISSION_ONLY else CONTENT_PURPOSES.get(c)
            if allowed and purpose not in allowed:
                raise _invalid(f"{c} can only be granted for {' or '.join(sorted(allowed))}")
        ck = Checker("EGRESS_INVALID", STEP)
        entries = [_scope_entry(s) for s in ck.items(scope, "scope", required=True)]
        text = mask_text(
            Checker("REQUEST_INVALID", "Give a reason").text(reason, "--reason", limit=MAX_TEXT)
        )[0]
        typed = interaction.prompt_text(
            f"Allow {purpose} of {', '.join(cats)} to {origin} for {vid}? "
            "Type the verification id to confirm: "
        )
        if typed is None or typed.strip() != vid:
            raise GuardError(
                "CONFIRMATION_MISMATCH",
                "The typed confirmation does not match the verification id",
                "Run the command again and type the exact verification id",
            )
        out: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            if used >= state["budget"]["total_seconds"]:
                raise GuardError(
                    "BUDGET_TIME_EXHAUSTED",
                    "The time limit is used up; no new outbound purpose can be granted",
                    budget.EXTEND_STEP,
                )
            rev = state["revision"]
            g = {
                "id": f"g-{len(state['egress']['grants']) + 1}",
                "purpose": purpose,
                "recipient": origin,
                "data": cats,
                "scope": entries,
                "reason": text,
                "at": now()[0],
                "role": "user",
            }
            state["egress"]["grants"].append(g)
            runs.commit_state(root, state, expected_revision=rev)
            out["grant"] = g
            out["budget"] = budget.status(state, used)
            return state

        _mutate(root, run_id, change, "none")
        return Result(command, True, {"verification_id": vid, **out}, [], [])

    return _call(command, project, body)


# --------------------------------------------------------------------------- agent declarations
def _items(raw: Any) -> list[str]:
    ck = Checker("EGRESS_INVALID", STEP)
    items = ck.items(raw, "items")
    if len(items) > MAX_ITEMS:
        raise _invalid(f"at most {MAX_ITEMS} items")
    return [mask_text(ck.text(i, f"items[{n}]", limit=MAX_ITEM))[0] for n, i in enumerate(items)]


def declare(project: str | None, run_id: str, request: str) -> Result:
    """The agent declares one outbound call before making it; recorded masked, allowed or refused."""
    command = "guard egress"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_EGRESS, "EGRESS_INVALID", STEP)
        ck = Checker("EGRESS_INVALID", STEP)
        ck.obj(
            doc,
            "egress",
            {"schema", "purpose", "recipient", "data", "items", "scope"},
            frozenset({"purpose", "recipient", "data", "scope"}),
        )
        purpose = ck.choice(doc["purpose"], "purpose", PURPOSES)
        origin = _origin(doc["recipient"])
        cats = _categories(doc["data"])
        entries = [_scope_entry(s) for s in ck.items(doc["scope"], "scope", required=True)]
        items = _items(doc.get("items"))
        out: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            rev = state["revision"]
            missing, grant_id = coverage(state, purpose, origin, cats, entries, None)
            d = {
                "id": f"eg-{len(state['egress']['declarations']) + 1}",
                "by": "agent",
                "purpose": purpose,
                "recipient": origin,
                "data": cats,
                "items": items,
                "scope": entries,
                "decision": "refused" if missing else "allowed",
                "missing": missing,
                "grant": grant_id,
                "at": now()[0],
                "used": False,
            }
            state["egress"]["declarations"].append(d)
            runs.commit_state(root, state, expected_revision=rev)
            out.update(
                declaration=d["id"],
                decision=d["decision"],
                missing=missing,
                grant=grant_id,
                budget=budget.status(state, used),
            )
            return state

        _mutate(root, run_id, change, "work")
        vid = runs.check_id(run_id)
        if out["missing"]:
            return Result(
                command,
                False,
                {"verification_id": vid, **out},
                [Problem("EGRESS_NOT_AUTHORIZED", f"Not authorized: no grant covers the {out['missing']}")],
                [STEP],
            )
        return Result(
            command, True, {"verification_id": vid, **out}, [], ["Send only the declared, minimized data"]
        )

    return _call(command, project, body)


# --------------------------------------------------------------------------- toolkit gate
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class Authorization(NamedTuple):
    id: str
    url: str
    payload: bytes
    digest: str


def _live(root: Path, state: dict[str, Any]) -> None:
    if state["status"] != "open":
        raise GuardError("RUN_FINISHED", "The verification is not open")
    budget.ensure(state)
    budget.require_running(state, consumed(root, state))


class EgressGate:
    """The only way toolkit code may send data out (single-use, bound, masked, no proxy, no redirect)."""

    def __init__(self, project: str, run_id: str, *, _opener: Any = None) -> None:
        self.root = Path(project)
        self.vid = runs.check_id(run_id)
        self._open = (_opener or globals()["_opener"]()).open

    def authorize(self, purpose: str, url: str, items: list[dict[str, Any]]) -> Authorization:
        if purpose not in PURPOSES:
            raise _invalid(f"purpose must be one of {', '.join(PURPOSES)}")
        origin, path, raw_path = _parse_url(url)
        cats = _categories([i.get("category") for i in items] if isinstance(items, list) else None)
        refs = [_scope_entry(i.get("ref")) for i in items]
        built = []
        for item in items:
            content = item.get("content")
            if not isinstance(content, str):
                raise _invalid("item content must be text")
            if PRIVATE_KEY_BLOCK.search(content) or MODEL_KEY.search(content):
                self._record(purpose, origin, path, cats, refs, "refused", "prohibited content", None)
                raise GuardError(
                    "EGRESS_PROHIBITED",
                    "A private key or model credential was found in the data; nothing was sent",
                    "Remove it from the data",
                )
            built.append(
                {"category": item["category"], "ref": item.get("ref"), "content": mask_text(content)[0]}
            )
        payload = json.dumps(built, sort_keys=True, ensure_ascii=False).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        did, missing = self._record(purpose, origin, path, cats, refs, None, None, digest)
        if missing:
            raise GuardError("EGRESS_NOT_AUTHORIZED", f"Not authorized: no grant covers the {missing}", STEP)
        return Authorization(did, origin + raw_path, payload, digest)

    def _record(self, purpose, origin, path, cats, refs, decision, note, digest) -> tuple[str, str | None]:
        holder: dict[str, Any] = {}

        def fn(state: dict[str, Any]) -> None:
            _live(self.root, state)
            missing, grant_id = (
                (note, None) if decision else coverage(state, purpose, origin, cats, refs, path)
            )
            d = {
                "id": f"eg-{len(state['egress']['declarations']) + 1}",
                "by": "toolkit",
                "purpose": purpose,
                "recipient": origin,
                "path": path,
                "data": cats,
                "items": refs,
                "scope": refs,
                "decision": "refused" if missing else "allowed",
                "missing": missing,
                "grant": grant_id,
                "digest": digest,
                "at": now()[0],
                "used": False,
            }
            state["egress"]["declarations"].append(d)
            holder.update(id=d["id"], missing=missing)

        with _locked(self.root):
            runs.update_state(self.root, self.vid, fn)
        return holder["id"], holder["missing"]

    def send(self, auth: Authorization) -> dict[str, Any]:
        origin, path = canonical_url(auth.url)

        def consume(state: dict[str, Any]) -> None:
            _live(self.root, state)
            d = next((x for x in state["egress"]["declarations"] if x["id"] == auth.id), None)
            sent = "sha256:" + hashlib.sha256(auth.payload).hexdigest()
            if d is None or d["decision"] != "allowed" or d["digest"] != sent:
                raise GuardError(
                    "EGRESS_NOT_AUTHORIZED", "This authorization is not recorded as allowed", STEP
                )
            if d["used"]:
                raise GuardError(
                    "EGRESS_REUSED", "An authorization can be used once", "Authorize the call again"
                )
            if (d["recipient"], d["path"]) != (origin, path):
                raise GuardError("EGRESS_NOT_AUTHORIZED", "The URL differs from the authorized one", STEP)
            d["used"] = True

        with _locked(self.root):
            runs.update_state(self.root, self.vid, consume)
        request = urllib.request.Request(
            auth.url, data=auth.payload, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            response = self._open(request, timeout=TIMEOUT)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                return {"status": exc.code, "redirect_not_followed": True}
            return {"status": exc.code, "redirect_not_followed": False}
        return {"status": response.status, "redirect_not_followed": False, "body": response.read(65536)}
    # --- P6 GET path (FEATURE-001-E, additive) ---
    # Body-less loopback GET for purpose `reference_fetch` only (DAO-018 OQ-01 A / DAO-020 TD DEC-01/02).
    # Kept inside this module: the delivered rule is that no other module opens network clients. v1.0
    # fetches only http://127.0.0.1[:port] (human item P-01): numeric AF_INET socket, no name resolution,
    # no TLS, no proxy, no redirect, no retry, HTTP/1.0 with fixed headers, strict response-head grammar,
    # allowlisted bounded headers, body read to EOF up to limit + 1, one absolute monotonic deadline and an
    # explicit close on success, error and timeout.
    GET_HEADERS = (
        ("User-Agent", "ai-secure-code-toolkit/{version}"),
        ("Accept", "text/html, text/plain, text/markdown"),
        ("Accept-Encoding", "identity"),
        ("Connection", "close"),
    )
    GET_ALLOWED = {"content-type": 256, "content-length": 20, "content-encoding": 64}
    GET_MAX_STATUS, GET_MAX_HEAD, GET_MAX_LINES, GET_CHUNK = 1024, 16384, 64, 65536
    GET_ORIGIN = re.compile(r"http://127\.0\.0\.1(?::[0-9]{1,5})?")
    GET_STATUS = re.compile(rb"HTTP/1\.[01] ([2-5][0-9]{2}) [\t\x20-\x7e\x80-\xff]*")
    GET_TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
    GET_VALUE = re.compile(rb"[\t\x20-\x7e\x80-\xff]*")
    GET_DIGITS = re.compile(rb"[0-9]{1,20}")
    GET_STEP = "Check the fixture server and the registered entry URL, then fetch again"

    @staticmethod
    def get_failed(detail: str, message: str) -> GuardError:
        """`EGRESS_GET_FAILED` with data `detail`: timeout | connection_failed | header_invalid."""
        return GuardError("EGRESS_GET_FAILED", message, EgressGate.GET_STEP, {"detail": detail})

    @staticmethod
    def require_loopback(url: Any) -> None:
        """EGRESS_INVALID unless exactly http://127.0.0.1[:port]/… (before consumption and any socket)."""
        origin, _, _ = _parse_url(url)
        parts = urlsplit(url)
        loopback = parts.scheme == "http" and parts.hostname == "127.0.0.1"
        if not (loopback and EgressGate.GET_ORIGIN.fullmatch(origin)):
            raise _invalid("The GET path fetches only http://127.0.0.1[:port] in v1.0 (human item P-01)")

    @staticmethod
    def parse_head(head: bytes) -> tuple[int, list[tuple[str, str]]]:
        """Strict grammar of a response head (without its final CRLF CRLF), applied to every line including
        headers that are later discarded; any violation is `header_invalid`."""
        g = EgressGate

        def bad(why: str) -> GuardError:
            return g.get_failed("header_invalid", f"The response head is not accepted ({why})")

        if len(head) > g.GET_MAX_HEAD:
            raise bad("head larger than 16 KiB")
        lines = head.split(b"\r\n")
        if any(b"\r" in line or b"\n" in line for line in lines):
            raise bad("bare CR or LF")
        if len(lines[0]) > g.GET_MAX_STATUS or not g.GET_STATUS.fullmatch(lines[0]):
            raise bad("status line")
        if len(lines) - 1 > g.GET_MAX_LINES:
            raise bad("too many header lines")
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        for line in lines[1:]:
            if line[:1] in (b" ", b"\t"):
                raise bad("obsolete line folding")
            name, colon, value = line.partition(b":")
            if not colon or not g.GET_TOKEN.fullmatch(name):
                raise bad("field line")
            value = value.strip(b" \t")
            if not g.GET_VALUE.fullmatch(value):
                raise bad("control character in a field value")
            lowered = name.decode("ascii").lower()
            if lowered == "transfer-encoding":
                raise bad("Transfer-Encoding is not supported")
            if lowered in g.GET_ALLOWED:
                if lowered in seen:
                    raise bad(f"duplicated {lowered}")
                too_long = len(value) > g.GET_ALLOWED[lowered]
                if too_long or (lowered == "content-length" and not g.GET_DIGITS.fullmatch(value)):
                    raise bad(f"{lowered} value")
            seen.add(lowered)
            out.append((lowered, value.decode("latin-1")))
        return int(lines[0][9:12]), out

    def get(self, auth: Authorization, *, limit: int, deadline: float) -> dict[str, Any]:
        """Body-less GET for purpose `reference_fetch` only (FEATURE-001-E, P6). Additive to `send`: the
        same single-use, URL-bound consumption under the Guard lock, then the loopback request."""
        self.require_loopback(auth.url)
        origin, path = canonical_url(auth.url)

        def consume(state: dict[str, Any]) -> None:
            _live(self.root, state)
            d = next((x for x in state["egress"]["declarations"] if x["id"] == auth.id), None)
            sent = "sha256:" + hashlib.sha256(auth.payload).hexdigest()
            if d is None or d["decision"] != "allowed" or d["digest"] != sent:
                raise GuardError(
                    "EGRESS_NOT_AUTHORIZED", "This authorization is not recorded as allowed", STEP
                )
            if d["purpose"] != "reference_fetch":
                raise _invalid("The GET path serves only purpose reference_fetch")
            if d["used"]:
                raise GuardError(
                    "EGRESS_REUSED", "An authorization can be used once", "Authorize the call again"
                )
            if (d["recipient"], d["path"]) != (origin, path):
                raise GuardError("EGRESS_NOT_AUTHORIZED", "The URL differs from the authorized one", STEP)
            d["used"] = True

        with _locked(self.root):
            runs.update_state(self.root, self.vid, consume)
        return self.get_request(auth.url, limit=limit, deadline=deadline)

    @staticmethod
    def get_request(url: str, *, limit: int, deadline: float) -> dict[str, Any]:
        """One GET → {"status", "headers" (allowlisted, lower-case names), "body" (≤ limit + 1 bytes),
        "truncated", "redirect_not_followed"}; EGRESS_GET_FAILED otherwise."""
        import socket
        import time

        from .. import __version__

        g = EgressGate
        g.require_loopback(url)
        _, _, raw = _parse_url(url)
        port = urlsplit(url).port or 80

        def remaining() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise g.get_failed("timeout", "The fetch deadline was reached")
            return left

        def io(call: Any, *args: Any) -> Any:
            sock.settimeout(remaining())
            try:
                return call(*args)
            except TimeoutError:
                raise g.get_failed("timeout", "The fetch deadline was reached") from None
            except OSError as exc:
                detail = f"The connection failed ({exc.strerror or exc})"
                raise g.get_failed("connection_failed", detail) from None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            io(sock.connect, ("127.0.0.1", port))
            headers = [(k, v.format(version=__version__)) for k, v in g.GET_HEADERS]
            lines = [f"GET {raw} HTTP/1.0", f"Host: 127.0.0.1:{port}", *(f"{k}: {v}" for k, v in headers)]
            io(sock.sendall, ("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            data = b""
            while b"\r\n\r\n" not in data:
                if (b"\r\n" not in data and len(data) > g.GET_MAX_STATUS) or len(data) > g.GET_MAX_HEAD + 4:
                    raise g.get_failed("header_invalid", "The response head is not accepted (too long)")
                chunk = io(sock.recv, 4096)
                if not chunk:
                    raise g.get_failed("header_invalid", "The response ended before its head was complete")
                data += chunk
            end = data.index(b"\r\n\r\n")
            status, fields = g.parse_head(data[:end])
            body = data[end + 4 :]
            allowed = {name: value for name, value in fields if name in g.GET_ALLOWED}
            result: dict[str, Any] = {"status": status, "headers": allowed, "body": b"", "truncated": False,
                                      "redirect_not_followed": 300 <= status < 400}
            if not 200 <= status < 300:
                return result
            declared = int(allowed["content-length"]) if "content-length" in allowed else None
            if declared is not None and declared > limit:
                result["truncated"] = True
                return result
            while len(body) <= limit:
                chunk = io(sock.recv, min(g.GET_CHUNK, limit + 1 - len(body)))
                if not chunk:
                    break
                body += chunk
            body = body[: limit + 1]
            truncated = len(body) > limit
            if declared is not None and not truncated and len(body) != declared:
                raise g.get_failed("header_invalid", "The body length differs from Content-Length")
            result.update(body=body, truncated=truncated)
            return result
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
    # --- end P6 GET path ---


# --------------------------------------------------------------------------- Adapter network needs
def adapter_network_check(state: dict[str, Any], adapter: str, argv: list[str]) -> ExecutionMode:
    """How an Adapter's tool may run: no network needed, granted, offline arguments, or refused."""
    spec = adapters.ADAPTERS.get(adapter)
    need = getattr(spec, "network", None)
    if not need:
        return ExecutionMode("none", [])
    origin = _origin(need["recipient"])
    missing, _ = coverage(state, need["purpose"], origin, list(need["data"]), [origin + "/"], None)
    if missing is None:
        return ExecutionMode("networked", [])
    if need.get("offline_argv"):
        return ExecutionMode("offline", list(need["offline_argv"]))
    raise GuardError(
        "EGRESS_NOT_AUTHORIZED",
        f"{adapter} needs network access for {need['purpose']} to {origin}; no grant covers the {missing}",
        STEP,
    )
