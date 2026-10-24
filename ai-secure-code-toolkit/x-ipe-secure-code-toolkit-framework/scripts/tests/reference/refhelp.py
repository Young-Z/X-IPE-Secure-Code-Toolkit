"""FEATURE-001-E test helpers: real initialized projects, a raw-TCP fixture server on 127.0.0.1, a frozen
clock, registration, Guard verification and in-process CLI helpers.

FEATURE-001-E modules are imported at Act (never during collection), so the tests fail for the right
reason before the implementation exists. Fixture pages are small synthetic pages written for these tests
(no copied third-party content, no internal policy content, nothing from the gitignored folders).
"""

from __future__ import annotations

import importlib
import json
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeInteraction
from knowledge.exithelp import Env, files, item

PAGES = Path(__file__).resolve().parent / "fixtures" / "pages"
REGISTRY = "x-ipe-docs/secure-code/knowledge/reference"
CACHE = ".x-ipe/private/secure-code/reference-cache"
GUARD_RUNS = ".x-ipe/private/secure-code/guard"
BATCH = "ai-secure-code-toolkit/reference-batch/v1"
LOCAL = "LOCAL/1/L-1"
CWE79 = "CWE/2024-top25/CWE-79"
CWE89 = "CWE/2024-top25/CWE-89"
T0 = datetime(2026, 10, 24, 1, 0, 0, tzinfo=UTC)


def mod(name: str) -> Any:
    """Import a FEATURE-001-E (or delivered) module at Act."""
    return importlib.import_module("x_ipe_secure_code." + name)


# --------------------------------------------------------------------------- fixture server
def http_response(
    body: bytes = b"",
    status: str = "200 OK",
    headers: list[tuple[str, str]] | None = None,
    *,
    content_type: str | None = "text/html; charset=utf-8",
    length: bool = True,
) -> bytes:
    lines = [f"HTTP/1.1 {status}"]
    if content_type is not None:
        lines.append(f"Content-Type: {content_type}")
    if length:
        lines.append(f"Content-Length: {len(body)}")
    lines += [f"{k}: {v}" for k, v in headers or []]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def page(name: str, content_type: str = "text/html; charset=utf-8") -> bytes:
    return http_response((PAGES / name).read_bytes(), content_type=content_type)


Handler = Callable[[socket.socket, bytes], None]


@dataclass
class FixtureServer:
    """Threaded raw-TCP HTTP fixture bound to the numeric address 127.0.0.1 on an ephemeral port."""

    routes: dict[str, bytes | Handler] = field(default_factory=dict)
    requests: list[bytes] = field(default_factory=list)
    closed: list[bool] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self._stop = False
        self._threads: list[threading.Thread] = []
        self._accept = threading.Thread(target=self._loop, daemon=True)
        self._accept.start()

    @property
    def count(self) -> int:
        return len(self.requests)

    def _loop(self) -> None:
        self.sock.settimeout(0.1)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            worker = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self._threads.append(worker)
            worker.start()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.requests.append(data)
            path = data.split(b" ", 2)[1].decode("latin-1") if data.count(b" ") >= 2 else "/"
            route = self.routes.get(path, http_response(b"not found", "404 Not Found"))
            try:
                if callable(route):
                    route(conn, data)
                else:
                    conn.sendall(route)
            except OSError:
                pass
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            closed = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    if conn.recv(65536) == b"":
                        closed = True
                        break
                except (TimeoutError, OSError):
                    closed = True
                    break
            self.closed.append(closed)
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop = True
        self._accept.join(timeout=2)
        self.sock.close()
        for worker in self._threads:
            worker.join(timeout=5)


@pytest.fixture
def server():
    srv = FixtureServer()
    yield srv
    srv.stop()


def closed_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# --------------------------------------------------------------------------- clock
class Clock:
    def __init__(self, monkeypatch: Any, at: datetime = T0) -> None:
        self.now = at
        monkeypatch.setattr(mod("reference.clock"), "utc_now", lambda: self.now)

    def advance(self, **delta: float) -> None:
        self.now = self.now + timedelta(**delta)


@pytest.fixture
def clock(monkeypatch):
    return Clock(monkeypatch)


# --------------------------------------------------------------------------- project env
def source_item(
    ns_ver: str = "CWE/2024-top25",
    domains: Any = ("127.0.0.1",),
    *,
    scheme: str | None = "http",
    port: Any = None,
    path_prefix: str | None = None,
    **over: Any,
) -> dict[str, Any]:
    ns, ver = ns_ver.split("/")
    data: dict[str, Any] = {"type": "source", "namespace": ns, "version": ver, "domains": list(domains)}
    if scheme is not None:
        data["scheme"] = scheme
    if port is not None:
        data["port"] = port
    if path_prefix is not None:
        data["path_prefix"] = path_prefix
    data.update(over)
    return data


def rule_item(rule: str, url: str, title: str = "Cross-site Scripting", **over: Any) -> dict[str, Any]:
    return {"type": "rule", "rule": rule, "title": title, "entry_url": url, **over}


class RefEnv(Env):
    """A real initialized project with one usable Local rule, a Maintainer and a fixture server."""

    def __init__(self, project: Path, work: Path, srv: FixtureServer | None = None, *, local: bool = True):
        super().__init__(project, work)
        self.srv = srv
        if local:
            loaded = self.load(item(LOCAL))
            assert loaded.ok, loaded.to_dict()

    # -- registry -----------------------------------------------------------------------------
    def register(self, *items: dict[str, Any], paths: Any = "default") -> Any:
        batch = self.req({"schema": BATCH, "items": list(items)})
        return mod("reference.registry_ops").register_batch(
            str(self.project), batch, trust_paths=self.paths if paths == "default" else paths
        )

    def url(self, path: str) -> str:
        assert self.srv is not None
        return self.srv.origin + path

    def standard(self, *rules: str, port: bool = True, prefix: str | None = "/docs/cwe/") -> Any:
        """Source CWE/2024-top25 on the fixture origin plus the named rules (79 and/or 89)."""
        entries = {
            CWE79: ("/docs/cwe/79.html", "Cross-site Scripting"),
            CWE89: ("/docs/cwe/89.html", "SQL Injection"),
        }
        items = [source_item(port=self.srv.port if port and self.srv else None, path_prefix=prefix)]
        for rule in rules:
            path, title = entries[rule]
            items.append(rule_item(rule, self.url(path), title))
        result = self.register(*items)
        assert result.ok, result.to_dict()
        return result

    def serve(self, path: str, response: bytes | Handler) -> None:
        assert self.srv is not None
        self.srv.routes[path] = response

    def serve_standard(self) -> None:
        self.serve("/docs/cwe/79.html", page("cwe-79.html"))
        self.serve("/docs/cwe/89.html", page("cwe-89.html"))
        self.serve("/docs/cwe/top25.html", page("cwe-top25-list.html"))

    # -- service calls ------------------------------------------------------------------------
    @property
    def service(self) -> Any:
        return mod("reference.service")

    def show(self, rule: str = CWE79) -> Any:  # type: ignore[override]
        return self.service.show(str(self.project), rule=rule)

    def registration_digest(self, rule: str = CWE79) -> str:
        shown = self.show(rule)
        assert shown.ok, shown.to_dict()
        return shown.data["registration_digest"]

    def source_digest(self, source: str = "CWE/2024-top25") -> str:
        shown = self.service.show(str(self.project), source=source)
        assert shown.ok, shown.to_dict()
        return shown.data["registration_digest"]

    def fetch(self, vid: str | None, rule: str = CWE79, *, refresh: bool = False, **limits: Any) -> Any:
        return self.service.fetch(str(self.project), vid, rule, refresh=refresh, **limits)

    def explore(
        self,
        vid: str | None,
        url: str,
        source: str = "CWE/2024-top25",
        *,
        refresh: bool = False,
        **limits: Any,
    ) -> Any:
        return self.service.explore(str(self.project), vid, source, url, refresh=refresh, **limits)

    def resolve(self, *rules: str, all_: bool = False) -> Any:
        return mod("policy.service").resolve_policies(str(self.project), list(rules), all_, [])

    def entry(self, rule: str = CWE79) -> dict[str, Any]:
        result = self.resolve(rule)
        return result.data["entries"][0]

    # -- scopes and Guard ---------------------------------------------------------------------
    def save_scope(self, *rules: str) -> str:
        proposal = self.resolve(*rules)
        decisions = [
            {
                "ref": e["requested"],
                "decision": "adopted",
                "state_digest": e["source_evidence"]["state_digest"],
            }
            for e in proposal.data["entries"]
        ]
        path = self.req(
            {
                "schema": "ai-secure-code-toolkit/scope-decisions/v1",
                "mode": "clues",
                "considered": list(rules),
                "proposal_digest": proposal.data["proposal_digest"],
                "clues": "reference fixture",
                "language_context": [],
                "decisions": decisions,
                "confirmation_note": "User explicitly confirmed the scope",
            }
        )
        saved = mod("policy.service").save_scope(str(self.project), path, True)
        assert saved.ok, saved.to_dict()
        return saved.data["scope_id"]

    def open_guard(self, scope_id: str | None = None) -> Any:
        scope_id = scope_id or self.save_scope(LOCAL)
        source = self.project / "src"
        source.mkdir(exist_ok=True)
        (source / "app.py").write_text("def app(value):\n    return value\n")
        path = self.req(
            {
                "schema": "ai-secure-code-toolkit/guard-open/v1",
                "scope_id": scope_id,
                "targets": [{"path": "src/app.py", "change": "modified"}],
            }
        )
        return mod("guard.service").open_verification(str(self.project), path)

    def opened(self, scope_id: str | None = None) -> str:
        result = self.open_guard(scope_id)
        assert result.ok, result.to_dict()
        return result.data["verification_id"]

    def grant(
        self,
        vid: str,
        *,
        recipient: str | None = None,
        scope: str | None = None,
        data: tuple[str, ...] = ("public_query",),
    ) -> Any:
        assert self.srv is not None or recipient
        recipient = recipient or self.srv.origin
        out = mod("guard.egress").allow_egress(
            str(self.project),
            vid,
            "reference_fetch",
            recipient,
            list(data),
            [scope or recipient + "/docs/cwe/"],
            "fetch Reference fixture pages",
            interaction=FakeInteraction(answers=[vid]),
        )
        assert out.ok, out.to_dict()
        return out

    def granted(self) -> str:
        vid = self.opened()
        self.grant(vid)
        return vid

    def state(self, vid: str) -> dict[str, Any]:
        return json.loads((self.project / GUARD_RUNS / vid / "state.json").read_text())

    def declarations(self, vid: str) -> list[dict[str, Any]]:
        return self.state(vid)["egress"]["declarations"]

    def conclude(self, vid: str) -> Any:
        return mod("guard.service").conclude(str(self.project), vid)

    # -- files --------------------------------------------------------------------------------
    def cache_files(self) -> dict[str, bytes | str]:
        return files(self.project / CACHE)

    def entry_files(self) -> list[Path]:
        folder = self.project / CACHE / "entries"
        return sorted(p for p in folder.iterdir() if p.suffix == ".json") if folder.is_dir() else []

    def registry_files(self) -> dict[str, bytes | str]:
        return files(self.project / REGISTRY)

    def knowledge_files(self) -> dict[str, bytes | str]:
        return files(self.project / "x-ipe-docs")

    def cli(self, *args: str) -> tuple[int, dict[str, Any], str]:
        """In-process `secure-code ...` (JSON and text) with this Env's trust root (never the host's)."""
        cli = mod("cli")
        trust_store = mod("auth.trust_store")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(trust_store, "default_app_dir", lambda: self.trust)
            result = cli.run(cli.build_parser().parse_args(list(args)))
        return (0 if result.ok else 1), json.loads(result.to_json()), result.to_text()


@pytest.fixture
def renv(project, tmp_path, server):
    return RefEnv(project, tmp_path, server)


def register_reference(env: Any, rule: str, *, origin: str = "http://127.0.0.1:8080") -> None:
    """Register a Reference source and rule for `rule` (used by the delivered conditional tag test)."""
    ns, ver, rid = rule.split("/")
    batch = env.req(
        {
            "schema": BATCH,
            "items": [
                source_item(f"{ns}/{ver}", port=int(origin.rsplit(":", 1)[1])),
                rule_item(rule, f"{origin}/{rid.lower()}.html", f"Reference rule {rid}"),
            ],
        }
    )
    result = mod("reference.registry_ops").register_batch(str(env.project), batch, trust_paths=env.paths)
    assert result.ok, result.to_dict()


# --------------------------------------------------------------------------- cache seeding (no network)
CAPACITY = 64 * 1024 * 1024
REQUIREMENT = (
    "Neutralize user-controllable input before it is placed in output that is served to other users."
)


def built_entry(
    env: Any, rule: str = CWE79, text: str = REQUIREMENT, *, record_over: dict | None = None
) -> tuple[dict[str, Any], int]:
    """A parsed rule result as `fetch` would build it (test-only; nothing is fetched), plus its start
    generation read the way the fetch flow reads it."""
    import hashlib

    cache, registry = mod("reference.cache"), mod("reference.registry")
    durable, clock_mod = mod("knowledge.durable"), mod("reference.clock")
    ref = mod("knowledge.identity").RuleRef.parse(rule)
    with durable.Tree(env.project) as tree:
        record, source = registry.view_at(tree).usable(ref)
        record = {**record, **(record_over or {})}
        generation = cache.current_generation(tree, cache.rule_key(record, source))
    entry = cache.build_entry(
        kind="rule",
        rule=record,
        explore_url=None,
        canonical_url=record["entry_url"],
        reg_digest=registry.registration_digest(record, source),
        fetched_at=clock_mod.utc_now(),
        http_status=200,
        content_type="text/html; charset=utf-8",
        response_digest="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
        text=text,
        masking={"applied": False, "kinds": []},
        links=[],
        links_truncated=False,
    )
    return entry, generation


def seed(env: Any, rule: str = CWE79, text: str = REQUIREMENT, *, capacity: int = CAPACITY) -> Any:
    entry, generation = built_entry(env, rule, text)
    return mod("reference.cache").publish(
        env.project,
        entry,
        start_generation=generation,
        fetch_digest=entry["registration_digest"],
        capacity=capacity,
    )


# --------------------------------------------------------------------------- tags and Presets
def tag_save(env: Any, name: str, members: list[str]) -> Any:
    path = env.req({"schema": "ai-secure-code-toolkit/tag-request/v1", "name": name, "members": members})
    return mod("knowledge.tags").save_tag(str(env.project), path, True, trust_paths=env.paths)


def preset_save(env: Any, name: str, rules: list[str]) -> Any:
    path = env.req({"schema": "ai-secure-code-toolkit/preset-request/v1", "name": name, "rules": rules})
    return mod("knowledge.presets").save_preset(str(env.project), path, True)
