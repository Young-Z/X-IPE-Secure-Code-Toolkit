"""Integration tests for FEATURE-002-C data egress (AC-002C-05a…05h)."""

from __future__ import annotations

import ast
import http.server
import json
import threading
from pathlib import Path

import pytest
from conftest import FakeInteraction, posix_only
from test_guard import (  # noqa: F401 - fixture reuse
    GUARD,
    REPORTS,
    TOKEN,
    env,
    opened,
    plan,
    req,
)
from test_guard_tool import check, fake, invocations, tc, tool  # noqa: F401
from test_guard_tool import planned as tool_planned

from x_ipe_secure_code import adapters
from x_ipe_secure_code.guard import cancel, control, egress, model
from x_ipe_secure_code.guard import service as guard

API = "https://api.example.com"
PEM = (
    "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq\n"
    "-----END PRIVATE KEY-----"
)


def state_of(env, vid):
    return json.loads((env["project"] / GUARD / vid / "state.json").read_text())


def grant(
    env,
    vid,
    purpose="submission",
    recipient=API,
    data=("findings",),
    scope=("src/login.py",),
    reason="send findings to the review service",
    answers=None,
    interactive=True,
):
    interaction = FakeInteraction(
        interactive=interactive, answers=list(answers if answers is not None else [vid])
    )
    return egress.allow_egress(
        str(env["project"]), vid, purpose, recipient, list(data), list(scope), reason, interaction=interaction
    )


def declare(env, vid, **over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-egress/v1",
        "purpose": "submission",
        "recipient": API,
        "data": ["findings"],
        "items": ["finding F1 summary"],
        "scope": ["src/login.py"],
    }
    doc.update(over)
    return egress.declare(str(env["project"]), vid, req(env, doc))


def planned(env):
    vid = opened(env)
    assert plan(env, vid).ok
    return vid


# ---------- AC-002C-05a / 05b
def test_05a_nothing_granted_by_default(env):
    vid = planned(env)
    assert state_of(env, vid)["egress"] == {"grants": [], "declarations": []}
    assert declare(env, vid).problems[0].code == "EGRESS_NOT_AUTHORIZED"


def test_05b_grant_by_user_at_terminal(env):
    vid = planned(env)
    out = grant(env, vid)
    assert out.ok, out.to_text()
    (g,) = state_of(env, vid)["egress"]["grants"]
    assert g["purpose"] == "submission" and g["recipient"] == API and g["data"] == ["findings"]
    assert g["role"] == "user" and g["at"]


@pytest.mark.parametrize(
    "over, code",
    [
        ({"interactive": False}, "INTERACTIVE_REQUIRED"),
        ({"answers": ["nope"]}, "CONFIRMATION_MISMATCH"),
        ({"recipient": "https://user:pw@api.example.com"}, "EGRESS_URL_CREDENTIALS"),
        ({"recipient": "https://api.example.com/?token=abc"}, "EGRESS_URL_CREDENTIALS"),
        ({"recipient": "ftp://api.example.com"}, "EGRESS_INVALID"),
        ({"data": ("credentials",)}, "EGRESS_PROHIBITED"),
        ({"data": ("model_credentials",)}, "EGRESS_PROHIBITED"),
        ({"data": ("signing_key",)}, "EGRESS_PROHIBITED"),
        ({"purpose": "target_requests", "data": ("findings",)}, "EGRESS_INVALID"),
        ({"purpose": "telemetry"}, "EGRESS_INVALID"),
        ({"scope": ("../outside.py",)}, "EGRESS_INVALID"),
    ],
)
def test_05b_grant_refusals_record_nothing(env, over, code):
    vid = planned(env)
    out = grant(env, vid, **over)
    assert out.problems[0].code == code, out.to_text()
    assert state_of(env, vid)["egress"]["grants"] == []


def test_05b_grant_allowed_while_paused_refused_when_cancelled(env):
    vid = planned(env)
    assert control.pause(str(env["project"]), vid, "asking the user for a grant").ok
    assert grant(env, vid).ok
    assert cancel.cancel(str(env["project"]), vid, "stop").ok
    assert grant(env, vid).problems[0].code == "RUN_CANCELLED"


def test_05b_grant_refused_when_time_exhausted(env, monkeypatch):
    vid = planned(env)
    opened_at = model.parse_time(state_of(env, vid)["opened_at"])
    later = opened_at.replace(hour=(opened_at.hour + 2) % 24) if opened_at.hour < 22 else opened_at
    from datetime import timedelta

    later = (opened_at + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(model, "utc_now", lambda: later)
    assert grant(env, vid).problems[0].code == "BUDGET_TIME_EXHAUSTED"


# ---------- AC-002C-05c / 05d / 05e
def test_05c_declaration_allowed_within_grant(env):
    vid = planned(env)
    grant(env, vid)
    out = declare(env, vid)
    assert out.ok and out.data["decision"] == "allowed" and out.data["declaration"] == "eg-1"
    (d,) = state_of(env, vid)["egress"]["declarations"]
    assert d["by"] == "agent" and d["decision"] == "allowed" and d["recipient"] == API


@pytest.mark.parametrize(
    "over, missing",
    [
        ({"purpose": "reference_fetch", "data": ["public_query"]}, "purpose"),
        ({"recipient": "https://other.example.com"}, "recipient"),
        ({"data": ["source_excerpts"]}, "data"),
        ({"scope": ["src/util.py"]}, "scope"),
    ],
)
def test_05c_declaration_refused_names_missing_element(env, over, missing):
    vid = planned(env)
    grant(env, vid)
    out = declare(env, vid, **over)
    assert not out.ok and out.problems[0].code == "EGRESS_NOT_AUTHORIZED"
    assert out.data["decision"] == "refused" and out.data["missing"] == missing
    assert state_of(env, vid)["egress"]["declarations"][-1]["decision"] == "refused"


def test_05d_network_purpose_never_authorizes_submission(env):
    vid = planned(env)
    assert grant(
        env,
        vid,
        purpose="target_requests",
        recipient="http://localhost:8080",
        data=("target_traffic",),
        scope=("http://localhost:8080/app",),
    ).ok
    out = declare(env, vid, recipient="http://localhost:8080", data=["findings"], scope=["src/login.py"])
    assert out.data["decision"] == "refused" and out.data["missing"] == "purpose"
    out = declare(
        env,
        vid,
        purpose="target_requests",
        recipient="http://localhost:8080",
        data=["source_excerpts"],
        scope=["http://localhost:8080/app/login"],
    )
    assert out.data["decision"] == "refused" and out.data["missing"] == "data"


def test_05e_every_stored_field_masked(env):
    vid = planned(env)
    assert grant(env, vid, reason=f"token {TOKEN}").ok
    declare(env, vid, items=[f"uses {TOKEN}", PEM])
    raw = (env["project"] / GUARD / vid / "state.json").read_text()
    assert TOKEN not in raw and "MIIBVgIBADAN" not in raw and "[masked:" in raw


def test_declaration_refused_while_paused(env):
    vid = planned(env)
    grant(env, vid)
    control.pause(str(env["project"]), vid, "wait")
    assert declare(env, vid).problems[0].code == "RUN_PAUSED"


# ---------- AC-002C-05f gate
class FakeOpener:
    def __init__(self):
        self.calls = []

    def open(self, request, timeout=None):
        self.calls.append((request.full_url, request.data))

        class Response:
            status = 200

            def read(self, n=-1):
                return b"ok"

        return Response()


def gate_for(env, vid, opener=None):
    return egress.EgressGate(str(env["project"]), vid, _opener=opener or FakeOpener())


def test_05f_gate_sends_bound_masked_payload_once(env):
    vid = planned(env)
    grant(env, vid, data=("findings", "metadata"), scope=("src/login.py", f"{API}/v1/review"))
    opener = FakeOpener()
    gate = gate_for(env, vid, opener)
    items = [{"category": "findings", "content": f"F1 high, key {TOKEN}", "ref": "src/login.py"}]
    auth = gate.authorize("submission", f"{API}/v1/review", items)
    out = gate.send(auth)
    assert out["status"] == 200 and len(opener.calls) == 1
    url, body = opener.calls[0]
    assert url == f"{API}/v1/review" and TOKEN not in body.decode() and "[masked:" in body.decode()
    with pytest.raises(model.GuardError) as exc:
        gate.send(auth)
    assert exc.value.code == "EGRESS_REUSED" and len(opener.calls) == 1
    d = state_of(env, vid)["egress"]["declarations"][-1]
    assert d["by"] == "toolkit" and d["used"] is True and d["digest"].startswith("sha256:")


@pytest.mark.parametrize(
    "url, item, code",
    [
        (
            f"{API}/v1/admin",
            {"category": "findings", "content": "x", "ref": "src/login.py"},
            "EGRESS_NOT_AUTHORIZED",
        ),
        (
            f"{API}/v1/review/%2e%2e/admin",
            {"category": "findings", "content": "x", "ref": "src/login.py"},
            "EGRESS_INVALID",
        ),
        (
            f"{API}/v1/review/../admin",
            {"category": "findings", "content": "x", "ref": "src/login.py"},
            "EGRESS_INVALID",
        ),
        (
            f"{API}/v1/review",
            {"category": "findings", "content": "x", "ref": "src/util.py"},
            "EGRESS_NOT_AUTHORIZED",
        ),
        (
            f"{API}/v1/review",
            {"category": "source_excerpts", "content": "x", "ref": "src/login.py"},
            "EGRESS_NOT_AUTHORIZED",
        ),
        (
            f"{API}/v1/review",
            {"category": "findings", "content": PEM, "ref": "src/login.py"},
            "EGRESS_PROHIBITED",
        ),
        (
            f"{API}/v1/review",
            {"category": "findings", "content": "sk-proj-" + "a" * 40, "ref": "src/login.py"},
            "EGRESS_PROHIBITED",
        ),
    ],
)
def test_05f_gate_refuses_unbound_calls_and_sends_nothing(env, url, item, code):
    vid = planned(env)
    grant(env, vid, data=("findings",), scope=("src/login.py", f"{API}/v1/review"))
    opener = FakeOpener()
    with pytest.raises(model.GuardError) as exc:
        gate_for(env, vid, opener).authorize("submission", url, [item])
    assert exc.value.code == code and opener.calls == []


def test_05f_gate_refuses_after_cancel_pause_or_concurrent_reuse(env):
    vid = planned(env)
    grant(env, vid, data=("findings",), scope=("src/login.py",))
    opener = FakeOpener()
    gate = gate_for(env, vid, opener)
    items = [{"category": "findings", "content": "F1", "ref": "src/login.py"}]
    auth = gate.authorize("submission", f"{API}/x", items)
    errors = []

    def use():
        try:
            gate.send(auth)
        except model.GuardError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=use) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(opener.calls) == 1 and errors == ["EGRESS_REUSED", "EGRESS_REUSED"]
    second = gate.authorize("submission", f"{API}/x", items)
    control.pause(str(env["project"]), vid, "wait")
    with pytest.raises(model.GuardError) as exc:
        gate.send(second)
    assert exc.value.code == "RUN_PAUSED"
    control.resume(str(env["project"]), vid)
    cancel.cancel(str(env["project"]), vid, "stop")
    with pytest.raises(model.GuardError) as exc:
        gate.send(second)
    assert exc.value.code == "RUN_CANCELLED" and len(opener.calls) == 1


class _Handler(http.server.BaseHTTPRequestHandler):
    hits: list = []

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        _Handler.hits.append(self.path)
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        return None


def test_05f_production_opener_ignores_proxies_and_never_follows_redirects(env, monkeypatch):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    try:
        vid = planned(env)
        grant(
            env, vid, purpose="target_requests", recipient=base, data=("target_traffic",), scope=(f"{base}/",)
        )
        gate = egress.EgressGate(str(env["project"]), vid)
        items = [{"category": "target_traffic", "content": "probe", "ref": f"{base}/ok"}]
        assert gate.send(gate.authorize("target_requests", f"{base}/ok", items))["status"] == 200
        out = gate.send(
            gate.authorize("target_requests", f"{base}/redirect", [{**items[0], "ref": f"{base}/redirect"}])
        )
        assert out["status"] == 302 and out["redirect_not_followed"] is True
        assert _Handler.hits == ["/ok", "/redirect"]
    finally:
        server.shutdown()


# ---------- AC-002C-05g / 05h
def test_05g_report_lists_grants_declarations_and_limits(env):
    vid = planned(env)
    grant(env, vid)
    declare(env, vid)
    declare(env, vid, data=["source_excerpts"])
    guard.conclude(str(env["project"]), vid)
    md = (env["project"] / REPORTS / f"{vid}.md").read_text()
    assert "## Outbound Calls (Egress)" in md and "api.example.com" in md
    assert "refused (missing data)" in md and "not OS-enforced" in md and "audit record" in md


def test_05h_adapter_network_check(env, monkeypatch):
    vid = planned(env)
    state = state_of(env, vid)
    assert egress.adapter_network_check(state, "opengrep", []) == egress.ExecutionMode("none", [])
    spec = adapters.AdapterSpec(
        "opengrep",
        network={
            "purpose": "tool_update",
            "recipient": "https://db.example.com",
            "data": ["metadata"],
            "offline_argv": ["--offline"],
        },
    )
    monkeypatch.setitem(adapters.ADAPTERS, "opengrep", spec)
    assert egress.adapter_network_check(state, "opengrep", []) == egress.ExecutionMode(
        "offline", ["--offline"]
    )
    no_offline = adapters.AdapterSpec("opengrep", network={**spec.network, "offline_argv": None})
    monkeypatch.setitem(adapters.ADAPTERS, "opengrep", no_offline)
    with pytest.raises(model.GuardError) as exc:
        egress.adapter_network_check(state, "opengrep", [])
    assert exc.value.code == "EGRESS_NOT_AUTHORIZED" and "tool_update" in exc.value.message
    assert grant(
        env,
        vid,
        purpose="tool_update",
        recipient="https://db.example.com",
        data=("metadata",),
        scope=("https://db.example.com/",),
    ).ok
    mode = egress.adapter_network_check(state_of(env, vid), "opengrep", [])
    assert mode.mode == "networked"


@posix_only
def test_05h_offline_argv_applied_to_the_tool(env, fake, monkeypatch):
    spec = adapters.AdapterSpec(
        "opengrep",
        network={
            "purpose": "tool_update",
            "recipient": "https://db.example.com",
            "data": ["metadata"],
            "offline_argv": ["--x-offline-mode"],
        },
    )
    monkeypatch.setitem(adapters.ADAPTERS, "opengrep", spec)
    vid = tool_planned(env, [check()])
    assert tool(env, vid, [tc()]).ok
    assert "--x-offline-mode" in invocations(fake)[0]["argv"]


def test_05f_no_network_client_outside_egress_module():
    src = Path(egress.__file__).parents[1]
    banned = {"socket", "http.client", "urllib.request", "requests", "ssl", "httpx", "urllib3"}
    for path in src.rglob("*.py"):
        if path.name == "egress.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            assert not (set(names) & banned), f"{path} imports {names}"


def test_cli_egress_declaration(env):
    from conftest import run_cli

    vid = planned(env)
    doc = {
        "schema": "ai-secure-code-toolkit/guard-egress/v1",
        "purpose": "submission",
        "recipient": API,
        "data": ["findings"],
        "items": ["x"],
        "scope": ["src/login.py"],
    }
    out = run_cli(
        [
            "guard",
            "egress",
            "--project",
            str(env["project"]),
            "--run",
            vid,
            "--request",
            req(env, doc),
            "--json",
        ],
        env["trust_dir"],
    )
    assert out.returncode == 1 and json.loads(out.stdout)["data"]["decision"] == "refused"


@posix_only
def test_05h_networked_tool_run_is_declared(env, fake, monkeypatch):
    spec = adapters.AdapterSpec(
        "opengrep",
        network={
            "purpose": "tool_update",
            "recipient": "https://db.example.com",
            "data": ["metadata"],
            "offline_argv": None,
        },
    )
    monkeypatch.setitem(adapters.ADAPTERS, "opengrep", spec)
    vid = tool_planned(env, [check()])
    assert grant(
        env,
        vid,
        purpose="tool_update",
        recipient="https://db.example.com",
        data=("metadata",),
        scope=("https://db.example.com/",),
    ).ok
    assert tool(env, vid, [tc()]).ok
    (d,) = state_of(env, vid)["egress"]["declarations"]
    assert d["by"] == "toolkit" and d["purpose"] == "tool_update" and d["decision"] == "allowed"


# ---------- code review fixes (TASK-037)
def test_05f_send_checks_the_payload_digest(env):
    vid = planned(env)
    grant(env, vid, data=("findings",), scope=("src/login.py",))
    opener = FakeOpener()
    gate = gate_for(env, vid, opener)
    auth = gate.authorize(
        "submission", f"{API}/x", [{"category": "findings", "content": "F1", "ref": "src/login.py"}]
    )
    with pytest.raises(model.GuardError) as exc:
        gate.send(auth._replace(payload=b"unmasked source"))
    assert exc.value.code == "EGRESS_NOT_AUTHORIZED" and opener.calls == []


def test_05f_encoded_urls_are_sent_as_given_and_unencoded_ones_refused(env):
    vid = planned(env)
    grant(env, vid, data=("findings",), scope=("src/login.py",))
    opener = FakeOpener()
    gate = gate_for(env, vid, opener)
    item = [{"category": "findings", "content": "F1", "ref": "src/login.py"}]
    gate.send(gate.authorize("submission", f"{API}/a%20b/caf%C3%A9", item))
    assert opener.calls[0][0] == f"{API}/a%20b/caf%C3%A9"
    for bad in (f"{API}/a b", f"{API}/café"):
        with pytest.raises(model.GuardError) as exc:
            gate.authorize("submission", bad, item)
        assert exc.value.code == "EGRESS_INVALID"


def test_05e_percent_encoded_credentials_are_refused(env):
    vid = planned(env)
    encoded = TOKEN.replace("_", "%5F")
    refused = grant(
        env,
        vid,
        purpose="target_requests",
        recipient="http://localhost:8080",
        data=("target_traffic",),
        scope=(f"http://localhost:8080/app/{encoded}",),
    )
    assert refused.problems[0].code == "EGRESS_URL_CREDENTIALS"
    grant(env, vid, data=("findings",), scope=("src/login.py",))
    with pytest.raises(model.GuardError) as exc:
        gate_for(env, vid).authorize(
            "submission",
            f"{API}/{encoded}",
            [{"category": "findings", "content": "x", "ref": "src/login.py"}],
        )
    assert exc.value.code == "EGRESS_URL_CREDENTIALS"
    assert TOKEN not in (env["project"] / GUARD / vid / "state.json").read_text()


def test_01b_egress_results_carry_the_budget(env):
    vid = planned(env)
    assert grant(env, vid).data["budget"]["total_seconds"] == 3600
    assert declare(env, vid).data["budget"]["remaining_seconds"] > 0
    assert declare(env, vid, data=["source_excerpts"]).data["budget"]
