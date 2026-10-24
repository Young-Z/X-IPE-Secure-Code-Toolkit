"""FEATURE-001-E integration/unit tests: the P6 GET path of the toolkit egress gate and fetch-transport
behaviour (AC-001E-01i, 04b, 04d, 04f…04i, 04l…04n; DAO-020 TD DEC-01/02/03, review findings 1 and 5).

Everything runs against the raw-TCP fixture server on 127.0.0.1 under the resolver/socket guards."""

from __future__ import annotations

import hashlib
import json
import socket
import time
from datetime import timedelta
from pathlib import Path

import pytest
import refhelp
from conftest import SCRIPTS, FakeInteraction
from netguard import GUARD, network_guards  # noqa: F401 - autouse guards
from refhelp import (
    CWE79,
    closed_port,
    http_response,
    mod,
    page,
    rule_item,
    source_item,
)

clock, renv, server = refhelp.clock, refhelp.renv, refhelp.server  # pytest fixtures

DELIVERED_EGRESS = "836f8b36a35b6418b354a467b1d53c96dfd288606b3bb4a9400d64afbc2ee7bc"
START = "    # --- P6 GET path (FEATURE-001-E, additive) ---"
END = "    # --- end P6 GET path ---"
EGRESS = SCRIPTS / "src" / "x_ipe_secure_code" / "guard" / "egress.py"
BODY = (Path(__file__).parent / "fixtures" / "pages" / "cwe-79.html").read_bytes()


def gate(env, vid, opener=None):
    return mod("guard.egress").EgressGate(str(env.project), vid, _opener=opener)


def items(url, category="public_query"):
    return [{"category": category, "ref": url, "content": url}]


def detail(result):
    assert not result.ok, result.to_dict()
    return result.problems[0].code, result.data.get("detail")


def ready(env, response=None):
    env.standard(CWE79)
    env.serve("/docs/cwe/79.html", response if response is not None else page("cwe-79.html"))
    return env.granted()


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


# DEC-01 (DAO-020 TD): the only change to egress.py is the delimited additive block
def test_egress_block_removal_restores_delivered_hash():
    lines = EGRESS.read_text(encoding="utf-8").split("\n")
    assert lines.count(START) == 1 and lines.count(END) == 1
    a, b = lines.index(START), lines.index(END)
    assert a < b
    stripped = "\n".join(lines[:a] + lines[b + 1 :])
    assert hashlib.sha256(stripped.encode("utf-8")).hexdigest() == DELIVERED_EGRESS
    send = next(i for i, line in enumerate(lines) if line.startswith("    def send("))
    assert send < a


# AC-001E-04m
def test_egress_post_region_unchanged():
    text = EGRESS.read_text(encoding="utf-8")
    before, rest = text.split(START, 1)
    _, after = rest.split(END, 1)
    assert "def send(" in before and "response.read(65536)" in before and 'method="POST"' in before
    assert "def get(" in rest and "def get(" not in before + after


# DEC-01 parity (DAO-020 TD)
def test_get_post_consume_parity(renv, monkeypatch):
    vid = ready(renv)
    opener = FakeOpener()
    g = gate(renv, vid, opener)
    get_url, post_url = renv.url("/docs/cwe/79.html"), renv.url("/docs/cwe/post")
    get_auth = g.authorize("reference_fetch", get_url, items(get_url))
    post_auth = g.authorize("reference_fetch", post_url, items(post_url))
    assert g.get(get_auth, limit=1 << 20, deadline=time.monotonic() + 10)["status"] == 200
    assert g.send(post_auth)["status"] == 200
    decl = {d["id"]: d for d in renv.declarations(vid)}
    one, two = decl[get_auth.id], decl[post_auth.id]
    assert set(one) == set(two) and one["used"] is two["used"] is True and one["by"] == two["by"] == "toolkit"
    GuardError = mod("guard.model").GuardError

    def code(call):
        with pytest.raises(GuardError) as caught:
            call()
        return caught.value.code

    deadline = time.monotonic() + 10
    assert code(lambda: g.get(get_auth, limit=100, deadline=deadline)) == "EGRESS_REUSED"
    assert code(lambda: g.send(post_auth)) == "EGRESS_REUSED"
    fresh_get = g.authorize("reference_fetch", get_url, items(get_url))
    fresh_post = g.authorize("reference_fetch", post_url, items(post_url))
    other = renv.url("/docs/cwe/89.html")
    assert (
        code(lambda: g.get(fresh_get._replace(url=other), limit=100, deadline=deadline))
        == code(lambda: g.send(fresh_post._replace(url=other)))
        == "EGRESS_NOT_AUTHORIZED"
    )
    with pytest.raises(GuardError):
        g.authorize("reference_fetch", "http://127.0.0.1:1/x", items("http://127.0.0.1:1/x"))
    shapes = [set(d) for d in renv.declarations(vid)]
    assert all(s == shapes[0] for s in shapes)
    assert [d["decision"] for d in renv.declarations(vid)][-1] == "refused"
    model = mod("guard.model")
    later = (model.parse_time(renv.state(vid)["opened_at"]) + timedelta(hours=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    monkeypatch.setattr(model, "utc_now", lambda: later)
    assert (
        code(lambda: g.get(fresh_get, limit=100, deadline=deadline))
        == code(lambda: g.send(fresh_post))
        == "BUDGET_TIME_EXHAUSTED"
    )
    monkeypatch.undo()
    for finish in ("cancel", "conclude"):
        run = renv.granted()
        g2 = gate(renv, run, FakeOpener())
        a = g2.authorize("reference_fetch", get_url, items(get_url))
        b = g2.authorize("reference_fetch", post_url, items(post_url))
        if finish == "cancel":
            assert mod("guard.cancel").cancel(str(renv.project), run, "stop").ok
        else:
            assert renv.conclude(run).ok
        assert code(lambda: g2.get(a, limit=100, deadline=deadline)) == code(lambda: g2.send(b))  # noqa: B023
    assert renv.srv.count == 1 and len(opener.calls) == 1


# DEC-02 / review finding 1
@pytest.mark.parametrize("case", ["https", "trailing_dot", "localhost", "ipv6", "other_ip"])
def test_require_loopback_http_only(renv, case):
    renv.standard()
    vid = renv.opened()
    port = renv.srv.port
    url = {
        "https": f"https://127.0.0.1:{port}/docs/cwe/x",
        "trailing_dot": f"http://127.0.0.1.:{port}/docs/cwe/x",
        "localhost": f"http://localhost:{port}/docs/cwe/x",
        "ipv6": f"http://[::1]:{port}/docs/cwe/x",
        "other_ip": f"http://127.0.0.2:{port}/docs/cwe/x",
    }[case]
    origin = url.split("/docs", 1)[0]
    renv.grant(vid, recipient=origin, scope=origin + "/docs/cwe/")
    g = gate(renv, vid)
    auth = g.authorize("reference_fetch", url, items(url))
    with pytest.raises(mod("guard.model").GuardError) as caught:
        g.get(auth, limit=100, deadline=time.monotonic() + 10)
    assert caught.value.code == "EGRESS_INVALID"
    assert [d["used"] for d in renv.declarations(vid)] == [False]
    assert GUARD["connects"] == [] and renv.srv.count == 0


def test_get_refuses_other_purposes(renv):
    renv.standard()
    vid = renv.opened()
    url = renv.url("/docs/cwe/79.html")
    for purpose in ("tool_update", "target_requests"):
        out = mod("guard.egress").allow_egress(
            str(renv.project),
            vid,
            purpose,
            renv.srv.origin,
            ["public_query"],
            [renv.srv.origin + "/docs/cwe/"],
            "other purpose",
            interaction=FakeInteraction(answers=[vid]),
        )
        assert out.ok, out.to_dict()
        g = gate(renv, vid)
        auth = g.authorize(purpose, url, items(url))
        with pytest.raises(mod("guard.model").GuardError) as caught:
            g.get(auth, limit=100, deadline=time.monotonic() + 10)
        assert caught.value.code == "EGRESS_INVALID"
    assert (
        all(not d["used"] for d in renv.declarations(vid)) and renv.srv.count == 0 and GUARD["connects"] == []
    )


def test_get_keeps_gate_guarantees(renv):
    vid = ready(renv)
    g = gate(renv, vid)
    url = renv.url("/docs/cwe/79.html")
    auth = g.authorize("reference_fetch", url, items(url))
    assert mod("guard.control").pause(str(renv.project), vid, "wait").ok
    with pytest.raises(mod("guard.model").GuardError) as caught:
        g.get(auth, limit=100, deadline=time.monotonic() + 10)
    assert caught.value.code == "RUN_PAUSED"
    assert mod("guard.control").resume(str(renv.project), vid).ok
    assert g.get(auth, limit=1 << 20, deadline=time.monotonic() + 10)["status"] == 200
    assert renv.srv.count == 1


# AC-001E-01i
def test_redirect_not_followed_no_location(renv, clock):
    target = "/docs/cwe/79-moved.html"
    vid = ready(renv, http_response(b"", "302 Found", [("Location", renv.url(target))]))
    renv.serve(target, page("cwe-79.html"))
    result = renv.fetch(vid)
    assert detail(result) == ("FETCH_FAILED", "redirect_not_followed")
    dumped = json.dumps(result.to_dict()) + result.to_text()
    assert target not in dumped and "Location" not in dumped
    assert renv.srv.count == 1 and renv.entry_files() == []


# AC-001E-04b
def test_fetch_through_gate_get_single_use_bound(renv, clock):
    vid = ready(renv)
    result = renv.fetch(vid)
    assert result.ok and result.data["outcome"] == "fetched", result.to_dict()
    (decl,) = renv.declarations(vid)
    assert decl["purpose"] == "reference_fetch" and decl["used"] and decl["decision"] == "allowed"
    assert decl["recipient"] == renv.srv.origin and decl["path"] == "/docs/cwe/79.html"
    assert result.data["egress"] == {"declaration": decl["id"], "verification_id": vid}
    raw = renv.srv.requests[0]
    assert raw.startswith(b"GET /docs/cwe/79.html HTTP/1.0\r\n") and raw.endswith(b"\r\n\r\n")
    assert renv.conclude(vid).ok
    reports = renv.project / "x-ipe-docs/secure-code/reports/guard"
    markdown = (reports / f"{vid}.md").read_text()
    assert "## Outbound Calls (Egress)" in markdown and renv.srv.origin.split("//", 1)[1] in markdown
    egress = json.loads((reports / f"{vid}.json").read_text())["egress"]
    assert [g["purpose"] for g in egress["grants"]] == ["reference_fetch"]
    assert [(d["purpose"], d["used"]) for d in egress["declarations"]] == [("reference_fetch", True)]


# AC-001E-04d
def test_request_carries_only_url_and_fixed_headers(renv, clock):
    vid = ready(renv)
    assert renv.fetch(vid).ok
    raw = renv.srv.requests[0].decode("latin-1")
    lines = raw.split("\r\n")
    assert lines[:6] == [
        "GET /docs/cwe/79.html HTTP/1.0",
        f"Host: 127.0.0.1:{renv.srv.port}",
        "User-Agent: ai-secure-code-toolkit/0.1.0",
        "Accept: text/html, text/plain, text/markdown",
        "Accept-Encoding: identity",
        "Connection: close",
    ]
    assert lines[6:] == ["", ""]
    assert str(renv.project) not in raw and "my project" not in raw
    assert renv.declarations(vid)[0]["data"] == ["public_query"]


def slow(head: bytes, body: bytes, *, head_delay=0.0, drip=0.0, body_delay=0.0):
    def handler(conn, _request):
        time.sleep(head_delay)
        conn.sendall(head)
        time.sleep(body_delay)
        for i in range(len(body)):
            conn.sendall(body[i : i + 1])
            time.sleep(drip)

    return handler


# AC-001E-04f
@pytest.mark.parametrize("case", ["declared", "absent", "false_smaller"])
def test_size_limit_declared_and_streamed(renv, clock, case):
    body = BODY + b"<p>" + b"x" * 5000 + b"</p>"
    head = {
        "declared": f"Content-Length: {len(body)}\r\n",
        "absent": "",
        "false_smaller": "Content-Length: 100\r\n",
    }[case]
    response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{head}\r\n".encode("latin-1")
    vid = ready(renv, slow(response, body, body_delay=3 if case == "declared" else 0))
    started = time.monotonic()
    result = renv.fetch(vid, max_bytes=1000, timeout=10)
    assert detail(result) == ("FETCH_FAILED", "size_limit")
    if case == "declared":
        assert time.monotonic() - started < 2.5  # refused from the header, before any body byte
    assert renv.entry_files() == [] and "requirement" not in json.dumps(result.data.get("reference", {}))


# AC-001E-04g
@pytest.mark.parametrize("case", ["accept_delay", "header_delay", "slow_drip"])
def test_absolute_deadline(renv, clock, case):
    head = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(BODY)}\r\n\r\n".encode()
    handler = {
        "accept_delay": slow(head, BODY, head_delay=6),  # nothing at all for 6 s after the connection
        "header_delay": slow(head[:20], b"", body_delay=6),  # part of the status line, then silence
        "slow_drip": slow(head, BODY, drip=1.0),  # one body byte per second
    }[case]
    vid = ready(renv, handler)
    started = time.monotonic()
    result = renv.fetch(vid, timeout=2)
    elapsed = time.monotonic() - started
    assert detail(result) == ("FETCH_FAILED", "timeout") and elapsed < 3.0, elapsed
    assert renv.entry_files() == []


def test_deadline_covers_connect_phase(monkeypatch):
    egress = mod("guard.egress")
    started = time.monotonic()
    with pytest.raises(mod("guard.model").GuardError) as caught:
        egress.EgressGate.get_request("http://127.0.0.1:9/x", limit=10, deadline=time.monotonic() - 0.1)
    assert caught.value.data["detail"] == "timeout" and GUARD["connects"] == []

    def blocked(self, address, *args):
        time.sleep(0.6)
        raise TimeoutError("connect timed out")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    with pytest.raises(mod("guard.model").GuardError) as caught:
        egress.EgressGate.get_request("http://127.0.0.1:9/x", limit=10, deadline=time.monotonic() + 0.5)
    assert caught.value.data["detail"] == "timeout" and time.monotonic() - started < 2


# AC-001E-04h
@pytest.mark.parametrize(
    "ctype, ok",
    [
        ("text/html; charset=utf-8", True),
        ("text/plain", True),
        ("text/markdown; charset=UTF-8", True),
        ("TEXT/HTML", True),
        ("application/pdf", False),
        ("application/octet-stream", False),
        (None, False),
    ],
)
def test_content_type_allowlist(renv, clock, ctype, ok):
    vid = ready(renv, http_response(BODY, content_type=ctype))
    result = renv.fetch(vid)
    if ok:
        assert result.ok and result.data["outcome"] == "fetched", result.to_dict()
    else:
        assert detail(result) == ("FETCH_FAILED", "content_type_not_allowed")
        assert renv.entry_files() == []


# AC-001E-04i
@pytest.mark.parametrize("case", ["404", "429", "500", "closed"])
def test_http_status_and_closed_port(project, tmp_path, server, clock, case):
    from refhelp import RefEnv

    env = RefEnv(project, tmp_path, server)
    if case == "closed":
        port = closed_port()
        env.register(
            source_item(port=port, path_prefix="/docs/cwe/"),
            rule_item(CWE79, f"http://127.0.0.1:{port}/docs/cwe/79.html"),
        )
        vid = env.opened()
        env.grant(vid, recipient=f"http://127.0.0.1:{port}", scope=f"http://127.0.0.1:{port}/docs/cwe/")
        assert detail(env.fetch(vid)) == ("FETCH_FAILED", "connection_failed")
        assert GUARD["connects"] == [("127.0.0.1", port)]
        return
    vid = ready(env, http_response(b"error", f"{case} Error"))
    result = env.fetch(vid)
    assert detail(result) == ("FETCH_FAILED", "http_status") and result.data["http_status"] == int(case)
    assert env.srv.count == 1 and env.entry_files() == []


# AC-001E-04l
@pytest.mark.parametrize("encoding", ["gzip", "br"])
def test_content_encoding_identity_only(renv, clock, encoding):
    vid = ready(renv, http_response(BODY, headers=[("Content-Encoding", encoding)]))
    assert detail(renv.fetch(vid)) == ("FETCH_FAILED", "content_encoding_not_allowed")
    assert renv.entry_files() == []


# AC-001E-04n
@pytest.mark.parametrize("case", ["ok", "error", "timeout"])
def test_get_response_allowlisted_headers_closed(renv, case):
    extra = [("Set-Cookie", "session=abc"), ("Location", "http://127.0.0.1:1/x"), ("X-Other", "1")]
    response = {
        "ok": http_response(BODY, headers=extra),
        "error": http_response(BODY, content_type="text/html; " + "a" * 300),
        "timeout": slow(http_response(BODY)[:30], b"", head_delay=0, body_delay=5),
    }[case]
    vid = ready(renv, response)
    g = gate(renv, vid)
    url = renv.url("/docs/cwe/79.html")
    auth = g.authorize("reference_fetch", url, items(url))
    deadline = time.monotonic() + (1 if case == "timeout" else 10)
    if case == "ok":
        got = g.get(auth, limit=1 << 20, deadline=deadline)
        assert set(got) == {"status", "headers", "body", "truncated", "redirect_not_followed"}
        assert set(got["headers"]) == {"content-type", "content-length"}
    else:
        with pytest.raises(mod("guard.model").GuardError) as caught:
            g.get(auth, limit=1 << 20, deadline=deadline)
        assert caught.value.data["detail"] == ("header_invalid" if case == "error" else "timeout")
    deadline = time.monotonic() + 8
    while not renv.srv.closed and time.monotonic() < deadline:
        time.sleep(0.05)
    assert renv.srv.closed == [True]


GRAMMAR = {
    "transfer_encoding": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
    "dup_content_length_equal": b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5",
    "dup_content_length_conflict": b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6",
    "content_length_list": b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5",
    "obs_fold": b"HTTP/1.1 200 OK\r\nX-A: 1\r\n folded",
    "space_before_colon": b"HTTP/1.1 200 OK\r\nContent-Type : text/html",
    "colonless": b"HTTP/1.1 200 OK\r\nnot a header",
    "bare_lf": b"HTTP/1.1 200 OK\nContent-Type: text/html",
    "bare_cr": b"HTTP/1.1 200 OK\r\nX-A: 1\rX-B: 2",
    "ctl_in_discarded_header": b"HTTP/1.1 200 OK\r\nX-Discarded: a\x00b",
    "del_in_value": b"HTTP/1.1 200 OK\r\nContent-Type: text/html\x7f",
    "status_1xx": b"HTTP/1.1 100 Continue",
    "bad_version": b"HTTP/2.0 200 OK",
}


# review finding 5 (unit)
@pytest.mark.parametrize("case", sorted(GRAMMAR))
def test_parse_head_strict_grammar(case):
    with pytest.raises(mod("guard.model").GuardError) as caught:
        mod("guard.egress").EgressGate.parse_head(GRAMMAR[case])
    assert caught.value.code == "EGRESS_GET_FAILED" and caught.value.data["detail"] == "header_invalid"
    status, fields = mod("guard.egress").EgressGate.parse_head(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Other:  v \r\nContent-Length: 3"
    )
    assert status == 200 and fields == [
        ("content-type", "text/html"),
        ("x-other", "v"),
        ("content-length", "3"),
    ]


# review finding 5 (raw bytes from the fixture server)
@pytest.mark.parametrize("case", sorted(GRAMMAR))
def test_strict_head_grammar_raw(renv, clock, case):
    vid = ready(renv, GRAMMAR[case] + b"\r\n\r\n" + BODY)
    assert detail(renv.fetch(vid)) == ("FETCH_FAILED", "header_invalid")
    assert renv.entry_files() == []
    deadline = time.monotonic() + 8
    while not renv.srv.closed and time.monotonic() < deadline:
        time.sleep(0.05)
    assert renv.srv.closed == [True]


# DEC-03 (DAO-020 TD)
@pytest.mark.parametrize("length", [60, 140])
def test_content_length_mismatch_below_limit(renv, clock, length):
    body = (BODY * 3)[:length]
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n" + body
    vid = ready(renv, raw)
    assert detail(renv.fetch(vid)) == ("FETCH_FAILED", "header_invalid")
    assert renv.entry_files() == []
