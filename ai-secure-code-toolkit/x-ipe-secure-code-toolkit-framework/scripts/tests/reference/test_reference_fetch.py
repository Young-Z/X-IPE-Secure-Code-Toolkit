"""FEATURE-001-E integration tests: fetching and exploring inside a Guard verification (AC-001E-01k, 01m,
03d…03g, 04a, 04c, 04e, 04j, 04k, 06a, 06c; DEC-17; review finding 3)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
import refhelp
from knowledge.exithelp import item
from netguard import GUARD, network_guards  # noqa: F401 - autouse guards
from refhelp import (
    CACHE,
    CWE79,
    CWE89,
    LOCAL,
    REGISTRY,
    http_response,
    mod,
    page,
    rule_item,
    source_item,
)

clock, renv, server = refhelp.clock, refhelp.renv, refhelp.server  # pytest fixtures

SECRET_HREFS = {
    "href_userinfo": '<a href="http://user:pw@127.0.0.1:{port}/docs/cwe/a.html">u</a>',
    "href_query_token": '<a href="/docs/cwe/a.html?access_token=abcdef0123456789">q</a>',
    "href_path_token": '<a href="/docs/cwe/sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX0123/x.html">p</a>',
    "markdown_link": "[k](http://127.0.0.1:{port}/docs/cwe/sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX0123.md)",
    "markdown_autolink": "<http://127.0.0.1:{port}/docs/cwe/x.md?password=hunter2hunter2>",
}


def fetched(env, vid, rule=CWE79, **kw):
    result = env.fetch(vid, rule, **kw)
    assert result.ok, result.to_dict()
    return result


def failed(result):
    assert not result.ok, result.to_dict()
    return result.problems[0].code, result.data.get("detail")


def ready(env, *rules, path="/docs/cwe/79.html", response=None):
    env.standard(*(rules or (CWE79,)))
    env.serve_standard()
    if response is not None:
        env.serve(path, response)
    return env.granted()


# AC-001E-03d
def test_refresh_of_expired_entry_fetches_new(renv, clock):
    vid = ready(renv)
    first = fetched(renv, vid)
    assert first.data["reference"]["retrieval_status"] == "fetched"
    clock.advance(days=8)
    assert renv.entry(CWE79)["reason"] == "cache_expired"
    again = fetched(renv, vid, refresh=True)
    assert again.data["reference"]["retrieval_status"] == "fetched"
    assert again.data["reference"]["source_evidence"]["fetched_at"] == "2026-11-01T01:00:00Z"
    assert again.data["reference"]["source_evidence"]["expires_at"] == "2026-11-08T01:00:00Z"
    assert renv.entry(CWE79)["retrieval_status"] == "cached" and renv.srv.count == 2


# AC-001E-03e
def test_refresh_reports_digest_change_kind(renv, clock):
    vid = ready(renv)
    fetched(renv, vid)
    renv.serve("/docs/cwe/79.html", page("cwe-79-nav-changed.html"))
    nav = fetched(renv, vid, refresh=True)
    assert nav.data["digest_changes"] == {
        "policy_state_digest_changed": False,
        "response_digest_changed": True,
    }
    renv.serve("/docs/cwe/79.html", page("cwe-79-req-changed.html"))
    req = fetched(renv, vid, refresh=True)
    assert req.data["digest_changes"] == {
        "policy_state_digest_changed": True,
        "response_digest_changed": True,
    }
    assert "strict allowlist" in renv.entry(CWE79)["requirement"]


# AC-001E-03f
@pytest.mark.parametrize("case", ["500", "timeout", "size", "type"])
def test_failed_refresh_unexpired_keeps_old(renv, clock, case):
    import time

    vid = ready(renv)
    fetched(renv, vid)
    path = renv.entry_files()[0]
    old = path.read_bytes()
    clock.advance(days=2)

    def stall(conn, _request):
        time.sleep(4)

    renv.serve(
        "/docs/cwe/79.html",
        {
            "500": http_response(b"boom", "500 Internal Server Error"),
            "timeout": stall,
            "size": page("cwe-79.html"),
            "type": http_response(b"%PDF", content_type="application/pdf"),
        }[case],
    )
    limits = {"timeout": 1} if case == "timeout" else {"max_bytes": 100} if case == "size" else {}
    result = renv.fetch(vid, refresh=True, **limits)
    code, why = failed(result)
    assert (
        code == "REFRESH_FAILED"
        and why
        == {
            "500": "http_status",
            "timeout": "timeout",
            "size": "size_limit",
            "type": "content_type_not_allowed",
        }[case]
    )
    assert (
        result.data["reference"]["reason"] == "refresh_failed"
        and "requirement" not in result.data["reference"]
    )
    assert result.data["unexpired_copy"]["fetched_at"] == "2026-10-24T01:00:00Z"
    assert result.data["unexpired_copy"]["expires_at"] == "2026-10-31T01:00:00Z"
    assert path.read_bytes() == old
    assert renv.entry(CWE79)["retrieval_status"] == "cached"


# AC-001E-03g
def test_failed_refresh_expired_never_cached_or_complete(renv, clock):
    vid = ready(renv)
    fetched(renv, vid)
    clock.advance(days=9)
    renv.serve("/docs/cwe/79.html", http_response(b"boom", "500 Internal Server Error"))
    result = renv.fetch(vid, refresh=True)
    assert failed(result) == ("REFRESH_FAILED", "http_status") and "unexpired_copy" not in result.data
    assert result.data.get("outcome") not in ("cached", "fetched")
    resolved = renv.resolve(LOCAL, CWE79)
    assert resolved.data["status"] != "complete"
    assert {e["requested"]: e.get("reason") for e in resolved.data["entries"]}[CWE79] == "cache_expired"


# AC-001E-04a
def test_fetch_without_grant_refused_recorded(renv, clock):
    renv.standard(CWE79)
    renv.serve_standard()
    vid = renv.opened()
    result = renv.fetch(vid)
    assert failed(result)[0] == "FETCH_NOT_AUTHORIZED"
    assert result.data["missing"] == "purpose" and result.data["recipient"] == renv.srv.origin
    assert "reference_fetch" in result.problems[0].message and renv.srv.origin in result.problems[0].message
    assert "guard allow-egress" in result.next_steps[0]
    (decl,) = renv.declarations(vid)
    assert (
        decl["decision"] == "refused"
        and decl["missing"] == "purpose"
        and decl["purpose"] == "reference_fetch"
    )
    assert renv.srv.count == 0 and GUARD["connects"] == []


# AC-001E-04c
@pytest.mark.parametrize("how", ["resolve", "scope_show", "guard_open", "copilot_open"])
def test_no_fetch_outside_verification(renv, clock, how):
    renv.standard(CWE79)
    renv.serve_standard()
    if how == "resolve":
        found = renv.entry(CWE79)
    else:
        scope_id = renv.save_scope(LOCAL)
        if how == "scope_show":
            mod("policy.service").show_scope(str(renv.project), scope_id)
        elif how == "guard_open":
            assert renv.open_guard(scope_id).ok
        else:
            copilot = mod("copilot.service")
            assert copilot.open_collaboration(str(renv.project), renv.open_request(scope_id, "copilot")).ok
        found = renv.entry(CWE79)
    assert found["reason"] == "not_cached"
    assert any("reference_fetch" in s for s in renv.resolve(CWE79).next_steps)
    assert renv.srv.count == 0 and GUARD["connects"] == []


# AC-001E-01m, AC-001E-04e
def test_real_domain_parked_production_path_guards(renv, clock):
    renv.register(
        source_item("CWE/2025", ["cwe.example.test"], scheme="https"),
        rule_item("CWE/2025/CWE-79", "https://cwe.example.test/docs/79.html"),
    )
    vid = renv.opened()
    renv.grant(vid, recipient="https://cwe.example.test", scope="https://cwe.example.test/docs/")
    before = renv.declarations(vid)
    result = renv.fetch(vid, "CWE/2025/CWE-79")
    assert failed(result)[0] == "REAL_FETCH_PARKED" and result.data["reason"] == "real_fetch_parked"
    assert "P-01" in result.problems[0].message and "P-01" in result.next_steps[0]
    assert GUARD["resolver"] == [] and GUARD["connects"] == [] and GUARD["refused_connects"] == []
    assert renv.declarations(vid) == before


def test_real_domain_parked_next_step(renv, clock):
    renv.register(
        source_item("OWASP/2025", ["owasp.example.test"], scheme="https"),
        rule_item("OWASP/2025/A01", "https://owasp.example.test/a01"),
    )
    result = renv.fetch(renv.granted(), "OWASP/2025/A01")
    assert result.problems[0].code == "REAL_FETCH_PARKED" and "human item P-01" in result.next_steps[0]


def test_https_loopback_scheme_not_allowed(renv, clock):
    port = renv.srv.port
    renv.register(
        source_item("CWE/tls", ["127.0.0.1"], scheme="https", port=port),
        rule_item("CWE/tls/CWE-79", f"https://127.0.0.1:{port}/docs/79.html"),
    )
    vid = renv.opened()
    renv.grant(vid, recipient=f"https://127.0.0.1:{port}", scope=f"https://127.0.0.1:{port}/docs/")
    result = renv.fetch(vid, "CWE/tls/CWE-79")
    assert failed(result) == ("FETCH_FAILED", "scheme_not_allowed")
    assert "P-01" in result.problems[0].message
    assert renv.declarations(vid) == [] and GUARD["connects"] == [] and renv.srv.count == 0


# AC-001E-04j
@pytest.mark.parametrize("case", ["concluded", "cancelled", "paused", "budget"])
def test_finished_or_exhausted_verification_refuses(renv, clock, monkeypatch, case):
    vid = ready(renv)
    p = str(renv.project)
    if case == "concluded":
        assert renv.conclude(vid).ok
    elif case == "cancelled":
        assert mod("guard.cancel").cancel(p, vid, "stop").ok
    elif case == "paused":
        assert mod("guard.control").pause(p, vid, "wait").ok
    else:
        model = mod("guard.model")
        later = model.parse_time(renv.state(vid)["opened_at"]) + timedelta(hours=5)
        monkeypatch.setattr(model, "utc_now", lambda: later.strftime("%Y-%m-%dT%H:%M:%SZ"))
    result = renv.fetch(vid)
    expected = {
        "concluded": ("RUN_FINISHED", "RUN_NOT_FOUND", "RUN_CLOSED"),
        "cancelled": ("RUN_CANCELLED", "RUN_FINISHED"),
        "paused": ("RUN_PAUSED",),
        "budget": ("BUDGET_TIME_EXHAUSTED",),
    }[case]
    assert result.problems[0].code in expected, result.to_dict()
    assert renv.srv.count == 0 and GUARD["connects"] == []


# AC-001E-04k
def test_fetch_cap_reached_cached_reads_work(renv, clock):
    rules = [f"CWE/2024-top25/CWE-{n}" for n in range(1, 4)]
    vid = ready(renv)
    renv.register(*[rule_item(r, renv.url(f"/docs/cwe/{r[-1]}.html"), f"Rule {r[-1]}") for r in rules])
    for r in rules:
        renv.serve(f"/docs/cwe/{r[-1]}.html", page("cwe-89.html"))
    for r in rules[:2]:
        fetched(renv, vid, r, max_fetches=2)
    refused = renv.fetch(vid, rules[2], max_fetches=2)
    assert failed(refused)[0] == "FETCH_CAP_REACHED" and "open a new verification" in refused.next_steps[0]
    assert renv.srv.count == 2
    cached = fetched(renv, vid, rules[0], max_fetches=2)
    assert cached.data["outcome"] == "cached" and renv.srv.count == 2
    assert renv.conclude(vid).ok
    assert fetched(renv, vid, rules[1]).data["outcome"] == "cached"
    assert renv.entry(rules[0])["retrieval_status"] == "cached"


def test_default_cap_is_twenty_and_limits_only_downward(renv, clock):
    service = mod("reference.service")
    assert service.check_limits() == {
        "max_bytes": 2 * 1024 * 1024,
        "max_text": 256 * 1024,
        "timeout": 30.0,
        "max_fetches": 20,
        "cache_capacity": 64 * 1024 * 1024,
    }
    vid = ready(renv)
    for over in (
        {"max_fetches": 21},
        {"max_bytes": 3 * 1024 * 1024},
        {"timeout": 31},
        {"timeout": 0},
        {"max_text": 0},
        {"cache_capacity": 1024},
    ):
        assert renv.fetch(vid, **over).problems[0].code == "LIMIT_INVALID", over
    assert renv.srv.count == 0


# AC-001E-06a
def test_prompt_injection_text_is_data(renv, clock):
    vid = ready(renv, CWE89, path="/docs/cwe/89.html", response=page("injection.html"))
    before = (renv.registry_files(), renv.knowledge_files())
    result = fetched(renv, vid, CWE89)
    reference = result.data["reference"]
    assert "Ignore previous instructions" in reference["requirement"]
    assert reference["content_label"] == "untrusted_external"
    dumped = json.dumps({k: v for k, v in result.data.items() if k != "reference"})
    assert "Ignore previous instructions" not in dumped
    assert renv.registry_files() == before[0]
    assert renv.srv.count == 1 and [r.split(b" ")[1] for r in renv.srv.requests] == [b"/docs/cwe/89.html"]
    assert len(renv.declarations(vid)) == 1


# AC-001E-06c
def test_credentials_masked_in_cache_and_output(renv, clock):
    vid = ready(renv, CWE89, path="/docs/cwe/89.html", response=page("credentials.html"))
    result = fetched(renv, vid, CWE89)
    assert result.data["reference"]["masking"]["applied"] is True
    secrets = ("MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq", "Sup3rSecretValue99")
    outputs = [json.dumps(result.to_dict()), result.to_text(), renv.entry_files()[0].read_text()]
    code, out, text = renv.cli(
        "knowledge", "reference", "show", "--project", str(renv.project), "--rule", CWE89
    )
    outputs += [json.dumps(out), text, json.dumps(renv.entry(CWE89))]
    assert renv.conclude(vid).ok
    outputs += [p.read_text() for p in (renv.project / "x-ipe-docs/secure-code/reports/guard").iterdir()]
    for blob in outputs:
        for secret in secrets:
            assert secret not in blob
    assert "[masked:credential.private_key]" in renv.entry(CWE89)["requirement"]


# review finding 3 / AC-001E-06c
@pytest.mark.parametrize("case", sorted(SECRET_HREFS))
def test_explore_link_secrets_never_retained(renv, clock, case):
    port = renv.srv.port
    markdown = case.startswith("markdown")
    body = SECRET_HREFS[case].format(port=port)
    content = (
        f"# Page\n\nRequirement text of the page.\n\n{body}\n"
        if markdown
        else f"<html><body><main><p>Requirement text of the page.</p>{body}</main></body></html>"
    )
    vid = ready(
        renv,
        path="/docs/cwe/page",
        response=http_response(content.encode(), content_type="text/markdown" if markdown else "text/html"),
    )
    result = renv.explore(vid, renv.url("/docs/cwe/page"))
    assert result.ok, result.to_dict()
    (link,) = result.data["links"]
    assert link["url"] is None and link["url_omitted"] in ("credential-like", "invalid")
    for blob in (json.dumps(result.to_dict()), result.to_text(), renv.entry_files()[0].read_text()):
        for secret in ("pw@", "abcdef0123456789", "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX0123", "hunter2hunter2"):
            assert secret not in blob


# AC-001E-01k
def test_explore_links_classified_not_followed(renv, clock):
    vid = ready(renv)
    result = renv.explore(vid, renv.url("/docs/cwe/top25.html"))
    assert result.ok, result.to_dict()
    assert (
        result.data["content_label"] == "untrusted_external" and "Candidate weaknesses" in result.data["text"]
    )
    links = result.data["links"]
    assert {"class": "registered_candidate", "url": renv.url("/docs/cwe/79.html")} in links
    assert {"class": "registered_candidate", "url": renv.url("/docs/cwe/89.html")} in links
    assert {"class": "registered_candidate", "url": renv.url("/docs/cwe/top25.html")} in links  # "#section"
    assert {
        "class": "outside_registered_domains_not_followed",
        "url": "https://other.example.test/cwe/22.html",
    } in links
    invalid = [x for x in links if x["class"] == "invalid_url_not_followed"]
    assert len(invalid) == 3 and all(x["url"] is None and x["url_omitted"] == "invalid" for x in invalid)
    assert renv.srv.count == 1
    again = renv.explore(vid, renv.url("/docs/cwe/top25.html"))
    assert again.data["outcome"] == "cached" and renv.srv.count == 1
    refused = renv.explore(vid, "http://127.0.0.1:1/other/x.html")
    assert failed(refused)[0] == "FETCH_FAILED"
    delivered = renv.explore(vid, renv.url("/docs/cwe/x.html?q=1"))
    assert delivered.problems[0].code == "EGRESS_URL_CREDENTIALS"


# DEC-17 (DAO-020 TD)
@pytest.mark.parametrize("case", ["local_used", "local_first_broken"])
def test_local_first_outcomes_use_no_network_or_budget(renv, clock, case):
    vid = ready(renv)
    assert renv.load(item(CWE79)).ok
    if case == "local_first_broken":
        renv.exit("deactivate", CWE79)
    state = renv.project / ".x-ipe/private/secure-code/guard" / vid / "state.json"
    before = state.read_bytes()
    result = renv.fetch(vid)
    if case == "local_used":
        assert result.ok and result.data["outcome"] == "local_used"
        assert result.data["reference"]["retrieval_status"] == "retrieved"
    else:
        assert (
            failed(result)[0] == "LOCAL_FIRST_BROKEN" and result.data["reference"]["reason"] == "deactivated"
        )
    assert state.read_bytes() == before and renv.srv.count == 0 and GUARD["connects"] == []


# AC-001E-09b part / B16
def test_fetch_without_run_refused(renv):
    renv.standard(CWE79)
    for run in (None, ""):
        result = renv.fetch(run)
        assert result.problems[0].code == "RUN_REQUIRED" and "B16" in result.next_steps[0]
    assert renv.srv.count == 0


def test_cli_fetch_and_explore(renv, clock):
    vid = ready(renv)
    code, out, text = renv.cli(
        "knowledge",
        "reference",
        "fetch",
        "--project",
        str(renv.project),
        "--run",
        vid,
        "--rule",
        CWE79,
        "--timeout",
        "5",
    )
    assert code == 0 and out["data"]["outcome"] == "fetched", out
    code, out, _ = renv.cli(
        "knowledge",
        "reference",
        "explore",
        "--project",
        str(renv.project),
        "--run",
        vid,
        "--source",
        "CWE/2024-top25",
        "--url",
        renv.url("/docs/cwe/top25.html"),
    )
    assert code == 0 and out["data"]["links"]
    code, out, _ = renv.cli("knowledge", "reference", "cache-clean", "--project", str(renv.project))
    assert code == 0 and out["data"]["removed"] == []
    assert (renv.project / CACHE).is_dir() and (renv.project / REGISTRY).is_dir()


# review fix 1 (DAO-007): masking can lengthen text; the limit is re-checked on the masked text
def test_masked_text_over_limit_is_size_limit(renv, clock):
    lines = "\n".join(f"Requirement line {i} uses key AKIA{i:016d} in examples." for i in range(40))
    limit = len(mod("reference.parse").normalize(lines).encode("utf-8"))
    vid = ready(renv, response=http_response(lines.encode(), content_type="text/plain"))
    result = renv.fetch(vid, max_text=limit)
    assert failed(result) == ("FETCH_FAILED", "size_limit")
    assert renv.entry_files() == [] and renv.entry(CWE79)["reason"] == "not_cached"


# review fix 1 (DAO-007): an entry larger than the 1 MiB read bound is never written or reported cached
def test_oversized_explore_entry_not_written(renv, clock):
    links = "".join(f'<a href="/docs/cwe/{i:03d}{"a" * 2000}.html">l</a>' for i in range(500))
    text = "Index of long pages with requirement text. " * 2000  # about 86 KB, below the text limit
    body = f"<html><body><main><p>{text}</p>{links}</main></body></html>".encode()
    vid = ready(renv, path="/docs/cwe/index", response=http_response(body))
    result = renv.explore(vid, renv.url("/docs/cwe/index"))
    assert result.ok, result.to_dict()
    assert result.data["cache"] == {
        "written": False,
        "note": "cache_not_written: entry_size",
        "generation": None,
    }
    assert len(result.data["links"]) == 500 and renv.entry_files() == []
    again = renv.explore(vid, renv.url("/docs/cwe/index"))
    assert again.data["outcome"] == "fetched" and renv.srv.count == 2
