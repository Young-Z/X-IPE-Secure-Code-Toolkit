"""FEATURE-001-E unit tests: bounded parser (AC-001E-05b…05e, 05g, 05h; review finding 2)."""

from __future__ import annotations

import importlib
import time

import pytest
from netguard import network_guards  # noqa: F401 - autouse guards
from refhelp import PAGES


def parse():
    return importlib.import_module("x_ipe_secure_code.reference.parse")


def extract(body, ctype="text/html; charset=utf-8", *, seconds=30.0, max_text=262144, links=False, **kw):
    return parse().extract(
        body if isinstance(body, bytes) else body.encode("utf-8"),
        ctype,
        deadline=time.monotonic() + seconds,
        max_text=max_text,
        title=kw.get("title", "Cross-site Scripting"),
        rule_id=kw.get("rule_id", "CWE-79"),
        base_url="http://127.0.0.1:8123/docs/cwe/79.html",
        want_links=links,
    )


def detail(body, ctype="text/html; charset=utf-8", **kw):
    with pytest.raises(parse().ParseError) as caught:
        extract(body, ctype, **kw)
    return caught.value.detail


def test_parser_version_and_defaults():
    ref = importlib.import_module("x_ipe_secure_code.reference")
    assert ref.PARSER_VERSION == "reference-parse/1"
    assert (ref.MAX_BYTES, ref.MAX_TEXT, ref.TIMEOUT, ref.MAX_FETCHES, ref.CACHE_CAPACITY) == (
        2 * 1024 * 1024,
        256 * 1024,
        30.0,
        20,
        64 * 1024 * 1024,
    )


def test_fixture_page_main_region_extracted():
    text = extract((PAGES / "cwe-79.html").read_bytes()).text
    assert "Neutralize user-controllable input before it is placed in output" in text
    assert "Site navigation" not in text and "Footer links" not in text


# AC-001E-05b
@pytest.mark.parametrize(
    "body",
    [
        "",
        "<html><body><nav><a href='/a'>Home</a></nav></body></html>",
        "<html><body><script>var x = 1;</script></body></html>",
        "<html><head><title>CWE-79</title></head>"
        "<body><h1>Cross-site Scripting</h1><p>CWE-79</p></body></html>",
    ],
)
def test_no_extractable_requirement_parse_failed(body):
    assert detail(body) == "parse_failed"


# AC-001E-05c
def test_hidden_elements_removed():
    text = extract((PAGES / "hidden.html").read_bytes()).text
    assert "Visible requirement text" in text
    for secret in (
        "SCRIPT-TEXT",
        "STYLE-TEXT",
        "TEMPLATE-TEXT",
        "NOSCRIPT-TEXT",
        "IFRAME-TEXT",
        "OBJECT-TEXT",
        "FORM-TEXT",
        "COMMENT-TEXT",
        "HIDDEN-ATTR-TEXT",
        "ARIA-HIDDEN-TEXT",
        "DISPLAY-NONE-TEXT",
        "VISIBILITY-HIDDEN-TEXT",
    ):
        assert secret not in text, secret
    assert "STYLESHEET-HIDDEN-TEXT" in text  # documented limit: stylesheet visibility not evaluated


# AC-001E-05d
def test_charset_decoding():
    latin1 = (PAGES / "latin1.html").read_bytes()
    assert "Ünicode-sichere Ausgabe" in extract(latin1, "text/html; charset=ISO-8859-1").text
    assert detail(latin1, "text/html; charset=x-unknown-label") == "decode_failed"
    assert detail(b"<p>\xff\xfe broken</p>", "text/html; charset=utf-8") == "decode_failed"
    assert detail(b"<p>aGVsbG8=</p>", "text/html; charset=base64") == "decode_failed"
    assert detail(b"<p>abc</p>", "text/html; charset=rot13") == "decode_failed"
    assert "requirement" in extract("\ufeffThe requirement applies.", "text/plain").text


def test_plain_and_markdown_kept_verbatim():
    md = extract("# A01\n\nEnforce <b>access</b> control on the server.\n", "text/markdown").text
    assert "Enforce <b>access</b> control on the server." in md
    assert extract("Validate   input\r\n\r\n\r\nalways.", "text/plain").text == "Validate input\n\nalways."


# AC-001E-05e
def test_extracted_text_limit():
    assert detail("<p>" + "a" * 2000 + "</p>", max_text=1000) == "size_limit"
    assert len(extract("<p>" + "a" * 900 + "</p>", max_text=1000).text) == 900


# AC-001E-05g
def test_digest_stability():
    p = parse()
    base = (PAGES / "cwe-79.html").read_text(encoding="utf-8")
    nav = (PAGES / "cwe-79-nav-changed.html").read_text(encoding="utf-8")
    req = (PAGES / "cwe-79-req-changed.html").read_text(encoding="utf-8")
    texts = [extract(t).text for t in (base, base, nav, req)]
    assert texts[0] == texts[1] == texts[2] and texts[3] != texts[0]
    assert p.normalize(texts[0]) == texts[0]


def test_normalization():
    p = parse()
    assert p.normalize("A\u0301 b\t\t c\u00a0d\r\n\r\n\r\n\r\nend  ") == "\u00c1 b c d\n\nend"


# AC-001E-05h
@pytest.mark.parametrize(
    "case",
    [
        "deep_nesting",
        "unterminated_tag",
        "huge_terminated_attribute",
        "huge_unterminated_attribute",
        "unterminated_comment",
        "unterminated_script",
    ],
)
def test_pathological_html_bounded(case):
    body = {
        "deep_nesting": "<div>" * 100000 + "x",
        "unterminated_tag": "<p>ok</p><a href='x' " + "b " * 200000,
        "huge_terminated_attribute": '<p title="' + "a" * 500000 + '">x</p>',
        "huge_unterminated_attribute": '<p title="' + "a" * 500000,
        "unterminated_comment": "<p>x</p><!-- " + "c" * 500000,
        "unterminated_script": "<p>x</p><script>" + "s" * 500000,
    }[case]
    start = time.monotonic()
    with pytest.raises(parse().ParseError) as caught:
        extract(body, seconds=2.0)
    assert caught.value.detail == "parse_failed"
    assert caught.value.cause in ("token_too_large", "unterminated_token", "nesting_too_deep")
    assert time.monotonic() - start <= 2.5


def test_deadline_reached_during_parse_is_timeout():
    with pytest.raises(parse().ParseError) as caught:
        extract("<p>" + "word " * 100000 + "</p>", seconds=0.0)
    assert caught.value.detail == "timeout"


# Review finding 2: every pre-scan bound ±1
@pytest.mark.parametrize(
    "make, bound",
    [
        (lambda n: "<p data-x='" + "a" * n + "'>req text here</p>", 4096),
        (lambda n: "<p " + "a" * (n - 4) + ">req text here</p>", 8192),
        (lambda n: "<p>req text here</p><!--" + "c" * n + "-->", 65536),
        (lambda n: "<p>req text here</p><!" + "d" * n + ">", 1024),
        (lambda n: "<p>req text here</p><script>" + "s" * n + "</script>", 1048576),
        (lambda n: "<title>" + "t" * n + "</title><p>req text here</p>", 65536),
    ],
)
def test_prescan_bounds_tokens(make, bound):
    p = parse()
    at = make(bound)
    over = make(bound + 4)
    p.prescan(at, time.monotonic() + 30)
    with pytest.raises(p.ParseError) as caught:
        p.prescan(over, time.monotonic() + 30)
    assert caught.value.cause == "token_too_large"


def test_prescan_escapes_stray_less_than_and_keeps_structure():
    p = parse()
    out = p.prescan("<p>a < b and 1<2</p><script>alert(1)</script>", time.monotonic() + 5)
    assert out == "<p>a &lt; b and 1&lt;2</p><script></script>"


def test_links_returned_raw_for_classification_only():
    found = extract((PAGES / "cwe-top25-list.html").read_bytes(), links=True)
    assert "/docs/cwe/79.html" in found.links and "#section" in found.links
    md = extract(
        "See [A01](https://owasp.example.test/a01) and <https://127.0.0.1:8/x>.", "text/markdown", links=True
    )
    assert md.links == ["https://owasp.example.test/a01", "https://127.0.0.1:8/x"]
