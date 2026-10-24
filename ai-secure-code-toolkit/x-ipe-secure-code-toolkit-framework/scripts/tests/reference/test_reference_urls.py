"""FEATURE-001-E unit tests: domain/URL/path-prefix rules (AC-001E-01e…01h, 01j, 01n, 06d)."""

from __future__ import annotations

import importlib
import ipaddress

import pytest
from netguard import network_guards  # noqa: F401 - autouse guards

SOURCE = {"scheme": "https", "domains": ["example.test"], "port": None, "path_prefix": None}


def urls():
    return importlib.import_module("x_ipe_secure_code.reference.urls")


def reason(fn, *args):
    with pytest.raises(urls().UrlRefusal) as caught:
        fn(*args)
    return caught.value.reason


# AC-001E-01e
@pytest.mark.parametrize(
    "host, ok",
    [
        ("example.test", True),
        ("docs.example.test", True),
        ("a.b.example.test", True),
        ("badexample.test", False),
        ("example.test.evil.test", False),
        ("test", False),
    ],
)
def test_domain_label_boundary_match(host, ok):
    url = f"https://{host}/x.html"
    if ok:
        assert urls().check_target(SOURCE, url).host == host
    else:
        assert reason(urls().check_target, SOURCE, url) == "unregistered_host"


def test_registered_subdomain_never_authorizes_parent():
    source = {**SOURCE, "domains": ["docs.example.test"]}
    assert reason(urls().check_target, source, "https://example.test/") == "unregistered_host"
    assert urls().check_target(source, "https://a.docs.example.test/").host == "a.docs.example.test"


# AC-001E-01f
def test_domain_idna_normalization():
    u = urls()
    assert u.normalize_domain("BÜCHER.test.") == "xn--bcher-kva.test"
    assert u.normalize_domain("Docs.Example.TEST") == "docs.example.test"
    source = {**SOURCE, "domains": [u.normalize_domain("bücher.test")]}
    assert u.check_target(source, "https://BÜCHER.test/a").host == "xn--bcher-kva.test"
    for bad in ("a..b.test", "x" * 64 + ".test", "exa mple.test", "ex@mple.test", "ex/ample.test", ""):
        assert reason(u.normalize_domain, bad) == "domain_invalid", bad


# AC-001E-01g
@pytest.mark.parametrize(
    "text, expected",
    [
        ("intranet", "single_label_domain"),
        ("localhost", "localhost_not_allowed"),
        ("api.localhost", "localhost_not_allowed"),
        ("::1", "ip_literal_not_allowed"),
        ("[::1]", "ip_literal_not_allowed"),
        ("fe80::1%en0", "ip_literal_not_allowed"),
        ("10.0.0.1", "ip_literal_not_allowed"),
        ("192.168.1.1", "ip_literal_not_allowed"),
        ("8.8.8.8", "ip_literal_not_allowed"),
        ("127.1", "ip_literal_not_allowed"),
        ("0x7f.0.0.1", "ip_literal_not_allowed"),
        ("2130706433", "ip_literal_not_allowed"),
        ("127.000.000.001", "ip_literal_not_allowed"),
        ("127.0.0.1.", "ip_literal_not_allowed"),
    ],
)
def test_registration_refusals(text, expected):
    assert reason(urls().normalize_domain, text) == expected


def test_registration_field_refusals():
    u = urls()
    assert u.normalize_domain("127.0.0.1") == "127.0.0.1"
    assert reason(u.check_scheme, "http", ["example.test"]) == "scheme_not_allowed"
    assert reason(u.check_scheme, "ftp", ["127.0.0.1"]) == "scheme_not_allowed"
    assert u.check_scheme("http", ["127.0.0.1"]) == "http"
    assert u.check_scheme("https", ["127.0.0.1"]) == "https"
    for port in ("80a", "-1", 0, 65536, True, "+8"):
        assert reason(u.check_port, port) == "port_invalid", port
    assert u.check_port("8123") == 8123 and u.check_port(None) is None
    for bad in ("docs/cwe", "/docs/cwe", "docs/cwe/", "/docs/../x/", "/a%2Fb/", "/a\\b/", "/a b/"):
        assert reason(u.check_prefix, bad) == "path_prefix_invalid", bad
    assert u.check_prefix("/docs/cwe/") == "/docs/cwe/"
    for url in ("https://user:pw@example.test/x", "https://example.test/x?q=1", "https://example.test/x#f"):
        assert reason(u.check_target, SOURCE, url) == "EGRESS_URL_CREDENTIALS", url


# AC-001E-01h
def test_port_registration():
    u = urls()
    source = {**SOURCE, "port": 8443}
    assert u.check_target(source, "https://example.test:8443/a").port == 8443
    assert reason(u.check_target, source, "https://example.test:9443/a") == "port_not_registered"
    assert reason(u.check_target, source, "https://example.test/a") == "port_not_registered"
    assert u.check_target(SOURCE, "https://example.test:443/a").port == 443
    assert reason(u.check_target, SOURCE, "https://example.test:8443/a") == "port_not_registered"


# AC-001E-01j
def test_address_class_validator_injected():
    u = urls()
    cases = {
        "127.0.0.1": False,
        "10.1.2.3": False,
        "192.168.0.1": False,
        "172.16.0.1": False,
        "169.254.1.1": False,
        "224.0.0.1": False,
        "0.0.0.0": False,
        "::1": False,
        "fe80::1": False,
        "::ffff:127.0.0.1": False,
        "::ffff:10.0.0.1": False,
        "ff02::1": False,
        "::": False,
        "93.184.216.34": True,
        "2606:4700::1111": True,
        "::ffff:93.184.216.34": True,
    }
    for text, expected in cases.items():
        assert u.public_unicast(ipaddress.ip_address(text)) is expected, text
    with pytest.raises(TypeError):
        u.public_unicast("example.test")


# AC-001E-01n
@pytest.mark.parametrize(
    "path, ok",
    [
        ("/docs/cwe/", True),
        ("/docs/cwe/79.html", True),
        ("/docs/cwe/sub/a.html", True),
        ("/docs/cwe", False),
        ("/docs/cwe-evil/x.html", False),
        ("/docs/", False),
        ("/", False),
        ("/other/x.html", False),
    ],
)
def test_path_prefix_enforcement(path, ok):
    source = {**SOURCE, "path_prefix": "/docs/cwe/"}
    url = "https://example.test" + path
    if ok:
        assert urls().check_target(source, url).path == path
    else:
        assert reason(urls().check_target, source, url) == "path_not_registered"


@pytest.mark.parametrize(
    "path", ["/docs/cwe/a%2Fb", "/docs/cwe/a%5Cb", "/docs/cwe/%25", "/docs/cwe/a\\b", "/docs/cwe/../x"]
)
def test_path_prefix_delivered_url_rules_first(path):
    source = {**SOURCE, "path_prefix": "/docs/cwe/"}
    assert reason(urls().check_target, source, "https://example.test" + path) == "EGRESS_INVALID"


# AC-001E-06d
@pytest.mark.parametrize(
    "url, code",
    [
        ("https://u@example.test/a", "EGRESS_URL_CREDENTIALS"),
        ("https://example.test/a?x=1", "EGRESS_URL_CREDENTIALS"),
        ("https://example.test/a#frag", "EGRESS_URL_CREDENTIALS"),
        ("https://example.test/a%2Fb", "EGRESS_INVALID"),
        ("https://example.test/a/../b", "EGRESS_INVALID"),
        ("ftp://example.test/a", "EGRESS_INVALID"),
    ],
)
def test_url_canonical_refusals(url, code):
    with pytest.raises(urls().UrlRefusal) as caught:
        urls().check_target(SOURCE, url)
    assert caught.value.reason == code and caught.value.delivered


# Review finding 1: trailing dots
def test_trailing_dot_handling():
    u = urls()
    target = u.check_target(SOURCE, "https://example.test./a")
    assert target.host == "example.test"
    local = {"scheme": "http", "domains": ["127.0.0.1"], "port": 8123, "path_prefix": None}
    assert reason(u.check_target, local, "http://127.0.0.1.:8123/a") == "ip_literal_not_allowed"
    assert reason(u.normalize_domain, "127.0.0.1.") == "ip_literal_not_allowed"
    assert u.check_target(local, "http://127.0.0.1:8123/a").url == "http://127.0.0.1:8123/a"


# FR-001E-4 step 4 (review finding 1): v1.0 transport decision
def test_transport_v1_loopback_http_only():
    u = urls()
    parked = u.transport_v1(u.check_target(SOURCE, "https://example.test/a"))
    assert parked is not None and parked.reason == "real_fetch_parked" and "P-01" in parked.message
    local = {"scheme": "https", "domains": ["127.0.0.1"], "port": 8443, "path_prefix": None}
    https = u.transport_v1(u.check_target(local, "https://127.0.0.1:8443/a"))
    assert https is not None and https.reason == "scheme_not_allowed" and "TLS" in https.message
    plain = {**local, "scheme": "http"}
    assert u.transport_v1(u.check_target(plain, "http://127.0.0.1:8443/a")) is None


def test_ip_literal_targets_only_registered_loopback():
    u = urls()
    local = {"scheme": "http", "domains": ["127.0.0.1"], "port": None, "path_prefix": None}
    assert u.check_target(local, "http://127.0.0.1/a").host == "127.0.0.1"
    assert reason(u.check_target, local, "http://127.0.0.2/a") == "ip_literal_not_allowed"
    assert reason(u.check_target, SOURCE, "https://127.0.0.1/a") == "ip_literal_not_allowed"
