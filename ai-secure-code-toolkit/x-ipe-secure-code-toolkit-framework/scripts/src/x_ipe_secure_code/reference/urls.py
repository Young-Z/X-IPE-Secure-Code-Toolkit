"""Pure target checks of Reference knowledge (FR-001E-3): domains, scheme, port, path prefix, IP literals,
the v1.0 transport decision and the (unreachable in v1.0) public-address validator.

Every URL check starts from the delivered FEATURE-002-C canonical-URL parser (`guard.egress._parse_url`),
whose refusals pass through unchanged. No function here resolves names or opens connections.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, NamedTuple
from urllib.parse import unquote, urljoin, urlsplit

from ..guard.mask import mask_text

LOOPBACK = "127.0.0.1"
DEFAULT_PORTS = {"http": 80, "https": 443}
NUMERIC_HOST = re.compile(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}")
BAD_DOMAIN_CHARS = set(":[]%/@\\") | {" ", "\t", "\r", "\n"}
MAX_LINK = 2048
P01 = "Real-domain fetching is parked (human item P-01); v1.0 fetches only from 127.0.0.1"
NO_TLS = "v1.0 has no TLS client; HTTPS is part of P-01"


class UrlRefusal(Exception):
    """A refused domain, URL or target: `reason` is a 001-E reason or a delivered 002-C code."""

    def __init__(self, reason: str, message: str, *, delivered: bool = False) -> None:
        super().__init__(message)
        self.reason, self.message, self.delivered = reason, message, delivered


class Target(NamedTuple):
    url: str  # canonical origin + raw (percent-encoded) path, as authorized and sent
    origin: str
    scheme: str
    host: str  # A-label host without a trailing dot (used for matching)
    port: int
    path: str  # decoded canonical path (used for prefix checks)
    raw_path: str


def _refuse(reason: str, message: str) -> UrlRefusal:
    return UrlRefusal(reason, message)


def _ip_like(text: str) -> bool:
    bare = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        pass
    return bool(NUMERIC_HOST.fullmatch(bare.lower().rstrip(".")))


def normalize_domain(text: Any) -> str:
    """Registered domain → lower-case IDNA A-label without trailing dot; only `127.0.0.1` as IP literal."""
    if not isinstance(text, str) or not text or len(text) > 253:
        raise _refuse("domain_invalid", f"{text!r} is not a domain name")
    if text == f"{LOOPBACK}.":
        raise _refuse(
            "ip_literal_not_allowed", "only the exact literal 127.0.0.1 is allowed (no trailing dot)"
        )
    if _ip_like(text):
        if text == LOOPBACK:
            return LOOPBACK
        raise _refuse("ip_literal_not_allowed", f"{text!r}: the only allowed IP literal is 127.0.0.1")
    if any(c in BAD_DOMAIN_CHARS for c in text):
        raise _refuse("domain_invalid", f"{text!r} contains a character not allowed in a domain name")
    name = text[:-1] if text.endswith(".") else text
    try:
        encoded = name.lower().encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise _refuse("domain_invalid", f"{text!r} cannot be IDNA-encoded") from None
    labels = encoded.split(".")
    if len(encoded) > 253 or any(not label or len(label) > 63 for label in labels):
        raise _refuse("domain_invalid", f"{text!r} has an empty or over-long label")
    if encoded == "localhost" or encoded.endswith(".localhost"):
        raise _refuse("localhost_not_allowed", f"{text!r}: localhost names are not allowed")
    if len(labels) == 1:
        raise _refuse("single_label_domain", f"{text!r} is a single-label name")
    return encoded


def check_scheme(scheme: Any, domains: list[str]) -> str:
    """`https`, or `http` only when every registered domain is exactly 127.0.0.1."""
    if scheme == "https":
        return scheme
    if scheme == "http" and domains and all(d == LOOPBACK for d in domains):
        return scheme
    raise _refuse("scheme_not_allowed", "scheme must be https, or http only for 127.0.0.1")


def check_port(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    if type(value) is not int or not 1 <= value <= 65535:
        raise _refuse("port_invalid", f"{value!r} is not a port number 1-65535")
    return value


def check_prefix(value: Any) -> str | None:
    """Optional path prefix: starts and ends with `/` and passes the delivered parser unchanged."""
    if value is None:
        return None
    from ..guard import egress
    from ..guard.model import GuardError

    ok = isinstance(value, str) and len(value) <= 1024 and value.startswith("/") and value.endswith("/")
    if ok:
        try:
            _, path, raw = egress._parse_url(f"http://{LOOPBACK}{value}")
            ok = raw == value and path == value and unquote(value) == value
        except (GuardError, ValueError):
            ok = False
    if not ok:
        raise _refuse("path_prefix_invalid", f"{value!r} must start and end with '/' (plain ASCII path)")
    return value


def _parse(url: Any) -> tuple[str, str, str, str, int | None]:
    """(origin, decoded path, raw path, host as encoded by the delivered parser, explicit port)."""
    from ..guard import egress
    from ..guard.model import GuardError

    try:
        origin, path, raw = egress._parse_url(url)
        parts = urlsplit(url)
        port = parts.port
    except GuardError as exc:
        raise UrlRefusal(exc.code, exc.message, delivered=True) from None
    except ValueError:
        raise _refuse("port_invalid", f"{url!r} has an invalid port") from None
    host = (parts.hostname or "").encode("idna").decode("ascii").lower()
    return origin, path, raw, host, port


def check_target(source: dict[str, Any], url: Any) -> Target:
    """Check a fetch target against a registered source (order fixed; first failure reported)."""
    origin, path, raw, host, port = _parse(url)
    scheme = origin.split("://", 1)[0]
    if scheme != source["scheme"]:
        raise _refuse("scheme_not_allowed", f"the source is registered for {source['scheme']} only")
    if host == f"{LOOPBACK}.":
        raise _refuse(
            "ip_literal_not_allowed", "only the exact literal 127.0.0.1 is allowed (no trailing dot)"
        )
    match = host[:-1] if host.endswith(".") else host
    domains = source["domains"]
    if _ip_like(match):
        if not (match == LOOPBACK and LOOPBACK in domains):
            raise _refuse("ip_literal_not_allowed", f"{match} is not the registered literal 127.0.0.1")
    elif not any(match == d or match.endswith("." + d) for d in domains if d != LOOPBACK):
        raise _refuse("unregistered_host", f"{match} is not within the registered domains")
    effective = port or DEFAULT_PORTS[scheme]
    if effective != (source.get("port") or DEFAULT_PORTS[scheme]):
        raise _refuse("port_not_registered", f"port {effective} is not the registered port")
    prefix = source.get("path_prefix")
    if prefix and not (path == prefix or path.startswith(prefix)):
        raise _refuse("path_not_registered", f"{path} is outside the registered path prefix {prefix}")
    return Target(origin + raw, origin, scheme, match, effective, path, raw)


def transport_v1(target: Target) -> UrlRefusal | None:
    """v1.0: only `http://127.0.0.1[:port]` is fetchable; decided before any resolver or socket call."""
    if target.host != LOOPBACK:
        return UrlRefusal("real_fetch_parked", P01)
    if target.scheme != "http":
        return UrlRefusal("scheme_not_allowed", NO_TLS)
    return None


def public_unicast(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reserved for P-01 (never called by the v1.0 fetch path): only public unicast addresses pass."""
    if not isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise TypeError("an injected ipaddress object is required (no name resolution)")
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(addr.is_global) and not (
        addr.is_multicast
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    )


def _secret_free(url: str) -> bool:
    return not mask_text(url)[1] and not mask_text(unquote(url))[1]


def classify_link(source: dict[str, Any], base_url: str, href: str | None) -> dict[str, Any]:
    """Explore link record: class plus the canonical URL, or `url: null` with the omission reason."""
    if href is None or len(href) > MAX_LINK:
        return {"class": "invalid_url_not_followed", "url": None, "url_omitted": "invalid"}
    joined = urljoin(base_url, href.strip()).split("#", 1)[0]
    try:
        target = check_target(source, joined)
        kind = "registered_candidate"
        url = target.url
    except UrlRefusal as exc:
        if exc.delivered or exc.reason == "port_invalid":
            return {"class": "invalid_url_not_followed", "url": None, "url_omitted": "invalid"}
        kind = "outside_registered_domains_not_followed"
        try:
            origin, _, raw, _, _ = _parse(joined)
            url = origin + raw
        except UrlRefusal:
            return {"class": "invalid_url_not_followed", "url": None, "url_omitted": "invalid"}
    if not _secret_free(url):
        return {"class": kind, "url": None, "url_omitted": "credential-like"}
    return {"class": kind, "url": url}
