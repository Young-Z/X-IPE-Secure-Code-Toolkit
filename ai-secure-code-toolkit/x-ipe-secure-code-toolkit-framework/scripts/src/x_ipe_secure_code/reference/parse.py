"""Bounded extraction of requirement text from fetched Reference content (FR-001E-8, `reference-parse/1`).

Content is never executed, rendered or sniffed and nothing is loaded. HTML passes a linear pre-scan that
bounds every token before the standard-library `HTMLParser` sees it; the parser keeps an explicit,
depth-limited element stack. The absolute fetch deadline also bounds parsing.
"""

from __future__ import annotations

import codecs
import re
import time
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser

MEDIA_TYPES = ("text/html", "text/plain", "text/markdown")
MAX_TAG, MAX_ATTR, MAX_COMMENT, MAX_DECL = 8192, 4096, 65536, 1024
MAX_RAWTEXT, MAX_RCDATA = 1024 * 1024, 65536
SLICE, MAX_DEPTH, MAX_LINKS, MAX_HREF = 65536, 1024, 500, 2048
CHARSET_LABEL = re.compile(r"[A-Za-z0-9._:-]{1,40}")
RAWTEXT = ("script", "style")
RCDATA = ("title", "textarea")
REMOVED = frozenset(
    {
        "script",
        "style",
        "template",
        "noscript",
        "iframe",
        "object",
        "form",
        "nav",
        "header",
        "footer",
        "aside",
        "head",
        "svg",
        "math",
        "title",
    }
)
VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)
BLOCK = frozenset(
    {
        "p",
        "div",
        "li",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "br",
        "tr",
        "section",
        "pre",
        "blockquote",
        "dd",
        "dt",
        "table",
        "ul",
        "ol",
        "main",
        "article",
        "hr",
    }
)
REGIONS = ("main", "article", "body")
_TAG_SPECIAL = re.compile(r"[\"'>=]")
_UNQUOTED = re.compile(r"[^\s\"'>]*")
_TAG_NAME = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9:-]*)")
_WS = re.compile(r"[ \t\f\v\u00a0]+")
_MD_LINKS = (re.compile(r"\]\(([^)\s]{1,2048})\)"), re.compile(r"<(https?://[^>\s]{1,2048})>"))


class ParseError(Exception):
    """`detail`: decode_failed | parse_failed | size_limit | timeout; `cause` names the bound hit."""

    def __init__(self, detail: str, cause: str | None = None) -> None:
        super().__init__(f"{detail}" + (f" ({cause})" if cause else ""))
        self.detail, self.cause = detail, cause


@dataclass
class Extracted:
    text: str
    links: list[str | None] = field(default_factory=list)
    page_title: str | None = None
    links_truncated: bool = False


def _check(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ParseError("timeout")


def media_type(content_type: str | None) -> tuple[str, dict[str, str]]:
    """(lower-case media type, parameters) from the allowlisted `Content-Type` header only."""
    if not content_type:
        return "", {}
    media, *rest = content_type.split(";")
    params = {}
    for part in rest:
        key, sep, value = part.partition("=")
        if sep:
            params[key.strip().lower()] = value.strip().strip('"').strip("'")
    return media.strip().lower(), params


def decode(body: bytes, label: str | None) -> str:
    label = label or "utf-8"
    if not CHARSET_LABEL.fullmatch(label):
        raise ParseError("decode_failed", "charset label")
    try:
        info = codecs.lookup(label)
    except LookupError:
        raise ParseError("decode_failed", "unknown charset") from None
    if not getattr(info, "_is_text_encoding", True):
        raise ParseError("decode_failed", "not a text encoding")
    try:
        text = body.decode(info.name, "strict")
    except (UnicodeDecodeError, LookupError):
        raise ParseError("decode_failed", "invalid bytes for the charset") from None
    return text[1:] if text.startswith("\ufeff") else text


def normalize(text: str) -> str:
    """NFC, LF line endings, whitespace runs collapsed per line, at most one empty line, trimmed."""
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    out: list[str] = []
    for line in text.split("\n"):
        line = _WS.sub(" ", line).strip()
        if line:
            out.append(line)
        elif out and out[-1] != "":
            out.append("")
    return "\n".join(out).strip()


# --------------------------------------------------------------------------- HTML pre-scan
def _bound(found: int, start: int, bound: int, length: int) -> int:
    if found < 0:
        raise ParseError(
            "parse_failed", "token_too_large" if length - start > bound else "unterminated_token"
        )
    return found


def _tag_end(text: str, i: int) -> int:
    """Index of the `>` closing the tag at `i` (outside quotes), within the tag and attribute bounds."""
    n, limit = len(text), i + MAX_TAG
    window = min(n, limit)
    k = i + 1
    while True:
        m = _TAG_SPECIAL.search(text, k, window)
        if m is None:
            raise ParseError("parse_failed", "token_too_large" if n >= limit else "unterminated_token")
        c, p = m.group(), m.start()
        if c == ">":
            return p
        if c in "\"'":
            close = text.find(c, p + 1, window)
            if close < 0:
                raise ParseError("parse_failed", "token_too_large" if n >= limit else "unterminated_token")
            if close - p - 1 > MAX_ATTR:
                raise ParseError("parse_failed", "token_too_large")
            k = close + 1
            continue
        q = p + 1
        while q < window and text[q] in " \t\r\n\f":
            q += 1
        if q < window and text[q] not in "\"'":
            value = _UNQUOTED.match(text, q, min(n, q + MAX_ATTR + 1))
            if value is not None and value.end() - q > MAX_ATTR:
                raise ParseError("parse_failed", "token_too_large")
            q = value.end() if value is not None else q
        k = q


def _content_end(text: str, start: int, name: str, bound: int) -> int:
    window = min(len(text), start + bound + len(name) + 4)
    m = re.compile(rf"</{name}(?=[\s/>])", re.I).search(text, start, window)
    return _bound(m.start() if m else -1, start, bound, len(text))


def prescan(text: str, deadline: float) -> str:
    """Linear single pass bounding every token; comments, declarations and script/style content dropped."""
    out: list[str] = []
    i, n, checked = 0, len(text), 0
    while i < n:
        if i - checked >= SLICE:
            _check(deadline)
            checked = i
        j = text.find("<", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        i = j
        if text.startswith("<!--", i):
            end = _bound(text.find("-->", i + 4, i + 4 + MAX_COMMENT + 3), i + 4, MAX_COMMENT, n)
            i = end + 3
            continue
        nxt = text[i + 1 : i + 2]
        if nxt in ("!", "?"):
            i = _bound(text.find(">", i + 2, i + 2 + MAX_DECL + 1), i + 2, MAX_DECL, n) + 1
            continue
        if not (nxt == "/" or (nxt.isascii() and nxt.isalpha())):
            out.append("&lt;")
            i += 1
            continue
        end = _tag_end(text, i)
        tag = text[i : end + 1]
        out.append(tag)
        i = end + 1
        name = _TAG_NAME.match(tag)
        if name is None or name.group(1) or tag.endswith("/>"):
            continue
        lowered = name.group(2).lower()
        if lowered in RAWTEXT:
            i = _content_end(text, i, lowered, MAX_RAWTEXT)
        elif lowered in RCDATA:
            close = _content_end(text, i, lowered, MAX_RCDATA)
            out.append(text[i:close].replace("<", "&lt;"))
            i = close
    _check(deadline)
    return "".join(out)


# --------------------------------------------------------------------------- HTML parse
class _Html(HTMLParser):
    def __init__(self, deadline: float, want_links: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.deadline, self.want_links, self.events = deadline, want_links, 0
        self.stack: list[tuple[str, bool]] = []
        self.state = dict.fromkeys(REGIONS, 0)
        self.depth = dict.fromkeys(REGIONS, 0)
        self.parts: dict[str, list[str]] = {r: [] for r in (*REGIONS, "all")}
        self.title: list[str] = []
        self.in_title = False
        self.title_seen = False
        self.links: list[str | None] = []
        self.links_truncated = False

    def _tick(self) -> None:
        self.events += 1
        if self.events % 1024 == 0:
            _check(self.deadline)

    def _removed(self) -> bool:
        return bool(self.stack) and self.stack[-1][1]

    def _emit(self, text: str) -> None:
        if self._removed():
            return
        self.parts["all"].append(text)
        for region in REGIONS:
            if self.state[region] == 1:
                self.parts[region].append(text)

    @staticmethod
    def _hidden(attrs: dict[str, str]) -> bool:
        if "hidden" in attrs or attrs.get("aria-hidden", "").strip().lower() == "true":
            return True
        style = re.sub(r"\s+", "", attrs.get("style", "").lower())
        return "display:none" in style or "visibility:hidden" in style

    def _link(self, tag: str, attrs: dict[str, str]) -> None:
        if tag != "a" or not self.want_links or self._removed() or "href" not in attrs:
            return
        if len(self.links) >= MAX_LINKS:
            self.links_truncated = True
            return
        href = attrs["href"]
        self.links.append(href if len(href) <= MAX_HREF else None)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tick()
        values = {k.lower(): v or "" for k, v in attrs}
        if tag == "title" and not self.title_seen:
            self.in_title = True
        if tag in VOID:
            if tag in BLOCK:
                self._emit("\n")
            return
        if len(self.stack) >= MAX_DEPTH:
            raise ParseError("parse_failed", "nesting_too_deep")
        removed = self._removed() or tag in REMOVED or self._hidden(values)
        self.stack.append((tag, removed))
        if tag in self.state and self.state[tag] == 0 and not removed:
            self.state[tag], self.depth[tag] = 1, len(self.stack)
        self._link(tag, values)
        if tag in BLOCK:
            self._emit("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tick()
        values = {k.lower(): v or "" for k, v in attrs}
        self._link(tag, values)
        if tag in BLOCK:
            self._emit("\n")

    def handle_endtag(self, tag: str) -> None:
        self._tick()
        if tag == "title" and self.in_title:
            self.in_title, self.title_seen = False, True
        index = next((k for k in range(len(self.stack) - 1, -1, -1) if self.stack[k][0] == tag), None)
        if index is None:
            return
        while len(self.stack) > index:
            if self.stack[-1][0] in BLOCK:
                self._emit("\n")
            for region in REGIONS:
                if self.state[region] == 1 and self.depth[region] == len(self.stack):
                    self.state[region] = 2
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        self._tick()
        if self.in_title:
            self.title.append(data)
            return
        self._emit(data)

    def text(self) -> str:
        for region in REGIONS:
            if self.state[region]:
                return "".join(self.parts[region])
        return "".join(self.parts["all"])


def _markdown_links(text: str) -> list[str | None]:
    found = sorted((m.start(), m.group(1)) for pattern in _MD_LINKS for m in pattern.finditer(text))
    return [href for _, href in found]


def extract(
    body: bytes,
    content_type: str,
    *,
    deadline: float,
    max_text: int,
    title: str | None,
    rule_id: str | None,
    base_url: str,
    want_links: bool,
) -> Extracted:
    """Extract normalized text (and raw link targets for classification only) from an allowed type."""
    media, params = media_type(content_type)
    if media not in MEDIA_TYPES:
        raise ParseError("parse_failed", "content type")
    text = decode(body, params.get("charset"))
    _check(deadline)
    links: list[str | None] = []
    page_title, truncated = None, False
    if media == "text/html":
        html = prescan(text, deadline)
        parser = _Html(deadline, want_links)
        for start in range(0, len(html), SLICE):
            _check(deadline)
            parser.feed(html[start : start + SLICE])
        parser.close()
        raw, links, truncated = parser.text(), parser.links, parser.links_truncated
        page_title = normalize("".join(parser.title)) or None
    else:
        raw = text
        if want_links and media == "text/markdown":
            found = _markdown_links(text)
            links, truncated = found[:MAX_LINKS], len(found) > MAX_LINKS
    _check(deadline)
    out = normalize(raw)
    if len(out.encode("utf-8")) > max_text:
        raise ParseError("size_limit")
    drop = {s.strip().lower() for s in (title, rule_id, page_title) if s}
    if not any(line and line.lower() not in drop for line in out.split("\n")):
        raise ParseError("parse_failed", "no_requirement_text")
    return Extracted(out, links, page_title, truncated)
