"""Bounded inputs of `secure-code guard compare` (FEATURE-002-G, NFR-002G-5).

Depth, value count and decoded string length are enforced by a streaming pre-scan of the raw bytes
before the JSON is parsed. The pre-scan never judges syntax: malformed text is reported afterwards by
`json.loads`. An exceeded limit is a `TooLarge` refusal (the run is not declared invalid); every other
input problem is an `Invalid` refusal naming a rule and a JSON path, never a value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .mask import mask_text

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 64  # nesting of objects and arrays; the top-level object is depth 1
MAX_VALUES = 2_000_000  # every object, array and scalar (object keys are not values)
MAX_STRING_BYTES = 1024 * 1024  # decoded UTF-8 bytes per string value or key (= model.MAX_CONTENT)

LIMITS: dict[str, tuple[int | None, str]] = {
    "max_input_bytes": (MAX_INPUT_BYTES, "bound.bytes"),
    "max_depth": (MAX_DEPTH, "bound.depth"),
    "max_values": (MAX_VALUES, "bound.values"),
    "max_string_bytes": (MAX_STRING_BYTES, "bound.string"),
    "memory": (None, "bound.memory"),
}

_WS = re.compile(rb"[ \t\n\r]*")
_PLAIN = re.compile(rb'[^"\\]*')
_SCALAR = re.compile(rb'[^ \t\n\r{}\[\],:"]+')
_SCALAR_RUN = re.compile(rb'[^ \t\n\r{}\[\],:"]+(?:[ \t\n\r]*,[ \t\n\r]*[^ \t\n\r{}\[\],:"]+)*')
_HEX4 = re.compile(rb"[0-9A-Fa-f]{4}")
_NAME_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,59}")


class TooLarge(Exception):
    """A comparison limit is exceeded: the comparison is not possible (the run stays valid)."""

    def __init__(self, limit: str, byte_offset: int | None = None) -> None:
        value, rule = LIMITS[limit]
        super().__init__(f"{limit} exceeded")
        self.limit = limit
        self.limit_value = value
        self.rule = rule
        self.byte_offset = byte_offset


class Invalid(Exception):
    """A structured result violates a rule; `path` is a JSON path built from fixed names and indices."""

    def __init__(self, rule: str, path: str) -> None:
        super().__init__(f"{rule} at {path}")
        self.rule = rule
        self.path = path


@dataclass
class Stats:
    """One JSON text: values (containers and scalars, keys excluded), depth and longest decoded string."""

    values: int = 0
    depth: int = 0
    longest: int = 0


class _Scan:
    def __init__(self, raw: bytes, max_depth: int | None, max_values: int | None, max_string: int | None):
        self.raw, self.end = raw, len(raw)
        self.max_depth, self.max_values, self.max_string = max_depth, max_values, max_string
        self.stats = Stats()

    def count(self, n: int, offset: int) -> None:
        self.stats.values += n
        if self.max_values is not None and self.stats.values > self.max_values:
            raise TooLarge("max_values", offset)

    def bound(self, length: int, pos: int) -> None:
        if length > self.stats.longest:
            self.stats.longest = length
            if self.max_string is not None and length > self.max_string:
                raise TooLarge("max_string_bytes", pos)

    def string(self, pos: int) -> int:
        """Walk one string from just after its opening quote; return the position after it."""
        raw, end, length = self.raw, self.end, 0
        while True:
            stop = _PLAIN.match(raw, pos).end()
            length += stop - pos
            pos = stop
            self.bound(length, pos)
            if pos >= end:  # unterminated: syntax is left to json.loads
                return pos
            if raw[pos] == 0x22:
                return pos + 1
            if pos + 1 >= end:  # truncated escape
                return end
            hex4 = _HEX4.match(raw, pos + 2) if raw[pos + 1] == 0x75 else None
            if hex4 is None:  # \" \\ \/ \b \f \n \r \t (and invalid escapes) count one byte
                length += 1
                pos += 2
            else:
                code = int(hex4.group(), 16)
                pos += 6
                if 0xD800 <= code <= 0xDBFF:
                    low = _HEX4.match(raw, pos + 2) if raw[pos : pos + 2] == b"\\u" else None
                    if low is not None and 0xDC00 <= int(low.group(), 16) <= 0xDFFF:
                        length += 4
                        pos += 6
                    else:
                        length += 3  # lone high surrogate (later refused as json.encoding)
                else:
                    length += 1 if code < 0x80 else 2 if code < 0x800 else 3
            self.bound(length, pos)

    def scalars(self, pos: int) -> int:
        match = _SCALAR_RUN.match(self.raw, pos)
        n = match.group().count(b",") + 1
        if self.max_values is not None and self.stats.values + n > self.max_values:
            for token in _SCALAR.finditer(self.raw, pos, match.end()):
                self.count(1, token.start())
        self.count(n, pos)
        return match.end()

    def run(self) -> Stats:
        raw, end = self.raw, self.end
        stack: list[bool] = []  # True = object frame
        expect_key = False
        pos = 0
        while True:
            pos = _WS.match(raw, pos).end()
            if pos >= end:
                return self.stats
            char = raw[pos]
            if char in (0x7B, 0x5B):  # { [
                self.count(1, pos)
                stack.append(char == 0x7B)
                if len(stack) > self.stats.depth:
                    self.stats.depth = len(stack)
                    if self.max_depth is not None and self.stats.depth > self.max_depth:
                        raise TooLarge("max_depth", pos)
                expect_key = char == 0x7B
                pos += 1
            elif char in (0x7D, 0x5D):  # } ]
                if stack:
                    stack.pop()
                expect_key = False
                pos += 1
            elif char == 0x2C:  # ,
                expect_key = bool(stack) and stack[-1]
                pos += 1
            elif char == 0x3A:  # :
                expect_key = False
                pos += 1
            elif char == 0x22:  # "
                is_key = expect_key and bool(stack) and stack[-1]
                start = pos
                pos = self.string(pos + 1)
                if not is_key:
                    self.count(1, start)
                expect_key = False
            else:
                pos = self.scalars(pos)
                expect_key = False


def measure(
    raw: bytes, *, max_depth: int | None = None, max_values: int | None = None, max_string: int | None = None
) -> Stats:
    """Values, depth and longest decoded UTF-8 string length of a JSON text, stopping at a given limit."""
    return _Scan(raw, max_depth, max_values, max_string).run()


def prescan(raw: bytes) -> Stats:
    """Enforce depth, value count and decoded string length before `json.loads` (raises TooLarge)."""
    return measure(raw, max_depth=MAX_DEPTH, max_values=MAX_VALUES, max_string=MAX_STRING_BYTES)


def key_part(key: str, index: int) -> str:
    """Path part of a data-defined key: the key only when it is name-like and unmasked, else its position."""
    if _NAME_KEY.fullmatch(key) and not mask_text(key)[1]:
        return "{" + key + "}"
    return "{" + str(index) + "}"


def check_encodable(doc: Any) -> None:
    """Every string and key must be UTF-8 encodable (a lone surrogate is refused as `json.encoding`)."""
    stack: list[tuple[Any, Any]] = [(doc, None)]
    while stack:
        value, where = stack.pop()
        if isinstance(value, str):
            if not _encodable(value):
                raise Invalid("json.encoding", _path(where))
        elif isinstance(value, dict):
            children = []
            for index, key in enumerate(sorted(value)):
                node = (where, key, index)
                if not _encodable(key):
                    raise Invalid("json.encoding", _path(node))
                children.append((value[key], node))
            stack.extend(reversed(children))
        elif isinstance(value, list):
            stack.extend((item, (where, i, None)) for i, item in reversed(list(enumerate(value))))


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _path(node: Any) -> str:
    parts = []
    while node is not None:
        node, part, index = node
        if index is None:
            parts.append(f"[{part}]")
        elif _encodable(part) and _NAME_KEY.fullmatch(part) and not mask_text(part)[1]:
            parts.append(f".{part}")
        else:
            parts.append("{" + str(index) + "}")
    return "$" + "".join(reversed(parts))
