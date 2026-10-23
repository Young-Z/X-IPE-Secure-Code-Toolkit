"""Advisory K-22 normative-language lint for drafted example comments (FEATURE-001-G, FR-001G-6).

Only comment text is linted (code tokens and string literals are not). Each comment line is NFKC
normalised, stripped of zero-width characters and case-folded; backtick code spans are excluded.
English terms match on word boundaries (longest first); Chinese terms are whole tokens of a
greedy lexicon segmentation (DEC-8). A comment line that quotes a current non-AI rule line
verbatim (`> ...`) is exempt. Warnings never refuse a draft: the Maintainer's attestation is the
binding K-22 control.
"""

from __future__ import annotations

import io
import re
import tokenize
import unicodedata
from typing import Any

EN_TERMS = (
    "must not",
    "must",
    "shall not",
    "shall",
    "is required to",
    "required",
    "mandatory",
    "should not",
    "should",
    "always",
    "never",
    "ensure",
    "only",
)
ZH_TERMS = frozenset({"必须", "应当", "应该", "禁止", "不得", "严禁", "务必"})
ZH_COMPOUNDS = frozenset(
    {"响应", "反应", "对应", "适应", "供应", "效应", "感应", "呼应", "答应", "照应", "应用", "理应"}
)
ZH_LEXICON = sorted(ZH_TERMS | ZH_COMPOUNDS, key=lambda t: (-len(t), t))
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"))
EN = re.compile(
    r"(?<![a-z0-9_])(?:"
    + "|".join(t.replace(" ", r"\s+") for t in sorted(EN_TERMS, key=lambda t: (-len(t), t)))
    + r")(?![a-z0-9_])"
)
CODE_SPAN = re.compile(r"```.*?```|`[^`]*`")
LIST_MARKER = re.compile(r"(?:[-*]|\d+\.)\s+")
BACKTICK_LANGS = frozenset({"javascript", "typescript", "go"})


def _collapse(text: str) -> str:
    return " ".join(text.split())


def quotable(rule_lines: list[str]) -> set[str]:
    """Whitespace-collapsed non-AI rule lines, also without a leading list marker."""
    result = set()
    for line in rule_lines:
        collapsed = _collapse(line)
        if collapsed:
            result.add(collapsed)
            result.add(LIST_MARKER.sub("", collapsed, count=1))
    return result


def _python_comments(text: str) -> list[tuple[int, str]]:
    try:
        return [
            (tok.start[0], tok.string[1:])
            for tok in tokenize.generate_tokens(io.StringIO(text).readline)
            if tok.type == tokenize.COMMENT
        ]
    except (tokenize.TokenError, SyntaxError, ValueError):
        return _hash_heuristic(text)


def _hash_heuristic(text: str) -> list[tuple[int, str]]:
    """Fallback when tokenizing fails: `#` outside single-line quotes."""
    found = []
    for number, line in enumerate(text.split("\n"), 1):
        quote = None
        for index, char in enumerate(line):
            if quote:
                if char == quote:
                    quote = None
            elif char in "'\"":
                quote = char
            elif char == "#":
                found.append((number, line[index + 1 :]))
                break
    return found


def _c_comments(text: str, lang: str) -> list[tuple[int, str]]:
    """`//` and `/* */` comments outside string literals (heuristic lexer)."""
    quotes = "\"'`" if lang in BACKTICK_LANGS else "\"'"
    found: list[tuple[int, str]] = []
    line, i, n = 1, 0, len(text)
    while i < n:
        char = text[i]
        if char in quotes:
            i += 1
            while i < n and text[i] != char:
                if text[i] == "\\" and char != "`":
                    i += 1
                elif text[i] == "\n":
                    if char != "`":
                        break
                    line += 1
                i += 1
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            found.append((line, text[i + 2 : end]))
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end
            for offset, part in enumerate(text[i + 2 : end].split("\n")):
                found.append((line + offset, part))
            line += text.count("\n", i, end)
            i = end + 2
        else:
            if char == "\n":
                line += 1
            i += 1
    return found


def comments(lang: str, text: str) -> list[tuple[int, str]]:
    return _python_comments(text) if lang == "python" else _c_comments(text, lang)


def normalise(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).casefold()
    return CODE_SPAN.sub(lambda m: " " * len(m.group(0)), folded)


def _zh_hits(text: str) -> list[tuple[int, str]]:
    hits, i = [], 0
    while i < len(text):
        term = next((t for t in ZH_LEXICON if text.startswith(t, i)), None)
        if term is None:
            i += 1
            continue
        if term in ZH_TERMS:
            hits.append((i, term))
        i += len(term)
    return hits


def lint(lang: str, part: str, text: str, rule_lines: list[str]) -> list[dict[str, Any]]:
    """Advisory `normative_language` warnings for one example part."""
    quotes = quotable(rule_lines)
    warnings = []
    for line, comment in comments(lang, text):
        stripped = comment.lstrip()
        if stripped.startswith(">") and stripped[1:2].isspace() and _collapse(stripped[1:]) in quotes:
            continue
        clean = normalise(comment)
        hits = [(m.start(), " ".join(m.group(0).split())) for m in EN.finditer(clean)] + _zh_hits(clean)
        warnings += [
            {"language": lang, "part": part, "line": line, "column": column + 1, "term": term}
            for column, term in hits
        ]
    return sorted(warnings, key=lambda w: (w["line"], w["column"]))
