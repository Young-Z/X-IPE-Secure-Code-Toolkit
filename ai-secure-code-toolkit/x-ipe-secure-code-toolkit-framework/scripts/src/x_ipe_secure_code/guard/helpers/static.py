"""Static checks of a helper script (FR-002F-3, AC-002F-02d/02f; design §5.3).

Defence in depth only: the rules refuse every write path they can decide statically and the
acquisition of write-capable objects, but they never make a script safe; the container is the
boundary. The script is parsed, never imported or executed. Checks run in a fixed order and the
first violation is reported with its rule name and line.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from typing import Any

from ..mask import mask_text
from .model import L03_BYTES, L03_LINES, L04_DEPTH, L04_NODES

ALLOWED = (
    "json re pathlib fnmatch collections itertools functools dataclasses typing enum string textwrap math "
    "hashlib base64 csv configparser ast tokenize io unicodedata xml.etree.ElementTree"
).split()
ELEMENT_TREE = "xml.etree.ElementTree"
DENIED_NAMES = frozenset(
    "exec eval compile __import__ getattr setattr delattr globals locals vars breakpoint input help "
    "memoryview".split()
)
WRITE_ATTRS = frozenset(
    "write_text write_bytes unlink rename replace mkdir rmdir chmod lchmod chown touch symlink_to "
    "hardlink_to "
    "link_to writelines writerow writerows truncate FileIO open_code BufferedWriter BufferedRandom "
    "BufferedRWPair TextIOWrapper get_type_hints".split()
)
RESULTS_PATH = "/results/result.json"
READ_MODES = frozenset({"r", "rb", "rt", "br", "tr"})


@dataclass(frozen=True)
class Failure:
    step: str  # size | credential | parse | ast_limits | static
    rule: str | None
    line: int | None
    reason: str


class _Violation(Exception):
    def __init__(self, rule: str, node: ast.AST, detail: str) -> None:
        super().__init__(detail)
        self.rule, self.line, self.detail = rule, getattr(node, "lineno", 0), detail


def check(data: bytes, version: tuple[int, ...]) -> Failure | None:
    """All checks in order; None when the script passes (it is then only "checked")."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Failure("size", None, None, "script exceeds L-03: not valid UTF-8 text")
    if len(data) > L03_BYTES or len(text.splitlines()) > L03_LINES:
        return Failure("size", None, None, f"script exceeds L-03 ({L03_BYTES} bytes, {L03_LINES} lines)")
    if mask_text(text)[1]:
        return Failure("credential", None, None, "script contains credential-like text")
    tree = parse(text, version)
    if isinstance(tree, Failure):
        return tree
    limits = ast_limits(tree)
    if limits is not None:
        return Failure("ast_limits", None, None, limits)
    try:
        _Rules(tree, version).run()
    except _Violation as v:
        return Failure("static", v.rule, v.line, f"static: {v.rule}: {v.detail} (line {v.line})")
    return None


def parse(text: str, version: tuple[int, ...]) -> ast.Module | Failure:
    """Parse with the image interpreter's grammar; a newer grammar than the host's fails closed."""
    target = tuple(version[:2])
    reason = "parse: toolkit parser cannot parse (fail closed)"
    if target > sys.version_info[:2] or target < (3, 7):
        return Failure(
            "parse", None, None, f"{reason}: interpreter {target[0]}.{target[1]} not parseable here"
        )
    try:
        return ast.parse(text, feature_version=target)
    except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        line = getattr(exc, "lineno", None)
        return Failure("parse", None, line, f"{reason}: {exc.__class__.__name__} (line {line})")


def ast_limits(tree: ast.AST) -> str | None:
    """L-04 nesting depth and node count, computed iteratively before any rule."""
    nodes = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if depth > L04_DEPTH:
            return f"ast_limits: AST nesting deeper than L-04 ({L04_DEPTH})"
        if nodes > L04_NODES:
            return f"ast_limits: more than L-04 ({L04_NODES}) AST nodes"
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return None


def _allowed(name: str, version: tuple[int, ...]) -> bool:
    allowed = ALLOWED + (["tomllib"] if tuple(version[:2]) >= (3, 11) else [])
    return any(name == entry or (entry != ELEMENT_TREE and name.startswith(entry + ".")) for entry in allowed)


def _ordered(tree: ast.AST) -> list[ast.AST]:
    return sorted(
        (n for n in ast.walk(tree) if hasattr(n, "lineno")),
        key=lambda n: (n.lineno, n.col_offset, type(n).__name__),
    )


def _const_str(node: Any) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class _Rules:
    def __init__(self, tree: ast.Module, version: tuple[int, ...]) -> None:
        self.tree, self.version = tree, version
        self.nodes = _ordered(tree)
        self.parent: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
        self.handles: set[str] = set()
        self.result_withs: list[ast.withitem] = []

    def run(self) -> None:
        for rule in (
            self.imports,
            self.names,
            self.dunders,
            self.open_alias,
            self.open_form,
            self.results_handle,
            self.writes,
        ):
            rule()

    # ----------------------------------------------------------------- rules
    def imports(self) -> None:
        for node in self.nodes:
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    raise _Violation("import_relative", node, "relative import")
                if any(a.name == "*" for a in node.names):
                    raise _Violation("import_star", node, f"from {node.module} import *")
        for node in self.nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if not _allowed(alias.name, self.version):
                        raise _Violation("import_denied", node, alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "xml.etree" and all(a.name == "ElementTree" for a in node.names):
                    continue
                if not _allowed(module, self.version):
                    raise _Violation("import_denied", node, module)

    def names(self) -> None:
        for node in self.nodes:
            for name in self._identifiers(node, dunders=False):
                if name in DENIED_NAMES:
                    raise _Violation("name_denied", node, name)

    def dunders(self) -> None:
        for node in self.nodes:
            for name in self._identifiers(node, dunders=True):
                if len(name) > 4 and name.startswith("__") and name.endswith("__"):
                    raise _Violation("dunder", node, name)

    def open_alias(self) -> None:
        for node in self.nodes:
            if self._is_open_ref(node) and not self._is_callee(node):
                raise _Violation("open_alias", node, "open used other than as a direct call")

    def open_form(self) -> None:
        for node in self.nodes:
            if not (isinstance(node, ast.Call) and self._is_open_ref(node.func)):
                continue
            if any(isinstance(a, ast.Starred) for a in node.args) or any(
                k.arg is None for k in node.keywords
            ):
                raise _Violation("open_form", node, "open with *args or **kwargs")
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "io":
                    raise _Violation("open_form", node, "io.open")
                mode_node = node.args[0] if node.args else self._keyword(node, "mode")
            else:
                mode_node = node.args[1] if len(node.args) > 1 else self._keyword(node, "mode")
            mode = "r" if mode_node is None else _const_str(mode_node)
            if mode is None:
                raise _Violation("open_form", node, "open mode must be a string literal")
            if isinstance(node.func, ast.Attribute):
                if mode not in READ_MODES:
                    raise _Violation("open_form", node, f".open with mode {mode!r} (read modes only)")
                continue
            if not any(c in mode for c in "wax+"):
                continue
            item = self.parent.get(node)
            literal = _const_str(node.args[0]) if node.args else None
            if (
                literal != RESULTS_PATH
                or not isinstance(item, ast.withitem)
                or item.context_expr is not node
                or not isinstance(item.optional_vars, ast.Name)
            ):
                raise _Violation(
                    "open_form", node, f"write mode only as `with open({RESULTS_PATH!r}, …) as name`"
                )
            self.handles.add(item.optional_vars.id)
            self.result_withs.append(item)

    def writes(self) -> None:
        for node in self.nodes:
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr in WRITE_ATTRS:
                raise _Violation("write_attribute", node, node.attr)
            if node.attr == "write" and not (
                isinstance(node.value, ast.Name) and node.value.id in self.handles and self._is_callee(node)
            ):
                raise _Violation("write_attribute", node, "write other than on the results handle")

    def results_handle(self) -> None:
        if len(self.result_withs) > 1:
            raise _Violation(
                "results_handle", self.result_withs[1].context_expr, "more than one results file"
            )
        targets = {id(item.optional_vars) for item in self.result_withs}
        for node in self.nodes:
            if not (isinstance(node, ast.Name) and node.id in self.handles) or id(node) in targets:
                continue
            parent = self.parent.get(node)
            if isinstance(parent, ast.Attribute) and parent.attr == "write" and self._is_callee(parent):
                continue
            if (
                isinstance(parent, ast.Call)
                and len(parent.args) > 1
                and parent.args[1] is node
                and isinstance(parent.func, ast.Attribute)
                and parent.func.attr == "dump"
                and isinstance(parent.func.value, ast.Name)
                and parent.func.value.id == "json"
            ):
                continue
            raise _Violation(
                "results_handle", node, f"results handle {node.id} used other than write/json.dump"
            )

    # ----------------------------------------------------------------- helpers
    def _identifiers(self, node: ast.AST, *, dunders: bool) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            return [node.attr]
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return [n for a in node.names for n in (a.name.split(".")[-1], a.asname) if n]
        if not dunders:
            return []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return [node.name]
        if isinstance(node, ast.arg):
            return [node.arg]
        if isinstance(node, ast.keyword):
            return [node.arg] if node.arg else []
        if isinstance(node, ast.Call):
            return [k.arg for k in node.keywords if k.arg]
        return []

    def _is_open_ref(self, node: ast.AST) -> bool:
        return (isinstance(node, ast.Name) and node.id == "open") or (
            isinstance(node, ast.Attribute) and node.attr == "open"
        )

    def _is_callee(self, node: ast.AST) -> bool:
        parent = self.parent.get(node)
        return isinstance(parent, ast.Call) and parent.func is node

    @staticmethod
    def _keyword(call: ast.Call, name: str) -> ast.AST | None:
        return next((k.value for k in call.keywords if k.arg == name), None)
