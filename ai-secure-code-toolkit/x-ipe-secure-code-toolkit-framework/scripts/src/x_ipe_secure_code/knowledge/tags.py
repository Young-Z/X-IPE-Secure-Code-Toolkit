"""`tag list/show/save/update/delete` (FEATURE-001-F).

Everyone may read tags and use them as clues. Create/update/delete are Maintainer-only through the
existing `require_maintainer` check — before the knowledge lock is requested and again under it —
for toolkit-mediated operations only (no filesystem-level isolation, 001-A / U-13). Tags are lookup
aids: they never change severity, mandatory marking or Preset membership.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..auth.service import require_maintainer
from ..auth.trust_store import TrustPaths
from ..policy import resolve
from ..projects import knowledge_root
from ..results import Result
from . import catalog, exit_journal, store
from .catalog import TAG, CatalogError

TAG_REQUEST = "ai-secure-code-toolkit/tag-request/v1"
KEYS = frozenset({"schema", "name", "members"})
ASK_STEP = "Ask a Maintainer to change tags; or save the rules as a Preset (secure-code preset save)"


def _member_rows(lib: resolve.Library, rels: list[str]) -> list[dict[str, Any]]:
    return [{k: v for k, v in row.items() if k != "state_digest"} for row in catalog.availability(lib, rels)]


def list_tags(project: str | None) -> Result:
    """All valid tags in name order plus invalid/ignored files; read-only, open to everyone."""
    command = "tag list"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    taken = catalog.in_session(command, root, lambda s: catalog.scan(s.tree, TAG))
    if isinstance(taken, Result):
        return taken
    found, recovered = taken
    data = {
        "tags": [
            {"name": e.name, "member_count": len(e.rels), "file_digest": e.digest} for e in found.entries
        ],
        "invalid": catalog.listed_invalid(found),
        "ignored": found.ignored,
        "note": catalog.TAG_NOTE,
    }
    return exit_journal.with_recovered(Result(command, True, data, [], []), recovered)


def show_tag(project: str | None, name: str) -> Result:
    """Members with current availability and broken references; read-only."""
    command = "tag show"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root

    def read(session: exit_journal.Session) -> dict[str, Any]:
        entry = catalog.read_one(session.tree, TAG, name)
        lib = resolve.snapshot(session.tree)
        return {
            "name": entry.name,
            "file_digest": entry.digest,
            "members": _member_rows(lib, entry.rels),
            "broken": catalog.broken_refs(lib, "tag", entry.name, entry.rels),
            "note": catalog.TAG_NOTE,
        }

    taken = catalog.in_session(command, root, read)
    if isinstance(taken, Result):
        return taken
    data, recovered = taken
    steps = [
        "Use the members as concrete references at proposal time (secure-code policy resolve --rule ...)"
    ]
    return exit_journal.with_recovered(Result(command, True, data, [], steps), recovered)


def _authorizer(op: str, trust_paths: TrustPaths | None) -> Callable[[], Result | None]:
    def check() -> Result | None:
        decision = require_maintainer(f"tag.{op}", paths=trust_paths)
        if decision.allowed:
            return None
        denied = decision.to_result()
        denied.next_steps = [ASK_STEP, *(s for s in denied.next_steps if s != ASK_STEP)]
        return denied

    return check


def _write(
    command: str, op: str, project: str | None, write: catalog.Write, trust_paths: TrustPaths | None
) -> tuple[catalog.Written, dict[str, Any] | None] | Result:
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    authorize = _authorizer(op, trust_paths)
    denied = authorize()
    if denied is not None:
        return denied
    store._pause_point("tag_write_authorized")
    write.authorize = authorize
    return catalog.in_session(command, root, lambda s: catalog.guarded_write(s, write), write=True)


def _members(data: dict[str, Any]) -> Callable[[catalog.Entry | None, resolve.Library], bytes]:
    members = catalog.ref_list(data, "members")

    def build(_current: catalog.Entry | None, lib: resolve.Library) -> bytes:
        valid, _ = catalog.validated_members(lib, members)
        return catalog.serialize(catalog.tag_doc(data["name"], valid))

    return build


def save_tag(
    project: str | None, request: str, confirmed: bool, *, trust_paths: TrustPaths | None = None
) -> Result:
    """Create one tag (Maintainer, explicit confirmation)."""
    command = "tag save"
    try:
        catalog.confirmed_or_refuse(confirmed)
        data = catalog.load_request(request, TAG_REQUEST, KEYS)
        catalog.check_slug(data.get("name"), "tag")
        build = _members(data)
    except CatalogError as exc:
        return exc.result(command)
    taken = _write(
        command, "save", project, catalog.Write(TAG, data["name"], create=True, build=build), trust_paths
    )
    if isinstance(taken, Result):
        return taken
    written, recovered = taken
    out = {
        "name": data["name"],
        "path": written.path,
        "file_digest": catalog.file_digest(written.data or b""),
        "member_count": len(catalog.parse(TAG, data["name"], written.data or b"")["members"]),
    }
    return exit_journal.with_recovered(Result(command, True, out, [], []), recovered)


def update_tag(
    project: str | None,
    name: str,
    request: str,
    digest: str | None,
    confirmed: bool,
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    """Replace a tag's members (Maintainer, current file digest, explicit confirmation)."""
    command = "tag update"
    try:
        catalog.confirmed_or_refuse(confirmed)
        data = catalog.load_request(request, TAG_REQUEST, KEYS)
        catalog.check_slug(name, "tag")
        if data.get("name", name) != name:
            raise catalog.request_error("A tag cannot be renamed: delete it and create a new one")
        build = _members({**data, "name": name})
    except CatalogError as exc:
        return exc.result(command)
    taken = _write(
        command, "update", project, catalog.Write(TAG, name, expected=digest, build=build), trust_paths
    )
    if isinstance(taken, Result):
        return taken
    written, recovered = taken
    assert written.previous is not None and written.data is not None
    new = catalog.parse(TAG, name, written.data)
    out = {
        "name": name,
        "path": written.path,
        "previous_digest": written.previous_digest,
        "file_digest": catalog.file_digest(written.data),
        "membership_changed": new["members"] != written.previous.data["members"],
        "changed": True,
    }
    return exit_journal.with_recovered(Result(command, True, out, [], []), recovered)


def delete_tag(
    project: str | None,
    name: str,
    digest: str | None,
    confirmed: bool,
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    """Remove one tag file (Maintainer, current file digest, explicit confirmation)."""
    command = "tag delete"
    try:
        catalog.confirmed_or_refuse(confirmed)
        catalog.check_slug(name, "tag")
    except CatalogError as exc:
        return exc.result(command)
    taken = _write(
        command, "delete", project, catalog.Write(TAG, name, delete=True, expected=digest), trust_paths
    )
    if isinstance(taken, Result):
        return taken
    written, recovered = taken
    out = {"name": name, "path": written.path, "removed": True}
    return exit_journal.with_recovered(Result(command, True, out, [], []), recovered)
