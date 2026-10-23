"""Project exit journal (FEATURE-001-D): schema, per-op validation contracts, progress check,
roll-forward, narrow EXDEV roll-back, `ensure_recovered` and the `session` hook.

Step paths are derived from (action, rule, target, exit_id); the journal never carries paths.
Recovery only completes an exit a Maintainer already confirmed (honest limit U-13: the journal
is not cryptographically bound to that authorization).
"""

from __future__ import annotations

import errno
import json
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..results import Result
from . import durable, lifecycle, store
from .durable import StoreError
from .identity import IdentityError, RuleRef
from .lifecycle import DIGEST, EXITS_REL, JOURNAL_NAME, sha

ORDER = {
    "deactivate": ("record", "changelog", "index", "transitions"),
    "reactivate": ("record", "changelog", "transitions"),
    "delete": ("tombstone_dir", "move", "tombstone_record", "pending", "index", "memory", "transitions"),
    "rename": ("record", "changelog", "move", "pending", "index", "memory", "transitions"),
}
OPS = {
    "record": "write", "changelog": "append", "tombstone_dir": "mkdir", "move": "move",
    "tombstone_record": "write", "pending": "remove", "index": "write", "memory": "write",
    "transitions": "write",
}
OPTIONAL = ("pending", "index")
STEP_KEYS = {
    "write": {"name", "op", "before", "after", "text"},
    "append": {"name", "op", "before", "after", "suffix", "suffix_digest"},
    "remove": {"name", "op", "before"},
    "move": {"name", "op", "fingerprint"},
    "mkdir": {"name", "op"},
}
PUBLIC = ("record", "changelog")
JOURNAL_TMP = re.compile(r"\.exit-.+\.journal\.tmp")
INVALID_STEP = (
    "A Maintainer must inspect `.x-ipe/private/secure-code/exits/journal.json` against the rule files, "
    "restore them (e.g. from version control) and move the journal aside; no knowledge was changed"
)
DONE, TODO = "done", "todo"


class JournalInvalid(Exception):
    pass


def invalid(message: str) -> StoreError:
    return StoreError("EXIT_JOURNAL_INVALID", f"exit journal is invalid: {message}", INVALID_STEP)


@dataclass(frozen=True)
class Derived:
    """Paths derived from the journal request; never read from the journal."""

    journal: dict[str, Any]
    ref: RuleRef
    target: RuleRef | None

    @property
    def exit_id(self) -> str:
        return self.journal["exit_id"]

    @property
    def action(self) -> str:
        return self.journal["action"]

    @property
    def rule_rel(self) -> str:
        return f"{store.LOCAL_REL}/{self.ref.rel}"

    @property
    def tomb_rel(self) -> str:
        return lifecycle.tombstone_rel(self.exit_id)

    @property
    def dest(self) -> tuple[str, str]:
        """(parent rel, name) the rule folder moves to."""
        if self.action == "delete":
            return self.tomb_rel, "rule"
        assert self.target is not None
        return f"{store.LOCAL_REL}/{self.target.namespace}/{self.target.version}", self.target.rule_id

    @property
    def source(self) -> tuple[str, str]:
        return f"{store.LOCAL_REL}/{self.ref.namespace}/{self.ref.version}", self.ref.rule_id

    def location(self, name: str, moved: bool) -> tuple[str, str]:
        if name in PUBLIC:
            folder = "/".join(self.dest) if moved else self.rule_rel
            return folder, "record.json" if name == "record" else "changelog.md"
        if name == "tombstone_record":
            return self.tomb_rel, lifecycle.EXIT_RECORD_NAME
        if name == "pending":
            return f"{store.PENDING_REL}/{self.ref.namespace}/{self.ref.version}", f"{self.ref.rule_id}.json"
        if name == "index":
            return lifecycle.INDEX_DIR, lifecycle.INDEX_NAME
        if name in ("memory", "transitions"):
            return EXITS_REL, lifecycle.MEMORY_NAME if name == "memory" else lifecycle.TRANSITIONS_NAME
        raise KeyError(name)

    def temp(self, name: str) -> str:
        return f".exit-{self.exit_id}.{name}.tmp"

    def folders(self) -> list[str]:
        found = {EXITS_REL, self.rule_rel, lifecycle.INDEX_DIR, self.location("pending", False)[0]}
        if self.action in ("delete", "rename"):
            found |= {"/".join(self.dest), self.tomb_rel}
        return sorted(found)


# --------------------------------------------------------------------------- journal-level checks
def _digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def derive(journal: Any) -> Derived:
    """Schema, action, identity, request and step-list checks; raises JournalInvalid."""
    j = journal
    if not isinstance(j, dict) or j.get("schema") != lifecycle.JOURNAL_SCHEMA:
        raise JournalInvalid("unknown schema")
    action = j.get("action")
    if action not in ORDER:
        raise JournalInvalid("unknown action")
    if not (isinstance(j.get("exit_id"), str) and lifecycle.EXIT_ID.fullmatch(j["exit_id"])):
        raise JournalInvalid("malformed exit id")
    if not (isinstance(j.get("at"), str) and lifecycle.TIME.fullmatch(j["at"])):
        raise JournalInvalid("malformed time")
    if not (_digest(j.get("impact_digest")) and _digest(j.get("transition_digest"))):
        raise JournalInvalid("malformed digests")
    if lifecycle.reason_problem(j.get("reason")):
        raise JournalInvalid("missing or invalid reason")
    try:
        ref = RuleRef.parse(j.get("rule"))
        target = RuleRef.parse(j["target"]) if j.get("target") is not None else None
    except IdentityError:
        raise JournalInvalid("malformed rule or target") from None
    if (action == "rename") != (target is not None):
        raise JournalInvalid("target present for a non-rename or missing for a rename")
    if target is not None and (
        (target.namespace, target.version) != (ref.namespace, ref.version) or target.rule_id == ref.rule_id
    ):
        raise JournalInvalid("rename target outside the rule's namespace and version")
    pre = j.get("pre_state")
    if not (
        isinstance(pre, dict)
        and set(pre) == {"pending", "index_edges"}
        and (pre["pending"] is None or _digest(pre["pending"]))
        and isinstance(pre.get("index_edges"), list)
        and all(_digest(d) for d in pre["index_edges"])
        and pre["index_edges"] == sorted(set(pre["index_edges"]))
    ):
        raise JournalInvalid("malformed pre_state")
    steps = j.get("steps")
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        raise JournalInvalid("malformed steps")
    names = [s.get("name") for s in steps]
    order = ORDER[action]
    if len(set(names)) != len(names) or any(n not in order for n in names):
        raise JournalInvalid("duplicate or unknown step")
    if names != [n for n in order if n in names]:
        raise JournalInvalid("steps out of order")
    expected = [n for n in order if n not in OPTIONAL]
    if action in ("delete", "rename") and pre["pending"] is not None:
        expected.append("pending")
    if pre["index_edges"] and "index" in order:
        expected.append("index")
    if sorted(expected) != sorted(names):
        raise JournalInvalid("required or pre-state optional steps missing or extra")
    for step in steps:
        _check_fields(step, pre)
    return Derived(j, ref, target)


def _check_fields(step: dict[str, Any], pre: dict[str, Any]) -> None:
    op = OPS[step["name"]]
    if step.get("op") != op:
        raise JournalInvalid(f"{step['name']}: wrong operation")
    if not STEP_KEYS[op] <= set(step):
        raise JournalInvalid(f"{step['name']}: missing fields {sorted(STEP_KEYS[op] - set(step))}")
    if op == "write":
        body = step.get("text")
        if not (isinstance(body, str) and step.get("after") == sha(body.encode("utf-8"))):
            raise JournalInvalid(f"{step['name']}: payload digest mismatch")
        if step.get("before") is not None and not _digest(step.get("before")):
            raise JournalInvalid(f"{step['name']}: malformed before digest")
    elif op == "append":
        suffix = step.get("suffix")
        if not (isinstance(suffix, str) and step.get("suffix_digest") == sha(suffix.encode("utf-8"))):
            raise JournalInvalid("changelog: suffix digest mismatch")
        if not (_digest(step.get("before")) and _digest(step.get("after"))):
            raise JournalInvalid("changelog: malformed digests")
    elif op == "remove":
        if not _digest(step.get("before")) or step["before"] != pre["pending"]:
            raise JournalInvalid("pending: before does not match the pre-state")
    elif op == "move" and not _digest(step.get("fingerprint")):
        raise JournalInvalid("move: malformed fingerprint")


# --------------------------------------------------------------------------- classification
def _read(tree: durable.Tree, rel: str, name: str) -> bytes | None:
    return lifecycle.read_at(tree, rel, name)


def _classify_file(step: dict[str, Any], current: bytes | None) -> str:
    op = step["op"]
    if op == "write":
        if current is not None and sha(current) == step["after"]:
            return DONE
        if (current is None and step["before"] is None) or (
            current is not None and sha(current) == step["before"]
        ):
            return TODO
    elif op == "append" and current is not None:
        if sha(current) == step["after"]:
            return DONE
        if sha(current) == step["before"] and sha(current + step["suffix"].encode("utf-8")) == step["after"]:
            return TODO
    elif op == "remove":
        if current is None:
            return DONE
        if sha(current) == step["before"]:
            return TODO
    raise JournalInvalid(f"{step['name']}: current file matches neither before nor after")


def planned_fingerprint(tree: durable.Tree, parent: str, name: str, final: dict[str, bytes]) -> str | None:
    """Fingerprint of folder parent/name (None if absent); `final` overrides planned file contents."""
    fd = tree.opt_dir(parent)
    if fd is None:
        return None
    try:
        found = durable.entry(fd, name)
        if found is None:
            return None
        if not stat.S_ISDIR(found.st_mode):
            raise durable.unsafe(f"{parent}/{name} is not a real folder")
        child = durable.open_child(fd, name)
    finally:
        durable.close(fd)
    try:
        rows, _ = lifecycle.folder_rows(child)
    finally:
        durable.close(child)
    rows = [[r[0], "file", sha(final[r[0]])] if r[0] in final else r for r in rows]
    return sha(lifecycle.canonical(sorted(rows)))


def _final_texts(tree: durable.Tree, d: Derived, steps: dict[str, dict[str, Any]]) -> dict[str, bytes]:
    """Planned contents of record/changelog after their steps (rename move fingerprint input)."""
    final: dict[str, bytes] = {}
    if "record" in steps:
        final["record.json"] = steps["record"]["text"].encode("utf-8")
    if "changelog" in steps:
        current = _read(tree, d.rule_rel, "changelog.md") or b""
        step = steps["changelog"]
        done = sha(current) == step["after"]
        final["changelog.md"] = current if done else current + step["suffix"].encode("utf-8")
    return final


def _classify_move(tree: durable.Tree, d: Derived, step: dict[str, Any], steps: dict[str, Any]) -> str:
    final = _final_texts(tree, d, steps) if d.action == "rename" else {}
    source = planned_fingerprint(tree, *d.source, final)
    dest = planned_fingerprint(tree, *d.dest, {})
    if source is not None and dest is None and source == step["fingerprint"]:
        return TODO
    if source is None and dest is not None and dest == step["fingerprint"]:
        return DONE
    raise JournalInvalid("move: folders match neither the planned source nor destination")


def _classify_mkdir(tree: durable.Tree, d: Derived) -> str:
    fd = tree.opt_dir(lifecycle.TOMBSTONES_REL)
    if fd is None:
        return TODO
    try:
        found = durable.entry(fd, d.exit_id)
    finally:
        durable.close(fd)
    if found is None:
        return TODO
    if stat.S_ISLNK(found.st_mode):
        raise durable.unsafe(f"{d.tomb_rel} is a symbolic link")
    if not stat.S_ISDIR(found.st_mode):
        raise JournalInvalid("tombstone folder is not a folder")
    child = tree.dir(d.tomb_rel)
    try:
        names = {n for n, _ in durable.listdir(child)}
    finally:
        durable.close(child)
    if not names <= {"rule", lifecycle.EXIT_RECORD_NAME}:
        raise JournalInvalid("tombstone folder holds foreign entries")
    return DONE


def classify(tree: durable.Tree, d: Derived) -> list[str]:
    """Status of every step plus payload checks; must be a done-prefix then a not-done suffix."""
    steps = {s["name"]: s for s in d.journal["steps"]}
    moved = False
    status: dict[str, str] = {}
    if "move" in steps:
        status["move"] = _classify_move(tree, d, steps["move"], steps)
        moved = status["move"] == DONE
    current: dict[str, bytes | None] = {}
    for name, step in steps.items():
        if name == "move":
            continue
        if name == "tombstone_dir":
            status[name] = _classify_mkdir(tree, d)
            continue
        current[name] = _read(tree, *d.location(name, moved))
        status[name] = _classify_file(step, current[name])
    ordered = [status[s["name"]] for s in d.journal["steps"]]
    first = ordered.index(TODO) if TODO in ordered else len(ordered)
    if any(s == DONE for s in ordered[first:]):
        raise JournalInvalid("progress is not a done-prefix")
    _check_payloads(tree, d, steps, status, current, moved)
    return ordered


# --------------------------------------------------------------------------- payload contracts
def _parse(step: dict[str, Any]) -> Any:
    try:
        return json.loads(step["text"])
    except ValueError:
        raise JournalInvalid(f"{step['name']}: payload is not JSON") from None


def _check_payloads(
    tree: durable.Tree, d: Derived, steps: dict[str, Any], status: dict[str, str],
    current: dict[str, bytes | None], moved: bool,
) -> None:
    td = d.journal["transition_digest"]
    if "record" in steps:
        _check_record(tree, d, _parse(steps["record"]), moved)
    if "changelog" in steps and f"- transition: {td}\n" not in steps["changelog"]["suffix"]:
        raise JournalInvalid("changelog entry does not bind the transition")
    if "memory" in steps:
        _check_memory(d, _parse(steps["memory"]), status["memory"], current["memory"])
    if "tombstone_record" in steps:
        record = _parse(steps["tombstone_record"])
        if not (
            isinstance(record, dict)
            and record.get("schema") == lifecycle.EXIT_RECORD_SCHEMA
            and record.get("exit_id") == d.exit_id
            and record.get("action") == "delete"
            and record.get("rule") == d.ref.rel
            and record.get("transition") == td
        ):
            raise JournalInvalid("exit record payload does not match the journal")
    _check_transitions(d, _parse(steps["transitions"]), status["transitions"], current["transitions"])
    _check_index(tree, d, steps, status, current)
    if d.action in ("delete", "rename") and "pending" not in steps:
        if _read(tree, *d.location("pending", False)) is not None:
            raise JournalInvalid("a pending decision exists but the journal does not remove it")


def _check_record(tree: durable.Tree, d: Derived, record: Any, moved: bool) -> None:
    ref = d.target if d.action == "rename" else d.ref
    assert ref is not None
    try:
        ok = (
            isinstance(record, dict)
            and record.get("schema") == store.RECORD_SCHEMA
            and (record.get("namespace"), record.get("version"), record.get("rule_id"))
            == (ref.namespace, ref.version, ref.rule_id)
            and "lifecycle" in record
            and store.lifecycle_valid(record)
        )
        state = record["lifecycle"]["state"] if ok else None
        if ok and d.action != "rename":
            ok = state == ("deactivated" if d.action == "deactivate" else "active")
        if ok:
            fd = tree.dir(d.location("record", moved)[0])
            try:
                files = store.logical_view(store.texts_at(fd))[0]
            finally:
                durable.close(fd)
            ok = store.item_from(ref, record, files).digest() == record.get("item_digest")
    except (ValueError, KeyError, TypeError, AttributeError, IdentityError):
        ok = False
    if not ok:
        raise JournalInvalid("record payload does not match the rule folder")


def _check_memory(d: Derived, data: Any, state: str, current: bytes | None) -> None:
    try:
        entries = lifecycle.memory_entries(json.dumps(data).encode())
        mine = [e for e in entries if e["exit_id"] == d.exit_id]
        others = [e for e in entries if e["exit_id"] != d.exit_id]
        previous = lifecycle.memory_entries(current) if state == TODO else others
    except (ValueError, KeyError, TypeError):
        raise JournalInvalid("memory payload is not exit-memory/v1") from None
    entry = mine[0] if len(mine) == 1 else {}
    expected_tomb = d.tomb_rel if d.action == "delete" else None
    if not (
        entry.get("rule") == d.ref.rel
        and entry.get("action") == lifecycle.EXITED[d.action]
        and entry.get("renamed_to") == (d.target.rel if d.target else None)
        and entry.get("transition") == d.journal["transition_digest"]
        and entry.get("tombstone") == expected_tomb
        and _same(previous, others)
    ):
        raise JournalInvalid("memory payload is not the previous entries plus this exit")


def _same(a: list[Any], b: list[Any]) -> bool:
    return sorted(lifecycle.canonical(x) for x in a) == sorted(lifecycle.canonical(x) for x in b)


def _check_transitions(d: Derived, data: Any, state: str, current: bytes | None) -> None:
    try:
        entries = lifecycle.transition_entries(json.dumps(data).encode())
        previous = lifecycle.transition_entries(current) if state == TODO else entries[:-1]
    except (ValueError, TypeError):
        raise JournalInvalid("transition log payload is not exit-transitions/v1") from None
    last = entries[-1] if entries else {}
    td = d.journal["transition_digest"]
    if not (
        last
        and last.get("digest") == td
        and lifecycle.transition_digest(last) == td
        and last.get("exit_id") == d.exit_id
        and last.get("action") == d.action
        and last.get("rule") == d.ref.rel
        and last.get("target") == (d.target.rel if d.target else None)
        and entries[:-1] == previous
    ):
        raise JournalInvalid("transition log payload does not append exactly this exit's transition")


def _check_index(
    tree: durable.Tree, d: Derived, steps: dict[str, Any], status: dict[str, str],
    current: dict[str, bytes | None],
) -> None:
    if d.action == "reactivate":
        return
    if "index" in steps and status["index"] == DONE:
        return
    raw = current["index"] if "index" in steps else _read(tree, lifecycle.INDEX_DIR, lifecycle.INDEX_NAME)
    try:
        index = lifecycle.index_entries(raw)
    except (ValueError, UnicodeDecodeError):
        raise JournalInvalid("document index is unreadable") from None
    edges = lifecycle.index_edges(index, d.ref.rel)
    if "index" not in steps:
        if edges:
            raise JournalInvalid("the index has edges for the rule but the journal does not invalidate them")
        return
    planned = _parse(steps["index"])
    expected = lifecycle.invalidate_index(index, d.ref.rel, edges, d.journal["at"])
    if edges != d.journal["pre_state"]["index_edges"] or planned != expected:
        raise JournalInvalid("index payload is not the current index with only the rule's edges invalidated")


# --------------------------------------------------------------------------- apply
def apply(tree: durable.Tree, d: Derived, step: dict[str, Any], moved: bool) -> None:
    name = step["name"]
    durable.set_step(name)
    op = step["op"]
    if op == "mkdir":
        durable.close(tree.dir(d.tomb_rel, create=True))
    elif op == "move":
        src = tree.dir(d.source[0])
        try:
            dst = tree.dir(d.dest[0], create=True)
            try:
                durable.move(src, d.source[1], dst, d.dest[1])
            finally:
                durable.close(dst)
        finally:
            durable.close(src)
    else:
        rel, file = d.location(name, moved)
        fd = tree.dir(rel, create=op == "write")
        try:
            if op == "remove":
                durable.unlink(fd, file)
            else:
                data = step["text"].encode("utf-8") if op == "write" else (
                    (durable.read(fd, file) or b"") + step["suffix"].encode("utf-8")
                )
                durable.write(fd, file, data, d.temp(name))
        finally:
            durable.close(fd)
    store._crash_point(f"exit_after_{name}")


def _roll_forward(tree: durable.Tree, d: Derived, ordered: list[str]) -> None:
    moved = "move" in [s["name"] for s, st in zip(d.journal["steps"], ordered, strict=True) if st == DONE]
    for step, state in zip(d.journal["steps"], ordered, strict=True):
        if state == DONE:
            continue
        apply(tree, d, step, moved)
        moved = moved or step["name"] == "move"


def run(tree: durable.Tree, journal: dict[str, Any]) -> None:
    """Commit point and steps; the caller holds the knowledge and scope locks."""
    d = derive(journal)
    if any(s != TODO for s in classify(tree, d)):
        raise JournalInvalid("planned journal does not match the current files")
    if has_pending(tree):
        # Never overwrite another exit's journal (the caller's session recovers under the lock).
        raise StoreError("IO_ERROR", "An earlier exit journal is pending", REPEAT_STEP)
    exits = tree.dir(EXITS_REL, create=True)
    try:
        durable.set_step("journal")
        durable.write(exits, JOURNAL_NAME, lifecycle.text(journal).encode("utf-8"), d.temp("journal"))
        store._crash_point("exit_after_journal")
        _roll_forward(tree, d, [TODO] * len(journal["steps"]))
        store._crash_point("exit_before_journal_delete")
        durable.set_step("journal")
        durable.unlink(exits, JOURNAL_NAME)
    finally:
        durable.set_step("")
        durable.close(exits)


# --------------------------------------------------------------------------- recovery
def _remove_temps(tree: durable.Tree, folder: str, pattern: re.Pattern[str]) -> int:
    fd = tree.opt_dir(folder)
    if fd is None:
        return 0
    removed = 0
    try:
        for name, info in durable.listdir(fd):
            if pattern.fullmatch(name) and stat.S_ISREG(info.st_mode):
                durable.unlink(fd, name)
                removed += 1
    finally:
        durable.close(fd)
    return removed


def has_pending(tree: durable.Tree) -> bool:
    fd = tree.opt_dir(EXITS_REL)
    if fd is None:
        return False
    try:
        return any(n == JOURNAL_NAME or JOURNAL_TMP.fullmatch(n) for n, _ in durable.listdir(fd))
    finally:
        durable.close(fd)


def recover_locked(tree: durable.Tree) -> dict[str, Any] | None:
    """Complete or roll back the pending exit (caller holds the knowledge lock)."""
    raw = _read(tree, EXITS_REL, JOURNAL_NAME)
    if raw is None:
        removed = _remove_temps(tree, EXITS_REL, JOURNAL_TMP)
        return {"outcome": "rolled_back"} if removed else None
    try:
        d = derive(json.loads(raw.decode("utf-8")))
        own = re.compile(re.escape(f".exit-{d.exit_id}.") + r"[a-z_]+\.tmp")
        for folder in d.folders():
            _remove_temps(tree, folder, own)
        ordered = classify(tree, d)
    except (JournalInvalid, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise invalid(f"{type(exc).__name__}: {exc}") from None
    info = {"exit_id": d.exit_id, "action": d.action, "rule": d.ref.rel,
            "target": d.target.rel if d.target else None}
    try:
        _roll_forward(tree, d, ordered)
    except OSError as exc:
        if exc.errno == errno.EXDEV and d.action == "delete" and ordered[:2] == [DONE, TODO]:
            return _narrow_rollback(tree, d, info)
        raise
    finally:
        durable.set_step("")
    exits = tree.dir(EXITS_REL)
    try:
        durable.unlink(exits, JOURNAL_NAME)
    finally:
        durable.close(exits)
    return {**info, "outcome": "completed"}


def _narrow_rollback(tree: durable.Tree, d: Derived, info: dict[str, Any]) -> dict[str, Any]:
    tombs = tree.dir(lifecycle.TOMBSTONES_REL)
    try:
        durable.rmdir_empty(tombs, d.exit_id)
    finally:
        durable.close(tombs)
    exits = tree.dir(EXITS_REL)
    try:
        durable.unlink(exits, JOURNAL_NAME)
    finally:
        durable.close(exits)
    return {**info, "outcome": "rolled_back", "reason": "tombstone on another device"}


def ensure_recovered(root: Path) -> dict[str, Any] | None:
    """Before authorization: briefly lock and recover only if a journal or exit temporary exists."""
    with durable.Tree(root) as tree:
        if not has_pending(tree):
            return None
        with durable.DirLock(tree, store.LOCK_REL, create=True):
            return recover_locked(tree)


@dataclass
class Session:
    tree: durable.Tree
    recovered: dict[str, Any] | None


@contextmanager
def session(root: Path, *, write: bool) -> Iterator[Session]:
    """Knowledge lock (created only for writers or a pending journal) + recovery; one Tree."""
    tree = durable.Tree(root)
    try:
        pending = has_pending(tree)
        with durable.DirLock(tree, store.LOCK_REL, create=write or pending):
            # Re-check under the lock: an exit may have failed after its commit point while we waited.
            recovered = recover_locked(tree) if pending or has_pending(tree) else None
            yield Session(tree, recovered)
    finally:
        tree.close()


RETRY_STEP = "Retry when the other operation finished"
REPEAT_STEP = "Re-run any knowledge command; it completes the interrupted exit"


def refusal(command: str, exc: BaseException, data: dict[str, Any] | None = None) -> Result:
    """Refusal for errors raised by the recovery hook, sessions and exit primitives."""
    if isinstance(exc, LockHeld):
        return Result.refused(command, "LOCKED", str(exc), RETRY_STEP, data)
    if isinstance(exc, StoreError):
        return Result.refused(command, exc.code, exc.message, exc.next_step, data)
    if isinstance(exc, JournalInvalid):
        error = invalid(str(exc))
        return Result.refused(command, error.code, error.message, error.next_step, data)
    if isinstance(exc, OSError):
        return Result.refused(command, "IO_ERROR", str(exc.strerror or exc), REPEAT_STEP, data)
    raise exc


def with_recovered(result: Result, recovered: dict[str, Any] | None) -> Result:
    """Name the earlier exit this command completed or rolled back (also on refusals)."""
    if recovered:
        result.data["recovered_exit"] = recovered
    return result
