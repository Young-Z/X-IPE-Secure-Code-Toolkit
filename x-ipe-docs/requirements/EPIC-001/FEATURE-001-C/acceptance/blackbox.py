"""Black-box acceptance scenarios for FEATURE-001-C (test-only artifact, TASK-018).

Calls the real CLI: `uvx --from <framework>/scripts secure-code ...`. Never imports toolkit code.

  python3 blackbox.py host                         # never-authorized User path (no trust writes)
  FAT_ISOLATED=1 python3 blackbox.py container     # Maintainer-prepared scenarios (disposable HOME only!)
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

TOOLKIT = (Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ
           else Path(__file__).resolve().parents[5] / "ai-secure-code-toolkit")
SCRIPTS = TOOLKIT / "x-ipe-secure-code-toolkit-framework" / "scripts"
LOCAL = "x-ipe-docs/secure-code/knowledge/local"
PENDING = ".x-ipe/private/secure-code/pending"
SCOPES = "x-ipe-docs/secure-code/scopes"
LOCK = ".x-ipe/private/secure-code/locks/knowledge.lock"
PASS = "acceptance passphrase 42"
SECRET_LINE = 'password = "Zq8vLr2mNp4tXw9yKp"\n'
RESULTS: list[dict] = []


def sc(*args: str, cwd: Path | None = None):
    proc = subprocess.run(["uvx", "--from", str(SCRIPTS), "secure-code", *args], capture_output=True,
                          text=True, env=dict(os.environ), cwd=cwd, timeout=300)
    try:
        data = json.loads(proc.stdout) if "--json" in args else None
    except json.JSONDecodeError:
        data = None
    return proc.returncode, data, proc.stdout, proc.stderr


def sc_pty(answers: list[str], *args: str) -> int:
    import pty

    cmd = ["uvx", "--from", str(SCRIPTS), "secure-code", *args]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(cmd[0], cmd, dict(os.environ))
    out, sent, end = b"", 0, time.time() + 120
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        if sent < len(answers) and out.lower().count(b"passphrase") > sent:
            os.write(fd, answers[sent].encode() + b"\n")
            sent += 1
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status)


def tree(*roots: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for root in roots:
        if root.exists():
            result.update({str(p): ("dir" if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest())
                           for p in sorted(root.rglob("*"))})
    return result


def case(tc: str, acs: list[str], fn) -> None:
    try:
        checks = fn()
        failed = [n for n, ok in checks if not ok]
        detail = {"status": "Pass" if not failed else "Fail", "checks": [n for n, _ in checks], "failed": failed}
    except Exception as exc:  # noqa: BLE001 - every unexpected error is a failed case
        detail = {"status": "Fail", "error": f"{type(exc).__name__}: {exc}"}
    RESULTS.append({"tc": tc, "acs": acs, **detail})
    print(json.dumps(RESULTS[-1]), flush=True)


def new_project() -> Path:
    root = Path(tempfile.mkdtemp(prefix="fat-c-")) / "proj ü"
    root.mkdir()
    assert sc("init", "--project", str(root), "--env", "github-copilot", "--json")[0] == 0
    return root


def item(rule: str, **over) -> dict:
    ns, ver, rid = rule.split("/")
    data = {"namespace": ns, "version": ver, "rule_id": rid, "content": f"Rule {rid} body.\n",
            "source_location": f"https://example.org/{rid}"}
    if ns.startswith("@"):
        data["name"] = f"Custom {rid}"
    data.update({k: v for k, v in over.items() if v is not None})
    for k, v in over.items():
        if v is None:
            data.pop(k, None)
    return data


def temp_json(project: Path, doc: dict) -> Path:
    path = Path(tempfile.mkstemp(suffix=".json", dir=project.parent)[1])
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def imp(project: Path, *items: dict):
    doc = {"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": list(items)}
    return sc("knowledge", "import", "--project", str(project), "--batch", str(temp_json(project, doc)), "--json")


def resolve(project: Path, *rules: str, all_: bool = False, languages: tuple = ()):
    args = ["policy", "resolve", "--project", str(project), "--json"]
    args += ["--all"] if all_ else [x for r in rules for x in ("--rule", r)]
    args += [x for lang in languages for x in ("--language", lang)]
    return sc(*args)


def entry(out: dict, requested: str) -> dict:
    return next(e for e in out["data"]["entries"] if e["requested"] == requested)


def adopt(out: dict, ref: str, note: str | None = None) -> dict:
    d = {"ref": ref, "decision": "adopted", "state_digest": entry(out, ref)["source_evidence"]["state_digest"]}
    if note:
        d["note"] = note
    return d


def skip(ref: str, reason: str) -> dict:
    return {"ref": ref, "decision": "not_adopted", "reason": reason}


def decisions(project: Path, out: dict, items: list, mode: str = "clues") -> Path:
    doc = {"schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": mode,
           "proposal_digest": out["data"]["proposal_digest"], "clues": "Java login service",
           "language_context": ["java"], "decisions": items, "confirmation_note": "User confirmed in chat"}
    if mode == "clues":
        doc["considered"] = [e["requested"] for e in out["data"]["entries"]]
    return temp_json(project, doc)


def save(project: Path, path: Path, confirmed: bool = True):
    args = ["scope", "save", "--project", str(project), "--decisions", str(path), "--json"]
    return sc(*(args + (["--confirmed"] if confirmed else [])))


def show(project: Path, scope_id: str):
    return sc("scope", "show", "--project", str(project), "--scope", scope_id, "--json")


def update(project: Path, rule: str, base: str, content: str):
    path = temp_json(project, {"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": content})
    return sc("knowledge", "update", "--project", str(project), "--rule", rule, "--base-state", base,
              "--input", str(path), "--json")


def code_of(out: dict | None) -> str | None:
    return out["problems"][0]["code"] if out and out.get("problems") else None


# --------------------------------------------------------------------------- cases
def tc_structure():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79", examples={"general": "Encode.\n", "python": "escape(x)\n"},
                applicability=["python"], relations=["CWE/4.14/CWE-80"]),
        item("CWE/4.14/CWE-89", source_location=None))
    code, out, _, _ = resolve(p, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89")
    a, b = entry(out, "CWE/4.14/CWE-79"), entry(out, "CWE/4.14/CWE-89")
    ev = a["source_evidence"]
    return [
        ("01a identity/name/kind", a["rule"] == "CWE/4.14/CWE-79" and "name" in a and a["kind"] == "institutional"),
        ("01a requirement = full content", a["requirement"] == "Rule CWE-79 body.\n"),
        ("01a applicability advisory list", a["applicability"] == ["python"]),
        ("01a examples + relations as references", a["examples"] == ["general", "python"]
         and a["relations"] == ["CWE/4.14/CWE-80"]),
        ("01a source evidence", ev["source_location"] == "https://example.org/CWE-79"
         and ev["state_digest"].startswith("sha256:") and bool(ev["last_changed_at"])),
        ("01a retrieved, no unresolved", a["retrieval_status"] == "retrieved" and a["unresolved"] == []),
        ("01b applicability unknown", b["applicability"] == "unknown"),
        ("01b location not recorded + unresolved", b["source_evidence"]["source_location"] == "not recorded"
         and "source location not recorded" in b["unresolved"] and b["availability"] == "available"),
        ("01f complete despite policy-level gap", code == 0 and out["data"]["status"] == "complete"),
    ]


def tc_mixed():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"), item("CWE/4.13/CWE-89"), item("CWE/4.14/CWE-89"))
    imp(p, item("CWE/4.14/CWE-798", content=SECRET_LINE))
    code, out, stdout, _ = resolve(p, "CWE/4.14/CWE-79", "CWE/4.14/CWE-1", "CWE/CWE-89", "CWE/4.14/CWE-798")
    d = out["data"]
    unclear = entry(out, "CWE/CWE-89")
    return [
        ("01c partial never complete", code == 0 and d["status"] == "partial"),
        ("01c counts consistent", d["counts"] == {"requested": 4, "available": 1, "missing": 2, "unclear": 1}),
        ("02a library size + nothing adopted + digest", d["library_size"] == 3 and d["adopted"] == []
         and d["proposal_digest"].startswith("sha256:")),
        ("02a no scope/preset written", not (p / SCOPES).exists()
         and list((p / "x-ipe-docs/secure-code/presets").iterdir()) == []),
        ("02b multiple_versions unclear with both candidates", unclear["reason"] == "multiple_versions"
         and sorted(c["rule"] for c in unclear["candidates"]) == ["CWE/4.13/CWE-89", "CWE/4.14/CWE-89"]
         and "requirement" not in unclear),
        ("02c not_found", entry(out, "CWE/4.14/CWE-1")["reason"] == "not_found"),
        ("02c pending_decision, content not returned", entry(out, "CWE/4.14/CWE-798")["reason"] == "pending_decision"
         and "Zq8vLr2mNp4tXw9yKp" not in stdout),
    ]


def tc_damaged():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"), item("CWE/4.14/CWE-89"))
    (p / LOCAL / "CWE/4.14/CWE-79/content.md").write_text("tampered by hand\n")
    (p / LOCAL / "CWE/4.14/CWE-89/content.md").write_bytes(b"\xff\xfe broken")
    code, out, stdout, stderr = resolve(p, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89")
    a, b = entry(out, "CWE/4.14/CWE-79"), entry(out, "CWE/4.14/CWE-89")
    return [
        ("01d inconsistent", (a["availability"], a["reason"]) == ("missing", "inconsistent")),
        ("01d unreadable", (b["availability"], b["reason"]) == ("missing", "unreadable")),
        ("01d no content returned", "tampered by hand" not in stdout and "requirement" not in a),
        ("01d envelope, no traceback", code == 1 and "Traceback" not in stderr),
    ]


def tc_language():
    p = new_project()
    imp(p, item("CWE/4.14/A", applicability=["python"]), item("CWE/4.14/B", applicability=["java"]),
        item("CWE/4.14/C"))
    code, out, _, _ = resolve(p, "CWE/4.14/A", "CWE/4.14/B", "CWE/4.14/C", languages=("java",))
    notes = {e["requested"]: e["language_note"] for e in out["data"]["entries"]}
    return [
        ("02d notes", notes == {"CWE/4.14/A": "does_not_match", "CWE/4.14/B": "matches", "CWE/4.14/C": "unknown"}),
        ("02d none excluded", code == 0 and out["data"]["counts"]["available"] == 3
         and out["data"]["status"] == "complete"),
    ]


def tc_empty():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-798", content=SECRET_LINE))
    checks = []
    for label, result in (("--all", resolve(p, all_=True)), ("--rule", resolve(p, "CWE/4.14/CWE-79"))):
        code, out, _, _ = result
        checks += [
            (f"03a {label} maintenance_needed exit 1", code == 1 and out["data"]["status"] == "maintenance_needed"
             and code_of(out) == "MAINTENANCE_NEEDED"),
            (f"03a {label} no Policy invented", all(e["availability"] != "available" for e in out["data"]["entries"])),
            (f"03a {label} next step Maintainer import", any("Maintainer" in s and "import" in s
                                                              for s in out["next_steps"])),
        ]
    return checks


def tc_none_available():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"), item("CWE/4.13/CWE-89"), item("CWE/4.14/CWE-89"))
    code, out, _, _ = resolve(p, "CWE/4.14/CWE-1", "CWE/CWE-89")
    return [("03b maintenance_needed", code == 1 and out["data"]["status"] == "maintenance_needed"),
            ("03b next step names refs", any("CWE/4.14/CWE-1" in s and "CWE/CWE-89" in s for s in out["next_steps"]))]


def tc_decisions():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"), item("CWE/4.13/CWE-89"), item("CWE/4.14/CWE-89"), item("@ACME/v1/A-1"))
    _, out, _, _ = resolve(p, "CWE/4.14/CWE-79", "CWE/4.14/CWE-1", "CWE/CWE-89", "@ACME/v1/A-1")
    c1, o1, _, _ = save(p, decisions(p, out, [adopt(out, "CWE/4.14/CWE-79")]))
    no_file_1 = not (p / SCOPES).exists()
    c2, o2, _, _ = save(p, decisions(p, out, [adopt(out, "CWE/4.14/CWE-79"), skip("CWE/4.14/CWE-1", "m"),
                                              {"ref": "CWE/CWE-89", "decision": "adopted", "state_digest": "sha256:x"},
                                              skip("@ACME/v1/A-1", "c")]))
    c3, o3, _, _ = save(p, decisions(p, out, [skip(r, "no") for r in
                                              ("CWE/4.14/CWE-79", "CWE/4.14/CWE-1", "CWE/CWE-89", "@ACME/v1/A-1")]))
    c4, o4, _, _ = save(p, decisions(p, out, [
        adopt(out, "CWE/4.14/CWE-79", note="user: applies to templates only"),
        skip("CWE/4.14/CWE-1", "missing: not_found; user agreed"),
        skip("CWE/CWE-89", "unclear: two versions; user deferred"),
        skip("@ACME/v1/A-1", "conflicts with CWE-79 guidance; user chose CWE")]))
    record = json.loads((p / o4["data"]["path"]).read_text()) if c4 == 0 else {}
    not_adopted = {n["requested"]: (n["availability"], n["reason"]) for n in record.get("not_adopted", [])}
    _, shown, _, _ = show(p, o4["data"]["scope_id"]) if c4 == 0 else (1, {"data": {}}, "", "")
    return [
        ("03c undecided refused naming refs", c1 == 1 and code_of(o1) == "DECISION_MISSING"
         and all(r in o1["problems"][0]["message"] for r in ("CWE/4.14/CWE-1", "CWE/CWE-89", "@ACME/v1/A-1"))),
        ("03c nothing written", no_file_1),
        ("03c unclear cannot be adopted", c2 == 1 and code_of(o2) == "NOT_ADOPTABLE"),
        ("03d zero adopted refused", c3 == 1 and code_of(o3) == "NOTHING_ADOPTED"),
        ("03d saved with not-adopted reasons", c4 == 0 and not_adopted.get("CWE/4.14/CWE-1", ("",))[0] == "missing"
         and not_adopted.get("CWE/CWE-89", ("",))[0] == "unclear"),
        ("03d never counted as adopted", shown["data"].get("adopted_rules") == ["CWE/4.14/CWE-79"]),
        ("02g note + conflict reason verbatim", record.get("adopted", [{}])[0].get("note")
         == "user: applies to templates only"
         and not_adopted.get("@ACME/v1/A-1") == ("available", "conflicts with CWE-79 guidance; user chose CWE")),
    ]


def tc_apply_all():
    p = new_project()
    imp(p, item("CWE/4.13/CWE-79"), item("CWE/4.14/CWE-79"), item("@ACME/v1/A-1"))
    imp(p, item("CWE/4.14/CWE-798", content=SECRET_LINE))
    code, out, _, _ = resolve(p, all_=True)
    _, _, text, _ = sc("policy", "resolve", "--project", str(p), "--all")
    notices = {n["code"]: n for n in out["data"]["notices"]}
    rules = sorted(e["rule"] for e in out["data"]["entries"])
    c, saved, _, _ = save(p, decisions(p, out, [adopt(out, r) for r in rules], mode="apply_all"))
    record = json.loads((p / saved["data"]["path"]).read_text()) if c == 0 else {}
    imp(p, item("CWE/4.14/CWE-22"))
    _, loaded, _, _ = show(p, saved["data"]["scope_id"]) if c == 0 else (1, {"data": {}}, "", "")
    return [
        ("04a highlighted notice first", list(out["data"])[0] == "notices" and "!! Notices" in text
         and "Apply All" in notices["APPLY_ALL_PROPOSED"]["message"]
         and notices["APPLY_ALL_PROPOSED"]["default_preset_exists"] is False),
        ("04a every rule of every ns/version", rules == ["@ACME/v1/A-1", "CWE/4.13/CWE-79", "CWE/4.14/CWE-79"]),
        ("04a multi-version highlighted", notices["MULTI_VERSION"]["rules"] == {"CWE/CWE-79": ["4.13", "4.14"]}),
        ("04a pending excluded and counted", notices["PENDING_EXCLUDED"]["count"] == 1),
        ("04b mode apply_all + concrete list", record.get("mode") == "apply_all"
         and sorted(a["rule"] for a in record.get("adopted", [])) == rules),
        ("04b artifact scope separate", record.get("artifact_scope") == "not determined by the Policy scope"),
        ("04c later import not adopted", loaded["data"].get("status") == "complete"
         and sorted(loaded["data"].get("adopted_rules", [])) == rules),
    ]


def tc_record():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"), item("CWE/4.14/CWE-89"))
    _, out, _, _ = resolve(p, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89", languages=("java",))
    path = decisions(p, out, [adopt(out, "CWE/4.14/CWE-79", note="n"), skip("CWE/4.14/CWE-89", "not relevant")])
    results: list = []
    threads = [threading.Thread(target=lambda: results.append(save(p, path))) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {r[1]["data"]["scope_id"] for r in results if r[0] == 0}
    files = list((p / SCOPES).glob("*.json"))
    record = json.loads(files[0].read_text()) if len(files) == 1 else {}
    again = save(p, path)[1]
    return [
        ("05a outside presets/knowledge", len(files) == 1 and files[0].parent == p / SCOPES),
        ("05a file named by id", files and files[0].name == record.get("scope_id", ":").split(":")[1] + ".json"),
        ("05a fields", record.get("mode") == "clues" and record.get("clues") == "Java login service"
         and record["adopted"][0]["state_digest"].startswith("sha256:") and record["adopted"][0]["note"] == "n"
         and record["not_adopted"][0]["reason"] == "not relevant"
         and record.get("confirmation_note") == "User confirmed in chat" and bool(record.get("created_at"))),
        ("05c 4 parallel CLI saves → one id, one created", len(results) == 4 and len(ids) == 1
         and sum(r[1]["data"]["created"] for r in results if r[0] == 0) == 1),
        ("05c second save keeps first created_at", again["data"]["created"] is False
         and again["data"]["created_at"] == record.get("created_at")),
    ]


def tc_drift_on_load():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"), item("CWE/4.14/CWE-89"), item("CWE/4.14/CWE-22"))
    refs = ("CWE/4.14/CWE-79", "CWE/4.14/CWE-89", "CWE/4.14/CWE-22")
    _, out, _, _ = resolve(p, *refs)
    _, saved, _, _ = save(p, decisions(p, out, [adopt(out, r) for r in refs]))
    sid = saved["data"]["scope_id"]
    c1, first, _, _ = show(p, sid.split(":")[1])
    confirmed = entry(out, "CWE/4.14/CWE-89")["source_evidence"]["state_digest"]
    update(p, "CWE/4.14/CWE-89", confirmed, "New body.\n")
    shutil.rmtree(p / LOCAL / "CWE/4.14/CWE-22")
    c2, second, _, _ = show(p, sid)
    by = {e["rule"]: e for e in second["data"]["entries"]}
    changed = by["CWE/4.14/CWE-89"]
    for rule in ("CWE/4.14/CWE-79", "CWE/4.14/CWE-89"):
        shutil.rmtree(p / LOCAL / rule)
    c3, third, _, _ = show(p, sid)
    return [
        ("05g unchanged → complete", c1 == 0 and first["data"]["status"] == "complete"),
        ("05b unchanged stays adopted", by["CWE/4.14/CWE-79"]["adoption"] == "adopted"
         and by["CWE/4.14/CWE-79"]["policy"]["requirement"] == "Rule CWE-79 body.\n"),
        ("05b changed → needs_reconfirmation with both digests", changed["adoption"] == "needs_reconfirmation"
         and changed["confirmed_state_digest"] == confirmed and changed["current_state_digest"] != confirmed
         and changed["for_review"]["requirement"] == "New body.\n"),
        ("05b removed → missing", by["CWE/4.14/CWE-22"]["adoption"] == "missing"),
        ("05b partial, only unchanged counted", c2 == 0 and second["data"]["status"] == "partial"
         and second["data"]["adopted_rules"] == ["CWE/4.14/CWE-79"]
         and any("confirm a new scope" in s for s in second["next_steps"])),
        ("05h none usable → maintenance_needed", c3 == 1 and third["data"]["status"] == "maintenance_needed"
         and third["data"]["adopted_rules"] == []),
    ]


def tc_invalid_record():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"))
    _, out, _, _ = resolve(p, "CWE/4.14/CWE-79")
    _, saved, _, _ = save(p, decisions(p, out, [adopt(out, "CWE/4.14/CWE-79")]))
    path = p / saved["data"]["path"]
    record = json.loads(path.read_text())
    record["adopted"][0]["rule"] = "CWE/4.14/CWE-89"
    path.write_text(json.dumps(record))
    c1, o1, _, _ = show(p, saved["data"]["scope_id"])
    path.write_text("{not json")
    c2, o2, _, e2 = show(p, saved["data"]["scope_id"])
    record["adopted"][0]["rule"] = "CWE/4.14/CWE-79"
    path.write_text(json.dumps({**record, "clues": "SURROGATE"}).replace('"SURROGATE"', '"\\ud800"'))
    c3, o3, _, e3 = show(p, saved["data"]["scope_id"])
    return [
        ("05d tampered refused", c1 == 1 and code_of(o1) == "SCOPE_INVALID" and o1["next_steps"]
         and "entries" not in o1["data"]),
        ("05d malformed refused", c2 == 1 and code_of(o2) == "SCOPE_INVALID" and "Traceback" not in e2),
        ("05d non-UTF-8 text refused (TASK-020)", c3 == 1 and code_of(o3) == "SCOPE_INVALID" and "Traceback" not in e3
         and bool(o3["next_steps"]) and "entries" not in o3["data"]),
    ]


def tc_confirmation_and_stale():
    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"), item("CWE/4.14/CWE-89"))
    _, out, _, _ = resolve(p, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89")
    path = decisions(p, out, [adopt(out, "CWE/4.14/CWE-79"), adopt(out, "CWE/4.14/CWE-89")])
    c1, o1, _, _ = save(p, path, confirmed=False)
    update(p, "CWE/4.14/CWE-89", entry(out, "CWE/4.14/CWE-89")["source_evidence"]["state_digest"], "Changed.\n")
    c2, o2, _, _ = save(p, path)
    _, all_out, _, _ = resolve(p, all_=True)
    all_path = decisions(p, all_out, [adopt(all_out, e["rule"]) for e in all_out["data"]["entries"]], mode="apply_all")
    imp(p, item("CWE/4.14/CWE-22"))
    c3, o3, _, _ = save(p, all_path)
    _, fresh, _, _ = resolve(p, "CWE/4.14/CWE-79", "CWE/4.14/CWE-89")
    removed_path = decisions(p, fresh, [adopt(fresh, "CWE/4.14/CWE-79"), adopt(fresh, "CWE/4.14/CWE-89")])
    shutil.rmtree(p / LOCAL / "CWE/4.14/CWE-89")
    c4, o4, _, _ = save(p, removed_path)
    return [
        ("05e no --confirmed refused", c1 == 1 and code_of(o1) == "CONFIRMATION_REQUIRED"),
        ("05f changed rule → STALE_CONFIRMATION naming it", c2 == 1 and code_of(o2) == "STALE_CONFIRMATION"
         and "CWE/4.14/CWE-89" in o2["problems"][0]["message"]
         and "CWE/4.14/CWE-79" not in o2["problems"][0]["message"]
         and any("confirm" in s.lower() for s in o2["next_steps"])),
        ("05f Apply All + new rule → STALE_CONFIRMATION", c3 == 1 and code_of(o3) == "STALE_CONFIRMATION"
         and "CWE/4.14/CWE-22" in o3["problems"][0]["message"]),
        ("05f removed rule → STALE_CONFIRMATION naming it", c4 == 1 and code_of(o4) == "STALE_CONFIRMATION"
         and "CWE/4.14/CWE-89" in o4["problems"][0]["message"]
         and "CWE/4.14/CWE-79" not in o4["problems"][0]["message"]
         and any("resolve" in x.lower() and "confirm" in x.lower() for x in o4["next_steps"])),
        ("05e/05f nothing written", not (p / SCOPES).exists()),
    ]


def tc_held_lock():
    import fcntl

    p = new_project()
    imp(p, item("CWE/4.14/CWE-79"))
    fd = os.open(p / LOCK, os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        code, out, _, err = resolve(p, "CWE/4.14/CWE-79")
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return [("NFR-1 LOCKED envelope", code == 1 and code_of(out) == "LOCKED" and out["next_steps"]
             and "Traceback" not in err)]


def tc_user_rights(revoke: bool):
    p = new_project()
    checks = []
    if revoke:
        imp(p, item("CWE/4.14/CWE-79"))
        imp(p, item("CWE/4.14/CWE-798", content=SECRET_LINE))
        sc_pty([PASS], "auth", "revoke")
    snap = tree(p / LOCAL, p / PENDING)
    code, out, _, _ = resolve(p, all_=True)
    checks.append(("01e knowledge/pending unchanged", tree(p / LOCAL, p / PENDING) == snap))
    if revoke:
        checks.append(("01e User resolves", code == 0 and out["data"]["status"] == "complete"))
        c, saved, _, _ = save(p, decisions(p, out, [adopt(out, "CWE/4.14/CWE-79")], mode="apply_all"))
        ci, oi, _, _ = imp(p, item("CWE/4.14/CWE-89"))
        checks += [("02f User saves scope", c == 0 and (p / saved["data"]["path"]).is_file()),
                   ("02f import still NOT_AUTHORIZED", ci == 1 and code_of(oi) == "NOT_AUTHORIZED")]
    else:
        checks.append(("01e/03a never-authorized User: maintenance_needed", code == 1
                       and out["data"]["status"] == "maintenance_needed"))
        cs, os_, _, _ = show(p, "sha256:" + "0" * 64)
        checks.append(("unknown scope → SCOPE_NOT_FOUND", cs == 1 and code_of(os_) == "SCOPE_NOT_FOUND"))
    return checks


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
        assert sc_pty([PASS, PASS], "auth", "init") == 0
        case("TC-C-01", ["AC-001C-01a", "AC-001C-01b", "AC-001C-01f"], tc_structure)
        case("TC-C-02", ["AC-001C-01c", "AC-001C-02a", "AC-001C-02b", "AC-001C-02c"], tc_mixed)
        case("TC-C-03", ["AC-001C-01d"], tc_damaged)
        case("TC-C-04", ["AC-001C-02d"], tc_language)
        case("TC-C-05", ["AC-001C-03a"], tc_empty)
        case("TC-C-06", ["AC-001C-03b"], tc_none_available)
        case("TC-C-07", ["AC-001C-03c", "AC-001C-03d", "AC-001C-02g"], tc_decisions)
        case("TC-C-08", ["AC-001C-04a", "AC-001C-04b", "AC-001C-04c"], tc_apply_all)
        case("TC-C-09", ["AC-001C-05a", "AC-001C-05c"], tc_record)
        case("TC-C-10", ["AC-001C-05b", "AC-001C-05g", "AC-001C-05h"], tc_drift_on_load)
        case("TC-C-11", ["AC-001C-05d"], tc_invalid_record)
        case("TC-C-12", ["AC-001C-05e", "AC-001C-05f"], tc_confirmation_and_stale)
        case("TC-C-13", ["NFR-001C-1"], tc_held_lock)
        case("TC-C-14", ["AC-001C-01e", "AC-001C-02f"], lambda: tc_user_rights(revoke=True))
    else:
        case("TC-C-15", ["AC-001C-01e", "AC-001C-03a"], lambda: tc_user_rights(revoke=False))
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
