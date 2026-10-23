"""Black-box acceptance scenarios for FEATURE-001-A (test-only artifact, TASK-007).

Calls the toolkit exactly as users do: `uvx --from <framework>/scripts secure-code ...`.
Never imports toolkit code. Prints one JSON object per test case on stdout.

  python3 blackbox.py host        # project init/status scenarios (no trust-store writes)
  FAT_ISOLATED=1 python3 blackbox.py container   # adds owner authorization (disposable HOME only!)
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
import time
from pathlib import Path

TOOLKIT = (Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ
           else Path(__file__).resolve().parents[5] / "ai-secure-code-toolkit")
FW = "x-ipe-secure-code-toolkit-framework"
SKILLS = (FW, "x-ipe-secure-code-toolkit-copilot", "x-ipe-secure-code-toolkit-guard")
BEGIN = "<!-- BEGIN ai-secure-code-toolkit"
PASS = "acceptance passphrase 42"
CANARY = "sk-acceptance-canary-9f8e7d"
LAYOUT = ["knowledge/local", "knowledge/reference", "presets", "tags", "improvements",
          "reports/copilot", "reports/guard"]
RESULTS: list[dict] = []
ENV = {**os.environ, "OPENAI_API_KEY": CANARY}
OUTPUTS: list[str] = []


def sc(*args: str, scripts: Path | None = None, inp: str | None = None, cwd: Path | None = None):
    cmd = ["uvx", "--from", str(scripts or TOOLKIT / FW / "scripts"), "secure-code", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, input=inp, cwd=cwd, env=ENV,
                          timeout=300)
    OUTPUTS.extend([proc.stdout, proc.stderr])
    data = None
    if "--json" in args:
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            data = None
    return proc.returncode, data, proc.stdout + proc.stderr


def sc_pty(answers: list[str], *args: str, timeout: int = 120):
    import pty

    cmd = ["uvx", "--from", str(TOOLKIT / FW / "scripts"), "secure-code", *args]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(cmd[0], cmd, ENV)
    out, sent, end = b"", 0, time.time() + timeout
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
    text = out.decode(errors="replace")
    OUTPUTS.append(text)
    return os.waitstatus_to_exitcode(status), text


def tree(*roots: Path) -> dict[str, str]:
    result = {}
    for root in roots:
        if root.exists():
            for p in sorted(root.rglob("*")):
                result[str(p)] = "dir" if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def case(tc: str, acs: list[str], fn) -> None:
    started = time.time()
    try:
        checks = fn()
        failed = [name for name, ok in checks if not ok]
        status = "Pass" if not failed else "Fail"
        detail = {"checks": [name for name, _ in checks], "failed": failed}
    except Exception as exc:  # noqa: BLE001 - any unexpected error is a failed case
        status, detail = "Fail", {"error": f"{type(exc).__name__}: {exc}"}
    RESULTS.append({"tc": tc, "acs": acs, "status": status,
                    "seconds": round(time.time() - started, 1), **detail})
    print(json.dumps(RESULTS[-1]), flush=True)


def new_project(name: str = "p") -> Path:
    root = Path(tempfile.mkdtemp(prefix="fat-")) / f"{name} ü"
    root.mkdir()
    return root


def init(project: Path, *extra: str, env: str | None = "github-copilot", scripts=None):
    args = ["init", "--project", str(project), "--json", *extra]
    if env:
        args += ["--env", env]
    return sc(*args, scripts=scripts)


def trust_dir() -> Path:
    home = Path(os.path.expanduser("~"))
    if sys.platform == "darwin":
        return home / "Library/Application Support/ai-secure-code-toolkit"
    return home / ".config/ai-secure-code-toolkit"


# ---------------------------------------------------------------- project init / status
def tc_init_fresh():
    p = new_project()
    before_trust = tree(trust_dir())
    code, out, _ = init(p)
    data_root = p / "x-ipe-docs/secure-code"
    agents = (p / "AGENTS.md").read_text(encoding="utf-8")
    return [
        ("exit 0", code == 0),
        ("three skills under .github/skills",
         all((p / ".github/skills" / s / "SKILL.md").is_file() for s in SKILLS)),
        ("framework scripts placed", (p / ".github/skills" / FW / "scripts/pyproject.toml").is_file()),
        ("dev tests not placed", not (p / ".github/skills" / FW / "scripts/tests").exists()),
        ("layout folders exist", all((data_root / d).is_dir() for d in LAYOUT)),
        ("no knowledge entries or presets", not [f for f in data_root.rglob("*") if f.is_file()]),
        ("one fragment in AGENTS.md", agents.count(BEGIN) == 1),
        ("environment named", bool(out) and out["data"]["environment"] == "github-copilot"),
        ("no .venv in project", not list(p.rglob(".venv"))),
        ("no X-IPE planning/config files",
         not (p / ".x-ipe.yaml").exists() and not (p / "x-ipe-docs/planning").exists()),
        ("trust store untouched", tree(trust_dir()) == before_trust),
    ]


def tc_init_bad_root():
    base = new_project("base")
    (base / "a-file").write_text("x")
    before = tree(base)
    results = []
    for args, expected in (([], "ROOT_REQUIRED"), (["--project", str(base / "missing")], "ROOT_INVALID"),
                           (["--project", str(base / "a-file")], "ROOT_INVALID")):
        code, out, _ = sc("init", "--env", "github-copilot", "--json", *args, cwd=base)
        results.append((f"{expected} for {args or 'no root'}",
                        code == 1 and out["problems"][0]["code"] == expected))
    results.append(("nothing written, no parent search", tree(base) == before))
    return results


def tc_explicit_env():
    p = new_project()
    (p / "AGENTS.md").write_text("team agents\n")
    (p / ".github").mkdir()
    code, out, _ = init(p, env="claude-code")
    return [
        ("exit 0", code == 0),
        ("claude-code used and named", out["data"]["environment"] == "claude-code"),
        ("skills in .claude/skills", all((p / ".claude/skills" / s / "SKILL.md").is_file() for s in SKILLS)),
        ("fragment in CLAUDE.md", BEGIN in (p / "CLAUDE.md").read_text()),
        ("AGENTS.md untouched", (p / "AGENTS.md").read_text() == "team agents\n"),
    ]


def tc_env_refused():
    p = new_project()
    before = tree(p)
    c1, o1, _ = init(p, env=None)
    c2, o2, _ = init(p, env="emacs")
    return [
        ("missing env -> ENV_REQUIRED", c1 == 1 and o1["problems"][0]["code"] == "ENV_REQUIRED"),
        ("unsupported -> ENV_UNSUPPORTED", c2 == 1 and o2["problems"][0]["code"] == "ENV_UNSUPPORTED"),
        ("supported environments listed",
         "github-copilot" in json.dumps(o1) and "claude-code" in json.dumps(o2)),
        ("nothing written", tree(p) == before),
    ]


def tc_fragment_preserves_user_bytes():
    p = new_project()
    original = "# Équipe\r\n\r\nRègles: soyez prudents.\r\n".encode()
    (p / "AGENTS.md").write_bytes(original)
    init(p)
    data = (p / "AGENTS.md").read_bytes()
    tail = data[len(original):]
    return [
        ("user bytes unchanged at start", data.startswith(original)),
        ("exactly one fragment", data.decode().count(BEGIN) == 1),
        ("CRLF style kept", b"\r\n" in tail and b"\n" not in tail.replace(b"\r\n", b"")),
    ]


def tc_fragment_rerun_edit_replace():
    p = new_project()
    init(p)
    first = (p / "AGENTS.md").read_bytes()
    init(p)
    unchanged = (p / "AGENTS.md").read_bytes() == first
    edited = first.replace(b"does not fix", b"does NOT fix")
    (p / "AGENTS.md").write_bytes(edited)
    code, out, _ = init(p)
    kept = (p / "AGENTS.md").read_bytes() == edited
    reported = any(x["code"] == "FRAGMENT_EDITED" for x in out["problems"])
    init(p, "--replace", "AGENTS.md")
    return [
        ("rerun adds no second fragment", unchanged),
        ("edited fragment kept", code == 0 and kept and edited != first),
        ("edit reported", reported),
        ("replaced only on explicit choice", (p / "AGENTS.md").read_bytes() == first),
    ]


def tc_reinit_same():
    p = new_project()
    init(p)
    before = tree(p)
    code, out, _ = init(p)
    return [("exit 0", code == 0), ("already current reported", out["data"]["already_current"] is True),
            ("no file modified", tree(p) == before)]


def tc_reinit_newer():
    p = new_project()
    init(p)
    (p / "x-ipe-docs/secure-code/reports/guard/r.md").write_text("report\n")
    data_before = tree(p / "x-ipe-docs")
    copilot = p / ".github/skills" / SKILLS[1] / "SKILL.md"
    guard = p / ".github/skills" / SKILLS[2] / "SKILL.md"
    copilot.write_text(copilot.read_text() + "\nMy local note.\n")
    newer = Path(tempfile.mkdtemp(prefix="fat-src-")) / "toolkit"
    shutil.copytree(TOOLKIT, newer, ignore=shutil.ignore_patterns(
        ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".coverage*"))
    for s in SKILLS[1:]:
        f = newer / s / "SKILL.md"
        f.write_text(f.read_text() + "\nUpstream v2 line.\n")
    code, out, _ = init(p, "--toolkit-source", str(newer))
    rel_c = f".github/skills/{SKILLS[1]}/SKILL.md"
    rel_g = f".github/skills/{SKILLS[2]}/SKILL.md"
    checks = [
        ("exit 0", code == 0),
        ("unedited file updated and listed",
         rel_g in out["data"]["files"]["updated"] and "Upstream v2 line." in guard.read_text()),
        ("edited file kept",
         "My local note." in copilot.read_text() and "Upstream v2 line." not in copilot.read_text()),
        ("edited file reported", rel_c in out["data"]["files"]["locally_edited"]
         and any(x["code"] == "LOCALLY_EDITED" for x in out["problems"])),
    ]
    code, out, _ = init(p, "--toolkit-source", str(newer), "--replace", rel_c)
    checks += [
        ("replaced on explicit choice",
         rel_c in out["data"]["files"]["replaced"] and "Upstream v2 line." in copilot.read_text()),
        ("secure-code data byte-identical", tree(p / "x-ipe-docs") == data_before),
    ]
    return checks


def tc_status_fresh():
    p = new_project()
    init(p)
    before = tree(p, trust_dir())
    code, out, _ = sc("status", "--project", str(p), "--json")
    text_code, _, text = sc("status", "--project", str(p))
    d = out["data"]
    auth = d["authorization"]
    return [
        ("exit 0", code == 0 and text_code == 0),
        ("install reported", d["install"]["state"] == "installed" and bool(d["install"]["version"])),
        ("authorization state with next step", auth["state"] in ("not_initialized", "valid", "revoked")
         and bool(auth["next_step"])),
        ("policies 0/0 with Maintainer next step", d["policies"]["local"] == 0
         and d["policies"]["reference"] == 0 and "Maintainer" in d["policies"]["next_step"]),
        ("each tool on its own line with next step", set(d["tools"]) == {"opengrep", "trivy", "strix"}
         and all(t["next_step"] for t in d["tools"].values())),
        ("host integration present, effect not verified", d["host_integration"]["fragment"] == "present"
         and d["host_integration"]["host_effect"] == "not verified"),
        ("no aggregate Ready", "ready" not in json.dumps(out).lower() and "ready" not in text.lower()),
        ("text sections", all(s in text for s in ("Install", "Authorization", "Policies", "Tools",
                                                  "Host integration"))),
        ("nothing created/modified (project + trust store)", tree(p, trust_dir()) == before),
    ]


def tc_status_details():
    p = new_project()
    init(p)
    (p / "x-ipe-docs/secure-code/tags").rmdir()
    (p / "x-ipe-docs/secure-code/presets/default.json").write_text("{}")
    _, out, _ = sc("status", "--project", str(p), "--json")
    d = out["data"]
    return [
        ("root reported", Path(d["install"]["root"]) == p.resolve()),
        ("install entry location", d["install"]["skills_dir"] == ".github/skills"),
        ("default preset detected", d["default_preset"]["exists"] is True),
        ("configuration problem reported", any("tags" in x["message"] for x in d["problems"])),
    ]


def tc_status_not_installed():
    parent = new_project("parent")
    child = parent / "child"
    child.mkdir()
    init(parent)
    _, out, _ = sc("status", "--project", str(child), "--json")
    d = out["data"]["install"]
    return [("not installed", d["state"] == "not installed"),
            ("init next step", "secure-code init" in d["next_step"]),
            ("child root, no parent lookup", Path(d["root"]) == child.resolve())]


# ---------------------------------------------------------------- owner authorization
def wipe_trust():
    shutil.rmtree(trust_dir(), ignore_errors=True)


def tc_auth_non_interactive():
    wipe_trust()
    c1, o1, _ = sc("auth", "init", "--json", inp=f"{PASS}\n{PASS}\n")
    c2, o2, _ = sc("auth", "revoke", "--json", inp=f"{PASS}\n")
    return [("init piped -> NOT_INTERACTIVE", c1 == 1 and o1["problems"][0]["code"] == "NOT_INTERACTIVE"),
            ("revoke piped -> NOT_INTERACTIVE", c2 == 1 and o2["problems"][0]["code"] == "NOT_INTERACTIVE"),
            ("no trust files created", not (trust_dir() / "trust").exists())]


def tc_auth_mismatch_and_nothing_to_revoke():
    wipe_trust()
    c1, t1 = sc_pty([PASS, PASS + "!"], "auth", "init")
    created = (trust_dir() / "trust").exists()
    c2, t2 = sc_pty([], "auth", "revoke")
    return [("mismatch refused", c1 == 1 and "PASSPHRASE_MISMATCH" in t1),
            ("nothing created", not created),
            ("revoke with nothing authorized reports it", c2 == 0 and "nothing_authorized" in t2),
            ("nothing changed", not (trust_dir() / "trust").exists())]


def tc_auth_lifecycle():
    wipe_trust()
    a, b = new_project("a"), new_project("b")
    c, text = sc_pty([PASS, PASS], "auth", "init")
    t = trust_dir() / "trust"
    pub_before = (t / "trusted-public-key.pem").read_bytes()
    _, sa, _ = sc("auth", "status", "--json", cwd=a)
    _, sb, _ = sc("auth", "status", "--json", cwd=b)
    c_again, t_again = sc_pty([PASS, PASS], "auth", "init")
    state = json.loads((t / "trust-state.json").read_text())
    grant_path = t / "grants" / f"{state['current_grant_id']}.json"
    saved_grant = grant_path.read_bytes()
    c_wrong, t_wrong = sc_pty(["wrong passphrase!!"], "auth", "revoke")
    _, after_wrong, _ = sc("auth", "status", "--json")
    c_rev, _ = sc_pty([PASS], "auth", "revoke")
    _, after_rev, _ = sc("auth", "status", "--json")
    p = new_project("st")
    init(p)
    _, st, _ = sc("status", "--project", str(p), "--json")
    grant_path.write_bytes(saved_grant)
    _, restored, _ = sc("auth", "status", "--json")
    c_re, _ = sc_pty([PASS], "auth", "init")
    _, re_status, _ = sc("auth", "status", "--json")
    new_state = json.loads((t / "trust-state.json").read_text())
    (t / "grants" / f"{new_state['current_grant_id']}.json").write_bytes(saved_grant)
    _, restored2, _ = sc("auth", "status", "--json")
    return [
        ("06a init exit 0", c == 0),
        ("06a trust files outside project, signing key encrypted",
         (t / "signing-key.pem").read_bytes().startswith(b"-----BEGIN ENCRYPTED")
         and Path.home() in t.parents),
        ("06a/07d Maintainer from two workspaces",
         sa["data"]["role"] == sb["data"]["role"] == "maintainer"),
        ("first init detectable: created_at/created_by",
         bool(sa["data"]["created_at"]) and bool(sa["data"]["created_by"]["os_user"])),
        ("06e passphrase/key not printed", PASS not in text and "PRIVATE KEY" not in text),
        ("06c second init refused", c_again == 1 and "ALREADY_INITIALIZED" in t_again),
        ("08b wrong passphrase refused, unchanged", c_wrong == 1 and "PASSPHRASE_WRONG" in t_wrong
         and after_wrong["data"]["state"] == "valid"),
        ("08a revoked -> User", c_rev == 0 and after_rev["data"]["role"] == "user"
         and after_rev["data"]["state"] == "revoked"),
        ("09e status shows revoked + next step", st["data"]["authorization"]["state"] == "revoked"
         and bool(st["data"]["authorization"]["next_step"])),
        ("08d restored grant after revoke rejected", restored["data"]["role"] == "user"),
        ("06f re-auth with existing passphrase, same trust root", c_re == 0
         and re_status["data"]["role"] == "maintainer"
         and (t / "trusted-public-key.pem").read_bytes() == pub_before),
        ("08d old grant restored over new one rejected", restored2["data"]["role"] == "user"),
    ]


def tc_auth_partial_and_invalid():
    wipe_trust()
    sc_pty([PASS, PASS], "auth", "init")
    t = trust_dir() / "trust"
    state = json.loads((t / "trust-state.json").read_text())
    (t / "grants" / f"{state['current_grant_id']}.json").unlink()
    snapshot = sorted(str(x) for x in t.rglob("*"))
    c, text = sc_pty([PASS, PASS], "auth", "init")
    after = sorted(str(x) for x in t.rglob("*"))
    (t / "trusted-public-key.pem").write_text("garbage")
    p = new_project()
    init(p)
    _, st, _ = sc("status", "--project", str(p), "--json")
    a = st["data"]["authorization"]
    return [("06g partial state refused", c == 1 and "TRUST_PARTIAL" in text),
            ("06g no new trust root", after == snapshot),
            ("09e invalid shown with reason, role User",
             a["state"] == "invalid" and a["role"] == "user" and bool(a["reason"]))]


def tc_no_secrets():
    blob = "\n".join(OUTPUTS)
    files = ""
    # Project folders only (AC-001A-10b); fat-src-* is the copied toolkit source with its dev tests.
    for root in Path(tempfile.gettempdir()).glob("fat-*"):
        if root.name.startswith("fat-src-"):
            continue
        for f in root.rglob("*"):
            if f.is_file() and ".venv" not in f.parts:
                files += f.read_bytes().decode(errors="replace")
    return [("no model credential in outputs/project files", CANARY not in blob and CANARY not in files),
            ("no passphrase in outputs/project files", PASS not in blob and PASS not in files),
            # Real key material carries the PEM header; the shipped pre-check pattern only mentions the words.
            ("no private key material", "-----BEGIN ENCRYPTED PRIVATE KEY-----" not in blob
             and "-----BEGIN ENCRYPTED PRIVATE KEY-----" not in files)]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    if mode == "container" and os.environ.get("FAT_ISOLATED") != "1":
        print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
        return 2
    case("TC-INT-01", ["AC-001A-04a", "AC-001A-04c", "AC-001A-04e"], tc_init_fresh)
    case("TC-INT-02", ["AC-001A-04b"], tc_init_bad_root)
    case("TC-INT-03", ["AC-001A-04f"], tc_explicit_env)
    case("TC-INT-04", ["AC-001A-04g"], tc_env_refused)
    case("TC-INT-05", ["AC-001A-04h"], tc_fragment_preserves_user_bytes)
    case("TC-INT-06", ["AC-001A-04i"], tc_fragment_rerun_edit_replace)
    case("TC-INT-07", ["AC-001A-05a"], tc_reinit_same)
    case("TC-INT-08", ["AC-001A-05b", "AC-001A-05c", "AC-001A-05d"], tc_reinit_newer)
    case("TC-INT-09", ["AC-001A-09a", "AC-001A-09b"], tc_status_fresh)
    case("TC-INT-10", ["AC-001A-09c"], tc_status_details)
    case("TC-INT-11", ["AC-001A-09d"], tc_status_not_installed)
    if mode == "container":
        case("TC-INT-12", ["AC-001A-06b", "AC-001A-08b"], tc_auth_non_interactive)
        case("TC-INT-13", ["AC-001A-06d", "AC-001A-08c"], tc_auth_mismatch_and_nothing_to_revoke)
        case("TC-INT-14", ["AC-001A-06a", "AC-001A-06c", "AC-001A-06e", "AC-001A-06f", "AC-001A-07d",
                           "AC-001A-08a", "AC-001A-08b", "AC-001A-08d", "AC-001A-09e"], tc_auth_lifecycle)
        case("TC-INT-15", ["AC-001A-06g", "AC-001A-09e"], tc_auth_partial_and_invalid)
    case("TC-INT-16", ["AC-001A-10b"], tc_no_secrets)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform,
                                  "python": sys.version.split()[0], "passed": passed,
                                  "total": len(RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
