"""Pre-001-E golden outputs of a Local-only project (design Implementation Step 1a; DEC-08/09/14).

`local_only_outputs(work)` builds a deterministic Local-only project with the delivered services and
returns the JSON results of the Local-only commands named by AC-001E-07e. It was run once on the
unmodified code (`capture`) to write `fixtures/golden/pre001e/`; `test_reference_plugins.py` runs it
again after FEATURE-001-E and compares byte for byte. Only the fields listed as volatile in
`MANIFEST.json` are normalized (paths, times, run ids, host name, OS user).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "golden" / "pre001e"
VOLATILE = [
    "absolute temporary paths (replaced by <folder name>)",
    "timestamps matching YYYY-MM-DDTHH:MM:SS[.f]Z (created_at, at, opened_at, ...)",
    "verification/collaboration/exit ids (<run-id>)",
    "host name and OS user of the authorization record",
]
R4_15 = "CWE/4.15/CWE-79"


def _cli(trust: Path, *args: str) -> str:
    from x_ipe_secure_code import cli
    from x_ipe_secure_code.auth import trust_store

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(trust_store, "default_app_dir", lambda: trust)
        result = cli.run(cli.build_parser().parse_args([*args, "--json"]))
    return json.dumps([0 if result.ok else 1, json.loads(result.to_json())], indent=2, ensure_ascii=False)


def local_only_outputs(work: Path) -> dict[str, str]:
    """Normalized JSON outputs of the Local-only commands (frozen knowledge/exit/scope clocks)."""
    from drafting.drafthelp import normalise
    from knowledge.exithelp import R1, R2, R3, item
    from presets.presethelp import PEnv, freeze

    project = work / "golden project"
    project.mkdir()
    out: dict[str, str] = {}
    with pytest.MonkeyPatch.context() as patch:
        freeze(patch)
        from x_ipe_secure_code.knowledge import presets

        patch.setattr(presets, "_now", lambda: "2026-10-22T08:00:00+00:00")
        env = PEnv(project, work)
        assert env.load(item(), item(R2), item(R3), item(R4_15)).ok
        p = str(project)
        out["resolve-rules.json"] = _cli(
            env.trust, "policy", "resolve", "--project", p, "--rule", R1, "--rule", R2, "--language", "python"
        )
        out["resolve-all.json"] = _cli(env.trust, "policy", "resolve", "--project", p, "--all")
        out["resolve-versionless.json"] = _cli(
            env.trust, "policy", "resolve", "--project", p, "--rule", "CWE/CWE-79", "--rule", "CWE/NOPE"
        )
        decisions = env.decisions((R2, R3))
        saved = _cli(env.trust, "scope", "save", "--project", p, "--decisions", decisions, "--confirmed")
        out["scope-save.json"] = saved
        scope_id = json.loads(saved)[1]["data"]["scope_id"]
        out["scope-show.json"] = _cli(env.trust, "scope", "show", "--project", p, "--scope", scope_id)
        assert env.tsave(members=[R2, R3]).ok
        out["tag-show.json"] = _cli(env.trust, "tag", "show", "injection", "--project", p)
        assert env.psave(rules=[R2, R3]).ok
        out["preset-resolve.json"] = _cli(
            env.trust, "preset", "resolve", "web-input", "--project", p, "--language", "python"
        )
        out["exit-preview.json"] = _cli(
            env.trust,
            "knowledge",
            "exit-preview",
            "--project",
            p,
            "--rule",
            R3,
            "--action",
            "deactivate",
            "--reason",
            "fixture reason",
        )
        out["status.json"] = _cli(env.trust, "status", "--project", p)
    return {k: normalise(v, project, work) for k, v in sorted(out.items())}


def src_digest() -> str:
    """SHA-256 over (relative path, file SHA-256) of every source file of the toolkit package."""
    src = Path(__file__).resolve().parents[2] / "src" / "x_ipe_secure_code"
    lines = [
        f"{p.relative_to(src).as_posix()} {hashlib.sha256(p.read_bytes()).hexdigest()}"
        for p in sorted(src.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    ]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def capture(work: Path) -> None:  # pragma: no cover - run once on the delivered code (Step 1a)
    outputs = local_only_outputs(work)
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        (GOLDEN / name).write_text(text + "\n", encoding="utf-8")
    manifest = {"captured_with_src_sha256": src_digest(), "files": sorted(outputs), "volatile": VOLATILE}
    (GOLDEN.parent / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    tests = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(tests), str(tests / "presets")]
    import conftest  # noqa: F401 - puts src/ and tests/support on sys.path

    capture(Path(sys.argv[1]))
