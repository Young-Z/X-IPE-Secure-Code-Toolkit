"""Test double emulating observed Opengrep v1.31.0 behaviour (tool-validation fixtures).

Tests copy this file into an executable with an absolute interpreter and an embedded CONFIG path.
Behaviour: languages python (.py), java (.java), generic (all files); folders named `tests` are
skipped (reported only because `--verbose` is passed) unless --x-ignore-semgrepignore-files; lines
containing `VULN` produce a result; other-language files are neither scanned nor skipped. Like the real
binary it unpacks its runtime into `$XDG_CACHE_HOME/opengrep/` and exits 0 without any output when that
path has non-ASCII characters (observed in acceptance TASK-031).
"""

import hashlib
import json
import os
import subprocess
import sys
import time

import yaml

CONFIG = "__CONFIG__"
EXT = {"python": (".py",), "java": (".java",)}


def main():
    cfg = json.load(open(CONFIG)) if os.path.exists(CONFIG) else {}
    mode = cfg.get("mode", "normal")
    with open(os.path.join(os.path.dirname(CONFIG), "invocations.jsonl"), "a") as log:
        log.write(
            json.dumps(
                {
                    "argv": sys.argv,
                    "env": sorted(os.environ),
                    "cwd": os.getcwd(),
                    "home": os.environ.get("HOME"),
                    "cache": os.environ.get("XDG_CACHE_HOME"),
                    "config_sha": [
                        "sha256:" + hashlib.sha256(open(sys.argv[i + 1], "rb").read()).hexdigest()
                        for i, a in enumerate(sys.argv)
                        if a == "--config"
                    ],
                }
            )
            + "\n"
        )
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.environ.get("HOME", ""), ".cache")
    if not cache.isascii():
        return 0
    os.makedirs(os.path.join(cache, "opengrep", "v1.31.0"), exist_ok=True)
    open(os.path.join(cache, "opengrep", "v1.31.0", "runtime.so"), "w").write("runtime")
    args = sys.argv[1:]
    assert args[0] == "scan", args
    flags, targets, config = set(), [], None
    i = 1
    while i < len(args):
        if args[i] == "--config":
            config = args[i + 1]
            i += 2
            continue
        if args[i].startswith("--"):
            flags.add(args[i])
        else:
            targets.append(args[i])
        i += 1
    if mode == "sleep":
        subprocess.Popen(["sleep", "120"])
        time.sleep(120)
    if mode == "nap":
        time.sleep(float(cfg.get("nap", 2)))
    if mode == "silent":
        return 0
    if mode == "garbage":
        print("this is not json")
        return 0
    if mode == "flood":
        sys.stdout.write("x" * (40 * 1024 * 1024))
        return 0
    rule = yaml.safe_load(open(config))["rules"][0]
    langs = rule["languages"]
    if mode == "write":
        for folder in (os.getcwd(), os.environ["HOME"]):
            open(os.path.join(folder, "tool-wrote.txt"), "w").write("x")
        for t in targets:
            base = t if os.path.isdir(t) else os.path.dirname(t)
            open(os.path.join(base, "tool-wrote-in-copy.txt"), "w").write("x")
        os.makedirs(os.path.join(os.environ["HOME"], ".opengrep"), exist_ok=True)
        open(os.path.join(os.environ["HOME"], ".opengrep", "semgrep.log"), "w").write("log")
    if mode == "git" and "--no-git-ignore" not in flags:
        targets = []  # observed: in a git work tree, files not listed by `git ls-files` are skipped
    scanned, skipped, results = [], [], []
    files = []
    for t in targets:
        if os.path.isdir(t):
            for dirpath, dirnames, filenames in os.walk(t):
                if os.path.basename(dirpath) == "tests" and "--x-ignore-semgrepignore-files" not in flags:
                    skipped.append({"path": dirpath, "reason": "semgrepignore_patterns_match"})
                    dirnames[:] = []
                    continue
                files += [os.path.join(dirpath, f) for f in filenames]
        else:
            files.append(t)
    for f in sorted(files):
        if "generic" not in langs and not any(f.endswith(e) for lang in langs for e in EXT.get(lang, ())):
            continue
        scanned.append(f)
        try:
            text = open(f, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        for n, line in enumerate(text, 1):
            if "VULN" in line:
                results.append(
                    {
                        "check_id": f"stage.rules.{rule['id']}",
                        "path": f,
                        "start": {"line": n, "col": 1},
                        "end": {"line": n, "col": 2},
                        "extra": {
                            "severity": rule.get("severity", "WARNING"),
                            "message": rule.get("message", "") + " :: " + line.strip(),
                            "metadata": rule.get("metadata", {}),
                            "lines": line,
                            "fingerprint": "ab" * 20,
                            "metavars": {"$X": {"abstract_content": line}},
                        },
                    }
                )
    doc = {
        "version": "1.31.0",
        "results": results,
        "errors": [],
        "skipped_rules": [],
        "paths": {"scanned": scanned, "skipped": skipped},
        "interfile_languages_used": [],
    }
    if mode == "errors":
        doc["errors"] = [
            {"type": "SemgrepError", "level": "error", "message": "something failed in " + targets[0]}
        ]
    if mode == "skipped_rule":
        doc["skipped_rules"] = [{"rule_id": rule["id"]}]
    if mode == "exit7":
        doc = {
            "version": "1.31.0",
            "results": [],
            "paths": {"scanned": []},
            "skipped_rules": [],
            "errors": [{"type": "InvalidRuleSchemaError", "level": "error", "message": "bad rule"}],
        }
        print(json.dumps(doc))
        return 7
    print(json.dumps(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
