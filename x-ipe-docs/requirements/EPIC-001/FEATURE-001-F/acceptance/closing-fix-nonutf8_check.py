"""TASK-071 closing-review fix: real raw-bytes (non-UTF-8) file names in presets/ and tags/ on Linux ext4/overlay.
Runs inside the disposable offline container only (FAT_ISOLATED=1); reuses the FEATURE-001-F acceptance runner."""
import json, os, shutil, sys
sys.path.insert(0, "/fat")
import blackbox as bb  # noqa: E402

def tc():
    p = bb.base_project()
    bb.pnew(p, "good", [bb.R89])
    bb.must(bb.tsave(p, "good-tag", [bb.R89]), "tag")
    for rel in (bb.PRESETS, bb.TAGS):
        fd = os.open(os.fsencode(str(p / rel)) + b"/\xff.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.write(fd, b"{}"); os.close(fd)
    shown = "\\xff.json"
    res = bb.preview(p, bb.R89, "deactivate")
    lk, pl, tl = bb.links(p), bb.plist(p), bb.tlist(p)
    imp = (res[1] or {}).get("data", {}).get("impact", {})
    bb.INFO.update(preview=res[2][-800:] + res[3][-800:], links=lk[3][-800:])
    ext = ((lk[1] or {}).get("data") or {}).get("preset_tag_links", {})
    checks = [
        ("raw-bytes name created on this filesystem", any(n == b"\xff.json" for n in os.listdir(os.fsencode(str(p / bb.PRESETS))))),
        ("preview ok; raw-bytes names are unreadable findings with a printable name",
         bb.ok(res) and [u["file"] for u in imp["presets"]["unreadable"]] == [shown]
         and [u["file"] for u in imp["tags"]["unreadable"]] == [shown] and bb.names(imp, "presets") == ["good"]),
        ("links ok; both reported unreadable",
         bb.ok(lk) and sorted((u["kind"], u["file"]) for u in ext.get("unreadable", [])) == [("preset", shown), ("tag", shown)]),
        ("preset list / tag list ok; name reported invalid",
         bb.ok(pl) and [i["file"] for i in pl[1]["data"]["invalid"]] == [shown]
         and bb.ok(tl) and [i["file"] for i in tl[1]["data"]["invalid"]] == [shown]),
    ]
    digest = res[1]["data"]["impact_digest"] if bb.ok(res) else None
    checks.append(("exit-confirm succeeds with that preview digest", bb.ok(bb.confirm(p, bb.R89, "deactivate", digest))))
    return checks

if os.environ.get("FAT_ISOLATED") != "1":
    sys.exit("container only")
shutil.rmtree(bb.APP, ignore_errors=True)
assert bb.sc_pty([(b"passphrase", bb.PASS), (b"passphrase", bb.PASS)], "auth", "init")[0] == 0
bb.case("TC-F-CLOSE-01", ["AC-001F-06f", "AC-001F-06e", "AC-001F-08a"], tc)
sys.exit(0 if all(r["status"] == "Pass" for r in bb.RESULTS) else 1)
