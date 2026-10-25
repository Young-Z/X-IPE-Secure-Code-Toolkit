"""TASK-112 D-1 re-run: the UNCHANGED acceptance runner (acceptance/blackbox.py, TASK-111) imported as a module and
driven for TC-F-20 (prerequisite: registration of the local image in a disposable trust store via maint.py),
TC-F-21 (real conformance) and TC-F-27 (real helper limit runs) only, against the frozen copy of the fixed tree.

    TOOLKIT_ROOT=<EV>/frozen/ai-secure-code-toolkit FAT_WORK=<EV>/work-d1 HANDOFF=<EV>/handoff \
        python3 rerun_d1.py > evidence-host-macos-d1.jsonl
"""

from __future__ import annotations

import sys
from pathlib import Path

ACC = Path("/Users/yzhang/Documents/projects/ai-secure-code-toolkit-v2/x-ipe-docs/requirements/EPIC-002/FEATURE-002-F/acceptance")
sys.path.insert(0, str(ACC))
sys.argv = [str(ACC / "blackbox.py"), "host"]

import blackbox as bb  # noqa: E402


def main() -> int:
    bb.WORK.mkdir(parents=True, exist_ok=True)
    bb.install_wrapper()
    bb.fault()
    bb.INFO["frozen"] = str(bb.TOOLKIT)
    bb.INFO["subset"] = "TASK-112 D-1 re-run: TC-F-20 (prerequisite), TC-F-21, TC-F-27"
    bb.case("TC-F-20", ["AC-002F-11a", "AC-002F-11d", "AC-002F-08f", "AC-002F-04c"], bb.tc_register)
    if bb.RESULTS[-1]["status"] != "Pass" and not (bb.WORK / "trust").exists():
        bb.summary("host-d1")
        return 1
    bb.case("TC-F-21", ["AC-002F-11b", "AC-002F-04l", "AC-002F-08f", "AC-002F-11d"], bb.tc_conformance)
    bb.case("TC-F-27", ["AC-002F-07g", "AC-002F-04m", "AC-002F-04l", "AC-002F-04k"], bb.tc_results_b)
    bb.fault()
    bb.INFO["docker_calls"] = len(bb.dlog())
    bb.INFO["forbidden_calls_total"] = bb.forbidden_calls(0)
    bb.INFO["all_creates_network_none"] = bb.network_none(bb.creates_since(0))
    bb.INFO["creates_total"] = len(bb.creates_since(0))
    bb.INFO["leftovers_end"] = bb.leftovers()
    bb.summary("host-d1")
    return 0 if all(r["status"] == "Pass" for r in bb.RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
