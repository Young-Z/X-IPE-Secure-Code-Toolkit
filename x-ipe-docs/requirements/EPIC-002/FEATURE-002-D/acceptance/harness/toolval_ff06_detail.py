import json, os, subprocess, sys
sys.argv=["x"]; exec(open("/p2.py").read().split("for t in [")[0])
from pathlib import Path
d=Path("/w/tp"); d.mkdir(parents=True, exist_ok=True); (d/"plan.out").write_text(json.dumps(PLAN))
for pat in (None, "terraformplan-json:plan\\.out"):
    code,res,msgs=run(str(d),pat); print(json.dumps({"case":"ff06-terraformplan-json-detail","pattern":pat,"exit":code,"results":res,"msgs":msgs[:3]}))
d2=Path("/w/an"); d2.mkdir(parents=True, exist_ok=True); (d2/"site.yml").write_text(CASES["ansible"][1])
for pat in (None, "ansible:site\\.yml"):
    code,res,msgs=run(str(d2),pat); print(json.dumps({"case":"ff06-ansible-yaml-detail","pattern":pat,"exit":code,"results":res,"msgs":msgs[:3]}))
