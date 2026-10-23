import json, os, subprocess
from pathlib import Path
B="/tv/ARM64/trivy"
F=["--skip-db-update","--skip-java-db-update","--skip-check-update","--offline-scan","--skip-version-check","--disable-telemetry","--no-progress","--format","json","--cache-dir","/cache","--debug","--list-all-pkgs"]
ENV={"PATH":"/bin:/usr/bin","HOME":"/w/h","TMPDIR":"/w/t","TZ":"UTC"}
for d in ("/w/h","/w/t"): os.makedirs(d,exist_ok=True)
lock=lambda name,ver:{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":True,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{name:ver}},f"node_modules/{name}":{"version":ver}}}
C={"pip-requests":("requirements.txt","requests==2.19.0\n"),
   "pip-urllib3":("requirements.txt","urllib3==1.24.1\n"),
   "npm-lodash":("package-lock.json",json.dumps(lock("lodash","4.17.4"))),
   "npm-minimist":("package-lock.json",json.dumps(lock("minimist","1.2.0"))),
   "cargo-smallvec":("Cargo.lock",'version = 3\n\n[[package]]\nname = "smallvec"\nversion = "0.6.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'),
   "composer-guzzle":("composer.lock",json.dumps({"packages":[{"name":"guzzlehttp/guzzle","version":"6.5.0"}],"packages-dev":[]})),
   "gem-rack":("Gemfile.lock","GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.0.1)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n\nBUNDLED WITH\n   2.1.4\n"),
}
for k,(n,body) in C.items():
    d=Path(f"/w/{k}"); d.mkdir(parents=True,exist_ok=True); (d/n).write_text(body)
    p=subprocess.run([B,"fs","--scanners","vuln",*F,str(d)],capture_output=True,text=True,env=ENV)
    doc=json.loads(p.stdout) if p.stdout.strip().startswith("{") else {}
    res=[(r["Target"],len(r.get("Packages") or []),len(r.get("Vulnerabilities") or [])) for r in doc.get("Results") or []]
    w=[l.split("\t")[2] for l in p.stderr.splitlines() if len(l.split("\t"))>2 and l.split("\t")[1] in ("WARN","ERROR","FATAL")]
    sk=[l.split("\t")[2] for l in p.stderr.splitlines() if "Skipping vulnerability scan" in l]
    print(json.dumps({"case":k,"exit":p.returncode,"results":res,"warn":w,"skipped":sk}))
