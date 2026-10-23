"""FF-06: --file-patterns <type>:<regex> per CONFIG_TYPES name, real Trivy v0.76.1, offline (tool level)."""
import json, os, re, shutil, subprocess
from pathlib import Path
B = "/tv/ARM64/trivy"
F = ["--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan", "--skip-version-check",
     "--disable-telemetry", "--no-progress", "--format", "json", "--cache-dir", "/cache"]
ENV = {"PATH": "/bin:/usr/bin", "HOME": "/w/h", "TMPDIR": "/w/t", "TZ": "UTC"}
for d in ("/w/h", "/w/t"):
    os.makedirs(d, exist_ok=True)
FX = Path("/fx/misconfig")
PLAN = {"format_version": "1.2", "terraform_version": "1.6.0",
        "planned_values": {"root_module": {"resources": [{"address": "aws_s3_bucket.demo", "mode": "managed",
            "type": "aws_s3_bucket", "name": "demo", "provider_name": "registry.terraform.io/hashicorp/aws",
            "schema_version": 0, "values": {"bucket": "demo-bucket", "acl": "public-read"}}]}},
        "resource_changes": [{"address": "aws_s3_bucket.demo", "mode": "managed", "type": "aws_s3_bucket", "name": "demo",
            "provider_name": "registry.terraform.io/hashicorp/aws", "change": {"actions": ["create"], "before": None,
            "after": {"bucket": "demo-bucket", "acl": "public-read"}}}],
        "configuration": {"root_module": {"resources": [{"address": "aws_s3_bucket.demo", "mode": "managed",
            "type": "aws_s3_bucket", "name": "demo", "provider_config_key": "aws",
            "expressions": {"bucket": {"constant_value": "demo-bucket"}, "acl": {"constant_value": "public-read"}},
            "schema_version": 0}]}}}
CFN = 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n'
ARM = json.dumps({"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                  "contentVersion": "1.0.0.0", "resources": [{"type": "Microsoft.Storage/storageAccounts",
                  "apiVersion": "2021-02-01", "name": "fatdemo", "location": "westeurope", "kind": "StorageV2",
                  "sku": {"name": "Standard_LRS"}, "properties": {"supportsHttpsTrafficOnly": False,
                  "minimumTlsVersion": "TLS1_0"}}]})
ANS = ("- name: Provision storage\n  hosts: localhost\n  tasks:\n    - name: Create a public bucket\n"
       "      amazon.aws.s3_bucket:\n        name: fat-demo-bucket\n        state: present\n        public_access:\n"
       "          block_public_acls: false\n          block_public_policy: false\n          ignore_public_acls: false\n"
       "          restrict_public_buckets: false\n")
CASES = {  # type -> (file name not matched by default, content)
    "dockerfile": ("Dockerfile_desktop", (FX / "Dockerfile").read_text()),
    "kubernetes": ("deploy.manifest", (FX / "deployment.yaml").read_text()),
    "terraform": ("bucket.tfx", 'resource "aws_s3_bucket" "demo" {\n  bucket = "demo-bucket"\n  acl    = "public-read"\n}\n'),
    "cloudformation": ("stack.cfn", CFN),
    "azure-arm": ("arm.tmpl", ARM),
    "terraformplan-json": ("plan.out", json.dumps(PLAN)),
    "ansible": ("site.playbook", ANS),
    "helm": (None, None), "terraformplan-snapshot": (None, None),
}
def run(folder, pattern=None):
    argv = [B, "fs", "--scanners", "misconfig", *F] + (["--file-patterns", pattern] if pattern else []) + [folder]
    p = subprocess.run(argv, capture_output=True, text=True, env=ENV)
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        doc = {}
    res = {r["Target"]: {"type": r.get("Type"), "summary": r.get("MisconfSummary"),
                         "fail": len([m for m in r.get("Misconfigurations") or [] if m.get("Status") == "FAIL"])}
           for r in doc.get("Results") or []}
    msgs = [l.split("\t")[1] + " " + l.split("\t")[2] for l in p.stderr.splitlines()
            if len(l.split("\t")) > 2 and l.split("\t")[1] in ("WARN", "ERROR", "FATAL")]
    return p.returncode, res, msgs
for t in ["azure-arm", "cloudformation", "dockerfile", "helm", "kubernetes", "terraform", "terraformplan-json",
          "terraformplan-snapshot", "ansible", "compose", "bogus"]:
    code, res, msgs = run("/w/empty" if os.makedirs("/w/empty", exist_ok=True) is None else "", f"{t}:nomatch\\.zzz")
    rec = {"case": "ff06-syntax", "type": t, "exit": code, "warn_error_fatal": msgs[:3]}
    name, body = CASES.get(t, (None, None))
    if name:
        d = Path(f"/w/eff-{t}")
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(body)
        c0, r0, m0 = run(str(d))
        c1, r1, m1 = run(str(d), f"{t}:{re.escape(name)}")
        rec["effect"] = {"file": name, "default": {"exit": c0, "file_result": r0.get(name), "targets": sorted(r0)},
                         "with_pattern": {"exit": c1, "file_result": r1.get(name), "targets": sorted(r1),
                                          "warn_error_fatal": m1[:3]}}
    print(json.dumps(rec), flush=True)
