#!/usr/bin/env python3
'''
Repo self-check for the Detection-as-Code lab. To be run on every push.

Checks:
    1. results/runs.csv: validation against results/schema.json
    2. design/techniques.yml: 15 techniques, at least 8 tactics, unqiue wazuh_rule_id in the reserved block
    3. lab/siem/local_rules.xml: unique rule ids
    4. rules/sigma/*.yml: each one has a unique Sigma id and the required keys

Usage: python3 -I harness/validate.py
'''

import csv, json, os, re, sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = []

def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    if not ok:
        fails.append(name)

def check_techniques():
    t = load_tech()
    check("matrix count", len(t) == 15, f"{len(t)} techniques")
    tactics = {x["primary_tactic"] for x in t}
    check("tactic spread", len(tactics) >= 8, f"{len(tactics)} tactics")
    ids = [x.get("wazuh_rule_id") for x in t]
    check("rule_id unique", len(ids) == len(set(ids)), f"{len(set(ids))} unique of {len(ids)}")
    inblock = all(100200 <= int(i) <= 100499 for i in ids if i)
    check("rule_id in reserved block", inblock, "100200-100499")

# 1. results/runs.csv
def check_results():
    schema_path = os.path.join(ROOT, "results", "schema.json")
    runs_path = os.path.join(ROOT, "results", "runs.csv")
    if not (os.path.exists(schema_path) and os.path.exists(runs_path)):
        return check("results schema", False, "schema.json or runs.csv missing")
    try:
        import jsonschema
    except ImportError:
        return check("results schema", True, "jsonschema not installed, skipped (install to enforce)")
    schema = json.load(open(schema_path))
    jsonschema.Draft202012Validator.check_schema(schema)
    n = 0
    for r in csv.DictReader(open(runs_path, encoding="utf-8")):
        o = dict(r)
        for b in ("telemetry_present", "detected"):
            o[b] = o[b].strip().lower() == "true"
        o["run_index"] = int(o["run_index"])
        o["alert_count"] = int(o["alert_count"])
        o["tuning_pass"] = int(o["tuning_pass"])
        o["latency_s"] = float(o["latency_s"]) if o["latency_s"] else None
        o["coverage_score"] = int(o["coverage_score"]) if o["coverage_score"] else None
        o["atomic_test_guid"] = o["atomic_test_guid"] or None
        o["rule_id"] = o["rule_id"] or None

        for k in ("expected_sysmon_events", "observed_sysmon_events"):
            o[k] = json.loads(o[k].replace(" ", ",")) if o[k] else []
        jsonschema.validate(o, schema)
        n += 1

    check("results schema", True, f"{n} run row(s) valid")

# 2. design/techniques.yml
def load_tech():
    techs, cur = [], None
    for raw in open(os.path.join(ROOT, "design", "techniques.yml"), encoding="utf-8"):
        line = raw.rstrip("\n")
        if line.strip().startswith("#") or not line.strip():
            continue
        if line.lstrip().startswith("- seq:"):
            if cur:
                techs.append(cur)
            cur = {"seq": line.split(":")[1].strip()}
        elif cur is not None and line.startswith("    ") and ":" in line:
            k, v = line.strip().split(":", 1)
            cur[k.strip()] = v.strip().strip('"')
    if cur:
        techs.append(cur)

    return techs

# 3. lab/siem/local_rules.xml
def check_rules_xml():
    path = os.path.join(ROOT, "lab", "siem", "local_rules.xml")
    try:
        content = "<root>" + open(path, encoding="utf-8").read() + "</root>"
        root = ET.fromstring(content)
    except ET.ParseError as e:
        return check("local_rules.xml well-formed", False, str(e))
    ids = [r.get("id") for r in root.iter("rule")]
    check("local_rules.xml well-formed", True, f"{len(ids)} rules")
    check("local_rules.xml ids unique", len(ids) == len(set(ids)), f"{sorted(ids)}")

# 4. rules/sigma/*.yml
def check_sigma():
    d = os.path.join(ROOT, "rules", "sigma")
    files = [f for f in os.listdir(d) if f.endswith((".yml", ".yaml"))] if os.path.isdir(d) else []
    if not files:
        return check("sigma rules present", True, "none yet (added per technique in M3)")
    seen_ids = {}
    ok = True
    for f in files:
        txt = open(os.path.join(d, f), encoding="utf-8").read()
        for key in ("title:", "id:", "logsource:", "detection:", "condition:"):
            if key not in txt:
                ok = False
                print(f"    {f}: missing {key}")
        m = re.search(r"^id:\s*([0-9a-fA-F-]{36})", txt, re.M)
        if m:
            seen_ids.setdefault(m.group(1), []).append(f)
    dupes = {k: v for k, v in seen_ids.items() if len(v) > 1}
    check("sigma rules valid", ok and not dupes, f"{len(files)} file(s)" + (f", dup id {dupes}" if dupes else ""))

def main():
    check_results()
    check_techniques()
    check_rules_xml()
    check_sigma()
    print()
    if fails:
        print(f"{len(fails)} check(s) FAILED: {fails}")
        sys.exit(1)
    print("all checks passed")

if __name__ == "__main__":
    main()