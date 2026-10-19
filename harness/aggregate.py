#!/usr/bin/env python3
'''
Aggregate results/runs.csv into the per-technique rollup for the dashboard.

Reads: design/techniques.yml, results/runs.csv
Writes: dashboard/data.json

Coverage score is computed from the runs, per evaluation-protocol.md §2.1. Run with -I for untrusted-free import.

Usage: python3 harness/aggregate.py
'''

import csv, json, ast, os, statistics, sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TECH = os.path.join(ROOT, "design", "techniques.yml")
RUNS = os.path.join(ROOT, "results", "runs.csv")
OUT = os.path.join(ROOT, "dashboard", "data.json")

def load_techniques():
    techs, cur = [], None
    for raw in open(TECH, encoding="utf-8"):
        line = raw.rstrip("\n")
        if line.strip().startswith("#") or not line.strip():
            continue
        if line.lstrip().startswith("- seq:"):
            if cur:
                techs.append(cur)
            cur = {"seq": int(line.split(":")[1])}
        elif cur is not None and line.startswith("    ") and ":" in line:
            k, v = line.strip().split(":", 1)
            cur[k.strip()] = v.strip().strip('"')
    if cur:
        techs.append(cur)
    return techs

def parse_bool(x):
    return str(x).strip().lower() == "true"

def load_runs():
    if not os.path.exists(RUNS):
        return []
    rows = []
    for r in csv.DictReader(open(RUNS, encoding="utf-8")):
        r["telemetry_present"] = parse_bool(r["telemetry_present"])
        r["detected"] = parse_bool(r["detected"])
        r["alert_count"] = int(r["alert_count"] or 0)
        r["latency_s"] = float(r["latency_s"]) if r["latency_s"] else None
        r["tuning_pass"] = int(r["tuning_pass"] or 0)
        rows.append(r)
    return rows

def coverage_score(mal_runs, fp_cost):
    valid = [r for r in mal_runs if r.get("atomic_status") in ("success", "")]
    if not valid:
        return None, "no-valid-runs"
    telemetry = any(r["telemetry_present"] for r in valid)
    detected = [r for r in valid if r["detected"]]
    if not telemetry and not detected:
        return 0, "no-telemetry"
    if telemetry and not detected:
        return 1, "telemetry-no-rule"
    if fp_cost and fp_cost > 0:
        return 2, "detected-noisy"
    return 3, "detected-clean"

def main():
    techs = load_techniques()
    runs = load_runs()
    latest = max((r["tuning_pass"] for r in runs), default=0)

    fp_by_rule = {}
    for r in runs:
        if r["run_type"] == "baseline" and r["tuning_pass"] == latest and r["rule_id"]:
            fp_by_rule[r["rule_id"]] = fp_by_rule.get(r["rule_id"], 0) + r["alert_count"]

    out_techs = []
    for t in techs:
        tid = t["technique_id"]
        mal = [r for r in runs if r["run_type"] == "malicious" and r["technique_id"] == tid and r["tuning_pass"] == latest]
        rule_id = next((r["rule_id"] for r in mal if r["rule_id"]), t.get("wazuh_rule_id"))
        fp_cost = fp_by_rule.get(str(rule_id), 0) if rule_id else 0
        lat = [r["latency_s"] for r in mal if r["latency_s"] is not None]
        detected_runs = sum(1 for r in mal if r["detected"])
        valid = [r for r in mal if r.get("atomic_status") in ("success", "")]
        score, label = coverage_score(mal, fp_cost) if mal else (None, "planned")
        precision = None

        if detected_runs or fp_cost:
            precision = round(detected_runs / (detected_runs + fp_cost), 3) if (detected_runs + fp_cost) else None
        out_techs.append({
            "technique_id": tid,
            "name": t.get("name"),
            "primary_tactic": t.get("primary_tactic"),
            "runs_malicious": len(mal),
            "valid_runs": len(valid),
            "telemetry_present": any(r["telemetry_present"] for r in valid) if valid else None,
            "detected_runs": detected_runs,
            "rule_id": str(rule_id) if rule_id else None,
            "mean_latency_s": round(statistics.mean(lat), 2) if lat else None,
            "fp_cost_5runs": fp_cost,
            "precision": precision,
            "coverage_score": score,
            "status": label
        })

    scored = [t for t in out_techs if t["coverage_score"] is not None]
    summary = {
        "attack_version": "20",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "techniques_planned": len(techs),
        "techniques_measured": len(scored),
        "score_counts": {str(s): sum(1 for t in scored if t["coverage_score"] == s) for s in range(4)},
        "tactics_covered": sorted({t["primary_tactic"] for t in out_techs})
    }

    os.makedirs(os.path.join(ROOT, "dashboard"), exist_ok=True)
    payload = {"summary": summary, "techniques": out_techs}
    json.dump(payload, open(OUT, "w"), indent=2)

    with open(os.path.join(ROOT, "dashboard", "data.js"), "w") as f:
        f.write("window.LAB_DATA = " + json.dumps(payload, indent=2) + ";\n")
        
    print(f"Wrote {OUT} and dashboard/data.js: {len(scored)}/{len(techs)} techniques measured " f"(scores {summary['score_counts']})")

if __name__ == "__main__":
    main()