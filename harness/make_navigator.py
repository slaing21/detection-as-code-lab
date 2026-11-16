#!/usr/bin/env python3
'''
Generate an ATT&CK Navigator layer from the aggregated coverage results to color code coverage score 0-3, and show a comment with FP cost and rule id.
Usage: python -I harness/make_navigator.py
'''
import json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "dashboard", "data.json")
OUT  = os.path.join(ROOT, "dashboard", "navigator-layer.json")

SCORE = {0: ("#d03b3b", "No telemetry"),
         1: ("#ec835a", "Telemetry, no rule"),
         2: ("#fab219", "Detected, noisy or inconsistent"),
         3: ("#0ca30c", "Detected, clean")}
BLOCKED = "#b8b6ae"

def build(data):
    summ = data.get("summary", {})
    techs = []
    for t in data.get("techniques", []):
        cs = t.get("coverage_score")
        if cs is None:
            color, label, score = BLOCKED, (t.get("status") or "not measured"), None
        else:
            color, label = SCORE[cs]; score = cs

        parts = [label]

        if t.get("rule_id"): 
            parts.append("rule " + str(t["rule_id"]))
        if cs is not None: 
            parts.append("FP cost {} over 5 baseline runs".format(t.get("fp_cost_5runs", 0)))
        if t.get("stock_attribution") and t["stock_attribution"] != "none":
            parts.append("stock: " + t["stock_attribution"])

        e = {"techniqueID": t["technique_id"], "color": color,
             "comment": " | ".join(parts), "enabled": True}

        if score is not None: 
            e["score"] = score
        techs.append(e)
    return {
        "name": "Wazuh Lab Detection Coverage",
        "versions": {"attack": str(summ.get("attack_version", "20")), "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Empirical Sysmon and Wazuh detection coverage with false-positive cost. "
                        "Color is coverage score 0-3, comment is FP cost and rule id. "
                        "Generated from results/runs.csv by harness/aggregate.py then make_navigator.py."),
        "techniques": techs,
        "gradient": {"colors": ["#d03b3b", "#fab219", "#0ca30c"], "minValue": 0, "maxValue": 3},
        "legendItems": [
            {"label": "0 No telemetry", "color": "#d03b3b"},
            {"label": "1 Telemetry, no rule (shadowed)", "color": "#ec835a"},
            {"label": "2 Detected, noisy", "color": "#fab219"},
            {"label": "3 Detected, clean", "color": "#0ca30c"},
            {"label": "Blocked / not measured", "color": BLOCKED}],
        "hideDisabled": False, "showTacticRowBackground": True,
        "tacticRowBackground": "#2c2c2a", "selectTechniquesAcrossTactics": True, "sorting": 0,
    }

def main():
    layer = build(json.load(open(DATA, encoding="utf-8")))
    json.dump(layer, open(OUT, "w"), indent=2)
    print("Wrote {} ({} techniques)".format(OUT, len(layer["techniques"])))

if __name__ == "__main__":
    main()