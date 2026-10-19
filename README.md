# Detection-as-Code: Lab for Measuring MITRE ATT&CK Detection Coverage with Sysmon, Sigma, and Atomic Red Team

A controlled, reproducible lab that measures **(1)** whether each technique is visible in Sysmon telemetry, **(2)** whether a detection rule fires when the technique runs, and **(3)** at what **false-positive cost** against a scripted baseline of benign Windows administration for a selection of MITRE ATT&CK techniques.

**Author:** Stephen Laing\
**Advisor:** Dr. Sayeed Sajal\
**Course:** CS 4200 UVU\
**Framework:** MITRE ATT&CK Enterprise **v20** (2026-10-13)

> **Status:** Milestone 2 (Design) complete. The lab is built and telemetry flows (Milestone 1). The design, protocol, tooling, and GUI are in place. The result file (`results/runs.csv`) currently holds **example rows** so the pipeline can be demonstrated end to end. The result file is planned to be populated with real data in Milestone 3.


## Architecture

Two VMs on an isolated host-only network. The endpoint reaches the internet temporarily to stage tooling, then is ran completely offline.

```
Windows 11 endpoint (.20)                Ubuntu Server - Wazuh 4.14 (.10)
  Sysmon (sysmon-modular)   --1514/1515-->  manager + indexer + dashboard
  Wazuh agent                                local HTTP file source
  Atomic Red Team                          ^
                                           | https
                                     Analyst browser
```

The full diagrams (architecture, detection pipeline) are in [`docs/design-spec.md`](docs/design-spec.md).

## The Two Metrics

1. **Coverage score (0–3):** 0 no telemetry, 1 telemetry but no rule, 2 detected but noisy, 3 detected cleanly. Telemetry is confirmed *before* any rule is written. A score of 0 is recorded as a blind spot.
2. **False-positive cost:** total alerts a rule raises across **5** runs of the benign baseline (`baseline/Invoke-Baseline.ps1`).

The metrics are defined in [`docs/evaluation-protocol.md`](docs/evaluation-protocol.md).

## Repository Map

|||
|---|---|
| [`docs/design-spec.md`](docs/design-spec.md) | Architecture, detection pipeline, rule namespace, outputs, traceability |
| [`docs/technique-matrix.md`](docs/technique-matrix.md) | 15 techniques, Selection criteria, Tactic spread |
| [`docs/evaluation-protocol.md`](docs/evaluation-protocol.md) | Metrics, Run loop, Baseline, Tuning, Validity |
| [`docs/research-notes.md`](docs/research-notes.md) | Living file of decisions with sources |
| [`docs/templates/`](docs/templates/) | ADS rule template + a worked T1059.001 example |
| `design/techniques.yml` | Machine-readable matrix (source for harness + dashboard) |
| `baseline/Invoke-Baseline.ps1` | Scripted benign admin workload + timestamp manifest |
| `harness/Invoke-Run.ps1` | Atomic run wrapper (timestamps + partial record) |
| `harness/aggregate.py` | Aggregate `results/runs.csv` into the per-technique rollup for the dashboard. |
| `harness/validate.py` | CI checks (schema, matrix, rule-id uniqueness) |
| `rules/sigma/` | Sigma rules, .yml file per technique (source of truth) |
| `rules/wazuh/` | Converted XML (build artifact) |
| `results/schema.json` | JSON Schema for a run record |
| `results/runs.csv` | One row per run (example rows for now, real data will be part of Milestone 3) |
| `dashboard/` | Static coverage dashboard |
| `lab/endpoint/sysmonconfig.xml` | Sysmon configuration |
| `lab/endpoint/ossec-conf-localfile-addition.conf` | Ossec local configuration |
| `lab/siem/local_rules.xml` | Local XML rules |

## Reproduce

**Build the lab**: [`docs/lab-build.md`](docs/lab-build.md).

**See the pipeline run on the example data** (no lab required):

```bash
python3 -I harness/validate.py      # schema / matrix / rules / sigma checks
python3 -I harness/aggregate.py     # build dashboard/data.json + data.js
# then open dashboard/index.html in a browser
```

**Run a measurement** (needs the lab): for each technique, from a clean `ep-02-baseline` snapshot, run `harness/Invoke-Run.ps1` ×3, then `baseline/Invoke-Baseline.ps1` ×5, record rows in `results/runs.csv`, and re-run `aggregate.py`. See the protocol for the exact instructions.

## Scope

15 techniques across 9 of the 15 ATT&CK Enterprise tactics (Execution, Persistence, Privilege Escalation, Stealth, Discovery, Lateral Movement, Command and Control, Collection, Impact), each executed 3 times from a clean snapshot.

## Schedule

| Weeks | Phase | Output |
|---|---|---|
| 1–3 | Build (M1, done) | Two-VM lab, telemetry flowing, snapshots |
| 4 | Converter gate | T1059.001 end to end, converter chosen, fidelity logged |
| 5–6 | **Design (M2)** | Matrix, protocol, templates, schema, harness, dashboard, spec |
| 7–9 | Measure (M3) | 15 techniques × (3 malicious + 5 baseline), rules + ADS, results |
| 10–11 | Analyze & write | Scores, Navigator layer, FP analysis, report |
| 12 | Package | Reproduce check from clean host, final deliverables |

## License

MIT (this project's own code and docs). Third-party tools under their own licenses — see [`LICENSE`](LICENSE). MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
