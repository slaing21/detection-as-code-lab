# Detection-as-Code: Lab for Measuring MITRE ATT&CK Detection Coverage with Sysmon, Sigma, and Atomic Red Team

[![validate](https://github.com/slaing21/detection-as-code-lab/actions/workflows/validate.yml/badge.svg)](https://github.com/slaing21/detection-as-code-lab/actions/workflows/validate.yml)

A controlled, reproducible lab that measures **(1)** whether each technique is visible in Sysmon telemetry, **(2)** whether a detection rule fires when the technique runs, and **(3)** at what **false-positive cost** against a scripted baseline of benign Windows administration for a selection of MITRE ATT&CK techniques.

> **Status:** Measurement complete. 14 of the 15 planned techniques were executed and scored, and T1548.002 was blocked by Microsoft Defender. Results are frozen in `results/runs.csv`. The final report is in progress (Milestone 5).

## Results at a Glance

Every number below is computed from `results/runs.csv` by `harness/aggregate.py` (output: `dashboard/data.json`).

| | |
|---|---|
| **Techniques** | 15 planned across 10 ATT&CK v20 tactics, 14 executed (T1548.002 blocked by Defender) |
| **Lab rule pack** | Detected 13 of 14: **8 clean** (coverage 3), **5 noisy** (coverage 2), **1 shadowed** by a stock rule (coverage 1) |
| **Stock Wazuh 4.14.7** | Attributed **4 of 14** to the right technique, mislabeled 1, and missed 9 (generic alert or no alert) |
| **Net-new coverage** | The pack detected all 9 techniques stock Wazuh missed, 5 of them cleanly |
| **Tuning** | 2 rules tuned (T1547.001, T1543.003): FP cost 5 to 0, all malicious runs still detected |
| **Telemetry** | The primary Sysmon event was present for all 14 executed techniques. Secondary events were missing for 3 (see the [gap analysis](docs/gap-analysis.md)) |

| Technique | Name | Tactic (v20) | Lab rule | Coverage | FP cost (5 runs) | Stock Wazuh | ADS |
|---|---|---|---|---|---|---|---|
| T1059.001 | PowerShell | Execution | 100001 | 3, clean | 0 | generic (92032) | [ADS](docs/ads/ads-T1059.001.md) |
| T1053.005 | Scheduled Task | Persistence | 100002 | 2, noisy | 5 | generic (92032) | [ADS](docs/ads/ads-T1053.005.md) |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | 100003 | 3, clean | 0 (5 before tuning) | correct (92302) | [ADS](docs/ads/ads-T1547.001.md) |
| T1546.003 | WMI Event Subscription | Persistence | 100004 | 3, clean | 0 | correct (89501) | [ADS](docs/ads/ads-T1546.003.md) |
| T1543.003 | Windows Service | Persistence | 100005 | 3, clean | 0 (5 before tuning) | correct (92307) | [ADS](docs/ads/ads-T1543.003.md) |
| T1548.002 | Bypass User Account Control | Privilege Escalation | 100006 | Blocked by Defender | n/a | not run | [ADS](docs/ads/ads-T1548.002.md) |
| T1036.003 | Rename Legitimate Utilities | Stealth | 100007 | 1, shadowed | 0 | mislabeled (61625 as T1055) | [ADS](docs/ads/ads-T1036.003.md) |
| T1218.010 | Regsvr32 | Stealth | 100008 | 3, clean | 0 | generic (92032) | [ADS](docs/ads/ads-T1218.010.md) |
| T1112 | Modify Registry | Defense Impairment | 100009 | 3, clean | 0 | no alert | [ADS](docs/ads/ads-T1112.md) |
| T1087.001 | Local Account | Discovery | 100010 | 2, noisy | 20 | correct at parent T1087 (92031) | [ADS](docs/ads/ads-T1087.001.md) |
| T1082 | System Information Discovery | Discovery | 100011 | 2, noisy | 5 | generic (92032) | [ADS](docs/ads/ads-T1082.md) |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | 100012 | 2, noisy | 10 | generic (92036) | [ADS](docs/ads/ads-T1021.002.md) |
| T1105 | Ingress Tool Transfer | Command and Control | 100013 | 3, clean | 0 | generic (92032) | [ADS](docs/ads/ads-T1105.md) |
| T1560 | Archive Collected Data | Collection | 100014 | 2, noisy | 5 | generic (92027) | [ADS](docs/ads/ads-T1560.md) |
| T1490 | Inhibit System Recovery | Impact | 100015 | 3, clean | 0 | generic (92032) | [ADS](docs/ads/ads-T1490.md) |

"Stock Wazuh" is the built-in rule that fired when the technique ran with no lab rules deployed. **correct** means it mapped the event to this technique or its parent, **generic** means a broad rule fired with an unrelated mapping, and **mislabeled** means it named a different specific technique (protocol §5.1).

## Key Findings

1. **Stock coverage is thin, and some of it is wrong.** Out of the box, Wazuh attributed only 4 of the 14 executed techniques correctly. Six of the eight generic hits came from rule 92032 ("Suspicious Windows cmd shell execution"), which fired because the Atomic executor launches tests through `cmd /c`, not because of the technique.
2. **Some detections are noisy by nature.** Five rules fire on the same commands the benign baseline runs (scheduled task creation, local account discovery, systeminfo, admin share mapping, Compress-Archive). No single-event filter separates them without gaming the baseline, so their FP cost is reported as the finding. Each ADS has a Tuning Decision section.
3. **Tuning works when a real discriminator exists.** The Run key and service rules dropped from FP cost 5 to 0 by excluding trusted install locations, and still detected all 3 malicious runs.
4. **A higher-severity stock rule can hide an accurate lab rule.** For T1036.003, stock rule 61625 (level 12) labels a renamed cmd.exe as T1055 Process Injection and outranks the correct lab rule, so an analyst sees the wrong technique.
5. **wazuh-logtest is necessary but not sufficient.** Its json decoder and the live eventchannel decoder present fields differently, so two tuned rules passed logtest and failed in production until they were rewritten (see `docs/research-notes.md`).
6. **Sigma conversion is not automatic.** sigma_to_wazuh converted 9 of 15 rules, every conversion needed manual fixes (parent rule scoping, missing end anchors, MITRE tags), and 6 rules had to be written by hand.

The full telemetry versus rules breakdown, with proposed fixes, is in [`docs/gap-analysis.md`](docs/gap-analysis.md).

## View the Results

- **Dashboard:** open `dashboard/index.html` in a browser. It is a static page with no server needed, and it reads `dashboard/data.js`.
- **ATT&CK Navigator layer:** open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose **Open Existing Layer**, then **Upload from local**, and select `dashboard/navigator-layer.json`. Cell color is the coverage score, and each technique's comment lists the rule ID, FP cost, and stock attribution.
- **Raw data:** `results/runs.csv` holds one row per run, validated against `results/schema.json`.
- **Per-rule documentation:** one ADS per rule in [`docs/ads/`](docs/ads/), linked in the table above.

## Architecture

Two VMs on an isolated host-only network. The endpoint reaches the internet temporarily to stage tooling, then runs completely offline.

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

1. **Coverage score (0–3):** 0 no telemetry, 1 telemetry but no rule, 2 detected but noisy or inconsistent, 3 detected cleanly. Telemetry is confirmed *before* any rule is written. A score of 0 is recorded as a blind spot.
2. **False-positive cost:** total alerts a rule raises across **5** runs of the benign baseline (`baseline/Invoke-Baseline.ps1`).

Two supporting measures are also reported. **Precision** is detected malicious runs divided by (detected malicious runs + baseline alerts). **Latency** is the Sysmon event time (`systemTime`) minus the run start time, both taken on the endpoint clock, so it measures how soon the detected event occurred after launch, not how long the SIEM took to alert.

The metrics are defined in [`docs/evaluation-protocol.md`](docs/evaluation-protocol.md).

## Repository Map

|||
|---|---|
| [`docs/design-spec.md`](docs/design-spec.md) | Architecture, detection pipeline, rule namespace, outputs, traceability (Milestone 2 design) |
| [`docs/technique-matrix.md`](docs/technique-matrix.md) | 15 techniques, Selection criteria, Tactic spread |
| [`docs/evaluation-protocol.md`](docs/evaluation-protocol.md) | Metrics, Run loop, Baseline, Shadowed rules, Tuning, Validity |
| [`docs/gap-analysis.md`](docs/gap-analysis.md) | Telemetry vs rules gap analysis and proposed fixes |
| [`docs/research-notes.md`](docs/research-notes.md) | Living file of decisions with sources |
| [`docs/lab-build.md`](docs/lab-build.md) | Step-by-step lab build |
| [`docs/ads/`](docs/ads/) | One ADS per rule (15) |
| [`docs/transcripts/`](docs/transcripts/) | wazuh-logtest transcripts for rules the deployed stack never lets fire |
| `design/techniques.yml` | Machine-readable matrix (source for harness + dashboard) |
| `baseline/Invoke-Baseline.ps1` | Scripted benign admin workload + timestamp manifest |
| `harness/Invoke-Run.ps1` | Atomic run wrapper (timestamps + partial record) |
| `harness/aggregate.py` | Aggregate `results/runs.csv` into the per-technique rollup for the dashboard. |
| `harness/make_navigator.py` | Build the ATT&CK Navigator layer from `dashboard/data.json` |
| `harness/validate.py` | CI checks (schema, matrix, rule-id uniqueness) |
| `tools/craft_event.py` | Rewrite a captured Event 1 into a crafted event for wazuh-logtest (used for T1548.002) |
| `rules/sigma/` | Sigma rules, .yml file per technique (source of truth) |
| `rules/wazuh/` | Converted XML (build artifact) |
| `results/schema.json` | JSON Schema for a run record |
| `results/runs.csv` | One row per run (real measured data from Milestone 3 onward) |
| `dashboard/` | Static coverage dashboard (`index.html`, `data.js`, `data.json`) and `navigator-layer.json` |
| `lab/endpoint/sysmonconfig.xml` | Sysmon configuration |
| `lab/endpoint/ossec-conf-localfile-addition.conf` | Ossec local configuration |
| `lab/siem/local_rules.xml` | Local XML rules (the deployed rule pack) |
| `.github/workflows/validate.yml` | CI: runs `validate.py` and `aggregate.py` on every push |

## Reproduce

**Build the lab**: [`docs/lab-build.md`](docs/lab-build.md).

**See the pipeline run on the committed results** (no lab required):

```bash
pip install jsonschema                # without it, validate.py skips the schema check
python3 -I harness/validate.py        # schema / matrix / rules / sigma checks
python3 -I harness/aggregate.py       # rebuild dashboard/data.json + data.js from results/runs.csv
python3 -I harness/make_navigator.py  # rebuild dashboard/navigator-layer.json from data.json
# then open dashboard/index.html in a browser
```

**Run a measurement** (needs the lab): starting every run from a clean `ep-02-baseline` snapshot, run `harness/Invoke-Run.ps1` x3 for each technique, then run `baseline/Invoke-Baseline.ps1` x5 once per measurement pass and score every deployed rule against each baseline run. Record each run as a row in `results/runs.csv`, then re-run `aggregate.py`. See the protocol for the exact instructions.

## Limitations

- **Single endpoint, single configuration.** Results are specific to Windows 11 25H2, the sysmon-modular balanced config, and Wazuh 4.14.7.
- **The baseline is scripted.** FP cost is relative to this workload. Only the two tuned rules were cleared against benign activity of the same kind. For the other six clean rules the baseline has no matching action (T1546.003, T1218.010, T1112, T1490) or uses a different tool (T1059.001, T1105), so their FP cost of 0 is expected rather than tested.
- **One alert per event.** Wazuh raises only the highest-level matching rule, so a stock rule can hide a lab rule on the same event (T1036.003, and Event 20 for T1546.003).
- **Atomic tests are single actions, not full intrusions.** Defender settings had to change for some tests, and one test (T1548.002) never ran.

The full list is in protocol §9.

## Scope

15 techniques across 10 of the 15 ATT&CK Enterprise tactics (Execution, Persistence, Privilege Escalation, Stealth, Defense Impairment, Discovery, Lateral Movement, Command and Control, Collection, Impact), each executed 3 times from a clean snapshot.

## Schedule

| Week | Dates | Activity | Milestone | Status |
|---|---|---|---|---|
| 2 | Sep 7-13 | Build VMs, install Sysmon and Wazuh, background research | M1 [Background Research] | Done |
| 3-6 | Sep 14-Oct 11 | Technique matrix, evaluation protocol, ADS template, results schema, dashboard wireframe, baseline scripts | | Done |
| 7 | Oct 12-18 | First set of techniques, create, convert, and validate rules | M2 [Design] | Done |
| 8 | Oct 19-25 | Second set of techniques, record results, tune rules | | Done |
| 9 | Oct 26-Nov 1 | Final set of techniques, re-run validation and baseline | M3 [Implementation] | Done |
| 10 | Nov 2-8 | Telemetry vs rules gap analysis, start dashboard and Navigator layer | | Done |
| 11 | Nov 9-15 | Finish dashboard, final measurements, reproducibility rebuild | M4 [Testing & Troubleshooting] | Done |
| 12-13 | Nov 16-29 | Project report, slides, and poster | M5 [Wrap-up and Write Report] | In progress |
| 14-15 | Nov 30-Dec 6 | Oral presentation and final submission | Final | |

## License

MIT (this project's own code and docs). Third-party tools under their own licenses — see [`LICENSE`](LICENSE). MITRE ATT&CK® is a registered trademark of The MITRE Corporation.