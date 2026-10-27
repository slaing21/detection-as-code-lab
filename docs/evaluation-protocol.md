# Evaluation Protocol (v0.1, Milestone 2)

This is the measurement procedure. It exists so that any run of any technique is done the same way, so that the two headline metrics: **detection coverage** and **false-positive cost** remain consistent across all 15 techniques, and allowing a reader to reproduce any number from the repo.

## 1. Pinned Variables

| Variable | Pinned Value | Location |
|---|---|---|
| ATT&CK Version | Enterprise v20 (2026-10-13) | `design/techniques.yml` |
| Sysmon Config | `lab/endpoint/sysmonconfig.xml` (sysmon-modular, balanced), commit/date logged | research-notes |
| Sysmon Binary Version | record `Sysmon64.exe` version at install | research-notes |
| Wazuh Version | 4.14 (manager, indexer, dashboard) | research-notes |
| Windows Build | record `winver` at `ep-02-baseline` snapshot | research-notes |
| Atomic Red Team Version | Invoke-AtomicRedTeam module version, plus the atomics commit (if cloned with git) or download date | research-notes |
| Endpoint Snapshot | `ep-02-baseline` (Sysmon + agent Active + atomics staged, NAT disconnected) | snapshot list |
| Clock Source | both VMs synced before each session, latency measured in seconds | - |

**Snapshot Discipline:** Every malicious *and* baseline run starts from the `ep-02-baseline` snapshot, so no run inherits state from a previous run.

## 2. The Two Metrics

### 2.1 Detection Coverage (per technique)

A 0-3 **coverage score**, assigned per technique after its 3 malicious runs:

- **0 - No telemetry.** The atomic ran but no Sysmon event attributable to it appears in Wazuh.
- **1 - Telemetry, no rule.** The Sysmon event is present in Wazuh archives, but no rule raises an alert above the noticed threshold.
- **2 - Detected, noisy or inconsistent.** A rule fires on at least one malicious run, but also fires during a baseline run (FP cost > 0) or misses at least one malicious run.
- **3 - Detected, clean.** A rule fires on all malicious runs and on zero baseline runs.

### 2.2 False-Positive Cost (per rule)

Run the benign baseline (`baseline/Invoke-Baseline.ps1`, §4) **N = 5 times**, each from a clean snapshot. For each rule under test, **FP cost = total alerts that rule raised across the 5 baseline runs**. Report per run, not just the total, so burst behavior is visible. Precision for a technique is reported as `true_positives / (true_positives + baseline_false_positives)` using the 3 malicious runs as the positive set.

**Why "cost" and not "rate":** since a research lab cannot claim a production false-positive *rate*, because that depends on a real environment's event volume, this lab will use "cost" since what is measured is how many times a rule fired against a fixed, scripted benign workload.

## 3. Choosing the one Atomic Test (per technique)

1. Executor is `powershell` or `command_prompt`.
2. No `-GetPrereqs` dependency that needs the internet at *run* time (fetching prereqs once while NAT is connected is fine; the run itself must work offline).
3. Does not require a second host, a domain controller, or paid tooling.
4. Prefer a test whose behavior a real adversary would use over a pure "atom" that only touches an artifact (e.g. for T1053.005 prefer creating a task that launches a payload over one that only writes a registry blob).
5. Record the chosen GUID, name, and why in `design/techniques.yml`. If no test satisfies 1–3, mark the technique `blocked` and replace it with another technique that meets the selection criteria in technique-matrix.md.

## 4. Benign Baseline Definition

The baseline is a fixed script of ordinary Windows administration, run on the same endpoint, so that "does this rule also fire on normal work?" has a repeatable answer. Contents (implemented in `baseline/Invoke-Baseline.ps1`):

- Create, start, query, stop, and delete a Windows service
- Register and delete a scheduled task
- Write and delete an HKCU Run key
- Enumerate local users and groups; run `systeminfo`, `ipconfig /all`, `tasklist`
- Map and unmap an SMB share to `\\127.0.0.1\C$`
- Download a small file from the SIEM VM's local HTTP server
- Compress a log folder with `Compress-Archive`
- Install a small MSI or run a signed installer, then uninstall
- A short block of scripted PowerShell (random numbers, process listing, module import)

The script writes a manifest (`baseline-manifest-<runid>.json`) with the UTC start/end of each action, so an alert's timestamp can be attributed to a specific benign action when analyzing FPs. Target duration ~15 minutes per run.

## 5. Per-technique Run Procedure

For each technique, repeat 3× for the malicious measurement:

1. **Restore** `ep-02-baseline`. Confirm agent shows **Active** in the dashboard and reports its host-only IP `192.168.56.20`.
2. **Mark start:** record `t_start` (UTC). Note the `run_id`.
3. **Execute** the chosen atomic: `Invoke-AtomicTest <technique> -TestGuids <guid>` via the run wrapper (`harness/Invoke-Run.ps1`), which stamps start/end.
4. **Confirm the atomic actually ran** (executor exit status). If it failed, record `atomic_status: execution_failed` and stop this run.
5. **Collect** from Wazuh for the `[t_start, t_start+5min]` window: did the expected Sysmon event appear in archives (telemetry Y/N)? Did any rule alert (detection Y/N, which rule_id, alert timestamp → `latency_s = alert_time - t_start`)?
6. **Record** one result row (schema §`results/`).
7. **Cleanup:** run the atomic's cleanup, then restore snapshot anyway for the next run.

Then the FP measurement, which is shared rather than per technique: once per measurement pass, with every rule under test deployed, run `Invoke-Baseline.ps1` 5× (each from a clean snapshot) and record each rule's alert count per baseline run.

## 6. Tuning Loop

A rule scoring 2 (noisy) may be tuned once:

1. Read the FP alerts; identify the benign action that triggered them (via the baseline manifest).
2. Narrow the rule (add a parent-image or command-line condition, and tighten `field` matches).
3. Re-run: 3 malicious + 5 baseline, from clean snapshots.
4. Record before/after coverage score and FP cost.

## 7. Milestone 3 Task Checklist

- All 15 techniques have 3 malicious runs and a coverage score
- Every rule under test has an FP cost from 5 baseline runs
- Every number traces to a `run_id` in `results/runs.csv`
- Blind spots and atomic failures are documented, not hidden
- One clean rebuild from the README reproduces the pipeline

## 8. Threats to Validity

- **Single endpoint, single config:** results are specific to this Windows build + this Sysmon config.
- **Scripted baseline ≠ real users:** FP cost is relative to *this* workload.
- **Defender interference:** exclusions needed to run some atomics are environment changes.
- **Converter fidelity:** rules converted from Sigma may not be semantically identical to the source.
- **One alert per event:** Wazuh raises one alert per event, so when two rules match the same event (rule 100200 and built-in rule 92057, or two registry-based rules such as the planned T1547.001 and T1112 rules), only one of them is counted. Each run records which rule fired.
- **Atomic realism:** atomics are single-action proofs, not full intrusions.