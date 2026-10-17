# Technique Matrix (v0.1, Milestone 2)

**Scope commitment:** 15 techniques spanning 9 of the 15 Enterprise tactics. Each technique is executed 3 times from a clean snapshot (see `evaluation-protocol.md`).

## Selection criteria

A technique is in scope only if all of these hold:

1. **Windows-applicable** and has at least one Atomic Red Team test for Windows.
2. **Local-only:** the chosen test needs no internet access and no second victim host (the endpoint is isolated on host-only `192.168.56.0/24`; the SIEM VM may serve files over HTTP when a test needs a network source).
3. **Sysmon-observable in principle:** at least one Sysmon event type is expected to record it. Whether it actually does is a measured result, not an assumption.
4. **Revertible:** any change it makes is undone by the test's cleanup or by snapshot restore.
5. **Telemetry diversity:** together the set must exercise process, registry, file, network, and WMI telemetry, not just process creation.
6. **Baseline relevance:** at least five techniques overlap with legitimate admin activity (scheduled tasks, services, registry run keys, account discovery, archiving) so the false-positive measurement is meaningful.

## Matrix

"Expected Sysmon events" is the hypothesis the run tests. "FP risk" is the predicted overlap with the benign baseline in `baseline/Invoke-Baseline.ps1`.

| # | Technique | Name | Primary tactic (v20) | Expected Sysmon events | FP risk vs baseline |
|---|---|---|---|---|---|
| 1 | T1059.001 | PowerShell | Execution | 1 (process create) | High: admins run PowerShell constantly |
| 2 | T1053.005 | Scheduled Task | Persistence | 1, 11 (task file), 13 | High: baseline registers a maintenance task |
| 3 | T1547.001 | Registry Run Keys / Startup Folder | Persistence | 13 (registry value set), 11 | Medium: software installers write Run keys |
| 4 | T1546.003 | WMI Event Subscription | Persistence | 19, 20, 21 (WMI filter/consumer/binding) | Low: rare in normal admin work |
| 5 | T1543.003 | Windows Service | Persistence | 1, 13 (service ImagePath) | High: baseline creates and removes a service |
| 6 | T1548.002 | Bypass User Account Control | Privilege Escalation | 1, 13 | Low |
| 7 | T1036.003 | Rename System Utilities | Stealth | 1 (OriginalFileName vs Image mismatch) | Low |
| 8 | T1218.010 | Regsvr32 | Stealth | 1, 7 (image load), 3 | Low to medium |
| 9 | T1112 | Modify Registry | Stealth | 12, 13 | High: baseline writes registry values |
| 10 | T1087.001 | Local Account discovery | Discovery | 1 | High: baseline lists local users |
| 11 | T1082 | System Information Discovery | Discovery | 1 | High: baseline runs systeminfo |
| 12 | T1021.002 | SMB/Windows Admin Shares | Lateral Movement | 1, 3 | Medium: baseline maps an admin share on localhost |
| 13 | T1105 | Ingress Tool Transfer | Command and Control | 1, 3 (network), 11 (file create), 22 (DNS) | Medium: baseline downloads a file from the SIEM VM |
| 14 | T1560 / T1560.001 | Archive Collected Data | Collection | 1, 11 | Medium: baseline zips a log folder |
| 15 | T1490 | Inhibit System Recovery | Impact | 1 | Low |

**Tactic Spread:** Execution, Persistence, Privilege Escalation, Stealth, Discovery, Lateral Movement, Command and Control, Collection, Impact = **9 tactics**.

**Telemetry Types Exercised:** process creation (1), network (3), image load (7), file create (11), registry (12/13), WMI (19–21), DNS (22).

**Not Covered (by design):** Initial Access (needs Office or mail infrastructure), Exfiltration (needs an external receiver), Reconnaissance and Resource Development (pre-compromise, not endpoint-observable), Credential Access and Defense Impairment, Linux/macOS techniques.