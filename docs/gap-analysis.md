# Gap Analysis: Telemetry vs Rules

This is the Week 10 telemetry versus rules gap analysis, updated with the final measurements from Milestone 4. It separates three layers: what Sysmon recorded (telemetry), what the rules did with it (detection), and what the tooling around the rules did (pipeline). Every number traces to `results/runs.csv` or `dashboard/data.json`, and each technique's details are in its ADS.

**Summary.** Telemetry was never the main gap. The primary Sysmon event was present for all 14 executed techniques, and no technique scored 0. The gaps are in the rule layer (one shadowed rule, five rules that cannot be separated from admin work at the single-event level, and narrow rules whose clean scores were not stress-tested) and in the pipeline (converter fidelity and decoder divergence).

## 1. Telemetry Layer

Expected events come from `design/techniques.yml` and observed events from the lab runs in `results/runs.csv`.

| Technique | Expected | Observed | Missing | Cause | Type |
|---|---|---|---|---|---|
| T1021.002 | 1, 3 | 1 | 3 | The atomic maps `\\Target\C$`, which does not resolve in the isolated lab, so no SMB connection was made | Test environment |
| T1105 | 1, 3, 11, 22 | 1 | 3, 11, 22 | No Event 3: the sysmon-modular network filtering did not log certutil's connection. No Event 22: the target was an IP address. No Event 11: the server returned 404 | Sensor config (3), test environment (11, 22) |
| T1560 | 1, 11 | 1 | 11 | Defender blocked the compression, so no archive was written | Test environment |
| T1548.002 | 1, 13 | none | all | Defender blocked the atomic on process start (execution_failed, not scored) | Prevention |

The other 10 executed techniques produced every expected event.

Two more telemetry observations matter for attribution:

- **sysmon-modular RuleName tags are not a reliable label.** The T1036.003 event was tagged `technique_id=T1083` (see `docs/transcripts/T1036.003-logtest.txt`) and the T1112 event was tagged T1548.002 (run notes). The tags help triage, but they did not name the technique under test in these two cases.
- **Scheduled task actions.** sysmon-modular does not log svchost's write of the TaskCache `Actions` value, so a scheduled task's command is visible only in the schtasks.exe command line.

## 2. Rule Layer

| Category | Techniques | What happened | Proposed fix |
|---|---|---|---|
| Shadowed (coverage 1) | T1036.003 | Stock 61625 (level 12) outranks 100007 (level 8) on the same event and labels the rename as T1055 Process Injection. It fired because the copy was named lsass.exe | A child rule on 61625 that matches the OriginalFileName and Image mismatch and tags T1036.003 at level 12 or higher, so the stock severity stays and the label is corrected. Also measure a rename to a name no stock rule watches |
| Partly shadowed | T1546.003 | Event 20 goes to stock 89501 (level 12, correct). 100004 still alerts on Events 19 and 21 | None needed. Coverage holds |
| Blocked | T1548.002 | Defender prevents the atomic. Stock 92046 (level 12, T1548.002) would shadow 100006 anyway | None for the SIEM. Optional rule on the ms-settings handler registry write (Event 13) to catch the setup step |
| Noisy, not separable at the single-event level (coverage 2) | T1053.005, T1087.001, T1082, T1021.002, T1560 | The benign baseline runs the same command. The only other difference is the parent process (cmd.exe from the atomic executor, powershell.exe from the baseline), which is a harness artifact, except for T1560, where both parents are PowerShell | Add context the lab does not have (user, host role, parent lineage beyond the harness) or use these rules as correlation inputs. Volume-only fixes: key 100010 on net1.exe only (FP cost 20 to 10), exclude `/delete` from 100012 (FP cost 10 to 5). Neither changes the score |
| Tuned (coverage 2 to 3) | T1547.001, T1543.003 | Trusted-location filters dropped FP cost 5 to 0 with all malicious runs still detected | Done. The filters are bypassable by writing into a trusted location, which needs privilege |
| Clean, FP not stress-tested (coverage 3) | T1059.001, T1546.003, T1218.010, T1112, T1105, T1490 | The baseline has no matching benign action (T1546.003, T1218.010, T1112, T1490) or uses a different tool (T1059.001, T1105), so FP cost 0 is expected rather than tested. All but T1546.003 also key on a single tool, flag, or registry value | Add benign counterparts to the baseline (a benign encoded PowerShell command, a certutil download, a vetted WMI subscription) and broader sibling rules for the variants listed in each ADS |

Telemetry-to-rule notes for the noisy group:

- **T1087.001** fires twice per command because net.exe starts net1.exe, so 3 net commands raise 6 alerts and each baseline run raises 4.
- **T1560** is visible only when Compress-Archive starts a new process. The original baseline ran it in-process and produced no Event 1, which would have measured an FP cost of 0 by construction. The baseline was changed to spawn a child PowerShell (commit c059eda) so the measurement is comparable. In-process use still evades the rule.

## 3. Pipeline Layer

**Sigma to Wazuh conversion (sigma_to_wazuh).** 9 of 15 rules converted. The other 6 were written by hand because the converter skips `1 of` and multi-selection (`all of selection_*`) conditions (T1053.005, T1087.001, T1021.002, T1105, T1560) or because the rule was built directly on the stock registry rules (T1547.001). Every converted rule needed fixes:

| Converter problem | Rules affected |
|---|---|
| Generic Windows parent list in `if_sid` instead of the Sysmon base rule (61603, 61609, 61615, 61647 to 61649) | all 9 |
| Sigma tags (`attack.*`) in `<mitre>` instead of technique IDs | all 9 |
| Sigma `endswith` turned into contains (no `$` anchor) | T1059.001, T1082, T1218.010, T1543.003, T1548.002, T1112 |
| Sigma OR between two selections emitted as one rule, which makes it an AND | T1082 |
| Event ID matched on any Windows channel, not only Sysmon | T1546.003 |
| Sigma `\|re` modifier not translated (pattern escaped as literal text on `full_log`, so the filter never matches) | T1543.003 |

**wazuh-logtest vs the live decoder.** Logtest decodes test events with the json decoder, while production uses the windows_eventchannel decoder. They differ in the rule chain they reach (61615 vs 92300 for Run key writes) and in escaping (doubled backslashes and escaped quotes in production). Rules 100003 and 100005 passed logtest and failed live until they were rewritten to absorb both forms. Fix adopted: verify every path or command-line regex both in logtest and live.

**Wazuh's built-in MITRE data lags ATT&CK v20.** Wazuh 4.14.7 still labels T1036.003 "Rename System Utilities" under "Defense Evasion" (logtest output), so the SIEM's tactic names do not match v20 names.

**Clock drift.** The SIEM clock drifted by about 10.5 minutes during Milestone 3, which hid alerts from time-window searches. Latency was unaffected because it is measured on the endpoint clock (Sysmon `systemTime` minus run start). Clocks were checked every session after that.

## 4. Proposed Fixes, in Priority Order

| # | Fix | Closes | Cost |
|---|---|---|---|
| 1 | Child rule on 61625 that relabels the renamed-utility event as T1036.003 at stock severity | Shadowed T1036.003 | One rule, 3 runs, one baseline pass |
| 2 | Add benign counterparts to the baseline (benign encoded PowerShell, certutil download, vetted WMI subscription) | Untested clean scores | Baseline script change, one baseline pass |
| 3 | Event 1 fallback for T1218.010 on the regsvr32 command line | Event 7 dependency | One rule |
| 4 | Sysmon network include for certutil, then an Event 3 rule | T1105 command-line-only detection | Config change, rebuild |
| 5 | PowerShell script block logging (4104) forwarded to Wazuh | In-process Compress-Archive (T1560) | Out of Sysmon-only scope |
| 6 | Volume fixes for 100010 (net1.exe only) and 100012 (exclude `/delete`) | Alert volume, not score | One baseline pass |
| 7 | Context-based correlation for the discovery and admin-tool rules | Irreducible noise | Needs data the lab does not have |

None of these were measured. They are future work.