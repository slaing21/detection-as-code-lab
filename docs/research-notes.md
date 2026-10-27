# Research Notes

Research notes, decisions, and sources. This is a living document so more will be appended as the project progresses.

## Framework Version

- **ATT&CK Enterprise v20** (released 2026-10-13) is the pinned framework. v19 (April 2026) split the old **Defense Evasion** tactic into **Stealth (TA0005)** and **Defense Impairment (TA0112)**, so Enterprise now has **15 tactics**. TA0005 is reused for Stealth, so older references to "TA0005 = Defense Evasion" are now stale. A mapping hazard this project avoids by using v20 tactic names throughout and recording any upstream `defense-evasion` tag where it differs.
  - Source: ATT&CK release notes, https://attack.mitre.org/resources/updates/updates-april-2026/ and https://attack.mitre.org/resources/updates/
- SigmaHQ has already migrated its rule tags to `attack.stealth` and `attack.defense-impairment` (checked October 2026), so rules adapted from SigmaHQ map directly to v20 tactics. Older rules and forks may still carry `attack.defense-evasion`.

## Pinned Versions

| Component | Version |
|---|---|
| VirtualBox | Version 7.2.14 r174565 (Qt6.8.0 on windows) |
| Ubuntu Server (SIEM) | Ubuntu 26.04.1 LTS (GNU/Linux 7.0.0-31-generic x86_64) |
| Wazuh (manager, indexer, dashboard) | v4.14.7 |
| Windows 11 (endpoint) | Version 25H2, OS build 26200.9457 |
| Sysmon | Version 15.22.0.0 |
| sysmon-modular config | balanced (medium verbosity), Sysmon schema 4.90, committed in aa25361 (2026-09-14) |
| Invoke-AtomicRedTeam module | 2.1.0 |
| Atomic Red Team | 2026-09-14 |

## Sysmon Configuration

- **Decision: sysmon-modular (Olaf Hartong), balanced profile**, over SwiftOnSecurity. Reason: sysmon-modular embeds ATT&CK technique IDs directly in `RuleName` (`technique_id=T....`), so the telemetry is self-labeling, and the reason the config was chosen and the thing that makes telemetry-to-technique attribution cheap.
  - The committed config (`lab/endpoint/sysmonconfig.xml`) is the exact file installed.
  - Trade-off acknowledged: "balanced" verbosity has documented blind spots (per the config's banner).

## Sigma → Wazuh Conversion

- **There is no official pySigma backend for Wazuh.** None is listed in the [pySigma plugin directory](https://github.com/SigmaHQ/pySigma-plugin-directory). Converter candidates: [sigma_to_wazuh](https://github.com/theflakes/sigma_to_wazuh) (Python, no longer maintained), its Go successor [StoW](https://github.com/theflakes/StoW), [SigWaz](https://sigwaz.com/), and a community pySigma Wazuh backend mentioned on the [Wazuh mailing list](https://groups.google.com/g/wazuh/c/VuRel-u0U3Y) with no published package.
- **Decision: Sigma is the source of truth, Wazuh XML is a validated build artifact.** Where conversion is lossy or unsupported, the Wazuh rule will be authored directly and the Sigma file will be kept as the documented intent.
- Known gaps to check per rule: `if_sid` scoping to the right Sysmon base rule, `level`/severity mapping, and unsupported modifiers (`base64offset|contains`, `|near`, `timeframe` correlation). The T1059.001 converter trial hit the first of these (`if_sid` scoping, see Converter trial 1 below). The rule avoids `base64offset|contains` by matching the encoded-command flag, not the decoded payload (documented in its ADS).
- **Fidelity method:** every deployed rule is checked with `wazuh-logtest` (using the temporary rule 60000 change Wazuh's own test runner makes) or live on the endpoint, and the result is recorded.
- **Converter trial 1 (2026-10-18):** sigma_to_wazuh converted the T1059.001 rule (1 of 1), but the output needed three correctness fixes: generic Windows parent rules instead of Sysmon Event 1 (61603), Sigma `endswith` converted to "contains", and Sigma tags in the `<mitre>` block instead of technique IDs. The tool reports conversion, not correctness. Its README also omits the PyYAML dependency. Details are in the T1059.001 ADS.
- **wazuh-logtest and Windows events:** wazuh-logtest submits every test event as a plain log line, so the Windows eventchannel decoder that rule 60000 requires never runs, even with `-l`. Wazuh's own [test runner](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/testing/runtests.py) temporarily sets rule 60000 to `decoded_as json`. This project validates Windows rules the same way, or live on the endpoint.
- **Built-in comparison:** Wazuh 4.14 already ships [rule 92057](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0800-sysmon_id_1.xml) for encoded PowerShell when the parent is powershell.exe. Built-in rules like this are the baseline the lab rules are compared against.

## Metric Definitions

- **Coverage score 0–3** (no telemetry / telemetry-no-rule / detected-noisy or detected-inconsistent / detected-clean) and **false-positive cost** (alerts a rule raises across 5 benign baseline runs). Defined in `evaluation-protocol.md`. Since DeTT&CT scores data-source coverage on paper, this project measures *observed* coverage empirically and adds the FP dimension that DeTT&CT does not.
- **Why "cost" and not "rate":** since a research lab cannot claim a production false-positive *rate*, because that depends on a real environment's event volume, this lab will use "cost" since what is measured is how many times a rule fired against a fixed, scripted benign workload.

## Related Work and The Gap

- SigmaHQ shares detections, Atomic Red Team shares tests, DeTT&CT scores data-source coverage, "Summiting the Pyramid" scores analytic robustness, Splunk Attack Range and Elastic detection-rules are vendor-specific and heavy to rebuild.
- **Gap this project fills:** an open, low-cost, reproducible lab that measures *both* detection coverage *and* false-positive cost for **Wazuh specifically**, and publishes the result as an ATT&CK Navigator layer.

## Atomic Red Team

- Windows index pulled from the Atomic Red Team repo. Tests age: some fail at run time (deprecated binaries e.g. WMIC removed from recent Windows 11, dead download URLs). A failed test is recorded as `atomic_status: execution_failed` and never scored as a failed detection.

## Standards Framing

- **Palantir ADS** is the per-rule documentation structure (`docs/templates/ads-template.md`). **NIST SP 800-61r3** frames the triage/response narrative and **NIST CSF 2.0** the Detect function.

## Sources

**Framework**
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK v20 release notes (October 2026)](https://attack.mitre.org/resources/updates/)
- [ATT&CK v19 release notes (April 2026), Defense Evasion split](https://attack.mitre.org/resources/updates/updates-april-2026/)
- [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)

**Telemetry and SIEM**
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [SwiftOnSecurity sysmon-config (considered, not selected)](https://github.com/SwiftOnSecurity/sysmon-config)
- [Wazuh 4.14 custom rules](https://documentation.wazuh.com/4.14/user-manual/ruleset/rules/custom.html)
- [Wazuh wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [Wazuh 4.14.0 release notes](https://documentation.wazuh.com/current/release-notes/release-4-14-0.html)
- [Wazuh source and ruleset](https://github.com/wazuh/wazuh)

**Detection rules and conversion**
- [Sigma specification](https://github.com/SigmaHQ/sigma-specification)
- [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma)
- [SigmaHQ reference rule for T1059.001](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_encode.yml)
- [pySigma](https://github.com/SigmaHQ/pySigma)
- [pySigma plugin directory](https://github.com/SigmaHQ/pySigma-plugin-directory)
- [sigma_to_wazuh](https://github.com/theflakes/sigma_to_wazuh)
- [StoW](https://github.com/theflakes/StoW)
- [SigWaz](https://sigwaz.com/)

**Emulation**
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Invoke-AtomicRedTeam wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki)

**Evaluation framing and related work**
- [Palantir ADS framework](https://github.com/palantir/alerting-detection-strategy-framework)
- [NIST SP 800-61 Rev. 3 (April 2025)](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST CSF 2.0, CSWP 29 (February 2024)](https://doi.org/10.6028/NIST.CSWP.29)
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT)
- [Summiting the Pyramid](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/)
- [Splunk Attack Range](https://github.com/splunk/attack_range)
- [Elastic detection-rules](https://github.com/elastic/detection-rules)