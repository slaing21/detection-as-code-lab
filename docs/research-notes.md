# Research Notes

Research notes, decisions, and sources. This is a living document so more will be appended as the project progresses.

## Framework Version

- **ATT&CK Enterprise v20** (released 2026-10-13) is the pinned framework. v19 (April 2026) split the old **Defense Evasion** tactic into **Stealth (TA0005)** and **Defense Impairment (TA0112)**, so Enterprise now has **15 tactics**. TA0005 is reused for Stealth, so older references to "TA0005 = Defense Evasion" are now stale. A mapping hazard this project avoids by using v20 tactic names throughout and recording any upstream `defense-evasion` tag where it differs.
  - Source: ATT&CK release notes, https://attack.mitre.org/resources/updates/updates-april-2026/ and https://attack.mitre.org/resources/updates/
- Many SigmaHQ rules still tag `attack.defense_evasion` so the matrix maps those techniques to Stealth or Defense Impairment per v20.

## Sysmon Configuration

- **Decision: sysmon-modular (Olaf Hartong), balanced profile**, over SwiftOnSecurity. Reason: sysmon-modular embeds ATT&CK technique IDs directly in `RuleName` (`technique_id=T....`), so the telemetry is self-labeling, and the reason the config was chosen and the thing that makes telemetry-to-technique attribution cheap.
  - The committed config (`lab/endpoint/sysmonconfig.xml`) is the exact file installed.
  - Trade-off acknowledged: "balanced" verbosity has documented blind spots (per the config's banner).

## Sigma → Wazuh Conversion

- **There is no official pySigma backend for Wazuh.** Converter candidates to trial on the T1059.001 gate rule and record the winner: community pySigma Wazuh backends, `sigma_to_wazuh`, `SigWaz`, `sigWah`.
- **Decision: Sigma is the source of truth, Wazuh XML is a validated build artifact.** Where conversion is lossy or unsupported, the Wazuh rule will be authored directly and the Sigma file will be kept as the documented intent.
- Known gaps to check per rule: `if_sid` scoping to the right Sysmon base rule, `level`/severity mapping, and unsupported modifiers (`base64offset|contains`, `|near`, `timeframe` correlation). The T1059.001 example rule hits exactly this: `base64offset|contains` cannot be reproduced in Wazuh, so rule 100200 matches the encoded-command flag, not the decoded payload (documented in its ADS).
- **Fidelity method:** every deployed rule is checked with `wazuh-logtest` against a synthetic event, and transcript is recorded.

## Metric Definitions

- **Coverage score 0–3** (no telemetry / telemetry-no-rule / detected-noisy / detected-clean) and **false-positive cost** (alerts a rule raises across 5 benign baseline runs). Defined in `evaluation-protocol.md`. Since DeTT&CT scores data-source coverage on paper, this project measures *observed* coverage empirically and adds the FP dimension that DeTT&CT does not.
- **Why "cost" and not "rate":** since a research lab cannot claim a production false-positive *rate*, because that depends on a real environment's event volume, this lab will use "cost" since what is measured is how many times a rule fired against a fixed, scripted benign workload.

## Related Work and The Gap

- SigmaHQ shares detections, Atomic Red Team shares tests, DeTT&CT scores data-source coverage, "Summiting the Pyramid" scores analytic robustness, Splunk Attack Range and Elastic detection-rules are vendor-specific and heavy to rebuild.
- **Gap this project fills:** an open, low-cost, reproducible lab that measures *both* detection coverage *and* false-positive cost for **Wazuh specifically**, and publishes the result as an ATT&CK Navigator layer.

## Atomic Red Team

- Windows index pulled from the Atomic Red Team repo. Tests age: some fail at run time (deprecated binaries e.g. WMIC removed from recent Windows 11, dead download URLs). A failed test is recorded as `atomic_status: execution_failed` and never scored as a failed detection.

## Standards Framing

- **Palantir ADS** is the per-rule documentation structure (`docs/templates/ads-template.md`). **NIST SP 800-61r3** frames the triage/response narrative and **NIST CSF 2.0** the Detect function.

## Sources

- MITRE ATT&CK v20 (2026-10-13), tactic/technique definitions and release notes
- Sigma specification and SigmaHQ rule repository
- Atomic Red Team documentation and Windows atomics
- Microsoft Sysmon event reference [`olafhartong/sysmon-modular`](https://github.com/olafhartong/sysmon-modular)
- [Wazuh 4.14 ruleset and agent documentation](https://documentation.wazuh.com/current/release-notes/release-4-14-0.html)
- Palantir Alerting and Detection Strategy framework
- NIST SP 800-61r3
- NIST CSF 2.0
- DeTT&CT; "Summiting the Pyramid"
