# Alerting and Detection Strategy (ADS) — Rule <rule_id>

Based on the Palantir ADS framework. One of these is written per rule under test. It documents *why* a detection exists and how it is validated, so the detection is auditable rather than a bare XML snippet.

---

## Goal

What adversary behavior this detection is meant to catch. Name the ATT&CK technique(s).

## Categorization

- **ATT&CK technique(s):** `Txxxx[.xxx]` — name
- **Tactic(s) (v20):**
- **Lab rule_id:** `100xxx`
- **Source Sigma rule:** path in `rules/sigma/`, and its upstream SigmaHQ id if adapted (or `original`)

## Strategy Abstract

How the detection works, in plain language: which telemetry field(s), what condition, what it keys on.

## Technical Context

The concrete detail a reviewer needs to judge the rule: the exact Sysmon event, the fields used, the Wazuh decoder/field names (`win.eventdata.commandLine`, `win.eventdata.image`, ...), and how the Sigma `logsource` maps onto them.

```xml
<!-- final rule as deployed in lab/siem/local_rules.xml -->
```

## Blind Spots and Assumptions

Where this detection fails or can be evaded.

## False Positives

What benign activity could trigger this, and what the baseline measurement actually showed. Reference the baseline manifest action if an FP was seen.

## Validation (how we know it works)

- **Positive test:** which atomic test GUID fires it, and the result (detected Y/N, latency).
- **Converter fidelity (if converted from Sigma):** `wazuh-logtest` output confirms the converted rule matches a crafted event
- **Negative test:** the 5-run baseline FP cost.

## Priority / Response

Suggested alert level and a one-line analyst response. 

## Lifecycle

- Created: `<date>` · Author: Stephen Laing
- Status: draft | validated | tuned | retired
- Changes: one line per tuning pass, with the before/after coverage score and FP cost