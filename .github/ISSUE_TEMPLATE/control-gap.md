---
name: Control Gap
about: Report a control that is flagged as CONTRADICTED or PARTIAL with evidence gaps
title: "[GAP] <control-id>: <brief description>"
labels: control-gap, isso-review
assignees: ''
---

## Control Information

**Control ID:** (e.g., AC-2)
**Current Status:** CONTRADICTED / PARTIAL / DRAFT-NEEDED
**Framework:** NIST 800-53 Rev 5

## What the SSP Claims

<!-- Copy the implementation narrative from sspp.json -->

## What the Evidence Shows

<!-- Copy the relevant by-components evidence descriptions -->

## Gap Description

<!-- Describe specifically what is missing or contradicted -->

## Tools Involved

- [ ] Wiz
- [ ] Jira  
- [ ] Tanium
- [ ] SailPoint
- [ ] Splunk
- [ ] Other: ___

## Data Quality vs. Control Failure

Is this gap due to:
- [ ] Missing tool connector (API not yet integrated)
- [ ] Data quality issue (tool data is inaccurate)
- [ ] Actual control deficiency (control is not implemented as claimed)
- [ ] Approved exception (gap has documented risk acceptance)

## Remediation Path

<!-- What needs to happen to close this gap? -->

## Approved Exception

If this gap has an approved exception, link the exception ticket here:
- Exception ticket: 

## Definition of Done

- [ ] Evidence collected from all relevant tools
- [ ] Implementation narrative updated to reflect evidence
- [ ] ISSO has reviewed and signed off
- [ ] Reconciler shows CONFIRMED status
