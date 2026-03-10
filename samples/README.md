# Sample Outputs

Representative outputs from each stage of the pipeline. All org-specific data — resource IDs, account IDs, hostnames, ticket numbers, and names — has been replaced with sanitized placeholders. The structure, field names, and logic reflect real pipeline output.

---

## Files

### `sspp-sample.json`
OSCAL System Security Plan output from `excel_to_oscal.py` + API connectors + `reconcile_oscal.py`.

Shows all five reconciler outcome states across five representative controls:

| Control | State | What It Shows |
|---|---|---|
| AC-2 | `CONFIRMED` | Jira process evidence confirms account management workflow |
| RA-5 | `PARTIAL` | Wiz cloud findings confirmed; Tanium patch SLA at 94.7% — gap flagged |
| CM-6 | `CONTRADICTED` | SSP claims CIS benchmark compliance; Wiz shows 2 HIGH deviations |
| IR-3 | `DRAFT-NEEDED` | No tabletop exercise record found in 365 days — ISSO action required |
| AU-11 | `CONFIRMED` | Splunk confirms log retention policy active with zero violations |

Key structural elements visible in this file:
- `by-components` architecture — primary SSP narrative slot + one slot per tool
- `has_data` gate — `api-ready` + `last-api-pull` props on every tool slot
- `[AUTO-RECONCILED]` prefix preserving original SSP baseline narrative
- `reconciler-status` prop on each control for easy querying

---

### `reconciliation-report-sample.json`
Output from `reconcile_oscal.py` — the structured brief the ISSO reviews.

Contains:
- Summary counts across all five outcome states
- Per-control detail for every outcome — evidence sources, gap description, required action
- Data quality flags (e.g., SOC ticket hygiene inflating IR-5 counts)
- Prioritized next steps list

This is what replaces the "manually review 400 controls" workflow. The ISSO reviews this report, not the raw OSCAL file.

---

### `wiz-evidence-sample.json`
Raw API pull output from `wiz_ingest.py` — what gets written to `evidence/wiz/YYYY-MM-DD.json`.

Shows:
- Individual finding structure from the Wiz GraphQL API
- Dynamic control mapping — each finding tagged with the NIST controls it evidences
- Control-level summary aggregated from all findings
- How severity breakdown per control is derived

This file is gitignored in production (may contain sensitive resource details). The sample shows the structure with all identifying information sanitized.

---

## How These Connect

```
excel_to_oscal.py
      ↓
sspp-sample.json (skeleton — all slots empty, last-api-pull: "never")
      ↓
wiz_ingest.py  →  wiz-evidence-sample.json (raw pull archived)
      ↓
sspp-sample.json (Wiz slots populated, timestamps set)
      ↓
reconcile_oscal.py
      ↓
sspp-sample.json (narratives updated, statuses reconciled)
reconciliation-report-sample.json (ISSO review brief generated)
```
