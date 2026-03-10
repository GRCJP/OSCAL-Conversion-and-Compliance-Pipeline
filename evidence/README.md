# Evidence Archives

This directory contains raw API pull artifacts from connected tool connectors.

## Structure

```
evidence/
├── wiz/
│   └── YYYY-MM-DD.json     # Daily Wiz findings pull
├── tanium/
│   └── YYYY-MM-DD.json     # Daily Tanium endpoint compliance pull
├── jira/
│   └── YYYY-MM-DD.json     # Jira process evidence pull
└── reconciliation-report.json  # Output of reconcile_oscal.py
```

## What's Committed vs. What's Gitignored

**Committed:**
- `reconciliation-report.json` — contains control IDs and gap summary (no raw data)

**Gitignored:**
- Raw API pull files (`wiz/*.json`, `tanium/*.json`, `jira/*.json`) — may contain sensitive data

Raw evidence files are kept locally for audit trail purposes. They should be retained according to your organization's records retention policy (typically the same as your log retention requirement — often 3 years for audit evidence).

## Retention

Evidence archives are the proof that your OSCAL claims are grounded in real data pulled on a specific date. Retain them for at least as long as your ATO period plus any post-assessment review window.
