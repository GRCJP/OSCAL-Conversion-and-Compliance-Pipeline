# OSCAL Compliance Automation Pipeline

> Turning a stale spreadsheet SSP into a living, evidence-backed OSCAL artifact — auto-populated from real security tool APIs, with an AI agent layer that pre-determines implementation accuracy before an ISSO ever touches it.

<div align="center">

**[🚀 Live Demo](https://grcjp.github.io/OSCAL-Conversion-and-Compliance-Pipeline/)** &nbsp;·&nbsp; [Architecture](docs/ARCHITECTURE.md) &nbsp;·&nbsp; [Tool Evidence Map](docs/TOOL_EVIDENCE_MAP.md) &nbsp;·&nbsp; [Troubleshooting](docs/TROUBLESHOOTING.md)

![OSCAL](https://img.shields.io/badge/OSCAL-1.1.2-0066cc?style=flat-square)
![NIST](https://img.shields.io/badge/NIST%20800--53-Rev%205-0066cc?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

---

## The Problem

SSPs are updated manually, once a year, right before an audit. They describe how controls *should* work. They never verify whether they actually do. This pipeline connects the claim to the evidence — continuously, automatically, and in a format that an AI agent can reason about.

## How It Works

```
Legacy Excel SSP
      ↓
excel_to_oscal.py   →   sspp.json  (OSCAL skeleton — master)
                               ↓
         ┌─────────────────────┼─────────────────────┐
         ↓                     ↓                     ↓
   wiz_ingest.py         jira_ingest.py        tanium_ingest.py
   Cloud findings        Process controls      Endpoint compliance
         └─────────────────────┼─────────────────────┘
                               ↓
                      reconcile_oscal.py
                      CONFIRMED · PARTIAL · CONTRADICTED
                      UNDOCUMENTED · DRAFT-NEEDED
                               ↓
                       GRC Agent  ← in development
                       Pre-determines accuracy,
                       reasons about compensating
                       controls, drafts narratives
                               ↓
                       ISSO validates and signs off
```

The ISSO reviews a structured brief — not raw tool data, not a spreadsheet. Their job becomes judgment, not evidence collection.

---

## Key Design Decisions

| Decision | Why It Matters |
|---|---|
| `by-components` structure | Every tool gets its own evidence slot per control — independently verifiable, independently timestamped |
| UUID v5 deterministic IDs | Git diffs show content changes only, not ID churn — the OSCAL file is auditable |
| Dynamic control mapping | Tools declare specific control IDs they can evidence, not families — prevents false positives and false negatives |
| `has_data` gate | A slot only counts as evidence if it has `api-ready: true` AND a real timestamp — boilerplate never triggers a false reconciliation |
| Baseline narrative preservation | The reconciler annotates, never overwrites — original SSP claim and tool evidence are always visible side by side |

---

## Status

| Component | Status |
|---|---|
| Excel → OSCAL converter (UUID v5, by-components) | ✅ Complete |
| 4-stage OSCAL validation | ✅ Complete |
| Wiz ingest — GraphQL, dynamic control mapping | ✅ Complete |
| Jira ingest — process controls, POA&M sync | ✅ Complete |
| Reconciler — 5 outcome states | ✅ Complete |
| Interactive demo (GitHub Pages) | ✅ Complete |
| Tanium ingest | 🔄 In Progress |
| Splunk ingest | 🔄 In Progress |
| GRC Agent — compensating control reasoning | 🔄 In Development |
| SailPoint / ForgeRock / BeyondTrust connectors | 📋 Planned |
| Submission export | 📋 Planned |

---

## Quick Start

```bash
pip install openpyxl requests python-dotenv
cp .env.example .env          # add your API credentials

python scripts/excel_to_oscal.py --input your-ssp.xlsx --output oscal/sspp.json
python scripts/wiz_ingest.py --oscal oscal/sspp.json
python scripts/jira_ingest.py --oscal oscal/sspp.json
python scripts/reconcile_oscal.py --oscal oscal/sspp.json
cat evidence/reconciliation-report.json
```

---

## Docs

- [Architecture & design decisions](docs/ARCHITECTURE.md)
- [Tool evidence map — what each tool can and cannot prove](docs/TOOL_EVIDENCE_MAP.md)
- [Troubleshooting — real issues, real fixes](docs/TROUBLESHOOTING.md)
- [References](docs/REFERENCES.md)
- [Security notes](SECURITY.md)

---

## License

MIT — use it, adapt it, build on it.
