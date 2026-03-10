# Security Intelligence Pipeline
### Built on OSCAL · Powered by Live Tool Evidence · Compliance as a Byproduct

**[🚀 Live Interactive Demo](https://grcjp.github.io/OSCAL-Conversion-and-Compliance-Pipeline/)** — explore the pipeline, click controls, run the reconciler

> *This is not about making compliance easier. It's about knowing what risk you actually carry — and building the infrastructure to close the gap before someone else finds it.*

---

## The Core Thesis

The SSP is not a compliance document. It's a plan.

It describes the intended implementation of every security control — what tools are responsible, how they're configured, what they're supposed to do for every component in the system. It's the rulebook auditors use to evaluate whether a system's actual capabilities match its claims. And it's supposed to reflect reality.

The operative word is *supposed to*.

In practice, the SSP reflects what was true when someone last updated it — usually right before the last audit. The system evolved. Tools changed. Controls drifted. Nobody updated the plan. So auditors are evaluating against a document that no longer reflects the actual implemented state. Engineers are building without knowing what the security requirements really are. And ISSOs are manually bridging a gap that grows wider every sprint.

**This pipeline closes that gap — not by automating compliance paperwork, but by continuously reconciling the planned state against the actual state:**

- Tanium finds unauthorized software on an endpoint → that's CM-7 telling you the plan wasn't followed
- Wiz flags a misconfiguration → that's CM-6 drifting from its documented state
- Jira shows 47 open incident tickets the SOC resolved weeks ago → that's a data quality problem, not IR-5 failing
- Wiz finds an overprivileged IAM role nobody mapped to AC-6 → that's a real risk hiding in the gap between tools

Without a system connecting tools to controls, you can't tell the difference between a real gap and a visibility gap. You fail controls for lack of evidence rather than lack of implementation. You miss risks hiding in the space between dashboards nobody is connecting.

This pipeline seeks, corrects, and surfaces. It takes the planned state the SSP describes and uses live tool evidence to determine how closely the actual state matches it — control by control, component by component, every day.

| The old way | This pipeline |
|---|---|
| SSP updated manually before audits | SSP continuously reconciled against live API evidence |
| Pass or fail — no context | Five outcome states that reflect what the evidence actually shows |
| Controls fail for lack of evidence | Evidence gap vs. real gap identified and flagged separately |
| Data quality issues look like control failures | Data quality flags are explicit — SOC ticket hygiene ≠ IR-5 failure |
| One dashboard per tool, no synthesis | 19 tools synthesized into one evidence picture per control |
| ISSO collects evidence, updates documents | ISSO reviews a structured brief and makes judgment calls |
| SSP as a snapshot of planned intent | SSP as a living description of actual implemented state |

The end goal is an AI agent that reasons across every component, every tool, every control — and tells you not just where the gap is, but what it would take to close it, and whether a compensating control already covers it. The SSP becomes what it was always supposed to be.

---

## What This Project Demonstrates

For GRC Managers, ISSOs, and security leaders evaluating this work:

**Security first, compliance as the byproduct.** The goal isn't an easier audit. It's continuous visibility into actual security posture — what's in place, what's drifted, what's unknown, and what the real risk is. When security is done right and continuously, the SSP stays current and the audit takes care of itself.

**Shift left in practice.** Catching drift at the tool level before it surfaces in an assessment or an incident. Building infrastructure that keeps posture visible across multiple systems — not siloed in one dashboard nobody is connecting to anything else. This is what shift left looks like applied to security assurance, not just development.

**Closing the unknowns.** Most organizations have the tools. What they don't have is a system that connects them, maps findings to a baseline, and surfaces what's known, what's unknown, and what the residual risk actually is. Unknowns are where incidents live. This pipeline makes them visible.

**Real operational experience.** The troubleshooting docs, the data quality handling, the SOC ticket hygiene problem, the SSL inspection workarounds — these came from running this against production security tool APIs. The design reflects what security engineering looks like in practice, not in a lab.

**Honest about the limits of automation.** The ISSO's role is not eliminated — it's elevated. Every design decision draws a clear line between what can be determined systematically and what requires professional judgment on risk. That line is load-bearing.

---

## How It Works — Plain English

**The problem:** Your System Security Plan says controls are "Implemented." Your security tools may tell a different story. Nobody is connecting the two systematically. Auditors read the SSP. Engineers look at tool dashboards. The gap between them is where real risk lives.

**The pipeline:**

```
Your legacy Excel SSP
        ↓
Step 1: Convert to OSCAL JSON (the living document)
        ↓
Step 2: Pull evidence from security tool APIs daily
        Wiz    → cloud misconfigurations, vulnerabilities
        Jira   → process controls, change tickets, POA&M
        Tanium → endpoint patch compliance, disk encryption
        Splunk → audit log coverage and retention
        + 15 more connectors planned
        ↓
Step 3: Reconcile — compare what the SSP claims vs. what tools show
        ↓
Step 4: ISSO reviews a structured brief, applies judgment, signs off
        ↓
Submission-ready OSCAL output
```

**The five outcome states** (instead of pass/fail):

| State | What It Means |
|---|---|
| `CONFIRMED` | SSP claim supported by evidence from all relevant tools |
| `PARTIAL` | Some tools confirm — gaps exist or connectors not yet active |
| `CONTRADICTED` | SSP claims implemented. Evidence directly contradicts it. |
| `UNDOCUMENTED` | Tool evidence shows something working. SSP doesn't mention it. |
| `DRAFT-NEEDED` | No automated evidence. Narrative missing or stale. |

**Every confirmed control is sourced back to the tool that proved it** — not just a green light, but a named source, a timestamp, and an archived evidence record. This is what makes Phase 2 possible: once you know precisely what's in place and where the proof lives, you stop re-litigating what's working and focus entirely on what isn't. Every assessment cycle stops starting from scratch. The conversation with teams, leadership, and auditors becomes targeted — here's what's solid, here's what's not, here's what's needed to close the gap.

---

## Sample Deliverables

### 1. Reconciliation Report — The ISSO Brief

This is what `reconcile_oscal.py` produces. It replaces the manual process of reviewing tool dashboards and updating the SSP by hand.

```json
{
  "generated": "2025-01-15T09:23:11Z",
  "summary": {
    "CONFIRMED": 11,    // SSP claim supported by API evidence
    "PARTIAL": 8,       // evidence exists but gaps remain
    "CONTRADICTED": 2,  // SSP claim directly contradicted by tools
    "UNDOCUMENTED": 1,  // tools show implementation not in SSP
    "DRAFT-NEEDED": 4   // no evidence yet — ISSO action required
  },

  // CONFIRMED example — what a clean control looks like
  "confirmed_controls": [
    {
      "control_id": "ac-2",
      "evidence_sources": ["jira"],
      "reason": "Jira: 14 account requests in 90 days, all approved. Avg resolution 3.2 hours."
    }
  ],

  // CONTRADICTED example — where the SSP and reality don't match
  "contradicted_controls": [
    {
      "control_id": "cm-6",
      "ssp_claim": "All cloud resources meet CIS benchmark baseline.",
      "evidence_shows": "Wiz: 11 open CIS deviations including 2 HIGH — unencrypted EBS volume, public S3 bucket with sensitive data tag.",
      "action_required": "Remediate HIGH findings or update SSP to reflect actual scope. ISSO sign-off required."
    }
  ],

  // Data quality flags — distinguishes real gaps from bad data
  "data_quality_flags": [
    {
      "tool": "jira",
      "control": "ir-5",
      "flag": "Incident count by status (47 open) is inflated. SOC team does not close tickets after resolution. Accurate count from resolution field: 6 unresolved. This is a process gap, not a control failure."
    }
  ],

  // Prioritized action list for the ISSO
  "next_steps": [
    "Remediate 2 CONTRADICTED controls before next assessment",
    "Resolve 2 overdue POA&M items (PROJ-441, PROJ-398)",
    "Schedule IR tabletop exercise — IR-3 has no record in 365 days",
    "Address 3 endpoints missing full disk encryption (SC-28 partial)"
  ]
}
```

> Full sample: [`samples/reconciliation-report-sample.json`](samples/reconciliation-report-sample.json)

---

### 2. OSCAL by-components Structure — One Control, Full Picture

This is what a single control looks like inside `sspp.json` after the pipeline runs. Every tool that can evidence the control gets its own slot — independently verifiable, independently timestamped.

```json
{
  "control-id": "ac-2",

  // Reconciler outcome written as a prop — queryable, not buried in text
  "props": [
    { "name": "reconciler-status",   "value": "CONFIRMED" },
    { "name": "evidence-sources",    "value": "jira, sailpoint" },
    { "name": "last-reconciled",     "value": "2025-01-15T09:23:11Z" }
  ],

  "statements": [{
    "by-components": [

      // Slot 1: The SSP narrative — the authoritative claim
      // Auto-reconciled block prepended; original text preserved below it
      {
        "component-uuid": "<this-system>",
        "description": "[AUTO-RECONCILED 2025-01-15] Validated by: Jira, SailPoint. Jira: 14 account requests in 90 days, all with documented approval chains. Original SSP baseline: Account management implemented through identity governance platform...",
        "implementation-status": { "state": "implemented" },
        "props": [
          { "name": "last-reconciled",        "value": "2025-01-15T09:23:11Z" },
          { "name": "evidence-sources-active","value": "jira" }
        ]
      },

      // Slot 2: Jira evidence — process controls
      // has_data gate: api-ready + last-api-pull must both be set
      // for the reconciler to treat this as real evidence
      {
        "component-uuid": "<jira>",
        "description": "Jira: 14 account requests in last 90 days. 14 resolved. Avg resolution: 3.2 hours.",
        "implementation-status": { "state": "implemented" },
        "props": [
          { "name": "api-ready",      "value": "true" },
          { "name": "last-api-pull",  "value": "2025-01-15T08:01:00Z" }
          //                                    ↑ real timestamp = real evidence
          //                          "never"   = skeleton placeholder, not counted
        ]
      },

      // Slot 3: SailPoint — not yet connected
      // Slot exists, api-ready false, reconciler ignores it
      // This is how the pipeline knows what's missing vs. what's confirmed
      {
        "component-uuid": "<sailpoint>",
        "description": "SailPoint — identity lifecycle evidence for AC-2. API connector not yet integrated.",
        "implementation-status": { "state": "planned" },
        "props": [
          { "name": "api-ready",     "value": "false" },
          { "name": "last-api-pull", "value": "never" }
        ]
      }

    ]
  }]
}
```

> Full sample with all 5 outcome states: [`samples/sspp-sample.json`](samples/sspp-sample.json)

---

### 3. Raw Tool Evidence — What the API Actually Returns

Before evidence gets written into OSCAL, the raw API pull is archived to `evidence/<tool>/YYYY-MM-DD.json`. This is the audit trail.

```json
// evidence/wiz/2025-01-15.json
{
  "pulled_at": "2025-01-15T08:00:00Z",
  "finding_count": 63,

  // Each finding is mapped to NIST controls dynamically —
  // based on what the finding IS, not a pre-declared tool boundary
  "findings": [
    {
      "id": "wiz-finding-00002",
      "severity": "HIGH",
      "type": "misconfiguration",
      "entitySnapshot": {
        "type": "Bucket",
        "cloudPlatform": "AWS"
      },
      "mapped_controls": ["cm-6", "sc-28"]
      //                   ↑ mapped at ingest time from finding characteristics
      //                     not from "Wiz covers the CM family"
    }
  ],

  // Aggregated per control for the reconciler
  "control_summary": {
    "cm-6": { "open_count": 11, "by_severity": { "HIGH": 2, "MEDIUM": 7, "LOW": 2 } },
    "ra-5": { "open_count": 18, "by_severity": { "CRITICAL": 3, "HIGH": 6, "MEDIUM": 8, "LOW": 1 } }
  }
}
```

> Full sample: [`samples/wiz-evidence-sample.json`](samples/wiz-evidence-sample.json)

---

## Getting Started

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the full step-by-step setup guide — environment config, running each connector, interpreting the reconciliation report output, and what to do with ISSO review flags.

---

## Phased Roadmap — Deliberate Progress Over Waiting for Perfect

GRC software is expensive, complex, and slow to deploy. Enterprise platforms take longer to implement than the ATO cycle they're supposed to support. The common response is to wait — for budget approval, for procurement, for the right tool.

This project takes the opposite approach: implement what's possible now, shift how analysts work today, and build toward the full vision incrementally.

```
PHASE 1 — Running Now
─────────────────────────────────────────────────────────────
Ingest evidence from security tool APIs daily
Map findings to NIST 800-53 controls dynamically
Reconcile SSP claims vs. actual tool evidence
Produce 5 outcome states — not pass/fail
Distinguish real control gaps from data quality problems
Flag gaps with owner, tool, evidence path, and action required

IMPACT: Analysts stop chasing evidence and start working
        side by side with engineering teams to reset baselines
        and identify what actually needs fixing.

PHASE 2 — In Development
─────────────────────────────────────────────────────────────
GRC Agent pre-determines implementation accuracy
Reasons about compensating controls across all tools
Cross-references approved exceptions from issue tracker
Separates true security risk from documentation gaps
Drafts implementation narratives grounded in evidence
ISSO reviews a structured brief — not 400 controls of raw data

IMPACT: ISSO role shifts from evidence collector to
        risk decision-maker. Compliance becomes a
        continuous feedback loop, not an annual exercise.

PHASE 3 — Planned
─────────────────────────────────────────────────────────────
Submission-ready output generated on demand
Framework crosswalk handles dual-framework compliance
Continuous ATO posture maintained between assessments
Full identity, endpoint, SIEM, and supply chain coverage

IMPACT: ATO is no longer an event. It's a state.
```

> **The thesis:** You don't need the perfect tool to start. You need to start. Every phase of this pipeline delivers immediate value while building the foundation for the next one.

---
## Project Status

| Component | Status | Notes |
|---|---|---|
| Excel → OSCAL converter | ✅ Complete | UUID v5, by-components, 19 tool slots per control |
| 4-stage OSCAL validation | ✅ Complete | JSON → schema → semantic → NIST conformance |
| Wiz ingest connector | ✅ Complete | GraphQL, raw findings, dynamic control mapping |
| Jira ingest connector | ✅ Complete | JQL-based, process controls, POA&M sync |
| Reconciler — 5 outcome states | ✅ Complete | has_data gate, baseline preservation, report output |
| Interactive demo | ✅ Complete | [Live →](https://grcjp.github.io/OSCAL-Conversion-and-Compliance-Pipeline/) |
| Tanium ingest | 🔄 In Progress | REST API + CSV fallback for on-prem |
| Splunk ingest | 🔄 In Progress | SPL query layer, log source coverage |
| GRC Agent — accuracy pre-determination | 🔄 In Development | Multi-tool synthesis, compensating control reasoning |
| SailPoint / ForgeRock connectors | 📋 Planned | Identity lifecycle evidence |
| Submission export | 📋 Planned | Framework-mapped output on demand |

---

## Docs

- [Architecture & design decisions](docs/ARCHITECTURE.md) — the reasoning behind every major decision
- [Tool evidence map](docs/TOOL_EVIDENCE_MAP.md) — what each tool can and cannot prove per control
- [Troubleshooting](docs/TROUBLESHOOTING.md) — real issues encountered running against production APIs
- [Security notes](SECURITY.md) — TLS configuration and git history guidance

---

## License

MIT — use it, adapt it, build on it.
