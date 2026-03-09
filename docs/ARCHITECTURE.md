# Architecture

This document explains the design decisions behind the pipeline in detail — the reasoning, the dead ends, and why things are the way they are.

---

## The Core Problem

Compliance frameworks like NIST 800-53 require you to *claim* that controls are implemented in a System Security Plan (SSP), and then *prove* those claims with evidence during assessment. In practice, the claim and the proof live in completely different places — the SSP in a document, the evidence scattered across security tools — and they're never systematically compared.

The result is a "split reality" problem:

- Your SSP says AC-2 is "Implemented"
- Your identity governance platform shows 47 accounts with no activity in 90+ days
- Nobody connected those two facts until the auditor did

This pipeline is the connector.

---

## Design Layers

### Layer 1: The OSCAL Skeleton (Master)

The OSCAL file is the single source of truth. Not the SSP Excel. Not the tool dashboards. The OSCAL file is where claims and evidence meet.

This was a non-obvious decision. The natural instinct is to treat the SSP as the master and generate the OSCAL from it. But that makes the SSP the structural driver, which means every structural change (adding a tool, adding a control family) requires changing the SSP first. That's backwards.

The OSCAL skeleton defines the structure. The SSP is one content layer inside it. Tools write evidence into other content layers. The reconciler reads all layers together.

### Layer 2: The SSP Narrative (Claim Layer)

The SSP implementation statement is the authoritative *claim* about how a control is implemented. It says: "We implement AC-2 using our identity governance platform, which provisions accounts within one business day of an approved request and deprovisions within 24 hours of termination."

That claim is preserved in the primary `by-components` entry for the control. The reconciler reads it as the baseline. It is never overwritten — only annotated.

### Layer 3: Tool Evidence Slots (Evidence Layer)

Every tool that can provide evidence for a control gets its own `by-components` entry in the OSCAL structure. These slots start empty (with `last-api-pull: never`). API connectors fill them in with real evidence.

This means:
- You can see which tools have provided evidence for a control and which haven't
- Evidence from different tools doesn't collide
- Each slot has an independent timestamp
- Adding a new tool connector doesn't change the structure — it just starts populating its slots

### Layer 4: The Reconciler (Truth Layer)

The reconciler reads the SSP claim and all tool evidence slots together and determines: is the claim supported by evidence, contradicted by it, or simply unverified?

It does not make a binary pass/fail decision. It produces one of five outcome states (CONFIRMED, PARTIAL, CONTRADICTED, UNDOCUMENTED, DRAFT-NEEDED) and updates the primary narrative to explain what it found.

---

## The by-components Structure

Standard OSCAL `implemented-requirements` look like this:

```json
{
  "control-id": "ac-2",
  "description": "The system implements account management using..."
}
```

This pipeline uses the full `by-components` pattern:

```json
{
  "control-id": "ac-2",
  "statements": [{
    "by-components": [
      {
        "component-uuid": "<this-system>",
        "description": "SSP narrative — the human-written claim",
        "implementation-status": { "state": "planned" },
        "props": [
          { "name": "last-reconciled", "value": "2024-01-15T09:23:11Z" },
          { "name": "evidence-sources-active", "value": "sailpoint, jira" }
        ]
      },
      {
        "component-uuid": "<sailpoint>",
        "description": "SailPoint confirms: 0 accounts inactive > 60 days as of 2024-01-15",
        "implementation-status": { "state": "implemented" },
        "props": [
          { "name": "api-ready", "value": "true" },
          { "name": "last-api-pull", "value": "2024-01-15T08:00:00Z" }
        ]
      },
      {
        "component-uuid": "<jira>",
        "description": "Jira: 12 account requests in last 90 days, all with documented approvals",
        "implementation-status": { "state": "implemented" },
        "props": [
          { "name": "api-ready", "value": "true" },
          { "name": "last-api-pull", "value": "2024-01-15T08:01:00Z" }
        ]
      }
    ]
  }]
}
```

This is more verbose but it's also auditable. You can look at any control and see exactly which tool provided evidence, when it was pulled, and what it showed.

---

## UUID v5: Why Deterministic Identifiers Matter

OSCAL requires UUIDs for every object. The obvious approach is UUID v4 (random). The problem with random UUIDs in a Git-tracked compliance document is that every time you regenerate the OSCAL file, every UUID changes — even if the underlying content didn't. Your Git diff becomes a wall of UUID noise that obscures real changes.

UUID v5 generates a UUID deterministically from a namespace and a name string. Given the same name, you always get the same UUID:

```python
import uuid

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

def stable_uuid(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, name))

stable_uuid("control:ac-2")        # always the same UUID
stable_uuid("component:sailpoint")  # always the same UUID
stable_uuid("req:ac-2:sailpoint")   # always the same UUID
```

Now a Git diff on your OSCAL file shows only what actually changed: a new evidence description, an updated status, a new timestamp. The UUIDs are stable.

---

## Dynamic Control Mapping (Not Pre-Declared)

Early design had tools pre-mapped to control families:

```python
# Wrong approach
TOOL_FAMILIES = {
    "wiz": ["ra", "cm", "si"],
    "sailpoint": ["ac", "ia"],
}
```

This breaks in two ways:

**False positives:** Wiz can evidence CM-6 (security configuration settings) for cloud resources. It cannot evidence CM-6 for on-premises systems it doesn't scan. Pre-declaring "Wiz covers CM" implies it covers all CM controls, which is wrong.

**False negatives:** A Wiz finding about an overprivileged IAM role is relevant to AC-6 (least privilege), not just RA-5 (vulnerability scanning). Pre-declaring family boundaries meant that finding was dropped at ingest instead of mapped to AC-6.

The fix: tools declare specific control IDs they can evidence, not families. And at ingest time, findings are mapped to controls based on the finding's characteristics — not based on a pre-drawn boundary around the tool.

```python
# Correct approach — specific controls only, no family-level claims
TOOL_COVERAGE = {
    "wiz": {
        "controls": ["ra-5", "cm-6", "cm-7", "sa-11", "si-2", "si-3", "si-4", "sc-7"],
        # NOT: "families": ["ra", "cm", "si"]
    }
}
```

---

## The has_data Gate

This was the most consequential bug in the early implementation.

The converter creates skeleton `by-components` entries for every tool across every control. These entries have descriptive text (the boilerplate about what the tool can prove). When the reconciler ran, it checked whether a `by-components` entry had a description, saw the boilerplate, and treated it as evidence. Controls that had no API data were being marked as reconciled.

The fix is a strict gate: a tool slot only counts as having data if:
1. `api-ready` prop is `"true"` **AND**
2. `last-api-pull` prop is a real timestamp (not `"never"`)

If either condition fails, the slot is treated as empty regardless of what the description field contains. The description is documentation. The timestamp is the evidence gate.

```python
def has_real_evidence(by_component: dict) -> bool:
    props = {p["name"]: p["value"] for p in by_component.get("props", [])}
    api_ready = props.get("api-ready", "false") == "true"
    last_pull = props.get("last-api-pull", "never")
    has_timestamp = last_pull != "never" and last_pull != ""
    return api_ready and has_timestamp
```

---

## Baseline Narrative Preservation

The reconciler modifies the primary `by-components` description to reflect what the evidence shows. The temptation is to replace the original SSP narrative with the auto-generated one.

Don't do that.

The original SSP narrative is a compliance artifact. It was written by someone who understood the system. It may contain context that the API evidence doesn't capture. And it's the claim that auditors will compare against the evidence.

The reconciler prepends an `[AUTO-RECONCILED]` block and appends the original text as historical context:

```
[AUTO-RECONCILED 2024-01-15] Control implementation validated by: SailPoint, Jira.
SailPoint confirms 0 accounts inactive >60 days as of 2024-01-15.
Jira documents 12 account provisioning requests in last 90 days, all approved.

Original SSP baseline: The organization implements account management through 
the identity governance platform. Accounts are provisioned within one business 
day of an approved request...

[Human review recommended before submission.]
```

An ISSO reading this sees both the evidence and the original claim. They can verify the auto-generated summary, refine the narrative, and sign off. They're not debugging a script output.

---

## The GRC Agent Layer

The deterministic reconciler handles structured comparisons well. What it can't do:

- Draft a coherent implementation narrative from fragmented evidence
- Reason about whether compensating controls apply
- Interpret ambiguous findings in context
- Cross-reference an exception ticket against a finding

The GRC agent is an LLM layer that handles these cases. It sits after the reconciler and processes only controls flagged as `DRAFT-NEEDED` or `PARTIAL`.

### Prompt Design

The agent receives a structured brief per control:

```
Control: AC-2 Account Management
Requirement: [full control text from NIST catalog]
SSP Claim: [original narrative]
Available Evidence: 
  - SailPoint (pulled 2024-01-15): [evidence summary]
  - Jira (pulled 2024-01-15): [evidence summary]
Missing Evidence: Tanium (not connected), Splunk (not connected)
Related controls with evidence: AC-2(3), AC-5, IA-4
Approved exceptions: [any Jira exception tickets]

Task: Draft an updated implementation statement that accurately reflects 
the available evidence. Flag any gaps the ISSO needs to address.
```

The agent output is a candidate narrative — it goes back into the `by-components` description as a draft, marked for ISSO review. The agent does not make final compliance determinations.

### Data Sovereignty Consideration

If your system processes sensitive data (PII, PHI, regulated federal data), you need to be careful about what goes to an LLM API. The agent brief includes control IDs and evidence summaries — not raw data, but still potentially sensitive in aggregate.

Options in order of data sovereignty strength:
1. **AWS Bedrock** (in an appropriate region) — data stays within your AWS boundary
2. **Local LLM (Ollama)** — data never leaves your environment
3. **Private API endpoint** — depends on your contract terms
4. **Commercial API** — appropriate for non-sensitive systems only

The agent is designed to work with any OpenAI-compatible endpoint. Switch backends by changing the `GRC_AGENT_BACKEND` environment variable.

---

## Validation Pipeline

Between generation and commit, every version of `sspp.json` runs through four validation stages:

1. **JSON syntax** — catches malformed JSON immediately
2. **OSCAL schema** — validates against official NIST OSCAL JSON schemas (Draft-07). Catches wrong field names, missing required fields, incorrect types.
3. **Semantic validation** — Pydantic models catch logically invalid content that passes schema (e.g., a status value that's syntactically valid but not in the allowed enum)
4. **Full NIST conformance** — optional `oscal-cli` check for submission readiness

Nothing commits to version control without passing all four stages. This catches schema drift early — before it becomes an auditor problem.

---

## Lessons From Building This

### The SSP is a claim layer, not the structural driver

Every instinct in the compliance world says "start with the SSP, fill in the tools." That's backwards for automation. The OSCAL skeleton is the master. The SSP is one layer of claims that sits inside it. Tools write evidence into their own slots. The reconciler reads all of it. The SSP narrative updates to reflect what's actually true — not the other way around.

### Pre-declared tool-to-family boundaries cause both false positives and false negatives

A cloud security platform finding tagged "misconfiguration" might evidence CM-6, RA-5, or SC-7 depending on what the misconfiguration actually is. Pre-declaring "this tool covers the CM family" credits it for controls it can't evidence and drops findings relevant to controls outside the declared boundary. The fix: tools declare only the specific control IDs they can genuinely evidence. Everything else maps dynamically at ingest time.

### Data quality issues are not control failures

Your tools will give you operationally bad data. Incident tickets left open after resolution. Patch counts including decommissioned endpoints. Access review completions attributed to the wrong quarter. The pipeline accounts for this explicitly — surfacing data quality flags rather than treating them as control failures. A SOC team that doesn't close tickets is a process problem, not a SI-5 finding.

### An empty slot is more honest than a filled slot with boilerplate

The most counterintuitive lesson: early versions of the reconciler read boilerplate skeleton text and treated it as evidence, producing false-positive confirmations on controls with zero actual API data. Fix: ignore description content entirely. A slot only counts if it has a real pull timestamp. No timestamp = no evidence = don't reconcile.

### Automation is a force multiplier, not a replacement for judgment

The end state is not a fully automated compliance pipeline. The end state is an ISSO who spends their time on judgment calls — not spreadsheet maintenance. Every design decision in this project draws a clear line between what can be determined systematically and what requires a human professional. That line is where ISSO value actually lives.
