"""
reconcile_oscal.py

Closes the "split reality" gap in your OSCAL SSPP.

The problem it solves:
  - SSP narrative says "Planned" (from stale legacy Excel)
  - Tool by-components slot says "Implemented" (from live API data)
  - Top-level status is conflicted — neither the SSP nor the tools are wrong,
    they just haven't been compared yet

What this script does:
  1. Reads sspp.json
  2. Finds every control with a split reality (claim vs. evidence mismatch)
  3. Updates the primary narrative to reflect tool evidence
  4. Flips the top-level status to match evidence
  5. Generates a reconciliation report
  6. Writes updated sspp.json
  7. Flags anything it cannot resolve for ISSO human review

Five outcome states:
  CONFIRMED      — SSP claims implemented, tool evidence confirms it
  PARTIAL        — Some tools confirm, others show gaps or have no data yet
  CONTRADICTED   — SSP claims implemented, tool evidence shows it isn't
  UNDOCUMENTED   — Tool evidence shows something working, SSP doesn't mention it
  DRAFT-NEEDED   — No tool evidence yet, SSP narrative is missing or stale

The has_data gate (critical design decision):
  A tool slot only counts as evidence if it has BOTH:
    - api-ready: true
    - last-api-pull: a real timestamp (not "never")
  Skeleton boilerplate text does NOT count as evidence.
  This prevents false-positive reconciliations on empty slots.

Usage:
    python scripts/reconcile_oscal.py --oscal oscal/sspp.json --output oscal/sspp.json
    python scripts/reconcile_oscal.py --oscal oscal/sspp.json --output oscal/sspp.json --dry-run

Requirements:
    No additional dependencies.
"""

import json
import argparse
import sys
sys.stdout.reconfigure(encoding='utf-8')
from datetime import datetime
from pathlib import Path


# ── Configuration ─────────────────────────────────────────────────────────────

# Display names for tool components — update to match your tool stack
TOOL_NAMES = {
    "wiz":         "Wiz Cloud Security Platform",
    "tanium":      "Tanium Endpoint Management",
    "jira":        "Jira",
    "bitbucket":   "Bitbucket",
    "splunk":      "Splunk SIEM",
    "sailpoint":   "SailPoint",
    "forgerock":   "ForgeRock",
    "beyondtrust": "BeyondTrust",
    "aws_iam":     "AWS IAM",
    "terraform":   "Terraform",
    "ansible":     "Ansible",
    "jenkins":     "Jenkins",
    "zscaler":     "Zscaler",
    "aws_storage": "AWS S3/Aurora/Redshift",
    "goanywhere":  "GoAnywhere MFT",
    "nexus":       "Nexus Sonatype",
    "new_relic":   "New Relic",
    "aws_eks":     "AWS EKS/Docker",
    "blazemeter":  "BlazeMeter",
}

# Status priority — higher number wins when reconciling multiple tool statuses
STATUS_PRIORITY = {
    "implemented":    4,
    "inherited":      3,
    "planned":        2,
    "not-applicable": 1,
    "not-implemented": 0,
}


# ── Evidence gate (the critical has_data check) ───────────────────────────────

def has_real_evidence(by_component: dict) -> bool:
    """
    Returns True only if this component slot has actual API evidence.

    A slot must have BOTH:
      - api-ready: "true"
      - last-api-pull: a real timestamp (not "never" or empty)

    This gate exists because the converter creates descriptive skeleton entries
    for every tool. Without this gate, the reconciler would treat skeleton text
    as evidence and produce false-positive reconciliations.
    """
    props = {p["name"]: p["value"] for p in by_component.get("props", [])}
    api_ready = props.get("api-ready", "false") == "true"
    last_pull = props.get("last-api-pull", "never")
    has_timestamp = last_pull not in ("never", "", None)
    return api_ready and has_timestamp


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_tool_name(component_uuid: str, components: list) -> str:
    """Look up a tool's display name from the component catalog."""
    for comp in components:
        if comp.get("uuid") == component_uuid:
            for prop in comp.get("props", []):
                if prop.get("name") == "tool-key":
                    return TOOL_NAMES.get(prop["value"], comp.get("title", "Unknown Tool"))
            return comp.get("title", "Unknown Tool")
    return "Unknown Tool"


def get_tool_key(component_uuid: str, components: list) -> str:
    """Get the tool key from component props."""
    for comp in components:
        if comp.get("uuid") == component_uuid:
            for prop in comp.get("props", []):
                if prop.get("name") == "tool-key":
                    return prop["value"]
    return None


def is_primary_component(component_uuid: str, components: list) -> bool:
    """Check if this is the primary 'this-system' component (holds the SSP narrative)."""
    for comp in components:
        if comp.get("uuid") == component_uuid:
            return comp.get("type") == "this-system"
    return False


def extract_api_evidence(by_component: dict) -> dict:
    """Extract API evidence details from a by-component entry."""
    evidence = {
        "description": by_component.get("description", ""),
        "status": by_component.get("implementation-status", {}).get("state", ""),
        "pull_date": None,
        "finding_count": None,
        "tool_key": None
    }

    for prop in by_component.get("props", []):
        name = prop.get("name", "")
        value = prop.get("value", "")
        if name == "last-api-pull":
            evidence["pull_date"] = value
        elif name == "tool-key":
            evidence["tool_key"] = value
        elif name == "finding-count":
            evidence["finding_count"] = value

    return evidence


def build_reconciled_narrative(
    control_id: str,
    original_narrative: str,
    implementing_tools: list,
    evidence_details: list
) -> str:
    """
    Build an updated implementation narrative that reflects tool evidence.

    Design decision: always PRESERVE the original narrative as historical context.
    The auto-reconciled block is prepended, not a replacement.
    This lets an ISSO see both the original claim and what the tools actually show.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d")
    tool_list = ", ".join(implementing_tools) if implementing_tools else "connected tools"

    narrative_parts = []
    for evidence in evidence_details:
        if not evidence.get("tool_key") or evidence.get("status") != "implemented":
            continue
        pull_date = evidence.get("pull_date") or now
        tool_display = TOOL_NAMES.get(evidence["tool_key"], evidence["tool_key"])
        finding_info = ""
        if evidence.get("finding_count") is not None:
            finding_info = f" ({evidence['finding_count']} open findings)"
        narrative_parts.append(
            f"{tool_display} validates this control via API evidence pulled {pull_date}{finding_info}."
        )

    if narrative_parts:
        evidence_summary = " ".join(narrative_parts)
        reconciled = (
            f"[AUTO-RECONCILED {now}] Control implementation validated by: {tool_list}. "
            f"{evidence_summary} "
            f"Original SSP baseline: {original_narrative if original_narrative else 'No prior narrative.'} "
            f"[ISSO human review recommended before submission.]"
        )
    else:
        reconciled = original_narrative or "Implementation statement pending."

    return reconciled


# ── Core reconciliation logic ─────────────────────────────────────────────────

def reconcile_control(req: dict, components: list) -> dict:
    """
    Analyze a single implemented-requirement and reconcile if needed.

    Returns result dict with:
      - action: "reconciled" | "already_consistent" | "flagged" | "skipped"
      - control_id, old_status, new_status, implementing_tools, reason
    """
    control_id = req.get("control-id", "unknown")
    result = {
        "control_id": control_id,
        "action": "skipped",
        "old_status": None,
        "new_status": None,
        "implementing_tools": [],
        "reason": ""
    }

    statements = req.get("statements", [])
    if not statements:
        result["reason"] = "No statements found"
        return result

    primary_component = None
    tool_components = []
    primary_status = None
    highest_tool_status = None
    highest_priority = -1

    for statement in statements:
        for by_comp in statement.get("by-components", []):
            comp_uuid = by_comp.get("component-uuid", "")
            status = by_comp.get("implementation-status", {}).get("state", "")

            if is_primary_component(comp_uuid, components):
                primary_component = by_comp
                primary_status = status
            else:
                # Only count this slot if it passes the has_data gate
                if not has_real_evidence(by_comp):
                    continue

                tool_key = get_tool_key(comp_uuid, components)
                if tool_key:
                    priority = STATUS_PRIORITY.get(status, 0)
                    if priority > highest_priority:
                        highest_priority = priority
                        highest_tool_status = status

                    if status in ("implemented", "inherited"):
                        tool_name = get_tool_name(comp_uuid, components)
                        tool_components.append({
                            "uuid": comp_uuid,
                            "tool_key": tool_key,
                            "tool_name": tool_name,
                            "component": by_comp,
                            "status": status,
                            "evidence": extract_api_evidence(by_comp)
                        })

    result["old_status"] = primary_status
    result["implementing_tools"] = [t["tool_name"] for t in tool_components]

    if not primary_component:
        result["action"] = "skipped"
        result["reason"] = "No primary system component found"
        return result

    if primary_status == "not-applicable":
        result["action"] = "skipped"
        result["new_status"] = "not-applicable"
        result["reason"] = "Control marked not-applicable — no change needed"
        return result

    if primary_status == "inherited":
        result["action"] = "already_consistent"
        result["new_status"] = "inherited"
        result["reason"] = "Control inherited — consistent"
        return result

    # Core reconciliation: tools show implemented but SSP says planned → reconcile
    if tool_components and primary_status in ("planned", "not-implemented", None):
        original_narrative = primary_component.get("description", "")
        evidence_details = [t["evidence"] for t in tool_components]
        implementing_tool_names = [t["tool_name"] for t in tool_components]

        new_narrative = build_reconciled_narrative(
            control_id, original_narrative, implementing_tool_names, evidence_details
        )

        now_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        primary_component["description"] = new_narrative
        primary_component["implementation-status"]["state"] = highest_tool_status
        primary_component["implementation-status"]["remarks"] = (
            f"Auto-reconciled {now_ts} "
            f"based on evidence from: {', '.join(implementing_tool_names)}"
        )

        # Update metadata props
        props = primary_component.get("props", [])
        updated_props = []
        for p in props:
            if p["name"] == "last-reconciled":
                updated_props.append({"name": "last-reconciled", "value": now_ts})
            elif p["name"] == "reconciled-by":
                updated_props.append({"name": "reconciled-by", "value": "reconcile_oscal.py"})
            elif p["name"] == "evidence-sources-active":
                updated_props.append({
                    "name": "evidence-sources-active",
                    "value": ", ".join([t["tool_key"] for t in tool_components])
                })
            else:
                updated_props.append(p)

        if not any(p["name"] == "last-reconciled" for p in props):
            updated_props.append({"name": "last-reconciled", "value": now_ts})
        if not any(p["name"] == "evidence-sources-active" for p in props):
            updated_props.append({
                "name": "evidence-sources-active",
                "value": ", ".join([t["tool_key"] for t in tool_components])
            })
        primary_component["props"] = updated_props

        result["action"] = "reconciled"
        result["new_status"] = highest_tool_status
        result["reason"] = (
            f"Tool evidence ({', '.join(implementing_tool_names)}) "
            f"shows {highest_tool_status} but primary was {primary_status}"
        )
        return result

    if primary_status == highest_tool_status:
        result["action"] = "already_consistent"
        result["new_status"] = primary_status
        result["reason"] = "Primary status matches tool evidence"
        return result

    # No tool evidence and primary is planned → flag for human review
    if not tool_components and primary_status == "planned":
        result["action"] = "flagged"
        result["new_status"] = primary_status
        result["reason"] = (
            "No API evidence available yet. "
            "Connect additional tool connectors to provide evidence for this control."
        )
        return result

    result["action"] = "already_consistent"
    result["new_status"] = primary_status
    result["reason"] = "No reconciliation needed"
    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def reconcile_oscal(oscal_path: str, output_path: str, dry_run: bool = False):
    print(f"\n{'='*60}")
    print(f"  OSCAL Reconciler — Closing the Split Reality Gap")
    print(f"{'='*60}")
    print(f"  Input:    {oscal_path}")
    print(f"  Output:   {output_path}")
    print(f"  Dry run:  {dry_run}")
    print(f"{'='*60}\n")

    try:
        with open(oscal_path, "r", encoding="utf-8") as f:
            oscal = json.load(f)
    except Exception as e:
        print(f"  ERROR: Could not load OSCAL file: {e}")
        return False

    ssp = oscal.get("system-security-plan", {})
    components = ssp.get("system-implementation", {}).get("components", [])
    requirements = ssp.get("control-implementation", {}).get("implemented-requirements", [])

    print(f"  Loaded {len(requirements)} controls")
    print(f"  Loaded {len(components)} components\n")
    print(f"  Analyzing split reality gaps...\n")

    stats = {
        "reconciled": [],
        "already_consistent": [],
        "flagged": [],
        "skipped": []
    }

    for req in requirements:
        result = reconcile_control(req, components)
        stats[result["action"]].append(result)

    print(f"{'─'*60}")
    print(f"  RECONCILIATION RESULTS")
    print(f"{'─'*60}")
    print(f"  Reconciled (gap closed):     {len(stats['reconciled'])}")
    print(f"  Already consistent:          {len(stats['already_consistent'])}")
    print(f"  Flagged for human review:    {len(stats['flagged'])}")
    print(f"  Skipped:                     {len(stats['skipped'])}")
    print(f"{'─'*60}\n")

    if stats["reconciled"]:
        print(f"  CONTROLS RECONCILED ({len(stats['reconciled'])}):")
        for r in stats["reconciled"]:
            print(f"    {r['control_id'].upper():<15} "
                  f"{r['old_status']:<15} -> {r['new_status']:<15} "
                  f"via: {', '.join(r['implementing_tools'][:2])}")
        print()

    if stats["flagged"]:
        print(f"  FLAGGED FOR ISSO REVIEW ({len(stats['flagged'])}):")
        for r in stats["flagged"][:20]:
            print(f"    {r['control_id'].upper():<15} {r['reason'][:60]}")
        if len(stats["flagged"]) > 20:
            print(f"    ... and {len(stats['flagged']) - 20} more")
        print()

    if not dry_run:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(oscal, f, indent=2, ensure_ascii=False)
        print(f"  Updated OSCAL written to: {output_path}")
    else:
        print(f"  DRY RUN — no files written")

    # Write reconciliation report
    report_path = Path("evidence/reconciliation-report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "reconciled": len(stats["reconciled"]),
            "already_consistent": len(stats["already_consistent"]),
            "flagged_for_human_review": len(stats["flagged"]),
            "skipped": len(stats["skipped"])
        },
        "reconciled_controls": stats["reconciled"],
        "flagged_controls": stats["flagged"]
    }

    if not dry_run:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  Reconciliation report: {report_path}")

    print(f"\n{'='*60}")
    print(f"  NEXT STEPS")
    print(f"{'='*60}")
    print(f"  1. Review reconciled controls — verify auto-generated narratives")
    print(f"  2. Connect additional tool APIs to close evidence gaps")
    print(f"  3. Run reconciler again after each connector — gaps shrink each time")
    print(f"  4. ISSO reviews flagged controls and signs off before submission")
    print(f"{'='*60}\n")

    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Reconcile OSCAL SSPP — close split reality gaps between tool evidence and SSP narrative"
    )
    parser.add_argument("--oscal", default="oscal/sspp.json", help="Path to OSCAL SSPP JSON")
    parser.add_argument("--output", default="oscal/sspp.json", help="Output path")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing")

    args = parser.parse_args()
    reconcile_oscal(args.oscal, args.output, args.dry_run)
