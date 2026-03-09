"""
jira_ingest.py

Ingests process control evidence from Jira and writes it into the
appropriate by-components slots in sspp.json.

Jira is the primary evidence source for PROCESS controls — controls that
require documented human workflows rather than technical configurations:
  - Account provisioning approval chains (AC-2)
  - Change request tickets with security impact analysis (CM-3, CM-4)
  - Incident tracking and response records (IR-5)
  - POA&M items with owners and due dates (CA-5)
  - Security testing and tabletop exercise records (IR-3)

Key design note on incident count inflation:
  SOC teams often don't close Jira tickets after incident resolution.
  This script filters on the 'resolution' field, not 'status', to get
  accurate closed incident counts. The raw inflation is documented as a
  data quality issue in the reconciliation report — not a control failure.

Usage:
    python scripts/jira_ingest.py --oscal oscal/sspp.json

Requirements:
    pip install requests python-dotenv

Environment variables (set in .env):
    JIRA_URL         — https://your-org.atlassian.net (or on-prem URL)
    JIRA_TOKEN       — API token (cloud) or personal access token (on-prem)
    JIRA_USERNAME    — Email address (cloud Jira only)
    JIRA_PROJECTS    — Comma-separated project keys: PROJ1,PROJ2
    JIRA_SIA_FIELD   — Custom field ID for Security Impact Analysis, e.g. customfield_11809
                       Discover with: GET /rest/api/2/field and search for your field name
"""

import json
import argparse
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()


# ── Configuration ─────────────────────────────────────────────────────────────

JIRA_URL = os.getenv("JIRA_URL", "").rstrip("/")
JIRA_TOKEN = os.getenv("JIRA_TOKEN", "")
JIRA_USERNAME = os.getenv("JIRA_USERNAME", "")  # Required for cloud Jira
JIRA_PROJECTS = [p.strip() for p in os.getenv("JIRA_PROJECTS", "").split(",") if p.strip()]

# Custom field ID for Security Impact Analysis
# Discover yours: GET /rest/api/2/field — look for your field's 'id' value
# Example: "customfield_11809"
SIA_FIELD = os.getenv("JIRA_SIA_FIELD", "customfield_10000")

# Evidence lookback window (days) — how far back to look for evidence
LOOKBACK_DAYS = int(os.getenv("JIRA_LOOKBACK_DAYS", "90"))

# TLS verification — always verify in production.
# If your environment uses SSL inspection with a custom corporate CA,
# set CA_BUNDLE in .env to the path of your CA certificate bundle.
# Never set this to False in a real deployment.
# Example .env entry:  CA_BUNDLE=/etc/ssl/certs/corporate-ca-bundle.crt
CA_BUNDLE = os.getenv("CA_BUNDLE", True)  # True = use system trust store

# Controls this connector evidences
JIRA_CONTROLS = ["ac-2", "cm-3", "cm-4", "ir-5", "ca-5", "ir-3"]


# ── Authentication helper ─────────────────────────────────────────────────────

def get_headers() -> dict:
    """
    Build Jira auth headers.
    Cloud Jira: Basic auth with email + API token
    On-prem Jira (Data Center): Bearer token (personal access token)
    """
    if JIRA_USERNAME:
        # Cloud Jira — Basic auth
        import base64
        credentials = base64.b64encode(
            f"{JIRA_USERNAME}:{JIRA_TOKEN}".encode()
        ).decode()
        return {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
        }
    else:
        # On-prem Jira Data Center — Bearer token
        return {
            "Authorization": f"Bearer {JIRA_TOKEN}",
            "Content-Type": "application/json",
        }


# ── JQL helpers ───────────────────────────────────────────────────────────────

def build_project_filter() -> str:
    """Build JQL project filter from configured projects."""
    if not JIRA_PROJECTS:
        return ""
    if len(JIRA_PROJECTS) == 1:
        return f"project = {JIRA_PROJECTS[0]}"
    projects = ", ".join(JIRA_PROJECTS)
    return f"project in ({projects})"


def jql_search(jql: str, fields: list = None, max_results: int = 500) -> list:
    """Execute a JQL search and return all matching issues."""
    headers = get_headers()
    url = f"{JIRA_URL}/rest/api/2/search"

    all_issues = []
    start_at = 0

    while True:
        params = {
            "jql": jql,
            "startAt": start_at,
            "maxResults": min(100, max_results - len(all_issues)),
        }
        if fields:
            params["fields"] = ",".join(fields)

        response = requests.get(
            url, headers=headers, params=params,
            verify=CA_BUNDLE, timeout=30
        )
        response.raise_for_status()
        data = response.json()

        issues = data.get("issues", [])
        all_issues.extend(issues)

        total = data.get("total", 0)
        start_at += len(issues)

        if start_at >= total or len(all_issues) >= max_results or not issues:
            break

    return all_issues


# ── Evidence collection ───────────────────────────────────────────────────────

def get_account_request_evidence() -> dict:
    """
    AC-2: Account management process evidence.
    Looks for account provisioning/deprovisioning tickets with approval chains.
    """
    project_filter = build_project_filter()
    date_filter = f"created >= -{LOOKBACK_DAYS}d"

    # Adjust issuetype to match your Jira issue type names
    jql = f'{project_filter} AND issuetype = "Account Request" AND {date_filter}'

    try:
        issues = jql_search(jql, fields=["summary", "status", "resolution", "created", "resolutiondate"])
    except Exception as e:
        print(f"  WARNING: Account request query failed: {e}")
        return {}

    total = len(issues)
    resolved = [i for i in issues if i.get("fields", {}).get("resolution")]
    avg_resolution_hours = None

    if resolved:
        resolution_times = []
        for issue in resolved:
            created = issue["fields"].get("created")
            resolved_date = issue["fields"].get("resolutiondate")
            if created and resolved_date:
                try:
                    c = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    r = datetime.fromisoformat(resolved_date.replace("Z", "+00:00"))
                    resolution_times.append((r - c).total_seconds() / 3600)
                except Exception:
                    pass
        if resolution_times:
            avg_resolution_hours = round(sum(resolution_times) / len(resolution_times), 1)

    return {
        "total_requests": total,
        "resolved_requests": len(resolved),
        "avg_resolution_hours": avg_resolution_hours,
        "lookback_days": LOOKBACK_DAYS,
    }


def get_change_request_evidence() -> dict:
    """
    CM-3, CM-4: Change management and impact analysis evidence.
    Looks for change tickets with security impact analysis completed.
    """
    project_filter = build_project_filter()
    date_filter = f"created >= -{LOOKBACK_DAYS}d"

    # Total change requests
    jql_all = f'{project_filter} AND issuetype = "Change Request" AND {date_filter}'
    # Change requests with security impact analysis field populated
    # cf[XXXXX] is the JQL syntax for custom fields
    jql_with_sia = (
        f'{project_filter} AND issuetype = "Change Request" '
        f'AND cf[{SIA_FIELD.replace("customfield_", "")}] is not EMPTY '
        f'AND {date_filter}'
    )

    try:
        all_changes = jql_search(jql_all, fields=["summary", "status"])
        changes_with_sia = jql_search(jql_with_sia, fields=["summary"])
    except Exception as e:
        print(f"  WARNING: Change request query failed: {e}")
        return {}

    total = len(all_changes)
    with_sia = len(changes_with_sia)
    sia_completion_pct = round(with_sia / total * 100, 1) if total > 0 else 0

    return {
        "total_change_requests": total,
        "with_security_impact_analysis": with_sia,
        "sia_completion_percent": sia_completion_pct,
        "lookback_days": LOOKBACK_DAYS,
    }


def get_incident_evidence() -> dict:
    """
    IR-5: Incident monitoring and tracking evidence.

    NOTE on data quality: SOC teams often leave tickets open after resolution.
    This query uses 'resolution is not EMPTY' instead of 'status = Done'
    to get accurate resolved counts.
    The raw open count vs. resolution-filtered count difference is documented
    as a data quality issue, not a control failure.
    """
    project_filter = build_project_filter()
    date_filter = f"created >= -{LOOKBACK_DAYS}d"

    jql_all = f'{project_filter} AND issuetype = "Security Incident" AND {date_filter}'
    jql_resolved = (
        f'{project_filter} AND issuetype = "Security Incident" '
        f'AND resolution is not EMPTY AND {date_filter}'
    )

    try:
        all_incidents = jql_search(jql_all, fields=["summary", "status", "priority", "resolution"])
        resolved_incidents = jql_search(jql_resolved, fields=["summary", "resolutiondate"])
    except Exception as e:
        print(f"  WARNING: Incident query failed: {e}")
        return {}

    total = len(all_incidents)
    resolved = len(resolved_incidents)
    # Raw open count using status field (inflated due to SOC workflow)
    open_by_status = len([i for i in all_incidents
                          if i.get("fields", {}).get("status", {}).get("name") not in
                          ("Done", "Closed", "Resolved")])

    return {
        "total_incidents": total,
        "resolved_by_resolution_field": resolved,
        "open_by_status_field": open_by_status,
        "data_quality_note": (
            f"Open count by status ({open_by_status}) may be inflated if SOC team "
            f"does not close tickets after resolution. Using resolution field "
            f"({total - resolved} unresolved) for accurate count."
        ),
        "lookback_days": LOOKBACK_DAYS,
    }


def get_poam_evidence() -> dict:
    """
    CA-5: Plan of Action and Milestones tracking.
    Looks for POA&M-labeled tickets with owners and due dates.
    """
    project_filter = build_project_filter()
    jql = f'{project_filter} AND labels = poam AND status != Done'

    try:
        poam_items = jql_search(
            jql,
            fields=["summary", "status", "priority", "duedate", "assignee"]
        )
    except Exception as e:
        print(f"  WARNING: POA&M query failed: {e}")
        return {}

    overdue = []
    for item in poam_items:
        due = item.get("fields", {}).get("duedate")
        if due:
            try:
                due_date = datetime.fromisoformat(due)
                if due_date.date() < datetime.now().date():
                    overdue.append(item["key"])
            except Exception:
                pass

    return {
        "open_poam_items": len(poam_items),
        "overdue_items": len(overdue),
        "overdue_keys": overdue[:10],  # First 10 for visibility
    }


# ── OSCAL update ──────────────────────────────────────────────────────────────

def find_component_uuid(components: list, tool_key: str) -> str:
    """Find the UUID of a component by its tool-key prop."""
    for comp in components:
        for prop in comp.get("props", []):
            if prop.get("name") == "tool-key" and prop.get("value") == tool_key:
                return comp.get("uuid")
    return None


def build_control_evidence_description(control_id: str, evidence: dict, pull_time: str) -> str:
    """Build OSCAL evidence description for each control type."""
    descriptions = {
        "ac-2": lambda e: (
            f"Jira account management process evidence as of {pull_time}. "
            f"{e.get('total_requests', 0)} account requests in last {e.get('lookback_days', 90)} days. "
            f"{e.get('resolved_requests', 0)} resolved. "
            f"Average resolution time: {e.get('avg_resolution_hours', 'N/A')} hours."
        ),
        "cm-3": lambda e: (
            f"Jira change management evidence as of {pull_time}. "
            f"{e.get('total_change_requests', 0)} change requests in last {e.get('lookback_days', 90)} days. "
            f"Security impact analysis completion: {e.get('sia_completion_percent', 0)}% "
            f"({e.get('with_security_impact_analysis', 0)} of {e.get('total_change_requests', 0)})."
        ),
        "cm-4": lambda e: (
            f"Jira security impact analysis evidence as of {pull_time}. "
            f"{e.get('sia_completion_percent', 0)}% of change requests have documented SIA."
        ),
        "ir-5": lambda e: (
            f"Jira incident monitoring evidence as of {pull_time}. "
            f"{e.get('total_incidents', 0)} incidents in last {e.get('lookback_days', 90)} days. "
            f"{e.get('resolved_by_resolution_field', 0)} resolved (by resolution field). "
            f"Data quality note: {e.get('data_quality_note', '')}"
        ),
        "ca-5": lambda e: (
            f"Jira POA&M tracking evidence as of {pull_time}. "
            f"{e.get('open_poam_items', 0)} open POA&M items. "
            f"{e.get('overdue_items', 0)} overdue. "
            f"{'Overdue items: ' + ', '.join(e.get('overdue_keys', [])) if e.get('overdue_keys') else ''}"
        ),
    }

    builder = descriptions.get(control_id)
    if builder:
        return builder(evidence)
    return (
        f"Jira process control evidence for {control_id.upper()} as of {pull_time}. "
        f"See reconciliation report for details."
    )


def update_oscal_with_evidence(
    oscal: dict,
    evidence_by_control: dict,
    pull_time: str
) -> tuple:
    """Write Jira evidence into the appropriate by-components slots."""
    ssp = oscal.get("system-security-plan", {})
    components = ssp.get("system-implementation", {}).get("components", [])
    requirements = ssp.get("control-implementation", {}).get("implemented-requirements", [])

    jira_component_uuid = find_component_uuid(components, "jira")
    if not jira_component_uuid:
        print("  ERROR: Jira component not found in OSCAL. Run excel_to_oscal.py first.")
        return oscal, {}

    stats = {"updated": 0, "no_evidence": 0}

    for req in requirements:
        control_id = req.get("control-id", "")
        if control_id not in JIRA_CONTROLS:
            continue

        evidence = evidence_by_control.get(control_id)
        if not evidence:
            stats["no_evidence"] += 1
            continue

        for statement in req.get("statements", []):
            for by_comp in statement.get("by-components", []):
                if by_comp.get("component-uuid") != jira_component_uuid:
                    continue

                description = build_control_evidence_description(control_id, evidence, pull_time)
                by_comp["description"] = description
                by_comp["implementation-status"]["state"] = "implemented"

                # Set has_data gate — both required for reconciler to count this as evidence
                props = by_comp.get("props", [])
                updated_props = []
                for p in props:
                    if p["name"] == "api-ready":
                        updated_props.append({"name": "api-ready", "value": "true"})
                    elif p["name"] == "last-api-pull":
                        updated_props.append({"name": "last-api-pull", "value": pull_time})
                    else:
                        updated_props.append(p)
                by_comp["props"] = updated_props
                stats["updated"] += 1

    return oscal, stats


# ── Main ──────────────────────────────────────────────────────────────────────

def run_jira_ingest(oscal_path: str):
    print(f"\n{'='*60}")
    print(f"  Jira Process Control Ingest")
    print(f"{'='*60}")
    print(f"  OSCAL:      {oscal_path}")
    print(f"  Jira URL:   {JIRA_URL}")
    print(f"  Projects:   {', '.join(JIRA_PROJECTS)}")
    print(f"  Lookback:   {LOOKBACK_DAYS} days")
    print(f"{'='*60}\n")

    if not JIRA_URL or not JIRA_TOKEN:
        print("  ERROR: JIRA_URL and JIRA_TOKEN must be set in .env")
        return False

    try:
        with open(oscal_path, "r", encoding="utf-8") as f:
            oscal = json.load(f)
    except Exception as e:
        print(f"  ERROR: Could not load OSCAL: {e}")
        return False

    pull_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pull_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Collect evidence for each control type
    print("  Collecting Jira evidence by control...\n")

    evidence_by_control = {}

    print("  AC-2: Account management...")
    ac2_evidence = get_account_request_evidence()
    if ac2_evidence:
        evidence_by_control["ac-2"] = ac2_evidence
        print(f"    {ac2_evidence.get('total_requests', 0)} account requests found")

    print("  CM-3/CM-4: Change management...")
    cm_evidence = get_change_request_evidence()
    if cm_evidence:
        evidence_by_control["cm-3"] = cm_evidence
        evidence_by_control["cm-4"] = cm_evidence
        print(f"    {cm_evidence.get('total_change_requests', 0)} change requests, "
              f"{cm_evidence.get('sia_completion_percent', 0)}% with SIA")

    print("  IR-5: Incident tracking...")
    ir_evidence = get_incident_evidence()
    if ir_evidence:
        evidence_by_control["ir-5"] = ir_evidence
        print(f"    {ir_evidence.get('total_incidents', 0)} incidents "
              f"({ir_evidence.get('resolved_by_resolution_field', 0)} resolved)")
        if ir_evidence.get("data_quality_note"):
            print(f"    DATA QUALITY: {ir_evidence['data_quality_note'][:80]}...")

    print("  CA-5: POA&M tracking...")
    poam_evidence = get_poam_evidence()
    if poam_evidence:
        evidence_by_control["ca-5"] = poam_evidence
        print(f"    {poam_evidence.get('open_poam_items', 0)} open POA&M items, "
              f"{poam_evidence.get('overdue_items', 0)} overdue")

    print()

    # Archive raw evidence
    evidence_dir = Path("evidence/jira")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / f"{pull_date}.json"
    with open(evidence_file, "w", encoding="utf-8") as f:
        json.dump({
            "pulled_at": pull_time,
            "lookback_days": LOOKBACK_DAYS,
            "evidence_by_control": evidence_by_control
        }, f, indent=2, ensure_ascii=False)
    print(f"  Raw evidence archived: {evidence_file}")

    # Update OSCAL
    print("  Writing evidence to OSCAL by-components slots...")
    updated_oscal, stats = update_oscal_with_evidence(oscal, evidence_by_control, pull_time)

    print(f"\n  Results:")
    print(f"    Controls updated:      {stats['updated']}")
    print(f"    Controls no evidence:  {stats['no_evidence']}")

    with open(oscal_path, "w", encoding="utf-8") as f:
        json.dump(updated_oscal, f, indent=2, ensure_ascii=False)

    print(f"\n  OSCAL updated: {oscal_path}")
    print(f"  Next step: run reconcile_oscal.py to process this evidence.")
    print(f"{'='*60}\n")
    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ingest Jira process control evidence into OSCAL SSPP"
    )
    parser.add_argument("--oscal", default="oscal/sspp.json", help="Path to OSCAL SSPP JSON")
    args = parser.parse_args()
    run_jira_ingest(args.oscal)
