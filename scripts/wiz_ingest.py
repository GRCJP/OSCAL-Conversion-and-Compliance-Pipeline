"""
wiz_ingest.py

Ingests cloud security findings from Wiz (or any cloud security platform
with a GraphQL API) and writes evidence into the appropriate by-components
slots in sspp.json.

Key design decisions:
  - Pulls RAW FINDINGS, not compliance posture scores.
    Compliance posture is a pre-packaged product feature that applies the
    vendor's own control mapping logic. This pipeline does its own mapping
    from raw findings so we control the logic and can audit it.
  - Maps findings to controls DYNAMICALLY at ingest time based on finding
    characteristics, not from a pre-declared family boundary.
  - The has_data gate: sets both api-ready and last-api-pull so the
    reconciler recognizes this slot as having real evidence.

Usage:
    python scripts/wiz_ingest.py --oscal oscal/sspp.json

Requirements:
    pip install requests python-dotenv

Environment variables (set in .env):
    WIZ_CLIENT_ID       — Wiz API client ID
    WIZ_CLIENT_SECRET   — Wiz API client secret
    WIZ_API_URL         — https://api.<your-tenant>.wiz.io/graphql
    WIZ_TOKEN_URL       — https://auth.app.wiz.io/oauth/token (or tenant-specific)
"""

import json
import argparse
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')
from datetime import datetime, timezone
from pathlib import Path

import requests

from dotenv import load_dotenv

load_dotenv()


# ── Configuration ─────────────────────────────────────────────────────────────

WIZ_CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
WIZ_CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
WIZ_API_URL = os.getenv("WIZ_API_URL")
WIZ_TOKEN_URL = os.getenv("WIZ_TOKEN_URL", "https://auth.app.wiz.io/oauth/token")

# TLS verification — always verify in production.
# If your environment uses SSL inspection with a custom corporate CA,
# set CA_BUNDLE in .env to the path of your CA certificate bundle.
# Never set this to False in a real deployment.
# Example .env entry:  CA_BUNDLE=/etc/ssl/certs/corporate-ca-bundle.crt
CA_BUNDLE = os.getenv("CA_BUNDLE", True)  # True = use system trust store

# ── Dynamic control mapping ───────────────────────────────────────────────────
# Maps Wiz finding categories to NIST 800-53 Rev 5 control IDs.
# This is the core of the dynamic mapping approach.
# Findings are mapped based on what they actually are, not based on a
# pre-declared boundary around the tool's "jurisdiction."
#
# Extend this mapping to cover your specific finding categories.
# Wiz category names vary by tenant — inspect your actual findings to tune.

FINDING_CATEGORY_TO_CONTROLS = {
    # Vulnerability findings → RA-5 (vulnerability scanning), SI-2 (flaw remediation)
    "vulnerability":          ["ra-5", "si-2"],
    "cve":                    ["ra-5", "si-2"],
    "patch":                  ["si-2"],

    # Configuration drift → CM-6 (configuration settings), CM-7 (least functionality)
    "misconfiguration":       ["cm-6", "cm-7"],
    "configuration":          ["cm-6"],
    "benchmark":              ["cm-6"],
    "cis":                    ["cm-6"],

    # Network exposure → SC-7 (boundary protection)
    "network":                ["sc-7"],
    "exposed":                ["sc-7"],
    "public exposure":        ["sc-7"],

    # Identity and access → handled by identity governance tool, but cloud IAM here
    "iam":                    ["ac-6", "ac-3"],
    "overprivileged":         ["ac-6"],
    "excessive permissions":  ["ac-6"],

    # Secrets and data → SC-28 (protection at rest)
    "secret":                 ["sc-13", "sc-28"],
    "encryption":             ["sc-28", "sc-13"],
    "unencrypted":            ["sc-28"],

    # Container security → CM-7, SI-3
    "container":              ["cm-7", "si-3"],
    "image":                  ["si-3"],

    # Code/supply chain → SA-11, SR-3
    "code":                   ["sa-11"],
    "supply chain":           ["sr-3", "sa-11"],
    "dependency":             ["sr-3"],
}

# Controls this connector can evidence — used to filter OSCAL update targets
WIZ_CONTROLS = [
    "ra-5", "cm-6", "cm-7", "sa-11", "si-2", "si-3", "si-4", "sc-7",
    "ac-3", "ac-6", "sc-13", "sc-28", "sr-3",
]

# GraphQL query — pulls open findings with severity and category
# NOTE: Field availability varies by Wiz tenant and subscription tier.
# If a field returns an error, remove it and use introspection to discover
# available fields: query { __type(name: "Issue") { fields { name } } }
WIZ_FINDINGS_QUERY = """
query GetFindings($first: Int, $after: String) {
  issues(
    filterBy: {
      status: [OPEN, IN_PROGRESS]
    }
    first: $first
    after: $after
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      severity
      status
      type
      entitySnapshot {
        id
        type
        name
        cloudPlatform
        region
      }
      createdAt
    }
  }
}
"""


# ── Authentication ────────────────────────────────────────────────────────────

def get_wiz_token() -> str:
    """Authenticate to Wiz API and return bearer token."""
    if not WIZ_CLIENT_ID or not WIZ_CLIENT_SECRET:
        raise ValueError(
            "WIZ_CLIENT_ID and WIZ_CLIENT_SECRET must be set in .env"
        )

    response = requests.post(
        WIZ_TOKEN_URL,
        json={
            "grant_type": "client_credentials",
            "client_id": WIZ_CLIENT_ID,
            "client_secret": WIZ_CLIENT_SECRET,
            "audience": "wiz-api",
        },
        verify=CA_BUNDLE,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


# ── API calls ─────────────────────────────────────────────────────────────────

def fetch_all_findings(token: str) -> list:
    """
    Fetch all open findings from Wiz, handling pagination.
    Returns list of raw finding objects.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    all_findings = []
    cursor = None
    page = 0

    while True:
        page += 1
        variables = {"first": 500}
        if cursor:
            variables["after"] = cursor

        response = requests.post(
            WIZ_API_URL,
            json={"query": WIZ_FINDINGS_QUERY, "variables": variables},
            headers=headers,
            verify=CA_BUNDLE,
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            raise ValueError(f"GraphQL errors: {data['errors']}")

        issues_data = data.get("data", {}).get("issues", {})
        nodes = issues_data.get("nodes", [])
        all_findings.extend(nodes)

        print(f"  Page {page}: {len(nodes)} findings (total: {len(all_findings)})")

        page_info = issues_data.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")

    return all_findings


# ── Control mapping ───────────────────────────────────────────────────────────

def map_finding_to_controls(finding: dict) -> list:
    """
    Map a Wiz finding to NIST 800-53 control IDs.

    This uses the dynamic approach: look at what the finding actually is
    (type, severity, affected resource) and map to controls accordingly.
    Not based on pre-declared family boundaries.
    """
    finding_type = (finding.get("type") or "").lower()
    controls = set()

    for keyword, control_ids in FINDING_CATEGORY_TO_CONTROLS.items():
        if keyword in finding_type:
            controls.update(control_ids)

    # Severity-based additional mappings
    severity = (finding.get("severity") or "").upper()
    if severity in ("CRITICAL", "HIGH"):
        # High-severity findings always evidence SI-4 (system monitoring)
        controls.add("si-4")

    # Resource type-based mappings
    entity = finding.get("entitySnapshot", {})
    entity_type = (entity.get("type") or "").lower()
    if "container" in entity_type or "pod" in entity_type:
        controls.add("cm-7")
        controls.add("si-3")
    if "storage" in entity_type or "bucket" in entity_type or "volume" in entity_type:
        controls.add("sc-28")

    # Filter to only controls this connector is authorized to evidence
    return [c for c in controls if c in WIZ_CONTROLS]


def aggregate_findings_by_control(findings: list) -> dict:
    """
    Aggregate findings by control ID.
    Returns dict: control_id -> {severity_counts, open_count, finding_types}
    """
    by_control = {}

    for finding in findings:
        mapped_controls = map_finding_to_controls(finding)
        severity = finding.get("severity", "INFORMATIONAL")

        for control_id in mapped_controls:
            if control_id not in by_control:
                by_control[control_id] = {
                    "open_count": 0,
                    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
                    "finding_types": set(),
                }
            by_control[control_id]["open_count"] += 1
            by_control[control_id]["by_severity"][severity] = (
                by_control[control_id]["by_severity"].get(severity, 0) + 1
            )
            finding_type = finding.get("type", "unknown")
            by_control[control_id]["finding_types"].add(finding_type)

    # Convert sets to lists for JSON serialization
    for control_id in by_control:
        by_control[control_id]["finding_types"] = list(by_control[control_id]["finding_types"])

    return by_control


# ── OSCAL update ──────────────────────────────────────────────────────────────

def find_component_uuid(components: list, tool_key: str) -> str:
    """Find the UUID of a component by its tool-key prop."""
    for comp in components:
        for prop in comp.get("props", []):
            if prop.get("name") == "tool-key" and prop.get("value") == tool_key:
                return comp.get("uuid")
    return None


def build_evidence_description(control_id: str, evidence: dict, pull_time: str) -> str:
    """Build a human-readable evidence description for the OSCAL component slot."""
    open_count = evidence["open_count"]
    by_sev = evidence["by_severity"]
    types = ", ".join(evidence["finding_types"][:5])  # First 5 finding types

    critical = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)

    if open_count == 0:
        status_text = "No open findings detected for this control. Control appears clean."
    else:
        sev_breakdown = f"({critical} CRITICAL, {high} HIGH)"
        status_text = (
            f"{open_count} open findings relevant to this control {sev_breakdown}. "
            f"Finding types: {types}."
        )

    return (
        f"Wiz Cloud Security Platform — API evidence for {control_id.upper()} "
        f"pulled {pull_time}. "
        f"{status_text} "
        f"Evidence state: {'implemented' if open_count == 0 else 'partial — findings require remediation'}."
    )


def update_oscal_with_evidence(
    oscal: dict,
    findings_by_control: dict,
    pull_time: str
) -> tuple:
    """
    Write Wiz evidence into the appropriate by-components slots in the OSCAL SSP.
    Returns (updated_oscal, stats_dict).
    """
    ssp = oscal.get("system-security-plan", {})
    components = ssp.get("system-implementation", {}).get("components", [])
    requirements = ssp.get("control-implementation", {}).get("implemented-requirements", [])

    wiz_component_uuid = find_component_uuid(components, "wiz")
    if not wiz_component_uuid:
        print("  ERROR: Wiz component not found in OSCAL component catalog.")
        print("  Ensure excel_to_oscal.py has been run and 'wiz' is in TOOL_CONTROL_COVERAGE.")
        return oscal, {}

    stats = {"updated": 0, "skipped_no_findings": 0, "controls_with_findings": 0}

    for req in requirements:
        control_id = req.get("control-id", "")
        if control_id not in WIZ_CONTROLS:
            continue

        evidence = findings_by_control.get(control_id)
        has_findings = evidence is not None
        if has_findings:
            stats["controls_with_findings"] += 1

        # Find the Wiz by-components slot for this control
        for statement in req.get("statements", []):
            for by_comp in statement.get("by-components", []):
                if by_comp.get("component-uuid") != wiz_component_uuid:
                    continue

                # Determine implementation status based on findings
                if not has_findings:
                    impl_state = "implemented"
                    description = (
                        f"Wiz Cloud Security Platform — no findings for {control_id.upper()} "
                        f"as of {pull_time}. Control appears clean."
                    )
                    stats["skipped_no_findings"] += 1
                else:
                    open_count = evidence["open_count"]
                    impl_state = "implemented" if open_count == 0 else "planned"
                    description = build_evidence_description(control_id, evidence, pull_time)

                # Write evidence into the slot
                by_comp["description"] = description
                by_comp["implementation-status"]["state"] = impl_state

                # Set the has_data gate properties — reconciler checks both of these
                props = by_comp.get("props", [])
                updated_props = []
                for p in props:
                    if p["name"] == "api-ready":
                        updated_props.append({"name": "api-ready", "value": "true"})
                    elif p["name"] == "last-api-pull":
                        updated_props.append({"name": "last-api-pull", "value": pull_time})
                    elif p["name"] == "finding-count" and has_findings:
                        updated_props.append({
                            "name": "finding-count",
                            "value": str(evidence["open_count"])
                        })
                    else:
                        updated_props.append(p)

                if not any(p["name"] == "finding-count" for p in props) and has_findings:
                    updated_props.append({
                        "name": "finding-count",
                        "value": str(evidence["open_count"])
                    })

                by_comp["props"] = updated_props
                stats["updated"] += 1

    return oscal, stats


# ── Main ──────────────────────────────────────────────────────────────────────

def run_wiz_ingest(oscal_path: str):
    print(f"\n{'='*60}")
    print(f"  Wiz Cloud Security Ingest")
    print(f"{'='*60}")
    print(f"  OSCAL:    {oscal_path}")
    print(f"  Tenant:   {WIZ_API_URL}")
    print(f"{'='*60}\n")

    # Load OSCAL
    try:
        with open(oscal_path, "r", encoding="utf-8") as f:
            oscal = json.load(f)
    except Exception as e:
        print(f"  ERROR: Could not load OSCAL: {e}")
        return False

    # Authenticate
    print("  Authenticating to Wiz...")
    try:
        token = get_wiz_token()
        print("  Authentication successful.\n")
    except Exception as e:
        print(f"  ERROR: Authentication failed: {e}")
        return False

    # Fetch findings
    print("  Fetching open findings...")
    try:
        findings = fetch_all_findings(token)
        print(f"  Total findings fetched: {len(findings)}\n")
    except Exception as e:
        print(f"  ERROR: Could not fetch findings: {e}")
        return False

    # Save raw evidence archive (dated, for audit trail)
    pull_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pull_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    evidence_dir = Path("evidence/wiz")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / f"{pull_date}.json"

    with open(evidence_file, "w", encoding="utf-8") as f:
        json.dump({
            "pulled_at": pull_time,
            "finding_count": len(findings),
            "findings": findings
        }, f, indent=2, ensure_ascii=False)

    print(f"  Raw evidence archived: {evidence_file}")

    # Aggregate and map findings
    print("  Mapping findings to NIST controls...")
    findings_by_control = aggregate_findings_by_control(findings)
    print(f"  Controls with findings: {len(findings_by_control)}")
    for control_id, evidence in sorted(findings_by_control.items()):
        print(f"    {control_id.upper():<15} {evidence['open_count']} findings")
    print()

    # Update OSCAL
    print("  Writing evidence to OSCAL by-components slots...")
    updated_oscal, stats = update_oscal_with_evidence(oscal, findings_by_control, pull_time)

    print(f"\n  Results:")
    print(f"    Controls updated:          {stats['updated']}")
    print(f"    Controls with findings:    {stats['controls_with_findings']}")
    print(f"    Controls clean (no finds): {stats['skipped_no_findings']}")

    # Write updated OSCAL
    with open(oscal_path, "w", encoding="utf-8") as f:
        json.dump(updated_oscal, f, indent=2, ensure_ascii=False)

    print(f"\n  OSCAL updated: {oscal_path}")
    print(f"\n  Next step: run reconcile_oscal.py to process this evidence.")
    print(f"{'='*60}\n")

    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ingest Wiz cloud security findings into OSCAL SSPP"
    )
    parser.add_argument(
        "--oscal",
        default="oscal/sspp.json",
        help="Path to OSCAL SSPP JSON file"
    )
    args = parser.parse_args()
    run_wiz_ingest(args.oscal)
