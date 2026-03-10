# Troubleshooting

Real issues hit during development and how they were resolved. Not a generic FAQ — these are specific problems with specific fixes.

---

## Python / Environment

### SSL inspection breaks pip installs

**Symptom:** `pip install openpyxl` fails with SSL certificate verification error.

**Cause:** Corporate network SSL inspection intercepts the connection to PyPI and presents its own certificate, which pip doesn't trust.

**Fix:**
```bash
pip install openpyxl --trusted-host pypi.org --trusted-host files.pythonhosted.org
```

Add these flags to every pip install on a managed corporate network. If you're on Windows, use `py -m pip` instead of `pip`.

---

### CRLF line endings break `.env` file parsing

**Symptom:** Script loads `.env` file but environment variables contain `\r` characters. API calls fail with authentication errors that don't make sense.

**Cause:** Windows line endings (CRLF) in a `.env` file parsed by a script expecting LF. The `\r` gets included in the variable value.

**Fix:**
```bash
# Convert in place
tr -d '\r' < .env > .env.clean && mv .env.clean .env
```

Or in Python, strip explicitly:
```python
value = os.getenv("WIZ_CLIENT_SECRET", "").strip()
```

---

### `python` not found on Windows, use `py`

On Windows systems where Python was installed from python.org (not the Microsoft Store), the launcher is `py`, not `python`:

```bash
# Wrong
python scripts/excel_to_oscal.py

# Right
py scripts/excel_to_oscal.py
py -m pip install openpyxl
```

---

## OSCAL Generation

### UUID churn makes Git diffs unreadable

**Symptom:** After re-running the converter, `git diff oscal/sspp.json` shows thousands of changed lines — almost all of them UUIDs.

**Cause:** UUID v4 (random) generates new UUIDs on every run. The content didn't change, but every identifier did.

**Fix:** Switch to UUID v5 (deterministic). Same name always produces same UUID.

```python
import uuid

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

def stable_uuid(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, name))

# Now diffs only show actual content changes
stable_uuid("control:ac-2")  # always identical
```

---

### Sheet name not found in Excel

**Symptom:** `KeyError: 'Sheet1'` or similar when opening the Excel SSP.

**Cause:** The sheet name in the converter config doesn't match the actual sheet name in the workbook.

**Fix:**
```python
import openpyxl
wb = openpyxl.load_workbook("your-ssp.xlsx", data_only=True)
print(wb.sheetnames)  # see actual sheet names
```

Update `SHEET_NAME` in `excel_to_oscal.py` to match.

---

### Header row offset — controls start at wrong row

**Symptom:** First several rows of output contain column headers or blank rows, not actual control data.

**Cause:** `DATA_START_ROW` is set incorrectly. Some SSP Excel files have merged header rows, title rows, or blank spacer rows before the data.

**Fix:** Open the file, find the row number where your first actual control data row is, and set:
```python
HEADER_ROW = 31    # adjust to where your headers are
DATA_START_ROW = 32  # adjust to where data starts
```

---

## Wiz API

### `frameworks` field not available on tenant

**Symptom:** GraphQL query fails with field not found error on `frameworks` or `enabled`.

**Cause:** Wiz API surface varies by tenant and subscription tier. Some fields present in documentation are not available on all tenants.

**Fix:** Remove unavailable fields from your GraphQL query. Use introspection to discover what's actually available:

```graphql
{
  __type(name: "Issue") {
    fields {
      name
      type { name }
    }
  }
}
```

Build your query from what the introspection returns, not from documentation that may reflect a different tier.

---

### Wiz compliance posture vs. raw findings — use raw findings

**Symptom:** Wiz compliance posture API returns pre-mapped framework scores. These look useful but break the pipeline's mapping logic.

**Cause:** Wiz's compliance posture feature applies Wiz's own control mapping logic. You lose visibility into the underlying findings and can't apply your own mapping rules.

**Fix:** Query the Issues API for raw findings, not the compliance posture endpoint. Map findings to controls yourself based on finding category, severity, and affected resource type.

```graphql
query GetFindings {
  issues(
    filterBy: { status: [OPEN, IN_PROGRESS] }
    first: 500
  ) {
    nodes {
      id
      severity
      status
      type
      entitySnapshot {
        id
        type
        name
        region
        cloudPlatform
      }
      createdAt
    }
  }
}
```

---

### SSL verification failure in API calls

**Symptom:** `requests.exceptions.SSLError` on API calls within corporate network.

**Cause:** Same SSL inspection issue as pip, but affecting API calls. Your corporate network intercepts TLS connections and presents its own certificate, which the system trust store doesn't recognize.

**The correct fix — pass your corporate CA bundle explicitly:**
```python
# Set CA_BUNDLE in your .env to the path of your corporate CA certificate
# CA_BUNDLE=/etc/ssl/certs/corporate-ca-bundle.crt
import os
ca_bundle = os.getenv("CA_BUNDLE", True)  # True = use system trust store
response = requests.post(url, json=payload, verify=ca_bundle)
```

Your IT/security team can provide the CA bundle. On many corporate systems it is already installed and can be located with:
```bash
# Linux
ls /etc/ssl/certs/

# Windows (PowerShell) — export the corp root cert
Get-ChildItem Cert:\LocalMachine\Root | Where Subject -like "*YourOrg*"
```

**What NOT to do — `verify=False` is not a fix:**

Disabling TLS verification silences the error but removes the protection that TLS is providing. In a compliance pipeline that connects to security tools, this is especially problematic — you lose the guarantee that you are talking to the real tool endpoint and not an intercepting proxy you haven't authorized. Do not ship code with `verify=False`. Do not use it in any environment that touches real evidence or credentials, even temporarily.

---

## Jira API

### Custom field IDs — you can't guess them

**Symptom:** JQL query for `"Security Impact Analysis" is not EMPTY` returns no results even though tickets clearly have that field populated.

**Cause:** Jira custom fields are referenced by ID (`customfield_XXXXX`), not by display name. The display name varies. The ID is what the API uses.

**Fix:** Discover field IDs through the API:
```bash
curl -u user:token \
  "https://your-jira.domain.com/rest/api/2/field" \
  | python -m json.tool | grep -A2 "Security Impact"
```

Then use the field ID in JQL:
```
cf[11809] is not EMPTY
```

Store the field ID in your `.env`, not hardcoded.

---

### Incident ticket count inflation — SOC doesn't close tickets

**Symptom:** IR-5 (incident tracking) shows 200+ open incidents. Actual security team says there are maybe 5 active incidents.

**Cause:** SOC team workflow doesn't include closing Jira tickets after incident resolution. Tickets sit in "In Progress" indefinitely.

**This is a data quality issue, not a control failure.** Handle it in the ingest layer:

```python
# Wrong: use status field
"status = Done"  # misses everything the SOC left open

# Right: use resolution field + time bound
"issuetype = 'Security Incident' AND resolution is not EMPTY"
# Or: filter for tickets with a resolution date set
```

Document the data quality gap in your reconciliation report. Flag it as a process improvement item (SOC ticket hygiene), not as a SI-5 finding. Coordinate with the SOC team on ticket closure workflow.

---

### JQL date functions

Relative dates in JQL use `-Nd` notation, not standard SQL:

```
# Last 90 days
created >= -90d

# Last year
created >= -365d

# Specific date
created >= "2024-01-01"
```

---

## Tanium

### On-prem Tanium with no REST API

**Symptom:** Tanium Connect REST API endpoint returns 404 or connection refused. Tanium is installed on-premises and the REST API module wasn't licensed or enabled.

**Options in priority order:**

1. **Enable Tanium Connect** — work with your Tanium admin to enable the Connect module. This is the clean path.

2. **CSV export** — Tanium's console supports scheduled CSV exports. Configure exports for the queries you need (patch compliance, software inventory, disk encryption status). Drop the CSVs to a shared location and parse them:
   ```python
   # scripts/tanium_ingest.py with CSV fallback
   if TANIUM_API_AVAILABLE:
       data = pull_from_api()
   else:
       data = parse_csv_export("evidence/tanium/latest-patch-report.csv")
   ```

3. **AWS SSM** — if your endpoints are managed by AWS Systems Manager, SSM Patch Manager provides equivalent patch compliance data via AWS API. This works well if Tanium is used for on-prem only and AWS hosts your workloads.

4. **Wiz cloud coverage** — Wiz scans cloud workloads agentlessly and can surface some endpoint-equivalent findings for cloud VMs. This doesn't cover on-prem endpoints.

---

## Reconciler

### False-positive reconciliations — boilerplate treated as evidence

**Symptom:** Reconciler marks controls as `CONFIRMED` even though no API connector has run yet.

**Cause:** The converter generates `by-components` entries with descriptive text. Early reconciler logic checked for description content and treated non-empty descriptions as evidence.

**Fix:** Enforce the `has_data` gate strictly. A slot only counts as evidence if it has both `api-ready: true` AND a real `last-api-pull` timestamp:

```python
def has_real_evidence(by_component: dict) -> bool:
    props = {p["name"]: p["value"] for p in by_component.get("props", [])}
    api_ready = props.get("api-ready", "false") == "true"
    last_pull = props.get("last-api-pull", "never")
    has_timestamp = last_pull not in ("never", "", None)
    return api_ready and has_timestamp
```

Never use description content as an evidence gate.

---

### Broad family-level tool mappings cause false positives

**Symptom:** A tool is credited with evidencing controls it doesn't actually touch. For example, Wiz shows as providing evidence for all RA-family controls, but it can only evidence RA-5.

**Cause:** Tool-to-control mapping defined at the family level instead of specific control IDs.

**Fix:** Map tools to specific control IDs, not families. Use empty `families: []` lists:

```python
# Wrong
"wiz": { "families": ["ra", "cm", "si"] }

# Right
"wiz": { "families": [], "controls": ["ra-5", "cm-6", "cm-7", "si-2", "si-3", "si-4", "sc-7"] }
```

---

## Git Workflow

### Accidentally staged secrets

**Symptom:** `git status` shows `.env` or a credentials file staged for commit.

**Fix — before commit:**
```bash
git reset HEAD .env
```

**Fix — after commit but before push:**
```bash
git reset --soft HEAD~1
git reset HEAD .env
git commit -m "your message"
```

**Fix — after push (worst case):**
Rotate the exposed credentials immediately. Then use `git filter-repo` or BFG Repo Cleaner to remove the secret from history. Force push. Notify your security team.

Prevention: ensure `.gitignore` blocks secrets before you ever do your first commit:

```gitignore
.env
*.pem
*.key
*_token.txt
evidence/wiz/*.json
evidence/tanium/*.json
evidence/jira/*.json
```

---

### Direct commits to main bypass branch protection

**Symptom:** `git push origin main` succeeds even though branch protection should require a PR.

**Cause:** Branch protection not configured, or the user pushing has admin rights that bypass protection rules.

**Fix:** In Bitbucket or GitHub, configure branch protection on `main`:
- Require pull request before merging
- Require at least one approval
- Restrict who can push directly

For Bitbucket Data Center: Repository Settings → Branch Permissions → Add restriction → `main` → Restrict pushes.

---

## Unicode / Encoding

### Windows terminal breaks on non-ASCII characters in OSCAL output

**Symptom:** Script crashes with `UnicodeEncodeError` when printing or writing OSCAL JSON that contains non-ASCII characters (em dashes, smart quotes from Excel cells, etc.).

**Fix:** Force UTF-8 encoding at the start of every script:

```python
import sys
sys.stdout.reconfigure(encoding='utf-8')
```

And write files explicitly with UTF-8:
```python
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
```

The `ensure_ascii=False` keeps non-ASCII characters as-is instead of escaping them, which keeps the JSON human-readable.
