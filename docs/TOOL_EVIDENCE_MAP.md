# Tool Evidence Map

The most important reference for understanding what each tool in this pipeline can and cannot prove. This map drives both the by-components structure and the reconciler's evidence evaluation logic.

**The key principle:** No single tool tells the full compliance story. Evidence synthesis across tools is required before any control can be declared implemented or failed.

---

## Reading This Document

Each tool entry includes:
- **Evidence type** — what category of evidence this tool produces
- **Controls it can evidence** — specific NIST 800-53 Rev 5 control IDs
- **What it proves** — specific, concrete claims this tool's data supports
- **What it cannot prove** — explicit boundaries, equally important
- **Integration method** — how the pipeline connects to it
- **Evidence examples** — the actual data points pulled

---

## Cloud Security Platform (e.g., Wiz, Prisma Cloud, Lacework)

**Evidence type:** Technical Configuration / Cloud Security Posture

**Controls it can evidence:**
- `RA-5` — Vulnerability monitoring and scanning
- `CM-6` — Configuration settings
- `CM-7` — Least functionality (unnecessary ports, services, protocols)
- `SA-11` — Developer security testing (IaC scan results)
- `SI-2` — Flaw remediation (open CVEs)
- `SI-3` — Malicious code protection (container image scanning)
- `SI-4` — System monitoring (CSPM continuous monitoring)
- `SC-7` — Boundary protection (exposed ports, network paths)

**What it proves:**
- Open vulnerabilities by severity and affected resource
- CIS benchmark deviations on cloud resources
- Overprivileged IAM roles (cloud-level, not application-level)
- Exposed ports and network paths
- Unencrypted storage resources
- Container image vulnerabilities
- IaC misconfigurations before deployment

**What it cannot prove:**
- Account lifecycle (provisioning, deprovisioning, joiner/mover/leaver)
- Process controls (approval workflows, change management)
- Patch SLAs for on-premises systems it doesn't scan
- Physical controls
- Personnel controls
- Application-level identity governance

**Integration method:** GraphQL API (raw findings endpoint, not compliance posture)

**Evidence examples:**
- "47 open critical CVEs across 12 resources as of 2024-01-15"
- "3 S3 buckets without server-side encryption enabled"
- "IAM role attached to EC2 with admin-equivalent permissions"
- "Port 22 exposed to 0.0.0.0/0 on 2 instances"

---

## Identity Governance Platform (e.g., SailPoint, Saviynt)

**Evidence type:** Identity Lifecycle / Access Governance

**Controls it can evidence:**
- `AC-2` — Account management (full lifecycle)
- `AC-2(2)` — Automated temporary/emergency account management
- `AC-2(3)` — Disable accounts after inactivity (60-day rule)
- `AC-2(4)` — Automated audit of account actions
- `AC-2(5)` — Inactivity logout enforcement
- `AC-5` — Separation of duties (SoD policy enforcement)
- `AC-6` — Least privilege (entitlement reviews)
- `AC-6(7)` — Review of user privileges (quarterly review completion)
- `IA-4` — Identifier management
- `PS-4` — Personnel termination (account disabled within 24 hours)
- `PS-5` — Personnel transfer (access review within 24 hours)

**What it proves:**
- Account provisioning and deprovisioning workflows with timestamps
- Accounts disabled for inactivity (with last-login date)
- Quarterly access certification completion rates
- SoD policy violations currently active
- Temporary account auto-disable within configured SLA
- Time from termination notification to account disable

**What it cannot prove:**
- Network or infrastructure configurations
- Vulnerability findings
- Patch compliance
- Physical access

**Integration method:** REST API

**Evidence examples:**
- "0 active accounts with last login > 60 days as of 2024-01-15"
- "Q4 2023 access certification: 98.3% completion rate"
- "Terminated accounts: avg 4.2 hours to disable (SLA: 24 hours)"
- "2 active SoD violations — both have documented exceptions in Jira"

---

## Authentication Platform (e.g., ForgeRock, PingOne, Okta)

**Evidence type:** Authentication & Session Management

**Controls it can evidence:**
- `IA-2` — Identification and authentication
- `IA-2(1)` — MFA for privileged accounts
- `IA-2(2)` — MFA for non-privileged accounts
- `IA-5` — Authenticator management
- `IA-8` — Non-organizational user authentication
- `AC-12` — Session termination

**What it proves:**
- MFA enrollment rates by user type (privileged vs. standard)
- Authenticator assurance level (AAL1/2/3) by session
- Session timeout enforcement (time to auto-terminate inactive sessions)
- Failed authentication attempts triggering lockout
- Authentication events for audit trail

**What it cannot prove:**
- Account lifecycle (provisioning/deprovisioning — that's the IGA platform)
- Vulnerability findings
- Configuration drift in other systems

**Integration method:** REST API / SCIM events

**Evidence examples:**
- "MFA enrollment: 100% of privileged accounts, 96.2% of standard accounts"
- "Session timeout enforced at 30 minutes for all authenticated sessions"
- "Lockout triggered after 5 failed attempts: policy enforced in 100% of cases"

---

## Privileged Access Management (e.g., BeyondTrust, CyberArk, Delinea)

**Evidence type:** Privileged Access

**Controls it can evidence:**
- `AC-2` — Account management (privileged account subset)
- `AC-6` — Least privilege (privileged access boundaries)
- `AC-17` — Remote access (privileged remote sessions)
- `AU-2` — Event logging (privileged session recording)
- `IA-5` — Authenticator management (credential vault)

**What it proves:**
- Privileged sessions recorded (timestamp, user, duration, commands)
- Credential rotation compliance by account type
- Just-in-time access grant and revocation events
- Shared account usage (who used which shared credential and when)

**What it cannot prove:**
- Non-privileged account lifecycle
- Vulnerability findings in scanned systems
- Application-level access controls

**Integration method:** REST API

---

## Endpoint Management Platform (e.g., Tanium, CrowdStrike, BigFix)

**Evidence type:** Endpoint Compliance

**Controls it can evidence:**
- `SI-2` — Flaw remediation (patch compliance by SLA)
- `CM-8` — System component inventory (software and hardware inventory)
- `RA-5` — Vulnerability monitoring (endpoint-side)
- `CM-3` — Configuration change control (unauthorized change detection)
- `SC-28` — Protection of information at rest (disk encryption status)

**What it proves:**
- Patch compliance percentage by severity tier (critical/high/moderate)
- Time-to-patch against defined SLA
- Endpoints missing full disk encryption
- Unauthorized software detected on managed endpoints
- Hardware and software inventory completeness

**What it cannot prove:**
- Cloud infrastructure configurations
- Identity governance
- Network boundary controls (cloud-layer)
- Process controls

**Integration method:** REST API (or CSV export fallback for on-prem instances)

**Patch SLA triage logic:**
- Critical: compliant if applied within 15 days
- High: compliant if applied within 30 days
- Moderate: compliant if applied within 90 days
- Low: compliant if applied within 180 days

**Evidence examples:**
- "Critical patch compliance: 94.7% (SLA: 15 days)"
- "Endpoints without FDE: 3 of 847 (0.35%) — all flagged for remediation"
- "Unauthorized software detected: 0 incidents in last 30 days"

---

## Issue Tracker / ITSM (e.g., Jira, ServiceNow)

**Evidence type:** Process Controls & POA&M

**Controls it can evidence:**
- `AC-2` — Account management (provisioning approval workflow)
- `CM-3` — Configuration change control (change request tickets)
- `CM-4` — Impact analysis (security impact analysis field on change requests)
- `IR-5` — Incident monitoring (incident ticket tracking)
- `CA-5` — Plan of action and milestones (POA&M items)
- `IR-3` — Incident response testing (tabletop exercise records)

**What it proves:**
- Account provisioning tickets with documented approval chains
- Change request tickets with security impact analysis completed
- Open POA&M items with owners, due dates, and status
- Incident records with timeline and resolution documentation
- Exception approval tickets (cross-referenced against findings)

**What it cannot prove:**
- Technical configurations
- Vulnerability details
- Endpoint patch status

**Integration method:** REST API using JQL queries

**Key JQL patterns:**
```
# Account provisioning evidence
issuetype = "Account Request" AND status = Done AND created >= -90d

# Change management evidence (check for SIA field)
issuetype = "Change Request" AND cf[FIELD_ID] is not EMPTY

# Incident tracking (use resolution, not status — SOC may leave tickets open)
issuetype = "Security Incident" AND resolution is not EMPTY

# POA&M tracking
labels = poam AND status != Done
```

**Data quality note:** Incident counts from the issue tracker are often inflated because tickets aren't closed after resolution. Always filter on resolution field, not status, when counting closed incidents. Document this as a data quality issue, not a control failure.

---

## SIEM (e.g., Splunk, Microsoft Sentinel, IBM QRadar)

**Evidence type:** Audit Logs & Security Event Monitoring

**Controls it can evidence:**
- `AU-2` — Event logging (what events are captured)
- `AU-3` — Content of audit records
- `AU-6` — Audit record review
- `AU-9` — Protection of audit information
- `AU-11` — Audit record retention
- `SI-4` — System monitoring (correlation rule coverage)
- `IR-5` — Incident monitoring (alert-to-response times)

**What it proves:**
- Log source completeness (which systems are shipping logs)
- Audit log retention compliance (active + archive periods)
- Weekly audit review completion records
- Alert response time (time from SIEM alert to ticket creation)
- Log integrity (tampering detection)

**What it cannot prove:**
- Configuration compliance of source systems
- Identity governance
- Vulnerability findings (SIEM gets alerts from scanners, not raw scan data)

**Integration method:** REST API using SPL (Splunk) or platform-specific query language

---

## Source Control (e.g., Bitbucket, GitHub, GitLab)

**Evidence type:** Change Control Audit Trail

**Controls it can evidence:**
- `CM-3` — Configuration change control (PRs as change records)
- `CM-5` — Access restrictions for change (branch protection enforcement)
- `SA-10` — Developer configuration management
- `AU-2` — Event logging (commit and PR audit trail)

**What it proves:**
- Every infrastructure or code change has a PR with documented approval
- Who approved what and when (immutable audit trail)
- Branch protection policies are enforced (no direct commits to main)
- Code review completion before merge

**What it cannot prove:**
- Runtime configurations (only what's in the repo)
- Vulnerability findings in running systems
- Identity governance

**Integration method:** REST API (PR history, branch protection policy status)

---

## Infrastructure as Code (Terraform, Ansible, CloudFormation)

**Evidence type:** Configuration Baseline

**Controls it can evidence:**
- `CM-2` — Baseline configuration
- `CM-3` — Configuration change control (via PR history)
- `CM-6` — Configuration settings (declared in IaC)
- `SA-10` — Developer configuration management

**What it proves:**
- Approved infrastructure baseline exists in version control
- Every infrastructure change went through PR approval
- Security group rules, encryption settings, and network configs are version-controlled
- Configuration drift prevention (no out-of-band changes)

**What it cannot prove:**
- Runtime security posture
- Account lifecycle
- Vulnerability findings in running workloads

**Integration method:** Git history (PRs, commits, approvals) — no runtime API needed

---

## Secure File Transfer (e.g., GoAnywhere, Axway MFT)

**Evidence type:** Data Transfer Security

**Controls it can evidence:**
- `SC-8` — Transmission confidentiality (encryption in transit)
- `SC-12` — Cryptographic key management
- `AU-2` — Event logging (transfer audit logs)
- `AC-17` — Remote access (secure transfer channels)

**What it proves:**
- All transfers encrypted with validated cipher suites
- Transfer audit log completeness (who sent what to whom, when)
- Failed authentication attempts on transfer endpoints
- Partner certificate status and expiration

---

## Controls With No Automated Evidence

Some control families cannot be automated and require document attestation and human review:

| Control Family | Why It Can't Be Automated | Evidence Method |
|---|---|---|
| PE (Physical & Environmental) | Physical space, locks, cameras — not API-accessible | Site visit records, physical access logs |
| PS (Personnel Security) | Background checks, training completion | HR system exports, LMS records |
| PL (Planning) | System security plans, rules of behavior | Document uploads |
| PM (Program Management) | Risk management decisions, governance | Meeting records, signed documents |
| PT (PII Processing Transparency) | Privacy impact assessments | Document uploads, attestations |
| CP (Contingency Planning) | DR/BCP tests, actual recovery | Test records, exercise reports |

These controls still go into the OSCAL structure — they just get their evidence through document upload and human attestation rather than API connectors.
