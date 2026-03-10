# References

Frameworks, specifications, tools, and resources used in building this pipeline. Annotated with why each one matters.

---

## Core Standards

### NIST OSCAL — Open Security Controls Assessment Language
https://pages.nist.gov/OSCAL/

The foundational standard this entire pipeline is built around. OSCAL defines a machine-readable format for security controls, implementation statements, and assessment evidence. Without OSCAL, compliance data lives in documents that can't be queried, compared, or automated.

Key documents to read:
- [OSCAL Concepts](https://pages.nist.gov/OSCAL/concepts/) — understand the data model before touching the schema
- [System Security Plan model](https://pages.nist.gov/OSCAL/reference/latest/system-security-plan/) — the specific model this pipeline generates
- [by-components structure](https://pages.nist.gov/OSCAL/reference/latest/system-security-plan/json-reference/#/system-security-plan/control-implementation/implemented-requirements/statements/by-components) — the core pattern for shared responsibility evidence

**Lesson learned:** Read the concepts documentation before reading the schema. The schema makes no sense without understanding the intent behind the data model.

### NIST SP 800-53 Rev 5 — Security and Privacy Controls
https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

The control catalog. Every control ID referenced in this pipeline maps to a requirement here. Rev 5 added privacy controls and significantly expanded supply chain requirements compared to Rev 4.

**For practitioners:** The control catalog is searchable online at https://csrc.nist.gov/projects/cprt/catalog — much faster than the PDF for looking up specific controls.

### NIST SP 800-53B — Control Baselines
https://csrc.nist.gov/publications/detail/sp/800-53b/final

Defines which controls apply at Low, Moderate, and High impact levels. If you're assessing a system, this tells you which of the 1,000+ controls in 800-53 you actually need to implement.

### NIST SP 800-60 Vol. 2 — Information Type Categorization
https://csrc.nist.gov/publications/detail/sp/800-60/vol-2/rev-1/final

Used to categorize information types and determine FIPS 199 impact levels. Referenced in the OSCAL system-characteristics section for information type categorization.

---

## OSCAL Tooling

### NIST OSCAL GitHub Repository
https://github.com/usnistgov/OSCAL

Official NIST repo containing:
- JSON and XML schemas for all OSCAL models
- Example OSCAL documents (good reference for structure questions)
- `oscal-cli` — command-line validation tool

The JSON schemas in `/json/schema/` are what Stage 2 of the validation pipeline validates against.

### oscal-cli
https://github.com/usnistgov/oscal-cli

NIST's official command-line tool for OSCAL validation. Used in Stage 4 (full conformance check) of the validation pipeline:

```bash
# Install
brew install usnistgov/oscal-brew-tap/oscal-cli

# Validate
oscal-cli ssp validate oscal/sspp.json
```

### AWS Labs OSCAL MCP Server
https://github.com/awslabs/aws-mcp-servers

AWS Labs implementation of an OSCAL validation MCP server. Provides `validate_oscal_content` and `validate_oscal_file` tools that can be called programmatically. Used in the validation pipeline to perform OSCAL schema validation without shelling out to oscal-cli.

Particularly useful for integrating validation into an LLM-assisted workflow where the agent needs to validate its own output before committing.

---

## Framework References (Generalized)

### Agency-Specific Overlays and Supplemental Requirements

Most federal and regulated programs apply an overlay on top of NIST 800-53 — additional or modified control requirements specific to that program, data type, or agency. Common examples include:

- **FedRAMP** — cloud system authorization requirements for federal use (fedramp.gov)
- **CMMC** — Cybersecurity Maturity Model Certification for DoD contractors (dodcmmc.com)
- **HIPAA Security Rule** — for systems processing electronic protected health information
- **IRS Publication 1075** — for state/local agencies receiving federal tax data from IRS
- **CMS ARC-AMPE** — for Medicaid and ACA-related systems (cms.gov)
- **CJIS Security Policy** — for criminal justice information systems (fbi.gov)

When your system is subject to an overlay, the `crosswalk/framework-crosswalk.json` file in this repo captures the delta — controls where the overlay is stricter than the NIST 800-53 baseline. This is the "high-watermark" approach: implement the stricter requirement once, satisfy both frameworks simultaneously.

### Dual Reporting Obligations

If your system is subject to multiple frameworks, check carefully for independent incident reporting chains. Some frameworks require notifications to separate authorities within different timeframes — missing one notification stream is a compliance failure regardless of whether you completed the other. Document both chains explicitly in your incident response policy and in your SSP IR-6 implementation statement.

### FedRAMP Documentation
https://www.fedramp.gov/documents-templates/

Even for non-FedRAMP systems, the FedRAMP SSP template and Control Implementation Summary (CIS) template are the best publicly available references for what good SSP implementation statement content looks like. Worth reading regardless of your specific framework.

---

## Design Inspiration

### myctrl.tools
https://myctrl.tools

A practitioner-built control browser that maps security tools to NIST 800-53 controls. Good reference for understanding how tool evidence maps to control families. Inspired the evidence source map UI component in this project.

### OSCAL Compass
https://github.com/compliance-framework

Community tooling around OSCAL automation. Useful reference for seeing how others have approached the same problems.

---

## Python Libraries

### openpyxl
https://openpyxl.readthedocs.io/

Used for reading Excel SSP files in the converter. Key consideration: always load with `data_only=True` to get computed cell values rather than formulas.

```python
wb = openpyxl.load_workbook(path, data_only=True)
```

### requests
https://docs.python-requests.org/

HTTP client for all API connectors. For corporate environments with SSL inspection, see the SSL workaround in `docs/TROUBLESHOOTING.md`.

### python-dotenv
https://pypi.org/project/python-dotenv/

Loads environment variables from `.env` file. Never hardcode API credentials. Never.

### pydantic
https://docs.pydantic.dev/

Used in Stage 3 of the validation pipeline for semantic validation of OSCAL content. Catches logically invalid content that passes JSON schema.

---

## Git Tooling

### BFG Repo Cleaner
https://rtyley.github.io/bfg-repo-cleaner/

If you accidentally commit a secret, BFG is the fastest way to remove it from Git history. Faster than `git filter-branch`. Use it, then force push, then rotate the exposed credential.

```bash
# Remove a specific file from all history
bfg --delete-files .env

# Remove all files larger than 10MB (for accidentally committed evidence archives)
bfg --strip-blobs-bigger-than 10M
```

---

## Background Reading

These aren't cited directly in the code but shaped the design thinking:

- **"The Phoenix Project"** — Gene Kim et al. The argument for treating compliance like software engineering rather than like paperwork applies directly.
- **"Accelerate"** — Forsgren, Humble, Kim. The metrics for high-performing engineering teams (deployment frequency, change failure rate, MTTR) map surprisingly well to compliance program maturity metrics.
- **NIST SP 800-37 Rev 2** — Risk Management Framework. The full RMF lifecycle that ATO processes follow. Understanding where the SSP fits in the broader ATO process is useful context.
- **FedRAMP documentation** — https://www.fedramp.gov/documents-templates/ — Even if your system isn't FedRAMP, the FedRAMP SSP template and the control implementation summary (CIS) template are excellent references for what good SSP content looks like.
