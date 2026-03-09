"""
grc_agent.py

LLM-assisted GRC agent for narrative drafting and gap analysis.

This agent handles the cases the deterministic reconciler cannot:
  - Drafting implementation narratives from partial evidence
  - Cross-control reasoning (compensating controls)
  - Exception cross-referencing (gap vs. approved risk acceptance)
  - Ambiguous finding interpretation in context

The agent does NOT make final compliance determinations.
Its output is always a DRAFT marked for ISSO human review.

Architecture:
  1. Load OSCAL SSPP
  2. Find all controls flagged DRAFT-NEEDED or PARTIAL by the reconciler
  3. For each flagged control, build a structured brief from:
     - The full NIST 800-53 control requirement text
     - The current SSP narrative (the claim)
     - Available evidence from all tool slots
     - Related controls that may provide compensating evidence
     - Any approved exception tickets
  4. Send brief to LLM with explicit instructions for what to output
  5. Write candidate narrative back into OSCAL as a draft
  6. Mark for ISSO review — agent output never auto-merges

LLM Backend Selection:
  The agent supports multiple backends via environment variable.
  For systems processing sensitive data, use Bedrock (in an appropriate region) or local LLM.

  GRC_AGENT_BACKEND options:
    bedrock   — AWS Bedrock (recommended for regulated/sensitive data workloads)
    ollama    — Local LLM via Ollama (air-gapped option)
    openai    — OpenAI API (non-sensitive systems only)
    anthropic — Anthropic API (non-sensitive systems only)

Usage:
    python agent/grc_agent.py --oscal oscal/sspp.json --output oscal/sspp.json
    python agent/grc_agent.py --oscal oscal/sspp.json --control ac-2  # single control

Requirements:
    pip install boto3 python-dotenv  # for Bedrock
    pip install ollama               # for Ollama
    pip install openai               # for OpenAI
"""

import json
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

BACKEND = os.getenv("GRC_AGENT_BACKEND", "bedrock")
MODEL = os.getenv("GRC_AGENT_MODEL", "anthropic.claude-3-sonnet-20240229-v1:0")
AWS_REGION = os.getenv("AWS_REGION", "us-gov-west-1")

# Controls to process (empty = all flagged controls)
TARGET_CONTROL = None  # Set via CLI --control argument

# Outcome states that trigger agent processing
AGENT_TRIGGER_STATES = {"DRAFT-NEEDED", "PARTIAL"}


# ── LLM client factory ────────────────────────────────────────────────────────

def get_llm_client():
    """
    Return an LLM client based on configured backend.
    Each client exposes a common interface: client.complete(prompt) -> str
    """
    if BACKEND == "bedrock":
        return BedrockClient(MODEL, AWS_REGION)
    elif BACKEND == "ollama":
        return OllamaClient(MODEL)
    elif BACKEND == "openai":
        return OpenAIClient(MODEL)
    elif BACKEND == "anthropic":
        return AnthropicClient(MODEL)
    else:
        raise ValueError(f"Unknown backend: {BACKEND}. Options: bedrock, ollama, openai, anthropic")


class BedrockClient:
    """
    AWS Bedrock client for regulated/sensitive-data LLM inference.
    Data stays within your AWS authorization boundary.
    Use the appropriate region for your compliance requirements (e.g., us-gov-west-1 for GovCloud).
    """
    def __init__(self, model_id: str, region: str):
        try:
            import boto3
        except ImportError:
            raise ImportError("pip install boto3")
        self.client = boto3.client("bedrock-runtime", region_name=region)
        self.model_id = model_id

    def complete(self, prompt: str) -> str:
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}]
        })
        response = self.client.invoke_model(modelId=self.model_id, body=body)
        result = json.loads(response["body"].read())
        return result["content"][0]["text"]


class OllamaClient:
    """
    Local LLM via Ollama — nothing leaves your environment.
    Air-gapped option for maximum data sovereignty.
    """
    def __init__(self, model: str):
        try:
            import ollama
        except ImportError:
            raise ImportError("pip install ollama")
        self.ollama = ollama
        self.model = model

    def complete(self, prompt: str) -> str:
        response = self.ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]


class OpenAIClient:
    """OpenAI API client — for non-sensitive systems only."""
    def __init__(self, model: str):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("pip install openai")
        self.client = OpenAI()
        self.model = model

    def complete(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content


class AnthropicClient:
    """Anthropic API client — for non-sensitive systems only."""
    def __init__(self, model: str):
        try:
            import anthropic
        except ImportError:
            raise ImportError("pip install anthropic")
        self.client = anthropic.Anthropic()
        self.model = model

    def complete(self, prompt: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text


# ── Control brief builder ─────────────────────────────────────────────────────

def build_control_brief(req: dict, components: list) -> str:
    """
    Build a structured brief for the LLM from OSCAL evidence.

    The brief is the key to useful agent output. It must include:
    - What the control requires (not just the ID)
    - What the SSP currently claims
    - What tools have confirmed
    - What tools haven't reported yet
    - Any approved exceptions
    """
    control_id = req.get("control-id", "unknown").upper()

    # Extract primary narrative and tool evidence
    primary_description = ""
    tool_evidence = []
    missing_tools = []

    for stmt in req.get("statements", []):
        for by_comp in stmt.get("by-components", []):
            comp_uuid = by_comp.get("component-uuid", "")
            description = by_comp.get("description", "")
            status = by_comp.get("implementation-status", {}).get("state", "")

            # Check if this is a tool slot
            props = {p["name"]: p["value"] for p in by_comp.get("props", [])}
            api_ready = props.get("api-ready", "false") == "true"
            last_pull = props.get("last-api-pull", "never")
            tool_name = props.get("tool-name", "")

            if not tool_name:
                # This is the primary system component
                primary_description = description
            elif api_ready and last_pull != "never":
                tool_evidence.append(f"- {tool_name} (pulled {last_pull}): {description[:200]}")
            elif api_ready:
                missing_tools.append(tool_name)

    tool_evidence_text = "\n".join(tool_evidence) if tool_evidence else "No tool evidence available yet."
    missing_tools_text = ", ".join(missing_tools) if missing_tools else "None"

    prompt = f"""You are a security compliance expert helping an ISSO update a System Security Plan.

CONTROL: {control_id}
(Look up the full NIST SP 800-53 Rev 5 requirement for this control ID)

CURRENT SSP NARRATIVE (what was previously claimed):
{primary_description or "No narrative exists yet."}

AVAILABLE TOOL EVIDENCE:
{tool_evidence_text}

TOOLS WITH NO DATA YET:
{missing_tools_text}

TASK:
Draft an updated implementation statement for this control based on the available evidence.

Requirements for your response:
1. Accurately reflect ONLY what the evidence confirms — do not assume tools with no data are compliant
2. Call out gaps explicitly — what evidence is missing and from which tools
3. Be specific and concrete — cite the tool names and what they confirmed
4. Keep it to 150-250 words — this is an ISSO's implementation statement, not an essay
5. End with a clear "GAP:" line if evidence is incomplete, stating what the ISSO needs to verify

Your response should be the implementation statement text only. No preamble. No explanation of your reasoning.
"""
    return prompt


# ── Main agent loop ───────────────────────────────────────────────────────────

def run_grc_agent(oscal_path: str, output_path: str, target_control: str = None):
    print(f"\n{'='*60}")
    print(f"  GRC Agent — Narrative Drafting")
    print(f"{'='*60}")
    print(f"  OSCAL:    {oscal_path}")
    print(f"  Backend:  {BACKEND} ({MODEL})")
    print(f"  Target:   {target_control or 'all flagged controls'}")
    print(f"{'='*60}\n")

    # Load OSCAL
    try:
        with open(oscal_path, "r", encoding="utf-8") as f:
            oscal = json.load(f)
    except Exception as e:
        print(f"  ERROR: Could not load OSCAL: {e}")
        return False

    ssp = oscal.get("system-security-plan", {})
    components = ssp.get("system-implementation", {}).get("components", [])
    requirements = ssp.get("control-implementation", {}).get("implemented-requirements", [])

    # Initialize LLM client
    try:
        llm = get_llm_client()
        print(f"  LLM client initialized: {BACKEND}\n")
    except Exception as e:
        print(f"  ERROR: Could not initialize LLM client: {e}")
        return False

    # Find controls that need agent processing
    controls_to_process = []
    for req in requirements:
        control_id = req.get("control-id", "")

        if target_control and control_id != target_control.lower():
            continue

        # Check if flagged for review
        props = {p.get("name"): p.get("value") for p in req.get("props", [])}
        needs_review = props.get("grc-agent-review-needed") == "true"

        if needs_review or target_control:
            controls_to_process.append(req)

    print(f"  Controls to process: {len(controls_to_process)}\n")

    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    processed = 0
    errors = 0

    for req in controls_to_process:
        control_id = req.get("control-id", "unknown")
        print(f"  Processing {control_id.upper()}...")

        try:
            brief = build_control_brief(req, components)
            draft_narrative = llm.complete(brief)

            # Write draft back into primary component
            for stmt in req.get("statements", []):
                for by_comp in stmt.get("by-components", []):
                    props_dict = {p["name"]: p["value"] for p in by_comp.get("props", [])}
                    if "tool-name" not in props_dict and "api-ready" not in props_dict:
                        # This is the primary system component
                        original = by_comp.get("description", "")
                        by_comp["description"] = (
                            f"[AGENT DRAFT {now_ts} — ISSO REVIEW REQUIRED]\n\n"
                            f"{draft_narrative}\n\n"
                            f"[Original narrative preserved below for reference]\n"
                            f"{original}"
                        )
                        # Update review flag
                        for p in by_comp.get("props", []):
                            if p["name"] == "grc-agent-review-needed":
                                p["value"] = "draft-generated"
                                p["remarks"] = f"Agent draft generated {now_ts}. ISSO review required."
                        break

            print(f"    ✓ Draft generated ({len(draft_narrative)} chars)")
            processed += 1

        except Exception as e:
            print(f"    ✗ Error: {e}")
            errors += 1

    # Write output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(oscal, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"  Results")
    print(f"{'='*60}")
    print(f"  Processed: {processed}")
    print(f"  Errors:    {errors}")
    print(f"  Output:    {output_path}")
    print(f"\n  IMPORTANT: Agent drafts require ISSO human review before submission.")
    print(f"  Search for '[AGENT DRAFT' in sspp.json to find all draft narratives.")
    print(f"{'='*60}\n")

    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="GRC Agent — LLM-assisted implementation narrative drafting"
    )
    parser.add_argument("--oscal", default="oscal/sspp.json", help="Path to OSCAL SSPP JSON")
    parser.add_argument("--output", default="oscal/sspp.json", help="Output path")
    parser.add_argument("--control", help="Process a single control ID (e.g., ac-2)")
    args = parser.parse_args()
    run_grc_agent(args.oscal, args.output, args.control)
