"""
llm_agent.py
------------
LLM Agent for structured SOC analysis.
Engine: OpenAI API client connected to OpenRouter (gpt-4o-mini).
"""

import os
import logging
from typing import Optional, Dict, Any, List

from backend.rag.rag_engine import retrieve_context
from backend.utils.json_parser import parse_and_validate_incident_report

logger = logging.getLogger(__name__)

# --- Configuration ---
MODEL_NAME = "openai/gpt-4o-mini"

def generate_inference(prompt: str) -> str:
    """Executes OpenRouter inference using OpenAI Client."""
    from openai import OpenAI
    
    # Allows falling back to user's OpenRouter or standard OpenAI API based on env configuration
    api_key = os.getenv("OPEN_ROUTER_API") or os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("No OpenRouter Key found in environment variables.")

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenRouter API failed: {e}")
        raise RuntimeError(f"OpenRouter generation failed: {e}")

def build_optimized_prompt(log_text: str, event_sequence: List[str], anomaly_score: float, threat_intel: str, rag_context: str) -> str:
    """Builds a token-optimized prompt forcing structured JSON output."""
    seq = " -> ".join(event_sequence) if event_sequence else "None"
    
    return f"""You are a specialized SOC Analyst strictly responding in JSON.
Analyze this cybersecurity event data and return EXACTLY this JSON structure, nothing else:
{{
  "attack_stage": "<str>",
  "mitre_technique": ["<str>"],
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "confidence": "<str>",
  "explanation": "<str>",
  "recommended_actions": ["<str>"]
}}

= DATA =
LOGS: {log_text[:600]}...
SEQ: {seq}
ANOMALY SCORE: {anomaly_score:.2f}
THREAT INTEL: {threat_intel or "Clean"}
MITRE CONTEXT: {rag_context or "None"}

Generate pure valid JSON."""

def investigate_logs(
    log_text: str,
    event_sequence: List[str] = None,
    anomaly_score: float = 0.0,
    threat_intel_summary: str = "",
    attack_graph_summary: str = "",
    rag_context: str = "",
) -> Dict[str, Any]:
    """
    Main investigator pipeline utilizing OpenRouter.
    Returns a strict dictionary matching the JSON report schema.
    """
    if not rag_context:
        rag_query = " ".join(event_sequence or []) + " " + log_text[:300]
        rag_context = retrieve_context(rag_query)

    # 1. Build tight prompt
    prompt = build_optimized_prompt(
        log_text=log_text,
        event_sequence=event_sequence,
        anomaly_score=anomaly_score,
        threat_intel=threat_intel_summary,
        rag_context=rag_context
    )

    llm_output = ""
    # 2. Execution logic
    try:
        llm_output = generate_inference(prompt)
    except Exception as e:
        llm_output = "" # Total failure; JSON parser will inject safe defaults
        logger.error(f"Complete LLM failure: {e}")

    # 3. Parse and strictly validate the JSON mapping
    final_report = parse_and_validate_incident_report(llm_output, anomaly_score=anomaly_score)
    return final_report
