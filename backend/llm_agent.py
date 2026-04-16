"""
llm_agent.py
------------
LLM Investigation Engine — OpenRouter API (Dolphin 3.0 Mistral 24b).

Replaces the local LLM with OpenRouter integration.
Uses RAG context + all pipeline outputs to generate SOC investigation reports.

Key design decisions:
  - Connects to OpenRouter.
  - Returns the parsed response directly without local hardware dependency.
"""

import os
from typing import Optional
from openai import OpenAI
from dotenv import load_dotenv

from backend.rag_engine import retrieve_context


# ─────────────────────────────────────────────────────────────
# MODULE-LEVEL CONFIGURATION
# ─────────────────────────────────────────────────────────────

load_dotenv()
_API_KEY = os.getenv("OPEN_ROUTER_API") or os.getenv("OPENROUTER_API_KEY")

if not _API_KEY:
    raise RuntimeError("OPEN_ROUTER_API key not found in environment variables.")

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=_API_KEY,
)

MODEL_NAME = "openai/gpt-4o-mini"


# ─────────────────────────────────────────────────────────────
# MAIN INVESTIGATION FUNCTION
# ─────────────────────────────────────────────────────────────

def investigate_logs(
    log_text: str,
    event_sequence: list = None,
    anomaly_score: float = 0.0,
    threat_intel_summary: str = "",
    attack_graph_summary: str = "",
    rag_context: str = "",
) -> str:
    """
    Generate a structured SOC incident investigation report using OpenRouter API.

    Parameters
    ----------
    log_text              : Raw log text (excerpt used in prompt)
    event_sequence        : List of event type strings e.g. ['LOGIN', 'PRIV_ESC']
    anomaly_score         : LSTM anomaly score in [0.0, 1.0]
    threat_intel_summary  : Pre-formatted threat intel enrichment text
    attack_graph_summary  : Pre-formatted attack graph summary text
    rag_context           : Pre-fetched MITRE ATT&CK passages from ChromaDB

    Returns
    -------
    str : Structured incident report text
    """
    # ── Step 1: RAG fallback (if caller didn't pre-fetch context) ─────────
    if not rag_context:
        rag_query = (
            " ".join(str(e) for e in (event_sequence or []))
            + " " + log_text[:400]
        )
        rag_context = retrieve_context(rag_query)

    # ── Step 2: Event sequence formatting ─────────────────────────────────
    seq_text = "None detected"
    if event_sequence:
        seq_text = " → ".join(str(e) for e in event_sequence)

    # ── Step 3: Anomaly interpretation ────────────────────────────────────
    if anomaly_score >= 0.8:
        anomaly_assessment = f"CRITICAL ANOMALY (score={anomaly_score:.2f})"
    elif anomaly_score >= 0.6:
        anomaly_assessment = f"HIGH ANOMALY (score={anomaly_score:.2f})"
    elif anomaly_score >= 0.4:
        anomaly_assessment = f"MODERATE ANOMALY (score={anomaly_score:.2f})"
    else:
        anomaly_assessment = f"LOW/NORMAL (score={anomaly_score:.2f})"

    # ── Step 4: Build structured prompt ───────────────────────────────────
    prompt = f"""You are an expert SOC analyst. Analyze the following security data and generate a structured incident report.

=== LOG DATA (excerpt) ===
{log_text[:800]}

=== DETECTED EVENT SEQUENCE ===
{seq_text}

=== LSTM ANOMALY ASSESSMENT ===
{anomaly_assessment}

=== THREAT INTELLIGENCE ===
{threat_intel_summary or "No threat intelligence indicators found."}

=== ATTACK GRAPH ===
{attack_graph_summary or "No attack graph data available."}

=== MITRE ATT&CK CONTEXT (from knowledge base) ===
{rag_context or "No MITRE ATT&CK context retrieved."}

=== TASK ===
Generate a structured SOC incident report using EXACTLY this format:

attack_stage: <e.g. Initial Access / Execution / Privilege Escalation / Lateral Movement / Exfiltration>
mitre_technique: <e.g. T1059.001 PowerShell, T1110 Brute Force>
severity: <CRITICAL / HIGH / MEDIUM / LOW>
confidence: <percentage, e.g. 85%>
explanation:
- <Key finding 1>
- <Key finding 2>
- <Key finding 3>
recommended_actions:
- <Action 1>
- <Action 2>
- <Action 3>
"""

    # ── Step 5: Generate using OpenRouter API ──────────────────────────────
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=2000  # Explicitly set so OpenRouter does not pre-authorize massive token limits!
        )
        result = completion.choices[0].message.content
        
        # Dolphin 3.0 / Reasoning models might output <think> tags. 
        # We strip the <think> blocks so it parses cleanly.
        import re
        result_clean = re.sub(r"<think>.*?</think>", "", result, flags=re.DOTALL)
        
        return result_clean.strip()

    except Exception as exc:
        raise RuntimeError(f"OpenRouter API failed: {exc}") from exc