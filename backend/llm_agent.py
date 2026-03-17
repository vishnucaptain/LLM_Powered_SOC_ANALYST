"""
llm_agent.py
------------
LLM Investigation Engine — integrates the full pipeline context
(event sequences, anomaly score, threat intel, attack graph, MITRE RAG)
and generates a comprehensive SOC incident investigation via Gemini.

RAG is now handled upstream (main.py) using get_mitre_query(events) which
builds a precise query from MITRE hints embedded in each detected event type.
The retrieved context is passed in here rather than re-fetched.
"""

import os
from google import genai
from google.genai import errors as genai_errors
from fastapi import HTTPException
from dotenv import load_dotenv
from backend.rag_engine import retrieve_context

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
MODEL = "gemini-2.5-flash"


def investigate_logs(
    log_text: str,
    event_sequence: list = None,
    anomaly_score: float = 0.0,
    threat_intel_summary: str = "",
    attack_graph_summary: str = "",
    rag_context: str = "",          # ← pre-fetched by main.py via get_mitre_query()
) -> str:
    """
    Run the LLM investigation engine with full pipeline context.

    Parameters
    ----------
    log_text            : Raw or normalized log text
    event_sequence      : List of event type strings (e.g. ['LOGIN', 'PRIV_ESC'])
    anomaly_score       : Float 0.0–1.0 from LSTM model
    threat_intel_summary: Human-readable threat intel enrichment text
    attack_graph_summary: Human-readable attack graph summary text
    rag_context         : Pre-fetched MITRE ATT&CK context from ChromaDB.
                          If empty, falls back to raw-log RAG query (legacy).

    Returns
    -------
    Raw LLM response text (structured report).
    """
    # ── Step 1: Use pre-fetched RAG context, or fall back to legacy fetch ──────
    if not rag_context:
        # Fallback: build query from event sequence + raw log text
        # (used when called outside the main pipeline, e.g. unit tests)
        rag_query = " ".join(str(e) for e in (event_sequence or [])) + " " + log_text[:400]
        rag_context = retrieve_context(rag_query)

    # ── Step 2: Format event sequence for prompt ────────────────────────────
    seq_text = "None detected"
    if event_sequence:
        seq_text = " → ".join(str(e) for e in event_sequence)

    # ── Step 3: Anomaly assessment text ────────────────────────────────────
    if anomaly_score >= 0.8:
        anomaly_assessment = f"CRITICAL ANOMALY (score={anomaly_score:.3f}) — behaviour is highly abnormal."
    elif anomaly_score >= 0.6:
        anomaly_assessment = f"HIGH ANOMALY (score={anomaly_score:.3f}) — significant deviation from baseline."
    elif anomaly_score >= 0.4:
        anomaly_assessment = f"MODERATE ANOMALY (score={anomaly_score:.3f}) — suspicious deviation detected."
    elif anomaly_score >= 0.2:
        anomaly_assessment = f"LOW ANOMALY (score={anomaly_score:.3f}) — minor deviation, monitor closely."
    else:
        anomaly_assessment = f"NORMAL BEHAVIOUR (score={anomaly_score:.3f}) — within expected patterns."

    # ── Step 4: Build the SOC investigation prompt ──────────────────────────
    prompt = f"""You are an expert SOC (Security Operations Center) analyst with 15 years of experience.
You have been provided with the full output of an automated threat detection pipeline.

=== SECURITY LOGS ===
{log_text}

=== BEHAVIOURAL ANALYSIS ===
Event Sequence Detected: {seq_text}
LSTM Anomaly Assessment: {anomaly_assessment}

=== THREAT INTELLIGENCE ENRICHMENT ===
{threat_intel_summary if threat_intel_summary else "No threat intelligence data available."}

=== ATTACK PROGRESSION ===
{attack_graph_summary if attack_graph_summary else "No attack graph data available."}

=== MITRE ATT&CK KNOWLEDGE BASE (RAG Retrieved — ChromaDB semantic search) ===
{rag_context if rag_context else "No relevant MITRE ATT&CK techniques retrieved."}

=== YOUR TASK ===
Analyze all the above data and produce a structured incident investigation report.
Be precise, concise, and actionable. Use the MITRE ATT&CK framework.
Reference specific MITRE techniques FROM the knowledge base above wherever relevant.

Your response MUST contain exactly these labelled sections:

attack_stage: [identify the kill-chain stage: Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Discovery / Lateral Movement / Collection / Command and Control / Exfiltration / Impact]

mitre_technique: [list the specific T-codes and names, e.g. T1110.003 Password Spraying, T1059.001 PowerShell]

severity: [CRITICAL / HIGH / MEDIUM / LOW]

confidence: [percentage, e.g. 87%]

explanation:
[5–8 bullet points explaining the attack timeline and what happened, referencing specific log evidence and the MITRE ATT&CK techniques above]

recommended_actions:
[5–8 specific, actionable response steps for the SOC team]
"""

    # ── Step 5: Call Gemini ─────────────────────────────────────────────────
    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=prompt,
        )
        return response.text

    except genai_errors.ClientError as e:
        status = getattr(e, "status_code", None) or 500
        msg = str(e)
        if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
            raise HTTPException(
                status_code=429,
                detail=(
                    "Gemini API quota exceeded. Please wait a minute and try again, "
                    "or check your API key billing at https://ai.dev/rate-limit"
                ),
            )
        raise HTTPException(status_code=status, detail=f"Gemini API error: {msg}")

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"LLM investigation failed: {str(e)}",
        )