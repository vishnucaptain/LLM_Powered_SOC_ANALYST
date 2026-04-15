"""
llm_agent.py
------------
LLM Investigation Engine — Local Hugging Face Phi-3.5-mini-instruct.

Replaces the Gemini API with a fully local LLM.
Uses RAG context + all pipeline outputs to generate SOC investigation reports.

Key design decisions:
  - Model is loaded LAZILY on first call — server starts fast even if weights
    are not yet cached (first call will trigger the ~7 GB download).
  - All errors are surfaced as RuntimeError so main.py can catch them and
    fall back to structured defaults without crashing the pipeline.
  - The prompt format matches the field names incident_report.py parses
    (attack_stage / mitre_technique / severity / confidence / explanation /
     recommended_actions).
"""

import os
from typing import Optional

from backend.rag_engine import retrieve_context


# ─────────────────────────────────────────────────────────────
# MODULE-LEVEL SINGLETONS (populated on first call)
# ─────────────────────────────────────────────────────────────

MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"

_tokenizer = None
_model     = None


def _load_model():
    """
    Lazily load Phi-3.5-mini tokenizer and model.
    Called once on the first investigate_logs() invocation.
    Raises RuntimeError with a clear message if anything goes wrong.
    """
    global _tokenizer, _model

    if _model is not None:
        return  # already loaded

    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM
    except ImportError as exc:
        raise RuntimeError(
            "Required packages missing. Run:\n"
            "  pip install transformers accelerate\n"
            f"Original error: {exc}"
        ) from exc

    try:
        _tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME,
            trust_remote_code=False,
        )

        # Detect if we should use Mac M-series acceleration
        device = "cpu"
        dtype = torch.float32
        if torch.cuda.is_available():
            device = "cuda"
            dtype = torch.float16
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = "mps"
            dtype = torch.float16

        _model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            trust_remote_code=False,
            torch_dtype=dtype,
            attn_implementation="eager", # Suppresses flash attention warnings
        ).to(device)
        _model.eval()

    except Exception as exc:
        # Reset so a retry will attempt the load again
        _tokenizer = None
        _model = None
        raise RuntimeError(
            f"Failed to load Phi-3.5 model '{MODEL_NAME}': {exc}\n"
            "Make sure you have an internet connection for the first download "
            "or that the model is already cached in ~/.cache/huggingface/."
        ) from exc


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
    Generate a structured SOC incident investigation report using Phi-3.5.

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
    import torch

    # ── Step 1: Lazy model load ────────────────────────────────────────────
    _load_model()  # no-op after first call; raises RuntimeError on failure

    # ── Step 2: RAG fallback (if caller didn't pre-fetch context) ─────────
    if not rag_context:
        rag_query = (
            " ".join(str(e) for e in (event_sequence or []))
            + " " + log_text[:400]
        )
        rag_context = retrieve_context(rag_query)

    # ── Step 3: Event sequence formatting ─────────────────────────────────
    seq_text = "None detected"
    if event_sequence:
        seq_text = " → ".join(str(e) for e in event_sequence)

    # ── Step 4: Anomaly interpretation ────────────────────────────────────
    if anomaly_score >= 0.8:
        anomaly_assessment = f"CRITICAL ANOMALY (score={anomaly_score:.2f})"
    elif anomaly_score >= 0.6:
        anomaly_assessment = f"HIGH ANOMALY (score={anomaly_score:.2f})"
    elif anomaly_score >= 0.4:
        anomaly_assessment = f"MODERATE ANOMALY (score={anomaly_score:.2f})"
    else:
        anomaly_assessment = f"LOW/NORMAL (score={anomaly_score:.2f})"

    # ── Step 5: Build structured prompt ───────────────────────────────────
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

    # ── Step 6: Apply chat template ────────────────────────────────────────
    messages = [{"role": "user", "content": prompt}]

    inputs = _tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(_model.device)

    # ── Step 7: Generate ───────────────────────────────────────────────────
    with torch.no_grad():
        outputs = _model.generate(
            **inputs,
            max_new_tokens=350,
            temperature=0.3,
            do_sample=True,
            pad_token_id=_tokenizer.eos_token_id,
        )

    # Decode only the newly generated tokens (strip the input prompt)
    result = _tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[-1]:],
        skip_special_tokens=True,
    )

    return result.strip()