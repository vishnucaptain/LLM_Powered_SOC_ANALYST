"""
gemini_agent.py
---------------
DEPRECATED — kept for backward-compatibility only. Not used by the pipeline.

The active LLM agent is `backend/llm_agent.py` which uses
microsoft/Phi-3.5-mini-instruct (local Hugging Face model) via the
transformers library and is invoked by main.py.

This file used the old google.generativeai / google-genai SDK.
It is no longer used; do not import it in new code.
"""

import os
from google import genai
from dotenv import load_dotenv

load_dotenv()


def _get_client() -> genai.Client:
    api_key = (os.getenv("GEMINI_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError(
            "Gemini API key is missing. Set GEMINI_API_KEY in your .env or environment."
        )
    return genai.Client(api_key=api_key)


def analyze_logs(log_text: str) -> str:
    """
    Simple log analysis stub (legacy).
    For the full pipeline, use backend.llm_agent.investigate_logs() instead.
    """
    prompt = f"""
    You are a SOC security analyst.
    Analyze the following security logs.
    Identify suspicious activity, possible attack stage, and explain reasoning clearly.

    Logs:
    {log_text}
    """

    client = _get_client()
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text
    except Exception as exc:
        msg = str(exc)
        if "PERMISSION_DENIED" in msg or "CONSUMER_SUSPENDED" in msg:
            raise RuntimeError(
                "Gemini API access denied: API key is suspended or unauthorized. "
                "Create a new key at https://aistudio.google.com/apikey and update GEMINI_API_KEY."
            ) from exc
        raise