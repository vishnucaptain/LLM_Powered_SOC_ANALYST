"""
gemini_agent.py
---------------
DEPRECATED — kept for backward-compatibility only. Not used by the pipeline.

The active LLM agent is `backend/reasoning/llm_agent.py` which uses
the OpenRouter API (gpt-4o-mini) via the OpenAI client and is invoked by main.py.

Do NOT import this file in new code.
"""

import os


def analyze_logs(log_text: str) -> str:
    """
    Legacy stub — raises NotImplementedError.
    Use backend.reasoning.llm_agent.investigate_logs() instead.
    """
    raise NotImplementedError(
        "gemini_agent is deprecated. Use backend.reasoning.llm_agent.investigate_logs() instead."
    )