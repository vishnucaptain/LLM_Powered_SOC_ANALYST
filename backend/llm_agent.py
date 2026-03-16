import os
from google import genai
from google.genai import errors as genai_errors
from fastapi import HTTPException
from dotenv import load_dotenv
from backend.rag_engine import retrieve_context

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
MODEL = "gemini-2.5-flash"


def investigate_logs(log_text: str):

    # Step 1: Retrieve MITRE knowledge
    context = retrieve_context(log_text)

    # Step 2: Build SOC investigation prompt
    prompt = f"""
You are an expert SOC analyst.

Analyze the following security logs and determine if an attack occurred.

Logs:
{log_text}

Relevant MITRE ATT&CK knowledge:
{context}

Return a structured report containing:
- attack_stage
- mitre_technique
- severity
- confidence
- explanation
- recommended_actions

highlight them as bullet points and keep the explanation under 10 lines and make it brief.
"""

    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=prompt,
        )
        return response.text

    except genai_errors.ClientError as e:
        status = getattr(e, 'status_code', None) or 500
        msg = str(e)
        if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
            raise HTTPException(
                status_code=429,
                detail="Gemini API quota exceeded. Please wait a minute and try again, or check your API key billing at https://ai.dev/rate-limit"
            )
        raise HTTPException(status_code=status, detail=f"Gemini API error: {msg}")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM investigation failed: {str(e)}")