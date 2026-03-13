import os
import google.generativeai as genai
from dotenv import load_dotenv
from backend.rag_engine import retrieve_context

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-2.5-flash")


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
"""

    response = model.generate_content(prompt)

    return response.text