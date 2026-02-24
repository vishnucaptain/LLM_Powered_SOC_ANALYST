import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-2.5-flash")

def analyze_logs(log_text: str):

    prompt = f"""
    You are a SOC security analyst.
    Analyze the following security logs.
    Identify suspicious activity, possible attack stage, and explain reasoning clearly.

    Logs:
    {log_text}
    """

    response = model.generate_content(prompt)

    return response.text