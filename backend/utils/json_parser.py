"""
json_parser.py
--------------
Handles parsing, validation, and fallback logic for LLM output.
Extracts strict JSON from potentially messy LLM reasoning strings.
"""
import re
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def extract_json_from_text(text: str) -> Dict[str, Any]:
    """
    Uses regex to find the first JSON block in a string.
    Robust against markdown formatting (e.g., ```json ... ```) and leading/trailing text.
    """
    # Try finding markdown JSON block
    match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass # Fall back to raw extraction

    # Try finding raw curly braces mapping
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # If all fails, return empty to trigger fallback logic upstream
    logger.warning("Could not extract JSON from LLM output. Returning empty dict.")
    return {}

def calculate_confidence_score(parsed_data: Dict[str, Any], lstm_anomaly_score: float) -> str:
    """
    Calculates a confidence score bridging the LSTM anomaly score and the parsed output.
    """
    # If the LLM output explicitly has a confidence, try parsing it
    llm_conf = parsed_data.get("confidence", "50%")
    try:
        conf_val = float(str(llm_conf).replace('%', '').strip())
    except (ValueError, TypeError):
        conf_val = 50.0

    # Weight the LSTM score (which is 0.0 to 1.0) with the LLM's confidence
    lstm_scaled = lstm_anomaly_score * 100
    
    # A simple weighted average: trust model 60%, trust LLM 40%
    final_conf = (lstm_scaled * 0.6) + (conf_val * 0.4)
    
    # Clamping
    final_conf = max(0.0, min(100.0, final_conf))
    return f"{final_conf:.1f}%"

def parse_and_validate_incident_report(llm_output: str, anomaly_score: float = 0.5) -> Dict[str, Any]:
    """
    Parses LLM text and guarantees a valid dictionary matching the Incident Report schema.
    
    Expected Structure:
    {
      "attack_stage": str,
      "mitre_technique": list[str],
      "severity": str,
      "confidence": str,
      "explanation": str,
      "recommended_actions": list[str]
    }
    """
    parsed = extract_json_from_text(llm_output)

    # Validate and fill missing fields with graceful fallbacks
    report = {
        "attack_stage": str(parsed.get("attack_stage", "Unknown")),
        "severity": str(parsed.get("severity", "MEDIUM")).upper(),
    }

    # Ensure mitre_technique is a list
    mitre = parsed.get("mitre_technique", [])
    if isinstance(mitre, str):
        report["mitre_technique"] = [m.strip() for m in mitre.split(",") if m.strip()]
    elif isinstance(mitre, list):
        report["mitre_technique"] = [str(m) for m in mitre]
    else:
        report["mitre_technique"] = ["Unknown"]

    # Calculate rigorous confidence
    report["confidence"] = calculate_confidence_score(parsed, anomaly_score)

    # Handle explanation
    exp = parsed.get("explanation", "")
    if isinstance(exp, list):
        report["explanation"] = "\n".join(str(e) for e in exp)
    else:
        report["explanation"] = str(exp) or "The system could not generate a valid explanation. Anomaly detected."

    # Handle actions
    actions = parsed.get("recommended_actions", [])
    if isinstance(actions, str):
        report["recommended_actions"] = [a.strip() for a in actions.split('\n') if a.strip()]
    elif isinstance(actions, list):
        report["recommended_actions"] = [str(a) for a in actions]
    else:
        report["recommended_actions"] = ["Review underlying logs manually.", "Verify system integrity."]

    # Clamp severity logically based on anomaly score if missing or invalid
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    if report["severity"] not in valid_severities:
        if anomaly_score >= 0.8:
            report["severity"] = "CRITICAL"
        elif anomaly_score >= 0.6:
            report["severity"] = "HIGH"
        else:
            report["severity"] = "MEDIUM"

    return report
