"""
json_parser.py
--------------
Handles parsing, validation, and fallback logic for LLM output.
Extracts strict JSON from potentially messy LLM reasoning strings
and enforces the canonical incident-report schema.

Schema (enforced on every return):
{
    "attack_stage":         str,
    "mitre_technique":      List[str],   # T-codes only, e.g. ["T1110", "T1059.001"]
    "severity":             str,         # LOW | MEDIUM | HIGH | CRITICAL
    "confidence":           float,       # 0.0 – 1.0
    "explanation":          str,
    "recommended_actions":  List[str]
}
"""

import re
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

# Matches T1234 or T1234.001
_TCODE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# Severity alias normalisation
_SEVERITY_MAP = {
    "LOW":        "LOW",
    "MEDIUM":     "MEDIUM",
    "HIGH":       "HIGH",
    "CRITICAL":   "CRITICAL",
    # common LLM aliases
    "INFO":       "LOW",
    "WARNING":    "MEDIUM",
    "ALERT":      "HIGH",
    "EMERGENCY":  "CRITICAL",
    "SEVERE":     "HIGH",
}


# ── Core helpers ──────────────────────────────────────────────────────────────

def _extract_json_block(text: str) -> Dict[str, Any]:
    """
    Try to extract a JSON object from the LLM output.
    Handles: pure JSON, markdown fenced JSON, JSON embedded in prose.
    """
    if not text:
        return {}

    # 1. Pure JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Fenced code block: ```json { … } ```
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            pass

    # 3. First {...} block in the string (greedy — largest match)
    block = re.search(r"\{.*\}", text, re.DOTALL)
    if block:
        try:
            return json.loads(block.group())
        except json.JSONDecodeError:
            pass

    # 4. Regex key-value fallback (best effort)
    return _regex_kv_parse(text)


def _regex_kv_parse(text: str) -> Dict[str, Any]:
    """Last-resort key-value extraction via regex when JSON is unparseable."""
    result: Dict[str, Any] = {}

    # attack_stage
    m = re.search(r"attack[_\s]stage[:\s]+([^\n,]+)", text, re.IGNORECASE)
    if m:
        result["attack_stage"] = m.group(1).strip().rstrip(".,")

    # MITRE T-codes (all occurrences)
    tcodes = _TCODE_RE.findall(text)
    if tcodes:
        result["mitre_technique"] = list(dict.fromkeys(tcodes))

    # severity
    m = re.search(r"severity[:\s]+(CRITICAL|HIGH|MEDIUM|LOW)", text, re.IGNORECASE)
    if m:
        result["severity"] = m.group(1).upper()

    # confidence (percentage or decimal)
    m = re.search(r"confidence[:\s]+(\d+\.?\d*)\s*%?", text, re.IGNORECASE)
    if m:
        result["confidence"] = m.group(1)

    # explanation
    m = re.search(
        r"explanation[:\s]+([^\n]+(?:\n(?![A-Z_\s]*:)[^\n]+)*)",
        text, re.IGNORECASE,
    )
    if m:
        result["explanation"] = m.group(1).strip()

    return result


def _normalise_severity(raw: Any) -> str:
    """Return a canonical severity string."""
    if not raw:
        return "MEDIUM"
    key = str(raw).upper().strip()
    return _SEVERITY_MAP.get(key, "MEDIUM")


def _normalise_confidence(raw: Any) -> float:
    """
    Convert any confidence representation to a float in [0.0, 1.0].
    Accepts: 0.75, 75, "75%", "0.75", "75% confidence".
    """
    if isinstance(raw, float):
        return max(0.0, min(1.0, raw))

    if isinstance(raw, int):
        # If someone sends 75 treat as percentage; if 0 or 1 treat as fraction
        return max(0.0, min(1.0, raw / 100.0 if raw > 1 else float(raw)))

    if isinstance(raw, str):
        cleaned = raw.strip().replace("%", "").split()[0]  # "75% confidence" → "75"
        try:
            val = float(cleaned)
            return max(0.0, min(1.0, val / 100.0 if val > 1.0 else val))
        except ValueError:
            pass

    return 0.5  # safe default


def _normalise_techniques(raw: Any) -> List[str]:
    """Extract and deduplicate MITRE T-codes from any input shape."""
    if not raw:
        return []
    source = " ".join(raw) if isinstance(raw, list) else str(raw)
    codes = _TCODE_RE.findall(source)
    return list(dict.fromkeys(codes))  # deduplicate, preserve order


def _normalise_actions(raw: Any) -> List[str]:
    """Return a clean list of recommended actions (max 10)."""
    if not raw:
        return []

    items: List[str] = []

    if isinstance(raw, list):
        for item in raw:
            cleaned = re.sub(r"^[\d\.\)\-\*•\s]+", "", str(item).strip())
            if len(cleaned) > 5:
                items.append(cleaned)
    elif isinstance(raw, str):
        for line in re.split(r"[\n;]", raw):
            cleaned = re.sub(r"^[\d\.\)\-\*•\s]+", "", line.strip())
            if len(cleaned) > 5:
                items.append(cleaned)

    return items[:10]


# ── Public API ────────────────────────────────────────────────────────────────

def parse_and_validate_incident_report(
    llm_output: str,
    anomaly_score: float = 0.5,
) -> Dict[str, Any]:
    """
    Parse LLM text and guarantee a valid dictionary matching the incident-report
    schema. This is the single canonical parser used by llm_agent.py.

    Args:
        llm_output:    Raw string produced by the LLM (may be empty).
        anomaly_score: LSTM score used to clamp severity / confidence when the
                       LLM output is absent or invalid.

    Returns:
        dict with keys: attack_stage, mitre_technique, severity, confidence,
                        explanation, recommended_actions.
    """
    parsed = _extract_json_block(llm_output)

    # ── Severity ─────────────────────────────────────────────────────────────
    raw_sev = parsed.get("severity", "")
    severity = _normalise_severity(raw_sev)

    # Override with anomaly-score-based floor when LLM is absent / unhelpful
    if not raw_sev:
        if anomaly_score >= 0.8:
            severity = "CRITICAL"
        elif anomaly_score >= 0.6:
            severity = "HIGH"
        elif anomaly_score >= 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # ── Confidence ───────────────────────────────────────────────────────────
    llm_conf = _normalise_confidence(parsed.get("confidence", 0.5))
    lstm_conf = anomaly_score  # already 0–1

    # Blend: 60 % LSTM weight, 40 % LLM weight (LSTM is more objective)
    confidence = round(lstm_conf * 0.6 + llm_conf * 0.4, 4)
    confidence = max(0.0, min(1.0, confidence))

    # ── MITRE techniques ─────────────────────────────────────────────────────
    mitre = _normalise_techniques(parsed.get("mitre_technique", []))

    # ── Explanation ───────────────────────────────────────────────────────────
    explanation = parsed.get("explanation", "")
    if isinstance(explanation, (list, dict)):
        explanation = str(explanation)
    explanation = str(explanation).strip()[:2000]
    if not explanation:
        explanation = "Anomalous activity detected. Manual review recommended."

    # ── Recommended actions ───────────────────────────────────────────────────
    actions = _normalise_actions(parsed.get("recommended_actions", []))
    if not actions:
        # Provide context-appropriate defaults
        if severity in ("HIGH", "CRITICAL"):
            actions = [
                "Isolate affected systems immediately",
                "Escalate to incident response team",
                "Preserve forensic evidence and logs",
            ]
        elif severity == "MEDIUM":
            actions = [
                "Investigate source IP and user account",
                "Review surrounding log context",
                "Monitor for related activity patterns",
            ]
        else:
            actions = [
                "Log event for baseline correlation",
                "Add to watchlist for future reference",
            ]

    # ── Attack stage ──────────────────────────────────────────────────────────
    attack_stage = str(parsed.get("attack_stage", "Unknown")).strip() or "Unknown"

    return {
        "attack_stage":        attack_stage,
        "mitre_technique":     mitre,
        "severity":            severity,
        "confidence":          confidence,   # always float 0.0–1.0
        "explanation":         explanation,
        "recommended_actions": actions,
    }


def calculate_confidence_score(parsed_data: Dict[str, Any], lstm_anomaly_score: float) -> float:
    """
    Standalone helper: blend LLM confidence with LSTM anomaly score.
    Returns a float in [0.0, 1.0].
    (Kept for backward-compat with any callers outside llm_agent.py.)
    """
    llm_conf = _normalise_confidence(parsed_data.get("confidence", 0.5))
    blended = lstm_anomaly_score * 0.6 + llm_conf * 0.4
    return round(max(0.0, min(1.0, blended)), 4)
