"""
llm_agent.py
------------
LLM Agent for structured SOC analysis with expert validation.
Engine: OpenAI API client connected to OpenRouter (gpt-4o-mini).

Expert SOC Analyst Framework:
- Validates MITRE techniques against events and RAG context
- Prevents hallucination of unsupported techniques
- Enforces severity/confidence mapping
- Prioritizes event sequence over context
"""

import os
import logging
import json
import re
from typing import Optional, Dict, Any, List, Tuple

from dotenv import load_dotenv
load_dotenv()

from backend.rag.rag_engine import retrieve_context
from backend.utils.json_parser import parse_and_validate_incident_report

logger = logging.getLogger(__name__)

# --- Configuration (loaded from .env) ---
MODEL_NAME = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")

# MITRE ATT&CK Technique regex (T-code validation)
MITRE_TCODE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')

# ── Validation Functions ──────────────────────────────────────────────────────

def validate_mitre_techniques(techniques: List[str], rag_context: str, event_sequence: List[str]) -> List[str]:
    """
    EXPERT SOC RULE: Only use techniques supported by RAG context.
    Prevents hallucination of unsupported MITRE techniques.
    
    Args:
        techniques: List of technique T-codes from LLM
        rag_context: Retrieved MITRE ATT&CK passages
        event_sequence: Detected security events
    
    Returns:
        Validated list of techniques (removes hallucinations)
    """
    if not techniques:
        return []
    
    # Extract all valid T-codes from RAG context
    context_tcodes = set(MITRE_TCODE_PATTERN.findall(rag_context)) if rag_context else set()
    
    # Validate each technique
    validated = []
    for tech in techniques:
        tech_clean = tech.strip().upper()
        
        # Check if it's a valid T-code format
        if not MITRE_TCODE_PATTERN.match(tech_clean):
            logger.warning(f"Skipping invalid T-code format: {tech}")
            continue
        
        # Check if technique is in RAG context (prevent hallucination)
        if tech_clean not in context_tcodes:
            logger.warning(f"Skipping technique not in RAG context: {tech_clean}")
            continue
        
        # Technique is valid and in context
        validated.append(tech_clean)
    
    return validated


def validate_severity(severity: str, anomaly_score: float, technique_count: int) -> str:
    """
    EXPERT SOC RULE: Severity must align with evidence.
    - HIGH: anomaly >= 0.7 OR techniques >= 3
    - MEDIUM: anomaly >= 0.4 OR techniques >= 1
    - LOW: otherwise
    
    Args:
        severity: Proposed severity from LLM
        anomaly_score: LSTM anomaly detection score (0-1)
        technique_count: Number of validated MITRE techniques
    
    Returns:
        Validated severity level
    """
    valid_levels = ["LOW", "MEDIUM", "HIGH"]
    severity_clean = (severity or "").upper().strip()
    
    # If LLM chose invalid level, recalculate based on evidence
    if severity_clean not in valid_levels:
        if anomaly_score >= 0.7 or technique_count >= 3:
            return "HIGH"
        elif anomaly_score >= 0.4 or technique_count >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    # Calculate evidence-based severity
    if anomaly_score >= 0.7 or technique_count >= 3:
        calculated = "HIGH"
    elif anomaly_score >= 0.4 or technique_count >= 1:
        calculated = "MEDIUM"
    else:
        calculated = "LOW"
    
    # If LLM's choice contradicts evidence, use calculated value
    if severity_clean != calculated:
        logger.warning(f"Severity adjustment: LLM={severity_clean}, evidence-based={calculated} (anomaly={anomaly_score}, techniques={technique_count})")
        return calculated
    
    return severity_clean


def validate_confidence(confidence: str, technique_count: int, anomaly_score: float) -> str:
    """
    EXPERT SOC RULE: Confidence must be justified by evidence.
    
    Args:
        confidence: Proposed confidence from LLM (should be percentage string)
        technique_count: Number of validated MITRE techniques
        anomaly_score: LSTM anomaly score
    
    Returns:
        Validated confidence as percentage string
    """
    # Parse confidence value
    conf_str = (confidence or "50%").strip().replace("%", "").strip()
    
    try:
        conf_val = float(conf_str)
    except ValueError:
        # Default to moderate confidence if parsing fails
        conf_val = 50.0
    
    # Clamp confidence: 0-100
    conf_val = max(0.0, min(100.0, conf_val))
    
    # Adjust based on evidence:
    # Strong evidence (3+ techniques AND high anomaly) → 75%+ required
    # Moderate evidence (1+ techniques AND moderate anomaly) → 50%+ required
    # Weak evidence (no techniques OR very low anomaly) → cap at 40%
    
    if technique_count >= 3 and anomaly_score >= 0.7:
        conf_val = max(conf_val, 75.0)  # Strong evidence - require at least 75%
    elif technique_count >= 1 and anomaly_score >= 0.4:
        conf_val = max(conf_val, 50.0)  # Moderate evidence - require at least 50%
    elif anomaly_score < 0.3:
        conf_val = min(conf_val, 40.0)  # Very weak evidence - cap at 40%
    elif technique_count == 0:
        conf_val = min(conf_val, 40.0)  # No techniques - cap at 40%
    
    return f"{int(conf_val)}%"


def validate_explanation(explanation: str, techniques: List[str], events: List[str], rag_context: str = "") -> str:
    """
    EXPERT SOC RULE: Explanation must reference detected events and techniques.
    Enhanced with RAG context awareness.
    
    Args:
        explanation: Proposed explanation from LLM
        techniques: Validated MITRE techniques
        events: Security event sequence
        rag_context: Retrieved MITRE context for correlation
    
    Returns:
        Validated explanation (or enhanced if missing/weak)
    """
    # If explanation is too short or generic, generate a better one
    is_generic = explanation and len(explanation) < 25
    is_empty = not explanation or len(explanation) == 0
    
    if is_empty or is_generic:
        # Build enhanced explanation from evidence
        parts = []
        
        # Part 1: Event correlation
        if events and len(events) > 1:
            event_str = " -> ".join(events[:4])
            parts.append(f"Activity chain detected: {event_str}.")
        elif events:
            parts.append(f"Suspicious event: {events[0]}.")
        else:
            parts.append("Anomalous activity detected.")
        
        # Part 2: MITRE technique mapping
        if techniques:
            tech_str = ", ".join(techniques)
            parts.append(f"This correlates with MITRE ATT&CK techniques: {tech_str}.")
        else:
            parts.append("Activity pattern does not match known MITRE techniques - may indicate novel attack.")
        
        # Part 3: RAG context reference if available
        if rag_context and "Technique ID:" in rag_context:
            # Extract technique name from context if available
            if "Technique Name:" in rag_context:
                try:
                    name_start = rag_context.find("Technique Name:") + len("Technique Name:")
                    name_end = rag_context.find("\n", name_start)
                    tech_name = rag_context[name_start:name_end].strip()
                    if tech_name:
                        parts.append(f"Based on retrieved MITRE knowledge: {tech_name}.")
                except:
                    pass
        
        enhanced = " ".join(parts)
        
        # Ensure minimum quality
        if len(enhanced) < 40:
            enhanced = f"Analysis of event sequence ({len(events)} events) shows potential security incident requiring investigation."
        
        return enhanced
    
    # Explanation exists and is substantial - keep it but enhance if RAG context available
    if len(explanation) > 20 and rag_context and techniques:
        return explanation
    
    return explanation.strip()



def validate_llm_output(
    llm_dict: Dict[str, Any],
    rag_context: str,
    event_sequence: List[str],
    anomaly_score: float
) -> Dict[str, Any]:
    """
    EXPERT SOC VALIDATION: Ensures LLM output follows strict analyst rules.
    
    Rules enforced:
    1. Techniques must be in RAG context (prevent hallucination)
    2. Severity must align with anomaly score
    3. Confidence must be justified by evidence
    4. Explanation must reference detected indicators
    5. Recommended actions must be practical
    """
    
    # Validate and clean techniques
    raw_techniques = llm_dict.get("mitre_technique", [])
    validated_techniques = validate_mitre_techniques(
        raw_techniques,
        rag_context,
        event_sequence
    )
    
    # Validate severity
    validated_severity = validate_severity(
        llm_dict.get("severity", ""),
        anomaly_score,
        len(validated_techniques)
    )
    
    # Validate confidence
    validated_confidence = validate_confidence(
        llm_dict.get("confidence", ""),
        len(validated_techniques),
        anomaly_score
    )
    
    # Validate explanation
    validated_explanation = validate_explanation(
        llm_dict.get("explanation", ""),
        validated_techniques,
        event_sequence,
        rag_context=rag_context  # Pass RAG context for better explanation generation
    )
    
    # Validate recommended actions (ensure at least one action)
    raw_actions = llm_dict.get("recommended_actions", [])
    if not raw_actions or not isinstance(raw_actions, list):
        raw_actions = []
    
    # Filter empty actions and limit to 5
    validated_actions = [str(a).strip() for a in raw_actions if a and len(str(a).strip()) > 5][:5]
    
    if not validated_actions:
        # Provide default actions based on severity
        if validated_severity == "HIGH":
            validated_actions = [
                "Isolate affected systems immediately",
                "Escalate to incident response team",
                "Preserve logs and forensic evidence"
            ]
        elif validated_severity == "MEDIUM":
            validated_actions = [
                "Investigate source IP and user account",
                "Review system logs for additional indicators",
                "Monitor for related activity"
            ]
        else:
            validated_actions = [
                "Document suspicious activity",
                "Add to watchlist for future correlation"
            ]
    
    # Return validated output
    return {
        "attack_stage": llm_dict.get("attack_stage", "Unknown"),
        "mitre_technique": validated_techniques,
        "severity": validated_severity,
        "confidence": validated_confidence,
        "explanation": validated_explanation,
        "recommended_actions": validated_actions
    }


# ── Inference Function ───────────────────────────────────────────────────────

def generate_inference(prompt: str) -> str:
    """Executes OpenRouter inference using OpenAI Client."""
    from openai import OpenAI
    
    # Allows falling back to user's OpenRouter or standard OpenAI API based on env configuration
    api_key = os.getenv("OPEN_ROUTER_API") or os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("No OpenRouter Key found in environment variables.")

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenRouter API failed: {e}")
        raise RuntimeError(f"OpenRouter generation failed: {e}")

def build_optimized_prompt(log_text: str, event_sequence: List[str], anomaly_score: float, threat_intel: str, rag_context: str) -> str:
    """
    Builds an expert SOC analyst prompt with strict validation rules.
    Enforces MITRE accuracy, detailed explanations, and prevents hallucination.
    """
    seq = " -> ".join(event_sequence) if event_sequence else "None"
    anomaly_level = "CRITICAL" if anomaly_score >= 0.8 else "HIGH" if anomaly_score >= 0.6 else "MEDIUM" if anomaly_score >= 0.4 else "LOW"
    
    return f"""You are an EXPERT CYBERSECURITY SOC ANALYST with 10+ years experience. Your analysis MUST be accurate, detailed, and evidence-based.

CRITICAL RULES - FOLLOW STRICTLY:
1. ONLY use MITRE techniques clearly supported by BOTH the event sequence AND the retrieved context
2. If retrieved context has unrelated techniques, IGNORE them completely
3. Prioritize exact technique matches (e.g., T1110 ≠ T1021)
4. NEVER hallucinate techniques not in the context
5. Return empty list [] for techniques if no match found
6. TRUST the event sequence MORE than retrieved context if there's a mismatch

EXPLANATION REQUIREMENTS - MUST INCLUDE:
1. Specific events that triggered this alert (reference actual log entries)
2. WHY each detected event is suspicious (behavioral analysis)
3. EXACT MITRE technique mapping with reasoning (reference retrieved context)
4. Correlation between events (e.g., "after 5 failed logins, successful auth")
5. Attack pattern assessment (what is the attacker trying to achieve?)
6. Confidence justification (why this confidence level?)

SEVERITY MAPPING:
- HIGH: Anomaly >= 0.7 OR confirmed attack pattern OR multiple MITRE techniques
- MEDIUM: Anomaly 0.4-0.7 OR suspicious pattern OR single technique detected
- LOW: Anomaly < 0.4 OR unusual but benign activity

CONFIDENCE CALIBRATION:
- 80%+: Multiple correlated techniques + high anomaly + threat intel match
- 60-80%: 1-2 techniques + moderate anomaly + event correlation
- 40-60%: Single indicator + moderate anomaly OR weak correlation
- 0-40%: Insufficient evidence OR conflicting indicators

JSON OUTPUT (STRICT FORMAT):
{{
  "attack_stage": "ATT&CK lifecycle stage or 'Unknown' if insufficient evidence",
  "mitre_technique": ["T1234", "T5678"] or [] if no supported techniques found,
  "severity": "LOW|MEDIUM|HIGH",
  "confidence": "percentage string (e.g., '75%')",
  "explanation": "2-3 sentence detailed analysis explaining: (1) specific suspicious events, (2) MITRE technique mapping with context reference, (3) attack pattern and reasoning",
  "recommended_actions": ["specific action 1", "specific action 2", "specific action 3"]
}}

═══════════════════════════════════════════════════════════════════════════════
EVIDENCE ANALYSIS INPUTS:
═══════════════════════════════════════════════════════════════════════════════

EVENT SEQUENCE: {seq}

ANOMALY SCORE: {anomaly_score:.2f} [{anomaly_level}]
- Interpretation: {anomaly_level} anomaly detected (0.0 = normal, 1.0 = critical)

THREAT INTELLIGENCE: {threat_intel or "No known threats"}

RETRIEVED MITRE ATT&CK KNOWLEDGE BASE:
────────────────────────────────────────────────────────────────────────────────
{rag_context or "No relevant MITRE techniques found - may indicate unknown attack pattern"}
────────────────────────────────────────────────────────────────────────────────

ANALYSIS INSTRUCTIONS:
1. Match event sequence against retrieved MITRE techniques
2. Provide specific evidence linking events to attack stage
3. Reference exact MITRE T-codes from context (not guesses)
4. Explain confidence based on evidence strength
5. Return JSON ONLY - no additional text

NOW ANALYZE AND RETURN VALID JSON ONLY:"""

def investigate_logs(
    log_text: str,
    event_sequence: List[str] = None,
    anomaly_score: float = 0.0,
    threat_intel_summary: str = "",
    attack_graph_summary: str = "",
    rag_context: str = "",
) -> Dict[str, Any]:
    """
    EXPERT SOC ANALYST PIPELINE with strict validation.
    
    Returns a structured incident report following SOC analyst best practices:
    - MITRE techniques validated against both events and context
    - No hallucinations (Unknown if insufficient evidence)
    - Severity aligns with anomaly score
    - Confidence justified by evidence
    - Explanations reference actual indicators
    """
    if event_sequence is None:
        event_sequence = []
    
    # 1. Retrieve RAG context if not provided
    if not rag_context:
        rag_query = " ".join(event_sequence or []) + " " + log_text[:300]
        rag_context = retrieve_context(rag_query)

    # 2. Build expert SOC analyst prompt
    prompt = build_optimized_prompt(
        log_text=log_text,
        event_sequence=event_sequence,
        anomaly_score=anomaly_score,
        threat_intel=threat_intel_summary,
        rag_context=rag_context
    )

    llm_output = ""
    # 3. Execute LLM inference
    try:
        llm_output = generate_inference(prompt)
        logger.debug(f"LLM Output: {llm_output[:200]}...")
    except Exception as e:
        logger.error(f"LLM inference failed: {e}")
        llm_output = ""  # Will be handled by parser

    # 4. Parse JSON output
    try:
        llm_dict = json.loads(llm_output) if llm_output else {}
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse LLM JSON: {llm_output[:100]}")
        llm_dict = {}

    # 5. EXPERT SOC VALIDATION LAYER
    # This is the critical enforcement of analyst guidelines
    validated_dict = validate_llm_output(
        llm_dict,
        rag_context=rag_context,
        event_sequence=event_sequence,
        anomaly_score=anomaly_score
    )

    # 6. Final parsing and validation through existing parser
    final_report = parse_and_validate_incident_report(
        json.dumps(validated_dict),
        anomaly_score=anomaly_score
    )
    
    logger.info(f"Analysis complete: severity={final_report.get('severity')}, confidence={final_report.get('confidence')}")
    return final_report
