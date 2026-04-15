"""
incident_report.py
------------------
Generates a structured JSON incident report from all pipeline outputs.

The report is the final output product of the SOC Analyst pipeline and
includes all enrichment data in a machine-readable + human-readable form.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "BENIGN":   0,
}


def _parse_severity_from_text(text: str) -> str:
    """Extract severity keyword from LLM output text."""
    text_lower = text.lower()
    for sev in ("critical", "high", "medium", "low"):
        if sev in text_lower:
            return sev.upper()
    return "MEDIUM"


def _parse_mitre_from_text(text: str) -> List[str]:
    """Extract MITRE T-codes from LLM output."""
    import re
    # Match patterns like T1078, T1059.001, T1110.003, etc.
    matches = re.findall(r"T\d{4}(?:\.\d{3})?", text)
    return list(dict.fromkeys(matches))  # deduplicate while preserving order


def _parse_attack_stage_from_text(text: str) -> str:
    """Extract attack stage from LLM output text."""
    import re
    patterns = [
        r"attack[_\s]stage[:\s]+([^\n\*]+)",
        r"attack stage[:\s]+([^\n\*]+)",
        r"stage[:\s]+([^\n\*]+)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1).strip().rstrip(".")
    return "Unknown"


def _calculate_confidence(
    anomaly_score: float,
    threat_intel_risk: int,
    event_types: List[str],
) -> float:
    """
    Calculate overall confidence score (0.0 – 1.0).

    Combines:
      - LSTM anomaly score (0.0 – 1.0)
      - Threat intel risk score (0 – 100)
      - Number of distinct attack event types observed
    """
    # Normalize threat intel risk to 0-1
    ti_score = min(threat_intel_risk, 100) / 100.0

    # Count non-normal attack event types
    attack_types = {
        "LOGIN", "PRIV_ESC", "SUSPICIOUS_EXEC", "OUTBOUND_CONN",
        "LATERAL_MOVE", "DEFENSE_EVADE", "EXFILTRATION",
    }
    attack_event_count = len(set(event_types) & attack_types)
    diversity_score = min(attack_event_count / 5.0, 1.0)  # max out at 5 types

    # Weighted average
    confidence = (
        anomaly_score * 0.4 +
        ti_score      * 0.35 +
        diversity_score * 0.25
    )
    return round(min(confidence, 1.0), 3)


def generate_report(
    sessions: List[Dict[str, Any]],
    anomaly_score: float,
    threat_intel: Dict[str, Any],
    attack_graph: Dict[str, Any],
    llm_output: str,
    raw_logs: str,
    rag_snippets: Optional[List[str]] = None,  # MITRE ATT&CK passages from ChromaDB
    mitre_query: Optional[str] = None,          # The query used for RAG retrieval
    events: Optional[List[Any]] = None,         # SecurityEvent objects for MITRE fallback
) -> Dict[str, Any]:
    """
    Generate the final structured incident report.

    Parameters
    ----------
    sessions       : List of session dicts from session_builder
    anomaly_score  : Float 0.0–1.0 from LSTM model (0=normal, 1=anomaly)
    threat_intel   : Dict from threat_intel.ThreatIntelReport.to_dict()
    attack_graph   : Dict from attack_graph.build_attack_graph()
    llm_output     : Raw text from Gemini LLM
    raw_logs       : Original raw log input
    rag_snippets   : MITRE ATT&CK text passages retrieved from ChromaDB
    mitre_query    : The compound query used to retrieve those passages

    Returns
    -------
    Fully structured JSON-serializable incident report dict.
    """
    # ── Core parsing ──────────────────────────────────────────────────────────
    severity_text = _parse_severity_from_text(llm_output)
    mitre_techniques = _parse_mitre_from_text(llm_output)
    attack_stage = _parse_attack_stage_from_text(llm_output)

    # Fallback: if LLM parsing found no T-codes, extract from mitre_query
    # (which is built from event-level mitre_hint fields like "T1110 Brute Force")
    if not mitre_techniques and mitre_query:
        mitre_techniques = _parse_mitre_from_text(mitre_query)

    # Second fallback: extract from event mitre_hints directly
    if not mitre_techniques and events:
        import re as _re
        for event in events:
            hint = getattr(event, "mitre_hint", None)
            if hint:
                found = _re.findall(r"T\d{4}(?:\.\d{3})?", hint)
                mitre_techniques.extend(found)
        mitre_techniques = list(dict.fromkeys(mitre_techniques))  # deduplicate

    # Collect all event types across sessions
    all_event_types = []
    for session in sessions:
        all_event_types.extend(session.get("unique_types", []))

    # Kill-chain stage from attack graph
    kill_chain_stage = attack_graph.get("kill_chain_stage", "Unknown")
    graph_stages = attack_graph.get("stages", [])

    # If attack graph gives further-along stage, prefer it for attack_stage
    if kill_chain_stage != "Benign" and attack_stage == "Unknown":
        attack_stage = kill_chain_stage

    # ── Confidence ───────────────────────────────────────────────────────────
    ti_risk = threat_intel.get("max_risk_score", 0)
    confidence = _calculate_confidence(anomaly_score, ti_risk, all_event_types)

    # ── Severity resolution ──────────────────────────────────────────────────
    # Take the max of: LLM-extracted, threat intel overall risk, anomaly score
    ti_overall = threat_intel.get("overall_risk", "LOW")
    sev_candidates = [severity_text, ti_overall]
    if anomaly_score >= 0.8:
        sev_candidates.append("HIGH")
    elif anomaly_score >= 0.6:
        sev_candidates.append("MEDIUM")
    final_severity = max(sev_candidates, key=lambda s: SEVERITY_MAP.get(s, 0))

    # ── Recommended response ─────────────────────────────────────────────────
    import re
    rec_match = re.search(
        r"recommended[_\s]actions?[:\s]+([\s\S]*?)(?:\n\n|$)",
        llm_output,
        re.IGNORECASE,
    )
    recommended_raw = rec_match.group(1).strip() if rec_match else llm_output
    recommended_actions = [
        line.lstrip("•-*0123456789. ").strip()
        for line in recommended_raw.splitlines()
        if line.strip() and len(line.strip()) > 5
    ][:8]  # cap at 8 actions

    # ── Assemble report ───────────────────────────────────────────────────────
    report = {
        "incident_id":       str(uuid.uuid4()),
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "severity":          final_severity,
        "confidence":        confidence,
        "attack_stage":      attack_stage,
        "kill_chain_stage":  kill_chain_stage,
        "kill_chain_path":   graph_stages,
        "mitre_techniques":  mitre_techniques if mitre_techniques else ["Unknown"],
        "anomaly_score":     round(anomaly_score, 4),
        "event_types":       list(dict.fromkeys(all_event_types)),
        "session_count":     len(sessions),
        "events_analyzed":   sum(s.get("event_count", 0) for s in sessions),
        "threat_intel":      threat_intel,
        "attack_graph":      {
            "node_count":      attack_graph.get("node_count", 0),
            "edge_count":      attack_graph.get("edge_count", 0),
            "attack_path":     attack_graph.get("attack_path", []),
            "stages":          graph_stages,
            "nodes":           attack_graph.get("nodes", []),
            "edges":           attack_graph.get("edges", []),
        },
        # ── RAG knowledge retrieval results ──────────────────────────────
        "rag_query":         mitre_query or "",
        "rag_snippets":      rag_snippets or [],   # MITRE ATT&CK passages from ChromaDB
        # ─────────────────────────────────────────────────────────────────
        "llm_explanation": llm_output,
        "recommended_response": recommended_actions,
        "raw_log_sample":    raw_logs[:500] if raw_logs else "",
    }

    return report


def format_report_text(report: Dict[str, Any]) -> str:
    """
    Produce a human-readable text version of the incident report
    for console output or logging.
    """
    lines = [
        "=" * 60,
        f"INCIDENT REPORT  [{report['incident_id']}]",
        f"Timestamp   : {report['timestamp']}",
        f"Severity    : {report['severity']}",
        f"Confidence  : {report['confidence'] * 100:.1f}%",
        f"Attack Stage: {report['attack_stage']}",
        f"Kill Chain  : {report['kill_chain_stage']}",
        f"MITRE       : {', '.join(report['mitre_techniques'])}",
        f"Anomaly Score: {report['anomaly_score']:.4f}",
        "-" * 60,
        "THREAT INTELLIGENCE:",
        f"  Malicious Indicators : {report['threat_intel'].get('malicious_indicators', 0)}",
        f"  Overall Risk         : {report['threat_intel'].get('overall_risk', 'N/A')}",
        "-" * 60,
        "ATTACK GRAPH:",
        f"  Path  : {' → '.join(report['attack_graph']['attack_path'])}",
        f"  Stages: {' → '.join(report['attack_graph']['stages'])}",
        "-" * 60,
        "RECOMMENDED RESPONSE:",
    ]
    for i, action in enumerate(report["recommended_response"], 1):
        lines.append(f"  {i}. {action}")
    lines.append("=" * 60)
    return "\n".join(lines)
