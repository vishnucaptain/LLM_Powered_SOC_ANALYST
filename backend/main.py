"""
main.py
-------
FastAPI application — LLM-Powered SOC Analyst API.

Full pipeline:
  POST /investigate
  1. Parse & normalize logs
  2. Extract typed security events
  3. Build behavioral sessions
  4. Score with LSTM anomaly detector (with heuristic fallback)
  5. Enrich with threat intelligence
  6. Retrieve MITRE ATT&CK RAG context  ← using get_mitre_query()
  7. LLM investigation (Gemini) — receives pre-fetched RAG context
  8. Reconstruct attack graph (NetworkX)
  9. Generate structured incident report  ← includes rag_context
  10. Return full JSON
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.models import LogRequest, InvestigateResponse
from backend.log_normalizer import normalize_logs
from backend.event_extractor import extract_events, events_to_sequence, get_mitre_query
from backend.session_builder import build_sessions, sessions_summary
from backend.threat_intel import enrich_events
from backend.attack_graph import build_attack_graph, attack_graph_summary
from backend.lstm_model import score_sequence
from backend.llm_agent import investigate_logs
from backend.rag_engine import retrieve_context
from backend.incident_report import generate_report

app = FastAPI(
    title="LLM-Powered SOC Analyst",
    description=(
        "AI-assisted Security Operations Center that automatically analyzes "
        "security logs, detects suspicious behaviour via LSTM anomaly detection, "
        "retrieves MITRE ATT&CK knowledge, and generates incident investigation reports."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Private Network Access (for opening directly from file://) ────────────────
@app.middleware("http")
async def add_private_network_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/")
def health_check():
    return {
        "status": "SOC Analyst API running",
        "version": "2.0.0",
        "pipeline": [
            "log_normalization",
            "event_extraction",
            "session_building",
            "lstm_anomaly_detection",
            "threat_intel_enrichment",
            "mitre_rag_retrieval",       # <— RAG step, now explicit
            "llm_investigation",
            "attack_graph_reconstruction",
            "incident_report_generation",
        ],
    }


# ── Main investigation endpoint ───────────────────────────────────────────────
@app.post("/investigate")
def investigate(request: LogRequest):
    """
    Full SOC investigation pipeline.

    Accepts raw security logs (text, JSON array, or JSON Lines).
    Returns a structured incident report with:
      - LSTM anomaly score
      - MITRE ATT&CK techniques
      - Threat intelligence enrichment
      - Attack graph (NetworkX)
      - RAG-retrieved MITRE ATT&CK passages  ← now surfaced
      - LLM-generated explanation and recommendations
    """
    raw_logs = request.logs

    # ── Step 1: Log Normalization ─────────────────────────────────────────
    normalized_logs = normalize_logs(raw_logs)

    # ── Step 2: Event Extraction ──────────────────────────────────────────
    events = extract_events(normalized_logs)
    event_sequence_ints = events_to_sequence(events)
    event_sequence_types = [e.event_type for e in events]

    # ── Step 3: Session Building ──────────────────────────────────────────
    sessions = build_sessions(events)
    session_data = sessions_summary(sessions)

    # ── Step 4: LSTM Anomaly Detection ────────────────────────────────────
    anomaly_score = score_sequence(event_sequence_ints)

    # ── Step 5: Threat Intelligence Enrichment ────────────────────────────
    ti_report = enrich_events(events)
    ti_dict = ti_report.to_dict()
    ti_summary = ti_report.summary_text()

    # ── Step 6: MITRE ATT&CK RAG Retrieval ───────────────────────────────
    # Build a targeted query from the MITRE hints embedded in each detected
    # event type (e.g. "T1110 Brute Force | T1059 Command Scripting |…")
    # instead of using raw log text — much better semantic matching.
    mitre_query = get_mitre_query(events)
    rag_context = retrieve_context(mitre_query)

    # Keep individual snippets so the frontend can display them
    rag_snippets = [
        s.strip() for s in rag_context.split("\n\n") if s.strip()
    ]

    # ── Step 7: LLM Investigation (receives pre-fetched RAG context) ──────
    llm_output = investigate_logs(
        log_text=raw_logs,
        event_sequence=event_sequence_types,
        anomaly_score=anomaly_score,
        threat_intel_summary=ti_summary,
        attack_graph_summary="",         # filled after graph step
        rag_context=rag_context,         # <— RAG context passed explicitly
    )

    # ── Step 8: Attack Graph Reconstruction ──────────────────────────────
    graph = build_attack_graph(events)
    graph_summary = attack_graph_summary(graph)

    # ── Step 9: Incident Report Generation ───────────────────────────────
    report = generate_report(
        sessions=session_data["sessions"],
        anomaly_score=anomaly_score,
        threat_intel=ti_dict,
        attack_graph=graph,
        llm_output=llm_output,
        raw_logs=raw_logs,
        rag_snippets=rag_snippets,       # <— RAG passages now in report
        mitre_query=mitre_query,         # <— show what query was used
    )

    # ── Step 10: Add legacy field for frontend backward-compat ────────────
    report["investigation"] = llm_output

    return report


# ── Auxiliary endpoints ───────────────────────────────────────────────────────

@app.post("/parse")
def parse_only(request: LogRequest):
    """
    Parse and normalize logs without running LLM investigation.
    Useful for testing the extraction pipeline.
    Also runs RAG retrieval so you can inspect what MITRE context would be used.
    """
    normalized = normalize_logs(request.logs)
    events = extract_events(normalized)
    sessions = build_sessions(events)
    anomaly_score = score_sequence(events_to_sequence(events))
    ti_report = enrich_events(events)
    graph = build_attack_graph(events)

    return {
        "normalized_count": len(normalized),
        "events": [e.to_dict() for e in events],
        "sessions": sessions_summary(sessions),
        "anomaly_score": anomaly_score,
        "threat_intel": ti_report.to_dict(),
        "attack_graph": graph,
    }