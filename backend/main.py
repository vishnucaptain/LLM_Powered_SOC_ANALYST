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
  7. LLM investigation (Phi-3.5 local) — receives pre-fetched RAG context
  8. Reconstruct attack graph (NetworkX)
  9. Generate structured incident report  ← includes rag_context
  10. Return full JSON
"""

import concurrent.futures
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional as _Optional

from backend.schemas import LogRequest, InvestigateResponse
from backend.ingestion.log_normalizer import normalize_logs
from backend.processing.event_extractor import extract_events, events_to_sequence, get_mitre_query
from backend.processing.session_builder import build_sessions, sessions_summary
from backend.processing.threat_intel import enrich_events
from backend.models.attack_graph import build_attack_graph, attack_graph_summary
from backend.models.lstm_model import score_sequence
from backend.reasoning.llm_agent import investigate_logs
from backend.rag.rag_engine import retrieve_context
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
@app.post("/investigate", response_model=InvestigateResponse)
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

    # ── Step 7: Attack Graph Reconstruction ──────────────────────────────
    graph = build_attack_graph(events)
    graph_summary = attack_graph_summary(graph)

    # ── Step 8: LLM Investigation (receives pre-fetched RAG context) ──────
    llm_warning = ""
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            investigate_logs,
            log_text=raw_logs,
            event_sequence=event_sequence_types,
            anomaly_score=anomaly_score,
            threat_intel_summary=ti_summary,
            attack_graph_summary=graph_summary,
            rag_context=rag_context,         # <— RAG context passed explicitly
        )
        # Timeout after 60 seconds for OpenRouter API
        llm_output = future.result(timeout=60.0)
        executor.shutdown(wait=False)
    except concurrent.futures.TimeoutError:
        llm_warning = "OpenRouter LLM generation timed out. The API request took too long."
        llm_output = {
            "attack_stage": "Unknown",
            "mitre_technique": ["Unknown"],
            "severity": "MEDIUM",
            "confidence": "50%",
            "explanation": "OpenRouter LLM generation timed out.\nThe API request to OpenRouter took too long to complete.",
            "recommended_actions": ["Check OpenRouter API status or check your internet connection."]
        }
    except Exception as e:  # catches RuntimeError, etc.
        llm_warning = f"OpenRouter LLM unavailable: {e}"
        llm_output = {
            "attack_stage": "Unknown",
            "mitre_technique": ["Unknown"],
            "severity": "MEDIUM",
            "confidence": "50%",
            "explanation": "OpenRouter LLM could not execute successfully.\nCore detections (events, sessions, anomaly score, threat intel, RAG, attack graph) were still processed.\nReview technical indicators and enrichment data in this report for triage.",
            "recommended_actions": ["Ensure your API key is valid and configured.", "Ensure you have stable internet connection."]
        }

    # ── Step 9: Incident Report Generation ───────────────────────────────
    report = generate_report(
        sessions=session_data["sessions"],
        anomaly_score=anomaly_score,
        threat_intel=ti_dict,
        attack_graph=graph,
        llm_parsed=llm_output,
        raw_logs=raw_logs,
        rag_snippets=rag_snippets,       # <— RAG passages now in report
        mitre_query=mitre_query,         # <— show what query was used
        events=events,                   # ← for MITRE technique fallback
    )

    if llm_warning:
        report["llm_warning"] = llm_warning

    # ── Step 10: Add legacy field for frontend backward-compat ────────────
    import json
    report["investigation"] = json.dumps(llm_output)

    return InvestigateResponse(**report)


# ── Auxiliary endpoints ───────────────────────────────────────────────────────

class _ParseRequest(BaseModel):
    logs: str = Field(..., min_length=1, description="Raw log text or query string")
    k: _Optional[int] = Field(default=3, ge=1, le=20, description="Max RAG snippets to return")


@app.post("/parse")
def parse_only(request: _ParseRequest):
    """
    Parse and normalize logs without running LLM investigation.
    Useful for testing the extraction pipeline.
    Also runs RAG retrieval so you can inspect what MITRE context would be used.
    Accepts optional `k` field (1-20) to control number of RAG snippets returned.
    """
    k = max(1, min(int(request.k or 3), 20))
    normalized = normalize_logs(request.logs)
    events = extract_events(normalized)
    sessions = build_sessions(events)
    anomaly_score = score_sequence(events_to_sequence(events))
    ti_report = enrich_events(events)
    graph = build_attack_graph(events)
    mitre_query = get_mitre_query(events)
    rag_context = retrieve_context(mitre_query, k=k)
    rag_snippets = [s.strip() for s in rag_context.split("\n\n") if s.strip()]
    rag_source = "vector_db" if rag_snippets else "none"

    return {
        "normalized_count": len(normalized),
        "events": [e.to_dict() for e in events],
        "sessions": sessions_summary(sessions),
        "anomaly_score": anomaly_score,
        "threat_intel": ti_report.to_dict(),
        "attack_graph": graph,
        "rag_query": mitre_query,
        "rag_source": rag_source,
        "rag_snippets": rag_snippets,
        "rag_context": rag_context,
    }


class _RagTestRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Direct semantic search query against the MITRE ATT&CK vector DB")
    k: _Optional[int] = Field(default=3, ge=1, le=20, description="Number of results to retrieve")


@app.post("/rag-test")
def rag_test(request: _RagTestRequest):
    """
    Direct RAG query endpoint — bypass log parsing and query the vector DB directly.
    Useful for testing what the MITRE ATT&CK ChromaDB retrieves for a given query.
    """
    k = max(1, min(int(request.k or 3), 20))
    rag_context = retrieve_context(request.query, k=k)
    rag_snippets = [s.strip() for s in rag_context.split("\n\n") if s.strip()]
    rag_source = "vector_db" if rag_snippets else "none"

    return {
        "query": request.query,
        "k": k,
        "rag_source": rag_source,
        "rag_snippets": rag_snippets,
        "rag_context": rag_context,
        "snippet_count": len(rag_snippets),
    }