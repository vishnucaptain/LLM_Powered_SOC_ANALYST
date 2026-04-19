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

# Load environment variables from .env FIRST before any other imports
from dotenv import load_dotenv
load_dotenv()

import concurrent.futures
from fastapi import FastAPI, Request, HTTPException, Depends, status
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
from backend.evaluation.evaluator import run_evaluation as _run_evaluation

# Authentication imports
from backend.api.auth import (
    get_current_user,
    AuthService,
    TokenData,
    TokenResponse,
    JWTConfig,
)


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
@app.get("/health")
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


# ── Authentication Endpoints ──────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """User login credentials."""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponseModel(BaseModel):
    """Token response model for OpenAPI documentation."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@app.post("/auth/token", response_model=TokenResponseModel)
def login(credentials: LoginRequest):
    """
    Authenticate user and get JWT token.
    
    **Demo Users (change passwords in production):**
    - username: `analyst` password: `password123`
    - username: `admin` password: `admin123`
    - username: `soc_team` password: `team123`
    
    **Usage:**
    ```bash
    # Get token
    curl -X POST "http://localhost:8000/auth/token" \\
      -H "Content-Type: application/json" \\
      -d '{"username": "analyst", "password": "password123"}'
    
    # Use token in protected endpoints
    curl -X POST "http://localhost:8000/investigate" \\
      -H "Authorization: Bearer <your_token>" \\
      -H "Content-Type: application/json" \\
      -d '{"logs": "your logs here"}'
    ```
    """
    # Authenticate user
    user_id = AuthService.authenticate_user(
        credentials.username,
        credentials.password
    )
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create JWT token
    token = AuthService.create_access_token(
        user_id=user_id,
        username=credentials.username
    )
    
    return TokenResponseModel(
        access_token=token,
        token_type="bearer",
        expires_in=JWTConfig.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.get("/auth/me")
async def get_current_user_info(current_user: TokenData = Depends(get_current_user)):
    """
    Get current authenticated user information.
    
    **Requires JWT token in Authorization header:**
    ```
    Authorization: Bearer <your_token>
    ```
    """
    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "scopes": current_user.scopes,
        "issued_at": current_user.issued_at.isoformat(),
        "expires_at": current_user.expires_at.isoformat(),
    }


@app.get("/")
def root():
    """Root endpoint with API information."""
    return {
        "message": "LLM-Powered SOC Analyst API",
        "version": "2.0.0",
        "docs": "/docs",
        "auth": "/auth/token",
        "health": "/health",
    }


# ── Main investigation endpoint ───────────────────────────────────────────────
@app.post("/investigate", response_model=InvestigateResponse)
async def investigate(
    request: LogRequest,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Full SOC investigation pipeline.
    
    **Requires JWT authentication.**
    
    1. Get token: POST /auth/token
    2. Use token: Add `Authorization: Bearer <token>` header
    
    Accepts raw security logs (text, JSON array, or JSON Lines).
    Returns a structured incident report with:
      - LSTM anomaly score
      - MITRE ATT&CK techniques
      - Threat intelligence enrichment
      - Attack graph (NetworkX)
      - RAG-retrieved MITRE ATT&CK passages
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


# ── Evaluation endpoint ────────────────────────────────────────────────────────

@app.get("/evaluate")
def evaluate(
    current_user: TokenData = Depends(get_current_user),
):
    """
    Run the built-in evaluation suite against the labelled test dataset.

    Uses the heuristic mock detector (no LLM inference required) so the endpoint
    responds quickly and can be used for CI/CD health-checks.

    Returns precision, recall, F1, FPR, accuracy and per-sample confusion matrix.

    **Requires JWT authentication.**
    """
    metrics = _run_evaluation(detection_func=None, verbose=False)
    return {
        "status": "ok",
        "dataset_size": metrics["total_samples"],
        "metrics": {
            "precision":           metrics["precision"],
            "recall":              metrics["recall"],
            "f1_score":            metrics["f1_score"],
            "false_positive_rate": metrics["false_positive_rate"],
            "specificity":         metrics["specificity"],
            "accuracy":            metrics["accuracy"],
        },
        "confusion_matrix": {
            "true_positives":  metrics["true_positives"],
            "false_positives": metrics["false_positives"],
            "true_negatives":  metrics["true_negatives"],
            "false_negatives": metrics["false_negatives"],
        },
    }