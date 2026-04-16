"""
models.py
---------
Pydantic request / response models for the FastAPI SOC Analyst API.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class LogRequest(BaseModel):
    """Request body for POST /investigate"""
    logs: str = Field(
        ...,
        description="Raw security logs (multi-line text, JSON array, or JSON Lines)",
        min_length=1,
    )


class ThreatIntelIndicator(BaseModel):
    indicator: str
    indicator_type: str
    is_malicious: bool
    threat_category: Optional[str] = None
    threat_description: Optional[str] = None
    confidence: float
    source: str
    risk_score: int


class ThreatIntelSummary(BaseModel):
    malicious_indicators: int
    total_indicators: int
    max_risk_score: int
    overall_risk: str
    indicators: List[ThreatIntelIndicator] = Field(default_factory=list)


class AttackGraphSummary(BaseModel):
    node_count: int
    edge_count: int
    attack_path: List[str] = Field(default_factory=list)
    stages: List[str] = Field(default_factory=list)
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)


class InvestigateResponse(BaseModel):
    """Full structured response from POST /investigate"""

    # Core identifiers
    incident_id: str
    timestamp: str

    # Risk assessment
    severity: str
    confidence: float
    anomaly_score: float

    # Attack characterization
    attack_stage: str
    kill_chain_stage: str
    kill_chain_path: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    # Event summary
    event_types: List[str] = Field(default_factory=list)
    session_count: int
    events_analyzed: int

    # Enrichment data
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    attack_graph: Dict[str, Any] = Field(default_factory=dict)

    # RAG retrieval results (MITRE ATT&CK knowledge base)
    rag_query: str = ""
    rag_snippets: List[str] = Field(default_factory=list)

    # LLM outputs
    llm_explanation: str
    recommended_response: List[str] = Field(default_factory=list)

    # Original input (truncated)
    raw_log_sample: str = ""

    # Legacy field for backwards-compat with existing frontend
    investigation: Optional[str] = None

    # Optional warning when fallback logic is used (e.g. LLM unavailable)
    llm_warning: Optional[str] = None