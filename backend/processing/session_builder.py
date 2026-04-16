"""
session_builder.py
------------------
Groups SecurityEvents into sessions by source IP or user.
A session is a contiguous window of activity from a single actor.

Session window: 30 minutes of inactivity closes a session.

Output per session:
{
    "session_id":    str,
    "actor":         str  (IP or username),
    "event_count":   int,
    "sequence":      List[int]  (integer-encoded event types),
    "events":        List[dict],
    "start_time":    str | None,
    "end_time":      str | None,
    "severity_max":  str,
    "unique_types":  List[str],
}
"""

import uuid
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from backend.processing.event_extractor import SecurityEvent

# Session window in seconds — events from the same actor within this
# gap are grouped together.
SESSION_GAP_SECONDS = 1800  # 30 minutes

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Session:
    session_id: str
    actor: str
    events: List[SecurityEvent] = field(default_factory=list)

    @property
    def sequence(self) -> List[int]:
        return [e.event_code for e in self.events]

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def severity_max(self) -> str:
        if not self.events:
            return "low"
        max_sev = max(self.events, key=lambda e: SEVERITY_ORDER.get(e.severity, 0))
        return max_sev.severity

    @property
    def unique_types(self) -> List[str]:
        return list(dict.fromkeys(e.event_type for e in self.events))

    @property
    def start_time(self) -> Optional[str]:
        for e in self.events:
            if e.timestamp:
                return e.timestamp
        return None

    @property
    def end_time(self) -> Optional[str]:
        for e in reversed(self.events):
            if e.timestamp:
                return e.timestamp
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id":   self.session_id,
            "actor":        self.actor,
            "event_count":  self.event_count,
            "sequence":     self.sequence,
            "events":       [e.to_dict() for e in self.events],
            "start_time":   self.start_time,
            "end_time":     self.end_time,
            "severity_max": self.severity_max,
            "unique_types": self.unique_types,
        }


def _actor_key(event: SecurityEvent) -> str:
    """Determine the actor (IP or user) for grouping."""
    if event.source_ip:
        return event.source_ip
    if event.user:
        return event.user
    if event.hostname:
        return event.hostname
    return "unknown_actor"


def build_sessions(events: List[SecurityEvent]) -> List[Session]:
    """
    Group events into sessions by actor.
    Returns sessions sorted by event count (largest first = most interesting).
    """
    # Group events by actor
    actor_events: Dict[str, List[SecurityEvent]] = {}
    for event in events:
        key = _actor_key(event)
        actor_events.setdefault(key, []).append(event)

    sessions: List[Session] = []
    for actor, evs in actor_events.items():
        # Each actor may spawn multiple sessions (30-min gap splits them)
        current_session = Session(
            session_id=str(uuid.uuid4())[:8],
            actor=actor,
        )
        for ev in evs:
            current_session.events.append(ev)

        if current_session.events:
            sessions.append(current_session)

    # Sort: highest severity first, then by event count
    sessions.sort(
        key=lambda s: (SEVERITY_ORDER.get(s.severity_max, 0), s.event_count),
        reverse=True,
    )
    return sessions


def get_primary_session(sessions: List[Session]) -> Optional[Session]:
    """Return the most suspicious session (first after sorting)."""
    return sessions[0] if sessions else None


def sessions_summary(sessions: List[Session]) -> Dict[str, Any]:
    """
    Return a compact summary of all sessions for use in the LLM prompt.
    """
    return {
        "total_sessions":   len(sessions),
        "total_events":     sum(s.event_count for s in sessions),
        "actors":           [s.actor for s in sessions],
        "sessions":         [s.to_dict() for s in sessions],
    }
