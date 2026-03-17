"""
event_extractor.py
------------------
Converts normalized log entries into typed SecurityEvent objects.

Event Types:
  LOGIN            — successful / failed authentication
  PRIV_ESC         — privilege escalation (sudo, SYSTEM, runas)
  SUSPICIOUS_EXEC  — suspicious process execution (PowerShell, curl, mimikatz…)
  OUTBOUND_CONN    — outbound network connections / data transfers
  FILE_ACCESS      — file read/write/delete on sensitive paths
  RECON            — reconnaissance activity (port scanning, enumeration)
  LATERAL_MOVE     — lateral movement (psexec, pass-the-hash, wmi)
  DEFENSE_EVADE    — defense evasion (shadow copy delete, av kill, log clear)
  EXFILTRATION     — data exfiltration indicators
  NORMAL           — benign / unclassified event
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

# ── Event type constants ──────────────────────────────────────────────────────
LOGIN           = "LOGIN"
PRIV_ESC        = "PRIV_ESC"
SUSPICIOUS_EXEC = "SUSPICIOUS_EXEC"
OUTBOUND_CONN   = "OUTBOUND_CONN"
FILE_ACCESS     = "FILE_ACCESS"
RECON           = "RECON"
LATERAL_MOVE    = "LATERAL_MOVE"
DEFENSE_EVADE   = "DEFENSE_EVADE"
EXFILTRATION    = "EXFILTRATION"
NORMAL          = "NORMAL"

# Integer encoding for LSTM input
EVENT_TYPE_MAP: Dict[str, int] = {
    NORMAL:          0,
    LOGIN:           1,
    FILE_ACCESS:     2,
    OUTBOUND_CONN:   3,
    RECON:           4,
    PRIV_ESC:        5,
    SUSPICIOUS_EXEC: 6,
    LATERAL_MOVE:    7,
    DEFENSE_EVADE:   8,
    EXFILTRATION:    9,
}
NUM_EVENT_TYPES = len(EVENT_TYPE_MAP)


@dataclass
class SecurityEvent:
    """A single typed security event extracted from a normalized log."""
    event_type: str
    event_code: int
    source_ip: Optional[str]
    dest_ip: Optional[str]
    user: Optional[str]
    hostname: Optional[str]
    timestamp: Optional[str]
    severity: str
    description: str
    raw: str
    mitre_hint: Optional[str] = None  # ATT&CK technique hint for RAG query

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type":  self.event_type,
            "event_code":  self.event_code,
            "source_ip":   self.source_ip,
            "dest_ip":     self.dest_ip,
            "user":        self.user,
            "hostname":    self.hostname,
            "timestamp":   self.timestamp,
            "severity":    self.severity,
            "description": self.description,
            "mitre_hint":  self.mitre_hint,
        }


# ── Classification rules ──────────────────────────────────────────────────────
# Each rule: (event_type, [regex_patterns], mitre_hint)
_RULES = [
    # Defense Evasion — check before SuspiciousExec
    (DEFENSE_EVADE, [
        r"shadow copy|vssadmin.*delete|vssadmin delete",
        r"event.*log.*clear|clear-eventlog|wevtutil.*cl",
        r"disable.*antivirus|av kill|taskkill.*defender",
        r"bcdedit.*recoveryenabled|bcdedit.*safeboot",
        r"set-mppreference.*-disablerealtimemonitoring",
        r"backup.*service.*stop|veeam.*terminat",
        r"readme_decrypt|\.locked\b|ransom",
    ], "T1562 Impair Defenses"),

    # Privilege Escalation
    (PRIV_ESC, [
        r"\bsudo\b",
        r"\bsu -\b|\bsu\s+root\b",
        r"runas\b.*\/user:.*administrator",
        r"spawned.*system|launched.*system|cmd.*system",
        r"privilege.*escalat|escalat.*privilege",
        r"token.*impersonat",
        r"uac bypass|eventvwr.*bypass",
        r"named pipe.*impersonat",
    ], "T1548 Abuse Elevation Control Mechanism"),

    # Lateral Movement
    (LATERAL_MOVE, [
        r"psexec|paexec",
        r"wmiexec|wmic.*process.*call",
        r"net use.*\\\\|net use.*admin\$",
        r"pass-the-hash|pth attempt",
        r"pass-the-ticket|golden ticket",
        r"dcsync|ntds\.dit",
        r"smb.*lateral|lateral.*smb",
        r"rdp.*session.*opened|mstsc",
    ], "T1021 Remote Services"),

    # Exfiltration
    (EXFILTRATION, [
        r"exfil|data.*transfer.*gb|transfer.*large",
        r"dns.*tunnel|dns.*query.*storm|base64.*dns",
        r"dlp alert|pii.*outbound",
        r"archive.*upload|7zip.*upload|compress.*upload",
    ], "T1041 Exfiltration Over C2 Channel"),

    # Suspicious Execution
    (SUSPICIOUS_EXEC, [
        r"mimikatz|lsass.*access",
        r"powershell.*download|invoke-expression|iex\(",
        r"powershell.*-enc|\bpwsh\b.*-e\b",
        r"macro execution|winword.*powershell|excel.*powershell",
        r"mshta|regsvr32|rundll32.*javascript",
        r"certutil.*-decode|certutil.*-urlcache",
        r"bitsadmin.*transfer",
        r"c2 beacon|reverse shell|bind shell",
        r"dropper|payload.*download",
        r"inject|shellcode",
    ], "T1059 Command and Scripting Interpreter"),

    # Reconnaissance
    (RECON, [
        r"nmap|masscan|port scan",
        r"enumerat|ldap.*search|net view|net user /domain",
        r"ping sweep|arp scan|host discovery",
        r"whoami|id\b.*uid|ifconfig|ipconfig",
        r"netstat|netsh",
    ], "T1018 Remote System Discovery"),

    # Outbound Connections
    (OUTBOUND_CONN, [
        r"outbound.*traffic|traffic.*spike",
        r"establish.*connection.*:(?:443|80|8080|4444|6666)",
        r"large.*transfer|upload.*https",
        r"\bdns query\b",
        r"connection established",
        r"wget|curl.*http",
    ], "T1071 Application Layer Protocol"),

    # File Access
    (FILE_ACCESS, [
        r"file rename|renamed.*\.\w+",
        r"open|read|write.*(?:/var|/etc|/home|C:\\Users|C:\\Windows)",
        r"file.*access|access.*file",
        r"chmod|chown",
        r"registry.*write|reg.*add|regedit",
    ], "T1005 Data from Local System"),

    # Login (last — most permissive)
    (LOGIN, [
        r"failed password|authentication fail|login fail",
        r"invalid user|invalid password",
        r"accepted password|session opened|successful.*login|logon.*success",
        r"authenticated.*via|authenticate.*to\b",
        r"pam_unix.*session",
    ], "T1110 Brute Force"),
]


def classify_event(log: Dict[str, Any]) -> SecurityEvent:
    """
    Given a normalized log dict, classify it into a SecurityEvent.
    Rules are evaluated in priority order; first match wins.
    """
    raw = log.get("raw", "")
    lower_raw = raw.lower()

    matched_type = NORMAL
    matched_mitre = None

    for (event_type, patterns, mitre_hint) in _RULES:
        for pat in patterns:
            if re.search(pat, lower_raw):
                matched_type = event_type
                matched_mitre = mitre_hint
                break
        if matched_type != NORMAL:
            break

    # Build human-readable description
    description = _build_description(matched_type, log)

    return SecurityEvent(
        event_type=matched_type,
        event_code=EVENT_TYPE_MAP.get(matched_type, 0),
        source_ip=log.get("source_ip"),
        dest_ip=log.get("dest_ip"),
        user=log.get("user"),
        hostname=log.get("hostname"),
        timestamp=log.get("timestamp"),
        severity=log.get("severity", "low"),
        description=description,
        raw=raw,
        mitre_hint=matched_mitre,
    )


def _build_description(event_type: str, log: Dict[str, Any]) -> str:
    parts = [event_type]
    if log.get("user"):
        parts.append(f"by {log['user']}")
    if log.get("source_ip"):
        parts.append(f"from {log['source_ip']}")
    if log.get("dest_ip"):
        parts.append(f"to {log['dest_ip']}")
    if log.get("target"):
        parts.append(f"on {log['target']}")
    return " ".join(parts)


def extract_events(normalized_logs: List[Dict[str, Any]]) -> List[SecurityEvent]:
    """
    Extract SecurityEvent objects from a list of normalized log dicts.
    Returns events sorted by timestamp (best-effort).
    """
    events = [classify_event(log) for log in normalized_logs]
    return events


def events_to_sequence(events: List[SecurityEvent]) -> List[int]:
    """Convert a list of SecurityEvents to an integer sequence for LSTM input."""
    return [e.event_code for e in events]


def get_mitre_query(events: List[SecurityEvent]) -> str:
    """
    Build a compound search query from event MITRE hints
    for RAG retrieval against the MITRE ATT&CK vector DB.
    """
    hints = list({e.mitre_hint for e in events if e.mitre_hint})
    if not hints:
        # Fall back to raw text of high-severity events
        high = [e.raw for e in events if e.severity == "high"]
        return " ".join(high[:3]) if high else "suspicious activity"
    return " | ".join(hints)
