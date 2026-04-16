"""
log_normalizer.py
-----------------
Converts heterogeneous security logs (raw text, syslog, JSON/osquery)
into a unified normalized schema for downstream event extraction.

Unified Schema per log entry:
{
    "timestamp":  str  (ISO-8601 or original string, best-effort),
    "source_ip":  str  (None if not found),
    "dest_ip":    str  (None if not found),
    "user":       str  (None if not found),
    "hostname":   str  (None if not found),
    "action":     str  (lower-case verb describing what happened),
    "target":     str  (file path, port, service, etc. – None if not found),
    "severity":   str  ("low" | "medium" | "high"),
    "raw":        str  (original log line)
}
"""

import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime


# ── Timestamp patterns ────────────────────────────────────────────────────────
_TS_PATTERNS = [
    # 2024-01-15 03:22:11
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
    # Jan 15 03:22:11
    r"[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    # 15/Jan/2024:03:22:11 +0000
    r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}",
]

# ── IP address ────────────────────────────────────────────────────────────────
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# ── Common username extraction ────────────────────────────────────────────────
_USER_RE = re.compile(
    r"(?:user|for|by|account)\s+([a-zA-Z0-9_\-\.]+)", re.IGNORECASE
)

# ── File / path extraction ────────────────────────────────────────────────────
_PATH_RE = re.compile(r"(/[^\s]+|[A-Za-z]:\\[^\s]+)")

# ── Severity keyword mapping ──────────────────────────────────────────────────
_HIGH_KEYWORDS = {
    "failed password", "authentication failure", "brute force",
    "mimikatz", "pass-the-hash", "ransomware", "shadow copy",
    "privilege escalation", "malware", "exploit", "backdoor",
    "exfiltration", "c2 beacon", "reverse shell", "dropper",
    "dll injection", "credential dump", "lsass",
}
_MEDIUM_KEYWORDS = {
    "sudo", "su -", "psexec", "net use", "powershell", "wget", "curl",
    "suspicious", "unusual", "anomaly", "unauthorized",
    "port scan", "nmap", "recon", "enumeration",
}


def _extract_timestamp(line: str) -> Optional[str]:
    """Try to extract a timestamp from the beginning of a log line."""
    for pattern in _TS_PATTERNS:
        m = re.search(pattern, line[:40])
        if m:
            return m.group(0)
    return None


def _extract_ips(line: str) -> List[str]:
    return _IP_RE.findall(line)


def _extract_user(line: str) -> Optional[str]:
    m = _USER_RE.search(line)
    return m.group(1) if m else None


def _extract_path(line: str) -> Optional[str]:
    m = _PATH_RE.search(line)
    return m.group(0) if m else None


def _classify_severity(line: str) -> str:
    lower = line.lower()
    if any(kw in lower for kw in _HIGH_KEYWORDS):
        return "high"
    if any(kw in lower for kw in _MEDIUM_KEYWORDS):
        return "medium"
    return "low"


def _extract_action(line: str) -> str:
    """
    Pull a short action verb phrase from common log patterns.
    Falls back to 'unknown_action'.
    """
    patterns = [
        (r"failed password", "failed_login"),
        (r"accepted password|session opened", "successful_login"),
        (r"authentication failure", "auth_failure"),
        (r"sudo:", "sudo_execution"),
        (r"psexec|ps exec", "remote_exec"),
        (r"net use", "share_mount"),
        (r"mimikatz|lsass", "credential_dump"),
        (r"pass-the-hash|pth", "pass_the_hash"),
        (r"shadow copy|vssadmin", "shadow_copy_delete"),
        (r"powershell|pwsh", "powershell_exec"),
        (r"wget|curl|invoke-webrequest", "download"),
        (r"c2 beacon|reverse shell", "c2_connection"),
        (r"file rename|\.locked", "file_encryption"),
        (r"outbound|upload|exfil", "data_exfiltration"),
        (r"dns query|dns storm", "dns_request"),
        (r"port 443|https", "https_connection"),
        (r"exec|execve", "process_exec"),
        (r"read|open|write", "file_access"),
        (r"login|logon|authenticate", "login_attempt"),
        (r"connect|establish", "connection"),
    ]
    lower = line.lower()
    for pattern, label in patterns:
        if re.search(pattern, lower):
            return label
    return "unknown_action"


def normalize_text_log(raw: str) -> Dict[str, Any]:
    """Normalize a single raw text log line into the unified schema."""
    ips = _extract_ips(raw)
    source_ip = ips[0] if ips else None
    dest_ip = ips[1] if len(ips) > 1 else None

    return {
        "timestamp": _extract_timestamp(raw),
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "user": _extract_user(raw),
        "hostname": None,
        "action": _extract_action(raw),
        "target": _extract_path(raw),
        "severity": _classify_severity(raw),
        "raw": raw.strip(),
    }


def normalize_json_log(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize an osquery-style or structured JSON log object.
    Common keys: name, hostIdentifier, calendarTime, columns.*
    """
    cols = obj.get("columns", obj)  # osquery wraps fields under "columns"
    raw = json.dumps(obj)

    timestamp = (
        obj.get("calendarTime")
        or obj.get("timestamp")
        or obj.get("time")
        or cols.get("time")
    )
    source_ip = cols.get("remote_address") or cols.get("source_ip") or cols.get("src")
    dest_ip = cols.get("local_address") or cols.get("dest_ip") or cols.get("dst")
    user = cols.get("username") or cols.get("user") or obj.get("user")
    hostname = obj.get("hostIdentifier") or obj.get("hostname") or cols.get("host")
    action = cols.get("cmdline") or cols.get("action") or obj.get("name", "unknown")
    target = cols.get("path") or cols.get("remote_port") or cols.get("pid")
    severity = _classify_severity(raw)

    return {
        "timestamp": str(timestamp) if timestamp else None,
        "source_ip": str(source_ip) if source_ip else None,
        "dest_ip": str(dest_ip) if dest_ip else None,
        "user": str(user) if user else None,
        "hostname": str(hostname) if hostname else None,
        "action": str(action) if action else "unknown_action",
        "target": str(target) if target else None,
        "severity": severity,
        "raw": raw,
    }


def normalize_logs(raw_input: str) -> List[Dict[str, Any]]:
    """
    Main entry point. Uses the new log_parser to determine formats,
    then routes to the correct normalization method.
    """
    from backend.ingestion.log_parser import detect_and_parse_logs
    
    normalized = []
    parsed_items = detect_and_parse_logs(raw_input)
    
    for item in parsed_items:
        if isinstance(item, dict):
            normalized.append(normalize_json_log(item))
        elif isinstance(item, str):
            normalized.append(normalize_text_log(item))
            
    return normalized
