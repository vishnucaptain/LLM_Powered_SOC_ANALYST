"""
threat_intel.py
---------------
Simulated threat intelligence enrichment layer.

In a production system this would query:
  - VirusTotal, AbuseIPDB, Shodan, MISP, OpenCTI, etc.

Here we maintain a curated static database of:
  - Known malicious IP ranges (Tor exit nodes, common C2 infrastructure)
  - Suspicious port patterns
  - Known malware hashes (sample)
  - High-risk user-agent strings

Returns a ThreatIntelResult for each queried indicator.
"""

import ipaddress
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


# ── Static threat intelligence database ──────────────────────────────────────

# Known malicious CIDR blocks (Tor exit node ranges, bulletproof hosters, etc.)
_MALICIOUS_CIDRS = [
    "185.220.0.0/16",    # Tor project exit nodes
    "199.87.154.0/24",   # Known C2 infrastructure
    "91.108.4.0/24",     # Telegram-based C2 / spam
    "45.33.0.0/16",      # Linode ranges used in attacks
    "104.131.0.0/16",    # DigitalOcean ranges (common for C2)
    "45.142.0.0/16",     # Bulletproof hosting
    "194.165.0.0/16",    # Ransomware C2 range
    "62.182.0.0/16",     # Known threat actor infrastructure
    "89.248.0.0/16",     # Shodan honeypot traffic
    "80.82.0.0/16",      # Port scanning bots
]

_MALICIOUS_CIDR_OBJECTS = [ipaddress.ip_network(cidr) for cidr in _MALICIOUS_CIDRS]

# Known exact malicious IPs
_KNOWN_MALICIOUS_IPS: Dict[str, Dict[str, str]] = {
    "185.220.101.5":  {"category": "tor_exit_node",   "source": "TorProject",    "threat": "Anonymization / Brute Force"},
    "185.220.101.34": {"category": "tor_exit_node",   "source": "TorProject",    "threat": "Anonymization"},
    "91.108.4.1":     {"category": "c2_server",       "source": "ThreatFox",     "threat": "Malware C2"},
    "45.33.32.156":   {"category": "c2_server",       "source": "AlienVault OTX","threat": "Data Exfiltration Endpoint"},
    "192.168.0.0":    {"category": "internal",        "source": "RFC1918",       "threat": "Internal Host"},
    "10.0.0.0":       {"category": "internal",        "source": "RFC1918",       "threat": "Internal Host"},
}

# Known malware process hashes (SHA256 prefix for demo)
_KNOWN_MALWARE_HASHES: Dict[str, str] = {
    "d38e2f6b": "Mimikatz credential dumper",
    "4a5e1e4b": "CobaltStrike Beacon",
    "e3b0c442": "Known ransomware dropper",
    "acbd18db": "Metasploit Meterpreter",
}

# Suspicious command keywords found in process names / cmdlines
_SUSPICIOUS_COMMANDS = {
    "mimikatz":           ("credential_dumper", "high"),
    "cobalt strike":      ("post_exploitation",  "high"),
    "metasploit":         ("exploitation_framework", "high"),
    "meterpreter":        ("post_exploitation",  "high"),
    "invoke-mimikatz":    ("credential_dumper",  "high"),
    "psexec":             ("lateral_movement",   "medium"),
    "powersploit":        ("post_exploitation",  "high"),
    "empire":             ("c2_framework",        "high"),
    "vssadmin delete":    ("defense_evasion",    "high"),
    "net user /add":      ("persistence",         "medium"),
    "schtasks /create":   ("persistence",         "medium"),
    "reg add.*run":       ("persistence",         "medium"),
}


@dataclass
class IndicatorResult:
    """Threat intelligence result for a single indicator."""
    indicator: str
    indicator_type: str  # "ip", "hash", "command", "domain"
    is_malicious: bool
    threat_category: Optional[str]
    threat_description: Optional[str]
    confidence: float      # 0.0 – 1.0
    source: str
    risk_score: int        # 0–100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator":          self.indicator,
            "indicator_type":     self.indicator_type,
            "is_malicious":       self.is_malicious,
            "threat_category":    self.threat_category,
            "threat_description": self.threat_description,
            "confidence":         self.confidence,
            "source":             self.source,
            "risk_score":         self.risk_score,
        }


@dataclass
class ThreatIntelReport:
    """Aggregated threat intel report for a set of events."""
    indicators: List[IndicatorResult] = field(default_factory=list)

    @property
    def malicious_count(self) -> int:
        return sum(1 for i in self.indicators if i.is_malicious)

    @property
    def max_risk_score(self) -> int:
        if not self.indicators:
            return 0
        return max(i.risk_score for i in self.indicators)

    @property
    def overall_risk(self) -> str:
        score = self.max_risk_score
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "malicious_indicators": self.malicious_count,
            "total_indicators":     len(self.indicators),
            "max_risk_score":       self.max_risk_score,
            "overall_risk":         self.overall_risk,
            "indicators":           [i.to_dict() for i in self.indicators],
        }

    def summary_text(self) -> str:
        if not self.indicators:
            return "No threat intelligence data collected."
        malicious = [i for i in self.indicators if i.is_malicious]
        if not malicious:
            return "No malicious indicators detected in threat intelligence lookup."
        parts = [f"THREAT INTEL: {len(malicious)} malicious indicator(s) detected."]
        for ind in malicious[:5]:  # limit to top 5
            parts.append(
                f"  [{ind.indicator_type.upper()}] {ind.indicator} → "
                f"{ind.threat_description} (risk={ind.risk_score}/100, src={ind.source})"
            )
        return "\n".join(parts)


# ── Lookup functions ──────────────────────────────────────────────────────────

def _check_ip(ip_str: str) -> IndicatorResult:
    """Check an IP address against the intel database."""
    # Direct match
    if ip_str in _KNOWN_MALICIOUS_IPS:
        info = _KNOWN_MALICIOUS_IPS[ip_str]
        return IndicatorResult(
            indicator=ip_str,
            indicator_type="ip",
            is_malicious=True,
            threat_category=info["category"],
            threat_description=info["threat"],
            confidence=0.95,
            source=info["source"],
            risk_score=90,
        )

    # CIDR range check — skip private IP ranges
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            return IndicatorResult(
                indicator=ip_str,
                indicator_type="ip",
                is_malicious=False,
                threat_category="internal",
                threat_description="Private / internal network address",
                confidence=1.0,
                source="RFC1918",
                risk_score=0,
            )
        for cidr in _MALICIOUS_CIDR_OBJECTS:
            if ip_obj in cidr:
                return IndicatorResult(
                    indicator=ip_str,
                    indicator_type="ip",
                    is_malicious=True,
                    threat_category="malicious_range",
                    threat_description=f"IP in known malicious CIDR {cidr}",
                    confidence=0.8,
                    source="StaticIntelDB",
                    risk_score=75,
                )
    except ValueError:
        pass

    return IndicatorResult(
        indicator=ip_str,
        indicator_type="ip",
        is_malicious=False,
        threat_category=None,
        threat_description="No threat intelligence found",
        confidence=0.5,
        source="StaticIntelDB",
        risk_score=5,
    )


def _check_command(cmd: str) -> Optional[IndicatorResult]:
    """Check if a command string matches known malicious tools."""
    lower = cmd.lower()
    for keyword, (category, risk_str) in _SUSPICIOUS_COMMANDS.items():
        if keyword in lower:
            risk_score = 90 if risk_str == "high" else 55
            return IndicatorResult(
                indicator=keyword,
                indicator_type="command",
                is_malicious=True,
                threat_category=category,
                threat_description=f"Known malicious tool/command: {keyword}",
                confidence=0.85,
                source="StaticThreatDB",
                risk_score=risk_score,
            )
    return None


def _check_hash(hash_prefix: str) -> Optional[IndicatorResult]:
    """Check an 8-char hash prefix against known malware hashes."""
    key = hash_prefix[:8].lower()
    if key in _KNOWN_MALWARE_HASHES:
        return IndicatorResult(
            indicator=key,
            indicator_type="hash",
            is_malicious=True,
            threat_category="malware",
            threat_description=_KNOWN_MALWARE_HASHES[key],
            confidence=0.99,
            source="MalwareHashDB",
            risk_score=95,
        )
    return None


# ── Main enrichment function ──────────────────────────────────────────────────

def enrich_events(events: list) -> ThreatIntelReport:
    """
    Given a list of SecurityEvent objects, extract indicators
    and look them up in the threat intel database.

    Returns a ThreatIntelReport.
    """
    report = ThreatIntelReport()
    seen_indicators: set = set()

    for event in events:
        # Check source IPs
        for ip_attr in ("source_ip", "dest_ip"):
            ip = getattr(event, ip_attr, None)
            if ip and ip not in seen_indicators:
                seen_indicators.add(ip)
                report.indicators.append(_check_ip(ip))

        # Check raw text for command matches
        raw = getattr(event, "raw", "")
        cmd_result = _check_command(raw)
        if cmd_result and cmd_result.indicator not in seen_indicators:
            seen_indicators.add(cmd_result.indicator)
            report.indicators.append(cmd_result)

        # Check for hashes in raw (pattern: [hash: xxxxxxxx])
        import re
        hash_matches = re.findall(r"hash:\s*([0-9a-fA-F]{8,})", raw)
        for h in hash_matches:
            if h not in seen_indicators:
                seen_indicators.add(h)
                result = _check_hash(h)
                if result:
                    report.indicators.append(result)

    return report
