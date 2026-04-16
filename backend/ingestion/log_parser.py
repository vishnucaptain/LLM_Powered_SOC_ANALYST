"""
log_parser.py
-------------
Entry point for the ingestion layer.
It takes a raw string input, parses it by format (Syslog, JSON Arrays, JSON Lines),
and hands it off to the normalizer.
"""

import json
from typing import List, Dict, Any

def detect_and_parse_logs(raw_input: str) -> List[Dict[str, Any]]:
    """
    Parses a raw log string into a list of dictionaries/strings ready for normalization.
    Auto-detects:
      - JSON Array
      - JSON Lines
      - Raw text/syslog
    """
    stripped = raw_input.strip()
    if not stripped:
        return []

    parsed_logs = []

    # Try parsing as JSON Array
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            objects = json.loads(stripped)
            for obj in objects:
                parsed_logs.append(obj)
            return parsed_logs
        except json.JSONDecodeError:
            pass  # Fall through to line-by-line

    # Try line-by-line (JSON Lines or raw text)
    lines = stripped.splitlines()
    for line in lines:
        lineStr = line.strip()
        if not lineStr:
            continue
        if lineStr.startswith("{") and lineStr.endswith("}"):
            try:
                obj = json.loads(lineStr)
                parsed_logs.append(obj)
                continue
            except json.JSONDecodeError:
                pass
        
        # If not JSON, append as raw string
        parsed_logs.append(lineStr)

    return parsed_logs
