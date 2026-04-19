"""
parsers.py
----------
Structured JSON output parser for LLM responses.
Handles inconsistent LLM output and enforces strict schema.
"""

import json
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class SeverityLevel(str, Enum):
    """Valid severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentSchema:
    """
    Strict schema for incident reports.
    Ensures valid structure regardless of LLM output quality.
    """
    
    REQUIRED_FIELDS = {
        "attack_stage": str,
        "mitre_technique": list,
        "severity": str,
        "confidence": float,
        "explanation": str,
        "recommended_actions": list,
    }
    
    SEVERITY_LEVELS = {s.value for s in SeverityLevel}
    
    # T-code pattern: T1234 or T1234.001
    TCODE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')
    
    @staticmethod
    def validate_severity(severity: str) -> str:
        """Validate and normalize severity level."""
        if not severity:
            return "MEDIUM"
        
        severity_upper = severity.upper().strip()
        
        # Handle variations
        severity_map = {
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
            "INFO": "LOW",
            "WARNING": "MEDIUM",
            "ALERT": "HIGH",
            "EMERGENCY": "CRITICAL",
        }
        
        normalized = severity_map.get(severity_upper, "MEDIUM")
        logger.debug(f"Severity normalized: {severity} → {normalized}")
        return normalized
    
    @staticmethod
    def validate_confidence(confidence: Any) -> float:
        """
        Validate and normalize confidence to 0.0-1.0 float.
        Handles: percentages (65%), decimal (0.65), text ("65%"), etc.
        """
        if isinstance(confidence, float):
            return max(0.0, min(1.0, confidence))
        
        if isinstance(confidence, int):
            return max(0.0, min(1.0, confidence / 100.0))
        
        if isinstance(confidence, str):
            conf_str = confidence.strip().replace("%", "").replace("confidence", "").strip()
            
            try:
                # Try as percentage (0-100)
                val = float(conf_str)
                if val > 1.0:
                    val = val / 100.0  # Treat as percentage
                return max(0.0, min(1.0, val))
            except ValueError:
                logger.warning(f"Could not parse confidence: {confidence}")
                return 0.5  # Default to moderate confidence
        
        return 0.5  # Default fallback
    
    @staticmethod
    def validate_techniques(techniques: Any) -> List[str]:
        """
        Validate and extract MITRE T-codes from various formats.
        Handles: lists, strings, comma-separated, etc.
        """
        if not techniques:
            return []
        
        tcodes = []
        
        # If already a list
        if isinstance(techniques, list):
            for item in techniques:
                if isinstance(item, str):
                    # Extract T-codes from string
                    matches = IncidentSchema.TCODE_PATTERN.findall(item)
                    tcodes.extend(matches)
        
        # If string, parse it
        elif isinstance(techniques, str):
            # Remove common text around T-codes
            text = techniques.replace("Technique:", "").replace("MITRE:", "")
            matches = IncidentSchema.TCODE_PATTERN.findall(text)
            tcodes.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_tcodes = []
        for code in tcodes:
            if code not in seen:
                seen.add(code)
                unique_tcodes.append(code)
        
        logger.debug(f"Extracted {len(unique_tcodes)} unique T-codes")
        return unique_tcodes
    
    @staticmethod
    def validate_actions(actions: Any) -> List[str]:
        """
        Validate and extract recommended actions.
        Handles: lists, strings, bullet points, numbered lists, etc.
        """
        if not actions:
            return []
        
        result = []
        
        if isinstance(actions, list):
            for item in actions:
                if isinstance(item, str) and len(item.strip()) > 5:
                    # Clean up numbering/bullets
                    cleaned = re.sub(r'^[\d\.\)\-\*•\s]+', '', item.strip())
                    if cleaned:
                        result.append(cleaned)
        
        elif isinstance(actions, str):
            # Split by common delimiters
            lines = re.split(r'[\n;]', actions)
            for line in lines:
                # Remove numbering/bullets
                cleaned = re.sub(r'^[\d\.\)\-\*•\s]+', '', line.strip())
                if len(cleaned) > 5:
                    result.append(cleaned)
        
        # Limit to 10 actions
        result = result[:10]
        
        logger.debug(f"Extracted {len(result)} recommended actions")
        return result


class LLMResponseParser:
    """
    Main parser for LLM responses.
    Converts inconsistent output to valid incident schema.
    """
    
    def __init__(self):
        self.schema = IncidentSchema()
    
    def parse(self, llm_output: str, **defaults) -> Dict[str, Any]:
        """
        Parse LLM output and return valid incident report.
        
        Args:
            llm_output: Raw LLM text response
            **defaults: Default values for missing fields
        
        Returns:
            Valid incident report dict with all required fields
        """
        # Step 1: Try to extract JSON from response
        parsed_dict = self._extract_json(llm_output)
        
        # Step 2: Validate and normalize each field
        incident = self._normalize_fields(parsed_dict, defaults)
        
        # Step 3: Validate complete structure
        self._validate_structure(incident)
        
        logger.info(f"Parsed incident: severity={incident['severity']}, "
                   f"techniques={incident['mitre_technique']}, "
                   f"confidence={incident['confidence']:.2f}")
        
        return incident
    
    def _extract_json(self, text: str) -> Dict[str, Any]:
        """
        Extract JSON from LLM response.
        Handles: pure JSON, JSON in text, malformed JSON, etc.
        """
        if not text:
            return {}
        
        # Try 1: Parse as pure JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Try 2: Extract JSON block (enclosed in {} or [])
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        # Try 3: Extract key-value pairs using regex
        parsed = self._regex_parse(text)
        if parsed:
            return parsed
        
        logger.warning("Could not extract JSON from LLM output")
        return {}
    
    def _regex_parse(self, text: str) -> Dict[str, Any]:
        """
        Parse key-value pairs from text using regex.
        Fallback when JSON parsing fails.
        """
        result = {}
        
        # Parse attack_stage
        stage_match = re.search(
            r'attack[_\s]stage[:\s]+([^\n]+)',
            text, re.IGNORECASE
        )
        if stage_match:
            result['attack_stage'] = stage_match.group(1).strip().rstrip('.,')
        
        # Parse MITRE techniques (T-codes)
        tcodes = re.findall(r'T\d{4}(?:\.\d{3})?', text)
        if tcodes:
            result['mitre_technique'] = list(dict.fromkeys(tcodes))  # Deduplicate
        
        # Parse severity
        severity_match = re.search(
            r'severity[:\s]+([^\n]+)',
            text, re.IGNORECASE
        )
        if severity_match:
            result['severity'] = severity_match.group(1).strip().rstrip('.,')
        
        # Parse confidence
        confidence_match = re.search(
            r'confidence[:\s]+(\d+\.?\d*%?)',
            text, re.IGNORECASE
        )
        if confidence_match:
            result['confidence'] = confidence_match.group(1).strip()
        
        # Parse explanation (first substantial paragraph)
        explanation_match = re.search(
            r'explanation[:\s]+([^\n]+(?:\n[^\n]+)*?)(?=\n\n|\nrecommended|\n[A-Z]|$)',
            text, re.IGNORECASE | re.DOTALL
        )
        if explanation_match:
            result['explanation'] = explanation_match.group(1).strip()
        
        # Parse recommended actions (everything after "recommended" or "actions")
        actions_match = re.search(
            r'(?:recommended[_\s]?actions?|actions?)[:\s]*\n?(.+?)(?=\n\n|$)',
            text, re.IGNORECASE | re.DOTALL
        )
        if actions_match:
            actions_text = actions_match.group(1)
            result['recommended_actions'] = actions_text
        
        return result
    
    def _normalize_fields(self, parsed: Dict[str, Any], 
                         defaults: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize and validate each field in the incident report.
        """
        normalized = {}
        
        # attack_stage
        attack_stage = parsed.get('attack_stage') or defaults.get('attack_stage', 'Unknown')
        normalized['attack_stage'] = str(attack_stage).strip() if attack_stage else 'Unknown'
        
        # mitre_technique
        raw_techniques = parsed.get('mitre_technique', [])
        normalized['mitre_technique'] = self.schema.validate_techniques(raw_techniques)
        
        # severity
        raw_severity = parsed.get('severity', defaults.get('severity', 'MEDIUM'))
        normalized['severity'] = self.schema.validate_severity(raw_severity)
        
        # confidence
        raw_confidence = parsed.get('confidence', defaults.get('confidence', 0.5))
        normalized['confidence'] = self.schema.validate_confidence(raw_confidence)
        
        # explanation
        explanation = parsed.get('explanation', defaults.get('explanation', ''))
        if isinstance(explanation, (list, dict)):
            explanation = str(explanation)
        normalized['explanation'] = str(explanation).strip()[:2000]  # Max 2000 chars
        
        # recommended_actions
        raw_actions = parsed.get('recommended_actions', defaults.get('recommended_actions', []))
        normalized['recommended_actions'] = self.schema.validate_actions(raw_actions)
        
        return normalized
    
    def _validate_structure(self, incident: Dict[str, Any]) -> None:
        """
        Validate complete incident structure.
        Adds defaults for any missing critical fields.
        """
        # Ensure all required fields exist
        for field, field_type in self.schema.REQUIRED_FIELDS.items():
            if field not in incident:
                if field_type == str:
                    incident[field] = ''
                elif field_type == list:
                    incident[field] = []
                elif field_type == float:
                    incident[field] = 0.5
                elif field_type == dict:
                    incident[field] = {}
        
        # Validate types
        assert isinstance(incident['attack_stage'], str)
        assert isinstance(incident['mitre_technique'], list)
        assert isinstance(incident['severity'], str)
        assert isinstance(incident['confidence'], (int, float))
        assert isinstance(incident['explanation'], str)
        assert isinstance(incident['recommended_actions'], list)
        
        # Ensure confidence is in valid range
        if not (0.0 <= incident['confidence'] <= 1.0):
            incident['confidence'] = max(0.0, min(1.0, incident['confidence']))
        
        # Ensure severity is valid
        if incident['severity'] not in self.schema.SEVERITY_LEVELS:
            incident['severity'] = 'MEDIUM'
        
        # Ensure at least one explanation or action
        if not incident['explanation'] and not incident['recommended_actions']:
            incident['explanation'] = 'Incident detected with limited contextual information.'
    
    def to_json(self, incident: Dict[str, Any]) -> str:
        """Convert incident to valid JSON string."""
        return json.dumps(incident, indent=2, default=str)


def parse_llm_response(llm_output: str, **defaults) -> Tuple[Dict[str, Any], str]:
    """
    Convenience function to parse LLM response.
    
    Args:
        llm_output: Raw LLM text response
        **defaults: Default values for missing fields
    
    Returns:
        Tuple of (incident_dict, json_string)
    """
    parser = LLMResponseParser()
    incident = parser.parse(llm_output, **defaults)
    json_str = parser.to_json(incident)
    return incident, json_str
