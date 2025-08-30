import re
from abc import ABC, abstractmethod
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs


class BaseValidator(ABC):
    """
    Abstract base class for all vulnerability validators.
    Provides common functionality and enforces interface consistency.
    """
    
    def __init__(self):
        pass
        
    @abstractmethod
    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a security finding.
        
        Args:
            finding: Dictionary containing vulnerability details
            
        Returns:
            Dictionary with validation results including:
            - is_valid: bool
            - type of the vulnerability
            - evidence: list of evidence items
            - reasoning: str explaining the decision
        """
        pass
    
    def _extract_url_components(self, url: str) -> Dict[str, Any]:
        """Extract and parse URL components for analysis."""
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'query_params': parse_qs(parsed.query)
        }
    
    def _contains_patterns(self, text: str, patterns: List[str]) -> List[str]:
        """Check if text contains any of the given patterns."""
        found = []
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                found.append(pattern)
        return found
    
    def _calculate_confidence(self, evidence_count: int, max_evidence: int = 5) -> float:
        """Calculate confidence score based on evidence strength."""
        return min(evidence_count / max_evidence, 1.0)