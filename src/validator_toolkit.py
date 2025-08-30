from typing import Dict, Any, List
import sys
from .validators import (
    XSSValidator,
    OpenRedirectValidator, 
    SQLInjectionValidator,
    RCEValidator,
    SSRFValidator
)


class VulnerabilityValidatorToolkit:
    """
    Main toolkit class that orchestrates all vulnerability validators.
    Provides a unified interface for validating different vulnerability types.
    """
    
    def __init__(self):
        self.validators = {
            'xss': XSSValidator(),
            'open_redirect': OpenRedirectValidator(),
            'sql_injection': SQLInjectionValidator(),
            'rce': RCEValidator(),
            'ssrf': SSRFValidator(),
        }

    def print_result(self, result: Dict[str, Any], compact: bool = False) -> None:
        """Print validation result in a structured, colored format."""
        if compact:
            # One-line compact format
            status = "VALID" if result['is_valid'] else "FALSE POSITIVE"
            evidence_str = " | ".join(result['evidence']) if result['evidence'] else "No evidence"
            
            confidence_val = result['confidence']
            print(f"{status} | "
                  f"Confidence: {confidence_val:.2f} | "
                  f"Evidence: {evidence_str} | "
                  f"Reasoning: {result['reasoning']}")
        else:
            # Multi-line structured format
            confidence_val = result['confidence']
            evidence_list = result['evidence']
            evidence_count = len(evidence_list)
            
            status = "VALID VULNERABILITY" if result['is_valid'] else "FALSE POSITIVE"
            confidence_str = f"{confidence_val:.2f}"
            reasoning = result['reasoning']
            
            print(f"\n{'=' * 60}")
            print(f"VALIDATION RESULT")
            print(f"{'=' * 60}")
            print(f"Status:     {status}")
            print(f"Type:       {result['validator_type']}")
            print(f"\nEvidences:")
            
            if evidence_list:
                for i, evidence in enumerate(evidence_list, 1):
                    print(f"  {i}. {evidence}")
            else:
                print(f"  No evidence found")
            
            print(f"\nReasoning:  {reasoning}")
            print(f"{'=' * 60}\n")
    
    def print_compact(self, result: Dict[str, Any]) -> None:
        """Print validation result in compact one-line format."""
        self.print_result(result, compact=True)
    
    def validate_finding(self, vulnerability_type: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a security finding using the appropriate validator.
        
        Args:
            vulnerability_type: Type of vulnerability ('xss', 'sql_injection', etc.)
            finding: Dictionary containing vulnerability details
            
        Returns:
            Dictionary with validation results
        """
        vuln_type = vulnerability_type.lower()
        
        if vuln_type not in self.validators:
            return {
                'is_valid': False,
                'confidence': 0.0,
                'evidence': [],
                'reasoning': f"Unknown vulnerability type: {vulnerability_type}",
                'validator_type': 'Unknown'
            }
        
        validator = self.validators[vuln_type]
        return validator.validate(finding)
    
    def validate_multiple(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate multiple findings.
        
        Args:
            findings: List of findings, each with 'type' and finding details
            
        Returns:
            List of validation results
        """
        results = []
        
        for finding in findings:
            vuln_type = finding.get('type', '')
            if vuln_type:
                # Remove type from finding dict before validation
                finding_data = {k: v for k, v in finding.items() if k != 'type'}
                result = self.validate_finding(vuln_type, finding_data)
                result['original_type'] = vuln_type
                results.append(result)
        
        return results
    
    def get_supported_types(self) -> List[str]:
        """Get list of supported vulnerability types."""
        return list(self.validators.keys())
    
    def generate_summary_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary report from validation results.
        
        Args:
            results: List of validation results
            
        Returns:
            Summary statistics and analysis
        """
        total_findings = len(results)
        valid_findings = len([r for r in results if r['is_valid']])
        false_positives = total_findings - valid_findings
        
        # Calculate average confidence
        avg_confidence = sum(r['confidence'] for r in results) / total_findings if total_findings > 0 else 0
        
        # Group by vulnerability type
        type_breakdown = {}
        for result in results:
            vuln_type = result.get('validator_type', 'Unknown')
            if vuln_type not in type_breakdown:
                type_breakdown[vuln_type] = {'total': 0, 'valid': 0}
            type_breakdown[vuln_type]['total'] += 1
            if result['is_valid']:
                type_breakdown[vuln_type]['valid'] += 1
        
        return {
            'summary': {
                'total_findings': total_findings,
                'valid_vulnerabilities': valid_findings,
                'false_positives': false_positives,
                'accuracy_rate': (valid_findings / total_findings) * 100 if total_findings > 0 else 0,
                'average_confidence': avg_confidence
            },
            'by_type': type_breakdown,
            'high_confidence_findings': [r for r in results if r['confidence'] >= 0.8 and r['is_valid']],
            'low_confidence_findings': [r for r in results if r['confidence'] < 0.5]
        }