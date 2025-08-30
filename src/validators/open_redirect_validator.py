import re
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs, unquote
from .base_validator import BaseValidator


class OpenRedirectValidator(BaseValidator):
    """
    Validator for Open Redirect vulnerabilities.
    
    Validates open redirect findings by:
    1. Checking for bypass techniques
    2. Validating redirect parameter manipulation
    3. Analyzing HTTP response codes and headers
    """
    
    def __init__(self):
        super().__init__()
        
        # Common redirect parameters
        self.redirect_params = [
            'redirect', 'url', 'return', 'returnUrl', 'return_url',
            'next', 'continue', 'goto', 'target', 'destination',
            'forward', 'callback', 'callbackUrl', 'redirect_uri'
        ]
        
        # External domains for testing
        # Removed test_domains to avoid bias - any external domain redirect is potentially vulnerable
    
    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate open redirect finding.
        
        Expected finding format:
        {
            'url': str,
            'parameter': str,
            'payload': str (target redirect URL),
            'response_headers': dict (optional),
            'status_code': int,
            'response_body': str
        }
        """
        url = finding.get('url', '')
        parameter = finding.get('parameter', '')
        payload = finding.get('payload', '')
        response_headers = finding.get('response_headers', {})
        status_code = finding.get('status_code', 0)
        response_body = finding.get('response_body', '')
        
        evidence = []
    
        # Check if this is a same-domain redirect (not a vulnerability)
        if url and payload:
            original_domain = self._extract_domain_from_url(url)
            payload_domain = self._extract_domain_from_payload(unquote(payload))
            
            if original_domain and payload_domain and original_domain == payload_domain:
                return {
                    'is_valid': False,
                    'confidence': 0.1,
                    'evidence': ["Same-domain redirect detected"],
                    'reasoning': "Redirect occurs but targets the same domain - this is not an open redirect vulnerability as it cannot redirect users to external sites",
                    'validator_type': 'Open Redirect'
                }
        
        # Validate redirect parameter
        param_evidence = self._validate_redirect_parameter(parameter)
        evidence.extend(param_evidence)
        
        # Analyze payload structure
        payload_evidence = self._analyze_redirect_payload(payload, url)
        evidence.extend(payload_evidence)
        
        # Analyze response headers
        if response_headers or status_code:
            header_evidence = self._analyze_redirect_response(response_headers, status_code)
            evidence.extend(header_evidence)
        
        # Check for meta refresh redirects in response body
        if response_body and self._check_meta_refresh(response_body, payload):
            evidence.append("Meta refresh redirect detected")
        
        # Check for JavaScript redirects in response body
        js_redirect_detected = False
        if response_body and self._check_js_redirect(response_body, payload):
            evidence.append("JavaScript redirect detected")
            js_redirect_detected = True
        
        # If status code is 200 and no meta refresh or JS redirects, it's not a redirect
        if status_code == 200 and response_body:
            meta_refresh_detected = self._check_meta_refresh(response_body, payload)
            if not meta_refresh_detected and not js_redirect_detected:
                return {
                    'is_valid': False,
                    'confidence': 0.1,
                    'evidence': ["Status code 200 with no redirect mechanism detected"],
                    'reasoning': "No redirect detected - status code 200 indicates normal response without any redirect mechanism (HTTP redirect, meta refresh, or JavaScript redirect)",
                    'validator_type': 'Open Redirect'
                }
        
        confidence = self._calculate_confidence(len(evidence), max_evidence=5)
        
        # Additional validation: if we have response headers, check if Location matches payload
        if response_headers and status_code in [301, 302, 303, 307, 308]:
            location = response_headers.get('Location', response_headers.get('location', ''))
            if location:
                # Check if Location header is a same-domain path (starts with single /)
                if location.startswith('/') and not location.startswith('//'):
                    return {
                        'is_valid': False,
                        'confidence': 0.1,
                        'evidence': ["Redirect to same-domain path detected"],
                        'reasoning': "Redirect occurs but targets a path on the same domain - this is not an open redirect vulnerability as it cannot redirect users to external sites",
                        'validator_type': 'Open Redirect'
                    }
                
                decoded_payload = unquote(payload)
                
                # Check for exact match
                if payload == location or decoded_payload == location:
                    # Exact match - this is definitely valid
                    pass
                else:
                    # Check if the domain from payload appears in location
                    payload_domain = self._extract_domain_from_payload(decoded_payload)
                    if payload_domain and payload_domain in location:
                        # Domain match - this is valid
                        pass
                    else:
                        # Redirect happened but not to our payload - likely filtered/blocked
                        confidence = max(0.2, confidence * 0.3)  # Drastically reduce confidence
                        evidence.append("Redirect occurred but target does not match payload - likely blocked")
        
        # Special handling for non-redirect parameters
        non_redirect_params = ['query', 'search', 'q', 'term', 'search_query']
        if parameter and parameter.lower() in non_redirect_params:
            # For non-redirect parameters, always false positive
            return {
                'is_valid': False,
                'confidence': 0.2,  # Low confidence for non-redirect parameters
                'evidence': evidence,
                'reasoning': f"Parameter '{parameter}' is not typically used for redirects",
                'validator_type': 'Open Redirect'
            }
        else:
            # Normal redirect validation
            is_valid = confidence >= 0.6 and len(evidence) >= 2
        
        return {
            'is_valid': is_valid,
            'confidence': confidence,
            'evidence': evidence,
            'reasoning': self._generate_reasoning(evidence, is_valid),
            'validator_type': 'Open Redirect'
        }
    
    def _validate_redirect_parameter(self, parameter: str) -> List[str]:
        """Validate if parameter name suggests redirect functionality."""
        evidence = []
        
        non_redirect_params = ['query', 'search', 'q', 'term', 'search_query']
        if parameter and parameter.lower() in non_redirect_params:
            return evidence
        
        if parameter.lower() in [p.lower() for p in self.redirect_params]:
            evidence.append(f"Parameter '{parameter}' is commonly used for redirects")
        else:
            # Only check patterns if not already found in exact list
            redirect_patterns = [
                r'redirect', r'return', r'next', r'goto', r'forward',
                r'callback', r'continue', r'target', r'destination'
            ]
            
            if any(re.search(pattern, parameter, re.IGNORECASE) for pattern in redirect_patterns):
                evidence.append(f"Parameter '{parameter}' follows redirect naming convention")
            
        return evidence
    
    def _analyze_redirect_payload(self, payload: str, original_url: str = '') -> List[str]:
        """Analyze redirect payload for malicious indicators."""
        evidence = []
        decoded_payload = unquote(payload)
        
        # Get original domain for comparison
        original_domain = self._extract_domain_from_url(original_url) if original_url else ''
        
        # Check for protocol-relative URLs (//domain.com)
        if decoded_payload.startswith('//'):
            evidence.append("Protocol-relative URL bypass technique detected")
            # Extract domain from protocol-relative URL
            try:
                domain = decoded_payload[2:].split('/')[0].split('?')[0].split('#')[0]
                if domain and original_domain and domain != original_domain:
                    evidence.append(f"Protocol-relative URL redirects to external domain: {domain}")
            except:
                pass
        
        # Check for single slash bypass (http:/domain.com instead of http://domain.com)
        if re.match(r'^https?:/[^/]', decoded_payload):
            evidence.append("Single slash bypass technique detected")
            # Extract domain from single slash URL
            try:
                # Remove protocol and single slash to get domain
                domain_part = re.sub(r'^https?:/', '', decoded_payload)
                domain = domain_part.split('/')[0].split('?')[0].split('#')[0]
                if domain and original_domain and domain != original_domain:
                    evidence.append(f"Single slash bypass redirects to external domain: {domain}")
            except:
                pass
        
        # Check if payload is an external URL
        try:
            parsed = urlparse(decoded_payload)
            if parsed.scheme and parsed.netloc:
                # Only add evidence if it's actually external
                if not original_domain or parsed.netloc != original_domain:
                    evidence.append("Payload contains external URL")
                    
                    # Check for protocol schemes
                    if parsed.scheme in ['http', 'https']:
                        evidence.append("Valid HTTP/HTTPS redirect URL detected")
                
                if parsed.scheme in ['javascript', 'data', 'vbscript']:
                    evidence.append("Dangerous protocol scheme detected")
        except:
            # If URL parsing fails but it's a protocol-relative URL, still check domain
            if decoded_payload.startswith('//'):
                try:
                    domain = decoded_payload[2:].split('/')[0].split('?')[0].split('#')[0]
                    if domain and original_domain and domain != original_domain:
                        evidence.append(f"External domain detected in protocol-relative URL: {domain}")
                except:
                    pass
        
        # Check for bypass techniques
        bypass_evidence = self._check_bypass_techniques(decoded_payload)
        evidence.extend(bypass_evidence)
        
        return evidence
    
    def _analyze_redirect_response(self, headers: Dict, status_code: int) -> List[str]:
        """Analyze HTTP response for redirect indicators."""
        evidence = []
        
        # Check status code
        if status_code in [301, 302, 303, 307, 308]:
            evidence.append(f"Redirect status code {status_code} indicates successful redirect")
        
        # Check Location header
        location = headers.get('Location', headers.get('location', ''))
        if location:
            # Check if Location header contains protocol-relative URL
            if location.startswith('//'):
                evidence.append("Location header contains protocol-relative URL")
                # Extract domain from protocol-relative URL
                try:
                    domain = location[2:].split('/')[0].split('?')[0].split('#')[0]
                    if domain:
                        evidence.append(f"Location header redirects to external domain: {domain}")
                except:
                    pass
            else:
                # Check if it's an external URL
                try:
                    parsed = urlparse(location)
                    if parsed.netloc:
                        evidence.append("Location header contains external URL")
                except:
                    pass
        
        return evidence
    
    def _check_bypass_techniques(self, payload: str) -> List[str]:
        """Check for common redirect bypass techniques."""
        evidence = []
        
        # Check for protocol bypass
        bypass_patterns = [
            r'\\\\',    # Backslash bypass
            r'@',       # @ symbol bypass
            r'\?',      # Question mark bypass
            r'#',       # Fragment bypass
        ]
        
        for pattern in bypass_patterns:
            if re.search(pattern, payload):
                evidence.append(f"Redirect bypass technique detected: {pattern}")
        
        # Check for encoding bypass
        if re.search(r'%2F%2F', payload):  # //
            evidence.append("URL encoding bypass detected")
        
        return evidence
    
    def _check_meta_refresh(self, response_body: str, payload: str) -> bool:
        """Check for meta refresh redirects."""
        meta_pattern = r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=[^>]*>'
        matches = re.findall(meta_pattern, response_body, re.IGNORECASE)
        
        for match in matches:
            if payload in match or unquote(payload) in match:
                return True
        
        
        if 'meta http-equiv="refresh"' in response_body and payload in response_body:
            return True
        
        return False
    
    def _check_js_redirect(self, response_body: str, payload: str) -> bool:
        """Check for JavaScript-based redirects."""
        js_redirect_patterns = [
            r'window\.location\s*=',
            r'window\.location\.href\s*=',
            r'document\.location\s*=',
            r'location\.replace\s*\(',
            r'location\.assign\s*\(',
        ]
        
        for pattern in js_redirect_patterns:
            matches = re.findall(pattern + r'[^;]*', response_body, re.IGNORECASE)
            for match in matches:
                if payload in match or unquote(payload) in match:
                    return True
        
        return False
    
    def _extract_domain_from_payload(self, payload: str) -> str:
        """Extract domain from payload URL."""
        try:
            # Handle protocol-relative URLs like //yahoo.com
            if payload.startswith('//'):
                payload = 'http:' + payload
            # Handle single slash bypass like http:/yahoo.com
            elif re.match(r'^https?:/[^/]', payload):
                payload = re.sub(r'^(https?):/', r'\1://', payload)
            
            parsed = urlparse(payload)
            return parsed.netloc
        except:
            return ''
    
    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from a full URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ''
    
    def _generate_reasoning(self, evidence: List[str], is_valid: bool) -> str:
        """Generate reasoning for the validation result."""
        if is_valid:
            # Analyze evidence to provide specific reasoning
            if any('external domain' in ev.lower() for ev in evidence):
                return "Application redirects to external domain"
            elif any('protocol-relative' in ev.lower() for ev in evidence):
                return "Protocol-relative URL bypass successfully redirects to external domain"
            elif any('bypass technique' in ev.lower() for ev in evidence):
                return "Bypass technique successfully circumvents redirect filters"
            elif any('meta refresh' in ev.lower() for ev in evidence):
                return "Meta refresh redirect to external domain detected"
            elif any('redirect status code' in ev.lower() for ev in evidence):
                return "HTTP redirect response successfully redirects to external URL"
            else:
                return "Application improperly redirects to destination"
        else:
            if evidence:
                # Analyze why it's a false positive
                if any('same-domain' in ev.lower() for ev in evidence):
                    return "Redirect occurs but targets the same domain - this is not an open redirect vulnerability as it cannot redirect users to external sites"
                elif any('blocked' in ev.lower() for ev in evidence):
                    return "Redirect attempt was blocked by security controls"
                else:
                    return "Insufficient evidence of successful external redirect"
            else:
                return "No evidence of open redirect vulnerability found. Likely false positive."