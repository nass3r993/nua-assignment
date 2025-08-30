import re
from typing import Dict, List, Any
from urllib.parse import unquote
from bs4 import BeautifulSoup
from .base_validator import BaseValidator


class XSSValidator(BaseValidator):
    """
    Validator for Cross-Site Scripting (XSS) vulnerabilities.
    
    Validates XSS findings by:
    1. Analyzing payload injection contexts
    2. Verifying DOM manipulation attempts
    3. Testing encoding bypass techniques
    """
    
    def __init__(self):
        super().__init__()
        
        # XSS payload patterns for detection
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<svg[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<svg[^>]*>.*?</svg>',
            r'<img[^>]*onerror[^>]*>',
            r'alert\s*\(',
            r'confirm\s*\(',
            r'prompt\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
        ]
        
        # Context-specific XSS patterns
        self.context_patterns = {
            'attribute': [r'["\'].*?on\w+.*?["\']', r'javascript:', r'data:text/html'],
            'script': [r'</script>', r'<!--', r'-->', r'\*/'],
            'style': [r'</style>', r'expression\s*\(', r'javascript:'],
            'comment': [r'-->', r'<!--']
        }
    
    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate XSS finding.
        
        Expected finding format:
        {
            'url': str,
            'payload': str,
            'response_body': str,
        }
        """
        url = finding.get('url', '')
        payload = finding.get('payload', '')
        response_body = finding.get('response_body', '')
        
        evidence = []
        confidence = 0.0
        
        # Validate payload structure
        payload_evidence = self._analyze_payload(payload)
        evidence.extend(payload_evidence)
        
        # Analyze response 
        if response_body:
            response_evidence = self._analyze_response(response_body, payload)
            evidence.extend(response_evidence)
            
            # Check for proper injection context - if payload is in attribute value but not breaking out, it's not XSS
            if self._is_payload_safely_contained(response_body, payload):
                return {
                    'is_valid': False,
                    'confidence': 0.2,
                    'evidence': ["Payload contained within attribute value - not breaking out"],
                    'reasoning': "Payload is contained within attribute value without breaking out of context",
                    'validator_type': 'XSS'
                }
        
        # Check for HTML encoding (sanitization) - this overrides other evidence
        if response_body and self._has_html_entities(response_body) and self._is_payload_html_encoded(response_body, payload):
            return {
                'is_valid': False,
                'confidence': 0.1,
                'evidence': ["Payload safely HTML-encoded"],
                'reasoning': "Payload safely HTML-encoded",
                'validator_type': 'XSS'
            }
        
        # Check if HTML tags are encoded with entities (direct check)
        if response_body and self._has_html_entities(response_body) and self._has_html_entities_in_response(response_body, payload):
            return {
                'is_valid': False,
                'confidence': 0.1,
                'evidence': ["Payload safely HTML-encoded"],
                'reasoning': "Payload safely HTML-encoded",
                'validator_type': 'XSS'
            }
        
        # Check if payload is inside HTML comments (not executable)
        if response_body and self._is_payload_in_comments(response_body, payload):
            return {
                'is_valid': False,
                'confidence': 0.1,
                'evidence': ["Payload inside HTML comments - not executable"],
                'reasoning': "Payload appears inside HTML comments and cannot execute",
                'validator_type': 'XSS'
            }

        # Check for JavaScript URL XSS first 
        if self._is_javascript_url_xss(response_body, payload):
            return {
                'is_valid': True,
                'confidence': 0.9,
                'evidence': ["JavaScript URL XSS detected in href attribute"],
                'reasoning': "JavaScript URL in href attribute is a valid XSS vector",
                'validator_type': 'XSS'
            }
        
        # Calculate confidence based on evidence
        confidence = self._calculate_confidence(len(evidence), max_evidence=6)
        
        # if response_body is provided but payload not reflected, it's not XSS
        if response_body and not any('reflected' in ev.lower() or 'injected' in ev.lower() for ev in evidence):
            is_valid = False
        else:
            is_valid = confidence >= 0.5 and len(evidence) >= 2
        
        return {
            'is_valid': is_valid,
            'confidence': confidence,
            'evidence': evidence,
            'reasoning': self._generate_reasoning(evidence, is_valid),
            'validator_type': 'XSS'
        }
    
    def _analyze_payload(self, payload: str) -> List[str]:
        """Analyze XSS payload for malicious patterns."""
        evidence = []
        decoded_payload = unquote(payload)
        
        # Check for basic XSS patterns
        found_patterns = self._contains_patterns(decoded_payload, self.xss_patterns)
        for pattern in found_patterns:
            evidence.append(f"Malicious XSS pattern detected: {pattern}")
        
        # Check for encoding bypass attempts
        if self._has_encoding_bypass(payload):
            evidence.append("Encoding bypass technique detected")
        
        # Check for context breaking attempts
        context_breaks = self._detect_context_breaks(decoded_payload)
        evidence.extend(context_breaks)
        
        return evidence
    
    def _analyze_response(self, response_body: str, payload: str) -> List[str]:
        """Analyze HTTP response for XSS indicators."""
        evidence = []
        
        # Check if payload is reflected exactly
        decoded_payload = unquote(payload)
        
        # Check if payload is HTML-encoded (sanitized)
        if self._is_html_encoded(response_body, decoded_payload):
            evidence.append("Payload is HTML-encoded (sanitized) - not executable")
            return evidence  # Return early - this is not XSS
        
        if payload in response_body:
            evidence.append("Payload reflected in response body")
        elif decoded_payload in response_body:
            evidence.append("URL-decoded payload reflected in response body")
        else:
            # Check for partial reflection (might indicate filtering)
            payload_parts = self._extract_payload_parts(decoded_payload)
            reflected_parts = sum(1 for part in payload_parts if part in response_body)
            
            if reflected_parts > 0 and reflected_parts < len(payload_parts):
                evidence.append(f"Payload partially reflected ({reflected_parts}/{len(payload_parts)} parts) - possible filtering")
                return evidence  # Don't add more evidence if payload is filtered
            elif reflected_parts == 0:
                # If payload is not reflected at all, this is not XSS
                return []  # Return empty evidence list - no XSS possible without reflection
        
        # Parse HTML and check injection context
        try:
            soup = BeautifulSoup(response_body, 'html.parser')
            context = self._determine_injection_context(soup, payload)
            if context:
                if context not in ["comment", "safe_attribute"]:
                    evidence.append(f"Payload injected in {context} context")
        except:
            pass
        
        return evidence
    
    def _extract_payload_parts(self, payload: str) -> List[str]:
        """Extract key parts of XSS payload for reflection analysis."""
        parts = []
        
        # Extract HTML tags
        tag_matches = re.findall(r'<[^>]+>', payload)
        parts.extend(tag_matches)
        
        # Extract JavaScript functions
        js_matches = re.findall(r'(alert|confirm|prompt|eval)\s*\([^)]*\)', payload)
        parts.extend(js_matches)
        
        # Extract event handlers
        event_matches = re.findall(r'on\w+\s*=\s*[^>\s]+', payload)
        parts.extend(event_matches)
        
        # If no specific parts found, split by common delimiters
        if not parts:
            parts = [p.strip() for p in re.split(r'[<>"\'=\s]+', payload) if p.strip()]
        
        return parts
    
    def _has_encoding_bypass(self, payload: str) -> bool:
        """Check for encoding bypass techniques."""
        bypass_patterns = [
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'&#x?[0-9a-fA-F]+;',  # HTML entity encoding
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            r'String\.fromCharCode',  # JavaScript encoding
        ]
        
        return any(re.search(pattern, payload) for pattern in bypass_patterns)
    
    def _detect_context_breaks(self, payload: str) -> List[str]:
        """Detect attempts to break out of different contexts."""
        evidence = []
        
        # Check for attribute context breaks
        if re.search(r'["\'].*?>', payload):
            evidence.append("Attribute context break attempt detected")
        
        # Check for script context breaks
        if re.search(r'</script>', payload, re.IGNORECASE):
            evidence.append("Script context break attempt detected")
        
        # Check for comment context breaks
        if '-->' in payload:
            evidence.append("Comment context break attempt detected")
            
        return evidence
    
    def _check_script_execution(self, response: str, payload: str) -> bool:
        """Check if script execution context is achieved."""
        decoded_payload = unquote(payload)
        
        # Look for script tags containing our payload
        script_pattern = r'<script[^>]*>.*?' + re.escape(decoded_payload) + r'.*?</script>'
        if re.search(script_pattern, response, re.IGNORECASE | re.DOTALL):
            return True
        
        # Look for event handlers with our payload
        event_pattern = r'on\w+\s*=\s*["\']?[^"\']*?' + re.escape(decoded_payload)
        if re.search(event_pattern, response, re.IGNORECASE):
            return True
            
        return False
    
    def _is_payload_html_encoded(self, response_body: str, payload: str) -> bool:
        """Check if the payload appears HTML-encoded in the response."""
        decoded_payload = unquote(payload)
        
        # If the original payload appears unencoded in response, it's NOT HTML-encoded
        if decoded_payload in response_body:
            return False
        
        # Create HTML-encoded version of payload
        html_encoded = decoded_payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;').replace('&', '&amp;')
        
        # Check if HTML-encoded version appears in response (and original doesn't)
        return html_encoded in response_body
    
    def _has_html_entities_in_response(self, response_body: str, payload: str) -> bool:
        """Check if HTML tags from payload appear as HTML entities in response."""
        decoded_payload = unquote(payload)
        
        # Extract HTML tags from payload
        html_tags = re.findall(r'<[^>]+>', decoded_payload)
        
        for tag in html_tags:
            # Convert tag to HTML entities
            entity_tag = tag.replace('<', '&lt;').replace('>', '&gt;')
            if entity_tag in response_body:
                return True
        
        return False
    
    def _has_html_entities(self, response_body: str) -> bool:
        """Check if response contains any HTML entities."""
        html_entities = ['&lt;', '&gt;', '&quot;', '&#x27;', '&#39;', '&amp;']
        return any(entity in response_body for entity in html_entities)
    
    def _is_html_encoded(self, response_body: str, payload: str) -> bool:
        """Check if payload is HTML-encoded in the response."""
        # Common HTML encodings
        html_encodings = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        
        # Create HTML-encoded version of payload
        encoded_payload = payload
        for char, encoding in html_encodings.items():
            encoded_payload = encoded_payload.replace(char, encoding)
        
        # Check if the HTML-encoded version is in the response
        return encoded_payload in response_body
    
    def _is_payload_safely_contained(self, response_body: str, payload: str) -> bool:
        """Check if payload is safely contained within attribute value without breaking out."""
        decoded_payload = unquote(payload)
        
        # Check if payload appears within attribute values and is properly contained
        try:
            soup = BeautifulSoup(response_body, 'html.parser')
            
            # Check all attributes in all tags
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and (decoded_payload in value or payload in value):
                        # Found payload in attribute value
                        # Check if it's properly contained (not breaking out)
                        
                        # Look at the raw HTML to see if quotes are properly escaped
                        tag_html = str(tag)
                        
                        # If the payload appears in quotes and doesn't break out, it's safe
                        # Pattern: value="...payload..." where payload doesn't close the quotes
                        attr_pattern = f'{attr}\\s*=\\s*["\'][^"\']*?{re.escape(decoded_payload)}[^"\']*?["\']'
                        if re.search(attr_pattern, tag_html):
                            return True
                            
            return False
        except:
            return False
        
        try:
            soup = BeautifulSoup(response_body, 'html.parser')
            
            # Check all attributes in all tags
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and decoded_payload in value:
                        # If we find the payload in an attribute value, check if it breaks out
                        # by looking for quotes in the payload that would close the attribute
                        return False  # If payload is in attribute and contains quotes, it's breaking out
            
            return False
        except:
            return False
    
    def _is_payload_in_comments(self, response_body: str, payload: str) -> bool:
        """Check if payload appears inside HTML comments."""
        decoded_payload = unquote(payload)
        
        # Find all HTML comments
        comment_pattern = r'<!--.*?-->'
        comments = re.findall(comment_pattern, response_body, re.DOTALL)
        
        # Check if payload is inside any comment
        for comment in comments:
            if decoded_payload in comment or payload in comment:
                return True
        
        return False
    
    def _is_payload_breaking_attribute_context(self, response_body: str, payload: str) -> bool:
        """Check if payload is breaking out of attribute context."""
        decoded_payload = unquote(payload)
        
        # If payload contains quotes and appears in response, it's likely breaking out
        if ('"' in decoded_payload or "'" in decoded_payload) and decoded_payload in response_body:
            return True
        
        return False
    
    def _is_javascript_url_xss(self, response_body: str, payload: str) -> bool:
        """Check if payload is a JavaScript URL in href attribute (valid XSS)."""
        decoded_payload = unquote(payload)
        
        try:
            soup = BeautifulSoup(response_body, 'html.parser')
            
            # Look for <a> tags with href containing our javascript: payload
            for a_tag in soup.find_all('a', href=True):
                href_value = a_tag['href']
                # Check if our payload matches href exactly and it's a javascript: URL
                if (decoded_payload == href_value or payload == href_value):
                    if href_value.lower().startswith('javascript:'):
                        return True
                # Also check if payload is contained within javascript: URL
                elif href_value.lower().startswith('javascript:') and (decoded_payload in href_value or payload in href_value):
                    return True
            
            # Also check for other tags that can execute javascript: URLs
            for tag in soup.find_all(['iframe', 'object', 'embed'], src=True):
                src_value = tag['src']
                if (decoded_payload == src_value or payload == src_value):
                    if src_value.lower().startswith('javascript:'):
                        return True
                elif src_value.lower().startswith('javascript:') and (decoded_payload in src_value or payload in src_value):
                    return True
                    
        except:
            pass
        
        return False
    
    def _determine_injection_context(self, soup: BeautifulSoup, payload: str) -> str:
        """Determine the context where payload was injected."""
        decoded_payload = unquote(payload)
        
        # Check script context
        for script in soup.find_all('script'):
            if script.string and decoded_payload in script.string:
                return "script"
        
        # Check attribute context
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and decoded_payload in value:
                    # Check if it's a dangerous attribute context
                    if attr.startswith('on') or attr in ['href', 'src'] and decoded_payload.startswith('javascript:'):
                        return f"attribute ({attr})"
                    else:
                        # Check if payload breaks out of attribute value
                        if '"' in decoded_payload or "'" in decoded_payload or '>' in decoded_payload:
                            return f"attribute ({attr})"
                        else:
                            return "safe_attribute"
        
        # Check text context
        if decoded_payload in soup.get_text():
            return "text"
            
        return "unknown"
    
    def _generate_reasoning(self, evidence: List[str], is_valid: bool) -> str:
        """Generate human-readable reasoning for the validation result."""
        if is_valid:
            # Analyze evidence to provide specific reasoning
            if any('script' in ev.lower() for ev in evidence):
                return "Malicious script tags detected in payload and successfully reflected in response"
            elif any('event' in ev.lower() or 'on' in ev.lower() for ev in evidence):
                return "Event handler injection detected, allowing JavaScript execution"
            elif any('javascript url' in ev.lower() for ev in evidence):
                return "JavaScript URL injection in href attribute, allowing JavaScript execution"
            elif any('context break' in ev.lower() for ev in evidence):
                return "Payload successfully breaks out of intended context to execute JavaScript"
            elif any('encoding bypass' in ev.lower() for ev in evidence):
                return "Encoding bypass technique successfully injects executable JavaScript"
            elif any('reflected' in ev.lower() for ev in evidence):
                return "Malicious payload reflected in response without sanitization"
            else:
                return "Payload successfully injects executable JavaScript code"
        else:
            if evidence:
                # Analyze why it's a false positive
                if any('html-encoded' in ev.lower() or 'sanitized' in ev.lower() for ev in evidence):
                    return "Payload is properly HTML-encoded and cannot execute as JavaScript"
                elif any('comments' in ev.lower() for ev in evidence):
                    return "Payload appears inside HTML comments and cannot execute"
                elif any('contained within attribute' in ev.lower() for ev in evidence):
                    return "Payload is safely contained within attribute value without breaking out"
                elif any('filtered' in ev.lower() for ev in evidence):
                    return "Payload appears to be filtered or partially blocked"
                else:
                    return "Payload does not achieve JavaScript execution context"
            else:
                return "No evidence of XSS vulnerability found. Likely false positive."