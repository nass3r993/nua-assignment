import re
import socket
from typing import Dict, List, Any
from urllib.parse import urlparse, unquote
from .base_validator import BaseValidator


class SSRFValidator(BaseValidator):
    """
    Validator for Server-Side Request Forgery (SSRF) vulnerabilities.
    
    Validates SSRF findings by:
    1. Checking for internal network access attempts
    2. Testing URL scheme manipulation
    3. Validating localhost/internal IP access
    4. Detecting reading internal files 
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Internal/private network ranges
        self.private_ranges = [
            r'127\.0\.0\.1',
            r'localhost',
            r'127\.1',              
            r'127\.0\.1',           
            r'10\.\d+\.\d+\.\d+',
            r'192\.168\.\d+\.\d+',
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
            r'169\.254\.\d+\.\d+',  
            r'::1',                 # IPv6 localhost
            r'0\.0\.0\.0',
            r'0+\.0+\.0+\.0+',      # Padded zeros
        ]
        
        # Dangerous URL schemes
        self.dangerous_schemes = [
            'file', 'ftp', 'dict', 'sftp', 'ldap', 'gopher',
            'jar', 'netdoc', 'mailto', 'news', 'php', 'expect'
        ]
        
        # Cloud metadata endpoints
        self.metadata_endpoints = [
            '169.254.169.254',      # AWS, Azure, GCP
            'metadata.google.internal',
            'metadata',
            '100.100.100.200',      # Alibaba Cloud
        ]
        
        # Bypass techniques patterns
        self.bypass_patterns = [
            r'@',                   
            r'#',                   
            r'\?',                  
            r'%[0-9a-fA-F]{2}',    
            r'\\'                  
        ]
        
        # Sensitive file content patterns (from RCE validator)
        self.sensitive_file_patterns = [
            r'root:x:0:0:root:/root:/bin/bash',  # /etc/passwd
            r'root:x:0:0:',                     # /etc/passwd general
            r'daemon:x:1:1:daemon',             # /etc/passwd
            r'bin:x:2:2:bin',                   # /etc/passwd
            r'sys:x:3:3:sys',                   # /etc/passwd
            r'nobody:x:\d+:\d+:nobody',         # /etc/passwd
            r'root:\$[16]\$[^:]+:[^:]+:',       # /etc/shadow
            r'127\.0\.0\.1\s+localhost',        # /etc/hosts
            r'::1\s+localhost',                 # /etc/hosts IPv6
            r'\[boot loader\]',                 # Windows boot.ini
            r'\[fonts\]',                       # Windows win.ini
            r'\[extensions\]',                  # Windows win.ini
            r'for 16-bit app support',          # Windows win.ini
            r'# /etc/hosts',                    # hosts file comment
            r'# This file controls',            # config file comment
            r'Linux version \d+\.\d+',          # /proc/version
            r'gcc version \d+\.\d+',            # /proc/version
            r'PATH=/usr/local/sbin',            # /proc/self/environ
            # Log file patterns
            r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[error\]',  # Nginx error log
            r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[warn\]',   # Nginx warn log
            r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[info\]',   # Nginx info log
            r'\[.*?\] \[error\] \[client',      # Apache error log
            r'\[.*?\] \[warn\] \[client',       # Apache warn log
            r'AH\d{5}:',                        # Apache error codes
            # Config file patterns
            r'server\s*{',                      # Nginx config
            r'location\s*/.*?\s*{',             # Nginx location block
            r'<VirtualHost.*?>',                # Apache vhost
            r'<Directory.*?>',                  # Apache directory
            r'LoadModule\s+\w+',                # Apache modules
            r'ServerRoot\s+',                   # Apache config
            # Database config patterns
            r'host\s*=\s*localhost',            # DB config
            r'password\s*=\s*["\'].*?["\']',    # DB password
            r'username\s*=\s*["\'].*?["\']',    # DB username
            r'database\s*=\s*["\'].*?["\']',    # DB name
            # Authentication log patterns
            r'Accepted password for \w+ from',  # SSH login success
            r'Failed password for \w+ from',    # SSH login failure
            r'authentication failure',          # Auth failure
            r'session opened for user',         # Session opened
            r'session closed for user',         # Session closed
            r'sudo:\s+\w+\s+:',                 # Sudo command
            r'su:\s+\(to \w+\)',                # Su command
            r'login:\s+FAILED LOGIN',           # Failed login
            r'sshd\[\d+\]:',                    # SSH daemon logs
            r'systemd\[\d+\]:',                 # Systemd logs
            r'kernel:\s+\[',                    # Kernel logs
            # Process and system info
            r'MemTotal:\s+\d+\s+kB',            # /proc/meminfo
            r'MemFree:\s+\d+\s+kB',             # /proc/meminfo
            r'processor\s+:\s+\d+',             # /proc/cpuinfo
            r'model name\s+:',                  # /proc/cpuinfo
            r'cpu MHz\s+:',                     # /proc/cpuinfo
            r'cache size\s+:',                  # /proc/cpuinfo
            # System services
            r'systemctl status',                # Systemctl output
            r'Active: active \(running\)',     # Service status
            r'Loaded: loaded',                  # Service status
            r'Main PID: \d+',                   # Service PID
            # Permission denied patterns
            r'Permission denied',               # Permission denied
            r'Access denied',                   # Access denied
            r'Operation not permitted',         # Operation not permitted
            r'cat:\s*.*?:\s*Permission denied', # cat permission denied
            r'cat:\s*.*?:\s*No such file',      # File not found
            r'-----BEGIN RSA PRIVATE KEY-----', # SSH RSA private key
            r'-----BEGIN OPENSSH PRIVATE KEY-----', # SSH OpenSSH private key
            r'-----BEGIN DSA PRIVATE KEY-----', # SSH DSA private key
            r'-----BEGIN EC PRIVATE KEY-----',  # SSH EC private key
            r'-----BEGIN PRIVATE KEY-----',     # Generic private key
            r'ssh-rsa AAAA[0-9A-Za-z+/]+',     # SSH public key RSA
            r'<configuration>',                 # Windows web.config
            r'<connectionStrings>',             # Windows web.config connection strings
            r'<appSettings>',                   # Windows web.config app settings
            r'<system\.web>',                   # Windows web.config system.web
            r'<\?php',                          # PHP code
            r'<\?=',                            # PHP short tag
            r'<%@\s+Page\s+Language="[^"]*"',   # ASPX page directive
        ]
    
    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SSRF finding.
        
        Expected finding format:
        {
            'url': str,
            'payload': str (target URL),
            'response_body': str,
        }
        """
        url = finding.get('url', '')
        payload = finding.get('payload', '')
        response_body = finding.get('response_body', '')
        
        evidence = []
        
        # Analyze payload URL structure
        payload_evidence = self._analyze_payload_url(payload)
        evidence.extend(payload_evidence)
        
        # Check for bypass techniques
        bypass_evidence = self._check_bypass_techniques(payload)
        evidence.extend(bypass_evidence)
        
        # Analyze response indicators
        if response_body:
            response_evidence = self._analyze_ssrf_response(response_body)
            evidence.extend(response_evidence)
            
            # If we have response body but no sensitive content detected, it's not SSRF
            if not response_evidence:
                return {
                    'is_valid': False,
                    'confidence': 0.1,
                    'evidence': ["No sensitive internal content detected in response"],
                    'reasoning': "The response body does not contain sensitive content, likely false positive",
                    'validator_type': 'SSRF'
                }
        
        # Calculate confidence with higher weight for internal content access
        confidence = self._calculate_ssrf_confidence(evidence)
        is_valid = confidence >= 0.4 and len(evidence) >= 1
        
        return {
            'is_valid': is_valid,
            'confidence': confidence,
            'evidence': evidence,
            'reasoning': self._generate_reasoning(evidence, is_valid),
            'validator_type': 'SSRF'
        }
    
    def _analyze_payload_url(self, payload: str) -> List[str]:
        """Analyze SSRF payload URL for malicious indicators."""
        evidence = []
        decoded_payload = unquote(payload)
        
        try:
            parsed = urlparse(decoded_payload)
            
            # Check for dangerous schemes
            if parsed.scheme in self.dangerous_schemes:
                evidence.append(f"Dangerous {parsed.scheme}:// scheme detected")
                
                # For file scheme, also check for sensitive file access
                if parsed.scheme == 'file' and '/etc/passwd' in parsed.path:
                    evidence.append("File scheme targeting /etc/passwd")
            
            # Check for internal/private IPs
            if parsed.netloc:
                for pattern in self.private_ranges:
                    if re.match(pattern, parsed.netloc):
                        evidence.append(f"Targeting internal network {parsed.netloc}")
                        break
                
                # Check for cloud metadata endpoints
                if any(endpoint in parsed.netloc for endpoint in self.metadata_endpoints):
                    evidence.append(f"Targeting cloud metadata endpoint {parsed.netloc}")
            
            # Check for localhost variations
            if self._is_localhost_variant(parsed.netloc):
                evidence.append(f"Targeting localhost variant {parsed.netloc}")
                
        except Exception:
            # If URL parsing fails, still check for patterns in raw payload
            if any(pattern in decoded_payload for pattern in ['127.0.0.1', 'localhost']):
                evidence.append("Internal network pattern in malformed URL")
        
        return evidence
    
    def _check_bypass_techniques(self, payload: str) -> List[str]:
        """Check for SSRF bypass techniques."""
        evidence = []
        decoded_payload = unquote(payload)
        
        # Check for encoding bypasses
        if payload != decoded_payload:
            evidence.append("URL encoding bypass detected")
        
        # Check for bypass with @
        if '@' in decoded_payload and not decoded_payload.startswith('mailto:'):
            evidence.append("Bypass using @ symbol detected")
        
        # Check for IPv6 localhost variants
        ipv6_patterns = ['::1', '::ffff:127.0.0.1', '::ffff:7f00:1']
        if any(pattern in decoded_payload for pattern in ipv6_patterns):
            evidence.append("IPv6 localhost variant detected")
        
        # Check for decimal/hex IP encoding
        if self._check_ip_encoding_bypass(decoded_payload):
            evidence.append("IP address encoding bypass detected")
        
        return evidence
    
    def _analyze_ssrf_response(self, response_body: str) -> List[str]:
        """Analyze SSRF response indicators."""
        evidence = []
        
        # Analyze response body
        ssrf_indicators = self._check_ssrf_response_indicators(response_body)
        evidence.extend(ssrf_indicators)
        
        # Check for sensitive file content patterns
        file_content_evidence = self._check_sensitive_file_content(response_body)
        evidence.extend(file_content_evidence)
        
        return evidence
    
    def _check_sensitive_file_content(self, response_body: str) -> List[str]:
        """Check for sensitive file content patterns in response."""
        evidence = []
        
        # Look for sensitive file content patterns
        found_contents = self._contains_patterns(response_body, self.sensitive_file_patterns)
        for content in found_contents:
            evidence.append("Sensitive file content detected")
        
        return evidence
    
    def _check_ssrf_response_indicators(self, response_body: str) -> List[str]:
        """Check response body for SSRF success indicators."""
        evidence = []
        
        # Convert response to lowercase for case-insensitive matching
        response_lower = response_body.lower()
        
        # Cloud metadata indicators
        metadata_patterns = [
            r'ami-[0-9a-f]+',       # AWS AMI ID
            r'i-[0-9a-f]+',         # AWS instance ID
            r'"instance-id"',       # GCP metadata
            r'"project-id"',        # GCP project
            r'accesskeyid',         # AWS credentials (case insensitive)
            r'secretaccesskey',     # AWS credentials (case insensitive)
            r'akia[0-9a-z]+',       # AWS access key format
        ]
        
        found_metadata = self._contains_patterns(response_lower, metadata_patterns)
        if found_metadata:
            evidence.append("Cloud metadata content detected")
        
        # Internal service indicators
        internal_patterns = [
            r'admin.*?panel',       # Admin panels (case insensitive)
            r'dashboard',           # Dashboards
            r'local.*?dev',         # Local development
            r'dev.*?server',        # Development servers
            r'internal.*?service',  # Internal services
            r'localhost.*?admin',   # Localhost admin
            r'management.*?console', # Management interfaces
            r'control.*?panel',     # Control panels
            r'apache.*?server',     # Internal Apache
            r'nginx/\d+\.\d+',     # Internal nginx
            r'iis \d+\.\d+',       # Internal IIS
            r'tomcat.*?\d+',       # Tomcat servers
            r'jetty.*?\d+',        # Jetty servers
            r'running.*?on.*?port', # Services running on ports
        ]
        
        found_internal = self._contains_patterns(response_lower, internal_patterns)
        if found_internal:
            evidence.append("Internal service content detected")
        
        # Additional high-confidence keywords (only if no pattern matches found)
        if not found_internal:
            high_confidence_keywords = [
                'admin', 'dashboard', 'panel', 'console', 'management',
                'internal', 'localhost', 'local', 'dev', 'development'
            ]
            
            for keyword in high_confidence_keywords:
                if keyword in response_lower:
                    evidence.append("Internal service keyword detected")
                    break  # Only add one keyword evidence to avoid duplicates
        
        return evidence
    
    def _is_localhost_variant(self, netloc: str) -> bool:
        """Check if netloc is a localhost variant."""
        localhost_variants = [
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            '127.1', '127.000.000.1', '0x7f.0x0.0x0.0x1', ''
        ]
        
        return netloc.lower() in localhost_variants
    
    def _check_ip_encoding_bypass(self, payload: str) -> bool:
        """Check for IP address encoding bypasses."""
        # Decimal IP encoding (8-10 digits for full IP)
        if re.search(r'http://\d{8,10}[:/]', payload):
            return True
        
        # Hex IP encoding (0x followed by 8 hex digits)
        if re.search(r'http://0x[0-9a-f]{8}[:/]', payload, re.IGNORECASE):
            return True
        
        # Octal IP encoding (leading zeros)
        if re.search(r'http://0[0-7]+[:/]', payload):
            return True
            
        # Mixed encoding (e.g., 0177.0.0.1)
        if re.search(r'http://0[0-7]+\.\d+\.\d+\.\d+[:/]', payload):
            return True
            
        # Short form IPs (e.g., 127.1, 10.1)
        if re.search(r'http://\d{1,3}\.\d{1,3}[:/]', payload):
            return True
        
        return False
    
    def _calculate_ssrf_confidence(self, evidence: List[str]) -> float:
        """Calculate SSRF confidence with higher weight for internal content access."""
        if not evidence:
            return 0.0
            
        confidence = 0.0
        
        for ev in evidence:
            # High confidence indicators
            if any(keyword in ev.lower() for keyword in ['admin panel', 'dashboard', 'internal service', 'metadata access', 'internal', 'localhost']):
                confidence += 0.6
            # Low confidence indicators
            else:
                confidence += 0.2
                
        return min(confidence, 1.0)
    
    def _generate_reasoning(self, evidence: List[str], is_valid: bool) -> str:
        """Generate reasoning for the validation result."""
        if is_valid:
            return "Evidence indicates successful access to internal network resources or sensitive cloud metadata endpoints that should not be accessible externally"
        else:
            if evidence:
                return "Likely false positive: Evidence shows SSRF attempt but no confirmation of successful internal access or sensitive data exposure"
            else:
                return "No evidence of SSRF vulnerability found. Likely false positive."