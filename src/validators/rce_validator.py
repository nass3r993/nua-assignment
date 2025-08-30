import re
import os
from typing import Dict, List, Any
from urllib.parse import unquote
from .base_validator import BaseValidator


class RCEValidator(BaseValidator):
    """
    Validator for Remote Code Execution (RCE) vulnerabilities that exploit file reading.
    
    Validates RCE findings by:
    1. Checking for system file access via commands
    2. Validating sensitive file content in responses
    """
    
    def __init__(self):
        super().__init__()
        
        # RCE command patterns for file reading
        self.rce_patterns = [
            r'cat\s+/etc/passwd',
            r'cat\s+/etc/shadow',
            r'cat\s+/etc/hosts',
            r'type\s+C:\\',
            r'more\s+/etc/',
            r'less\s+/etc/',
            r'head\s+/etc/',
            r'tail\s+/etc/',
            r'cat\s+/proc/',
            r'cat\s+.*\.conf',
            r'cat\s+.*\.ini',
            r'cat\s+.*\.log',
            r';\s*cat\s+',
            r'\|\s*cat\s+',
            r'&&\s*cat\s+',
            r'`cat\s+',
            r'\$\(cat\s+',
        ]
        
        # Sensitive file content patterns (high confidence indicators)
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
        Validate RCE finding.
        
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
        
        # Check for generic security blocking responses FIRST (before any other analysis)
        if response_body:
            response_lower = response_body.lower().strip()
            
            # Generic blocking responses (not command-specific)
            generic_blocks = [
                'access denied', 'permission denied', 'forbidden', 'unauthorized',
                'blocked', 'filtered', 'not allowed', 'restricted access',
                'security violation', 'policy violation', 'request denied'
            ]
            
            # Only block if it's a generic message (not command-specific like "cat: /file: Permission denied")
            if response_lower in generic_blocks or any(block in response_lower for block in generic_blocks):
                return {
                    'is_valid': False,
                    'confidence': 0.1,
                    'evidence': ["Request blocked by security controls"],
                    'reasoning': "Request blocked by security controls - not a valid RCE",
                    'validator_type': 'RCE'
                }
        
        # Analyze payload patterns
        payload_evidence = self._analyze_payload_patterns(payload)
        evidence.extend(payload_evidence)
        
        # Analyze response body for sensitive file content (HIGH PRIORITY)
        if response_body:
            # If we detect sensitive file content, this is automatically valid with high confidence
            found_contents = self._contains_patterns(response_body, self.sensitive_file_patterns)
            if found_contents:
                evidence.append("Sensitive file content detected")
                return {
                    'is_valid': True,
                    'confidence': 0.95,
                    'evidence': evidence,
                    'reasoning': "RCE confirmed by sensitive file content in response",
                    'validator_type': 'RCE'
                }
            
            # Check for general file content indicators
            file_indicators = [
                r':\d+:\d+:',  # passwd format
                r'\[.*?\]',    # config sections
                r'#.*?config', # config comments
                r'version \d+\.\d+', # version info
                r'PATH=',      # environment variables
            ]
            
            if any(re.search(pattern, response_body, re.IGNORECASE) for pattern in file_indicators):
                evidence.append("File content indicators detected")
                confidence = max(0.85, self._calculate_confidence(len(evidence), max_evidence=6))
                return {
                    'is_valid': True,
                    'confidence': confidence,
                    'evidence': evidence,
                    'reasoning': self._generate_reasoning(evidence, True),
                    'validator_type': 'RCE'
                }
        
        # If no file content detected in response, it's likely a false positive
        if response_body:
            return {
                'is_valid': False,
                'confidence': 0.0,
                'evidence': [],
                'reasoning': "No evidence of RCE vulnerability found. Likely false positive.",
                'validator_type': 'RCE'
            }
        
        confidence = self._calculate_confidence(len(evidence), max_evidence=6)
        is_valid = confidence >= 0.4 and len(evidence) >= 2
        
        return {
            'is_valid': is_valid,
            'confidence': confidence,
            'evidence': evidence,
            'reasoning': self._generate_reasoning(evidence, is_valid),
            'validator_type': 'RCE'
        }
    
    def _analyze_payload_patterns(self, payload: str) -> List[str]:
        """Analyze payload for RCE command patterns."""
        evidence = []
        decoded_payload = unquote(payload)
        
        # Check for RCE command patterns
        found_patterns = self._contains_patterns(decoded_payload, self.rce_patterns)
        if found_patterns:
            evidence.append("System file access command detected")
        
        # Check for command injection indicators
        injection_patterns = [
            r';\s*cat', r'\|\s*cat', r'&&\s*cat', r'`cat', r'\$\(cat'
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, decoded_payload, re.IGNORECASE):
                evidence.append("Command injection pattern detected")
        
        return evidence