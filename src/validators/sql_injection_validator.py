import re
from typing import Dict, List, Any, Optional
from urllib.parse import unquote
from .base_validator import BaseValidator


class SQLInjectionValidator(BaseValidator):
    """
    Validator for Error-based SQL Injection vulnerabilities.
    
    Validates error-based SQL injection findings by:
    1. Analyzing response body for database error messages
    2. Checking for data extraction patterns in response
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Database error message patterns
        self.error_patterns = [
            # MySQL errors
            r"You have an error in your SQL syntax",
            r"mysql_fetch_array\(\)",
            r"MySQL result index",
            r"Warning.*?mysql_.*",
            r"Unknown column.*?in.*?field list",
            r"Table.*?doesn't exist",
            r"Column.*?cannot be null",
            r"Duplicate entry.*?for key",
            r"Data truncated for column",
            r"Out of range value for column",
            
            # PostgreSQL errors
            r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_.*",
            r"invalid input syntax for type",
            r"column.*?does not exist",
            r"relation.*?does not exist",
            r"syntax error at or near",
            r"operator does not exist",
            r"function.*?does not exist",
            
            # SQL Server errors
            r"Microsoft.*?ODBC.*?SQL Server",
            r"OLE DB.*?SQL Server",
            r"Unclosed quotation mark after the character string",
            r"Invalid column name",
            r"Invalid object name",
            r"Conversion failed when converting",
            r"The multi-part identifier.*?could not be bound",
            
            # Oracle errors
            r"ORA-[0-9]+",
            r"Oracle.*?Driver",
            r"table or view does not exist",
            r"invalid identifier",
            r"missing expression",
            
            # SQLite errors
            r"SQLite.*?error",
            r"sqlite3\.OperationalError",
            r"no such table",
            r"no such column",
            r"syntax error",
            
            # Generic SQL errors
            r"SQL syntax.*?error",
            r"Warning.*?mysql_num_rows",
            r"supplied argument is not a valid",
            r"database error",
            r"query failed",
            r"sql error",
            r"database connection error",
            r"invalid query",
            r"malformed query",
            r"unexpected token",
            r"syntax error in query",
            r"Internal Server Error",
            r"Error:"
        ]
        
        # Data extraction patterns
        self.data_extraction_patterns = [
            # User data patterns
            r'admin.*?password',
            r'username.*?hash',
            r'email.*?@.*?\.',
            r'user_id.*?[0-9]+',
            r'[a-f0-9]{32}',  # MD5 hashes
            r'[a-f0-9]{40}',  # SHA1 hashes
            r'[a-f0-9]{64}',  # SHA256 hashes
            r'\$2[aby]\$\d+\$',  # Bcrypt hashes
            
            # Database structure patterns
            r'database.*?version',
            r'table.*?column',
            r'information_schema',
            r'mysql\.user',
            r'pg_catalog',
            r'sys\.tables',
            r'sqlite_master',
            
            # Common database content
            r'root.*?localhost',
            r'admin.*?admin',
            r'user.*?user',
            r'test.*?test',
            
            # Database version strings
            r'mysql.*?\d+\.\d+',
            r'postgresql.*?\d+\.\d+',
            r'microsoft sql server.*?\d+',
            r'oracle.*?\d+\.\d+',
            r'sqlite.*?\d+\.\d+',
            
            # Column names that suggest database data
            r'id\s+username\s+password',
            r'user_id\s+email\s+hash',
            r'name\s+email\s+role',
            
            # Data that looks like database records
            r'\d+\s+\w+\s+[a-f0-9]{32,}',  # ID + username + hash
            r'\w+:\w+:\d+:\d+:',  # Unix passwd format in DB
            
            # Additional database content indicators
            r'SELECT.*?FROM.*?WHERE',
            r'INSERT.*?INTO.*?VALUES',
            r'UPDATE.*?SET.*?WHERE',
            r'DELETE.*?FROM.*?WHERE',
            r'CREATE.*?TABLE',
            r'ALTER.*?TABLE',
            r'DROP.*?TABLE',
            r'GRANT.*?ON',
            r'REVOKE.*?ON',
            
            # Database-specific content
            r'@@version',
            r'version\(\)',
            r'user\(\)',
            r'database\(\)',
            r'schema\(\)',
            r'current_user',
            r'session_user',
            r'system_user',
            
            # Error-based extraction indicators
            r'XPATH syntax error',
            r'XPath.*?error',
            r'XML.*?error',
            r'conversion.*?error',
            r'cast.*?error',
            r'convert.*?error',
            
            # Union-based data extraction
            r'\d+\|\w+\|\w+',  # Pipe-separated data
            r'\d+,\w+,\w+',    # Comma-separated data
            r'\d+\s+\w+\s+\w+', # Space-separated data
            
            # Hex/binary data patterns
            r'0x[0-9a-f]{8,}',
            r'\\x[0-9a-f]{2}',
            
            # Database function outputs
            r'concat\(',
            r'group_concat\(',
            r'string_agg\(',
            r'listagg\(',
        ]
    
    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SQL injection finding based on database errors in response.
        
        Expected finding format:
        {
            'url': str,
            'payload': str,
            'response_body': str
        }
        """
        url = finding.get('url', '')
        payload = finding.get('payload', '')
        response_body = finding.get('response_body', '')
        
        evidence = []
        
        # Check for database errors in response body
        error_evidence = self._check_database_errors(response_body)
        evidence.extend(error_evidence)
        
        # If we have database errors, this is automatically a true positive
        if error_evidence:
            confidence = 0.95
            return {
                'is_valid': True,
                'confidence': confidence,
                'evidence': evidence,
                'reasoning': "The response shows database errors, confirming the payload triggered a malformed SQL query and proving SQL injection vulnerability",
                'validator_type': 'SQL Injection'
            }
        
        # Check for data extraction patterns
        extraction_evidence = self._check_data_extraction(response_body)
        if extraction_evidence:
            evidence.extend(extraction_evidence)
        
        # If we detect data extraction patterns, this is high confidence
        if extraction_evidence and len(extraction_evidence) > 0:
            confidence = 0.90
            return {
                'is_valid': True,
                'confidence': confidence,
                'evidence': evidence,
                'reasoning': "The response contains database content patterns indicating successful data extraction from the database",
                'validator_type': 'SQL Injection'
            }
        
        # If no database errors or data extraction found, it's a false positive
        return {
            'is_valid': False,
            'confidence': 0.0,
            'evidence': ["No database errors or extracted data found in response"],
            'reasoning': "The response does not reveal any database errors or extracted data, suggesting that SQL injection did not occur",
            'validator_type': 'SQL Injection'
        }
    
    def _check_database_errors(self, text: str) -> List[str]:
        """Check for database error messages indicating SQL injection."""
        evidence = []
        
        found_errors = self._contains_patterns(text, self.error_patterns)
        for error in found_errors:
            evidence.append(f"Database error detected: {error}")
        
        return evidence
    
    def _check_data_extraction(self, response: str) -> List[str]:
        """Check for signs of successful data extraction. Returns list of evidence."""
        evidence = []
        evidence = []
        
        # Check for user data patterns
        if re.search(r'admin.*?password', response, re.IGNORECASE):
            evidence.append("Admin credentials detected in response")
        
        if re.search(r'username.*?hash', response, re.IGNORECASE):
            evidence.append("Username and hash data detected")
        
        if re.search(r'\w+@\w+\.\w+', response):
            evidence.append("Email addresses detected in response")
        
        if re.search(r'[a-f0-9]{32}', response):
            evidence.append("MD5 hash patterns detected")
        
        if re.search(r'[a-f0-9]{40}', response):
            evidence.append("SHA1 hash patterns detected")
        
        if re.search(r'\$2[aby]\$\d+\$', response):
            evidence.append("Bcrypt hash patterns detected")
        
        # Check for database structure patterns
        if re.search(r'information_schema', response, re.IGNORECASE):
            evidence.append("Database schema information detected")
        
        if re.search(r'mysql\.user', response, re.IGNORECASE):
            evidence.append("MySQL user table data detected")
        
        if re.search(r'pg_catalog', response, re.IGNORECASE):
            evidence.append("PostgreSQL catalog data detected")
        
        # Check for database version strings
        if re.search(r'mysql.*?\d+\.\d+', response, re.IGNORECASE):
            evidence.append("MySQL version information detected")
        
        if re.search(r'postgresql.*?\d+\.\d+', response, re.IGNORECASE):
            evidence.append("PostgreSQL version information detected")
        
        if re.search(r'microsoft sql server.*?\d+', response, re.IGNORECASE):
            evidence.append("SQL Server version information detected")
        
        # Check for typical database record patterns
        if re.search(r'\d+\s+\w+\s+[a-f0-9]{32,}', response):
            evidence.append("Database record pattern detected (ID, username, hash)")
        
        if re.search(r'id\s+username\s+password', response, re.IGNORECASE):
            evidence.append("Database column headers detected")
        
        # Check for database function outputs
        if re.search(r'@@version', response, re.IGNORECASE):
            evidence.append("Database version function output detected")
        
        if re.search(r'user\(\)', response, re.IGNORECASE):
            evidence.append("Database user function output detected")
        
        if re.search(r'database\(\)', response, re.IGNORECASE):
            evidence.append("Database name function output detected")
        
        return evidence
    
    def _generate_reasoning(self, evidence: List[str], is_valid: bool) -> str:
        """Generate reasoning for the validation result."""
        if is_valid:
            return (f"SQL injection vulnerability confirmed. Found {len(evidence)} pieces of evidence: "
                   f"{', '.join(evidence[:3])}{'...' if len(evidence) > 3 else ''}")
        else:
            if evidence:
                return (f"Potential false positive. Only {len(evidence)} pieces of evidence found: "
                       f"{', '.join(evidence)}")
            else:
                return "No evidence of SQL injection vulnerability found. Likely false positive."