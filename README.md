# Vulnerability Validator Toolkit

A Python toolkit for deterministic validation of security vulnerabilities. It helps distinguish between valid findings and false positive findings across different vulnerability classes.

# Overview

The toolkit implements validators for:
- **XSS (Cross-Site Scripting)**
- **Open Redirect**  
- **SQL Injection**
- **RCE/File Read (Remote Code Execution)**
- **SSRF (Server-Side Request Forgery)**

Each validator uses deterministic analysis techniques to provide confidence scores and detailed evidence for validation decisions.

### Basic Usage

```python
from src.validator_toolkit import VulnerabilityValidatorToolkit

# Initialize toolkit
toolkit = VulnerabilityValidatorToolkit()

# Validate an XSS finding
xss_finding = {
    'url': 'https://example.com/search?q=test',
    'payload': '<script>alert(1)</script>',
    'parameter': 'q',
    'response_body': '<div><script>alert(1)</script></div>'
}

toolkit.print_result(toolkit.validate_finding('xss', xss_finding))
```

### Run Tests

```bash
python run_tests.py
```

## Vulnerability Validators

### 1. XSS (Cross-Site Scripting) Validator

**Theoretical Foundation**: 
XSS validation is fundamentally about proving that user-controlled input can execute JavaScript code in a victim's browser. This requires demonstrating that:
1. User input is reflected in the HTTP response
2. The input breaks out of its intended context (HTML attribute, text node, etc.)
3. The payload can execute JavaScript without being sanitized or encoded
4. The injection occurs in an executable context (not in comments or encoded form)

The core challenge is distinguishing between harmless reflection (where input is safely contained) and dangerous injection (where input can execute code). This requires analyzing HTML parsing contexts, encoding mechanisms, and JavaScript execution environments.

**How it works**:
- **Payload Reflection Analysis**: Verifies that the malicious payload appears in the HTTP response
- **Context Escape Detection**: Determines if payload breaks out of safe contexts (HTML attributes, text nodes)
- **Encoding Bypass Recognition**: Identifies attempts to bypass HTML entity encoding and other sanitization
- **Execution Context Validation**: Confirms payload appears in executable JavaScript contexts
- **DOM Structure Analysis**: Parses HTML to validate successful injection into dangerous contexts
- **Sanitization Detection**: when payloads are safely HTML-encoded and cannot execute (e.g. in HTML comments)

**Validation Criteria**:
- **True Positive**: Payload reflected unencoded in executable context (script tags, event handlers ..etc)
- **False Positive**: Payload HTML-encoded, in comments, or safely contained in attribute values

**Expected Finding Format**:
```python
xss_finding = {
    'url': 'https://example.com/search',
    'payload': '<script>alert(1)</script>',
    'response_body': '<div>Results: <script>alert(1)</script></div>'
}
```

### 2. Open Redirect Validator

**Theoretical Foundation**:
Open redirect validation proves that an application can be manipulated to redirect users to attacker-controlled external domains. the vulnerability requires proving external domain redirection, not just any redirect.

The key distinction is between legitimate same-domain redirects (safe) and external domain redirects (vulnerable). Validation must prove that user input can control the redirect destination to point to attacker-controlled external sites.

**How it works**:
- **Parameter Name Validation**: Confirms parameter names indicate redirect functionality (redirect, next, return_url)
- **External Domain Detection**: Verifies payload targets external domains, not same-domain paths
- **HTTP Redirect Analysis**: Validates redirect status codes (301, 302, 307, 308) and Location headers
- **Bypass Technique Recognition**: Identifies protocol-relative URLs (//evil.com) and other bypass methods
- **Client-Side Redirect Detection**: Detects meta refresh and JavaScript-based redirects
- **Same-Domain Protection**: Ensures redirects to same domain are classified as safe

**Validation Criteria**:
- **True Positive**: Redirect to external domain via HTTP headers, meta refresh, or JavaScript
- **False Positive**: Same-domain redirects, no redirect mechanism detected, or blocked attempts

**Expected Finding Format**:
```python
redirect_finding = {
    'url': 'https://example.com/login',
    'parameter': 'redirect_url',
    'payload': 'https://malicious.com',
    'response_headers': {'Location': 'https://malicious.com'},
    'status_code': 302,
    'response_body': 'Redirecting...'
}
```

### 3. SQL Injection (Error based) Validator

**Theoretical Foundation**:
SQL injection validation proves that user input can manipulate SQL query structure to access unauthorized data. The validation focuses on:
1. Database error messages that reveal SQL syntax manipulation
2. Successful data extraction from database tables
3. Evidence that the application's SQL queries are being modified by user input

Unlike other vulnerabilities, SQL injection validation relies heavily on response analysis because the vulnerability manifests through database interactions. Error messages are the strongest indicator because they prove the SQL query structure was modified.

**How it works**:
- **Database Error Detection**: Identifies database-specific error messages proving SQL syntax manipulation
- **Data Extraction Analysis**: Recognizes patterns indicating successful data retrieval from database
- **Query Structure Validation**: Confirms that user input modified the intended SQL query structure
- **Database Content Recognition**: Identifies database records, schema information, and version details
- **Response Content Analysis**: Validates that response contains database-originated content

**Validation Criteria**:
- **True Positive**: Database error messages or successful data extraction patterns in response
- **False Positive**: No database errors or extracted data found in response body

**Expected Finding Format**:
```python
sqli_finding = {
    'url': 'https://example.com/product',
    'payload': "1' UNION SELECT username,password FROM users--",
    'response_body': 'admin:5d41402abc4b2a76b9719d911017c592'
}
```

### 4. RCE/File Read Validator

**Theoretical Foundation**:
RCE validation proves that user input can execute system commands or read arbitrary files on the server. The validation focuses on:
1. Successful file content retrieval from sensitive system files
2. Command execution that produces recognizable system output
3. Evidence that the application executed attacker-controlled commands

The key is proving actual command execution occurred, not just that command injection syntax was attempted. This requires analyzing response content for system file contents, log entries, or other evidence of successful command execution.

**How it works**:
- **System File Content Detection**: Identifies sensitive file contents (/etc/passwd, win.ini, etc.)
- **Command Execution Validation**: Confirms that system commands were actually executed
- **File Access Verification**: Validates successful reading of system files and configurations
- **Permission Analysis**: Distinguishes between successful access and permission-denied responses
- **Output Pattern Recognition**: Identifies system logs, configuration files, and authentication data

**Validation Criteria**:
- **True Positive**: Response contains sensitive file content proving successful command execution
- **False Positive**: No file content detected or permission denied responses

**Expected Finding Format**:
```python
rce_finding = {
    'url': 'https://example.com/ping',
    'payload': 'cat /etc/passwd',
    'response_body': 'root:x:0:0:root:/root:/bin/bash'
}
```

### 5. SSRF (Server-Side Request Forgery) Validator

**Theoretical Foundation**:
SSRF validation proves that an application can be manipulated to make server-side requests to attacker-controlled targets. The focus is on:
1. Access to internal network resources that should not be externally accessible
2. Retrieval of sensitive cloud metadata or internal content

The vulnerability is confirmed when the response contains content from internal services, cloud metadata endpoints, or other resources that prove the server made unintended requests to internal/private network locations.

**How it works**:
- **Internal Network Detection**: Identifies attempts to access private IP ranges and localhost
- **Cloud Metadata Analysis**: Detects access to cloud provider metadata endpoints
- **Protocol Scheme Validation**: Identifies dangerous protocols (file://, gopher://, etc.)
- **Bypass Technique Recognition**: Detects IP encoding, and other evasion methods
- **Internal Content Verification**: Confirms response contains internal content or metadata content
- **Security Control Detection**: Identifies when requests are blocked by firewalls or security controls

**Validation Criteria**:
- **True Positive**: Response contains internal content or cloud metadata proving successful SSRF
- **False Positive**: Requests blocked by security controls or no internal content accessed

**Expected Finding Format**:
```python
ssrf_finding = {
    'url': 'https://example.com/fetch',
    'payload': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'parameter': 'url',
    'response_body': '{"AccessKeyId": "AKIA...", "SecretAccessKey": "..."}'
}
```

## Validation Results

Each validator returns a standardized result structure:

```python
{
    'Status':              # Valid vulnerability or False positive
    'validator_type':      # Type of validator used
    'Evidences':           # List of evidence supporting the decision
    'Reasoning':           # Explanation of the decision
}
```

## AI Usage Note

AI was used to generate regex patterns and enhance code readability. This assisted in creating accurate validation patterns and making the code easier to read and understand.