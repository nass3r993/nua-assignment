import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator_toolkit import VulnerabilityValidatorToolkit

toolkit = VulnerabilityValidatorToolkit()

# ✅ Valid – error-based SQLi triggers database error
print("1. Valid vulnerability – error-based SQLi:")
error_based_sqli = {
    "url": "https://target.com/login?user=admin'--",
    "response_body": "Syntax error: near \"'--\""
}
print(json.dumps(error_based_sqli, indent=4))
toolkit.print_result(toolkit.validate_finding('sql_injection', error_based_sqli))

# ✅ Valid – successful data extraction from SQLi
print("2. Valid vulnerability – data extraction from SQLi:")
data_extraction_sqli = {
    "url": "https://victim.com/search",
    "payload": "' UNION SELECT 1, username, password FROM users--",
    "response_body": "<table><tr><td>1</td><td>john</td><td>202cb962ac59075b964b07152d234b70</td></tr></table>"
}
print(json.dumps(data_extraction_sqli, indent=4))
toolkit.print_result(toolkit.validate_finding('sql_injection', data_extraction_sqli))

# ❌ False Positive – normal input, no SQL error
print("3. False Positive – normal input, no SQL error:")
normal_input_sqli = {
    "url": "https://example.com/item?id=1",
    "payload": "1",
    "response_body": "Product found"
}
print(json.dumps(normal_input_sqli, indent=4))
toolkit.print_result(toolkit.validate_finding('sql_injection', normal_input_sqli))

# ❌ Blocked by WAF – SQLi attempt blocked
print("4. False Positive – Blocked by WAF, SQLi attempt blocked:")
blocked_sqli = {
    "url": "https://example.com/item?id=1",
    "payload": "1 AND (SELECT 1/0)",
    "response_body": "Request blocked by WAF"
}
print(json.dumps(blocked_sqli, indent=4))
toolkit.print_result(toolkit.validate_finding('sql_injection', blocked_sqli))