import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator_toolkit import VulnerabilityValidatorToolkit

toolkit = VulnerabilityValidatorToolkit()

# ✅ Valid – classic XSS
print("1. Valid vulnerability – classic XSS:")
classic_xss = {
    "url": "https://example.com/page",
    "payload": "<script>alert(1)</script>",
    "response_body": "<div><script>alert(1)</script></div>"
}
print(json.dumps(classic_xss, indent=4))
toolkit.print_result(toolkit.validate_finding('xss', classic_xss))

# ✅ Valid – XSS with onerror and quotes
print("2. Valid vulnerability – XSS with onerror and quotes:")
onerror_xss = {
    "url": "https://example.com/img",
    "payload": '" onerror="alert(1)"',
    "response_body": '<img src="" onerror="alert(1)">'
}
print(json.dumps(onerror_xss, indent=4))
toolkit.print_result(toolkit.validate_finding('xss', onerror_xss))

# ❌ False Positive – HTML-encoded script
print("3. False Positive – HTML-encoded script:")
html_encoded_xss = {
    "url": "https://example.com/page",
    "payload": "<b>bold</b>",
    "response_body": "<div>Showing: &lt;b&gt;bold&lt;/b&gt;</div>"
}
print(json.dumps(html_encoded_xss, indent=4))
toolkit.print_result(toolkit.validate_finding('xss', html_encoded_xss))

# ❌ False Positive – Payload inside comments
print("4. False Positive – Payload inside comments:")
commented_xss = {
    "url": "https://victim.com/search?q=<!--<script>alert(1)</script>-->",
    "payload": "<script>alert(1)</script>",
    "response_body": "<h3>test</h3><!--<script>alert(1)</script>-->"
}
print(json.dumps(commented_xss, indent=4))
toolkit.print_result(toolkit.validate_finding('xss', commented_xss))