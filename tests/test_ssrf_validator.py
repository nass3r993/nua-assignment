import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator_toolkit import VulnerabilityValidatorToolkit

toolkit = VulnerabilityValidatorToolkit()

# ✅ Valid – local admin access
print("1. Valid vulnerability – local admin access:")
local_admin_ssrf = {
    "url": "https://example.com/fetch?url=http://127.0.0.1:8080/admin",
    "payload": "http://127.0.0.1:8080/admin",
    "response_body": "<h1>Admin Dashboard</h1>"
}
print(json.dumps(local_admin_ssrf, indent=4))
toolkit.print_result(toolkit.validate_finding('ssrf', local_admin_ssrf))

# ✅ Valid – cloud metadata access
print("2. Valid vulnerability – cloud metadata access:")
cloud_metadata_ssrf = {
    "url": "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
    "payload": "http://169.254.169.254/latest/meta-data/",
    "response_body": "<pre>{\"AccessKeyId\":\"AKIA...\"}</pre>"
}
print(json.dumps(cloud_metadata_ssrf, indent=4))
toolkit.print_result(toolkit.validate_finding('ssrf', cloud_metadata_ssrf))

# ✅ Valid – File:///etc/passwd
print("3. Valid vulnerability – File:///etc/passwd:")
file_ssrf = {
    "url": "https://example.com/download?path=file:///etc/passwd",
    "payload": "file:///etc/passwd",
    "response_body": "root:x:0:0:root:/root:/bin/bash..."
}
print(json.dumps(file_ssrf, indent=4))
toolkit.print_result(toolkit.validate_finding('ssrf', file_ssrf))

# ❌ Normal Response – no SSRF
print("4. Normal Response – no SSRF:")
normal_response_ssrf = {
    "url": "https://example.com/fetch?url=https://example.com/home",
    "payload": "https://example.com/home",
    "response_body": "<h1>Welcome Home</h1>"
}
print(json.dumps(normal_response_ssrf, indent=4))
toolkit.print_result(toolkit.validate_finding('ssrf', normal_response_ssrf))