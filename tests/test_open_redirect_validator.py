import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator_toolkit import VulnerabilityValidatorToolkit

toolkit = VulnerabilityValidatorToolkit()

# ✅ Valid – classic open redirect
print("Valid vulnerability – classic open redirect:")
classic_open_redirect = {
    "url": "https://victim.com/redirect",
    "parameter": "ret_url",
    "payload": "//evil.com",
    "response_headers": {
        "Location": "//evil.com"
    },
    "status_code": 302
}
print(json.dumps(classic_open_redirect, indent=4))
toolkit.print_result(toolkit.validate_finding('open_redirect', classic_open_redirect))

# ✅ Confusing Valid – meta refresh redirect
print("Valid vulnerability – meta refresh redirect:")
meta_refresh_redirect = {
    "url": "https://victim.com/redirect",
    "parameter": "ret_url",
    "payload": "//evil.com",
    "response_body": '<meta http-equiv="refresh" content="0;url=//evil.com">',
    "status_code": 200
}
print(json.dumps(meta_refresh_redirect, indent=4))
toolkit.print_result(toolkit.validate_finding('open_redirect', meta_refresh_redirect))

# ❌ False Positive – redirect to same domain
print("False Positive – redirect to same domain:")
redirect_same_domain = {
    "url": "https://victim.com/redirect",
    "parameter": "ret_url",
    "payload": "//attacker.com",
    "response_headers": {
        "Location": "/dashboard"
    },
    "status_code": 302
}
print(json.dumps(redirect_same_domain, indent=4))
toolkit.print_result(toolkit.validate_finding('open_redirect', redirect_same_domain))

# ❌ Normal Response – no redirect
print("Normal Response – no redirect:")
normal_response = {
    "url": "https://victim.com/redirect",
    "parameter": "ret_url",
    "payload": "/home",
    "response_body": "<h1>Welcome Home</h1>",
    "status_code": 200
}
print(json.dumps(normal_response, indent=4))
toolkit.print_result(toolkit.validate_finding('open_redirect', normal_response))