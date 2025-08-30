import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator_toolkit import VulnerabilityValidatorToolkit

toolkit = VulnerabilityValidatorToolkit()

# ✅ Valid – read root SSH key
print("1. Valid vulnerability – read root SSH key:")
ssh_key_rce = {
    "url": "https://target.com/run?cmd=cat+/root/.ssh/id_rsa",
    "payload": "cat /root/.ssh/id_rsa",
    "response_body": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAv..."
}
print(json.dumps(ssh_key_rce, indent=4))
toolkit.print_result(toolkit.validate_finding('rce', ssh_key_rce))

# ✅ True Positive – read PHP config file with DB credentials
print("2. Valid vulnerability – read PHP config file with DB credentials:")
php_config_rce = {
    "url": "https://target.com/run?cmd=cat+/var/www/html/config.php",
    "payload": "cat /var/www/html/config.php",
    "response_body": "<?php $db_user='admin'; $db_pass='P@ssw0rd'; ?>"
}
print(json.dumps(php_config_rce, indent=4))
toolkit.print_result(toolkit.validate_finding('rce', php_config_rce))

# ❌ Blocked by WAF – access denied
print("3. Blocked by WAF – access denied:")
waf_blocked_rce = {
    "url": "https://target.com/run?cmd=cat+/etc/shadow",
    "payload": "cat /etc/shadow",
    "response_body": "403 Forbidden"
}
print(json.dumps(waf_blocked_rce, indent=4))
toolkit.print_result(toolkit.validate_finding('rce', waf_blocked_rce))

# ❌ Normal Response – no RCE
print("4. Normal Response – no RCE:")
normal_response_rce = {
    "url": "https://target.com/run?cmd=cat+/var/www/html/config.php",
    "payload": "cat /var/www/html/config.php",
    "response_body": "<h1> Home page</h1>"
}
print(json.dumps(normal_response_rce, indent=4))
toolkit.print_result(toolkit.validate_finding('rce', normal_response_rce))
