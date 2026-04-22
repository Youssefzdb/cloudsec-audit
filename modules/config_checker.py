#!/usr/bin/env python3
"""Config Checker - Audit cloud config files for misconfigurations"""
import json

CHECKS = [
    {"key": "logging.enabled", "expected": True, "severity": "HIGH", "msg": "Logging disabled"},
    {"key": "mfa.required", "expected": True, "severity": "CRITICAL", "msg": "MFA not required"},
    {"key": "encryption.at_rest", "expected": True, "severity": "HIGH", "msg": "Encryption at rest disabled"},
    {"key": "encryption.in_transit", "expected": True, "severity": "HIGH", "msg": "Encryption in transit disabled"},
    {"key": "public_access.blocked", "expected": True, "severity": "CRITICAL", "msg": "Public access not blocked"},
    {"key": "versioning.enabled", "expected": True, "severity": "MEDIUM", "msg": "Versioning disabled"},
]

def get_nested(data, key_path):
    keys = key_path.split(".")
    for k in keys:
        if isinstance(data, dict):
            data = data.get(k)
        else:
            return None
    return data

class ConfigChecker:
    def __init__(self, config_path):
        self.config_path = config_path

    def check(self):
        findings = []
        try:
            with open(self.config_path) as f:
                config = json.load(f)
            for check in CHECKS:
                value = get_nested(config, check["key"])
                if value != check["expected"]:
                    findings.append({
                        "type": "Misconfiguration",
                        "key": check["key"],
                        "message": check["msg"],
                        "severity": check["severity"]
                    })
                    print(f"[!] {check['severity']}: {check['msg']}")
        except Exception as e:
            findings.append({"error": str(e)})
        return findings
