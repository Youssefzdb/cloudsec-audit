#!/usr/bin/env python3
"""IAM Analyzer - Detect overprivileged roles and policies"""
import json

class IAMAnalyzer:
    def __init__(self, config_path):
        self.config_path = config_path

    def analyze(self):
        findings = []
        try:
            with open(self.config_path) as f:
                config = json.load(f)

            iam = config.get("iam", {})
            users = iam.get("users", [])

            for user in users:
                policies = user.get("policies", [])
                if "AdministratorAccess" in policies:
                    findings.append({
                        "type": "Overprivileged User",
                        "user": user.get("name"),
                        "policy": "AdministratorAccess",
                        "severity": "CRITICAL"
                    })
                    print(f"[!] CRITICAL: User {user.get('name')} has AdministratorAccess")

                if not user.get("mfa_enabled", False):
                    findings.append({
                        "type": "MFA Disabled",
                        "user": user.get("name"),
                        "severity": "HIGH"
                    })

                if user.get("access_key_age_days", 0) > 90:
                    findings.append({
                        "type": "Stale Access Key",
                        "user": user.get("name"),
                        "age_days": user["access_key_age_days"],
                        "severity": "MEDIUM"
                    })
        except Exception as e:
            findings.append({"error": str(e)})
        return findings
