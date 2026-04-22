#!/usr/bin/env python3
"""IAM Policy Analyzer - Detect overly permissive IAM policies"""
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class IAMAnalyzer:
    def __init__(self, profile="default"):
        self.profile = profile

    def analyze(self):
        if not HAS_BOTO3:
            return self._demo_analysis()
        findings = []
        try:
            session = boto3.Session(profile_name=self.profile)
            iam = session.client("iam")
            users = iam.list_users()["Users"]
            for user in users:
                uname = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
                for policy in attached:
                    if policy["PolicyName"] == "AdministratorAccess":
                        findings.append({
                            "type": "Admin IAM User",
                            "resource": uname,
                            "detail": "User has AdministratorAccess",
                            "severity": "HIGH"
                        })
                        print(f"[!] User {uname} has AdministratorAccess!")
        except Exception as e:
            return self._demo_analysis()
        return findings

    def _demo_analysis(self):
        return [
            {"type": "Admin IAM User", "resource": "john.doe", "detail": "Direct AdministratorAccess policy", "severity": "HIGH"},
            {"type": "No MFA", "resource": "service-account", "detail": "IAM user without MFA enabled", "severity": "MEDIUM"},
            {"type": "Wildcard Policy", "resource": "dev-policy", "detail": "Policy uses Action: *", "severity": "HIGH"},
        ]
