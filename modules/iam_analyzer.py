import json
import re

class IAMAnalyzer:
    def __init__(self, filepath=""):
        self.filepath = filepath
        self.findings = []

    def check_policy(self, policy_str):
        # Check for overly permissive policies
        if '"*"' in policy_str or "'*'" in policy_str:
            self.findings.append({
                "issue": "Wildcard permissions (*)",
                "severity": "HIGH",
                "description": "Policy grants access to all resources/actions"
            })
            print("[!] HIGH: Wildcard IAM permissions found")

        if re.search(r'"Effect":\s*"Allow"', policy_str) and re.search(r'"Action":\s*"\*"', policy_str):
            self.findings.append({
                "issue": "Full admin access policy",
                "severity": "CRITICAL",
                "description": "Policy allows all actions on all resources"
            })
            print("[!] CRITICAL: Full admin IAM policy detected")

    def analyze(self):
        if self.filepath and self.filepath.endswith(".json"):
            try:
                with open(self.filepath, "r") as f:
                    content = f.read()
                self.check_policy(content)
            except:
                pass
        return self.findings
