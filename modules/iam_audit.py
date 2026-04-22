#!/usr/bin/env python3
"""IAM Security Auditor"""
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class IAMAuditor:
    def __init__(self, profile="default"):
        self.profile = profile
        self.findings = []

    def audit(self):
        if not HAS_BOTO3:
            return [{"severity": "INFO", "service": "IAM", "issue": "boto3 not installed"}]
        try:
            session = boto3.Session(profile_name=self.profile)
            iam = session.client("iam")

            # Check root MFA
            summary = iam.get_account_summary()["SummaryMap"]
            if not summary.get("AccountMFAEnabled"):
                self.findings.append({"severity": "CRITICAL", "service": "IAM", "issue": "Root account MFA is DISABLED!"})
                print("[!] Root MFA disabled!")

            # Check users without MFA
            users = iam.list_users()["Users"]
            mfa_devices = {d["UserName"] for d in iam.list_virtual_mfa_devices()["VirtualMFADevices"] if "User" in d}
            for user in users:
                uname = user["UserName"]
                if uname not in mfa_devices:
                    self.findings.append({"severity": "HIGH", "service": "IAM", "issue": f"User {uname} has no MFA"})
                    print(f"[!] No MFA: {uname}")

            # Check password policy
            try:
                policy = iam.get_account_password_policy()["PasswordPolicy"]
                if policy.get("MinimumPasswordLength", 0) < 14:
                    self.findings.append({"severity": "MEDIUM", "service": "IAM", "issue": "Password minimum length < 14"})
            except:
                self.findings.append({"severity": "HIGH", "service": "IAM", "issue": "No password policy set!"})

        except Exception as e:
            self.findings.append({"severity": "ERROR", "service": "IAM", "issue": str(e)})
        return self.findings
