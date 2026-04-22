#!/usr/bin/env python3
"""AWS Security Auditor - Check common AWS misconfigurations"""
import subprocess
import json

class AWSAuditor:
    def audit(self):
        findings = []
        checks = [
            self._check_mfa_root,
            self._check_password_policy,
            self._check_cloudtrail,
        ]
        for check in checks:
            try:
                result = check()
                if result:
                    findings.append(result)
            except Exception as e:
                print(f"[-] Check failed: {e}")
        return findings

    def _check_mfa_root(self):
        print("[*] Checking root MFA status...")
        try:
            result = subprocess.run(
                ["aws", "iam", "get-account-summary"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                mfa = data.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
                if mfa == 0:
                    print("[!] CRITICAL: Root account MFA is NOT enabled!")
                    return {"check": "Root MFA", "status": "FAIL", "severity": "CRITICAL",
                            "desc": "Root account has no MFA enabled"}
                print("[+] Root MFA: OK")
        except FileNotFoundError:
            print("[-] AWS CLI not installed")
        return None

    def _check_password_policy(self):
        print("[*] Checking IAM password policy...")
        try:
            result = subprocess.run(
                ["aws", "iam", "get-account-password-policy"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                print("[!] HIGH: No password policy configured!")
                return {"check": "Password Policy", "status": "FAIL", "severity": "HIGH",
                        "desc": "No IAM password policy configured"}
            data = json.loads(result.stdout).get("PasswordPolicy", {})
            if not data.get("RequireUppercaseCharacters"):
                return {"check": "Password Policy", "status": "WARN", "severity": "MEDIUM",
                        "desc": "Password policy does not require uppercase characters"}
        except FileNotFoundError:
            print("[-] AWS CLI not installed")
        return None

    def _check_cloudtrail(self):
        print("[*] Checking CloudTrail status...")
        try:
            result = subprocess.run(
                ["aws", "cloudtrail", "describe-trails"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                trails = data.get("trailList", [])
                if not trails:
                    print("[!] HIGH: No CloudTrail configured!")
                    return {"check": "CloudTrail", "status": "FAIL", "severity": "HIGH",
                            "desc": "No CloudTrail logging configured"}
        except FileNotFoundError:
            print("[-] AWS CLI not installed")
        return None
