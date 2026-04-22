#!/usr/bin/env python3
"""IAM Policy Analyzer"""
import subprocess
import json

class IAMAnalyzer:
    def analyze(self):
        findings = []
        print("[*] Analyzing IAM policies...")
        try:
            result = subprocess.run(
                ["aws", "iam", "list-users"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                users = json.loads(result.stdout).get("Users", [])
                print(f"[+] Found {len(users)} IAM users")
                for user in users:
                    uname = user.get("UserName")
                    keys_result = subprocess.run(
                        ["aws", "iam", "list-access-keys", "--user-name", uname],
                        capture_output=True, text=True, timeout=10
                    )
                    if keys_result.returncode == 0:
                        keys = json.loads(keys_result.stdout).get("AccessKeyMetadata", [])
                        for key in keys:
                            if key.get("Status") == "Active":
                                findings.append({
                                    "check": "Active Access Key",
                                    "user": uname,
                                    "key_id": key.get("AccessKeyId"),
                                    "severity": "INFO"
                                })
        except FileNotFoundError:
            print("[-] AWS CLI not installed. Install: pip install awscli")
        return findings
