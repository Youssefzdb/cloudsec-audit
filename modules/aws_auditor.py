#!/usr/bin/env python3
"""AWS Security Auditor - Checks IAM, S3, SGs, CloudTrail"""
import subprocess
import json

class AWSAuditor:
    def __init__(self, profile="default"):
        self.profile = profile
        self.findings = []

    def _run_aws(self, cmd):
        try:
            result = subprocess.run(
                ["aws"] + cmd + ["--profile", self.profile, "--output", "json"],
                capture_output=True, text=True, timeout=15
            )
            return json.loads(result.stdout) if result.stdout else {}
        except:
            return {}

    def check_s3_public(self):
        print("[*] Checking S3 buckets for public access...")
        data = self._run_aws(["s3api", "list-buckets"])
        buckets = data.get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            acl = self._run_aws(["s3api", "get-bucket-acl", "--bucket", name])
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if "AllUsers" in grantee.get("URI", ""):
                    self.findings.append({
                        "resource": f"s3://{name}",
                        "issue": "Bucket is publicly accessible",
                        "severity": "CRITICAL",
                        "service": "S3"
                    })
                    print(f"[!] CRITICAL: S3 bucket {name} is PUBLIC")

    def check_iam_users(self):
        print("[*] Checking IAM users for MFA and access keys...")
        data = self._run_aws(["iam", "generate-credential-report"])
        report = self._run_aws(["iam", "get-credential-report"])
        import base64
        content = base64.b64decode(report.get("Content","")).decode() if report.get("Content") else ""
        for line in content.splitlines()[1:]:
            parts = line.split(",")
            if len(parts) > 7:
                user = parts[0]
                mfa = parts[7]
                if mfa == "false":
                    self.findings.append({
                        "resource": f"iam:user:{user}",
                        "issue": "MFA not enabled",
                        "severity": "HIGH",
                        "service": "IAM"
                    })
                    print(f"[!] HIGH: IAM user {user} has no MFA")

    def check_security_groups(self):
        print("[*] Checking Security Groups for open ports...")
        data = self._run_aws(["ec2", "describe-security-groups"])
        for sg in data.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = perm.get("FromPort", "all")
                        self.findings.append({
                            "resource": f"sg:{sg['GroupId']}",
                            "issue": f"Port {port} open to 0.0.0.0/0",
                            "severity": "HIGH",
                            "service": "EC2/SG"
                        })
                        print(f"[!] HIGH: SG {sg['GroupId']} port {port} open to world")

    def check_cloudtrail(self):
        print("[*] Checking CloudTrail logging...")
        data = self._run_aws(["cloudtrail", "describe-trails"])
        trails = data.get("trailList", [])
        if not trails:
            self.findings.append({
                "resource": "cloudtrail",
                "issue": "No CloudTrail trails configured",
                "severity": "HIGH",
                "service": "CloudTrail"
            })
        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                self.findings.append({
                    "resource": trail.get("TrailARN", ""),
                    "issue": "CloudTrail not multi-region",
                    "severity": "MEDIUM",
                    "service": "CloudTrail"
                })

    def audit(self):
        self.check_s3_public()
        self.check_iam_users()
        self.check_security_groups()
        self.check_cloudtrail()
        print(f"[+] AWS audit complete: {len(self.findings)} findings")
        return self.findings
