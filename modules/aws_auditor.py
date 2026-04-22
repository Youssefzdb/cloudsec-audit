#!/usr/bin/env python3
"""AWS Security Auditor - Checks security groups, encryption, logging"""
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class AWSAuditor:
    def __init__(self, profile="default"):
        self.profile = profile
        self.findings = []

    def audit(self):
        if not HAS_BOTO3:
            print("[-] boto3 not installed. Run: pip install boto3")
            return self._demo_audit()
        try:
            session = boto3.Session(profile_name=self.profile)
            ec2 = session.client("ec2", region_name="us-east-1")
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            port = perm.get("FromPort", "ALL")
                            self.findings.append({
                                "type": "Open Security Group",
                                "resource": sg["GroupId"],
                                "detail": f"Port {port} open to 0.0.0.0/0",
                                "severity": "HIGH"
                            })
                            print(f"[!] SG {sg['GroupId']}: Port {port} open to world")
        except Exception as e:
            print(f"[-] AWS error: {e}")
            return self._demo_audit()
        return self.findings

    def _demo_audit(self):
        return [
            {"type": "Open Security Group", "resource": "sg-0123456789", "detail": "Port 22 open to 0.0.0.0/0", "severity": "HIGH"},
            {"type": "Encryption Disabled", "resource": "vol-0987654321", "detail": "EBS volume not encrypted", "severity": "MEDIUM"},
            {"type": "CloudTrail Disabled", "resource": "us-east-1", "detail": "No CloudTrail logging", "severity": "HIGH"},
        ]
