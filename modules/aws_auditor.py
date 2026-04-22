#!/usr/bin/env python3
"""AWS Security Auditor - Check common AWS misconfigurations"""
try:
    import boto3
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

class AWSAuditor:
    def __init__(self):
        self.findings = []

    def _check_s3_public(self):
        if not HAS_BOTO:
            return []
        try:
            s3 = boto3.client("s3")
            buckets = s3.list_buckets()["Buckets"]
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl["Grants"]:
                        if "AllUsers" in grant["Grantee"].get("URI", ""):
                            self.findings.append({
                                "type": "Public S3 Bucket",
                                "resource": name,
                                "severity": "CRITICAL"
                            })
                            print(f"[!] PUBLIC S3 BUCKET: {name}")
                except:
                    pass
        except Exception as e:
            self.findings.append({"type": "Error", "message": str(e)})
        return self.findings

    def _check_security_groups(self):
        if not HAS_BOTO:
            return []
        try:
            ec2 = boto3.client("ec2")
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    for cidr in rule.get("IpRanges", []):
                        if cidr.get("CidrIp") == "0.0.0.0/0":
                            port = rule.get("FromPort", "ALL")
                            self.findings.append({
                                "type": "Open Security Group",
                                "resource": sg["GroupId"],
                                "port": port,
                                "severity": "HIGH"
                            })
        except:
            pass
        return self.findings

    def audit(self):
        print("[*] Auditing AWS infrastructure...")
        self._check_s3_public()
        self._check_security_groups()
        print(f"[+] Found {len(self.findings)} AWS issues")
        return self.findings
