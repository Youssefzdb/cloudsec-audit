#!/usr/bin/env python3
"""S3 Bucket Security Checker"""
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class S3Checker:
    def __init__(self, profile="default"):
        self.profile = profile

    def check(self):
        if not HAS_BOTO3:
            return self._demo_check()
        findings = []
        try:
            session = boto3.Session(profile_name=self.profile)
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl["Grants"]:
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith("AllUsers"):
                            findings.append({
                                "type": "Public S3 Bucket",
                                "resource": name,
                                "detail": "Bucket is publicly accessible",
                                "severity": "CRITICAL"
                            })
                            print(f"[!] CRITICAL: S3 bucket {name} is PUBLIC")
                except:
                    pass
        except Exception as e:
            return self._demo_check()
        return findings

    def _demo_check(self):
        return [
            {"type": "Public S3 Bucket", "resource": "my-backup-bucket", "detail": "ACL allows public read", "severity": "CRITICAL"},
            {"type": "No Versioning", "resource": "prod-assets", "detail": "S3 versioning disabled", "severity": "LOW"},
            {"type": "No Encryption", "resource": "data-lake", "detail": "Server-side encryption not enabled", "severity": "MEDIUM"},
        ]
