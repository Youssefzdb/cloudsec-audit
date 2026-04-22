#!/usr/bin/env python3
"""S3 Bucket Security Checker"""
try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class S3Checker:
    def __init__(self, profile="default"):
        self.profile = profile
        self.findings = []

    def check(self):
        if not HAS_BOTO3:
            return [{"severity": "INFO", "service": "S3", "issue": "boto3 not installed"}]
        try:
            session = boto3.Session(profile_name=self.profile)
            s3 = session.client("s3")
            buckets = s3.list_buckets()["Buckets"]
            print(f"[*] Checking {len(buckets)} S3 buckets...")

            for bucket in buckets:
                name = bucket["Name"]
                self._check_public_acl(s3, name)
                self._check_encryption(s3, name)
                self._check_versioning(s3, name)
        except Exception as e:
            self.findings.append({"severity": "ERROR", "service": "S3", "issue": str(e)})
        return self.findings

    def _check_public_acl(self, s3, name):
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl["Grants"]:
                if "AllUsers" in str(grant) or "AuthenticatedUsers" in str(grant):
                    self.findings.append({"severity": "CRITICAL", "service": "S3", "issue": f"Bucket {name} is PUBLIC!"})
                    print(f"[!] PUBLIC bucket: {name}")
                    return
            print(f"[+] {name}: ACL OK")
        except Exception as e:
            pass

    def _check_encryption(self, s3, name):
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception:
            self.findings.append({"severity": "MEDIUM", "service": "S3", "issue": f"Bucket {name} has no encryption"})

    def _check_versioning(self, s3, name):
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            if v.get("Status") != "Enabled":
                self.findings.append({"severity": "LOW", "service": "S3", "issue": f"Bucket {name} versioning disabled"})
        except Exception:
            pass
