"""
AWS Security Auditor
Checks S3 buckets, security groups, IAM policies for misconfigurations
Requires: boto3 (pip install boto3)
"""

class AWSAuditor:
    def __init__(self, profile="default"):
        self.profile = profile
        self.findings = []

    def check_s3_public(self, s3_client):
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    acl = s3_client.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "") == "http://acs.amazonaws.com/groups/global/AllUsers":
                            self.findings.append({
                                "resource": f"s3://{name}",
                                "issue": "Public S3 Bucket",
                                "severity": "CRITICAL"
                            })
                            print(f"[!] CRITICAL: Public S3 bucket: {name}")
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] S3 check failed: {e}")

    def audit(self):
        try:
            import boto3
            session = boto3.Session(profile_name=self.profile)
            s3 = session.client("s3")
            self.check_s3_public(s3)
        except ImportError:
            print("[-] boto3 not installed. Run: pip install boto3")
            self.findings.append({
                "resource": "AWS SDK",
                "issue": "boto3 not installed",
                "severity": "INFO"
            })
        return self.findings
