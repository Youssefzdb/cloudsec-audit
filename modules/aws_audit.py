#!/usr/bin/env python3
"""AWS General Security Auditor"""
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class AWSAuditor:
    def __init__(self, profile="default"):
        self.profile = profile
        self.findings = []

    def _check_cloudtrail(self, session):
        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails()["trailList"]
            if not trails:
                self.findings.append({"severity": "HIGH", "service": "CloudTrail", "issue": "No trails configured - no audit logging!"})
            for trail in trails:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging"):
                    self.findings.append({"severity": "HIGH", "service": "CloudTrail", "issue": f"Trail {trail['Name']} is NOT logging"})
                else:
                    print(f"[+] CloudTrail {trail['Name']}: logging enabled")
        except Exception as e:
            self.findings.append({"severity": "INFO", "service": "CloudTrail", "issue": f"Check failed: {e}"})

    def _check_guardduty(self, session):
        try:
            gd = session.client("guardduty")
            detectors = gd.list_detectors()["DetectorIds"]
            if not detectors:
                self.findings.append({"severity": "HIGH", "service": "GuardDuty", "issue": "GuardDuty not enabled in this region!"})
            else:
                print(f"[+] GuardDuty: {len(detectors)} detector(s) active")
        except Exception as e:
            self.findings.append({"severity": "INFO", "service": "GuardDuty", "issue": f"Check failed: {e}"})

    def audit(self):
        if not HAS_BOTO3:
            self.findings.append({"severity": "INFO", "service": "AWS", "issue": "boto3 not installed. Run: pip install boto3"})
            return self.findings
        try:
            session = boto3.Session(profile_name=self.profile)
            self._check_cloudtrail(session)
            self._check_guardduty(session)
        except Exception as e:
            self.findings.append({"severity": "ERROR", "service": "AWS", "issue": str(e)})
        return self.findings
