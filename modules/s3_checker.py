#!/usr/bin/env python3
"""S3 Bucket Security Checker"""
import requests

class S3Checker:
    def __init__(self, bucket_name):
        self.bucket = bucket_name

    def check(self):
        result = {"bucket": self.bucket, "findings": []}
        urls = [
            f"https://{self.bucket}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{self.bucket}/",
        ]
        for url in urls:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    result["findings"].append({
                        "severity": "CRITICAL",
                        "issue": "Public S3 bucket - listing enabled",
                        "url": url
                    })
                    print(f"[!] CRITICAL: Public S3 bucket found: {url}")
                elif r.status_code == 403:
                    result["findings"].append({
                        "severity": "LOW",
                        "issue": "Bucket exists but access denied",
                        "url": url
                    })
                    print(f"[+] Bucket exists (403 - access denied): {url}")
            except Exception as e:
                print(f"[-] S3 check error: {e}")
        return result
