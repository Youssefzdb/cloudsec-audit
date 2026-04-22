#!/usr/bin/env python3
"""Cloud Security Reporter"""
import json
from datetime import datetime

class CloudSecReporter:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        total = sum(len(v) for v in self.results.values() if isinstance(v, list))
        report = {
            "engine": "cloudsec-audit v1.0",
            "generated": datetime.now().isoformat(),
            "total_findings": total,
            "results": self.results
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] {total} findings saved to {filename}")
