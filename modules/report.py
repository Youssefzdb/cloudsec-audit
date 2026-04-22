#!/usr/bin/env python3
"""Cloud Security Report Generator"""
from datetime import datetime
import json

class CloudReport:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        findings_html = ""
        for section, data in self.results.items():
            findings_html += f"<h2>{section.upper()}</h2>"
            if isinstance(data, list):
                for f in data:
                    severity = f.get("severity", "INFO")
                    color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44aaff", "INFO": "#888"}.get(severity, "#888")
                    findings_html += f"<div style='border-left:4px solid {color};padding:10px;margin:5px 0;background:#0f1923'>"
                    findings_html += f"<span style='color:{color}'>[{severity}]</span> <b>{f.get('check','')}</b><br>"
                    findings_html += f"<small>{f.get('desc','')}{f.get('issue','')}</small></div>"

        html = f"""<!DOCTYPE html>
<html>
<head><title>CloudSec Audit Report</title>
<style>
body{{font-family:Arial;background:#07111a;color:#cce0ff;padding:20px}}
h1{{color:#00aaff}} h2{{color:#4fc3f7;margin-top:20px}}
</style></head>
<body>
<h1>CloudSec Audit Report</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
{findings_html}
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Cloud report saved: {filename}")
