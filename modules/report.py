#!/usr/bin/env python3
from datetime import datetime

SEV_COLOR = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffcc00", "LOW": "#88cc00", "INFO": "#4488ff", "ERROR": "#ff44aa"}

class Report:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        all_findings = []
        for category, items in self.results.items():
            all_findings.extend(items)

        rows = "".join(
            f"<tr><td style='color:{SEV_COLOR.get(f.get(\"severity\",\"INFO\"),\"white\")}'>{f.get('severity')}</td><td>{f.get('service')}</td><td>{f.get('issue')}</td></tr>"
            for f in all_findings
        )
        html = f"""<!DOCTYPE html><html><head><title>CloudSec Audit</title>
<style>body{{font-family:Arial;background:#0f172a;color:#e2e8f0;padding:20px}}
h1{{color:#38bdf8}}table{{width:100%;border-collapse:collapse;margin:10px 0}}
td,th{{padding:8px;border:1px solid #1e293b}}th{{background:#1e293b}}</style></head>
<body><h1>Cloud Security Audit Report</h1>
<p>Findings: <b>{len(all_findings)}</b> | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<table><tr><th>Severity</th><th>Service</th><th>Issue</th></tr>
{rows if rows else '<tr><td colspan=3>No findings</td></tr>'}
</table></body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Saved: {filename}")
