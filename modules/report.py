#!/usr/bin/env python3
from datetime import datetime

class CloudReport:
    def __init__(self, provider, findings):
        self.provider = provider
        self.findings = findings

    def save(self, filename):
        severity_colors = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffaa00", "LOW": "#00aa00"}
        rows = ""
        for f in self.findings:
            color = severity_colors.get(f.get("severity",""), "#ffffff")
            rows += f"<tr><td>{f.get('service','')}</td><td>{f.get('resource','')}</td><td style='color:{color}'><b>{f.get('severity','')}</b></td><td>{f.get('issue','')}</td></tr>"
        
        html = f"""<!DOCTYPE html><html><head><title>CloudSec Audit</title>
<style>body{{font-family:Arial;background:#0f1117;color:#e2e8f0;padding:20px}}
h1{{color:#38bdf8}}table{{width:100%;border-collapse:collapse}}
td,th{{padding:10px;border:1px solid #1e293b;text-align:left}}th{{background:#1e3a5f}}</style></head>
<body><h1>CloudSec Audit Report — {self.provider.upper()}</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M')} | Total findings: <b>{len(self.findings)}</b></p>
<table><tr><th>Service</th><th>Resource</th><th>Severity</th><th>Issue</th></tr>
{rows}</table></body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Report saved: {filename}")
