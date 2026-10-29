import json
import csv
import os
from typing import List
from .models import SecurityAlert

class AlertReporter:
    def __init__(self, alerts: List[SecurityAlert], output_dir: str):
        self.alerts = alerts
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(self):
        self.export_json()
        self.export_csv()
        self.export_html()

    def export_json(self):
        data = [
            {
                "alert_id": a.alert_id,
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat(),
                "affected_host": a.affected_host,
                "mitre_technique": a.mitre_technique,
                "description": a.description,
                "recommended_action": a.recommended_action,
                "evidence": a.evidence
            } for a in self.alerts
        ]
        with open(os.path.join(self.output_dir, "alerts.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def export_csv(self):
        with open(os.path.join(self.output_dir, "alerts.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Alert ID", "Severity", "Rule ID", "Rule Name", "Timestamp", "Affected Host", "MITRE ID"])
            for a in self.alerts:
                writer.writerow([a.alert_id, a.severity, a.rule_id, a.rule_name, a.timestamp.isoformat(), a.affected_host, a.mitre_technique])

    def export_html(self):
        rows = "".join([f"""
            <tr class="{a.severity.lower()}">
                <td><span class="badge {a.severity.lower()}">{a.severity}</span></td>
                <td>{a.rule_id}</td>
                <td><strong>{a.rule_name}</strong></td>
                <td>{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{a.affected_host or 'N/A'}</td>
                <td><code>{a.mitre_technique}</code></td>
                <td>{a.description}</td>
                <td>{a.recommended_action}</td>
            </tr>
        """ for a in self.alerts])

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Sentinel SOC Lab - Incident Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 2rem; }}
        h1 {{ color: #38bdf8; margin-bottom: 0.25rem; }}
        p {{ color: #94a3b8; margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; display: inline-block; }}
        .badge.critical {{ background: #dc2626; color: white; }}
        .badge.high {{ background: #ea580c; color: white; }}
        .badge.medium {{ background: #ca8a04; color: white; }}
        code {{ background: #334155; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
    </style>
</head>
<body>
    <h1>Sentinel SOC - Incident Detection Summary</h1>
    <p>Pipeline run complete. Total alerts generated: <strong style="color: #38bdf8;">{len(self.alerts)}</strong></p>
    <table>
        <thead>
            <tr>
                <th>Severity</th><th>Rule ID</th><th>Rule Name</th><th>Timestamp</th>
                <th>Affected Host</th><th>MITRE ATT&CK</th><th>Description</th><th>Analyst Action</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""
        with open(os.path.join(self.output_dir, "report.html"), "w", encoding="utf-8") as f:
            f.write(html_content)