import uuid
from typing import List
from datetime import datetime
from collections import defaultdict
from .models import NormalizedEvent, SecurityAlert

class DetectionEngine:
    def __init__(self, config: dict, iocs: dict):
        self.config = config
        self.iocs = set(iocs.get("malicious_ips", []))
        self.auth_failures = defaultdict(list)
        self.port_scans = defaultdict(lambda: defaultdict(set))
        self.alerts: List[SecurityAlert] = []

    def evaluate(self, event: NormalizedEvent):
        self._check_ioc_match(event)
        self._check_powershell_obfuscation(event)
        self._check_audit_tampering(event)
        self._check_privilege_escalation(event)
        self._check_authentication_anomalies(event)
        self._check_port_scanning(event)

    def _check_ioc_match(self, e: NormalizedEvent):
        target = e.destination_ip or e.source_ip
        if target and target in self.iocs:
            self._create_alert(
                rule_id="SOC-004",
                rule_name="C2 Communication / Malicious IOC Hit",
                severity="HIGH",
                event=e,
                mitre="T1071 - Application Layer Protocol",
                desc=f"Observed network traffic with known malicious C2 indicator: {target}",
                action="Block source/destination IP on perimeter firewall immediately."
            )

    def _check_powershell_obfuscation(self, e: NormalizedEvent):
        if e.command_line and "powershell" in e.command_line.lower():
            cmd = e.command_line.lower()
            if any(flag in cmd for flag in ["-encodedcommand", "-enc ", "-e "]):
                self._create_alert(
                    rule_id="SOC-005",
                    rule_name="Suspicious Encoded PowerShell Execution",
                    severity="HIGH",
                    event=e,
                    mitre="T1059.001 - PowerShell",
                    desc="PowerShell launched with base64 encoded command arguments.",
                    action="Isolate host from network; decode command payload for forensic analysis."
                )

    def _check_audit_tampering(self, e: NormalizedEvent):
        if e.command_line and "wevtutil" in e.command_line.lower():
            if "cl " in e.command_line.lower() or "clear-log" in e.command_line.lower():
                self._create_alert(
                    rule_id="SOC-007",
                    rule_name="Security Audit Log Tampering",
                    severity="CRITICAL",
                    event=e,
                    mitre="T1070.001 - Clear Windows Event Logs",
                    desc="System log clearing command executed (wevtutil cl).",
                    action="CRITICAL: Threat actor may be covering tracks. Triage host immediately."
                )

    def _check_privilege_escalation(self, e: NormalizedEvent):
        if e.command_line and "net localgroup administrators" in e.command_line.lower() and "/add" in e.command_line.lower():
            self._create_alert(
                rule_id="SOC-006",
                rule_name="Privileged Group Modification",
                severity="HIGH",
                event=e,
                mitre="T1098 - Account Manipulation",
                desc="User account was added to local Administrators group.",
                action="Verify change authorization with system owner; revert membership if unauthorized."
            )

    def _check_authentication_anomalies(self, e: NormalizedEvent):
        if e.event_type == "auth_failure" and e.source_ip:
            self.auth_failures[e.source_ip].append(e.timestamp)
            cutoff = e.timestamp.timestamp() - self.config["auth_window_seconds"]
            self.auth_failures[e.source_ip] = [
                t for t in self.auth_failures[e.source_ip] if t.timestamp() >= cutoff
            ]
            
            if len(self.auth_failures[e.source_ip]) == self.config["auth_failure_threshold"]:
                self._create_alert(
                    rule_id="SOC-001",
                    rule_name="Repeated Authentication Failures (Brute Force)",
                    severity="HIGH",
                    event=e,
                    mitre="T1110 - Brute Force",
                    desc=f"{self.config['auth_failure_threshold']} logon failures detected within time window.",
                    action="Rate limit / block source IP; audit targeted user accounts."
                )

        elif e.event_type == "auth_success" and e.source_ip in self.auth_failures:
            if len(self.auth_failures[e.source_ip]) >= self.config["auth_failure_threshold"] - 2:
                self._create_alert(
                    rule_id="SOC-002",
                    rule_name="Successful Logon Post-Failure Spike (Account Compromise)",
                    severity="HIGH",
                    event=e,
                    mitre="T1110.001 - Password Guessing",
                    desc="Successful authentication observed immediately after repeated failures.",
                    action="Force password reset for target user; terminate active sessions."
                )

    def _check_port_scanning(self, e: NormalizedEvent):
        if e.event_type == "network_connection" and e.source_ip and e.destination_port:
            key = (e.source_ip, e.destination_ip)
            ports = self.port_scans[key]
            ports[e.timestamp].add(e.destination_port)
            
            cutoff = e.timestamp.timestamp() - self.config["port_scan_window_seconds"]
            recent_ports = set()
            for t, p_set in list(ports.items()):
                if t.timestamp() < cutoff:
                    del ports[t]
                else:
                    recent_ports.update(p_set)
            
            if len(recent_ports) == self.config["port_scan_threshold"]:
                self._create_alert(
                    rule_id="SOC-003",
                    rule_name="Horizontal Port Scanning Detected",
                    severity="MEDIUM",
                    event=e,
                    mitre="T1046 - Network Service Discovery",
                    desc=f"Probing of {len(recent_ports)} distinct ports observed from {e.source_ip}.",
                    action="Check firewall drops; investigate potential reconnaissance host."
                )

    def _create_alert(self, rule_id, rule_name, severity, event, mitre, desc, action):
        self.alerts.append(SecurityAlert(
            alert_id=str(uuid.uuid4())[:8],
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            timestamp=event.timestamp,
            affected_host=event.host_name or event.destination_ip,
            mitre_technique=mitre,
            description=desc,
            recommended_action=action,
            evidence=event.raw_data
        ))