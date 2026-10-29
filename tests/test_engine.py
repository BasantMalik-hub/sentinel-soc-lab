from datetime import datetime
from sentinel_soc.models import NormalizedEvent
from sentinel_soc.engine import DetectionEngine

def test_powershell_encoded_detection():
    engine = DetectionEngine({}, {"malicious_ips": []})
    event = NormalizedEvent(
        timestamp=datetime.now(),
        event_type="process_creation",
        command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABz...",
        host_name="WIN-SRV01"
    )
    engine.evaluate(event)
    assert len(engine.alerts) == 1
    assert engine.alerts[0].rule_id == "SOC-005"
    assert engine.alerts[0].severity == "HIGH"

def test_audit_tampering_critical_detection():
    engine = DetectionEngine({}, {"malicious_ips": []})
    event = NormalizedEvent(
        timestamp=datetime.now(),
        event_type="process_creation",
        command_line="wevtutil cl Security",
        host_name="WIN-SRV01"
    )
    engine.evaluate(event)
    assert len(engine.alerts) == 1
    assert engine.alerts[0].rule_id == "SOC-007"
    assert engine.alerts[0].severity == "CRITICAL"

def test_benign_negative_powershell_no_alert():
    """Negative Test: Standard administrative script should NOT trigger an alert."""
    engine = DetectionEngine({}, {"malicious_ips": []})
    event = NormalizedEvent(
        timestamp=datetime.now(),
        event_type="process_creation",
        command_line="powershell.exe -File C:\\Scripts\\backup.ps1",
        host_name="WIN-SRV01"
    )
    engine.evaluate(event)
    assert len(engine.alerts) == 0

def test_sub_threshold_auth_failure_no_alert():
    """Negative Test: 2 failed logins (below threshold of 5) should NOT trigger an alert."""
    config = {"auth_failure_threshold": 5, "auth_window_seconds": 120}
    engine = DetectionEngine(config, {"malicious_ips": []})
    for _ in range(2):
        event = NormalizedEvent(
            timestamp=datetime.now(),
            event_type="auth_failure",
            source_ip="192.168.1.100",
            host_name="WIN-SRV01"
        )
        engine.evaluate(event)
    assert len(engine.alerts) == 0