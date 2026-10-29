from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime

@dataclass
class NormalizedEvent:
    timestamp: datetime
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    user_id: Optional[str] = None
    host_name: Optional[str] = None
    command_line: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityAlert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    affected_host: Optional[str]
    mitre_technique: str
    description: str
    recommended_action: str
    evidence: Dict[str, Any]