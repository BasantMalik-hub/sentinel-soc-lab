import json
from datetime import datetime
from typing import Iterator
from .models import NormalizedEvent

class TelemetryNormalizer:
    @staticmethod
    def parse_iso(ts_str: str) -> datetime:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

    def normalize_stream(self, filepath: str) -> Iterator[NormalizedEvent]:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    yield NormalizedEvent(
                        timestamp=self.parse_iso(raw.get("timestamp")),
                        event_type=raw.get("event_type", "unknown"),
                        source_ip=raw.get("source_ip"),
                        destination_ip=raw.get("destination_ip"),
                        destination_port=raw.get("destination_port"),
                        user_id=raw.get("user_id"),
                        host_name=raw.get("host_name"),
                        command_line=raw.get("command_line"),
                        raw_data=raw
                    )
                except Exception as e:
                    print(f"[-] Warning: Failed to parse line {line_no}: {e}")