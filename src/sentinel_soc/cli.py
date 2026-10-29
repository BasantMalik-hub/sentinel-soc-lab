import argparse
import json
import sys
import os
from .normalizer import TelemetryNormalizer
from .engine import DetectionEngine
from .reporter import AlertReporter

def main():
    parser = argparse.ArgumentParser(description="Sentinel SOC Detection Pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze logs for threats")
    analyze_parser.add_argument("--input", required=True, help="Path to input .jsonl file")
    analyze_parser.add_argument("--output-dir", default="output", help="Directory for reports")

    args = parser.parse_args()

    if args.command == "analyze":
        if not os.path.exists("config/rules.json") or not os.path.exists("config/iocs.json"):
            print("[-] Error: Missing config/rules.json or config/iocs.json")
            sys.exit(1)

        with open("config/rules.json") as f:
            config = json.load(f)
        with open("config/iocs.json") as f:
            iocs = json.load(f)

        normalizer = TelemetryNormalizer()
        engine = DetectionEngine(config, iocs)

        print(f"[*] Processing telemetry from: {args.input}")
        count = 0
        for event in normalizer.normalize_stream(args.input):
            engine.evaluate(event)
            count += 1

        print(f"[+] Total Events Analyzed: {count}")
        print(f"[!] Threat Detections Fired: {len(engine.alerts)}")

        reporter = AlertReporter(engine.alerts, args.output_dir)
        reporter.generate_all()
        print(f"[+] Artifacts generated successfully in '{args.output_dir}/'")

if __name__ == "__main__":
    main()