# Sentinel SOC Lab: Lightweight Detection Engineering & SIEM Pipeline

[![Detection Engine CI](https://github.com/BasantMalik-hub/sentinel-soc-lab/actions/workflows/tests.yml/badge.svg?branch=main&event=push)](https://github.com/BasantMalik-hub/sentinel-soc-lab/actions/workflows/tests.yml)

🌐 **Live SOC Dashboard Demo:** https://basantmalik-hub.github.io/sentinel-soc-lab/

A lightweight, test-driven Security Operations Center (SOC) detection engine built in Python. The project normalizes heterogeneous security telemetry, evaluates time-window correlation rules, matches indicators against threat intelligence feeds, and generates actionable triage outputs (JSON, CSV, HTML Dashboard).

---

## Architecture Overview

```text
[ Raw Telemetry (.jsonl) ] ──> [ Normalizer ] ──> [ Canonical Events ]
                                                         │
                                                         ▼
                                           [ Stateful Detection Engine ]
                                           ├── Sliding Memory Windows (120s / 60s)
                                           ├── Pattern / Heuristic Analysis
                                           └── IOC Threat Intel Correlation
                                                         │
                                                         ▼
                                           [ Enriched Security Alerts ]
                                                         │
                     ┌───────────────────────────────────┼───────────────────────────────────┐
                     ▼                                   ▼                                   ▼
             [ alerts.json ]                      [ alerts.csv ]                      [ report.html ]