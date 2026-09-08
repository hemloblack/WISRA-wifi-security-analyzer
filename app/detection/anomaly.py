"""
Lightweight anomaly detection layer.

Combines fingerprint drift + duplicate-SSID signals into a single
per-network "is this behaving normally?" verdict, mainly used for the
ANOMALY flag surfaced in the API/UI. Threshold is configurable via
config/risk_rules.json (anomaly_threshold).
"""
from typing import List
from app.security import rules


class AnomalyDetector:
    def is_anomalous(self, combined_delta: float, reasons: List[str]) -> bool:
        threshold = rules.get("anomaly_threshold", 20)
        return combined_delta >= threshold and len(reasons) > 0
