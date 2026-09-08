"""
Risk Engine: orchestrates SecurityAnalyzer + EvilTwinDetector +
FingerprintEngine + AnomalyDetector to produce one explainable
Risk Score (0-100) per access point.

IMPORTANT: a high score means "suspicious / worth a second look", not
"this network has definitely been compromised or is spying on you".
Passive Wi-Fi metadata alone cannot prove malicious intent — see the
README section "Why WISRA cannot prove a network is malicious".
"""
from dataclasses import dataclass, field
from typing import List, Optional

from app.scanner.models import WiFiNetwork
from app.security.security_analyzer import SecurityAnalyzer
from app.security import rules
from app.detection.evil_twin import EvilTwinDetector
from app.detection.fingerprint import FingerprintEngine
from app.detection.anomaly import AnomalyDetector
from app.utils.helpers import clamp


@dataclass
class RiskAssessment:
    ssid: str
    bssid: str
    score: float
    level: str
    is_anomalous: bool
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "risk_score": round(self.score, 1),
            "risk_level": self.level,
            "anomaly": self.is_anomalous,
            "reasons": self.reasons,
        }


class RiskEngine:
    def __init__(self, database=None):
        self.security_analyzer = SecurityAnalyzer()
        self.evil_twin_detector = EvilTwinDetector()
        self.fingerprint_engine = FingerprintEngine()
        self.anomaly_detector = AnomalyDetector()
        self.database = database  # optional; enables fingerprint history

    def assess_batch(self, networks: List[WiFiNetwork]) -> List[RiskAssessment]:
        evil_twin_results = self.evil_twin_detector.analyze_batch(networks)

        assessments = []
        for network in networks:
            assessments.append(self._assess_single(network, evil_twin_results))
        return assessments

    def _assess_single(self, network: WiFiNetwork, evil_twin_results: dict) -> RiskAssessment:
        total_score = 0.0
        reasons: List[str] = []
        drift_score = 0.0  # fingerprint + evil-twin contribution, used for the anomaly flag

        base_score, base_reasons = self.security_analyzer.analyze(network)
        total_score += base_score
        reasons.extend(base_reasons)

        if network.bssid in evil_twin_results:
            et_score, et_reasons = evil_twin_results[network.bssid]
            total_score += et_score
            drift_score += et_score
            reasons.extend(et_reasons)

        if self.database is not None:
            last_known = self.database.get_fingerprint(network.ssid)
            fp_score, fp_reasons = self.fingerprint_engine.compare(network, last_known)
            total_score += fp_score
            drift_score += max(fp_score, 0)
            reasons.extend(fp_reasons)

        total_score = clamp(total_score, rules.MIN_SCORE, rules.MAX_SCORE)
        level = rules.risk_level_from_score(total_score)
        anomalous = self.anomaly_detector.is_anomalous(drift_score, reasons)

        return RiskAssessment(
            ssid=network.ssid,
            bssid=network.bssid,
            score=total_score,
            level=level,
            is_anomalous=anomalous,
            reasons=reasons,
        )
