"""
Base security analysis: evaluates a single WiFiNetwork in isolation,
without any historical context. Produces a base score + reasons.
All weights come from app.security.rules (backed by config/risk_rules.json).
"""
from typing import List, Tuple
from app.scanner.models import WiFiNetwork
from app.security import rules


class SecurityAnalyzer:
    """Analyzes intrinsic properties of a single observed network."""

    def analyze(self, network: WiFiNetwork) -> Tuple[float, List[str]]:
        score = 0.0
        reasons: List[str] = []

        base = rules.security_base_score(network.security_level)
        score += base
        auth_label = network.authentication or network.security_level
        reasons.append(f"Base risk for {auth_label} security: +{base}")

        if network.is_enterprise:
            bonus = rules.get("enterprise_auth_bonus", 0)
            score += bonus
            reasons.append(f"Enterprise authentication (centrally managed): {bonus}")

        threshold = rules.get("unusually_strong_signal_threshold_percent", 90)
        if network.signal_percent is not None and network.signal_percent >= threshold:
            bonus = rules.get("unusually_strong_signal_bonus", 5)
            score += bonus
            reasons.append(
                f"Unusually strong signal ({network.signal_percent}%) suggests a nearby device: +{bonus}"
            )

        keywords = rules.get("suspicious_ssid_keywords", [])
        ssid_lower = (network.ssid or "").lower()
        if any(keyword in ssid_lower for keyword in keywords):
            bonus = rules.get("suspicious_ssid_keyword_bonus", 6)
            score += bonus
            reasons.append(f"SSID contains a commonly spoofed keyword: +{bonus}")

        return score, reasons
