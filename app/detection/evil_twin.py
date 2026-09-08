"""
Evil Twin / duplicate-SSID detection.

Looks across the CURRENT scan batch for multiple access points sharing
an SSID but differing in BSSID/security/encryption/band -- a classic
Evil Twin signature. This is a heuristic, not proof: legitimate
multi-AP setups (mesh networks, enterprise APs with many access
points) also share an SSID across many BSSIDs, so results are labeled
"Potential" / "Possible" and reported with reasons for a human to
review, never as a definitive verdict.
"""
from collections import defaultdict
from typing import Dict, List, Tuple

from app.scanner.models import WiFiNetwork, SECURITY_RANK
from app.security import rules


class EvilTwinDetector:
    def analyze_batch(self, networks: List[WiFiNetwork]) -> Dict[str, Tuple[float, List[str]]]:
        """
        Returns a mapping of bssid -> (score_delta, reasons) for every
        network in the batch that shows duplicate-SSID risk signals.
        """
        by_ssid: Dict[str, List[WiFiNetwork]] = defaultdict(list)
        for net in networks:
            if net.ssid and net.ssid != "<hidden>":
                by_ssid[net.ssid].append(net)

        results: Dict[str, Tuple[float, List[str]]] = {}

        for ssid, group in by_ssid.items():
            if len(group) < 2:
                continue

            bssids = {n.bssid for n in group}
            if len(bssids) < 2:
                continue  # same AP seen twice, not a duplicate

            security_levels = {n.security_level for n in group}
            encryptions = {n.encryption for n in group}
            bands = {n.band for n in group}
            strongest_security = self._strongest(security_levels)

            for net in group:
                score = 0.0
                reasons = []

                w = rules.get("duplicate_ssid_different_bssid", 15)
                score += w
                reasons.append(
                    f"SSID '{ssid}' seen on multiple access points (BSSIDs) in this scan: +{w}"
                )

                if net.security_level != strongest_security:
                    w = rules.get("duplicate_ssid_weaker_security", 25)
                    score += w
                    reasons.append(
                        f"This access point uses weaker security ({net.security_level}) than "
                        f"another access point with the same SSID ({strongest_security}): +{w}"
                    )

                if len(encryptions) > 1:
                    w = rules.get("duplicate_ssid_different_encryption", 8)
                    score += w
                    reasons.append(f"Duplicate SSID observed with inconsistent encryption: +{w}")

                if len(bands) > 1:
                    w = rules.get("duplicate_ssid_different_band", 5)
                    score += w
                    reasons.append(f"Duplicate SSID observed across different frequency bands: +{w}")

                results[net.bssid] = (score, reasons)

        return results

    @staticmethod
    def _strongest(levels: set) -> str:
        ranked = sorted(levels, key=lambda lvl: SECURITY_RANK.get(lvl, -1), reverse=True)
        return ranked[0] if ranked else "UNKNOWN"
