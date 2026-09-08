"""
Fingerprinting: compares a freshly observed access point against the
last known "fingerprint" stored in the database for the same SSID,
and flags meaningful configuration drift (security downgrade, new
BSSID, channel/encryption change).
"""
from typing import List, Optional, Tuple

from app.scanner.models import WiFiNetwork, SECURITY_RANK
from app.security import rules


class FingerprintEngine:
    def compare(
        self, current: WiFiNetwork, last_known: Optional[dict]
    ) -> Tuple[float, List[str]]:
        """
        `last_known` is a dict as returned by Database.get_fingerprint()
        (keys: bssid, security_level, channel, encryption, band), or
        None if this SSID has never been seen before.
        """
        score = 0.0
        reasons: List[str] = []

        if last_known is None:
            return score, reasons  # brand new network: nothing to compare against

        if last_known["bssid"] == current.bssid:
            w = rules.get("fingerprint_stable_bonus", -10)
            score += w
            reasons.append(f"Matches previously known access point (stable fingerprint): {w}")
        else:
            w = rules.get("fingerprint_bssid_changed", 15)
            score += w
            reasons.append(
                f"BSSID differs from the last known access point for this SSID: +{w}"
            )

        prev_rank = SECURITY_RANK.get(last_known.get("security_level", "UNKNOWN"), -1)
        cur_rank = SECURITY_RANK.get(current.security_level, -1)
        if cur_rank < prev_rank:
            w = rules.get("fingerprint_security_downgrade", 30)
            score += w
            reasons.append(
                f"Security downgraded from {last_known['security_level']} to "
                f"{current.security_level} since last observation: +{w}"
            )
        else:
            w = rules.get("known_network_bonus", -5)
            score += w
            reasons.append(f"Previously known network with stable/improved security: {w}")

        if last_known.get("channel") is not None and current.channel != last_known["channel"]:
            w = rules.get("fingerprint_channel_changed", 5)
            score += w
            reasons.append(
                f"Channel changed from {last_known['channel']} to {current.channel}: +{w}"
            )

        if last_known.get("encryption") and current.encryption != last_known["encryption"]:
            w = rules.get("fingerprint_encryption_changed", 10)
            score += w
            reasons.append(
                f"Encryption changed from {last_known['encryption']} to {current.encryption}: +{w}"
            )

        return score, reasons
