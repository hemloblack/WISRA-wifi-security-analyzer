"""
Data models for scanned Wi-Fi networks.

Every field here maps directly to something `netsh` reports on
Windows. Nothing is invented: if Windows/the adapter doesn't expose a
value, the field stays None and callers/UI must render that as
"Unknown" / "N/A" — never a guessed value.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# Normalized security levels, ranked weakest -> strongest.
SECURITY_RANK = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4, "UNKNOWN": -1}


@dataclass
class WiFiNetwork:
    """Represents a single observed Wi-Fi access point (one BSSID)."""

    ssid: str                              # "<hidden>" if broadcast SSID is empty
    bssid: str                             # MAC address of this specific AP, uppercase
    signal_percent: Optional[int] = None   # 0-100, as reported by Windows (not dBm)
    channel: Optional[int] = None
    band: Optional[str] = None             # "2.4GHz" / "5GHz" / "6GHz" — derived from channel, best-effort
    radio_type: Optional[str] = None       # e.g. "802.11ac", "802.11ax"
    authentication: Optional[str] = None   # raw Windows string, e.g. "WPA2-Personal"
    encryption: Optional[str] = None       # raw Windows string, e.g. "CCMP"
    security_level: str = "UNKNOWN"        # normalized: OPEN/WEP/WPA/WPA2/WPA3/UNKNOWN
    is_enterprise: bool = False
    connected: bool = False                # True if this is the currently associated network
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def band_from_channel(channel: Optional[int]) -> Optional[str]:
        """
        Best-effort band inference from channel number alone (Windows'
        `netsh wlan show networks` does not report band directly).
        Channel numbering overlaps between 2.4GHz/5GHz/6GHz in some
        ranges, so this is an approximation, not a certainty.
        """
        if channel is None:
            return None
        if 1 <= channel <= 14:
            return "2.4GHz"
        if 36 <= channel <= 177:
            return "5GHz"
        if channel > 177:
            return "6GHz"
        return None

    @staticmethod
    def normalize_authentication(raw: Optional[str]) -> "tuple[str, bool]":
        """
        Maps a raw Windows Authentication string (e.g. 'WPA2-Personal',
        'WPA3-Enterprise', 'Open', 'Shared') to a normalized security
        level plus an is_enterprise flag. Returns (level, is_enterprise).
        """
        if not raw:
            return "UNKNOWN", False
        text = raw.upper()
        is_enterprise = "ENTERPRISE" in text

        if "OPEN" in text:
            return "OPEN", is_enterprise
        if "WPA3" in text:
            return "WPA3", is_enterprise
        if "WPA2" in text:
            return "WPA2", is_enterprise
        if "WPA" in text:
            return "WPA", is_enterprise
        if "WEP" in text or "SHARED" in text:
            return "WEP", is_enterprise
        return "UNKNOWN", is_enterprise
