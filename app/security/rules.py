"""
Loads risk-scoring weights and thresholds from config/risk_rules.json.

This module intentionally does NOT hardcode weights in Python: every
number that affects a risk score lives in the JSON file so it can be
tuned without touching code. If the file is missing or malformed, a
built-in DEFAULTS dict is used as a safe fallback and a warning is
logged (the app must never crash just because the config is absent).
"""
import json
from pathlib import Path
from typing import Any, Dict

from app.utils.logger import get_logger

log = get_logger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "risk_rules.json"

DEFAULTS: Dict[str, Any] = {
    "security_base_score": {
        "OPEN": 40, "WEP": 50, "WPA": 25, "WPA2": 10, "WPA3": 3, "UNKNOWN": 20
    },
    "enterprise_auth_bonus": -3,
    "unusually_strong_signal_threshold_percent": 90,
    "unusually_strong_signal_bonus": 5,
    "suspicious_ssid_keywords": ["free", "public", "guest", "airport", "open"],
    "suspicious_ssid_keyword_bonus": 6,
    "duplicate_ssid_different_bssid": 15,
    "duplicate_ssid_weaker_security": 25,
    "duplicate_ssid_different_encryption": 8,
    "duplicate_ssid_different_band": 5,
    "fingerprint_security_downgrade": 30,
    "fingerprint_bssid_changed": 15,
    "fingerprint_channel_changed": 5,
    "fingerprint_encryption_changed": 10,
    "fingerprint_stable_bonus": -10,
    "known_network_bonus": -5,
    "unknown_bssid_bonus": 10,
    "anomaly_threshold": 20,
    "risk_levels": {
        "VERY_LOW": [0, 20], "LOW": [21, 40], "MEDIUM": [41, 60],
        "HIGH": [61, 80], "CRITICAL": [81, 100],
    },
    "min_score": 0,
    "max_score": 100,
}


def _load() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        log.warning("risk_rules.json not found at %s — using built-in defaults.", CONFIG_PATH)
        return dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        merged = dict(DEFAULTS)
        merged.update({k: v for k, v in data.items() if not k.startswith("_")})
        return merged
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to load risk_rules.json (%s) — using built-in defaults.", exc)
        return dict(DEFAULTS)


_RULES = _load()


def reload_rules() -> None:
    """Re-reads config/risk_rules.json from disk. Call after editing it live."""
    global _RULES
    _RULES = _load()


def get(key: str, default: Any = None) -> Any:
    return _RULES.get(key, default)


# --- Convenience accessors mirroring the old constant names ---------------
def security_base_score(level: str) -> float:
    table = _RULES["security_base_score"]
    return table.get(level, table.get("UNKNOWN", 20))


def risk_level_from_score(score: float) -> str:
    """Returns one of VERY_LOW / LOW / MEDIUM / HIGH / CRITICAL (or UNKNOWN)."""
    for level, (low, high) in _RULES["risk_levels"].items():
        if low <= score <= high:
            return level
    return "UNKNOWN"


MIN_SCORE = _RULES["min_score"]
MAX_SCORE = _RULES["max_score"]
