"""Small shared helper functions."""
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp(value: float, low: float = 0, high: float = 100) -> float:
    return max(low, min(high, value))
