"""
SQLite persistence layer.

Tables: networks (one per SSID), access_points (one per BSSID under a
network), observations (one row per scan snapshot of an AP),
risk_assessments (one row per computed score), fingerprints (latest
known configuration per SSID, used as the drift-detection baseline).
"""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional

from app.database.models import SCHEMA
from app.scanner.models import WiFiNetwork
from app.security.risk_engine import RiskAssessment
from app.utils.helpers import now_iso
from app.utils.logger import get_logger

log = get_logger(__name__)

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "wifi_analyzer.db"


class Database:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def record_observation(self, network: WiFiNetwork) -> int:
        """
        Upserts the network + access_point rows for this observation,
        inserts an observations row, and returns the access_point id.
        """
        ts = now_iso()
        with self._connect() as conn:
            network_id = self._upsert_network(conn, network.ssid, ts)
            ap_id = self._upsert_access_point(conn, network_id, network.bssid, ts)

            conn.execute(
                """INSERT INTO observations
                   (access_point_id, timestamp, signal_percent, channel, band,
                    radio_type, authentication, encryption, security_level, connected)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ap_id, ts, network.signal_percent, network.channel, network.band,
                 network.radio_type, network.authentication, network.encryption,
                 network.security_level, int(network.connected)),
            )
            return ap_id

    @staticmethod
    def _upsert_network(conn, ssid: str, ts: str) -> int:
        cur = conn.execute("SELECT id FROM networks WHERE ssid = ?", (ssid,))
        row = cur.fetchone()
        if row:
            conn.execute("UPDATE networks SET last_seen = ? WHERE id = ?", (ts, row["id"]))
            return row["id"]
        cur = conn.execute(
            "INSERT INTO networks (ssid, first_seen, last_seen) VALUES (?, ?, ?)",
            (ssid, ts, ts),
        )
        return cur.lastrowid

    @staticmethod
    def _upsert_access_point(conn, network_id: int, bssid: str, ts: str) -> int:
        cur = conn.execute(
            "SELECT id, observation_count FROM access_points WHERE network_id = ? AND bssid = ?",
            (network_id, bssid),
        )
        row = cur.fetchone()
        if row:
            conn.execute(
                "UPDATE access_points SET last_seen = ?, observation_count = ? WHERE id = ?",
                (ts, row["observation_count"] + 1, row["id"]),
            )
            return row["id"]
        cur = conn.execute(
            """INSERT INTO access_points (network_id, bssid, first_seen, last_seen, observation_count)
               VALUES (?, ?, ?, ?, 1)""",
            (network_id, bssid, ts, ts),
        )
        return cur.lastrowid

    def save_risk_assessment(self, access_point_id: int, assessment: RiskAssessment):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO risk_assessments
                   (access_point_id, score, level, anomaly, reasons, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (access_point_id, assessment.score, assessment.level,
                 int(assessment.is_anomalous), json.dumps(assessment.reasons), now_iso()),
            )

    def update_fingerprint(self, network: WiFiNetwork):
        """Overwrites the stored fingerprint baseline for this SSID."""
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO fingerprints (ssid, bssid, security_level, encryption, channel, band, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ssid) DO UPDATE SET
                     bssid=excluded.bssid, security_level=excluded.security_level,
                     encryption=excluded.encryption, channel=excluded.channel,
                     band=excluded.band, updated_at=excluded.updated_at""",
                (network.ssid, network.bssid, network.security_level, network.encryption,
                 network.channel, network.band, now_iso()),
            )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def get_fingerprint(self, ssid: str) -> Optional[dict]:
        """Returns the stored baseline (bssid/security_level/channel/encryption/band) for an SSID."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT bssid, security_level, channel, encryption, band FROM fingerprints WHERE ssid = ?",
                (ssid,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def list_access_points(self) -> List[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT ap.id, ap.bssid, ap.first_seen, ap.last_seen, ap.observation_count,
                          n.ssid
                   FROM access_points ap
                   JOIN networks n ON n.id = ap.network_id
                   ORDER BY ap.last_seen DESC"""
            )
            return [dict(r) for r in cur.fetchall()]

    def get_access_point(self, access_point_id: int) -> Optional[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT ap.id, ap.bssid, ap.first_seen, ap.last_seen, ap.observation_count,
                          n.ssid
                   FROM access_points ap
                   JOIN networks n ON n.id = ap.network_id
                   WHERE ap.id = ?""",
                (access_point_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def get_latest_observation(self, access_point_id: int) -> Optional[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT * FROM observations WHERE access_point_id = ?
                   ORDER BY timestamp DESC LIMIT 1""",
                (access_point_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def get_latest_risk(self, access_point_id: int) -> Optional[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT * FROM risk_assessments WHERE access_point_id = ?
                   ORDER BY timestamp DESC LIMIT 1""",
                (access_point_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
            return d

    def get_risk_history(self, access_point_id: int) -> List[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT * FROM risk_assessments WHERE access_point_id = ?
                   ORDER BY timestamp ASC""",
                (access_point_id,),
            )
            results = []
            for row in cur.fetchall():
                d = dict(row)
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
                results.append(d)
            return results
