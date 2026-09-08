import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database.database import Database
from app.scanner.models import WiFiNetwork
from app.security.risk_engine import RiskAssessment


def make_network(**kwargs):
    defaults = dict(
        ssid="Test", bssid="AA:BB:CC:DD:EE:FF", signal_percent=60, channel=6,
        band="2.4GHz", authentication="WPA2-Personal", encryption="CCMP",
        security_level="WPA2",
    )
    defaults.update(kwargs)
    return WiFiNetwork(**defaults)


def temp_db() -> Database:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Database(db_path=tmp.name)


def test_record_observation_creates_network_and_access_point():
    db = temp_db()
    net = make_network()
    ap_id = db.record_observation(net)

    ap = db.get_access_point(ap_id)
    assert ap["ssid"] == "Test"
    assert ap["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert ap["observation_count"] == 1


def test_repeated_observation_increments_count_not_duplicates_ap():
    db = temp_db()
    net = make_network()
    ap_id_1 = db.record_observation(net)
    ap_id_2 = db.record_observation(net)

    assert ap_id_1 == ap_id_2
    ap = db.get_access_point(ap_id_1)
    assert ap["observation_count"] == 2


def test_fingerprint_round_trip():
    db = temp_db()
    net = make_network(ssid="Cafe", bssid="11:22:33:44:55:66")
    assert db.get_fingerprint("Cafe") is None

    db.update_fingerprint(net)
    fp = db.get_fingerprint("Cafe")
    assert fp["bssid"] == "11:22:33:44:55:66"
    assert fp["security_level"] == "WPA2"


def test_save_and_read_risk_assessment():
    db = temp_db()
    net = make_network()
    ap_id = db.record_observation(net)

    assessment = RiskAssessment(
        ssid=net.ssid, bssid=net.bssid, score=42.0, level="MEDIUM",
        is_anomalous=False, reasons=["Base risk for WPA2 security: +10"],
    )
    db.save_risk_assessment(ap_id, assessment)

    latest = db.get_latest_risk(ap_id)
    assert latest["score"] == 42.0
    assert latest["level"] == "MEDIUM"
    assert latest["reasons"] == ["Base risk for WPA2 security: +10"]
