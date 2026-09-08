import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanner.models import WiFiNetwork
from app.security.risk_engine import RiskEngine
from app.security import rules


def make_network(**kwargs):
    defaults = dict(
        ssid="Test", bssid="AA:BB:CC:DD:EE:FF", signal_percent=60, channel=6,
        band="2.4GHz", authentication="WPA2-Personal", encryption="CCMP",
        security_level="WPA2",
    )
    defaults.update(kwargs)
    return WiFiNetwork(**defaults)


def test_risk_score_bounds():
    engine = RiskEngine()
    networks = [
        make_network(security_level="OPEN", authentication="Open"),
        make_network(ssid="B", security_level="WPA3", authentication="WPA3-Personal"),
    ]
    assessments = engine.assess_batch(networks)
    for a in assessments:
        assert 0 <= a.score <= 100


def test_open_network_ranked_higher_than_wpa3():
    engine = RiskEngine()
    open_net = make_network(ssid="OpenNet", bssid="11:11:11:11:11:11", security_level="OPEN", authentication="Open")
    wpa3_net = make_network(ssid="SecureNet", bssid="22:22:22:22:22:22", security_level="WPA3", authentication="WPA3-Personal")

    assessments = engine.assess_batch([open_net, wpa3_net])
    scores = {a.ssid: a.score for a in assessments}

    assert scores["OpenNet"] > scores["SecureNet"]


def test_duplicate_ssid_increases_risk_and_flags_anomaly():
    engine = RiskEngine()
    legit = make_network(ssid="Cafe", bssid="AA:AA:AA:AA:AA:AA", security_level="WPA2")
    twin = make_network(ssid="Cafe", bssid="BB:BB:BB:BB:BB:BB", security_level="OPEN", authentication="Open")

    assessments = engine.assess_batch([legit, twin])
    twin_assessment = next(a for a in assessments if a.bssid == "BB:BB:BB:BB:BB:BB")

    assert twin_assessment.score > 40
    assert twin_assessment.level in ("HIGH", "CRITICAL")


def test_every_assessment_has_reasons():
    engine = RiskEngine()
    assessments = engine.assess_batch([make_network()])
    assert len(assessments[0].reasons) > 0


def test_risk_level_labels_use_config_thresholds():
    assert rules.risk_level_from_score(5) == "VERY_LOW"
    assert rules.risk_level_from_score(30) == "LOW"
    assert rules.risk_level_from_score(50) == "MEDIUM"
    assert rules.risk_level_from_score(70) == "HIGH"
    assert rules.risk_level_from_score(95) == "CRITICAL"


def test_connected_flag_is_preserved_through_scoring():
    engine = RiskEngine()
    net = make_network(connected=True)
    assessments = engine.assess_batch([net])
    # connected is on the WiFiNetwork, not the assessment — verify it wasn't mutated away
    assert net.connected is True
    assert assessments[0].bssid == net.bssid
