import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanner.models import WiFiNetwork
from app.security.security_analyzer import SecurityAnalyzer
from app.detection.evil_twin import EvilTwinDetector
from app.detection.fingerprint import FingerprintEngine


def make_network(**kwargs):
    defaults = dict(
        ssid="Test", bssid="AA:BB:CC:DD:EE:FF", signal_percent=60, channel=6,
        band="2.4GHz", authentication="WPA2-Personal", encryption="CCMP",
        security_level="WPA2",
    )
    defaults.update(kwargs)
    return WiFiNetwork(**defaults)


def test_open_network_scores_higher_than_wpa3():
    analyzer = SecurityAnalyzer()
    open_net = make_network(security_level="OPEN", authentication="Open")
    wpa3_net = make_network(security_level="WPA3", authentication="WPA3-Personal")

    open_score, _ = analyzer.analyze(open_net)
    wpa3_score, _ = analyzer.analyze(wpa3_net)

    assert open_score > wpa3_score


def test_wep_is_worse_than_wpa2():
    analyzer = SecurityAnalyzer()
    wep_score, _ = analyzer.analyze(make_network(security_level="WEP", authentication="Shared"))
    wpa2_score, _ = analyzer.analyze(make_network(security_level="WPA2"))
    assert wep_score > wpa2_score


def test_enterprise_authentication_gets_small_discount():
    analyzer = SecurityAnalyzer()
    personal_score, _ = analyzer.analyze(
        make_network(security_level="WPA2", authentication="WPA2-Personal", is_enterprise=False)
    )
    enterprise_score, _ = analyzer.analyze(
        make_network(security_level="WPA2", authentication="WPA2-Enterprise", is_enterprise=True)
    )
    assert enterprise_score < personal_score


def test_evil_twin_flags_duplicate_ssid_different_bssid():
    detector = EvilTwinDetector()
    net_a = make_network(ssid="Cafe", bssid="AA:AA:AA:AA:AA:AA", security_level="WPA2")
    net_b = make_network(ssid="Cafe", bssid="BB:BB:BB:BB:BB:BB", security_level="OPEN", authentication="Open")

    results = detector.analyze_batch([net_a, net_b])

    assert net_a.bssid in results
    assert net_b.bssid in results
    assert results[net_b.bssid][0] > results[net_a.bssid][0]


def test_evil_twin_ignores_single_network():
    detector = EvilTwinDetector()
    net = make_network(ssid="Solo")
    results = detector.analyze_batch([net])
    assert results == {}


def test_evil_twin_ignores_hidden_ssid_groups():
    detector = EvilTwinDetector()
    net_a = make_network(ssid="<hidden>", bssid="AA:AA:AA:AA:AA:AA")
    net_b = make_network(ssid="<hidden>", bssid="BB:BB:BB:BB:BB:BB")
    results = detector.analyze_batch([net_a, net_b])
    assert results == {}


def test_fingerprint_flags_security_downgrade():
    engine = FingerprintEngine()
    current = make_network(security_level="OPEN", authentication="Open", bssid="AA:AA:AA:AA:AA:AA")
    last_known = {"bssid": "AA:AA:AA:AA:AA:AA", "security_level": "WPA2", "channel": 6, "encryption": "CCMP", "band": "2.4GHz"}

    score, reasons = engine.compare(current, last_known)
    assert score > 0
    assert any("downgraded" in r for r in reasons)


def test_fingerprint_stable_network_lowers_score():
    engine = FingerprintEngine()
    current = make_network(security_level="WPA2", bssid="AA:AA:AA:AA:AA:AA", channel=6)
    last_known = {"bssid": "AA:AA:AA:AA:AA:AA", "security_level": "WPA2", "channel": 6, "encryption": "CCMP", "band": "2.4GHz"}

    score, _ = engine.compare(current, last_known)
    assert score < 0


def test_fingerprint_new_network_is_neutral():
    engine = FingerprintEngine()
    current = make_network()
    score, reasons = engine.compare(current, None)
    assert score == 0
    assert reasons == []


def test_fingerprint_flags_encryption_change():
    engine = FingerprintEngine()
    current = make_network(bssid="AA:AA:AA:AA:AA:AA", encryption="TKIP")
    last_known = {"bssid": "AA:AA:AA:AA:AA:AA", "security_level": "WPA2", "channel": 6, "encryption": "CCMP", "band": "2.4GHz"}
    score, reasons = engine.compare(current, last_known)
    assert any("Encryption changed" in r for r in reasons)
