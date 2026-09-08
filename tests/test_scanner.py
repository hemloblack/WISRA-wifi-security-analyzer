"""
Tests for the Windows netsh parser and WindowsWiFiScanner.

Mock data is used ONLY here, to feed realistic sample `netsh` text
through the real parsing code — never as a runtime fallback in the
application itself.
"""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanner.parser import parse_show_networks, parse_show_interfaces
from app.scanner.wifi_scanner import (
    WindowsWiFiScanner, NetshUnavailableError, AdapterNotFoundError, ScannerError,
)

SAMPLE_SHOW_NETWORKS = """Interface name : Wi-Fi

There are 4 networks currently visible.

SSID 1 : Home_WiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption               : CCMP
    BSSID 1                  : aa:bb:cc:11:22:33
         Signal             : 82%
         Radio type         : 802.11ac
         Channel            : 36
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54

SSID 2 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption               : CCMP
    BSSID 1                  : 11:22:33:44:55:66
         Signal             : 60%
         Radio type         : 802.11n
         Channel            : 6

SSID 3 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : Open
    Encryption               : None
    BSSID 1                  : de:ad:be:ef:00:01
         Signal             : 88%
         Radio type         : 802.11n
         Channel            : 1

SSID 4 :
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption               : GCMP
    BSSID 1                  : 99:88:77:66:55:44
         Signal             : 45%
         Radio type         : 802.11ax
         Channel            : 149
"""

SAMPLE_SHOW_INTERFACES_CONNECTED = """There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Example Wireless Adapter
    State                  : connected
    SSID                   : Home_WiFi
    BSSID                  : aa:bb:cc:11:22:33
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 36
    Signal                 : 82%
    Profile                : Home_WiFi
"""

SAMPLE_SHOW_INTERFACES_DISCONNECTED = """There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Example Wireless Adapter
    State                  : disconnected
"""


def test_parse_show_networks_basic_fields():
    networks = parse_show_networks(SAMPLE_SHOW_NETWORKS)
    assert len(networks) == 4
    home = next(n for n in networks if n.ssid == "Home_WiFi")
    assert home.bssid == "AA:BB:CC:11:22:33"
    assert home.signal_percent == 82
    assert home.channel == 36
    assert home.security_level == "WPA2"
    assert home.encryption == "CCMP"
    assert home.band == "5GHz"


def test_parse_show_networks_hidden_ssid():
    networks = parse_show_networks(SAMPLE_SHOW_NETWORKS)
    hidden = next(n for n in networks if n.bssid == "99:88:77:66:55:44")
    assert hidden.ssid == "<hidden>"
    assert hidden.security_level == "WPA3"


def test_parse_show_networks_duplicate_ssid_different_bssids():
    networks = parse_show_networks(SAMPLE_SHOW_NETWORKS)
    coffee = [n for n in networks if n.ssid == "CoffeeShop"]
    assert len(coffee) == 2
    bssids = {n.bssid for n in coffee}
    assert bssids == {"11:22:33:44:55:66", "DE:AD:BE:EF:00:01"}
    securities = {n.security_level for n in coffee}
    assert securities == {"WPA2", "OPEN"}


def test_parse_show_networks_never_fabricates_missing_fields():
    raw = (
        "SSID 1 : NoExtras\n"
        "    Authentication          : WPA2-Personal\n"
        "    Encryption               : CCMP\n"
        "    BSSID 1                  : 00:11:22:33:44:55\n"
    )
    networks = parse_show_networks(raw)
    assert len(networks) == 1
    net = networks[0]
    assert net.signal_percent is None
    assert net.channel is None
    assert net.radio_type is None
    assert net.band is None


def test_parse_show_interfaces_connected():
    net = parse_show_interfaces(SAMPLE_SHOW_INTERFACES_CONNECTED)
    assert net is not None
    assert net.ssid == "Home_WiFi"
    assert net.connected is True
    assert net.security_level == "WPA2"
    assert net.signal_percent == 82


def test_parse_show_interfaces_disconnected_returns_none():
    net = parse_show_interfaces(SAMPLE_SHOW_INTERFACES_DISCONNECTED)
    assert net is None


def _mock_completed_process(stdout="", returncode=0, stderr=""):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def test_scanner_raises_when_netsh_missing():
    scanner = WindowsWiFiScanner()
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        try:
            scanner.scan()
            assert False, "expected NetshUnavailableError"
        except NetshUnavailableError:
            pass


def test_scanner_raises_adapter_not_found():
    scanner = WindowsWiFiScanner()
    error_proc = _mock_completed_process(
        stdout="", returncode=1, stderr="There is no wireless interface on the system."
    )
    with patch("subprocess.run", return_value=error_proc):
        try:
            scanner.scan()
            assert False, "expected AdapterNotFoundError"
        except AdapterNotFoundError:
            pass


def test_scanner_marks_connected_network():
    scanner = WindowsWiFiScanner()
    networks_proc = _mock_completed_process(stdout=SAMPLE_SHOW_NETWORKS)
    interfaces_proc = _mock_completed_process(stdout=SAMPLE_SHOW_INTERFACES_CONNECTED)

    def fake_run(cmd, **kwargs):
        if "networks" in cmd:
            return networks_proc
        return interfaces_proc

    with patch("subprocess.run", side_effect=fake_run):
        networks = scanner.scan()

    home = next(n for n in networks if n.ssid == "Home_WiFi")
    assert home.connected is True
    others = [n for n in networks if n.ssid != "Home_WiFi"]
    assert all(n.connected is False for n in others)
