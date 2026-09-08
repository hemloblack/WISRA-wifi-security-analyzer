"""
Real, passive Windows Wi-Fi scanner.

Uses Microsoft's own `netsh wlan` CLI (part of every Windows 10/11
install, no extra drivers or admin rights normally required) to:

  1. List every access point currently visible to the adapter
     (`netsh wlan show networks mode=bssid`) — this NEVER associates
     to any network, it only reads what the adapter already sees.
  2. Report the network the adapter is currently connected to, if any
     (`netsh wlan show interfaces`).

Why netsh and not the raw Windows Native Wifi API (WlanAPI.dll)?
netsh is officially supported, stable across Windows 10/11 builds,
requires no extra Python dependency (ctypes bindings to WlanAPI are
brittle and version-sensitive), and exposes every field this project
needs. This is documented as a deliberate trade-off in the README.

This module contains NO mock/demo/sample data. If the real scan
cannot be performed, it raises a specific ScannerError subclass so the
caller can show an honest error instead of fabricating results.
"""
import subprocess
from typing import List, Optional

from app.scanner.models import WiFiNetwork
from app.scanner.parser import parse_show_networks, parse_show_interfaces, NetshParseError
from app.utils.logger import get_logger

log = get_logger(__name__)

NETSH_SHOW_NETWORKS_CMD = ["netsh", "wlan", "show", "networks", "mode=bssid"]
NETSH_SHOW_INTERFACES_CMD = ["netsh", "wlan", "show", "interfaces"]
NETSH_TIMEOUT_SECONDS = 20


class ScannerError(Exception):
    """Base class for all real-world scan failures."""


class NetshUnavailableError(ScannerError):
    """`netsh` is not on PATH — this is very likely not Windows."""


class AdapterNotFoundError(ScannerError):
    """No wireless network adapter is present on this machine."""


class WifiRadioOffError(ScannerError):
    """A Wi-Fi adapter exists but its radio is turned off."""


class ScanTimeoutError(ScannerError):
    """netsh did not respond within the allotted time."""


class ScanParseError(ScannerError):
    """netsh returned output that could not be understood."""


def _run_netsh(cmd: List[str]) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NETSH_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise NetshUnavailableError(
            "The 'netsh' command was not found. This tool requires Windows 10/11."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanTimeoutError(f"netsh did not respond within {NETSH_TIMEOUT_SECONDS}s.") from exc

    combined_output = (result.stdout or "") + (result.stderr or "")
    lowered = combined_output.lower()

    if result.returncode != 0:
        if "no wireless" in lowered or "there is no wireless interface" in lowered:
            raise AdapterNotFoundError(
                "No Wi-Fi adapter was found on this system, or it has no driver installed."
            )
        if "wireless autoconfig" in lowered or "radio" in lowered and "off" in lowered:
            raise WifiRadioOffError(
                "The Wi-Fi radio appears to be turned off. Enable Wi-Fi and try again."
            )
        raise ScannerError(f"netsh failed (exit code {result.returncode}): {combined_output.strip()}")

    return result.stdout


class WindowsWiFiScanner:
    """Passive, real-data-only Wi-Fi scanner for Windows 10/11."""

    def scan(self) -> List[WiFiNetwork]:
        """
        Returns every currently visible access point. Raises a
        ScannerError subclass on any failure — never returns fake data.
        """
        raw_output = _run_netsh(NETSH_SHOW_NETWORKS_CMD)

        try:
            networks = parse_show_networks(raw_output)
        except NetshParseError as exc:
            log.error("Failed to parse 'netsh wlan show networks' output: %s", exc)
            raise ScanParseError(str(exc)) from exc

        connected = self.get_current_connection()
        if connected:
            for net in networks:
                if net.bssid == connected.bssid:
                    net.connected = True

        log.info("Scan complete: %d access point(s) discovered.", len(networks))
        return networks

    def get_current_connection(self) -> Optional[WiFiNetwork]:
        """Returns the network the adapter is currently associated with, or None."""
        raw_output = _run_netsh(NETSH_SHOW_INTERFACES_CMD)
        try:
            return parse_show_interfaces(raw_output)
        except NetshParseError as exc:
            log.error("Failed to parse 'netsh wlan show interfaces' output: %s", exc)
            raise ScanParseError(str(exc)) from exc
