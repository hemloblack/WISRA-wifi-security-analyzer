"""
Parsers for `netsh wlan` text output.

Windows exposes visible (not-yet-connected) networks through:
    netsh wlan show networks mode=bssid
and the currently associated network through:
    netsh wlan show interfaces

Both are plain, localized, indentation-based text. This module parses
the ENGLISH-locale output format. Output is line-oriented "Key : Value"
pairs with a nesting structure (SSID block -> BSSID sub-blocks).

Nothing here invents data: any field netsh doesn't report is left as
None. Callers must not fabricate replacements.
"""
import re
from typing import List, Optional

from app.scanner.models import WiFiNetwork

_SSID_HEADER_RE = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$")
_BSSID_HEADER_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*(.*)$")
_KV_RE = re.compile(r"^\s*([A-Za-z0-9 /()%._-]+?)\s*:\s*(.*)$")


class NetshParseError(Exception):
    """Raised when netsh output cannot be interpreted at all."""


def parse_show_networks(raw_output: str) -> List[WiFiNetwork]:
    """
    Parses `netsh wlan show networks mode=bssid` output into a list of
    WiFiNetwork objects — one per BSSID (individual access point).
    """
    if raw_output is None:
        raise NetshParseError("Empty netsh output")

    lines = raw_output.splitlines()
    networks: List[WiFiNetwork] = []

    current_ssid: Optional[str] = None
    current_auth: Optional[str] = None
    current_enc: Optional[str] = None

    # Fields accumulated for the BSSID currently being read.
    bssid: Optional[str] = None
    signal: Optional[int] = None
    radio_type: Optional[str] = None
    channel: Optional[int] = None

    def flush_bssid():
        nonlocal bssid, signal, radio_type, channel
        if bssid is None or current_ssid is None:
            return
        level, is_ent = WiFiNetwork.normalize_authentication(current_auth)
        net = WiFiNetwork(
            ssid=current_ssid if current_ssid else "<hidden>",
            bssid=bssid.upper(),
            signal_percent=signal,
            channel=channel,
            band=WiFiNetwork.band_from_channel(channel),
            radio_type=radio_type,
            authentication=current_auth,
            encryption=current_enc,
            security_level=level,
            is_enterprise=is_ent,
        )
        networks.append(net)
        bssid, signal, radio_type, channel = None, None, None, None

    for raw_line in lines:
        line = raw_line.rstrip()
        if not line.strip():
            continue

        ssid_match = _SSID_HEADER_RE.match(line.strip())
        if ssid_match:
            flush_bssid()  # close out any previous BSSID
            current_ssid = ssid_match.group(1).strip()
            current_auth = None
            current_enc = None
            continue

        bssid_match = _BSSID_HEADER_RE.match(line)
        if bssid_match:
            flush_bssid()  # close out the previous BSSID in this SSID group
            bssid = bssid_match.group(1).strip()
            continue

        kv_match = _KV_RE.match(line)
        if not kv_match:
            continue
        key = kv_match.group(1).strip().lower()
        value = kv_match.group(2).strip()

        if key == "authentication":
            current_auth = value or None
        elif key == "encryption":
            current_enc = value or None
        elif key == "signal":
            m = re.search(r"(\d+)", value)
            signal = int(m.group(1)) if m else None
        elif key == "radio type":
            radio_type = value or None
        elif key == "channel":
            m = re.search(r"(\d+)", value)
            channel = int(m.group(1)) if m else None
        # Other keys (Network type, Basic rates, Other rates, etc.) are
        # intentionally ignored — they don't feed the risk model.

    flush_bssid()  # close out the very last BSSID in the output

    return networks


def parse_show_interfaces(raw_output: str) -> Optional[WiFiNetwork]:
    """
    Parses `netsh wlan show interfaces` and returns the currently
    connected network as a WiFiNetwork (connected=True), or None if no
    interface is currently associated to a network.
    """
    if raw_output is None:
        raise NetshParseError("Empty netsh output")

    fields = {}
    for raw_line in raw_output.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        kv_match = _KV_RE.match(line)
        if not kv_match:
            continue
        key = kv_match.group(1).strip().lower()
        value = kv_match.group(2).strip()
        fields[key] = value

    state = fields.get("state", "").lower()
    if "connected" not in state or "disconnected" in state:
        return None

    ssid = fields.get("ssid")
    bssid = fields.get("bssid")
    if not ssid or not bssid:
        return None

    signal = None
    if "signal" in fields:
        m = re.search(r"(\d+)", fields["signal"])
        signal = int(m.group(1)) if m else None

    channel = None
    if "channel" in fields:
        m = re.search(r"(\d+)", fields["channel"])
        channel = int(m.group(1)) if m else None

    authentication = fields.get("authentication")
    encryption = fields.get("cipher")
    radio_type = fields.get("radio type")

    level, is_ent = WiFiNetwork.normalize_authentication(authentication)

    return WiFiNetwork(
        ssid=ssid,
        bssid=bssid.upper(),
        signal_percent=signal,
        channel=channel,
        band=WiFiNetwork.band_from_channel(channel),
        radio_type=radio_type,
        authentication=authentication,
        encryption=encryption,
        security_level=level,
        is_enterprise=is_ent,
        connected=True,
    )
