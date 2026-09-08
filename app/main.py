"""
CLI entry point for WISRA (Windows).

Runs a single real scan + risk assessment cycle and prints a
formatted report to the terminal. No mock data — if the scan fails,
the actual Windows/netsh error is shown.
"""
import argparse
import sys

from app.scanner.wifi_scanner import WindowsWiFiScanner, ScannerError
from app.security.risk_engine import RiskEngine
from app.database.database import Database
from app.pipeline import execute_scan
from app.utils.logger import get_logger

log = get_logger(__name__)

LEVEL_COLOR = {
    "VERY_LOW": "\033[92m",   # green
    "LOW": "\033[92m",
    "MEDIUM": "\033[93m",     # yellow
    "HIGH": "\033[91m",       # red
    "CRITICAL": "\033[95m",   # magenta
}
RESET = "\033[0m"


def _fmt(value, suffix=""):
    return f"{value}{suffix}" if value is not None else "N/A"


def print_current_connection(scanner: WindowsWiFiScanner, use_color: bool):
    try:
        connected = scanner.get_current_connection()
    except ScannerError as exc:
        print(f"(Could not read current connection: {exc})")
        return

    print("\nCurrent connection:")
    if connected is None:
        print("  Not connected to any Wi-Fi network.")
        return
    print(f"  SSID           : {connected.ssid}")
    print(f"  BSSID          : {connected.bssid}")
    print(f"  Authentication : {_fmt(connected.authentication)}")
    print(f"  Encryption     : {_fmt(connected.encryption)}")
    print(f"  Signal         : {_fmt(connected.signal_percent, '%')}")
    print(f"  Channel/Band   : {_fmt(connected.channel)} / {_fmt(connected.band)}")


def print_report(results, use_color=True):
    print("\n" + "=" * 64)
    print(" WISRA — Wi-Fi Security Risk Analyzer (Windows)")
    print("=" * 64)

    for network, assessment, _ in results:
        color = LEVEL_COLOR.get(assessment.level, "") if use_color else ""
        reset = RESET if use_color else ""
        tag = " [CONNECTED]" if network.connected else ""
        print(f"\nSSID           : {network.ssid}{tag}")
        print(f"BSSID          : {network.bssid}")
        print(f"Authentication : {_fmt(network.authentication)}")
        print(f"Encryption     : {_fmt(network.encryption)}")
        print(f"Signal         : {_fmt(network.signal_percent, '%')}   "
              f"Channel: {_fmt(network.channel)}   Band: {_fmt(network.band)}   "
              f"Radio: {_fmt(network.radio_type)}")
        print(f"Risk           : {color}{assessment.score:.1f}/100  [{assessment.level}]{reset}")
        if assessment.is_anomalous:
            print(f"                 {color}\u26a0 ANOMALY DETECTED{reset}")
        if assessment.reasons:
            print("Reasons        :")
            for reason in assessment.reasons:
                print(f"   - {reason}")

    print("\n" + "=" * 64)
    print(f" Scan complete. {len(results)} access point(s) analyzed.")
    print("=" * 64 + "\n")


def main():
    parser = argparse.ArgumentParser(description="WISRA - Wi-Fi Security Risk Analyzer (Windows)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--no-db", action="store_true", help="Skip saving results to the database")
    parser.add_argument("--json", action="store_true", help="Print raw JSON instead of a formatted report")
    args = parser.parse_args()

    scanner = WindowsWiFiScanner()
    db = None if args.no_db else Database()
    engine = RiskEngine(database=db)

    try:
        networks = scanner.scan()
    except ScannerError as exc:
        print(f"Error during scan: {exc}", file=sys.stderr)
        log.error("CLI scan failed: %s", exc)
        sys.exit(1)

    if not networks:
        print("No Wi-Fi networks were found. Make sure Wi-Fi is enabled and try again.")
        sys.exit(0)

    results = execute_scan(networks, engine, db)

    if args.json:
        import json
        payload = [
            {
                **a.to_dict(),
                "signal_percent": n.signal_percent,
                "channel": n.channel,
                "band": n.band,
                "radio_type": n.radio_type,
                "authentication": n.authentication,
                "encryption": n.encryption,
                "connected": n.connected,
            }
            for n, a, _ in results
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print_current_connection(scanner, use_color=not args.no_color)
        print_report(results, use_color=not args.no_color)


if __name__ == "__main__":
    main()
