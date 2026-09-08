"""
FastAPI HTTP layer for WISRA (Windows).

Endpoints:
  POST /api/scan                        -> real scan + risk assessment of nearby networks
  GET  /api/current-connection          -> the network this machine is currently connected to (or null)
  GET  /api/access-points               -> list all known access points (from history)
  GET  /api/access-points/{id}          -> details for one access point
  GET  /api/access-points/{id}/risk     -> latest risk assessment
  GET  /api/access-points/{id}/history  -> risk score history

No mock or sample data is ever used here. If the real Windows scan
fails, the API returns a clear HTTP error describing why (no adapter,
Wi-Fi off, netsh missing, etc.) instead of fabricating results.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.scanner.wifi_scanner import WindowsWiFiScanner, ScannerError
from app.security.risk_engine import RiskEngine
from app.database.database import Database
from app.pipeline import execute_scan
from app.utils.logger import get_logger

log = get_logger(__name__)

app = FastAPI(
    title="WISRA - Wi-Fi Security Risk Analyzer",
    description="Passive, real-data-only Windows Wi-Fi risk analysis API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()
engine = RiskEngine(database=db)
scanner = WindowsWiFiScanner()


def _scanner_error_to_http(exc: ScannerError) -> HTTPException:
    log.error("Scanner error: %s", exc)
    return HTTPException(status_code=503, detail=str(exc))


@app.post("/api/scan")
def run_scan():
    try:
        networks = scanner.scan()
    except ScannerError as exc:
        raise _scanner_error_to_http(exc)

    results = execute_scan(networks, engine, db)

    payload = []
    for network, assessment, ap_id in results:
        entry = assessment.to_dict()
        entry["id"] = ap_id
        entry["signal_percent"] = network.signal_percent
        entry["channel"] = network.channel
        entry["band"] = network.band
        entry["radio_type"] = network.radio_type
        entry["authentication"] = network.authentication
        entry["encryption"] = network.encryption
        entry["connected"] = network.connected
        payload.append(entry)

    return {"count": len(payload), "networks": payload}


@app.get("/api/current-connection")
def current_connection():
    try:
        connected = scanner.get_current_connection()
    except ScannerError as exc:
        raise _scanner_error_to_http(exc)

    if connected is None:
        return {"connected": False, "network": None}

    return {
        "connected": True,
        "network": {
            "ssid": connected.ssid,
            "bssid": connected.bssid,
            "signal_percent": connected.signal_percent,
            "channel": connected.channel,
            "band": connected.band,
            "radio_type": connected.radio_type,
            "authentication": connected.authentication,
            "encryption": connected.encryption,
        },
    }


@app.get("/api/access-points")
def list_access_points():
    aps = db.list_access_points()
    enriched = []
    for ap in aps:
        risk = db.get_latest_risk(ap["id"])
        observation = db.get_latest_observation(ap["id"])
        enriched.append({**ap, "risk": risk, "latest_observation": observation})
    return {"count": len(enriched), "access_points": enriched}


@app.get("/api/access-points/{ap_id}")
def get_access_point(ap_id: int):
    ap = db.get_access_point(ap_id)
    if not ap:
        raise HTTPException(status_code=404, detail="Access point not found")
    ap["risk"] = db.get_latest_risk(ap_id)
    ap["latest_observation"] = db.get_latest_observation(ap_id)
    return ap


@app.get("/api/access-points/{ap_id}/risk")
def get_access_point_risk(ap_id: int):
    ap = db.get_access_point(ap_id)
    if not ap:
        raise HTTPException(status_code=404, detail="Access point not found")
    risk = db.get_latest_risk(ap_id)
    if not risk:
        raise HTTPException(status_code=404, detail="No risk assessment yet for this access point")
    return {**risk, "ssid": ap["ssid"], "bssid": ap["bssid"]}


@app.get("/api/access-points/{ap_id}/history")
def get_access_point_history(ap_id: int):
    ap = db.get_access_point(ap_id)
    if not ap:
        raise HTTPException(status_code=404, detail="Access point not found")
    return {"ssid": ap["ssid"], "bssid": ap["bssid"], "history": db.get_risk_history(ap_id)}


# Serve the HTML/JS dashboard at "/"
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
