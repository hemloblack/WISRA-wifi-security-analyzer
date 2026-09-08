"""SQL schema for the WISRA SQLite database."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL,
    bssid TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(network_id, bssid),
    FOREIGN KEY(network_id) REFERENCES networks(id)
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_point_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    signal_percent INTEGER,
    channel INTEGER,
    band TEXT,
    radio_type TEXT,
    authentication TEXT,
    encryption TEXT,
    security_level TEXT,
    connected INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(access_point_id) REFERENCES access_points(id)
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_point_id INTEGER NOT NULL,
    score REAL NOT NULL,
    level TEXT NOT NULL,
    anomaly INTEGER NOT NULL DEFAULT 0,
    reasons TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(access_point_id) REFERENCES access_points(id)
);

-- One row per SSID: the latest known configuration, used as the
-- baseline for fingerprint-drift detection on the NEXT scan.
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL UNIQUE,
    bssid TEXT NOT NULL,
    security_level TEXT,
    encryption TEXT,
    channel INTEGER,
    band TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_points_network ON access_points(network_id);
CREATE INDEX IF NOT EXISTS idx_observations_ap ON observations(access_point_id);
CREATE INDEX IF NOT EXISTS idx_risk_ap ON risk_assessments(access_point_id);
"""
