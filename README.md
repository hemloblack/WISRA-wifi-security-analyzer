# WISRA — Wi-Fi Security Risk Analyzer

**A passive, explainable Wi-Fi risk-scoring tool for Linux.**

WISRA scans nearby Wi-Fi access points *before* you connect to them and
produces a transparent, 0–100 **Risk Score** for each one — instead of
a blunt "safe / unsafe" verdict — along with the exact reasons behind
that score. It is designed to be defensible both as an academic
project (explainable, testable, well-documented) and as the foundation
of a real product (clean architecture, REST API, persistent history).

> **Scope note:** WISRA is strictly *passive and defensive*. It never
> transmits deauthentication frames, never attempts unauthorized
> association/authentication, and never captures or decrypts traffic.
> It only reads what your OS's Wi-Fi stack (NetworkManager) already
> makes visible before you connect — the same information your phone's
> Wi-Fi picker shows you, just analyzed more rigorously.

---

## 1. Why this exists

Most people (and most Wi-Fi UIs) decide whether a network is "safe" by
looking at one signal: the padlock icon (open vs. encrypted). That is
not enough:

- A network can be WPA2-encrypted and still be a rogue/Evil-Twin AP.
- A previously trusted network can silently change its security
  configuration.
- Two networks can broadcast the **same SSID** with different BSSIDs
  and security levels — a classic Evil Twin signature.

WISRA combines several independent signals — base protocol strength,
duplicate-SSID detection, and historical fingerprint drift — into one
explainable score, so the user (or a downstream system) can make an
informed decision.

## 2. Key features

| Feature | Description |
|---|---|
| Passive Wi-Fi discovery | Uses `nmcli` (NetworkManager) to list visible APs — no special hardware or monitor mode required |
| Explainable Risk Engine | 0–100 score per network with a human-readable list of *why* |
| Evil Twin detection | Flags duplicate SSIDs broadcast with different BSSID/security/channel |
| Fingerprint history | Detects when a known network's security or BSSID has changed since last seen |
| Anomaly flag | Highlights configuration drift that deviates from a network's established fingerprint |
| REST API | FastAPI backend exposing scan + history endpoints |
| Web dashboard | Lightweight HTML/JS UI showing live results and per-network detail |
| SQLite persistence | Every observation and risk assessment is stored for trend/history analysis |
| CLI mode | One-command terminal scan report, no server required |
| Demo mode | Runs without Wi-Fi hardware/nmcli using a realistic sample dataset — useful for grading, CI, and demos on machines without a wireless adapter |
| Test suite | Pytest coverage for the parser, security analyzer, Evil Twin detector, fingerprinting, and the end-to-end risk engine |

## 3. Architecture

```
Wi-Fi Adapter → nmcli/NetworkManager
                     │
                     ▼
              WiFiScanner (passive discovery)
                     │
                     ▼
              nmcli output Parser → WiFiNetwork objects
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
 SecurityAnalyzer  EvilTwinDetector FingerprintEngine
        │            │             │
        └────────────┼─────────────┘
                     ▼
               RiskEngine (combines + clamps 0-100)
                     │
        ┌────────────┼─────────────┐
        ▼                          ▼
   SQLite Database            FastAPI REST API
                                    │
                                    ▼
                             Web Dashboard (HTML/JS)
```

Each analysis stage returns a **score delta + list of reasons**, which
the Risk Engine sums and clamps to [0, 100]. This makes the whole
pipeline auditable: every point on the final score traces back to a
named rule (see `app/security/rules.py`).

## 4. Project layout

```
wifi-security-analyzer/
├── app/
│   ├── main.py                 # CLI entry point
│   ├── scanner/
│   │   ├── wifi_scanner.py     # nmcli wrapper + demo-mode fallback
│   │   ├── parser.py           # nmcli terse-output parser
│   │   └── models.py           # WiFiNetwork dataclass
│   ├── security/
│   │   ├── security_analyzer.py# base per-network scoring
│   │   ├── risk_engine.py      # orchestrates all analyzers
│   │   └── rules.py            # all scoring weights, documented
│   ├── detection/
│   │   ├── evil_twin.py        # duplicate-SSID detection
│   │   ├── fingerprint.py      # historical drift detection
│   │   └── anomaly.py          # anomaly flagging
│   ├── database/
│   │   ├── database.py         # SQLite access layer
│   │   └── models.py           # SQL schema
│   ├── api/
│   │   └── routes.py           # FastAPI app + endpoints
│   └── utils/
│       ├── logger.py
│       └── helpers.py
├── frontend/                   # HTML/CSS/JS dashboard
├── tests/                      # Pytest suite
├── data/                       # SQLite DB (created at runtime)
├── requirements.txt
├── run.py                      # `python run.py cli|api`
└── README.md
```

## 5. Installation

Requires Python 3.9+ on Linux (NetworkManager/`nmcli` recommended but
not required — see Demo Mode below).

```bash
git clone <this-repo>
cd wifi-security-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 6. Usage

### CLI (fastest way to try it)

```bash
python run.py cli                 # scan real hardware via nmcli
python run.py cli --demo          # run without hardware (sample data)
python run.py cli --demo --json   # machine-readable output
```

Sample output:

```
============================================================
 WISRA — Wi-Fi Security Risk Analyzer
============================================================

SSID     : CoffeeShop
BSSID    : DE:AD:BE:EF:00:01
Security : OPEN
Signal   : -40 dBm   Channel: 1   Band: 2.4GHz
Risk     : 71.0/100  [HIGH]
           ⚠ ANOMALY DETECTED
Reasons  :
   - Base risk for OPEN security: +45
   - SSID contains a commonly spoofed keyword: +6
   - SSID 'CoffeeShop' seen on multiple BSSIDs in this scan: +20
   - This AP uses weaker security (OPEN) than another AP with the same SSID (WPA2): +25
============================================================
```

### Web dashboard + API

```bash
python run.py api                 # starts at http://127.0.0.1:8000
```

Open `http://127.0.0.1:8000` for the dashboard, or call the API
directly:

```bash
curl -X POST http://127.0.0.1:8000/api/scan
curl http://127.0.0.1:8000/api/networks
curl http://127.0.0.1:8000/api/networks/1/risk
curl http://127.0.0.1:8000/api/networks/1/history
```

> If no Wi-Fi hardware/`nmcli` is detected, the scanner automatically
> falls back to **demo mode** with a realistic sample dataset (including
> a deliberately duplicated SSID to demonstrate Evil Twin detection),
> so the whole system remains fully demonstrable on any machine.

### Running the tests

```bash
pytest tests/ -v
```

## 7. Risk scoring model

The score is a sum of independent, documented rule contributions
(full list in `app/security/rules.py`):

| Signal | Contribution |
|---|---|
| OPEN network | +45 |
| WEP | +55 |
| WPA | +25 |
| WPA2 | +10 |
| WPA3 | +3 |
| Unusually strong signal (≥ -35 dBm) | +8 |
| Suspicious SSID keyword (free/public/guest/…) | +6 |
| Duplicate SSID, different BSSID | +20 |
| Duplicate SSID, weaker security than sibling AP | +25 |
| Duplicate SSID, different channel | +5 |
| BSSID changed since last observation | +15 |
| Security downgraded since last observation | +30 |
| Channel changed since last observation | +5 |
| Matches previously known, stable AP | −10 |
| Known network with stable/improved security | −5 |

Scores are clamped to `[0, 100]` and mapped to a level:

```
0–19   LOW
20–44  MEDIUM
45–69  HIGH
70–100 CRITICAL
```

These weights are a documented starting point, not a claim of
ground-truth accuracy — tuning them against labeled real-world data is
listed as future work below.

## 8. Roadmap / future work

- [ ] Calibrate rule weights against a labeled dataset of known-safe
      and known-malicious APs.
- [ ] Scheduled background scanning + push notifications on new
      CRITICAL-level networks.
- [ ] Signed/exportable PDF risk reports.
- [ ] Optional Docker packaging and a `systemd` service unit.
- [ ] Mobile companion app consuming the existing REST API.

## 9. Ethical & legal notes

WISRA is built for **defensive** use: helping a user or organization
decide whether it is safe to connect to a network. It intentionally
does **not** implement any offensive capability (deauthentication,
handshake capture, credential harvesting, traffic interception). This
keeps it legal to run in essentially any jurisdiction and appropriate
for academic submission, portfolio use, or commercial distribution
without the legal complications that come with penetration-testing
tools.

## 10. License

Choose a license appropriate for your use case (MIT is a common
default for portfolio/academic projects; consult your institution or
legal counsel before commercial distribution).
