# WISRA — Wi-Fi Security Risk Analyzer (Windows Edition)

**A passive, explainable Wi-Fi risk-scoring tool for Windows 10/11, built on real adapter data.**

WISRA scans the Wi-Fi networks your machine's real wireless adapter can
already see — **before you connect to any of them** — and produces a
transparent 0–100 **Risk Score** per access point, with the exact
reasons behind that score. There is no mock, sample, demo, or
hardcoded network data anywhere in the application path: every field
you see came from your own adapter via Windows.

> **Scope note:** WISRA is strictly *passive and defensive*. It never
> connects/associates to a network to analyze it, never transmits
> deauthentication frames, never captures or decrypts traffic, and
> never attempts to crack a password. It only reads what Windows'
> `netsh wlan` already exposes about visible access points — the same
> information the Windows Wi-Fi picker shows you, analyzed more
> rigorously and with history.

---

## 1. What WISRA does

```
Windows Wi-Fi Adapter
        │
        ▼
netsh wlan show networks mode=bssid   (passive scan, no association)
        │
        ▼
Parser → normalized WiFiNetwork objects (one per BSSID)
        │
        ▼
Security Analyzer + Evil Twin Detector + Fingerprint Engine
        │
        ▼
Risk Engine → 0-100 score, level, explainable reasons
        │
        ▼
SQLite history  +  FastAPI  +  Web Dashboard
```

Every network shown to you is a real access point your adapter
detected in that moment. Nothing is invented, guessed, or filled in
with placeholder values — a field Windows doesn't report is shown as
`N/A` / `null`, never faked.

## 2. Requirements

- **Windows 10 or Windows 11.** WISRA relies on the built-in `netsh
  wlan` command, part of every standard Windows install — no extra
  drivers, no admin rights normally required.
- Python 3.9+
- A Wi-Fi adapter with its driver installed and the radio turned on.

WISRA will **not** run meaningfully on Linux/macOS — `netsh` doesn't
exist there, and the scanner raises `NetshUnavailableError` with a
clear message rather than silently falling back to fake data.

## 3. Why `netsh` and not the raw Windows Wi-Fi API?

Windows exposes Wi-Fi scanning through the low-level **Native Wifi API**
(`wlanapi.dll`), and through **`netsh wlan`**, a thin, officially
supported wrapper over that same API. We chose `netsh` deliberately:

| | `netsh wlan` (chosen) | Raw `wlanapi.dll` via ctypes/WMI |
|---|---|---|
| Extra dependency | None — built into Windows | Requires ctypes struct bindings or a third-party wrapper |
| Stability across Windows builds | Very stable, unchanged for years | Struct layouts/constants can be version-sensitive |
| Fields needed by this project | All exposed (SSID, BSSID, signal, channel, radio type, authentication, encryption) | Same fields, more integration work |
| Admin privileges | Not required for `show networks` / `show interfaces` | Not required either, but implementation is significantly more complex |

If event-driven (vs. polled) scanning is needed later, the scanner is
isolated behind `WindowsWiFiScanner` in `app/scanner/wifi_scanner.py` —
swapping the backend doesn't require touching the security/risk layers.

## 4. What information is collected — and what isn't

For every visible access point, WISRA extracts exactly what `netsh`
reports and nothing more:

| Field | Source | Notes |
|---|---|---|
| SSID | `netsh wlan show networks` | `<hidden>` if the AP doesn't broadcast a name |
| BSSID (AP's MAC address) | same | Each BSSID is tracked as an independent access point, even under a shared SSID |
| Signal | same | Reported by Windows as a 0–100% value, not dBm |
| Channel | same | |
| Band (2.4/5/6 GHz) | **derived** from channel number | Best-effort — channel numbering overlaps between bands in some ranges, so this is an approximation, not a guarantee (documented in code) |
| Radio type (e.g. 802.11ac) | same | |
| Authentication (e.g. `WPA2-Personal`) | same | Raw string, shown as-is |
| Encryption/cipher (e.g. `CCMP`) | same | Raw string, shown as-is |
| Currently connected? | `netsh wlan show interfaces` | Cross-referenced by BSSID |

If Windows or the adapter doesn't report a field (common for signal
strength on some drivers, or radio type on older adapters), that field
is `null`/`N/A` in the API and UI — WISRA never substitutes a guessed
value.

**BSSID vs SSID:** multiple access points can broadcast the same SSID
(e.g. a mesh network, or an Evil Twin). WISRA always treats each
**BSSID** as an independent access point in the database and risk
engine; the SSID is only used for grouping and fingerprinting.

## 5. Installation

```powershell
git clone <this-repo>
cd wifi-security-analyzer
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 6. Usage

### CLI

```powershell
python run.py cli              # real scan + formatted report
python run.py cli --json       # machine-readable output
python run.py cli --no-db      # score without writing to history
```

Sample output:

```
Current connection:
  SSID           : Home_WiFi
  BSSID          : AA:BB:CC:11:22:33
  Authentication : WPA2-Personal
  Encryption     : CCMP
  Signal         : 82%
  Channel/Band   : 36 / 5GHz

================================================================
 WISRA — Wi-Fi Security Risk Analyzer (Windows)
================================================================

SSID           : CoffeeShop
BSSID          : DE:AD:BE:EF:00:01
Authentication : Open
Encryption     : None
Signal         : 88%   Channel: 1   Band: 2.4GHz   Radio: 802.11n
Risk           : 78.0/100  [HIGH]
                 ⚠ ANOMALY DETECTED
Reasons        :
   - Base risk for Open security: +40
   - SSID contains a commonly spoofed keyword: +6
   - SSID 'CoffeeShop' seen on multiple access points (BSSIDs) in this scan: +15
   - This access point uses weaker security (OPEN) than another access point with the same SSID (WPA2): +25
================================================================
```

### Web dashboard + API

```powershell
python run.py api              # starts at http://127.0.0.1:8000
```

Endpoints:

```
POST /api/scan                        real scan + risk assessment of nearby networks
GET  /api/current-connection          the network this machine is connected to (or null)
GET  /api/access-points               all known access points, from history
GET  /api/access-points/{id}          details for one access point
GET  /api/access-points/{id}/risk     latest risk assessment
GET  /api/access-points/{id}/history  risk score history over time
```

If the scan can't run (Wi-Fi off, no adapter, `netsh` unavailable), the
API returns HTTP `503` with a plain-language `detail` message — the
dashboard surfaces this in a visible error box instead of silently
showing nothing.

### Tests

```powershell
pytest tests/ -v
```

All 29 tests run against the real parsing/scoring code. The **only**
place sample `netsh` text or mocked subprocess calls appear is inside
`tests/` — this is enforced as a project rule, not just a convention.

## 7. Risk scoring model

All weights and thresholds live in **`config/risk_rules.json`** — edit
that file to retune the model without touching any code. A built-in
fallback is used only if the file is missing or malformed (with a
logged warning); it never overrides a valid config.

```json
{
  "security_base_score": { "OPEN": 40, "WEP": 50, "WPA": 25, "WPA2": 10, "WPA3": 3, "UNKNOWN": 20 },
  "duplicate_ssid_different_bssid": 15,
  "duplicate_ssid_weaker_security": 25,
  "fingerprint_security_downgrade": 30,
  "fingerprint_bssid_changed": 15
}
```

Risk levels are also configurable (defaults below), matching a
0–100 **suspicion level**, not a certainty of compromise:

| Range | Level |
|---|---|
| 0–20 | VERY LOW |
| 21–40 | LOW |
| 41–60 | MEDIUM |
| 61–80 | HIGH |
| 81–100 | CRITICAL |

**Increases risk:** open/WEP/legacy security, unusually strong signal
for an unfamiliar AP, suspicious SSID naming (`free`, `public`,
`guest`...), duplicate SSID across BSSIDs with weaker/different
security or encryption, a new BSSID replacing a previously known one,
a security downgrade since the last time this SSID was seen, a channel
or encryption change since last seen.

**Decreases risk:** WPA3, enterprise authentication (centrally
managed), a stable/matching fingerprint versus history, a previously
known network with unchanged or improved security.

Every point is logged with a plain-English reason (see the sample
output above) — explainability is a core design goal, not an
afterthought.

## 8. Evil Twin & duplicate-SSID detection — and their limits

WISRA groups access points by SSID within a single scan and flags when
the same SSID appears on multiple BSSIDs that differ in security
level, encryption, or band. This raises the risk score and is
surfaced as *"Potential Evil Twin"* / *"Duplicate SSID detected"* —
**never** as a confirmed verdict. Legitimate reasons this can trigger
with no malicious intent:

- Mesh Wi-Fi systems and enterprise deployments intentionally run many
  physical access points under one SSID.
- A router replacement or firmware update can legitimately change
  security settings.
- Two unrelated networks in range can coincidentally share a common
  SSID like "Free_WiFi" or a default router name.

WISRA cannot see through walls, cannot verify who administers an
access point, and cannot correlate this against your physical
location. Treat every finding as **"worth a closer look,"** not proof.

## 9. Why WISRA cannot prove a network is malicious

Passive Wi-Fi broadcast metadata (SSID, BSSID, channel, signal,
security type) is, by design, the *only* thing visible before you
connect — and it is trivial for an attacker to spoof any of it. A
rogue AP can present a perfectly unremarkable configuration, and a
completely legitimate network can look unusual after a router
replacement. Because of this:

- WISRA reports **risk / suspicion / anomaly**, never certainty.
- No amount of passive metadata analysis can substitute for verifying
  a network out-of-band (asking staff for the correct SSID, checking a
  posted network name, using a VPN regardless of the network's score).
- A LOW score does not guarantee safety, and a HIGH score does not
  guarantee malice — it means "this configuration is statistically
  more consistent with risk than with a typical stable network."

## 10. Database schema

SQLite (`data/wifi_analyzer.db`), five tables:

```
networks           one row per unique SSID
access_points       one row per unique BSSID under a network
observations         one row per scan snapshot of an access point
risk_assessments      one row per computed risk score
fingerprints           latest known configuration per SSID (drift baseline)
```

Fingerprint comparison always uses the **previous** stored baseline —
the risk engine reads it before the new observation overwrites it, so
a security downgrade or BSSID change from the last scan is never
missed.

## 11. Error handling

The scanner never crashes the app; it raises a specific, human-readable
error for each real-world failure mode:

| Situation | Exception | HTTP status |
|---|---|---|
| Not running on Windows / `netsh` missing | `NetshUnavailableError` | 503 |
| No Wi-Fi adapter present | `AdapterNotFoundError` | 503 |
| Wi-Fi radio turned off | `WifiRadioOffError` | 503 |
| `netsh` hangs | `ScanTimeoutError` | 503 |
| Unrecognized `netsh` output | `ScanParseError` | 503 |

The CLI prints the message and exits with a non-zero status; the API
returns the same message as the `detail` field of a `503` response,
and the dashboard shows it in a visible error banner.

## 12. Logging

Structured logs go to both the console and `logs/wisra.log` (rotating,
max 2MB × 3 backups). Logged: scan start/completion, network counts,
parser/database errors. **Not logged:** full SSIDs/BSSIDs at INFO
level, to avoid writing a de-facto record of every network you've ever
been near — enable DEBUG locally if you need per-network detail while
developing.

## 13. Project layout

```
wifi-security-analyzer/
├── app/
│   ├── main.py                   # CLI entry point
│   ├── pipeline.py                # shared scan→score→persist orchestration (CLI + API)
│   ├── scanner/
│   │   ├── wifi_scanner.py        # WindowsWiFiScanner (netsh wrapper, real data only)
│   │   ├── parser.py              # netsh output parser
│   │   └── models.py              # WiFiNetwork dataclass, band/security normalization
│   ├── security/
│   │   ├── security_analyzer.py   # base per-AP scoring
│   │   ├── risk_engine.py         # orchestrates all analyzers
│   │   └── rules.py               # loads config/risk_rules.json
│   ├── detection/
│   │   ├── evil_twin.py           # duplicate-SSID detection
│   │   ├── fingerprint.py         # historical drift detection
│   │   └── anomaly.py             # anomaly flagging
│   ├── database/
│   │   ├── database.py            # SQLite access layer
│   │   └── models.py              # SQL schema
│   ├── api/
│   │   └── routes.py              # FastAPI app + endpoints
│   └── utils/
│       ├── logger.py              # console + rotating file logging
│       └── helpers.py
├── config/
│   └── risk_rules.json            # all scoring weights & thresholds — edit freely
├── frontend/                      # HTML/CSS/JS dashboard
├── tests/                         # pytest suite (mocks live ONLY here)
├── logs/                          # wisra.log (rotating)
├── data/                          # SQLite DB (created at runtime)
├── requirements.txt
├── run.py                         # `python run.py cli|api`
└── README.md
```

## 14. Roadmap

- [ ] Optional raw Native Wifi API backend for event-driven (vs. polled) scanning.
- [ ] Calibrate `config/risk_rules.json` weights against a labeled dataset.
- [ ] Scheduled background scanning + Windows toast notifications on CRITICAL findings.
- [ ] Exportable PDF risk reports.
- [ ] Packaged Windows installer / system tray app.

## 15. Ethics & legal

WISRA performs **passive discovery only**: it never captures traffic,
cracks passwords, deauthenticates users, performs MITM, or connects
automatically to anything. This is a deliberate scope boundary, not a
missing feature — it's what keeps the tool legal to run in effectively
any jurisdiction and appropriate for academic submission or commercial
distribution without the legal complications of penetration-testing
tools.

## 16. License

Choose a license appropriate for your use case (MIT is a common
default for portfolio/academic projects; consult your institution or
legal counsel before commercial distribution).
#   W I S R A - w i f i - s e c u r i t y - a n a l y z e r  
 