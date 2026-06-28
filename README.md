# DEFCON Level Monitor v3.0

> **OSINT threat assessment monitor** — tracks real-time DEFCON level from multiple sources,
> computes a composite threat score across 6 domains, and fires alerts via Telegram / email.

**⚠️ OSINT Estimate Only — not an official U.S. government signal.**

---

## Features

| Domain | Source | Trigger |
|---|---|---|
| Geopolitical DEFCON | ClawdWatch + defconlevel.com | Web scraping / local agent |
| Weather | NWS api.weather.gov | Active alerts in your zone |
| Seismic | USGS Earthquake API | M6+ events globally |
| Biological | Manual | Set via CLI when H5N1/pandemic news warrants |
| Food Security | Manual | Set via CLI during supply chain crises |
| Cyber | npm audit | Package vulnerabilities |

- **6-domain composite score** (0–100) → DEFCON level 5→1
- **Terminal dashboard** — color ASCII panel, no dependencies
- **Web dashboard** — Flask UI with API endpoint
- **Alert engine** — Telegram + email with cooldown rules
- **State persistence** — JSON file, history, trend tracking
- **Standalone** — pure Python stdlib, no pip install required for core

---

## Quick Start

```bash
# 1. Clone / download the project
cd DEFCON

# 2. Configure (edit config.py or set env vars)
export NWS_ZONE=OHZ061                  # your NWS zone
export CLAWDWATCH_URL=http://localhost:3444  # optional
export DEFCON_TELEGRAM_BOT_TOKEN=...     # optional
export DEFCON_TELEGRAM_CHAT_ID=...       # optional

# 3. Run a scan
python defcon_monitor.py

# 4. View dashboard
python defcon_dashboard.py

# 5. Health check
python defcon_health.py

# 6. Check alerts
python defcon_alert.py

# 7. Web dashboard (requires Flask)
pip install flask
python defcon_web.py
# → http://localhost:5000/
```

---

## Project Structure

```
DEFCON/
├── defcon_monitor.py      # Main scanner — run all domain checks
├── defcon_dashboard.py    # ASCII terminal dashboard
├── defcon_health.py       # System diagnostics
├── defcon_alert.py        # Rules-based alert dispatcher
├── defcon_web.py          # Flask web dashboard (optional)
├── config.py              # Configuration template — COPY and fill in
├── requirements.txt       # Python dependencies (Flask only)
├── src/
│   ├── __init__.py
│   ├── constants.py       # DEFCON enums, score bands, labels
│   ├── state.py           # StateManager — read/write defcon-state.json
│   └── fetcher.py         # HTTP client with retries, UA rotation, TLS
├── logs/                  # Auto-created; scan + alert logs land here
├── README.md
└── SKILL.md               # Hermes Agent skill definition
```

---

## Configuration

### Environment Variables (recommended for secrets)

```bash
export DEFCON_TELEGRAM_BOT_TOKEN="123456:ABC-..."   # Telegram bot token
export DEFCON_TELEGRAM_CHAT_ID="123456789"          # Your chat ID
export DEFCON_TELEGRAM_TOPIC_ID="777"               # Optional topic/thread
export NWS_ZONE="OHZ061"                            # Your NWS zone code
export CLAWDWATCH_URL="http://localhost:3444"       # ClawdWatch agent
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="you@gmail.com"
export SMTP_PASS="app-password"
export SMTP_TO="recipient@example.com"
```

### config.py

Copy `config.py` (the template) to your own `config.py` and fill in values.
The repository ships with `config.py` as a template with placeholder values.

---

## DEFCON Levels

| Level | Label | Composite Score | Meaning |
|---|---|---|---|
| 5 | GREEN / FADE OUT | 0–19 | Normal peacetime posture |
| 4 | YELLOW / DOUBLE TAKE | 20–39 | Above-normal readiness |
| 3 | ORANGE / ROUND HOUSE | 40–59 | Enhanced vigilance, 15-min stage |
| 2 | RED / FAST PACE | 60–79 | Armed forces mobilizing ≤6h |
| 1 | BLACK / COCKED PISTOL | 80–100 | War imminent / nuclear conflict |

---

## Manual Level Overrides

Biological and food security are **manual** — they require human judgment:

```bash
# Set biological threat (e.g., confirmed H5N1 human transmission)
python defcon_monitor.py --bio 3 "Confirmed H5N1 human case in region"

# Clear biological threat (event resolved)
python defcon_monitor.py --bio 0

# Set food security level (e.g., major supply disruption)
python defcon_monitor.py --food 2 "Port strike — food supply chain disrupted"

# Manual DEFCON level override (expert mode)
python defcon_monitor.py --level 3
```

---

## Cron Setup (automated scans)

```bash
# Add to crontab (crontab -e):
# Run full scan every 30 minutes
*/30 * * * * /usr/bin/python3 /path/to/DEFCON/defcon_monitor.py >> /path/to/DEFCON/logs/cron.log 2>&1

# Run alert check every 15 minutes
*/15 * * * * /usr/bin/python3 /path/to/DEFCON/defcon_alert.py >> /path/to/DEFCON/logs/alert-cron.log 2>&1
```

---

## Web Dashboard

```bash
pip install flask gunicorn
python defcon_web.py --port 5000
```

Endpoints:
- `/` — Color HTML dashboard
- `/api/state` — JSON state (for scripts / integrations)
- `/history` — Recent scan history

---

## Alert Rules

| Rule | Priority | Cooldown |
|---|---|---|
| DEFCON 1 | Critical | None |
| DEFCON 2 | Critical | None |
| DEFCON 3 | High | 2h |
| Tornado Warning | Critical | None |
| Heat Advisory | Medium | 6h |
| Winter Storm | High | 4h |
| H5N1 human case | Critical | None |
| npm >10 vulns | High | 12h |
| npm 6–10 vulns | Medium | 24h |

---

## Hermes Agent Integration

See `SKILL.md` for the full skill definition. Install it in Hermes:

```
# Copy SKILL.md to your Hermes skills directory
cp SKILL.md ~/.hermes/skills/intelligence/defcon-monitor/

# The monitor then auto-loads when you ask about DEFCON level
```

---

## Data Sources

| Source | URL | Rate |
|---|---|---|
| defconlevel.com | https://www.defconlevel.com/current-level | OSINT estimate |
| NWS Alerts | https://api.weather.gov/alerts/active?zone={zone} | Real-time |
| USGS | https://earthquake.usgs.gov/fdsnws/event/1/query | ~1min |
| npm audit | package.json scan | Local only |

---

## License

MIT — See LICENSE file.
