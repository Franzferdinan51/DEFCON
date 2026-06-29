# DEFCON Level Monitor v3.2

> **15-domain OSINT threat assessment** — real-time composite threat score + multi-channel alerts.

**⚠️ OSINT Estimate Only — not an official U.S. government signal.**

---

## 15 Threat Domains

| # | Domain | Source | What It Detects |
|---|---|---|---|
| 1 | 🌐 **Geopolitical** | ClawdWatch + defconlevel.com | DEFCON level, conflict zones |
| 2 | 💻 **Cyber** | CISA KEV Catalog | Known exploited vulnerabilities |
| 3 | 🌋 **Seismic** | USGS Earthquake API | M4+ earthquakes globally |
| 4 | ⛈️ **Weather** | NWS api.weather.gov | Tornado, hurricane, flood, heat |
| 5 | 🌋 **Volcano** | USGS Volcano Hazards | Eruptions, ash advisories |
| 6 | 🔥 **Wildfire** | InciWeb + NASA FIRMS | Active large wildfires |
| 7 | 🦠 **Public Health** | WHO DON + ProMED-mail | Disease outbreaks, epidemics |
| 8 | 📊 **Economic** | CBOE VIX + FRED | Market stress, yield curve |
| 9 | ☢️ **Nuclear** | IAEA + CTBTO | Radiological incidents |
| 10 | 🧬 **Biological** | WHO BWC + PubMed | Biorisk, biosafety incidents |
| 11 | 🌾 **Food** | USDA + RASFF + FAO | Food security threats |
| 12 | 🏗️ **Infrastructure** | CISA + NTSB | Critical infra failures |
| 13 | 🌌 **Space Weather** | NOAA SWPC | Geomagnetic storms, solar flares |
| 14 | ✈️ **Maritime/Aviation** | NOAA + ICAO | Disruptions, SIGMETs |
| 15 | 📰 **Disinformation** | GDELT Project | Conflict/war news volume |

- **6-domain composite score** (0–100) → DEFCON level 5→1
- **Terminal dashboard** — color ASCII panel, no dependencies
- **Web dashboard** — Flask UI with API endpoint
- **Alert engine** — Telegram + email with cooldown rules
- **State persistence** — JSON file, history, trend tracking
- **Standalone** — pure Python stdlib, no pip install required for core

---

## Quick Start

```bash
# Install (Flask optional — needed for web dashboard only)
pip install -r requirements.txt

# Full 15-domain scan
python defcon_monitor.py

# Quick 5-domain scan (faster)
python defcon_monitor.py --quick

# Single domain
python defcon_monitor.py --domain cyber

# Multi-zone weather
python defcon_monitor.py --zones "OHZ061,VAZ053,CAZ048"

# Daemon mode (every 30 minutes)
python defcon_monitor.py --daemon 1800

# Export history as JSON or CSV
python defcon_monitor.py --export json --history 30

# View terminal dashboard
python defcon_dashboard.py

# System diagnostics
python defcon_health.py

# Check alerts (no scan, just dispatch)
python defcon_alert.py

# Web dashboard (requires Flask)
python defcon_web.py
# → http://localhost:5000/
```

---

## Project Structure

```
DEFCON/
├── defcon_monitor.py          # Main CLI — 15-domain scanner
├── defcon_dashboard.py         # Color ASCII terminal dashboard
├── defcon_health.py           # 20-point system diagnostics
├── defcon_alert.py            # Alert dispatcher (run after scan)
├── defcon_web.py              # Flask web dashboard (optional)
├── config.py                  # Configuration — COPY and fill in values
├── requirements.txt            # Python deps (Flask only)
├── src/
│   ├── constants.py           # DEFCON enums, 15-domain metadata, dataclasses
│   ├── state.py              # StateManager — read/write defcon-state.json
│   ├── fetcher.py            # HTTP client — retries, UA rotation, TLS, cache
│   ├── history.py            # SQLite timeline + TrendEngine + anomaly detection
│   ├── notifiers.py          # Telegram, Discord, Slack, PagerDuty, SMTP, Webhook
│   └── sources/              # One scanner per domain
│       ├── defcon.py          # Geopolitical / DEFCON level
│       ├── nws.py             # Severe weather
│       ├── usgs.py            # Seismic / earthquakes
│       ├── cyber.py           # CISA KEV vulnerabilities
│       ├── public_health.py  # WHO + ProMED disease outbreaks
│       ├── economic.py        # VIX, oil, yield curve
│       ├── nuclear.py         # IAEA + CTBTO
│       ├── food.py           # USDA + RASFF food security
│       ├── infrastructure.py  # CISA + NTSB infra
│       ├── space_weather.py   # NOAA SWPC solar/geomagnetic
│       ├── volcano.py        # USGS volcano alerts
│       ├── wildfire.py       # InciWeb + NASA FIRMS
│       ├── maritime.py       # Maritime + aviation disruptions
│       ├── disinfo.py        # GDELT conflict signal
│       └── biological.py     # WHO BWC + PubMed biorisk
├── templates/
│   └── dashboard.html        # Web dashboard HTML template
├── logs/                      # Auto-created; scan + alert logs land here
├── .env.template             # Env vars template — copy and fill in
├── .gitignore
├── LICENSE
├── README.md
└── SKILL.md                  # Hermes Agent skill definition

---

## Active Intelligence (v3.2 — June 28, 2026)

### 🔥 FLAME Incident — Claude Mythos 5 + Fable 5 Export Controls
| | |
|---|---|
| **THREAT ID** | `THREAT-2026-0628-002` |
| **Severity** | HIGH |
| **Date** | June 12, 2026 |
| **Actors** | US Commerce Dept (Howard Lutnick), Anthropic, Amazon (Andy Jassy) |
| **What** | First-ever US export controls on a released AI model. Amazon CEO reported jailbreak exposing offensive cyber capabilities. Global access suspended June 12-13. Partially restored June 25-28 for ~100 vetted US institutions. |
| **Precedent** | US now treats frontier AI software like controlled munitions |
| **Impact on Grok/xAI** | None — only Anthropic models targeted |
| **Source** | [x.com/stretchcloud](https://x.com/stretchcloud/status/2070738897429205321) |

### 📊 BIS AI Data Center Debt Crisis — Active
| | |
|---|---|
| **THREAT ID** | `THREAT-2026-0628-001` |
| **Severity** | CRITICAL |
| **Date** | June 28, 2026 (BIS Annual Report released today) |
| **Actors** | BIS, Bank of Canada (Tiff Macklem), ECB |
| **What** | Three major institutions simultaneously warn US AI data center debt poses global financial stability risk. $75B+ in 2025 bond issuance. $600B projected private credit to AI. Structured finance ($9B+) held by pensions/insurers. Bank of Canada forcing sales of data center securities. |
| **DEFCON Impact** | Economic domain auto-elevated to DEFCON 3 when this threat is active |
| **Source** | [BIS Annual Report 2026](https://www.bis.org/publ/arpdf/ar2026e.htm) |

### 🏗️ Blackstone Positioning — Active
| | |
|---|---|
| **THREAT ID** | `THREAT-2026-0628-003` |
| **Severity** | HIGH |
| **Date** | June 28, 2026 |
| **Actors** | Blackstone ($BX), Oracle ($ORCL), SOXX, DRAM |
| **What** | Blackstone positioned to dump empty/underutilized data centers back to pension funds in default. Pension funds are end-buyers of last resort. |
| **Source** | [x.com/rdd147](https://x.com/rdd147/status/2071339539646533902) |

### Your FLAME Risk (US Citizen using Grok/xAI)
| Scenario | Risk Level | Notes |
|---|---|---|
| Using Grok as private US citizen | ✅ **LOW** | No current ban on xAI/Grok |
| Federal contractor work | ⚠️ **MEDIUM** | EO 14173 proposed; Lutnick hostile to foreign AI |
| Processing government data via Grok | 🔴 **HIGH** | Explicitly prohibited under current policy |
| Anthropic Claude (Mythos/Fable) recall | ✅ **N/A** | Only affects Claude, not Grok |
| Future model restrictions | ⚠️ **MEDIUM** | FLAME shows US will restrict AI exports at software level |
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
