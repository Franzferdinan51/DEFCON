---
name: defcon-monitor
description: "15-domain OSINT DEFCON threat monitor — geopolitical, cyber, seismic, weather, public health, economic, nuclear, biological, food, space weather, volcano, wildfire, infrastructure, maritime, disinfo. Real-time composite score + Telegram/Discord/Slack/PagerDuty alerts."
version: 3.2.0
author: DEFCON Monitor Community
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [DEFCON, threat-level, OSINT, 15-domain, composite-monitor, CISA, NWS, USGS, WHO, alert]
    category: intelligence
---

# DEFCON Monitor v3.0 — Hermes Agent Skill

Tracks real-time DEFCON level via web scraping (defconlevel.com) + ClawdWatch agent,
computes a 6-domain composite threat score, and dispatches Telegram/email alerts.

## When to Use

- User asks "what's the DEFCON level", "are we safe", "threat level"
- Morning brief needs a threat score + weather line
- Manual level override after a real-world event
- Running the dashboard during a live situation
- Health check via cron

## Prerequisites

**Python 3.10+** — stdlib only for core; Flask for web dashboard.

**ClawdWatch (optional):** OSINT agent running on port 3444.
If down, monitor falls back to defconlevel.com scraping automatically.

**Telegram (optional):** Get a bot token from `@BotFather`, set
`DEFCON_TELEGRAM_BOT_TOKEN` and `DEFCON_TELEGRAM_CHAT_ID` env vars.

## Scripts

| Script | Purpose |
|---|---|
| `defcon_monitor.py` | Full 6-domain composite scan → state update |
| `defcon_dashboard.py` | Color ASCII terminal dashboard |
| `defcon_health.py` | 20-point system diagnostics |
| `defcon_alert.py` | Rules-based escalation dispatcher (cooldown-aware) |
| `defcon_web.py` | Flask web dashboard + `/api/state` endpoint |

## Threat Score (0–100)

| Domain | Max Pts | How Triggered |
|---|---|---|
| Geopolitical DEFCON | 32 | `(5 - level) × 8` |
| Weather (NWS) | 20 | Any active NWS alert in zone |
| Seismic (USGS) | 15 | M6+ in USGS 30-day feed |
| Biological | 15 | Manual flag via `--bio` |
| Food Security | 10 | Manual flag via `--food` |
| Cyber (npm) | 8 | `npm audit` total vulns |

**Level from score:** 5→0–19, 4→20–39, 3→40–59, 2→60–79, 1→80–100

## Run Commands

```bash
# Full 6-domain scan
python3 DEFCON/defcon_monitor.py

# Terminal dashboard
python3 DEFCON/defcon_dashboard.py

# System health
python3 DEFCON/defcon_health.py

# Alert dispatcher (run after monitor)
python3 DEFCON/defcon_alert.py

# Manual biological override
python3 DEFCON/defcon_monitor.py --bio 3 "H5N1 confirmed human case"

# Clear biological override
python3 DEFCON/defcon_monitor.py --bio 0

# Manual food security override
python3 DEFCON/defcon_monitor.py --food 2 "Port strike — supply chain alert"

# Web dashboard
python3 DEFCON/defcon_web.py --port 5000
```

## DEFCON Levels

| Level | Label | Trigger |
|---|---|---|
| 1 | BLACK / COCKED PISTOL | Major war imminent |
| 2 | RED / FAST PACE | Armed forces 6-hr readiness |
| 3 | ORANGE / ROUND HOUSE | Enhanced vigilance, 15-min stage |
| 4 | YELLOW / DOUBLE TAKE | Intelligence watching |
| 5 | GREEN / FADE OUT | Normal posture |

## Alert Rules

Fires on: DEFCON ≤2, Tornado Warning, Heat Advisory, H5N1 human case, npm >10 vulns.
Critical alerts (DEFCON 1-2, Tornado) → no cooldown.
High priority → 2–4h cooldown. Medium → 6–24h cooldown.

## Pitfalls

- **DEFCON is directional OSINT signal only** — not official US government DEFCON.
- **Biological/Food are manual flags** — set via `defcon_monitor.py --bio/--food`.
  The monitor doesn't auto-detect these. Reset after events resolve.
- **Seismic is automatic** — USGS feed, no config needed.
- **Telegram silently skipped** when env vars are not set.
- **Web dashboard requires Flask** — `pip install flask`.

## Cron Setup

```bash
# crontab -e
*/30 * * * * /usr/bin/python3 /path/to/DEFCON/defcon_monitor.py
*/15 * * * * /usr/bin/python3 /path/to/DEFCON/defcon_alert.py
```

## Environment Variables

```bash
DEFCON_TELEGRAM_BOT_TOKEN   # Telegram bot token
DEFCON_TELEGRAM_CHAT_ID     # Your chat ID
DEFCON_TELEGRAM_TOPIC_ID    # Optional topic ID
NWS_ZONE                    # e.g. OHZ061, VAZ053
CLAWDWATCH_URL              # e.g. http://localhost:3444
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_TO  # Email alerts
```
