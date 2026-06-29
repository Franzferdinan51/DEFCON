---
name: defcon-monitor
description: "16-domain OSINT DEFCON threat monitor for OpenClaw/Hermes agents. Tracks geopolitical, cyber, economic, weather, seismic, public health, nuclear, biological, food, infrastructure, disinfo, local. Reads config/locations.yaml for local area alerts. Designed for autonomous cron operation. Stateless — safe to run in parallel with other agents."
version: 3.4.1
compatibility: ">= 2.0.0"
author: "DEFCON / OpenClaw Agents Community"
platforms: [windows, linux, macos]

## Overview
DEFCON is an autonomous threat monitor. Each run is independent — safe for cron/parallel agent use. State is persisted to defcon-state.json.

## Run Commands
# Full 16-domain scan (includes local Huber Heights OH)
python defcon_monitor.py --deep

# Quick 5-domain scan
python defcon_monitor.py --quick

# Single domain
python defcon_monitor.py --domain local
python defcon_monitor.py --domain cyber
python defcon_monitor.py --domain economic

# Display DEFCON 1-5 rules framework
python defcon_monitor.py --rules

# Hack response protocol
python hack_response.py --collect       # Auto-collect system forensics
python hack_response.py --attacker       # Geo-IP + WHOIS + firewall blocks
python hack_response.py --wireshark     # PCAP analysis guide
defcon_monitor.py --hack-check          # All hack phases

# Misinformation checker
python misinfo.py "claim to verify"
python misinfo.py --json "claim"        # JSON output

## Environment Variables
DEFCON_TELEGRAM_BOT_TOKEN=  # Telegram bot token
DEFCON_TELEGRAM_CHAT_ID=       # Telegram chat ID
SMTP_HOST=                     # SMTP server for email alerts
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_TO=                      # Email recipient

## DEFCON Levels
Level 1: BLACK/COCKED PISTOL — IMMEDIATE — war, catastrophic cyber attack
Level 2: RED/FAST PACE — <15 min — confirmed state actor breach, VIX>40
Level 3: ORANGE/ROUND HOUSE — <1h — BIS AI debt alert, FLAME, tornado watch
Level 4: YELLOW/DOUBLE TAKE — <4h — elevated CVE activity, VIX>20
Level 5: GREEN/FADE OUT — Routine — nominal
