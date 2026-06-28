# DEFCON Monitor — Configuration
# Copy this file to config.py and fill in your values.
# The monitor reads from config.py — no personal info embedded in scripts.

import os
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
# Override with environment variables for portability.

BASE_DIR = Path(__file__).parent  # Project root

STATE_DIR = os.environ.get(
    "DEFCON_STATE_DIR",
    str(Path.home() / ".openclaw" / "memory")
)
STATE_FILE = Path(STATE_DIR) / "defcon-state.json"

LOG_DIR = os.environ.get(
    "DEFCON_LOG_DIR",
    str(BASE_DIR / "logs")
)

# ── Location ──────────────────────────────────────────────────────────────────
# NWS weather zone for your area.
# Find yours at: https://www.weather.gov/publish/
# Examples: OHZ061=Dayton OH, VAZ053=DC Metro, CAZ048=Los Angeles CA

NWS_ZONE = os.environ.get("NWS_ZONE", "OHZ061")

# ── ClawdWatch OSINT Agent (optional) ────────────────────────────────────────
# If you run ClawdWatch locally, specify its URL here.
# The monitor falls back to defconlevel.com scraping if ClawdWatch is unavailable.

CLAWDWATCH_URL = os.environ.get(
    "CLAWDWATCH_URL",
    "http://localhost:3444"
)

# ── Telegram Alerts (optional) ────────────────────────────────────────────────
# Get a bot token from @BotFather on Telegram.
# Your chat_id can be obtained from @userinfobot.

TELEGRAM_BOT_TOKEN = os.environ.get(
    "DEFCON_TELEGRAM_BOT_TOKEN",
    "YOUR_BOT_TOKEN"     # ← Replace with your Telegram bot token
)
TELEGRAM_CHAT_ID = os.environ.get(
    "DEFCON_TELEGRAM_CHAT_ID",
    "YOUR_CHAT_ID"       # ← Replace with your Telegram chat ID
)
TELEGRAM_TOPIC_ID = os.environ.get(
    "DEFCON_TELEGRAM_TOPIC_ID",
    None                 # ← Optional: Telegram topic/thread ID
)

# ── SMTP Email Alerts (optional) ──────────────────────────────────────────────
# Set SMTP_* env vars to enable email alerts on critical DEFCON changes.

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_TO   = os.environ.get("SMTP_TO", "")

# ── npm Audit (optional) ───────────────────────────────────────────────────────
# Directory containing package.json for vulnerability scanning.
# Set to "" to disable npm audit scanning.

NODE_PROJECT_DIR = os.environ.get(
    "NODE_PROJECT_DIR",
    str(Path.home())
)

# ── Alert Cooldown (hours) ────────────────────────────────────────────────────
# Minimum hours between repeated non-critical alerts.
# Critical alerts (DEFCON 1-2, Tornado) fire regardless of cooldown.

ALERT_COOLDOWN_HOURS = 2
